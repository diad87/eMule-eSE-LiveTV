// SPDX-License-Identifier: MIT
//
// libkad6 — kad6_shaped_bulk.cpp: shaped bulk carrier codec (ticket K6-0.7),
// class-5 anti-watermark (spec §9.6.1).
//
// AEAD abstraction (judgment call, documented for reviewers): libkad6 embeds no
// crypto (kad6_crypto.h). The real onion is a stack of AEAD layers owned by the
// host; each layer seals the buffer and contributes next_link_nonce(8)||tag(16).
// At the CODEC level we do not seal or open anything — we model each layer as an
// IDENTITY transform that contributes exactly kK6OnionLayerOverhead (24) opaque
// bytes. Concretely BuildK6ShapedBulk lays the L-byte authenticated prefix out as
//     [ plaintext : 16414 ][ per-layer opaque : 24 * depth ]
// with the per-layer region filled by the injected CSPRNG (standing in for the
// host's ciphertext/tags). ParseK6ShapedBulk, given the known remaining depth,
// recovers the plaintext from the first 16414 bytes of the prefix and never reads
// the tail. This keeps the library honest about "no homemade crypto" (spec I6)
// while still owning the two things that actually matter for class-5 coverage:
// the exact-size framing and the authenticated-prefix / regenerated-tail split.
#include "kad6/kad6_shaped_bulk.h"

#include "kad6/kad6_bytes.h"

namespace kad6 {

std::size_t K6ShapedPrefixLen(int depth) noexcept {
    if (depth != 2 && depth != 3)
        return 0; // class-5 is 2- or 3-hop only (K6-BULK-007)
    return kK6ShapedPlainSize + kK6OnionLayerOverhead * static_cast<std::size_t>(depth);
}

// ── plaintext (de)serialization ─────────────────────────────────────────────

Kad6Status EncodeK6ShapedPlain(const K6ShapedBulkPlainV1& p, const Kad6CryptoHooks& h,
                               std::vector<Byte>& out) {
    out.clear();
    if (p.kind < static_cast<Byte>(K6BulkKind::Data) ||
        p.kind > static_cast<Byte>(K6BulkKind::Close))
        return Kad6Status::BadValue;
    if (p.inner.size() > kK6ShapedInnerMax)
        return Kad6Status::TooLarge;
    if (!h.random_bytes)
        return Kad6Status::BadValue; // random_padding fill needs a CSPRNG

    out.reserve(kK6ShapedPlainSize);
    ByteWriter w(out);
    w.u8(1); // version is always 1 on the wire
    w.u8(p.kind);
    w.u16le(p.flags);
    w.u64le(p.stream_id);
    w.u64le(p.logical_sequence);
    w.u32le(static_cast<std::uint32_t>(p.inner.size()));
    w.bytes(p.inner.data(), p.inner.size());

    // out now holds 24 + inner_len bytes; pad the rest with CSPRNG to exactly 16414.
    const std::size_t used = out.size();          // 24 + inner_len, <= 16414
    const std::size_t padLen = kK6ShapedPlainSize - used;
    out.resize(kK6ShapedPlainSize);               // appends padLen zero bytes
    if (padLen && !h.random_bytes(out.data() + used, padLen)) {
        out.clear();
        return Kad6Status::AuthFailed; // CSPRNG hook failed
    }
    return Kad6Status::Ok;
}

Kad6Status DecodeK6ShapedPlain(const Byte* in, std::size_t len,
                               K6ShapedBulkPlainV1& out) noexcept {
    out = K6ShapedBulkPlainV1{};
    if (in == nullptr && len != 0)
        return Kad6Status::NullArgument;
    if (len != kK6ShapedPlainSize)
        return Kad6Status::Malformed; // plaintext is a fixed quantum

    ByteReader r(in, len);
    out.version          = r.u8();
    out.kind             = r.u8();
    out.flags            = r.u16le();
    out.stream_id        = r.u64le();
    out.logical_sequence = r.u64le();
    const std::uint32_t inner_len = r.u32le();
    if (!r.ok()) {
        out = K6ShapedBulkPlainV1{};
        return Kad6Status::Truncated;
    }
    if (out.version != 1) {
        out = K6ShapedBulkPlainV1{};
        return Kad6Status::UnsupportedVersion;
    }
    if (out.kind < static_cast<Byte>(K6BulkKind::Data) ||
        out.kind > static_cast<Byte>(K6BulkKind::Close)) {
        out = K6ShapedBulkPlainV1{};
        return Kad6Status::Malformed;
    }
    if (inner_len > kK6ShapedInnerMax) {
        out = K6ShapedBulkPlainV1{};
        return Kad6Status::Malformed;
    }
    const Byte* ip = r.take(inner_len);
    if (!ip) {
        out = K6ShapedBulkPlainV1{};
        return Kad6Status::Truncated; // unreachable given the fixed size, but prudent
    }
    out.inner.assign(ip, ip + inner_len);
    // trailing bytes (up to 16414) are random_padding: ignored on receipt.
    return Kad6Status::Ok;
}

// ── shaped frame build / parse / re-link ────────────────────────────────────

Kad6Status BuildK6ShapedBulk(const K6ShapedBulkPlainV1& plain, int depth,
                             std::uint32_t circ_id, std::uint64_t link_nonce_seq,
                             const Kad6CryptoHooks& h, std::vector<Byte>& out) {
    out.clear();
    const std::size_t L = K6ShapedPrefixLen(depth);
    if (L == 0)
        return Kad6Status::BadValue; // depth must be exactly 2 or 3
    if (!h.random_bytes)
        return Kad6Status::BadValue;

    // Serialize the plaintext (validates kind / inner size).
    std::vector<Byte> pt;
    const Kad6Status ps = EncodeK6ShapedPlain(plain, h, pt);
    if (ps != Kad6Status::Ok)
        return ps;

    out.reserve(kK6ShapedTotal);
    ByteWriter w(out);
    w.u32le(circ_id);
    w.u8(kK6ShapedBcmd);
    w.u64le(link_nonce_seq);
    w.u32le(kK6ShapedLengthField); // always 16983
    // Authenticated onion prefix: plaintext then depth*24 opaque per-layer bytes.
    w.bytes(pt.data(), pt.size());                        // 16414
    const std::size_t overhead = kK6OnionLayerOverhead * static_cast<std::size_t>(depth);
    const std::size_t prefixFillOff = out.size();         // 17 + 16414
    out.resize(prefixFillOff + overhead);
    if (overhead && !h.random_bytes(out.data() + prefixFillOff, overhead)) {
        out.clear();
        return Kad6Status::AuthFailed;
    }
    // out.size() is now 17 + L. Fill the tail with CSPRNG up to exactly 17000.
    const std::size_t tailOff = kK6ShapedHeaderSize + L; // 17 + L
    const std::size_t tailLen = kK6ShapedTotal - tailOff; // 16983 - L
    out.resize(kK6ShapedTotal);
    if (tailLen && !h.random_bytes(out.data() + tailOff, tailLen)) {
        out.clear();
        return Kad6Status::AuthFailed;
    }
    return Kad6Status::Ok;
}

Kad6Status PeekK6ShapedHeader(const Byte* in, std::size_t len, K6ShapedHeader& out) noexcept {
    out = K6ShapedHeader{};
    if (in == nullptr && len != 0)
        return Kad6Status::NullArgument;
    if (len != kK6ShapedTotal)
        return Kad6Status::Malformed; // shaped frames are exactly 17000

    ByteReader r(in, len);
    out.circ_id        = r.u32le();
    out.bcmd           = r.u8();
    out.link_nonce_seq = r.u64le();
    out.length         = r.u32le();
    if (!r.ok())
        return Kad6Status::Truncated; // unreachable at len==17000, but prudent
    if (out.bcmd != kK6ShapedBcmd)
        return Kad6Status::Malformed;
    if (out.length != kK6ShapedLengthField)
        return Kad6Status::Malformed;
    return Kad6Status::Ok;
}

Kad6Status ParseK6ShapedBulk(const Byte* in, std::size_t len, int depth,
                             K6ShapedBulkPlainV1& out, K6ShapedHeader* hdr) noexcept {
    out = K6ShapedBulkPlainV1{};
    if (hdr)
        *hdr = K6ShapedHeader{};
    if (in == nullptr && len != 0)
        return Kad6Status::NullArgument;
    // Total size must be EXACTLY 17000; anything else is Malformed (K6-BULK-007).
    if (len != kK6ShapedTotal)
        return Kad6Status::Malformed;
    const std::size_t L = K6ShapedPrefixLen(depth);
    if (L == 0)
        return Kad6Status::BadValue; // depth outside {2,3}

    K6ShapedHeader h{};
    const Kad6Status hs = PeekK6ShapedHeader(in, len, h); // checks bcmd + length
    if (hs != Kad6Status::Ok)
        return hs;
    if (hdr)
        *hdr = h;

    // The authenticated prefix is [17, 17+L). Recover the plaintext from its first
    // 16414 bytes; the remaining depth*24 opaque per-layer bytes and the tail are
    // NOT decoded here (tail is never even read).
    const std::size_t plainOff = kK6ShapedHeaderSize; // 17
    return DecodeK6ShapedPlain(in + plainOff, kK6ShapedPlainSize, out);
}

Kad6Status RelinkK6ShapedBulk(std::vector<Byte>& frame, int depth,
                              std::uint32_t new_circ_id, std::uint64_t new_link_nonce_seq,
                              const Kad6CryptoHooks& h) {
    if (frame.size() != kK6ShapedTotal)
        return Kad6Status::Malformed;
    const std::size_t L = K6ShapedPrefixLen(depth);
    if (L == 0)
        return Kad6Status::BadValue;
    if (!h.random_bytes)
        return Kad6Status::BadValue;

    // Confirm this is already a shaped frame before we rewrite anything.
    K6ShapedHeader cur{};
    const Kad6Status hs = PeekK6ShapedHeader(frame.data(), frame.size(), cur);
    if (hs != Kad6Status::Ok)
        return hs;

    // Rewrite circ_id (offset 0, u32 LE). bcmd (offset 4) and length (offset 13)
    // are left untouched so the carrier stays indistinguishable.
    for (std::size_t i = 0; i < 4; ++i)
        frame[i] = static_cast<Byte>((new_circ_id >> (8 * i)) & 0xFF);
    // Rewrite link_nonce_seq (offset 5, u64 LE).
    for (std::size_t i = 0; i < 8; ++i)
        frame[5 + i] = static_cast<Byte>((new_link_nonce_seq >> (8 * i)) & 0xFF);

    // Regenerate the entire tail; the authenticated prefix [17, 17+L) is preserved.
    const std::size_t tailOff = kK6ShapedHeaderSize + L; // 17 + L
    const std::size_t tailLen = kK6ShapedTotal - tailOff; // 16983 - L
    if (tailLen && !h.random_bytes(frame.data() + tailOff, tailLen))
        return Kad6Status::AuthFailed;
    return Kad6Status::Ok;
}

} // namespace kad6
