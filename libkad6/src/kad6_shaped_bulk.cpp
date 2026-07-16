// SPDX-License-Identifier: MIT
//
// libkad6 — fixed-size shaped bulk carrier. Onion cryptography is host-owned;
// this file handles only terminal plaintext serialization and opaque framing.
#include "kad6/kad6_shaped_bulk.h"

#include "kad6/kad6_bytes.h"

namespace kad6 {

std::size_t K6ShapedPrefixLen(int remaining_layers) noexcept {
    if (remaining_layers < 1 || remaining_layers > 3)
        return 0;
    return kK6ShapedPlainSize +
           kK6OnionLayerOverhead * static_cast<std::size_t>(remaining_layers);
}

Kad6Status EncodeK6ShapedPlain(const K6ShapedBulkPlainV1& p,
                               const Kad6CryptoHooks& h,
                               std::vector<Byte>& out) {
    out.clear();
    if (p.version != 1)
        return Kad6Status::UnsupportedVersion;
    if (p.kind < static_cast<Byte>(K6BulkKind::Data) ||
        p.kind > static_cast<Byte>(K6BulkKind::Close))
        return Kad6Status::BadValue;
    if (p.inner.size() > kK6ShapedInnerMax)
        return Kad6Status::TooLarge;
    if (!h.random_bytes)
        return Kad6Status::BadValue;

    out.reserve(kK6ShapedPlainSize);
    ByteWriter w(out);
    w.u8(p.version);
    w.u8(p.kind);
    w.u16le(p.flags);
    w.u64le(p.stream_id);
    w.u64le(p.logical_sequence);
    w.u32le(static_cast<std::uint32_t>(p.inner.size()));
    w.bytes(p.inner.data(), p.inner.size());

    const std::size_t used = out.size();
    const std::size_t pad_len = kK6ShapedPlainSize - used;
    out.resize(kK6ShapedPlainSize);
    if (pad_len && !h.random_bytes(out.data() + used, pad_len)) {
        out.clear();
        return Kad6Status::AuthFailed;
    }
    return Kad6Status::Ok;
}

Kad6Status DecodeK6ShapedPlain(const Byte* in, std::size_t len,
                               K6ShapedBulkPlainV1& out) noexcept {
    out = K6ShapedBulkPlainV1{};
    if (!in && len != 0)
        return Kad6Status::NullArgument;
    if (len != kK6ShapedPlainSize)
        return Kad6Status::Malformed;

    ByteReader r(in, len);
    out.version = r.u8();
    out.kind = r.u8();
    out.flags = r.u16le();
    out.stream_id = r.u64le();
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
        out.kind > static_cast<Byte>(K6BulkKind::Close) ||
        inner_len > kK6ShapedInnerMax) {
        out = K6ShapedBulkPlainV1{};
        return Kad6Status::Malformed;
    }
    const Byte* inner = r.take(inner_len);
    if (!inner) {
        out = K6ShapedBulkPlainV1{};
        return Kad6Status::Truncated;
    }
    out.inner.assign(inner, inner + inner_len);
    return Kad6Status::Ok;
}

Kad6Status BuildK6ShapedCarrier(const Byte* authenticated_prefix,
                                std::size_t prefix_len,
                                int remaining_layers,
                                std::uint32_t circ_id,
                                std::uint64_t link_nonce_seq,
                                const Kad6CryptoHooks& h,
                                std::vector<Byte>& out) {
    out.clear();
    if (!authenticated_prefix && prefix_len != 0)
        return Kad6Status::NullArgument;
    const std::size_t expected = K6ShapedPrefixLen(remaining_layers);
    if (expected == 0)
        return Kad6Status::BadValue;
    if (prefix_len != expected)
        return Kad6Status::Malformed;
    if (link_nonce_seq == 0 || link_nonce_seq == kK6ShapedPaddingSentinel
        || !h.random_bytes)
        return Kad6Status::BadValue;

    out.reserve(kK6ShapedTotal);
    ByteWriter w(out);
    w.u32le(circ_id);
    w.u8(kK6ShapedBcmd);
    w.u64le(link_nonce_seq);
    w.u32le(kK6ShapedLengthField);
    w.bytes(authenticated_prefix, prefix_len);

    const std::size_t tail_offset = kK6ShapedHeaderSize + prefix_len;
    const std::size_t tail_len = kK6ShapedTotal - tail_offset;
    out.resize(kK6ShapedTotal);
    if (tail_len && !h.random_bytes(out.data() + tail_offset, tail_len)) {
        out.clear();
        return Kad6Status::AuthFailed;
    }
    return Kad6Status::Ok;
}

Kad6Status PeekK6ShapedHeader(const Byte* in, std::size_t len,
                              K6ShapedHeader& out) noexcept {
    out = K6ShapedHeader{};
    if (!in && len != 0)
        return Kad6Status::NullArgument;
    if (len != kK6ShapedTotal)
        return Kad6Status::Malformed;

    ByteReader r(in, len);
    out.circ_id = r.u32le();
    out.bcmd = r.u8();
    out.link_nonce_seq = r.u64le();
    out.length = r.u32le();
    if (!r.ok())
        return Kad6Status::Truncated;
    if (out.bcmd != kK6ShapedBcmd ||
        out.length != kK6ShapedLengthField ||
        out.link_nonce_seq == 0
        || out.link_nonce_seq == kK6ShapedPaddingSentinel)
        return Kad6Status::Malformed;
    return Kad6Status::Ok;
}

Kad6Status ExtractK6ShapedPrefix(const Byte* in, std::size_t len,
                                 int remaining_layers,
                                 std::vector<Byte>& authenticated_prefix,
                                 K6ShapedHeader* hdr) {
    authenticated_prefix.clear();
    if (hdr)
        *hdr = K6ShapedHeader{};
    if (!in && len != 0)
        return Kad6Status::NullArgument;
    if (len != kK6ShapedTotal)
        return Kad6Status::Malformed;
    const std::size_t prefix_len = K6ShapedPrefixLen(remaining_layers);
    if (prefix_len == 0)
        return Kad6Status::BadValue;

    K6ShapedHeader parsed{};
    const Kad6Status status = PeekK6ShapedHeader(in, len, parsed);
    if (status != Kad6Status::Ok)
        return status;
    authenticated_prefix.assign(in + kK6ShapedHeaderSize,
                                in + kK6ShapedHeaderSize + prefix_len);
    if (hdr)
        *hdr = parsed;
    return Kad6Status::Ok;
}

} // namespace kad6
