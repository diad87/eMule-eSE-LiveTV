// SPDX-License-Identifier: MIT
//
// libkad6 — kad6_frame.cpp: implementation of the K6FrameV1 codec (the
// common header of every Kad6 gateway message). New code (not derived from
// eMule), MIT-licensed, no MFC/sockets/threads/embedded crypto.
#include "kad6/kad6_frame.h"

namespace kad6 {

std::size_t K6FrameEncodedSize(const K6Frame& f) noexcept {
    return kK6FrameHeaderSize + f.body.size();
}

Kad6Status EncodeK6Frame(const K6Frame& f, std::vector<Byte>& out) {
    out.clear();

    // ── Producer validation (strict) ──────────────────────────────────────
    if (f.version != 1)
        return Kad6Status::UnsupportedVersion;
    if ((f.flags & kK6FlagReservedMask) != 0)
        return Kad6Status::BadValue;
    if (f.body.size() > kK6FrameMaxBody)
        return Kad6Status::TooLarge;

    out.reserve(kK6FrameHeaderSize + f.body.size());
    ByteWriter w(out);
    w.u8(f.version);
    w.u8(f.msg_type);
    w.u16le(f.flags);
    w.u32le(f.request_id);
    w.u64le(f.session_id);
    w.u32le(static_cast<std::uint32_t>(f.body.size()));
    w.bytes(f.body.data(), f.body.size());

    return Kad6Status::Ok;
}

Kad6Status DecodeK6Frame(const Byte* in, std::size_t len, K6Frame& out,
                          std::size_t* consumed) noexcept {
    if (consumed != nullptr)
        *consumed = 0;
    out = K6Frame{};
    out.body.clear();

    // A null buffer that claims a non-zero length is a caller bug; anything
    // shorter than the fixed header cannot possibly be a frame.
    if (in == nullptr && len != 0)
        return Kad6Status::NullArgument;
    if (len < kK6FrameHeaderSize)
        return Kad6Status::Truncated;

    ByteReader r(in, len);
    const Byte version       = r.u8();
    const Byte msg_type      = r.u8();
    const std::uint16_t flags = r.u16le();
    const std::uint32_t request_id = r.u32le();
    const std::uint64_t session_id = r.u64le();
    const std::uint32_t body_len    = r.u32le();
    if (!r.ok())
        return Kad6Status::Truncated; // defensive; len check above already covers this

    if (version != 1)
        return Kad6Status::UnsupportedVersion;

    // Check the declared body length against the configured cap BEFORE ever
    // sizing a body buffer — this rejects a hostile huge body_len without
    // allocating anything.
    if (body_len > kK6FrameMaxBody)
        return Kad6Status::TooLarge;

    // The remaining bytes after the header must match body_len exactly: too
    // few is a truncated buffer; too many means the declared length doesn't
    // describe the buffer we were actually given (a partial parse is an
    // error either way — Postel).
    if (r.remaining() < static_cast<std::size_t>(body_len))
        return Kad6Status::Truncated;
    if (r.remaining() > static_cast<std::size_t>(body_len))
        return Kad6Status::Malformed;

    // All structural checks passed — commit to `out`. Reserved flag bits
    // (9..15), if set, are preserved verbatim: the decoder does not fail on
    // them and does not mask them off.
    out.version    = version;
    out.msg_type   = msg_type;
    out.flags      = flags;
    out.request_id = request_id;
    out.session_id = session_id;
    out.body.resize(body_len);
    if (body_len != 0 && !r.bytes(out.body.data(), body_len)) {
        // Cannot happen given the remaining() check above; guard anyway
        // rather than trust arithmetic silently.
        out = K6Frame{};
        return Kad6Status::Malformed;
    }

    if (consumed != nullptr)
        *consumed = kK6FrameHeaderSize + body_len;
    return Kad6Status::Ok;
}

} // namespace kad6
