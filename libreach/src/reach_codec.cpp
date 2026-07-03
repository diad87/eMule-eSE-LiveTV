// SPDX-License-Identifier: MIT
//
// libreach — reach_codec.cpp: implementation of the TAG_REACH TLV codec.
// New code (not derived from eMule), so it may be MIT-licensed and embedded
// freely across the ecosystem (thesis §13.2).
#include "reach/reach_codec.h"

namespace reach {

const char* ReachStatusName(ReachStatus s) noexcept {
    switch (s) {
        case ReachStatus::Ok:              return "Ok";
        case ReachStatus::Truncated:       return "Truncated";
        case ReachStatus::BadVersionZero:  return "BadVersionZero";
        case ReachStatus::TooManyRdv:      return "TooManyRdv";
        case ReachStatus::ReservedBitsSet: return "ReservedBitsSet";
        case ReachStatus::BufferTooSmall:  return "BufferTooSmall";
        case ReachStatus::NullArgument:    return "NullArgument";
    }
    return "Unknown";
}

namespace {

// Little-endian scalar writers. The cursor `p` is advanced past the field.
inline void put_u16le(Byte*& p, std::uint16_t v) noexcept {
    p[0] = static_cast<Byte>(v & 0xFF);
    p[1] = static_cast<Byte>((v >> 8) & 0xFF);
    p += 2;
}

inline std::uint16_t get_u16le(const Byte* p) noexcept {
    return static_cast<std::uint16_t>(
        static_cast<std::uint16_t>(p[0]) |
        (static_cast<std::uint16_t>(p[1]) << 8));
}

} // namespace

std::size_t ReachEncodedSize(const ReachVector& v) noexcept {
    // Clamp rdv count to the wire maximum for the size estimate; Encode is the
    // checked path that rejects an over-long vector outright.
    const std::size_t n =
        v.rdv.size() < kMaxRdv ? v.rdv.size() : kMaxRdv;
    return kReachHeaderSize + n * kRdvWireSize + v.trailing.size();
}

ReachStatus EncodeReachVector(const ReachVector& v,
                              Byte* out, std::size_t outCap,
                              std::size_t* written) noexcept {
    if (written != nullptr)
        *written = 0;

    // ── Producer validation (strict) ──────────────────────────────────────
    if (v.version == 0)
        return ReachStatus::BadVersionZero;
    if (v.rdv.size() > kMaxRdv)
        return ReachStatus::TooManyRdv;
    // Reserved bits must be clear when we emit a v1 vector. A producer that
    // wants to set a future bit must bump the version byte first.
    if (v.version == kReachVersion &&
        (v.capFlags & ~kKadCapKnownMask) != 0)
        return ReachStatus::ReservedBitsSet;

    const std::size_t need =
        kReachHeaderSize + v.rdv.size() * kRdvWireSize + v.trailing.size();

    if (out == nullptr) {
        // Pure size probe is only legal with zero capacity; any non-zero
        // capacity with a null buffer is a programming error.
        if (outCap == 0)
            return ReachStatus::BufferTooSmall;
        return ReachStatus::NullArgument;
    }
    if (outCap < need)
        return ReachStatus::BufferTooSmall;

    Byte* p = out;
    *p++ = v.version;
    put_u16le(p, v.capFlags);
    *p++ = static_cast<Byte>(v.rdv.size());
    for (const RdvEntry& e : v.rdv) {
        // NodeID: 16 opaque bytes verbatim.
        for (std::size_t i = 0; i < kKadIdSize; ++i)
            *p++ = e.nodeId[i];
        // IPv4: 4 raw octets verbatim (host convention, never reordered).
        for (std::size_t i = 0; i < kIPv4Size; ++i)
            *p++ = e.ipv4[i];
        // UDP port: little-endian u16.
        put_u16le(p, e.udpPort);
    }
    // Optional trailing TLV bytes (e.g. signature) verbatim.
    for (Byte b : v.trailing)
        *p++ = b;

    if (written != nullptr)
        *written = need;
    return ReachStatus::Ok;
}

ReachStatus EncodeReachVector(const ReachVector& v, std::vector<Byte>& out) {
    out.clear();
    // Pre-validate so we don't size a buffer for an invalid vector.
    if (v.version == 0)
        return ReachStatus::BadVersionZero;
    if (v.rdv.size() > kMaxRdv)
        return ReachStatus::TooManyRdv;
    if (v.version == kReachVersion &&
        (v.capFlags & ~kKadCapKnownMask) != 0)
        return ReachStatus::ReservedBitsSet;

    const std::size_t need =
        kReachHeaderSize + v.rdv.size() * kRdvWireSize + v.trailing.size();
    out.resize(need);
    std::size_t written = 0;
    const ReachStatus st =
        EncodeReachVector(v, out.data(), out.size(), &written);
    if (st != ReachStatus::Ok)
        out.clear();
    return st;
}

ReachStatus DecodeReachVector(const Byte* in, std::size_t len,
                              ReachVector& out,
                              std::size_t* consumed) noexcept {
    if (consumed != nullptr)
        *consumed = 0;
    out = ReachVector{};
    out.rdv.clear();
    out.trailing.clear();

    // A null buffer that claims a non-zero length is a caller bug; a zero
    // length is simply an empty (truncated) input, regardless of pointer.
    if (in == nullptr && len != 0)
        return ReachStatus::NullArgument;
    if (len < kReachHeaderSize)
        return ReachStatus::Truncated;

    const Byte version = in[0];
    if (version == 0)
        return ReachStatus::BadVersionZero;

    const std::uint16_t capFlags = get_u16le(in + 1);
    const Byte nRdv = in[3];
    if (nRdv > kMaxRdv)
        return ReachStatus::TooManyRdv;

    const std::size_t bodyLen =
        kReachHeaderSize + static_cast<std::size_t>(nRdv) * kRdvWireSize;
    if (len < bodyLen)
        return ReachStatus::Truncated;

    // All structural checks passed — commit to `out`.
    out.version  = version;
    out.capFlags = capFlags;   // raw: reserved/unknown bits preserved (Postel)
    out.rdv.reserve(nRdv);

    const Byte* p = in + kReachHeaderSize;
    for (Byte i = 0; i < nRdv; ++i) {
        RdvEntry e;
        for (std::size_t j = 0; j < kKadIdSize; ++j)
            e.nodeId[j] = *p++;
        for (std::size_t j = 0; j < kIPv4Size; ++j)
            e.ipv4[j] = *p++;
        e.udpPort = get_u16le(p);
        p += 2;
        out.rdv.push_back(e);
    }

    // Anything past the known prefix is an optional trailing TLV (a signature
    // in the spec, or fields a newer minor version appended). Keep it opaque
    // so re-encoding is byte-stable and forward data is never lost.
    if (len > bodyLen)
        out.trailing.assign(in + bodyLen, in + len);

    if (consumed != nullptr)
        *consumed = len; // a bare TAG_REACH payload occupies the whole buffer
    return ReachStatus::Ok;
}

} // namespace reach
