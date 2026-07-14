// SPDX-License-Identifier: MIT
//
// libkad6 — kad6_types.h: shared primitive types for the Kad6 codecs.
// No MFC, no sockets, no threads, no embedded crypto (see kad6_crypto.h for the
// host-injected primitives). Brand-neutral names (kad6_*), MIT — same contract
// as libreach (thesis §13.2), so any client can embed the Kad6 wire codecs
// without dragging in eSE/MFC.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace kad6 {

using Byte = std::uint8_t;

// Fixed-size identifiers used across the wire objects (spec §6, §7, §10, §14, §17).
constexpr std::size_t kKadIdSize     = 16;   // 128-bit KadID / object/source ids
constexpr std::size_t kHash16Size    = 16;
constexpr std::size_t kHash20Size    = 20;
constexpr std::size_t kHash32Size    = 32;   // SHA-256 / provenance digest
constexpr std::size_t kEd25519PubSize = 32;
constexpr std::size_t kEd25519SigSize = 64;
constexpr std::size_t kMacSize       = 32;   // HMAC-SHA256
constexpr std::size_t kNonce16Size   = 16;

using KadId  = std::array<Byte, kKadIdSize>;
using Hash16 = std::array<Byte, kHash16Size>;
using Hash20 = std::array<Byte, kHash20Size>;
using Hash32 = std::array<Byte, kHash32Size>;

// Codec-level status. NOTE: this is a LIBRARY return code, distinct from the
// K6E_* wire error codes in spec §24 (those travel inside K6M_ERROR). Keeping
// them separate avoids leaking library internals onto the wire.
enum class Kad6Status {
    Ok = 0,
    Truncated,           // input shorter than required
    Malformed,           // structurally invalid (bad family/len, length mismatch, ...)
    UnsupportedVersion,  // version byte this build does not accept
    UnsupportedOption,   // unknown CRITICAL TLV option (spec K6-TLV-002)
    TooLarge,            // a length exceeds its configured limit
    BadValue,            // a field is outside its allowed range
    NullArgument,        // null buffer with non-zero length (caller bug)
    AuthFailed,          // signature / MAC / verify failed
    StaleEpoch,          // epoch rollback / replay
    TargetForbidden,     // endpoint blocked by policy (loopback/LAN/...)
    Expired,             // time window elapsed (ticket/lease/record expires_at)
};

// Human-readable name for a status (diagnostics/tests only; never on the wire).
inline const char* Kad6StatusName(Kad6Status s) noexcept {
    switch (s) {
        case Kad6Status::Ok:                 return "Ok";
        case Kad6Status::Truncated:          return "Truncated";
        case Kad6Status::Malformed:          return "Malformed";
        case Kad6Status::UnsupportedVersion: return "UnsupportedVersion";
        case Kad6Status::UnsupportedOption:  return "UnsupportedOption";
        case Kad6Status::TooLarge:           return "TooLarge";
        case Kad6Status::BadValue:           return "BadValue";
        case Kad6Status::NullArgument:       return "NullArgument";
        case Kad6Status::AuthFailed:         return "AuthFailed";
        case Kad6Status::StaleEpoch:         return "StaleEpoch";
        case Kad6Status::TargetForbidden:    return "TargetForbidden";
        case Kad6Status::Expired:            return "Expired";
    }
    return "?";
}

// Constant-time equality of two equal-length buffers. Returns true iff equal.
// Not a "crypto algorithm" — a comparison utility kept in one place so every
// MAC/tag check goes through it instead of a short-circuiting std::memcmp.
inline bool Kad6CtEqual(const Byte* a, const Byte* b, std::size_t n) noexcept {
    Byte diff = 0;
    for (std::size_t i = 0; i < n; ++i)
        diff = static_cast<Byte>(diff | (a[i] ^ b[i]));
    return diff == 0;
}

} // namespace kad6
