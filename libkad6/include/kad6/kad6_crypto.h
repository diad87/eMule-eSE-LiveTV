// SPDX-License-Identifier: MIT
//
// libkad6 — kad6_crypto.h: inversion-of-control crypto hooks. libkad6 owns the
// serialization, canonicalization and validation of every Kad6 object; it does
// NOT embed a crypto implementation (no CryptoPP, no vendored primitives). The
// host injects the primitives — eSE wires CryptoPP, the unit tests wire a mock /
// test-vector oracle. Mirrors libreach's IoC discipline (host injects all side
// effects). Rationale: keeps libkad6 MFC-free and standalone-testable, and keeps
// "no homemade crypto" honest (spec I6 / K6-ABUSE-018).
#pragma once

#include "kad6/kad6_types.h"

namespace kad6 {

struct Kad6CryptoHooks {
    // HMAC-SHA256(key, msg) -> mac[32]. Returns true on success.
    bool (*hmac_sha256)(const Byte* key, std::size_t keyLen,
                        const Byte* msg, std::size_t msgLen,
                        Byte mac[kMacSize]) = nullptr;

    // SHA-256(msg) -> out[32]. Returns true on success.
    bool (*sha256)(const Byte* msg, std::size_t msgLen,
                   Byte out[kHash32Size]) = nullptr;

    // Ed25519 detached sign: sig[64] = Sign(sk, msg). The host decides its own
    // secret-key convention (seed vs expanded); libkad6 only forwards bytes.
    bool (*ed25519_sign)(const Byte* sk, std::size_t skLen,
                         const Byte* msg, std::size_t msgLen,
                         Byte sig[kEd25519SigSize]) = nullptr;

    // Ed25519 verify: true iff sig is valid for msg under pub[32].
    bool (*ed25519_verify)(const Byte pub[kEd25519PubSize],
                           const Byte* msg, std::size_t msgLen,
                           const Byte sig[kEd25519SigSize]) = nullptr;

    // CSPRNG: fill out[0..n). Returns true on success. Must be a real CSPRNG,
    // never seeded from clock/counter/ticket (spec K6-ID-016).
    bool (*random_bytes)(Byte* out, std::size_t n) = nullptr;
};

// True iff every hook is non-null. Codecs that only serialize do not require
// hooks; the sign / verify / MAC paths do.
inline bool Kad6CryptoReady(const Kad6CryptoHooks& h) noexcept {
    return h.hmac_sha256 && h.sha256 && h.ed25519_sign && h.ed25519_verify && h.random_bytes;
}

} // namespace kad6
