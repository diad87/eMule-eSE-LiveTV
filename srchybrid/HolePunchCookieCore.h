//this file is part of eMule (eSE fork)
// HolePunchCookieCore.h — stateless return-routability cookie for the Kad
// hole-punch responder (P0 anti-reflection hardening).
//
// PURE CORE: no MFC, no eMule globals, no heap. Only CryptoPP. Header-only so
// it can be unit-tested standalone (srchybrid/tests/test_holepunch_cookie.cpp)
// AND included by the MFC wrapper (HolePunchCookie.cpp) without a separate
// precompiled-header translation unit.
//
// Threat closed: today Process_ESE_HOLEPUNCH_REQ seeds a NAT expectation and
// reflects an ACK on the FIRST packet, whose UDP source IP is spoofable — a
// reflection / state-seeding vector. With this, an unverified REQ gets only a
// CHALLENGE carrying a cookie; the initiator must echo the cookie (proving it
// receives packets at the claimed IP) before any state is seeded.
//
// Cookie = HMAC-SHA256( HMAC-SHA256(secret, epoch || nodeHash),  ip || nonceA )
//          truncated to 16 bytes.
//   * `secret`   : 32 CSPRNG bytes minted once per process — the value that
//                  makes the cookie unforgeable AND prevents inter-session
//                  replay (a previous session's cookies use a dead secret).
//   * epoch      : floor(now_ms / 16000) — the signing key "mutates" every
//                  ~16 s; cookies expire after one epoch (+ one of grace).
//   * nodeHash   : our 16-byte Kad ID (GetPrefs()->GetKadID().ToByteArray) —
//                  binds cookies to this node identity. Any stable 16-byte node
//                  identity works; the responder passes the Kad ID, matching the
//                  HolePunchCookie.h facade doc and Process_ESE_HOLEPUNCH_REQ.
//   * ip         : the client's IPv4 — return-routability proves IP ownership.
//                  NOTE bound to IP only, NOT port: a NAT may remap the source
//                  port between the CHALLENGE and the echoed REQ; what we prove
//                  is "you receive datagrams at this IP", and that is enough.
//   * nonceA     : the initiator's nonce — prevents cross-exchange cookie reuse.
#pragma once

#include <cstdint>
#include <cstddef>
#include <cstring>

#include "cryptopp/hmac.h"
#include "cryptopp/sha.h"

namespace eSE {

static const size_t   HP_COOKIE_SIZE = 16;    // truncated HMAC tag on the wire
static const size_t   HP_SECRET_SIZE = 32;    // per-process master secret
static const uint32_t HP_EPOCH_MS    = 16000; // 16 s rotation window

inline void HpPutU32LE(uint8_t* p, uint32_t v) noexcept {
    p[0] = static_cast<uint8_t>(v);
    p[1] = static_cast<uint8_t>(v >> 8);
    p[2] = static_cast<uint8_t>(v >> 16);
    p[3] = static_cast<uint8_t>(v >> 24);
}

// Best-effort secret wipe that the optimiser may not elide (volatile sink).
inline void HpWipe(uint8_t* p, size_t n) noexcept {
    volatile uint8_t* vp = p;
    while (n--) *vp++ = 0;
}

inline uint32_t HpEpoch(uint32_t nowMs) noexcept { return nowMs / HP_EPOCH_MS; }

// One HMAC-SHA256 with the MAC object on the stack (no heap allocation).
inline void HpHmac(const uint8_t* key, size_t keyLen,
                   const uint8_t* msg, size_t msgLen,
                   uint8_t out[CryptoPP::SHA256::DIGESTSIZE]) noexcept {
    CryptoPP::HMAC<CryptoPP::SHA256> mac(key, keyLen);
    mac.Update(msg, msgLen);
    mac.Final(out);
}

// Deterministic, allocation-free. `out` receives HP_COOKIE_SIZE bytes.
inline void HpComputeCookie(const uint8_t secret[HP_SECRET_SIZE],
                            const uint8_t nodeHash[16],
                            uint32_t epoch,
                            uint32_t clientIPv4,
                            uint32_t nonceA,
                            uint8_t out[HP_COOKIE_SIZE]) noexcept {
    // epochKey = HMAC(secret, LE(epoch) || nodeHash) — rotates each epoch.
    uint8_t emsg[4 + 16];
    HpPutU32LE(emsg, epoch);
    std::memcpy(emsg + 4, nodeHash, 16);
    uint8_t epochKey[CryptoPP::SHA256::DIGESTSIZE];
    HpHmac(secret, HP_SECRET_SIZE, emsg, sizeof(emsg), epochKey);

    // tag = HMAC(epochKey, LE(ip) || LE(nonceA)); cookie = tag[:16].
    uint8_t cmsg[4 + 4];
    HpPutU32LE(cmsg, clientIPv4);
    HpPutU32LE(cmsg + 4, nonceA);
    uint8_t tag[CryptoPP::SHA256::DIGESTSIZE];
    HpHmac(epochKey, sizeof(epochKey), cmsg, sizeof(cmsg), tag);

    std::memcpy(out, tag, HP_COOKIE_SIZE);
    HpWipe(epochKey, sizeof(epochKey));
}

// Constant-time 16-byte tag compare (no early-out on first mismatch).
inline bool HpCtEqual(const uint8_t* a, const uint8_t* b, size_t n) noexcept {
    uint8_t d = 0;
    for (size_t i = 0; i < n; ++i)
        d = static_cast<uint8_t>(d | (a[i] ^ b[i]));
    return d == 0;
}

// Accepts the current epoch and the previous one (grace across the boundary so
// a cookie issued at the tail of epoch N still verifies early in epoch N+1).
inline bool HpVerifyCookie(const uint8_t secret[HP_SECRET_SIZE],
                           const uint8_t nodeHash[16],
                           uint32_t nowMs,
                           uint32_t clientIPv4,
                           uint32_t nonceA,
                           const uint8_t cookie[HP_COOKIE_SIZE]) noexcept {
    const uint32_t e = HpEpoch(nowMs);
    uint8_t expect[HP_COOKIE_SIZE];

    HpComputeCookie(secret, nodeHash, e, clientIPv4, nonceA, expect);
    if (HpCtEqual(expect, cookie, HP_COOKIE_SIZE))
        return true;
    if (e > 0) {
        HpComputeCookie(secret, nodeHash, e - 1, clientIPv4, nonceA, expect);
        if (HpCtEqual(expect, cookie, HP_COOKIE_SIZE))
            return true;
    }
    return false;
}

} // namespace eSE
