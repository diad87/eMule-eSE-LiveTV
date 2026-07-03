//this file is part of eMule (eSE fork)
// HolePunchCookie.h — MFC-side facade over the pure HolePunchCookieCore.
//
// Owns the ONLY piece of state the cookie scheme needs: a 32-byte per-process
// master secret, minted once via CSPRNG and IMMUTABLE thereafter. Because the
// secret never changes after init, every reader (the Kad main thread computing
// cookies, and — for metadata only — WebServer workers) reads it with ZERO
// synchronisation: no mutex, no atomics, no double-buffer/swap. The "rotation"
// of the signing key is implicit and stateless (epoch = now_ms / 16 s is a pure
// function derived on the stack per call inside the core), so there is nothing
// mutable to protect. See HolePunchCookieCore.h for the construction and the
// design rationale.
//
// The caller supplies nodeHash (our 16-byte Kad ID) per call — this facade does
// NOT depend on Kad init order; it only owns the secret.
#pragma once

#include <cstdint>
#include "HolePunchCookieCore.h"   // eSE::HP_COOKIE_SIZE, HpComputeCookie/HpVerifyCookie

namespace eSE {

class EseHolePunchCookie
{
public:
	// Compute the current-epoch cookie for (nodeHash, clientIPv4, nonceA).
	// `out` receives HP_COOKIE_SIZE (16) bytes. Allocation-free, lock-free.
	static void Compute(const uint8_t nodeHash[16], uint32_t clientIPv4,
	                    uint32_t nonceA, uint8_t out[HP_COOKIE_SIZE]) noexcept;

	// Verify an echoed cookie against epoch e and e-1 (grace across the 16 s
	// boundary). Constant-time compare. Returns true iff it matches.
	static bool Verify(const uint8_t nodeHash[16], uint32_t nowMs,
	                   uint32_t clientIPv4, uint32_t nonceA,
	                   const uint8_t cookie[HP_COOKIE_SIZE]) noexcept;
};

} // namespace eSE
