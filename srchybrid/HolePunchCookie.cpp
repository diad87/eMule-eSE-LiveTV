//this file is part of eMule (eSE fork)
// HolePunchCookie.cpp — see HolePunchCookie.h.
#include "stdafx.h"
#include "HolePunchCookie.h"
#include "cryptopp/osrng.h"   // CryptoPP::AutoSeededRandomPool

namespace eSE {

// Per-process master secret: HP_SECRET_SIZE (32) CSPRNG bytes minted EXACTLY
// once, the first time MasterSecret() is called, and never written again.
//
//  * Thread-safe init: C++11 "magic statics" guarantee the constructor runs
//    once even under a concurrent first-call race (MSVC >= 2015 honours this).
//  * Lock-free reads: after construction the buffer is immutable, so the Kad
//    main thread (and any other reader) needs no synchronisation — there is no
//    writer to race. Publication is safe by happens-before: the secret is born
//    inside the first call and the returned pointer can only be observed after
//    that constructor has completed.
//  * Not persisted: a restart mints a fresh secret, which invalidates every
//    outstanding cookie (no replay across sessions) — desirable, and needs no
//    disk/DPAPI.  No heap: the bytes live in the static object itself.
static const uint8_t* MasterSecret() noexcept
{
	static const struct Secret {
		uint8_t b[HP_SECRET_SIZE];
		Secret() {
			CryptoPP::AutoSeededRandomPool rng;
			rng.GenerateBlock(b, sizeof b);
		}
	} s;
	return s.b;
}

void EseHolePunchCookie::Compute(const uint8_t nodeHash[16], uint32_t clientIPv4,
                                 uint32_t nonceA, uint8_t out[HP_COOKIE_SIZE]) noexcept
{
	// Epoch from the monotonic tick (NOT wall-clock — consistent with the
	// fork's zero-the-wall-clock-on-wire stance; only relative epochs matter).
	HpComputeCookie(MasterSecret(), nodeHash, HpEpoch(::GetTickCount()),
	                clientIPv4, nonceA, out);
}

bool EseHolePunchCookie::Verify(const uint8_t nodeHash[16], uint32_t nowMs,
                                uint32_t clientIPv4, uint32_t nonceA,
                                const uint8_t cookie[HP_COOKIE_SIZE]) noexcept
{
	return HpVerifyCookie(MasterSecret(), nodeHash, nowMs,
	                      clientIPv4, nonceA, cookie);
}

} // namespace eSE
