//this file is part of eMule
// eSE — Live broadcaster identity (Ed25519 keypair, sign/verify)
//
// v7.6.0 introduces self-certifying broadcaster identities. Each live
// broadcast generates a fresh Ed25519 keypair at start time. The streamKey
// (16 bytes, used everywhere downstream) is derived from the public key by
// sha1(pubkey)[:16], so anyone who knows the streamKey can verify any
// announcement / chunk / END that comes with a matching pubkey + signature.
//
// This eliminates several attacks at once:
//   #1 — predictable streamKey: pubkey is random, so streamKey is random
//   #2 — Kad publish forgery: announcements must be signed by the privkey
//   #4 — OP_LIVE_END spoof: END includes a sig
//   #5 — chunk poisoning: each chunk's payload is signed
//
// The privkey never leaves the broadcaster; only pubkey + signatures go on
// the wire. Verification is a public-key operation, so any peer can do it
// with the data they already received.
#pragma once

#include <cstddef>
#include <cstdint>

namespace eSELive {

// Sizes — match CryptoPP::ed25519 constants. Exported here so callers don't
// need to include cryptopp headers.
const size_t LIVE_PUBKEY_SIZE     = 32;
const size_t LIVE_PRIVKEY_SIZE    = 32;
const size_t LIVE_SIGNATURE_SIZE  = 64;
const size_t LIVE_STREAMKEY_SIZE  = 16;

// Generate a fresh Ed25519 keypair using AutoSeededRandomPool.
// Returns true on success.
bool GenerateBroadcasterKeypair(uint8_t pubkey[LIVE_PUBKEY_SIZE],
                                uint8_t privkey[LIVE_PRIVKEY_SIZE]);

// Sign `msg` (msgLen bytes) with `privkey`. `pubkey` MUST match the privkey;
// it's passed in so the Signer can be constructed without re-deriving.
// Writes LIVE_SIGNATURE_SIZE bytes to `sig`. Returns true on success.
bool SignMessage(const uint8_t privkey[LIVE_PRIVKEY_SIZE],
                 const uint8_t pubkey[LIVE_PUBKEY_SIZE],
                 const uint8_t* msg, size_t msgLen,
                 uint8_t sig[LIVE_SIGNATURE_SIZE]);

// Verify `sig` against `msg` using `pubkey`. Returns true iff the signature
// is valid (constant-time as far as CryptoPP guarantees).
bool VerifySignature(const uint8_t pubkey[LIVE_PUBKEY_SIZE],
                     const uint8_t* msg, size_t msgLen,
                     const uint8_t sig[LIVE_SIGNATURE_SIZE]);

// Derive the canonical 16-byte streamKey from a 32-byte pubkey.
// streamKey = first 16 bytes of SHA1(pubkey).
void DeriveStreamKey(const uint8_t pubkey[LIVE_PUBKEY_SIZE],
                     uint8_t streamKey[LIVE_STREAMKEY_SIZE]);

// Check that a streamKey claimed in a packet matches the pubkey the same
// packet supplied. Returns true if DeriveStreamKey(pubkey) equals streamKey.
bool StreamKeyMatchesPubkey(const uint8_t streamKey[LIVE_STREAMKEY_SIZE],
                            const uint8_t pubkey[LIVE_PUBKEY_SIZE]);

} // namespace eSELive
