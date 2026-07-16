// this file is part of eMule eSE — persistent per-node Ed25519 identity (Phase 1)
//
// A long-term Ed25519 keypair that identifies THIS node as a tunnel relay,
// distinct from the per-broadcast keypair in LiveCrypto. Generated once on first
// run and persisted via INodeIdentityStorage (DPAPI on Windows, 0600 file on
// POSIX). The public key is advertised in HELLO as TAG_ESE_NODE_PUB (0x6D) so
// peers can pin it for the authenticated CREATE/CREATED v2 handshake.
//
// See docs/AUTHENTICATED_TUNNEL_HANDSHAKE_PLAN.md §1.
#pragma once

#include <cstddef>
#include <cstdint>

namespace eSELive {

// Load the node identity from disk, or generate + persist a fresh one on first
// run. Idempotent (later calls are no-ops). Returns true if an identity is
// available in memory afterwards (even if persistence failed — it is then
// regenerated next run). Call once at startup on the MAIN thread, BEFORE the
// first HELLO is built.
bool NodeIdentityInit();

// True only if the active identity was loaded from or successfully written to
// durable storage. Security-sensitive capabilities (AUTH/KAD6 routing) must
// not be advertised for a session-only key.
bool NodeIdentityIsPersistent();

// 32-byte Ed25519 public key, or nullptr if NodeIdentityInit() has not produced
// an identity yet. Stable for the process lifetime.
const uint8_t* NodeIdentityPub();

// Sign `msg` (msgLen bytes) with the node private key. Writes 64 bytes to `sig`.
// Returns false if no identity is ready. (Used by the v2 handshake in Phase 2.)
bool NodeIdentitySign(const uint8_t* msg, std::size_t msgLen, uint8_t sig[64]);

} // namespace eSELive
