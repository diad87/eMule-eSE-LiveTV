// SPDX-License-Identifier: MIT
//
// libreach — reach_cascade.h: the connection-cascade transition function (L3).
//
// This is the deterministic HEART of the cascade (KEP-1 Appendix B, thesis §7.1):
// given my capability bits and a peer's decoded reachability vector, it answers
// "which layer do I try next?". It is a PURE function — it depends only on
// capability bits and the presence of rdv anchors, never on endpoints, sockets,
// host state, or the clock. That purity is deliberate: the layer-selection rules
// are the dialect-prone part worth pinning with golden vectors, exactly like the
// TLV codec, and they are identical on every platform and FFI consumer.
//
// The ACTUATOR — turning a chosen layer into a host action (open_transport /
// signal_via_rdv with a concrete endpoint) — lives in the engine and needs the
// peer's primary endpoint, which the vector does not carry. That wiring is a
// separate concern; this header is the policy, not the mechanism.
#pragma once

#include <cstdint>

#include "reach/reach.h"        // reach_layer (C ABI enum, attempt order)
#include "reach/reach_types.h"  // ReachVector, KadCap

namespace reach {

// Returns the next cascade layer strictly AFTER `after` whose Appendix-B
// preconditions hold for (myCaps, peer), or REACH_LAYER_CLASSIC when none of the
// remaining eSE layers apply (invariant 3: all-layers-fail degrades to classic,
// never to a new error).
//
// Walk the ladder by seeding `after = REACH_LAYER_NONE` for the first attempt,
// then feeding back the previously-tried layer after each failure:
//
//     reach_layer l = NextApplicableLayer(myCaps, peer, REACH_LAYER_NONE);
//     while (l != REACH_LAYER_CLASSIC && attempt_failed(l))
//         l = NextApplicableLayer(myCaps, peer, l);
//
// Invariant 1 (no eSE layer without a MUTUAL cap bit) is enforced here for every
// layer that is symmetric by nature (v6, punch). Asymmetric layers gate on the
// side that must hold the capability: DIRECT_V4 needs only the peer to accept
// inbound TCP (we can always connect out); CALLBACK needs US to accept inbound.
reach_layer NextApplicableLayer(std::uint16_t myCaps,
                                const ReachVector& peer,
                                reach_layer after) noexcept;

} // namespace reach
