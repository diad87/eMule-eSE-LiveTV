// SPDX-License-Identifier: MIT
//
// reach_cascade.cpp — the L3 cascade transition function. New code, MIT.
// Implements KEP-1 Appendix B / thesis §7.1 exactly; pure and allocation-free.
#include "reach/reach_cascade.h"

namespace reach {
namespace {

inline bool has(std::uint16_t caps, KadCap bit) noexcept {
    return (caps & static_cast<std::uint16_t>(bit)) != 0;
}

// Appendix-B applicability predicate for a single layer.
//   A = me (myCaps), B = peer (peer.capFlags + peer.rdv).
bool layerApplicable(reach_layer layer, std::uint16_t myCaps,
                     const ReachVector& peer) noexcept {
    const std::uint16_t bc = peer.capFlags;
    const bool bHasRdv = !peer.rdv.empty();

    switch (layer) {
    case REACH_LAYER_DIRECT_V6:
        // 1. DIRECTO_V6 — B reachable on v6 AND I have v6 (mutual, §7.1).
        return has(bc, KAD_CAP_V6_IN) && has(myCaps, KAD_CAP_V6_IN);

    case REACH_LAYER_DIRECT_V4:
        // 2. DIRECTO_V4 — B accepts inbound v4 TCP (HighID-equivalent). No "mutual"
        //    bit: connecting OUT never needs a local capability.
        return has(bc, KAD_CAP_V4_TCP_IN);

    case REACH_LAYER_CALLBACK: {
        // 3. CALLBACK — B opens a TCP connection back to A, so A MUST accept
        //    inbound TCP: A.v4_tcp_in, or A.v6_in with a v6-capable B (§7.1).
        //    AND B must be signalable to issue the callback: B has open v4 UDP
        //    (3a, direct callback) OR B has an rdv to relay the request (3b).
        const bool aCanAccept =
            has(myCaps, KAD_CAP_V4_TCP_IN) ||
            (has(myCaps, KAD_CAP_V6_IN) && has(bc, KAD_CAP_V6_IN));
        const bool bSignalable = has(bc, KAD_CAP_V4_UDP_IN) || bHasRdv;
        return aCanAccept && bSignalable;
    }

    case REACH_LAYER_PUNCH_2W:
        // 4. PUNCH_2W — mutual 2-way punch support (invariant 1). "Tengo ruta UDP
        //    a B" is a property of the host's UDP socket, assumed available.
        return has(bc, KAD_CAP_PUNCH_2W) && has(myCaps, KAD_CAP_PUNCH_2W);

    case REACH_LAYER_PUNCH_3W:
        // 5. PUNCH_3W — mutual 3-way punch support AND B has an rdv to coordinate.
        return has(bc, KAD_CAP_PUNCH_3W) && has(myCaps, KAD_CAP_PUNCH_3W) && bHasRdv;

    case REACH_LAYER_RELAY:
        // 6. RELAY — terminal eSE path: a relay-capable rdv exists and both sides
        //    accept relay circuits. The precise data-plane cap is an eSE-layer
        //    concern carried in my_cap_flags; KAD_CAP_RELAY_OFFER is the
        //    brand-neutral proxy for "participates in capped relay".
        return bHasRdv && has(bc, KAD_CAP_RELAY_OFFER) && has(myCaps, KAD_CAP_RELAY_OFFER);

    default:
        // REACH_LAYER_NONE / REACH_LAYER_CLASSIC are not applicability candidates.
        return false;
    }
}

} // namespace

reach_layer NextApplicableLayer(std::uint16_t myCaps, const ReachVector& peer,
                                reach_layer after) noexcept {
    // Scan strictly after `after`, in attempt order, up to (not including) the
    // classic fallback. The first layer whose preconditions hold wins.
    for (int l = static_cast<int>(after) + 1; l < REACH_LAYER_CLASSIC; ++l) {
        if (layerApplicable(static_cast<reach_layer>(l), myCaps, peer))
            return static_cast<reach_layer>(l);
    }
    return REACH_LAYER_CLASSIC;
}

} // namespace reach
