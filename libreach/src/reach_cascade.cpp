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

inline bool validReservedRdv(const ReachVector& peer) noexcept {
    if (peer.version < kReachVersion || peer.rdv.empty())
        return false;
    for (const RdvEntry& e : peer.rdv) {
        if (e.udpPort == 0 || e.expiresAt == 0)
            return false;
        Byte any = 0;
        for (Byte b : e.token)
            any |= b;
        if (any == 0)
            return false;
    }
    return true;
}

// Appendix-B applicability predicate for a single layer.
//   A = me (myCaps), B = peer (peer.capFlags + peer.rdv).
bool layerApplicable(reach_layer layer, std::uint16_t myCaps,
                     const ReachVector& peer) noexcept {
    const std::uint16_t bc = peer.capFlags;
    const bool bHasReservedRdv = validReservedRdv(peer);

    switch (layer) {
    case REACH_LAYER_DIRECT_V6:
        // 1. DIRECTO_V6 — B accepts inbound v6 and I can originate v6.
        // Local inbound reachability is irrelevant for an outbound dial.
        return has(bc, KAD_CAP_V6_IN) && has(myCaps, KAD_CAP_V6_OUT);

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
            (has(myCaps, KAD_CAP_V6_IN) && has(bc, KAD_CAP_V6_OUT));
        const bool bSignalable = has(bc, KAD_CAP_V4_UDP_IN) || bHasReservedRdv;
        return aCanAccept && bSignalable;
    }

    case REACH_LAYER_PUNCH_2W:
        // 4. PUNCH_2W — mutual 2-way punch support (invariant 1). "Tengo ruta UDP
        //    a B" is a property of the host's UDP socket, assumed available.
        return has(bc, KAD_CAP_PUNCH_2W) && has(myCaps, KAD_CAP_PUNCH_2W);

    case REACH_LAYER_PUNCH_3W:
        // 5. PUNCH_3W — mutual 3-way punch support AND B has an rdv to coordinate.
        return has(bc, KAD_CAP_PUNCH_3W) && has(myCaps, KAD_CAP_PUNCH_3W)
            && bHasReservedRdv;

    case REACH_LAYER_RELAY:
        // 6. RELAY — using a relay and volunteering relay service are distinct
        // permissions. A v2 reservation identifies the service; both endpoints
        // only need to consent as relay clients.
        return bHasReservedRdv && has(bc, KAD_CAP_RELAY_CLIENT)
            && has(myCaps, KAD_CAP_RELAY_CLIENT);

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
