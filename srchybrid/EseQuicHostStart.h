#pragma once
#include "EseNativeQuicRuntime.h"
#include "reach/direct_coordinator.h"
namespace ese {
struct QuicHostStartContext {
    std::array<std::uint8_t,32> localNode{};
    std::uint64_t topology=0,now=0;
    std::uint16_t boundPort=0;
    bool persistent=false;
};
inline bool ValidQuicHostStart(const NativeQuicConfig& native,const QuicPeerConfig& peer,
    const reach::DirectSessionRoute& route,const reach::DirectCoordinatorSnapshot& attempt,
    const QuicHostStartContext& host) noexcept {
    return host.persistent && host.boundPort && host.topology &&
        native.local.port==host.boundPort && peer.persistent &&
        peer.local.node==host.localNode && peer.local.role==(native.server ? 1 : 0) &&
        peer.local.topologyGeneration==host.topology &&
        route.candidate.topology_generation==host.topology &&
        route.candidate.expires_monotonic_ms>host.now &&
        route.id && route.transport==reach::DirectQuic &&
        (attempt.state==reach::DirectSessionState::Connecting ||
         attempt.state==reach::DirectSessionState::Authenticating) &&
        attempt.peer.domain==reach::DirectPeerDomain::NodePublicKey &&
        attempt.peer.identity==peer.expectedNode && HasQuicPeerTrustPolicy(peer) &&
        attempt.attempt_id==peer.local.attempt && attempt.epoch==peer.sessionEpoch;
}
}
