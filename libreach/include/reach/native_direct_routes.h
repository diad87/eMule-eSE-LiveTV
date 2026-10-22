// SPDX-License-Identifier: MIT
#pragma once
#include "reach/native_direct_snapshot.h"
#include "reach/direct_session.h"
#include <limits>
namespace reach {
struct NativeValidatedUdpPath {
    std::array<std::uint8_t,32> node{};
    std::array<std::uint8_t,16> address{};
    std::uint8_t family=0;
    std::uint16_t port=0;
    std::uint64_t topology_generation=0,expires_monotonic_ms=0;
    DirectScope scope=DirectScope::Global;
    std::uint64_t interface_id=0;
};
struct NativeDirectTransportPolicy {
    std::uint8_t enabled_transports=DirectTcp;
    bool udp_path_validated=false;
    bool quic_binding_available=false;
    // Host-owned return validations, not copied from advertised wire evidence.
    // The global switch alone never authorizes a particular UDP endpoint.
    std::array<NativeValidatedUdpPath,kDirectMaxCandidates> validated_udp_paths{};
    std::size_t validated_udp_count=0;
};
struct NativeDirectRoutes {
    NativeSnapshotStatus snapshot_status=NativeSnapshotStatus::InvalidGeneration;
    DirectStatus status=DirectStatus::InvalidPolicy;
    std::vector<DirectSessionRoute> routes;
};
// The host supplies enabled adapters and validated path/binding facts; they
// are not inferred from an endpoint or a transport bit in an advertisement.
// Select one UDP transport per candidate (QUIC preferred only with binding),
// preserving candidate priority and leaving the core's TCP race unchanged.
inline NativeDirectRoutes BuildNativeDirectRoutes(const NativeDirectCandidateSnapshotV1& snapshot,
    const DirectPolicy& policy,const NativeDirectTransportPolicy& transport,std::uint32_t firstRouteId) {
    NativeDirectRoutes result;
    if(!firstRouteId || transport.validated_udp_count>transport.validated_udp_paths.size() ||
        (transport.enabled_transports & ~(DirectTcp|DirectUtp|DirectQuic))) return result;
    auto validated=snapshot;
    // A fresh authenticated UDP return may make a direct advertised endpoint
    // usable for QUIC, but proves neither TCP reachability nor a mapping.
    if(transport.udp_path_validated && transport.quic_binding_available && snapshot.peer.expected_node_pub &&
        snapshot.count<=snapshot.candidates.size()) {
        for(std::size_t c=0;c<snapshot.count;++c) {
            auto& candidate=validated.candidates[c].route;
            if(candidate.evidence!=DirectEvidence::Advertised || !(candidate.transport_mask & DirectQuic) ||
                (candidate.kind!=DirectKind::DirectV4 && candidate.kind!=DirectKind::DirectV6)) continue;
            for(std::size_t i=0;i<transport.validated_udp_count;++i) {
                const auto& path=transport.validated_udp_paths[i];
                if(path.node!=*snapshot.peer.expected_node_pub || path.family!=candidate.family ||
                    path.address!=candidate.address || path.port!=candidate.port || path.scope!=candidate.scope || path.interface_id!=candidate.interface_id ||
                    path.topology_generation!=snapshot.local_generation || path.expires_monotonic_ms<=policy.now_monotonic_ms) continue;
                candidate.evidence=DirectEvidence::Observed;
                candidate.transport_mask=DirectQuic; // UDP proof is not TCP/uTP consent.
                if(path.expires_monotonic_ms<candidate.expires_monotonic_ms)
                    candidate.expires_monotonic_ms=path.expires_monotonic_ms;
                break;
            }
        }
    }
    const auto plan=BuildNativeDirectPlan(validated,policy);
    result.snapshot_status=plan.snapshot_status; result.status=plan.plan.status;
    if(result.snapshot_status!=NativeSnapshotStatus::Ok || result.status!=DirectStatus::Ok) return result;
    result.routes.reserve(kDirectMaxRoutes);
    for(unsigned pass=0;pass<2;++pass) for(const auto& candidate:plan.plan.routes) {
        const auto mask=candidate.transport_mask & transport.enabled_transports;
        std::uint64_t pathUntil=0;
        if(snapshot.peer.expected_node_pub) for(std::size_t i=0;i<transport.validated_udp_count;++i) {
            const auto& path=transport.validated_udp_paths[i];
            if(path.node==*snapshot.peer.expected_node_pub && path.family==candidate.family &&
                path.address==candidate.address && path.port==candidate.port && path.scope==candidate.scope && path.interface_id==candidate.interface_id &&
                path.topology_generation==snapshot.local_generation &&
                path.expires_monotonic_ms>policy.now_monotonic_ms && path.expires_monotonic_ms>pathUntil)
                pathUntil=path.expires_monotonic_ms;
        }
        const std::uint8_t udp=(mask & DirectQuic) && pathUntil && transport.udp_path_validated && transport.quic_binding_available
            ? DirectQuic : (mask & DirectUtp) ? DirectUtp : 0;
        for(const auto selected:{std::uint8_t((mask & DirectTcp) ? DirectTcp : 0),udp}) {
            if(!selected || result.routes.size()==kDirectMaxRoutes) continue;
            const bool directTcp=selected==DirectTcp && (candidate.kind==DirectKind::DirectV6 || candidate.kind==DirectKind::DirectV4);
            // Keep direct TCP v6/v4 adjacent: inserting a UDP alternative
            // between them would prevent the core's 200ms IPv4 overlap.
            if((pass==0)!=directTcp) continue;
            const auto offset=static_cast<std::uint32_t>(result.routes.size());
            if(firstRouteId>(std::numeric_limits<std::uint32_t>::max)()-offset) {
                result.routes.clear(); result.status=DirectStatus::InvalidPolicy; return result;
            }
            result.routes.push_back({firstRouteId+offset,candidate,selected});
            if(selected==DirectQuic && pathUntil<result.routes.back().candidate.expires_monotonic_ms)
                result.routes.back().candidate.expires_monotonic_ms=pathUntil;
        }
    }
    return result;
}
// Route policy only. Caller must have independently verified the signed
// UDP return and local consent; these bytes alone confer no authority.
inline NativeDirectRoutes BuildNativeQuicReturnRoutes(const NativeValidatedUdpPath& path,std::uint64_t now,DirectPolicy policy={}) {
    if((path.family!=4 && path.family!=6) || path.expires_monotonic_ms<=now ||
        path.expires_monotonic_ms-now>15000) return {};
    NativeDirectCandidateSnapshotV1 snapshot; snapshot.local_generation=path.topology_generation;
    snapshot.peer.expected_node_pub=path.node; snapshot.count=1;
    snapshot.candidates[0].source=DirectCandidateSource::Observed;
    auto& route=snapshot.candidates[0].route; route.id=1;
    route.kind=path.family==6 ? DirectKind::DirectV6 : DirectKind::DirectV4;
    route.family=path.family; route.address=path.address; route.port=path.port;
    route.transport_mask=DirectQuic; route.evidence=DirectEvidence::Observed;
    route.scope=path.scope; route.interface_id=path.interface_id;
    route.topology_generation=path.topology_generation; route.expires_monotonic_ms=path.expires_monotonic_ms;
    policy.topology_generation=path.topology_generation; policy.now_monotonic_ms=now;
    NativeDirectTransportPolicy transport; transport.enabled_transports=DirectQuic;
    transport.udp_path_validated=true; transport.quic_binding_available=true;
    transport.validated_udp_count=1; transport.validated_udp_paths[0]=path;
    return BuildNativeDirectRoutes(snapshot,policy,transport,1);
}
}
