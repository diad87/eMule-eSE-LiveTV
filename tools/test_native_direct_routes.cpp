#include "reach/native_direct_routes.h"
#include "reach/direct_coordinator.h"
#include <cstdio>
#include <cstdlib>
static unsigned checks=0;
static void Check(bool condition) { ++checks; if(!condition) std::exit(1); }
int main() {
    using namespace reach;
    NativeDirectCandidateSnapshotV1 snapshot; snapshot.local_generation=7; snapshot.remote_generation=90; snapshot.count=1;
    auto& candidate=snapshot.candidates[0].route;
    candidate.id=12; candidate.family=4; candidate.address[0]=1; candidate.address[1]=2;
    candidate.address[2]=3; candidate.address[3]=4; candidate.port=4662;
    candidate.evidence=DirectEvidence::Observed; candidate.topology_generation=7;
    candidate.expires_monotonic_ms=20000; candidate.transport_mask=DirectTcp|DirectUtp|DirectQuic;
    DirectPolicy policy; policy.topology_generation=7;
    NativeDirectTransportPolicy transports; transports.enabled_transports=DirectTcp|DirectUtp|DirectQuic;
    auto routes=BuildNativeDirectRoutes(snapshot,policy,transports,1);
    Check(routes.status==DirectStatus::Ok && routes.routes.size()==2);
    Check(routes.routes[0].transport==DirectTcp && routes.routes[1].transport==DirectUtp);
    transports.udp_path_validated=true;
    Check(BuildNativeDirectRoutes(snapshot,policy,transports,1).routes[1].transport==DirectUtp);
    transports.quic_binding_available=true;
    Check(BuildNativeDirectRoutes(snapshot,policy,transports,1).routes[1].transport==DirectUtp);
    std::array<std::uint8_t,32> expectedNode{}; expectedNode[0]=1;
    snapshot.peer.expected_node_pub=expectedNode;
    auto& path=transports.validated_udp_paths[0];
    path.node=expectedNode; path.address=candidate.address; path.family=4; path.port=candidate.port;
    path.topology_generation=7; path.expires_monotonic_ms=25000; transports.validated_udp_count=1;
    const auto validPath=path;
    ++path.port;
    Check(BuildNativeDirectRoutes(snapshot,policy,transports,1).routes[1].transport==DirectUtp);
    path=validPath; ++path.node[0];
    Check(BuildNativeDirectRoutes(snapshot,policy,transports,1).routes[1].transport==DirectUtp);
    path=validPath; ++path.topology_generation;
    Check(BuildNativeDirectRoutes(snapshot,policy,transports,1).routes[1].transport==DirectUtp);
    path=validPath; path.expires_monotonic_ms=0;
    Check(BuildNativeDirectRoutes(snapshot,policy,transports,1).routes[1].transport==DirectUtp);
    path=validPath; path.expires_monotonic_ms=100;
    Check(BuildNativeDirectRoutes(snapshot,policy,transports,1).routes[1].candidate.expires_monotonic_ms==100);
    policy.now_monotonic_ms=100;
    Check(BuildNativeDirectRoutes(snapshot,policy,transports,1).routes[1].transport==DirectUtp);
    policy.now_monotonic_ms=0; path=validPath;
    transports.validated_udp_count=transports.validated_udp_paths.size()+1;
    Check(BuildNativeDirectRoutes(snapshot,policy,transports,1).status==DirectStatus::InvalidPolicy);
    transports.validated_udp_count=1;
    candidate.evidence=DirectEvidence::Advertised;
    const auto provenAdvertisement=BuildNativeDirectRoutes(snapshot,policy,transports,1);
    Check(provenAdvertisement.routes.size()==1 && provenAdvertisement.routes[0].transport==DirectQuic &&
        provenAdvertisement.routes[0].candidate.evidence==DirectEvidence::Observed &&
        provenAdvertisement.routes[0].candidate.transport_mask==DirectQuic);
    Check(candidate.evidence==DirectEvidence::Advertised && candidate.transport_mask==7);
    ++path.port;
    Check(BuildNativeDirectRoutes(snapshot,policy,transports,1).routes.empty());
    path=validPath; candidate.evidence=DirectEvidence::Observed;
    routes=BuildNativeDirectRoutes(snapshot,policy,transports,10);
    Check(routes.routes[1].transport==DirectQuic && routes.routes[0].id==10 && routes.routes[1].id==11);
    Check(routes.routes[0].candidate.id==12 && candidate.transport_mask==7);
    transports.enabled_transports=DirectQuic;
    Check(BuildNativeDirectRoutes(snapshot,policy,transports,1).routes.size()==1);
    transports.udp_path_validated=false;
    Check(BuildNativeDirectRoutes(snapshot,policy,transports,1).routes.empty());
    transports.enabled_transports=0;
    Check(BuildNativeDirectRoutes(snapshot,policy,transports,1).routes.empty());
    transports.enabled_transports=128;
    Check(BuildNativeDirectRoutes(snapshot,policy,transports,1).status==DirectStatus::InvalidPolicy);
    transports.enabled_transports=7;
    Check(BuildNativeDirectRoutes(snapshot,policy,transports,0).status==DirectStatus::InvalidPolicy);
    Check(BuildNativeDirectRoutes(snapshot,policy,transports,0xffffffffu).status==DirectStatus::InvalidPolicy);
    snapshot.local_generation=6;
    Check(BuildNativeDirectRoutes(snapshot,policy,transports,1).snapshot_status==NativeSnapshotStatus::InvalidGeneration);
    snapshot.local_generation=7;
    DirectCoordinator coordinator; DirectPeerKey peer; peer.source_record_id=1; peer.source_epoch=1;
    DirectAttemptId attempt{}; attempt[0]=1;
    const auto request=coordinator.Request(peer,1,attempt,7,0);
    routes=BuildNativeDirectRoutes(snapshot,policy,transports,1);
    const auto batch=coordinator.SetRoutes(request.handle,routes.routes,0);
    Check(batch.actions.size()==1 && batch.actions[0].type==DirectActionType::Start);
    Check(coordinator.AuthorizesStart(request.handle,routes.routes[0],batch.actions[0].session_epoch));
    auto forged=routes.routes[0]; forged.candidate.port=1;
    Check(!coordinator.AuthorizesStart(request.handle,forged,batch.actions[0].session_epoch));
    for(std::size_t i=1;i<8;++i) {
        snapshot.candidates[i]=snapshot.candidates[0]; snapshot.candidates[i].route.id=12+i;
        snapshot.candidates[i].route.port=static_cast<std::uint16_t>(4662+i);
    }
    snapshot.count=8;
    Check(BuildNativeDirectRoutes(snapshot,policy,transports,1).routes.size()==8);
    snapshot.count=2;
    auto& v6=snapshot.candidates[1].route;
    v6.kind=DirectKind::DirectV6; v6.family=6; v6.address={};
    v6.address[0]=0x20; v6.address[1]=1; v6.address[2]=0x48; v6.address[3]=0x60; v6.address[15]=1;
    routes=BuildNativeDirectRoutes(snapshot,policy,transports,1);
    Check(routes.routes.size()==4 && routes.routes[0].candidate.family==6 && routes.routes[1].candidate.family==4);
    Check(routes.routes[2].transport==DirectUtp && routes.routes[3].transport==DirectUtp);
    Check(routes.routes[0].transport==DirectTcp && routes.routes[1].transport==DirectTcp);
    DirectCoordinator race;
    const auto racing=race.Request(peer,1,attempt,7,0);
    Check(race.SetRoutes(racing.handle,routes.routes,0).actions.size()==1);
    Check(race.Advance(racing.handle,199).actions.empty());
    const auto overlapped=race.Advance(racing.handle,200);
    Check(overlapped.actions.size()==1 && overlapped.actions[0].type==DirectActionType::Start && overlapped.actions[0].route_id==2);
    NativeValidatedUdpPath returned; returned.node.fill(19); returned.address[0]=8; returned.address[1]=8;
    returned.address[2]=8; returned.address[3]=8; returned.family=4; returned.port=4242;
    returned.topology_generation=7; returned.expires_monotonic_ms=15100;
    const auto publicReturn=BuildNativeQuicReturnRoutes(returned,100);
    Check(publicReturn.routes.size()==1 && publicReturn.routes[0].transport==DirectQuic &&
        publicReturn.routes[0].candidate.evidence==DirectEvidence::Observed && publicReturn.routes[0].candidate.expires_monotonic_ms==15100);
    auto invalidReturn=returned; invalidReturn.expires_monotonic_ms=15101;
    Check(BuildNativeQuicReturnRoutes(invalidReturn,100).routes.empty());
    invalidReturn=returned; invalidReturn.expires_monotonic_ms=100;
    Check(BuildNativeQuicReturnRoutes(invalidReturn,100).routes.empty());
    invalidReturn=returned; invalidReturn.node={};
    Check(BuildNativeQuicReturnRoutes(invalidReturn,100).routes.empty());
    invalidReturn=returned; invalidReturn.topology_generation=0;
    Check(BuildNativeQuicReturnRoutes(invalidReturn,100).routes.empty());
    invalidReturn=returned; invalidReturn.port=0;
    Check(BuildNativeQuicReturnRoutes(invalidReturn,100).routes.empty());
    invalidReturn=returned; invalidReturn.family=5;
    Check(BuildNativeQuicReturnRoutes(invalidReturn,100).routes.empty());
    invalidReturn=returned; invalidReturn.address={}; invalidReturn.address[0]=127; invalidReturn.address[3]=1;
    Check(BuildNativeQuicReturnRoutes(invalidReturn,100).routes.empty());
    returned.family=6; returned.address={}; returned.address[0]=0x20; returned.address[1]=1; returned.address[2]=0x48; returned.address[3]=0x60;
    returned.address[15]=0x88;
    Check(BuildNativeQuicReturnRoutes(returned,100).routes.size()==1);
    returned.address={}; returned.address[15]=1;
    Check(BuildNativeQuicReturnRoutes(returned,100).routes.empty());
    std::printf("native direct routes: %u checks PASS\n",checks);
}
