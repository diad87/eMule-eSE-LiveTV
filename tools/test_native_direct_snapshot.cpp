#include "reach/native_direct_snapshot.h"
#include "reach/native_direct_request.h"
#include "reach/native_direct_reask.h"
#include "../srchybrid/EseFileReaskTime.h"
#include <cstdio>
#include <cstdlib>
static unsigned checks=0;
static void Check(bool condition) { ++checks; if(!condition) std::exit(1); }
int main() {
    using namespace reach;
    Check(ese::FileReaskRemaining(0,100,60000)==0);
    Check(ese::FileReaskRemaining(100,100,60000)==60000);
    Check(ese::FileReaskRemaining(100,60099,60000)==1);
    Check(ese::FileReaskRemaining(100,60100,60000)==0);
    Check(ese::FileReaskRemaining(100,60101,60000)==0);
    constexpr std::uint32_t wrapStart=0xfffffff0u;
    Check(ese::FileReaskRemaining(wrapStart,wrapStart,60000)==60000);
    Check(ese::FileReaskRemaining(wrapStart,0xffffffffu,60000)==59985);
    Check(ese::FileReaskRemaining(wrapStart,0,60000)==59984);
    Check(ese::FileReaskRemaining(wrapStart,wrapStart+59999u,60000)==1);
    Check(ese::FileReaskRemaining(wrapStart,wrapStart+60000u,60000)==0);
    Check(ese::FileReaskRemaining(wrapStart,wrapStart+60001u,60000)==0);
    Check(ese::FileReaskRemaining(100,101,0)==0);
    NativeDirectReaskGate gate;
    Check(!gate.Allow(100,0));
    Check(gate.Allow(100,7));
    gate.Defer(100);
    Check(!gate.Allow(100,7));
    Check(!gate.Allow(99,7));
    Check(!gate.Allow(60099,7));
    Check(gate.Allow(60100,7));
    gate.Negotiating(true);
    Check(!gate.Allow(999999,7));
    Check(!gate.Allow(999999,8)); // New topology does not authorize parallel negotiation.
    gate.Ended(1000000,8);
    Check(!gate.Allow(1059999,8));
    Check(gate.Allow(1060000,8));
    gate.Defer(1060000);
    Check(gate.Allow(1060001,9));
    Check(!gate.Allow(1060001,0));
    NativeDirectReaskGate firstTerminal;
    firstTerminal.Ended(100,7); // First observation must not erase terminal cooldown.
    Check(!firstTerminal.Allow(100,7));
    Check(firstTerminal.Allow(60100,7));
    gate.Defer((std::numeric_limits<std::uint64_t>::max)()-1);
    Check(!gate.Allow((std::numeric_limits<std::uint64_t>::max)(),9));
    Check(gate.Allow(1,10)); // Only a genuine new generation clears overflow latch.
    NativeDirectCandidateSnapshotV1 snapshot;
    Check(ValidateNativeSnapshot(snapshot,0)==NativeSnapshotStatus::InvalidGeneration);
    snapshot.local_generation=7;
    Check(ValidateNativeSnapshot(snapshot,7)==NativeSnapshotStatus::Ok);
    Check(ValidateNativeSnapshot(snapshot,8)==NativeSnapshotStatus::InvalidGeneration);
    snapshot.remote_generation=99;
    Check(ValidateNativeSnapshot(snapshot,7)==NativeSnapshotStatus::Ok); // identity domains/generations not collapsed
    snapshot.remote_generation=0;
    Check(ValidateNativeSnapshot(snapshot,7)==NativeSnapshotStatus::InvalidGeneration);
    snapshot.remote_generation.reset(); snapshot.count=16;
    Check(ValidateNativeSnapshot(snapshot,7)==NativeSnapshotStatus::Ok);
    snapshot.count=17; Check(ValidateNativeSnapshot(snapshot,7)==NativeSnapshotStatus::TooManyCandidates);
    snapshot.count=1;
    snapshot.peer.expected_node_pub=std::array<std::uint8_t,32>{};
    Check(ValidateNativeSnapshot(snapshot,7)==NativeSnapshotStatus::InvalidIdentity);
    (*snapshot.peer.expected_node_pub)[31]=9;
    snapshot.peer.expected_user_hash=std::array<std::uint8_t,16>{};
    Check(ValidateNativeSnapshot(snapshot,7)==NativeSnapshotStatus::InvalidIdentity);
    (*snapshot.peer.expected_user_hash)[15]=8;
    snapshot.peer.kad_id=std::array<std::uint8_t,16>{};
    Check(ValidateNativeSnapshot(snapshot,7)==NativeSnapshotStatus::InvalidIdentity);
    (*snapshot.peer.kad_id)[15]=7;
    Check(ValidateNativeSnapshot(snapshot,7)==NativeSnapshotStatus::Ok);
    snapshot.peer.trust=static_cast<DirectIdentityTrust>(255);
    Check(ValidateNativeSnapshot(snapshot,7)==NativeSnapshotStatus::InvalidIdentity);
    snapshot.peer.trust=DirectIdentityTrust::Unknown;
    snapshot.candidates[0].mapping_id=0;
    Check(ValidateNativeSnapshot(snapshot,7)==NativeSnapshotStatus::InvalidSource);
    snapshot.candidates[0].mapping_id=15;
    snapshot.candidates[0].source=static_cast<DirectCandidateSource>(255);
    Check(ValidateNativeSnapshot(snapshot,7)==NativeSnapshotStatus::InvalidSource);
    snapshot.candidates[0].source=DirectCandidateSource::ReachRecord;
    snapshot.candidates[0].route.address[0]=203; snapshot.candidates[0].route.port=4662;
    const auto copy=snapshot;
    snapshot.candidates[0].route.port=1; (*snapshot.peer.expected_node_pub)[31]=1;
    Check(copy.candidates[0].route.port==4662 && (*copy.peer.expected_node_pub)[31]==9);
    Check(copy.peer.expected_user_hash!=copy.peer.kad_id);
    Check(ValidateNativeSnapshot(copy,7)==NativeSnapshotStatus::Ok);
    snapshot=NativeDirectCandidateSnapshotV1{};
    snapshot.local_generation=7; snapshot.remote_generation=99; snapshot.count=1;
    auto& route=snapshot.candidates[0].route;
    route.id=1; route.family=4; route.address[0]=1; route.address[1]=1;
    route.address[2]=1; route.address[3]=1; route.port=4662;
    route.transport_mask=DirectTcp; route.topology_generation=7; route.expires_monotonic_ms=1000;
    DirectPolicy policy; policy.topology_generation=7; policy.now_monotonic_ms=10;
    Check(BuildNativeDirectPlan(snapshot,policy).plan.routes.empty()); // advertised alone is not observed
    route.evidence=DirectEvidence::Observed;
    auto selected=BuildNativeDirectPlan(snapshot,policy);
    Check(selected.snapshot_status==NativeSnapshotStatus::Ok && selected.plan.status==DirectStatus::Ok);
    Check(selected.plan.routes.size()==1 && selected.plan.routes[0].port==4662);
    route.topology_generation=99;
    Check(BuildNativeDirectPlan(snapshot,policy).plan.routes.empty()); // remote generation cannot authorize route
    route.topology_generation=6;
    Check(BuildNativeDirectPlan(snapshot,policy).plan.routes.empty()); // no stale rebasing
    route.topology_generation=7; route.expires_monotonic_ms=10;
    Check(BuildNativeDirectPlan(snapshot,policy).plan.routes.empty());
    snapshot.local_generation=6;
    selected=BuildNativeDirectPlan(snapshot,policy);
    Check(selected.snapshot_status==NativeSnapshotStatus::InvalidGeneration && selected.plan.routes.empty());
    snapshot.local_generation=7; snapshot.count=17;
    Check(BuildNativeDirectPlan(snapshot,policy).snapshot_status==NativeSnapshotStatus::TooManyCandidates);
    Check(snapshot.remote_generation==99 && route.topology_generation==7); // caller unchanged
    snapshot.count=0;
    DirectCoordinator coordinator;
    DirectAttemptId attempt{}; attempt[0]=1;
    auto admitted=RequestNativeDirect(coordinator,snapshot,7,0,0,1,attempt,10);
    Check(admitted.request.status==DirectRequestStatus::InvalidRequest && coordinator.Size()==0);
    admitted=RequestNativeDirect(coordinator,snapshot,7,42,1,1,attempt,10);
    Check(admitted.request.status==DirectRequestStatus::Created && coordinator.Size()==1);
    attempt[0]=2;
    const auto joined=RequestNativeDirect(coordinator,snapshot,7,42,1,2,attempt,10);
    Check(joined.request.status==DirectRequestStatus::Joined && coordinator.Size()==1);
    Check(coordinator.Snapshot(joined.request.handle)->subscribers==2);
    Check(coordinator.Snapshot(joined.request.handle)->attempt_id[0]==1);
    snapshot.peer.kad_id=std::array<std::uint8_t,16>{}; (*snapshot.peer.kad_id)[0]=3;
    Check(!NativeDirectPeerKey(snapshot.peer,0,0)); // Kad is not user hash
    snapshot.peer.expected_user_hash=std::array<std::uint8_t,16>{}; (*snapshot.peer.expected_user_hash)[0]=3;
    const auto classic=NativeDirectPeerKey(snapshot.peer,42,1);
    Check(classic && classic->domain==DirectPeerDomain::UserHash && classic->identity[16]==0);
    admitted=RequestNativeDirect(coordinator,snapshot,7,42,1,3,attempt,10);
    Check(admitted.request.status==DirectRequestStatus::Created && coordinator.Size()==2);
    snapshot.peer.expected_node_pub=std::array<std::uint8_t,32>{}; (*snapshot.peer.expected_node_pub)[0]=3;
    const auto native=NativeDirectPeerKey(snapshot.peer,42,1);
    Check(native && native->domain==DirectPeerDomain::NodePublicKey && native->source_record_id==0);
    {
        DirectCoordinator incoming; DirectAttemptId wireAttempt{}; wireAttempt[0]=19;
        const auto created=incoming.RequestSharedAttempt(*native,51,wireAttempt,7,10);
        Check(created.status==DirectRequestStatus::Created);
        auto otherAttempt=wireAttempt; ++otherAttempt[0];
        Check(incoming.RequestSharedAttempt(*native,52,otherAttempt,7,11).status==DirectRequestStatus::InvalidRequest);
        Check(incoming.Snapshot(created.handle)->subscribers==1 && incoming.Snapshot(created.handle)->attempt_id==wireAttempt);
        Check(incoming.RequestSharedAttempt(*native,52,wireAttempt,7,11).status==DirectRequestStatus::Joined);
        Check(incoming.Snapshot(created.handle)->subscribers==2);
        auto otherPeer=*native; ++otherPeer.identity[0];
        Check(incoming.RequestSharedAttempt(otherPeer,53,wireAttempt,7,11).status==DirectRequestStatus::InvalidRequest && incoming.Size()==1);
        Check(incoming.RequestSharedAttempt(*classic,53,otherAttempt,7,11).status==DirectRequestStatus::InvalidRequest);
        Check(incoming.RequestSharedAttempt(*native,53,wireAttempt,8,11).status==DirectRequestStatus::StaleTopology);
        Check(incoming.Snapshot(created.handle)->subscribers==2);
        incoming.Cancel(created.handle,DirectReason::Disabled);
        Check(incoming.RequestSharedAttempt(*native,53,wireAttempt,7,12).status==DirectRequestStatus::AwaitingRelease);
        DirectCoordinator adapter;
        Check(RequestNativeDirectShared(adapter,snapshot,8,61,wireAttempt,10).snapshot_status==NativeSnapshotStatus::InvalidGeneration && adapter.Size()==0);
        const auto shared=RequestNativeDirectShared(adapter,snapshot,7,61,wireAttempt,10);
        Check(shared.request.status==DirectRequestStatus::Created && adapter.Snapshot(shared.request.handle)->attempt_id==wireAttempt);
        Check(RequestNativeDirectShared(adapter,snapshot,7,62,otherAttempt,11).request.status==DirectRequestStatus::InvalidRequest);
        Check(adapter.Snapshot(shared.request.handle)->subscribers==1);
    }
    attempt[0]=3;
    admitted=RequestNativeDirect(coordinator,snapshot,7,42,1,4,attempt,10);
    Check(admitted.request.status==DirectRequestStatus::Created && coordinator.Size()==3);
    snapshot.local_generation=6;
    admitted=RequestNativeDirect(coordinator,snapshot,7,42,1,5,attempt,10);
    Check(admitted.snapshot_status==NativeSnapshotStatus::InvalidGeneration && coordinator.Size()==3);
    snapshot.peer.expected_node_pub=std::array<std::uint8_t,32>{};
    Check(!NativeDirectPeerKey(snapshot.peer,42,1)); // malformed supplied key cannot downgrade
    std::printf("native candidate snapshot: %u checks PASS (owned contract, not route/auth acceptance)\n",checks);
}
