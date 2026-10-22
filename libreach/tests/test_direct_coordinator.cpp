// SPDX-License-Identifier: MIT
#include "reach/direct_coordinator.h"
#include "reach/direct_subscribers.h"
#include <cstdio>

using namespace reach;
static int checks=0,failures=0;
#define CHECK(x) do {++checks; if(!(x)){++failures; std::printf("FAIL line %d: %s\n",__LINE__,#x);}} while(0)
static DirectPeerKey Peer(std::uint64_t n)
{
    DirectPeerKey key; key.source_record_id=n; key.source_epoch=1; return key;
}
static DirectAttemptId Id(std::uint64_t n)
{
    DirectAttemptId id{};
    for(std::size_t i=0;i<8;++i) id[i]=static_cast<std::uint8_t>(n>>(i*8));
    return id;
}
int main()
{
    DirectCoordinator c;
    auto r=c.Request(Peer(1),10,Id(1),7,0);
    CHECK(r.status==DirectRequestStatus::Created && c.Size()==1);
    CHECK(c.Snapshot(r.handle)->highest_route_id==0 && c.Snapshot(r.handle)->NextRouteId()==1);
    CHECK(c.Snapshot(r.handle)->NextRouteId(42)==42 && !c.Snapshot(r.handle)->NextRouteId(0));
    auto exhausted=*c.Snapshot(r.handle);
    exhausted.highest_route_id=(std::numeric_limits<std::uint32_t>::max)();
    CHECK(!exhausted.NextRouteId() && !exhausted.NextRouteId(exhausted.highest_route_id));
    exhausted.highest_route_id-=1;
    CHECK(exhausted.NextRouteId()==(std::numeric_limits<std::uint32_t>::max)());
    auto join=c.Request(Peer(1),11,Id(2),7,0);
    CHECK(join.status==DirectRequestStatus::Joined && join.handle.slot==r.handle.slot &&
        join.handle.generation==r.handle.generation && c.Size()==1);
    CHECK(c.Snapshot(r.handle)->attempt_id==Id(1) && c.Snapshot(r.handle)->subscribers==2);
    CHECK(c.ActiveHandles().size()==1 && c.ActiveHandles()[0].generation==r.handle.generation);
    c.Request(Peer(1),11,Id(2),7,0);
    CHECK(c.Snapshot(r.handle)->subscribers==2);
    CHECK(c.Request(Peer(1),12,Id(2),8,0).status==DirectRequestStatus::StaleTopology);
    for(std::uint64_t i=12;i<26;++i) c.Request(Peer(1),i,Id(2),7,0);
    CHECK(c.Snapshot(r.handle)->subscribers==16);
    CHECK(c.Request(Peer(1),26,Id(2),7,0).status==DirectRequestStatus::ResourceLimit);
    CHECK(!c.Release(r.handle));
    auto a=c.Cancel(r.handle,DirectReason::Disabled);
    CHECK(a.actions.size()==1 && a.terminal_subscribers.size()==16);
    CHECK(c.Cancel(r.handle,DirectReason::PeerGone).terminal_subscribers.empty());
    CHECK(c.Request(Peer(1),10,Id(1),7,0).status==DirectRequestStatus::AwaitingRelease);
    CHECK(c.Release(r.handle) && c.Size()==0 && !c.Snapshot(r.handle));
    CHECK(c.ActiveHandles().empty());
    auto next=c.Request(Peer(2),1,Id(2),7,0);
    CHECK(next.handle.slot==r.handle.slot && next.handle.generation==r.handle.generation+1);
    CHECK(c.Cancel(r.handle,DirectReason::Disabled).actions.empty());
    CHECK(c.Snapshot(next.handle)->state==DirectSessionState::Gathering);
    CHECK(c.Unsubscribe(next.handle,999).actions.empty());
    a=c.Unsubscribe(next.handle,1);
    CHECK(a.actions.size()==1 && a.terminal_subscribers.empty());
    CHECK(c.Release(next.handle));

    DirectPeerKey node; node.domain=DirectPeerDomain::NodePublicKey; node.identity[0]=1;
    DirectPeerKey hash=node; hash.domain=DirectPeerDomain::UserHash;
    auto nr=c.Request(node,1,Id(3),7,0);
    auto hr=c.Request(hash,1,Id(4),7,0);
    CHECK(nr.status==DirectRequestStatus::Created && hr.status==DirectRequestStatus::Created && c.Size()==2);
    CHECK(c.Request(Peer(3),1,Id(3),7,0).status==DirectRequestStatus::InvalidRequest);
    auto malformed=hash; malformed.identity[31]=1;
    CHECK(c.Request(malformed,1,Id(5),7,0).status==DirectRequestStatus::InvalidRequest);
    CHECK(c.Request(Peer(0),1,Id(5),7,0).status==DirectRequestStatus::InvalidRequest);
    CHECK(c.Request(Peer(3),0,Id(5),7,0).status==DirectRequestStatus::InvalidRequest);
    CHECK(c.Request(Peer(3),1,{},7,0).status==DirectRequestStatus::InvalidRequest);
    CHECK(c.Request(Peer(3),1,Id(5),0,0).status==DirectRequestStatus::InvalidRequest);
    CHECK(c.InvalidateTopology(7).empty());
    auto batches=c.InvalidateTopology(8);
    CHECK(batches.size()==2 && batches[0].terminal_subscribers.size()==1);
    CHECK(c.InvalidateTopology(9).empty());
    CHECK(c.Release(nr.handle) && c.Release(hr.handle));
    auto active=c.Request(Peer(42),42,Id(42),7,0);
    DirectSessionRoute route;
    route.id=1; route.transport=DirectTcp; route.candidate.id=1;
    route.candidate.transport_mask=DirectTcp; route.candidate.topology_generation=7;
    route.candidate.expires_monotonic_ms=10000;
    a=c.SetRoutes(active.handle,{route},0);
    CHECK(a.actions.size()==1 && a.actions[0].type==DirectActionType::Start);
    CHECK(c.Snapshot(active.handle)->highest_route_id==1 && c.Snapshot(active.handle)->NextRouteId()==2);
    CHECK(c.AuthorizesStart(active.handle,route,a.actions[0].session_epoch));
    CHECK(a.actions[0].session_epoch==0);
    CHECK(!c.AuthorizesStart(active.handle,route,1));
    auto changed=route; ++changed.candidate.port;
    CHECK(!c.AuthorizesStart(active.handle,changed,0));
    changed=route; changed.candidate.address[0]=1;
    CHECK(!c.AuthorizesStart(active.handle,changed,0));
    changed=route; ++changed.candidate.expires_monotonic_ms;
    CHECK(!c.AuthorizesStart(active.handle,changed,0));
    CHECK(!c.AuthorizesStart({active.handle.slot,active.handle.generation+1},route,0));
    DirectSessionEvent event{active.handle,7,1,1,0,DirectEventType::Connected,0};
    c.Advance(active.handle,10,{event});
    CHECK(!c.AuthorizesStart(active.handle,route,0));
    event.sequence=2; event.type=DirectEventType::Authenticated;
    a=c.Advance(active.handle,20,{event});
    CHECK(a.actions.size()==1 && a.actions[0].type==DirectActionType::Attach &&
          c.Snapshot(active.handle)->winner==1 && c.Snapshot(active.handle)->epoch==1);
    a=c.Cancel(active.handle,DirectReason::PeerGone);
    CHECK(a.actions.size()==2 && a.terminal_subscribers==std::vector<std::uint64_t>{42});
    CHECK(c.Release(active.handle));
    CHECK(!c.AuthorizesStart(active.handle,route,0));
    CHECK(c.SetRoutes(active.handle,{route},30).actions.empty());
    CHECK(c.Advance(active.handle,30,{event}).actions.empty());
    CHECK(!c.Release(active.handle));
    {
        DirectCoordinator receiver;
        DirectPeerKey peer; peer.domain=DirectPeerDomain::NodePublicKey; peer.identity.fill(7);
        const auto shared=receiver.RequestSharedAttempt(peer,71,Id(71),7,0);
        CHECK(shared.status==DirectRequestStatus::Created);
        auto first=route;
        CHECK(receiver.SetRoutes(shared.handle,{first},0).actions.size()==1);
        DirectSessionEvent connected{shared.handle,7,1,1,0,DirectEventType::Connected,0};
        receiver.Advance(shared.handle,10,{connected});
        auto authenticated=connected; authenticated.sequence=2; authenticated.type=DirectEventType::Authenticated;
        receiver.Advance(shared.handle,20,{authenticated});
        auto lost=authenticated; lost.sequence=3; lost.session_epoch=1; lost.type=DirectEventType::Closed;
        lost.reason=DirectReason::DirectUnreachable;
        receiver.Advance(shared.handle,30,{lost});
        const auto before=receiver.Snapshot(shared.handle);
        CHECK(before && before->state==DirectSessionState::Recovering && before->epoch==1 && before->highest_route_id==1);
        const auto joined=receiver.RequestSharedAttempt(peer,71,Id(71),7,31);
        CHECK(joined.status==DirectRequestStatus::Joined && joined.handle.slot==shared.handle.slot &&
            joined.handle.generation==shared.handle.generation && receiver.Size()==1);
        CHECK(receiver.RequestSharedAttempt(peer,72,Id(72),7,31).status==DirectRequestStatus::InvalidRequest);
        CHECK(receiver.Snapshot(shared.handle)->subscribers==1);
        CHECK(!receiver.AuthorizesStart(shared.handle,first,1)); // old ID cannot start twice
        auto fresh=first; fresh.id=before->NextRouteId(); fresh.candidate.id=fresh.id;
        const auto started=receiver.SetRoutes(shared.handle,{fresh},32);
        CHECK(started.actions.size()==1 && started.actions[0].type==DirectActionType::Start &&
            started.actions[0].route_id==2 && started.actions[0].session_epoch==1);
        CHECK(receiver.AuthorizesStart(shared.handle,fresh,1));
        CHECK(!receiver.AuthorizesStart(shared.handle,first,1));
        CHECK(receiver.Snapshot(shared.handle)->attempt_id==Id(71) && receiver.Snapshot(shared.handle)->epoch==1);
        receiver.Cancel(shared.handle,DirectReason::PeerGone);
        CHECK(receiver.Release(shared.handle));
    }
    std::vector<DirectHandle> handles;
    {
        DirectSubscribers subscribers;
        const DirectHandle original{1,1}, target{2,1};
        const auto older=subscribers.Acquire(10,DirectConsumerKind::Download);
        const auto established=subscribers.Acquire(20,DirectConsumerKind::Download);
        CHECK(subscribers.Bind(older,original) && subscribers.Bind(established,target));
        CHECK(!subscribers.RebindMerged(original,target,{older,older}));
        CHECK(!subscribers.RebindMerged(original,target,{older,999}));
        CHECK(subscribers.Resolve(older)->attempt->slot==original.slot);
        CHECK(subscribers.RebindMerged(original,target,{older}));
        CHECK(subscribers.HasTransferBinding(10,target) && subscribers.HasTransferBinding(20,target));
        CHECK(subscribers.TransferLifetime(target)==20); // stable adopted delivery owner
        CHECK(!subscribers.HasTransferBinding(10,original));
        CHECK(!subscribers.RebindMerged(original,target,{older}));
        subscribers.Remove(established);
        CHECK(subscribers.TransferLifetime(target)==10);
    }
    {
        DirectCoordinator identities;
        DirectPeerKey authenticated; authenticated.domain=DirectPeerDomain::UserHash;
        authenticated.identity[0]=42;
        auto known=identities.Request(authenticated,100,Id(100),7,0);
        auto provisional=identities.Request(Peer(200),200,Id(200),7,0);
        identities.SetRoutes(known.handle,{route},0);
        identities.SetRoutes(provisional.handle,{route},0);
        CHECK(identities.ResolveAuthenticatedPeer(provisional.handle,1,0,authenticated).status==DirectIdentityResolution::Rejected);
        DirectSessionEvent connected{known.handle,7,1,1,0,DirectEventType::Connected,0};
        identities.Advance(known.handle,1,{connected});
        auto proof=connected; proof.sequence=2; proof.type=DirectEventType::Authenticated;
        identities.Advance(known.handle,2,{proof});
        connected.handle=provisional.handle;
        identities.Advance(provisional.handle,1,{connected});
        CHECK(identities.ResolveAuthenticatedPeer(provisional.handle,1,1,authenticated).status==DirectIdentityResolution::Rejected);
        const auto merged=identities.ResolveAuthenticatedPeer(provisional.handle,1,0,authenticated);
        CHECK(merged.status==DirectIdentityResolution::Merged && merged.destination.slot==known.handle.slot);
        CHECK(merged.moved_subscribers.size()==1 && merged.moved_subscribers[0]==200 && merged.retired.terminal_subscribers.empty());
        CHECK(identities.Snapshot(known.handle)->subscribers==2 && identities.Snapshot(known.handle)->winner==1 && identities.Snapshot(known.handle)->epoch==1);
        CHECK(identities.Snapshot(provisional.handle)->state==DirectSessionState::Cancelled);
        proof.handle=provisional.handle;
        CHECK(identities.Advance(provisional.handle,3,{proof}).actions.empty());
        CHECK(identities.ResolveAuthenticatedPeer(provisional.handle,1,0,authenticated).status==DirectIdentityResolution::Rejected);
        CHECK(identities.Release(provisional.handle)); // caller still must drain adapters
        auto alone=identities.Request(Peer(201),201,Id(201),7,4);
        identities.SetRoutes(alone.handle,{route},4);
        connected.handle=alone.handle; identities.Advance(alone.handle,5,{connected});
        auto other=authenticated; other.identity[0]=43;
        CHECK(identities.ResolveAuthenticatedPeer(alone.handle,1,0,other).status==DirectIdentityResolution::Promoted);
        CHECK(identities.Snapshot(alone.handle)->peer.identity==other.identity);
        CHECK(identities.ResolveAuthenticatedPeer(alone.handle,1,0,other).status==DirectIdentityResolution::Unchanged);
        CHECK(identities.ResolveAuthenticatedPeer(alone.handle,1,0,authenticated).status==DirectIdentityResolution::Rejected);
        identities.Cancel(known.handle,DirectReason::Disabled); identities.Release(known.handle);
        identities.Cancel(alone.handle,DirectReason::Disabled); identities.Release(alone.handle);
        CHECK(identities.Size()==0);
        auto full=identities.Request(authenticated,1,Id(1),7,0);
        for(std::uint64_t i=2;i<=16;++i) CHECK(identities.Request(authenticated,i,Id(i),7,0).status==DirectRequestStatus::Joined);
        auto excess=identities.Request(Peer(300),300,Id(300),7,0);
        identities.SetRoutes(excess.handle,{route},0);
        connected.handle=excess.handle; identities.Advance(excess.handle,1,{connected});
        CHECK(identities.ResolveAuthenticatedPeer(excess.handle,1,0,authenticated).status==DirectIdentityResolution::ResourceLimit);
        CHECK(identities.Snapshot(full.handle)->subscribers==16 && identities.Snapshot(excess.handle)->subscribers==1 &&
            identities.Snapshot(excess.handle)->state==DirectSessionState::Authenticating);
        auto wrongTopology=authenticated; wrongTopology.identity[0]=44;
        identities.Request(wrongTopology,400,Id(400),8,0);
        CHECK(identities.ResolveAuthenticatedPeer(excess.handle,1,0,wrongTopology).status==DirectIdentityResolution::Rejected);
        CHECK(identities.ResolveAuthenticatedPeer(excess.handle,1,0,Peer(400)).status==DirectIdentityResolution::Rejected);
        auto malformedIdentity=authenticated; malformedIdentity.identity[31]=1;
        CHECK(identities.ResolveAuthenticatedPeer(excess.handle,1,0,malformedIdentity).status==DirectIdentityResolution::Rejected);
    }
    for(std::uint64_t i=1;i<=256;++i) {
        const auto created=c.Request(Peer(i),i,Id(i),7,0);
        CHECK(created.status==DirectRequestStatus::Created);
        handles.push_back(created.handle);
    }
    CHECK(c.Size()==256);
    CHECK(c.Request(Peer(257),257,Id(257),7,0).status==DirectRequestStatus::ResourceLimit);
    CHECK(c.Request(Peer(1),257,Id(257),7,0).status==DirectRequestStatus::Joined);
    a=c.Advance(handles[0],15000);
    CHECK(a.terminal_subscribers.size()==2 && c.Snapshot(handles[0])->reason==DirectReason::Deadline);
    CHECK(c.Advance(handles[0],16000).terminal_subscribers.empty());
    CHECK(c.Snapshot(handles[0])->reason_count==1 &&
        c.Snapshot(handles[0])->reason_chain[0].reason==DirectReason::Deadline);
    c.InvalidateTopology(8);
    for(const auto handle:handles) CHECK(c.Release(handle));
    CHECK(c.Size()==0);
    std::printf("test_direct_coordinator: %d checks, %d failures\n",checks,failures);
    return failures ? 1 : 0;
}
