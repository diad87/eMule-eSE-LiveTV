// SPDX-License-Identifier: MIT
#include "reach/direct_session.h"
#include <cstdio>
#include <limits>

using namespace reach;
static int checks = 0, failures = 0;
#define CHECK(x) do { ++checks; if (!(x)) { ++failures; std::printf("FAIL line %d: %s\n", __LINE__, #x); } } while (0)

static DirectSessionRoute Route(std::uint32_t id, DirectKind kind, std::uint8_t transport=DirectTcp)
{
    DirectSessionRoute r;
    r.id=id; r.transport=transport; r.candidate.id=id; r.candidate.kind=kind;
    r.candidate.family=kind==DirectKind::DirectV6 ? 6 : 4;
    r.candidate.transport_mask=transport; r.candidate.topology_generation=7;
    r.candidate.expires_monotonic_ms=100000;
    return r;
}
static DirectSessionEvent Event(std::uint32_t route, std::uint64_t seq, DirectEventType type,
                                std::uint64_t epoch=0, std::uint64_t bytes=0)
{
    return {{3,5},7,route,seq,epoch,type,bytes};
}
static std::size_t Count(const std::vector<DirectSessionAction>& actions, DirectActionType type)
{
    std::size_t count=0;
    for (const auto& a:actions) if(a.type==type) ++count;
    return count;
}

int main()
{
    const auto v6=Route(20,DirectKind::DirectV6);
    const auto v4=Route(10,DirectKind::DirectV4);
    const auto punch=Route(30,DirectKind::Punch2,DirectQuic);
    DirectSession s({3,5},7,0);
    CHECK(s.State()==DirectSessionState::Gathering);
    CHECK(s.HighestRouteId()==0);
    CHECK(s.Advance(100).empty() && s.State()==DirectSessionState::Gathering);
    auto a=s.SetRoutes({v6,v4,punch},250);
    CHECK(s.HighestRouteId()==30); // includes pending routes, not just the winner
    CHECK(a.size()==1 && a[0].type==DirectActionType::Start && a[0].route_id==20);
    CHECK(s.Advance(449).empty());
    a=s.Advance(450);
    CHECK(a.size()==1 && a[0].route_id==10);
    CHECK(s.FallbackCount()==0); // Happy Eyeballs overlap is not fallback
    CHECK(s.Advance(460).empty()); // no Punch while direct viable
    auto stale=Event(20,1,DirectEventType::Connected); stale.handle.generation=4;
    CHECK(s.Advance(470,{stale}).empty() && s.State()==DirectSessionState::Connecting);
    stale=Event(20,1,DirectEventType::Connected); stale.topology_generation=6;
    CHECK(s.Advance(480,{stale}).empty() && s.State()==DirectSessionState::Connecting);
    s.Advance(490,{Event(10,1,DirectEventType::Connected),Event(20,1,DirectEventType::Connected)});
    CHECK(s.State()==DirectSessionState::Authenticating && s.Winner()==0 && s.Epoch()==0);
    // Callback order and numeric route ID must not override plan priority.
    a=s.Advance(500,{Event(10,2,DirectEventType::Authenticated),Event(20,2,DirectEventType::Authenticated)});
    CHECK(s.State()==DirectSessionState::Ready && s.Winner()==20 && s.Epoch()==1);
    CHECK(Count(a,DirectActionType::Attach)==1 && Count(a,DirectActionType::Close)==1);
    CHECK(s.Advance(510,{Event(10,3,DirectEventType::Authenticated)}).empty());
    CHECK(s.Advance(520,{Event(20,3,DirectEventType::UsefulRange,0,100)}).empty());
    CHECK(s.UsefulBytes()==0 && !s.TransferVerified());
    s.Advance(530,{Event(20,3,DirectEventType::UsefulRange,1,100)});
    CHECK(s.State()==DirectSessionState::Transferring && s.UsefulBytes()==100 && !s.TransferVerified());
    s.Advance(540,{Event(20,3,DirectEventType::UsefulRange,1,100)});
    CHECK(s.UsefulBytes()==100); // exactly-once event accounting
    s.Advance(550,{Event(20,4,DirectEventType::VerifiedPart,1)});
    CHECK(s.TransferVerified() && s.State()==DirectSessionState::Transferring);
    CHECK(s.Advance(16000).empty() && s.Winner()==20); // established connection lives past connect budget
    a=s.Advance(16010,{Event(20,5,DirectEventType::Closed,1)});
    CHECK(s.State()==DirectSessionState::Recovering && s.Winner()==0 && s.UsefulBytes()==100);
    CHECK(s.HighestRouteId()==30);
    CHECK(Count(a,DirectActionType::Close)==1);
    const auto recovery=Route(40,DirectKind::DirectV4);
    a=s.SetRoutes({recovery},16020);
    CHECK(s.HighestRouteId()==40);
    CHECK(a.size()==1 && a[0].type==DirectActionType::Start);
    CHECK(s.FallbackCount()==1); // sequential recovery route
    s.Advance(16025,{Event(40,1,DirectEventType::Connected,0)});
    CHECK(s.State()==DirectSessionState::Connecting);
    s.Advance(16030,{Event(40,1,DirectEventType::Connected,1)});
    s.Advance(16040,{Event(40,2,DirectEventType::Authenticated,1)});
    CHECK(s.Epoch()==2 && s.Winner()==40 && s.TransferVerified());
    s.Advance(16050,{Event(40,3,DirectEventType::UsefulRange,1,999)});
    CHECK(s.UsefulBytes()==100);
    s.Advance(16060,{Event(40,3,DirectEventType::UsefulRange,2,25)});
    CHECK(s.UsefulBytes()==125);
    a=s.Cancel(DirectReason::PeerGone);
    CHECK(s.State()==DirectSessionState::Cancelled && s.Winner()==0);
    CHECK(Count(a,DirectActionType::Terminal)==1 && Count(a,DirectActionType::Close)==1);
    CHECK(s.Cancel(DirectReason::Disabled).empty() && s.Advance(17000).empty());

    DirectSession timeout({3,5},7,0);
    timeout.SetRoutes({v6,v4,punch},0);
    timeout.Advance(200);
    a=timeout.Advance(1700);
    CHECK(Count(a,DirectActionType::Close)==2 && Count(a,DirectActionType::Start)==1);
    CHECK(a.back().route_id==30);
    CHECK(timeout.FallbackCount()==1); // Punch after both direct routes fail
    timeout.Advance(1750,{Event(30,1,DirectEventType::Connected)});
    a=timeout.Advance(6750);
    CHECK(timeout.State()==DirectSessionState::Failed && timeout.Reason()==DirectReason::AuthTimeout);
    CHECK(Count(a,DirectActionType::Terminal)==1);

    DirectSession deadline({3,5},7,0);
    a=deadline.Advance(15000);
    CHECK(deadline.Reason()==DirectReason::Deadline && Count(a,DirectActionType::Terminal)==1);
    DirectSession empty({3,5},7,0);
    empty.SetRoutes({},250);
    CHECK(empty.Reason()==DirectReason::NoCandidate);
    DirectSession topology({3,5},7,0);
    topology.SetRoutes({v4},250);
    CHECK(topology.InvalidateTopology(7).empty());
    a=topology.InvalidateTopology(8);
    CHECK(topology.Reason()==DirectReason::StaleTopology && Count(a,DirectActionType::Close)==1);
    CHECK(topology.Advance(500,{Event(10,1,DirectEventType::Connected)}).empty());
    DirectSession auth({3,5},7,0);
    auth.SetRoutes({v4},0);
    auth.Advance(1,{Event(10,1,DirectEventType::Authenticated)});
    CHECK(auth.Winner()==0); // transport must connect before auth
    auth.Advance(2,{Event(10,2,DirectEventType::Connected)});
    auth.Advance(3,{Event(10,3,DirectEventType::AuthenticationFailed)});
    CHECK(auth.State()==DirectSessionState::Failed && auth.Winner()==0 &&
          auth.Reason()==DirectReason::IdentityMismatch);
    DirectSession typedAuth({3,5},7,0);
    typedAuth.SetRoutes({v4},0); typedAuth.Advance(1,{Event(10,1,DirectEventType::Connected)});
    auto timedAuth=Event(10,2,DirectEventType::AuthenticationFailed); timedAuth.reason=DirectReason::AuthTimeout;
    typedAuth.Advance(2,{timedAuth}); CHECK(typedAuth.Reason()==DirectReason::AuthTimeout);
    DirectSession typedClose({3,5},7,0); typedClose.SetRoutes({v4},0);
    auto resourceClose=Event(10,1,DirectEventType::Closed); resourceClose.reason=DirectReason::ResourceLimit;
    typedClose.Advance(1,{resourceClose}); CHECK(typedClose.Reason()==DirectReason::ResourceLimit);
    DirectSession backwards({3,5},7,100);
    for (const auto reason : {DirectReason::IdentityMismatch, DirectReason::PinChanged}) {
        DirectSession identityClose({3,5},7,0);
        identityClose.SetRoutes({v4},0);
        identityClose.Advance(1,{Event(10,1,DirectEventType::Connected)});
        identityClose.Advance(2,{Event(10,2,DirectEventType::Authenticated)});
        CHECK(identityClose.State()==DirectSessionState::Ready && identityClose.Epoch()==1);
        auto fatal=Event(10,3,DirectEventType::Closed,1); fatal.reason=reason;
        a=identityClose.Advance(3,{fatal});
        CHECK(identityClose.State()==DirectSessionState::Failed && identityClose.Winner()==0);
        CHECK(identityClose.Reason()==reason);
        CHECK(Count(a,DirectActionType::Close)==1 && Count(a,DirectActionType::Terminal)==1);
        CHECK(Count(a,DirectActionType::Start)==0 && a.back().reason==reason);
        CHECK(identityClose.Advance(16000,{fatal}).empty());
        CHECK(identityClose.SetRoutes({recovery},16001).empty());
        CHECK(identityClose.Cancel(DirectReason::PeerGone).empty() && identityClose.Reason()==reason);
    }
    CHECK(backwards.SetRoutes({v4},99).empty());
    CHECK(backwards.State()==DirectSessionState::Gathering);
    DirectSession invalid({3,0},7,0);
    CHECK(invalid.State()==DirectSessionState::Failed);
    DirectSession overflow({3,5},7,std::numeric_limits<std::uint64_t>::max()-100);
    overflow.Advance(std::numeric_limits<std::uint64_t>::max());
    CHECK(overflow.Reason()==DirectReason::Deadline);
    DirectSession cap({3,5},7,0);
    std::vector<DirectSessionRoute> many;
    for(std::uint32_t i=1;i<=9;++i) many.push_back(Route(i,DirectKind::DirectV4));
    cap.SetRoutes(many,0);
    CHECK(cap.Reason()==DirectReason::ResourceLimit);
    CHECK(cap.ReasonCount()==1 && cap.ReasonChain()[0].route_id==0 &&
        cap.ReasonChain()[0].reason==DirectReason::ResourceLimit);
    // History survives recovery, is bounded, and late/cancelled events cannot
    // rewrite it. Overflow retains the most recent sixteen typed causes.
    DirectSession history({3,5},7,0);
    for(std::uint32_t i=1;i<=20;++i) {
        auto current=Route(i,DirectKind::DirectV4);
        history.SetRoutes({current},i*10);
        history.Advance(i*10+1,{Event(i,1,DirectEventType::Connected,history.Epoch())});
        history.Advance(i*10+2,{Event(i,2,DirectEventType::Authenticated,history.Epoch())});
        auto closed=Event(i,3,DirectEventType::Closed,history.Epoch());
        closed.reason=DirectReason::UdpBlocked;
        history.Advance(i*10+3,{closed});
    }
    CHECK(history.ReasonCount()==16 && history.ReasonChain()[0].route_id==5 &&
        history.ReasonChain()[15].route_id==20);
    history.Cancel(DirectReason::Disabled);
    CHECK(history.ReasonCount()==16 && history.ReasonChain()[15].route_id==0 &&
        history.ReasonChain()[15].reason==DirectReason::Disabled);
    history.Cancel(DirectReason::PeerGone);
    history.Advance(500,{Event(20,4,DirectEventType::Closed,history.Epoch())});
    CHECK(history.ReasonChain()[15].reason==DirectReason::Disabled);
    std::printf("test_direct_session: %d checks, %d failures\n",checks,failures);
    return failures ? 1 : 0;
}
