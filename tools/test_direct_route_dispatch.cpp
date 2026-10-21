#include "reach/direct_route_dispatch.h"
#include "../srchybrid/EseDirectAttemptRetirement.h"
#include <cstdio>
#include <memory>
using namespace reach;
int main() {
    unsigned checks=0,failures=0;
    auto check=[&](bool value) { ++checks; if(!value) { ++failures; std::printf("FAIL check %u\n",checks); } };
    DirectRouteDispatch dispatch;
    const DirectHandle handle{3,5};
    check(dispatch.Register(handle,1,DirectTcp));
    check(dispatch.Register(handle,2,DirectUtp));
    check(dispatch.Register(handle,3,DirectQuic));
    check(dispatch.Register(handle,1,DirectTcp));
    check(!dispatch.Register(handle,1,DirectQuic));
    check(!dispatch.Register({3,6},4,DirectTcp));
    check(!dispatch.Register({256,1},1,DirectTcp));
    check(!dispatch.Register(handle,4,DirectTcp|DirectQuic));
    check(!dispatch.Register({3,0},4,DirectTcp));
    DirectCoordinatorBatch batch{handle,{{DirectActionType::Start,1,0,DirectReason::None},
        {DirectActionType::Start,3,0,DirectReason::None},{DirectActionType::Attach,3,1,DirectReason::None},
        {DirectActionType::Close,1,1,DirectReason::None},{DirectActionType::Close,2,1,DirectReason::None},
        {DirectActionType::Terminal,0,1,DirectReason::PeerGone}},{11,12}};
    const auto split=dispatch.Split(batch);
    check(split.has_value());
    if(split) {
        check(split->transports[0].actions.size()==3);
        check(split->transports[1].actions.size()==2);
        check(split->transports[2].actions.size()==3);
        check(split->transports[2].actions[1].type==DirectActionType::Attach && split->transports[2].actions[1].session_epoch==1);
        check(split->terminal_subscribers==batch.terminal_subscribers);
        check(split->order.size()==8);
        bool ordered=true;
        for(std::size_t i=0;i<5;++i) {
            const auto step=split->order[i];
            const auto& action=split->transports[step.transport].actions[step.action];
            ordered=ordered && action.type==batch.actions[i].type && action.route_id==batch.actions[i].route_id;
        }
        check(ordered);
        for(const auto& output:split->transports) check(output.terminal_subscribers.empty() && output.actions.back().reason==DirectReason::PeerGone);
    }
    auto malformed=batch; malformed.handle.generation=4; check(!dispatch.Split(malformed));
    malformed=batch; malformed.actions[0].route_id=99; check(!dispatch.Split(malformed));
    malformed=batch; malformed.actions.push_back(batch.actions.back()); check(!dispatch.Split(malformed));
    malformed=batch; malformed.actions.pop_back(); check(!dispatch.Split(malformed));
    malformed=batch; malformed.actions={batch.actions.back()}; malformed.handle.generation=4;
    check(!dispatch.Split(malformed)); // stale terminal must not notify subscribers
    malformed=batch; malformed.actions={batch.actions.back(),batch.actions.front()};
    check(!dispatch.Split(malformed));
    malformed=batch; malformed.actions.back().route_id=1; check(!dispatch.Split(malformed));
    DirectCoordinatorBatch gathering{{4,1},{{DirectActionType::Terminal,0,0,DirectReason::PeerGone}},{13}};
    const auto empty=dispatch.Split(gathering);
    check(empty && empty->terminal_subscribers==gathering.terminal_subscribers);
    if(empty) for(const auto& output:empty->transports) check(output.actions.empty());
    malformed=gathering; malformed.terminal_subscribers={13,13}; check(!dispatch.Split(malformed));
    malformed=gathering; malformed.terminal_subscribers={0}; check(!dispatch.Split(malformed));
    malformed=gathering; malformed.terminal_subscribers.resize(kDirectMaxSubscribers+1,13);
    check(!dispatch.Split(malformed));
    for(unsigned i=4;i<=8;++i) check(dispatch.Register(handle,i,DirectTcp));
    check(!dispatch.Register(handle,9,DirectTcp));
    check(!dispatch.DrainedTerminal(handle));
    check(!dispatch.MarkTerminal({3,4}));
    check(dispatch.MarkTerminal(handle));
    check(!dispatch.MarkTerminal(handle));
    check(!dispatch.Split(batch));
    check(!dispatch.Register(handle,1,DirectTcp));
    check(!dispatch.MarkDrained({3,4},1,DirectTcp));
    check(!dispatch.MarkDrained(handle,1,DirectQuic));
    check(dispatch.MarkDrained(handle,1,DirectTcp));
    check(dispatch.MarkDrained(handle,2,DirectUtp));
    check(!dispatch.DrainedTerminal(handle));
    check(dispatch.MarkDrained(handle,3,DirectQuic));
    for(unsigned i=4;i<=8;++i) check(dispatch.MarkDrained(handle,i,DirectTcp));
    check(dispatch.DrainedTerminal(handle));
    check(!dispatch.DrainedTerminal({3,4}));
    check(dispatch.MarkTerminal(gathering.handle));
    check(dispatch.DrainedTerminal(gathering.handle));
    dispatch.EraseReleased({3,4}); check(!dispatch.Register({3,6},1,DirectTcp));
    dispatch.EraseReleased(handle); check(dispatch.Register({3,6},1,DirectQuic));
    check(!dispatch.Split(batch));
    DirectRouteDispatch capacity;
    bool full=true;
    for(std::uint32_t slot=0;slot<kDirectMaxAttempts;++slot)
        for(std::uint32_t route=1;route<=kDirectMaxRoutes;++route)
            full=capacity.Register({slot,1},route,DirectTcp) && full;
    check(full);
    check(!capacity.Register({0,1},9,DirectTcp));
    capacity.EraseReleased({0,1});
    check(capacity.Register({0,2},1,DirectUtp));
    gathering.handle={1,1};
    const auto occupied=capacity.Split(gathering);
    check(occupied && occupied->transports[0].actions.size()==1 && occupied->transports[1].actions.empty());
    {
        DirectCoordinator coordinator; DirectRouteDispatch retirement; DirectEventQueue events;
        DirectPeerKey peer; peer.source_record_id=1; peer.source_epoch=1;
        DirectAttemptId attempt{}; attempt[0]=1;
        const auto request=coordinator.Request(peer,1,attempt,7,0);
        check(request.status==DirectRequestStatus::Created);
        DirectSessionRoute tcp; tcp.id=1; tcp.transport=DirectTcp;
        tcp.candidate.id=1; tcp.candidate.family=4; tcp.candidate.transport_mask=DirectTcp;
        tcp.candidate.topology_generation=7; tcp.candidate.expires_monotonic_ms=100000;
        auto quic=tcp; quic.id=2; quic.transport=DirectQuic;
        quic.candidate.id=2; quic.candidate.transport_mask=DirectQuic;
        coordinator.SetRoutes(request.handle,{tcp,quic},0);
        check(retirement.Register(request.handle,1,DirectTcp));
        check(!ese::ReleaseDirectAttempt(coordinator,retirement,events,request.handle));
        const auto terminal=coordinator.Cancel(request.handle,DirectReason::Disabled);
        check(!terminal.actions.empty());
        check(retirement.MarkTerminal(request.handle));
        check(retirement.MarkDrained(request.handle,1,DirectTcp));
        check(!ese::ReleaseDirectAttempt(coordinator,retirement,events,request.handle)); // unregistered QUIC
        // Register is deliberately closed after terminal: a missing owner is
        // a host setup error, never infer its drain from absence in registry.
        check(coordinator.Snapshot(request.handle).has_value());
        retirement.EraseReleased(request.handle); // isolated fixture repair, not production retirement
        check(retirement.Register(request.handle,1,DirectTcp));
        check(retirement.Register(request.handle,2,DirectQuic));
        check(retirement.MarkTerminal(request.handle));
        check(retirement.MarkDrained(request.handle,1,DirectTcp));
        check(!ese::ReleaseDirectAttempt(coordinator,retirement,events,request.handle));
        check(retirement.MarkDrained(request.handle,2,DirectQuic));
        DirectSessionEvent event{request.handle,7,2,1,0,DirectEventType::Closed,0,DirectReason::Disabled};
        check(events.TryPush(event)==DirectEnqueueStatus::Accepted);
        check(!ese::ReleaseDirectAttempt(coordinator,retirement,events,request.handle));
        check(events.Drain().size()==1);
        check(ese::ReleaseDirectAttempt(coordinator,retirement,events,request.handle));
        check(!coordinator.Snapshot(request.handle));
        check(!retirement.DrainedTerminal(request.handle));
        check(!ese::ReleaseDirectAttempt(coordinator,retirement,events,request.handle));
        const auto next=coordinator.Request(peer,2,attempt,7,1);
        check(next.handle.slot==request.handle.slot && next.handle.generation!=request.handle.generation);
        check(!ese::ReleaseDirectAttempt(coordinator,retirement,events,next.handle));
    }
    for(const auto fallbackTransport : {DirectTcp,DirectUtp}) {
        auto recoveryStorage=std::make_unique<DirectCoordinator>();
        auto ownerStorage=std::make_unique<DirectRouteDispatch>();
        auto& recovery=*recoveryStorage; auto& owners=*ownerStorage;
        DirectPeerKey peer; peer.source_record_id=71; peer.source_epoch=1;
        DirectAttemptId attempt{}; attempt[0]=41;
        const auto request=recovery.Request(peer,101,attempt,7,0);
        check(request.status==DirectRequestStatus::Created);
        check(recovery.Request(peer,102,attempt,7,0).status==DirectRequestStatus::Joined);
        DirectSessionRoute first; first.id=1; first.transport=DirectQuic;
        first.candidate.id=1; first.candidate.family=4; first.candidate.kind=DirectKind::DirectV4;
        first.candidate.transport_mask=DirectQuic; first.candidate.topology_generation=7;
        first.candidate.expires_monotonic_ms=100000;
        check(owners.Register(request.handle,1,DirectQuic));
        auto recoveryBatch=recovery.SetRoutes(request.handle,{first},0);
        check(owners.Split(recoveryBatch).has_value());
        auto event=[&](std::uint32_t route,std::uint64_t sequence,std::uint64_t epoch,
                      DirectEventType type,std::uint64_t bytes=0) {
            return DirectSessionEvent{request.handle,7,route,sequence,epoch,type,bytes};
        };
        recovery.Advance(request.handle,1,{event(1,1,0,DirectEventType::Connected)});
        recoveryBatch=recovery.Advance(request.handle,2,{event(1,2,0,DirectEventType::Authenticated)});
        check(owners.Split(recoveryBatch).has_value());
        recovery.Advance(request.handle,3,{event(1,3,1,DirectEventType::UsefulRange,4096)});
        recoveryBatch=recovery.Advance(request.handle,4,{event(1,4,1,DirectEventType::Closed)});
        const auto oldClose=owners.Split(recoveryBatch);
        check(oldClose && oldClose->transports[2].actions.size()==1 &&
              oldClose->transports[2].actions[0].type==DirectActionType::Close);
        check(recovery.Snapshot(request.handle)->state==DirectSessionState::Recovering);
        auto next=first; next.id=2; next.candidate.id=2;
        next.transport=static_cast<std::uint8_t>(fallbackTransport); next.candidate.transport_mask=next.transport;
        check(owners.Register(request.handle,2,next.transport));
        recoveryBatch=recovery.SetRoutes(request.handle,{next},5);
        const auto start=owners.Split(recoveryBatch);
        const unsigned lane=fallbackTransport==DirectTcp?0:1;
        check(start && start->transports[lane].actions.size()==1 &&
              start->transports[lane].actions[0].type==DirectActionType::Start &&
              start->transports[lane].actions[0].session_epoch==1);
        recovery.Advance(request.handle,6,{event(2,1,1,DirectEventType::Connected)});
        recoveryBatch=recovery.Advance(request.handle,7,{event(2,2,1,DirectEventType::Authenticated)});
        const auto attach=owners.Split(recoveryBatch);
        check(attach && attach->transports[lane].actions.size()==1 &&
              attach->transports[lane].actions[0].type==DirectActionType::Attach &&
              attach->transports[lane].actions[0].session_epoch==2);
        recovery.Advance(request.handle,8,{event(1,5,1,DirectEventType::UsefulRange,999),
            event(2,3,1,DirectEventType::UsefulRange,999)});
        auto state=recovery.Snapshot(request.handle);
        check(state && state->epoch==2 && state->useful_bytes==4096 && state->subscribers==2 &&
              state->attempt_id==attempt && state->winner==2 && !state->transfer_verified);
        recovery.Advance(request.handle,9,{event(2,3,2,DirectEventType::UsefulRange,1)});
        recovery.Advance(request.handle,10,{event(2,3,2,DirectEventType::UsefulRange,1)});
        state=recovery.Snapshot(request.handle);
        check(state && state->useful_bytes==4097 && !state->transfer_verified);
        recovery.Advance(request.handle,11,{event(2,4,2,DirectEventType::VerifiedPart)});
        check(recovery.Snapshot(request.handle)->transfer_verified);
    }
    std::printf("direct route dispatch: %u checks, %u failures\n",checks,failures);
    return failures ? 1 : 0;
}
