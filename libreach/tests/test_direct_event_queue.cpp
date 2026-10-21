// SPDX-License-Identifier: MIT
#include "reach/direct_event_queue.h"
#include "reach/direct_coordinator.h"
#include <atomic>
#include <cstdio>
#include <thread>

using namespace reach;
static int checks=0,failures=0;
#define CHECK(x) do {++checks; if(!(x)){++failures; std::printf("FAIL line %d: %s\n",__LINE__,#x);}} while(0)
static DirectSessionEvent Event(std::uint64_t sequence,DirectEventType type=DirectEventType::Connected)
{
    return {{1,1},7,1,sequence,0,type,0};
}
int main()
{
    DirectEventQueue queue;
    CHECK(queue.Size()==0 && queue.Drain().empty());
    CHECK(!queue.HasHandle({1,1}));
    CHECK(queue.TryPush(Event(1))==DirectEnqueueStatus::Accepted);
    CHECK(queue.HasHandle({1,1}) && !queue.HasHandle({1,2}) && !queue.HasHandle({2,1}));
    CHECK(queue.Drain(0).empty() && queue.HasHandle({1,1}));
    CHECK(queue.Drain(1).size()==1 && !queue.HasHandle({1,1}));
    CHECK(queue.TryPush(Event(0))==DirectEnqueueStatus::Invalid);
    // Every local cause survives queue -> coordinator -> terminal unchanged.
    // In particular UnsupportedRemote is failure, not an implicit success.
    for(unsigned value=1;value<=static_cast<unsigned>(DirectReason::UnsupportedRemote);++value) {
        DirectCoordinator reasonCoordinator;
        DirectPeerKey reasonPeer; reasonPeer.source_record_id=value; reasonPeer.source_epoch=1;
        DirectAttemptId reasonId{}; reasonId[0]=static_cast<std::uint8_t>(value);
        const auto requested=reasonCoordinator.Request(reasonPeer,77,reasonId,7,0);
        DirectSessionRoute reasonRoute;
        reasonRoute.id=1; reasonRoute.transport=DirectQuic;
        reasonRoute.candidate.id=1; reasonRoute.candidate.transport_mask=DirectQuic;
        reasonRoute.candidate.topology_generation=7; reasonRoute.candidate.expires_monotonic_ms=10000;
        CHECK(reasonCoordinator.SetRoutes(requested.handle,{reasonRoute},0).actions.size()==1);
        auto closed=Event(1,DirectEventType::Closed); closed.handle=requested.handle;
        closed.reason=static_cast<DirectReason>(value);
        CHECK(queue.TryPush(closed)==DirectEnqueueStatus::Accepted);
        const auto terminal=reasonCoordinator.AdvanceAll(1,queue.Drain());
        CHECK(terminal.size()==1 && terminal[0].terminal_subscribers==std::vector<std::uint64_t>{77});
        CHECK(reasonCoordinator.Snapshot(requested.handle)->state==DirectSessionState::Failed &&
            reasonCoordinator.Snapshot(requested.handle)->reason==closed.reason);
        CHECK(terminal[0].actions.back().type==DirectActionType::Terminal &&
            terminal[0].actions.back().reason==closed.reason);
        CHECK(reasonCoordinator.Release(requested.handle));
    }
    auto invalidReason=Event(1,DirectEventType::Closed);
    invalidReason.reason=static_cast<DirectReason>(static_cast<unsigned>(DirectReason::UnsupportedRemote)+1);
    CHECK(queue.TryPush(invalidReason)==DirectEnqueueStatus::Invalid && queue.Size()==0);
    for(std::size_t i=1;i<=3840;++i)
        CHECK(queue.TryPush(Event(i))==DirectEnqueueStatus::Accepted);
    CHECK(queue.TryPush(Event(3841))==DirectEnqueueStatus::WouldBlock);
    for(std::size_t i=3841;i<=4096;++i)
        CHECK(queue.TryPush(Event(i,DirectEventType::Closed))==DirectEnqueueStatus::Accepted);
    CHECK(queue.Size()==4096);
    CHECK(queue.TryPush(Event(4097,DirectEventType::Closed))==DirectEnqueueStatus::WouldBlock);
    CHECK(queue.Drain(0).empty() && queue.Size()==4096);
    auto first=queue.Drain(100);
    CHECK(first.size()==100 && first.front().sequence==1 && first.back().sequence==100);
    CHECK(queue.TryPush(Event(4097))==DirectEnqueueStatus::WouldBlock);
    auto rest=queue.Drain();
    CHECK(rest.size()==3996 && rest.front().sequence==101 && rest.back().sequence==4096);
    CHECK(queue.Size()==0);
    CHECK(queue.TryPush(Event(4097))==DirectEnqueueStatus::Accepted);
    CHECK(queue.Drain().front().sequence==4097); // wrap keeps FIFO

    // Single worker vs main consumer: every accepted event appears once,
    // sequentially, including after backpressure and ring wrap.
    constexpr std::uint64_t total=50000;
    std::atomic<bool> done{false};
    std::atomic<bool> worker_failed{false};
    std::thread worker([&]{
        for(std::uint64_t i=1;i<=total;++i) {
            for(;;) {
                const auto status=queue.TryPush(Event(i));
                if(status==DirectEnqueueStatus::Accepted) break;
                if(status!=DirectEnqueueStatus::WouldBlock) { worker_failed=true; done=true; return; }
                std::this_thread::yield();
            }
        }
        done=true;
    });
    std::uint64_t expected=1;
    bool ordered=true;
    while(!done.load() || queue.Size()) {
        for(const auto& event:queue.Drain(127))
            if(event.sequence!=expected++) ordered=false;
        std::this_thread::yield();
    }
    worker.join();
    CHECK(!worker_failed && ordered && expected==total+1 && queue.Size()==0);

    DirectCoordinator coordinator;
    DirectPeerKey peer; peer.source_record_id=1; peer.source_epoch=1;
    DirectAttemptId id{}; id[0]=1;
    const auto request=coordinator.Request(peer,1,id,7,0);
    DirectSessionRoute route;
    route.id=1; route.transport=DirectTcp; route.candidate.id=1;
    route.candidate.transport_mask=DirectTcp; route.candidate.topology_generation=7;
    route.candidate.expires_monotonic_ms=10000;
    coordinator.SetRoutes(request.handle,{route},0);
    CHECK(coordinator.UsesOnlyTransport(request.handle,DirectTcp));
    CHECK(!coordinator.UsesOnlyTransport(request.handle,DirectQuic));
    auto connected=Event(1); connected.handle=request.handle;
    auto authenticated=connected; authenticated.sequence=2; authenticated.type=DirectEventType::Authenticated;
    queue.TryPush(connected); queue.TryPush(authenticated);
    auto batches=coordinator.AdvanceAll(10,queue.Drain());
    CHECK(batches.size()==1 && batches[0].actions.size()==1 &&
          batches[0].actions[0].type==DirectActionType::Attach);
    const auto stale=Event(3,DirectEventType::Closed);
    CHECK(coordinator.AdvanceAll(20,{stale}).empty() && coordinator.Snapshot(request.handle)->winner==1);
    // Empty worker queue still advances every pending attempt deadline.
    peer.source_record_id=2; id[0]=2;
    const auto pending=coordinator.Request(peer,2,id,7,20);
    batches=coordinator.AdvanceAll(15020);
    CHECK(batches.size()==1 && batches[0].handle.slot==pending.handle.slot &&
          batches[0].terminal_subscribers.size()==1);
    std::printf("test_direct_event_queue: %d checks, %d failures\n",checks,failures);
    return failures ? 1 : 0;
}
