#include "../../srchybrid/EseQuicRouteOwners.h"
#include "../../srchybrid/EseDirectBatchConsumer.h"
#include <stdexcept>
#include <cstdio>
#include <cstdlib>
static unsigned checks=0;
static void Check(bool b) { ++checks; if(!b) { std::printf("FAIL %u\n",checks); std::exit(1); } }
int main() {
    {
        ese::DirectBatchPump tick;
        struct Consumer final : ese::DirectBatchConsumer {
            std::vector<reach::DirectCoordinatorBatch> received;
            unsigned polls=0;
            void Poll() noexcept override { ++polls; }
            void Accept(std::vector<reach::DirectCoordinatorBatch>&& batches) noexcept override { received=std::move(batches); }
        } consumer;
        unsigned pumps=0;
        auto empty=[&] { ++pumps; return std::vector<reach::DirectCoordinatorBatch>{}; };
        Check(!tick.Tick(nullptr,empty) && pumps==0);
        Check(tick.Tick(&consumer,empty) && pumps==1 && consumer.received.empty());
        Check(tick.Tick(&consumer,[&] {
            Check(tick.Busy() && !tick.Tick(&consumer,empty));
            return std::vector<reach::DirectCoordinatorBatch>{{{3,5},
                {{reach::DirectActionType::Start,7,0,reach::DirectReason::None},
                 {reach::DirectActionType::Terminal,0,1,reach::DirectReason::Disabled}}, {42,43}}};
        }));
        Check(!tick.Busy() && pumps==1 && consumer.received.size()==1);
        Check(consumer.received[0].handle.generation==5 && consumer.received[0].actions.size()==2 &&
            consumer.received[0].terminal_subscribers==std::vector<std::uint64_t>({42,43}));
        try { tick.Tick(&consumer,[]()->std::vector<reach::DirectCoordinatorBatch> { throw std::runtime_error("pump failure"); }); Check(false); }
        catch(const std::runtime_error&) { Check(!tick.Busy()); }
        Check(tick.Tick(&consumer,empty) && pumps==2);
        Check(consumer.polls==3);
    }
    ese::QuicRouteOwners owners; const reach::DirectHandle h{0,1};
    Check(!owners.Reserve({256,1},1,0)); Check(!owners.Reserve({0,0},1,0));
    Check(!owners.Reserve(h,0,0)); Check(owners.Reserve(h,1,0));
    Check(!owners.Reserve(h,1,1)); Check(owners.Find(h,1)->owner==0);
    Check(!owners.Bind(h,1,0)); Check(owners.Bind(h,1,42));
    owners.CancelReservation(h,1); Check(owners.Find(h,1)->owner==42);
    Check(owners.Reserve(h,2,0)); Check(!owners.Bind(h,2,42));
    Check(owners.HasHandle(h) && !owners.HasHandle({0,2}));
    owners.CancelReservation(h,2); Check(!owners.Find(h,2));
    Check(!owners.Find({0,2},1)); Check(!owners.Adopt(42,2));
    Check(owners.Adopt(42,1)); Check(!owners.Adopt(42,1));
    Check(owners.Find(h,1)->epoch==1); owners.Erase(0);
    Check(owners.Find(h,1)); owners.Erase(42); Check(!owners.Find(h,1));
    Check(!owners.HasHandle(h));
    for(unsigned i=0;i<256;++i) Check(owners.Reserve({i,1},1,0));
    Check(!owners.Reserve({0,2},2,0));
    owners.CancelReservation({0,1},1); Check(owners.Reserve({0,2},2,0));
    std::printf("QUIC route owners: %u checks PASS (bounded registry only)\n",checks);
}
