#include "reach/direct_subscribers.h"
#include "reach/direct_client_lifetime.h"
#include <algorithm>
#include <thread>
#include <cstdio>
#include <cstdlib>
#include <memory>
static unsigned checks=0;
static void Check(bool condition) { ++checks; if(!condition) std::exit(1); }
int main() {
    using namespace reach;
    auto registry=std::make_unique<DirectSubscribers>();
    Check(!registry->Acquire(0,DirectConsumerKind::Download));
    Check(!registry->Acquire(1,static_cast<DirectConsumerKind>(255)));
    const auto first=registry->Acquire(1,DirectConsumerKind::Download);
    Check(first!=0 && registry->Acquire(1,DirectConsumerKind::Download)==first);
    const auto upload=registry->Acquire(1,DirectConsumerKind::Upload);
    Check(upload!=0 && upload!=first);
    Check(!registry->Bind(first,{0,0}));
    Check(registry->Bind(first,{3,7}));
    Check(registry->Bind(first,{3,7}));
    Check(registry->HasTransferBinding(1,{3,7}));
    Check(registry->TransferLifetime({3,7})==1);
    Check(!registry->TransferLifetime({3,8}) && !registry->TransferLifetime({256,7}));
    Check(!registry->HasTransferBinding(0,{3,7}) && !registry->HasTransferBinding(2,{3,7}));
    Check(!registry->HasTransferBinding(1,{3,8}) && !registry->HasTransferBinding(1,{4,7}));
    Check(!registry->HasTransferBinding(1,{3,0}) && !registry->HasTransferBinding(1,{256,7}));
    Check(!registry->Bind(first,{3,8}));
    Check(!registry->Bind(first,{4,7}));
    Check(registry->Complete(first,DirectReason::Deadline));
    Check(!registry->HasTransferBinding(1,{3,7}));
    Check(!registry->TransferLifetime({3,7}));
    Check(registry->Bind(upload,{3,7}) && registry->HasTransferBinding(1,{3,7}));
    Check(registry->Remove(upload).has_value() && !registry->HasTransferBinding(1,{3,7}));
    const auto uploadReplacement=registry->Acquire(1,DirectConsumerKind::Upload);
    Check(uploadReplacement>upload && !registry->HasTransferBinding(1,{3,7}));
    const auto discovery=registry->Acquire(9,DirectConsumerKind::Discovery);
    Check(registry->Bind(discovery,{3,7}) && !registry->HasTransferBinding(9,{3,7}));
    Check(registry->Remove(discovery).has_value());
    {
        auto selection=std::make_unique<DirectSubscribers>();
        const auto later=selection->Acquire(90,DirectConsumerKind::Download);
        const auto earlier=selection->Acquire(20,DirectConsumerKind::Upload);
        Check(selection->Bind(later,{1,4}) && selection->Bind(earlier,{1,4}));
        Check(selection->TransferLifetime({1,4})==20);
        Check(selection->Complete(earlier,DirectReason::PeerGone) && selection->TransferLifetime({1,4})==90);
        Check(selection->Remove(later).has_value() && !selection->TransferLifetime({1,4}));
    }
    Check(!registry->Complete(first,DirectReason::PeerGone));
    Check(registry->TakeTerminal(first)==DirectReason::Deadline);
    Check(!registry->TakeTerminal(first));
    Check(!registry->Complete(first,DirectReason::PeerGone));
    const auto copy=registry->Resolve(first);
    const auto retired=registry->Remove(first);
    Check(retired && retired->attempt->generation==7);
    Check(!registry->Resolve(first) && !registry->Remove(first));
    const auto replacement=registry->Acquire(2,DirectConsumerKind::Download);
    Check(replacement>upload && !registry->Bind(first,{3,7}));
    Check(!registry->Complete(first,DirectReason::Deadline) && !registry->TakeTerminal(first));
    Check(!registry->Complete(replacement,DirectReason::Deadline));
    Check(copy && copy->client_lifetime==1 && copy->attempt->slot==3);
    for(std::size_t i=2;i<DirectSubscribers::Capacity;++i)
        Check(registry->Acquire(i+10,DirectConsumerKind::Discovery)!=0);
    Check(!registry->Acquire(99999,DirectConsumerKind::ClientList));
    Check(registry->Acquire(1,DirectConsumerKind::Upload)==uploadReplacement); // join even when full
    Check(registry->Remove(uploadReplacement).has_value());
    Check(registry->Acquire(99999,DirectConsumerKind::ClientList)>replacement);
    Check(!registry->Resolve(0) && !registry->Remove(0));
    Check(registry->Size()==DirectSubscribers::Capacity);
    const auto byLifetime=registry->FindLifetime(2);
    Check(byLifetime && byLifetime->token==replacement);
    Check(!registry->FindLifetime(0) && !registry->FindLifetime(999999));
    DirectClientLifetimeSequence sequence;
    std::array<std::uint64_t,4000> lifetimes{};
    std::array<std::thread,4> workers;
    for(std::size_t worker=0;worker<workers.size();++worker)
        workers[worker]=std::thread([&,worker] {
            for(std::size_t i=0;i<1000;++i) lifetimes[worker*1000+i]=sequence.Next();
        });
    for(auto& worker:workers) worker.join();
    std::sort(lifetimes.begin(),lifetimes.end());
    for(std::size_t i=0;i<lifetimes.size();++i) Check(lifetimes[i]==i+1);
    const auto processFirst=NextDirectClientLifetime();
    Check(processFirst!=0 && NextDirectClientLifetime()==processFirst+1);
    const auto fileFirst=NextDirectFileLifetime();
    Check(fileFirst!=0 && NextDirectFileLifetime()==fileFirst+1);
    Check(NextDirectClientLifetime()==processFirst+2); // file sequence is independent
    std::printf("direct subscribers: %u checks PASS\n",checks);
}
