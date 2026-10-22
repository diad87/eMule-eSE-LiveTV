#include "../libnatmap/include/natmap/mapper_result_mailbox.h"
#include <cstdio>
#include <cstdlib>
#include <thread>
static unsigned checks=0;
static void Check(bool value) { ++checks; if(!value) std::exit(1); }
int main() {
    natmap::MapperResultMailbox mailbox;
    natmap::MapperOperation op; op.id=1; op.generation=7; op.started=100; op.deadline=200;
    op.mapper=natmap::MapperKind::Pcp; op.tcp=4662; op.udp=4672;
    Check(mailbox.Begin(op)); Check(!mailbox.Begin(op));
    natmap::MapperResult result; result.success=true; result.external_ipv4=123;
    result.external_tcp=50000; result.external_udp=50001;
    natmap::OwnedMapperResult out;
    Check(!mailbox.Take(1,7,101,out));
    bool published=false;
    std::thread worker([&] { published=mailbox.Publish(1,result); }); worker.join();
    Check(published); Check(!mailbox.Publish(1,result));
    result.external_tcp=1; op.tcp=1;
    Check(mailbox.Take(1,7,101,out)); Check(out.operation.tcp==4662 && out.result.external_tcp==50000);
    Check(!mailbox.Take(1,7,102,out)); Check(out.operation.id==0);
    op.tcp=4662;
    for(unsigned id=2;id<18;++id) { op.id=id; Check(mailbox.Begin(op)); Check(mailbox.Publish(id,result)); }
    op.id=18; Check(!mailbox.Begin(op));
    Check(!mailbox.Take(2,8,101,out)); Check(out.operation.id==0);
    Check(mailbox.Begin(op)); mailbox.Discard(18); Check(!mailbox.Publish(18,result));
    Check(!mailbox.Begin(op)); // cancelled id remains consumed
    Check(!mailbox.Take(3,7,200,out)); Check(out.operation.id==0);
    Check(!mailbox.Take(4,7,99,out)); Check(out.operation.id==0);
    mailbox.Expire(200);
    op.id=19; Check(mailbox.Begin(op)); Check(mailbox.Publish(19,result));
    Check(mailbox.Take(19,7,199,out));
    op.id=20; Check(mailbox.Begin(op)); mailbox.DiscardAll();
    Check(!mailbox.Publish(20,result)); Check(!mailbox.Begin(op));
    op.id=21; Check(mailbox.Begin(op)); Check(mailbox.Publish(21,result));
    Check(mailbox.Take(21,7,199,out));
    auto shared=std::make_shared<natmap::MapperResultMailbox>();
    op.id=1; Check(shared->Begin(op));
    natmap::MapperResultPublisher publisher(shared,1);
    Check(!publisher.Publish(result,[&](std::uint64_t id) { Check(id==1); return false; }));
    Check(!shared->Take(1,7,199,out)); Check(!shared->Publish(1,result));
    op.id=2; Check(shared->Begin(op));
    natmap::MapperResultPublisher retained(shared,2);
    std::weak_ptr<natmap::MapperResultMailbox> lifetime=shared;
    shared.reset(); Check(!lifetime.expired());
    Check(retained.Publish(result,[&](std::uint64_t id) { Check(id==2); return true; }));
    Check(lifetime.lock()->Take(2,7,199,out));
    Check(!retained.Publish(result,[](std::uint64_t) { return true; }));
    op.id=3; Check(lifetime.lock()->Begin(op));
    natmap::MapperResultPublisher throwing(lifetime.lock(),3);
    bool caught=false;
    try { throwing.Publish(result,[](std::uint64_t)->bool { throw 42; }); }
    catch(int code) { caught=code==42; }
    Check(caught); Check(!lifetime.lock()->Take(3,7,199,out));
    op.id=4; Check(lifetime.lock()->Begin(op));
    natmap::MapperResultPublisher oldWorker(lifetime.lock(),4);
    oldWorker.Cancel();
    op.id=5; Check(lifetime.lock()->Begin(op));
    natmap::MapperResultPublisher newWorker(lifetime.lock(),5);
    bool staleNotified=false;
    Check(!oldWorker.Publish(result,[&](std::uint64_t) { staleNotified=true; return true; }));
    Check(!staleNotified);
    Check(newWorker.Publish(result,[](std::uint64_t id) { return id==5; }));
    Check(lifetime.lock()->Take(5,7,199,out)); Check(out.operation.id==5);
    oldWorker.Cancel(); Check(!lifetime.lock()->Begin(op));
    auto setupQueue=std::make_shared<natmap::MapperResultMailbox>();
    op.id=1; Check(setupQueue->Begin(op));
    unsigned setupCalls=0;
    Check(!natmap::ArmMapperNotification(setupQueue,op.id,[&] { ++setupCalls; return false; }));
    Check(setupCalls==1); Check(!setupQueue->Publish(op.id,result)); Check(!setupQueue->Begin(op));
    op.id=2; Check(setupQueue->Begin(op));
    bool allocationCaught=false;
    try { natmap::ArmMapperNotification(setupQueue,op.id,[&]()->bool { ++setupCalls; throw std::bad_alloc(); }); }
    catch(const std::bad_alloc&) { allocationCaught=true; }
    Check(allocationCaught); Check(setupCalls==2); Check(!setupQueue->Publish(op.id,result));
    op.id=3; Check(setupQueue->Begin(op));
    Check(natmap::ArmMapperNotification(setupQueue,op.id,[&] { ++setupCalls; return true; }));
    Check(setupCalls==3); Check(setupQueue->Publish(op.id,result)); Check(setupQueue->Take(op.id,7,199,out));
    Check(!natmap::ArmMapperNotification(nullptr,4,[&] { ++setupCalls; return true; }));
    Check(!natmap::ArmMapperNotification(setupQueue,0,[&] { ++setupCalls; return true; }));
    Check(setupCalls==3);
    std::printf("mapper mailbox: %u checks PASS (owned transfer, not mapper runtime)\n",checks);
}
