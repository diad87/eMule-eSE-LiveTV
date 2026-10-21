#include "../../srchybrid/EseQuicUdpRouter.h"
#include <cstdio>
#include <cstdlib>
#include <chrono>
using namespace ese;
static unsigned checks=0;
static void Check(bool b) { ++checks; if(!b) { std::printf("FAIL %u\n",checks); std::exit(1); } }
struct Probe final : udp::Inspector {
    udp::Header header;
    udp::Match control=udp::Match::None;
    std::uint64_t controlOwner=99;
    udp::Match Control(const std::uint8_t*,std::size_t,const udp::Endpoint&,std::uint64_t& owner) const noexcept override { owner=control==udp::Match::Valid ? controlOwner : 0; return control; }
    udp::Match Utp(const std::uint8_t*,std::size_t,const udp::Endpoint&,std::uint64_t&) const noexcept override { return udp::Match::None; }
    bool QuicHeader(const std::uint8_t*,std::size_t,std::size_t,udp::Header& out) const noexcept override { out=header; return true; }
    bool AcceptInitial(const std::uint8_t*,std::size_t) const noexcept override { return true; }
};
struct Crypto final : binding::Crypto {
    bool Hash(const std::uint8_t*,std::size_t,std::array<std::uint8_t,32>&) noexcept override { return false; }
    bool Export(const std::array<std::uint8_t,32>&,std::array<std::uint8_t,32>&) noexcept override { return false; }
    bool Sign(const std::uint8_t*,std::size_t,std::array<std::uint8_t,64>&) noexcept override { return false; }
    bool Verify(const std::array<std::uint8_t,32>&,const std::uint8_t*,std::size_t,const std::uint8_t*) noexcept override { return false; }
};
struct Runtime final : QuicRuntime {
    ::Crypto crypto;
    std::uint64_t NowMs() const noexcept override { return 10; }
    binding::Crypto& Crypto() noexcept override { return crypto; }
    bool Start(const reach::DirectSessionRoute&,QuicIo&) override { return true; }
    void Poll(std::uint64_t) override {}
    void SetReadBudget(std::size_t) override {}
    void Shutdown() noexcept override {}
};
int main() {
    Probe probe; QuicUdpRouter router(probe); udp::Endpoint peer; peer.port=4665;
    udp::Cid cid; cid.size=8; cid.bytes.fill(1); probe.header.destination=cid;
    const std::uint8_t packet=0x40;
    probe.control=udp::Match::Valid; Check(router.Receive(peer,{&packet,1}));
    probe.control=udp::Match::Invalid; Check(router.Receive(peer,{&packet,1}));
    QuicUdpRouter::PendingControl pending;
    Check(router.PopControl(pending) && pending.size==1 && pending.bytes[0]==packet && pending.peer==peer && pending.owner==99);
    Check(!router.PopControl(pending) && !pending.size && !pending.owner);
    probe.control=udp::Match::Valid;
    std::uint8_t borrowed=7;
    Check(router.Receive(peer,{&borrowed,1})); borrowed=8;
    Check(router.PopControl(pending) && pending.bytes[0]==7);
    for(std::uint8_t i=0;i<8;++i) {
        probe.controlOwner=(i%2) ? 100 : 99;
        Check(router.Receive(peer,{&i,1}));
    }
    router.RemoveControl(99);
    for(std::uint8_t i=1;i<8;i+=2) Check(router.PopControl(pending) && pending.owner==100 && pending.bytes[0]==i);
    Check(!router.PopControl(pending)); probe.controlOwner=99;
    for(unsigned i=0;i<33;++i) Check(router.Receive(peer,{&packet,1}));
    for(unsigned i=0;i<32;++i) Check(router.PopControl(pending));
    Check(!router.PopControl(pending));
    Check(router.Receive(peer,{&packet,1})); router.SocketReset();
    Check(!router.PopControl(pending));
    probe.control=udp::Match::None;
    Check(!router.Receive(peer,{&packet,1}));
    Check(!router.Reserve(0) && router.Reserve(1) && !router.Reserve(1));
    Check(!router.RegisterCid(2,cid) && router.RegisterCid(1,cid));
    Check(router.Receive(peer,{&packet,1})); // reserved owner, no session yet: claimed
    Check(!router.RemoveCid(2,cid) && router.RemoveCid(1,cid));
    Check(!router.Receive(peer,{&packet,1}));
    std::unique_ptr<QuicTransport> empty;
    Check(!router.Adopt(1,empty));
    Check(router.Release(1) && !router.Release(1) && !router.Reserve(1));
    for(std::uint64_t id=2;id<258;++id) Check(router.Reserve(id));
    Check(!router.Reserve(258));
    router.SocketReset();
    for(std::uint64_t id=2;id<258;++id) Check(router.Release(id));
    Check(router.Reserve(258) && router.Release(258));
    {
        reach::DirectBufferPool pool; reach::DirectEventQueue events;
        QuicPeerConfig config; config.local.node.fill(1); config.local.attempt.fill(2);
        config.local.nonce.fill(3); config.local.caps=1; config.local.topologyGeneration=7;
        config.expectedNode.fill(4); config.pin=config.expectedNode;
        config.hasPin=true; config.persistent=true; config.sessionEpoch=1;
        auto transport=std::make_unique<QuicTransport>(config,std::make_unique<Runtime>(),pool,events);
        reach::DirectSessionRoute route; route.id=3; route.transport=reach::DirectQuic;
        route.candidate.family=4; route.candidate.port=4665; route.candidate.address[0]=127;
        route.candidate.transport_mask=reach::DirectQuic; route.candidate.topology_generation=7;
        route.candidate.expires_monotonic_ms=10000;
        Check(transport->Start({0,1},route));
        Check(router.Reserve(259) && router.Adopt(259,transport) && !transport);
        Check(router.Find(259) && !router.Release(259));
        reach::DirectSessionEvent filler; filler.type=reach::DirectEventType::Closed;
        filler.handle={8,1}; filler.route_id=9; filler.topology_generation=7;
        for(std::size_t i=0;i<reach::kDirectEventCapacity;++i) {
            filler.sequence=i+1;
            Check(events.TryPush(filler)==reach::DirectEnqueueStatus::Accepted);
        }
        router.SocketReset(); Check(!router.Release(259));
        events.Drain(); router.Poll(static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count()));
        Check(router.Release(259) && !router.Find(259) && pool.Used()==0);
        const auto terminal=events.Drain();
        Check(terminal.size()==1 && terminal[0].handle.slot==0 && terminal[0].reason==reach::DirectReason::Disabled);
    }
    std::printf("QUIC UDP router: %u checks PASS (registry + retained terminal event, runtime double)\n",checks);
}
