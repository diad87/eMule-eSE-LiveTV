#include "../../srchybrid/EseQuicTransport.h"
#include "../../srchybrid/EseQuicDcoActions.h"
#include "../../srchybrid/EseQuicAttemptRetirement.h"
#include "../../srchybrid/EseEd2kFramer.h"
#include "../../srchybrid/EseQuicEd2kPump.h"
#include "../../srchybrid/EseQuicEd2kWriter.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <atomic>
#include <chrono>
#include <thread>
#include <memory>
using namespace ese;
using namespace reach;
static unsigned checks=0;
static void Check(bool b) { ++checks; if(!b) { std::printf("FAIL %u\n",checks); std::exit(1); } }
struct FakeCrypto final : binding::Crypto {
    bool Hash(const std::uint8_t* p,std::size_t n,std::array<std::uint8_t,32>& out) noexcept override {
        out.fill(0); for(std::size_t i=0;i<n;++i) out[i%32]=static_cast<std::uint8_t>(out[i%32]*33U+p[i]); return true;
    }
    bool Export(const std::array<std::uint8_t,32>& c,std::array<std::uint8_t,32>& out) noexcept override { out=c; return true; }
    bool Sign(const std::uint8_t* p,std::size_t n,std::array<std::uint8_t,64>& out) noexcept override {
        std::array<std::uint8_t,32> h{}; Hash(p,n,h); for(std::size_t i=0;i<64;++i) out[i]=h[i%32]; return true;
    }
    bool Verify(const std::array<std::uint8_t,32>&,const std::uint8_t* p,std::size_t n,const std::uint8_t* sig) noexcept override {
        std::array<std::uint8_t,64> out{}; Sign(p,n,out); return std::memcmp(sig,out.data(),64)==0;
    }
};
struct FakeRuntime final : QuicRuntime {
    FakeCrypto crypto; QuicIo* io=nullptr; std::uint64_t now=10;
    bool handshake=true,earlyBulk=false,inside=false; unsigned shutdown=0;
    std::uint64_t NowMs() const noexcept override { return now; }
    binding::Crypto& Crypto() noexcept override { return crypto; }
    bool Start(const DirectSessionRoute&,QuicIo& sink) override { io=&sink; return true; }
    void Poll(std::uint64_t value) override {
        now=value; inside=true;
        if(handshake) { handshake=false; Check(io->HandshakeComplete()); }
        if(earlyBulk) { const std::uint8_t b=1; Check(io->Received(4,{&b,1}).status==DirectIoStatus::Invalid); }
        inside=false;
    }
    void SetReadBudget(std::size_t) override {}
    void Shutdown() noexcept override { Check(!inside); ++shutdown; }
};
static QuicPeerConfig Config(bool server) {
    QuicPeerConfig c; c.local.role=server ? 1 : 0; c.local.node.fill(server ? 2 : 1);
    c.local.nonce.fill(server ? 5 : 4); c.local.attempt.fill(3); c.local.caps=1;
    c.local.topologyGeneration=7; c.expectedNode.fill(server ? 1 : 2);
    c.pin=c.expectedNode; c.hasPin=true; c.persistent=true; c.sessionEpoch=1; return c;
}
static DirectSessionRoute Route() {
    DirectSessionRoute route; route.id=3; route.transport=DirectQuic;
    route.candidate.family=4; route.candidate.port=4665; route.candidate.address[0]=203;
    route.candidate.transport_mask=DirectQuic; route.candidate.topology_generation=7;
    route.candidate.expires_monotonic_ms=100000; return route;
}
static void Move(QuicTransport& from,QuicTransport& to,std::int64_t stream) {
    const auto p=from.Pending(stream); Check(p.size>0); Check(from.Submitted(stream,p.size));
    const auto r=to.Received(stream,p); Check(r.status==DirectIoStatus::Accepted && r.accepted==p.size);
}
int main() {
    for(const auto result : {trust::CommitResult::Stored,trust::CommitResult::PersistenceFailed,trust::CommitResult::PinChanged}) {
        struct TrustPolicy final : trust::Committer {
            trust::CommitResult result; QuicTransport* transport=nullptr; unsigned calls=0;
            explicit TrustPolicy(trust::CommitResult value):result(value) {}
            trust::CommitResult Commit(const binding::Session& session,const std::array<std::uint8_t,32>& expected) noexcept override {
                ++calls; Check(session.Ready() && session.BoundPeer()->node==expected);
                Check(transport && !transport->Ready() && !transport->DataReady() && !transport->BoundPeer());
                const std::uint8_t byte=1;
                Check(transport->Send({&byte,1}).status==DirectIoStatus::WouldBlock);
                return result;
            }
        };
        DirectBufferPool pool;
        auto clientQueue=std::make_unique<DirectEventQueue>();
        auto serverQueue=std::make_unique<DirectEventQueue>();
        auto& clientEvents=*clientQueue; auto& serverEvents=*serverQueue;
        auto config=Config(false); config.hasPin=false; config.pin={};
        {
            QuicTransport forbidden(config,std::make_unique<FakeRuntime>(),pool,clientEvents);
            Check(!forbidden.Start({0,1},Route()));
        }
        config.allowFirstUse=true;
        {
            QuicTransport forbidden(config,std::make_unique<FakeRuntime>(),pool,clientEvents);
            Check(!forbidden.Start({0,1},Route()));
        }
        auto policy=std::make_shared<TrustPolicy>(result); config.trustCommitter=policy;
        QuicTransport client(config,std::make_unique<FakeRuntime>(),pool,clientEvents);
        policy->transport=&client;
        QuicTransport server(Config(true),std::make_unique<FakeRuntime>(),pool,serverEvents);
        Check(client.Start({0,1},Route()) && server.Start({1,1},Route()));
        client.Poll(10); server.Poll(10);
        Move(client,server,0); Move(server,client,0);
        Check(!client.Ready() && policy->calls==0);
        const auto pending=client.Pending(0);
        std::vector<std::uint8_t> owned(pending.data,pending.data+pending.size);
        Check(client.Submitted(0,owned.size()));
        Check(policy->calls==1 && client.Ready()==(result==trust::CommitResult::Stored));
        if(result==trust::CommitResult::Stored)
            Check(server.Received(0,{owned.data(),owned.size()}).accepted==owned.size());
        client.Poll(11); Check(policy->calls==1);
        const auto events=clientEvents.Drain(); unsigned authenticated=0,failed=0;
        for(const auto& event:events) {
            if(event.type==DirectEventType::Authenticated) ++authenticated;
            if(event.type==DirectEventType::AuthenticationFailed) {
                ++failed; Check(event.reason==(result==trust::CommitResult::PinChanged ? DirectReason::PinChanged : DirectReason::ResourceLimit));
            }
        }
        Check(authenticated==(result==trust::CommitResult::Stored ? 1u : 0u));
        Check(failed==(result==trust::CommitResult::Stored ? 0u : 1u));
        client.Close(DirectReason::Disabled); server.Close(DirectReason::Disabled);
        clientEvents.Drain(); serverEvents.Drain(); client.Poll(12); server.Poll(12);
        Check(client.Retirable() && server.Retirable() && pool.Used()==0);
    }
    {
        DirectBufferPool shutdownPool(32); QuicEd2kWriter mailbox(shutdownPool);
        std::atomic<bool> queued{false},sawClosed{false},failed{false};
        std::thread producer([&] {
            const std::uint8_t bytes[]={0xe3,3,0,0,0,0x11,7,8};
            const auto first=mailbox.Queue({bytes,sizeof(bytes)});
            if(first.accepted!=sizeof(bytes)) { failed=true; queued=true; return; }
            queued=true;
            for(;;) {
                const auto result=mailbox.Queue({bytes,sizeof(bytes)});
                if(result.status==DirectIoStatus::Closed) { sawClosed=true; return; }
                if(result.status!=DirectIoStatus::WouldBlock) { failed=true; return; }
                std::this_thread::yield();
            }
        });
        while(!queued) std::this_thread::yield();
        Check(!failed && mailbox.Remaining()==8 && shutdownPool.Used()==8);
        mailbox.Stop(); producer.join();
        Check(sawClosed && !failed && mailbox.Remaining()==0 && shutdownPool.Used()==0);
        mailbox.Stop(); Check(shutdownPool.Used()==0);
    }
    {
        std::vector<std::uint8_t> wire;
        for(unsigned i=0;i<100;++i) {
            const auto n=i%13;
            wire.push_back(i%3==0 ? 0xe3 : (i%3==1 ? 0xc5 : 0xd4));
            wire.insert(wire.end(),{static_cast<std::uint8_t>(n+1),0,0,0,static_cast<std::uint8_t>(i)});
            for(unsigned j=0;j<n;++j) wire.push_back(static_cast<std::uint8_t>(i+j));
        }
        for(const auto step : {std::size_t(1),std::size_t(7),wire.size()}) {
            DirectBufferPool framingPool; Ed2kFramer reader(framingPool);
            std::size_t offset=0; unsigned packets=0;
            while(offset<wire.size()) {
                std::size_t consumed=0;
                const auto status=reader.Feed({wire.data()+offset,(std::min)(step,wire.size()-offset)},consumed);
                Check(consumed>0 && status!=Ed2kFrameStatus::Invalid && status!=Ed2kFrameStatus::ResourceLimit);
                offset+=consumed;
                if(status==Ed2kFrameStatus::Frame) {
                    Check(reader.Header()[5]==packets && reader.Payload().size==packets%13);
                    for(std::size_t j=0;j<reader.Payload().size;++j)
                        Check(reader.Payload().data[j]==static_cast<std::uint8_t>(packets+j));
                    Check(framingPool.Used()==reader.Payload().size+1);
                    std::size_t repeated=9;
                    Check(reader.Feed({},repeated)==Ed2kFrameStatus::Frame && repeated==0);
                    Check(reader.Next() && framingPool.Used()==0); ++packets;
                }
            }
            Check(packets==100 && framingPool.Used()==0);
        }
        for(const auto header : {std::array<std::uint8_t,6>{0xe3,0,0,0,0,1},
            std::array<std::uint8_t,6>{0x40,1,0,0,0,1},
            std::array<std::uint8_t,6>{0xe3,0xff,0xff,0xff,0xff,1}}) {
            DirectBufferPool framingPool; Ed2kFramer reader(framingPool); std::size_t n=0;
            Check(reader.Feed({header.data(),header.size()},n)==Ed2kFrameStatus::Invalid && n==6 && framingPool.Used()==0);
            Check(reader.Feed({},n)==Ed2kFrameStatus::Invalid && !reader.Next());
        }
        DirectBufferPool tiny(1); Ed2kFramer limited(tiny); std::size_t n=0;
        const std::uint8_t header[]={0xe3,2,0,0,0,1};
        Check(limited.Feed({header,sizeof(header)},n)==Ed2kFrameStatus::ResourceLimit && tiny.Used()==0);
    }
    DirectBufferPool pool;
    auto queueStorage=std::make_unique<DirectEventQueue>(); auto& queue=*queueStorage;
    for(unsigned mode=0;mode<3;++mode) {
        DirectBufferPool gracefulPool;
        auto gracefulQueue=std::make_unique<DirectEventQueue>();
        QuicTransport sender(Config(false),std::make_unique<FakeRuntime>(),gracefulPool,*gracefulQueue);
        QuicTransport receiver(Config(true),std::make_unique<FakeRuntime>(),gracefulPool,*gracefulQueue);
        Check(sender.Start({0,1},Route()) && receiver.Start({0,1},Route()));
        Check(!sender.RequestClose(16));
        sender.Poll(10); receiver.Poll(10);
        Move(sender,receiver,0); Move(receiver,sender,0); Move(sender,receiver,0);
        gracefulQueue->Drain();
        Check(!sender.RequestClose(0) && sender.Ready());
        Check(sender.RequestClose(15) && sender.RequestClose(15) && !sender.RequestClose(16));
        const std::uint8_t byte=1;
        Check(!sender.Ready() && !sender.Retirable() && sender.Send({&byte,1}).status==DirectIoStatus::Closed);
        Check(sender.Received(4,{&byte,1}).status==DirectIoStatus::WouldBlock);
        const auto close=sender.Pending(0);
        const std::uint8_t golden[]={0,0,0,3,3,0,15};
        Check(close.size==7 && std::memcmp(close.data,golden,7)==0);
        Check(sender.Submitted(0,3) && sender.Pending(0).size==4);
        Check(sender.Acknowledged(0,0,188) && !sender.Retirable());
        if(mode==0) {
            Check(!sender.Acknowledged(0,189,1)); // ACK hole cannot imply delivery
            Check(sender.Submitted(0,4) && sender.Acknowledged(0,188,3) && !sender.Retirable());
            Check(sender.Acknowledged(0,191,1) && sender.Retirable());
        } else if(mode==1) {
            sender.Poll(1009); Check(!sender.Retirable());
            sender.Poll(1010); Check(sender.Retirable());
        } else {
            sender.Close(DirectReason::ResourceLimit); Check(sender.Retirable());
        }
        const auto events=gracefulQueue->Drain();
        Check(events.size()==1 && events[0].reason==(mode==2 ? DirectReason::ResourceLimit : DirectReason::Disabled));
        Check(gracefulPool.Used()==0 && !sender.RequestClose(15));
        receiver.Close(DirectReason::Disabled); gracefulQueue->Drain();
    }
    // Independent golden codebook: wire numbers are not DirectReason ordinals.
    const DirectReason closeReasons[]={DirectReason::UnsupportedRemote,
        DirectReason::NoCandidate,
        DirectReason::NoRoute,
        DirectReason::DirectUnreachable,
        DirectReason::PeerIncompatible,
        DirectReason::CapabilityMissing,
        DirectReason::Deadline,
        DirectReason::StaleTopology,
        DirectReason::IdentityMismatch,
        DirectReason::PinChanged,
        DirectReason::AuthTimeout,
        DirectReason::UdpBlocked,
        DirectReason::QuicNoProgress,
        DirectReason::MtuTooSmall,
        DirectReason::ResourceLimit,
        DirectReason::Disabled,
        DirectReason::PeerGone,
        DirectReason::BootstrapRequired,
        DirectReason::DiscoveryUnavailable,
        DirectReason::StaleDescriptor,
        DirectReason::RendezvousUnavailable,
        DirectReason::LegacyCallbackUnavailable,
    };
    for(const unsigned code : {0U,1U,2U,3U,4U,5U,6U,7U,8U,9U,10U,11U,
        12U,13U,14U,15U,16U,17U,18U,19U,20U,21U,22U,256U,65535U}) {
        DirectBufferPool reasonPool;
        auto reasonQueue=std::make_unique<DirectEventQueue>();
        auto& reasonEvents=*reasonQueue;
        QuicTransport sender(Config(false),std::make_unique<FakeRuntime>(),reasonPool,reasonEvents);
        QuicTransport receiver(Config(true),std::make_unique<FakeRuntime>(),reasonPool,reasonEvents);
        Check(sender.Start({4,9},Route()) && receiver.Start({4,9},Route()));
        sender.Poll(10); receiver.Poll(10);
        Move(sender,receiver,0); Move(receiver,sender,0); Move(sender,receiver,0);
        reasonEvents.Drain();
        const std::uint8_t close[]={0,0,0,3,3,static_cast<std::uint8_t>(code>>8),static_cast<std::uint8_t>(code)};
        Check(receiver.Received(0,{close,sizeof(close)}).accepted==sizeof(close));
        const auto events=reasonEvents.Drain();
        Check(events.size()==1 && events[0].reason==(code<22 ? closeReasons[code] : DirectReason::UnsupportedRemote));
        Check(events[0].handle.slot==4 && events[0].handle.generation==9 &&
            events[0].route_id==3 && events[0].session_epoch==1);
        Check(receiver.Retirable() && reasonPool.Used()==0);
        sender.Close(DirectReason::Disabled); reasonEvents.Drain();
    }
    // CLOSE must be atomic across every wire split and retire only after the
    // control callback unwinds. Malformed lengths must never be accepted.
    for(unsigned payloadSize : {0U,1U,2U,3U}) {
        for(std::size_t split=1;split<5+payloadSize;++split) {
            DirectBufferPool closePool;
            auto closeStorage=std::make_unique<DirectEventQueue>(); auto& closeEvents=*closeStorage;
            auto a=std::make_unique<FakeRuntime>(),b=std::make_unique<FakeRuntime>();
            auto* receiverRuntime=b.get();
            QuicTransport sender(Config(false),std::move(a),closePool,closeEvents);
            QuicTransport receiver(Config(true),std::move(b),closePool,closeEvents);
            Check(sender.Start({0,1},Route()) && receiver.Start({0,1},Route()));
            sender.Poll(10); receiver.Poll(10);
            Move(sender,receiver,0); Move(receiver,sender,0);
            Move(sender,receiver,0);
            Check(sender.Ready() && receiver.Ready());
            closeEvents.Drain();
            const std::uint8_t pending[]={9,8,7};
            Check(receiver.Received(4,{pending,sizeof(pending)}).accepted==sizeof(pending));
            std::vector<std::uint8_t> close{0,0,0,static_cast<std::uint8_t>(payloadSize+1),3};
            close.resize(5+payloadSize,0); if(payloadSize) close.back()=1;
            const auto first=receiver.Received(0,{close.data(),split});
            Check(first.status==DirectIoStatus::Accepted && first.accepted==split);
            Check(receiver.Ready() && closeEvents.Size()==0 && closePool.Used()==sizeof(pending));
            const auto last=receiver.Received(0,{close.data()+split,close.size()-split});
            Check(last.status==(payloadSize==2 ? DirectIoStatus::Accepted : DirectIoStatus::Invalid));
            Check(receiver.Retirable() && receiverRuntime->shutdown==1 && closePool.Used()==0);
            const auto events=closeEvents.Drain();
            Check(events.size()==(payloadSize==2 ? 1U : 2U) && events.back().type==DirectEventType::Closed);
            if(payloadSize!=2) Check(events.front().type==DirectEventType::AuthenticationFailed);
            Check(events.back().reason==(payloadSize==2 ? DirectReason::NoCandidate : DirectReason::IdentityMismatch));
            Check(receiver.Received(0,{close.data(),close.size()}).status==DirectIoStatus::Closed);
            receiver.Close(DirectReason::Disabled);
            Check(closeEvents.Size()==0 && receiverRuntime->shutdown==1);
            sender.Close(DirectReason::Disabled); closeEvents.Drain();
        }
    }
    {
        auto a=std::make_unique<FakeRuntime>(),b=std::make_unique<FakeRuntime>();
        auto ca=Config(false),cb=Config(true); ca.sessionEpoch=cb.sessionEpoch=0;
        auto coordinatorStorage=std::make_unique<DirectCoordinator>(); auto& coordinator=*coordinatorStorage;
        DirectPeerKey key;
        key.domain=DirectPeerDomain::NodePublicKey; key.identity=ca.expectedNode;
        const auto requested=coordinator.Request(key,42,ca.local.attempt,7,10);
        Check(requested.status==DirectRequestStatus::Created && requested.handle.slot==0);
        Check(coordinator.SetRoutes(requested.handle,{Route()},10).actions.size()==1);
        QuicRouteOwners owners;
        Check(owners.Reserve(requested.handle,3,0) && owners.Bind(requested.handle,3,42));
        QuicTransport client(ca,std::move(a),pool,queue),server(cb,std::move(b),pool,queue);
        Check(client.Start({0,1},Route()) && server.Start({1,1},Route()));
        Check(!client.AdoptWinner({0,1},3,1)); // before binding
        Check(!client.AllowsDelivery({0,1},3,0) && !client.BoundPeer());
        const std::uint8_t bytes[]={1,2,3,4,5,6,7,8};
        Check(client.Send({bytes,8}).status==DirectIoStatus::WouldBlock && pool.Used()==0);
        client.Poll(10); server.Poll(10);
        Move(client,server,0); Move(server,client,0); Move(client,server,0);
        Check(client.Ready() && server.Ready());
        const auto events=queue.Drain(); Check(events.size()==4);
        Check(events[0].type==DirectEventType::Connected && events[2].type==DirectEventType::Authenticated);
        Check(events[2].handle.generation==1 && events[2].route_id==3 && events[2].session_epoch==0 && events[2].sequence==2);
        Check(!client.AdoptWinner({0,2},3,1));
        Check(!client.AdoptWinner({0,1},4,1));
        Check(!client.AdoptWinner({0,1},3,0));
        Check(!client.AdoptWinner({0,1},3,2));
        auto batches=coordinator.AdvanceAll(10,events);
        Check(batches.size()==1 && batches[0].actions[0].type==DirectActionType::Attach);
        ApplyQuicDcoActions(coordinator,owners,batches,
            [&](std::uint64_t id)->QuicTransport* { return id==42 ? &client : nullptr; },
            [&](std::uint64_t id,DirectHandle handle) {
                const auto state=coordinator.Snapshot(handle);
                return id==42 && state && client.AdoptWinner(handle,state->winner,state->epoch) && owners.Adopt(id,state->epoch);
            });
        Check(coordinator.Snapshot(requested.handle)->state==DirectSessionState::Ready &&
            owners.Find(requested.handle,3)->epoch==1);
        Check(server.AdoptWinner({1,1},3,1));
        Check(client.AllowsDelivery({0,1},3,1) && client.BoundPeer());
        Check(!client.AllowsDelivery({0,1},3,0) && !client.AllowsDelivery({0,2},3,1) &&
            !client.AllowsDelivery({0,1},4,1));
        Check(!client.AdoptWinner({0,1},3,1) && !client.AdoptWinner({0,1},3,2));
        {
            QuicEd2kWriter writer(pool);
            const std::uint8_t wire[]={0xe3,3,0,0,0,0x11,7,8};
            Check(writer.Queue({wire,sizeof(wire)}).accepted==sizeof(wire) && pool.Used()==sizeof(wire));
            Check(writer.Queue({wire,sizeof(wire)}).status==DirectIoStatus::WouldBlock);
            Check(writer.Flush(client,{0,1},3,0,7).status==DirectIoStatus::Invalid && writer.Remaining()==sizeof(wire));
            Check(writer.Flush(client,{0,1},3,1,0).status==DirectIoStatus::WouldBlock);
            const auto pressure=kDirectGlobalBufferLimit-15; // writer owns 8; leave only 7 for facade
            Check(pool.ReserveExact(pressure));
            Check(writer.Flush(client,{0,1},3,1,64).accepted==7 && writer.Remaining()==1 && pool.Used()==kDirectGlobalBufferLimit);
            Check(writer.Flush(client,{0,1},3,1,64).status==DirectIoStatus::WouldBlock && writer.Remaining()==1);
            pool.Release(pressure);
            Check(pool.Used()==15);
            Check(writer.Flush(client,{0,1},3,1,7).accepted==1 && writer.Remaining()==0 && pool.Used()==8);
            std::size_t offset=0;
            while(client.Pending(4).size) {
                const auto chunk=client.Pending(4);
                Check(std::memcmp(chunk.data,wire+offset,chunk.size)==0);
                Check(client.Submitted(4,chunk.size) && client.Acknowledged(4,offset,chunk.size));
                offset+=chunk.size;
            }
            Check(offset==sizeof(wire) && pool.Used()==0);
        }
        {
            Ed2kFramer reader(pool); unsigned delivered=0;
            const std::uint8_t frames[]={0xe3,3,0,0,0,0x11,7,8,0xc5,1,0,0,0,0x22};
            Check(client.Received(4,{frames,sizeof(frames)}).accepted==sizeof(frames));
            auto deliver=[&](const Ed2kFramer& frame) {
                Check(frame.Header()[5]==(delivered ? 0x22 : 0x11));
                Check(frame.Payload().size==(delivered ? std::size_t{0} : std::size_t{2})); ++delivered; return true;
            };
            Check(!PumpQuicEd2k(client,reader,{0,1},3,0,deliver).valid && delivered==0);
            Check(client.Snapshot().rx_buffered==sizeof(frames));
            while(client.Snapshot().rx_buffered) {
                const auto pumped=PumpQuicEd2k(client,reader,{0,1},3,1,deliver,1,1);
                Check(pumped.valid && pumped.bytes==1 && pumped.frames<=1);
            }
            Check(delivered==2 && pool.Used()==0);
            Check(PumpQuicEd2k(client,reader,{0,1},3,1,deliver).frames==0 && delivered==2);
        }
        {
            QuicEd2kWriter mailbox(pool);
            std::atomic<bool> done{false},failed{false};
            std::thread producer([&] {
                if(mailbox.Flush(client,{0,1},3,1).status!=DirectIoStatus::Invalid) {
                    failed=true; done=true; return;
                }
                for(unsigned i=0;i<100;++i) {
                    std::uint8_t wire[]={0xe3,3,0,0,0,0x11,7,static_cast<std::uint8_t>(i)};
                    for(;;) {
                        const auto result=mailbox.Queue({wire,sizeof(wire)});
                        if(result.status==DirectIoStatus::Accepted) { wire[7]=255; break; }
                        if(result.status!=DirectIoStatus::WouldBlock) { failed=true; done=true; return; }
                        std::this_thread::yield();
                    }
                }
                done=true;
            });
            const auto base=client.Snapshot().acknowledged_offset;
            std::size_t offset=0;
            const auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(5);
            while(offset<800 && std::chrono::steady_clock::now()<deadline) {
                const auto flushed=mailbox.Flush(client,{0,1},3,1,7);
                Check(flushed.status==DirectIoStatus::Accepted || flushed.status==DirectIoStatus::WouldBlock);
                const auto chunk=client.Pending(4);
                const std::uint8_t golden[]={0xe3,3,0,0,0,0x11,7,0};
                for(std::size_t j=0;j<chunk.size;++j) {
                    const auto position=offset+j;
                    Check(position<800 && chunk.data[j]==(position%8==7 ? static_cast<std::uint8_t>(position/8) : golden[position%8]));
                }
                if(chunk.size) Check(client.Submitted(4,chunk.size) && client.Acknowledged(4,base+offset,chunk.size));
                offset+=chunk.size; std::this_thread::yield();
            }
            mailbox.Stop(); producer.join();
            Check(done && !failed && offset==800 && mailbox.Remaining()==0 && pool.Used()==0);
            const std::uint8_t byte=1;
            Check(mailbox.Queue({&byte,1}).status==DirectIoStatus::Closed);
            Check(mailbox.Flush(client,{0,1},3,1).status==DirectIoStatus::Closed);
            mailbox.Stop(); Check(pool.Used()==0);
        }
        const auto dataAckBase=client.Snapshot().acknowledged_offset;
        Check(client.Send({bytes,8}).accepted==8);
        const auto p=client.Pending(4); Check(p.size==8 && client.Submitted(4,4));
        Check(!client.Acknowledged(4,dataAckBase,5));
        Check(server.Received(4,{p.data,4}).accepted==4 && client.Acknowledged(4,dataAckBase,4));
        Check(pool.Used()==12 && client.Pending(4).data==p.data+4);
        Move(client,server,4); Check(client.Acknowledged(4,dataAckBase+4,4));
        Check(server.ConsumeReceived(8) && pool.Used()==0);
        Check(queue.Size()==0); // raw data/ACK never counts as useful eD2K progress
        Check(server.ReportUsefulBytes(2));
        const auto useful=queue.Drain();
        Check(useful.size()==1 && useful[0].type==DirectEventType::UsefulRange
            && useful[0].useful_bytes==2 && useful[0].session_epoch==1);
        DirectSessionEvent progressFiller; progressFiller.type=DirectEventType::Closed;
        progressFiller.handle={8,1}; progressFiller.topology_generation=7; progressFiller.route_id=9;
        for(std::size_t i=0;i<kDirectEventCapacity;++i) {
            progressFiller.sequence=i+1;
            Check(queue.TryPush(progressFiller)==DirectEnqueueStatus::Accepted);
        }
        Check(server.ReportUsefulBytes(1) && server.ReportUsefulBytes(2));
        Check(!server.ReportUsefulBytes(server.ConsumedData())); // already reported bytes cannot be counted again
        queue.Drain(); server.Poll(10);
        const auto coalesced=queue.Drain();
        Check(coalesced.size()==1 && coalesced[0].type==DirectEventType::UsefulRange
            && coalesced[0].useful_bytes==3 && coalesced[0].session_epoch==1);
        Check(server.ReportUsefulBytes(12,2)); // decompressed accepted bytes > compressed stream cost
        Check(!server.ReportUsefulBytes(1,0));
        Check(!server.ReportUsefulBytes((std::numeric_limits<std::uint64_t>::max)(),1));
        const auto logicalProgress=queue.Drain();
        Check(logicalProgress.size()==1 && logicalProgress[0].useful_bytes==12);
        Check(ClassifyPartVerification(false,false,false,false)==PartVerification::Unavailable);
        Check(ClassifyPartVerification(true,false,false,false)==PartVerification::Verified);
        Check(ClassifyPartVerification(false,false,true,false)==PartVerification::Verified);
        Check(ClassifyPartVerification(true,true,true,false)==PartVerification::Corrupt);
        Check(ClassifyPartVerification(true,false,true,true)==PartVerification::Corrupt);
        Check(!server.ReportVerifiedPart(PartVerification::Unavailable));
        Check(!server.ReportVerifiedPart(PartVerification::Corrupt));
        Check(server.ReportVerifiedPart(PartVerification::Verified));
        Check(!server.ReportVerifiedPart(PartVerification::Verified));
        const auto verified=queue.Drain();
        Check(verified.size()==1 && verified[0].type==DirectEventType::VerifiedPart && verified[0].session_epoch==1);
        std::vector<DirectCoordinatorBatch> stale{{requested.handle,
            {{DirectActionType::Close,3,0,DirectReason::PeerGone}}, {}}};
        ApplyQuicDcoActions(coordinator,owners,stale,
            [&](std::uint64_t)->QuicTransport* { return &client; },
            [](std::uint64_t,DirectHandle) { return false; });
        Check(!client.Snapshot().closed); // previous-epoch close is fenced
        auto cancelled=coordinator.Cancel(requested.handle,DirectReason::Disabled);
        std::vector<DirectCoordinatorBatch> closing{cancelled};
        ApplyQuicDcoActions(coordinator,owners,closing,
            [&](std::uint64_t)->QuicTransport* { return &client; },
            [](std::uint64_t,DirectHandle) { return false; });
        Check(closing[0].terminal_subscribers==std::vector<std::uint64_t>{42});
        client.Close(DirectReason::PeerGone);
        Check(client.Retirable() && queue.Size()==1);
        const auto closed=queue.Drain();
        Check(closed[0].reason==DirectReason::Disabled && closed[0].session_epoch==1);
        const std::uint8_t closeFrame[]={0,0,0,3,3,0,16};
        Check(server.Received(0,{closeFrame,sizeof(closeFrame)}).accepted==sizeof(closeFrame) && server.Retirable());
        Check(queue.Drain()[0].reason==DirectReason::PeerGone);
        Check(!ReleaseQuicAttempt(coordinator,owners,queue,requested.handle));
        owners.Erase(42);
        DirectSessionEvent retiring{requested.handle,7,3,99,1,DirectEventType::Closed,0,DirectReason::Disabled};
        Check(queue.TryPush(retiring)==DirectEnqueueStatus::Accepted);
        Check(!ReleaseQuicAttempt(coordinator,owners,queue,requested.handle));
        Check(queue.Drain().size()==1);
        Check(ReleaseQuicAttempt(coordinator,owners,queue,requested.handle) && !coordinator.Snapshot(requested.handle));
        const auto next=coordinator.Request(key,43,Config(false).local.attempt,7,20);
        Check(next.handle.slot==requested.handle.slot && next.handle.generation==requested.handle.generation+1);
        Check(!ReleaseQuicAttempt(coordinator,owners,queue,next.handle)); // active attempt
        auto tcp=Route(); tcp.transport=DirectTcp; tcp.candidate.transport_mask=DirectTcp;
        coordinator.SetRoutes(next.handle,{tcp},20);
        coordinator.Cancel(next.handle,DirectReason::Disabled);
        Check(!ReleaseQuicAttempt(coordinator,owners,queue,next.handle)); // other transport unaccounted
        Check(coordinator.Release(next.handle));
    }
    {
        auto coordinatorStorage=std::make_unique<DirectCoordinator>(); auto& coordinator=*coordinatorStorage;
        DirectPeerKey key;
        key.domain=DirectPeerDomain::NodePublicKey; key.identity.fill(2);
        const auto requested=coordinator.Request(key,77,Config(false).local.attempt,7,10);
        coordinator.SetRoutes(requested.handle,{Route()},10);
        DirectSessionEvent connected{requested.handle,7,3,1,0,DirectEventType::Connected,0};
        auto authenticated=connected; authenticated.sequence=2; authenticated.type=DirectEventType::Authenticated;
        auto batches=coordinator.AdvanceAll(10,{connected,authenticated});
        QuicRouteOwners owners; Check(owners.Reserve(requested.handle,3,0) && owners.Bind(requested.handle,3,99));
        auto config=Config(false); config.sessionEpoch=0;
        QuicTransport transport(config,std::make_unique<FakeRuntime>(),pool,queue);
        Check(transport.Start(requested.handle,Route()));
        unsigned adoptions=0;
        ApplyQuicDcoActions(coordinator,owners,batches,
            [&](std::uint64_t id)->QuicTransport* { return id==99 ? &transport : nullptr; },
            [&](std::uint64_t,DirectHandle) { ++adoptions; return false; });
        Check(adoptions==1 && coordinator.Snapshot(requested.handle)->state==DirectSessionState::Cancelled);
        Check(transport.Retirable() && batches.size()==2 && batches[1].terminal_subscribers==std::vector<std::uint64_t>{77});
        Check(batches[1].actions.back().type==DirectActionType::Terminal);
        const auto closed=queue.Drain(); Check(closed.size()==1 && closed[0].reason==DirectReason::DirectUnreachable);
    }
    for(unsigned fault=0;fault<4;++fault) {
        DirectBufferPool small(32);
        auto failureStorage=std::make_unique<DirectEventQueue>(); auto& failures=*failureStorage;
        auto ca=Config(false),cb=Config(true); ca.sessionEpoch=cb.sessionEpoch=0;
        QuicTransport receiver(ca,std::make_unique<FakeRuntime>(),small,failures),
            peer(cb,std::make_unique<FakeRuntime>(),small,failures);
        Check(receiver.Start({0,1},Route()) && peer.Start({1,1},Route()));
        receiver.Poll(10); peer.Poll(10);
        Move(receiver,peer,0); Move(peer,receiver,0); Move(receiver,peer,0);
        Check(receiver.AdoptWinner({0,1},3,1) && peer.AdoptWinner({1,1},3,1));
        failures.Drain();
        const std::uint8_t valid[]={0xe3,3,0,0,0,0x11,7,8};
        const std::uint8_t malformed[]={0x40,1,0,0,0,0x11};
        const std::uint8_t tooLargeForPool[]={0xe3,1,4,0,0,0x11};
        const DirectByteView input=fault==0 ? DirectByteView{malformed,sizeof(malformed)} :
            (fault==3 ? DirectByteView{tooLargeForPool,sizeof(tooLargeForPool)} : DirectByteView{valid,sizeof(valid)});
        Check(receiver.Received(4,input).accepted==input.size);
        Ed2kFramer reader(small); unsigned deliveries=0;
        auto reject=[&](const Ed2kFramer&) {
            ++deliveries;
            if(fault==2) throw std::runtime_error("consumer failure");
            return false;
        };
        const auto result=PumpQuicEd2k(receiver,reader,{0,1},3,1,reject);
        Check(!result.valid && result.frames==0 && !reader.Ready());
        Check(deliveries==(fault==1 || fault==2 ? 1u : 0u));
        Check(receiver.Snapshot().closed && receiver.Retirable() && small.Used()==0);
        const auto closed=failures.Drain();
        Check(closed.size()==1 && closed[0].session_epoch==1 && closed[0].reason==
            (fault>=2 ? DirectReason::ResourceLimit : DirectReason::DirectUnreachable));
        const auto count=deliveries;
        Check(!PumpQuicEd2k(receiver,reader,{0,1},3,1,reject).valid && deliveries==count && failures.Size()==0);
        peer.Close(DirectReason::Disabled); failures.Drain();
        Check(small.Used()==0);
    }
    queue.Drain(); Check(pool.Used()==0);
    {
        auto native=std::make_unique<FakeRuntime>(); auto* observe=native.get();
        native->earlyBulk=true;
        QuicTransport transport(Config(false),std::move(native),pool,queue);
        Check(transport.Start({2,1},Route())); transport.Poll(10);
        Check(transport.Snapshot().closed && observe->shutdown==1 && pool.Used()==0 && transport.Retirable());
        const auto events=queue.Drain(); Check(events.size()==2 && events.back().reason==DirectReason::IdentityMismatch);
    }
    {
        auto native=std::make_unique<FakeRuntime>(); native->handshake=false;
        QuicTransport transport(Config(false),std::move(native),pool,queue);
        Check(transport.Start({3,1},Route())); transport.Poll(4010);
        const auto events=queue.Drain(); Check(events.size()==1 && events[0].reason==DirectReason::Deadline);
    }
    {
        auto native=std::make_unique<FakeRuntime>();
        QuicTransport transport(Config(false),std::move(native),pool,queue);
        Check(transport.Start({4,1},Route())); transport.Poll(10); queue.Drain(); transport.Poll(5010);
        const auto events=queue.Drain();
        Check(events.size()==2 && events[0].type==DirectEventType::AuthenticationFailed && events[0].reason==DirectReason::AuthTimeout);
    }
    {
        DirectSessionEvent filler; filler.handle={8,1}; filler.route_id=9; filler.topology_generation=7;
        for(std::size_t i=0;i<kDirectEventCapacity-kDirectTerminalReserve;++i) {
            filler.sequence=i+1; Check(queue.TryPush(filler)==DirectEnqueueStatus::Accepted);
        }
        auto native=std::make_unique<FakeRuntime>();
        QuicTransport transport(Config(false),std::move(native),pool,queue);
        Check(transport.Start({5,1},Route())); transport.Poll(10); transport.Close(DirectReason::Disabled);
        Check(!transport.Retirable()); queue.Drain(); transport.Poll(11);
        Check(transport.Retirable()); const auto events=queue.Drain();
        Check(events.size()==2 && events[0].sequence==1 && events[1].sequence==2 && events[1].reason==DirectReason::Disabled);
        filler.reason=static_cast<DirectReason>(255); Check(queue.TryPush(filler)==DirectEnqueueStatus::Invalid);
    }
    std::printf("QuicTransport: %u checks PASS (runtime/crypto doubles, not native adapter acceptance)\n",checks);
}
