#include "EseQuicHostFactory.h"
#ifdef ESE_NATIVE_QUIC_LAB_AVAILABLE
#include "EseQuicSocketOwner.h"
#include "EseQuicHeaderProbe.h"
#include "EseControlEnvelope.h"
#include "EseControlPacketBudget.h"
#include "EseControlServiceRoutes.h"
#include <chrono>
namespace ese {
namespace {
std::uint64_t ControlNow() noexcept {
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count());
}
class Probe final : public udp::Inspector {
public:
    control::PendingRoutes routes;
    control::ServiceRoutes service;
    udp::Match Control(const std::uint8_t* bytes,std::size_t size,const udp::Endpoint& peer,std::uint64_t& owner) const noexcept override {
        const auto now=ControlNow();
        const auto pending=routes.Inspect(bytes,size,peer,now,owner);
        // Exact owned replies/bootstrap windows retain precedence. The
        // service classifier grants no signature, session or data authority.
        if(pending==udp::Match::Valid) return pending;
        return service.Inspect(bytes,size,peer,now,owner);
    }
    udp::Match Utp(const std::uint8_t*,std::size_t,const udp::Endpoint&,std::uint64_t&) const noexcept override { return udp::Match::None; }
    bool QuicHeader(const std::uint8_t* p,std::size_t n,std::size_t cid,udp::Header& h) const noexcept override { return udp::DecodeQuicHeader(p,n,cid,h); }
    bool AcceptInitial(const std::uint8_t* p,std::size_t n) const noexcept override { return udp::AcceptQuicInitial(p,n); }
};
class Host final : public QuicSessionHost {
    Probe probe_; // Must outlive owner.
    QuicSocketOwner owner_;
    control::PacketBudget& controlBudget_;
    std::uint64_t serviceOwner_=0;
public:
    Host(QuicSocketPort& port,reach::DirectBufferPool& pool,reach::DirectEventQueue& queue,control::PacketBudget& budget)
        : owner_(port,probe_,pool,queue),controlBudget_(budget) {}
    bool Attach() { return owner_.Attach(); }
    bool ActivateControlService(const std::array<std::uint8_t,32>& local,std::uint64_t owner,std::uint64_t generation) override {
        if(!owner_.Attached() || !probe_.service.Activate(local,owner,generation)) return false;
        serviceOwner_=owner; return true;
    }
    bool RegisterControlServiceSession(const std::array<std::uint8_t,32>& peer,const udp::Endpoint& endpoint,
        const control::Header& context,std::uint64_t now,std::uint64_t until) override {
        return owner_.Attached() && probe_.service.RegisterVerified(peer,endpoint,context,now,until);
    }
    bool ResolveControlServicePeer(const udp::Endpoint& endpoint,const control::Header& context,std::uint64_t now,
        std::array<std::uint8_t,32>& peer) const override {
        peer={}; return owner_.Attached() && probe_.service.Resolve(endpoint,context,now,peer);
    }
    void RetireControlService(std::uint64_t owner) override {
        if(!owner || owner!=serviceOwner_) return;
        probe_.service.Reset(); serviceOwner_=0; owner_.RemoveControl(owner);
    }
    bool ExpectControlBootstrap(const std::array<std::uint8_t,32>& local,
        const std::array<std::uint8_t,32>& expected,const udp::Endpoint& peer,
        std::uint64_t owner,std::uint64_t until) override {
        return owner_.Attached() && probe_.routes.AddBootstrap(local,expected,peer,owner,ControlNow(),until);
    }
    void Stop() override { probe_.routes.Reset(); probe_.service.Reset(); serviceOwner_=0; owner_.Stop(); }
    void Poll(std::uint64_t now) override { probe_.routes.Advance(now); owner_.Poll(now); }
    bool ExpectControlReply(const control::Header& request,std::uint8_t reply,const udp::Endpoint& peer,
        std::uint64_t owner,std::uint64_t until) override {
        return owner_.Attached() && probe_.routes.Add(request,reply,peer,owner,ControlNow(),until);
    }
    void RemoveControlReplies(std::uint64_t owner) override { probe_.routes.Remove(owner); owner_.RemoveControl(owner); }
    bool PopControlReply(QuicUdpRouter::PendingControl& out) override {
        out={}; return owner_.Attached() && owner_.PopControl(out);
    }
    QuicUdpSendResult SendControl(const udp::Endpoint& peer,reach::DirectByteView bytes) override {
        control::Envelope envelope;
        if(!owner_.Attached()) return {QuicUdpSendStatus::Closed,0};
        if(!control::ParseUntrusted(bytes.data,bytes.size,envelope)) return {QuicUdpSendStatus::Invalid,0};
        if(!controlBudget_.Allow(ControlNow())) return {QuicUdpSendStatus::WouldBlock,0};
        return owner_.SendControl(peer,bytes);
    }
    std::size_t RetireClosed() override { return owner_.RetireClosed(); }
    bool Empty() const noexcept override { return owner_.Empty(); }
    std::uint64_t Begin(NativeQuicConfig native,QuicPeerConfig peer,reach::DirectHandle handle,
        const reach::DirectSessionRoute& route) override { return owner_.Begin(native,peer,handle,route); }
    QuicTransport* Find(std::uint64_t id) const override { return owner_.Find(id); }
    bool Release(std::uint64_t id) override { return owner_.Release(id); }
};
}
std::unique_ptr<QuicSessionHost> CreateQuicSessionHost(QuicSocketPort& port,
    reach::DirectBufferPool& pool,reach::DirectEventQueue& queue,control::PacketBudget& budget) {
    auto host=std::make_unique<Host>(port,pool,queue,budget);
    if(!host->Attach()) return nullptr;
    return host;
}
}
#else
namespace ese {
std::unique_ptr<QuicSessionHost> CreateQuicSessionHost(QuicSocketPort&,
    reach::DirectBufferPool&,reach::DirectEventQueue&,control::PacketBudget&) { return nullptr; }
}
#endif
