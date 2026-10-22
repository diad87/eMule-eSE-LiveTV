#include "EseQuicSocketOwner.h"
#include <limits>
#include <stdexcept>
#include "EseControlEnvelope.h"
namespace ese {
QuicSocketOwner::QuicSocketOwner(QuicSocketPort& port,const udp::Inspector& probe,
    reach::DirectBufferPool& pool,reach::DirectEventQueue& events)
    : port_(port),pool_(pool),events_(events),router_(probe) {}
QuicSocketOwner::~QuicSocketOwner() { if(attached_) Detach(); }
bool QuicSocketOwner::Attach() {
    if(attached_ || !port_.AttachQuicIngress(this)) return false;
    attached_=true; return true;
}
QuicUdpSendResult QuicSocketOwner::SendControl(const udp::Endpoint& peer,reach::DirectByteView bytes) {
    control::Envelope envelope;
    if(!attached_) return {QuicUdpSendStatus::Closed,0};
    if(!control::ParseUntrusted(bytes.data,bytes.size,envelope)) return {QuicUdpSendStatus::Invalid,0};
    // Serialization check only. Owner of the request must enforce session,
    // signature, correlation and retry budget before calling this method.
    return port_.SendQuicDatagram(this,peer,bytes.data,bytes.size);
}
bool QuicSocketOwner::Detach() {
    if(!attached_) return false;
    return port_.DetachQuicIngress(this); // socket removes registration, then calls SocketReset
}
void QuicSocketOwner::SocketReset() noexcept {
    attached_=false; router_.SocketReset();
}
std::uint64_t QuicSocketOwner::Begin(NativeQuicConfig native,QuicPeerConfig peer,
    reach::DirectHandle handle,const reach::DirectSessionRoute& route,QuicIdentitySigner* signer) {
    if(!attached_ || nextId_==std::numeric_limits<std::uint64_t>::max()) return 0;
    std::unique_ptr<Sink>* slot=nullptr;
    for(auto& entry:sinks_) if(!entry) { slot=&entry; break; }
    if(!slot) return 0;
    const auto id=++nextId_;
    if(!router_.Reserve(id)) return 0;
    std::unique_ptr<QuicTransport> transport;
    try {
        *slot=std::make_unique<Sink>(*this,id);
        auto runtime=CreateNativeQuicRuntime(native,**slot,(*slot)->rxPool,signer);
        const auto now=runtime->NowMs();
        if(native.server) {
            udp::Endpoint remote; remote.address=route.candidate.address; remote.port=route.candidate.port;
            remote.ipv6=route.candidate.family==6;
            remote.scope=remote.ipv6 && route.candidate.scope==reach::DirectScope::SameLan ? native.local.scope : 0;
            if(!router_.ExpectInitial(id,remote,now+4000)) {
                runtime->Shutdown(); runtime.reset();
                router_.Release(id); slot->reset(); return 0;
            }
        }
        transport=std::make_unique<QuicTransport>(peer,std::move(runtime),(*slot)->txPool,(*slot)->rxPool,events_);
        const bool started=transport->Start(handle,route);
        if(!started) transport->Close(reach::DirectReason::DirectUnreachable);
        if(!router_.Adopt(id,transport)) throw std::runtime_error("QUIC owner adoption failed");
        if(!started && Release(id)) return 0;
        return id; // closed but non-retirable failures remain visible until event drain
    } catch(...) {
        if(transport) {
            transport->Close(reach::DirectReason::ResourceLimit);
            if(!transport->Retirable() && router_.Adopt(id,transport)) return id;
        }
        router_.Release(id); slot->reset(); return 0;
    }
}
bool QuicSocketOwner::Release(std::uint64_t id) {
    // A retained framer/Packet reservation also borrows this sink's RX pool.
    // Do not destroy the pool merely because native callbacks have drained.
    for(const auto& entry:sinks_) if(entry && entry->id==id &&
        (entry->rxPool.Used() || entry->txPool.Used())) return false;
    if(!router_.Release(id)) return false;
    for(auto& entry:sinks_) if(entry && entry->id==id) { entry.reset(); break; }
    return true;
}
std::size_t QuicSocketOwner::RetireClosed() {
    std::size_t retired=0;
    for(auto& entry:sinks_) {
        if(!entry) continue;
        const auto id=entry->id;
        const auto* transport=router_.Find(id);
        if(transport && transport->Retirable() && Release(id)) ++retired;
    }
    return retired;
}
bool QuicSocketOwner::Empty() const noexcept {
    for(const auto& entry:sinks_) if(entry) return false;
    return true;
}
void QuicSocketOwner::Poll(std::uint64_t now) {
    router_.Poll(now);
    for(auto& entry:sinks_) if(entry && entry->failure!=reach::DirectReason::None) {
        if(auto* transport=router_.Find(entry->id)) transport->Close(entry->failure);
    }
}
bool QuicSocketOwner::Sink::Send(const udp::Endpoint& peer,reach::DirectByteView bytes) noexcept {
    if(failure!=reach::DirectReason::None || !parent.attached_) return false;
    try {
        const auto result=parent.port_.SendQuicDatagram(&parent,peer,bytes.data,bytes.size);
        if(result.status==QuicUdpSendStatus::Sent) return true;
        if(result.status!=QuicUdpSendStatus::WouldBlock) failure=reach::DirectReason::DirectUnreachable;
    } catch(...) { failure=reach::DirectReason::ResourceLimit; }
    return false;
}
bool QuicSocketOwner::Sink::RegisterCid(const udp::Cid& cid) noexcept { return parent.router_.RegisterCid(id,cid); }
bool QuicSocketOwner::Sink::RemoveCid(const udp::Cid& cid) noexcept { return parent.router_.RemoveCid(id,cid); }
void QuicSocketOwner::Sink::RemoveCids() noexcept { parent.router_.RemoveCids(id); }
}
