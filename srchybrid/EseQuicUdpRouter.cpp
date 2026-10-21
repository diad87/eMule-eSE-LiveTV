#include "EseQuicUdpRouter.h"
#include <cassert>
#include <chrono>
#include <exception>
namespace ese {
QuicUdpRouter::~QuicUdpRouter() {
    // Pending terminal events must not be discarded by owner teardown.
    for(const auto& entry:entries_) if(entry.owner) {
        assert(false && "release all QUIC owners before router destruction");
        std::terminate();
    }
}
QuicUdpRouter::Entry* QuicUdpRouter::Slot(std::uint64_t owner) {
    if(!owner) return nullptr;
    for(auto& entry:entries_) if(entry.owner==owner) return &entry;
    return nullptr;
}
bool QuicUdpRouter::Reserve(std::uint64_t owner) {
    if(!owner || owner<=lastOwner_) return false;
    for(auto& entry:entries_) if(!entry.owner) {
        entry.owner=owner; lastOwner_=owner; return true;
    }
    return false;
}
bool QuicUdpRouter::Adopt(std::uint64_t owner,std::unique_ptr<QuicTransport>& transport) {
    auto* entry=Slot(owner);
    if(!entry || entry->transport || !transport) return false;
    entry->transport=std::move(transport); return true;
}
bool QuicUdpRouter::Release(std::uint64_t owner) {
    auto* entry=Slot(owner);
    if(!entry || (entry->transport && !entry->transport->Retirable())) return false;
    demux_.RemoveOwner(owner); entry->transport.reset(); entry->owner=0; return true;
}
QuicTransport* QuicUdpRouter::Find(std::uint64_t owner) const {
    for(const auto& entry:entries_) if(owner && entry.owner==owner) return entry.transport.get();
    return nullptr;
}
bool QuicUdpRouter::RegisterCid(std::uint64_t owner,const udp::Cid& cid) {
    return Slot(owner) && demux_.RegisterCid(cid,owner);
}
bool QuicUdpRouter::RemoveCid(std::uint64_t owner,const udp::Cid& cid) {
    return Slot(owner) && demux_.RemoveCid(cid,owner);
}
void QuicUdpRouter::RemoveCids(std::uint64_t owner) {
    if(Slot(owner)) demux_.RemoveOwner(owner);
}
udp::Decision QuicUdpRouter::Classify(const udp::Endpoint& peer,reach::DirectByteView packet,std::uint64_t now) const {
    return demux_.Inspect(probe_,packet.data,packet.size,peer,now);
}
bool QuicUdpRouter::ExpectInitial(std::uint64_t owner,const udp::Endpoint& peer,std::uint64_t expires) {
    return Slot(owner) && expires>now_ && demux_.ExpectInitial(peer,owner,expires);
}
bool QuicUdpRouter::Receive(const udp::Endpoint& peer,reach::DirectByteView packet) noexcept {
    const auto current=static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count());
    if(current>now_) now_=current;
    const auto decision=demux_.Inspect(probe_,packet.data,packet.size,peer,now_);
    if(decision.channel==udp::Channel::Drop) return true;
    // A recognized Control/1 packet must never fall through to legacy/uTP.
    // Copy only; no inline callback, crypto or session mutation on receive.
    if(decision.channel==udp::Channel::Control) {
        if(demux_.Current(decision) && packet.data && packet.size && packet.size<=1200 && controlCount_<control_.size()) {
            auto& pending=control_[(controlHead_+controlCount_)%control_.size()];
            pending.peer=peer; pending.owner=decision.owner; pending.receivedMs=now_; pending.size=packet.size;
            std::memcpy(pending.bytes.data(),packet.data,packet.size); ++controlCount_;
        }
        return true; // saturation is a drop, never fallback
    }
    if(decision.channel!=udp::Channel::Quic) return false;
    // A known QUIC packet stays claimed even if its session is not adopted,
    // closed, or temporarily out of buffer credit. Never reinterpret as uTP.
    if(demux_.Current(decision)) {
        if(auto* transport=Find(decision.owner)) {
            try { transport->ReceiveDatagram(peer,packet); }
            catch(...) { /* packet remains claimed; never legacy fallback */ }
        }
    }
    return true;
}
void QuicUdpRouter::SocketReset() noexcept {
    control_={}; controlHead_=0; controlCount_=0;
    for(auto& entry:entries_) if(entry.owner) {
        demux_.RemoveOwner(entry.owner);
        if(entry.transport) {
            try { entry.transport->Close(reach::DirectReason::Disabled); }
            catch(...) { /* retained; owner Poll retries delivery/retirement */ }
        }
    }
}
void QuicUdpRouter::Poll(std::uint64_t now) {
    if(now<now_) return;
    now_=now; demux_.Expire(now);
    for(auto& entry:entries_) if(entry.transport) entry.transport->Poll(now);
}
}
