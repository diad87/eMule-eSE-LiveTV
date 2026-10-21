#pragma once
#include "EseKad6Resolution.h"
#include "EseQuicHostFactory.h"
namespace ese { namespace discovery {
// Main-thread FIND/DESC_GET bridge. Borrowed host/resolution outlive this owner.
// Caller supplies the live session ledger, pin policy and signed request.
// Does not mark a source READY or grant an eD2K identity/route.
class Kad6ResolutionHost {
public:
    Kad6ResolutionHost(QuicSessionHost& host,Kad6Resolution& resolution) noexcept
        : host_(host),resolution_(resolution) {}
    ~Kad6ResolutionHost() { Cancel(); }
    Kad6ResolutionHost(const Kad6ResolutionHost&)=delete;
    Kad6ResolutionHost& operator=(const Kad6ResolutionHost&)=delete;
    bool StartFind(unsigned slot,std::uint64_t owner,const std::array<std::uint8_t,32>& witness,
        const udp::Endpoint& peer,const std::array<std::uint8_t,32>& requester,
        const control::Datagram& packet,const control::Sessions& sessions,
        std::uint64_t now,std::uint64_t deadline) {
        control::Envelope envelope;
        if(slot>=entries_.size() || entries_[slot].owner || !owner || owner<=lastOwner_ ||
            deadline<=now || deadline-now>2000 || deadline>resolution_.Lookup().Deadline() ||
            packet.size>packet.bytes.size() || !control::ParseUntrusted(packet.bytes.data(),packet.size,envelope) ||
            envelope.header.type!=wire::kEseWireUdpK6DirectFind ||
            !sessions.Current(witness,peer,envelope.header,now)) return false;
        if(!host_.ExpectControlReply(envelope.header,wire::kEseWireUdpK6DirectFindResult,peer,owner,deadline)) return false;
        if(!resolution_.StartSignedFind(slot,witness,peer,requester,packet,now)) {
            host_.RemoveControlReplies(owner); return false;
        }
        entries_[slot]={owner,witness,peer,envelope.header,packet,deadline,true};
        lastOwner_=owner; return true;
    }
    QuicUdpSendResult SendFind(unsigned slot,const control::Sessions& sessions,std::uint64_t now) {
        if(slot>=entries_.size()) return {QuicUdpSendStatus::Invalid,0};
        auto& entry=entries_[slot];
        if(!Current(entry,sessions,now) || !resolution_.Poll(now)) {
            Retire(entry); return {QuicUdpSendStatus::Invalid,0};
        }
        control::Datagram packet;
        if(entry.first) { packet=entry.packet; entry.first=false; }
        else if(!resolution_.RetrySignedFind(slot,now,packet)) return {QuicUdpSendStatus::Invalid,0};
        ++entry.transmissions;
        const auto delay=entry.transmissions==1 ? 500U : 1000U;
        entry.nextRetry=entry.transmissions<3 && entry.deadline-now>delay ? now+delay : 0;
        // Failed sends consume authorization too; no hidden budget renewal.
        return host_.SendControl(entry.peer,{packet.bytes.data(),packet.size});
    }
    // Explicit scheduler hook: at most two retries, 500/1000ms backoff from
    // actual submission, no catch-up burst and no deadline/session renewal.
    void PumpFindRetries(const control::Sessions& sessions,std::uint64_t now) {
        Poll(sessions,now);
        for(unsigned slot=0;slot<entries_.size();++slot) {
            auto& entry=entries_[slot];
            if(entry.owner && entry.nextRetry && now>=entry.nextRetry) {
                entry.nextRetry=0;
                SendFind(slot,sessions,now);
            }
        }
    }
    bool ReceiveFind(std::uint64_t owner,const control::Sessions& sessions,
        const udp::Endpoint& peer,const std::uint8_t* bytes,std::size_t size,
        std::uint64_t now,FindResultView& out,control::FindContactsVerifier* contacts=nullptr) {
        out={};
        for(unsigned slot=0;slot<entries_.size();++slot) {
            auto& entry=entries_[slot];
            if(!owner || entry.owner!=owner) continue;
            if(!Current(entry,sessions,now)) { Retire(entry); return false; }
            if(!resolution_.ReceiveFind(slot,peer,bytes,size,now,out,contacts)) return false;
            Retire(entry); return true;
        }
        return false;
    }
    bool StartGet(unsigned slot,std::uint64_t owner,const std::array<std::uint8_t,32>& witness,
        const udp::Endpoint& peer,const std::array<std::uint8_t,32>& requester,
        const Locator& locator,const control::Datagram& packet,const control::Sessions& sessions,
        std::uint64_t now,std::uint64_t deadline) {
        control::Header header; GetView get;
        if(slot>=gets_.size() || gets_[slot].owner || !owner || owner<=lastOwner_ ||
            deadline<=now || deadline-now>2000 || deadline>resolution_.Lookup().Deadline() ||
            packet.size>packet.bytes.size() ||
            !control::VerifyDescriptorGet(requester,packet.bytes.data(),packet.size,header,get) ||
            !resolution_.MatchesFile(get.file) || get.node!=locator.node || get.digest!=locator.digest ||
            !sessions.Current(witness,peer,header,now)) return false;
        if(!host_.ExpectControlReply(header,wire::kEseWireUdpDescriptorResult,peer,owner,deadline)) return false;
        auto responseHeader=header; responseHeader.type=wire::kEseWireUdpDescriptorResult;
        if(!resolution_.StartGet(slot,witness,peer,responseHeader,locator,now,deadline)) {
            host_.RemoveControlReplies(owner); return false;
        }
        gets_[slot]={owner,witness,peer,header,packet,deadline,true}; lastOwner_=owner; return true;
    }
    // Single authorized transmission. Retransmission policy is not implicit.
    QuicUdpSendResult SendGet(unsigned slot,const control::Sessions& sessions,std::uint64_t now) {
        if(slot>=gets_.size()) return {QuicUdpSendStatus::Invalid,0};
        auto& entry=gets_[slot];
        if(!Current(entry,sessions,now) || !resolution_.Poll(now)) {
            Retire(entry); return {QuicUdpSendStatus::Invalid,0};
        }
        if(!entry.first) return {QuicUdpSendStatus::Invalid,0};
        entry.first=false;
        entry.transmissions=1;
        entry.nextRetry=entry.deadline-now>500 ? now+500 : 0;
        return host_.SendControl(entry.peer,{entry.packet.bytes.data(),entry.packet.size});
    }
    // GET retry is an explicit owner policy, never a new request/TTL grant.
    void PumpGetRetries(const control::Sessions& sessions,std::uint64_t now) {
        Poll(sessions,now);
        for(auto& entry:gets_) if(entry.owner && entry.nextRetry && now>=entry.nextRetry) {
            entry.nextRetry=0;
            if(!Current(entry,sessions,now) || !resolution_.Poll(now)) { Retire(entry); continue; }
            ++entry.transmissions;
            if(entry.transmissions<3 && entry.deadline-now>1000) entry.nextRetry=now+1000;
            host_.SendControl(entry.peer,{entry.packet.bytes.data(),entry.packet.size});
        }
    }
    bool ReceiveResolved(std::uint64_t owner,const control::Sessions& sessions,
        const udp::Endpoint& peer,const std::uint8_t* bytes,std::size_t size,
        std::uint64_t now,Kad6Resolution::ResolvedCandidate& out) {
        out={};
        for(unsigned slot=0;slot<gets_.size();++slot) {
            auto& entry=gets_[slot];
            if(!owner || entry.owner!=owner) continue;
            if(!Current(entry,sessions,now)) { Retire(entry); return false; }
            if(!resolution_.ReceiveResolved(slot,peer,bytes,size,now,out)) return false;
            Retire(entry); return true;
        }
        return false;
    }
    void Poll(const control::Sessions& sessions,std::uint64_t now) {
        const bool live=resolution_.Poll(now);
        for(auto& entry:entries_) if(entry.owner && (!live || !Current(entry,sessions,now))) Retire(entry);
        for(auto& entry:gets_) if(entry.owner && (!live || !Current(entry,sessions,now))) Retire(entry);
    }
    bool OwnsFind(std::uint64_t owner) const noexcept {
        for(const auto& entry:entries_) if(owner && entry.owner==owner) return true;
        return false;
    }
    bool OwnsGet(std::uint64_t owner) const noexcept {
        for(const auto& entry:gets_) if(owner && entry.owner==owner) return true;
        return false;
    }
    QuicUdpSendResult SendOwnedGet(std::uint64_t owner,const control::Sessions& sessions,std::uint64_t now) {
        for(unsigned slot=0;slot<gets_.size();++slot) if(owner && gets_[slot].owner==owner)
            return SendGet(slot,sessions,now);
        return {QuicUdpSendStatus::Invalid,0};
    }
    QuicUdpSendResult SendOwnedFind(std::uint64_t owner,const control::Sessions& sessions,std::uint64_t now) {
        for(unsigned slot=0;slot<entries_.size();++slot) if(owner && entries_[slot].owner==owner)
            return SendFind(slot,sessions,now);
        return {QuicUdpSendStatus::Invalid,0};
    }
    void Cancel() { for(auto& entry:entries_) Retire(entry); for(auto& entry:gets_) Retire(entry); }
private:
    struct Entry {
        std::uint64_t owner=0; std::array<std::uint8_t,32> witness{}; udp::Endpoint peer;
        control::Header header; control::Datagram packet; std::uint64_t deadline=0; bool first=false;
        unsigned transmissions=0; std::uint64_t nextRetry=0;
    };
    static bool Current(const Entry& entry,const control::Sessions& sessions,std::uint64_t now) noexcept {
        return entry.owner && now<entry.deadline && sessions.Current(entry.witness,entry.peer,entry.header,now);
    }
    void Retire(Entry& entry) {
        if(entry.owner) { const auto owner=entry.owner; entry={}; host_.RemoveControlReplies(owner); }
    }
    QuicSessionHost& host_; Kad6Resolution& resolution_; std::array<Entry,2> entries_{};
    std::array<Entry,4> gets_{};
    std::uint64_t lastOwner_=0;
};
} }
