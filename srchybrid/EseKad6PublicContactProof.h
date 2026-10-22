#pragma once
#include <array>
#include <cstdint>
#include <limits>
namespace ese { namespace discovery {
struct PublicUdpContact {
    std::array<std::uint8_t,4> address{};
    std::uint16_t localPort=0,publicPort=0;
    std::uint64_t generation=0,until=0;
    bool SameTuple(const PublicUdpContact& other) const noexcept {
        return address==other.address && localPort==other.localPort && publicPort==other.publicPort && generation==other.generation;
    }
};
// A generation-bound external UDP firewall test, independent of TCP callback,
// server HighID, NodeBound and a peer's advertised evidence. Caller invokes
// Receive only after the existing Kad UDP tester admitted the requested peer.
class PublicContactProof {
public:
    bool Begin(std::uint32_t peer,const PublicUdpContact& contact,std::uint64_t now) noexcept {
        if(!peer || !Clock(now) || !Usable(contact,now) || now>(std::numeric_limits<std::uint64_t>::max)()-180000) return false;
        Pending* available=nullptr;
        for(auto& entry:pending_) {
            if(entry.used && now>=entry.deadline) entry={};
            if(entry.used && entry.peer==peer) return false;
            if(!entry.used && !available) available=&entry;
        }
        if(!available) return false;
        *available={contact,peer,(contact.until<now+180000)?contact.until:now+180000,true}; return true;
    }
    bool Receive(std::uint32_t peer,std::uint16_t testedPublicPort,std::uint16_t localReceivePort,
        const PublicUdpContact& current,std::uint64_t now) noexcept {
        if(!Clock(now) || !Usable(current,now) || testedPublicPort!=current.publicPort || localReceivePort!=current.localPort ||
            now>(std::numeric_limits<std::uint64_t>::max)()-60000) return false;
        for(auto& entry:pending_) if(entry.used && entry.peer==peer && now<entry.deadline && entry.contact.SameTuple(current)) {
            verified_=current; verified_.until=(entry.deadline<now+60000)?entry.deadline:now+60000;
            if(current.until<verified_.until) verified_.until=current.until;
            entry={}; return true;
        }
        return false;
    }
    bool Current(const PublicUdpContact& contact,std::uint64_t now) const noexcept {
        return (!haveTime_ || now>=last_) && Usable(contact,now) && verified_.SameTuple(contact) && now<verified_.until;
    }
    std::uint64_t VerifiedUntil(const PublicUdpContact& contact,std::uint64_t now) const noexcept {
        if(!Current(contact,now)) return 0;
        return contact.until<verified_.until ? contact.until : verified_.until;
    }
    void Reset() noexcept { pending_={}; verified_={}; last_=0; haveTime_=false; }
private:
    static bool Usable(const PublicUdpContact& contact,std::uint64_t now) noexcept {
        const auto& ip=contact.address;
        return contact.generation && contact.localPort && contact.publicPort && now<contact.until && ip[0] && ip[0]<224 &&
            ip[0]!=10 && ip[0]!=127 && !(ip[0]==192 && ip[1]==168) && !(ip[0]==172 && ip[1]>=16 && ip[1]<=31) &&
            !(ip[0]==100 && ip[1]>=64 && ip[1]<=127) && !(ip[0]==169 && ip[1]==254) &&
            !(ip[0]==198 && (ip[1]==18 || ip[1]==19));
    }
    bool Clock(std::uint64_t now) noexcept {
        if(haveTime_ && now<last_) return false;
        last_=now; haveTime_=true; return true;
    }
    struct Pending { PublicUdpContact contact; std::uint32_t peer=0; std::uint64_t deadline=0; bool used=false; };
    std::array<Pending,2> pending_{};
    PublicUdpContact verified_;
    std::uint64_t last_=0; bool haveTime_=false;
};
} }
