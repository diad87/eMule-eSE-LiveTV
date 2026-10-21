#pragma once
#include <array>
#include <cstdint>
#include <limits>
namespace ese { namespace classic {
struct CallbackTcpEndpoint {
    std::array<std::uint8_t,4> address{};
    std::uint16_t localPort=0,publicPort=0;
    std::uint64_t generation=0,until=0;
    bool SameTuple(const CallbackTcpEndpoint& other) const noexcept {
        return address==other.address && localPort==other.localPort &&
            publicPort==other.publicPort && generation==other.generation;
    }
};
// Legacy firewall ACK has no nonce. It is accepted only on a NEW inbound
// IPv4 socket from the requested peer, opened after that request, for the
// captured local listener and current externally advertised tuple. This is
// limited classic reachability evidence, never NodeBound or server HighID.
class CallbackProof {
public:
    bool Begin(std::uint32_t peer,const CallbackTcpEndpoint& endpoint,std::uint64_t now) noexcept {
        if(!peer || !Clock(now) || !Usable(endpoint,now) ||
            now>(std::numeric_limits<std::uint64_t>::max)()-180000) return false;
        Pending* available=nullptr;
        for(auto& entry:pending_) {
            if(entry.used && now>=entry.deadline) entry={};
            if(entry.used && entry.peer==peer) return false; // no renewal by duplicate
            if(!entry.used && !available) available=&entry;
        }
        if(!available) return false;
        const auto deadline=(endpoint.until<now+180000)?endpoint.until:now+180000;
        *available={endpoint,peer,now,deadline,true}; return true;
    }
    bool Accept(std::uint32_t peer,const CallbackTcpEndpoint& current,
        std::uint64_t inboundGeneration,std::uint16_t localPort,std::uint64_t acceptedAt,
        std::uint64_t now) noexcept {
        if(!Clock(now) || !Usable(current,now) || inboundGeneration!=current.generation ||
            localPort!=current.localPort || acceptedAt>now ||
            now>(std::numeric_limits<std::uint64_t>::max)()-60000) return false;
        for(auto& entry:pending_) if(entry.used && entry.peer==peer) {
            if(now>=entry.deadline || acceptedAt<entry.started || !entry.endpoint.SameTuple(current)) return false;
            verified_=current;
            verified_.until=(entry.deadline<now+60000)?entry.deadline:now+60000;
            if(current.until<verified_.until) verified_.until=current.until;
            entry={}; return true;
        }
        return false;
    }
    bool RememberInbound(std::uint32_t peer,std::uint64_t generation,std::uint16_t localPort,
        std::uint64_t acceptedAt) noexcept {
        if(!Clock(acceptedAt)) return false;
        for(auto& entry:pending_) if(entry.used && entry.peer==peer && acceptedAt>=entry.started &&
            acceptedAt<entry.deadline && generation==entry.endpoint.generation && localPort==entry.endpoint.localPort) {
            if(entry.inbound) return false; // first accept only; no lease renewal
            entry.acceptedAt=acceptedAt; entry.inbound=true; return true;
        }
        return false;
    }
    bool AcceptRecorded(std::uint32_t peer,const CallbackTcpEndpoint& current,std::uint64_t now) noexcept {
        for(const auto& entry:pending_) if(entry.used && entry.peer==peer && entry.inbound)
            return Accept(peer,current,entry.endpoint.generation,entry.endpoint.localPort,entry.acceptedAt,now);
        return false;
    }
    bool Current(const CallbackTcpEndpoint& endpoint,std::uint64_t now) const noexcept {
        return (!haveTime_ || now>=last_) && Usable(endpoint,now) &&
            verified_.SameTuple(endpoint) && now<verified_.until;
    }
    std::uint64_t VerifiedUntil(const CallbackTcpEndpoint& endpoint,std::uint64_t now) const noexcept {
        if(!Current(endpoint,now)) return 0;
        return endpoint.until<verified_.until ? endpoint.until : verified_.until;
    }
    void Reset() noexcept { pending_={}; verified_={}; last_=0; haveTime_=false; }
private:
    static bool Usable(const CallbackTcpEndpoint& endpoint,std::uint64_t now) noexcept {
        const auto& ip=endpoint.address;
        return endpoint.generation && endpoint.localPort && endpoint.publicPort && now<endpoint.until &&
            ip[0] && ip[0]<224 && ip[0]!=10 && ip[0]!=127 &&
            !(ip[0]==169 && ip[1]==254) && !(ip[0]==172 && ip[1]>=16 && ip[1]<=31) &&
            !(ip[0]==192 && ip[1]==168) && !(ip[0]==100 && ip[1]>=64 && ip[1]<=127) &&
            !(ip[0]==198 && (ip[1]==18 || ip[1]==19));
    }
    bool Clock(std::uint64_t now) noexcept {
        if(haveTime_ && now<last_) return false;
        last_=now; haveTime_=true; return true;
    }
    struct Pending { CallbackTcpEndpoint endpoint; std::uint32_t peer=0;
        std::uint64_t started=0,deadline=0; bool used=false;
        std::uint64_t acceptedAt=0; bool inbound=false; };
    std::array<Pending,16> pending_{};
    CallbackTcpEndpoint verified_;
    std::uint64_t last_=0; bool haveTime_=false;
};
} }
