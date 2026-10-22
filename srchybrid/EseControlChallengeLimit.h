#pragma once
#include "EseUdpDemux.h"
#include "EseControlPacketBudget.h"
namespace ese { namespace control {
// GET requests: strict rolling 1000ms windows, not a token-bucket burst.
// Call after session/signature/replay checks. No active-identity eviction.
template<std::size_t Capacity=256> class DescriptorGetLimit {
public:
    DescriptorGetLimit() noexcept = default; // isolated tests/single emitter
    explicit DescriptorGetLimit(PacketBudget& shared) noexcept : shared_(&shared) {}
    bool Allow(const std::array<std::uint8_t,32>& identity,std::uint64_t now) noexcept {
        return AllowOperation(identity,now,false);
    }
    bool AllowPut(const std::array<std::uint8_t,32>& identity,std::uint64_t now) noexcept {
        return AllowOperation(identity,now,true);
    }
private:
    bool AllowOperation(const std::array<std::uint8_t,32>& identity,std::uint64_t now,bool put) noexcept {
        unsigned key=0; for(auto b:identity) key|=b;
        if(!key || (clockSet_ && now<lastNow_)) return false;
        clockSet_=true; lastNow_=now;
        Entry* selected=nullptr; Entry* free=nullptr;
        for(auto& entry:identities_) {
            while(entry.size && now-entry.times[entry.head]>=1000) {
                entry.head=(entry.head+1)%entry.times.size(); --entry.size;
            }
            if(entry.putActive && now-entry.lastPut>=1000) entry.putActive=false;
            if(!entry.size && !entry.putActive) { if(!free) free=&entry; continue; }
            if(entry.identity==identity) selected=&entry;
        }
        if(!selected) {
            if(!free) return false;
            selected=free; *selected=Entry{}; selected->identity=identity;
        }
        if(put) {
            if(selected->putActive) return false;
            if(!(shared_ ? *shared_ : local_).Allow(now)) return false;
            selected->putActive=true; selected->lastPut=now;
        } else {
            if(selected->size==selected->times.size()) return false;
            if(!(shared_ ? *shared_ : local_).Allow(now)) return false;
            selected->times[(selected->head+selected->size)%selected->times.size()]=now; ++selected->size;
        }
        return true;
    }
private:
    struct Entry {
        std::array<std::uint8_t,32> identity{};
        std::array<std::uint64_t,4> times{};
        std::size_t head=0,size=0;
        std::uint64_t lastPut=0;
        bool putActive=false;
    };
    std::array<Entry,Capacity> identities_{};
    PacketBudget local_;
    PacketBudget* shared_=nullptr; // injected owner must outlive this limiter
    std::uint64_t lastNow_=0;
    bool clockSet_=false;
};
// Main-thread owned. Call only for a validated PROBE just before sending a
// challenge. No callbacks, heap allocations or autonomous retransmissions.
class ChallengeLimit {
public:
    ChallengeLimit() noexcept = default; // isolated tests/single emitter
    explicit ChallengeLimit(PacketBudget& shared) noexcept : shared_(&shared) {}
    bool Allow(const udp::Endpoint& source,std::uint64_t now) noexcept {
        if(!source.port || (clockSet_ && now<lastNow_)) return false;
        if(!source.ipv6) for(unsigned i=4;i<16;++i) if(source.address[i]) return false;
        clockSet_=true; lastNow_=now;
        const auto length=source.ipv6 ? 8U : 3U;
        Entry* selected=nullptr; Entry* free=nullptr;
        for(auto& entry:prefixes_) {
            if(entry.used && now-entry.updated>=2000) entry.used=false;
            if(!entry.used) { if(!free) free=&entry; continue; }
            bool same=entry.ipv6==source.ipv6;
            for(unsigned i=0;i<length;++i) same=same && entry.prefix[i]==source.address[i];
            if(same) { selected=&entry; break; }
        }
        if(!selected) {
            if(!free) return false;
            selected=free; *selected=Entry{}; selected->used=true;
            selected->ipv6=source.ipv6; selected->updated=now;
            for(unsigned i=0;i<length;++i) selected->prefix[i]=source.address[i];
        }
        const auto elapsed=now-selected->updated;
        // Milli-tokens: 4000 burst, 2 per ms refill, 1000 per challenge.
        const auto refill=elapsed>=2000 ? 4000U : static_cast<unsigned>(elapsed*2);
        selected->tokens=(selected->tokens+refill>4000) ? 4000 : selected->tokens+refill;
        selected->updated=now;
        if(selected->tokens<1000) return false;
        if(!(shared_ ? *shared_ : local_).Allow(now)) return false;
        selected->tokens-=1000;
        return true;
    }
private:
    struct Entry {
        std::array<std::uint8_t,8> prefix{};
        std::uint64_t updated=0;
        unsigned tokens=4000;
        bool ipv6=false,used=false;
    };
    std::array<Entry,256> prefixes_{};
    PacketBudget local_;
    PacketBudget* shared_=nullptr; // injected owner must outlive this limiter
    std::uint64_t lastNow_=0;
    bool clockSet_=false;
};
} }
