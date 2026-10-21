#pragma once
#include <array>
#include <cstdint>
#include <limits>
namespace ese { namespace discovery {
// Main-thread monotonic clock. Caller supplies a topology revision only after
// an actual change; network packets themselves must not increment that token.
template<unsigned Capacity=256> class ResolutionCooldown {
public:
    struct Key { std::array<std::uint8_t,32> node{}; std::uint64_t generation=0;
        bool operator==(const Key& other) const noexcept { return node==other.node && generation==other.generation; } };
    bool RecordExpired(const Key& key,std::uint64_t topology,std::uint64_t now) noexcept {
        unsigned pub=0; for(auto b:key.node) pub|=b;
        if(!pub || !key.generation || !Clock(now) || now>(std::numeric_limits<std::uint64_t>::max)()-60000) return false;
        Entry* free=nullptr;
        for(auto& entry:entries_) {
            if(entry.used && entry.key==key) {
                // Duplicate expiry notifications must not prolong cooldown.
                if(entry.until>now && entry.topology==topology) return true;
                entry={key,topology,now+60000,true}; return true;
            }
            if(!entry.used || entry.until<=now) if(!free) free=&entry;
        }
        if(!free) {
            // Remember saturation without evicting another key: untracked keys
            // must not look eligible merely because this insertion failed.
            if(now+60000>saturatedUntil_) { saturatedUntil_=now+60000; saturatedTopology_=topology; }
            return false;
        }
        *free={key,topology,now+60000,true}; return true;
    }
    bool Permit(const Key& key,std::uint64_t topology,std::uint64_t now,bool explicitUserAction=false) noexcept {
        unsigned pub=0; for(auto b:key.node) pub|=b;
        if(!pub || !key.generation || !Clock(now)) return false;
        for(const auto& entry:entries_) if(entry.used && entry.key==key)
            return explicitUserAction || entry.topology!=topology || now>=entry.until;
        return explicitUserAction || topology!=saturatedTopology_ || now>=saturatedUntil_;
    }
private:
    bool Clock(std::uint64_t now) noexcept {
        if(haveTime_ && now<last_) return false;
        last_=now; haveTime_=true; return true;
    }
    struct Entry { Key key; std::uint64_t topology=0,until=0; bool used=false; };
    std::array<Entry,Capacity> entries_{};
    std::uint64_t last_=0,saturatedUntil_=0,saturatedTopology_=0; bool haveTime_=false;
};
} }
