#pragma once
#include "EseReachDescriptor.h"
#include <limits>
namespace ese { namespace discovery {
enum class SerialResult { Accepted, Duplicate, Stale, Conflict, Expired, Invalid, Full };
// Metadata only, NOT the witness publication store. Does not retain payloads or
// grant route freshness. Caller verified pub/digest/signature before admission.
// Retains serial high-water marks even after TTL; never evicts one implicitly
// to re-admit an older signed descriptor. Capacity is an explicit owner budget.
template<std::size_t Capacity=256> class DescriptorSerials {
public:
    SerialResult AcceptVerified(const DescriptorView& descriptor,const std::array<std::uint8_t,32>& digest,
        std::uint32_t sourceTtl,std::uint64_t now,std::uint64_t& deadline) noexcept {
        deadline=0;
        if(clockSet_ && now<lastNow_) return SerialResult::Invalid;
        clockSet_=true; lastNow_=now;
        unsigned nonzero=0; for(auto byte:descriptor.node) nonzero|=byte;
        if(!nonzero || !descriptor.generation || !sourceTtl || !descriptor.ttl || descriptor.ttl>120) return SerialResult::Invalid;
        Entry* free=nullptr;
        for(auto& entry:entries_) {
            if(!entry.used) { if(!free) free=&entry; continue; }
            if(entry.node!=descriptor.node || entry.generation!=descriptor.generation) continue;
            if(descriptor.serial<entry.serial) return SerialResult::Stale;
            if(descriptor.serial==entry.serial) {
                if(entry.digest!=digest) return SerialResult::Conflict;
                if(now>=entry.deadline) return SerialResult::Expired;
                deadline=entry.deadline; return SerialResult::Duplicate;
            }
            return Store(entry,descriptor,digest,sourceTtl,now,deadline);
        }
        if(!free) return SerialResult::Full;
        return Store(*free,descriptor,digest,sourceTtl,now,deadline);
    }
private:
    struct Entry {
        std::array<std::uint8_t,32> node{},digest{};
        std::uint64_t generation=0,serial=0,deadline=0;
        bool used=false;
    };
    static SerialResult Store(Entry& entry,const DescriptorView& descriptor,
        const std::array<std::uint8_t,32>& digest,std::uint32_t sourceTtl,
        std::uint64_t now,std::uint64_t& deadline) noexcept {
        const auto ttl=sourceTtl<descriptor.ttl ? sourceTtl : descriptor.ttl;
        const auto lifetime=static_cast<std::uint64_t>(ttl)*1000;
        if(now>(std::numeric_limits<std::uint64_t>::max)()-lifetime) return SerialResult::Invalid;
        Entry replacement; replacement.used=true; replacement.node=descriptor.node;
        replacement.digest=digest; replacement.generation=descriptor.generation;
        replacement.serial=descriptor.serial; replacement.deadline=now+lifetime;
        entry=replacement; deadline=replacement.deadline; return SerialResult::Accepted;
    }
    std::array<Entry,Capacity> entries_{};
    std::uint64_t lastNow_=0;
    bool clockSet_=false;
};
} }
