#pragma once
#include "EseReachDescriptor.h"
#include "EseK6DirectSource.h"
#include "EseUdpDemux.h"
#include <vector>
#include <limits>
namespace ese { namespace discovery {
enum class StoreResult { Stored, Provisional, Duplicate, Stale, Conflict, Limit, Invalid };
struct StoredDescriptor { const std::uint8_t* bytes=nullptr; std::size_t size=0; std::uint64_t deadline=0; };
enum class SourceStoreResult { Stored, Duplicate, NeedDescriptor, Stale, Conflict, Invalid };
struct FoundSources {
    std::array<std::array<std::uint8_t,173>,4> records{};
    std::array<std::uint32_t,4> remainingTtl{};
    std::size_t count=0;
};
// Main-thread owner; construct on heap for production capacity. Call only after
// authenticated PUT and descriptor verification. SourceTTL comes from a live,
// identity-bound source index, not the publisher's assertion. Zero waits <=5s.
// Metadata high-water marks survive payload expiry; no implicit reclamation.
template<std::size_t Capacity=10000,std::size_t Budget=8*1024*1024> class WitnessDescriptors {
    static_assert(Capacity<=10000,"W descriptor capacity exceeds contract");
    struct Stage {
        std::vector<std::uint8_t> bytes;
        std::array<std::uint8_t,32> digest{};
        std::array<std::uint8_t,9> prefix{};
        std::uint64_t serial=0,deadline=0,until=0;
    };
    struct Entry {
        std::array<std::uint8_t,16> file{};
        std::array<std::uint8_t,32> node{},digest{};
        std::array<std::uint8_t,9> prefix{};
        std::vector<std::uint8_t> bytes;
        Stage staged;
        std::array<std::uint8_t,173> sourceRecord{};
        std::uint64_t fileSize=0;
        std::uint64_t generation=0,serial=0,deadline=0,pendingUntil=0;
        bool used=false,pending=false,indexed=false;
    };
public:
    StoreResult PutVerified(const std::array<std::uint8_t,16>& file,const std::uint8_t* bytes,
        std::size_t size,const std::array<std::uint8_t,32>& digest,const udp::Endpoint& source,
        std::uint32_t sourceTtl,std::uint64_t now) noexcept {
        DescriptorView descriptor; std::array<std::uint8_t,9> prefix{};
        if(!ParseUntrusted(bytes,size,descriptor) || !descriptor.generation || !Prefix(source,prefix) ||
            !Clock(now)) return StoreResult::Invalid;
        unsigned key=0; for(auto b:descriptor.node) key|=b;
        if(!key) return StoreResult::Invalid;
        ExpirePayloads(now);
        Entry* existing=nullptr; Entry* free=nullptr;
        std::size_t byNode=0,byPrefix=0,pendingNode=0;
        for(auto& entry:entries_) {
            if(!entry.used) { if(!free) free=&entry; continue; }
            if(entry.file==file && entry.node==descriptor.node && entry.generation==descriptor.generation) existing=&entry;
        }
        if(existing) {
            if(descriptor.serial<existing->serial) return StoreResult::Stale;
            if(descriptor.serial==existing->serial) {
                if(digest!=existing->digest) return StoreResult::Conflict;
                return existing->bytes.empty() ? StoreResult::Stale : StoreResult::Duplicate;
            }
            if(descriptor.serial<existing->staged.serial) return StoreResult::Stale;
            if(descriptor.serial==existing->staged.serial) {
                if(digest!=existing->staged.digest) return StoreResult::Conflict;
                return existing->staged.bytes.empty() ? StoreResult::Stale : StoreResult::Duplicate;
            }
        }
        for(const auto& entry:entries_) if(&entry!=existing && !entry.bytes.empty()) {
            if(entry.node==descriptor.node) { ++byNode; if(entry.pending) ++pendingNode; }
            if(entry.prefix==prefix) ++byPrefix;
        }
        std::size_t liveCost=0;
        for(const auto& entry:entries_) {
            if(!entry.bytes.empty()) ++liveCost;
            if(!entry.staged.bytes.empty()) {
                ++liveCost;
                if(&entry!=existing) {
                    if(entry.node==descriptor.node) { ++byNode; ++pendingNode; }
                    if(entry.staged.prefix==prefix) ++byPrefix;
                }
            }
        }
        const bool paired=existing && (existing->indexed || !existing->staged.bytes.empty());
        if(!paired && (!existing || existing->bytes.empty()) && liveCost>=Capacity) return StoreResult::Limit;
        if(paired) {
            if(!existing->bytes.empty()) {
                ++byNode; if(existing->prefix==prefix) ++byPrefix;
            }
            if(liveCost-(existing->staged.bytes.empty() ? 0 : 1)>=Capacity || pendingNode) return StoreResult::Limit;
        }
        if(byNode>=8 || byPrefix>=16 || (!sourceTtl && pendingNode) || (!existing && !free)) return StoreResult::Limit;
        const auto ttl=sourceTtl && sourceTtl<descriptor.ttl ? sourceTtl : descriptor.ttl;
        if(now>(std::numeric_limits<std::uint64_t>::max)()-static_cast<std::uint64_t>(ttl)*1000 ||
            ((!sourceTtl || paired) && now>(std::numeric_limits<std::uint64_t>::max)()-5000)) return StoreResult::Invalid;
        try {
            if(paired) {
                Stage stage; stage.bytes.assign(bytes,bytes+size);
                const auto old=existing->staged.bytes.capacity();
                if(usedBytes_-old>Budget || stage.bytes.capacity()>Budget-(usedBytes_-old)) return StoreResult::Limit;
                stage.digest=digest; stage.prefix=prefix; stage.serial=descriptor.serial;
                stage.deadline=now+static_cast<std::uint64_t>(ttl)*1000;
                stage.until=existing->staged.bytes.empty() ? now+5000 : existing->staged.until;
                usedBytes_=usedBytes_-old+stage.bytes.capacity(); existing->staged=std::move(stage);
                return StoreResult::Provisional;
            }
            Entry replacement; replacement.bytes.assign(bytes,bytes+size);
            const auto old=existing ? existing->bytes.capacity() : 0;
            if(usedBytes_-old>Budget || replacement.bytes.capacity()>Budget-(usedBytes_-old)) return StoreResult::Limit;
            replacement.used=true; replacement.file=file; replacement.node=descriptor.node; replacement.digest=digest;
            replacement.prefix=prefix; replacement.generation=descriptor.generation; replacement.serial=descriptor.serial;
            replacement.deadline=now+static_cast<std::uint64_t>(ttl)*1000;
            replacement.pending=!sourceTtl; replacement.pendingUntil=now+(!sourceTtl ? 5000 : 0);
            if(existing && existing->pending && !sourceTtl && !existing->bytes.empty())
                replacement.pendingUntil=existing->pendingUntil; // replacement cannot prolong provisional wait
            usedBytes_=usedBytes_-old+replacement.bytes.capacity();
            *(existing ? existing : free)=std::move(replacement);
            return sourceTtl ? StoreResult::Stored : StoreResult::Provisional;
        } catch(...) { return StoreResult::Limit; }
    }
    bool SourceVerified(const std::array<std::uint8_t,16>& file,const std::array<std::uint8_t,32>& node,
        std::uint32_t ttl,std::uint64_t now) noexcept {
        if(!ttl || !Clock(now)) return false;
        ExpirePayloads(now); bool promoted=false;
        const auto lifetime=static_cast<std::uint64_t>(ttl>120 ? 120 : ttl)*1000;
        if(now>(std::numeric_limits<std::uint64_t>::max)()-lifetime) return false;
        for(auto& entry:entries_) if(entry.pending && !entry.bytes.empty() && entry.file==file && entry.node==node) {
            if(now+lifetime<entry.deadline) entry.deadline=now+lifetime;
            entry.pending=false; promoted=true;
        }
        return promoted;
    }
    // Caller verified independent record signature AND live Control PUT. This
    // gate only matches/promotes records; it cannot authenticate arbitrary data.
    SourceStoreResult DirectSourceVerified(const std::uint8_t* bytes,std::size_t size,
        std::uint64_t maxFileSize,std::uint64_t now) noexcept {
        DirectSource source;
        if(!DecodeSource(bytes,size,maxFileSize,source) || !Clock(now)) return SourceStoreResult::Invalid;
        ExpirePayloads(now);
        for(auto& entry:entries_) if(entry.used && entry.file==source.file && entry.node==source.node && entry.generation==source.generation) {
            if(source.serial==entry.staged.serial && !entry.staged.bytes.empty()) {
                if(source.digest!=entry.staged.digest) return SourceStoreResult::Conflict;
                const auto lifetime=static_cast<std::uint64_t>(source.ttl)*1000;
                if(now>(std::numeric_limits<std::uint64_t>::max)()-lifetime) return SourceStoreResult::Invalid;
                usedBytes_-=entry.bytes.capacity(); entry.bytes=std::move(entry.staged.bytes);
                entry.digest=entry.staged.digest; entry.prefix=entry.staged.prefix; entry.serial=entry.staged.serial;
                entry.deadline=entry.staged.deadline<now+lifetime ? entry.staged.deadline : now+lifetime;
                entry.staged=Stage{}; std::memcpy(entry.sourceRecord.data(),bytes,173);
                entry.fileSize=source.fileSize; entry.indexed=true; entry.pending=false; return SourceStoreResult::Stored;
            }
            if(source.serial<entry.serial) return SourceStoreResult::Stale;
            if(source.serial>entry.serial || entry.bytes.empty()) return SourceStoreResult::NeedDescriptor;
            if(source.digest!=entry.digest) return SourceStoreResult::Conflict;
            if(entry.indexed) {
                if(std::memcmp(entry.sourceRecord.data(),bytes,173)) return SourceStoreResult::Conflict;
                return SourceStoreResult::Duplicate;
            }
            const auto lifetime=static_cast<std::uint64_t>(source.ttl)*1000;
            if(now>(std::numeric_limits<std::uint64_t>::max)()-lifetime) return SourceStoreResult::Invalid;
            if(now+lifetime<entry.deadline) entry.deadline=now+lifetime;
            std::memcpy(entry.sourceRecord.data(),bytes,173); entry.fileSize=source.fileSize;
            entry.indexed=true; entry.pending=false; return SourceStoreResult::Stored;
        }
        return SourceStoreResult::NeedDescriptor;
    }
    bool Find(const std::array<std::uint8_t,16>& file,std::uint64_t fileSize,
        std::uint8_t maximum,std::uint64_t now,FoundSources& out) noexcept {
        out={}; if(!fileSize || !maximum || maximum>4 || !Clock(now)) return false;
        ExpirePayloads(now);
        for(const auto& entry:entries_) if(entry.indexed && !entry.bytes.empty() && entry.file==file && entry.fileSize==fileSize) {
            const auto ttl=(entry.deadline-now)/1000;
            if(!ttl) continue;
            out.records[out.count]=entry.sourceRecord; out.remainingTtl[out.count]=static_cast<std::uint32_t>(ttl);
            if(++out.count==maximum) break;
        }
        return true;
    }
    StoredDescriptor Get(const std::array<std::uint8_t,16>& file,const std::array<std::uint8_t,32>& node,
        const std::array<std::uint8_t,32>& digest,std::uint64_t now) noexcept {
        if(!Clock(now)) return {};
        ExpirePayloads(now);
        for(const auto& entry:entries_) if(!entry.pending && !entry.bytes.empty() && entry.file==file && entry.node==node && entry.digest==digest)
            return {entry.bytes.data(),entry.bytes.size(),entry.deadline};
        return {};
    }
    std::size_t ChargedBytes() const noexcept { return usedBytes_; }
private:
    static bool Prefix(const udp::Endpoint& source,std::array<std::uint8_t,9>& out) noexcept {
        if(!source.port) return false;
        if(!source.ipv6) for(unsigned i=4;i<16;++i) if(source.address[i]) return false;
        out[0]=source.ipv6 ? 6 : 4;
        for(unsigned i=0;i<(source.ipv6 ? 8U : 3U);++i) out[i+1]=source.address[i];
        return true;
    }
    bool Clock(std::uint64_t now) noexcept {
        if(clockSet_ && now<lastNow_) return false;
        clockSet_=true; lastNow_=now; return true;
    }
    void ExpirePayloads(std::uint64_t now) noexcept {
        for(auto& entry:entries_) if(!entry.staged.bytes.empty() && (now>=entry.staged.deadline || now>=entry.staged.until)) {
            usedBytes_-=entry.staged.bytes.capacity(); std::vector<std::uint8_t>().swap(entry.staged.bytes);
        }
        for(auto& entry:entries_) if(!entry.bytes.empty() && (now>=entry.deadline || (entry.pending && now>=entry.pendingUntil))) {
            usedBytes_-=entry.bytes.capacity(); std::vector<std::uint8_t>().swap(entry.bytes);
            entry.sourceRecord={}; entry.fileSize=0; entry.indexed=false;
        }
    }
    std::array<Entry,Capacity> entries_{};
    std::size_t usedBytes_=sizeof(WitnessDescriptors);
    std::uint64_t lastNow_=0;
    bool clockSet_=false;
};
} }
