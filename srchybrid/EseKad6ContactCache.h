#pragma once
#include "EseKad6ContactRefresh.h"
namespace ese { namespace discovery {
// Complete signed records only. Import permission/pins belong to the caller;
// cached signature validity is never a restored session or return proof.
class Kad6ContactCache {
public:
    // Signed storage hint only: deliberately does not check freshness, claim a
    // refresh cooldown, or restore a session. Never use this as authorization.
    bool ReadHint(const std::array<std::uint8_t,32>& node,kad6::K6RouterRecord& out) const noexcept {
        out={};
        try {
            for(const auto& entry:entries_) if(entry.size && entry.node==node) {
                std::size_t consumed=0;
                return kad6::DecodeK6RouterRecord(entry.bytes.data(),entry.size,out,&consumed)==kad6::Kad6Status::Ok && consumed==entry.size;
            }
        } catch(...) { out={}; }
        return false;
    }
    // Bounded discovery hints only. Even a loaded, signed key is not a pin,
    // live session, fresh contact or return-path proof. Callers must recheck
    // Fresh() and complete the exact-endpoint bootstrap before using it.
    unsigned SnapshotHints(std::array<std::array<std::uint8_t,32>,64>& out) const noexcept {
        out={}; unsigned count=0;
        for(const auto& entry:entries_) if(entry.size) out[count++]=entry.node;
        return count;
    }
    bool Serialize(std::array<std::uint8_t,32768>& out,std::size_t& size) const noexcept {
        out={}; size=0; const char magic[8]={'E','S','E','K','6','C','1',0}; std::memcpy(out.data(),magic,8);
        unsigned count=0; std::size_t offset=12;
        for(const auto& entry:entries_) if(entry.size) {
            if(entry.size>out.size()-offset-2) { out={}; return false; }
            out[offset]=static_cast<std::uint8_t>(entry.size>>8); out[offset+1]=static_cast<std::uint8_t>(entry.size);
            std::memcpy(out.data()+offset+2,entry.bytes.data(),entry.size); offset+=2+entry.size; ++count;
        }
        out[8]=static_cast<std::uint8_t>(count>>8); out[9]=static_cast<std::uint8_t>(count); size=offset; return true;
    }
    // Cold-load only: never overwrite an active cache/cooldown. Parse into a
    // temporary owner and commit after every complete record signature passes.
    bool Load(const std::uint8_t* bytes,std::size_t size,const kad6::Kad6CryptoHooks& crypto) noexcept {
        const char magic[8]={'E','S','E','K','6','C','1',0};
        if(haveTime_ || !bytes || size<12 || size>32768 || std::memcmp(bytes,magic,8) || bytes[10] || bytes[11]) return false;
        for(const auto& entry:entries_) if(entry.size) return false;
        const auto count=static_cast<unsigned>(ReadBe(bytes+8,2)); if(count>64) return false;
        try {
            Kad6ContactCache candidate; std::size_t offset=12;
            for(unsigned i=0;i<count;++i) {
                if(size-offset<2) return false;
                const auto length=static_cast<std::size_t>(ReadBe(bytes+offset,2)); offset+=2;
                if(length>size-offset) return false;
                kad6::K6RouterRecord record; std::size_t consumed=0;
                if(kad6::DecodeK6RouterRecord(bytes+offset,length,record,&consumed)!=kad6::Kad6Status::Ok || consumed!=length) return false;
                for(const auto& entry:candidate.entries_) if(entry.size && entry.node==record.node_pub) return false;
                if(!candidate.Import(record.node_pub,bytes+offset,length,crypto)) return false;
                offset+=length;
            }
            if(offset!=size) return false;
            *this=candidate; return true;
        } catch(...) { return false; }
    }
    bool Import(const std::array<std::uint8_t,32>& expected,const std::uint8_t* bytes,std::size_t size,
        const kad6::Kad6CryptoHooks& crypto) noexcept {
        if(!bytes || size<kad6::kK6RouterRecordMinSize || size>kad6::kK6RouterRecordMaxSize) return false;
        try {
            kad6::K6RouterRecord record; std::size_t consumed=0;
            if(kad6::DecodeK6RouterRecord(bytes,size,record,&consumed)!=kad6::Kad6Status::Ok || consumed!=size || record.node_pub!=expected ||
                kad6::VerifyK6RouterRecord(crypto,record)!=kad6::Kad6Status::Ok) return false;
            Entry* chosen=nullptr;
            for(auto& entry:entries_) if(entry.size && entry.node==expected) { chosen=&entry; break; }
            if(chosen) {
                kad6::K6RouterRecord previous; std::size_t previousConsumed=0;
                if(kad6::DecodeK6RouterRecord(chosen->bytes.data(),chosen->size,previous,&previousConsumed)!=kad6::Kad6Status::Ok ||
                    previousConsumed!=chosen->size || record.epoch<previous.epoch) return false;
            }
            if(!chosen) for(auto& entry:entries_) if(!entry.size) { chosen=&entry; break; }
            if(!chosen) return false;
            // Preserve refresh cooldown even when bytes are replaced.
            chosen->node=expected; std::memcpy(chosen->bytes.data(),bytes,size); chosen->size=size; return true;
        } catch(...) { return false; }
    }
    bool Fresh(const std::array<std::uint8_t,32>& node,const kad6::Kad6CryptoHooks& crypto,
        std::uint64_t nowUnix,kad6::K6RouterRecord& out) const noexcept {
        out={};
        for(const auto& entry:entries_) if(entry.size && entry.node==node)
            return control::VerifySelfContact(node,entry.bytes.data(),entry.size,crypto,nowUnix,out);
        return false;
    }
    // Only caller-approved signature-verified cached keys are eligible. A
    // successful claim consumes the cooldown even if network refresh fails.
    bool BeginRefresh(const std::array<std::uint8_t,32>& node,std::uint64_t now,
        std::array<std::uint8_t,kad6::kK6RouterRecordMaxSize>& bytes,std::size_t& size) noexcept {
        bytes={}; size=0;
        if(haveTime_ && now<last_) return false;
        last_=now; haveTime_=true;
        if(now>(std::numeric_limits<std::uint64_t>::max)()-60000) return false;
        for(auto& entry:entries_) if(entry.size && entry.node==node) {
            if(entry.refreshUntil>now) return false;
            entry.refreshUntil=now+60000; bytes=entry.bytes; size=entry.size; return true;
        }
        return false;
    }
private:
    struct Entry {
        std::array<std::uint8_t,32> node{};
        std::array<std::uint8_t,kad6::kK6RouterRecordMaxSize> bytes{};
        std::size_t size=0; std::uint64_t refreshUntil=0;
    };
    std::array<Entry,64> entries_{}; std::uint64_t last_=0; bool haveTime_=false;
};
static_assert(sizeof(Kad6ContactCache)<=32768,"complete contacts cache budget");
// Validate into a copy of the pending request. Cache rejection (rollback/full)
// must not consume it; only an imported original signed record commits both.
inline bool ImportRefreshedContact(Kad6ContactCache& cache,control::ContactRefreshRequest& pending,
    const control::Sessions& sessions,const udp::Endpoint& endpoint,const std::uint8_t* bytes,
    std::size_t size,std::uint64_t now,const kad6::Kad6CryptoHooks& crypto,
    std::uint64_t nowUnix,kad6::K6RouterRecord& out) noexcept {
    out={};
    auto candidate=pending; kad6::K6RouterRecord record;
    if(!candidate.ReceiveInSession(sessions,endpoint,bytes,size,now,crypto,nowUnix,record)) return false;
    control::Envelope envelope;
    if(!control::ParseUntrusted(bytes,size,envelope) || envelope.payloadSize<130) return false;
    const auto length=static_cast<std::size_t>(ReadBe(envelope.payload+64,2));
    if(!cache.Import(record.node_pub,envelope.payload+66,length,crypto)) return false;
    pending=candidate; out=std::move(record); return true;
}
} }
