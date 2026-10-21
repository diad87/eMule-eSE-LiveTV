// SPDX-License-Identifier: MIT
#pragma once
#include "reach/direct_session.h"
#include "reach/part_verification.h"
#include <optional>
#include <limits>
#include <vector>
namespace reach {
struct DirectFileKey {
    std::uint64_t lifetime=0;
    std::array<std::uint8_t,16> hash{};
};
enum class DirectPartOwnerKind : std::uint8_t { Quic = 0, Legacy = 1 };
struct DirectPartContributor {
    std::uint64_t owner=0;
    DirectHandle handle;
    std::uint32_t route=0;
    std::uint64_t epoch=0,topology=0;
    DirectPartOwnerKind kind=DirectPartOwnerKind::Quic;
};
struct DirectPartReceipt {
    DirectFileKey file;
    std::uint32_t part=0;
    DirectPartContributor source;
    std::uint64_t bytes=0,revision=0,hash_generation=0;
    std::uint64_t part_revision=0;
};
// Main-thread owned, bounded provenance. Worker snapshots are value copies.
// Hash-job generation validation remains mandatory in the PartFile callback.
class DirectPartContributions {
public:
    static constexpr std::size_t Capacity=4096;
    std::size_t Size() const noexcept {
        std::size_t count=0;
        for(const auto& record:records_) if(record.revision) ++count;
        return count;
    }
    bool Contains(const DirectFileKey& file,std::uint32_t part,const DirectPartContributor& source) const noexcept {
        for(const auto& record:records_) if(record.revision && Same(record,file,part,source)) return true;
        return false;
    }
    bool Record(const DirectFileKey& file,std::uint32_t part,const DirectPartContributor& source,std::uint64_t bytes) noexcept {
        bool nonzero=false; for(const auto b:file.hash) nonzero=nonzero || b!=0;
        if((source.kind!=DirectPartOwnerKind::Quic && source.kind!=DirectPartOwnerKind::Legacy) ||
            !file.lifetime || !nonzero || !source.owner || !source.handle.generation || source.handle.slot>=256 ||
            !source.route || !source.epoch || !source.topology || !bytes || last_revision_==(std::numeric_limits<std::uint64_t>::max)()) return false;
        DirectPartReceipt* empty=nullptr;
        for(auto& record:records_) {
            if(!record.revision) { if(!empty) empty=&record; continue; }
            if(Same(record,file,part,source)) {
                if(bytes>(std::numeric_limits<std::uint64_t>::max)()-record.bytes) return false;
                record.bytes+=bytes; record.revision=++last_revision_;
                UpdatePartRevision(file,part,last_revision_); return true;
            }
        }
        if(!empty) return false; // never evict an unverified contributor
        *empty={file,part,source,bytes,++last_revision_,0};
        UpdatePartRevision(file,part,last_revision_); return true;
    }
    std::vector<DirectPartReceipt> Snapshot(const DirectFileKey& file,std::uint32_t part,std::uint64_t hashGeneration) const {
        std::vector<DirectPartReceipt> result;
        if(!hashGeneration) return result;
        for(const auto& record:records_) if(record.revision && record.file.lifetime==file.lifetime && record.file.hash==file.hash && record.part==part) {
            auto copy=record; copy.hash_generation=hashGeneration; result.push_back(copy);
        }
        return result;
    }
    std::optional<DirectPartReceipt> TakeVerified(const DirectPartReceipt& receipt,std::uint64_t currentHashGeneration,PartVerification proof) noexcept {
        if(proof!=PartVerification::Verified || !currentHashGeneration || receipt.hash_generation!=currentHashGeneration) return std::nullopt;
        for(auto& record:records_) if(record.revision && record.revision==receipt.revision && record.part_revision==receipt.part_revision && record.bytes==receipt.bytes && Same(record,receipt.file,receipt.part,receipt.source)) {
            const auto accepted=receipt; record={}; return accepted;
        }
        return std::nullopt;
    }
    void DiscardFile(const DirectFileKey& file) noexcept {
        for(auto& record:records_) if(record.file.lifetime==file.lifetime && record.file.hash==file.hash) record={};
    }
    std::size_t DiscardHandle(DirectHandle handle) noexcept {
        std::size_t removed=0;
        for(auto& record:records_) if(record.revision && record.source.handle.slot==handle.slot &&
            record.source.handle.generation==handle.generation) { record={}; ++removed; }
        return removed;
    }
    void Clear() noexcept {
        for(auto& record:records_) record={}; // revision counter never reset
    }
    void InvalidateRange(const DirectFileKey& file,std::uint32_t first,std::uint32_t last,bool discard=false) noexcept {
        if(last<first) return;
        const bool exhausted=last_revision_==(std::numeric_limits<std::uint64_t>::max)();
        const auto revision=exhausted ? last_revision_ : ++last_revision_;
        for(auto& record:records_) if(record.revision && record.file.lifetime==file.lifetime &&
            record.file.hash==file.hash && record.part>=first && record.part<=last) {
            if(discard || exhausted) record={};
            else record.part_revision=revision;
        }
    }
    // Retiring a delivery must not leave receipts eligible for a later session.
    // Match the complete identity: owner IDs alone may be reused by a new host.
    std::size_t DiscardSource(const DirectPartContributor& source) noexcept {
        std::size_t removed=0;
        for(auto& record:records_) if(record.revision && SameSource(record.source,source)) {
            record={}; ++removed;
        }
        return removed;
    }
private:
    static bool SameSource(const DirectPartContributor& old,const DirectPartContributor& source) noexcept {
        return old.kind==source.kind && old.owner==source.owner && old.handle.slot==source.handle.slot && old.handle.generation==source.handle.generation &&
            old.route==source.route && old.epoch==source.epoch && old.topology==source.topology;
    }
    void UpdatePartRevision(const DirectFileKey& file,std::uint32_t part,std::uint64_t revision) noexcept {
        for(auto& record:records_) if(record.revision && record.file.lifetime==file.lifetime && record.file.hash==file.hash && record.part==part)
            record.part_revision=revision;
    }
    static bool Same(const DirectPartReceipt& record,const DirectFileKey& file,std::uint32_t part,const DirectPartContributor& source) noexcept {
        return record.file.lifetime==file.lifetime && record.file.hash==file.hash && record.part==part &&
            SameSource(record.source,source);
    }
    std::array<DirectPartReceipt,Capacity> records_{};
    std::uint64_t last_revision_=0;
};
}
