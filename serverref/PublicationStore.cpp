#include "PublicationStore.h"
#include <algorithm>
#include <cstring>
#include <limits>

namespace ese::server {
namespace {
constexpr std::uint64_t StageMilliseconds=30000;
constexpr std::size_t MaximumCanonicalBytes=MaxPublicationRecords*(16+8+2+255+1);

std::uint64_t StageDeadline(std::uint64_t now) noexcept
{
    const auto max=(std::numeric_limits<std::uint64_t>::max)();
    return now>max-StageMilliseconds ? max : now+StageMilliseconds;
}

bool SameState(const PublishState& left,const PublishState& right) noexcept
{
    return left.revision==right.revision && left.records==right.records && left.digest==right.digest;
}
}

PublicationStore::PublicationStore(const Bytes32& emptyDigest) : visible_{0,0,emptyDigest} {}

void PublicationStore::Expire(std::uint64_t now) noexcept
{
    if(pending_ && now>=pending_->until) pending_.reset();
}

std::uint16_t PublicationStore::Begin(const PublishState& desired,std::uint64_t now)
{
    Expire(now);
    if(!desired.revision || desired.records>MaxPublicationRecords) return kEseWireServerMalformed;
    if(desired.revision==visible_.revision)
        return SameState(desired,visible_) ? 0 : kEseWireServerConflict;
    if(desired.revision<visible_.revision) return kEseWireServerConflict;
    if(pending_) {
        if(desired.revision<pending_->desired.revision) return kEseWireServerConflict;
        if(desired.revision==pending_->desired.revision)
            return SameState(desired,pending_->desired) ? 0 : kEseWireServerConflict;
    }
    Pending next;
    next.desired=desired;
    next.until=StageDeadline(now);
    pending_=std::move(next);
    return 0;
}

std::uint16_t PublicationStore::Conflict() noexcept
{
    pending_.reset();
    return kEseWireServerConflict;
}

std::uint16_t PublicationStore::Chunk(ByteView payload,std::uint64_t now)
{
    Expire(now);
    PublishChunk chunk;
    if(!DecodePublishChunk(payload,chunk)) return kEseWireServerMalformed;
    if(!pending_ || pending_->desired.revision!=chunk.revision) return kEseWireServerWrongState;
    auto& stage=*pending_;
    if(chunk.index<stage.chunks.size()) {
        const auto range=stage.chunks[chunk.index];
        if(range.size!=chunk.canonicalRecords.size ||
            std::memcmp(stage.canonical.data()+range.offset,chunk.canonicalRecords.data,range.size)!=0)
            return Conflict();
        return 0; // Idempotent replay does not renew the staging deadline.
    }
    if(chunk.index!=stage.chunks.size() || chunk.records>stage.desired.records-stage.count ||
        (stage.count && std::memcmp(stage.lastKey.data(),chunk.firstKey.data,stage.lastKey.size())>=0))
        return Conflict();
    if(chunk.canonicalRecords.size>MaximumCanonicalBytes-stage.canonical.size()) return kEseWireServerResourceLimit;
    // Reserve both allocations before changing the contents, so a failure
    // cannot leave the chunk cursor and canonical byte buffer out of sync.
    const auto offset=stage.canonical.size();
    if(stage.chunks.size()==stage.chunks.capacity())
        stage.chunks.reserve((std::min)(std::size_t{stage.desired.records},
            (std::max)(std::size_t{8},stage.chunks.capacity()*2)));
    const auto needed=offset+chunk.canonicalRecords.size;
    if(needed>stage.canonical.capacity())
        stage.canonical.reserve((std::min)(MaximumCanonicalBytes,
            (std::max)(needed,stage.canonical.capacity()*2)));
    stage.canonical.insert(stage.canonical.end(),chunk.canonicalRecords.data,
        chunk.canonicalRecords.data+chunk.canonicalRecords.size);
    stage.chunks.push_back({offset,chunk.canonicalRecords.size});
    stage.count+=chunk.records;
    std::copy_n(chunk.lastKey.data,stage.lastKey.size(),stage.lastKey.begin());
    stage.until=StageDeadline(now);
    return 0;
}

std::uint16_t PublicationStore::Commit(std::uint64_t revision,const Bytes32& digest,AuthCrypto& crypto,
    std::uint64_t now)
{
    Expire(now);
    if(revision==visible_.revision) return digest==visible_.digest ? 0 : kEseWireServerConflict;
    if(!pending_ || pending_->desired.revision!=revision) return kEseWireServerWrongState;
    auto& stage=*pending_;
    if(stage.count!=stage.desired.records || digest!=stage.desired.digest) return Conflict();
    Bytes32 actual{};
    if(!crypto.Hash({stage.canonical.data(),stage.canonical.size()},actual)) return kEseWireServerResourceLimit;
    if(actual!=digest) return Conflict();
    canonical_.swap(stage.canonical);
    visible_=stage.desired;
    pending_.reset();
    return 0;
}
}
