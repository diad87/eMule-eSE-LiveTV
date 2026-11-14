#include "ServerIndex.h"

namespace ese::server {
ServerIndex::Entry* ServerIndex::Find(const Bytes32& node) noexcept
{
    for(auto& entry:entries_)
        if(entry && entry->node==node) return &*entry;
    return nullptr;
}

std::uint16_t ServerIndex::ActivatePrimary(const ClientHello& client,std::uint64_t generation,std::uint64_t lease)
{
    const std::lock_guard<std::mutex> lock(mutex_);
    auto* entry=Find(client.node);
    if(!entry) {
        for(auto& slot:entries_)
            if(!slot) {
                slot.emplace(Entry{client.node,client.userHash,generation,lease,PublicationStore(emptyDigest_)});
                return 0;
            }
        return kEseWireServerResourceLimit;
    }
    if(generation<=entry->generation) return kEseWireServerWrongState;
    entry->generation=generation;
    entry->lease=lease;
    entry->userHash=client.userHash;
    entry->publication.ClearStaging();
    return 0;
}

bool ServerIndex::CurrentPrimary(const Bytes32& node,std::uint64_t generation,std::uint64_t now)
{
    const std::lock_guard<std::mutex> lock(mutex_);
    const auto* entry=Find(node);
    return entry && entry->generation==generation && entry->lease>now;
}

void ServerIndex::Expire(std::uint64_t now)
{
    const std::lock_guard<std::mutex> lock(mutex_);
    for(auto& entry:entries_)
        if(entry) entry->publication.Expire(now);
}

void ServerIndex::Renew(const Bytes32& node,std::uint64_t generation,std::uint64_t lease)
{
    const std::lock_guard<std::mutex> lock(mutex_);
    auto* entry=Find(node);
    if(entry && entry->generation==generation && entry->lease) entry->lease=lease;
}

void ServerIndex::Deactivate(const Bytes32& node,std::uint64_t generation)
{
    const std::lock_guard<std::mutex> lock(mutex_);
    auto* entry=Find(node);
    if(entry && entry->generation==generation) {
        entry->lease=0;
        entry->publication.ClearStaging();
    }
}

std::uint16_t ServerIndex::Publish(const Bytes32& node,std::uint64_t generation,std::uint16_t type,
    ByteView payload,AuthCrypto& crypto,std::uint64_t now,PublishState& state)
{
    const std::lock_guard<std::mutex> lock(mutex_);
    auto* entry=Find(node);
    if(!entry || entry->generation!=generation || entry->lease<=now) return kEseWireServerWrongState;
    auto& publication=entry->publication;
    publication.Expire(now);
    switch(type) {
    case kEseWireServerPubStateGet:
        if(payload.size) return kEseWireServerMalformed;
        state=publication.State();
        return 0;
    case kEseWireServerPubBegin: {
        PublishState desired;
        return DecodePublishState(payload,desired) ? publication.Begin(desired,now) : kEseWireServerMalformed;
    }
    case kEseWireServerPubChunk:
        return publication.Chunk(payload,now);
    case kEseWireServerPubCommit: {
        std::uint64_t revision=0;
        Bytes32 digest{};
        return DecodePublishCommit(payload,revision,digest) ?
            publication.Commit(revision,digest,crypto,now) : kEseWireServerMalformed;
    }
    default:
        return kEseWireServerUnsupported;
    }
}

std::optional<std::vector<std::uint8_t>> ServerIndex::Hints(const Bytes32& requester,std::uint64_t primaryGeneration,
    const std::array<std::uint8_t,24>& key,std::uint64_t now)
{
    const std::lock_guard<std::mutex> lock(mutex_);
    if(primaryGeneration) {
        const auto* active=Find(requester);
        if(!active || active->generation!=primaryGeneration || active->lease<=now) return std::nullopt;
    }
    std::vector<std::uint8_t> result(2);
    result.reserve(2+entries_.size()*48);
    for(const auto& entry:entries_) {
        if(!entry || entry->lease<=now || !entry->publication.Contains(key)) continue;
        result.insert(result.end(),entry->node.begin(),entry->node.end());
        result.insert(result.end(),entry->userHash.begin(),entry->userHash.end());
        ++result[1];
    }
    return result;
}
}
