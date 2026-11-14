#pragma once
#include "PublicationStore.h"
#include <mutex>

namespace ese::server {
// Scope and memory are deliberately bounded. The reference can retain at most
// sixteen unique identities in an epoch. With two 4096*282-byte snapshots
// per entry, canonical publication bytes cannot exceed 36 MiB.
class ServerIndex {
public:
    explicit ServerIndex(const Bytes32& emptyDigest) : emptyDigest_(emptyDigest) {}
    std::uint16_t ActivatePrimary(const ClientHello&,std::uint64_t generation,std::uint64_t lease);
    bool CurrentPrimary(const Bytes32& node,std::uint64_t generation,std::uint64_t now);
    void Expire(std::uint64_t now);
    void Renew(const Bytes32& node,std::uint64_t generation,std::uint64_t lease);
    void Deactivate(const Bytes32& node,std::uint64_t generation);
    std::uint16_t Publish(const Bytes32& node,std::uint64_t generation,std::uint16_t type,
        ByteView payload,AuthCrypto&,std::uint64_t now,PublishState& state);
    std::optional<std::vector<std::uint8_t>> Hints(const Bytes32& requester,std::uint64_t primaryGeneration,
        const std::array<std::uint8_t,24>& key,std::uint64_t now);
private:
    struct Entry {
        Bytes32 node;
        Bytes16 userHash;
        std::uint64_t generation = 0, lease = 0;
        PublicationStore publication;
    };

    Entry* Find(const Bytes32& node) noexcept;
    std::array<std::optional<Entry>,16> entries_{};
    Bytes32 emptyDigest_;
    std::mutex mutex_;
};
}
