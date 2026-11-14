#pragma once
#include "EseServerPublication.h"

namespace ese::server {
class PublicationStore {
public:
    explicit PublicationStore(const Bytes32& emptyDigest);
    const PublishState& State() const noexcept { return visible_; }
    void Expire(std::uint64_t now) noexcept;
    std::uint16_t Begin(const PublishState& desired,std::uint64_t now);
    std::uint16_t Chunk(ByteView payload,std::uint64_t now);
    std::uint16_t Commit(std::uint64_t revision,const Bytes32& digest,AuthCrypto&,
        std::uint64_t now);

private:
    struct Range { std::size_t offset,size; };
    struct Pending {
        PublishState desired;
        std::uint32_t count=0;
        std::uint64_t until=0;
        std::array<std::uint8_t,24> lastKey{};
        std::vector<std::uint8_t> canonical;
        std::vector<Range> chunks;
    };
    std::uint16_t Conflict() noexcept;
    PublishState visible_;
    std::vector<std::uint8_t> canonical_;
    std::optional<Pending> pending_;
};
}
