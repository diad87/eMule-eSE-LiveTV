#pragma once
#include "EseServerAuth.h"

namespace ese::server {
inline constexpr std::uint32_t MaxPublicationRecords=4096;
inline constexpr std::uint16_t MaxPublicationChunkRecords=128;

struct PublishState {
    std::uint64_t revision=0;
    std::uint32_t records=0;
    Bytes32 digest{};
};
struct PublishChunk {
    std::uint64_t revision=0;
    std::uint32_t index=0;
    std::uint16_t records=0;
    ByteView canonicalRecords;
    ByteView firstKey, lastKey; // byte-ordered hash16 and big-endian size64
};

bool DecodePublishState(ByteView,PublishState&) noexcept;
std::array<std::uint8_t,44> EncodePublishState(const PublishState&) noexcept;
bool DecodePublishChunk(ByteView,PublishChunk&) noexcept;
bool DecodePublishCommit(ByteView,std::uint64_t& revision,Bytes32& digest) noexcept;
}
