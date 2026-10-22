#pragma once
#include <cstdint>
#include <limits>
namespace ese {
struct BlockPacketBounds {
    std::uint64_t start=0,end=0;
    std::uint32_t header=0,payload=0;
};
// eD2K block offsets are little endian. Validate without unaligned casts,
// allocation, client state changes or overflow of an exclusive end offset.
inline bool ReadBlockPacketBounds(const std::uint8_t* packet,std::uint32_t size,
    bool packed,bool wide,BlockPacketBounds& out) noexcept {
    out={};
    const std::uint32_t width=wide ? 8U : 4U;
    const std::uint32_t header=16U+width+(packed ? 4U : width);
    if(!packet || size<=header) return false;
    auto read=[&](std::uint32_t position,std::uint32_t bytes) {
        std::uint64_t result=0;
        for(std::uint32_t i=0;i<bytes;++i) result|=std::uint64_t(packet[position+i])<<(i*8);
        return result;
    };
    const auto start=read(16,width);
    const auto payload=size-header;
    std::uint64_t end=0;
    if(packed) {
        // This end bounds the compressed wire fragment, not inflated data.
        if(start>(std::numeric_limits<std::uint64_t>::max)()-payload) return false;
        end=start+payload;
    } else {
        end=read(16+width,width);
        if(end<=start || end-start!=payload) return false;
    }
    out={start,end,header,payload}; return true;
}
}
