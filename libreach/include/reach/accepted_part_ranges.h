// SPDX-License-Identifier: MIT
#pragma once
#include <cstdint>
#include <limits>
namespace reach {
// Only whole accepted ranges can be split. An aggregate count of unknown
// gaps is not enough to infer ownership. Validate everything before callbacks.
template<class Consumer>
bool ForEachAcceptedPart(std::uint64_t start,std::uint64_t end,
    std::uint32_t accepted,std::uint64_t partSize,Consumer&& consume) {
    if(!accepted || !partSize || end<start || end-start!=accepted-1) return false;
    const auto first=start/partSize,last=end/partSize;
    if(last>(std::numeric_limits<std::uint32_t>::max)() || last-first>=64) return false;
    auto position=start;
    std::uint64_t remaining=accepted;
    while(remaining) {
        const auto room=partSize-position%partSize;
        const auto count=remaining<room ? remaining : room;
        if(!consume(static_cast<std::uint32_t>(position/partSize),static_cast<std::uint32_t>(count))) return false;
        remaining-=count;
        if(remaining) position+=count; // do not overflow past UINT64_MAX at EOF
    }
    return true;
}
}
