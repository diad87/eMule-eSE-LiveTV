#pragma once
#include <cstdint>

namespace ese {
// GetTickCount elapsed time, including one 32-bit rollover. Intervals used
// by the download scheduler are far shorter than the 49-day counter period.
// Zero preserves the existing "never asked" timestamp convention.
constexpr std::uint32_t FileReaskRemaining(std::uint32_t last,
    std::uint32_t now,std::uint32_t interval) noexcept {
    if(!last) return 0;
    const std::uint32_t elapsed=now-last;
    return elapsed>=interval ? 0 : interval-elapsed;
}
}
