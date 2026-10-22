// SPDX-License-Identifier: MIT
#pragma once
#include <atomic>
#include <cstdint>
#include <limits>
namespace reach {
// Process-wide, independent of manager construction or restart. Zero means
// exhaustion; never wrap to a lifetime formerly owned by a destroyed client.
class DirectClientLifetimeSequence {
public:
    std::uint64_t Next() noexcept {
        auto old=last_.load(std::memory_order_relaxed);
        while(old!=(std::numeric_limits<std::uint64_t>::max)()) {
            if(last_.compare_exchange_weak(old,old+1,std::memory_order_relaxed)) return old+1;
        }
        return 0;
    }
private:
    std::atomic<std::uint64_t> last_{0};
};
inline std::uint64_t NextDirectClientLifetime() noexcept {
    static DirectClientLifetimeSequence sequence;
    return sequence.Next();
}
inline std::uint64_t NextDirectFileLifetime() noexcept {
    static DirectClientLifetimeSequence sequence;
    return sequence.Next();
}
}
