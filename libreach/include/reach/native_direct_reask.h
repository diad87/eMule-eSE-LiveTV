// SPDX-License-Identifier: MIT
#pragma once
#include <cstdint>
#include <limits>
namespace reach {
// Owned scheduler gate. All time comes from the caller's monotonic clock,
// allowing deterministic tests without sleeping or renewing source leases.
class NativeDirectReaskGate {
public:
    bool Allow(std::uint64_t now,std::uint64_t generation) noexcept {
        if(!Observe(generation)) return false;
        return !pending_ && !exhausted_ && now>=until_;
    }
    void Defer(std::uint64_t now) noexcept {
        constexpr std::uint64_t cooldown=60000;
        const auto maximum=(std::numeric_limits<std::uint64_t>::max)();
        exhausted_=now>maximum-cooldown;
        until_=exhausted_ ? maximum : now+cooldown;
    }
    void Negotiating(bool pending) noexcept { pending_=pending; }
    void Ended(std::uint64_t now,std::uint64_t generation) noexcept {
        Observe(generation); pending_=false; Defer(now);
    }
private:
    bool Observe(std::uint64_t generation) noexcept {
        if(!generation) return false;
        if(generation_!=generation) { generation_=generation; until_=0; exhausted_=false; }
        return true; // A topology change never clears a still-live negotiation.
    }
    std::uint64_t generation_=0,until_=0;
    bool pending_=false,exhausted_=false;
};
}
