#pragma once
#include <cstdint>
namespace ese { namespace classic {
// One fallback reservation per explicit connection cycle. Duplicate LowID
// packets cannot extend it. Cancellation does not replenish the budget.
class ServerCallbackRetry {
public:
    void Reset() noexcept { used_=pending_=false; generation_=0; }
    bool Reserve(std::uint64_t generation) noexcept {
        if (!generation || used_) return false;
        used_=pending_=true; generation_=generation; return true;
    }
    bool Consume(std::uint64_t current) noexcept {
        if (!pending_) return false;
        pending_=false; return current && current==generation_;
    }
    void CancelPending() noexcept { pending_=false; }
    bool Pending() const noexcept { return pending_; }
    bool Used() const noexcept { return used_; }
private:
    std::uint64_t generation_=0;
    bool used_=false,pending_=false;
};
}}
