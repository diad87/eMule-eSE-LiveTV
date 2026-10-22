#pragma once
#include <cstdint>
#include <limits>
namespace ese { namespace mapping {
// Cadence only. A successful timer never authorizes a mapping or a route.
class ReadbackSchedule {
public:
    bool Activate(std::uint32_t lifetime,std::uint64_t now) noexcept {
        Clear(); auto seconds=lifetime ? lifetime/4 : 60U;
        if(seconds<5) seconds=5;
        if(seconds>60) seconds=60;
        interval_=seconds*1000ULL;
        if(now>(std::numeric_limits<std::uint64_t>::max)()-interval_) { Clear(); return false; }
        next_=now+interval_; active_=true; return true;
    }
    bool Due(std::uint64_t now) const noexcept { return active_ && now>=next_; }
    bool Mark(std::uint64_t now) noexcept {
        if(!Due(now) || now>(std::numeric_limits<std::uint64_t>::max)()-interval_) return false;
        next_=now+interval_; return true;
    }
    void Clear() noexcept { interval_=next_=0; active_=false; }
    std::uint64_t Next() const noexcept { return next_; }
    std::uint64_t Interval() const noexcept { return interval_; }
private:
    std::uint64_t interval_=0,next_=0; bool active_=false;
};
}}
