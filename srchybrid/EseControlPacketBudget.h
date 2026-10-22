#pragma once
#include <array>
#include <cstdint>
#include <cstddef>
namespace ese { namespace control {
// One shared owner must pass this budget to all its control senders. Charging
// occurs before socket submission, including WOULD_BLOCK: failure cannot mint
// fresh capacity. No reset on operation cancellation; no QUIC data charging.
class PacketBudget {
public:
    bool Allow(std::uint64_t now) noexcept {
        if(clockSet_ && now<last_) return false;
        clockSet_=true; last_=now;
        while(size_ && now-times_[head_]>=1000) {
            head_=(head_+1)%times_.size(); --size_;
        }
        if(size_==times_.size()) return false;
        times_[(head_+size_)%times_.size()]=now; ++size_; return true;
    }
private:
    std::array<std::uint64_t,100> times_{};
    std::size_t head_=0,size_=0;
    std::uint64_t last_=0;
    bool clockSet_=false;
};
} }
