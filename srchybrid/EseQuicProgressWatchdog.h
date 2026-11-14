#pragma once
#include <algorithm>
#include <cstdint>

namespace ese {
// Counts only time during which the application is waiting for useful work.
// All samples are made by the owner thread. ACKs for control do not count.
class QuicProgressWatchdog {
public:
    enum class Action { None, Probe, Recover };

    Action Observe(std::uint64_t now, bool waiting, std::uint64_t progress,
        std::uint64_t smoothedRttMs) noexcept
    {
        if (!waiting) {
            *this = {};
            return Action::None;
        }
        if (!armed_ || now < since_ || progress != progress_) {
            armed_ = true;
            since_ = now;
            progress_ = progress;
            probed_ = false;
            // Bound the multiply before applying the 15 s minimum.
            window_ = (std::max)(std::uint64_t{15000},
                8 * (std::min)(smoothedRttMs, std::uint64_t{7500}));
            return Action::None;
        }
        const auto elapsed = now - since_;
        if (elapsed >= 2 * window_)
            return Action::Recover;
        if (!probed_ && elapsed >= window_) {
            probed_ = true;
            return Action::Probe;
        }
        return Action::None;
    }

private:
    std::uint64_t since_ = 0;
    std::uint64_t progress_ = 0;
    std::uint64_t window_ = 15000;
    bool armed_ = false;
    bool probed_ = false;
};
}
