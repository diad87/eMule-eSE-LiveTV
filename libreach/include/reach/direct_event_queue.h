// SPDX-License-Identifier: MIT
#pragma once
#include "reach/direct_session.h"
#include <mutex>

namespace reach {
inline constexpr std::size_t kDirectEventCapacity = 4096;
inline constexpr std::size_t kDirectTerminalReserve = 256;
enum class DirectEnqueueStatus : std::uint8_t { Accepted, WouldBlock, Invalid };

// Thread-safe scalar control-event queue. No host pointers, callbacks or
// transport locks cross this boundary. A full queue leaves ownership with
// the producer, which must retry; Accepted means exactly one stored copy.
class DirectEventQueue {
public:
    DirectEnqueueStatus TryPush(const DirectSessionEvent& event);
    std::vector<DirectSessionEvent> Drain(std::size_t maximum = kDirectEventCapacity);
    std::size_t Size() const;
    bool HasHandle(DirectHandle) const;
private:
    mutable std::mutex mutex_;
    std::array<DirectSessionEvent, kDirectEventCapacity> events_{};
    std::size_t head_ = 0;
    std::size_t size_ = 0;
};
} // namespace reach
