// SPDX-License-Identifier: MIT
#include "reach/direct_event_queue.h"
#include <algorithm>

namespace reach {
DirectEnqueueStatus DirectEventQueue::TryPush(const DirectSessionEvent& event)
{
    if (!event.handle.generation || !event.topology_generation || !event.route_id ||
        !event.sequence || event.handle.slot >= 256 ||
        static_cast<unsigned>(event.type) > static_cast<unsigned>(DirectEventType::VerifiedPart) ||
        static_cast<unsigned>(event.reason) > static_cast<unsigned>(DirectReason::UnsupportedRemote))
        return DirectEnqueueStatus::Invalid;
    const bool terminal = event.type == DirectEventType::Closed ||
                          event.type == DirectEventType::AuthenticationFailed;
    const auto limit = terminal ? kDirectEventCapacity :
                                 kDirectEventCapacity - kDirectTerminalReserve;
    std::lock_guard<std::mutex> lock(mutex_);
    if (size_ >= limit) return DirectEnqueueStatus::WouldBlock;
    events_[(head_ + size_) % kDirectEventCapacity] = event;
    ++size_;
    return DirectEnqueueStatus::Accepted;
}

std::vector<DirectSessionEvent> DirectEventQueue::Drain(std::size_t maximum)
{
    maximum = std::min(maximum, kDirectEventCapacity);
    std::vector<DirectSessionEvent> result;
    result.reserve(maximum);
    std::lock_guard<std::mutex> lock(mutex_);
    const auto count = std::min(maximum, size_);
    for (std::size_t i = 0; i < count; ++i) {
        result.push_back(events_[head_]);
        events_[head_] = {};
        head_ = (head_ + 1) % kDirectEventCapacity;
    }
    size_ -= count;
    return result;
}

std::size_t DirectEventQueue::Size() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return size_;
}
bool DirectEventQueue::HasHandle(DirectHandle handle) const
{
    std::lock_guard<std::mutex> lock(mutex_);
    for(std::size_t i=0;i<size_;++i) {
        const auto& event=events_[(head_+i)%kDirectEventCapacity];
        if(event.handle.slot==handle.slot && event.handle.generation==handle.generation) return true;
    }
    return false;
}
} // namespace reach
