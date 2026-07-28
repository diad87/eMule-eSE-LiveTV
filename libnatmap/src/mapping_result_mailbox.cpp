#include "natmap/mapping_result_mailbox.h"

#include "natmap/mapping_request.h"

#include <algorithm>

namespace natmap {

MappingResultMailbox::MappingResultMailbox(
    std::uint32_t first_delivery_id) noexcept
    : next_delivery_id_(first_delivery_id),
      exhausted_(first_delivery_id == 0 ||
                 first_delivery_id > kMaximumDeliveryId) {
}

MailboxPublish MappingResultMailbox::Publish(
    const MapperResultData& data) {
    const MappingRequestContext envelope{
        data.request_id, data.topology_generation, data.operation};
    if (!envelope.IsValid())
        return {MailboxPublishStatus::InvalidEnvelope, 0};

    std::lock_guard<std::mutex> lock(mutex_);
    if (closed_)
        return {MailboxPublishStatus::Closed, 0};
    if (exhausted_)
        return {MailboxPublishStatus::Exhausted, 0};
    if (entries_.size() >= kMaximumPending)
        return {MailboxPublishStatus::Full, 0};

    const std::uint32_t deliveryId = next_delivery_id_;
    entries_.push_back(Entry{deliveryId, data});
    if (next_delivery_id_ == kMaximumDeliveryId)
        exhausted_ = true;
    else
        ++next_delivery_id_;
    return {MailboxPublishStatus::Published, deliveryId};
}

bool MappingResultMailbox::Take(
    std::uint32_t delivery_id,
    MapperResultData& data) {
    if (delivery_id == 0 || delivery_id > kMaximumDeliveryId)
        return false;
    std::lock_guard<std::mutex> lock(mutex_);
    const std::deque<Entry>::iterator found = std::find_if(
        entries_.begin(), entries_.end(),
        [delivery_id](const Entry& entry) {
            return entry.delivery_id == delivery_id;
        });
    if (found == entries_.end())
        return false;
    data = found->data;
    entries_.erase(found);
    return true;
}

bool MappingResultMailbox::Discard(std::uint32_t delivery_id) {
    MapperResultData ignored{};
    return Take(delivery_id, ignored);
}

void MappingResultMailbox::Clear() noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    entries_.clear();
}

bool MappingResultMailbox::Close() noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    entries_.clear();
    if (closed_)
        return false;
    closed_ = true;
    return true;
}

std::size_t MappingResultMailbox::pending_count() const noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    return entries_.size();
}

} // namespace natmap
