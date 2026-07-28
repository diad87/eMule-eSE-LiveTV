#pragma once

#include "natmap/mapper_result.h"

#include <cstddef>
#include <cstdint>
#include <deque>
#include <mutex>

namespace natmap {

enum class MailboxPublishStatus : std::uint8_t {
    Published = 0,
    InvalidEnvelope = 1,
    Full = 2,
    Exhausted = 3,
    Closed = 4,
};

struct MailboxPublish {
    MailboxPublishStatus status =
        MailboxPublishStatus::InvalidEnvelope;
    std::uint32_t delivery_id = 0;

    bool IsPublished() const noexcept {
        return status == MailboxPublishStatus::Published &&
               delivery_id != 0;
    }
};

// Process-local, value-only handoff from mapper workers to the UI thread.
// Delivery IDs fit in the low 31 bits of WPARAM; zero and the high marker bit
// are never issued. Entries are taken by exact ID, so message order and the
// currently selected concrete mapper cannot redirect a result.
class MappingResultMailbox {
public:
    static constexpr std::size_t kMaximumPending = 64;
    static constexpr std::uint32_t kMaximumDeliveryId = 0x7fffffffu;

    explicit MappingResultMailbox(
        std::uint32_t first_delivery_id = 1) noexcept;
    MappingResultMailbox(const MappingResultMailbox&) = delete;
    MappingResultMailbox& operator=(const MappingResultMailbox&) = delete;
    MappingResultMailbox(MappingResultMailbox&&) = delete;
    MappingResultMailbox& operator=(MappingResultMailbox&&) = delete;

    MailboxPublish Publish(const MapperResultData& data);
    bool Take(std::uint32_t delivery_id, MapperResultData& data);
    bool Discard(std::uint32_t delivery_id);
    void Clear() noexcept;
    bool Close() noexcept;
    std::size_t pending_count() const noexcept;

private:
    struct Entry {
        std::uint32_t delivery_id = 0;
        MapperResultData data{};
    };

    mutable std::mutex mutex_;
    std::deque<Entry> entries_;
    std::uint32_t next_delivery_id_ = 1;
    bool exhausted_ = false;
    bool closed_ = false;
};

static_assert(
    static_cast<std::uint8_t>(MailboxPublishStatus::Exhausted) == 3,
    "mailbox publish status persistence contract changed");
static_assert(
    static_cast<std::uint8_t>(MailboxPublishStatus::Closed) == 4,
    "mailbox close status persistence contract changed");

} // namespace natmap
