// SPDX-License-Identifier: MIT
// Class-5 fixed-record scheduler.  Hosts instantiate one scheduler per
// (circuit mapping, direction); arrival timing never determines a send slot.
#pragma once

#include "kad6/kad6_shaped_bulk.h"

#include <cstddef>
#include <cstdint>
#include <deque>
#include <vector>

namespace kad6 {

constexpr std::uint32_t kK6ShapeMinBucketKiB = 64;
constexpr std::uint32_t kK6ShapeMaxBucketKiB = 4096;
constexpr std::uint32_t kK6ShapeMinReservoirMs = 2000;
constexpr std::uint32_t kK6ShapeMaxReservoirMs = 5000;
constexpr std::uint64_t kK6ShapeEpochUs = 30ull * 1000 * 1000;
constexpr std::size_t kK6ShapeMaxStreams = 64;
constexpr std::size_t kK6ShapeMaxReservoirRecords = 2048;

enum class K6ShapeSlotKind : Byte { Data = 1, Padding = 2 };

struct K6ShapeSlot {
    K6ShapeSlotKind kind = K6ShapeSlotKind::Padding;
    std::uint64_t stream_id = 0;
    std::uint64_t epoch = 0;
    std::uint64_t scheduled_us = 0;
};

class K6Class5Scheduler {
public:
    Kad6Status Configure(std::uint32_t bucket_kib_per_second,
                         std::uint32_t reservoir_ms,
                         std::uint64_t now_us,
                         std::uint64_t independent_phase_seed) noexcept;

    // Queue one or more already-shaped logical records for a stream. False
    // means bounded reservoir overflow; exposed() then remains sticky.
    bool Enqueue(std::uint64_t stream_id, std::size_t records = 1) noexcept;

    // Emits at most one decision (and therefore never a catch-up burst), while
    // respecting a zero `maximum`. Empty queues emit Padding. Missing a full
    // interval rephases at now and marks exposure sticky.
    std::size_t Poll(std::uint64_t now_us, std::size_t maximum,
                     std::vector<K6ShapeSlot>& out) noexcept;

    std::uint64_t slot_interval_us() const noexcept { return slot_interval_us_; }
    std::uint64_t next_slot_us() const noexcept { return next_slot_us_; }
    std::size_t reservoir_capacity() const noexcept { return reservoir_capacity_; }
    std::size_t queued_records() const noexcept { return queued_records_; }
    bool exposed() const noexcept { return exposed_; }
    bool configured() const noexcept { return configured_; }
    void ClearExposure() noexcept { exposed_ = false; }

private:
    struct StreamQueue { std::uint64_t id = 0; std::size_t records = 0; };
    std::uint64_t NextIntervalUs() noexcept;
    std::deque<StreamQueue> streams_;
    std::uint64_t slot_interval_us_ = 0;
    std::uint64_t next_slot_us_ = 0;
    std::uint64_t epoch_origin_us_ = 0;
    std::uint64_t jitter_seed_ = 0;
    std::uint64_t interval_sequence_ = 0;
    std::size_t reservoir_capacity_ = 0;
    std::size_t queued_records_ = 0;
    bool configured_ = false;
    bool exposed_ = false;
};

} // namespace kad6
