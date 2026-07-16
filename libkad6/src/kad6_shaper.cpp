// SPDX-License-Identifier: MIT
#include "kad6/kad6_shaper.h"

#include <algorithm>
#include <limits>

namespace kad6 {
namespace {
bool ValidBucket(std::uint32_t value) noexcept
{
    return value >= kK6ShapeMinBucketKiB && value <= kK6ShapeMaxBucketKiB
        && (value & (value - 1)) == 0;
}

std::uint64_t Mix64(std::uint64_t value) noexcept
{
    value += 0x9E3779B97F4A7C15ull;
    value = (value ^ (value >> 30)) * 0xBF58476D1CE4E5B9ull;
    value = (value ^ (value >> 27)) * 0x94D049BB133111EBull;
    return value ^ (value >> 31);
}
}

std::uint64_t K6Class5Scheduler::NextIntervalUs() noexcept
{
    // A locally seeded, zero-sum pair breaks an exact cadence without
    // changing the negotiated average rate.  Each first interval carries at
    // most +/-5% jitter and the following interval repays exactly that debt;
    // neither transition can collapse into a catch-up burst.
    const std::uint64_t maximum_jitter =
        (std::max<std::uint64_t>)(1, slot_interval_us_ / 20);
    const std::uint64_t pair = interval_sequence_ / 2;
    const std::uint64_t span = maximum_jitter * 2 + 1;
    std::int64_t jitter = static_cast<std::int64_t>(
        Mix64(jitter_seed_ + pair) % span) -
        static_cast<std::int64_t>(maximum_jitter);
    if ((interval_sequence_ & 1) != 0) jitter = -jitter;
    ++interval_sequence_;
    return static_cast<std::uint64_t>(
        static_cast<std::int64_t>(slot_interval_us_) + jitter);
}

Kad6Status K6Class5Scheduler::Configure(std::uint32_t bucket_kib_per_second,
                                        std::uint32_t reservoir_ms,
                                        std::uint64_t now_us,
                                        std::uint64_t independent_phase_seed) noexcept
{
    streams_.clear(); queued_records_ = 0; exposed_ = false; configured_ = false;
    interval_sequence_ = 0;
    if (!ValidBucket(bucket_kib_per_second)
        || reservoir_ms < kK6ShapeMinReservoirMs
        || reservoir_ms > kK6ShapeMaxReservoirMs)
        return Kad6Status::BadValue;
    const std::uint64_t bytes_per_second =
        static_cast<std::uint64_t>(bucket_kib_per_second) * 1024;
    slot_interval_us_ = (kK6ShapedTotal * 1000000ull + bytes_per_second - 1)
        / bytes_per_second;
    if (slot_interval_us_ == 0) return Kad6Status::BadValue;
    const std::uint64_t reservoir_bytes =
        (bytes_per_second * reservoir_ms + 999) / 1000;
    const std::uint64_t capacity =
        (reservoir_bytes + kK6ShapedTotal - 1) / kK6ShapedTotal;
    reservoir_capacity_ = static_cast<std::size_t>(
        (std::min<std::uint64_t>)(capacity, kK6ShapeMaxReservoirRecords));
    if (reservoir_capacity_ == 0) return Kad6Status::BadValue;
    epoch_origin_us_ = now_us;
    next_slot_us_ = now_us + (independent_phase_seed % slot_interval_us_);
    jitter_seed_ = Mix64(independent_phase_seed ^ 0x4B364A4954544552ull);
    configured_ = true;
    return Kad6Status::Ok;
}

bool K6Class5Scheduler::Enqueue(std::uint64_t stream_id, std::size_t records) noexcept
{
    if (!configured_ || stream_id == 0 || records == 0) return false;
    if (records > reservoir_capacity_ -
        (std::min)(queued_records_, reservoir_capacity_)) {
        exposed_ = true;
        return false;
    }
    for (StreamQueue& stream : streams_) {
        if (stream.id == stream_id) {
            stream.records += records;
            queued_records_ += records;
            return true;
        }
    }
    if (streams_.size() >= kK6ShapeMaxStreams) {
        exposed_ = true;
        return false;
    }
    streams_.push_back(StreamQueue{stream_id, records});
    queued_records_ += records;
    return true;
}

std::size_t K6Class5Scheduler::Poll(std::uint64_t now_us, std::size_t maximum,
                                    std::vector<K6ShapeSlot>& out) noexcept
{
    out.clear();
    if (!configured_ || maximum == 0 || now_us < next_slot_us_) return 0;
    // Missing a complete interval means the host can no longer honour the
    // negotiated shape. Mark it exposed and rephase at `now`; never send a
    // catch-up train whose burst would itself become a watermark.
    if (now_us - next_slot_us_ >= slot_interval_us_) {
        exposed_ = true;
        next_slot_us_ = now_us;
    }
    out.reserve(1);
    while (out.empty() && now_us >= next_slot_us_) {
        K6ShapeSlot slot;
        slot.epoch = (next_slot_us_ - epoch_origin_us_) / kK6ShapeEpochUs;
        slot.scheduled_us = next_slot_us_;
        if (!streams_.empty()) {
            StreamQueue stream = streams_.front();
            streams_.pop_front();
            slot.kind = K6ShapeSlotKind::Data;
            slot.stream_id = stream.id;
            --stream.records; --queued_records_;
            if (stream.records) streams_.push_back(stream); // record-level DRR
        }
        out.push_back(slot);
        const std::uint64_t interval = NextIntervalUs();
        if (next_slot_us_ > std::numeric_limits<std::uint64_t>::max()
                            - interval) {
            configured_ = false;
            break;
        }
        next_slot_us_ += interval;
    }
    return out.size();
}

} // namespace kad6
