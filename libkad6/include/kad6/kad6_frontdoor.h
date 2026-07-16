// SPDX-License-Identifier: MIT
// K6-5 bounded pre-authentication gate and single-backend cohort scheduler.
#pragma once

#include "kad6/kad6_types.h"

#include <array>
#include <cstddef>
#include <cstdint>

namespace kad6 {

constexpr std::size_t kK6PreAuthMaxSlots = 512;
constexpr std::size_t kK6PreAuthMaxHelloBytes = 512;
constexpr std::size_t kK6PreAuthMaxV4Per32 = 4;
constexpr std::size_t kK6PreAuthMaxV6Per64 = 8;
constexpr std::uint64_t kK6PreAuthDeadlineMs = 10000;
constexpr std::uint64_t kK6PreAuthRateGraceMs = 2000;
constexpr std::uint64_t kK6PreAuthMinBytesPerSecond = 128;

struct K6RemoteGroup {
    Byte family = 0; // 4 or 6
    std::array<Byte, 16> address{};
};

enum class K6PreAuthDecision : Byte { NeedMore = 0, Ready = 1, Reject = 2 };

struct K6PreAuthStats {
    std::uint64_t admitted = 0;
    std::uint64_t rejected_capacity = 0;
    std::uint64_t rejected_group = 0;
    std::uint64_t rejected_protocol = 0;
    std::uint64_t timed_out = 0;
    std::uint64_t promoted = 0;
    std::size_t active = 0;
    std::size_t peak = 0;
};

class K6PreAuthGate {
public:
    // Returns a stable slot index or -1. The class has fixed storage and does
    // not allocate per connection.
    int Admit(const K6RemoteGroup& group, std::uint64_t now_ms) noexcept;
    K6PreAuthDecision Observe(std::size_t slot, const Byte* peeked,
                              std::size_t peeked_len, std::uint64_t now_ms,
                              std::size_t* hello_frame_size = nullptr) noexcept;
    K6PreAuthDecision Tick(std::size_t slot, std::uint64_t now_ms) noexcept;
    void Release(std::size_t slot) noexcept;
    bool IsActive(std::size_t slot) const noexcept;
    const K6PreAuthStats& Stats() const noexcept { return stats_; }

private:
    struct Slot {
        K6RemoteGroup group{};
        std::uint64_t accepted_at_ms = 0;
        std::size_t observed_bytes = 0;
        bool active = false;
    };
    K6PreAuthDecision CheckTime(Slot& slot, std::uint64_t now_ms) noexcept;
    std::array<Slot, kK6PreAuthMaxSlots> slots_{};
    K6PreAuthStats stats_{};
};

constexpr std::size_t kK6CohortMaxBackends = 512;
constexpr std::size_t kK6CohortMaxStreams = 512;

struct K6CohortBackend {
    std::uint64_t lease_id = 0;
    std::uint32_t circuit_id = 0;
    Hash16 file_hash{};
    Hash16 cohort_id{};
    bool serving = false;
};

// Fixed-capacity selector. A stream is pinned to exactly one backend until it
// is released; selection never returns or broadcasts to multiple origins.
class K6CohortScheduler {
public:
    void Reset() noexcept;
    bool Register(const K6CohortBackend& backend) noexcept;
    bool Unregister(std::uint64_t lease_id) noexcept;
    bool SetServing(std::uint64_t lease_id, bool serving) noexcept;
    bool Select(const Hash16& file_hash, const Hash16& cohort_id,
                std::uint64_t stream_id, K6CohortBackend& selected) noexcept;
    bool ReleaseStream(std::uint64_t stream_id) noexcept;
    std::size_t BackendCount() const noexcept;
    std::size_t PinnedCount() const noexcept;

private:
    struct BackendSlot {
        K6CohortBackend value{};
        std::uint64_t served_streams = 0;
        bool used = false;
    };
    struct StreamPin { std::uint64_t stream_id = 0; std::uint64_t lease_id = 0; bool used = false; };
    std::array<BackendSlot, kK6CohortMaxBackends> backends_{};
    std::array<StreamPin, kK6CohortMaxStreams> pins_{};
    std::size_t cursor_ = 0; // tie-breaker only; fairness is per backend/cohort
};

} // namespace kad6
