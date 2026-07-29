// this file is part of eMule eSE - tunnel scheduling and deferred-work owner
#pragma once

#include "kad6/kad6_hardening.h"
#include "kad6/kad6_release.h"

#include <cstddef>
#include <cstdint>
#include <deque>
#include <mutex>
#include <vector>

namespace eSELive {

enum class LiveDeferredOp : std::uint8_t {
    Send = 1,
    Build1Hop = 2,
    Build2Hop = 3,
    SendMessage = 4,
    Build3Hop = 5,
    K6ServiceSwitch = 6,
    K6ReleaseSwitch = 7,
};

struct LiveDeferredWork {
    LiveDeferredOp op = LiveDeferredOp::Send;
    std::uint32_t reqId = 0;
    std::uint8_t subCmd = 0;
    std::uint32_t requiredExitCaps = 0;
    std::uint32_t pinnedCircId = 0;
    std::uint64_t k6StreamId = 0;
    std::size_t k6FlowBytes = 0;
    std::uint64_t k6Sequence = 0;
    std::size_t k6DataBytes = 0;
    kad6::K6Service k6Service = kad6::K6Service::Control;
    bool k6Enable = true;
    std::uint32_t k6DrainSeconds = 0;
    bool k6HasReleaseEvidence = false;
    kad6::K6ReleaseEvidence k6ReleaseEvidence;
    std::vector<std::uint8_t> payload;
};

struct LiveDeferredFlowUsage {
    std::size_t stream_messages = 0;
    std::size_t stream_bytes = 0;
    std::size_t global_bytes = 0;
};

class LiveTunnelScheduler {
public:
    static const std::size_t kDefaultDrainBudget = 256;

    LiveTunnelScheduler() = default;
    LiveTunnelScheduler(const LiveTunnelScheduler&) = delete;
    LiveTunnelScheduler& operator=(const LiveTunnelScheduler&) = delete;

    bool Enqueue(LiveDeferredWork work);
    std::vector<LiveDeferredWork> EnqueueBatch(
        std::vector<LiveDeferredWork> work);
    bool TryTake(LiveDeferredWork& work);
    std::size_t PendingCount() const;
    LiveDeferredFlowUsage MeasureK6Flow(std::uint64_t stream_id) const;
    std::vector<LiveDeferredWork> CloseDeferredWork();
    void ReopenDeferredWork();
    bool AcceptingDeferredWork() const;

    static std::uint32_t Elapsed32(std::uint32_t now,
                                   std::uint32_t since) noexcept;
    static bool HasElapsed32(std::uint32_t now, std::uint32_t since,
                             std::uint32_t interval) noexcept;
    static bool HasStrictlyElapsed32(std::uint32_t now, std::uint32_t since,
                                     std::uint32_t interval) noexcept;
    static bool DeadlineReached32(std::uint32_t now,
                                  std::uint32_t deadline) noexcept;
    static std::uint64_t Elapsed64(std::uint64_t now,
                                   std::uint64_t since) noexcept;

    bool DueRttProbe(std::uint32_t now, std::uint32_t interval) noexcept;
    bool DueBulkSubscription(std::uint32_t now,
                             std::uint32_t interval) const noexcept;
    void MarkBulkSubscription(std::uint32_t now) noexcept;
    void RecordTick(std::uint32_t now) noexcept;
    std::uint32_t LastTick() const noexcept;

    bool HasClass5Timer() const noexcept;
    std::uintptr_t Class5TimerToken() const noexcept;
    bool PublishClass5Timer(std::uintptr_t token) noexcept;
    std::uintptr_t ReleaseClass5Timer() noexcept;
    bool ShouldStopClass5Timer(bool has_shaped_links,
                               bool fair_work_active) const noexcept;

private:
    mutable std::mutex m_deferred_mutex;
    std::deque<LiveDeferredWork> m_deferred_work;
    bool m_accepting_deferred_work = true;
    std::uint32_t m_last_tick = 0;
    std::uint32_t m_last_rtt_probe = 0;
    std::uint32_t m_last_bulk_subscription = 0;
    std::uintptr_t m_class5_timer = 0;
};

bool RunLiveTunnelSchedulerCharacterizationSelfTest();

} // namespace eSELive
