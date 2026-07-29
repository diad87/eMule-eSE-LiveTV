// this file is part of eMule eSE - tunnel scheduling and deferred-work owner
#include "LiveTunnelScheduler.h"

#include <algorithm>
#include <limits>
#include <utility>

namespace eSELive {

void LiveTunnelScheduler::Enqueue(LiveDeferredWork work)
{
    std::lock_guard<std::mutex> lock(m_deferred_mutex);
    m_deferred_work.push_back(std::move(work));
}

void LiveTunnelScheduler::EnqueueBatch(std::vector<LiveDeferredWork> work)
{
    if (work.empty())
        return;

    std::lock_guard<std::mutex> lock(m_deferred_mutex);
    for (std::size_t index = 0; index < work.size(); ++index)
        m_deferred_work.push_back(std::move(work[index]));
}

bool LiveTunnelScheduler::TryTake(LiveDeferredWork& work)
{
    std::lock_guard<std::mutex> lock(m_deferred_mutex);
    if (m_deferred_work.empty())
        return false;

    work = std::move(m_deferred_work.front());
    m_deferred_work.pop_front();
    return true;
}

std::size_t LiveTunnelScheduler::PendingCount() const
{
    std::lock_guard<std::mutex> lock(m_deferred_mutex);
    return m_deferred_work.size();
}

LiveDeferredFlowUsage LiveTunnelScheduler::MeasureK6Flow(
    std::uint64_t stream_id) const
{
    LiveDeferredFlowUsage usage;
    std::lock_guard<std::mutex> lock(m_deferred_mutex);
    for (const LiveDeferredWork& work : m_deferred_work) {
        if (work.k6StreamId == 0)
            continue;
        usage.global_bytes += work.k6FlowBytes;
        if (work.k6StreamId == stream_id) {
            ++usage.stream_messages;
            usage.stream_bytes += work.k6FlowBytes;
        }
    }
    return usage;
}

std::size_t LiveTunnelScheduler::ClearDeferredWork()
{
    std::lock_guard<std::mutex> lock(m_deferred_mutex);
    const std::size_t count = m_deferred_work.size();
    m_deferred_work.clear();
    return count;
}

std::uint32_t LiveTunnelScheduler::Elapsed32(
    std::uint32_t now, std::uint32_t since) noexcept
{
    return now - since;
}

bool LiveTunnelScheduler::HasElapsed32(
    std::uint32_t now, std::uint32_t since, std::uint32_t interval) noexcept
{
    return Elapsed32(now, since) >= interval;
}

bool LiveTunnelScheduler::HasStrictlyElapsed32(
    std::uint32_t now, std::uint32_t since, std::uint32_t interval) noexcept
{
    return Elapsed32(now, since) > interval;
}

bool LiveTunnelScheduler::DeadlineReached32(
    std::uint32_t now, std::uint32_t deadline) noexcept
{
    return static_cast<std::int32_t>(now - deadline) >= 0;
}

std::uint64_t LiveTunnelScheduler::Elapsed64(
    std::uint64_t now, std::uint64_t since) noexcept
{
    return now - since;
}

bool LiveTunnelScheduler::DueRttProbe(
    std::uint32_t now, std::uint32_t interval) noexcept
{
    if (!HasElapsed32(now, m_last_rtt_probe, interval))
        return false;
    m_last_rtt_probe = now;
    return true;
}

bool LiveTunnelScheduler::DueBulkSubscription(
    std::uint32_t now, std::uint32_t interval) const noexcept
{
    return HasStrictlyElapsed32(now, m_last_bulk_subscription, interval);
}

void LiveTunnelScheduler::MarkBulkSubscription(std::uint32_t now) noexcept
{
    m_last_bulk_subscription = now;
}

void LiveTunnelScheduler::RecordTick(std::uint32_t now) noexcept
{
    m_last_tick = now;
}

std::uint32_t LiveTunnelScheduler::LastTick() const noexcept
{
    return m_last_tick;
}

bool LiveTunnelScheduler::HasClass5Timer() const noexcept
{
    return m_class5_timer != 0;
}

std::uintptr_t LiveTunnelScheduler::Class5TimerToken() const noexcept
{
    return m_class5_timer;
}

bool LiveTunnelScheduler::PublishClass5Timer(std::uintptr_t token) noexcept
{
    if (token == 0 || m_class5_timer != 0)
        return false;
    m_class5_timer = token;
    return true;
}

std::uintptr_t LiveTunnelScheduler::ReleaseClass5Timer() noexcept
{
    const std::uintptr_t token = m_class5_timer;
    m_class5_timer = 0;
    return token;
}

bool LiveTunnelScheduler::ShouldStopClass5Timer(
    bool has_shaped_links, bool fair_work_active) const noexcept
{
    return !has_shaped_links && !fair_work_active;
}

namespace {

class FakeClock32 {
public:
    explicit FakeClock32(std::uint32_t start) : m_now(start) {}
    std::uint32_t Now() const { return m_now; }
    void Advance(std::uint32_t delta) { m_now += delta; }

private:
    std::uint32_t m_now;
};

bool CharacterizeQueueFifoAndMove()
{
    LiveTunnelScheduler scheduler;
    LiveDeferredWork first;
    first.op = LiveDeferredOp::SendMessage;
    first.reqId = 7;
    first.payload = {1, 2, 3};
    scheduler.Enqueue(std::move(first));

    LiveDeferredWork second;
    second.op = LiveDeferredOp::Build3Hop;
    second.reqId = 8;
    scheduler.Enqueue(std::move(second));

    if (scheduler.PendingCount() != 2)
        return false;

    LiveDeferredWork taken;
    if (!scheduler.TryTake(taken)
        || taken.op != LiveDeferredOp::SendMessage
        || taken.reqId != 7
        || taken.payload != std::vector<std::uint8_t>({1, 2, 3}))
        return false;
    if (!scheduler.TryTake(taken)
        || taken.op != LiveDeferredOp::Build3Hop
        || taken.reqId != 8)
        return false;
    return !scheduler.TryTake(taken) && scheduler.PendingCount() == 0;
}

bool CharacterizeBatchAndClear()
{
    LiveTunnelScheduler scheduler;
    std::vector<LiveDeferredWork> batch(3);
    batch[0].reqId = 11;
    batch[1].reqId = 12;
    batch[2].reqId = 13;
    scheduler.EnqueueBatch(std::move(batch));
    if (scheduler.PendingCount() != 3)
        return false;
    if (scheduler.ClearDeferredWork() != 3)
        return false;
    return scheduler.PendingCount() == 0
        && scheduler.ClearDeferredWork() == 0;
}

bool CharacterizeFlowAccounting()
{
    LiveTunnelScheduler scheduler;
    LiveDeferredWork first;
    first.k6StreamId = 41;
    first.k6FlowBytes = 100;
    scheduler.Enqueue(std::move(first));

    LiveDeferredWork second;
    second.k6StreamId = 42;
    second.k6FlowBytes = 70;
    scheduler.Enqueue(std::move(second));

    LiveDeferredWork third;
    third.k6StreamId = 41;
    third.k6FlowBytes = 30;
    scheduler.Enqueue(std::move(third));

    LiveDeferredWork non_flow;
    non_flow.payload.resize(4096);
    scheduler.Enqueue(std::move(non_flow));

    const LiveDeferredFlowUsage usage = scheduler.MeasureK6Flow(41);
    return usage.stream_messages == 2
        && usage.stream_bytes == 130
        && usage.global_bytes == 200;
}

bool CharacterizeWraparoundClock()
{
    FakeClock32 clock((std::numeric_limits<std::uint32_t>::max)() - 5);
    const std::uint32_t start = clock.Now();
    clock.Advance(10);
    if (LiveTunnelScheduler::Elapsed32(clock.Now(), start) != 10)
        return false;
    if (!LiveTunnelScheduler::HasElapsed32(clock.Now(), start, 10))
        return false;
    if (LiveTunnelScheduler::HasStrictlyElapsed32(clock.Now(), start, 10))
        return false;
    clock.Advance(1);
    if (!LiveTunnelScheduler::HasStrictlyElapsed32(clock.Now(), start, 10))
        return false;

    const std::uint32_t deadline = clock.Now() + 20;
    if (LiveTunnelScheduler::DeadlineReached32(clock.Now(), deadline))
        return false;
    clock.Advance(20);
    return LiveTunnelScheduler::DeadlineReached32(clock.Now(), deadline);
}

bool CharacterizePeriodicGates()
{
    LiveTunnelScheduler scheduler;
    if (scheduler.DueRttProbe(4999, 5000))
        return false;
    if (!scheduler.DueRttProbe(5000, 5000))
        return false;
    if (scheduler.DueRttProbe(9999, 5000))
        return false;
    if (!scheduler.DueRttProbe(10000, 5000))
        return false;

    if (scheduler.DueBulkSubscription(10000, 10000))
        return false;
    if (!scheduler.DueBulkSubscription(10001, 10000))
        return false;
    scheduler.MarkBulkSubscription(10001);
    if (scheduler.DueBulkSubscription(20001, 10000))
        return false;
    if (!scheduler.DueBulkSubscription(20002, 10000))
        return false;

    scheduler.RecordTick(0xFFFFFFF0u);
    return scheduler.LastTick() == 0xFFFFFFF0u;
}

bool CharacterizeTimerLifecycle()
{
    LiveTunnelScheduler scheduler;
    if (scheduler.HasClass5Timer()
        || scheduler.Class5TimerToken() != 0
        || scheduler.PublishClass5Timer(0))
        return false;
    if (!scheduler.PublishClass5Timer(17)
        || !scheduler.HasClass5Timer()
        || scheduler.Class5TimerToken() != 17)
        return false;
    if (scheduler.PublishClass5Timer(18))
        return false;
    if (scheduler.ShouldStopClass5Timer(true, false)
        || scheduler.ShouldStopClass5Timer(false, true)
        || !scheduler.ShouldStopClass5Timer(false, false))
        return false;
    if (scheduler.ReleaseClass5Timer() != 17
        || scheduler.HasClass5Timer()
        || scheduler.ReleaseClass5Timer() != 0)
        return false;
    return true;
}

} // namespace

bool RunLiveTunnelSchedulerCharacterizationSelfTest()
{
    return CharacterizeQueueFifoAndMove()
        && CharacterizeBatchAndClear()
        && CharacterizeFlowAccounting()
        && CharacterizeWraparoundClock()
        && CharacterizePeriodicGates()
        && CharacterizeTimerLifecycle();
}

} // namespace eSELive
