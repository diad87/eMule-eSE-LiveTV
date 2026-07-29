// this file is part of eMule eSE - tunnel scheduling and deferred-work owner
#include "LiveTunnelScheduler.h"

#include <algorithm>
#include <atomic>
#include <initializer_list>
#include <limits>
#include <thread>
#include <utility>

namespace eSELive {

bool LiveTunnelScheduler::Enqueue(LiveDeferredWork work)
{
    std::lock_guard<std::mutex> lock(m_deferred_mutex);
    if (!m_accepting_deferred_work)
        return false;
    m_deferred_work.push_back(std::move(work));
    return true;
}

std::vector<LiveDeferredWork> LiveTunnelScheduler::EnqueueBatch(
    std::vector<LiveDeferredWork> work)
{
    if (work.empty())
        return {};

    std::lock_guard<std::mutex> lock(m_deferred_mutex);
    if (!m_accepting_deferred_work)
        return work;
    for (std::size_t index = 0; index < work.size(); ++index)
        m_deferred_work.push_back(std::move(work[index]));
    return {};
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

std::vector<LiveDeferredWork> LiveTunnelScheduler::CloseDeferredWork()
{
    std::lock_guard<std::mutex> lock(m_deferred_mutex);
    m_accepting_deferred_work = false;
    std::vector<LiveDeferredWork> cancelled;
    cancelled.reserve(m_deferred_work.size());
    while (!m_deferred_work.empty()) {
        cancelled.push_back(std::move(m_deferred_work.front()));
        m_deferred_work.pop_front();
    }
    return cancelled;
}

void LiveTunnelScheduler::ReopenDeferredWork()
{
    std::lock_guard<std::mutex> lock(m_deferred_mutex);
    m_accepting_deferred_work = true;
}

bool LiveTunnelScheduler::AcceptingDeferredWork() const
{
    std::lock_guard<std::mutex> lock(m_deferred_mutex);
    return m_accepting_deferred_work;
}

namespace {

bool AllRequestsAre(
    const std::vector<LiveDeferredWork>& work,
    std::initializer_list<std::uint32_t> expected)
{
    if (work.size() != expected.size())
        return false;
    std::size_t index = 0;
    for (const std::uint32_t request : expected) {
        if (work[index++].reqId != request)
            return false;
    }
    return true;
}

} // namespace

/*
 * Closing is deliberately an atomic queue operation: either a producer
 * publishes before CloseDeferredWork and its command is returned for explicit
 * cancellation, or it observes the closed state and publication fails.
 * Nothing can survive on the queue across the shutdown boundary.
 */

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
    if (!scheduler.Enqueue(std::move(first)))
        return false;

    LiveDeferredWork second;
    second.op = LiveDeferredOp::Build3Hop;
    second.reqId = 8;
    if (!scheduler.Enqueue(std::move(second)))
        return false;

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

bool CharacterizeBatchAndClose()
{
    LiveTunnelScheduler scheduler;
    std::vector<LiveDeferredWork> batch(3);
    batch[0].reqId = 11;
    batch[1].reqId = 12;
    batch[2].reqId = 13;
    if (!scheduler.EnqueueBatch(std::move(batch)).empty())
        return false;
    if (scheduler.PendingCount() != 3)
        return false;
    const std::vector<LiveDeferredWork> cancelled =
        scheduler.CloseDeferredWork();
    if (!AllRequestsAre(cancelled, {11, 12, 13}))
        return false;
    LiveDeferredWork rejected;
    rejected.reqId = 14;
    if (scheduler.Enqueue(std::move(rejected)))
        return false;
    if (scheduler.AcceptingDeferredWork() || scheduler.PendingCount() != 0)
        return false;
    scheduler.ReopenDeferredWork();
    LiveDeferredWork accepted;
    accepted.reqId = 15;
    return scheduler.AcceptingDeferredWork()
        && scheduler.Enqueue(std::move(accepted))
        && scheduler.PendingCount() == 1;
}

bool CharacterizeFlowAccounting()
{
    LiveTunnelScheduler scheduler;
    LiveDeferredWork first;
    first.k6StreamId = 41;
    first.k6FlowBytes = 100;
    if (!scheduler.Enqueue(std::move(first)))
        return false;

    LiveDeferredWork second;
    second.k6StreamId = 42;
    second.k6FlowBytes = 70;
    if (!scheduler.Enqueue(std::move(second)))
        return false;

    LiveDeferredWork third;
    third.k6StreamId = 41;
    third.k6FlowBytes = 30;
    if (!scheduler.Enqueue(std::move(third)))
        return false;

    LiveDeferredWork non_flow;
    non_flow.payload.resize(4096);
    if (!scheduler.Enqueue(std::move(non_flow)))
        return false;

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

bool CharacterizeConcurrentClosePublication()
{
    for (std::uint32_t iteration = 1; iteration <= 256; ++iteration) {
        LiveTunnelScheduler scheduler;
        std::atomic<bool> start{false};
        std::atomic<bool> accepted{false};
        std::thread producer([&]() {
            LiveDeferredWork work;
            work.reqId = iteration;
            while (!start.load(std::memory_order_acquire))
                std::this_thread::yield();
            accepted.store(
                scheduler.Enqueue(std::move(work)),
                std::memory_order_release);
        });
        start.store(true, std::memory_order_release);
        const std::vector<LiveDeferredWork> cancelled =
            scheduler.CloseDeferredWork();
        producer.join();

        if (scheduler.PendingCount() != 0
            || scheduler.AcceptingDeferredWork())
            return false;
        if (accepted.load(std::memory_order_acquire)) {
            if (!AllRequestsAre(cancelled, {iteration}))
                return false;
        } else if (!cancelled.empty()) {
            return false;
        }
    }
    return true;
}

} // namespace

bool RunLiveTunnelSchedulerCharacterizationSelfTest()
{
    return CharacterizeQueueFifoAndMove()
        && CharacterizeBatchAndClose()
        && CharacterizeFlowAccounting()
        && CharacterizeWraparoundClock()
        && CharacterizePeriodicGates()
        && CharacterizeTimerLifecycle()
        && CharacterizeConcurrentClosePublication();
}

} // namespace eSELive
