// this file is part of eMule eSE - tunnel scheduling and deferred-work owner
#pragma once

#include "Kad6ExitNoticeServer.h"
#include "LiveBulk.h"
#include "M2ABindingPort.h"
#include "kad6/kad6_economy.h"
#include "kad6/kad6_hardening.h"
#include "kad6/kad6_release.h"
#include "kad6/kad6_shaped_bulk.h"
#include "kad6/kad6_shaper.h"

#include <cstddef>
#include <cstdint>
#include <deque>
#include <map>
#include <mutex>
#include <vector>

namespace kad6 { struct K6ExitNotice; }
namespace eSELive {
struct LiveK6ReleaseRuntimeSnapshot;

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

struct LiveShapedQueuedRecord {
    std::uint64_t incoming_nonce = 0;
    bool terminal = false;
    std::vector<std::uint8_t> bytes;
};

struct LiveShapedLinkConfig {
    std::uint32_t circ_id = 0;
    std::uint32_t bucket_kib = 0;
    int output_layers = 0;
    std::uint32_t reservoir_ms = 0;
    std::uint64_t phase = 0;
    std::uint32_t nonce_epoch_high_base = 0;
    std::uint64_t padding_sequence = 0;
    std::uint64_t now_us = 0;
    std::uint8_t idle_tail_epochs = 1;
};

struct LiveShapedTickWork {
    std::uint32_t circ_id = 0;
    kad6::K6ShapeSlot slot;
};

struct LiveShapedRetirement {
    std::uint32_t circ_id = 0;
    std::uint8_t idle_tail_epochs = 0;
};

struct LiveShapedTickResult {
    std::vector<LiveShapedTickWork> work;
    std::vector<LiveShapedRetirement> retired;
    std::vector<std::uint32_t> exposed;
    bool has_links = false;
};

struct LiveShapedEmission {
    std::vector<std::uint8_t> layer_plain;
    std::uint64_t link_nonce = 0;
    std::size_t record_bytes = 0;
    int output_layers = 0;
};

struct LiveFairReady {
    std::uint64_t stream_id = 0;
    std::uint8_t direction = 0;
    std::size_t credit_bytes = 0;
    std::vector<std::uint8_t> bytes;
};

class LiveTunnelScheduler {
public:
    static const std::size_t kDefaultDrainBudget = 256;

    LiveTunnelScheduler();
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
    void ConfigureReleaseGate(
        const std::wstring&, bool (*)(void*, std::uint8_t*, std::size_t), void*,
        bool (*)(void*, bool, std::uint32_t));
    bool SaveReleaseEvidence(kad6::K6ReleaseEvidence,
        const kad6::Kad6CryptoHooks&, const std::uint8_t*, std::uint64_t);
    bool StartReleaseNotice(std::uint16_t, const kad6::K6ExitNotice&,
        const kad6::Kad6CryptoHooks&, const std::uint8_t*);
    void StopReleaseNotice() noexcept;
    K6ExitNoticeServerSnapshot GetReleaseNoticeSnapshot() const noexcept;
    kad6::K6ReleaseGateStatus GetReleaseSnapshot(
        LiveK6ReleaseRuntimeSnapshot&, bool, bool,
        const std::uint8_t*, const kad6::Kad6CryptoHooks&, std::uint64_t);
    void ApplyReleaseEvaluation(
        bool, bool, bool, kad6::K6ReleaseGateStatus, std::uint32_t);
    bool IsReleaseEnabled() const noexcept;
    bool GetReleaseChallenge(std::string&, std::uint64_t);
    bool ConsumeReleaseChallenge(const std::string&, std::uint64_t) noexcept;

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

    bool ConfigureShapedLink(const LiveShapedLinkConfig& config);
    bool HasShapedLink(std::uint32_t circ_id) const noexcept;
    bool ShapedLinkMatches(std::uint32_t circ_id, int output_layers,
                           std::uint32_t bucket_kib) const noexcept;
    std::size_t ShapedLinkCount() const noexcept;
    std::size_t ShapedReservoirCapacity(std::uint32_t circ_id) const noexcept;
    void RemoveShapedLink(std::uint32_t circ_id);
    void ClearShaping();
    bool QueueShapedRecord(std::uint32_t circ_id, std::uint64_t stream_id,
                           LiveShapedQueuedRecord record,
                           std::uint64_t now_us);
    LiveShapedTickResult PollShapedLinks(
        std::uint64_t now_us,
        const std::vector<std::uint32_t>& live_relay_circuits,
        std::size_t maximum_per_link);
    bool NeedsShapedEpoch(std::uint32_t circ_id,
                          std::uint64_t epoch) const noexcept;
    bool PrepareShapedEmission(std::uint32_t circ_id,
                               const kad6::K6ShapeSlot& slot,
                               const kad6::Kad6CryptoHooks& crypto,
                               std::uint32_t epoch_low_base,
                               LiveShapedEmission& emission);
    void MarkShapedExposed(std::uint32_t circ_id) noexcept;
    bool ShapedLinkExposed(std::uint32_t circ_id) const noexcept;
    bool AcceptShapedReplay(std::uint32_t circ_id, std::uint8_t lane,
                            std::uint64_t nonce);
    void SweepShapedReplay(
        const std::vector<std::uint32_t>& live_circuits);

    bool RegisterFairAllocation(
        std::uint64_t allocation_id, const kad6::Hash32& issuer,
        std::uint64_t allocation_max_bytes,
        std::uint64_t issuer_max_bytes);
    bool RegisterFairStream(
        std::uint64_t allocation_id, std::uint64_t stream_id,
        const kad6::Hash32& target, std::uint64_t stream_max_bytes,
        std::uint64_t target_max_bytes);
    bool HasFairStream(std::uint64_t stream_id) const noexcept;
    bool QueueFairPayload(std::uint64_t stream_id, std::uint8_t direction,
                          std::vector<std::uint8_t> bytes,
                          std::size_t credit_bytes);
    void ReleaseFairStream(std::uint64_t stream_id);
    void ReleaseFairAllocation(std::uint64_t allocation_id) noexcept;
    std::vector<LiveFairReady> PollFair(
        std::uint64_t max_bytes, std::size_t max_grants);
    bool HasFairWork() const noexcept;
    void ClearFair() noexcept;

private:
    struct ShapedLinkState {
        kad6::K6Class5Scheduler scheduler;
        std::map<std::uint64_t, std::deque<LiveShapedQueuedRecord>> records;
        std::uint32_t bucket_kib = 0;
        int output_layers = 0;
        std::uint64_t nonce_epoch = 0;
        std::uint32_t nonce_epoch_high_base = 0;
        std::uint32_t nonce_epoch_low_base = 0;
        std::uint32_t nonce_in_epoch = 0;
        std::uint64_t padding_sequence = 0;
        std::uint64_t last_input_us = 0;
        std::uint8_t idle_tail_epochs = 1;
        bool nonce_epoch_ready = false;
        bool exposed = false;
    };

    mutable std::mutex m_deferred_mutex;
    std::deque<LiveDeferredWork> m_deferred_work;
    bool m_accepting_deferred_work = true;
    std::uint32_t m_last_tick = 0;
    std::uint32_t m_last_rtt_probe = 0;
    std::uint32_t m_last_bulk_subscription = 0;
    std::uintptr_t m_class5_timer = 0;
    std::map<std::uint32_t, ShapedLinkState> m_shaped_links;
    std::map<std::uint64_t, Bulk::BulkReplayWindow> m_shaped_replay;
    struct FairPayload {
        std::uint8_t direction = 0;
        std::size_t credit_bytes = 0;
        std::vector<std::uint8_t> bytes;
    };
    kad6::K6FairScheduler m_fair_scheduler;
    std::map<std::uint64_t, std::deque<FairPayload>> m_fair_payloads;
    std::map<std::uint64_t, std::uint64_t> m_fair_credits;
    std::map<std::uint64_t, std::uint64_t> m_fair_allocation_by_stream;
    std::uint64_t m_fair_payload_bytes = 0;
    M2AModuleHandle m_m2a_binding_bab3ce64a0;
    CKad6ExitNoticeServer m_release_notice_adapter;
};

bool RunLiveTunnelSchedulerCharacterizationSelfTest();

} // namespace eSELive
