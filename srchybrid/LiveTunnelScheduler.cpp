// this file is part of eMule eSE - tunnel scheduling and deferred-work owner
#include "LiveTunnelScheduler.h"
#include "M2ABindingPort.h"

#include <algorithm>
#include <atomic>
#include <cstring>
#include <initializer_list>
#include <limits>
#include <thread>
#include <utility>

namespace eSELive {

M2AModuleHandle M2A_BIND_LT1_BAB3CE64A0(const M2AParentPort&);
M2AModuleHandle M2A_BIND_LT2_8892179A6E(const M2AParentPort&);
void M2A_LT2_InitializeBridge(M2AModuleHandle&);
bool M2A_LT2_HardeningCanAdmitBridge(const M2AModuleHandle&,kad6::K6Service) noexcept;
bool M2A_LT2_HardeningSetEnabledBridge(M2AModuleHandle&,kad6::K6Service,bool,std::uint64_t,std::uint32_t,std::uint64_t);
kad6::K6HardeningSnapshot M2A_LT2_HardeningSnapshotBridge(const M2AModuleHandle&) noexcept;
kad6::K6DrainResult M2A_LT2_HardeningTickBridge(M2AModuleHandle&,std::uint64_t,const std::array<std::uint64_t,static_cast<size_t>(kad6::K6Service::Count)>&);
void M2A_LT2_RecordUsefulBytesBridge(M2AModuleHandle&, std::uint64_t) noexcept;
void M2A_LT2_RecordPublishAttemptBridge(M2AModuleHandle&, std::uint64_t) noexcept;
bool M2A_LT2_EconomyHealthyBridge(const M2AModuleHandle&) noexcept;
bool M2A_LT2_EconomyAdmitBridge(M2AModuleHandle&, kad6::K6Service, std::uint64_t);
void M2A_LT2_RefreshEconomyBridge(
    M2AModuleHandle&, std::uint64_t,
    const std::array<std::uint64_t,
        static_cast<size_t>(kad6::K6Service::Count)>&,
    double, std::uint64_t, std::uint64_t, std::uint64_t);
void M2A_LT2_FillEconomySnapshotBridge(
    const M2AModuleHandle&, bool&,
    std::array<double, static_cast<size_t>(kad6::K6Service::Count)>&,
    std::array<kad6::K6EconomyWindowSnapshot,
        static_cast<size_t>(kad6::K6Service::Count)>&);
void M2A_LT2_ResetQuotaStateBridge(M2AModuleHandle&);
std::vector<std::uint64_t> M2A_LT2_PruneQuotaGrantsBridge(M2AModuleHandle&, std::uint64_t);
bool M2A_LT2_EnsureQuotaAuthorityBridge(
    M2AModuleHandle&, std::uint64_t, const std::string&,
    const std::uint8_t[32], const kad6::Kad6CryptoHooks&);
bool M2A_LT2_QuotaCertificateWireBridge(const M2AModuleHandle&, std::vector<std::uint8_t>&);
bool M2A_LT2_BlindQuotaTokenBridge(
    M2AModuleHandle&, const kad6::K6QuotaIssuerCertificate&,
    const kad6::K6QuotaToken&, kad6::K6QuotaBlindState&);
bool M2A_LT2_FinalizeQuotaTokenBridge(
    M2AModuleHandle&, const kad6::K6QuotaIssuerCertificate&,
    const kad6::K6QuotaBlindState&,
    const std::vector<std::uint8_t>&, kad6::K6QuotaPresentation&);
void M2A_LT2_IssueQuotaBridge(
    M2AModuleHandle&, const kad6::K6QuotaBlindRequest&,
    const std::array<std::uint8_t, 32>&,
    const std::array<std::uint8_t, 6>&,
    std::uint32_t, std::uint64_t, std::uint64_t,
    kad6::K6QuotaBlindResponse&);
using M2ARegisterFairAllocation = bool (*)(
    void*, std::uint64_t, const kad6::Hash32&,
    std::uint64_t, std::uint64_t);
using M2AReleaseFairAllocation = void (*)(void*, std::uint64_t);
void M2A_LT2_PresentQuotaBridge(
    M2AModuleHandle&, const kad6::K6QuotaPresentation&,
    bool, std::uint32_t, std::uint64_t,
    const kad6::Kad6CryptoHooks&, void*,
    M2ARegisterFairAllocation, M2AReleaseFairAllocation,
    kad6::K6QuotaPresentationResult&);
bool M2A_LT2_ConsumeQuotaGrantBridge(
    M2AModuleHandle&, std::uint32_t,
    const std::array<std::uint8_t, 32>&,
    std::uint8_t, std::uint64_t, bool,
    std::uint64_t&, std::uint64_t&);
bool RunLiveTunnelReleaseGateCharacterizationSelfTest();
void M2A_LT1_ConfigureBridge(M2AModuleHandle&, CKad6ExitNoticeServer&, const std::wstring&, bool (*)(void*, std::uint8_t*, std::size_t), void*, bool (*)(void*, bool, std::uint32_t));
bool M2A_LT1_SaveEvidenceBridge(M2AModuleHandle&, kad6::K6ReleaseEvidence, const kad6::Kad6CryptoHooks&, const std::uint8_t*, std::uint64_t);
bool M2A_LT1_StartNoticeBridge(M2AModuleHandle&, std::uint16_t, const kad6::K6ExitNotice&, const kad6::Kad6CryptoHooks&, const std::uint8_t*);
void M2A_LT1_StopNoticeBridge(M2AModuleHandle&) noexcept;
K6ExitNoticeServerSnapshot M2A_LT1_NoticeSnapshotBridge(const M2AModuleHandle&) noexcept;
kad6::K6ReleaseGateStatus M2A_LT1_GetSnapshotBridge(M2AModuleHandle&, LiveK6ReleaseRuntimeSnapshot&, bool, bool, const std::uint8_t*, const kad6::Kad6CryptoHooks&, std::uint64_t);
void M2A_LT1_ApplyEvaluationBridge(M2AModuleHandle&, bool, bool, bool, kad6::K6ReleaseGateStatus, std::uint32_t);
bool M2A_LT1_IsEnabledBridge(const M2AModuleHandle&) noexcept;
bool M2A_LT1_GetChallengeBridge(M2AModuleHandle&, std::string&, std::uint64_t);
bool M2A_LT1_ConsumeChallengeBridge(M2AModuleHandle&, const std::string&, std::uint64_t) noexcept;

LiveTunnelScheduler::LiveTunnelScheduler()
    : m_m2a_binding_bab3ce64a0(M2AAssignmentPolicy::RetainExisting),
      m_m2a_binding_8892179a6e(M2AAssignmentPolicy::RetainExisting)
{
    m_m2a_binding_8892179a6e = M2A_BIND_LT2_8892179A6E(M2AParentPort{this});
    M2A_LT2_InitializeBridge(m_m2a_binding_8892179a6e);
}

bool LiveTunnelScheduler::LT2HardeningCanAdmit(kad6::K6Service service) const noexcept { return M2A_LT2_HardeningCanAdmitBridge(m_m2a_binding_8892179a6e,service); }
bool LiveTunnelScheduler::LT2HardeningSetEnabled(kad6::K6Service service,bool enabled,std::uint64_t now,std::uint32_t drain,std::uint64_t active) { return M2A_LT2_HardeningSetEnabledBridge(m_m2a_binding_8892179a6e,service,enabled,now,drain,active); }
kad6::K6HardeningSnapshot LiveTunnelScheduler::LT2HardeningSnapshot() const noexcept { return M2A_LT2_HardeningSnapshotBridge(m_m2a_binding_8892179a6e); }
kad6::K6DrainResult LiveTunnelScheduler::LT2HardeningTick(std::uint64_t now,const std::array<std::uint64_t,static_cast<size_t>(kad6::K6Service::Count)>& active) { return M2A_LT2_HardeningTickBridge(m_m2a_binding_8892179a6e,now,active); }
void LiveTunnelScheduler::LT2RecordUsefulBytes(
    std::uint64_t delta) noexcept {
    M2A_LT2_RecordUsefulBytesBridge(m_m2a_binding_8892179a6e, delta);
}
void LiveTunnelScheduler::LT2RecordPublishAttempt(
    std::uint64_t delta) noexcept {
    M2A_LT2_RecordPublishAttemptBridge(m_m2a_binding_8892179a6e, delta);
}
bool LiveTunnelScheduler::LT2EconomyHealthy() const noexcept {
    return M2A_LT2_EconomyHealthyBridge(m_m2a_binding_8892179a6e);
}
bool LiveTunnelScheduler::LT2EconomyAdmit(
    kad6::K6Service service, std::uint64_t now) {
    return M2A_LT2_EconomyAdmitBridge(
        m_m2a_binding_8892179a6e, service, now);
}
void LiveTunnelScheduler::LT2RefreshEconomy(
    std::uint64_t now,
    const std::array<std::uint64_t,
        static_cast<size_t>(kad6::K6Service::Count)>& active,
    double capacity, std::uint64_t processNow,
    std::uint64_t systemNow, std::uint64_t occupied) {
    M2A_LT2_RefreshEconomyBridge(
        m_m2a_binding_8892179a6e, now, active, capacity,
        processNow, systemNow, occupied);
}
void LiveTunnelScheduler::LT2FillEconomySnapshot(
    bool& measurementReady,
    std::array<double, static_cast<size_t>(kad6::K6Service::Count)>& rho,
    std::array<kad6::K6EconomyWindowSnapshot,
        static_cast<size_t>(kad6::K6Service::Count)>& economy) const {
    M2A_LT2_FillEconomySnapshotBridge(
        m_m2a_binding_8892179a6e, measurementReady, rho, economy);
}
namespace {
bool M2A_LT2_RegisterFair(
    void* context, std::uint64_t allocation,
    const kad6::Hash32& issuer, std::uint64_t allocationLimit,
    std::uint64_t issuerLimit) {
    LiveTunnelScheduler* scheduler =
        static_cast<LiveTunnelScheduler*>(context);
    return scheduler && scheduler->RegisterFairAllocation(
        allocation, issuer, allocationLimit, issuerLimit);
}
void M2A_LT2_ReleaseFair(void* context, std::uint64_t allocation) {
    LiveTunnelScheduler* scheduler =
        static_cast<LiveTunnelScheduler*>(context);
    if (scheduler)
        scheduler->ReleaseFairAllocation(allocation);
}
}
void LiveTunnelScheduler::LT2ResetQuotaState() { M2A_LT2_ResetQuotaStateBridge(m_m2a_binding_8892179a6e); }
void LiveTunnelScheduler::LT2PruneQuotaGrants(std::uint64_t now) {
    const std::vector<std::uint64_t> released =
        M2A_LT2_PruneQuotaGrantsBridge(m_m2a_binding_8892179a6e, now);
    for (std::uint64_t allocation : released)
        ReleaseFairAllocation(allocation);
}
bool LiveTunnelScheduler::LT2EnsureQuotaAuthority(
    std::uint64_t now, const std::string& storagePath,
    const std::uint8_t nodePublicKey[32],
    const kad6::Kad6CryptoHooks& identityCrypto) {
    return M2A_LT2_EnsureQuotaAuthorityBridge(
        m_m2a_binding_8892179a6e, now, storagePath,
        nodePublicKey, identityCrypto);
}
std::vector<std::uint8_t> LiveTunnelScheduler::LT2QuotaCertificateWire() const {
    std::vector<std::uint8_t> out;
    M2A_LT2_QuotaCertificateWireBridge(m_m2a_binding_8892179a6e, out);
    return out;
}

bool LiveTunnelScheduler::LT2BlindQuotaToken(
    const kad6::K6QuotaIssuerCertificate& certificate,
    const kad6::K6QuotaToken& token,
    kad6::K6QuotaBlindState& blind) {
    return M2A_LT2_BlindQuotaTokenBridge(
        m_m2a_binding_8892179a6e, certificate, token, blind);
}

bool LiveTunnelScheduler::LT2FinalizeQuotaToken(
    const kad6::K6QuotaIssuerCertificate& certificate,
    const kad6::K6QuotaBlindState& blind,
    const std::vector<std::uint8_t>& blindSignature,
    kad6::K6QuotaPresentation& presentation) {
    return M2A_LT2_FinalizeQuotaTokenBridge(
        m_m2a_binding_8892179a6e, certificate, blind,
        blindSignature, presentation);
}

void LiveTunnelScheduler::LT2IssueQuota(
    const kad6::K6QuotaBlindRequest& request,
    const std::array<std::uint8_t, 32>& principal,
    const std::array<std::uint8_t, 6>& prefix48,
    std::uint32_t asn, std::uint64_t now,
    std::uint64_t monotonicNowMs,
    kad6::K6QuotaBlindResponse& response) {
    M2A_LT2_IssueQuotaBridge(
        m_m2a_binding_8892179a6e, request, principal, prefix48,
        asn, now, monotonicNowMs, response);
}

void LiveTunnelScheduler::LT2PresentQuota(
    const kad6::K6QuotaPresentation& presentation,
    bool issuerTrusted, std::uint32_t circuitId, std::uint64_t now,
    const kad6::Kad6CryptoHooks& identityCrypto,
    kad6::K6QuotaPresentationResult& result) {
    M2A_LT2_PresentQuotaBridge(
        m_m2a_binding_8892179a6e, presentation, issuerTrusted,
        circuitId, now, identityCrypto, this,
        &M2A_LT2_RegisterFair, &M2A_LT2_ReleaseFair, result);
}

bool LiveTunnelScheduler::LT2ConsumeQuotaGrant(
    std::uint32_t circuitId,
    const std::array<std::uint8_t, 32>& context,
    std::uint8_t service, std::uint64_t now,
    bool allowMissing, std::uint64_t* allocationId) {
    if (allocationId)
        *allocationId = 0;
    std::uint64_t allocation = 0;
    std::uint64_t release = 0;
    const bool allowed = M2A_LT2_ConsumeQuotaGrantBridge(
        m_m2a_binding_8892179a6e, circuitId, context, service,
        now, allowMissing, allocation, release);
    if (release)
        ReleaseFairAllocation(release);
    if (!allowed)
        return false;
    if (allocationId)
        *allocationId = allocation;
    else if (allocation)
        ReleaseFairAllocation(allocation);
    return true;
}

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
    m_m2a_binding_bab3ce64a0 =
        M2A_BIND_LT1_BAB3CE64A0(M2AParentPort{this});
    std::lock_guard<std::mutex> lock(m_deferred_mutex);
    m_accepting_deferred_work = true;
}

bool LiveTunnelScheduler::AcceptingDeferredWork() const
{
    std::lock_guard<std::mutex> lock(m_deferred_mutex);
    return m_accepting_deferred_work;
}

void LiveTunnelScheduler::ConfigureReleaseGate(const std::wstring& path, bool (*random)(void*, std::uint8_t*, std::size_t), void* context, bool (*services)(void*, bool, std::uint32_t)) { M2A_LT1_ConfigureBridge(m_m2a_binding_bab3ce64a0, m_release_notice_adapter, path, random, context, services); }
bool LiveTunnelScheduler::SaveReleaseEvidence(kad6::K6ReleaseEvidence evidence, const kad6::Kad6CryptoHooks& crypto, const std::uint8_t* pub, std::uint64_t now) { return M2A_LT1_SaveEvidenceBridge(m_m2a_binding_bab3ce64a0, std::move(evidence), crypto, pub, now); }
bool LiveTunnelScheduler::StartReleaseNotice(std::uint16_t port, const kad6::K6ExitNotice& notice, const kad6::Kad6CryptoHooks& crypto, const std::uint8_t* pub) { return M2A_LT1_StartNoticeBridge(m_m2a_binding_bab3ce64a0, port, notice, crypto, pub); }
void LiveTunnelScheduler::StopReleaseNotice() noexcept { M2A_LT1_StopNoticeBridge(m_m2a_binding_bab3ce64a0); }
K6ExitNoticeServerSnapshot LiveTunnelScheduler::GetReleaseNoticeSnapshot() const noexcept { return M2A_LT1_NoticeSnapshotBridge(m_m2a_binding_bab3ce64a0); }
kad6::K6ReleaseGateStatus LiveTunnelScheduler::GetReleaseSnapshot(LiveK6ReleaseRuntimeSnapshot& out, bool optIn, bool betaOptIn, const std::uint8_t* pub, const kad6::Kad6CryptoHooks& crypto, std::uint64_t now) { return M2A_LT1_GetSnapshotBridge(m_m2a_binding_bab3ce64a0, out, optIn, betaOptIn, pub, crypto, now); }
void LiveTunnelScheduler::ApplyReleaseEvaluation(bool optIn, bool betaOptIn, bool healthy, kad6::K6ReleaseGateStatus evidence, std::uint32_t drain) { M2A_LT1_ApplyEvaluationBridge(m_m2a_binding_bab3ce64a0, optIn, betaOptIn, healthy, evidence, drain); }
bool LiveTunnelScheduler::IsReleaseEnabled() const noexcept { return M2A_LT1_IsEnabledBridge(m_m2a_binding_bab3ce64a0); }
bool LiveTunnelScheduler::GetReleaseChallenge(std::string& challenge, std::uint64_t now) { return M2A_LT1_GetChallengeBridge(m_m2a_binding_bab3ce64a0, challenge, now); }
bool LiveTunnelScheduler::ConsumeReleaseChallenge(const std::string& challenge, std::uint64_t now) noexcept { return M2A_LT1_ConsumeChallengeBridge(m_m2a_binding_bab3ce64a0, challenge, now); }

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

std::uint64_t ShapedReplayKey(
    std::uint32_t circ_id, std::uint8_t lane) noexcept
{
    return (static_cast<std::uint64_t>(circ_id) << 8) | lane;
}

} // namespace

bool LiveTunnelScheduler::ConfigureShapedLink(
    const LiveShapedLinkConfig& config)
{
    if (config.circ_id == 0 || config.output_layers < 1
        || config.output_layers > 3 || config.nonce_epoch_high_base == 0)
        return false;
    const auto existing = m_shaped_links.find(config.circ_id);
    if (existing != m_shaped_links.end())
        return existing->second.output_layers == config.output_layers
            && existing->second.bucket_kib == config.bucket_kib
            && existing->second.scheduler.configured();

    ShapedLinkState state;
    state.bucket_kib = config.bucket_kib;
    state.output_layers = config.output_layers;
    state.nonce_epoch_high_base = config.nonce_epoch_high_base;
    state.padding_sequence = config.padding_sequence;
    state.last_input_us = config.now_us;
    state.idle_tail_epochs = config.idle_tail_epochs;
    if (state.scheduler.Configure(
            config.bucket_kib, config.reservoir_ms,
            config.now_us, config.phase) != kad6::Kad6Status::Ok)
        return false;
    m_shaped_links.emplace(config.circ_id, std::move(state));
    return true;
}

bool LiveTunnelScheduler::HasShapedLink(std::uint32_t circ_id) const noexcept
{
    return m_shaped_links.find(circ_id) != m_shaped_links.end();
}

bool LiveTunnelScheduler::ShapedLinkMatches(
    std::uint32_t circ_id, int output_layers,
    std::uint32_t bucket_kib) const noexcept
{
    const auto found = m_shaped_links.find(circ_id);
    return found != m_shaped_links.end()
        && found->second.output_layers == output_layers
        && found->second.bucket_kib == bucket_kib
        && found->second.scheduler.configured();
}

std::size_t LiveTunnelScheduler::ShapedLinkCount() const noexcept
{
    return m_shaped_links.size();
}

std::size_t LiveTunnelScheduler::ShapedReservoirCapacity(
    std::uint32_t circ_id) const noexcept
{
    const auto found = m_shaped_links.find(circ_id);
    return found == m_shaped_links.end()
        ? 0 : found->second.scheduler.reservoir_capacity();
}

void LiveTunnelScheduler::RemoveShapedLink(std::uint32_t circ_id)
{
    m_shaped_links.erase(circ_id);
    for (auto replay = m_shaped_replay.begin();
         replay != m_shaped_replay.end();) {
        if (static_cast<std::uint32_t>(replay->first >> 8) == circ_id)
            replay = m_shaped_replay.erase(replay);
        else
            ++replay;
    }
}

void LiveTunnelScheduler::ClearShaping()
{
    m_shaped_links.clear();
    m_shaped_replay.clear();
}

bool LiveTunnelScheduler::QueueShapedRecord(
    std::uint32_t circ_id, std::uint64_t stream_id,
    LiveShapedQueuedRecord record, std::uint64_t now_us)
{
    if (stream_id == 0)
        return false;
    const auto found = m_shaped_links.find(circ_id);
    if (found == m_shaped_links.end())
        return false;
    ShapedLinkState& state = found->second;
    try {
        std::deque<LiveShapedQueuedRecord>& queue = state.records[stream_id];
        queue.push_back(std::move(record));
        if (!state.scheduler.Enqueue(stream_id)) {
            queue.pop_back();
            if (queue.empty())
                state.records.erase(stream_id);
            state.exposed = true;
            return false;
        }
    } catch (...) {
        state.exposed = true;
        return false;
    }
    state.last_input_us = now_us;
    return true;
}

LiveShapedTickResult LiveTunnelScheduler::PollShapedLinks(
    std::uint64_t now_us,
    const std::vector<std::uint32_t>& live_relay_circuits,
    std::size_t maximum_per_link)
{
    LiveShapedTickResult result;
    for (auto link = m_shaped_links.begin(); link != m_shaped_links.end();) {
        if (std::find(live_relay_circuits.begin(), live_relay_circuits.end(),
                      link->first) == live_relay_circuits.end()) {
            const std::uint32_t dead = link->first;
            link = m_shaped_links.erase(link);
            for (auto replay = m_shaped_replay.begin();
                 replay != m_shaped_replay.end();) {
                if (static_cast<std::uint32_t>(replay->first >> 8) == dead)
                    replay = m_shaped_replay.erase(replay);
                else
                    ++replay;
            }
            continue;
        }

        ShapedLinkState& state = link->second;
        const std::uint64_t idle_tail_us =
            static_cast<std::uint64_t>(state.idle_tail_epochs)
            * kad6::kK6ShapeEpochUs;
        if (state.scheduler.queued_records() == 0
            && Elapsed64(now_us, state.last_input_us) >= idle_tail_us) {
            result.retired.push_back({link->first, state.idle_tail_epochs});
            link = m_shaped_links.erase(link);
            continue;
        }

        std::vector<kad6::K6ShapeSlot> slots;
        state.scheduler.Poll(now_us, maximum_per_link, slots);
        if (state.scheduler.exposed()) {
            state.exposed = true;
            result.exposed.push_back(link->first);
        }
        for (const kad6::K6ShapeSlot& slot : slots)
            result.work.push_back({link->first, slot});
        ++link;
    }
    result.has_links = !m_shaped_links.empty();
    return result;
}

bool LiveTunnelScheduler::NeedsShapedEpoch(
    std::uint32_t circ_id, std::uint64_t epoch) const noexcept
{
    const auto found = m_shaped_links.find(circ_id);
    return found != m_shaped_links.end()
        && (!found->second.nonce_epoch_ready
            || found->second.nonce_epoch != epoch);
}

bool LiveTunnelScheduler::PrepareShapedEmission(
    std::uint32_t circ_id, const kad6::K6ShapeSlot& slot,
    const kad6::Kad6CryptoHooks& crypto, std::uint32_t epoch_low_base,
    LiveShapedEmission& emission)
{
    const auto found = m_shaped_links.find(circ_id);
    if (found == m_shaped_links.end())
        return false;
    ShapedLinkState& state = found->second;
    LiveShapedQueuedRecord record;
    bool have_record = false;
    if (slot.kind == kad6::K6ShapeSlotKind::Data) {
        const auto queue = state.records.find(slot.stream_id);
        if (queue == state.records.end() || queue->second.empty()) {
            state.exposed = true;
            return false;
        }
        record = std::move(queue->second.front());
        queue->second.pop_front();
        if (queue->second.empty())
            state.records.erase(queue);
        have_record = true;
    }

    std::vector<std::uint8_t> layer_plain;
    if (have_record) {
        if (record.terminal) {
            if (state.output_layers != 1
                || record.bytes.size() != kad6::kK6ShapedPlainSize)
                return false;
            layer_plain.resize(8 + record.bytes.size());
            std::memset(layer_plain.data(), 0, 8);
            std::memcpy(layer_plain.data() + 8,
                        record.bytes.data(), record.bytes.size());
        } else {
            const std::size_t expected =
                kad6::K6ShapedPrefixLen(state.output_layers - 1);
            if (state.output_layers <= 1 || record.incoming_nonce == 0
                || record.incoming_nonce == kad6::kK6ShapedPaddingSentinel
                || record.bytes.size() != expected)
                return false;
            layer_plain.resize(8 + record.bytes.size());
            for (std::size_t index = 0; index < 8; ++index)
                layer_plain[index] = static_cast<std::uint8_t>(
                    record.incoming_nonce >> (8 * index));
            std::memcpy(layer_plain.data() + 8,
                        record.bytes.data(), record.bytes.size());
        }
    } else if (state.output_layers == 1) {
        kad6::K6ShapedBulkPlainV1 padding;
        padding.kind = static_cast<std::uint8_t>(kad6::K6BulkKind::Padding);
        padding.stream_id = circ_id;
        padding.logical_sequence = state.padding_sequence++;
        std::vector<std::uint8_t> encoded;
        if (kad6::EncodeK6ShapedPlain(padding, crypto, encoded)
            != kad6::Kad6Status::Ok)
            return false;
        layer_plain.resize(8 + encoded.size());
        std::memset(layer_plain.data(), 0, 8);
        std::memcpy(layer_plain.data() + 8, encoded.data(), encoded.size());
    } else {
        const std::size_t lower =
            kad6::K6ShapedPrefixLen(state.output_layers - 1);
        layer_plain.resize(8 + lower);
        for (std::size_t index = 0; index < 8; ++index)
            layer_plain[index] = 0xFF;
        if (!crypto.random_bytes
            || !crypto.random_bytes(layer_plain.data() + 8, lower))
            return false;
    }

    if (!state.nonce_epoch_ready || state.nonce_epoch != slot.epoch) {
        const std::uint64_t epoch_high =
            static_cast<std::uint64_t>(state.nonce_epoch_high_base)
            + slot.epoch;
        if (epoch_high >= 0xFFFFFFFFull)
            return false;
        state.nonce_epoch = slot.epoch;
        state.nonce_epoch_low_base = epoch_low_base & 0x00FFFFFFu;
        state.nonce_in_epoch = 0;
        state.nonce_epoch_ready = true;
    }
    if (state.nonce_in_epoch >= 0xFF000000u)
        return false;
    const std::uint64_t link_nonce =
        ((static_cast<std::uint64_t>(state.nonce_epoch_high_base)
          + state.nonce_epoch) << 32)
        | static_cast<std::uint64_t>(
            state.nonce_epoch_low_base + state.nonce_in_epoch++);
    if (link_nonce == 0 || link_nonce == kad6::kK6ShapedPaddingSentinel)
        return false;

    emission.layer_plain = std::move(layer_plain);
    emission.link_nonce = link_nonce;
    emission.record_bytes = have_record ? record.bytes.size() : 0;
    emission.output_layers = state.output_layers;
    return true;
}

void LiveTunnelScheduler::MarkShapedExposed(std::uint32_t circ_id) noexcept
{
    const auto found = m_shaped_links.find(circ_id);
    if (found != m_shaped_links.end())
        found->second.exposed = true;
}

bool LiveTunnelScheduler::ShapedLinkExposed(
    std::uint32_t circ_id) const noexcept
{
    const auto found = m_shaped_links.find(circ_id);
    return found != m_shaped_links.end() && found->second.exposed;
}

bool LiveTunnelScheduler::AcceptShapedReplay(
    std::uint32_t circ_id, std::uint8_t lane, std::uint64_t nonce)
{
    return m_shaped_replay[ShapedReplayKey(circ_id, lane)].Check(nonce);
}

void LiveTunnelScheduler::SweepShapedReplay(
    const std::vector<std::uint32_t>& live_circuits)
{
    for (auto replay = m_shaped_replay.begin();
         replay != m_shaped_replay.end();) {
        const std::uint32_t circ_id =
            static_cast<std::uint32_t>(replay->first >> 8);
        if (std::find(live_circuits.begin(), live_circuits.end(), circ_id)
            == live_circuits.end())
            replay = m_shaped_replay.erase(replay);
        else
            ++replay;
    }
}

bool LiveTunnelScheduler::RegisterFairAllocation(
    std::uint64_t allocation_id, const kad6::Hash32& issuer,
    std::uint64_t allocation_max_bytes, std::uint64_t issuer_max_bytes)
{
    return m_fair_scheduler.RegisterAllocation(
        allocation_id, issuer, allocation_max_bytes, issuer_max_bytes);
}

bool LiveTunnelScheduler::RegisterFairStream(
    std::uint64_t allocation_id, std::uint64_t stream_id,
    const kad6::Hash32& target, std::uint64_t stream_max_bytes,
    std::uint64_t target_max_bytes)
{
    if (!m_fair_scheduler.RegisterStream(
            allocation_id, stream_id, target,
            stream_max_bytes, target_max_bytes))
        return false;
    try {
        m_fair_allocation_by_stream[stream_id] = allocation_id;
    } catch (...) {
        m_fair_scheduler.ReleaseStream(stream_id);
        return false;
    }
    return true;
}

bool LiveTunnelScheduler::HasFairStream(
    std::uint64_t stream_id) const noexcept
{
    return m_fair_allocation_by_stream.find(stream_id)
        != m_fair_allocation_by_stream.end();
}

bool LiveTunnelScheduler::QueueFairPayload(
    std::uint64_t stream_id, std::uint8_t direction,
    std::vector<std::uint8_t> bytes, std::size_t credit_bytes)
{
    if (stream_id == 0 || direction > 1 || bytes.empty()
        || !HasFairStream(stream_id))
        return false;
    std::deque<FairPayload>& queue = m_fair_payloads[stream_id];
    std::uint64_t stream_bytes = 0;
    for (const FairPayload& payload : queue)
        stream_bytes += payload.bytes.size();
    if (queue.size() >= 64
        || stream_bytes + bytes.size() > 2u * 1024u * 1024u
        || m_fair_payload_bytes + bytes.size()
            > kad6::kK6FairMaxQueuedBytes)
        return false;
    if (!m_fair_scheduler.Enqueue(stream_id, bytes.size()))
        return false;
    FairPayload payload;
    payload.direction = direction;
    payload.credit_bytes = credit_bytes;
    payload.bytes = std::move(bytes);
    m_fair_payload_bytes += payload.bytes.size();
    queue.push_back(std::move(payload));
    return true;
}

void LiveTunnelScheduler::ReleaseFairStream(std::uint64_t stream_id)
{
    const auto payloads = m_fair_payloads.find(stream_id);
    if (payloads != m_fair_payloads.end()) {
        for (const FairPayload& payload : payloads->second)
            m_fair_payload_bytes -= (std::min<std::uint64_t>)(
                m_fair_payload_bytes, payload.bytes.size());
        m_fair_payloads.erase(payloads);
    }
    m_fair_credits.erase(stream_id);
    m_fair_scheduler.ReleaseStream(stream_id);
    const auto allocation = m_fair_allocation_by_stream.find(stream_id);
    if (allocation != m_fair_allocation_by_stream.end()) {
        m_fair_scheduler.ReleaseAllocation(allocation->second);
        m_fair_allocation_by_stream.erase(allocation);
    }
}

void LiveTunnelScheduler::ReleaseFairAllocation(
    std::uint64_t allocation_id) noexcept
{
    m_fair_scheduler.ReleaseAllocation(allocation_id);
}

std::vector<LiveFairReady> LiveTunnelScheduler::PollFair(
    std::uint64_t max_bytes, std::size_t max_grants)
{
    std::vector<kad6::K6FairGrant> grants;
    m_fair_scheduler.Poll(max_bytes, max_grants, grants);
    std::vector<std::uint64_t> touched;
    for (const kad6::K6FairGrant& grant : grants) {
        m_fair_credits[grant.stream_id] += grant.bytes;
        if (std::find(touched.begin(), touched.end(), grant.stream_id)
            == touched.end())
            touched.push_back(grant.stream_id);
    }

    std::vector<LiveFairReady> ready;
    for (const std::uint64_t stream_id : touched) {
        const auto queue = m_fair_payloads.find(stream_id);
        if (queue == m_fair_payloads.end())
            continue;
        std::uint64_t& credit = m_fair_credits[stream_id];
        while (!queue->second.empty()
               && credit >= queue->second.front().bytes.size()) {
            FairPayload payload = std::move(queue->second.front());
            queue->second.pop_front();
            credit -= payload.bytes.size();
            m_fair_payload_bytes -= (std::min<std::uint64_t>)(
                m_fair_payload_bytes, payload.bytes.size());
            LiveFairReady item;
            item.stream_id = stream_id;
            item.direction = payload.direction;
            item.credit_bytes = payload.credit_bytes;
            item.bytes = std::move(payload.bytes);
            ready.push_back(std::move(item));
        }
        if (queue->second.empty()) {
            m_fair_payloads.erase(queue);
            if (credit == 0)
                m_fair_credits.erase(stream_id);
        }
    }
    return ready;
}

bool LiveTunnelScheduler::HasFairWork() const noexcept
{
    return !m_fair_allocation_by_stream.empty()
        || m_fair_payload_bytes != 0
        || m_fair_scheduler.queued_bytes() != 0;
}

void LiveTunnelScheduler::ClearFair() noexcept
{
    m_fair_payloads.clear();
    m_fair_credits.clear();
    m_fair_allocation_by_stream.clear();
    m_fair_payload_bytes = 0;
    m_fair_scheduler.Reset();
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

bool CharacterizeShapingOwnership()
{
    LiveTunnelScheduler scheduler;
    LiveShapedLinkConfig config;
    config.circ_id = 7;
    config.bucket_kib = 64;
    config.output_layers = 1;
    config.reservoir_ms = 2000;
    config.phase = 7;
    config.nonce_epoch_high_base = 9;
    config.padding_sequence = 11;
    config.now_us = 1000;
    config.idle_tail_epochs = 2;
    if (!scheduler.ConfigureShapedLink(config)
        || !scheduler.HasShapedLink(7)
        || scheduler.ShapedReservoirCapacity(7) != 8)
        return false;

    LiveShapedQueuedRecord record;
    record.terminal = true;
    record.bytes.resize(kad6::kK6ShapedPlainSize);
    if (!scheduler.QueueShapedRecord(7, 99, std::move(record), 1000))
        return false;
    const LiveShapedTickResult first =
        scheduler.PollShapedLinks(1007, {7}, 1);
    if (!first.has_links || first.work.size() != 1
        || first.work[0].circ_id != 7
        || first.work[0].slot.kind != kad6::K6ShapeSlotKind::Data)
        return false;

    if (!scheduler.AcceptShapedReplay(7, 2, 10)
        || scheduler.AcceptShapedReplay(7, 2, 10))
        return false;
    scheduler.SweepShapedReplay({});
    if (!scheduler.AcceptShapedReplay(7, 2, 10))
        return false;
    scheduler.RemoveShapedLink(7);
    if (scheduler.ShapedLinkCount() != 0)
        return false;

    config.circ_id = 8;
    config.now_us = 0;
    config.idle_tail_epochs = 1;
    if (!scheduler.ConfigureShapedLink(config))
        return false;
    const LiveShapedTickResult idle = scheduler.PollShapedLinks(
        kad6::kK6ShapeEpochUs, {8}, 1);
    if (idle.has_links || idle.retired.size() != 1
        || idle.retired[0].circ_id != 8)
        return false;

    kad6::Hash32 issuer{};
    kad6::Hash32 target{};
    issuer[0] = 1;
    target[0] = 2;
    if (!scheduler.RegisterFairAllocation(41, issuer, 1 << 20, 1 << 21)
        || !scheduler.RegisterFairStream(41, 51, target, 1 << 18, 1 << 20)
        || !scheduler.HasFairStream(51)
        || !scheduler.QueueFairPayload(51, 0, {1, 2, 3}, 3)
        || !scheduler.HasFairWork())
        return false;
    scheduler.ReleaseFairStream(51);
    scheduler.ClearFair();
    scheduler.ClearShaping();
    return !scheduler.HasFairWork() && scheduler.ShapedLinkCount() == 0;
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
        && CharacterizeConcurrentClosePublication()
        && CharacterizeShapingOwnership()
        && RunM2ABindingPortCharacterizationSelfTest()
        && RunLiveTunnelReleaseGateCharacterizationSelfTest();
}

} // namespace eSELive
