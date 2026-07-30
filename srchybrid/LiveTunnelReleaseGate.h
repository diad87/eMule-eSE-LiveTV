// this file is part of eMule eSE - portable Kad6 release state owner
#pragma once
#include "M2ABindingPort.h"
#include <array>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>
#include <vector>
namespace eSELive {
struct LiveTunnelReleaseNoticeSnapshot {
    bool running = false;
    std::uint16_t port = 0;
    std::uint64_t requests = 0, rejected = 0, bytes_sent = 0;
};
struct LiveTunnelReleaseStorePort {
    void *context = nullptr, *services_context = nullptr;
    bool (*load)(void*, std::vector<std::uint8_t>&, std::uint32_t&) = nullptr;
    bool (*save)(void*, const std::vector<std::uint8_t>&) = nullptr;
    bool (*random)(void*, std::uint8_t*, std::size_t) = nullptr;
    bool (*notice_start)(void*, std::uint16_t, const std::string&) = nullptr;
    void (*notice_stop)(void*) noexcept = nullptr;
    LiveTunnelReleaseNoticeSnapshot (*notice_snapshot)(void*) noexcept = nullptr;
    bool (*services)(void*, bool, std::uint32_t) = nullptr;
};
struct LiveTunnelReleaseSnapshot {
    bool evidence_present = false;
    bool runtime_healthy = false, public_enabled = false, beta_enabled = false;
    std::uint32_t status = 0;
    std::vector<std::uint8_t> evidence_wire;
};
class LiveTunnelReleaseGate final {
public:
    explicit LiveTunnelReleaseGate(const M2AParentPort& parent);
    LiveTunnelReleaseGate(const LiveTunnelReleaseGate&) = delete;
    LiveTunnelReleaseGate& operator=(const LiveTunnelReleaseGate&) = delete;
    void Configure(const LiveTunnelReleaseStorePort&) noexcept;
    bool LoadEvidence();
    bool SaveEvidence(const std::vector<std::uint8_t>&);
    LiveTunnelReleaseSnapshot Snapshot() const;
    void ApplyEvaluation(bool, bool, bool, std::uint32_t, std::uint32_t,
        std::uint32_t, std::uint32_t, std::uint32_t);
    bool IsEnabled() const noexcept;
    bool GetChallenge(std::string&, std::uint64_t);
    bool ConsumeChallenge(const std::string&, std::uint64_t) noexcept;
    bool StartNotice(std::uint16_t, const std::string&);
    void StopNotice() noexcept;
    LiveTunnelReleaseNoticeSnapshot NoticeSnapshot() const noexcept;
private:
    static bool DecodeHex(
        const std::string&, std::array<std::uint8_t, 32>&) noexcept;
    void ClearChallengeLocked() noexcept;
    bool m_k6PublicStableEnabled = false;
    bool m_k6PublicBetaEnabled = false;
    bool m_k6ReleaseEvidenceLoaded = false;
    bool m_k6ReleaseEvidencePresent = false;
    bool m_k6ReleaseRuntimeHealthy = false;
    std::uint32_t m_k6ReleaseStatus = 0;
    std::vector<std::uint8_t> m_k6ReleaseEvidence;
    mutable std::mutex m_k6ReleaseLock;
    std::array<std::uint8_t, 32> m_k6ReleaseChallenge{};
    std::uint64_t m_k6ReleaseChallengeExpires = 0;
    bool m_k6ReleaseChallengeReady = false;
    LiveTunnelReleaseStorePort m_k6ExitNoticeServer;
};
M2AModuleHandle M2A_BIND_LT1_BAB3CE64A0(const M2AParentPort& parent);
LiveTunnelReleaseGate* ResolveLiveTunnelReleaseGate(M2AModuleHandle&) noexcept;
const LiveTunnelReleaseGate* ResolveLiveTunnelReleaseGate(
    const M2AModuleHandle&) noexcept;
bool RunLiveTunnelReleaseGateCharacterizationSelfTest();
} // namespace eSELive
