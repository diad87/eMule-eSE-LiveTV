#pragma once
#include "M2ABindingPort.h"
#include <cstdint>
#include <memory>
#include <mutex>
namespace eSELive {
struct LiveTunnelQuotaBridge;
class LiveTunnelQuotaAuthority {
public:
    explicit LiveTunnelQuotaAuthority(const M2AParentPort&) noexcept;
    ~LiveTunnelQuotaAuthority() noexcept;
    LiveTunnelQuotaAuthority(const LiveTunnelQuotaAuthority&) = delete;
private:
    friend struct LiveTunnelQuotaBridge;
    using Store = std::unique_ptr<void, void (*)(void*)>;
    Store m_k6Hardening{nullptr, nullptr};
    Store m_k6EconomyTelemetry{nullptr, nullptr};
    Store m_k6EconomyInputs{nullptr, nullptr};
    bool m_k6EconomyReady = false;
    std::uint64_t m_k6EconomyUsefulBytes = 0;
    std::uint64_t m_k6EconomyPublishAttempts = 0;
    std::uint64_t m_k6EconomyLastUsefulBytes = 0;
    std::uint64_t m_k6EconomyLastPublishAttempts = 0;
    std::uint64_t m_k6EconomyLastSampleAt = 0;
    std::uint64_t m_k6EconomyLastProcessCpu = 0;
    std::uint64_t m_k6EconomyLastSystemCpu = 0;
    mutable std::mutex m_k6EconomyMutex;
    Store m_k6QuotaCrypto{nullptr, nullptr};
    Store m_k6QuotaCertificate{nullptr, nullptr};
    Store m_k6QuotaCertificateWire{nullptr, nullptr};
    std::uint64_t m_k6QuotaCertificateEpoch = 0;
    bool m_k6QuotaInitAttempted = false;
    Store m_k6QuotaIssuerLimiter{nullptr, nullptr};
    Store m_k6QuotaHierarchy{nullptr, nullptr};
    Store m_k6QuotaSpent{nullptr, nullptr};
    Store m_k6QuotaGrants{nullptr, nullptr};
    mutable std::mutex m_k6QuotaMutex;
};
M2AModuleHandle M2A_BIND_LT2_8892179A6E(const M2AParentPort& parent);
} // namespace eSELive
