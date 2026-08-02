// this file is part of eMule eSE - LT9 coordinator state owner
#pragma once
#include "LiveTunnelCoordinatorPort.h"
#include "M2ABindingPort.h"
namespace eSELive {
class LiveTunnelCoordinatorFacade {
public:
    explicit LiveTunnelCoordinatorFacade(const M2AParentPort& parent) noexcept;
    LiveTunnelGuardLoadDecision BeginGuardLoad(std::uint64_t now) noexcept;
    void SetGuard(const std::uint8_t nodePub[32],std::uint64_t expiresAt) noexcept;
    bool CopyGuard(std::array<std::uint8_t,32>& nodePub) const noexcept;
    bool ConsumeRtt(std::uint32_t requestId,std::uint32_t now,std::uint32_t& elapsed) noexcept;
    void RecordRtt(std::uint32_t requestId,std::uint32_t sentAt) noexcept;
    void ClearRtt() noexcept;
    bool ShouldAttemptQuotaGuard(std::uint32_t now,
                                 std::uint32_t interval) noexcept;
private:
    const void* m_parent=nullptr;
    std::array<std::uint8_t,32> m_k6GuardNodePub{};
    std::uint64_t m_k6GuardExpiresAt=0;
    bool m_k6GuardLoaded=false;
    std::uint32_t m_rttPingSentTick=0;
    std::uint32_t m_rttPingReqId=0;
    std::uint32_t m_lastK6QuotaGuardAttemptTick=0;
};
M2AModuleHandle M2A_BIND_LT9_A14692E28F(const M2AParentPort&);
bool RunLiveTunnelCoordinatorFacadeCharacterizationSelfTest();
} // namespace eSELive
