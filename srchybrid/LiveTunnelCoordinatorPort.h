// this file is part of eMule eSE - neutral LT9 guard/RTT state port
#pragma once
#include <array>
#include <cstdint>
namespace eSELive {
enum class LiveTunnelGuardLoadDecision : std::uint8_t {
    NeedStorage,
    CachedValid,
    CachedExpired,
};
struct LiveTunnelGuardSnapshot {
    std::array<std::uint8_t,32> node_pub{};
    std::uint64_t expires_at=0;
    bool loaded=false;
};
bool RunLiveTunnelCoordinatorFacadeCharacterizationSelfTest();
} // namespace eSELive
