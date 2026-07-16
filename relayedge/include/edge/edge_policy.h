// SPDX-License-Identifier: MIT
#pragma once

#include "edge/edge_runtime.h"
#include "relay/epr_lease.h"
#include "relay/krp_authority.h"

#include <array>
#include <cstddef>
#include <cstdint>

namespace relayedge {

struct EdgeTarget {
    relay::EprAddressFamily family = relay::EprAddressFamily::None;
    relay::EprAddressBytes address{};
    std::uint16_t port = 0;
};

class IEdgeIpFilter {
public:
    virtual ~IEdgeIpFilter() = default;
    virtual bool IsDenied(const EdgeTarget& target) const noexcept = 0;
};

struct EdgePolicyConfig {
    bool explicit_lab_loopback_port_test = false;
    bool explicit_lab_loopback_ed2k = false;
    std::uint16_t relay_listener_port = 0;
    std::array<std::uint16_t, 32> denied_ports{};
    std::size_t denied_port_count = 0;
};

class EdgePolicyEngine {
public:
    EdgePolicyEngine(const EdgePolicyConfig& config,
                     const IEdgeIpFilter* ip_filter,
                     EdgeMetrics* metrics) noexcept;

    relay::RelayStatus Check(relay::KrpService service,
                             const EdgeTarget& target) noexcept;
    relay::RelayStatus RevalidateBeforeConnect(relay::KrpService service,
                                               const EdgeTarget& target) noexcept;
    std::uint64_t decision_generation() const noexcept { return decision_generation_; }

    static bool IsSpecialAddress(const EdgeTarget& target) noexcept;
    static bool IsInfrastructurePort(std::uint16_t port) noexcept;

private:
    relay::RelayStatus Evaluate(relay::KrpService service,
                                const EdgeTarget& target) noexcept;

    EdgePolicyConfig config_{};
    const IEdgeIpFilter* ip_filter_ = nullptr;
    EdgeMetrics* metrics_ = nullptr;
    std::uint64_t decision_generation_ = 0;
};

} // namespace relayedge
