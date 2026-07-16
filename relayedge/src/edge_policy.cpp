// SPDX-License-Identifier: MIT
#include "edge/edge_policy.h"

#include <algorithm>
#include <limits>

namespace relayedge {

namespace {

bool IsLabLoopback(const EdgeTarget& target) noexcept {
    if (target.family == relay::EprAddressFamily::IPv4)
        return target.address[0] == 127;
    if (target.family != relay::EprAddressFamily::IPv6)
        return false;
    for (std::size_t index = 0; index < 15; ++index) {
        if (target.address[index] != 0)
            return false;
    }
    return target.address[15] == 1;
}

} // namespace

EdgePolicyEngine::EdgePolicyEngine(const EdgePolicyConfig& config,
                                   const IEdgeIpFilter* ip_filter,
                                   EdgeMetrics* metrics) noexcept
    : config_(config), ip_filter_(ip_filter), metrics_(metrics) {
    if (config_.denied_port_count > config_.denied_ports.size())
        config_.denied_port_count = config_.denied_ports.size();
}

bool EdgePolicyEngine::IsSpecialAddress(const EdgeTarget& target) noexcept {
    const relay::Byte* const p = target.address.data();
    if (target.family == relay::EprAddressFamily::IPv4) {
        for (std::size_t index = 4; index < target.address.size(); ++index) {
            if (p[index] != 0)
                return true;
        }
        const relay::Byte a = p[0], b = p[1], c = p[2];
        if (a == 0 || a == 10 || a == 127 || a >= 224)
            return true;
        if (a == 100 && b >= 64 && b <= 127)
            return true;
        if (a == 169 && b == 254)
            return true;
        if (a == 172 && b >= 16 && b <= 31)
            return true;
        if (a == 192 && (b == 168 || b == 0))
            return true;
        if (a == 192 && b == 88 && c == 99)
            return true;
        if (a == 198 && (b == 18 || b == 19 || (b == 51 && c == 100)))
            return true;
        if (a == 203 && b == 0 && c == 113)
            return true;
        return false;
    }
    if (target.family != relay::EprAddressFamily::IPv6)
        return true;
    if ((p[0] & 0xE0u) != 0x20u)
        return true;
    if (p[0] == 0x20 && p[1] == 0x01 &&
        ((p[2] == 0x0D && p[3] == 0xB8) ||
         (p[2] == 0x00 && (p[3] == 0x02 || p[3] == 0x10))))
        return true;
    return false;
}

bool EdgePolicyEngine::IsInfrastructurePort(std::uint16_t port) noexcept {
    constexpr std::array<std::uint16_t, 17> denied = {
        0, 22, 23, 25, 53, 67, 68, 69, 111,
        123, 135, 137, 138, 139, 161, 389, 445,
    };
    return std::find(denied.begin(), denied.end(), port) != denied.end();
}

relay::RelayStatus EdgePolicyEngine::Evaluate(relay::KrpService service,
                                               const EdgeTarget& target) noexcept {
    if (decision_generation_ != (std::numeric_limits<std::uint64_t>::max)())
        ++decision_generation_;
    if (target.port == 0)
        return relay::RelayStatus::TargetForbidden;
    if (service < relay::KrpService::Control ||
        service > relay::KrpService::Diagnostic)
        return relay::RelayStatus::TargetForbidden;

    const bool lab_exception = IsLabLoopback(target) &&
        ((config_.explicit_lab_loopback_port_test && service == relay::KrpService::PortTest) ||
         (config_.explicit_lab_loopback_ed2k && service == relay::KrpService::Ed2kServer));
    if (!lab_exception && IsSpecialAddress(target))
        return relay::RelayStatus::TargetForbidden;
    if (service == relay::KrpService::Control ||
        service == relay::KrpService::LegacyTcpInbound ||
        service == relay::KrpService::Diagnostic)
        return relay::RelayStatus::TargetForbidden;
    if (IsInfrastructurePort(target.port) || target.port == config_.relay_listener_port)
        return relay::RelayStatus::TargetForbidden;
    if (std::find(config_.denied_ports.begin(),
                  config_.denied_ports.begin() + config_.denied_port_count,
                  target.port) != config_.denied_ports.begin() + config_.denied_port_count)
        return relay::RelayStatus::TargetForbidden;
    if (ip_filter_ != nullptr && ip_filter_->IsDenied(target))
        return relay::RelayStatus::TargetForbidden;
    return relay::RelayStatus::Ok;
}

relay::RelayStatus EdgePolicyEngine::Check(relay::KrpService service,
                                            const EdgeTarget& target) noexcept {
    const relay::RelayStatus status = Evaluate(service, target);
    if (status != relay::RelayStatus::Ok && metrics_ != nullptr)
        metrics_->Increment(EdgeMetric::PolicyDenied);
    return status;
}

relay::RelayStatus EdgePolicyEngine::RevalidateBeforeConnect(
    relay::KrpService service,
    const EdgeTarget& target) noexcept {
    return Check(service, target);
}

} // namespace relayedge
