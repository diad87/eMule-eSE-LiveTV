#include "natmap/instance_isolation.h"

#include <cstring>

namespace natmap {
namespace {

bool IsKnownTransport(Transport transport) noexcept {
    return transport == Transport::Tcp || transport == Transport::Udp;
}

bool SameName(const OwnedFirewallRuleName& left,
              const OwnedFirewallRuleName& right) noexcept {
    return std::memcmp(left.data(), right.data(), left.size()) == 0;
}

} // namespace

OwnedFirewallRuleName BuildOwnedFirewallRuleName(
    std::uint64_t profile_owner_token,
    Transport transport) noexcept {
    OwnedFirewallRuleName result{};
    if (profile_owner_token == 0 || !IsKnownTransport(transport))
        return result;

    const char prefix[] = "eSE-fw-";
    std::memcpy(result.data(), prefix, sizeof(prefix) - 1);
    result[7] = transport == Transport::Tcp ? 'T' : 'U';
    result[8] = '-';
    static constexpr char hex[] = "0123456789abcdef";
    for (unsigned i = 0; i < 16; ++i) {
        const unsigned shift = (15u - i) * 4u;
        result[9 + i] = hex[(profile_owner_token >> shift) & 0x0fu];
    }
    result[25] = '\0';
    return result;
}

bool IsOwnedFirewallRuleName(
    std::uint64_t profile_owner_token,
    Transport transport,
    const OwnedFirewallRuleName& observed_rule_name) noexcept {
    if (profile_owner_token == 0 || !IsKnownTransport(transport))
        return false;
    return SameName(
        BuildOwnedFirewallRuleName(profile_owner_token, transport),
        observed_rule_name);
}

bool FirewallRuleProof::IsStructurallyValid() const noexcept {
    if (profile_owner_token == 0 || local_port == 0 ||
        !IsKnownTransport(transport))
        return false;
    return IsOwnedFirewallRuleName(
        profile_owner_token, transport, rule_name);
}

FirewallCleanupDecision EvaluateFirewallCleanup(
    const FirewallRuleProof& proof,
    std::uint64_t current_profile_owner_token,
    Transport observed_transport,
    std::uint16_t observed_local_port,
    const OwnedFirewallRuleName& observed_rule_name) noexcept {
    if (!proof.IsStructurallyValid())
        return FirewallCleanupDecision::InvalidProof;
    if (current_profile_owner_token == 0 || observed_local_port == 0 ||
        !IsKnownTransport(observed_transport))
        return FirewallCleanupDecision::InvalidObservation;
    if (proof.profile_owner_token != current_profile_owner_token)
        return FirewallCleanupDecision::ProfileMismatch;
    if (proof.transport != observed_transport)
        return FirewallCleanupDecision::TransportMismatch;
    if (proof.local_port != observed_local_port)
        return FirewallCleanupDecision::PortMismatch;
    if (!SameName(proof.rule_name, observed_rule_name))
        return FirewallCleanupDecision::NameMismatch;
    return FirewallCleanupDecision::Owned;
}

PortCollisionDecision ResolveInstancePortCollision(
    std::uint64_t requester_profile,
    std::uint64_t observed_owner_profile,
    std::uint16_t requested_port,
    bool requested_port_occupied,
    const SecureAlternativePort& alternative) noexcept {
    if (requester_profile == 0 || requested_port == 0)
        return PortCollisionDecision::ExplicitFailure;
    if (!requested_port_occupied)
        return PortCollisionDecision::RequestedPort;
    if (observed_owner_profile == requester_profile)
        return PortCollisionDecision::RequestedPort;
    if (alternative.entropy_from_os && alternative.port != 0 &&
        alternative.port != requested_port)
        return PortCollisionDecision::AlternativePort;
    return PortCollisionDecision::ExplicitFailure;
}

} // namespace natmap
