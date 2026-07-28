#pragma once

#include "natmap/natmap_types.h"

#include <array>
#include <cstddef>
#include <cstdint>

namespace natmap {

constexpr std::size_t kOwnedFirewallRuleNameCapacity = 32;
using OwnedFirewallRuleName =
    std::array<char, kOwnedFirewallRuleNameCapacity>;

OwnedFirewallRuleName BuildOwnedFirewallRuleName(
    std::uint64_t profile_owner_token,
    Transport transport) noexcept;
bool IsOwnedFirewallRuleName(
    std::uint64_t profile_owner_token,
    Transport transport,
    const OwnedFirewallRuleName& observed_rule_name) noexcept;

struct FirewallRuleProof {
    std::uint64_t profile_owner_token = 0;
    Transport transport = Transport::Tcp;
    std::uint16_t local_port = 0;
    OwnedFirewallRuleName rule_name{};

    bool IsStructurallyValid() const noexcept;
};

enum class FirewallCleanupDecision : std::uint8_t {
    Owned = 0,
    InvalidProof = 1,
    InvalidObservation = 2,
    ProfileMismatch = 3,
    TransportMismatch = 4,
    PortMismatch = 5,
    NameMismatch = 6,
};

FirewallCleanupDecision EvaluateFirewallCleanup(
    const FirewallRuleProof& proof,
    std::uint64_t current_profile_owner_token,
    Transport observed_transport,
    std::uint16_t observed_local_port,
    const OwnedFirewallRuleName& observed_rule_name) noexcept;

struct SecureAlternativePort {
    std::uint16_t port = 0;
    bool entropy_from_os = false;
};

enum class PortCollisionDecision : std::uint8_t {
    RequestedPort = 0,
    AlternativePort = 1,
    ExplicitFailure = 2,
};

// Resolves only the local policy decision. The caller still owns the actual
// bind/MAP request. A foreign occupied port is never adopted by coincidence.
PortCollisionDecision ResolveInstancePortCollision(
    std::uint64_t requester_profile,
    std::uint64_t observed_owner_profile,
    std::uint16_t requested_port,
    bool requested_port_occupied,
    const SecureAlternativePort& alternative) noexcept;

} // namespace natmap
