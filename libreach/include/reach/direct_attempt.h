// SPDX-License-Identifier: MIT
// Deterministic, side-effect-free filtering and ordering of native peer routes.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace reach {

inline constexpr std::size_t kDirectMaxCandidates = 16;
// Raw observations may include invalid entries and duplicates. Bound their
// processing separately from the retained, validated candidate set.
inline constexpr std::size_t kDirectMaxCandidateInputs = 64;
inline constexpr std::size_t kDirectMaxRoutes = 8;

enum class DirectStatus : std::uint8_t {
    Ok,
    TooManyCandidates,
    TooManyRoutes,
    InvalidPolicy
};

enum class DirectKind : std::uint8_t {
    DirectV6,
    DirectV4,
    VerifiedMapping,
    Callback,
    Punch2,
    Punch3,
    Predicted,
    Birthday
};

enum class DirectEvidence : std::uint8_t {
    Advertised,
    Observed,
    Reserved,
    MappingVerified,
    InboundVerified
};

enum class DirectScope : std::uint8_t { Global, SameLan };

enum DirectTransport : std::uint8_t {
    DirectTcp = 1u << 0,
    DirectUtp = 1u << 1,
    DirectQuic = 1u << 2
};

struct DirectCandidate {
    std::uint64_t id = 0;
    DirectKind kind = DirectKind::DirectV4;
    std::uint8_t family = 0;             // 4 or 6
    std::array<std::uint8_t, 16> address{}; // v4 occupies bytes 0..3; tail is zero
    std::uint16_t port = 0;
    std::uint8_t transport_mask = 0;
    DirectEvidence evidence = DirectEvidence::Advertised;
    DirectScope scope = DirectScope::Global;
    std::uint64_t topology_generation = 0;
    std::uint64_t expires_monotonic_ms = 0;
    std::uint64_t interface_id = 0;       // required for SameLan
    std::uint32_t rtt_ms = 0;             // zero means unknown
};

struct DirectPolicy {
    std::uint64_t topology_generation = 0;
    std::uint64_t now_monotonic_ms = 0;
    std::uint64_t required_interface_id = 0;
    std::uint8_t local_interface_family = 0;
    std::array<std::uint8_t, 16> local_interface_address{};
    std::uint8_t local_prefix_length = 0;
    bool allow_ipv4 = true;
    bool allow_ipv6 = true;
    bool allow_same_lan = false;
    bool allow_birthday = false; // experimental, explicit opt-in only
};

struct DirectPlan {
    DirectStatus status = DirectStatus::Ok;
    std::vector<DirectCandidate> routes;
};

// Reject malformed, stale, expired, unsafe, or untrusted candidates before
// ordering. SAME_LAN also requires a matching local interface prefix. Duplicates
// collapse deterministically to their strongest evidence.
DirectPlan BuildDirectPlan(const DirectPolicy& policy,
                           const std::vector<DirectCandidate>& candidates);

} // namespace reach
