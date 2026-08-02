#pragma once

#include <cstdint>

namespace natmap {

enum class CandidateReadiness : std::uint8_t {
    Absent = 0,
    Candidate = 1,
    Verified = 2,
};

enum class PreferredDirectRoute : std::uint8_t {
    Classic = 0,
    MappedV4 = 1,
    DirectV4 = 2,
    DirectV6 = 3,
};

// Stable diagnostic values. Append only; never renumber.
enum class RouteSelectionReason : std::uint8_t {
    NoVerifiedRoute = 0,
    VerifiedMappedV4 = 1,
    VerifiedDirectV4 = 2,
    VerifiedDirectV6 = 3,
    CandidateUnverified = 4,
    StaleGeneration = 5,
    Ipv6Disabled = 6,
    MappingsDisabled = 7,
    PeerIncompatible = 8,
    InvalidInput = 9,
    DirectV4EndpointMismatch = 10,
};

struct CandidateObservation {
    CandidateReadiness readiness = CandidateReadiness::Absent;
    std::uint64_t generation = 0;

    bool IsStructurallyValid(
        std::uint64_t current_generation) const noexcept;
    bool IsVerifiedFor(
        std::uint64_t current_generation) const noexcept;
    bool IsCandidateFor(
        std::uint64_t current_generation) const noexcept;
    bool IsStaleFor(
        std::uint64_t current_generation) const noexcept;
};

struct DirectV4EvidenceInput {
    std::uint64_t current_generation = 0;
    std::uint64_t captured_generation = 0;
    bool server_evidence_current = false;
    bool inbound_evidence_current = false;
    bool public_endpoint_matches_local = false;
    bool local_address_direct_publishable = false;
};

// Converts the product's independently captured OS/server facts into a
// generation-bound observation. Direct IPv4 has no unverified publishable
// state: incomplete or stale evidence remains absent.
CandidateObservation ObserveDirectV4Evidence(
    const DirectV4EvidenceInput& input) noexcept;

struct DirectRouteSelectionInput {
    std::uint64_t topology_generation = 0;
    CandidateObservation direct_v6{};
    CandidateObservation direct_v4{};
    CandidateObservation mapped_v4{};
    bool ipv6_enabled = false;
    bool mappings_enabled = false;
    bool peer_supports_ipv6 = false;
    bool direct_v4_endpoint_current = false;

    bool IsStructurallyValid() const noexcept;
};

struct DirectRouteSelection {
    PreferredDirectRoute route = PreferredDirectRoute::Classic;
    RouteSelectionReason reason =
        RouteSelectionReason::NoVerifiedRoute;
    std::uint64_t generation = 0;
    bool uses_verified_evidence = false;

    bool IsModern() const noexcept {
        return route != PreferredDirectRoute::Classic;
    }
};

// Selection is deterministic and fail-closed. Candidate or stale evidence
// can explain a fallback but can never select a modern route.
DirectRouteSelection SelectPreferredDirectRoute(
    const DirectRouteSelectionInput& input) noexcept;

} // namespace natmap
