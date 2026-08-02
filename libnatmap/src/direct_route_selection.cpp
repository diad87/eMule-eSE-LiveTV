#include "natmap/direct_route_selection.h"

namespace natmap {

namespace {

bool IsKnownReadiness(CandidateReadiness readiness) noexcept {
    return readiness == CandidateReadiness::Absent ||
           readiness == CandidateReadiness::Candidate ||
           readiness == CandidateReadiness::Verified;
}

DirectRouteSelection VerifiedSelection(
    PreferredDirectRoute route,
    RouteSelectionReason reason,
    std::uint64_t generation) noexcept {
    DirectRouteSelection selected{};
    selected.route = route;
    selected.reason = reason;
    selected.generation = generation;
    selected.uses_verified_evidence = true;
    return selected;
}

DirectRouteSelection ClassicSelection(
    RouteSelectionReason reason) noexcept {
    DirectRouteSelection selected{};
    selected.reason = reason;
    return selected;
}

} // namespace

bool CandidateObservation::IsStructurallyValid(
    std::uint64_t current_generation) const noexcept {
    if (current_generation == 0 || !IsKnownReadiness(readiness))
        return false;
    if (readiness == CandidateReadiness::Absent)
        return generation == 0;
    return generation != 0 && generation <= current_generation;
}

bool CandidateObservation::IsVerifiedFor(
    std::uint64_t current_generation) const noexcept {
    return readiness == CandidateReadiness::Verified &&
           generation == current_generation;
}

bool CandidateObservation::IsCandidateFor(
    std::uint64_t current_generation) const noexcept {
    return readiness == CandidateReadiness::Candidate &&
           generation == current_generation;
}

bool CandidateObservation::IsStaleFor(
    std::uint64_t current_generation) const noexcept {
    return readiness != CandidateReadiness::Absent &&
           generation != 0 && generation < current_generation;
}

CandidateObservation ObserveDirectV4Evidence(
    const DirectV4EvidenceInput& input) noexcept {
    CandidateObservation observation{};
    if (input.current_generation == 0 ||
        input.captured_generation == 0 ||
        input.captured_generation != input.current_generation ||
        !input.server_evidence_current ||
        !input.inbound_evidence_current ||
        !input.public_endpoint_matches_local ||
        !input.local_address_direct_publishable)
        return observation;
    observation.readiness = CandidateReadiness::Verified;
    observation.generation = input.current_generation;
    return observation;
}

bool DirectRouteSelectionInput::IsStructurallyValid() const noexcept {
    return topology_generation != 0 &&
           direct_v6.IsStructurallyValid(topology_generation) &&
           direct_v4.IsStructurallyValid(topology_generation) &&
           mapped_v4.IsStructurallyValid(topology_generation);
}

DirectRouteSelection SelectPreferredDirectRoute(
    const DirectRouteSelectionInput& input) noexcept {
    if (!input.IsStructurallyValid())
        return ClassicSelection(RouteSelectionReason::InvalidInput);

    if (input.ipv6_enabled && input.peer_supports_ipv6 &&
        input.direct_v6.IsVerifiedFor(input.topology_generation))
        return VerifiedSelection(
            PreferredDirectRoute::DirectV6,
            RouteSelectionReason::VerifiedDirectV6,
            input.topology_generation);

    if (input.direct_v4.IsVerifiedFor(input.topology_generation) &&
        input.direct_v4_endpoint_current)
        return VerifiedSelection(
            PreferredDirectRoute::DirectV4,
            RouteSelectionReason::VerifiedDirectV4,
            input.topology_generation);

    if (input.mappings_enabled &&
        input.mapped_v4.IsVerifiedFor(input.topology_generation))
        return VerifiedSelection(
            PreferredDirectRoute::MappedV4,
            RouteSelectionReason::VerifiedMappedV4,
            input.topology_generation);

    const bool currentVerifiedV6 =
        input.direct_v6.IsVerifiedFor(input.topology_generation);
    if (currentVerifiedV6 && !input.ipv6_enabled)
        return ClassicSelection(RouteSelectionReason::Ipv6Disabled);
    if (currentVerifiedV6 && !input.peer_supports_ipv6)
        return ClassicSelection(RouteSelectionReason::PeerIncompatible);
    if (input.mapped_v4.IsVerifiedFor(input.topology_generation) &&
        !input.mappings_enabled)
        return ClassicSelection(RouteSelectionReason::MappingsDisabled);
    if (input.direct_v4.IsVerifiedFor(input.topology_generation) &&
        !input.direct_v4_endpoint_current)
        return ClassicSelection(
            RouteSelectionReason::DirectV4EndpointMismatch);

    if (input.direct_v6.IsStaleFor(input.topology_generation) ||
        input.direct_v4.IsStaleFor(input.topology_generation) ||
        input.mapped_v4.IsStaleFor(input.topology_generation))
        return ClassicSelection(RouteSelectionReason::StaleGeneration);

    if (input.direct_v6.IsCandidateFor(input.topology_generation) ||
        input.direct_v4.IsCandidateFor(input.topology_generation) ||
        input.mapped_v4.IsCandidateFor(input.topology_generation))
        return ClassicSelection(RouteSelectionReason::CandidateUnverified);

    return ClassicSelection(RouteSelectionReason::NoVerifiedRoute);
}

} // namespace natmap
