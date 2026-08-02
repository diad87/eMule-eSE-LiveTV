#include "natmap/direct_route_selection.h"

#include <cstdio>

using namespace natmap;

namespace {

int failures = 0;
int checks = 0;

#define CHECK(expr) do { ++checks; if (!(expr)) { ++failures; \
    std::printf("FAIL line %d: %s\n", __LINE__, #expr); } } while (0)

CandidateObservation Observation(CandidateReadiness readiness,
                                 std::uint64_t generation = 11) {
    CandidateObservation result{};
    result.readiness = readiness;
    result.generation =
        readiness == CandidateReadiness::Absent ? 0 : generation;
    return result;
}

DirectRouteSelectionInput Baseline() {
    DirectRouteSelectionInput input{};
    input.topology_generation = 11;
    input.ipv6_enabled = true;
    input.mappings_enabled = true;
    input.peer_supports_ipv6 = true;
    input.direct_v4_endpoint_current = true;
    return input;
}

void CheckSelection(const DirectRouteSelectionInput& input,
                    PreferredDirectRoute route,
                    RouteSelectionReason reason,
                    bool verified) {
    const DirectRouteSelection selected = SelectPreferredDirectRoute(input);
    CHECK(selected.route == route);
    CHECK(selected.reason == reason);
    CHECK(selected.uses_verified_evidence == verified);
    CHECK(selected.generation ==
          (verified ? input.topology_generation : 0));
    CHECK(selected.IsModern() == (route != PreferredDirectRoute::Classic));
}

void TestNormativeTable() {
    DirectRouteSelectionInput input = Baseline();
    input.direct_v6 = Observation(CandidateReadiness::Verified);
    input.direct_v4 = Observation(CandidateReadiness::Verified);
    input.mapped_v4 = Observation(CandidateReadiness::Verified);
    CheckSelection(input, PreferredDirectRoute::DirectV6,
                   RouteSelectionReason::VerifiedDirectV6, true);

    input.direct_v6 = Observation(CandidateReadiness::Candidate);
    CheckSelection(input, PreferredDirectRoute::DirectV4,
                   RouteSelectionReason::VerifiedDirectV4, true);

    input.direct_v6 = Observation(CandidateReadiness::Absent);
    input.direct_v4 = Observation(CandidateReadiness::Absent);
    CheckSelection(input, PreferredDirectRoute::MappedV4,
                   RouteSelectionReason::VerifiedMappedV4, true);

    input.mapped_v4 = Observation(CandidateReadiness::Candidate);
    CheckSelection(input, PreferredDirectRoute::Classic,
                   RouteSelectionReason::CandidateUnverified, false);
}

void TestIPv6AndMappingPreferences() {
    DirectRouteSelectionInput input = Baseline();
    input.direct_v6 = Observation(CandidateReadiness::Verified);
    input.direct_v4 = Observation(CandidateReadiness::Verified);
    input.mapped_v4 = Observation(CandidateReadiness::Verified);

    input.ipv6_enabled = false;
    CheckSelection(input, PreferredDirectRoute::DirectV4,
                   RouteSelectionReason::VerifiedDirectV4, true);

    input.direct_v4 = Observation(CandidateReadiness::Absent);
    CheckSelection(input, PreferredDirectRoute::MappedV4,
                   RouteSelectionReason::VerifiedMappedV4, true);

    input.mappings_enabled = false;
    CheckSelection(input, PreferredDirectRoute::Classic,
                   RouteSelectionReason::Ipv6Disabled, false);

    input.ipv6_enabled = true;
    CheckSelection(input, PreferredDirectRoute::DirectV6,
                   RouteSelectionReason::VerifiedDirectV6, true);

    input = Baseline();
    input.mapped_v4 = Observation(CandidateReadiness::Verified);
    input.mappings_enabled = false;
    CheckSelection(input, PreferredDirectRoute::Classic,
                   RouteSelectionReason::MappingsDisabled, false);
}

void TestOldPeerFallback() {
    DirectRouteSelectionInput input = Baseline();
    input.direct_v6 = Observation(CandidateReadiness::Verified);
    input.direct_v4 = Observation(CandidateReadiness::Verified);
    input.mapped_v4 = Observation(CandidateReadiness::Verified);
    input.peer_supports_ipv6 = false;
    CheckSelection(input, PreferredDirectRoute::DirectV4,
                   RouteSelectionReason::VerifiedDirectV4, true);

    input.direct_v4 = Observation(CandidateReadiness::Absent);
    CheckSelection(input, PreferredDirectRoute::MappedV4,
                   RouteSelectionReason::VerifiedMappedV4, true);

    input.mappings_enabled = false;
    CheckSelection(input, PreferredDirectRoute::Classic,
                   RouteSelectionReason::PeerIncompatible, false);
}

void TestGenerationFencing() {
    DirectRouteSelectionInput input = Baseline();
    input.direct_v6 = Observation(CandidateReadiness::Verified, 10);
    input.direct_v4 = Observation(CandidateReadiness::Verified, 11);
    input.mapped_v4 = Observation(CandidateReadiness::Verified, 10);
    CheckSelection(input, PreferredDirectRoute::DirectV4,
                   RouteSelectionReason::VerifiedDirectV4, true);

    input.direct_v4 = Observation(CandidateReadiness::Absent);
    CheckSelection(input, PreferredDirectRoute::Classic,
                   RouteSelectionReason::StaleGeneration, false);

    input.direct_v6 = Observation(CandidateReadiness::Verified, 12);
    CheckSelection(input, PreferredDirectRoute::Classic,
                   RouteSelectionReason::InvalidInput, false);

    input = Baseline();
    input.topology_generation = 0;
    CheckSelection(input, PreferredDirectRoute::Classic,
                   RouteSelectionReason::InvalidInput, false);
}

void TestCandidatesNeverWin() {
    for (unsigned mask = 0; mask < 8; ++mask) {
        DirectRouteSelectionInput input = Baseline();
        input.direct_v6 = (mask & 1) != 0
            ? Observation(CandidateReadiness::Candidate)
            : Observation(CandidateReadiness::Absent);
        input.direct_v4 = (mask & 2) != 0
            ? Observation(CandidateReadiness::Candidate)
            : Observation(CandidateReadiness::Absent);
        input.mapped_v4 = (mask & 4) != 0
            ? Observation(CandidateReadiness::Candidate)
            : Observation(CandidateReadiness::Absent);
        const DirectRouteSelection selected =
            SelectPreferredDirectRoute(input);
        CHECK(selected.route == PreferredDirectRoute::Classic);
        CHECK(!selected.uses_verified_evidence);
        CHECK(selected.generation == 0);
        CHECK(selected.reason == ((mask == 0)
            ? RouteSelectionReason::NoVerifiedRoute
            : RouteSelectionReason::CandidateUnverified));
    }
}

void TestDirectV4EndpointBinding() {
    DirectRouteSelectionInput input = Baseline();
    input.direct_v4 = Observation(CandidateReadiness::Verified);
    input.direct_v4_endpoint_current = false;
    CheckSelection(input, PreferredDirectRoute::Classic,
                   RouteSelectionReason::DirectV4EndpointMismatch, false);

    input.mapped_v4 = Observation(CandidateReadiness::Verified);
    CheckSelection(input, PreferredDirectRoute::MappedV4,
                   RouteSelectionReason::VerifiedMappedV4, true);
}

void TestClosedInputShape() {
    DirectRouteSelectionInput input = Baseline();
    input.direct_v6 = Observation(CandidateReadiness::Absent);
    input.direct_v6.generation = 11;
    CheckSelection(input, PreferredDirectRoute::Classic,
                   RouteSelectionReason::InvalidInput, false);

    input = Baseline();
    input.direct_v4.readiness =
        static_cast<CandidateReadiness>(255);
    CheckSelection(input, PreferredDirectRoute::Classic,
                   RouteSelectionReason::InvalidInput, false);

    input = Baseline();
    input.mapped_v4 = Observation(CandidateReadiness::Candidate);
    input.mapped_v4.generation = 0;
    CheckSelection(input, PreferredDirectRoute::Classic,
                   RouteSelectionReason::InvalidInput, false);
}

void TestDirectV4EvidenceProducer() {
    DirectV4EvidenceInput input{};
    input.current_generation = 11;
    input.captured_generation = 11;
    input.server_evidence_current = true;
    input.inbound_evidence_current = true;
    input.public_endpoint_matches_local = true;
    input.local_address_direct_publishable = true;

    const auto check = [](const DirectV4EvidenceInput& evidence,
                          CandidateReadiness readiness,
                          std::uint64_t generation) {
        const CandidateObservation observed =
            ObserveDirectV4Evidence(evidence);
        CHECK(observed.readiness == readiness);
        CHECK(observed.generation == generation);
    };
    check(input, CandidateReadiness::Verified, 11);

    input.server_evidence_current = false;
    check(input, CandidateReadiness::Absent, 0);
    input.server_evidence_current = true;
    input.inbound_evidence_current = false;
    check(input, CandidateReadiness::Absent, 0);
    input.inbound_evidence_current = true;
    input.public_endpoint_matches_local = false;
    check(input, CandidateReadiness::Absent, 0);
    input.public_endpoint_matches_local = true;
    input.local_address_direct_publishable = false;
    check(input, CandidateReadiness::Absent, 0);
    input.local_address_direct_publishable = true;
    input.captured_generation = 10;
    check(input, CandidateReadiness::Absent, 0);
    input.captured_generation = 0;
    check(input, CandidateReadiness::Absent, 0);
    input.captured_generation = 11;
    input.current_generation = 0;
    check(input, CandidateReadiness::Absent, 0);
}

} // namespace

int main() {
    TestNormativeTable();
    TestIPv6AndMappingPreferences();
    TestOldPeerFallback();
    TestGenerationFencing();
    TestCandidatesNeverWin();
    TestDirectV4EndpointBinding();
    TestClosedInputShape();
    TestDirectV4EvidenceProducer();
    std::printf("test_direct_route_selection: %d checks, %d failures\n",
                checks, failures);
    return failures == 0 ? 0 : 1;
}
