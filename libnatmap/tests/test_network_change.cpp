#include "natmap/network_change.h"

#include "natmap/mapping_request.h"
#include "natmap/natmap_policy.h"
#include "natmap/natmap_state.h"

#include <cstdio>
#include <limits>

using namespace natmap;

namespace {

int failures = 0;
int checks = 0;

#define CHECK(expr) do { ++checks; if (!(expr)) { ++failures; \
    std::printf("FAIL line %d: %s\n", __LINE__, #expr); } } while (0)

Endpoint Ep(std::uint8_t a, std::uint8_t b, std::uint8_t c,
            std::uint8_t d, std::uint16_t port,
            EndpointSource source) {
    return Endpoint{IpAddress::V4(a, b, c, d), port, source};
}

PlaneSnapshot Candidate(std::uint64_t generation,
                        Transport transport,
                        std::uint16_t local_port,
                        std::uint16_t public_port) {
    PlaneSnapshot plane{};
    plane.local = Ep(
        192, 168, 50, 20, local_port, EndpointSource::LocalInterface);
    TransitionResult result = ApplyEvent(
        plane, StateEvent{EventType::BeginGeneration, generation});
    CHECK(result.disposition == TransitionDisposition::Applied);
    plane = result.snapshot;
    result = ApplyEvent(
        plane, StateEvent{EventType::MappingStarted, generation});
    CHECK(result.disposition == TransitionDisposition::Applied);
    plane = result.snapshot;
    StateEvent mapped{};
    mapped.type = EventType::MappingSucceeded;
    mapped.generation = generation;
    mapped.lease.mapper = MapperKind::UpnpIgd;
    mapped.lease.transport = transport;
    mapped.lease.gateway = Ep(
        192, 168, 50, 1, 0, EndpointSource::LocalInterface);
    mapped.lease.local = plane.local;
    mapped.lease.public_endpoint = Ep(
        8, 8, 8, 8, public_port, EndpointSource::UpnpExternalAddress);
    mapped.lease.requested_external_port = local_port;
    mapped.lease.granted_external_port = public_port;
    mapped.lease.lifetime_seconds = 3600;
    mapped.lease.generation = generation;
    mapped.lease.owned_by_us = true;
    result = ApplyEvent(plane, mapped);
    CHECK(result.disposition == TransitionDisposition::Applied);
    return result.snapshot;
}

void TestInvalidatesEveryPlaneAndAdvancesExactlyOnce() {
    ReachabilitySnapshot current{};
    current.topology_generation = 7;
    current.ed2k_tcp_v4 = Candidate(7, Transport::Tcp, 4662, 51000);
    current.kad_udp_v4 = Candidate(7, Transport::Udp, 4672, 51001);
    current.direct_v6.state = ReachabilityState::Disabled;
    current.direct_v6.generation = 7;

    VerificationAttempt attempt{};
    attempt.attempt_id = 41;
    attempt.topology_generation = 7;
    attempt.endpoint = current.ed2k_tcp_v4.advertised;
    attempt.transport = Transport::Tcp;
    attempt.path = VerificationPath::Direct;
    attempt.started_monotonic_ms = 100;
    attempt.deadline_monotonic_ms = 200;
    StateEvent verify{};
    verify.type = EventType::VerificationStarted;
    verify.generation = 7;
    verify.verification_attempt = attempt;
    const TransitionResult verifying =
        ApplyEvent(current.ed2k_tcp_v4, verify);
    CHECK(verifying.disposition == TransitionDisposition::Applied);
    current.ed2k_tcp_v4 = verifying.snapshot;

    const NetworkChangeTransition changed =
        PrepareNetworkChange(current);
    CHECK(changed.IsApplied());
    CHECK(changed.previous_generation == 7);
    CHECK(changed.current_generation == 8);
    CHECK(changed.snapshot.topology_generation == 8);
    CHECK(changed.snapshot.ed2k_tcp_v4.generation == 8);
    CHECK(changed.snapshot.kad_udp_v4.generation == 8);
    CHECK(changed.snapshot.direct_v6.generation == 8);
    CHECK(changed.snapshot.ed2k_tcp_v4.state ==
          ReachabilityState::Disabled);
    CHECK(changed.snapshot.kad_udp_v4.state ==
          ReachabilityState::Disabled);
    CHECK(changed.snapshot.direct_v6.state ==
          ReachabilityState::Disabled);
    CHECK(changed.snapshot.ed2k_tcp_v4.reason ==
          ReasonCode::InterfaceChanged);
    CHECK(changed.snapshot.kad_udp_v4.reason ==
          ReasonCode::InterfaceChanged);
    CHECK(changed.snapshot.ed2k_tcp_v4.advertised.SameSocketEndpoint(
        changed.snapshot.ed2k_tcp_v4.local));
    CHECK(changed.snapshot.kad_udp_v4.advertised.SameSocketEndpoint(
        changed.snapshot.kad_udp_v4.local));
    CHECK(changed.cancelled_attempt_ids[0] == 41);
    CHECK(changed.cancelled_attempt_ids[1] == 0);
    CHECK(changed.cancelled_attempt_ids[2] == 0);
    CHECK(changed.withdrew_advertisement);
    CHECK(IsSnapshotConsistent(changed.snapshot.ed2k_tcp_v4));
    CHECK(IsSnapshotConsistent(changed.snapshot.kad_udp_v4));
    CHECK(IsSnapshotConsistent(changed.snapshot.direct_v6));
}

void TestRequestAndCallbackAreFencedByOriginalIdentity() {
    MappingRequestSequence sequence(90);
    MappingResultGate gate;
    const RequestIssue old_request =
        sequence.Issue(7, MappingOperation::Refresh);
    CHECK(old_request.IsIssued());
    CHECK(gate.Arm(old_request.context, 7));
    const MappingRequestContext cancelled = gate.pending();
    CHECK(cancelled.request_id == 90);
    CHECK(cancelled.topology_generation == 7);
    CHECK(gate.CancelPending());
    CHECK(!gate.has_pending());

    MapperResultData late{};
    late.request_id = cancelled.request_id;
    late.topology_generation = cancelled.topology_generation;
    late.operation = cancelled.operation;
    CHECK(gate.ConsumeLegacyEnvelope(late, 8) ==
          ResultAcceptance::NoPendingRequest);

    const RequestIssue rediscovery =
        sequence.Issue(8, MappingOperation::Initial);
    CHECK(rediscovery.IsIssued());
    CHECK(rediscovery.context.request_id == 91);
    CHECK(rediscovery.context.topology_generation == 8);
    CHECK(gate.Arm(rediscovery.context, 8));
    CHECK(gate.ConsumeLegacyEnvelope(late, 8) ==
          ResultAcceptance::StaleTopology);
    CHECK(gate.has_pending());

    MapperResultData current{};
    current.request_id = rediscovery.context.request_id;
    current.topology_generation = 8;
    current.operation = MappingOperation::Initial;
    CHECK(gate.ConsumeLegacyEnvelope(current, 8) ==
          ResultAcceptance::Apply);
    CHECK(!gate.has_pending());
}

void TestInvalidAndExhaustedInputsAreTransactional() {
    ReachabilitySnapshot invalid{};
    invalid.topology_generation = 0;
    const NetworkChangeTransition rejected =
        PrepareNetworkChange(invalid);
    CHECK(rejected.status == NetworkChangeStatus::InvalidSnapshot);
    CHECK(rejected.snapshot.topology_generation == 0);

    ReachabilitySnapshot future_plane{};
    future_plane.topology_generation = 7;
    future_plane.ed2k_tcp_v4.state = ReachabilityState::Disabled;
    future_plane.ed2k_tcp_v4.generation = 8;
    future_plane.kad_udp_v4.state = ReachabilityState::Disabled;
    future_plane.kad_udp_v4.generation = 7;
    future_plane.direct_v6 = future_plane.kad_udp_v4;
    const NetworkChangeTransition future_rejected =
        PrepareNetworkChange(future_plane);
    CHECK(future_rejected.status ==
          NetworkChangeStatus::InvalidSnapshot);
    CHECK(future_rejected.snapshot.ed2k_tcp_v4.generation == 8);

    ReachabilitySnapshot exhausted{};
    exhausted.topology_generation =
        (std::numeric_limits<std::uint64_t>::max)();
    exhausted.ed2k_tcp_v4.state = ReachabilityState::Disabled;
    exhausted.ed2k_tcp_v4.generation =
        exhausted.topology_generation;
    exhausted.kad_udp_v4 = exhausted.ed2k_tcp_v4;
    exhausted.direct_v6 = exhausted.ed2k_tcp_v4;
    const NetworkChangeTransition overflow =
        PrepareNetworkChange(exhausted);
    CHECK(overflow.status == NetworkChangeStatus::GenerationExhausted);
    CHECK(!overflow.IsApplied());
    CHECK(overflow.snapshot.topology_generation ==
          exhausted.topology_generation);
    CHECK(overflow.snapshot.ed2k_tcp_v4.generation ==
          exhausted.ed2k_tcp_v4.generation);
}

void TestRediscoveryCompletesThePreparedGeneration() {
    CHECK(IsNetworkChangeRediscovery(8, 8, 8, false, false));
    PlaneSnapshot mapped =
        Candidate(8, Transport::Tcp, 4662, 52000);
    CHECK(mapped.generation == 8);
    CHECK(mapped.state == ReachabilityState::CandidateMapped);
    CHECK(RequiresAdvertisementRelogin(
        AdvertisementObservation{8, 8, true, false, true}));
    CHECK(ShouldRestartAdvertisementLogin(
        AdvertisementObservation{8, 8, true, false, true},
        false, true, false));
    CHECK(!ShouldRestartAdvertisementLogin(
        AdvertisementObservation{8, 8, true, false, true},
        false, false, false));
    CHECK(!ShouldRestartAdvertisementLogin(
        AdvertisementObservation{8, 8, true, false, true},
        true, false, true));

    VerificationAttempt new_attempt{};
    new_attempt.attempt_id = 42;
    new_attempt.topology_generation = 8;
    new_attempt.endpoint = mapped.advertised;
    new_attempt.transport = Transport::Tcp;
    new_attempt.path = VerificationPath::Direct;
    new_attempt.started_monotonic_ms = 300;
    new_attempt.deadline_monotonic_ms = 400;
    CHECK(new_attempt.attempt_id != 41);
    StateEvent verify{};
    verify.type = EventType::VerificationStarted;
    verify.generation = 8;
    verify.verification_attempt = new_attempt;
    const TransitionResult verifying = ApplyEvent(mapped, verify);
    CHECK(verifying.disposition == TransitionDisposition::Applied);
    mapped = verifying.snapshot;
    CHECK(mapped.state == ReachabilityState::Verifying);
    CHECK(mapped.verification_attempt.attempt_id == 42);
    CHECK(mapped.verification_attempt.topology_generation == 8);

    CHECK(!IsNetworkChangeRediscovery(0, 8, 8, false, false));
    CHECK(!IsNetworkChangeRediscovery(8, 9, 8, false, false));
    CHECK(!IsNetworkChangeRediscovery(8, 8, 7, false, false));
    CHECK(!IsNetworkChangeRediscovery(8, 8, 8, true, false));
    CHECK(!IsNetworkChangeRediscovery(8, 8, 8, false, true));
}

}  // namespace

int main() {
    TestInvalidatesEveryPlaneAndAdvancesExactlyOnce();
    TestRequestAndCallbackAreFencedByOriginalIdentity();
    TestInvalidAndExhaustedInputsAreTransactional();
    TestRediscoveryCompletesThePreparedGeneration();
    std::printf("test_network_change: %d checks, %d failures\n",
                checks, failures);
    return failures == 0 ? 0 : 1;
}
