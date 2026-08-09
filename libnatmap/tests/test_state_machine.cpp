#include "natmap/natmap_state.h"

#include <cstdint>
#include <cstdio>

using namespace natmap;

namespace {

int checks = 0;
int failures = 0;
#define CHECK(expr) do { ++checks; if (!(expr)) { ++failures; \
    std::printf("FAIL line %d: %s\n", __LINE__, #expr); } } while (0)

Endpoint Ep(std::uint8_t a, std::uint8_t b, std::uint8_t c,
            std::uint8_t d, std::uint16_t port, EndpointSource source) {
    return Endpoint{IpAddress::V4(a, b, c, d), port, source};
}

PortLease Lease(std::uint64_t generation, std::uint16_t external_port) {
    PortLease lease{};
    lease.mapper = MapperKind::Pcp;
    lease.transport = Transport::Tcp;
    lease.local = Ep(192, 168, 1, 20, 4662, EndpointSource::LocalInterface);
    lease.public_endpoint = Ep(88, 11, 22, 4, external_port, EndpointSource::PcpMap);
    lease.requested_external_port = 4662;
    lease.granted_external_port = external_port;
    lease.lifetime_seconds = 3600;
    lease.generation = generation;
    lease.owned_by_us = true;
    return lease;
}

VerificationAttempt Attempt(
    const Endpoint& endpoint, std::uint64_t generation,
    std::uint64_t attempt_id, std::uint64_t started_ms = 0) {
    VerificationAttempt attempt{};
    attempt.attempt_id = attempt_id;
    attempt.topology_generation = generation;
    attempt.endpoint = endpoint;
    attempt.transport = Transport::Tcp;
    attempt.path = VerificationPath::Direct;
    attempt.started_monotonic_ms = started_ms;
    attempt.deadline_monotonic_ms =
        started_ms + VerificationAttempt::kMaximumWindowMs;
    return attempt;
}

StateEvent StartVerificationEvent(
    const Endpoint& endpoint, std::uint64_t generation,
    std::uint64_t attempt_id, std::uint64_t started_ms = 0) {
    StateEvent event{};
    event.type = EventType::VerificationStarted;
    event.generation = generation;
    event.verification_attempt =
        Attempt(endpoint, generation, attempt_id, started_ms);
    return event;
}

void TestHappyPathAndStaleFencing() {
    PlaneSnapshot state{};
    state.local = Ep(192, 168, 1, 20, 4662, EndpointSource::LocalInterface);
    TransitionResult r = ApplyEvent(state, StateEvent{EventType::BeginGeneration, 1});
    CHECK(r.disposition == TransitionDisposition::Applied);
    state = r.snapshot;
    r = ApplyEvent(state, StateEvent{EventType::MappingStarted, 1});
    CHECK(r.snapshot.state == ReachabilityState::Mapping);
    state = r.snapshot;

    StateEvent mapped{};
    mapped.type = EventType::MappingSucceeded;
    mapped.generation = 1;
    mapped.lease = Lease(1, 52144);
    r = ApplyEvent(state, mapped);
    CHECK(r.snapshot.state == ReachabilityState::CandidateMapped);
    state = r.snapshot;

    const VerificationAttempt attempt =
        Attempt(mapped.lease.public_endpoint, 1, 1001);
    StateEvent started = StartVerificationEvent(
        mapped.lease.public_endpoint, 1, attempt.attempt_id);
    r = ApplyEvent(state, started);
    CHECK(r.snapshot.state == ReachabilityState::Verifying);
    state = r.snapshot;

    StateEvent verified{};
    verified.type = EventType::VerificationSucceeded;
    verified.generation = 1;
    verified.advertised = mapped.lease.public_endpoint;
    verified.verification_attempt = attempt;
    StateEvent server{};
    server.type = EventType::ServerEvidenceObserved;
    server.generation = 1;
    server.primary_evidence = Evidence{
        EvidenceKind::ServerHighId, verified.advertised, 1, 100,
        attempt.attempt_id};
    r = ApplyEvent(state, server);
    CHECK(r.snapshot.state == ReachabilityState::Verifying);
    state = r.snapshot;
    StateEvent inbound{};
    inbound.type = EventType::InboundEvidenceObserved;
    inbound.generation = 1;
    inbound.inbound_evidence = Evidence{
        EvidenceKind::InboundTcpAccept, verified.advertised, 1, 101,
        attempt.attempt_id};
    r = ApplyEvent(state, inbound);
    CHECK(r.snapshot.state == ReachabilityState::Verifying);
    state = r.snapshot;
    r = ApplyEvent(state, verified);
    CHECK(r.snapshot.state == ReachabilityState::Reachable);
    CHECK(r.snapshot.HasClassicHighIdEvidence());
    state = r.snapshot;

    StateEvent stale{EventType::LeaseLost, 0};
    r = ApplyEvent(state, stale);
    CHECK(r.disposition == TransitionDisposition::Stale);
    CHECK(r.snapshot.state == ReachabilityState::Reachable);

    r = ApplyEvent(state, StateEvent{EventType::BeginGeneration, 2});
    CHECK(r.snapshot.state == ReachabilityState::Discovering);
    CHECK(!r.snapshot.HasClassicHighIdEvidence());

    const TransitionResult invalidated =
        InvalidateForMapperEpochReset(state, 2);
    CHECK(invalidated.disposition == TransitionDisposition::Applied);
    CHECK(invalidated.snapshot.state == ReachabilityState::Degraded);
    CHECK(invalidated.snapshot.reason == ReasonCode::LeaseExpired);
    CHECK(invalidated.snapshot.generation == 2);
    CHECK(invalidated.snapshot.local.port == 4662);
    CHECK(!invalidated.snapshot.lease.IsStructurallyValid());
    CHECK(!invalidated.snapshot.advertised.IsUsable());
    CHECK(!invalidated.snapshot.HasClassicHighIdEvidence());
}

void TestHundredThousandAdversarialTransitions() {
    PlaneSnapshot state{};
    state.local = Ep(192, 168, 1, 20, 4662, EndpointSource::LocalInterface);
    state = ApplyEvent(state, StateEvent{EventType::BeginGeneration, 1}).snapshot;
    std::uint32_t rng = 0xC0FFEEu;

    for (int i = 0; i < 100000; ++i) {
        rng = rng * 1664525u + 1013904223u;
        StateEvent event{};
        event.type = static_cast<EventType>((rng >> 16) % 14);
        event.generation = (rng & 3u) == 0 ? state.generation + 1 :
                           (rng & 3u) == 1 && state.generation > 0 ? state.generation - 1 :
                           state.generation;
        event.lease = Lease(event.generation, static_cast<std::uint16_t>(40000 + (rng % 20000)));
        event.advertised = event.lease.public_endpoint;
        event.verification_attempt = Attempt(
            event.advertised, event.generation,
            static_cast<std::uint64_t>(i) + 1,
            static_cast<std::uint64_t>(i));
        event.primary_evidence = Evidence{
            EvidenceKind::ServerHighId, event.advertised, event.generation,
            static_cast<std::uint64_t>(i),
            event.verification_attempt.attempt_id};
        event.inbound_evidence = Evidence{
            EvidenceKind::InboundTcpAccept, event.advertised, event.generation,
            static_cast<std::uint64_t>(i + 1),
            event.verification_attempt.attempt_id};

        const PlaneSnapshot before = state;
        const TransitionResult result = ApplyEvent(state, event);
        if (result.disposition == TransitionDisposition::Applied) {
            CHECK(IsSnapshotConsistent(result.snapshot));
            state = result.snapshot;
        } else {
            CHECK(result.snapshot.state == before.state);
            CHECK(result.snapshot.generation == before.generation);
        }
    }
}

void TestSplitEvidenceAndFailedVerification() {
    PlaneSnapshot state{};
    state.local = Ep(192, 168, 1, 20, 4662, EndpointSource::LocalInterface);
    state = ApplyEvent(state, StateEvent{EventType::BeginGeneration, 21}).snapshot;
    state = ApplyEvent(state, StateEvent{EventType::MappingStarted, 21}).snapshot;
    StateEvent mapped{};
    mapped.type = EventType::MappingSucceeded;
    mapped.generation = 21;
    mapped.lease = Lease(21, 443);
    state = ApplyEvent(state, mapped).snapshot;

    const VerificationAttempt attempt =
        Attempt(mapped.lease.public_endpoint, 21, 2101);
    state = ApplyEvent(
        state,
        StartVerificationEvent(
            mapped.lease.public_endpoint, 21, attempt.attempt_id)).snapshot;

    StateEvent inbound{};
    inbound.type = EventType::InboundEvidenceObserved;
    inbound.generation = 21;
    inbound.inbound_evidence = Evidence{
        EvidenceKind::InboundTcpAccept, mapped.lease.public_endpoint, 21, 50,
        attempt.attempt_id};
    TransitionResult result = ApplyEvent(state, inbound);
    CHECK(result.disposition == TransitionDisposition::Applied);
    CHECK(result.snapshot.state == ReachabilityState::Verifying);
    state = result.snapshot;

    StateEvent server{};
    server.type = EventType::ServerEvidenceObserved;
    server.generation = 21;
    server.primary_evidence = Evidence{
        EvidenceKind::ServerHighId, mapped.lease.public_endpoint, 21, 60,
        attempt.attempt_id};
    result = ApplyEvent(state, server);
    CHECK(result.snapshot.state == ReachabilityState::Verifying);
    StateEvent verified{};
    verified.type = EventType::VerificationSucceeded;
    verified.generation = 21;
    verified.advertised = mapped.lease.public_endpoint;
    verified.verification_attempt = attempt;
    result = ApplyEvent(result.snapshot, verified);
    CHECK(result.snapshot.state == ReachabilityState::Reachable);
    CHECK(result.snapshot.HasClassicHighIdEvidence());

    state = ApplyEvent(result.snapshot, StateEvent{EventType::BeginGeneration, 22}).snapshot;
    state = ApplyEvent(state, StateEvent{EventType::MappingStarted, 22}).snapshot;
    mapped.generation = 22;
    mapped.lease = Lease(22, 52144);
    state = ApplyEvent(state, mapped).snapshot;
    const VerificationAttempt failedAttempt =
        Attempt(mapped.lease.public_endpoint, 22, 2201);
    state = ApplyEvent(
        state,
        StartVerificationEvent(
            mapped.lease.public_endpoint, 22,
            failedAttempt.attempt_id)).snapshot;
    StateEvent failed{};
    failed.type = EventType::VerificationFailed;
    failed.generation = 22;
    failed.reason = ReasonCode::ServerCallbackFailed;
    failed.verification_attempt = failedAttempt;
    result = ApplyEvent(state, failed);
    CHECK(result.snapshot.state == ReachabilityState::Degraded);
    CHECK(result.snapshot.lease.granted_external_port == 52144);
    CHECK(!result.snapshot.HasClassicHighIdEvidence());
}

void TestLeaseExpiryWithdrawsEndpointAndFencesLateCallbacks() {
    PlaneSnapshot state{};
    state.local = Ep(
        192, 168, 1, 20, 4662, EndpointSource::LocalInterface);
    state = ApplyEvent(
        state, StateEvent{EventType::BeginGeneration, 31}).snapshot;
    state = ApplyEvent(
        state, StateEvent{EventType::MappingStarted, 31}).snapshot;

    StateEvent mapped{};
    mapped.type = EventType::MappingSucceeded;
    mapped.generation = 31;
    mapped.lease = Lease(31, 52144);
    mapped.lease.mapper = MapperKind::NatPmp;
    mapped.lease.public_endpoint.source =
        EndpointSource::NatPmpPublicAddress;
    mapped.lease.lifetime_seconds = 100;
    mapped.lease.mapper_epoch = 17;
    state = ApplyEvent(state, mapped).snapshot;
    const VerificationAttempt attempt =
        Attempt(mapped.lease.public_endpoint, 31, 3101, 1000);
    state = ApplyEvent(
        state,
        StartVerificationEvent(
            mapped.lease.public_endpoint, 31, attempt.attempt_id,
            attempt.started_monotonic_ms)).snapshot;

    StateEvent verified{};
    verified.type = EventType::VerificationSucceeded;
    verified.generation = 31;
    verified.advertised = mapped.lease.public_endpoint;
    verified.verification_attempt = attempt;
    StateEvent server{};
    server.type = EventType::ServerEvidenceObserved;
    server.generation = 31;
    server.primary_evidence = Evidence{
        EvidenceKind::ServerHighId, verified.advertised, 31, 1000,
        attempt.attempt_id};
    state = ApplyEvent(state, server).snapshot;
    StateEvent inbound{};
    inbound.type = EventType::InboundEvidenceObserved;
    inbound.generation = 31;
    inbound.inbound_evidence = Evidence{
        EvidenceKind::InboundTcpAccept, verified.advertised, 31, 1001,
        attempt.attempt_id};
    state = ApplyEvent(state, inbound).snapshot;
    state = ApplyEvent(state, verified).snapshot;
    CHECK(state.state == ReachabilityState::Reachable);

    const TransitionResult expired =
        InvalidateForLeaseExpiry(state, 32);
    CHECK(expired.disposition == TransitionDisposition::Applied);
    CHECK(expired.snapshot.state == ReachabilityState::Degraded);
    CHECK(expired.snapshot.reason == ReasonCode::LeaseExpired);
    CHECK(expired.snapshot.generation == 32);
    CHECK(expired.snapshot.local.port == 4662);
    CHECK(!expired.snapshot.mapped.IsUsable());
    CHECK(!expired.snapshot.advertised.IsUsable());
    CHECK(!expired.snapshot.lease.IsStructurallyValid());
    CHECK(!expired.snapshot.primary_evidence.IsCurrent(32));
    CHECK(!expired.snapshot.inbound_evidence.IsCurrent(32));

    StateEvent lateRenewal{};
    lateRenewal.type = EventType::RenewalSucceeded;
    lateRenewal.generation = 31;
    lateRenewal.lease = mapped.lease;
    TransitionResult late = ApplyEvent(expired.snapshot, lateRenewal);
    CHECK(late.disposition == TransitionDisposition::Stale);
    CHECK(late.snapshot.state == ReachabilityState::Degraded);

    StateEvent lateServer{};
    lateServer.type = EventType::ServerEvidenceObserved;
    lateServer.generation = 32;
    lateServer.primary_evidence = Evidence{
        EvidenceKind::ServerHighId, mapped.lease.public_endpoint, 32, 2000};
    late = ApplyEvent(expired.snapshot, lateServer);
    CHECK(late.disposition == TransitionDisposition::Invalid);
    CHECK(!late.snapshot.advertised.IsUsable());

    StateEvent lateInbound{};
    lateInbound.type = EventType::InboundEvidenceObserved;
    lateInbound.generation = 32;
    lateInbound.inbound_evidence = Evidence{
        EvidenceKind::InboundTcpAccept,
        mapped.lease.public_endpoint, 32, 2001};
    late = ApplyEvent(expired.snapshot, lateInbound);
    CHECK(late.disposition == TransitionDisposition::Invalid);
    CHECK(!late.snapshot.advertised.IsUsable());
}

void TestRejectedMapperProjectionWithdrawsCandidateInPlace() {
    PlaneSnapshot state{};
    state.local = Ep(192, 168, 1, 20, 4662,
                     EndpointSource::LocalInterface);
    state = ApplyEvent(
        state, StateEvent{EventType::BeginGeneration, 41}).snapshot;
    state = ApplyEvent(
        state, StateEvent{EventType::MappingStarted, 41}).snapshot;
    StateEvent mapped{};
    mapped.type = EventType::MappingSucceeded;
    mapped.generation = 41;
    mapped.lease = Lease(41, 52144);
    state = ApplyEvent(state, mapped).snapshot;
    CHECK(state.state == ReachabilityState::CandidateMapped);
    CHECK(state.lease.IsStructurallyValid());

    const TransitionResult rejected = ApplyEvent(
        state, StateEvent{EventType::RouterBlocked, 41,
                          ReasonCode::InvalidResponse});
    CHECK(rejected.disposition == TransitionDisposition::Applied);
    CHECK(rejected.snapshot.generation == 41);
    CHECK(rejected.snapshot.state == ReachabilityState::BlockedByRouter);
    CHECK(rejected.snapshot.reason == ReasonCode::InvalidResponse);
    CHECK(!rejected.snapshot.lease.IsStructurallyValid());
    CHECK(!rejected.snapshot.mapped.IsUsable());
    CHECK(!rejected.snapshot.advertised.IsUsable());
}

} // namespace

int main() {
    TestHappyPathAndStaleFencing();
    TestSplitEvidenceAndFailedVerification();
    TestLeaseExpiryWithdrawsEndpointAndFencesLateCallbacks();
    TestRejectedMapperProjectionWithdrawsCandidateInPlace();
    TestHundredThousandAdversarialTransitions();
    std::printf("test_state_machine: %d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
