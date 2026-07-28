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

PortLease Lease(std::uint64_t generation) {
    PortLease lease{};
    lease.mapper = MapperKind::Pcp;
    lease.transport = Transport::Tcp;
    lease.local =
        Ep(192, 168, 1, 20, 4662, EndpointSource::LocalInterface);
    lease.public_endpoint =
        Ep(88, 11, 22, 4, 52144, EndpointSource::PcpMap);
    lease.requested_external_port = 4662;
    lease.granted_external_port = 52144;
    lease.lifetime_seconds = 3600;
    lease.generation = generation;
    lease.owned_by_us = true;
    return lease;
}

PlaneSnapshot MappedCandidate(std::uint64_t generation) {
    PlaneSnapshot state{};
    state.local =
        Ep(192, 168, 1, 20, 4662, EndpointSource::LocalInterface);
    state =
        ApplyEvent(state, StateEvent{
            EventType::BeginGeneration, generation}).snapshot;
    state =
        ApplyEvent(state, StateEvent{
            EventType::MappingStarted, generation}).snapshot;
    StateEvent mapped{};
    mapped.type = EventType::MappingSucceeded;
    mapped.generation = generation;
    mapped.lease = Lease(generation);
    return ApplyEvent(state, mapped).snapshot;
}

VerificationAttempt Attempt(
    const PlaneSnapshot& state, std::uint64_t attempt_id,
    std::uint64_t started_ms = 100,
    std::uint64_t deadline_ms = 30000) {
    VerificationAttempt attempt{};
    attempt.attempt_id = attempt_id;
    attempt.topology_generation = state.generation;
    attempt.endpoint = state.advertised;
    attempt.transport = Transport::Tcp;
    attempt.started_monotonic_ms = started_ms;
    attempt.deadline_monotonic_ms = deadline_ms;
    return attempt;
}

PlaneSnapshot StartVerification(
    const PlaneSnapshot& candidate, const VerificationAttempt& attempt) {
    StateEvent started{};
    started.type = EventType::VerificationStarted;
    started.generation = candidate.generation;
    started.verification_attempt = attempt;
    return ApplyEvent(candidate, started).snapshot;
}

PlaneSnapshot VerifiedState(std::uint64_t generation) {
    PlaneSnapshot state = MappedCandidate(generation);
    const VerificationAttempt attempt = Attempt(state, 7001);
    state = StartVerification(state, attempt);
    StateEvent server{};
    server.type = EventType::ServerEvidenceObserved;
    server.generation = generation;
    server.primary_evidence = Evidence{
        EvidenceKind::ServerHighId, state.advertised, generation,
        400, attempt.attempt_id};
    state = ApplyEvent(state, server).snapshot;
    StateEvent inbound{};
    inbound.type = EventType::InboundEvidenceObserved;
    inbound.generation = generation;
    inbound.inbound_evidence = Evidence{
        EvidenceKind::InboundTcpAccept,
        state.advertised, generation, 401, attempt.attempt_id};
    state = ApplyEvent(state, inbound).snapshot;
    StateEvent verified{};
    verified.type = EventType::VerificationSucceeded;
    verified.generation = generation;
    verified.advertised = state.advertised;
    verified.verification_attempt = attempt;
    return ApplyEvent(state, verified).snapshot;
}

void TestMappingAndServerHighIdWithoutInboundStayUnverified() {
    constexpr std::uint64_t generation = 501;
    PlaneSnapshot state = MappedCandidate(generation);
    CHECK(state.state == ReachabilityState::CandidateMapped);
    CHECK(!state.HasClassicHighIdEvidence());

    const VerificationAttempt attempt = Attempt(state, 7002);
    StateEvent started{};
    started.type = EventType::VerificationStarted;
    started.generation = generation;
    started.verification_attempt = attempt;
    TransitionResult result = ApplyEvent(state, started);
    CHECK(result.disposition == TransitionDisposition::Applied);
    state = result.snapshot;

    StateEvent server{};
    server.type = EventType::ServerEvidenceObserved;
    server.generation = generation;
    server.primary_evidence = Evidence{
        EvidenceKind::ServerHighId, state.advertised, generation,
        100, attempt.attempt_id};
    result = ApplyEvent(state, server);
    CHECK(result.disposition == TransitionDisposition::Applied);
    CHECK(result.snapshot.state == ReachabilityState::Verifying);
    CHECK(result.snapshot.primary_evidence.kind ==
          EvidenceKind::ServerHighId);
    CHECK(result.snapshot.inbound_evidence.kind == EvidenceKind::None);
    CHECK(!result.snapshot.HasClassicHighIdEvidence());
}

void TestDerivedSuccessCannotBypassMissingInboundEvidence() {
    constexpr std::uint64_t generation = 502;
    PlaneSnapshot state = MappedCandidate(generation);
    const VerificationAttempt attempt = Attempt(state, 7003);
    state = StartVerification(state, attempt);

    StateEvent premature{};
    premature.type = EventType::VerificationSucceeded;
    premature.generation = generation;
    premature.advertised = state.advertised;
    premature.verification_attempt = attempt;
    premature.primary_evidence = Evidence{
        EvidenceKind::ServerHighId, state.advertised, generation,
        200, attempt.attempt_id};
    const TransitionResult result = ApplyEvent(state, premature);
    CHECK(result.disposition == TransitionDisposition::Invalid);
    CHECK(result.snapshot.state == ReachabilityState::Verifying);
    CHECK(!result.snapshot.HasClassicHighIdEvidence());
}

void TestForgedReachableServerOnlySnapshotIsInconsistent() {
    constexpr std::uint64_t generation = 503;
    PlaneSnapshot forged = MappedCandidate(generation);
    const VerificationAttempt attempt = Attempt(forged, 7004);
    forged.verification_attempt = attempt;
    forged.state = ReachabilityState::Reachable;
    forged.primary_evidence = Evidence{
        EvidenceKind::ServerHighId, forged.advertised, generation,
        300, attempt.attempt_id};
    CHECK(!IsSnapshotConsistent(forged));
    CHECK(!forged.HasClassicHighIdEvidence());
}

void TestSamePortDifferentAddressRenewalFailsClosed() {
    constexpr std::uint64_t generation = 504;
    PlaneSnapshot state = VerifiedState(generation);
    CHECK(state.HasClassicHighIdEvidence());
    TransitionResult result = ApplyEvent(
        state, StateEvent{EventType::RenewalDue, generation});
    CHECK(result.disposition == TransitionDisposition::Applied);
    CHECK(result.snapshot.state == ReachabilityState::Renewing);
    state = result.snapshot;

    StateEvent renewal{};
    renewal.type = EventType::RenewalSucceeded;
    renewal.generation = generation;
    renewal.lease = state.lease;
    renewal.lease.public_endpoint.address =
        IpAddress::V4(88, 11, 22, 99);
    result = ApplyEvent(state, renewal);
    CHECK(result.disposition == TransitionDisposition::Invalid);
    CHECK(result.snapshot.state == ReachabilityState::Renewing);
    CHECK(result.snapshot.lease.public_endpoint.address.bytes[3] == 4);
    CHECK(!IsSnapshotConsistent(PlaneSnapshot{
        ReachabilityState::Reachable,
        state.reason,
        state.local,
        state.mapped,
        state.advertised,
        renewal.lease,
        state.primary_evidence,
        state.inbound_evidence,
        generation,
        state.verification_attempt}));
}

void TestWrongAttemptCannotBeRelabeledAsCurrent() {
    constexpr std::uint64_t generation = 505;
    PlaneSnapshot state = MappedCandidate(generation);
    const VerificationAttempt current = Attempt(state, 8002);
    state = StartVerification(state, current);

    StateEvent staleServer{};
    staleServer.type = EventType::ServerEvidenceObserved;
    staleServer.generation = generation;
    staleServer.primary_evidence = Evidence{
        EvidenceKind::ServerHighId, state.advertised, generation,
        120, 8001};
    TransitionResult result = ApplyEvent(state, staleServer);
    CHECK(result.disposition == TransitionDisposition::Invalid);
    CHECK(result.snapshot.primary_evidence.kind == EvidenceKind::None);

    StateEvent staleInbound{};
    staleInbound.type = EventType::InboundEvidenceObserved;
    staleInbound.generation = generation;
    staleInbound.inbound_evidence = Evidence{
        EvidenceKind::InboundTcpAccept, state.advertised, generation,
        121, 8001};
    result = ApplyEvent(state, staleInbound);
    CHECK(result.disposition == TransitionDisposition::Invalid);
    CHECK(result.snapshot.inbound_evidence.kind == EvidenceKind::None);
    CHECK(!result.snapshot.HasClassicHighIdEvidence());
}

void TestExpiredEvidenceCannotPromoteReachable() {
    constexpr std::uint64_t generation = 506;
    PlaneSnapshot state = MappedCandidate(generation);
    const VerificationAttempt attempt = Attempt(state, 8003, 100, 200);
    state = StartVerification(state, attempt);

    StateEvent expired{};
    expired.type = EventType::ServerEvidenceObserved;
    expired.generation = generation;
    expired.primary_evidence = Evidence{
        EvidenceKind::ServerHighId, state.advertised, generation,
        201, attempt.attempt_id};
    const TransitionResult result = ApplyEvent(state, expired);
    CHECK(result.disposition == TransitionDisposition::Invalid);
    CHECK(result.snapshot.state == ReachabilityState::Verifying);
    CHECK(result.snapshot.primary_evidence.kind == EvidenceKind::None);
}

void TestOldGenerationCallbacksCannotPromoteNewEndpoint() {
    PlaneSnapshot oldState = MappedCandidate(507);
    const VerificationAttempt oldAttempt = Attempt(oldState, 8004);
    oldState = StartVerification(oldState, oldAttempt);

    PlaneSnapshot current = oldState;
    current = ApplyEvent(
        current, StateEvent{EventType::BeginGeneration, 508}).snapshot;
    current = ApplyEvent(
        current, StateEvent{EventType::MappingStarted, 508}).snapshot;
    StateEvent mapped{};
    mapped.type = EventType::MappingSucceeded;
    mapped.generation = 508;
    mapped.lease = Lease(508);
    mapped.lease.public_endpoint =
        Ep(88, 11, 22, 99, 53144, EndpointSource::PcpMap);
    mapped.lease.granted_external_port = 53144;
    current = ApplyEvent(current, mapped).snapshot;
    const VerificationAttempt currentAttempt = Attempt(current, 8005);
    current = StartVerification(current, currentAttempt);

    StateEvent oldServer{};
    oldServer.type = EventType::ServerEvidenceObserved;
    oldServer.generation = oldAttempt.topology_generation;
    oldServer.primary_evidence = Evidence{
        EvidenceKind::ServerHighId, oldAttempt.endpoint,
        oldAttempt.topology_generation, 130, oldAttempt.attempt_id};
    TransitionResult result = ApplyEvent(current, oldServer);
    CHECK(result.disposition == TransitionDisposition::Stale);

    StateEvent oldInbound{};
    oldInbound.type = EventType::InboundEvidenceObserved;
    oldInbound.generation = oldAttempt.topology_generation;
    oldInbound.inbound_evidence = Evidence{
        EvidenceKind::InboundTcpAccept, oldAttempt.endpoint,
        oldAttempt.topology_generation, 131, oldAttempt.attempt_id};
    result = ApplyEvent(current, oldInbound);
    CHECK(result.disposition == TransitionDisposition::Stale);
    CHECK(result.snapshot.state == ReachabilityState::Verifying);
    CHECK(result.snapshot.primary_evidence.kind == EvidenceKind::None);
    CHECK(result.snapshot.inbound_evidence.kind == EvidenceKind::None);
}

} // namespace

int main() {
    TestMappingAndServerHighIdWithoutInboundStayUnverified();
    TestDerivedSuccessCannotBypassMissingInboundEvidence();
    TestForgedReachableServerOnlySnapshotIsInconsistent();
    TestSamePortDifferentAddressRenewalFailsClosed();
    TestWrongAttemptCannotBeRelabeledAsCurrent();
    TestExpiredEvidenceCannotPromoteReachable();
    TestOldGenerationCallbacksCannotPromoteNewEndpoint();
    std::printf("false HighID L05: %d checks, %d failures\n",
                checks, failures);
    return failures == 0 ? 0 : 1;
}
