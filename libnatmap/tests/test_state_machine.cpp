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

    r = ApplyEvent(state, StateEvent{EventType::VerificationStarted, 1});
    CHECK(r.snapshot.state == ReachabilityState::Verifying);
    state = r.snapshot;

    StateEvent verified{};
    verified.type = EventType::VerificationSucceeded;
    verified.generation = 1;
    verified.advertised = mapped.lease.public_endpoint;
    verified.primary_evidence = Evidence{
        EvidenceKind::ServerHighId, verified.advertised, 1, 100};
    verified.inbound_evidence = Evidence{
        EvidenceKind::InboundTcpAccept, verified.advertised, 1, 101};
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
        event.primary_evidence = Evidence{
            EvidenceKind::ServerHighId, event.advertised, event.generation,
            static_cast<std::uint64_t>(i)};
        event.inbound_evidence = Evidence{
            EvidenceKind::InboundTcpAccept, event.advertised, event.generation,
            static_cast<std::uint64_t>(i + 1)};

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

    StateEvent inbound{};
    inbound.type = EventType::InboundEvidenceObserved;
    inbound.generation = 21;
    inbound.inbound_evidence = Evidence{
        EvidenceKind::InboundTcpAccept, mapped.lease.public_endpoint, 21, 50};
    TransitionResult result = ApplyEvent(state, inbound);
    CHECK(result.disposition == TransitionDisposition::Applied);
    CHECK(result.snapshot.state == ReachabilityState::CandidateMapped);
    state = result.snapshot;

    state = ApplyEvent(state, StateEvent{EventType::VerificationStarted, 21}).snapshot;
    StateEvent server{};
    server.type = EventType::ServerEvidenceObserved;
    server.generation = 21;
    server.primary_evidence = Evidence{
        EvidenceKind::ServerHighId, mapped.lease.public_endpoint, 21, 60};
    result = ApplyEvent(state, server);
    CHECK(result.snapshot.state == ReachabilityState::Reachable);
    CHECK(result.snapshot.HasClassicHighIdEvidence());

    state = ApplyEvent(result.snapshot, StateEvent{EventType::BeginGeneration, 22}).snapshot;
    state = ApplyEvent(state, StateEvent{EventType::MappingStarted, 22}).snapshot;
    mapped.generation = 22;
    mapped.lease = Lease(22, 52144);
    state = ApplyEvent(state, mapped).snapshot;
    state = ApplyEvent(state, StateEvent{EventType::VerificationStarted, 22}).snapshot;
    result = ApplyEvent(state, StateEvent{
        EventType::VerificationFailed, 22, ReasonCode::ServerCallbackFailed});
    CHECK(result.snapshot.state == ReachabilityState::Degraded);
    CHECK(result.snapshot.lease.granted_external_port == 52144);
    CHECK(!result.snapshot.HasClassicHighIdEvidence());
}

} // namespace

int main() {
    TestHappyPathAndStaleFencing();
    TestSplitEvidenceAndFailedVerification();
    TestHundredThousandAdversarialTransitions();
    std::printf("test_state_machine: %d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
