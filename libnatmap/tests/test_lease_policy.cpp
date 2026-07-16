#include "natmap/natmap_policy.h"
#include "fake_network.h"

#include <cstdio>

using namespace natmap;
using namespace natmap::test;

namespace {

int checks = 0;
int failures = 0;
#define CHECK(expr) do { ++checks; if (!(expr)) { ++failures; \
    std::printf("FAIL line %d: %s\n", __LINE__, #expr); } } while (0)

Endpoint Ep(std::uint8_t a, std::uint8_t b, std::uint8_t c,
            std::uint8_t d, std::uint16_t port,
            EndpointSource source = EndpointSource::LocalInterface) {
    return Endpoint{IpAddress::V4(a, b, c, d), port, source};
}

void TestCandidatePolicy() {
    const PortIntent intent = BuildAutomaticPortIntent(
        Transport::Tcp, Ep(192, 168, 1, 20, 4662), 7200, 12345);
    CHECK(intent.IsValid());
    CHECK(intent.candidate_count == 7);
    CHECK(intent.external_candidates[0] == 4662);
    CHECK(intent.external_candidates[1] == 0);
    CHECK(intent.external_candidates[2] >= 49152);
    CHECK(intent.external_candidates[3] >= 49152);
    CHECK(intent.external_candidates[4] >= 49152);
    CHECK(intent.external_candidates[5] == 443);
    CHECK(intent.external_candidates[6] == 80);
}

void TestDifferentPortRenewAndDelete() {
    FakeGateway gateway{};
    gateway.mapper = MapperKind::Pcp;
    gateway.gateway = Ep(192, 168, 1, 1, 5351);
    gateway.external_address = IpAddress::V4(88, 11, 22, 4);
    gateway.forced_external_port = 52144;
    gateway.lifetime_seconds = 100;
    const PortIntent intent = BuildAutomaticPortIntent(
        Transport::Tcp, Ep(192, 168, 1, 20, 4662), 100, 7);
    MapResult mapped = gateway.Map(intent, 9);
    CHECK(mapped.success && mapped.lease.granted_external_port == 52144);

    LeaseController controller;
    CHECK(controller.Activate(mapped.lease, 1000));
    CHECK(controller.lease().public_endpoint.port == 52144);
    CHECK(controller.timing().renew_monotonic_ms == 46000);
    CHECK(!controller.ShouldRenew(45999));
    CHECK(controller.ShouldRenew(46000));

    mapped.lease.mapper_epoch = 500;
    CHECK(controller.AcceptRenewal(mapped.lease, 46000));
    CHECK(controller.timing().renew_monotonic_ms == 91000);
    mapped.lease.mapper_epoch = 3;
    CHECK(controller.AcceptRenewal(mapped.lease, 91000));
    CHECK(controller.LastRenewalObservedEpochReset());

    PortLease stale = mapped.lease;
    stale.generation = 10;
    CHECK(!controller.AcceptRenewal(stale, 92000));
    PortLease deletion{};
    CHECK(!controller.TakeOwnedForDeletion(8, deletion));
    CHECK(controller.TakeOwnedForDeletion(9, deletion));
    CHECK(deletion.granted_external_port == 52144);
    CHECK(!controller.HasLease());
}

void TestChangedEndpointIsNotSilentRenewal() {
    FakeGateway gateway{};
    gateway.mapper = MapperKind::NatPmp;
    gateway.gateway = Ep(192, 168, 1, 1, 5351);
    gateway.external_address = IpAddress::V4(88, 11, 22, 4);
    gateway.forced_external_port = 50000;
    gateway.lifetime_seconds = 2;
    const PortIntent intent = BuildAutomaticPortIntent(
        Transport::Udp, Ep(192, 168, 1, 20, 4672), 2, 11);
    MapResult mapped = gateway.Map(intent, 12);
    LeaseController controller;
    CHECK(controller.Activate(mapped.lease, 0));
    CHECK(controller.ShouldRenew(900));
    CHECK(controller.IsExpired(2000));
    mapped.lease.granted_external_port = 50001;
    mapped.lease.public_endpoint.port = 50001;
    CHECK(!controller.AcceptRenewal(mapped.lease, 1000));
}

void TestApplicationRefreshSchedule() {
    LeaseRefreshSchedule schedule;
    CHECK(schedule.Activate(100, 1000));
    CHECK(schedule.IsFinite());
    CHECK(schedule.timing().renew_monotonic_ms == 46000);
    CHECK(schedule.timing().expires_monotonic_ms == 101000);
    CHECK(!schedule.ShouldAttempt(45999));
    CHECK(schedule.ShouldAttempt(46000));

    schedule.MarkAttempt(46000);
    CHECK(schedule.attempt_count() == 1);
    CHECK(schedule.next_attempt_ms() == 76000);
    CHECK(!schedule.ShouldAttempt(75999));
    CHECK(schedule.ShouldAttempt(76000));

    schedule.MarkAttempt(76000);
    CHECK(schedule.attempt_count() == 2);
    CHECK(schedule.next_attempt_ms() == 101000);
    CHECK(!schedule.ShouldAttempt(101000));
    CHECK(schedule.IsExpired(101000));

    // A successful renewal installs a fresh lease and resets backoff.
    CHECK(schedule.Activate(7200, 80000));
    CHECK(schedule.attempt_count() == 0);
    CHECK(schedule.next_attempt_ms() == 3320000);
}

void TestPermanentLeaseHasNoRefreshClock() {
    LeaseRefreshSchedule schedule;
    CHECK(!schedule.Activate(0, 1234));
    CHECK(!schedule.IsFinite());
    CHECK(!schedule.ShouldAttempt(UINT64_MAX));
    CHECK(!schedule.IsExpired(UINT64_MAX));
    schedule.MarkAttempt(UINT64_MAX);
    CHECK(schedule.attempt_count() == 0);
    schedule.Clear();
    CHECK(schedule.next_attempt_ms() == 0);
}

void TestRefreshBackoffIsBounded() {
    LeaseRefreshSchedule schedule;
    CHECK(schedule.Activate(7200, 0));
    const std::uint64_t due = schedule.next_attempt_ms();
    schedule.MarkAttempt(due);
    CHECK(schedule.next_attempt_ms() - due == 30000);
    schedule.MarkAttempt(schedule.next_attempt_ms());
    CHECK(schedule.next_attempt_ms() - due == 90000);
    schedule.MarkAttempt(schedule.next_attempt_ms());
    CHECK(schedule.next_attempt_ms() - due == 210000);
    schedule.MarkAttempt(schedule.next_attempt_ms());
    CHECK(schedule.next_attempt_ms() - due == 450000);
    const std::uint64_t fourth = schedule.next_attempt_ms();
    schedule.MarkAttempt(fourth);
    CHECK(schedule.next_attempt_ms() - fourth == 300000);
    const std::uint64_t fifth = schedule.next_attempt_ms();
    schedule.MarkAttempt(fifth);
    CHECK(schedule.next_attempt_ms() - fifth == 300000);
}

void TestPermanentMappingHealthProbe() {
    PermanentMappingProbeSchedule schedule;
    CHECK(!schedule.IsActive());
    CHECK(!schedule.ShouldAttempt(UINT64_MAX));
    schedule.Activate(1000);
    CHECK(schedule.IsActive());
    CHECK(schedule.next_attempt_ms() == 901000);
    CHECK(!schedule.ShouldAttempt(900999));
    CHECK(schedule.ShouldAttempt(901000));
    schedule.MarkAttempt(901000);
    CHECK(schedule.attempt_count() == 1);
    CHECK(schedule.next_attempt_ms() == 961000);
    schedule.MarkAttempt(961000);
    CHECK(schedule.next_attempt_ms() == 1081000);
    schedule.MarkAttempt(1081000);
    CHECK(schedule.next_attempt_ms() == 1321000);
    schedule.MarkAttempt(1321000);
    CHECK(schedule.next_attempt_ms() == 1621000);
    schedule.Activate(2000000);
    CHECK(schedule.attempt_count() == 0);
    CHECK(schedule.next_attempt_ms() == 2900000);
    schedule.Clear();
    CHECK(!schedule.IsActive());
    CHECK(schedule.next_attempt_ms() == 0);
}

} // namespace

int main() {
    TestCandidatePolicy();
    TestDifferentPortRenewAndDelete();
    TestChangedEndpointIsNotSilentRenewal();
    TestApplicationRefreshSchedule();
    TestPermanentLeaseHasNoRefreshClock();
    TestRefreshBackoffIsBounded();
	TestPermanentMappingHealthProbe();
    std::printf("test_lease_policy: %d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
