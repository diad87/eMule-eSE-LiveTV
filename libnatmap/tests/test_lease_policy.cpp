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

void TestPcpEpochToleranceAndResetSignal() {
    FakeGateway gateway{};
    gateway.mapper = MapperKind::Pcp;
    gateway.gateway = Ep(192, 168, 1, 1, 5351);
    gateway.external_address = IpAddress::V4(88, 11, 22, 4);
    gateway.forced_external_port = 52144;
    gateway.lifetime_seconds = 100;
    const PortIntent intent = BuildAutomaticPortIntent(
        Transport::Tcp, Ep(192, 168, 1, 20, 4662), 100, 17);
    MapResult mapped = gateway.Map(intent, 17);
    mapped.lease.mapper_epoch = 500;

    LeaseController valid;
    CHECK(valid.Activate(mapped.lease, 1000));
    PortLease advanced = mapped.lease;
    advanced.mapper_epoch = 560;
    CHECK(valid.AcceptRenewal(advanced, 61000));
    CHECK(!valid.LastRenewalObservedEpochReset());
    CHECK(valid.lease().generation == 17);

    LeaseController reordered;
    CHECK(reordered.Activate(mapped.lease, 0));
    PortLease one_second_older = mapped.lease;
    one_second_older.mapper_epoch = 499;
    CHECK(reordered.AcceptRenewal(one_second_older, 1000));
    CHECK(!reordered.LastRenewalObservedEpochReset());
    CHECK(reordered.lease().generation == 17);

    LeaseController rebooted;
    CHECK(rebooted.Activate(mapped.lease, 0));
    PortLease reset = mapped.lease;
    reset.mapper_epoch = 0;
    CHECK(rebooted.AcceptRenewal(reset, 1000));
    CHECK(rebooted.LastRenewalObservedEpochReset());
    CHECK(rebooted.lease().generation == 17);

    LeaseController too_slow;
    CHECK(too_slow.Activate(mapped.lease, 0));
    PortLease barely_advanced = mapped.lease;
    barely_advanced.mapper_epoch = 501;
    CHECK(too_slow.AcceptRenewal(barely_advanced, 3600000));
    CHECK(too_slow.LastRenewalObservedEpochReset());

    LeaseController too_fast;
    CHECK(too_fast.Activate(mapped.lease, 0));
    PortLease jumped = mapped.lease;
    jumped.mapper_epoch = 4100;
    CHECK(too_fast.AcceptRenewal(jumped, 1000));
    CHECK(too_fast.LastRenewalObservedEpochReset());
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

    PortLease changed_gateway = controller.lease();
    changed_gateway.gateway =
        Ep(192, 168, 1, 254, 5351);
    CHECK(!controller.AcceptRenewal(changed_gateway, 1000));
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

void TestThreeNatPmpRenewalsWithFakeClock() {
    PortLease lease{};
    lease.mapper = MapperKind::NatPmp;
    lease.transport = Transport::Tcp;
    lease.local = Ep(
        192, 168, 1, 20, 4662,
        EndpointSource::LocalInterface);
    lease.public_endpoint = Ep(
        88, 11, 22, 4, 52144,
        EndpointSource::NatPmpPublicAddress);
    lease.requested_external_port = 4662;
    lease.granted_external_port = 52144;
    lease.lifetime_seconds = 100;
    lease.mapper_epoch = 10;
    lease.generation = 77;
    lease.owned_by_us = true;

    std::uint64_t fakeNowMs = 1000;
    LeaseController controller;
    LeaseRefreshSchedule schedule;
    CHECK(controller.Activate(lease, fakeNowMs));
    CHECK(schedule.Activate(lease.lifetime_seconds, fakeNowMs));

    for (std::uint32_t renewal = 1; renewal <= 3; ++renewal) {
        const std::uint64_t due = fakeNowMs + 45000;
        CHECK(schedule.next_attempt_ms() == due);
        CHECK(!schedule.ShouldAttempt(due - 1));
        CHECK(schedule.ShouldAttempt(due));
        fakeNowMs = due;
        lease.mapper_epoch += 45;
        CHECK(controller.AcceptRenewal(lease, fakeNowMs));
        CHECK(!controller.LastRenewalObservedEpochReset());
        CHECK(controller.lease().generation == 77);
        CHECK(controller.lease().local.port == 4662);
        CHECK(controller.lease().public_endpoint.port == 52144);
        CHECK(controller.lease().mapper_epoch == 10 + renewal * 45);
        CHECK(schedule.Activate(lease.lifetime_seconds, fakeNowMs));
        CHECK(schedule.attempt_count() == 0);
        CHECK(schedule.timing().expires_monotonic_ms
            == fakeNowMs + 100000);
    }
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

void TestAdvertisementReloginIsExactlyOnce() {
    unsigned relogins = 0;
    const auto observe = [&relogins](
        std::uint64_t previous_generation,
        std::uint64_t current_generation,
        bool was_enabled,
        bool is_enabled,
        bool observed = true) {
        const bool required = RequiresAdvertisementRelogin(
            AdvertisementObservation{
                previous_generation,
                current_generation,
                observed,
                was_enabled,
                is_enabled});
        if (required)
            ++relogins;
        return required;
    };

    // One atomic TCP/UDP publication produces exactly one re-login.
    CHECK(observe(1, 2, false, true));
    CHECK(relogins == 1);

    // An identical renewal preserves the generation and produces none.
    CHECK(!observe(2, 2, true, true));
    CHECK(relogins == 1);

    // One real endpoint change advances once and produces exactly one.
    CHECK(observe(2, 3, true, true));
    CHECK(relogins == 2);

    // A duplicate delivery of that callback produces no additional re-login.
    CHECK(!observe(3, 3, true, true));
    CHECK(relogins == 2);

    // A terminal withdrawal at the generation limit must still be advertised.
    CHECK(observe(3, 3, true, false));
    CHECK(relogins == 3);

    // Network-change rediscovery publishes inside the generation that already
    // fenced the old mapping. Disabled-to-enabled therefore needs one re-login
    // even though the generation number deliberately remains unchanged.
    CHECK(observe(3, 3, false, true));
    CHECK(relogins == 4);
    CHECK(!observe(3, 3, true, true));
    CHECK(relogins == 4);

    // Unconsumed/stale observations never trigger external side effects.
    CHECK(!observe(3, 4, false, true, false));
    CHECK(relogins == 4);

    const AdvertisementObservation republished{
        3, 3, true, false, true};
    CHECK(ShouldRestartAdvertisementLogin(
        republished, false, true, false));
    CHECK(ShouldRestartAdvertisementLogin(
        republished, true, false, false));
    CHECK(!ShouldRestartAdvertisementLogin(
        republished, false, false, false));
    CHECK(!ShouldRestartAdvertisementLogin(
        republished, true, false, true));
}

} // namespace

int main() {
    TestCandidatePolicy();
    TestDifferentPortRenewAndDelete();
    TestPcpEpochToleranceAndResetSignal();
    TestChangedEndpointIsNotSilentRenewal();
    TestApplicationRefreshSchedule();
    TestThreeNatPmpRenewalsWithFakeClock();
    TestPermanentLeaseHasNoRefreshClock();
    TestRefreshBackoffIsBounded();
	TestPermanentMappingHealthProbe();
    TestAdvertisementReloginIsExactlyOnce();
    std::printf("test_lease_policy: %d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
