#include "natmap/upnp_lease_policy.h"

#include <cstdio>

using namespace natmap;

namespace {

int failures = 0;
int checks = 0;

#define CHECK(expr) do { ++checks; if (!(expr)) { ++failures; \
    std::printf("FAIL line %d: %s\n", __LINE__, #expr); } } while (0)

void TestFiniteAccepted() {
    CHECK(EvaluateUpnpLeaseAttempt(
        UpnpLeaseRequestKind::Finite, true) ==
        UpnpLeaseAttemptAction::AcceptFinite);
}

void TestFiniteRejectedPermanentAccepted() {
    CHECK(EvaluateUpnpLeaseAttempt(
        UpnpLeaseRequestKind::Finite, false) ==
        UpnpLeaseAttemptAction::TryPermanent);
    CHECK(EvaluateUpnpLeaseAttempt(
        UpnpLeaseRequestKind::Permanent, true) ==
        UpnpLeaseAttemptAction::AcceptPermanent);
    CHECK(EvaluateUpnpLeaseAttempt(
        UpnpLeaseRequestKind::Permanent, false) ==
        UpnpLeaseAttemptAction::Fail);
    CHECK(EvaluateUpnpLeaseAttempt(
        static_cast<UpnpLeaseRequestKind>(255), true) ==
        UpnpLeaseAttemptAction::Fail);
}

void TestPermanentHealthProbe() {
    UpnpExistingLeaseObservation observation{};
    observation.refresh = true;
    observation.query_succeeded = true;
    observation.target_matches = true;
    observation.ownership_matches = true;
    observation.remaining_lifetime_seconds = 0;
    CHECK(EvaluateUpnpExistingLease(observation) ==
          UpnpExistingLeaseAction::Reuse);
}

void TestFiniteRefreshRenews() {
    UpnpExistingLeaseObservation observation{};
    observation.refresh = true;
    observation.query_succeeded = true;
    observation.target_matches = true;
    observation.ownership_matches = true;
    observation.remaining_lifetime_seconds = 3600;
    CHECK(EvaluateUpnpExistingLease(observation) ==
          UpnpExistingLeaseAction::RenewFinite);
}

void TestMissingMappingIsRecreated() {
    UpnpExistingLeaseObservation observation{};
    observation.refresh = true;
    CHECK(EvaluateUpnpExistingLease(observation) ==
          UpnpExistingLeaseAction::Create);

    observation.query_succeeded = true;
    observation.target_matches = false;
    CHECK(EvaluateUpnpExistingLease(observation) ==
          UpnpExistingLeaseAction::Create);
}

void TestInitialCompatibleMappingIsReused() {
    UpnpExistingLeaseObservation observation{};
    observation.query_succeeded = true;
    observation.target_matches = true;
    observation.ownership_matches = true;
    observation.remaining_lifetime_seconds = 3600;
    CHECK(EvaluateUpnpExistingLease(observation) ==
          UpnpExistingLeaseAction::Reuse);
}

} // namespace

int main() {
    TestFiniteAccepted();
    TestFiniteRejectedPermanentAccepted();
    TestPermanentHealthProbe();
    TestFiniteRefreshRenews();
    TestMissingMappingIsRecreated();
    TestInitialCompatibleMappingIsReused();
    std::printf("test_upnp_lease_policy: %d checks, %d failures\n",
                checks, failures);
    return failures == 0 ? 0 : 1;
}
