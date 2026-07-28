#include "natmap/natpmp_epoch_policy.h"

#include <cstdio>

using namespace natmap;

namespace {

int failures = 0;
int checks = 0;

#define CHECK(expr) do { ++checks; if (!(expr)) { ++failures; \
    std::printf("FAIL line %d: %s\n", __LINE__, #expr); } } while (0)

NatPmpEpochObservation Seen(
    std::uint32_t epoch,
    bool accepted = true,
    std::uint64_t observedAtSeconds = 0) {
    NatPmpEpochObservation observation{};
    observation.observed = true;
    observation.accepted = accepted;
    observation.epoch = epoch;
    observation.observed_at_seconds = observedAtSeconds;
    return observation;
}

NatPmpEpochSequence Complete(
    std::uint32_t previous,
    std::uint32_t external,
    std::uint32_t tcp,
    std::uint32_t udp) {
    NatPmpEpochSequence sequence{};
    sequence.previous_snapshot = Seen(previous);
    sequence.external_address = Seen(external);
    sequence.tcp_map = Seen(tcp);
    sequence.udp_map = Seen(udp);
    return sequence;
}

void TestContinuousSequenceCommitsAndPublishesAddress() {
    const NatPmpEpochDecision decision =
        EvaluateNatPmpEpochSequence(
            Complete(100, 101, 102, 103));
    CHECK(decision.strongest_boundary
        == NatPmpEpochBoundary::Continuous);
    CHECK(!decision.previous_pair_invalidated);
    CHECK(decision.external_address_current);
    CHECK(decision.pair_can_commit);
    CHECK(!decision.should_retry_pair);
    CHECK(decision.has_latest_epoch);
    CHECK(decision.latest_epoch == 103);
    CHECK(decision.has_continuity_epoch);
    CHECK(decision.continuity_epoch == 103);
}

void TestResetBeforeFreshExternalCanCommitANewPair() {
    const NatPmpEpochDecision decision =
        EvaluateNatPmpEpochSequence(
            Complete(100, 2, 3, 4));
    CHECK(decision.strongest_boundary
        == NatPmpEpochBoundary::ResetBeforeExternalAddress);
    CHECK(decision.previous_pair_invalidated);
    CHECK(decision.external_address_current);
    CHECK(decision.pair_can_commit);
    CHECK(!decision.should_retry_pair);
    CHECK(decision.latest_epoch == 4);
    CHECK(decision.continuity_epoch == 4);
}

void TestResetBeforeTcpInvalidatesTheEarlierAddressOnly() {
    const NatPmpEpochDecision decision =
        EvaluateNatPmpEpochSequence(
            Complete(100, 101, 2, 3));
    CHECK(decision.strongest_boundary
        == NatPmpEpochBoundary::ResetBeforeTcpMap);
    CHECK(decision.previous_pair_invalidated);
    CHECK(!decision.external_address_current);
    CHECK(decision.pair_can_commit);
    CHECK(!decision.should_retry_pair);
    CHECK(decision.latest_epoch == 3);
    CHECK(decision.continuity_epoch == 3);
}

void TestResetBetweenTcpAndUdpFailsAndRetriesPair() {
    const NatPmpEpochDecision decision =
        EvaluateNatPmpEpochSequence(
            Complete(90, 99, 100, 2));
    CHECK(decision.strongest_boundary
        == NatPmpEpochBoundary::ResetBetweenTcpAndUdp);
    CHECK(decision.previous_pair_invalidated);
    CHECK(!decision.external_address_current);
    CHECK(!decision.pair_can_commit);
    CHECK(decision.should_retry_pair);
    CHECK(decision.latest_epoch == 2);
    CHECK(decision.continuity_epoch == 2);
}

void TestTwoSecondBackwardToleranceRemainsContinuous() {
    const NatPmpEpochDecision decision =
        EvaluateNatPmpEpochSequence(
            Complete(100, 100, 100, 98));
    CHECK(decision.strongest_boundary
        == NatPmpEpochBoundary::Continuous);
    CHECK(decision.external_address_current);
    CHECK(decision.pair_can_commit);
    CHECK(!decision.should_retry_pair);
    CHECK(decision.latest_epoch == 98);
    CHECK(decision.continuity_epoch == 100);
}

void TestRejectedMapStillInvalidatesPreviousPair() {
    NatPmpEpochSequence tcpRejected{};
    tcpRejected.previous_snapshot = Seen(100);
    tcpRejected.tcp_map = Seen(2, false);
    const NatPmpEpochDecision tcpDecision =
        EvaluateNatPmpEpochSequence(tcpRejected);
    CHECK(tcpDecision.previous_pair_invalidated);
    CHECK(!tcpDecision.pair_can_commit);
    CHECK(tcpDecision.should_retry_pair);
    CHECK(tcpDecision.latest_epoch == 2);

    NatPmpEpochSequence udpRejected =
        Complete(90, 99, 100, 2);
    udpRejected.udp_map.accepted = false;
    const NatPmpEpochDecision udpDecision =
        EvaluateNatPmpEpochSequence(udpRejected);
    CHECK(udpDecision.previous_pair_invalidated);
    CHECK(!udpDecision.pair_can_commit);
    CHECK(udpDecision.should_retry_pair);
}

void TestMissingExternalAddressCanStillCommitPair() {
    NatPmpEpochSequence sequence{};
    sequence.previous_snapshot = Seen(100);
    sequence.tcp_map = Seen(2);
    sequence.udp_map = Seen(3);
    const NatPmpEpochDecision decision =
        EvaluateNatPmpEpochSequence(sequence);
    CHECK(decision.previous_pair_invalidated);
    CHECK(!decision.external_address_current);
    CHECK(decision.pair_can_commit);
    CHECK(!decision.should_retry_pair);
    CHECK(decision.latest_epoch == 3);
    CHECK(decision.continuity_epoch == 3);
}

void TestTcpOnlyMappingDoesNotRequireUdpObservation() {
    NatPmpEpochSequence sequence{};
    sequence.udp_required = false;
    sequence.tcp_map = Seen(42);
    const NatPmpEpochDecision decision =
        EvaluateNatPmpEpochSequence(sequence);
    CHECK(decision.pair_can_commit);
    CHECK(!decision.should_retry_pair);
    CHECK(decision.latest_epoch == 42);
    CHECK(decision.continuity_epoch == 42);
}

void TestMissingUdpFailsWithoutInventingReset() {
    NatPmpEpochSequence sequence{};
    sequence.previous_snapshot = Seen(100);
    sequence.external_address = Seen(101);
    sequence.tcp_map = Seen(102);
    const NatPmpEpochDecision decision =
        EvaluateNatPmpEpochSequence(sequence);
    CHECK(!decision.previous_pair_invalidated);
    CHECK(!decision.pair_can_commit);
    CHECK(!decision.should_retry_pair);
    CHECK(decision.latest_epoch == 102);
    CHECK(decision.continuity_epoch == 102);
}

void TestLatestContinuousObservationCarriesIntoNextAttempt() {
    NatPmpEpochSequence firstAttempt{};
    firstAttempt.previous_snapshot = Seen(100);
    firstAttempt.external_address = Seen(101);
    const NatPmpEpochDecision firstDecision =
        EvaluateNatPmpEpochSequence(firstAttempt);
    CHECK(!firstDecision.previous_pair_invalidated);
    CHECK(!firstDecision.pair_can_commit);
    CHECK(firstDecision.has_latest_epoch);
    CHECK(firstDecision.latest_epoch == 101);
    CHECK(firstDecision.continuity_epoch == 101);

    NatPmpEpochSequence secondAttempt{};
    secondAttempt.previous_snapshot =
        Seen(firstDecision.continuity_epoch);
    secondAttempt.tcp_map = Seen(98);
    const NatPmpEpochDecision secondDecision =
        EvaluateNatPmpEpochSequence(secondAttempt);
    CHECK(secondDecision.previous_pair_invalidated);
    CHECK(secondDecision.strongest_boundary
        == NatPmpEpochBoundary::ResetBeforeTcpMap);
}

void TestBackwardToleranceCannotAccumulateAcrossSequence() {
    const NatPmpEpochDecision resetBeforeTcp =
        EvaluateNatPmpEpochSequence(
            Complete(100, 98, 96, 95));
    CHECK(resetBeforeTcp.strongest_boundary
        == NatPmpEpochBoundary::ResetBeforeTcpMap);
    CHECK(resetBeforeTcp.previous_pair_invalidated);
    CHECK(!resetBeforeTcp.external_address_current);
    CHECK(resetBeforeTcp.pair_can_commit);
    CHECK(!resetBeforeTcp.should_retry_pair);
    CHECK(resetBeforeTcp.continuity_epoch == 96);
    CHECK(resetBeforeTcp.latest_epoch == 95);

    const NatPmpEpochDecision resetBetweenPair =
        EvaluateNatPmpEpochSequence(
            Complete(100, 99, 98, 97));
    CHECK(resetBetweenPair.strongest_boundary
        == NatPmpEpochBoundary::ResetBetweenTcpAndUdp);
    CHECK(resetBetweenPair.previous_pair_invalidated);
    CHECK(!resetBetweenPair.external_address_current);
    CHECK(!resetBetweenPair.pair_can_commit);
    CHECK(resetBetweenPair.should_retry_pair);
    CHECK(resetBetweenPair.continuity_epoch == 97);
}

void TestElapsedMonotonicTimeDetectsARebootAtTheOldEpoch() {
    NatPmpEpochSequence sequence{};
    sequence.previous_snapshot = Seen(100, true, 1000);
    sequence.tcp_map = Seen(100, true, 4600);
    sequence.udp_map = Seen(101, true, 4601);
    const NatPmpEpochDecision decision =
        EvaluateNatPmpEpochSequence(sequence);
    CHECK(decision.strongest_boundary
        == NatPmpEpochBoundary::ResetBeforeTcpMap);
    CHECK(decision.previous_pair_invalidated);
    CHECK(!decision.external_address_current);
    CHECK(decision.pair_can_commit);
    CHECK(decision.continuity_epoch == 100);
    CHECK(decision.continuity_observed_at_seconds == 4600);
}

void TestContinuousEpochTracksElapsedMonotonicTime() {
    NatPmpEpochSequence sequence{};
    sequence.previous_snapshot = Seen(100, true, 1000);
    sequence.external_address = Seen(3699, true, 4600);
    sequence.tcp_map = Seen(3700, true, 4601);
    sequence.udp_map = Seen(3701, true, 4602);
    const NatPmpEpochDecision decision =
        EvaluateNatPmpEpochSequence(sequence);
    CHECK(decision.strongest_boundary
        == NatPmpEpochBoundary::Continuous);
    CHECK(!decision.previous_pair_invalidated);
    CHECK(decision.external_address_current);
    CHECK(decision.pair_can_commit);
    // The original anchor projects to 3702 here, which is stricter than
    // replacing it with the slightly lagging (but tolerated) observations.
    CHECK(decision.continuity_epoch == 100);
    CHECK(decision.continuity_observed_at_seconds == 1000);
}

void TestElapsedProjectionSaturatesWithoutWrapping() {
    NatPmpEpochSequence sequence{};
    sequence.previous_snapshot = Seen(100, true, 1);
    sequence.tcp_map = Seen(100, true, 0xffffffffffffffffULL);
    const NatPmpEpochDecision decision =
        EvaluateNatPmpEpochSequence(sequence);
    CHECK(decision.strongest_boundary
        == NatPmpEpochBoundary::ResetBeforeTcpMap);
    CHECK(decision.previous_pair_invalidated);
    CHECK(decision.continuity_epoch == 100);
    CHECK(decision.continuity_observed_at_seconds
        == 0xffffffffffffffffULL);
}

} // namespace

int main() {
    TestContinuousSequenceCommitsAndPublishesAddress();
    TestResetBeforeFreshExternalCanCommitANewPair();
    TestResetBeforeTcpInvalidatesTheEarlierAddressOnly();
    TestResetBetweenTcpAndUdpFailsAndRetriesPair();
    TestTwoSecondBackwardToleranceRemainsContinuous();
    TestRejectedMapStillInvalidatesPreviousPair();
    TestMissingExternalAddressCanStillCommitPair();
    TestTcpOnlyMappingDoesNotRequireUdpObservation();
    TestMissingUdpFailsWithoutInventingReset();
    TestLatestContinuousObservationCarriesIntoNextAttempt();
    TestBackwardToleranceCannotAccumulateAcrossSequence();
    TestElapsedMonotonicTimeDetectsARebootAtTheOldEpoch();
    TestContinuousEpochTracksElapsedMonotonicTime();
    TestElapsedProjectionSaturatesWithoutWrapping();
    std::printf(
        "test_natpmp_epoch_policy: %d checks, %d failures\n",
        checks, failures);
    return failures == 0 ? 0 : 1;
}
