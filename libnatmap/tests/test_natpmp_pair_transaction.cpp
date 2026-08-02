#include "natmap/natpmp_pair_transaction.h"

#include <cstdio>
#include <limits>

using namespace natmap;

namespace {

int failures = 0;
int checks = 0;

#define CHECK(expr) do { ++checks; if (!(expr)) { ++failures; \
    std::printf("FAIL line %d: %s\n", __LINE__, #expr); } } while (0)

NatPmpMapProjection Projection(
    NatPmpTransport transport,
    std::uint16_t internal_port,
    std::uint16_t requested_external_port,
    std::uint16_t granted_external_port) {
    NatPmpMapProjection projection{};
    projection.transport = transport;
    projection.requested_external_port = requested_external_port;
    projection.response.result_code = 0;
    projection.response.epoch = 1234;
    projection.response.internal_port = internal_port;
    projection.response.external_port = granted_external_port;
    projection.response.lifetime_seconds = 7200;
    return projection;
}

NatPmpMapProjection Tcp() {
    return Projection(
        NatPmpTransport::Tcp, 4662, 4662, 52144);
}

NatPmpMapProjection Udp() {
    return Projection(
        NatPmpTransport::Udp, 4672, 4672, 52145);
}

void TestCompletePairCommitsAlternativePortsExactlyOnce() {
    NatPmpPairTransaction transaction(true, true);
    NatPmpPairCommit commit{};
    CHECK(transaction.StageTcp(Tcp()));
    CHECK(transaction.status()
        == NatPmpPairTransactionStatus::AwaitingUdp);
    CHECK(!transaction.TryCommit(commit));
    CHECK(!commit.IsValid());
    CHECK(transaction.StageUdp(Udp()));
    CHECK(transaction.status()
        == NatPmpPairTransactionStatus::Ready);
    CHECK(transaction.TryCommit(commit));
    CHECK(commit.IsValid());
    CHECK(commit.has_udp);
    CHECK(commit.tcp.requested_external_port == 4662);
    CHECK(commit.tcp.response.external_port == 52144);
    CHECK(commit.udp.requested_external_port == 4672);
    CHECK(commit.udp.response.external_port == 52145);
    CHECK(transaction.status()
        == NatPmpPairTransactionStatus::Committed);

    NatPmpPairCommit reused = commit;
    CHECK(!transaction.TryCommit(reused));
    CHECK(!reused.IsValid());
}

void TestInitialUdpFailureRequiresExactTcpRollback() {
    NatPmpPairTransaction transaction(true, true);
    CHECK(transaction.StageTcp(Tcp()));
    transaction.RecordUdpFailure();
    CHECK(transaction.status()
        == NatPmpPairTransactionStatus::TcpRollbackRequired);

    NatPmpPairCommit partial{};
    CHECK(!transaction.TryCommit(partial));
    CHECK(!partial.IsValid());
    CHECK(!transaction.StageUdp(Udp()));

    NatPmpRollbackTarget rollback{};
    CHECK(transaction.GetTcpRollbackTarget(rollback));
    CHECK(rollback.transport == NatPmpTransport::Tcp);
    CHECK(rollback.internal_port == 4662);
}

void TestRefreshUdpFailurePreservesPreviousPair() {
    NatPmpPairTransaction transaction(true, false);
    CHECK(transaction.StageTcp(Tcp()));
    transaction.RecordUdpFailure();
    CHECK(transaction.status()
        == NatPmpPairTransactionStatus::Failed);

    NatPmpRollbackTarget rollback{};
    CHECK(!transaction.GetTcpRollbackTarget(rollback));
    CHECK(!rollback.IsValid());
    NatPmpPairCommit partial{};
    CHECK(!transaction.TryCommit(partial));
    CHECK(!partial.IsValid());
}

void TestFailureDispositionInvalidatesAPreResetPair() {
    CHECK(ResolveNatPmpPairFailureDisposition(true, false)
        == NatPmpPairFailureDisposition::ClearProvisional);
    CHECK(ResolveNatPmpPairFailureDisposition(false, false)
        == NatPmpPairFailureDisposition::PreservePrevious);
    CHECK(ResolveNatPmpPairFailureDisposition(false, true)
        == NatPmpPairFailureDisposition::InvalidatePrevious);
    CHECK(ResolveNatPmpPairFailureDisposition(true, true)
        == NatPmpPairFailureDisposition::InvalidatePrevious);

    const bool external_address_observed_reset = true;
    const bool map_completed = false;
    CHECK(!map_completed &&
        ResolveNatPmpPairFailureDisposition(
            false, external_address_observed_reset)
        == NatPmpPairFailureDisposition::InvalidatePrevious);
}

void TestRejectedResponsesStillCarryCorrelatedEpochEvidence() {
    NatPmpMapResponse rejected{};
    rejected.result_code = 4;
    rejected.epoch = 2;
    rejected.internal_port = 4662;
    CHECK(HasCorrelatedNatPmpMapObservation(rejected, 4662));
    CHECK(rejected.epoch == 2);
    CHECK(!HasCorrelatedNatPmpMapObservation(rejected, 4672));
    CHECK(!HasCorrelatedNatPmpMapObservation({}, 4662));
    CHECK(!HasCorrelatedNatPmpMapObservation(rejected, 0));
}

void TestTcpFailurePublishesAndRollsBackNothing() {
    NatPmpPairTransaction transaction(true, true);
    transaction.RecordTcpFailure();
    CHECK(transaction.status()
        == NatPmpPairTransactionStatus::Failed);

    NatPmpPairCommit commit{};
    NatPmpRollbackTarget rollback{};
    CHECK(!transaction.TryCommit(commit));
    CHECK(!commit.IsValid());
    CHECK(!transaction.GetTcpRollbackTarget(rollback));
    CHECK(!rollback.IsValid());
    CHECK(!transaction.StageTcp(Tcp()));
}

void TestTcpOnlyOperationCanCommit() {
    NatPmpPairTransaction transaction(false, true);
    CHECK(transaction.StageTcp(Tcp()));
    CHECK(transaction.status()
        == NatPmpPairTransactionStatus::Ready);
    NatPmpPairCommit commit{};
    CHECK(transaction.TryCommit(commit));
    CHECK(commit.IsValid());
    CHECK(!commit.has_udp);
    CHECK(commit.tcp.response.external_port == 52144);
}

void TestMalformedOrWrongTransportProjectionsFailClosed() {
    NatPmpPairTransaction transaction(true, true);
    CHECK(!transaction.StageTcp(Udp()));

    NatPmpMapProjection rejected = Tcp();
    rejected.response.result_code = 2;
    CHECK(!transaction.StageTcp(rejected));
    NatPmpMapProjection zero_internal = Tcp();
    zero_internal.response.internal_port = 0;
    CHECK(!transaction.StageTcp(zero_internal));
    NatPmpMapProjection zero_external = Tcp();
    zero_external.response.external_port = 0;
    CHECK(!transaction.StageTcp(zero_external));
    NatPmpMapProjection zero_lifetime = Tcp();
    zero_lifetime.response.lifetime_seconds = 0;
    CHECK(!transaction.StageTcp(zero_lifetime));

    CHECK(transaction.StageTcp(Tcp()));
    CHECK(!transaction.StageUdp(Tcp()));
    CHECK(transaction.status()
        == NatPmpPairTransactionStatus::AwaitingUdp);
}

void TestLeaseDeadlineStartsBeforeMapAndSaturates() {
    CHECK(ConservativeNatPmpLeaseDeadline(100, 7200) == 7300);
    CHECK(ConservativeNatPmpLeaseDeadline(0, 7200) == 0);
    CHECK(ConservativeNatPmpLeaseDeadline(100, 0) == 0);
    const std::uint64_t maximum =
        (std::numeric_limits<std::uint64_t>::max)();
    CHECK(ConservativeNatPmpLeaseDeadline(
        maximum - 5, 10) == maximum);
}

void TestCleanupGenerationMatchesHostAcceptance() {
    CHECK(ResolveNatPmpCleanupGeneration(
        31, true, true, false, true) == 32);
    CHECK(ResolveNatPmpCleanupGeneration(
        31, true, true, false, false) == 31);
    CHECK(ResolveNatPmpCleanupGeneration(
        31, true, false, true, false) == 32);
    CHECK(ResolveNatPmpCleanupGeneration(
        31, false, true, true, true) == 31);
    CHECK(ResolveNatPmpCleanupGeneration(
        31, false, true, false, true) == 31);
    CHECK(ResolveNatPmpCleanupGeneration(
        0, true, true, false, true) == 0);
    const std::uint64_t maximum =
        (std::numeric_limits<std::uint64_t>::max)();
    CHECK(ResolveNatPmpCleanupGeneration(
        maximum, true, true, false, true) == 0);
}

NatPmpCleanupProof CleanupProof() {
    NatPmpCleanupProof proof{};
    proof.gateway_address = {192, 168, 1, 1};
    proof.interface_index = 17;
    proof.generation = 31;
    proof.expires_monotonic_seconds = 10000;
    proof.mappings[0] = NatPmpCleanupMapping{
        NatPmpTransport::Tcp, 4662, 52144};
    proof.mappings[1] = NatPmpCleanupMapping{
        NatPmpTransport::Udp, 4672, 52145};
    proof.mapping_count = 2;
    proof.in_process_proof = true;
    return proof;
}

NatPmpCleanupRequest CleanupRequest(
    const NatPmpCleanupMapping& mapping) {
    NatPmpCleanupRequest request{};
    request.gateway_address = {192, 168, 1, 1};
    request.interface_index = 17;
    request.generation = 31;
    request.observed_monotonic_seconds = 9998;
    request.mapping = mapping;
    return request;
}

void TestCleanupRequiresExactLiveSessionProof() {
    const NatPmpCleanupProof proof = CleanupProof();
    CHECK(proof.IsValid());
    CHECK(AllowsNatPmpCleanup(
        proof, CleanupRequest(proof.mappings[0])));
    CHECK(AllowsNatPmpCleanup(
        proof, CleanupRequest(proof.mappings[1])));

    NatPmpCleanupRequest wrong =
        CleanupRequest(proof.mappings[0]);
    wrong.gateway_address[3] = 2;
    CHECK(!AllowsNatPmpCleanup(proof, wrong));
    wrong = CleanupRequest(proof.mappings[0]);
    wrong.interface_index = 18;
    CHECK(!AllowsNatPmpCleanup(proof, wrong));
    wrong = CleanupRequest(proof.mappings[0]);
    wrong.generation = 30;
    CHECK(!AllowsNatPmpCleanup(proof, wrong));
    wrong = CleanupRequest(proof.mappings[0]);
    wrong.observed_monotonic_seconds = 9999;
    CHECK(!AllowsNatPmpCleanup(proof, wrong));
    wrong = CleanupRequest(proof.mappings[0]);
    wrong.observed_monotonic_seconds = 10000;
    CHECK(!AllowsNatPmpCleanup(proof, wrong));
    wrong = CleanupRequest(proof.mappings[0]);
    wrong.observed_monotonic_seconds = 10001;
    CHECK(!AllowsNatPmpCleanup(proof, wrong));
    wrong = CleanupRequest(proof.mappings[0]);
    wrong.mapping.internal_port = 4663;
    CHECK(!AllowsNatPmpCleanup(proof, wrong));
    wrong = CleanupRequest(proof.mappings[0]);
    wrong.mapping.external_port = 52145;
    CHECK(!AllowsNatPmpCleanup(proof, wrong));
    wrong = CleanupRequest(proof.mappings[0]);
    wrong.mapping.transport = NatPmpTransport::Udp;
    CHECK(!AllowsNatPmpCleanup(proof, wrong));
}

void TestCrashOrMalformedCleanupProofNeverDeletes() {
    const NatPmpCleanupProof proof = CleanupProof();
    CHECK(!AllowsNatPmpCleanup(
        NatPmpCleanupProof{},
        CleanupRequest(proof.mappings[0])));

    NatPmpCleanupProof malformed = proof;
    malformed.in_process_proof = false;
    CHECK(!malformed.IsValid());
    malformed = proof;
    malformed.generation = 0;
    CHECK(!malformed.IsValid());
    malformed = proof;
    malformed.expires_monotonic_seconds = 0;
    CHECK(!malformed.IsValid());
    malformed = proof;
    malformed.mapping_count = 0;
    CHECK(!malformed.IsValid());
    malformed = proof;
    malformed.mapping_count = 4;
    CHECK(!malformed.IsValid());
    malformed = proof;
    malformed.mappings[2] = malformed.mappings[0];
    malformed.mapping_count = 3;
    CHECK(!malformed.IsValid());
    malformed = proof;
    malformed.mappings[2] = malformed.mappings[0];
    malformed.mappings[2].external_port = 60000;
    malformed.mapping_count = 3;
    CHECK(!malformed.IsValid());
    malformed = proof;
    malformed.mappings[2] = NatPmpCleanupMapping{
        NatPmpTransport::Tcp, 4711, 0};
    malformed.mapping_count = 3;
    CHECK(!malformed.IsValid());

    malformed = proof;
    malformed.gateway_address = {127, 0, 0, 1};
    CHECK(!malformed.IsValid());
    malformed = proof;
    malformed.interface_index =
        kNatPmpMaximumInterfaceIndex + 1;
    CHECK(!malformed.IsValid());
}

void TestSessionCrashAndNaturalExpiryLifecycle() {
    NatPmpCleanupProof live = CleanupProof();
    const NatPmpCleanupRequest current =
        CleanupRequest(live.mappings[0]);
    NatPmpCleanupContext context{};
    context.gateway_address = current.gateway_address;
    context.interface_index = current.interface_index;
    context.generation = current.generation;
    context.observed_monotonic_seconds =
        current.observed_monotonic_seconds;
    const NatPmpCleanupPlan active =
        TakeNatPmpCleanupPlan(live, context);
    CHECK(active.mapping_count == 2);
    CHECK(active.mappings[0].internal_port == 4662);
    CHECK(active.mappings[1].internal_port == 4672);
    CHECK(!live.IsValid());

    // A restarted process has no in-memory proof. Port coincidence alone
    // must never recreate authority to delete the router rule.
    NatPmpCleanupProof after_crash{};
    const NatPmpCleanupPlan restarted =
        TakeNatPmpCleanupPlan(after_crash, context);
    CHECK(restarted.IsEmpty());
    CHECK(!after_crash.IsValid());

    // Once the conservative deadline is reached, the bounded lease is left
    // for the router to expire naturally; no ambiguous DELETE is emitted.
    NatPmpCleanupProof expired = CleanupProof();
    context.observed_monotonic_seconds =
        expired.expires_monotonic_seconds;
    const NatPmpCleanupPlan natural_expiry =
        TakeNatPmpCleanupPlan(expired, context);
    CHECK(natural_expiry.IsEmpty());
    CHECK(!expired.IsValid());
}

} // namespace

int main() {
    TestCompletePairCommitsAlternativePortsExactlyOnce();
    TestInitialUdpFailureRequiresExactTcpRollback();
    TestRefreshUdpFailurePreservesPreviousPair();
    TestFailureDispositionInvalidatesAPreResetPair();
    TestRejectedResponsesStillCarryCorrelatedEpochEvidence();
    TestTcpFailurePublishesAndRollsBackNothing();
    TestTcpOnlyOperationCanCommit();
    TestMalformedOrWrongTransportProjectionsFailClosed();
    TestLeaseDeadlineStartsBeforeMapAndSaturates();
    TestCleanupGenerationMatchesHostAcceptance();
    TestCleanupRequiresExactLiveSessionProof();
    TestCrashOrMalformedCleanupProofNeverDeletes();
    TestSessionCrashAndNaturalExpiryLifecycle();
    std::printf(
        "test_natpmp_pair_transaction: %d checks, %d failures\n",
        checks, failures);
    return failures == 0 ? 0 : 1;
}
