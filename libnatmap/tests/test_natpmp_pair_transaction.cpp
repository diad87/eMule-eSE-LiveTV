#include "natmap/natpmp_pair_transaction.h"

#include <cstdio>

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
    std::printf(
        "test_natpmp_pair_transaction: %d checks, %d failures\n",
        checks, failures);
    return failures == 0 ? 0 : 1;
}
