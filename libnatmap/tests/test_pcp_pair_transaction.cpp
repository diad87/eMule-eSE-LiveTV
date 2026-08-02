#include "natmap/pcp_pair_transaction.h"

#include <cstdio>

using namespace natmap;

namespace {

int failures = 0;
int checks = 0;

#define CHECK(expr) do { ++checks; if (!(expr)) { ++failures; \
    std::printf("FAIL line %d: %s\n", __LINE__, #expr); } } while (0)

PcpMapProjection Projection(
    Transport transport,
    std::uint16_t internal_port,
    std::uint16_t external_port,
    std::uint8_t nonce_seed) {
    PcpMapProjection projection{};
    projection.transport = transport;
    projection.internal_port = internal_port;
    projection.requested_external_port = internal_port;
    projection.granted_external_port = external_port;
    projection.external_address = IpAddress::V4(88, 11, 22, 44);
    projection.lifetime_seconds = 7200;
    projection.epoch = 1234;
    for (std::size_t i = 0; i < projection.nonce.size(); ++i)
        projection.nonce[i] =
            static_cast<std::uint8_t>(nonce_seed + i);
    return projection;
}

PcpMapProjection Tcp() {
    return Projection(Transport::Tcp, 4662, 52144, 1);
}

PcpMapProjection Udp() {
    return Projection(Transport::Udp, 4672, 52145, 21);
}

void TestCompletePairCommitsExactlyOnce() {
    PcpPairTransaction transaction(true, true);
    PcpPairCommit commit{};
    CHECK(transaction.StageTcp(Tcp()));
    CHECK(transaction.status()
        == PcpPairTransactionStatus::AwaitingUdp);
    CHECK(!transaction.TryCommit(commit));
    CHECK(!commit.IsValid());
    CHECK(transaction.StageUdp(Udp()));
    CHECK(transaction.status() == PcpPairTransactionStatus::Ready);
    CHECK(transaction.TryCommit(commit));
    CHECK(commit.IsValid());
    CHECK(commit.has_udp);
    CHECK(commit.tcp.granted_external_port == 52144);
    CHECK(commit.udp.granted_external_port == 52145);
    CHECK(commit.tcp.nonce == Tcp().nonce);
    CHECK(commit.udp.nonce == Udp().nonce);
    CHECK(transaction.status()
        == PcpPairTransactionStatus::Committed);

    PcpPairCommit reused = commit;
    CHECK(!transaction.TryCommit(reused));
    CHECK(!reused.IsValid());
}

void TestInitialUdpFailureRequiresExactTcpRollback() {
    PcpPairTransaction transaction(true, true);
    CHECK(transaction.StageTcp(Tcp()));
    transaction.RecordUdpFailure();
    CHECK(transaction.status()
        == PcpPairTransactionStatus::TcpRollbackRequired);

    PcpPairCommit partial{};
    CHECK(!transaction.TryCommit(partial));
    CHECK(!partial.IsValid());
    CHECK(!transaction.StageUdp(Udp()));

    PcpMappingIdentity rollback{};
    CHECK(transaction.GetTcpRollbackIdentity(rollback));
    CHECK(rollback.transport == Transport::Tcp);
    CHECK(rollback.internal_port == 4662);
    CHECK(rollback.nonce == Tcp().nonce);
}

void TestRefreshUdpFailureNeverDeletesExistingTcp() {
    PcpPairTransaction transaction(true, false);
    CHECK(transaction.StageTcp(Tcp()));
    transaction.RecordUdpFailure();
    CHECK(transaction.status() == PcpPairTransactionStatus::Failed);

    PcpMappingIdentity rollback{};
    CHECK(!transaction.GetTcpRollbackIdentity(rollback));
    CHECK(rollback.IsEmpty());
    PcpPairCommit partial{};
    CHECK(!transaction.TryCommit(partial));
    CHECK(!partial.IsValid());
}

void TestEpochResetBetweenTcpAndUdpFailsThePair() {
    PcpPairTransaction transaction(true, true);
    CHECK(transaction.StageTcp(Tcp()));
    PcpMapProjection rebooted_udp = Udp();
    rebooted_udp.epoch = 1;
    CHECK(!transaction.StageUdp(rebooted_udp));
    transaction.RecordUdpFailure();
    CHECK(transaction.status()
        == PcpPairTransactionStatus::TcpRollbackRequired);
    PcpPairCommit partial{};
    CHECK(!transaction.TryCommit(partial));
    CHECK(!partial.IsValid());
    PcpMappingIdentity rollback{};
    CHECK(transaction.GetTcpRollbackIdentity(rollback));
    CHECK(rollback.nonce == Tcp().nonce);

    PcpPairTransaction reordered(true, true);
    CHECK(reordered.StageTcp(Tcp()));
    PcpMapProjection one_second_older = Udp();
    one_second_older.epoch = Tcp().epoch - 1;
    CHECK(reordered.StageUdp(one_second_older));
    PcpPairCommit commit{};
    CHECK(reordered.TryCommit(commit));
    CHECK(commit.IsValid());
}

void TestTcpFailurePublishesAndRollsBackNothing() {
    PcpPairTransaction transaction(true, true);
    transaction.RecordTcpFailure();
    CHECK(transaction.status() == PcpPairTransactionStatus::Failed);

    PcpPairCommit commit{};
    PcpMappingIdentity rollback{};
    CHECK(!transaction.TryCommit(commit));
    CHECK(!commit.IsValid());
    CHECK(!transaction.GetTcpRollbackIdentity(rollback));
    CHECK(rollback.IsEmpty());
    CHECK(!transaction.StageTcp(Tcp()));
}

void TestTcpOnlyOperationCanCommit() {
    PcpPairTransaction transaction(false, true);
    CHECK(transaction.StageTcp(Tcp()));
    CHECK(transaction.status() == PcpPairTransactionStatus::Ready);
    PcpPairCommit commit{};
    CHECK(transaction.TryCommit(commit));
    CHECK(commit.IsValid());
    CHECK(!commit.has_udp);
    CHECK(commit.tcp.nonce == Tcp().nonce);
}

void TestWrongTransportsFailClosed() {
    PcpPairTransaction transaction(true, true);
    CHECK(!transaction.StageTcp(Udp()));
    CHECK(transaction.status()
        == PcpPairTransactionStatus::AwaitingTcp);
    CHECK(transaction.StageTcp(Tcp()));
    CHECK(!transaction.StageUdp(Tcp()));
    CHECK(transaction.status()
        == PcpPairTransactionStatus::AwaitingUdp);
}

} // namespace

int main() {
    TestCompletePairCommitsExactlyOnce();
    TestInitialUdpFailureRequiresExactTcpRollback();
    TestRefreshUdpFailureNeverDeletesExistingTcp();
    TestEpochResetBetweenTcpAndUdpFailsThePair();
    TestTcpFailurePublishesAndRollsBackNothing();
    TestTcpOnlyOperationCanCommit();
    TestWrongTransportsFailClosed();
    std::printf("test_pcp_pair_transaction: %d checks, %d failures\n",
                checks, failures);
    return failures == 0 ? 0 : 1;
}
