#include "natmap/ownership_ledger.h"
#include "natmap/upnp_recovery_policy.h"

#include <array>
#include <cstdio>

using namespace natmap;

namespace {

int failures = 0;
int checks = 0;

#define CHECK(expr) do { ++checks; if (!(expr)) { ++failures; \
    std::printf("FAIL line %d: %s\n", __LINE__, #expr); } } while (0)

constexpr std::uint64_t kToken = 0x0123456789abcdefull;
constexpr std::uint64_t kGateway = 0xa56eea124da91c07ull;

UpnpOwnershipRecord Record() {
    UpnpOwnershipRecord record{};
    record.owner_token = kToken;
    record.gateway_fingerprint = kGateway;
    record.transport = Transport::Tcp;
    record.local_address = IpAddress::V4(192, 168, 68, 54);
    record.local_port = 4662;
    record.external_port = 4662;
    record.lifetime_seconds = 7200;
    record.acquired_unix_seconds = 1784220000;
    record.generation = 7;
    record.description =
        BuildOwnershipDescription(kToken, Transport::Tcp);
    return record;
}

ObservedUpnpMapping Observation(const UpnpOwnershipRecord& record) {
    ObservedUpnpMapping observed{};
    observed.transport = record.transport;
    observed.local_address = record.local_address;
    observed.local_port = record.local_port;
    observed.external_port = record.external_port;
    observed.description = record.description;
    return observed;
}

void TestExactOwnedMappingCanBeDeleted() {
    const UpnpOwnershipRecord record = Record();
    CHECK(EvaluateOwnershipForDeletion(
        record, kGateway, Observation(record)) ==
        OwnershipDecision::Owned);
    CHECK(EvaluateUpnpRecovery(
        OwnershipDecision::Owned) ==
        UpnpRecoveryAction::DeleteOwnedMapping);
}

void TestAbsentMappingDropsOnlyProof() {
    CHECK(EvaluateUpnpRecovery(
        UpnpRecoveryObservation::MappingAbsent) ==
        UpnpRecoveryAction::DropLocalProof);
}

void TestDescriptionMismatchNeverDeletes() {
    const UpnpOwnershipRecord record = Record();
    ObservedUpnpMapping observed = Observation(record);
    observed.description[4] = 'X';
    CHECK(EvaluateOwnershipForDeletion(
        record, kGateway, observed) ==
        OwnershipDecision::DescriptionMismatch);
    CHECK(EvaluateUpnpRecovery(
        OwnershipDecision::DescriptionMismatch) ==
        UpnpRecoveryAction::DropLocalProof);
}

void TestGatewayMismatchNeverDeletes() {
    const UpnpOwnershipRecord record = Record();
    CHECK(EvaluateOwnershipForDeletion(
        record, kGateway + 1, Observation(record)) ==
        OwnershipDecision::GatewayMismatch);
    CHECK(EvaluateUpnpRecovery(
        OwnershipDecision::GatewayMismatch) ==
        UpnpRecoveryAction::DropLocalProof);
}

void TestTransientAndUnknownKeepProof() {
    CHECK(EvaluateUpnpRecovery(
        UpnpRecoveryObservation::TransientReadbackFailure) ==
        UpnpRecoveryAction::KeepLocalProof);
    CHECK(EvaluateUpnpRecovery(
        static_cast<UpnpRecoveryObservation>(255)) ==
        UpnpRecoveryAction::KeepLocalProof);
    CHECK(EvaluateUpnpRecovery(
        OwnershipDecision::InvalidObservation) ==
        UpnpRecoveryAction::KeepLocalProof);
    CHECK(EvaluateUpnpRecovery(
        OwnershipDecision::InvalidRecord) ==
        UpnpRecoveryAction::KeepLocalProof);
    CHECK(EvaluateUpnpRecovery(
        static_cast<OwnershipDecision>(255)) ==
        UpnpRecoveryAction::KeepLocalProof);
}

void TestTruncatedJournalIsRejected() {
    OwnershipLedger ledger{};
    ledger.records[0] = Record();
    ledger.count = 1;
    std::array<std::uint8_t, kOwnershipLedgerMaxEncodedSize> bytes{};
    const std::size_t size =
        EncodeOwnershipLedger(ledger, bytes.data(), bytes.size());
    CHECK(size != 0);
    OwnershipLedger decoded{};
    CHECK(DecodeOwnershipLedger(bytes.data(), size - 1, decoded) ==
          OwnershipLedgerDecodeStatus::BadLength);
    CHECK(decoded.count == 0);
}

void TestPortReadbackIsStrict() {
    std::uint16_t port = 99;
    CHECK(ParseUpnpDecimalPort("4662", port));
    CHECK(port == 4662);
    CHECK(ParseUpnpDecimalPort("65535", port));
    CHECK(port == 65535);
    CHECK(!ParseUpnpDecimalPort("4662junk", port));
    CHECK(port == 0);
    CHECK(!ParseUpnpDecimalPort("65536", port));
    CHECK(!ParseUpnpDecimalPort("0", port));
    CHECK(!ParseUpnpDecimalPort("+4662", port));
    CHECK(!ParseUpnpDecimalPort(" 4662", port));
    CHECK(!ParseUpnpDecimalPort("", port));
    CHECK(!ParseUpnpDecimalPort(nullptr, port));
}

} // namespace

int main() {
    TestExactOwnedMappingCanBeDeleted();
    TestAbsentMappingDropsOnlyProof();
    TestDescriptionMismatchNeverDeletes();
    TestGatewayMismatchNeverDeletes();
    TestTransientAndUnknownKeepProof();
    TestTruncatedJournalIsRejected();
    TestPortReadbackIsStrict();
    std::printf("test_upnp_recovery_policy: %d checks, %d failures\n",
                checks, failures);
    return failures == 0 ? 0 : 1;
}
