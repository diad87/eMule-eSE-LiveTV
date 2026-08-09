#include "natmap/ownership_cleanup_policy.h"

#include <cstdio>

using namespace natmap;
namespace {
int checks = 0;
int failures = 0;
#define CHECK(x) do { ++checks; if (!(x)) { ++failures; std::printf("FAIL line %d: %s\n", __LINE__, #x); } } while (0)

std::array<OwnershipCleanupAuthorization, 2> OwnedPair() {
    return {{{Transport::Tcp, OwnershipDecision::Owned},
             {Transport::Udp, OwnershipDecision::Owned}}};
}

UpnpOwnershipRecord Record(Transport transport) {
    UpnpOwnershipRecord record{};
    record.owner_token = 11;
    record.gateway_fingerprint = 22;
    record.transport = transport;
    record.local_address = IpAddress::V4(192, 168, 1, 9);
    record.local_port = transport == Transport::Tcp ? 41001 : 41002;
    record.external_port = transport == Transport::Tcp ? 42001 : 42002;
    record.lifetime_seconds = 3600;
    record.acquired_unix_seconds = 1;
    record.generation = 7;
    record.description = BuildOwnershipDescription(record.owner_token, transport);
    return record;
}

void TestPairIdentityRejectsEveryDiscordance() {
    OwnershipLedger ledger{};
    ledger.count = 2;
    ledger.records[0] = Record(Transport::Tcp);
    ledger.records[1] = Record(Transport::Udp);
    CHECK(IsCoherentOwnershipPair(ledger));
    OwnershipLedger hostile = ledger;
    hostile.records[1].owner_token++;
    hostile.records[1].description = BuildOwnershipDescription(
        hostile.records[1].owner_token, Transport::Udp);
    CHECK(!IsCoherentOwnershipPair(hostile));
    hostile = ledger; hostile.records[1].gateway_fingerprint++;
    CHECK(!IsCoherentOwnershipPair(hostile));
    hostile = ledger; hostile.records[1].generation++;
    CHECK(!IsCoherentOwnershipPair(hostile));
    hostile = ledger; hostile.records[1].local_address =
        IpAddress::V4(192, 168, 1, 10);
    CHECK(!IsCoherentOwnershipPair(hostile));
    hostile = ledger; hostile.records[1] = hostile.records[0];
    CHECK(!IsCoherentOwnershipPair(hostile));
    hostile = ledger; hostile.count = 1;
    CHECK(!IsCoherentOwnershipPair(hostile));
}

void TestAllMismatchCasesDeleteZero() {
    for (unsigned value = static_cast<unsigned>(OwnershipDecision::InvalidRecord);
         value <= static_cast<unsigned>(OwnershipDecision::DescriptionMismatch);
         ++value) {
        auto pair = OwnedPair();
        pair[1].decision = static_cast<OwnershipDecision>(value);
        const auto blocked = BeginOwnershipCleanup(pair);
        CHECK(blocked.state == OwnershipCleanupState::Blocked);
        CHECK(!blocked.may_delete());
    }
    auto duplicate = OwnedPair();
    duplicate[1].transport = Transport::Tcp;
    CHECK(!BeginOwnershipCleanup(duplicate).may_delete());
}

void TestPartialIsObservableAndBounded() {
    auto cleanup = BeginOwnershipCleanup(OwnedPair());
    CHECK(cleanup.state == OwnershipCleanupState::Ready);
    CHECK(RecordOwnershipCleanupAttempt(cleanup, Transport::Tcp, true, true));
    CHECK(cleanup.state == OwnershipCleanupState::Partial);
    CHECK(cleanup.absent[0] && !cleanup.absent[1]);
    CHECK(!cleanup.may_clear_journal());
    CHECK(RecordOwnershipCleanupAttempt(cleanup, Transport::Udp, false, false));
    CHECK(cleanup.state == OwnershipCleanupState::Partial);
    CHECK(RecordOwnershipCleanupAttempt(cleanup, Transport::Udp, true, true));
    CHECK(cleanup.state == OwnershipCleanupState::Complete);
    CHECK(cleanup.may_clear_journal());
    CHECK(!RecordOwnershipCleanupAttempt(cleanup, Transport::Udp, true, true));
}

void TestRetryExhaustionPreservesJournal() {
    auto cleanup = BeginOwnershipCleanup(OwnedPair());
    CHECK(RecordOwnershipCleanupAttempt(cleanup, Transport::Tcp, false, false));
    CHECK(RecordOwnershipCleanupAttempt(cleanup, Transport::Tcp, false, false));
    CHECK(RecordOwnershipCleanupAttempt(cleanup, Transport::Udp, true, true));
    CHECK(cleanup.state == OwnershipCleanupState::RetryExhausted);
    CHECK(!cleanup.may_delete());
    CHECK(!cleanup.may_clear_journal());
}

void TestSoapSuccessWithoutAbsenceNeverClearsJournal() {
    auto cleanup = BeginOwnershipCleanup(OwnedPair());
    CHECK(RecordOwnershipCleanupAttempt(cleanup, Transport::Tcp, true, false));
    CHECK(cleanup.state == OwnershipCleanupState::Partial);
    CHECK(!cleanup.absent[0]);
    CHECK(!cleanup.may_clear_journal());
    // Models crash/save failure recovery: the durable record remains and a
    // later 714 can retire it, but SOAP success alone never can.
    CHECK(RecordOwnershipCleanupAttempt(cleanup, Transport::Tcp, false, true));
    CHECK(cleanup.absent[0]);
    CHECK(!cleanup.may_clear_journal());
}
}

int main() {
    TestAllMismatchCasesDeleteZero();
    TestPairIdentityRejectsEveryDiscordance();
    TestPartialIsObservableAndBounded();
    TestRetryExhaustionPreservesJournal();
    TestSoapSuccessWithoutAbsenceNeverClearsJournal();
    std::printf("ownership cleanup policy: %d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
