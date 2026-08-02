#include "natmap/ownership_ledger.h"

#include <array>
#include <cstdio>
#include <cstring>

using namespace natmap;

namespace {

int checks = 0;
int failures = 0;
#define CHECK(expr) do { ++checks; if (!(expr)) { ++failures; \
    std::printf("FAIL line %d: %s\n", __LINE__, #expr); } } while (0)

constexpr std::uint64_t kToken = 0x0123456789abcdefull;
constexpr std::uint64_t kGateway = 0xa56eea124da91c07ull;

std::uint32_t Crc32(const std::uint8_t* bytes, std::size_t length) {
    std::uint32_t crc = 0xffffffffu;
    for (std::size_t i = 0; i < length; ++i) {
        crc ^= bytes[i];
        for (unsigned bit = 0; bit < 8; ++bit)
            crc = (crc >> 1) ^
                (0xedb88320u & (0u - (crc & 1u)));
    }
    return ~crc;
}

void RewriteChecksum(std::uint8_t* bytes, std::size_t length) {
    const std::uint32_t checksum = Crc32(bytes, length - 4);
    for (unsigned i = 0; i < 4; ++i)
        bytes[length - 4 + i] =
            static_cast<std::uint8_t>(checksum >> (i * 8));
}

UpnpOwnershipRecord Record(Transport transport = Transport::Tcp,
                           std::uint16_t local_port = 4662,
                           std::uint16_t external_port = 4662) {
    UpnpOwnershipRecord record{};
    record.owner_token = kToken;
    record.gateway_fingerprint = kGateway;
    record.transport = transport;
    record.local_address = IpAddress::V4(192, 168, 68, 54);
    record.local_port = local_port;
    record.external_port = external_port;
    record.lifetime_seconds = 7200;
    record.acquired_unix_seconds = 1784220000;
    record.generation = 7;
    record.description = BuildOwnershipDescription(kToken, transport);
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

void TestDescriptionAndRecordValidation() {
    const OwnershipDescription tcp =
        BuildOwnershipDescription(kToken, Transport::Tcp);
    const OwnershipDescription udp =
        BuildOwnershipDescription(kToken, Transport::Udp);
    CHECK(std::strcmp(tcp.data(), "eT028T5CY4TQKFF") == 0);
    CHECK(std::strcmp(udp.data(), "eU028T5CY4TQKFF") == 0);
    CHECK(std::strlen(tcp.data()) <= 15);
    CHECK(Record().IsStructurallyValid());

    UpnpOwnershipRecord invalid = Record();
    invalid.owner_token = 0;
    CHECK(!invalid.IsStructurallyValid());
    invalid = Record();
    invalid.description[8] = 'X';
    CHECK(!invalid.IsStructurallyValid());
    invalid = Record();
    invalid.local_address = IpAddress::V4(0, 0, 0, 0);
    CHECK(!invalid.IsStructurallyValid());

    UpnpOwnershipRecord legacy = Record();
    const char legacyDescription[] = "eMuleT-0123456789ABCDEF";
    std::memcpy(legacy.description.data(), legacyDescription,
                sizeof(legacyDescription));
    CHECK(legacy.IsStructurallyValid());
}

void TestDeletionGateFailsClosed() {
    const UpnpOwnershipRecord record = Record();
    ObservedUpnpMapping observed = Observation(record);
    CHECK(EvaluateOwnershipForDeletion(record, kGateway, observed) ==
          OwnershipDecision::Owned);
    CHECK(EvaluateOwnershipForDeletion(record, 0, observed) ==
          OwnershipDecision::GatewayMismatch);
    CHECK(EvaluateOwnershipForDeletion(record, kGateway + 1, observed) ==
          OwnershipDecision::GatewayMismatch);

    observed.transport = Transport::Udp;
    CHECK(EvaluateOwnershipForDeletion(record, kGateway, observed) ==
          OwnershipDecision::TransportMismatch);
    observed = Observation(record);
    observed.external_port++;
    CHECK(EvaluateOwnershipForDeletion(record, kGateway, observed) ==
          OwnershipDecision::ExternalPortMismatch);
    observed = Observation(record);
    observed.local_address = IpAddress::V4(192, 168, 68, 55);
    CHECK(EvaluateOwnershipForDeletion(record, kGateway, observed) ==
          OwnershipDecision::InternalClientMismatch);
    observed = Observation(record);
    observed.local_port++;
    CHECK(EvaluateOwnershipForDeletion(record, kGateway, observed) ==
          OwnershipDecision::InternalPortMismatch);
    observed = Observation(record);
    observed.description[14] = '0';
    CHECK(EvaluateOwnershipForDeletion(record, kGateway, observed) ==
          OwnershipDecision::DescriptionMismatch);
    observed = Observation(record);
    observed.description.fill('A');
    CHECK(EvaluateOwnershipForDeletion(record, kGateway, observed) ==
          OwnershipDecision::InvalidObservation);

    UpnpOwnershipRecord malicious = record;
    malicious.description = BuildOwnershipDescription(kToken + 1,
                                                       Transport::Tcp);
    CHECK(EvaluateOwnershipForDeletion(malicious, kGateway,
                                       Observation(malicious)) ==
          OwnershipDecision::InvalidRecord);
}

void TestCodecRoundTripAndCorruption() {
    OwnershipLedger source{};
    source.records[0] = Record();
    source.records[1] = Record(Transport::Udp, 4672, 4672);
    source.count = 2;
    CHECK(source.IsStructurallyValid());

    std::array<std::uint8_t, kOwnershipLedgerMaxEncodedSize> bytes{};
    const std::size_t size =
        EncodeOwnershipLedger(source, bytes.data(), bytes.size());
    CHECK(size == 16 + 2 * 84 + 4);
    OwnershipLedger decoded{};
    CHECK(DecodeOwnershipLedger(bytes.data(), size, decoded) ==
          OwnershipLedgerDecodeStatus::Ok);
    CHECK(decoded.count == 2);
    CHECK(decoded.records[0].owner_token == kToken);
    CHECK(decoded.records[0].external_port == 4662);
    CHECK(decoded.records[1].transport == Transport::Udp);
    CHECK(decoded.records[1].local_port == 4672);
    CHECK(std::strcmp(decoded.records[1].description.data(),
                      "eU028T5CY4TQKFF") == 0);

    std::array<std::uint8_t, kOwnershipLedgerMaxEncodedSize> corrupt = bytes;
    corrupt[40] ^= 0x80;
    CHECK(DecodeOwnershipLedger(corrupt.data(), size, decoded) ==
          OwnershipLedgerDecodeStatus::BadChecksum);
    CHECK(DecodeOwnershipLedger(bytes.data(), size - 1, decoded) ==
          OwnershipLedgerDecodeStatus::BadLength);
    corrupt = bytes;
    corrupt[0] = 'X';
    CHECK(DecodeOwnershipLedger(corrupt.data(), size, decoded) ==
          OwnershipLedgerDecodeStatus::BadMagic);
    corrupt = bytes;
    corrupt[8] = 2;
    CHECK(DecodeOwnershipLedger(corrupt.data(), size, decoded) ==
          OwnershipLedgerDecodeStatus::UnsupportedVersion);
    CHECK(EncodeOwnershipLedger(source, bytes.data(), size - 1) == 0);

    // A syntactically checksummed but semantically forged record still fails.
    corrupt = bytes;
    for (std::size_t i = 16; i < 24; ++i)
        corrupt[i] = 0; // owner token
    RewriteChecksum(corrupt.data(), size);
    CHECK(DecodeOwnershipLedger(corrupt.data(), size, decoded) ==
          OwnershipLedgerDecodeStatus::InvalidRecord);
    CHECK(decoded.count == 0);
    corrupt = bytes;
    corrupt[34] = 1; // reserved record byte
    RewriteChecksum(corrupt.data(), size);
    CHECK(DecodeOwnershipLedger(corrupt.data(), size, decoded) ==
          OwnershipLedgerDecodeStatus::InvalidRecord);
    CHECK(decoded.count == 0);

    OwnershipLedger empty{};
    const std::size_t emptySize =
        EncodeOwnershipLedger(empty, bytes.data(), bytes.size());
    CHECK(emptySize == 20);
    CHECK(DecodeOwnershipLedger(bytes.data(), emptySize, decoded) ==
          OwnershipLedgerDecodeStatus::Ok);
    CHECK(decoded.count == 0);
}

void TestJournalCorruptionCorpus() {
    OwnershipLedger source{};
    source.records[0] = Record();
    source.records[1] = Record(Transport::Udp, 4672, 4672);
    source.count = 2;

    std::array<std::uint8_t, kOwnershipLedgerMaxEncodedSize> bytes{};
    const std::size_t size =
        EncodeOwnershipLedger(source, bytes.data(), bytes.size());
    CHECK(size == 16 + 2 * 84 + 4);

    // Every strict prefix cuts either the header, a record field or checksum.
    // None may leave even a partial ownership proof behind.
    for (std::size_t length = 0; length < size; ++length) {
        OwnershipLedger decoded{};
        decoded.records[0] = Record();
        decoded.count = 1;
        CHECK(DecodeOwnershipLedger(bytes.data(), length, decoded) !=
              OwnershipLedgerDecodeStatus::Ok);
        CHECK(decoded.count == 0);
    }

    OwnershipLedger decoded{};
    std::array<std::uint8_t, kOwnershipLedgerMaxEncodedSize + 1>
        oversized{};
    std::copy(bytes.begin(), bytes.begin() + size, oversized.begin());
    CHECK(DecodeOwnershipLedger(
              oversized.data(), size + 1, decoded) ==
          OwnershipLedgerDecodeStatus::BadLength);
    CHECK(decoded.count == 0);

    auto corrupt = bytes;
    corrupt[8] = 0xff; // unknown version
    CHECK(DecodeOwnershipLedger(corrupt.data(), size, decoded) ==
          OwnershipLedgerDecodeStatus::UnsupportedVersion);
    CHECK(decoded.count == 0);

    corrupt = bytes;
    corrupt[10] = 0; // unknown record width
    CHECK(DecodeOwnershipLedger(corrupt.data(), size, decoded) ==
          OwnershipLedgerDecodeStatus::BadRecordSize);
    CHECK(decoded.count == 0);

    corrupt = bytes;
    corrupt[12] = static_cast<std::uint8_t>(
        kMaxOwnershipRecords + 1); // excessive count
    CHECK(DecodeOwnershipLedger(corrupt.data(), size, decoded) ==
          OwnershipLedgerDecodeStatus::TooManyRecords);
    CHECK(decoded.count == 0);

    corrupt = bytes;
    corrupt[14] = 1; // non-zero header reserved field
    CHECK(DecodeOwnershipLedger(corrupt.data(), size, decoded) ==
          OwnershipLedgerDecodeStatus::BadLength);
    CHECK(decoded.count == 0);

    corrupt = bytes;
    std::copy(corrupt.begin() + 16, corrupt.begin() + 16 + 84,
              corrupt.begin() + 16 + 84);
    RewriteChecksum(corrupt.data(), size);
    CHECK(DecodeOwnershipLedger(corrupt.data(), size, decoded) ==
          OwnershipLedgerDecodeStatus::InvalidRecord);
    CHECK(decoded.count == 0);

    OwnershipLedger one{};
    one.records[0] = Record();
    one.count = 1;
    std::array<std::uint8_t, kOwnershipLedgerMaxEncodedSize> canonical{};
    const std::size_t canonicalSize =
        EncodeOwnershipLedger(one, canonical.data(), canonical.size());
    CHECK(canonicalSize == 16 + 84 + 4);

    auto expectInvalidRange =
        [&](std::size_t begin, std::size_t end,
            std::uint8_t replacement = 0) {
            auto invalid = canonical;
            std::fill(invalid.begin() + begin, invalid.begin() + end,
                      replacement);
            RewriteChecksum(invalid.data(), canonicalSize);
            decoded.records[0] = Record();
            decoded.count = 1;
            CHECK(DecodeOwnershipLedger(
                      invalid.data(), canonicalSize, decoded) ==
                  OwnershipLedgerDecodeStatus::InvalidRecord);
            CHECK(decoded.count == 0);
        };

    // Record offsets include the 16-byte header.
    expectInvalidRange(16, 24); // owner token
    expectInvalidRange(24, 32); // gateway fingerprint
    expectInvalidRange(32, 33, 0xff); // transport
    expectInvalidRange(33, 34, 0xff); // address family
    expectInvalidRange(34, 35, 1); // record reserved field
    expectInvalidRange(36, 40); // unspecified IPv4 address
    expectInvalidRange(52, 54); // local port
    expectInvalidRange(54, 56); // external port
    expectInvalidRange(60, 68); // acquisition time
    expectInvalidRange(68, 76); // generation
    expectInvalidRange(76, 77, 0x1f); // non-printable description
    expectInvalidRange(76, 77, 'X'); // description/token mismatch

    // IPv4 padding and bytes after the first description terminator are
    // serialized structure, so accepting hidden non-zero data is ambiguous.
    expectInvalidRange(40, 41, 1);
    expectInvalidRange(92, 93, 'X');
}

void TestLedgerRejectsAmbiguousRules() {
    OwnershipLedger ledger{};
    ledger.records[0] = Record();
    ledger.records[1] = Record();
    ledger.records[1].owner_token++;
    ledger.records[1].description = BuildOwnershipDescription(
        ledger.records[1].owner_token, ledger.records[1].transport);
    ledger.count = 2;
    CHECK(!ledger.IsStructurallyValid());

    ledger.records[1] = Record(Transport::Udp, 4672, 4672);
    CHECK(ledger.IsStructurallyValid());
    ledger.count = static_cast<std::uint8_t>(kMaxOwnershipRecords + 1);
    CHECK(!ledger.IsStructurallyValid());
}

void TestJournalCommitRequiresExactOrderAndVerification() {
    OwnershipJournalCommit commit;
    CHECK(!commit.IsPersisted());
    CHECK(commit.Complete(OwnershipJournalStep::Encoded));
    CHECK(commit.Complete(OwnershipJournalStep::TemporaryWritten));
    CHECK(commit.Complete(OwnershipJournalStep::TemporaryFlushed));
    CHECK(commit.Complete(OwnershipJournalStep::TemporaryClosed));
    CHECK(commit.Complete(OwnershipJournalStep::FinalReplaced));
    CHECK(!commit.IsPersisted());
    CHECK(commit.Complete(OwnershipJournalStep::FinalVerified));
    CHECK(commit.IsPersisted());
    CHECK(!commit.Complete(OwnershipJournalStep::FinalVerified));
    CHECK(commit.HasFailed());

    OwnershipJournalCommit skipped;
    CHECK(skipped.Complete(OwnershipJournalStep::Encoded));
    CHECK(!skipped.Complete(OwnershipJournalStep::TemporaryFlushed));
    CHECK(skipped.HasFailed());
    CHECK(!skipped.Complete(OwnershipJournalStep::TemporaryWritten));
    CHECK(!skipped.IsPersisted());

    OwnershipJournalCommit failed;
    CHECK(failed.Complete(OwnershipJournalStep::Encoded));
    failed.Fail();
    CHECK(!failed.Complete(OwnershipJournalStep::TemporaryWritten));
    CHECK(failed.HasFailed());
    CHECK(!failed.IsPersisted());

    OwnershipJournalCommit invalid;
    CHECK(!invalid.Complete(
        static_cast<OwnershipJournalStep>(255)));
    CHECK(invalid.HasFailed());
}

void TestCleanupRequiresEveryOwnershipProof() {
    const UpnpOwnershipRecord record = Record();
    ObservedUpnpMapping observed = Observation(record);
    CHECK(IsUpnpCleanupAuthorized(record, kGateway, observed));

    UpnpOwnershipRecord invalidRecord = record;
    invalidRecord.owner_token = 0;
    CHECK(!IsUpnpCleanupAuthorized(
        invalidRecord, kGateway, observed));
    CHECK(!IsUpnpCleanupAuthorized(record, 0, observed));
    CHECK(!IsUpnpCleanupAuthorized(
        record, kGateway + 1, observed));

    observed = Observation(record);
    observed.description[3] = 'X';
    CHECK(!IsUpnpCleanupAuthorized(record, kGateway, observed));
    observed = Observation(record);
    observed.local_address = IpAddress::V4(192, 168, 68, 55);
    CHECK(!IsUpnpCleanupAuthorized(record, kGateway, observed));
    observed = Observation(record);
    observed.local_port = 4672;
    CHECK(!IsUpnpCleanupAuthorized(record, kGateway, observed));
    observed = Observation(record);
    observed.external_port = 4672;
    CHECK(!IsUpnpCleanupAuthorized(record, kGateway, observed));
    observed = Observation(record);
    observed.transport = Transport::Udp;
    CHECK(!IsUpnpCleanupAuthorized(record, kGateway, observed));
    observed = Observation(record);
    observed.local_port = 0;
    CHECK(!IsUpnpCleanupAuthorized(record, kGateway, observed));
}

void TestOwnershipDescriptionNeverTruncates() {
    OwnershipDescription parsed{};
    const OwnershipDescription compact =
        BuildOwnershipDescription(kToken, Transport::Tcp);
    CHECK(ParseOwnershipDescription(
        compact.data(), compact.size(), parsed));
    CHECK(parsed == compact);

    const char legacy[] = "eMuleT-0123456789ABCDEF";
    CHECK(ParseOwnershipDescription(
        legacy, sizeof(legacy), parsed));
    CHECK(std::strcmp(parsed.data(), legacy) == 0);

    const char legacyWithSuffix[] =
        "eMuleT-0123456789ABCDEFSUFFIX";
    CHECK(!ParseOwnershipDescription(
        legacyWithSuffix, sizeof(legacyWithSuffix), parsed));
    CHECK(parsed[0] == 0);

    const char unterminated[] = {
        'e', 'T', '0', '2', '8', 'T', '5', 'C'
    };
    CHECK(!ParseOwnershipDescription(
        unterminated, sizeof(unterminated), parsed));
    CHECK(!ParseOwnershipDescription(nullptr, 0, parsed));
}

} // namespace

int main() {
    TestDescriptionAndRecordValidation();
    TestDeletionGateFailsClosed();
    TestCodecRoundTripAndCorruption();
    TestJournalCorruptionCorpus();
    TestLedgerRejectsAmbiguousRules();
    TestJournalCommitRequiresExactOrderAndVerification();
    TestCleanupRequiresEveryOwnershipProof();
    TestOwnershipDescriptionNeverTruncates();
    std::printf("test_ownership_ledger: %d checks, %d failures\n",
                checks, failures);
    return failures == 0 ? 0 : 1;
}
