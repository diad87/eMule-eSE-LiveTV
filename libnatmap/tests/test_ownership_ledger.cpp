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

} // namespace

int main() {
    TestDescriptionAndRecordValidation();
    TestDeletionGateFailsClosed();
    TestCodecRoundTripAndCorruption();
    TestLedgerRejectsAmbiguousRules();
    std::printf("test_ownership_ledger: %d checks, %d failures\n",
                checks, failures);
    return failures == 0 ? 0 : 1;
}
