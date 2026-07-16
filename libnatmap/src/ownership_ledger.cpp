#include "natmap/ownership_ledger.h"

#include <algorithm>

namespace natmap {
namespace {

constexpr std::uint8_t kMagic[8] = {
    'N', 'A', 'T', 'O', 'W', 'N', '1', 0
};
constexpr std::uint16_t kVersion = 1;
constexpr std::uint16_t kHeaderSize = 16;
constexpr std::uint16_t kRecordSize = 84;
constexpr std::size_t kChecksumSize = 4;

bool SameAddress(const IpAddress& left, const IpAddress& right) noexcept {
    return left.family == right.family && left.bytes == right.bytes;
}

bool ValidTransport(Transport transport) noexcept {
    return transport == Transport::Tcp || transport == Transport::Udp;
}

bool IsTerminatedPrintable(const OwnershipDescription& value) noexcept {
    for (char ch : value) {
        if (ch == 0)
            return true;
        const unsigned char byte = static_cast<unsigned char>(ch);
        if (byte < 0x20 || byte > 0x7e)
            return false;
    }
    return false;
}

bool SameDescription(const OwnershipDescription& left,
                     const OwnershipDescription& right) noexcept {
    for (std::size_t i = 0; i < left.size(); ++i) {
        if (left[i] != right[i])
            return false;
        if (left[i] == 0)
            return true;
    }
    return false;
}

void Put16(std::uint8_t*& out, std::uint16_t value) noexcept {
    *out++ = static_cast<std::uint8_t>(value);
    *out++ = static_cast<std::uint8_t>(value >> 8);
}

void Put32(std::uint8_t*& out, std::uint32_t value) noexcept {
    for (unsigned i = 0; i < 4; ++i)
        *out++ = static_cast<std::uint8_t>(value >> (i * 8));
}

void Put64(std::uint8_t*& out, std::uint64_t value) noexcept {
    for (unsigned i = 0; i < 8; ++i)
        *out++ = static_cast<std::uint8_t>(value >> (i * 8));
}

std::uint16_t Get16(const std::uint8_t*& in) noexcept {
    const std::uint16_t value = static_cast<std::uint16_t>(in[0]) |
        (static_cast<std::uint16_t>(in[1]) << 8);
    in += 2;
    return value;
}

std::uint32_t Get32(const std::uint8_t*& in) noexcept {
    std::uint32_t value = 0;
    for (unsigned i = 0; i < 4; ++i)
        value |= static_cast<std::uint32_t>(*in++) << (i * 8);
    return value;
}

std::uint64_t Get64(const std::uint8_t*& in) noexcept {
    std::uint64_t value = 0;
    for (unsigned i = 0; i < 8; ++i)
        value |= static_cast<std::uint64_t>(*in++) << (i * 8);
    return value;
}

std::uint32_t Crc32(const std::uint8_t* bytes,
                    std::size_t length) noexcept {
    std::uint32_t crc = 0xffffffffu;
    for (std::size_t i = 0; i < length; ++i) {
        crc ^= bytes[i];
        for (unsigned bit = 0; bit < 8; ++bit)
            crc = (crc >> 1) ^
                (0xedb88320u & (0u - (crc & 1u)));
    }
    return ~crc;
}

bool SameRuleIdentity(const UpnpOwnershipRecord& left,
                      const UpnpOwnershipRecord& right) noexcept {
    return left.gateway_fingerprint == right.gateway_fingerprint &&
        left.transport == right.transport &&
        left.external_port == right.external_port;
}

} // namespace

OwnershipDescription BuildOwnershipDescription(
    std::uint64_t owner_token, Transport transport) noexcept {
    OwnershipDescription result{};
    const char protocol = transport == Transport::Udp ? 'U' : 'T';
    const char prefix[] = {'e', 'M', 'u', 'l', 'e', protocol, '-'};
    std::copy(prefix, prefix + sizeof(prefix), result.begin());
    static const char hex[] = "0123456789ABCDEF";
    for (unsigned i = 0; i < 16; ++i) {
        const unsigned shift = (15u - i) * 4u;
        result[7 + i] = hex[(owner_token >> shift) & 0x0fu];
    }
    return result;
}

bool UpnpOwnershipRecord::IsStructurallyValid() const noexcept {
    return owner_token != 0 && gateway_fingerprint != 0 &&
        ValidTransport(transport) &&
        local_address.family == AddressFamily::IPv4 &&
        !local_address.IsUnspecified() && local_port != 0 &&
        external_port != 0 && acquired_unix_seconds != 0 &&
        generation != 0 && IsTerminatedPrintable(description) &&
        SameDescription(description,
                        BuildOwnershipDescription(owner_token, transport));
}

bool ObservedUpnpMapping::IsStructurallyValid() const noexcept {
    return ValidTransport(transport) &&
        local_address.family == AddressFamily::IPv4 &&
        !local_address.IsUnspecified() && local_port != 0 &&
        external_port != 0 && IsTerminatedPrintable(description);
}

OwnershipDecision EvaluateOwnershipForDeletion(
    const UpnpOwnershipRecord& record,
    std::uint64_t current_gateway_fingerprint,
    const ObservedUpnpMapping& observed) noexcept {
    if (!record.IsStructurallyValid())
        return OwnershipDecision::InvalidRecord;
    if (!observed.IsStructurallyValid())
        return OwnershipDecision::InvalidObservation;
    if (current_gateway_fingerprint == 0 ||
        record.gateway_fingerprint != current_gateway_fingerprint)
        return OwnershipDecision::GatewayMismatch;
    if (record.transport != observed.transport)
        return OwnershipDecision::TransportMismatch;
    if (record.external_port != observed.external_port)
        return OwnershipDecision::ExternalPortMismatch;
    if (!SameAddress(record.local_address, observed.local_address))
        return OwnershipDecision::InternalClientMismatch;
    if (record.local_port != observed.local_port)
        return OwnershipDecision::InternalPortMismatch;
    if (!SameDescription(record.description, observed.description))
        return OwnershipDecision::DescriptionMismatch;
    return OwnershipDecision::Owned;
}

bool OwnershipLedger::IsStructurallyValid() const noexcept {
    if (count > records.size())
        return false;
    for (std::uint8_t i = 0; i < count; ++i) {
        if (!records[i].IsStructurallyValid())
            return false;
        for (std::uint8_t j = 0; j < i; ++j)
            if (SameRuleIdentity(records[i], records[j]))
                return false;
    }
    return true;
}

std::size_t EncodeOwnershipLedger(const OwnershipLedger& ledger,
                                  std::uint8_t* out,
                                  std::size_t capacity) noexcept {
    if (out == nullptr || !ledger.IsStructurallyValid())
        return 0;
    const std::size_t size = kHeaderSize +
        static_cast<std::size_t>(ledger.count) * kRecordSize + kChecksumSize;
    if (capacity < size)
        return 0;

    std::uint8_t* cursor = out;
    std::copy(kMagic, kMagic + sizeof(kMagic), cursor);
    cursor += sizeof(kMagic);
    Put16(cursor, kVersion);
    Put16(cursor, kRecordSize);
    Put16(cursor, ledger.count);
    Put16(cursor, 0);

    for (std::uint8_t i = 0; i < ledger.count; ++i) {
        const UpnpOwnershipRecord& record = ledger.records[i];
        Put64(cursor, record.owner_token);
        Put64(cursor, record.gateway_fingerprint);
        *cursor++ = static_cast<std::uint8_t>(record.transport);
        *cursor++ = static_cast<std::uint8_t>(record.local_address.family);
        Put16(cursor, 0);
        std::copy(record.local_address.bytes.begin(),
                  record.local_address.bytes.end(), cursor);
        cursor += record.local_address.bytes.size();
        Put16(cursor, record.local_port);
        Put16(cursor, record.external_port);
        Put32(cursor, record.lifetime_seconds);
        Put64(cursor, record.acquired_unix_seconds);
        Put64(cursor, record.generation);
        std::copy(record.description.begin(), record.description.end(), cursor);
        cursor += record.description.size();
    }

    Put32(cursor, Crc32(out, size - kChecksumSize));
    return size;
}

OwnershipLedgerDecodeStatus DecodeOwnershipLedger(
    const std::uint8_t* bytes, std::size_t length,
    OwnershipLedger& ledger) noexcept {
    ledger = OwnershipLedger{};
    if (bytes == nullptr || length < kHeaderSize + kChecksumSize)
        return OwnershipLedgerDecodeStatus::Truncated;
    if (!std::equal(kMagic, kMagic + sizeof(kMagic), bytes))
        return OwnershipLedgerDecodeStatus::BadMagic;

    const std::uint8_t* cursor = bytes + sizeof(kMagic);
    if (Get16(cursor) != kVersion)
        return OwnershipLedgerDecodeStatus::UnsupportedVersion;
    if (Get16(cursor) != kRecordSize)
        return OwnershipLedgerDecodeStatus::BadRecordSize;
    const std::uint16_t count = Get16(cursor);
    const std::uint16_t reserved = Get16(cursor);
    if (count > kMaxOwnershipRecords)
        return OwnershipLedgerDecodeStatus::TooManyRecords;
    const std::size_t expected = kHeaderSize +
        static_cast<std::size_t>(count) * kRecordSize + kChecksumSize;
    if (length != expected || reserved != 0)
        return OwnershipLedgerDecodeStatus::BadLength;

    const std::uint8_t* checksum_cursor = bytes + length - kChecksumSize;
    const std::uint8_t* checksum_reader = checksum_cursor;
    const std::uint32_t stored_checksum = Get32(checksum_reader);
    if (stored_checksum != Crc32(bytes, length - kChecksumSize))
        return OwnershipLedgerDecodeStatus::BadChecksum;

    ledger.count = static_cast<std::uint8_t>(count);
    for (std::uint8_t i = 0; i < ledger.count; ++i) {
        UpnpOwnershipRecord& record = ledger.records[i];
        record.owner_token = Get64(cursor);
        record.gateway_fingerprint = Get64(cursor);
        record.transport = static_cast<Transport>(*cursor++);
        record.local_address.family = static_cast<AddressFamily>(*cursor++);
        if (Get16(cursor) != 0) {
            ledger = OwnershipLedger{};
            return OwnershipLedgerDecodeStatus::InvalidRecord;
        }
        std::copy(cursor, cursor + record.local_address.bytes.size(),
                  record.local_address.bytes.begin());
        cursor += record.local_address.bytes.size();
        record.local_port = Get16(cursor);
        record.external_port = Get16(cursor);
        record.lifetime_seconds = Get32(cursor);
        record.acquired_unix_seconds = Get64(cursor);
        record.generation = Get64(cursor);
        std::copy(cursor, cursor + record.description.size(),
                  record.description.begin());
        cursor += record.description.size();
    }

    if (cursor != checksum_cursor || !ledger.IsStructurallyValid()) {
        ledger = OwnershipLedger{};
        return OwnershipLedgerDecodeStatus::InvalidRecord;
    }
    return OwnershipLedgerDecodeStatus::Ok;
}

} // namespace natmap
