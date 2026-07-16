// SPDX-License-Identifier: MIT
#include "kad6/kad6_store.h"

#include "kad6/kad6_bytes.h"

#include <cstring>

namespace kad6 {
namespace {
template <std::size_t N>
bool AllZero(const std::array<Byte, N>& value) noexcept {
    Byte any = 0;
    for (Byte b : value) any = static_cast<Byte>(any | b);
    return any == 0;
}

bool SameHash(const Hash16& a, const Hash16& b) noexcept {
    return std::memcmp(a.data(), b.data(), a.size()) == 0;
}
}

Kad6Status EncodeK6StoreSourceRequest(const K6StoreSourceRequest& message,
                                      std::vector<Byte>& out) {
    out.clear();
    if (AllZero(message.target_hash) ||
        !SameHash(message.target_hash, message.record.object_hash))
        return Kad6Status::BadValue;
    std::vector<Byte> header, record;
    Kad6Status status = EncodeK6RouteHeader(message.header, header);
    if (status != Kad6Status::Ok) return status;
    status = EncodeK6SourceRecord(message.record, record);
    if (status != Kad6Status::Ok) return status;
    if (record.size() > 0xffffu ||
        header.size() + 16u + 2u + record.size() > kK6StoreMaxPayloadSize)
        return Kad6Status::TooLarge;
    out = std::move(header);
    ByteWriter writer(out);
    writer.bytes(message.target_hash.data(), message.target_hash.size());
    writer.u16le(static_cast<std::uint16_t>(record.size()));
    writer.bytes(record.data(), record.size());
    return Kad6Status::Ok;
}

Kad6Status DecodeK6StoreSourceRequest(const Byte* in, std::size_t len,
                                      K6StoreSourceRequest& message) noexcept {
    message = K6StoreSourceRequest{};
    if (!in && len != 0) return Kad6Status::NullArgument;
    if (len > kK6StoreMaxPayloadSize) return Kad6Status::TooLarge;
    std::size_t headerSize = 0;
    K6StoreSourceRequest candidate;
    Kad6Status status = DecodeK6RouteHeader(in, len, candidate.header, &headerSize);
    if (status != Kad6Status::Ok) return status;
    ByteReader reader(in + headerSize, len - headerSize);
    reader.bytes(candidate.target_hash.data(), candidate.target_hash.size());
    const std::uint16_t recordLength = reader.u16le();
    if (!reader.ok()) return Kad6Status::Truncated;
    const Byte* record = reader.take(recordLength);
    if (!reader.ok()) return Kad6Status::Truncated;
    if (reader.remaining() != 0) return Kad6Status::Malformed;
    std::size_t consumed = 0;
    status = DecodeK6SourceRecord(record, recordLength, candidate.record, &consumed);
    if (status != Kad6Status::Ok) return status;
    if (consumed != recordLength || AllZero(candidate.target_hash) ||
        !SameHash(candidate.target_hash, candidate.record.object_hash))
        return Kad6Status::Malformed;
    message = std::move(candidate);
    return Kad6Status::Ok;
}

Kad6Status EncodeK6StoreSourceResponse(const K6StoreSourceResponse& message,
                                       std::vector<Byte>& out) {
    out.clear();
    if (AllZero(message.target_hash) || message.reserved != 0 ||
        static_cast<Byte>(message.status) > static_cast<Byte>(K6StoreStatus::Overloaded) ||
        message.load > 100 ||
        (message.status == K6StoreStatus::Stored && message.accepted_epoch == 0))
        return Kad6Status::BadValue;
    std::vector<Byte> header;
    Kad6Status status = EncodeK6RouteHeader(message.header, header);
    if (status != Kad6Status::Ok) return status;
    if (header.size() + 28u > kK6StoreMaxPayloadSize)
        return Kad6Status::TooLarge;
    out = std::move(header);
    ByteWriter writer(out);
    writer.bytes(message.target_hash.data(), message.target_hash.size());
    writer.u8(static_cast<Byte>(message.status));
    writer.u8(message.load);
    writer.u16le(message.reserved);
    writer.u64le(message.accepted_epoch);
    return Kad6Status::Ok;
}

Kad6Status DecodeK6StoreSourceResponse(const Byte* in, std::size_t len,
                                       K6StoreSourceResponse& message) noexcept {
    message = K6StoreSourceResponse{};
    if (!in && len != 0) return Kad6Status::NullArgument;
    if (len > kK6StoreMaxPayloadSize) return Kad6Status::TooLarge;
    std::size_t headerSize = 0;
    K6StoreSourceResponse candidate;
    Kad6Status status = DecodeK6RouteHeader(in, len, candidate.header, &headerSize);
    if (status != Kad6Status::Ok) return status;
    ByteReader reader(in + headerSize, len - headerSize);
    reader.bytes(candidate.target_hash.data(), candidate.target_hash.size());
    candidate.status = static_cast<K6StoreStatus>(reader.u8());
    candidate.load = reader.u8();
    candidate.reserved = reader.u16le();
    candidate.accepted_epoch = reader.u64le();
    if (!reader.ok()) return Kad6Status::Truncated;
    if (reader.remaining() != 0 || AllZero(candidate.target_hash) ||
        candidate.reserved != 0 || candidate.load > 100 ||
        static_cast<Byte>(candidate.status) > static_cast<Byte>(K6StoreStatus::Overloaded) ||
        (candidate.status == K6StoreStatus::Stored && candidate.accepted_epoch == 0))
        return Kad6Status::Malformed;
    message = std::move(candidate);
    return Kad6Status::Ok;
}

Kad6Status EncodeK6FindSourceRequest(const K6FindSourceRequest& message,
                                     std::vector<Byte>& out) {
    out.clear();
    if (AllZero(message.target_hash) || message.max_records == 0 ||
        message.max_records > kK6FindSourceMaxRecords)
        return Kad6Status::BadValue;
    std::vector<Byte> header;
    Kad6Status status = EncodeK6RouteHeader(message.header, header);
    if (status != Kad6Status::Ok) return status;
    out = std::move(header);
    ByteWriter writer(out);
    writer.bytes(message.target_hash.data(), message.target_hash.size());
    writer.u8(message.max_records);
    writer.u8(0); writer.u8(0); writer.u8(0);
    return out.size() <= kK6StoreMaxPayloadSize
        ? Kad6Status::Ok : Kad6Status::TooLarge;
}

Kad6Status DecodeK6FindSourceRequest(const Byte* in, std::size_t len,
                                     K6FindSourceRequest& message) noexcept {
    message = K6FindSourceRequest{};
    if (!in && len != 0) return Kad6Status::NullArgument;
    if (len > kK6StoreMaxPayloadSize) return Kad6Status::TooLarge;
    std::size_t headerSize = 0;
    K6FindSourceRequest candidate;
    Kad6Status status = DecodeK6RouteHeader(in, len, candidate.header, &headerSize);
    if (status != Kad6Status::Ok) return status;
    ByteReader reader(in + headerSize, len - headerSize);
    reader.bytes(candidate.target_hash.data(), candidate.target_hash.size());
    candidate.max_records = reader.u8();
    const Byte r0 = reader.u8(), r1 = reader.u8(), r2 = reader.u8();
    if (!reader.ok()) return Kad6Status::Truncated;
    if (reader.remaining() != 0 || AllZero(candidate.target_hash) ||
        candidate.max_records == 0 || candidate.max_records > kK6FindSourceMaxRecords ||
        r0 != 0 || r1 != 0 || r2 != 0)
        return Kad6Status::Malformed;
    message = std::move(candidate);
    return Kad6Status::Ok;
}

Kad6Status EncodeK6FindSourceResponse(const K6FindSourceResponse& message,
                                      std::vector<Byte>& out) {
    out.clear();
    if (AllZero(message.target_hash) ||
        message.records.size() > kK6FindSourceMaxRecords)
        return Kad6Status::BadValue;
    std::vector<Byte> header;
    Kad6Status status = EncodeK6RouteHeader(message.header, header);
    if (status != Kad6Status::Ok) return status;
    out = std::move(header);
    ByteWriter writer(out);
    writer.bytes(message.target_hash.data(), message.target_hash.size());
    writer.u8(static_cast<Byte>(message.records.size()));
    writer.u8(0); writer.u8(0); writer.u8(0);
    for (const K6SourceRecord& record : message.records) {
        if (!SameHash(message.target_hash, record.object_hash)) {
            out.clear(); return Kad6Status::BadValue;
        }
        std::vector<Byte> encoded;
        status = EncodeK6SourceRecord(record, encoded);
        if (status != Kad6Status::Ok) { out.clear(); return status; }
        if (encoded.size() > 0xffffu || out.size() + 2u + encoded.size() >
                kK6StoreMaxPayloadSize) {
            out.clear(); return Kad6Status::TooLarge;
        }
        writer.u16le(static_cast<std::uint16_t>(encoded.size()));
        writer.bytes(encoded.data(), encoded.size());
    }
    return Kad6Status::Ok;
}

Kad6Status DecodeK6FindSourceResponse(const Byte* in, std::size_t len,
                                      K6FindSourceResponse& message) noexcept {
    message = K6FindSourceResponse{};
    if (!in && len != 0) return Kad6Status::NullArgument;
    if (len > kK6StoreMaxPayloadSize) return Kad6Status::TooLarge;
    std::size_t headerSize = 0;
    K6FindSourceResponse candidate;
    Kad6Status status = DecodeK6RouteHeader(in, len, candidate.header, &headerSize);
    if (status != Kad6Status::Ok) return status;
    ByteReader reader(in + headerSize, len - headerSize);
    reader.bytes(candidate.target_hash.data(), candidate.target_hash.size());
    const Byte count = reader.u8();
    const Byte r0 = reader.u8(), r1 = reader.u8(), r2 = reader.u8();
    if (!reader.ok()) return Kad6Status::Truncated;
    if (AllZero(candidate.target_hash) || count > kK6FindSourceMaxRecords ||
        r0 != 0 || r1 != 0 || r2 != 0)
        return Kad6Status::Malformed;
    candidate.records.reserve(count);
    for (Byte i = 0; i < count; ++i) {
        const std::uint16_t recordLength = reader.u16le();
        if (!reader.ok()) return Kad6Status::Truncated;
        const Byte* recordWire = reader.take(recordLength);
        if (!reader.ok()) return Kad6Status::Truncated;
        K6SourceRecord record;
        std::size_t consumed = 0;
        status = DecodeK6SourceRecord(recordWire, recordLength, record, &consumed);
        if (status != Kad6Status::Ok) return status;
        if (consumed != recordLength || !SameHash(candidate.target_hash,
                record.object_hash))
            return Kad6Status::Malformed;
        candidate.records.push_back(std::move(record));
    }
    if (reader.remaining() != 0) return Kad6Status::Malformed;
    message = std::move(candidate);
    return Kad6Status::Ok;
}

} // namespace kad6
