// SPDX-License-Identifier: MIT
#include "kad6/kad6_bootstrap.h"

#include "kad6/kad6_bytes.h"

#include <algorithm>
#include <cstring>
#include <limits>

namespace kad6 {
namespace {

const Byte kMagic[8] = {'K', '6', 'B', 'O', 'O', 'T', '1', 0};
const char kDomain[] = "eSE-Kad6-BootstrapBundle-v1";

bool IsZero(const Byte* value, std::size_t size) noexcept {
    Byte accum = 0;
    for (std::size_t i = 0; i < size; ++i)
        accum = static_cast<Byte>(accum | value[i]);
    return accum == 0;
}

bool NativeKad6Endpoint(const K6Endpoint& endpoint) noexcept {
    if (endpoint.addr.family != Kad6Address::Family::IPv6 ||
        endpoint.udp_port == 0 ||
        (endpoint.transport_flags & kK6EpUdpKad6) == 0 ||
        (endpoint.transport_flags & kK6EpReservedMask) != 0 ||
        endpoint.observed > 1)
        return false;
    Kad6Address normalized = endpoint.addr;
    Kad6AddressNormalize(normalized);
    return normalized.family == Kad6Address::Family::IPv6;
}

Kad6Status ValidateBundleScalars(const K6BootstrapBundle& bundle) noexcept {
    if (bundle.version != kK6BootstrapBundleVersion)
        return Kad6Status::UnsupportedVersion;
    if (bundle.flags != 0 || bundle.sequence == 0 || bundle.valid_from == 0 ||
        bundle.valid_until <= bundle.valid_from)
        return Kad6Status::BadValue;
    if (bundle.records.size() < kK6BootstrapMinEntries ||
        bundle.records.size() > kK6BootstrapMaxEntries)
        return Kad6Status::BadValue;
    return Kad6Status::Ok;
}

Kad6Status BuildEntries(const K6BootstrapBundle& bundle,
                        std::vector<Byte>& entries) {
    entries.clear();
    for (std::size_t i = 0; i < bundle.records.size(); ++i) {
        const K6RouterRecord& record = bundle.records[i];
        for (std::size_t j = 0; j < i; ++j) {
            if (bundle.records[j].kad_id == record.kad_id ||
                bundle.records[j].node_pub == record.node_pub)
                return Kad6Status::BadValue;
        }
        std::vector<Byte> encoded;
        const Kad6Status status = EncodeK6RouterRecord(record, encoded);
        if (status != Kad6Status::Ok)
            return status;
        if (encoded.size() < kK6RouterRecordMinSize ||
            encoded.size() > kK6RouterRecordMaxSize ||
            encoded.size() > std::numeric_limits<std::uint16_t>::max())
            return Kad6Status::TooLarge;
        if (entries.size() > kK6BootstrapMaxEntriesBytes - 2 - encoded.size())
            return Kad6Status::TooLarge;
        ByteWriter writer(entries);
        writer.u16le(static_cast<std::uint16_t>(encoded.size()));
        writer.bytes(encoded.data(), encoded.size());
    }
    return Kad6Status::Ok;
}

void BuildPrefix(const K6BootstrapBundle& bundle,
                 const std::vector<Byte>& entries,
                 std::vector<Byte>& prefix) {
    prefix.clear();
    prefix.reserve(kK6BootstrapHeaderSize + entries.size());
    ByteWriter writer(prefix);
    writer.bytes(kMagic, sizeof kMagic);
    writer.u16le(bundle.version);
    writer.u16le(bundle.flags);
    writer.u64le(bundle.sequence);
    writer.u64le(bundle.valid_from);
    writer.u64le(bundle.valid_until);
    writer.u16le(static_cast<std::uint16_t>(bundle.records.size()));
    writer.u16le(0);
    writer.u32le(static_cast<std::uint32_t>(entries.size()));
    writer.bytes(entries.data(), entries.size());
}

void BuildSignatureMessage(const Hash32& hash, std::vector<Byte>& message) {
    const Byte* domain = reinterpret_cast<const Byte*>(kDomain);
    message.assign(domain, domain + sizeof(kDomain) - 1);
    message.insert(message.end(), hash.begin(), hash.end());
}

Kad6Status PrescanEntries(const Byte* entries, std::size_t entriesLength,
                          std::uint16_t count) noexcept {
    ByteReader reader(entries, entriesLength);
    for (std::uint16_t i = 0; i < count; ++i) {
        const std::uint16_t recordLength = reader.u16le();
        if (!reader.ok())
            return Kad6Status::Truncated;
        if (recordLength < kK6RouterRecordMinSize ||
            recordLength > kK6RouterRecordMaxSize)
            return Kad6Status::Malformed;
        if (reader.take(recordLength) == nullptr)
            return Kad6Status::Truncated;
    }
    return reader.remaining() == 0 ? Kad6Status::Ok : Kad6Status::Malformed;
}

} // namespace

Kad6Status SignK6BootstrapBundle(const Kad6CryptoHooks& hooks,
                                 const Ed25519Pub& distributionPub,
                                 const Byte* distributionSecret,
                                 std::size_t distributionSecretLen,
                                 K6BootstrapBundle& bundle,
                                 std::vector<Byte>& out) {
    out.clear();
    if (!hooks.sha256 || !hooks.ed25519_sign ||
        IsZero(distributionPub.data(), distributionPub.size()))
        return Kad6Status::BadValue;
    const Kad6Status scalars = ValidateBundleScalars(bundle);
    if (scalars != Kad6Status::Ok)
        return scalars;
    std::vector<Byte> entries;
    Kad6Status status = BuildEntries(bundle, entries);
    if (status != Kad6Status::Ok)
        return status;
    std::vector<Byte> prefix;
    BuildPrefix(bundle, entries, prefix);
    if (!hooks.sha256(prefix.data(), prefix.size(), bundle.bundle_hash.data()) ||
        !hooks.sha256(distributionPub.data(), distributionPub.size(),
                      bundle.signer_key_id.data()))
        return Kad6Status::AuthFailed;
    std::vector<Byte> message;
    BuildSignatureMessage(bundle.bundle_hash, message);
    if (!hooks.ed25519_sign(distributionSecret, distributionSecretLen,
                            message.data(), message.size(),
                            bundle.signature.data()))
        return Kad6Status::AuthFailed;

    out = prefix;
    ByteWriter writer(out);
    writer.bytes(bundle.bundle_hash.data(), bundle.bundle_hash.size());
    writer.bytes(bundle.signer_key_id.data(), bundle.signer_key_id.size());
    writer.bytes(bundle.signature.data(), bundle.signature.size());
    return Kad6Status::Ok;
}

Kad6Status VerifyAndDecodeK6BootstrapBundle(
    const Kad6CryptoHooks& hooks,
    const Ed25519Pub& pinnedDistributionPub,
    const Byte* in, std::size_t len,
    std::uint64_t lastSequence,
    std::uint64_t nowUnix,
    K6BootstrapBundle& out) noexcept {
    out = K6BootstrapBundle{};
    if (in == nullptr && len != 0)
        return Kad6Status::NullArgument;
    if (!hooks.sha256 || !hooks.ed25519_verify ||
        IsZero(pinnedDistributionPub.data(), pinnedDistributionPub.size()) ||
        nowUnix == 0)
        return Kad6Status::BadValue;
    if (len > kK6BootstrapMaxWireSize)
        return Kad6Status::TooLarge;

    ByteReader reader(in, len);
    Byte magic[8] = {};
    reader.bytes(magic, sizeof magic);
    K6BootstrapBundle candidate;
    candidate.version = reader.u16le();
    candidate.flags = reader.u16le();
    candidate.sequence = reader.u64le();
    candidate.valid_from = reader.u64le();
    candidate.valid_until = reader.u64le();
    const std::uint16_t count = reader.u16le();
    const std::uint16_t reserved = reader.u16le();
    const std::uint32_t entriesLength = reader.u32le();
    if (!reader.ok())
        return Kad6Status::Truncated;
    if (std::memcmp(magic, kMagic, sizeof magic) != 0 ||
        candidate.flags != 0 || reserved != 0 || candidate.sequence == 0 ||
        candidate.valid_from == 0 ||
        candidate.valid_until <= candidate.valid_from)
        return Kad6Status::Malformed;
    if (candidate.version != kK6BootstrapBundleVersion)
        return Kad6Status::UnsupportedVersion;
    if (count < kK6BootstrapMinEntries || count > kK6BootstrapMaxEntries)
        return Kad6Status::BadValue;
    if (entriesLength > kK6BootstrapMaxEntriesBytes)
        return Kad6Status::TooLarge;
    const std::size_t expectedTail = static_cast<std::size_t>(entriesLength) +
                                     kK6BootstrapTrailerSize;
    if (reader.remaining() != expectedTail)
        return reader.remaining() < expectedTail
            ? Kad6Status::Truncated : Kad6Status::Malformed;

    const Byte* entries = reader.take(entriesLength);
    if (entries == nullptr)
        return Kad6Status::Truncated;
    Kad6Status status = PrescanEntries(entries, entriesLength, count);
    if (status != Kad6Status::Ok)
        return status;
    reader.bytes(candidate.bundle_hash.data(), candidate.bundle_hash.size());
    reader.bytes(candidate.signer_key_id.data(), candidate.signer_key_id.size());
    reader.bytes(candidate.signature.data(), candidate.signature.size());
    if (!reader.ok() || reader.remaining() != 0)
        return Kad6Status::Truncated;

    Hash32 computedHash{};
    const std::size_t prefixLength = kK6BootstrapHeaderSize + entriesLength;
    if (!hooks.sha256(in, prefixLength, computedHash.data()))
        return Kad6Status::AuthFailed;
    Hash32 expectedKeyId{};
    if (!hooks.sha256(pinnedDistributionPub.data(),
                      pinnedDistributionPub.size(), expectedKeyId.data()))
        return Kad6Status::AuthFailed;
    if (!Kad6CtEqual(computedHash.data(), candidate.bundle_hash.data(),
                     computedHash.size()) ||
        !Kad6CtEqual(expectedKeyId.data(), candidate.signer_key_id.data(),
                     expectedKeyId.size()))
        return Kad6Status::AuthFailed;
    std::vector<Byte> message;
    BuildSignatureMessage(candidate.bundle_hash, message);
    if (!hooks.ed25519_verify(pinnedDistributionPub.data(), message.data(),
                              message.size(), candidate.signature.data()))
        return Kad6Status::AuthFailed;

    if (candidate.sequence <= lastSequence)
        return Kad6Status::StaleEpoch;
    if (nowUnix < candidate.valid_from)
        return Kad6Status::BadValue;
    if (nowUnix >= candidate.valid_until)
        return Kad6Status::Expired;

    ByteReader entryReader(entries, entriesLength);
    candidate.records.reserve(count);
    for (std::uint16_t i = 0; i < count; ++i) {
        const std::uint16_t recordLength = entryReader.u16le();
        const Byte* recordBytes = entryReader.take(recordLength);
        if (!entryReader.ok() || recordBytes == nullptr)
            return Kad6Status::Truncated;
        K6RouterRecord record;
        std::size_t consumed = 0;
        status = DecodeK6RouterRecord(recordBytes, recordLength, record,
                                      &consumed);
        if (status != Kad6Status::Ok || consumed != recordLength)
            return status == Kad6Status::Ok ? Kad6Status::Malformed : status;
        status = VerifyK6RouterRecord(hooks, record);
        if (status != Kad6Status::Ok)
            return status;
        status = K6RouterRecordCheckFresh(record, nowUnix);
        if (status != Kad6Status::Ok)
            return status;
        bool native = false;
        for (const K6Endpoint& endpoint : record.endpoints)
            native = native || NativeKad6Endpoint(endpoint);
        if (!native)
            return Kad6Status::BadValue;
        for (const K6RouterRecord& previous : candidate.records) {
            if (previous.kad_id == record.kad_id ||
                previous.node_pub == record.node_pub)
                return Kad6Status::Malformed;
        }
        candidate.records.push_back(record);
    }
    out = candidate;
    return Kad6Status::Ok;
}

} // namespace kad6
