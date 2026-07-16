// SPDX-License-Identifier: MIT
#include "kad6/kad6_routing.h"

#include "kad6/kad6_bytes.h"

#include <algorithm>
#include <cstring>

namespace kad6 {
namespace {

bool IsZeroId(const KadId& id) noexcept {
    Byte accum = 0;
    for (Byte b : id)
        accum = static_cast<Byte>(accum | b);
    return accum == 0;
}

bool IsZeroPub(const Ed25519Pub& pub) noexcept {
    Byte accum = 0;
    for (Byte b : pub)
        accum = static_cast<Byte>(accum | b);
    return accum == 0;
}

bool IsZeroSignature(const Ed25519Sig& signature) noexcept {
    Byte accum = 0;
    for (Byte b : signature)
        accum = static_cast<Byte>(accum | b);
    return accum == 0;
}

bool SameId(const KadId& a, const KadId& b) noexcept {
    return std::memcmp(a.data(), b.data(), a.size()) == 0;
}

bool SameEndpoint(const K6Endpoint& a, const K6Endpoint& b) noexcept {
    return a.addr == b.addr && a.tcp_port == b.tcp_port &&
           a.udp_port == b.udp_port &&
           a.transport_flags == b.transport_flags &&
           a.priority == b.priority && a.observed == b.observed &&
           a.valid_until == b.valid_until;
}

bool IsRouteEndpoint(const K6Endpoint& endpoint) noexcept {
    if (endpoint.addr.family != Kad6Address::Family::IPv6)
        return false;
    Kad6Address normalized = endpoint.addr;
    Kad6AddressNormalize(normalized);
    if (normalized.family != Kad6Address::Family::IPv6) // reject v4-mapped IPv6
        return false;
    if (endpoint.udp_port == 0)
        return false;
    if ((endpoint.transport_flags & kK6EpUdpKad6) == 0)
        return false;
    if ((endpoint.transport_flags & kK6EpReservedMask) != 0)
        return false;
    return endpoint.observed <= 1;
}

Kad6Status ValidateRecordCoherence(const K6RouteHeader& header) noexcept {
    if (header.version == kK6RouteLegacyWireVersion)
        return Kad6Status::Ok;
    if (header.version != kK6RouteWireVersion)
        return Kad6Status::UnsupportedVersion;
    if (!SameId(header.sender_record.kad_id, header.sender_id) ||
        header.sender_record.epoch != header.sender_epoch ||
        header.sender_record.caps != header.sender_caps)
        return Kad6Status::BadValue;
    bool found = false;
    for (const K6Endpoint& endpoint : header.sender_record.endpoints) {
        if (!IsRouteEndpoint(endpoint))
            return Kad6Status::BadValue;
        if (SameEndpoint(endpoint, header.sender_endpoint))
            found = true;
    }
    return found ? Kad6Status::Ok : Kad6Status::BadValue;
}

Kad6Status ValidateHeaderForEncode(const K6RouteHeader& header) noexcept {
    if ((header.version != kK6RouteLegacyWireVersion &&
         header.version != kK6RouteWireVersion) || header.flags != 0 ||
        header.reserved != 0 || header.txid == 0 ||
        IsZeroId(header.sender_id) || header.sender_epoch == 0 ||
        !IsRouteEndpoint(header.sender_endpoint))
        return Kad6Status::BadValue;
    return ValidateRecordCoherence(header);
}

Kad6Status ValidateContactForEncode(const K6RouteContact& contact) noexcept {
    if (IsZeroId(contact.node_id) || contact.epoch == 0 ||
        !IsRouteEndpoint(contact.endpoint))
        return Kad6Status::BadValue;
    return Kad6Status::Ok;
}

Kad6Status EncodeHeader(const K6RouteHeader& header, ByteWriter& writer) {
    const Kad6Status valid = ValidateHeaderForEncode(header);
    if (valid != Kad6Status::Ok)
        return valid;

    std::vector<Byte> endpoint;
    const Kad6Status status = EncodeK6Endpoint(header.sender_endpoint, endpoint);
    if (status != Kad6Status::Ok)
        return status;

    std::vector<Byte> record;
    if (header.version == kK6RouteWireVersion) {
        const Kad6Status recordStatus =
            EncodeK6RouterRecord(header.sender_record, record);
        if (recordStatus != Kad6Status::Ok)
            return recordStatus;
        if (record.size() < kK6RouterRecordMinSize ||
            record.size() > kK6RouterRecordMaxSize)
            return Kad6Status::TooLarge;
    }

    writer.u8(header.version);
    writer.u8(header.flags);
    writer.u16le(header.reserved);
    writer.u32le(header.txid);
    writer.bytes(header.sender_id.data(), header.sender_id.size());
    writer.u64le(header.sender_caps);
    writer.u64le(header.sender_epoch);
    writer.bytes(endpoint.data(), endpoint.size());
    if (header.version == kK6RouteWireVersion) {
        writer.u16le(static_cast<std::uint16_t>(record.size()));
        writer.bytes(record.data(), record.size());
    }
    return Kad6Status::Ok;
}

Kad6Status EncodeContact(const K6RouteContact& contact, ByteWriter& writer) {
    const Kad6Status valid = ValidateContactForEncode(contact);
    if (valid != Kad6Status::Ok)
        return valid;

    std::vector<Byte> endpoint;
    const Kad6Status status = EncodeK6Endpoint(contact.endpoint, endpoint);
    if (status != Kad6Status::Ok)
        return status;

    writer.bytes(contact.node_id.data(), contact.node_id.size());
    writer.bytes(endpoint.data(), endpoint.size());
    writer.u64le(contact.caps);
    writer.u64le(contact.epoch);
    return Kad6Status::Ok;
}

Kad6Status DecodeEndpoint(ByteReader& reader, K6Endpoint& endpoint) noexcept {
    if (!reader.need(2))
        return Kad6Status::Truncated;
    const Byte* start = reader.take(0);
    std::size_t consumed = 0;
    const Kad6Status status = DecodeK6Endpoint(start, reader.remaining(), endpoint,
                                               &consumed);
    if (status != Kad6Status::Ok)
        return status;
    if (!reader.take(consumed))
        return Kad6Status::Truncated;
    if (!IsRouteEndpoint(endpoint))
        return Kad6Status::Malformed;
    return Kad6Status::Ok;
}

Kad6Status DecodeHeader(ByteReader& reader, K6RouteHeader& header) noexcept {
    header = K6RouteHeader{};
    header.version = reader.u8();
    header.flags = reader.u8();
    header.reserved = reader.u16le();
    header.txid = reader.u32le();
    reader.bytes(header.sender_id.data(), header.sender_id.size());
    header.sender_caps = reader.u64le();
    header.sender_epoch = reader.u64le();
    if (!reader.ok())
        return Kad6Status::Truncated;
    if (header.version != kK6RouteLegacyWireVersion &&
        header.version != kK6RouteWireVersion)
        return Kad6Status::UnsupportedVersion;
    if (header.flags != 0 || header.reserved != 0 || header.txid == 0 ||
        IsZeroId(header.sender_id) || header.sender_epoch == 0)
        return Kad6Status::Malformed;
    Kad6Status status = DecodeEndpoint(reader, header.sender_endpoint);
    if (status != Kad6Status::Ok ||
        header.version == kK6RouteLegacyWireVersion)
        return status;

    const std::uint16_t recordLength = reader.u16le();
    if (!reader.ok())
        return Kad6Status::Truncated;
    if (recordLength < kK6RouterRecordMinSize ||
        recordLength > kK6RouterRecordMaxSize)
        return Kad6Status::Malformed;
    const Byte* recordBytes = reader.take(recordLength);
    if (recordBytes == nullptr)
        return Kad6Status::Truncated;
    std::size_t consumed = 0;
    status = DecodeK6RouterRecord(recordBytes, recordLength,
                                  header.sender_record, &consumed);
    if (status != Kad6Status::Ok)
        return status;
    if (consumed != recordLength)
        return Kad6Status::Malformed;
    status = ValidateRecordCoherence(header);
    return status == Kad6Status::Ok ? status : Kad6Status::Malformed;
}

Kad6Status DecodeContact(ByteReader& reader, K6RouteContact& contact) noexcept {
    contact = K6RouteContact{};
    reader.bytes(contact.node_id.data(), contact.node_id.size());
    if (!reader.ok())
        return Kad6Status::Truncated;
    if (IsZeroId(contact.node_id))
        return Kad6Status::Malformed;
    Kad6Status status = DecodeEndpoint(reader, contact.endpoint);
    if (status != Kad6Status::Ok)
        return status;
    contact.caps = reader.u64le();
    contact.epoch = reader.u64le();
    if (!reader.ok())
        return Kad6Status::Truncated;
    if (contact.epoch == 0)
        return Kad6Status::Malformed;
    return Kad6Status::Ok;
}

bool HasDuplicateIds(const std::vector<K6RouteContact>& contacts) noexcept {
    for (std::size_t i = 0; i < contacts.size(); ++i)
        for (std::size_t j = i + 1; j < contacts.size(); ++j)
            if (SameId(contacts[i].node_id, contacts[j].node_id))
                return true;
    return false;
}

Kad6Status EncodeContactList(const std::vector<K6RouteContact>& contacts,
                             ByteWriter& writer) {
    if (contacts.size() > kK6RouteMaxContacts)
        return Kad6Status::TooLarge;
    if (HasDuplicateIds(contacts))
        return Kad6Status::BadValue;
    writer.u8(static_cast<Byte>(contacts.size()));
    for (const K6RouteContact& contact : contacts) {
        const Kad6Status status = EncodeContact(contact, writer);
        if (status != Kad6Status::Ok)
            return status;
    }
    return Kad6Status::Ok;
}

Kad6Status DecodeContactList(ByteReader& reader,
                             std::vector<K6RouteContact>& contacts) noexcept {
    contacts.clear();
    const Byte count = reader.u8();
    if (!reader.ok())
        return Kad6Status::Truncated;
    if (count > kK6RouteMaxContacts)
        return Kad6Status::TooLarge;
    // Every v1 contact is exactly 66 bytes. Check before allocating or parsing.
    if (reader.remaining() < static_cast<std::size_t>(count) *
                             kK6RouteContactV1Size)
        return Kad6Status::Truncated;
    contacts.reserve(count);
    for (Byte i = 0; i < count; ++i) {
        K6RouteContact contact;
        const Kad6Status status = DecodeContact(reader, contact);
        if (status != Kad6Status::Ok) {
            contacts.clear();
            return status;
        }
        for (const K6RouteContact& previous : contacts) {
            if (SameId(previous.node_id, contact.node_id)) {
                contacts.clear();
                return Kad6Status::Malformed;
            }
        }
        contacts.push_back(contact);
    }
    return Kad6Status::Ok;
}

template <typename Message>
Kad6Status EncodeHeaderOnly(const Message& message, std::vector<Byte>& out) {
    out.clear();
    out.reserve(kK6RouteHeaderV2MaxSize);
    ByteWriter writer(out);
    const Kad6Status status = EncodeHeader(message.header, writer);
    if (status != Kad6Status::Ok)
        out.clear();
    return status;
}

template <typename Message>
Kad6Status DecodeHeaderOnly(const Byte* in, std::size_t len,
                            Message& out) noexcept {
    out = Message{};
    if (in == nullptr && len != 0)
        return Kad6Status::NullArgument;
    ByteReader reader(in, len);
    const Kad6Status status = DecodeHeader(reader, out.header);
    if (status != Kad6Status::Ok) {
        out = Message{};
        return status;
    }
    if (reader.remaining() != 0) {
        out = Message{};
        return Kad6Status::Malformed;
    }
    return Kad6Status::Ok;
}

} // namespace

Kad6Status EncodeK6RouteHeader(const K6RouteHeader& header,
                               std::vector<Byte>& out) {
    out.clear();
    out.reserve(kK6RouteHeaderV2MaxSize);
    ByteWriter writer(out);
    const Kad6Status status = EncodeHeader(header, writer);
    if (status != Kad6Status::Ok) out.clear();
    return status;
}

Kad6Status DecodeK6RouteHeader(const Byte* in, std::size_t len,
                               K6RouteHeader& header,
                               std::size_t* consumed) noexcept {
    header = K6RouteHeader{};
    if (consumed) *consumed = 0;
    if (in == nullptr && len != 0) return Kad6Status::NullArgument;
    ByteReader reader(in, len);
    const Kad6Status status = DecodeHeader(reader, header);
    if (status != Kad6Status::Ok) {
        header = K6RouteHeader{};
        return status;
    }
    if (consumed) *consumed = reader.pos();
    return Kad6Status::Ok;
}

Kad6Status EncodeK6BootstrapRequest(const K6BootstrapRequest& message,
                                    std::vector<Byte>& out) {
    return EncodeHeaderOnly(message, out);
}

Kad6Status EncodeK6HelloRequest(const K6HelloRequest& message,
                                std::vector<Byte>& out) {
    return EncodeHeaderOnly(message, out);
}

Kad6Status EncodeK6HelloResponse(const K6HelloResponse& message,
                                 std::vector<Byte>& out) {
    return EncodeHeaderOnly(message, out);
}

Kad6Status EncodeK6BootstrapResponse(const K6BootstrapResponse& message,
                                     std::vector<Byte>& out) {
    out.clear();
    out.reserve(kK6RouteHeaderV2MaxSize + 1 +
                message.contacts.size() * kK6RouteContactV1Size);
    ByteWriter writer(out);
    Kad6Status status = EncodeHeader(message.header, writer);
    if (status == Kad6Status::Ok)
        status = EncodeContactList(message.contacts, writer);
    if (status != Kad6Status::Ok)
        out.clear();
    return status;
}

Kad6Status EncodeK6FindNodeRequest(const K6FindNodeRequest& message,
                                   std::vector<Byte>& out) {
    out.clear();
    out.reserve(kK6RouteHeaderV2MaxSize + kKadIdSize + 4);
    ByteWriter writer(out);
    Kad6Status status = EncodeHeader(message.header, writer);
    if (status != Kad6Status::Ok) {
        out.clear();
        return status;
    }
    if (IsZeroId(message.target_id) || message.max_results == 0 ||
        message.max_results > kK6RouteMaxContacts) {
        out.clear();
        return Kad6Status::BadValue;
    }
    writer.bytes(message.target_id.data(), message.target_id.size());
    writer.u8(message.max_results);
    writer.u8(0);
    writer.u16le(0);
    return Kad6Status::Ok;
}

Kad6Status EncodeK6FindNodeResponse(const K6FindNodeResponse& message,
                                    std::vector<Byte>& out) {
    out.clear();
    out.reserve(kK6RouteMaxPayloadSize);
    ByteWriter writer(out);
    Kad6Status status = EncodeHeader(message.header, writer);
    if (status != Kad6Status::Ok || IsZeroId(message.target_id)) {
        out.clear();
        return status != Kad6Status::Ok ? status : Kad6Status::BadValue;
    }
    writer.bytes(message.target_id.data(), message.target_id.size());
    status = EncodeContactList(message.contacts, writer);
    if (status != Kad6Status::Ok)
        out.clear();
    return status;
}

Kad6Status DecodeK6BootstrapRequest(const Byte* in, std::size_t len,
                                    K6BootstrapRequest& out) noexcept {
    return DecodeHeaderOnly(in, len, out);
}

Kad6Status DecodeK6HelloRequest(const Byte* in, std::size_t len,
                                K6HelloRequest& out) noexcept {
    return DecodeHeaderOnly(in, len, out);
}

Kad6Status DecodeK6HelloResponse(const Byte* in, std::size_t len,
                                 K6HelloResponse& out) noexcept {
    return DecodeHeaderOnly(in, len, out);
}

Kad6Status DecodeK6BootstrapResponse(const Byte* in, std::size_t len,
                                     K6BootstrapResponse& out) noexcept {
    out = K6BootstrapResponse{};
    if (in == nullptr && len != 0)
        return Kad6Status::NullArgument;
    ByteReader reader(in, len);
    Kad6Status status = DecodeHeader(reader, out.header);
    if (status == Kad6Status::Ok)
        status = DecodeContactList(reader, out.contacts);
    if (status == Kad6Status::Ok && reader.remaining() != 0)
        status = Kad6Status::Malformed;
    if (status != Kad6Status::Ok)
        out = K6BootstrapResponse{};
    return status;
}

Kad6Status DecodeK6FindNodeRequest(const Byte* in, std::size_t len,
                                   K6FindNodeRequest& out) noexcept {
    out = K6FindNodeRequest{};
    if (in == nullptr && len != 0)
        return Kad6Status::NullArgument;
    ByteReader reader(in, len);
    Kad6Status status = DecodeHeader(reader, out.header);
    if (status != Kad6Status::Ok) {
        out = K6FindNodeRequest{};
        return status;
    }
    reader.bytes(out.target_id.data(), out.target_id.size());
    out.max_results = reader.u8();
    const Byte reserved8 = reader.u8();
    const std::uint16_t reserved16 = reader.u16le();
    if (!reader.ok())
        status = Kad6Status::Truncated;
    else if (IsZeroId(out.target_id) || out.max_results == 0 ||
             out.max_results > kK6RouteMaxContacts || reserved8 != 0 ||
             reserved16 != 0 || reader.remaining() != 0)
        status = Kad6Status::Malformed;
    if (status != Kad6Status::Ok)
        out = K6FindNodeRequest{};
    return status;
}

Kad6Status DecodeK6FindNodeResponse(const Byte* in, std::size_t len,
                                    K6FindNodeResponse& out) noexcept {
    out = K6FindNodeResponse{};
    if (in == nullptr && len != 0)
        return Kad6Status::NullArgument;
    ByteReader reader(in, len);
    Kad6Status status = DecodeHeader(reader, out.header);
    if (status != Kad6Status::Ok) {
        out = K6FindNodeResponse{};
        return status;
    }
    reader.bytes(out.target_id.data(), out.target_id.size());
    if (!reader.ok())
        status = Kad6Status::Truncated;
    else if (IsZeroId(out.target_id))
        status = Kad6Status::Malformed;
    else
        status = DecodeContactList(reader, out.contacts);
    if (status == Kad6Status::Ok && reader.remaining() != 0)
        status = Kad6Status::Malformed;
    if (status != Kad6Status::Ok)
        out = K6FindNodeResponse{};
    return status;
}

Kad6Status EncodeK6RouteSnapshot(
    const std::vector<K6RouteSnapshotEntry>& entries, std::vector<Byte>& out) {
    out.clear();
    if (entries.size() > kK6RouteMaxStoredContacts)
        return Kad6Status::TooLarge;
    std::vector<K6RouteContact> contacts;
    contacts.reserve(entries.size());
    for (const K6RouteSnapshotEntry& entry : entries) {
        if (entry.verified > 1 || entry.has_signed_identity > 1 ||
            entry.last_seen == 0 ||
            (entry.verified != 0 && entry.has_signed_identity == 0) ||
            (entry.has_signed_identity != 0 &&
             (IsZeroPub(entry.node_pub) || entry.signed_epoch == 0)) ||
            (entry.has_signed_identity != 0 &&
             IsZeroSignature(entry.router_signature)) ||
            (entry.has_signed_identity == 0 &&
             (entry.signed_epoch != 0 || !IsZeroPub(entry.node_pub) ||
              !IsZeroSignature(entry.router_signature))))
            return Kad6Status::BadValue;
        const Kad6Status valid = ValidateContactForEncode(entry.contact);
        if (valid != Kad6Status::Ok)
            return valid;
        contacts.push_back(entry.contact);
    }
    if (HasDuplicateIds(contacts))
        return Kad6Status::BadValue;

    out.reserve(kK6RouteSnapshotHeaderV1Size +
                entries.size() * kK6RouteSnapshotEntryV1Size);
    ByteWriter writer(out);
    static const Byte magic[4] = {'K', '6', 'N', 'D'};
    writer.bytes(magic, sizeof magic);
    writer.u8(kK6RouteSnapshotVersion);
    writer.u8(0);
    writer.u16le(0);
    writer.u16le(static_cast<std::uint16_t>(entries.size()));
    writer.u16le(0);
    for (const K6RouteSnapshotEntry& entry : entries) {
        const Kad6Status status = EncodeContact(entry.contact, writer);
        if (status != Kad6Status::Ok) {
            out.clear();
            return status;
        }
        writer.u64le(entry.last_seen);
        writer.u8(entry.verified);
        writer.u8(entry.failures);
        writer.u8(entry.has_signed_identity);
        writer.u8(0);
        writer.bytes(entry.node_pub.data(), entry.node_pub.size());
        writer.u64le(entry.signed_epoch);
        writer.bytes(entry.router_signature.data(),
                     entry.router_signature.size());
    }
    return Kad6Status::Ok;
}

Kad6Status DecodeK6RouteSnapshot(
    const Byte* in, std::size_t len,
    std::vector<K6RouteSnapshotEntry>& entries) noexcept {
    entries.clear();
    if (in == nullptr && len != 0)
        return Kad6Status::NullArgument;
    ByteReader reader(in, len);
    Byte magic[4] = {};
    reader.bytes(magic, sizeof magic);
    const Byte version = reader.u8();
    const Byte flags = reader.u8();
    const std::uint16_t reserved = reader.u16le();
    const std::uint16_t count = reader.u16le();
    const std::uint16_t reserved2 = reader.u16le();
    if (!reader.ok())
        return Kad6Status::Truncated;
    static const Byte expectedMagic[4] = {'K', '6', 'N', 'D'};
    if (std::memcmp(magic, expectedMagic, sizeof magic) != 0)
        return Kad6Status::Malformed;
    if (version != kK6RouteSnapshotLegacyVersion &&
        version != kK6RouteSnapshotVersion)
        return Kad6Status::UnsupportedVersion;
    if (flags != 0 || reserved != 0 || reserved2 != 0)
        return Kad6Status::Malformed;
    if (count > kK6RouteMaxStoredContacts)
        return Kad6Status::TooLarge;
    const std::size_t entrySize = version == kK6RouteSnapshotLegacyVersion
        ? kK6RouteSnapshotEntryV1Size : kK6RouteSnapshotEntryV2Size;
    if (reader.remaining() != static_cast<std::size_t>(count) * entrySize)
        return reader.remaining() < static_cast<std::size_t>(count) * entrySize
            ? Kad6Status::Truncated : Kad6Status::Malformed;

    entries.reserve(count);
    for (std::uint16_t i = 0; i < count; ++i) {
        K6RouteSnapshotEntry entry;
        Kad6Status status = DecodeContact(reader, entry.contact);
        if (status != Kad6Status::Ok) {
            entries.clear();
            return status;
        }
        entry.last_seen = reader.u64le();
        entry.verified = reader.u8();
        entry.failures = reader.u8();
        if (version == kK6RouteSnapshotLegacyVersion) {
            const std::uint16_t entryReserved = reader.u16le();
            if (entryReserved != 0) {
                entries.clear();
                return Kad6Status::Malformed;
            }
            // v1 verification was return-routability only. Never preserve it
            // after introducing mandatory signed router identities.
            entry.verified = 0;
        } else {
            entry.has_signed_identity = reader.u8();
            const Byte entryReserved = reader.u8();
            reader.bytes(entry.node_pub.data(), entry.node_pub.size());
            entry.signed_epoch = reader.u64le();
            reader.bytes(entry.router_signature.data(),
                         entry.router_signature.size());
            if (entryReserved != 0) {
                entries.clear();
                return Kad6Status::Malformed;
            }
        }
        if (!reader.ok()) {
            entries.clear();
            return Kad6Status::Truncated;
        }
        if (entry.last_seen == 0 || entry.verified > 1 ||
            entry.has_signed_identity > 1 ||
            (entry.verified != 0 && entry.has_signed_identity == 0) ||
            (entry.has_signed_identity != 0 &&
             (IsZeroPub(entry.node_pub) || entry.signed_epoch == 0)) ||
            (entry.has_signed_identity != 0 &&
             IsZeroSignature(entry.router_signature)) ||
            (entry.has_signed_identity == 0 &&
             (entry.signed_epoch != 0 || !IsZeroPub(entry.node_pub) ||
              !IsZeroSignature(entry.router_signature)))) {
            entries.clear();
            return Kad6Status::Malformed;
        }
        for (const K6RouteSnapshotEntry& previous : entries) {
            if (SameId(previous.contact.node_id, entry.contact.node_id)) {
                entries.clear();
                return Kad6Status::Malformed;
            }
        }
        entries.push_back(entry);
    }
    return Kad6Status::Ok;
}

} // namespace kad6
