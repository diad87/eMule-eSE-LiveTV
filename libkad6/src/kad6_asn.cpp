// SPDX-License-Identifier: MIT
#include "kad6/kad6_asn.h"

#include "kad6/kad6_bytes.h"

#include <algorithm>
#include <cstring>
#include <limits>
#include <set>

namespace kad6 {
namespace {

bool IsCanonicalPrefix(const K6AsnPrefix& entry) noexcept {
    const std::size_t addressBytes = entry.prefix.family == Kad6Address::Family::IPv4
        ? 4 : entry.prefix.family == Kad6Address::Family::IPv6 ? 16 : 0;
    const std::size_t addressBits = addressBytes * 8;
    if (addressBytes == 0 || entry.prefix_length == 0 ||
        entry.prefix_length > addressBits || entry.asn == 0)
        return false;
    const std::size_t fullBytes = entry.prefix_length / 8;
    const unsigned remainder = entry.prefix_length % 8;
    if (remainder != 0) {
        const Byte hostMask = static_cast<Byte>((1u << (8 - remainder)) - 1u);
        if ((entry.prefix.addr[fullBytes] & hostMask) != 0)
            return false;
    }
    const std::size_t firstHostByte = fullBytes + (remainder != 0 ? 1 : 0);
    for (std::size_t i = firstHostByte; i < addressBytes; ++i)
        if (entry.prefix.addr[i] != 0)
            return false;
    for (std::size_t i = addressBytes; i < entry.prefix.addr.size(); ++i)
        if (entry.prefix.addr[i] != 0)
            return false;
    return true;
}

std::array<Byte, 18> PrefixKey(const K6AsnPrefix& entry) noexcept {
    std::array<Byte, 18> key{};
    std::copy(entry.prefix.addr.begin(), entry.prefix.addr.end(), key.begin());
    key[16] = entry.prefix_length;
    key[17] = static_cast<Byte>(entry.prefix.family);
    return key;
}

unsigned AddressBit(const Kad6Address& address, std::size_t bit) noexcept {
    return (address.addr[bit / 8] >> (7 - (bit % 8))) & 1u;
}

} // namespace

Kad6Status EncodeK6AsnSnapshot(std::uint64_t sequence,
                               const std::vector<K6AsnPrefix>& entries,
                               std::vector<Byte>& out) {
    out.clear();
    if (sequence == 0)
        return Kad6Status::BadValue;
    if (entries.size() > kK6AsnMaxEntries)
        return Kad6Status::TooLarge;
    std::set<std::array<Byte, 18>> unique;
    for (const K6AsnPrefix& entry : entries) {
        if (!IsCanonicalPrefix(entry))
            return Kad6Status::BadValue;
        if (!unique.insert(PrefixKey(entry)).second)
            return Kad6Status::BadValue;
    }
    if (entries.size() >
        (std::numeric_limits<std::size_t>::max() - kK6AsnSnapshotHeaderSize) /
            kK6AsnSnapshotEntrySize)
        return Kad6Status::TooLarge;

    out.reserve(kK6AsnSnapshotHeaderSize +
                entries.size() * kK6AsnSnapshotEntrySize);
    ByteWriter writer(out);
    static const Byte magic[4] = {'K', '6', 'A', 'S'};
    writer.bytes(magic, sizeof magic);
    writer.u16le(kK6AsnSnapshotVersion);
    writer.u16le(0);
    writer.u64le(sequence);
    writer.u32le(static_cast<std::uint32_t>(entries.size()));
    writer.u32le(0);
    for (const K6AsnPrefix& entry : entries) {
        writer.bytes(entry.prefix.addr.data(), entry.prefix.addr.size());
        writer.u8(entry.prefix_length);
        writer.u8(static_cast<Byte>(entry.prefix.family));
        writer.u16le(0);
        writer.u32le(entry.asn);
        writer.u32le(entry.operator_group);
    }
    return Kad6Status::Ok;
}

Kad6Status DecodeK6AsnSnapshot(const Byte* in, std::size_t len,
                               std::uint64_t& sequence,
                               std::vector<K6AsnPrefix>& entries) noexcept {
    sequence = 0;
    entries.clear();
    if (in == nullptr && len != 0)
        return Kad6Status::NullArgument;
    ByteReader reader(in, len);
    Byte magic[4] = {};
    reader.bytes(magic, sizeof magic);
    const std::uint16_t version = reader.u16le();
    const std::uint16_t flags = reader.u16le();
    const std::uint64_t decodedSequence = reader.u64le();
    const std::uint32_t count = reader.u32le();
    const std::uint32_t reserved = reader.u32le();
    if (!reader.ok())
        return Kad6Status::Truncated;
    static const Byte expectedMagic[4] = {'K', '6', 'A', 'S'};
    if (std::memcmp(magic, expectedMagic, sizeof magic) != 0 ||
        flags != 0 || reserved != 0 || decodedSequence == 0)
        return Kad6Status::Malformed;
    if (version != kK6AsnSnapshotLegacyVersion &&
        version != kK6AsnSnapshotVersion)
        return Kad6Status::UnsupportedVersion;
    if (count > kK6AsnMaxEntries)
        return Kad6Status::TooLarge;
    const std::size_t expected = static_cast<std::size_t>(count) *
                                 kK6AsnSnapshotEntrySize;
    if (reader.remaining() != expected)
        return reader.remaining() < expected
            ? Kad6Status::Truncated : Kad6Status::Malformed;

    entries.reserve(count);
    std::set<std::array<Byte, 18>> unique;
    for (std::uint32_t i = 0; i < count; ++i) {
        K6AsnPrefix entry;
        entry.prefix.family = Kad6Address::Family::IPv6;
        reader.bytes(entry.prefix.addr.data(), entry.prefix.addr.size());
        entry.prefix_length = reader.u8();
        const Byte familyOrReserved = reader.u8();
        const std::uint16_t reserved16 = reader.u16le();
        entry.asn = reader.u32le();
        entry.operator_group = reader.u32le();
        if (!reader.ok()) {
            entries.clear();
            return Kad6Status::Truncated;
        }
        if (version == kK6AsnSnapshotVersion) {
            if (familyOrReserved == static_cast<Byte>(Kad6Address::Family::IPv4))
                entry.prefix.family = Kad6Address::Family::IPv4;
            else if (familyOrReserved == static_cast<Byte>(Kad6Address::Family::IPv6))
                entry.prefix.family = Kad6Address::Family::IPv6;
            else {
                entries.clear();
                return Kad6Status::Malformed;
            }
        } else if (familyOrReserved != 0) {
            entries.clear();
            return Kad6Status::Malformed;
        }
        if (reserved16 != 0 || !IsCanonicalPrefix(entry)) {
            entries.clear();
            return Kad6Status::Malformed;
        }
        if (!unique.insert(PrefixKey(entry)).second) {
            entries.clear();
            return Kad6Status::Malformed;
        }
        entries.push_back(entry);
    }
    sequence = decodedSequence;
    return Kad6Status::Ok;
}

K6AsnDatabase::K6AsnDatabase() {
    nodes_.push_back(Node{});
    nodes_.push_back(Node{});
}

void K6AsnDatabase::Clear() {
    nodes_.clear();
    nodes_.push_back(Node{});
    nodes_.push_back(Node{});
    sequence_ = 0;
    entry_count_ = 0;
}

Kad6Status K6AsnDatabase::LoadEntries(
    std::uint64_t sequence, const std::vector<K6AsnPrefix>& entries) {
    if (sequence == 0)
        return Kad6Status::BadValue;
    if (entries.size() > kK6AsnMaxEntries)
        return Kad6Status::TooLarge;

    std::vector<Node> candidate;
    candidate.push_back(Node{});
    candidate.push_back(Node{});
    for (const K6AsnPrefix& entry : entries) {
        if (!IsCanonicalPrefix(entry))
            return Kad6Status::BadValue;
        std::size_t nodeIndex = entry.prefix.family == Kad6Address::Family::IPv4 ? 0 : 1;
        for (std::size_t bit = 0; bit < entry.prefix_length; ++bit) {
            const unsigned branch = AddressBit(entry.prefix, bit);
            std::uint32_t next = candidate[nodeIndex].child[branch];
            if (next == 0) {
                if (candidate.size() >= kK6AsnMaxTrieNodes)
                    return Kad6Status::TooLarge;
                candidate.push_back(Node{});
                next = static_cast<std::uint32_t>(candidate.size());
                candidate[nodeIndex].child[branch] = next;
            }
            nodeIndex = static_cast<std::size_t>(next - 1);
        }
        if (candidate[nodeIndex].has_value)
            return Kad6Status::BadValue;
        candidate[nodeIndex].has_value = true;
        candidate[nodeIndex].asn = entry.asn;
        candidate[nodeIndex].operator_group = entry.operator_group;
        candidate[nodeIndex].prefix_length = entry.prefix_length;
    }

    nodes_.swap(candidate);
    sequence_ = sequence;
    entry_count_ = entries.size();
    return Kad6Status::Ok;
}

bool K6AsnDatabase::Lookup(const Kad6Address& address,
                           K6AsnInfo& out) const noexcept {
    out = K6AsnInfo{};
    if ((address.family != Kad6Address::Family::IPv4 &&
         address.family != Kad6Address::Family::IPv6) || nodes_.size() < 2)
        return false;
    std::size_t nodeIndex = address.family == Kad6Address::Family::IPv4 ? 0 : 1;
    bool found = false;
    if (nodes_[nodeIndex].has_value) {
        out.asn = nodes_[nodeIndex].asn;
        out.operator_group = nodes_[nodeIndex].operator_group;
        out.matched_prefix_length = nodes_[nodeIndex].prefix_length;
        found = true;
    }
    const std::size_t addressBits = address.family == Kad6Address::Family::IPv4 ? 32 : 128;
    for (std::size_t bit = 0; bit < addressBits; ++bit) {
        const unsigned branch = AddressBit(address, bit);
        const std::uint32_t next = nodes_[nodeIndex].child[branch];
        if (next == 0)
            break;
        nodeIndex = static_cast<std::size_t>(next - 1);
        if (nodes_[nodeIndex].has_value) {
            out.asn = nodes_[nodeIndex].asn;
            out.operator_group = nodes_[nodeIndex].operator_group;
            out.matched_prefix_length = nodes_[nodeIndex].prefix_length;
            found = true;
        }
    }
    return found;
}

} // namespace kad6
