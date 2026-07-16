// SPDX-License-Identifier: MIT
#include "kad6/kad6_asn.h"

#include <cstdio>
#include <cstring>
#include <vector>

using namespace kad6;

static int g_pass = 0;
static int g_fail = 0;
#define CHECK(c, m) do { if (c) ++g_pass; else { ++g_fail; \
    std::printf("  FAIL: %s (%s:%d)\n", m, __FILE__, __LINE__); } } while (0)

static K6AsnPrefix Prefix(Byte second, Byte length, std::uint32_t asn,
                          std::uint32_t operatorGroup = 0) {
    K6AsnPrefix result;
    result.prefix.family = Kad6Address::Family::IPv6;
    result.prefix.addr = {0x20, second, 0, 0, 0, 0, 0, 0,
                          0, 0, 0, 0, 0, 0, 0, 0};
    result.prefix_length = length;
    result.asn = asn;
    result.operator_group = operatorGroup;
    return result;
}

static K6AsnPrefix Prefix4(Byte first, Byte length, std::uint32_t asn,
                           std::uint32_t operatorGroup = 0) {
    K6AsnPrefix result;
    result.prefix.family = Kad6Address::Family::IPv4;
    result.prefix.addr = {first, 0, 0, 0};
    result.prefix_length = length;
    result.asn = asn;
    result.operator_group = operatorGroup;
    return result;
}

int main() {
    std::vector<K6AsnPrefix> entries;
    entries.push_back(Prefix(0x00, 12, 64500, 10));
    entries.push_back(Prefix(0x01, 32, 64501, 11));
    entries.back().prefix.addr[2] = 0x0d;
    entries.back().prefix.addr[3] = 0xb8;
    entries.push_back(Prefix4(198, 24, 64502, 12));
    entries.back().prefix.addr[1] = 51;
    entries.back().prefix.addr[2] = 100;

    std::vector<Byte> wire;
    CHECK(EncodeK6AsnSnapshot(7, entries, wire) == Kad6Status::Ok,
          "ASN snapshot encodes");
    CHECK(wire.size() == kK6AsnSnapshotHeaderSize +
                         entries.size() * kK6AsnSnapshotEntrySize,
          "ASN snapshot exact size");
    CHECK(wire[0] == 'K' && wire[1] == '6' && wire[2] == 'A' && wire[3] == 'S',
          "ASN snapshot magic");

    std::uint64_t sequence = 0;
    std::vector<K6AsnPrefix> decoded;
    CHECK(DecodeK6AsnSnapshot(wire.data(), wire.size(), sequence, decoded) ==
              Kad6Status::Ok,
          "ASN snapshot decodes");
    CHECK(sequence == 7 && decoded.size() == 3 &&
              decoded[1].asn == 64501 && decoded[1].operator_group == 11 &&
              decoded[2].prefix.family == Kad6Address::Family::IPv4,
          "ASN snapshot round trip");

    K6AsnDatabase db;
    CHECK(db.LoadEntries(sequence, decoded) == Kad6Status::Ok,
          "ASN trie loads atomically");
    CHECK(db.sequence() == 7 && db.entry_count() == 3,
          "ASN trie metadata");
    Kad6Address address;
    address.family = Kad6Address::Family::IPv6;
    address.addr = {0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 1};
    K6AsnInfo info;
    CHECK(db.Lookup(address, info) && info.asn == 64501 &&
              info.operator_group == 11 && info.matched_prefix_length == 32,
          "longest prefix wins");
    address.addr[2] = 0x12;
    CHECK(db.Lookup(address, info) && info.asn == 64500 &&
              info.matched_prefix_length == 12,
          "less-specific fallback");
    address.addr[0] = 0x30;
    CHECK(!db.Lookup(address, info), "unknown address remains unknown");
    Kad6Address address4; address4.family = Kad6Address::Family::IPv4;
    address4.addr = {198, 51, 100, 77};
    CHECK(db.Lookup(address4, info) && info.asn == 64502 &&
              info.operator_group == 12 && info.matched_prefix_length == 24,
          "IPv4 longest-prefix lookup is family separated");
    address4.addr = {203, 0, 113, 1};
    CHECK(!db.Lookup(address4, info), "unknown IPv4 remains unknown");

    std::vector<K6AsnPrefix> duplicate = entries;
    duplicate.push_back(entries[0]);
    CHECK(EncodeK6AsnSnapshot(8, duplicate, wire) == Kad6Status::BadValue &&
              wire.empty(),
          "duplicate prefix rejected by producer");
    CHECK(db.LoadEntries(8, duplicate) == Kad6Status::BadValue &&
              db.sequence() == 7 && db.entry_count() == 3,
          "failed trie load leaves prior DB intact");

    K6AsnPrefix nonCanonical = Prefix(0x01, 17, 64510);
    nonCanonical.prefix.addr[2] = 1;
    CHECK(EncodeK6AsnSnapshot(8, {nonCanonical}, wire) == Kad6Status::BadValue,
          "host bits outside prefix rejected");
    CHECK(EncodeK6AsnSnapshot(0, entries, wire) == Kad6Status::BadValue,
          "zero sequence rejected");

    CHECK(EncodeK6AsnSnapshot(7, entries, wire) == Kad6Status::Ok,
          "valid ASN wire restored");
    std::vector<Byte> trailing = wire;
    trailing.push_back(0);
    CHECK(DecodeK6AsnSnapshot(trailing.data(), trailing.size(), sequence,
                              decoded) == Kad6Status::Malformed,
          "trailing bytes rejected");
    std::vector<Byte> bad = wire;
    bad[0] = 'X';
    CHECK(DecodeK6AsnSnapshot(bad.data(), bad.size(), sequence, decoded) ==
              Kad6Status::Malformed,
          "bad magic rejected");
    bad = wire;
    bad[4] = 3;
    CHECK(DecodeK6AsnSnapshot(bad.data(), bad.size(), sequence, decoded) ==
              Kad6Status::UnsupportedVersion,
          "unknown ASN version rejected");
    std::vector<K6AsnPrefix> legacyEntries(entries.begin(), entries.begin() + 2);
    CHECK(EncodeK6AsnSnapshot(6, legacyEntries, bad) == Kad6Status::Ok,
          "legacy fixture encoded as v2");
    bad[4] = static_cast<Byte>(kK6AsnSnapshotLegacyVersion);
    bad[5] = 0;
    for (std::size_t i = 0; i < legacyEntries.size(); ++i)
        bad[kK6AsnSnapshotHeaderSize + i * kK6AsnSnapshotEntrySize + 17] = 0;
    CHECK(DecodeK6AsnSnapshot(bad.data(), bad.size(), sequence, decoded) ==
              Kad6Status::Ok && decoded.size() == 2 &&
              decoded[0].prefix.family == Kad6Address::Family::IPv6,
          "v1 IPv6 ASN snapshots remain readable");
    CHECK(DecodeK6AsnSnapshot(nullptr, 1, sequence, decoded) ==
              Kad6Status::NullArgument,
          "ASN null input rejected");
    for (std::size_t cut = 0; cut < wire.size(); ++cut) {
        CHECK(DecodeK6AsnSnapshot(wire.data(), cut, sequence, decoded) !=
                  Kad6Status::Ok,
              "every truncated ASN prefix rejected");
    }

    std::uint32_t state = 0x4b364153u;
    for (int iteration = 0; iteration < 4096; ++iteration) {
        state = state * 1664525u + 1013904223u;
        const std::size_t size = state % 2048;
        std::vector<Byte> input(size);
        for (Byte& value : input) {
            state = state * 1664525u + 1013904223u;
            value = static_cast<Byte>(state >> 24);
        }
        const Kad6Status status = DecodeK6AsnSnapshot(
            input.empty() ? nullptr : input.data(), input.size(), sequence,
            decoded);
        CHECK(status != Kad6Status::Ok || decoded.size() <= kK6AsnMaxEntries,
              "bounded random ASN decode");
    }

    std::printf("test_kad6_asn: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
