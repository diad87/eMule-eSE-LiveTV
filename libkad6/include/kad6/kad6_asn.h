// SPDX-License-Identifier: MIT
//
// Offline, versioned IPv4/IPv6 prefix -> ASN/operator database for Kad6 routing
// diversity (ADR-08). The library performs no network lookup. Hosts load a
// local K6AS snapshot and may replace it atomically after release/update
// verification performed by their packaging layer.
#pragma once

#include "kad6/kad6_address.h"
#include "kad6/kad6_types.h"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace kad6 {

constexpr std::uint16_t kK6AsnSnapshotLegacyVersion = 1;
constexpr std::uint16_t kK6AsnSnapshotVersion = 2;
constexpr std::size_t kK6AsnSnapshotHeaderSize = 24;
constexpr std::size_t kK6AsnSnapshotEntrySize = 28;
constexpr std::size_t kK6AsnMaxEntries = 500000;
constexpr std::size_t kK6AsnMaxTrieNodes = 8000000;

struct K6AsnPrefix {
    Kad6Address prefix;          // canonical IPv4 or IPv6 network address
    Byte prefix_length = 0;      // IPv4 1..32; IPv6 1..128
    std::uint32_t asn = 0;       // non-zero
    std::uint32_t operator_group = 0; // 0 = unknown/unclassified
};

struct K6AsnInfo {
    std::uint32_t asn = 0;
    std::uint32_t operator_group = 0;
    Byte matched_prefix_length = 0;
};

Kad6Status EncodeK6AsnSnapshot(std::uint64_t sequence,
                               const std::vector<K6AsnPrefix>& entries,
                               std::vector<Byte>& out);
Kad6Status DecodeK6AsnSnapshot(const Byte* in, std::size_t len,
                               std::uint64_t& sequence,
                               std::vector<K6AsnPrefix>& entries) noexcept;

// Immutable-after-load lookup index. LoadEntries builds a temporary bounded
// binary trie and only swaps it into place on complete success.
class K6AsnDatabase {
public:
    K6AsnDatabase();

    Kad6Status LoadEntries(std::uint64_t sequence,
                           const std::vector<K6AsnPrefix>& entries);
    bool Lookup(const Kad6Address& address, K6AsnInfo& out) const noexcept;
    void Clear();

    std::uint64_t sequence() const noexcept { return sequence_; }
    std::size_t entry_count() const noexcept { return entry_count_; }
    bool empty() const noexcept { return entry_count_ == 0; }

private:
    struct Node {
        std::uint32_t child[2] = {0, 0}; // index+1; zero means absent
        std::uint32_t asn = 0;
        std::uint32_t operator_group = 0;
        Byte prefix_length = 0;
        bool has_value = false;
    };

    std::vector<Node> nodes_;
    std::uint64_t sequence_ = 0;
    std::size_t entry_count_ = 0;
};

} // namespace kad6
