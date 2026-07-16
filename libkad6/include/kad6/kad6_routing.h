// SPDX-License-Identifier: MIT
//
// libkad6 - native-IPv6 Kademlia routing RPC payloads (K6-2, wire v2).
//
// These codecs cover the payload after eMule's two-byte UDP envelope
// [OP_KADEMLIAHEADER][KADEMLIA3_*].  They deliberately do not contain an
// opcode: the opcode selects one of the six exact payload layouts below.
// All integers are little-endian and every decoder requires exact input
// consumption (trailing bytes are malformed).
#pragma once

#include "kad6/kad6_endpoint.h"
#include "kad6/kad6_records.h"
#include "kad6/kad6_types.h"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace kad6 {

// v1 was the unsigned experimental cut. v2 appends a length-delimited,
// Ed25519-signed K6RouterRecord for the sender. Decoders retain v1 support for
// diagnostics/migration, while the host runtime only promotes v2 senders.
constexpr Byte kK6RouteLegacyWireVersion = 1;
constexpr Byte kK6RouteWireVersion = 2;
constexpr std::size_t kK6RouteMaxContacts = 10;
constexpr std::size_t kK6RouteHeaderV1Size = 74;   // unsigned legacy header
constexpr std::size_t kK6RouteHeaderV2PrefixSize = 76; // v1 fields + record_len:u16
constexpr std::size_t kK6RouteHeaderV2MinSize =
    kK6RouteHeaderV2PrefixSize + kK6RouterRecordFixedSize +
    kK6EndpointMaxEncodedSize;
constexpr std::size_t kK6RouteHeaderV2MaxSize =
    kK6RouteHeaderV2PrefixSize + kK6RouterRecordMaxSize;
constexpr std::size_t kK6RouteContactV1Size = 66; // with mandatory IPv6 endpoint
constexpr std::size_t kK6RouteMaxPayloadSize =
    kK6RouteHeaderV2MaxSize + kKadIdSize + 1 +
    (kK6RouteMaxContacts * kK6RouteContactV1Size); // 1037 bytes
constexpr std::size_t kK6RouteMaxStoredContacts = 1024;
constexpr Byte kK6RouteSnapshotLegacyVersion = 1;
constexpr Byte kK6RouteSnapshotVersion = 2;
constexpr std::size_t kK6RouteSnapshotHeaderV1Size = 12;
constexpr std::size_t kK6RouteSnapshotEntryV1Size = 78;
constexpr std::size_t kK6RouteSnapshotEntryV2Size = 182;

// Present at the start of every K6-2 routing RPC.
//
// wire: version:u8, flags:u8, reserved:u16, txid:u32, sender_id:16,
//       sender_caps:u64, sender_epoch:u64, sender_endpoint:K6Endpoint.
// Both versions require flags/reserved == 0. txid, sender_id and sender_epoch
// are non-zero. sender_endpoint is native IPv6, advertises UDP Kad6 and has a
// non-zero UDP port. Version 2 additionally requires `sender_record` and exact
// coherence between its identity/caps/epoch and the advertised endpoint.
struct K6RouteHeader {
    Byte version = kK6RouteWireVersion;
    Byte flags = 0;
    std::uint16_t reserved = 0;
    std::uint32_t txid = 0;
    KadId sender_id{};
    std::uint64_t sender_caps = 0;
    std::uint64_t sender_epoch = 0;
    K6Endpoint sender_endpoint;
    K6RouterRecord sender_record; // mandatory and length-delimited in v2
};

// Compact routing-table contact returned by BOOTSTRAP_RES and RES.
// wire: node_id:16, endpoint:K6Endpoint, caps:u64, epoch:u64.
struct K6RouteContact {
    KadId node_id{};
    K6Endpoint endpoint;
    std::uint64_t caps = 0;
    std::uint64_t epoch = 0;
};

struct K6BootstrapRequest {
    K6RouteHeader header;
};

struct K6BootstrapResponse {
    K6RouteHeader header;
    std::vector<K6RouteContact> contacts;
};

struct K6HelloRequest {
    K6RouteHeader header;
};

struct K6HelloResponse {
    K6RouteHeader header;
};

struct K6FindNodeRequest {
    K6RouteHeader header;
    KadId target_id{};
    Byte max_results = static_cast<Byte>(kK6RouteMaxContacts);
};

struct K6FindNodeResponse {
    K6RouteHeader header;
    KadId target_id{};
    std::vector<K6RouteContact> contacts;
};

// Shared authenticated routing header for K6-3+ native RPC families. Unlike
// the six routing messages below, Decode reports the consumed prefix and
// deliberately permits a caller-owned body after it.
Kad6Status EncodeK6RouteHeader(const K6RouteHeader& header,
                               std::vector<Byte>& out);
Kad6Status DecodeK6RouteHeader(const Byte* in, std::size_t len,
                               K6RouteHeader& header,
                               std::size_t* consumed = nullptr) noexcept;

// Separate nodes_v6.dat snapshot. Persisted verification is only advisory:
// the host must load every entry into probation and revalidate it before use.
struct K6RouteSnapshotEntry {
    K6RouteContact contact;
    std::uint64_t last_seen = 0;
    Byte verified = 0;
    Byte failures = 0;
    Byte has_signed_identity = 0;
    Ed25519Pub node_pub{};
    std::uint64_t signed_epoch = 0;
    Ed25519Sig router_signature{};
};

// Producer-side validation is strict. Bad values return BadValue, oversized
// contact lists return TooLarge, and `out` is empty after every failure.
Kad6Status EncodeK6BootstrapRequest(const K6BootstrapRequest& message,
                                    std::vector<Byte>& out);
Kad6Status EncodeK6BootstrapResponse(const K6BootstrapResponse& message,
                                     std::vector<Byte>& out);
Kad6Status EncodeK6HelloRequest(const K6HelloRequest& message,
                                std::vector<Byte>& out);
Kad6Status EncodeK6HelloResponse(const K6HelloResponse& message,
                                 std::vector<Byte>& out);
Kad6Status EncodeK6FindNodeRequest(const K6FindNodeRequest& message,
                                   std::vector<Byte>& out);
Kad6Status EncodeK6FindNodeResponse(const K6FindNodeResponse& message,
                                    std::vector<Byte>& out);
Kad6Status EncodeK6RouteSnapshot(
    const std::vector<K6RouteSnapshotEntry>& entries, std::vector<Byte>& out);

// Consumer-side validation mirrors the producer. Empty/short input returns
// Truncated, null + non-zero length returns NullArgument, bad values or
// trailing bytes return Malformed, unknown versions return
// UnsupportedVersion, and excessive counts return TooLarge.
Kad6Status DecodeK6BootstrapRequest(const Byte* in, std::size_t len,
                                    K6BootstrapRequest& out) noexcept;
Kad6Status DecodeK6BootstrapResponse(const Byte* in, std::size_t len,
                                     K6BootstrapResponse& out) noexcept;
Kad6Status DecodeK6HelloRequest(const Byte* in, std::size_t len,
                                K6HelloRequest& out) noexcept;
Kad6Status DecodeK6HelloResponse(const Byte* in, std::size_t len,
                                 K6HelloResponse& out) noexcept;
Kad6Status DecodeK6FindNodeRequest(const Byte* in, std::size_t len,
                                   K6FindNodeRequest& out) noexcept;
Kad6Status DecodeK6FindNodeResponse(const Byte* in, std::size_t len,
                                    K6FindNodeResponse& out) noexcept;
Kad6Status DecodeK6RouteSnapshot(
    const Byte* in, std::size_t len,
    std::vector<K6RouteSnapshotEntry>& entries) noexcept;

} // namespace kad6
