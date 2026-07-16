// SPDX-License-Identifier: MIT
// Standalone K6-2 native-IPv6 routing RPC codec tests.
#include "kad6/kad6_routing.h"

#include <cstdio>
#include <cstring>
#include <vector>

using namespace kad6;

static int g_fail = 0;
static int g_pass = 0;

#define CHECK(cond, msg) do { if (cond) { ++g_pass; } else { ++g_fail; \
    std::printf("  FAIL: %s  (%s:%d)\n", msg, __FILE__, __LINE__); } } while (0)

static KadId Id(Byte seed) {
    KadId id{};
    for (std::size_t i = 0; i < id.size(); ++i)
        id[i] = static_cast<Byte>(seed + i);
    return id;
}

static K6Endpoint Endpoint(Byte host, std::uint16_t port) {
    K6Endpoint endpoint;
    endpoint.addr.family = Kad6Address::Family::IPv6;
    endpoint.addr.addr = {0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0,
                          0, 0, 0, 0, 0, 0, 0, host};
    endpoint.udp_port = port;
    endpoint.tcp_port = static_cast<std::uint16_t>(port + 1);
    endpoint.transport_flags = kK6EpUdpKad6;
    endpoint.priority = host;
    endpoint.observed = 1;
    endpoint.valid_until = 2'000'000'000ull + host;
    return endpoint;
}

static K6RouteHeader Header(std::uint32_t txid = 0x12345678u) {
    K6RouteHeader header;
    header.txid = txid;
    header.sender_id = Id(0x10);
    header.sender_caps = 0x0102030405060708ull;
    header.sender_epoch = 0x1112131415161718ull;
    header.sender_endpoint = Endpoint(1, 4672);
    header.sender_record.kad_id = header.sender_id;
    for (std::size_t i = 0; i < header.sender_record.node_pub.size(); ++i)
        header.sender_record.node_pub[i] = static_cast<Byte>(0x80 + i);
    header.sender_record.epoch = header.sender_epoch;
    header.sender_record.caps = header.sender_caps;
    header.sender_record.valid_from = 1'700'000'000ull;
    header.sender_record.valid_until = 1'700'003'600ull;
    header.sender_endpoint.valid_until = header.sender_record.valid_until;
    header.sender_record.endpoints.push_back(header.sender_endpoint);
    return header;
}

static K6RouteContact Contact(Byte seed, Byte host) {
    K6RouteContact contact;
    contact.node_id = Id(seed);
    contact.endpoint = Endpoint(host, static_cast<std::uint16_t>(4700 + host));
    contact.caps = 0xA000000000000000ull | host;
    contact.epoch = 1000 + host;
    return contact;
}

static bool SameEndpoint(const K6Endpoint& a, const K6Endpoint& b) {
    return a.addr == b.addr && a.udp_port == b.udp_port &&
           a.tcp_port == b.tcp_port &&
           a.transport_flags == b.transport_flags &&
           a.priority == b.priority && a.observed == b.observed &&
           a.valid_until == b.valid_until;
}

static bool SameHeader(const K6RouteHeader& a, const K6RouteHeader& b) {
    return a.version == b.version && a.flags == b.flags &&
           a.reserved == b.reserved && a.txid == b.txid &&
           a.sender_id == b.sender_id && a.sender_caps == b.sender_caps &&
           a.sender_epoch == b.sender_epoch &&
           SameEndpoint(a.sender_endpoint, b.sender_endpoint) &&
           a.sender_record.version == b.sender_record.version &&
           a.sender_record.flags == b.sender_record.flags &&
           a.sender_record.kad_id == b.sender_record.kad_id &&
           a.sender_record.node_pub == b.sender_record.node_pub &&
           a.sender_record.epoch == b.sender_record.epoch &&
           a.sender_record.caps == b.sender_record.caps &&
           a.sender_record.valid_from == b.sender_record.valid_from &&
           a.sender_record.valid_until == b.sender_record.valid_until &&
           a.sender_record.endpoints.size() == b.sender_record.endpoints.size() &&
           SameEndpoint(a.sender_record.endpoints[0], b.sender_record.endpoints[0]) &&
           a.sender_record.signature == b.sender_record.signature;
}

static bool SameContact(const K6RouteContact& a, const K6RouteContact& b) {
    return a.node_id == b.node_id && SameEndpoint(a.endpoint, b.endpoint) &&
           a.caps == b.caps && a.epoch == b.epoch;
}

static void HeaderOnlyTests() {
    K6BootstrapRequest bootstrap;
    bootstrap.header = Header();
    std::vector<Byte> wire;
    CHECK(EncodeK6BootstrapRequest(bootstrap, wire) == Kad6Status::Ok,
          "bootstrap request encodes");
    CHECK(wire.size() == kK6RouteHeaderV2MinSize,
          "bootstrap request exact signed-v2 size");

    K6BootstrapRequest decoded;
    CHECK(DecodeK6BootstrapRequest(wire.data(), wire.size(), decoded) ==
              Kad6Status::Ok,
          "bootstrap request decodes");
    CHECK(SameHeader(decoded.header, bootstrap.header),
          "bootstrap request round trip");

    K6HelloRequest helloRequest;
    helloRequest.header = Header(7);
    CHECK(EncodeK6HelloRequest(helloRequest, wire) == Kad6Status::Ok,
          "hello request encodes");
    K6HelloRequest decodedRequest;
    CHECK(DecodeK6HelloRequest(wire.data(), wire.size(), decodedRequest) ==
              Kad6Status::Ok &&
              SameHeader(decodedRequest.header, helloRequest.header),
          "hello request round trip");

    K6HelloResponse helloResponse;
    helloResponse.header = Header(7);
    CHECK(EncodeK6HelloResponse(helloResponse, wire) == Kad6Status::Ok,
          "hello response encodes");
    K6HelloResponse decodedResponse;
    CHECK(DecodeK6HelloResponse(wire.data(), wire.size(), decodedResponse) ==
              Kad6Status::Ok &&
              SameHeader(decodedResponse.header, helloResponse.header),
          "hello response round trip");

    wire.push_back(0xCC);
    CHECK(DecodeK6HelloResponse(wire.data(), wire.size(), decodedResponse) ==
              Kad6Status::Malformed,
          "header-only message rejects trailing bytes");
    CHECK(DecodeK6HelloRequest(nullptr, 1, decodedRequest) ==
              Kad6Status::NullArgument,
          "null non-empty input rejected");
    CHECK(DecodeK6HelloRequest(nullptr, 0, decodedRequest) ==
              Kad6Status::Truncated,
          "empty input is truncated");
}

static void BootstrapResponseTests() {
    K6BootstrapResponse message;
    message.header = Header();
    message.contacts.push_back(Contact(0x30, 2));
    message.contacts.push_back(Contact(0x50, 3));

    std::vector<Byte> wire;
    CHECK(EncodeK6BootstrapResponse(message, wire) == Kad6Status::Ok,
          "bootstrap response encodes");
    CHECK(wire.size() == kK6RouteHeaderV2MinSize + 1 +
                         2 * kK6RouteContactV1Size,
          "bootstrap response exact size");
    CHECK(wire[kK6RouteHeaderV2MinSize] == 2,
          "bootstrap response count on wire");

    K6BootstrapResponse decoded;
    CHECK(DecodeK6BootstrapResponse(wire.data(), wire.size(), decoded) ==
              Kad6Status::Ok,
          "bootstrap response decodes");
    CHECK(SameHeader(decoded.header, message.header) &&
              decoded.contacts.size() == 2 &&
              SameContact(decoded.contacts[0], message.contacts[0]) &&
              SameContact(decoded.contacts[1], message.contacts[1]),
          "bootstrap response round trip");

    std::vector<Byte> trailing = wire;
    trailing.push_back(0);
    CHECK(DecodeK6BootstrapResponse(trailing.data(), trailing.size(), decoded) ==
              Kad6Status::Malformed,
          "bootstrap response rejects trailing byte");

    std::vector<Byte> tooMany = wire;
    tooMany[kK6RouteHeaderV2MinSize] =
        static_cast<Byte>(kK6RouteMaxContacts + 1);
    CHECK(DecodeK6BootstrapResponse(tooMany.data(), tooMany.size(), decoded) ==
              Kad6Status::TooLarge,
          "contact count rejected before allocation");

    K6BootstrapResponse duplicate = message;
    duplicate.contacts[1].node_id = duplicate.contacts[0].node_id;
    CHECK(EncodeK6BootstrapResponse(duplicate, trailing) ==
              Kad6Status::BadValue && trailing.empty(),
          "encoder rejects duplicate node IDs atomically");

    // Create a duplicate directly on the wire to exercise consumer policy.
    const std::size_t firstId = kK6RouteHeaderV2MinSize + 1;
    const std::size_t secondId = firstId + kK6RouteContactV1Size;
    std::memcpy(wire.data() + secondId, wire.data() + firstId, kKadIdSize);
    CHECK(DecodeK6BootstrapResponse(wire.data(), wire.size(), decoded) ==
              Kad6Status::Malformed,
          "decoder rejects duplicate node IDs");
}

static void FindNodeTests() {
    K6FindNodeRequest request;
    request.header = Header(0xAABBCCDDu);
    request.target_id = Id(0x80);
    request.max_results = 9;
    std::vector<Byte> wire;
    CHECK(EncodeK6FindNodeRequest(request, wire) == Kad6Status::Ok,
          "find-node request encodes");
    CHECK(wire.size() == kK6RouteHeaderV2MinSize + kKadIdSize + 4,
          "find-node request exact size");

    K6FindNodeRequest decodedRequest;
    CHECK(DecodeK6FindNodeRequest(wire.data(), wire.size(), decodedRequest) ==
              Kad6Status::Ok,
          "find-node request decodes");
    CHECK(SameHeader(decodedRequest.header, request.header) &&
              decodedRequest.target_id == request.target_id &&
              decodedRequest.max_results == request.max_results,
          "find-node request round trip");

    std::vector<Byte> badReserved = wire;
    badReserved.back() = 1;
    CHECK(DecodeK6FindNodeRequest(badReserved.data(), badReserved.size(),
                                 decodedRequest) == Kad6Status::Malformed,
          "find-node request reserved bytes are zero");

    K6FindNodeResponse response;
    response.header = Header(request.header.txid);
    response.target_id = request.target_id;
    for (Byte i = 0; i < kK6RouteMaxContacts; ++i)
        response.contacts.push_back(Contact(static_cast<Byte>(0x20 + i * 2),
                                            static_cast<Byte>(20 + i)));
    CHECK(EncodeK6FindNodeResponse(response, wire) == Kad6Status::Ok,
          "maximum find-node response encodes");
    CHECK(wire.size() <= kK6RouteMaxPayloadSize && wire.size() < 1200,
          "maximum response remains below UDP budget");

    K6FindNodeResponse decodedResponse;
    CHECK(DecodeK6FindNodeResponse(wire.data(), wire.size(), decodedResponse) ==
              Kad6Status::Ok,
          "maximum find-node response decodes");
    CHECK(decodedResponse.contacts.size() == kK6RouteMaxContacts &&
              SameContact(decodedResponse.contacts.back(),
                          response.contacts.back()),
          "maximum response round trip");

    request.max_results = 0;
    CHECK(EncodeK6FindNodeRequest(request, wire) == Kad6Status::BadValue &&
              wire.empty(),
          "zero result request rejected atomically");
    request.max_results = static_cast<Byte>(kK6RouteMaxContacts + 1);
    CHECK(EncodeK6FindNodeRequest(request, wire) == Kad6Status::BadValue,
          "oversized result request rejected");
}

static void ValidationTests() {
    K6HelloRequest message;
    message.header = Header();
    std::vector<Byte> wire;

    message.header.txid = 0;
    CHECK(EncodeK6HelloRequest(message, wire) == Kad6Status::BadValue,
          "zero txid rejected");
    message.header = Header();
    message.header.sender_epoch = 0;
    CHECK(EncodeK6HelloRequest(message, wire) == Kad6Status::BadValue,
          "zero epoch rejected");
    message.header = Header();
    message.header.sender_id.fill(0);
    CHECK(EncodeK6HelloRequest(message, wire) == Kad6Status::BadValue,
          "zero sender ID rejected");
    message.header = Header();
    message.header.sender_endpoint.addr.family = Kad6Address::Family::IPv4;
    CHECK(EncodeK6HelloRequest(message, wire) == Kad6Status::BadValue,
          "IPv4 routing endpoint rejected");
    message.header = Header();
    message.header.sender_endpoint.udp_port = 0;
    CHECK(EncodeK6HelloRequest(message, wire) == Kad6Status::BadValue,
          "zero Kad UDP port rejected");
    message.header = Header();
    message.header.sender_endpoint.transport_flags = kK6EpTcpEd2k;
    CHECK(EncodeK6HelloRequest(message, wire) == Kad6Status::BadValue,
          "endpoint without Kad6 UDP flag rejected");

    message.header = Header();
    CHECK(EncodeK6HelloRequest(message, wire) == Kad6Status::Ok,
          "valid message restored");
    K6HelloRequest decoded;
    std::vector<Byte> mutated = wire;
    mutated[0] = 3;
    CHECK(DecodeK6HelloRequest(mutated.data(), mutated.size(), decoded) ==
              Kad6Status::UnsupportedVersion,
          "unknown route version rejected distinctly");
    mutated = wire;
    mutated[1] = 1;
    CHECK(DecodeK6HelloRequest(mutated.data(), mutated.size(), decoded) ==
              Kad6Status::Malformed,
          "v1 flags must be zero");
    mutated = wire;
    mutated[4] = mutated[5] = mutated[6] = mutated[7] = 0;
    CHECK(DecodeK6HelloRequest(mutated.data(), mutated.size(), decoded) ==
              Kad6Status::Malformed,
          "wire zero txid rejected");

    // Endpoint address starts at offset 40: family, length, then 16 bytes.
    mutated = wire;
    std::memset(mutated.data() + 42, 0, 10);
    mutated[52] = mutated[53] = 0xFF; // ::ffff:192.0.2.1
    mutated[54] = 192; mutated[55] = 0; mutated[56] = 2; mutated[57] = 1;
    CHECK(DecodeK6HelloRequest(mutated.data(), mutated.size(), decoded) ==
              Kad6Status::Malformed,
          "IPv4-mapped IPv6 endpoint rejected");

    // The signed record starts after the base header and its u16 length.
    // Mutating the record's KadID must fail coherence before runtime crypto.
    mutated = wire;
    mutated[kK6RouteHeaderV2PrefixSize + 4] ^= 0x01;
    CHECK(DecodeK6HelloRequest(mutated.data(), mutated.size(), decoded) ==
              Kad6Status::Malformed,
          "signed record must match sender KadID");

    // Legacy v1 remains parseable for migration tooling, but carries no
    // sender_record. The production runtime rejects it before promotion.
    message.header = Header();
    message.header.version = kK6RouteLegacyWireVersion;
    CHECK(EncodeK6HelloRequest(message, wire) == Kad6Status::Ok &&
              wire.size() == kK6RouteHeaderV1Size,
          "unsigned v1 remains codec-compatible");
    CHECK(DecodeK6HelloRequest(wire.data(), wire.size(), decoded) ==
              Kad6Status::Ok &&
              decoded.header.version == kK6RouteLegacyWireVersion,
          "unsigned v1 migration decode");

    message.header = Header();
    CHECK(EncodeK6HelloRequest(message, wire) == Kad6Status::Ok,
          "restore signed v2 for truncation sweep");

    for (std::size_t cut = 0; cut < wire.size(); ++cut) {
        CHECK(DecodeK6HelloRequest(wire.data(), cut, decoded) != Kad6Status::Ok,
              "every truncated header prefix is rejected");
    }
}

static void SnapshotTests() {
    std::vector<K6RouteSnapshotEntry> entries(2);
    entries[0].contact = Contact(0x31, 8);
    entries[0].last_seen = 1'700'000'001ull;
    entries[0].verified = 1;
    entries[0].failures = 2;
    entries[0].has_signed_identity = 1;
    entries[0].signed_epoch = entries[0].contact.epoch;
    for (std::size_t i = 0; i < entries[0].node_pub.size(); ++i)
        entries[0].node_pub[i] = static_cast<Byte>(0x70 + i);
    for (std::size_t i = 0; i < entries[0].router_signature.size(); ++i)
        entries[0].router_signature[i] = static_cast<Byte>(0x20 + i);
    entries[1].contact = Contact(0x51, 9);
    entries[1].last_seen = 1'700'000'002ull;

    std::vector<Byte> wire;
    CHECK(EncodeK6RouteSnapshot(entries, wire) == Kad6Status::Ok,
          "routing snapshot encodes");
    CHECK(wire.size() == kK6RouteSnapshotHeaderV1Size +
                         2 * kK6RouteSnapshotEntryV2Size,
          "routing snapshot exact size");
    CHECK(wire[0] == 'K' && wire[1] == '6' && wire[2] == 'N' && wire[3] == 'D',
          "routing snapshot magic");

    std::vector<K6RouteSnapshotEntry> decoded;
    CHECK(DecodeK6RouteSnapshot(wire.data(), wire.size(), decoded) ==
              Kad6Status::Ok,
          "routing snapshot decodes");
    CHECK(decoded.size() == 2 &&
              SameContact(decoded[0].contact, entries[0].contact) &&
              decoded[0].last_seen == entries[0].last_seen &&
              decoded[0].verified == 1 && decoded[0].failures == 2 &&
              decoded[0].has_signed_identity == 1 &&
              decoded[0].node_pub == entries[0].node_pub &&
              decoded[0].signed_epoch == entries[0].signed_epoch &&
              decoded[0].router_signature == entries[0].router_signature,
          "routing snapshot round trip");

    std::vector<Byte> trailing = wire;
    trailing.push_back(0);
    CHECK(DecodeK6RouteSnapshot(trailing.data(), trailing.size(), decoded) ==
              Kad6Status::Malformed,
          "routing snapshot rejects trailing data");
    std::vector<Byte> badMagic = wire;
    badMagic[0] = 'X';
    CHECK(DecodeK6RouteSnapshot(badMagic.data(), badMagic.size(), decoded) ==
              Kad6Status::Malformed,
          "routing snapshot rejects wrong magic");
    std::vector<Byte> duplicate = wire;
    const std::size_t firstId = kK6RouteSnapshotHeaderV1Size;
    const std::size_t secondId = firstId + kK6RouteSnapshotEntryV2Size;
    std::memcpy(duplicate.data() + secondId, duplicate.data() + firstId,
                kKadIdSize);
    CHECK(DecodeK6RouteSnapshot(duplicate.data(), duplicate.size(), decoded) ==
              Kad6Status::Malformed,
          "routing snapshot rejects duplicate IDs");

    entries[0].verified = 2;
    CHECK(EncodeK6RouteSnapshot(entries, wire) == Kad6Status::BadValue &&
              wire.empty(),
          "routing snapshot canonical verified flag");

    // v1 snapshots remain readable, but their historical return-routability
    // bit is deliberately downgraded because no identity signature was saved.
    std::vector<K6RouteSnapshotEntry> legacyEntry(1);
    legacyEntry[0].contact = Contact(0x61, 12);
    legacyEntry[0].last_seen = 1'700'000'100ull;
    CHECK(EncodeK6RouteSnapshot(legacyEntry, wire) == Kad6Status::Ok,
          "v2 unsigned fixture for legacy conversion");
    wire[4] = kK6RouteSnapshotLegacyVersion;
    wire.resize(kK6RouteSnapshotHeaderV1Size + kK6RouteSnapshotEntryV1Size);
    CHECK(DecodeK6RouteSnapshot(wire.data(), wire.size(), decoded) ==
              Kad6Status::Ok && decoded.size() == 1 &&
              decoded[0].verified == 0 &&
              decoded[0].has_signed_identity == 0,
          "legacy nodes_v6 snapshot migrates into unsigned probation");
}

static void FuzzSmoke() {
    std::uint32_t state = 0x6B362002u;
    K6FindNodeResponse decoded;
    for (int n = 0; n < 4096; ++n) {
        state = state * 1664525u + 1013904223u;
        const std::size_t len = state % 1400;
        std::vector<Byte> bytes(len);
        for (std::size_t i = 0; i < len; ++i) {
            state = state * 1664525u + 1013904223u;
            bytes[i] = static_cast<Byte>(state >> 24);
        }
        const Kad6Status status = DecodeK6FindNodeResponse(
            bytes.empty() ? nullptr : bytes.data(), bytes.size(), decoded);
        CHECK(status != Kad6Status::Ok || bytes.size() <= kK6RouteMaxPayloadSize,
              "bounded random decode");
    }
}

int main() {
    HeaderOnlyTests();
    BootstrapResponseTests();
    FindNodeTests();
    ValidationTests();
    SnapshotTests();
    FuzzSmoke();
    std::printf("test_kad6_routing: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
