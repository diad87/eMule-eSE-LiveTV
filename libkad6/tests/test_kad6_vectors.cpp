// SPDX-License-Identifier: MIT
// External, reviewable codec vectors. Run from libkad6/ so vectors/*.json is
// independent of the eMule application and its current working directory.
#include "vector_json.h"

#include "kad6/kad6_address.h"
#include "kad6/kad6_frame.h"
#include "kad6/kad6_records.h"
#include "kad6/kad6_shaped_bulk.h"
#include "kad6/kad6_tags.h"
#include "kad6/kad6_ticket.h"

#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

using namespace kad6;
using namespace kad6_vectors;

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond, msg) do { if (cond) { ++g_pass; } else { ++g_fail; \
    std::printf("  FAIL: %s  (%s:%d)\n", msg, __FILE__, __LINE__); } } while (0)

static bool ExpectedBytes(const char* file, const char* id, std::vector<Byte>& out) {
    const std::string json = LoadText(file);
    const std::string object = ObjectById(json, id);
    return !json.empty() && !object.empty() && HexToBytes(StringField(object, "expected_hex"), out);
}

static std::string ExpectedStatus(const char* file, const char* id) {
    return StringField(ObjectById(LoadText(file), id), "expected_status");
}

static void CheckWire(const char* file, const char* id, const std::vector<Byte>& actual) {
    std::vector<Byte> expected;
    CHECK(ExpectedBytes(file, id, expected), "vector file/id/hex loads");
    if (expected != actual) {
        std::printf("  vector %s actual: %s\n", id, BytesToHex(actual).c_str());
        CHECK(false, "encoded bytes match external golden");
    } else {
        CHECK(true, "encoded bytes match external golden");
    }
}

static void CheckStatus(const char* file, const char* id, Kad6Status actual) {
    const std::string expected = ExpectedStatus(file, id);
    CHECK(!expected.empty(), "expected status loads");
    CHECK(expected == Kad6StatusName(actual), "adversarial status matches vector");
}

static void TestAddress() {
    Kad6Address address;
    address.family = Kad6Address::Family::IPv4;
    address.addr = {8, 8, 8, 8};
    std::vector<Byte> wire;
    CHECK(EncodeKad6Address(address, wire) == Kad6Status::Ok, "address vector encodes");
    CheckWire("vectors/address.json", "address-ipv4-google-dns", wire);
    const Byte bad[] = {4, 16};
    CheckStatus("vectors/address.json", "address-family-length-mismatch",
                DecodeKad6Address(bad, sizeof(bad), address));
}

static void TestFrame() {
    K6Frame frame;
    std::vector<Byte> wire;
    CHECK(EncodeK6Frame(frame, wire) == Kad6Status::Ok, "frame vector encodes");
    CheckWire("vectors/frame.json", "frame-minimal-v1", wire);
    wire[0] = 2;
    CheckStatus("vectors/frame.json", "frame-unsupported-version",
                DecodeK6Frame(wire.data(), wire.size(), frame));
}

static void TestTags() {
    K6Tag tag;
    tag.name = {0x10};
    tag.value = {0x42};
    K6TagList tags = {tag};
    std::vector<Byte> wire;
    CHECK(EncodeK6TagList(tags, wire) == Kad6Status::Ok, "tag vector encodes");
    CheckWire("vectors/tags.json", "tags-one-u8", wire);
    const Byte bad[] = {2, 0, 0, 7, 0, 0, 0};
    CheckStatus("vectors/tags.json", "tags-unsupported-version",
                DecodeK6TagList(bad, sizeof(bad), tags));
}

static K6TargetTicket TicketFixture() {
    K6TargetTicket ticket;
    ticket.lease_id = 1;
    ticket.provenance_session = 2;
    ticket.provenance_stream = 3;
    ticket.provenance_seq = 4;
    ticket.target_endpoint.addr.family = Kad6Address::Family::IPv4;
    ticket.target_endpoint.addr.addr = {8, 8, 8, 8};
    ticket.target_endpoint.udp_port = 4672;
    ticket.target_endpoint.tcp_port = 4662;
    ticket.target_endpoint.valid_until = 2000;
    ticket.issued_at = 1000;
    ticket.expires_at = 1300;
    ticket.max_bytes = 1;
    ticket.max_connections = 1;
    return ticket;
}

static void TestTicket() {
    K6TargetTicket ticket = TicketFixture();
    std::vector<Byte> wire;
    CHECK(EncodeK6TargetTicket(ticket, wire) == Kad6Status::Ok, "ticket vector encodes");
    CheckWire("vectors/tickets.json", "ticket-canonical-zero-mac", wire);
    wire[13] = 1;
    CheckStatus("vectors/tickets.json", "ticket-reserved-byte-set",
                DecodeK6TargetTicket(wire.data(), wire.size(), ticket));
}

static void TestRecords() {
    K6NodeBind bind;
    for (std::size_t i = 0; i < bind.kad_id.size(); ++i)
        bind.kad_id[i] = static_cast<Byte>(i);
    for (std::size_t i = 0; i < bind.node_pub.size(); ++i)
        bind.node_pub[i] = static_cast<Byte>(0x20 + i);
    bind.epoch = 1;
    std::vector<Byte> wire;
    CHECK(EncodeK6NodeBind(bind, wire) == Kad6Status::Ok, "record vector encodes");
    CheckWire("vectors/records.json", "node-bind-canonical", wire);
    K6NodeBind out;
    CheckStatus("vectors/records.json", "node-bind-truncated",
                DecodeK6NodeBind(wire.data(), 16, out));
}

static bool Fill5a(Byte* out, std::size_t n) {
    for (std::size_t i = 0; i < n; ++i) out[i] = 0x5a;
    return true;
}

static void TestShaped() {
    const std::string json = LoadText("vectors/shaped.json");
    const std::string object = ObjectById(json, "shaped-one-layer-fixed-17000");
    std::vector<Byte> header, prefixByte, tailByte;
    CHECK(HexToBytes(StringField(object, "expected_header_hex"), header), "shaped header hex loads");
    CHECK(HexToBytes(StringField(object, "expected_prefix_hex"), prefixByte), "shaped prefix hex loads");
    CHECK(HexToBytes(StringField(object, "expected_tail_hex"), tailByte), "shaped tail hex loads");
    const std::size_t prefixRepeat = static_cast<std::size_t>(
        std::strtoull(StringField(object, "expected_prefix_repeat").c_str(), nullptr, 10));
    const std::size_t tailRepeat = static_cast<std::size_t>(
        std::strtoull(StringField(object, "expected_tail_repeat").c_str(), nullptr, 10));
    std::vector<Byte> expected = header;
    expected.insert(expected.end(), prefixRepeat, prefixByte.empty() ? 0 : prefixByte[0]);
    expected.insert(expected.end(), tailRepeat, tailByte.empty() ? 0 : tailByte[0]);
    CHECK(expected.size() == kK6ShapedTotal, "compact shaped vector specifies all 17000 bytes");

    std::vector<Byte> prefix(K6ShapedPrefixLen(1), 0xa5);
    Kad6CryptoHooks hooks{};
    hooks.random_bytes = &Fill5a;
    std::vector<Byte> wire;
    CHECK(BuildK6ShapedCarrier(prefix.data(), prefix.size(), 1,
              0x11223344u, 0x1122334455667788ull, hooks, wire) == Kad6Status::Ok,
          "shaped vector builds");
    CHECK(wire == expected, "all shaped carrier bytes match external vector");
    wire[4] = 2;
    K6ShapedHeader parsed;
    CheckStatus("vectors/shaped.json", "shaped-invalid-bcmd",
                PeekK6ShapedHeader(wire.data(), wire.size(), parsed));
}

int main() {
    TestAddress();
    TestFrame();
    TestTags();
    TestTicket();
    TestRecords();
    TestShaped();
    std::printf("test_kad6_vectors: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
