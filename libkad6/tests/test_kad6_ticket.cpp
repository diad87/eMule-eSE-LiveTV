// SPDX-License-Identifier: MIT
//
// test_kad6_ticket.cpp — K6TargetTicketV1 codec + MAC + policy (ticket K6-0.5),
// and K6EndpointV1 round-trip (K6-0.6 support piece).
//
// The HMAC here is a MOCK: a deterministic, full-avalanche stand-in used only to
// exercise the codec's MAC plumbing, tamper detection and constant-time compare.
// Real HMAC-SHA256 test vectors are pinned separately (K6-0.9) against the host's
// CryptoPP. What this test proves is codec behaviour, not the HMAC construction.
//
//   from libkad6/:
//   make.bat test_kad6_ticket tests\test_kad6_ticket.cpp src\kad6_ticket.cpp ^
//            src\kad6_endpoint.cpp src\kad6_address.cpp
#include "kad6/kad6_ticket.h"

#include <cstdio>
#include <vector>

using namespace kad6;

static int g_fail = 0;
static int g_pass = 0;

#define CHECK(cond, msg) do { if (cond) { ++g_pass; } else { ++g_fail; \
    std::printf("  FAIL: %s  (%s:%d)\n", msg, __FILE__, __LINE__); } } while (0)

// ── mock crypto: deterministic full-avalanche pseudo-HMAC (NOT real) ─────────
static bool mock_hmac(const Byte* key, std::size_t keyLen,
                      const Byte* msg, std::size_t msgLen, Byte mac[32]) {
    std::uint64_t h = 1469598103934665603ull; // FNV-1a offset basis
    for (std::size_t i = 0; i < keyLen; ++i) { h ^= key[i]; h *= 1099511628211ull; }
    h ^= 0x1FU; h *= 1099511628211ull; // key/msg separator
    for (std::size_t i = 0; i < msgLen; ++i) { h ^= msg[i]; h *= 1099511628211ull; }
    // Expand the accumulator (which depends on the whole key+msg) into 32 bytes.
    for (int i = 0; i < 32; ++i) {
        h ^= static_cast<std::uint64_t>(i) * 0x9E3779B97F4A7C15ull;
        h *= 1099511628211ull;
        mac[i] = static_cast<Byte>(h >> ((i % 8) * 8));
    }
    return true;
}

static Kad6CryptoHooks Hooks() {
    Kad6CryptoHooks h{};
    h.hmac_sha256 = &mock_hmac;
    return h;
}

// A well-formed, public, dial-able ticket template.
static K6TargetTicket MakeValidTicket() {
    K6TargetTicket t;
    t.service = static_cast<Byte>(K6TicketService::Ed2kTcp);
    t.provenance_kind = static_cast<Byte>(K6Provenance::KadResult);
    t.lease_id = 0x1122334455667788ull;
    t.provenance_session = 0xAABBCCDDull;
    t.provenance_stream = 7;
    t.provenance_seq = 42;
    for (Byte i = 0; i < 32; ++i) t.provenance_digest[i] = static_cast<Byte>(0x40 + i);
    // Public IPv4 target 203.0.113.10 (TEST-NET-3, routable-shaped, not forbidden).
    t.target_endpoint.addr.family = Kad6Address::Family::IPv4;
    t.target_endpoint.addr.addr = {203, 0, 113, 10};
    t.target_endpoint.tcp_port = 4662;
    t.target_endpoint.udp_port = 4672;
    for (Byte i = 0; i < 16; ++i) t.object_hash[i] = static_cast<Byte>(i);
    t.issued_at = 1000;
    t.expires_at = 1000 + 300;       // exactly the max TTL
    t.max_bytes = 9728000;
    t.max_connections = 1;
    for (Byte i = 0; i < 16; ++i) t.nonce[i] = static_cast<Byte>(0xF0 + i);
    return t;
}

static void test_issue_verify_roundtrip() {
    const Kad6CryptoHooks h = Hooks();
    const Byte secret[] = {'e', 'x', 'i', 't', '-', 's', 'e', 'c', 'r', 'e', 't'};
    K6TargetTicket t = MakeValidTicket();
    std::vector<Byte> wire;
    CHECK(IssueK6TargetTicket(h, secret, sizeof(secret), t, wire) == Kad6Status::Ok, "issue ok");
    CHECK(!wire.empty(), "wire non-empty");

    // Decode-only preserves every field.
    K6TargetTicket dec;
    std::size_t consumed = 0;
    CHECK(DecodeK6TargetTicket(wire.data(), wire.size(), dec, &consumed) == Kad6Status::Ok, "decode ok");
    CHECK(consumed == wire.size(), "consumed all");
    CHECK(dec.lease_id == t.lease_id, "lease_id round-trip");
    CHECK(dec.provenance_seq == 42, "prov seq round-trip");
    CHECK(dec.target_endpoint.tcp_port == 4662, "tcp port round-trip");
    CHECK(dec.target_endpoint.addr == t.target_endpoint.addr, "addr round-trip");
    CHECK(dec.max_connections == 1, "max_conn round-trip");

    // Verify with the right secret, in-window.
    K6TargetTicket ver;
    CHECK(VerifyK6TargetTicket(h, secret, sizeof(secret), wire.data(), wire.size(), 1100, ver)
          == Kad6Status::Ok, "verify ok in-window");
}

static void test_tamper_and_wrong_secret() {
    const Kad6CryptoHooks h = Hooks();
    const Byte secret[] = {'s', '1'};
    const Byte other[]  = {'s', '2'};
    K6TargetTicket t = MakeValidTicket();
    std::vector<Byte> wire;
    (void)IssueK6TargetTicket(h, secret, sizeof(secret), t, wire);

    // Flip one byte anywhere in the signed region -> MAC mismatch.
    std::vector<Byte> tampered = wire;
    tampered[5] ^= 0x01;
    K6TargetTicket out;
    CHECK(VerifyK6TargetTicket(h, secret, sizeof(secret), tampered.data(), tampered.size(), 1100, out)
          == Kad6Status::AuthFailed, "tamper -> AuthFailed");

    // Flip a byte in the MAC itself -> mismatch.
    std::vector<Byte> tampered2 = wire;
    tampered2[tampered2.size() - 1] ^= 0x80;
    CHECK(VerifyK6TargetTicket(h, secret, sizeof(secret), tampered2.data(), tampered2.size(), 1100, out)
          == Kad6Status::AuthFailed, "mac tamper -> AuthFailed");

    // Correct bytes but wrong secret -> mismatch.
    CHECK(VerifyK6TargetTicket(h, other, sizeof(other), wire.data(), wire.size(), 1100, out)
          == Kad6Status::AuthFailed, "wrong secret -> AuthFailed");
}

static void test_expiry() {
    const Kad6CryptoHooks h = Hooks();
    const Byte secret[] = {'k'};
    K6TargetTicket t = MakeValidTicket(); // window [1000, 1300)
    std::vector<Byte> wire;
    (void)IssueK6TargetTicket(h, secret, sizeof(secret), t, wire);
    K6TargetTicket out;
    CHECK(VerifyK6TargetTicket(h, secret, sizeof(secret), wire.data(), wire.size(), 1299, out)
          == Kad6Status::Ok, "just-in-window ok");
    CHECK(VerifyK6TargetTicket(h, secret, sizeof(secret), wire.data(), wire.size(), 1300, out)
          == Kad6Status::Expired, "expires_at boundary -> Expired");
    CHECK(VerifyK6TargetTicket(h, secret, sizeof(secret), wire.data(), wire.size(), 5000, out)
          == Kad6Status::Expired, "way past -> Expired");
}

static void test_ttl_and_range_guards() {
    const Kad6CryptoHooks h = Hooks();
    const Byte secret[] = {'k'};
    std::vector<Byte> wire;

    { // TTL > 300 rejected at issue
        K6TargetTicket t = MakeValidTicket();
        t.expires_at = t.issued_at + 301;
        CHECK(IssueK6TargetTicket(h, secret, sizeof(secret), t, wire) == Kad6Status::BadValue, "ttl>300 BadValue");
    }
    { // expires <= issued rejected
        K6TargetTicket t = MakeValidTicket();
        t.expires_at = t.issued_at;
        CHECK(IssueK6TargetTicket(h, secret, sizeof(secret), t, wire) == Kad6Status::BadValue, "expires<=issued BadValue");
    }
    { // bad service
        K6TargetTicket t = MakeValidTicket();
        t.service = 9;
        CHECK(IssueK6TargetTicket(h, secret, sizeof(secret), t, wire) == Kad6Status::BadValue, "bad service BadValue");
    }
    { // bad provenance
        K6TargetTicket t = MakeValidTicket();
        t.provenance_kind = 0;
        CHECK(IssueK6TargetTicket(h, secret, sizeof(secret), t, wire) == Kad6Status::BadValue, "bad prov BadValue");
    }
}

static void test_forbidden_targets() {
    const Kad6CryptoHooks h = Hooks();
    const Byte secret[] = {'k'};
    std::vector<Byte> wire;

    struct V4 { Byte a, b, c, d; const char* name; };
    const V4 bad4[] = {
        {127, 0, 0, 1, "loopback"}, {10, 1, 2, 3, "rfc1918-10"},
        {172, 16, 0, 1, "rfc1918-172"}, {192, 168, 1, 1, "rfc1918-192"},
        {169, 254, 0, 1, "link-local"}, {224, 0, 0, 1, "multicast"},
        {255, 255, 255, 255, "broadcast"}, {0, 0, 0, 0, "unspecified"},
    };
    for (const V4& v : bad4) {
        K6TargetTicket t = MakeValidTicket();
        t.target_endpoint.addr.addr = {v.a, v.b, v.c, v.d};
        CHECK(IssueK6TargetTicket(h, secret, sizeof(secret), t, wire) == Kad6Status::TargetForbidden, v.name);
    }
    { // port 0 for the service in use
        K6TargetTicket t = MakeValidTicket();
        t.target_endpoint.tcp_port = 0; // service is Ed2kTcp
        CHECK(IssueK6TargetTicket(h, secret, sizeof(secret), t, wire) == Kad6Status::TargetForbidden, "tcp port 0");
    }
    { // IPv6 ::1 loopback
        K6TargetTicket t = MakeValidTicket();
        t.target_endpoint.addr.family = Kad6Address::Family::IPv6;
        t.target_endpoint.addr.addr = {};
        t.target_endpoint.addr.addr[15] = 1;
        CHECK(IssueK6TargetTicket(h, secret, sizeof(secret), t, wire) == Kad6Status::TargetForbidden, "v6 ::1");
    }
    { // IPv6 fe80::/10 link-local
        K6TargetTicket t = MakeValidTicket();
        t.target_endpoint.addr.family = Kad6Address::Family::IPv6;
        t.target_endpoint.addr.addr = {};
        t.target_endpoint.addr.addr[0] = 0xFE; t.target_endpoint.addr.addr[1] = 0x80;
        t.target_endpoint.addr.addr[15] = 5;
        CHECK(IssueK6TargetTicket(h, secret, sizeof(secret), t, wire) == Kad6Status::TargetForbidden, "v6 fe80");
    }
    { // a public IPv6 (2001:db8::1) is allowed
        K6TargetTicket t = MakeValidTicket();
        t.target_endpoint.addr.family = Kad6Address::Family::IPv6;
        t.target_endpoint.addr.addr = {};
        t.target_endpoint.addr.addr[0] = 0x20; t.target_endpoint.addr.addr[1] = 0x01;
        t.target_endpoint.addr.addr[2] = 0x0D; t.target_endpoint.addr.addr[3] = 0xB8;
        t.target_endpoint.addr.addr[15] = 1;
        CHECK(IssueK6TargetTicket(h, secret, sizeof(secret), t, wire) == Kad6Status::Ok, "v6 public ok");
    }
}

static void test_endpoint_roundtrip_and_truncation() {
    K6Endpoint e;
    e.addr.family = Kad6Address::Family::IPv6;
    for (Byte i = 0; i < 16; ++i) e.addr.addr[i] = static_cast<Byte>(0x10 + i);
    e.udp_port = 1234; e.tcp_port = 5678; e.transport_flags = kK6EpUdpKad6 | kK6EpTcpEd2k;
    e.priority = 3; e.observed = 1; e.valid_until = 0x0102030405060708ull;

    std::vector<Byte> w;
    CHECK(EncodeK6Endpoint(e, w) == Kad6Status::Ok, "endpoint encode");
    CHECK(w.size() == K6EndpointEncodedSize(e), "endpoint size matches");
    CHECK(w.size() == 18 + 16, "endpoint v6 wire size");

    K6Endpoint d;
    std::size_t c = 0;
    CHECK(DecodeK6Endpoint(w.data(), w.size(), d, &c) == Kad6Status::Ok, "endpoint decode");
    CHECK(c == w.size(), "endpoint consumed all");
    CHECK(d.udp_port == 1234 && d.tcp_port == 5678, "endpoint ports");
    CHECK(d.valid_until == e.valid_until, "endpoint valid_until");
    CHECK(d.addr == e.addr, "endpoint addr");

    // Truncated tail (drop the last 3 bytes) -> Truncated, no OOB.
    K6Endpoint td;
    CHECK(DecodeK6Endpoint(w.data(), w.size() - 3, td, nullptr) == Kad6Status::Truncated, "endpoint truncated tail");
}

static void test_ticket_truncation_fuzz() {
    const Kad6CryptoHooks h = Hooks();
    const Byte secret[] = {'k'};
    K6TargetTicket t = MakeValidTicket();
    std::vector<Byte> wire;
    (void)IssueK6TargetTicket(h, secret, sizeof(secret), t, wire);

    // Every proper prefix of a valid ticket must decode to Truncated/Malformed,
    // never Ok and never a crash.
    K6TargetTicket out;
    bool anyOk = false;
    for (std::size_t n = 0; n < wire.size(); ++n) {
        const Kad6Status s = DecodeK6TargetTicket(wire.data(), n, out, nullptr);
        if (s == Kad6Status::Ok) anyOk = true;
    }
    CHECK(!anyOk, "no proper prefix decodes Ok");

    // Small LCG fuzz (fixed seed): random buffers never crash, never spurious Ok.
    std::uint32_t st = 0xC0FFEEu;
    auto rnd = [&]() { st = st * 1664525u + 1013904223u; return static_cast<Byte>(st >> 24); };
    bool spuriousOk = false;
    for (int iter = 0; iter < 5000; ++iter) {
        std::size_t n = rnd() % 200;
        std::vector<Byte> buf(n);
        for (auto& b : buf) b = rnd();
        std::size_t c = 0;
        if (DecodeK6TargetTicket(buf.empty() ? nullptr : buf.data(), n, out, &c) == Kad6Status::Ok) {
            // A random buffer that happens to be structurally valid is fine, but
            // consumed must be self-consistent.
            if (c > n) spuriousOk = true;
        }
    }
    CHECK(!spuriousOk, "fuzz: consumed never exceeds input");
}

int main() {
    test_issue_verify_roundtrip();
    test_tamper_and_wrong_secret();
    test_expiry();
    test_ttl_and_range_guards();
    test_forbidden_targets();
    test_endpoint_roundtrip_and_truncation();
    test_ticket_truncation_fuzz();

    std::printf("test_kad6_ticket: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
