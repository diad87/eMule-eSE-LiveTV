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

static bool allow_target(void*, Byte, const K6Endpoint&) {
    return true;
}

static bool deny_admin_port(void*, Byte service, const K6Endpoint& endpoint) {
    const bool tcp = service == static_cast<Byte>(K6TicketService::Ed2kTcp);
    const std::uint16_t port = tcp ? endpoint.tcp_port : endpoint.udp_port;
    return port != 22 && port != 3389;
}

static bool consume_allow(void*, const K6TargetTicket&) {
    return true;
}

struct UseState { std::uint16_t used = 0; };

static bool consume_limited(void* context, const K6TargetTicket& ticket) {
    UseState* state = static_cast<UseState*>(context);
    if (!state || state->used >= ticket.max_connections)
        return false;
    ++state->used;
    return true;
}

static K6TargetPolicy Policy(bool denyAdmin = false) {
    K6TargetPolicy p{};
    p.allow_target = denyAdmin ? &deny_admin_port : &allow_target;
    p.consume_use = &consume_allow;
    return p;
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
    // Ordinary globally reachable-shaped IPv4 target (not special-purpose).
    t.target_endpoint.addr.family = Kad6Address::Family::IPv4;
    t.target_endpoint.addr.addr = {8, 8, 8, 8};
    t.target_endpoint.tcp_port = 4662;
    t.target_endpoint.udp_port = 4672;
    t.target_endpoint.valid_until = 2000;
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
    CHECK(IssueK6TargetTicket(h, Policy(), secret, sizeof(secret), t, wire) == Kad6Status::Ok, "issue ok");
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
    CHECK(VerifyK6TargetTicket(h, Policy(), secret, sizeof(secret), wire.data(), wire.size(), 1100, ver)
          == Kad6Status::Ok, "verify ok in-window");
}

static void test_tamper_and_wrong_secret() {
    const Kad6CryptoHooks h = Hooks();
    const Byte secret[] = {'s', '1'};
    const Byte other[]  = {'s', '2'};
    K6TargetTicket t = MakeValidTicket();
    std::vector<Byte> wire;
    (void)IssueK6TargetTicket(h, Policy(), secret, sizeof(secret), t, wire);

    // Flip one byte anywhere in the signed region -> MAC mismatch.
    std::vector<Byte> tampered = wire;
    tampered[5] ^= 0x01;
    K6TargetTicket out;
    CHECK(VerifyK6TargetTicket(h, Policy(), secret, sizeof(secret), tampered.data(), tampered.size(), 1100, out)
          == Kad6Status::AuthFailed, "tamper -> AuthFailed");

    // Flip a byte in the MAC itself -> mismatch.
    std::vector<Byte> tampered2 = wire;
    tampered2[tampered2.size() - 1] ^= 0x80;
    CHECK(VerifyK6TargetTicket(h, Policy(), secret, sizeof(secret), tampered2.data(), tampered2.size(), 1100, out)
          == Kad6Status::AuthFailed, "mac tamper -> AuthFailed");

    // Correct bytes but wrong secret -> mismatch.
    CHECK(VerifyK6TargetTicket(h, Policy(), other, sizeof(other), wire.data(), wire.size(), 1100, out)
          == Kad6Status::AuthFailed, "wrong secret -> AuthFailed");
}

static void test_expiry() {
    const Kad6CryptoHooks h = Hooks();
    const Byte secret[] = {'k'};
    K6TargetTicket t = MakeValidTicket(); // window [1000, 1300)
    std::vector<Byte> wire;
    (void)IssueK6TargetTicket(h, Policy(), secret, sizeof(secret), t, wire);
    K6TargetTicket out;
    CHECK(VerifyK6TargetTicket(h, Policy(), secret, sizeof(secret), wire.data(), wire.size(), 1299, out)
          == Kad6Status::Ok, "just-in-window ok");
    CHECK(VerifyK6TargetTicket(h, Policy(), secret, sizeof(secret), wire.data(), wire.size(), 1300, out)
          == Kad6Status::Expired, "expires_at boundary -> Expired");
    CHECK(VerifyK6TargetTicket(h, Policy(), secret, sizeof(secret), wire.data(), wire.size(), 5000, out)
          == Kad6Status::Expired, "way past -> Expired");
}

static void test_atomic_use_consumption() {
    const Kad6CryptoHooks h = Hooks();
    const Byte secret[] = {'u', 's', 'e'};
    K6TargetTicket t = MakeValidTicket();
    std::vector<Byte> wire;
    (void)IssueK6TargetTicket(h, Policy(), secret, sizeof(secret), t, wire);

    UseState single{};
    K6TargetPolicy singlePolicy = Policy();
    singlePolicy.context = &single;
    singlePolicy.consume_use = &consume_limited;
    K6TargetTicket out;
    CHECK(VerifyK6TargetTicket(h, singlePolicy, secret, sizeof(secret),
                              wire.data(), wire.size(), 1100, out) == Kad6Status::Ok,
          "single-use ticket first consume succeeds");
    CHECK(VerifyK6TargetTicket(h, singlePolicy, secret, sizeof(secret),
                              wire.data(), wire.size(), 1100, out) == Kad6Status::AuthFailed,
          "single-use ticket replay rejected");
    CHECK(out.lease_id == 0, "failed verify does not expose an accepted ticket");

    K6TargetPolicy missingConsume = Policy();
    missingConsume.consume_use = nullptr;
    CHECK(VerifyK6TargetTicket(h, missingConsume, secret, sizeof(secret),
                              wire.data(), wire.size(), 1100, out) == Kad6Status::BadValue,
          "missing atomic consume hook fails closed");

    K6TargetTicket reusable = MakeValidTicket();
    reusable.flags = kK6TicketFlagReusable;
    reusable.max_connections = 2;
    std::vector<Byte> reusableWire;
    (void)IssueK6TargetTicket(h, Policy(), secret, sizeof(secret), reusable, reusableWire);
    UseState twice{};
    K6TargetPolicy twicePolicy = Policy();
    twicePolicy.context = &twice;
    twicePolicy.consume_use = &consume_limited;
    CHECK(VerifyK6TargetTicket(h, twicePolicy, secret, sizeof(secret),
                              reusableWire.data(), reusableWire.size(), 1100, out) == Kad6Status::Ok,
          "reusable ticket use 1 succeeds");
    CHECK(VerifyK6TargetTicket(h, twicePolicy, secret, sizeof(secret),
                              reusableWire.data(), reusableWire.size(), 1100, out) == Kad6Status::Ok,
          "reusable ticket use 2 succeeds");
    CHECK(VerifyK6TargetTicket(h, twicePolicy, secret, sizeof(secret),
                              reusableWire.data(), reusableWire.size(), 1100, out) == Kad6Status::AuthFailed,
          "reusable ticket over max_connections rejected");
}

static void test_ttl_and_range_guards() {
    const Kad6CryptoHooks h = Hooks();
    const Byte secret[] = {'k'};
    std::vector<Byte> wire;

    { // TTL > 300 rejected at issue
        K6TargetTicket t = MakeValidTicket();
        t.expires_at = t.issued_at + 301;
        CHECK(IssueK6TargetTicket(h, Policy(), secret, sizeof(secret), t, wire) == Kad6Status::BadValue, "ttl>300 BadValue");
    }
    { // expires <= issued rejected
        K6TargetTicket t = MakeValidTicket();
        t.expires_at = t.issued_at;
        CHECK(IssueK6TargetTicket(h, Policy(), secret, sizeof(secret), t, wire) == Kad6Status::BadValue, "expires<=issued BadValue");
    }
    { // bad service
        K6TargetTicket t = MakeValidTicket();
        t.service = 9;
        CHECK(IssueK6TargetTicket(h, Policy(), secret, sizeof(secret), t, wire) == Kad6Status::BadValue, "bad service BadValue");
    }
    { // bad provenance
        K6TargetTicket t = MakeValidTicket();
        t.provenance_kind = 0;
        CHECK(IssueK6TargetTicket(h, Policy(), secret, sizeof(secret), t, wire) == Kad6Status::BadValue, "bad prov BadValue");
    }
    { // zero byte budget is ambiguous and must not mean unlimited
        K6TargetTicket t = MakeValidTicket();
        t.max_bytes = 0;
        CHECK(IssueK6TargetTicket(h, Policy(), secret, sizeof(secret), t, wire) == Kad6Status::BadValue,
              "zero max_bytes BadValue");
    }
    { // default tickets are exactly single-use
        K6TargetTicket t = MakeValidTicket();
        t.max_connections = 2;
        CHECK(IssueK6TargetTicket(h, Policy(), secret, sizeof(secret), t, wire) == Kad6Status::BadValue,
              "non-reusable max_connections>1 BadValue");
        t.flags = kK6TicketFlagReusable;
        CHECK(IssueK6TargetTicket(h, Policy(), secret, sizeof(secret), t, wire) == Kad6Status::Ok,
              "explicit reusable ticket may allow multiple connections");
    }
    { // authorization cannot outlive the endpoint that introduced the target
        K6TargetTicket t = MakeValidTicket();
        t.target_endpoint.valid_until = t.expires_at - 1;
        CHECK(IssueK6TargetTicket(h, Policy(), secret, sizeof(secret), t, wire) == Kad6Status::BadValue,
              "ticket cannot outlive endpoint");
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
        CHECK(IssueK6TargetTicket(h, Policy(), secret, sizeof(secret), t, wire) == Kad6Status::TargetForbidden, v.name);
    }
    { // port 0 for the service in use
        K6TargetTicket t = MakeValidTicket();
        t.target_endpoint.tcp_port = 0; // service is Ed2kTcp
        CHECK(IssueK6TargetTicket(h, Policy(), secret, sizeof(secret), t, wire) == Kad6Status::TargetForbidden, "tcp port 0");
    }
    { // IPv6 ::1 loopback
        K6TargetTicket t = MakeValidTicket();
        t.target_endpoint.addr.family = Kad6Address::Family::IPv6;
        t.target_endpoint.addr.addr = {};
        t.target_endpoint.addr.addr[15] = 1;
        CHECK(IssueK6TargetTicket(h, Policy(), secret, sizeof(secret), t, wire) == Kad6Status::TargetForbidden, "v6 ::1");
    }
    { // IPv6 fe80::/10 link-local
        K6TargetTicket t = MakeValidTicket();
        t.target_endpoint.addr.family = Kad6Address::Family::IPv6;
        t.target_endpoint.addr.addr = {};
        t.target_endpoint.addr.addr[0] = 0xFE; t.target_endpoint.addr.addr[1] = 0x80;
        t.target_endpoint.addr.addr[15] = 5;
        CHECK(IssueK6TargetTicket(h, Policy(), secret, sizeof(secret), t, wire) == Kad6Status::TargetForbidden, "v6 fe80");
    }
    { // an ordinary global IPv6 is allowed
        K6TargetTicket t = MakeValidTicket();
        t.target_endpoint.addr.family = Kad6Address::Family::IPv6;
        t.target_endpoint.addr.addr = {};
        t.target_endpoint.addr.addr[0] = 0x26; t.target_endpoint.addr.addr[1] = 0x06;
        t.target_endpoint.addr.addr[2] = 0x47; t.target_endpoint.addr.addr[3] = 0x00;
        t.target_endpoint.addr.addr[15] = 1;
        CHECK(IssueK6TargetTicket(h, Policy(), secret, sizeof(secret), t, wire) == Kad6Status::Ok, "v6 public ok");
    }

    const V4 special4[] = {
        {100, 64, 0, 1, "cgnat"}, {192, 0, 2, 1, "test-net-1"},
        {198, 18, 0, 1, "benchmark"}, {198, 51, 100, 1, "test-net-2"},
        {203, 0, 113, 1, "test-net-3"},
    };
    for (const V4& v : special4) {
        K6TargetTicket t = MakeValidTicket();
        t.target_endpoint.addr.addr = {v.a, v.b, v.c, v.d};
        CHECK(IssueK6TargetTicket(h, Policy(), secret, sizeof(secret), t, wire)
              == Kad6Status::TargetForbidden, v.name);
    }
    { // host policy is mandatory and may deny administrative ports
        K6TargetTicket t = MakeValidTicket();
        t.target_endpoint.tcp_port = 22;
        CHECK(IssueK6TargetTicket(h, Policy(true), secret, sizeof(secret), t, wire)
              == Kad6Status::TargetForbidden, "host policy blocks admin port");
        CHECK(IssueK6TargetTicket(h, K6TargetPolicy{}, secret, sizeof(secret), t, wire)
              == Kad6Status::BadValue, "missing host target policy fails closed");
    }
    { // a policy change after issue is re-evaluated before use
        K6TargetTicket t = MakeValidTicket();
        t.target_endpoint.tcp_port = 22;
        CHECK(IssueK6TargetTicket(h, Policy(), secret, sizeof(secret), t, wire) == Kad6Status::Ok,
              "ticket issued under old policy");
        K6TargetTicket out;
        CHECK(VerifyK6TargetTicket(h, Policy(true), secret, sizeof(secret),
                                  wire.data(), wire.size(), 1100, out)
              == Kad6Status::TargetForbidden, "verify re-evaluates current host policy");
    }
}

static void test_canonical_wire_guards() {
    const Kad6CryptoHooks h = Hooks();
    const Byte secret[] = {'k'};
    K6TargetTicket t = MakeValidTicket();
    std::vector<Byte> wire;
    CHECK(IssueK6TargetTicket(h, Policy(), secret, sizeof(secret), t, wire) == Kad6Status::Ok,
          "canonical guard helper issue");

    // reserved lives at offset 13. It is part of the canonical MAC transcript;
    // a decoder must not normalize an attacker-supplied non-zero byte to zero.
    std::vector<Byte> reserved = wire;
    reserved[13] = 1;
    K6TargetTicket out;
    CHECK(VerifyK6TargetTicket(h, Policy(), secret, sizeof(secret), reserved.data(), reserved.size(), 1100, out)
          == Kad6Status::Malformed, "reserved byte cannot bypass MAC via normalization");

    std::vector<Byte> trailing = wire;
    trailing.push_back(0xA5);
    CHECK(VerifyK6TargetTicket(h, Policy(), secret, sizeof(secret), trailing.data(), trailing.size(), 1100, out)
          == Kad6Status::Malformed, "verify rejects unauthenticated trailing bytes");
    CHECK(VerifyK6TargetTicket(h, Policy(), secret, sizeof(secret), wire.data(), wire.size(), 999, out)
          == Kad6Status::BadValue, "ticket is not valid before issued_at");
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

    // observed is a canonical boolean on both producer and consumer paths.
    std::vector<Byte> badObserved = w;
    const std::size_t observedOffset = 2 + 16 + 2 + 2 + 2 + 1;
    badObserved[observedOffset] = 2;
    CHECK(DecodeK6Endpoint(badObserved.data(), badObserved.size(), td, nullptr) ==
              Kad6Status::Malformed,
          "endpoint decode rejects observed=2");
}

static void test_ticket_truncation_fuzz() {
    const Kad6CryptoHooks h = Hooks();
    const Byte secret[] = {'k'};
    K6TargetTicket t = MakeValidTicket();
    std::vector<Byte> wire;
    (void)IssueK6TargetTicket(h, Policy(), secret, sizeof(secret), t, wire);

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
    test_atomic_use_consumption();
    test_ttl_and_range_guards();
    test_forbidden_targets();
    test_canonical_wire_guards();
    test_endpoint_roundtrip_and_truncation();
    test_ticket_truncation_fuzz();

    std::printf("test_kad6_ticket: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
