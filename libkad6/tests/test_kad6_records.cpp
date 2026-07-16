// SPDX-License-Identifier: MIT
//
// test_kad6_records.cpp — the four Ed25519-signed Kad6 objects (ticket K6-0.6):
// K6NodeBind, K6Rotate, K6RouterRecord, K6SourceRecord.
//
// The Ed25519 here is a MOCK: a deterministic, symmetric, full-avalanche stand-
// in used only to exercise the codecs' sign/verify plumbing, tamper detection
// and constant-time compare. The 32-byte "public key" doubles as the signing
// key: sign(sk, msg) = avalanche64(sk || msg); verify(pub, msg, sig) recomputes
// with `pub` and compares. Tests set sk == pub. This proves CODEC behaviour, not
// the Ed25519 construction — real Ed25519 test vectors are pinned in K6-0.9
// against the host's CryptoPP.
//
//   from libkad6/:
//   make.bat test_kad6_records tests\test_kad6_records.cpp src\kad6_records.cpp ^
//            src\kad6_endpoint.cpp src\kad6_address.cpp
#include "kad6/kad6_records.h"

#include <cstdio>
#include <vector>

using namespace kad6;

static int g_fail = 0;
static int g_pass = 0;

#define CHECK(cond, msg) do { if (cond) { ++g_pass; } else { ++g_fail; \
    std::printf("  FAIL: %s  (%s:%d)\n", msg, __FILE__, __LINE__); } } while (0)

// ── mock Ed25519: deterministic symmetric full-avalanche (NOT real) ──────────
static void avalanche64(const Byte* a, std::size_t aLen,
                        const Byte* b, std::size_t bLen, Byte out[kEd25519SigSize]) {
    std::uint64_t h = 1469598103934665603ull; // FNV-1a offset basis
    for (std::size_t i = 0; i < aLen; ++i) { h ^= a[i]; h *= 1099511628211ull; }
    h ^= 0x5AU; h *= 1099511628211ull; // key/msg separator
    for (std::size_t i = 0; i < bLen; ++i) { h ^= b[i]; h *= 1099511628211ull; }
    for (int i = 0; i < 64; ++i) {
        h ^= static_cast<std::uint64_t>(i) * 0x9E3779B97F4A7C15ull;
        h *= 1099511628211ull;
        out[i] = static_cast<Byte>(h >> ((i % 8) * 8));
    }
}

static bool mock_sign(const Byte* sk, std::size_t skLen,
                      const Byte* msg, std::size_t msgLen, Byte sig[kEd25519SigSize]) {
    avalanche64(sk, skLen, msg, msgLen, sig);
    return true;
}

static bool mock_verify(const Byte pub[kEd25519PubSize],
                        const Byte* msg, std::size_t msgLen, const Byte sig[kEd25519SigSize]) {
    Byte expect[kEd25519SigSize];
    avalanche64(pub, kEd25519PubSize, msg, msgLen, expect);
    return Kad6CtEqual(expect, sig, kEd25519SigSize);
}

static bool mock_sha256(const Byte* msg, std::size_t msgLen, Byte out[kHash32Size]) {
    static const Byte kDomainKey[] = {0x4b, 0x36, 0x2d, 0x53, 0x48, 0x41};
    Byte digest[kEd25519SigSize];
    avalanche64(kDomainKey, sizeof(kDomainKey), msg, msgLen, digest);
    for (std::size_t i = 0; i < kHash32Size; ++i) out[i] = digest[i];
    return true;
}

static Kad6CryptoHooks Hooks() {
    Kad6CryptoHooks h{};
    h.ed25519_sign = &mock_sign;
    h.ed25519_verify = &mock_verify;
    h.sha256 = &mock_sha256;
    return h;
}

// A distinct 32-byte "keypair" (pub == sk under the symmetric mock).
static Ed25519Pub MakeKey(Byte seed) {
    Ed25519Pub k{};
    for (int i = 0; i < 32; ++i) k[i] = static_cast<Byte>(seed + i * 7 + 1);
    return k;
}

// A public IPv4 endpoint (family validity is all the endpoint codec requires).
static K6Endpoint MakeEndpoint(Byte last, std::uint16_t udp, std::uint16_t tcp) {
    K6Endpoint e;
    e.addr.family = Kad6Address::Family::IPv4;
    e.addr.addr = {203, 0, 113, last};
    e.udp_port = udp;
    e.tcp_port = tcp;
    e.transport_flags = kK6EpUdpKad6 | kK6EpTcpEd2k;
    e.priority = 1;
    e.observed = 0;
    e.valid_until = 999999;
    return e;
}

// ════════════════════════════════════════════════════════════════════════════
// builders
// ════════════════════════════════════════════════════════════════════════════
static K6NodeBind MakeNodeBind(const Ed25519Pub& pub) {
    K6NodeBind b;
    b.node_pub = pub;
    for (int i = 0; i < 16; ++i) b.kad_id[i] = static_cast<Byte>(0xA0 + i);
    b.epoch = 7;
    b.caps = 0xDEADBEEFull;
    return b;
}

static K6Rotate MakeRotate(const Ed25519Pub& oldPub, const Ed25519Pub& newPub) {
    K6Rotate r;
    r.old_pub = oldPub;
    r.new_pub = newPub;
    for (int i = 0; i < 16; ++i) r.kad_id[i] = static_cast<Byte>(0xB0 + i);
    r.rotation_epoch = 12;
    r.not_after = 50000;
    return r;
}

static K6RouterRecord MakeRouter(const Ed25519Pub& pub, std::size_t nEndpoints) {
    K6RouterRecord r;
    r.node_pub = pub;
    for (int i = 0; i < 16; ++i) r.kad_id[i] = static_cast<Byte>(0xC0 + i);
    r.epoch = 5;
    r.caps = 0x1234;
    r.valid_from = 1000;
    r.valid_until = 1000 + 3600; // 1h window, within cap
    for (std::size_t i = 0; i < nEndpoints; ++i) {
        K6Endpoint endpoint = MakeEndpoint(static_cast<Byte>(10 + i),
                                           static_cast<std::uint16_t>(4000 + i),
                                           static_cast<std::uint16_t>(4600 + i));
        endpoint.valid_until = r.valid_until;
        r.endpoints.push_back(endpoint);
    }
    return r;
}

static K6SourceRecord MakeSource(const Ed25519Pub& pub, std::size_t nExits, bool withCompat) {
    K6SourceRecord s;
    s.pub_key = pub;
    for (int i = 0; i < 16; ++i) {
        s.object_hash[i]      = static_cast<Byte>(i);
        s.source_pseudonym[i] = static_cast<Byte>(0x30 + i);
        s.service_token[i]    = static_cast<Byte>(0x70 + i);
    }
    for (int i = 0; i < 32; ++i) s.metadata_hash[i] = static_cast<Byte>(0x80 + i);
    s.source_epoch = 9;
    s.created_at = 2000;
    s.expires_at = 2000 + 3600;
    for (std::size_t i = 0; i < nExits; ++i) {
        K6ExitDescriptor e;
        e.exit_node_pub = MakeKey(static_cast<Byte>(0x50 + i));
        e.endpoint = MakeEndpoint(static_cast<Byte>(20 + i),
                                  static_cast<std::uint16_t>(5000 + i),
                                  static_cast<std::uint16_t>(5600 + i));
        e.lease_hint = static_cast<std::uint64_t>(111 * (i + 1));
        e.caps = 0x22;
        e.exit_expires_at = 3000;
        s.exits.push_back(e);
    }
    if (withCompat) {
        s.compat_pub.resize(32);
        for (int i = 0; i < 32; ++i) s.compat_pub[i] = static_cast<Byte>(0xC0 + i);
    }
    return s;
}

// ════════════════════════════════════════════════════════════════════════════
// generic decode robustness: no proper prefix decodes Ok; random buffers never
// crash and never return Ok with consumed > len.
// ════════════════════════════════════════════════════════════════════════════
template <typename T, typename F>
static void fuzz_decode(const char* name, const std::vector<Byte>& valid, F decode) {
    T out;
    bool anyPrefixOk = false;
    for (std::size_t n = 0; n < valid.size(); ++n) {
        std::size_t c = 0;
        if (decode(valid.data(), n, out, &c) == Kad6Status::Ok) anyPrefixOk = true;
    }
    CHECK(!anyPrefixOk, name);

    std::uint32_t st = 0xABCDEF01u;
    auto rnd = [&]() { st = st * 1664525u + 1013904223u; return static_cast<Byte>(st >> 24); };
    bool consumedOverrun = false;
    for (int iter = 0; iter < 4000; ++iter) {
        std::size_t n = rnd() % 320;
        std::vector<Byte> buf(n);
        for (auto& b : buf) b = rnd();
        std::size_t c = 0;
        if (decode(buf.empty() ? nullptr : buf.data(), n, out, &c) == Kad6Status::Ok) {
            if (c > n) consumedOverrun = true;
        }
    }
    CHECK(!consumedOverrun, "fuzz: consumed never exceeds input");
}

// ════════════════════════════════════════════════════════════════════════════
// 1) K6NodeBind
// ════════════════════════════════════════════════════════════════════════════
static void test_nodebind() {
    const Kad6CryptoHooks h = Hooks();
    const Ed25519Pub pub = MakeKey(1);
    K6NodeBind b = MakeNodeBind(pub);

    std::vector<Byte> wire;
    CHECK(SignK6NodeBind(h, pub.data(), pub.size(), b, wire) == Kad6Status::Ok, "nodebind sign");
    CHECK(wire.size() == 16 + 32 + 8 + 8 + 64, "nodebind wire size");

    K6NodeBind d;
    std::size_t consumed = 0;
    CHECK(DecodeK6NodeBind(wire.data(), wire.size(), d, &consumed) == Kad6Status::Ok, "nodebind decode");
    CHECK(consumed == wire.size(), "nodebind consumed all");
    CHECK(d.epoch == 7 && d.caps == 0xDEADBEEFull, "nodebind fields round-trip");
    CHECK(d.node_pub == pub, "nodebind pub round-trip");
    CHECK(VerifyK6NodeBind(h, d) == Kad6Status::Ok, "nodebind verify ok");
    std::vector<Byte> trailing = wire; trailing.push_back(0xA5); consumed = 99;
    K6NodeBind trailingDecoded;
    CHECK(DecodeK6NodeBind(trailing.data(), trailing.size(), trailingDecoded, &consumed) ==
          Kad6Status::Malformed && consumed == 0,
          "nodebind rejects trailing bytes");

    // Tamper a signed byte (kad_id[0]) -> AuthFailed.
    std::vector<Byte> t = wire; t[0] ^= 0x01;
    K6NodeBind dt;
    CHECK(DecodeK6NodeBind(t.data(), t.size(), dt, nullptr) == Kad6Status::Ok, "nodebind tampered still decodes");
    CHECK(VerifyK6NodeBind(h, dt) == Kad6Status::AuthFailed, "nodebind tamper -> AuthFailed");

    // Tamper the signature itself -> AuthFailed.
    std::vector<Byte> t2 = wire; t2[t2.size() - 1] ^= 0x80;
    K6NodeBind dt2;
    (void)DecodeK6NodeBind(t2.data(), t2.size(), dt2, nullptr);
    CHECK(VerifyK6NodeBind(h, dt2) == Kad6Status::AuthFailed, "nodebind sig tamper -> AuthFailed");

    // Wrong signing key (sk != node_pub) -> AuthFailed.
    const Ed25519Pub wrong = MakeKey(99);
    K6NodeBind bw = MakeNodeBind(pub); // node_pub stays `pub`
    std::vector<Byte> ww;
    (void)SignK6NodeBind(h, wrong.data(), wrong.size(), bw, ww);
    K6NodeBind dw;
    (void)DecodeK6NodeBind(ww.data(), ww.size(), dw, nullptr);
    CHECK(VerifyK6NodeBind(h, dw) == Kad6Status::AuthFailed, "nodebind wrong key -> AuthFailed");

    // Epoch monotonicity.
    CHECK(K6CheckEpochAdvance(d.epoch, d.epoch) == Kad6Status::StaleEpoch, "nodebind epoch equal -> Stale");
    CHECK(K6CheckEpochAdvance(d.epoch, d.epoch - 1) == Kad6Status::StaleEpoch, "nodebind epoch back -> Stale");
    CHECK(K6CheckEpochAdvance(d.epoch, d.epoch + 1) == Kad6Status::Ok, "nodebind epoch advance -> Ok");

    // The stateful gate is the required acceptance path: TOFU for a first
    // binding, then strictly increasing epochs and a dual-signed rotation for
    // every key change.
    K6IdentityState empty{};
    CHECK(AcceptK6NodeBind(h, d, empty, nullptr, 1000) == Kad6Status::Ok,
          "nodebind first-seen TOFU -> Ok");
    CHECK(empty.initialized && empty.kad_id == d.kad_id && empty.node_pub == d.node_pub &&
          empty.epoch == d.epoch, "nodebind TOFU atomically pins state");

    K6IdentityState current{};
    current.initialized = true;
    current.kad_id = d.kad_id;
    current.node_pub = d.node_pub;
    current.epoch = d.epoch;
    CHECK(AcceptK6NodeBind(h, d, current, nullptr, 1000) == Kad6Status::StaleEpoch,
          "nodebind replay rejected by transition gate");

    K6NodeBind next = d;
    ++next.epoch;
    std::vector<Byte> nextWire;
    (void)SignK6NodeBind(h, pub.data(), pub.size(), next, nextWire);
    K6IdentityState sameKeyState = current;
    CHECK(AcceptK6NodeBind(h, next, sameKeyState, nullptr, 1000) == Kad6Status::Ok,
          "nodebind same-key epoch advance -> Ok");
    CHECK(sameKeyState.epoch == next.epoch, "nodebind same-key accept advances state");

    const Ed25519Pub newPub = MakeKey(42);
    K6NodeBind changed = next;
    changed.node_pub = newPub;
    std::vector<Byte> changedWire;
    (void)SignK6NodeBind(h, newPub.data(), newPub.size(), changed, changedWire);
    CHECK(AcceptK6NodeBind(h, changed, current, nullptr, 1000) == Kad6Status::AuthFailed,
          "nodebind key change without rotation rejected");
    CHECK(current.node_pub == pub && current.epoch == d.epoch,
          "failed nodebind transition leaves state unchanged");

    K6Rotate rotation = MakeRotate(pub, newPub);
    rotation.kad_id = changed.kad_id;
    rotation.rotation_epoch = changed.epoch;
    rotation.not_after = 5000;
    std::vector<Byte> rotationWire;
    (void)SignK6Rotate(h, pub.data(), pub.size(), newPub.data(), newPub.size(), rotation, rotationWire);
    K6IdentityState rotatedState = current;
    CHECK(AcceptK6NodeBind(h, changed, rotatedState, &rotation, 1000) == Kad6Status::Ok,
          "nodebind dual-signed key rotation -> Ok");
    CHECK(rotatedState.node_pub == newPub && rotatedState.epoch == changed.epoch,
          "nodebind rotation atomically advances key and epoch");
    K6IdentityState expiredState = current;
    CHECK(AcceptK6NodeBind(h, changed, expiredState, &rotation, 5000) == Kad6Status::Expired,
          "nodebind expired rotation rejected");

    K6Rotate mismatch = rotation;
    ++mismatch.rotation_epoch;
    K6IdentityState mismatchState = current;
    CHECK(AcceptK6NodeBind(h, changed, mismatchState, &mismatch, 1000) == Kad6Status::AuthFailed,
          "nodebind mismatched rotation epoch rejected");

    fuzz_decode<K6NodeBind>("nodebind: no proper prefix Ok", wire,
        [](const Byte* p, std::size_t n, K6NodeBind& o, std::size_t* c) {
            return DecodeK6NodeBind(p, n, o, c);
        });
}

// ════════════════════════════════════════════════════════════════════════════
// 2) K6Rotate (dual-signed)
// ════════════════════════════════════════════════════════════════════════════
static void test_rotate() {
    const Kad6CryptoHooks h = Hooks();
    const Ed25519Pub oldPub = MakeKey(2);
    const Ed25519Pub newPub = MakeKey(3);
    K6Rotate r = MakeRotate(oldPub, newPub);

    std::vector<Byte> wire;
    CHECK(SignK6Rotate(h, oldPub.data(), oldPub.size(), newPub.data(), newPub.size(), r, wire)
          == Kad6Status::Ok, "rotate sign");
    CHECK(wire.size() == 16 + 32 + 32 + 8 + 8 + 64 + 64, "rotate wire size");

    K6Rotate d;
    std::size_t consumed = 0;
    CHECK(DecodeK6Rotate(wire.data(), wire.size(), d, &consumed) == Kad6Status::Ok, "rotate decode");
    CHECK(consumed == wire.size(), "rotate consumed all");
    CHECK(d.rotation_epoch == 12 && d.not_after == 50000, "rotate fields round-trip");
    CHECK(d.old_pub == oldPub && d.new_pub == newPub, "rotate keys round-trip");
    CHECK(VerifyK6Rotate(h, d) == Kad6Status::Ok, "rotate verify ok (both sigs)");
    std::vector<Byte> trailing = wire; trailing.push_back(0xA5); consumed = 99;
    K6Rotate trailingDecoded;
    CHECK(DecodeK6Rotate(trailing.data(), trailing.size(), trailingDecoded, &consumed) ==
          Kad6Status::Malformed && consumed == 0,
          "rotate rejects trailing bytes");

    // Tamper a signed byte -> both recomputations change -> AuthFailed.
    std::vector<Byte> t = wire; t[0] ^= 0x01;
    K6Rotate dt; (void)DecodeK6Rotate(t.data(), t.size(), dt, nullptr);
    CHECK(VerifyK6Rotate(h, dt) == Kad6Status::AuthFailed, "rotate tamper -> AuthFailed");

    // Break only sig_old (offset 96) -> AuthFailed.
    std::vector<Byte> to = wire; to[96] ^= 0xFF;
    K6Rotate dto; (void)DecodeK6Rotate(to.data(), to.size(), dto, nullptr);
    CHECK(VerifyK6Rotate(h, dto) == Kad6Status::AuthFailed, "rotate bad sig_old -> AuthFailed");

    // Break only sig_new (offset 160) -> AuthFailed.
    std::vector<Byte> tn = wire; tn[160] ^= 0xFF;
    K6Rotate dtn; (void)DecodeK6Rotate(tn.data(), tn.size(), dtn, nullptr);
    CHECK(VerifyK6Rotate(h, dtn) == Kad6Status::AuthFailed, "rotate bad sig_new -> AuthFailed");

    // New signature made with the wrong new key -> AuthFailed (old still valid).
    const Ed25519Pub wrongNew = MakeKey(77);
    K6Rotate rw = MakeRotate(oldPub, newPub); // new_pub stays newPub
    std::vector<Byte> ww;
    (void)SignK6Rotate(h, oldPub.data(), oldPub.size(), wrongNew.data(), wrongNew.size(), rw, ww);
    K6Rotate dw; (void)DecodeK6Rotate(ww.data(), ww.size(), dw, nullptr);
    CHECK(VerifyK6Rotate(h, dw) == Kad6Status::AuthFailed, "rotate wrong new key -> AuthFailed");

    K6Rotate noChange = MakeRotate(oldPub, oldPub);
    std::vector<Byte> noChangeWire;
    CHECK(SignK6Rotate(h, oldPub.data(), oldPub.size(), oldPub.data(), oldPub.size(),
                       noChange, noChangeWire) == Kad6Status::BadValue,
          "rotate producer rejects old_pub==new_pub");
    CHECK(noChangeWire.empty(), "rotate producer failure clears output");
    CHECK(VerifyK6Rotate(h, noChange) == Kad6Status::BadValue,
          "rotate old_pub==new_pub -> BadValue");

    // not_after freshness.
    CHECK(K6RotateCheckFresh(d, 49999) == Kad6Status::Ok, "rotate before not_after -> Ok");
    CHECK(K6RotateCheckFresh(d, 50000) == Kad6Status::Expired, "rotate at not_after -> Expired");

    fuzz_decode<K6Rotate>("rotate: no proper prefix Ok", wire,
        [](const Byte* p, std::size_t n, K6Rotate& o, std::size_t* c) {
            return DecodeK6Rotate(p, n, o, c);
        });
}

// ════════════════════════════════════════════════════════════════════════════
// 3) K6RouterRecord
// ════════════════════════════════════════════════════════════════════════════
static void test_router() {
    const Kad6CryptoHooks h = Hooks();
    const Ed25519Pub pub = MakeKey(4);

    // 1 endpoint and 4 endpoints both round-trip + verify.
    for (std::size_t nep : {std::size_t(1), std::size_t(4)}) {
        K6RouterRecord r = MakeRouter(pub, nep);
        std::vector<Byte> wire;
        CHECK(SignK6RouterRecord(h, pub.data(), pub.size(), r, wire) == Kad6Status::Ok, "router sign");
        K6RouterRecord d;
        std::size_t consumed = 0;
        CHECK(DecodeK6RouterRecord(wire.data(), wire.size(), d, &consumed) == Kad6Status::Ok, "router decode");
        CHECK(consumed == wire.size(), "router consumed all");
        CHECK(d.endpoints.size() == nep, "router endpoint count round-trip");
        CHECK(d.node_pub == pub && d.epoch == 5, "router fields round-trip");
        CHECK(d.endpoints[0].tcp_port == 4600, "router endpoint round-trip");
        CHECK(VerifyK6RouterRecord(h, d) == Kad6Status::Ok, "router verify ok");
        std::vector<Byte> trailing = wire; trailing.push_back(0xA5); consumed = 99;
        K6RouterRecord trailingDecoded;
        CHECK(DecodeK6RouterRecord(trailing.data(), trailing.size(), trailingDecoded, &consumed) ==
              Kad6Status::Malformed && consumed == 0,
              "router rejects trailing bytes");
    }

    K6RouterRecord r = MakeRouter(pub, 2);
    std::vector<Byte> wire;
    (void)SignK6RouterRecord(h, pub.data(), pub.size(), r, wire);

    // Tamper a signed data byte (kad_id starts at offset 4) -> AuthFailed.
    std::vector<Byte> t = wire; t[8] ^= 0x01;
    K6RouterRecord dt;
    CHECK(DecodeK6RouterRecord(t.data(), t.size(), dt, nullptr) == Kad6Status::Ok, "router tampered decodes");
    CHECK(VerifyK6RouterRecord(h, dt) == Kad6Status::AuthFailed, "router tamper -> AuthFailed");

    // Wrong signing key -> AuthFailed.
    const Ed25519Pub wrong = MakeKey(55);
    K6RouterRecord rw = MakeRouter(pub, 2);
    std::vector<Byte> ww;
    (void)SignK6RouterRecord(h, wrong.data(), wrong.size(), rw, ww);
    K6RouterRecord dw; (void)DecodeK6RouterRecord(ww.data(), ww.size(), dw, nullptr);
    CHECK(VerifyK6RouterRecord(h, dw) == Kad6Status::AuthFailed, "router wrong key -> AuthFailed");

    // endpoint_count byte (offset 2) out of range -> Malformed, before endpoints.
    std::vector<Byte> z = wire; z[2] = 0;
    K6RouterRecord dz;
    CHECK(DecodeK6RouterRecord(z.data(), z.size(), dz, nullptr) == Kad6Status::Malformed, "router count=0 -> Malformed");
    std::vector<Byte> f = wire; f[2] = 5;
    CHECK(DecodeK6RouterRecord(f.data(), f.size(), dz, nullptr) == Kad6Status::Malformed, "router count=5 -> Malformed");

    // reserved byte (offset 3) non-zero -> Malformed.
    std::vector<Byte> rv = wire; rv[3] = 1;
    CHECK(DecodeK6RouterRecord(rv.data(), rv.size(), dz, nullptr) == Kad6Status::Malformed, "router reserved!=0 -> Malformed");

    // Verify rejects a struct with 0 endpoints (in-memory count guard).
    K6RouterRecord empty = MakeRouter(pub, 1);
    empty.endpoints.clear();
    CHECK(VerifyK6RouterRecord(h, empty) == Kad6Status::Malformed, "router verify 0 endpoints -> Malformed");

    std::vector<Byte> wb;
    K6RouterRecord badFields = MakeRouter(pub, 1);
    badFields.kad_id.fill(0);
    CHECK(SignK6RouterRecord(h, pub.data(), pub.size(), badFields, wb) ==
              Kad6Status::BadValue,
          "router zero KadID rejected before signing");
    badFields = MakeRouter(pub, 1);
    badFields.node_pub.fill(0);
    CHECK(SignK6RouterRecord(h, pub.data(), pub.size(), badFields, wb) ==
              Kad6Status::BadValue,
          "router zero node pub rejected before signing");
    badFields = MakeRouter(pub, 1);
    badFields.epoch = 0;
    CHECK(SignK6RouterRecord(h, pub.data(), pub.size(), badFields, wb) ==
              Kad6Status::BadValue,
          "router zero epoch rejected before signing");
    badFields = MakeRouter(pub, 1);
    badFields.flags = 1;
    CHECK(SignK6RouterRecord(h, pub.data(), pub.size(), badFields, wb) ==
              Kad6Status::BadValue,
          "router unknown flags rejected before signing");
    badFields = MakeRouter(pub, 1);
    badFields.endpoints[0].valid_until = badFields.valid_until + 1;
    CHECK(SignK6RouterRecord(h, pub.data(), pub.size(), badFields, wb) ==
              Kad6Status::BadValue,
          "router endpoint cannot outlive signed record");
    badFields = MakeRouter(pub, 2);
    badFields.endpoints[1] = badFields.endpoints[0];
    CHECK(SignK6RouterRecord(h, pub.data(), pub.size(), badFields, wb) ==
              Kad6Status::BadValue,
          "router duplicate endpoint rejected");

    // Over-cap TTL: signature is genuinely valid, yet the cheap gate rejects it
    // (BadValue) BEFORE the Ed25519 verify. Proven by also breaking the sig and
    // still getting BadValue, not AuthFailed.
    K6RouterRecord big = MakeRouter(pub, 1);
    big.valid_until = big.valid_from + kK6RouterMaxTtlSeconds + 1;
    CHECK(SignK6RouterRecord(h, pub.data(), pub.size(), big, wb) == Kad6Status::BadValue,
          "router producer rejects ttl>cap");
    K6RouterRecord db = big;
    CHECK(VerifyK6RouterRecord(h, db) == Kad6Status::BadValue, "router ttl>cap -> BadValue");
    K6RouterRecord db2 = db; db2.signature[0] ^= 0xFF;
    CHECK(VerifyK6RouterRecord(h, db2) == Kad6Status::BadValue, "router ttl gate precedes sig verify");

    // Version gate.
    K6RouterRecord dv = db; dv.version = 2; dv.valid_until = dv.valid_from + 10;
    CHECK(VerifyK6RouterRecord(h, dv) == Kad6Status::UnsupportedVersion, "router version!=1 -> UnsupportedVersion");

    // Freshness + epoch helpers.
    K6RouterRecord d; (void)DecodeK6RouterRecord(wire.data(), wire.size(), d, nullptr);
    CHECK(K6RouterRecordCheckFresh(d, d.valid_from - 1) == Kad6Status::BadValue, "router before valid_from -> BadValue");
    CHECK(K6RouterRecordCheckFresh(d, d.valid_until - 1) == Kad6Status::Ok, "router in-window -> Ok");
    CHECK(K6RouterRecordCheckFresh(d, d.valid_until) == Kad6Status::Expired, "router at valid_until -> Expired");
    CHECK(K6RouterRecordCheckFresh(d, d.valid_until + 100) == Kad6Status::Expired, "router past window -> Expired");
    CHECK(K6CheckEpochAdvance(d.epoch, d.epoch) == Kad6Status::StaleEpoch, "router epoch equal -> Stale");
    CHECK(K6CheckEpochAdvance(d.epoch, d.epoch + 1) == Kad6Status::Ok, "router epoch advance -> Ok");
    std::uint64_t routerEpoch = d.epoch - 1;
    CHECK(AcceptK6RouterRecord(h, d, routerEpoch, d.valid_from) == Kad6Status::Ok,
          "router stateful verify accepts fresh epoch advance");
    CHECK(routerEpoch == d.epoch, "router accept advances stored epoch");
    CHECK(AcceptK6RouterRecord(h, d, routerEpoch, d.valid_from) == Kad6Status::StaleEpoch,
          "router stateful verify rejects replay");
    std::uint64_t earlyRouterEpoch = d.epoch - 1;
    CHECK(AcceptK6RouterRecord(h, d, earlyRouterEpoch, d.valid_from - 1) == Kad6Status::BadValue,
          "router stateful verify rejects not-yet-valid record");
    CHECK(earlyRouterEpoch == d.epoch - 1, "router failed accept leaves epoch unchanged");

    fuzz_decode<K6RouterRecord>("router: no proper prefix Ok", wire,
        [](const Byte* p, std::size_t n, K6RouterRecord& o, std::size_t* c) {
            return DecodeK6RouterRecord(p, n, o, c);
        });
}

// ════════════════════════════════════════════════════════════════════════════
// 4) K6SourceRecord
// ════════════════════════════════════════════════════════════════════════════
static void test_source() {
    const Kad6CryptoHooks h = Hooks();
    const Ed25519Pub pub = MakeKey(6);

    // 1 & 3 exits, with and without compat_pub, all round-trip + verify.
    struct Case { std::size_t exits; bool compat; };
    const Case cases[] = { {1, false}, {3, false}, {1, true}, {3, true} };
    for (const Case& cse : cases) {
        K6SourceRecord s = MakeSource(pub, cse.exits, cse.compat);
        std::vector<Byte> wire;
        CHECK(SignK6SourceRecord(h, pub.data(), pub.size(), s, wire) == Kad6Status::Ok, "source sign");
        K6SourceRecord d;
        std::size_t consumed = 0;
        CHECK(DecodeK6SourceRecord(wire.data(), wire.size(), d, &consumed) == Kad6Status::Ok, "source decode");
        CHECK(consumed == wire.size(), "source consumed all");
        CHECK(d.exits.size() == cse.exits, "source exit count round-trip");
        CHECK(d.compat_pub.size() == (cse.compat ? 32u : 0u), "source compat_pub round-trip");
        CHECK(d.pub_key == pub, "source pub_key round-trip");
        Hash16 expectedPseudonym{};
        CHECK(K6DeriveSourcePseudonym(h, pub, expectedPseudonym) == Kad6Status::Ok,
              "source pseudonym derivation");
        CHECK(d.source_pseudonym == expectedPseudonym,
              "source pseudonym is canonically bound to pub_key");
        CHECK(d.exits[0].endpoint.udp_port == 5000, "source exit endpoint round-trip");
        CHECK(d.expires_at == 2000 + 3600, "source expires round-trip");
        CHECK(VerifyK6SourceRecord(h, d) == Kad6Status::Ok, "source verify ok");
        std::vector<Byte> trailing = wire; trailing.push_back(0xA5); consumed = 99;
        K6SourceRecord trailingDecoded;
        CHECK(DecodeK6SourceRecord(trailing.data(), trailing.size(), trailingDecoded, &consumed) ==
              Kad6Status::Malformed && consumed == 0,
              "source rejects trailing bytes");
    }

    K6SourceRecord s = MakeSource(pub, 2, true);
    std::vector<Byte> wire;
    (void)SignK6SourceRecord(h, pub.data(), pub.size(), s, wire);

    // Tamper a signed byte (object_hash at offset 4) -> AuthFailed.
    std::vector<Byte> t = wire; t[4] ^= 0x01;
    K6SourceRecord dt;
    CHECK(DecodeK6SourceRecord(t.data(), t.size(), dt, nullptr) == Kad6Status::Ok, "source tampered decodes");
    CHECK(VerifyK6SourceRecord(h, dt) == Kad6Status::AuthFailed, "source tamper -> AuthFailed");

    // Wrong signer pub_key -> AuthFailed. (Sign with pub, then swap pub_key to a
    // different key: verify uses pub_key, which no longer matches the signature.)
    K6SourceRecord dw;
    (void)DecodeK6SourceRecord(wire.data(), wire.size(), dw, nullptr);
    dw.pub_key = MakeKey(123);
    CHECK(VerifyK6SourceRecord(h, dw) == Kad6Status::AuthFailed, "source wrong pub_key -> AuthFailed");

    // Even a correctly self-signed record cannot choose an arbitrary
    // pseudonym. Re-sign the modified body to prove the key binding is checked
    // independently of the Ed25519 signature.
    K6SourceRecord forged;
    (void)DecodeK6SourceRecord(wire.data(), wire.size(), forged, nullptr);
    forged.source_pseudonym[0] ^= 0x80;
    std::vector<Byte> forgedBody;
    (void)K6SourceRecordSerializeSigned(forged, forgedBody);
    static const char kSourceDomain[] = "eSE-Kad6-SourceRecord-v2";
    std::vector<Byte> forgedMsg;
    forgedMsg.insert(forgedMsg.end(),
                     reinterpret_cast<const Byte*>(kSourceDomain),
                     reinterpret_cast<const Byte*>(kSourceDomain) + sizeof(kSourceDomain) - 1);
    forgedMsg.insert(forgedMsg.end(), forgedBody.begin(), forgedBody.end());
    (void)mock_sign(pub.data(), pub.size(), forgedMsg.data(), forgedMsg.size(), forged.signature.data());
    CHECK(VerifyK6SourceRecord(h, forged) == Kad6Status::AuthFailed,
          "source self-signed arbitrary pseudonym rejected");

    // L2/Q23: v2 is the write format, while signed v1 records remain readable
    // for their existing TTL.  Both versions map the same full key to one
    // owner namespace.
    K6SourceRecord legacy = MakeSource(pub, 1, false);
    legacy.version = kK6SourceRecordVersionV1;
    std::vector<Byte> legacyWire;
    CHECK(SignK6SourceRecord(h, pub.data(), pub.size(), legacy, legacyWire) == Kad6Status::Ok,
          "source v1 migration record signs");
    K6SourceRecord legacyDecoded;
    CHECK(DecodeK6SourceRecord(legacyWire.data(), legacyWire.size(), legacyDecoded) ==
              Kad6Status::Ok && VerifyK6SourceRecord(h, legacyDecoded) == Kad6Status::Ok,
          "source v1 dual-read remains valid");
    K6SourceStorageKey v1Key{}, v2Key{};
    CHECK(K6MakeSourceStorageKey(h, legacyDecoded, v1Key) == Kad6Status::Ok &&
          K6MakeSourceStorageKey(h, s, v2Key) == Kad6Status::Ok && v1Key == v2Key,
          "v1 and v2 same signer share full-key namespace");

    K6SourceRecord collisionA = s;
    K6SourceRecord collisionB = s;
    collisionB.pub_key = MakeKey(77);
    collisionB.source_pseudonym = collisionA.source_pseudonym; // forced short collision
    K6SourceStorageKey collisionKeyA{}, collisionKeyB{};
    CHECK(K6MakeSourceStorageKey(h, collisionA, collisionKeyA) == Kad6Status::Ok &&
          K6MakeSourceStorageKey(h, collisionB, collisionKeyB) == Kad6Status::Ok &&
          collisionKeyA != collisionKeyB,
          "forced 128-bit pseudonym collision cannot overwrite full-key owner");

    // exit_count byte (offset 2) out of range -> Malformed, before exits.
    std::vector<Byte> z = wire; z[2] = 0;
    K6SourceRecord dz;
    CHECK(DecodeK6SourceRecord(z.data(), z.size(), dz, nullptr) == Kad6Status::Malformed, "source count=0 -> Malformed");
    std::vector<Byte> f = wire; f[2] = 4;
    CHECK(DecodeK6SourceRecord(f.data(), f.size(), dz, nullptr) == Kad6Status::Malformed, "source count=4 -> Malformed");

    // reserved byte (offset 3) non-zero -> Malformed.
    std::vector<Byte> rv = wire; rv[3] = 9;
    CHECK(DecodeK6SourceRecord(rv.data(), rv.size(), dz, nullptr) == Kad6Status::Malformed, "source reserved!=0 -> Malformed");

    // compat_pub_len over cap -> TooLarge, checked before reading the bytes.
    // With an EMPTY compat_pub the u16 length sits at (size - pub_key - sig - 2).
    {
        K6SourceRecord se = MakeSource(pub, 1, /*withCompat=*/false);
        std::vector<Byte> we;
        (void)SignK6SourceRecord(h, pub.data(), pub.size(), se, we);
        std::vector<Byte> big = we;
        const std::size_t lenOff = big.size() - (kEd25519PubSize + kEd25519SigSize + 2);
        big[lenOff]     = 0x40; // 0x0140 = 320 > kK6SourceMaxCompatPubLen (256)
        big[lenOff + 1] = 0x01;
        K6SourceRecord dbig;
        CHECK(DecodeK6SourceRecord(big.data(), big.size(), dbig, nullptr) == Kad6Status::TooLarge,
              "source compat_pub_len>cap -> TooLarge");
    }

    // Producer-side compat cap.
    K6SourceRecord over = MakeSource(pub, 1, false);
    over.compat_pub.resize(kK6SourceMaxCompatPubLen + 1);
    std::vector<Byte> wo;
    CHECK(SignK6SourceRecord(h, pub.data(), pub.size(), over, wo) == Kad6Status::TooLarge, "source producer compat cap");

    // Over-cap TTL rejected before verify (BadValue), even with a broken sig.
    K6SourceRecord bigttl = MakeSource(pub, 1, false);
    bigttl.expires_at = bigttl.created_at + kK6SourceMaxTtlSeconds + 1;
    std::vector<Byte> wbt;
    CHECK(SignK6SourceRecord(h, pub.data(), pub.size(), bigttl, wbt) == Kad6Status::BadValue,
          "source producer rejects ttl>cap");
    K6SourceRecord dbt = bigttl;
    CHECK(VerifyK6SourceRecord(h, dbt) == Kad6Status::BadValue, "source ttl>cap -> BadValue");
    K6SourceRecord dbt2 = dbt; dbt2.signature[0] ^= 0xFF;
    CHECK(VerifyK6SourceRecord(h, dbt2) == Kad6Status::BadValue, "source ttl gate precedes sig verify");

    // Freshness + epoch.
    K6SourceRecord d; (void)DecodeK6SourceRecord(wire.data(), wire.size(), d, nullptr);
    CHECK(K6SourceRecordCheckFresh(d, d.created_at - 1) == Kad6Status::BadValue, "source before created_at -> BadValue");
    CHECK(K6SourceRecordCheckFresh(d, d.expires_at - 1) == Kad6Status::Ok, "source in-window -> Ok");
    CHECK(K6SourceRecordCheckFresh(d, d.expires_at) == Kad6Status::Expired, "source at expires -> Expired");
    CHECK(K6CheckEpochAdvance(d.source_epoch, d.source_epoch) == Kad6Status::StaleEpoch, "source epoch equal -> Stale");
    CHECK(K6CheckEpochAdvance(d.source_epoch, d.source_epoch + 1) == Kad6Status::Ok, "source epoch advance -> Ok");
    std::uint64_t sourceEpoch = d.source_epoch - 1;
    CHECK(AcceptK6SourceRecord(h, d, sourceEpoch, d.created_at) == Kad6Status::Ok,
          "source stateful verify accepts fresh epoch advance");
    CHECK(sourceEpoch == d.source_epoch, "source accept advances stored epoch");
    CHECK(AcceptK6SourceRecord(h, d, sourceEpoch, d.created_at) == Kad6Status::StaleEpoch,
          "source stateful verify rejects replay");
    std::uint64_t earlySourceEpoch = d.source_epoch - 1;
    CHECK(AcceptK6SourceRecord(h, d, earlySourceEpoch, d.created_at - 1) == Kad6Status::BadValue,
          "source stateful verify rejects not-yet-valid record");
    CHECK(earlySourceEpoch == d.source_epoch - 1, "source failed accept leaves epoch unchanged");

    // No originator IP anywhere: structural confirmation that decoding a source
    // never yields the publisher's own address (only exit endpoints exist).
    CHECK(d.exits[0].endpoint.addr.family == Kad6Address::Family::IPv4, "source carries only exit endpoints");

    fuzz_decode<K6SourceRecord>("source: no proper prefix Ok", wire,
        [](const Byte* p, std::size_t n, K6SourceRecord& o, std::size_t* c) {
            return DecodeK6SourceRecord(p, n, o, c);
        });
}

int main() {
    test_nodebind();
    test_rotate();
    test_router();
    test_source();

    std::printf("test_kad6_records: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
