// SPDX-License-Identifier: MIT
//
// test_reach_codec.cpp — golden-vector + adversarial unit tests for the
// TAG_REACH TLV codec (KEP-1 Appendix A). These vectors are the normative
// pin: any drift in libreach OR in a third-party implementation is a
// conformance failure. Mirrors the spirit of tests/test_address_wire.py for
// the reachability vector.
//
// Standalone build (no MFC, no eMule headers), from libreach/:
//   cl /EHsc /O2 /I include /Fe:test_reach_codec.exe ^
//      tests\test_reach_codec.cpp src\reach_codec.cpp
//   test_reach_codec.exe        (exit 0 = all pass, non-zero = failure count)
// Or with g++:  g++ -std=c++17 -O2 -Iinclude -o test_reach_codec \
//                   tests/test_reach_codec.cpp src/reach_codec.cpp
#include "reach/reach_codec.h"

#include <cstdio>
#include <cstdint>
#include <string>
#include <vector>

using namespace reach;

static int g_fail = 0;
static int g_pass = 0;

#define CHECK(cond, msg) do { if (cond) { ++g_pass; } else { ++g_fail; \
    std::printf("  FAIL: %s  (%s:%d)\n", msg, __FILE__, __LINE__); } } while (0)

static std::string hex(const std::vector<Byte>& b) {
    static const char* d = "0123456789abcdef";
    std::string s;
    s.reserve(b.size() * 2);
    for (Byte x : b) { s.push_back(d[x >> 4]); s.push_back(d[x & 0xF]); }
    return s;
}

static bool eq(const std::vector<Byte>& a, const std::vector<Byte>& b) {
    return a.size() == b.size() &&
           (a.empty() || std::equal(a.begin(), a.end(), b.begin()));
}

// Build a 16-byte NodeID 0x00..0x0F for deterministic vectors.
static KadId seqId() {
    KadId id{};
    for (std::size_t i = 0; i < kKadIdSize; ++i) id[i] = static_cast<Byte>(i);
    return id;
}

// ── 1. Exact byte layout (the normative pin) ──────────────────────────────
static void test_byte_layout() {
    // Empty v1 vector: version 01, capflags 00 00, nRdv 00.
    {
        ReachVector v;                 // defaults: version=1, caps=0, no rdv
        std::vector<Byte> w;
        CHECK(EncodeReachVector(v, w) == ReachStatus::Ok, "empty encode ok");
        const std::vector<Byte> want = {0x01, 0x00, 0x00, 0x00};
        CHECK(eq(w, want), ("empty layout " + hex(w)).c_str());
    }
    // caps = V4_TCP_IN | PUNCH_2W = 0x0009 (little-endian → 09 00), nRdv 0.
    {
        ReachVector v;
        v.capFlags = KAD_CAP_V4_TCP_IN | KAD_CAP_PUNCH_2W;
        std::vector<Byte> w;
        CHECK(EncodeReachVector(v, w) == ReachStatus::Ok, "caps encode ok");
        const std::vector<Byte> want = {0x01, 0x09, 0x00, 0x00};
        CHECK(eq(w, want), ("caps layout " + hex(w)).c_str());
    }
    // One rdv: caps KEEPALIVE|RELAY_OFFER = 0x60, NodeID 00..0F,
    // ipv4 = 10.0.0.1, udpPort = 0x1234 (LE → 34 12). Total 26 bytes.
    {
        ReachVector v;
        v.capFlags = KAD_CAP_KEEPALIVE | KAD_CAP_RELAY_OFFER; // 0x60
        RdvEntry e;
        e.nodeId = seqId();
        e.ipv4 = {10, 0, 0, 1};
        e.udpPort = 0x1234;
        v.rdv.push_back(e);
        std::vector<Byte> w;
        CHECK(EncodeReachVector(v, w) == ReachStatus::Ok, "1-rdv encode ok");
        std::vector<Byte> want = {0x01, 0x60, 0x00, 0x01};
        for (std::size_t i = 0; i < 16; ++i) want.push_back(static_cast<Byte>(i));
        want.insert(want.end(), {0x0A, 0x00, 0x00, 0x01, 0x34, 0x12});
        CHECK(w.size() == kReachHeaderSize + kRdvWireSize, "1-rdv size 26");
        CHECK(eq(w, want), ("1-rdv layout " + hex(w)).c_str());
    }
}

// ── 2. Round-trip across the full grid, incl. max 3 rdv ───────────────────
static void test_roundtrip() {
    for (int n = 0; n <= static_cast<int>(kMaxRdv); ++n) {
        ReachVector v;
        v.capFlags = static_cast<std::uint16_t>(n * 0x11) & kKadCapKnownMask;
        for (int i = 0; i < n; ++i) {
            RdvEntry e;
            e.nodeId = seqId();
            e.nodeId[0] = static_cast<Byte>(0xE0 + i);
            e.ipv4 = {static_cast<Byte>(192), 168, 0, static_cast<Byte>(i + 1)};
            e.udpPort = static_cast<std::uint16_t>(4660 + i);
            v.rdv.push_back(e);
        }
        std::vector<Byte> w;
        CHECK(EncodeReachVector(v, w) == ReachStatus::Ok, "grid encode ok");

        ReachVector back;
        std::size_t consumed = 0;
        CHECK(DecodeReachVector(w.data(), w.size(), back, &consumed) == ReachStatus::Ok,
              "grid decode ok");
        CHECK(consumed == w.size(), "grid consumed all");
        CHECK(back.version == v.version, "grid version");
        CHECK(back.capFlags == v.capFlags, "grid capFlags");
        CHECK(back.rdv.size() == v.rdv.size(), "grid rdv count");
        for (std::size_t i = 0; i < back.rdv.size(); ++i) {
            CHECK(back.rdv[i].nodeId == v.rdv[i].nodeId, "grid rdv nodeId");
            CHECK(back.rdv[i].ipv4 == v.rdv[i].ipv4, "grid rdv ipv4");
            CHECK(back.rdv[i].udpPort == v.rdv[i].udpPort, "grid rdv port");
        }
        // Re-encode is byte-identical.
        std::vector<Byte> w2;
        CHECK(EncodeReachVector(back, w2) == ReachStatus::Ok, "grid re-encode ok");
        CHECK(eq(w, w2), "grid re-encode stable");
    }
    // Max vector is exactly 70 bytes.
    ReachVector vmax;
    vmax.rdv.resize(kMaxRdv);
    std::vector<Byte> wmax;
    CHECK(EncodeReachVector(vmax, wmax) == ReachStatus::Ok, "max encode ok");
    CHECK(wmax.size() == kReachMaxKnownSize, "max size 70");
}

// ── 3. Forward-compat: newer version + trailing TLV preserved ─────────────
static void test_forward_compat() {
    // Hand-craft a "v2" buffer: version 02, caps, nRdv 1, one rdv, then 5
    // trailing bytes a v1 parser doesn't understand.
    std::vector<Byte> buf = {0x02, 0x09, 0x00, 0x01};
    for (std::size_t i = 0; i < 16; ++i) buf.push_back(static_cast<Byte>(i));
    buf.insert(buf.end(), {0x0A, 0x00, 0x00, 0x02, 0x78, 0x56}); // ip 10.0.0.2 port 0x5678
    const std::vector<Byte> tail = {0xDE, 0xAD, 0xBE, 0xEF, 0x99};
    buf.insert(buf.end(), tail.begin(), tail.end());

    ReachVector v;
    CHECK(DecodeReachVector(buf.data(), buf.size(), v) == ReachStatus::Ok,
          "v2 decode tolerated");
    CHECK(v.version == 0x02, "v2 version preserved");
    CHECK(v.rdv.size() == 1, "v2 rdv parsed");
    CHECK(v.rdv[0].udpPort == 0x5678, "v2 rdv port");
    CHECK(eq(v.trailing, tail), "v2 trailing preserved");

    // Re-encoding a decoded non-v1 vector keeps the tail and the version byte,
    // and does NOT apply the reserved-bit check (that only guards v1 emit).
    std::vector<Byte> w;
    CHECK(EncodeReachVector(v, w) == ReachStatus::Ok, "v2 re-encode ok");
    CHECK(eq(w, buf), "v2 re-encode byte-identical");
}

// ── 4. Decode rejection (malformed wire) ──────────────────────────────────
static void test_decode_rejection() {
    ReachVector v;
    // Too short for the header.
    const std::vector<Byte> three = {0x01, 0x00, 0x00};
    CHECK(DecodeReachVector(three.data(), three.size(), v) == ReachStatus::Truncated,
          "len<4 truncated");
    // version 0.
    const std::vector<Byte> v0 = {0x00, 0x00, 0x00, 0x00};
    CHECK(DecodeReachVector(v0.data(), v0.size(), v) == ReachStatus::BadVersionZero,
          "version 0 rejected");
    // nRdv = 4 (> max).
    const std::vector<Byte> too = {0x01, 0x00, 0x00, 0x04};
    CHECK(DecodeReachVector(too.data(), too.size(), v) == ReachStatus::TooManyRdv,
          "nRdv>3 rejected");
    // nRdv = 2 but body truncated (only header present).
    const std::vector<Byte> shortBody = {0x01, 0x00, 0x00, 0x02};
    CHECK(DecodeReachVector(shortBody.data(), shortBody.size(), v) == ReachStatus::Truncated,
          "short body truncated");
    // A null buffer that claims bytes is a caller bug; a genuinely empty
    // (zero-length) input is Truncated whether the pointer is null or not.
    CHECK(DecodeReachVector(nullptr, 5, v) == ReachStatus::NullArgument, "null in w/ len");
    const std::vector<Byte> empty;
    CHECK(DecodeReachVector(empty.data(), 0, v) == ReachStatus::Truncated, "empty truncated");
    // A successful decode followed by a failed one must leave `out` cleared.
    const std::vector<Byte> ok = {0x01, 0x00, 0x00, 0x00};
    CHECK(DecodeReachVector(ok.data(), ok.size(), v) == ReachStatus::Ok, "ok decode");
    CHECK(DecodeReachVector(too.data(), too.size(), v) == ReachStatus::TooManyRdv, "re-reject");
    CHECK(v.rdv.empty() && v.trailing.empty(), "out cleared after failure");
}

// ── 5. Encode validation (strict producer) ────────────────────────────────
static void test_encode_validation() {
    std::vector<Byte> w;
    // Too many rdv.
    {
        ReachVector v;
        v.rdv.resize(kMaxRdv + 1);
        CHECK(EncodeReachVector(v, w) == ReachStatus::TooManyRdv, "emit too many rdv");
        CHECK(w.empty(), "emit too many leaves out empty");
    }
    // Reserved capflag bit on a v1 vector.
    {
        ReachVector v;
        v.capFlags = 0x0080; // bit7 reserved
        CHECK(EncodeReachVector(v, w) == ReachStatus::ReservedBitsSet, "emit reserved bit");
    }
    // version 0.
    {
        ReachVector v;
        v.version = 0;
        CHECK(EncodeReachVector(v, w) == ReachStatus::BadVersionZero, "emit version 0");
    }
    // Buffer too small (raw-pointer path).
    {
        ReachVector v;                 // needs 4 bytes
        Byte small[2];
        std::size_t written = 123;
        CHECK(EncodeReachVector(v, small, sizeof(small), &written) == ReachStatus::BufferTooSmall,
              "emit buffer too small");
        CHECK(written == 0, "emit failure zeroes written");
    }
    // Exact-fit buffer succeeds and reports the right length.
    {
        ReachVector v;
        Byte buf[kReachHeaderSize];
        std::size_t written = 0;
        CHECK(EncodeReachVector(v, buf, sizeof(buf), &written) == ReachStatus::Ok,
              "emit exact fit ok");
        CHECK(written == kReachHeaderSize, "emit exact fit length");
    }
}

// ── 6. Pure cap helpers ───────────────────────────────────────────────────
static void test_cap_helpers() {
    ReachVector v;
    v.capFlags = KAD_CAP_PUNCH_2W | KAD_CAP_KEEPALIVE; // 0x28
    CHECK(ReachHasCaps(v, KAD_CAP_PUNCH_2W), "has punch2w");
    CHECK(ReachHasCaps(v, KAD_CAP_PUNCH_2W | KAD_CAP_KEEPALIVE), "has both");
    CHECK(!ReachHasCaps(v, KAD_CAP_RELAY_OFFER), "lacks relay");
    CHECK(!ReachHasCaps(v, KAD_CAP_PUNCH_2W | KAD_CAP_RELAY_OFFER), "lacks one of two");
    // Known-cap mask strips reserved bits a future peer might set.
    v.capFlags = 0xFFFF;
    CHECK(ReachKnownCaps(v) == kKadCapKnownMask, "known-cap mask 0x7F");
}

int main() {
    std::printf("test_reach_codec — KEP-1 Appendix A golden vectors\n");
    test_byte_layout();
    test_roundtrip();
    test_forward_compat();
    test_decode_rejection();
    test_encode_validation();
    test_cap_helpers();
    std::printf("\nTOTAL: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
