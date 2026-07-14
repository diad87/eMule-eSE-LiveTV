// SPDX-License-Identifier: MIT
//
// test_kad6_address.cpp — Kad6 address codec tests (ticket K6-0.3): golden
// byte layouts for the three valid (family, addr_len) combinations,
// round-trips, rejection of every other combination (with no OOB read),
// IPv4-mapped-IPv6 normalization, and subnet masking/equality.
//
//   from libkad6/:  make.bat test_kad6_address tests\test_kad6_address.cpp src\kad6_address.cpp
#include "kad6/kad6_address.h"
#include "kad6/kad6_types.h"

#include <cstdio>
#include <vector>

using namespace kad6;

static int g_fail = 0;
static int g_pass = 0;

#define CHECK(cond, msg) do { if (cond) { ++g_pass; } else { ++g_fail; \
    std::printf("  FAIL: %s  (%s:%d)\n", msg, __FILE__, __LINE__); } } while (0)

namespace {

Kad6Address MakeNone() {
    Kad6Address a;
    a.family = Kad6Address::Family::None;
    return a;
}

Kad6Address MakeIPv4(Byte b0, Byte b1, Byte b2, Byte b3) {
    Kad6Address a;
    a.family = Kad6Address::Family::IPv4;
    a.addr[0] = b0; a.addr[1] = b1; a.addr[2] = b2; a.addr[3] = b3;
    return a;
}

Kad6Address MakeIPv6(const Byte (&bytes)[16]) {
    Kad6Address a;
    a.family = Kad6Address::Family::IPv6;
    for (std::size_t i = 0; i < 16; ++i)
        a.addr[i] = bytes[i];
    return a;
}

} // namespace

static void TestGoldenAndRoundTrip() {
    // family=None: total 2 bytes, [0x00, 0x00].
    {
        Kad6Address a = MakeNone();
        CHECK(Kad6AddressEncodedSize(a) == 2, "None encoded size");

        std::vector<Byte> buf;
        CHECK(EncodeKad6Address(a, buf) == Kad6Status::Ok, "None encode ok");
        CHECK(buf.size() == 2, "None wire size");
        const Byte expect[2] = {0x00, 0x00};
        CHECK(buf.size() == 2 && buf[0] == expect[0] && buf[1] == expect[1],
              "None golden bytes");

        Kad6Address rt;
        std::size_t consumed = 0;
        CHECK(DecodeKad6Address(buf.data(), buf.size(), rt, &consumed) == Kad6Status::Ok,
              "None decode ok");
        CHECK(consumed == 2, "None consumed");
        CHECK(rt.family == Kad6Address::Family::None, "None round-trip family");
        CHECK(rt == a, "None round-trip equal");
    }

    // family=IPv4: total 6 bytes, [0x04, 0x04, addr...].
    {
        Kad6Address a = MakeIPv4(203, 0, 113, 7);
        CHECK(Kad6AddressEncodedSize(a) == 6, "IPv4 encoded size");

        std::vector<Byte> buf;
        CHECK(EncodeKad6Address(a, buf) == Kad6Status::Ok, "IPv4 encode ok");
        const Byte expect[6] = {0x04, 0x04, 203, 0, 113, 7};
        bool golden = buf.size() == 6;
        for (std::size_t i = 0; golden && i < 6; ++i)
            golden = golden && buf[i] == expect[i];
        CHECK(golden, "IPv4 golden bytes");

        // Also exercise the fixed-buffer overload.
        Byte fixed[6] = {};
        std::size_t written = 0;
        CHECK(EncodeKad6Address(a, fixed, sizeof(fixed), &written) == Kad6Status::Ok,
              "IPv4 fixed-buffer encode ok");
        CHECK(written == 6, "IPv4 fixed-buffer written");

        Kad6Address rt;
        std::size_t consumed = 0;
        CHECK(DecodeKad6Address(buf.data(), buf.size(), rt, &consumed) == Kad6Status::Ok,
              "IPv4 decode ok");
        CHECK(consumed == 6, "IPv4 consumed");
        CHECK(rt.family == Kad6Address::Family::IPv4, "IPv4 round-trip family");
        CHECK(rt.addr[0] == 203 && rt.addr[1] == 0 && rt.addr[2] == 113 && rt.addr[3] == 7,
              "IPv4 round-trip bytes");
        CHECK(rt == a, "IPv4 round-trip equal");
    }

    // family=IPv6: total 18 bytes, [0x06, 0x10, addr...16].
    {
        const Byte v6[16] = {0x20,0x01,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,0x01};
        Kad6Address a = MakeIPv6(v6);
        CHECK(Kad6AddressEncodedSize(a) == 18, "IPv6 encoded size");

        std::vector<Byte> buf;
        CHECK(EncodeKad6Address(a, buf) == Kad6Status::Ok, "IPv6 encode ok");
        bool golden = buf.size() == 18 && buf[0] == 0x06 && buf[1] == 0x10;
        for (std::size_t i = 0; golden && i < 16; ++i)
            golden = golden && buf[2 + i] == v6[i];
        CHECK(golden, "IPv6 golden bytes");

        Kad6Address rt;
        std::size_t consumed = 0;
        CHECK(DecodeKad6Address(buf.data(), buf.size(), rt, &consumed) == Kad6Status::Ok,
              "IPv6 decode ok");
        CHECK(consumed == 18, "IPv6 consumed");
        CHECK(rt.family == Kad6Address::Family::IPv6, "IPv6 round-trip family");
        CHECK(rt == a, "IPv6 round-trip equal");
    }
}

static void TestRejects() {
    // family=5 (not None/IPv4/IPv6), any addr_len.
    {
        const Byte bad[2] = {5, 0};
        Kad6Address out;
        CHECK(DecodeKad6Address(bad, sizeof(bad), out, nullptr) == Kad6Status::Malformed,
              "reject family=5");
    }
    // family=4 with addr_len=16 (mismatched, even though both individually valid values).
    {
        Byte bad[18] = {};
        bad[0] = 4; bad[1] = 16;
        Kad6Address out;
        CHECK(DecodeKad6Address(bad, sizeof(bad), out, nullptr) == Kad6Status::Malformed,
              "reject family=4 len=16");
    }
    // family=6 with addr_len=4.
    {
        Byte bad[6] = {};
        bad[0] = 6; bad[1] = 4;
        Kad6Address out;
        CHECK(DecodeKad6Address(bad, sizeof(bad), out, nullptr) == Kad6Status::Malformed,
              "reject family=6 len=4");
    }
    // family=4 header present (correct addr_len byte) but only the 2 header
    // bytes are actually in the buffer -> Truncated, not an OOB read.
    {
        const Byte shortBuf[2] = {4, 4};
        Kad6Address out;
        Kad6Status st = DecodeKad6Address(shortBuf, sizeof(shortBuf), out, nullptr);
        CHECK(st == Kad6Status::Truncated, "reject family=4 short body");
    }
    // Empty buffer.
    {
        Kad6Address out;
        Kad6Status st = DecodeKad6Address(nullptr, 0, out, nullptr);
        CHECK(st == Kad6Status::Truncated, "reject empty buffer");
    }
    // Null buffer with non-zero length is a caller bug, not a parse error.
    {
        Kad6Address out;
        Kad6Status st = DecodeKad6Address(nullptr, 6, out, nullptr);
        CHECK(st == Kad6Status::NullArgument, "reject null with nonzero len");
    }
    // Encode rejects an invalid Family value (constructed via static_cast, as
    // a caller bug would).
    {
        Kad6Address a;
        a.family = static_cast<Kad6Address::Family>(5);
        std::vector<Byte> buf{0xAA}; // pre-populate to confirm it gets cleared
        CHECK(EncodeKad6Address(a, buf) == Kad6Status::Malformed, "encode rejects bad family");
        CHECK(buf.empty(), "encode clears out on failure");
    }
    // Fixed-buffer encode: capacity smaller than required.
    {
        Kad6Address a = MakeIPv4(1, 2, 3, 4);
        Byte tiny[3] = {};
        std::size_t written = 99;
        Kad6Status st = EncodeKad6Address(a, tiny, sizeof(tiny), &written);
        CHECK(st == Kad6Status::TooLarge, "encode too-small buffer");
        CHECK(written == 0, "encode written reset on failure");
    }
}

static void TestNormalization() {
    // ::ffff:10.0.0.1 normalizes to family IPv4, addr 10.0.0.1.
    const Byte mapped[16] = {0,0,0,0,0,0,0,0,0,0,0xFF,0xFF, 10,0,0,1};
    Kad6Address a = MakeIPv6(mapped);
    Kad6AddressNormalize(a);
    CHECK(a.family == Kad6Address::Family::IPv4, "mapped v6 -> IPv4 family");
    CHECK(a.addr[0] == 10 && a.addr[1] == 0 && a.addr[2] == 0 && a.addr[3] == 1,
          "mapped v6 -> IPv4 bytes");

    // A plain IPv4 address compares equal to its IPv4-mapped-IPv6 form.
    Kad6Address v4 = MakeIPv4(10, 0, 0, 1);
    Kad6Address v6mapped = MakeIPv6(mapped);
    CHECK(v4 == v6mapped, "IPv4 == its IPv4-mapped-IPv6 form");

    // A non-mapped IPv6 address does NOT normalize away.
    const Byte notMapped[16] = {0x20,0x01,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,1};
    Kad6Address b = MakeIPv6(notMapped);
    Kad6AddressNormalize(b);
    CHECK(b.family == Kad6Address::Family::IPv6, "non-mapped v6 stays IPv6");

    // Garbage in the unused tail bytes of an IPv4 address must not affect
    // equality (operator== only compares the meaningful prefix).
    Kad6Address dirty = MakeIPv4(192, 168, 1, 1);
    for (std::size_t i = 4; i < dirty.addr.size(); ++i)
        dirty.addr[i] = 0xEE;
    Kad6Address clean = MakeIPv4(192, 168, 1, 1);
    CHECK(dirty == clean, "IPv4 equality ignores unused tail garbage");
}

static void TestSubnet() {
    // IPv4 /24: 10.0.0.1 vs 10.0.0.2 same subnet; vs 10.0.1.2 different.
    Kad6Address a = MakeIPv4(10, 0, 0, 1);
    Kad6Address b = MakeIPv4(10, 0, 0, 2);
    Kad6Address c = MakeIPv4(10, 0, 1, 2);
    CHECK(Kad6AddressInSameSubnet(a, b, 24), "IPv4 /24 same subnet");
    CHECK(!Kad6AddressInSameSubnet(a, c, 24), "IPv4 /24 different subnet");

    // Subnet() masks host bits explicitly for a /24.
    Kad6Address maskedA = Kad6AddressSubnet(a, 24);
    CHECK(maskedA.addr[0] == 10 && maskedA.addr[1] == 0 && maskedA.addr[2] == 0
          && maskedA.addr[3] == 0, "IPv4 /24 subnet masks last octet");

    // A /0 makes any two addresses of the same family "the same subnet".
    CHECK(Kad6AddressInSameSubnet(a, c, 0), "IPv4 /0 always same subnet");
    // A /32 requires an exact match.
    CHECK(!Kad6AddressInSameSubnet(a, b, 32), "IPv4 /32 requires exact match");
    CHECK(Kad6AddressInSameSubnet(a, a, 32), "IPv4 /32 self same subnet");

    // prefixBits out of range clamps rather than misbehaving.
    CHECK(Kad6AddressInSameSubnet(a, b, 999) == Kad6AddressInSameSubnet(a, b, 32),
          "IPv4 prefixBits clamps to 32");

    // IPv6 /64: same top 8 bytes -> same subnet; differing top bytes -> not.
    const Byte v6a[16] = {0x20,0x01,0x0d,0xb8,0x12,0x34,0x56,0x78, 0,0,0,0,0,0,0,0x01};
    const Byte v6b[16] = {0x20,0x01,0x0d,0xb8,0x12,0x34,0x56,0x78, 0,0,0,0,0,0,0,0x02};
    const Byte v6c[16] = {0x20,0x01,0x0d,0xb8,0x12,0x34,0x56,0x79, 0,0,0,0,0,0,0,0x01};
    Kad6Address ip6a = MakeIPv6(v6a);
    Kad6Address ip6b = MakeIPv6(v6b);
    Kad6Address ip6c = MakeIPv6(v6c);
    CHECK(Kad6AddressInSameSubnet(ip6a, ip6b, 64), "IPv6 /64 same subnet");
    CHECK(!Kad6AddressInSameSubnet(ip6a, ip6c, 64), "IPv6 /64 different subnet");

    // Different families are never in the same subnet, even at /0.
    Kad6Address v4 = MakeIPv4(1, 2, 3, 4);
    CHECK(!Kad6AddressInSameSubnet(v4, ip6a, 0), "different families never same subnet");
}

int main() {
    TestGoldenAndRoundTrip();
    TestRejects();
    TestNormalization();
    TestSubnet();

    std::printf("test_kad6_address: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
