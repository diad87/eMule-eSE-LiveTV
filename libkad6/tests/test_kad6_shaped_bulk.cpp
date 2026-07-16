// SPDX-License-Identifier: MIT
//
// Shaped carrier tests. The carrier API accepts only an opaque prefix: actual
// onion AEAD vectors belong to the host integration, never to an identity model.
#include "kad6/kad6_shaped_bulk.h"

#include <cstdio>
#include <vector>

using namespace kad6;

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond, msg) do { if (cond) { ++g_pass; } else { ++g_fail; \
    std::printf("  FAIL: %s  (%s:%d)\n", msg, __FILE__, __LINE__); } } while (0)

static std::uint64_t g_rng = 1;
static bool g_rng_fail = false;

static void rng_seed(std::uint64_t seed) { g_rng = seed ? seed : 1; }

static bool mock_random(Byte* out, std::size_t len) {
    if (g_rng_fail) return false;
    for (std::size_t i = 0; i < len; ++i) {
        g_rng ^= g_rng << 13;
        g_rng ^= g_rng >> 7;
        g_rng ^= g_rng << 17;
        out[i] = static_cast<Byte>(g_rng >> 24);
    }
    return true;
}

static Kad6CryptoHooks Hooks() {
    Kad6CryptoHooks h{};
    h.random_bytes = &mock_random;
    return h;
}

static std::vector<Byte> OpaquePrefix(int layers, Byte seed) {
    std::vector<Byte> out(K6ShapedPrefixLen(layers));
    std::uint32_t s = static_cast<std::uint32_t>(seed) + 1;
    for (Byte& b : out) {
        s = s * 1664525u + 1013904223u;
        b = static_cast<Byte>(s >> 24);
    }
    return out;
}

static K6ShapedBulkPlainV1 Plain(K6BulkKind kind, std::size_t inner_len) {
    K6ShapedBulkPlainV1 p;
    p.kind = static_cast<Byte>(kind);
    p.flags = 0xBEEF;
    p.stream_id = 0x0102030405060708ull;
    p.logical_sequence = 0x8877665544332211ull;
    p.inner.resize(inner_len);
    for (std::size_t i = 0; i < inner_len; ++i)
        p.inner[i] = static_cast<Byte>((i * 29 + 7) & 0xFF);
    return p;
}

static void test_sizes() {
    const auto eq = [](std::size_t a, std::size_t b) { return a == b; };
    CHECK(eq(kK6ShapedTotal, 17000), "total size 17000");
    CHECK(eq(kK6ShapedHeaderSize, 17), "header size 17");
    CHECK(eq(kK6ShapedLengthField, 16983), "length field 16983");
    CHECK(eq(kK6ShapedPlainSize, 16438), "plaintext size 16438");
    CHECK(eq(kK6ShapedInnerMax, 16414), "inner max fits one complete bulk symbol");
    CHECK(K6ShapedPrefixLen(1) == 16462, "one remaining layer");
    CHECK(K6ShapedPrefixLen(2) == 16486, "two remaining layers");
    CHECK(K6ShapedPrefixLen(3) == 16510, "three remaining layers");
    CHECK(K6ShapedPrefixLen(0) == 0, "zero remaining layers rejected");
    CHECK(K6ShapedPrefixLen(4) == 0, "four remaining layers rejected");
}

static void test_plaintext_codec() {
    const Kad6CryptoHooks h = Hooks();
    const K6BulkKind kinds[] = {K6BulkKind::Data, K6BulkKind::Padding,
                                K6BulkKind::Credit, K6BulkKind::Close};
    for (K6BulkKind kind : kinds) {
        for (std::size_t n : {std::size_t(0), std::size_t(1), kK6ShapedInnerMax}) {
            rng_seed(100 + n + static_cast<Byte>(kind));
            K6ShapedBulkPlainV1 p = Plain(kind, n);
            std::vector<Byte> wire;
            CHECK(EncodeK6ShapedPlain(p, h, wire) == Kad6Status::Ok, "plain encode");
            CHECK(wire.size() == kK6ShapedPlainSize, "plain exact size");
            K6ShapedBulkPlainV1 d;
            CHECK(DecodeK6ShapedPlain(wire.data(), wire.size(), d) == Kad6Status::Ok,
                  "plain decode");
            CHECK(d.kind == p.kind && d.flags == p.flags, "plain kind and flags");
            CHECK(d.stream_id == p.stream_id && d.logical_sequence == p.logical_sequence,
                  "plain sequence fields");
            CHECK(d.inner == p.inner, "plain inner round trip");
        }
    }

    std::vector<Byte> wire;
    K6ShapedBulkPlainV1 bad = Plain(K6BulkKind::Data, 1);
    bad.version = 2;
    CHECK(EncodeK6ShapedPlain(bad, h, wire) == Kad6Status::UnsupportedVersion,
          "producer version guard");
    bad = Plain(K6BulkKind::Data, 1); bad.kind = 0;
    CHECK(EncodeK6ShapedPlain(bad, h, wire) == Kad6Status::BadValue, "producer kind guard");
    bad = Plain(K6BulkKind::Data, kK6ShapedInnerMax + 1);
    CHECK(EncodeK6ShapedPlain(bad, h, wire) == Kad6Status::TooLarge, "producer inner cap");

    Kad6CryptoHooks empty{};
    bad = Plain(K6BulkKind::Data, 1);
    CHECK(EncodeK6ShapedPlain(bad, empty, wire) == Kad6Status::BadValue, "plain requires CSPRNG");
    g_rng_fail = true;
    CHECK(EncodeK6ShapedPlain(bad, h, wire) == Kad6Status::AuthFailed, "plain CSPRNG failure");
    CHECK(wire.empty(), "plain failure clears output");
    g_rng_fail = false;

    rng_seed(9);
    (void)EncodeK6ShapedPlain(Plain(K6BulkKind::Data, 4), h, wire);
    K6ShapedBulkPlainV1 d;
    CHECK(DecodeK6ShapedPlain(wire.data(), wire.size() - 1, d) == Kad6Status::Malformed,
          "short plaintext rejected");
    std::vector<Byte> forged = wire; forged[0] = 2;
    CHECK(DecodeK6ShapedPlain(forged.data(), forged.size(), d) == Kad6Status::UnsupportedVersion,
          "consumer version guard");
    forged = wire; forged[1] = 9;
    CHECK(DecodeK6ShapedPlain(forged.data(), forged.size(), d) == Kad6Status::Malformed,
          "consumer kind guard");
    forged = wire;
    const std::uint32_t too_big = static_cast<std::uint32_t>(kK6ShapedInnerMax + 1);
    for (std::size_t i = 0; i < 4; ++i)
        forged[20 + i] = static_cast<Byte>((too_big >> (8 * i)) & 0xFF);
    CHECK(DecodeK6ShapedPlain(forged.data(), forged.size(), d) == Kad6Status::Malformed,
          "consumer inner cap");
}

static void test_opaque_carrier() {
    const Kad6CryptoHooks h = Hooks();
    for (int layers = 1; layers <= 3; ++layers) {
        const std::vector<Byte> prefix = OpaquePrefix(layers, static_cast<Byte>(layers));
        std::vector<Byte> frame;
        rng_seed(0xA000 + layers);
        CHECK(BuildK6ShapedCarrier(prefix.data(), prefix.size(), layers,
                                   0xDEADBEEFu, 0x0102030405060708ull, h, frame)
              == Kad6Status::Ok, "carrier build");
        CHECK(frame.size() == kK6ShapedTotal, "carrier exact size");

        K6ShapedHeader hdr;
        std::vector<Byte> extracted;
        CHECK(ExtractK6ShapedPrefix(frame.data(), frame.size(), layers, extracted, &hdr)
              == Kad6Status::Ok, "opaque prefix extract");
        CHECK(extracted == prefix, "opaque prefix preserved byte-for-byte");
        CHECK(hdr.circ_id == 0xDEADBEEFu && hdr.bcmd == kK6ShapedBcmd,
              "outer route header");
        CHECK(hdr.link_nonce_seq == 0x0102030405060708ull &&
              hdr.length == kK6ShapedLengthField, "outer nonce and fixed length");

        bool tail_nonzero = false;
        for (std::size_t i = kK6ShapedHeaderSize + prefix.size(); i < frame.size(); ++i)
            tail_nonzero = tail_nonzero || frame[i] != 0;
        CHECK(tail_nonzero, "carrier tail filled by CSPRNG");
    }

    // The carrier does not infer or parse a kind: distinct opaque ciphertexts
    // still expose exactly the same outer header and total length.
    std::vector<Byte> frames[4];
    for (int i = 0; i < 4; ++i) {
        const std::vector<Byte> prefix = OpaquePrefix(3, static_cast<Byte>(50 + i));
        rng_seed(800 + i);
        (void)BuildK6ShapedCarrier(prefix.data(), prefix.size(), 3, 77, 88, h, frames[i]);
    }
    for (int i = 1; i < 4; ++i) {
        bool same = frames[i].size() == frames[0].size();
        for (std::size_t n = 0; same && n < kK6ShapedHeaderSize; ++n)
            same = frames[i][n] == frames[0][n];
        CHECK(same, "all opaque kinds share carrier header and size");
    }
}

static void test_guards() {
    const Kad6CryptoHooks h = Hooks();
    const std::vector<Byte> prefix = OpaquePrefix(2, 3);
    std::vector<Byte> frame;
    CHECK(BuildK6ShapedCarrier(prefix.data(), prefix.size(), 0, 1, 1, h, frame)
          == Kad6Status::BadValue, "carrier remaining_layers low guard");
    CHECK(BuildK6ShapedCarrier(prefix.data(), prefix.size(), 4, 1, 1, h, frame)
          == Kad6Status::BadValue, "carrier remaining_layers high guard");
    CHECK(BuildK6ShapedCarrier(prefix.data(), prefix.size() - 1, 2, 1, 1, h, frame)
          == Kad6Status::Malformed, "carrier prefix length guard");
    CHECK(BuildK6ShapedCarrier(nullptr, prefix.size(), 2, 1, 1, h, frame)
          == Kad6Status::NullArgument, "carrier null prefix guard");
    CHECK(BuildK6ShapedCarrier(prefix.data(), prefix.size(), 2, 1, 0, h, frame)
          == Kad6Status::BadValue, "carrier zero link nonce rejected");
    CHECK(BuildK6ShapedCarrier(prefix.data(), prefix.size(), 2, 1,
                               kK6ShapedPaddingSentinel, h, frame)
          == Kad6Status::BadValue, "carrier padding sentinel rejected as outer nonce");
    Kad6CryptoHooks empty{};
    CHECK(BuildK6ShapedCarrier(prefix.data(), prefix.size(), 2, 1, 1, empty, frame)
          == Kad6Status::BadValue, "carrier requires CSPRNG");
    g_rng_fail = true;
    CHECK(BuildK6ShapedCarrier(prefix.data(), prefix.size(), 2, 1, 1, h, frame)
          == Kad6Status::AuthFailed, "carrier CSPRNG failure");
    CHECK(frame.empty(), "carrier failure clears output");
    g_rng_fail = false;

    rng_seed(7);
    (void)BuildK6ShapedCarrier(prefix.data(), prefix.size(), 2, 1, 1, h, frame);
    K6ShapedHeader hdr;
    std::vector<Byte> out;
    CHECK(ExtractK6ShapedPrefix(frame.data(), frame.size() - 1, 2, out) == Kad6Status::Malformed,
          "extract exact-size guard");
    CHECK(ExtractK6ShapedPrefix(frame.data(), frame.size(), 0, out) == Kad6Status::BadValue,
          "extract remaining_layers guard");
    std::vector<Byte> bad = frame; bad[4] = 2;
    CHECK(ExtractK6ShapedPrefix(bad.data(), bad.size(), 2, out) == Kad6Status::Malformed,
          "extract bcmd guard");
    bad = frame; bad[5] = bad[6] = bad[7] = bad[8] = 0;
    bad[9] = bad[10] = bad[11] = bad[12] = 0;
    CHECK(PeekK6ShapedHeader(bad.data(), bad.size(), hdr) == Kad6Status::Malformed,
          "peek zero link nonce guard");
    bad = frame; bad[13] ^= 1;
    CHECK(PeekK6ShapedHeader(bad.data(), bad.size(), hdr) == Kad6Status::Malformed,
          "peek fixed length guard");
}

static void test_relay_rebuild() {
    const Kad6CryptoHooks h = Hooks();
    for (int incoming_layers : {3, 2}) {
        const std::vector<Byte> incoming = OpaquePrefix(incoming_layers, 20);
        std::vector<Byte> first;
        rng_seed(1000 + incoming_layers);
        (void)BuildK6ShapedCarrier(incoming.data(), incoming.size(), incoming_layers,
                                   0x11111111u, 0x1111111111111111ull, h, first);

        std::vector<Byte> received;
        CHECK(ExtractK6ShapedPrefix(first.data(), first.size(), incoming_layers, received)
              == Kad6Status::Ok, "relay extracts incoming opaque layer stack");
        CHECK(received == incoming, "relay input exact before host AEAD open");

        // Simulate the host's successful AEAD peel. The codec receives only the
        // resulting shorter opaque prefix and cannot bypass that step in place.
        const int outgoing_layers = incoming_layers - 1;
        const std::vector<Byte> peeled = OpaquePrefix(outgoing_layers, 90);
        std::vector<Byte> forwarded;
        rng_seed(2000 + incoming_layers);
        CHECK(BuildK6ShapedCarrier(peeled.data(), peeled.size(), outgoing_layers,
                                   0x22222222u, 0x2222222222222222ull, h, forwarded)
              == Kad6Status::Ok, "relay rebuilds after host peel");
        CHECK(forwarded.size() == first.size(), "relay preserves fixed carrier size");
        K6ShapedHeader hdr;
        std::vector<Byte> check;
        CHECK(ExtractK6ShapedPrefix(forwarded.data(), forwarded.size(), outgoing_layers,
                                    check, &hdr) == Kad6Status::Ok,
              "forwarded shorter prefix extracts");
        CHECK(check == peeled, "forwarded prefix is host-authenticated peel result");
        CHECK(hdr.circ_id == 0x22222222u && hdr.link_nonce_seq == 0x2222222222222222ull,
              "relay rewrites link-local identifiers");
    }
}

static void test_fuzz_extract() {
    std::uint32_t state = 0xC0FFEEu;
    auto rnd = [&]() { state = state * 1664525u + 1013904223u; return state; };
    bool invalid_ok = false;
    for (int iter = 0; iter < 12000; ++iter) {
        const std::size_t n = (iter & 1) ? kK6ShapedTotal : rnd() % 20000;
        std::vector<Byte> buf(n);
        for (Byte& b : buf) b = static_cast<Byte>(rnd() >> 24);
        if (n == kK6ShapedTotal && (iter & 2)) {
            buf[4] = kK6ShapedBcmd;
            buf[5] = 1; for (int i = 6; i <= 12; ++i) buf[i] = 0;
            const std::uint32_t fixed = kK6ShapedLengthField;
            for (std::size_t i = 0; i < 4; ++i)
                buf[13 + i] = static_cast<Byte>((fixed >> (8 * i)) & 0xFF);
        }
        const int layers = static_cast<int>(rnd() % 5);
        std::vector<Byte> prefix;
        K6ShapedHeader hdr;
        const Kad6Status status = ExtractK6ShapedPrefix(
            buf.empty() ? nullptr : buf.data(), n, layers, prefix, &hdr);
        if (status == Kad6Status::Ok) {
            const bool valid = n == kK6ShapedTotal && layers >= 1 && layers <= 3 &&
                hdr.bcmd == kK6ShapedBcmd && hdr.length == kK6ShapedLengthField &&
                hdr.link_nonce_seq != 0 && prefix.size() == K6ShapedPrefixLen(layers);
            invalid_ok = invalid_ok || !valid;
        }
    }
    CHECK(!invalid_ok, "fuzz: Ok only for structurally valid opaque carrier");
}

int main() {
    test_sizes();
    test_plaintext_codec();
    test_opaque_carrier();
    test_guards();
    test_relay_rebuild();
    test_fuzz_extract();

    std::printf("test_kad6_shaped_bulk: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
