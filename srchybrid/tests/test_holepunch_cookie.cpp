// test_holepunch_cookie.cpp — unit tests for the stateless hole-punch cookie
// core (P0 return-routability). No MFC, no eMule; pure CryptoPP.
//
// Standalone build from srchybrid/ (links the prebuilt cryptlib.lib):
//   cl /EHsc /O2 /W4 /std:c++17 /I.. tests\test_holepunch_cookie.cpp ^
//      x64\Release\cryptlib.lib
//   test_holepunch_cookie.exe       (exit 0 = all pass)
#include "../HolePunchCookieCore.h"

#include <cstdio>
#include <cstdint>
#include <cstring>

using namespace eSE;

static int g_fail = 0, g_pass = 0;
#define CHECK(cond, msg) do { if (cond) { ++g_pass; } else { ++g_fail; \
    std::printf("  FAIL: %s  (%s:%d)\n", msg, __FILE__, __LINE__); } } while (0)

static void hexline(const char* label, const uint8_t* b, size_t n) {
    std::printf("%s", label);
    for (size_t i = 0; i < n; ++i) std::printf("%02x", b[i]);
    std::printf("\n");
}

// Fixed test inputs.
static void fillSecret(uint8_t s[HP_SECRET_SIZE]) {
    for (size_t i = 0; i < HP_SECRET_SIZE; ++i) s[i] = static_cast<uint8_t>(i);
}
static void fillNode(uint8_t h[16], uint8_t base = 0xA0) {
    for (size_t i = 0; i < 16; ++i) h[i] = static_cast<uint8_t>(base + i);
}

// Golden regression pin: cookie for (secret=0..1F, node=A0..AF, epoch=12345,
// ip=0x01020304, nonce=0xDEADBEEF). Locked after the first run so an accidental
// algorithm change (key order, truncation, endianness) is caught.
static const uint8_t kGolden[HP_COOKIE_SIZE] = {
    0x3c,0x0a,0x52,0x7b,0x1f,0x9d,0xc4,0x6e,0xab,0x88,0x10,0x33,0x2d,0x71,0xe8,0x95
};

static void test_golden_and_determinism() {
    uint8_t secret[HP_SECRET_SIZE]; fillSecret(secret);
    uint8_t node[16]; fillNode(node);
    uint8_t c1[HP_COOKIE_SIZE], c2[HP_COOKIE_SIZE];
    HpComputeCookie(secret, node, 12345u, 0x01020304u, 0xDEADBEEFu, c1);
    HpComputeCookie(secret, node, 12345u, 0x01020304u, 0xDEADBEEFu, c2);
    hexline("  GOLDEN cookie = ", c1, HP_COOKIE_SIZE);
    CHECK(std::memcmp(c1, c2, HP_COOKIE_SIZE) == 0, "deterministic");
    CHECK(std::memcmp(c1, kGolden, HP_COOKIE_SIZE) == 0, "matches golden pin");
}

static void test_bindings() {
    uint8_t secret[HP_SECRET_SIZE]; fillSecret(secret);
    uint8_t node[16]; fillNode(node);
    uint8_t base[HP_COOKIE_SIZE], v[HP_COOKIE_SIZE];
    HpComputeCookie(secret, node, 7u, 0x0A000001u, 0x11112222u, base);

    HpComputeCookie(secret, node, 7u, 0x0A000002u, 0x11112222u, v);     // diff IP
    CHECK(std::memcmp(base, v, HP_COOKIE_SIZE) != 0, "ip-bound");
    HpComputeCookie(secret, node, 7u, 0x0A000001u, 0x11112223u, v);     // diff nonce
    CHECK(std::memcmp(base, v, HP_COOKIE_SIZE) != 0, "nonce-bound");
    HpComputeCookie(secret, node, 8u, 0x0A000001u, 0x11112222u, v);     // diff epoch
    CHECK(std::memcmp(base, v, HP_COOKIE_SIZE) != 0, "epoch-bound");
    uint8_t node2[16]; fillNode(node2, 0xB0);
    HpComputeCookie(secret, node2, 7u, 0x0A000001u, 0x11112222u, v);    // diff node
    CHECK(std::memcmp(base, v, HP_COOKIE_SIZE) != 0, "node-bound");
}

static void test_forge_rejection() {
    // An attacker without the secret cannot produce a cookie we accept.
    uint8_t realSecret[HP_SECRET_SIZE]; fillSecret(realSecret);
    uint8_t guess[HP_SECRET_SIZE]; std::memset(guess, 0x77, sizeof(guess));
    uint8_t node[16]; fillNode(node);

    uint8_t forged[HP_COOKIE_SIZE];
    HpComputeCookie(guess, node, HpEpoch(50000u), 0x7F000001u, 0xCAFEBABEu, forged);
    CHECK(!HpVerifyCookie(realSecret, node, 50000u, 0x7F000001u, 0xCAFEBABEu, forged),
          "forged cookie (wrong secret) rejected");

    // The genuine cookie verifies.
    uint8_t good[HP_COOKIE_SIZE];
    HpComputeCookie(realSecret, node, HpEpoch(50000u), 0x7F000001u, 0xCAFEBABEu, good);
    CHECK(HpVerifyCookie(realSecret, node, 50000u, 0x7F000001u, 0xCAFEBABEu, good),
          "genuine cookie accepted");
    // ...but not for a different IP (replay against another victim).
    CHECK(!HpVerifyCookie(realSecret, node, 50000u, 0x7F000002u, 0xCAFEBABEu, good),
          "cookie not valid for a different IP");
}

static void test_epoch_window() {
    uint8_t secret[HP_SECRET_SIZE]; fillSecret(secret);
    uint8_t node[16]; fillNode(node);
    const uint32_t now0 = 100000u;          // epoch 6
    uint8_t cookie[HP_COOKIE_SIZE];
    HpComputeCookie(secret, node, HpEpoch(now0), 0x08080808u, 0x12345678u, cookie);

    CHECK(HpVerifyCookie(secret, node, now0, 0x08080808u, 0x12345678u, cookie),
          "verifies in the issuing epoch");
    CHECK(HpVerifyCookie(secret, node, now0 + HP_EPOCH_MS, 0x08080808u, 0x12345678u, cookie),
          "verifies one epoch later (grace)");
    CHECK(!HpVerifyCookie(secret, node, now0 + 2 * HP_EPOCH_MS, 0x08080808u, 0x12345678u, cookie),
          "rejected two epochs later (expired)");
}

static void test_ct_equal() {
    uint8_t a[4] = {1,2,3,4}, b[4] = {1,2,3,4}, c[4] = {1,2,3,5};
    CHECK(HpCtEqual(a, b, 4), "ct-equal equal");
    CHECK(!HpCtEqual(a, c, 4), "ct-equal differ");
}

int main() {
    std::printf("test_holepunch_cookie — P0 stateless return-routability\n");
    test_golden_and_determinism();
    test_bindings();
    test_forge_rejection();
    test_epoch_window();
    test_ct_equal();
    std::printf("\nTOTAL: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
