// SPDX-License-Identifier: MIT
#include "kad6/kad6_exit_notice.h"

#include <cstdio>
#include <vector>

using namespace kad6;

static int g_pass = 0;
static int g_fail = 0;
#define CHECK(c, m) do { if (c) ++g_pass; else { ++g_fail; \
    std::printf("  FAIL: %s (%s:%d)\n", m, __FILE__, __LINE__); } } while (0)

static std::array<Byte, 32> g_pub{};

static bool Sha(const Byte* data, std::size_t size, Byte output[32]) {
    std::uint32_t state = 2166136261u;
    for (std::size_t i = 0; i < size; ++i) state = (state ^ data[i]) * 16777619u;
    for (std::size_t i = 0; i < 32; ++i) {
        state = state * 1664525u + 1013904223u + static_cast<std::uint32_t>(i);
        output[i] = static_cast<Byte>(state >> 24);
    }
    return true;
}

static void Signature(const Byte pub[32], const Byte* message,
                      std::size_t size, Byte output[64]) {
    std::vector<Byte> material(pub, pub + 32);
    material.insert(material.end(), message, message + size);
    Sha(material.data(), material.size(), output);
    material.push_back(0xA5);
    Sha(material.data(), material.size(), output + 32);
}

static bool Sign(const Byte* secret, std::size_t secret_size, const Byte* message,
                 std::size_t size, Byte output[64]) {
    if (secret != nullptr || secret_size != 0) return false;
    Signature(g_pub.data(), message, size, output);
    return true;
}

static bool Verify(const Byte pub[32], const Byte* message, std::size_t size,
                   const Byte signature[64]) {
    Byte expected[64]{};
    Signature(pub, message, size, expected);
    return Kad6CtEqual(expected, signature, sizeof expected);
}

static Kad6CryptoHooks Hooks() {
    Kad6CryptoHooks hooks{};
    hooks.sha256 = &Sha;
    hooks.ed25519_sign = &Sign;
    hooks.ed25519_verify = &Verify;
    return hooks;
}

static K6ExitNotice Fixture() {
    K6ExitNotice notice;
    for (std::size_t i = 0; i < notice.node_pub.size(); ++i)
        notice.node_pub[i] = static_cast<Byte>(i + 1);
    g_pub = notice.node_pub;
    K6ExitNoticeEndpoint v6;
    v6.address.family = Kad6Address::Family::IPv6;
    v6.address.addr = {0x20,0x01,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,1};
    v6.port = 8081;
    K6ExitNoticeEndpoint v4;
    v4.address.family = Kad6Address::Family::IPv4;
    v4.address.addr = {203,0,113,10};
    v4.port = 8080;
    notice.endpoints = {v6, v4}; // intentionally unsorted
    notice.service_classes = {K6ExitNoticeService::ExitEd2kDial,
                              K6ExitNoticeService::ExitKad};
    notice.software = "eMule-eSE/0.70b";
    notice.configured_limits.max_kbps = 4096;
    notice.configured_limits.max_sessions = 64;
    notice.valid_from = 1700000000;
    notice.valid_until = 1700003600;
    notice.logging_policy = K6ExitLoggingPolicy::SystemMetadataPossible;
    notice.abuse_contact = "mailto:abuse@example.invalid";
    notice.policy_url = "https://example.invalid/kad6";
    return notice;
}

static void TestCanonicalAndSignature() {
    const Kad6CryptoHooks hooks = Hooks();
    K6ExitNotice notice = Fixture();
    std::string json;
    CHECK(SignK6ExitNotice(hooks, notice, json) == Kad6Status::Ok,
          "exit notice signs");
    CHECK(VerifyK6ExitNotice(hooks, notice) == Kad6Status::Ok,
          "exit notice verifies");
    CHECK(json.rfind("{\"abuse_contact\":", 0) == 0,
          "JCS starts with lexicographically first key");
    CHECK(json.find("\"configured_limits\":{\"max_kbps\":4096,\"max_sessions\":64}") !=
          std::string::npos, "nested configured limits are canonical");
    CHECK(json.find("\"address\":\"203.0.113.10\",\"family\":4,\"port\":8080") !=
          std::string::npos, "IPv4 endpoint canonical");
    CHECK(json.find("\"address\":\"2001:db8::1\",\"family\":6,\"port\":8081") !=
          std::string::npos, "IPv6 endpoint RFC 5952 canonical");
    CHECK(json.find("EXIT_KAD\",\"EXIT_ED2K_DIAL") != std::string::npos,
          "service class array protocol-sorted");
    CHECK(json.find(' ') != std::string::npos, "fixed human notice retains required spaces");
    CHECK(json.find("=\"") == std::string::npos,
          "base64url fields carry no padding");
    const std::size_t service = json.find("\"service_classes\"");
    const std::size_t signature = json.find("\"signature\"");
    const std::size_t software = json.find("\"software\"");
    CHECK(service < signature && signature < software,
          "signature inserted at JCS lexical position");

    notice.configured_limits.max_sessions++;
    CHECK(VerifyK6ExitNotice(hooks, notice) == Kad6Status::AuthFailed,
          "notice content tamper rejected");
}

static void TestValidation() {
    const Kad6CryptoHooks hooks = Hooks();
    K6ExitNotice notice = Fixture();
    std::string json;
    notice.policy_url = "http://example.invalid";
    CHECK(SignK6ExitNotice(hooks, notice, json) == Kad6Status::BadValue,
          "policy URL requires HTTPS");
    notice = Fixture();
    notice.service_classes.push_back(K6ExitNoticeService::ExitKad);
    CHECK(SignK6ExitNotice(hooks, notice, json) == Kad6Status::BadValue,
          "duplicate service class rejected");
    notice = Fixture();
    notice.valid_until = notice.valid_from + kK6ExitNoticeMaxValiditySeconds + 1;
    CHECK(SignK6ExitNotice(hooks, notice, json) == Kad6Status::BadValue,
          "overlong notice validity rejected");
    notice = Fixture();
    notice.notice = "Not the required relay disclosure";
    CHECK(SignK6ExitNotice(hooks, notice, json) == Kad6Status::BadValue,
          "relay disclosure cannot be weakened");
    notice = Fixture();
    notice.software = std::string("bad\0text", 8);
    CHECK(SignK6ExitNotice(hooks, notice, json) == Kad6Status::BadValue,
          "I-JSON NUL rejected");
}

int main() {
    TestCanonicalAndSignature();
    TestValidation();
    std::printf("test_kad6_exit_notice: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
