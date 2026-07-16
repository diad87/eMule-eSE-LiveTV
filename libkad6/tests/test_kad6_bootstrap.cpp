// SPDX-License-Identifier: MIT
#include "kad6/kad6_bootstrap.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <vector>

using namespace kad6;

static int g_pass = 0;
static int g_fail = 0;
#define CHECK(c, m) do { if (c) ++g_pass; else { ++g_fail; \
    std::printf("  FAIL: %s (%s:%d)\n", m, __FILE__, __LINE__); } } while (0)

static bool FakeSha(const Byte* data, std::size_t length, Byte out[32]) {
    std::uint32_t state = 2166136261u;
    for (std::size_t i = 0; i < length; ++i)
        state = (state ^ data[i]) * 16777619u;
    for (std::size_t i = 0; i < 32; ++i) {
        state = state * 1664525u + 1013904223u + static_cast<std::uint32_t>(i);
        out[i] = static_cast<Byte>(state >> 24);
    }
    return true;
}

static void FakeSignature(const Byte pub[32], const Byte* message,
                          std::size_t length, Byte signature[64]) {
    std::vector<Byte> input(pub, pub + 32);
    input.insert(input.end(), message, message + length);
    FakeSha(input.data(), input.size(), signature);
    input.push_back(0xA5);
    FakeSha(input.data(), input.size(), signature + 32);
}

static bool FakeSign(const Byte* secret, std::size_t secretLength,
                     const Byte* message, std::size_t length,
                     Byte signature[64]) {
    if (secret == nullptr || secretLength != 32)
        return false;
    FakeSignature(secret, message, length, signature);
    return true;
}

static bool FakeVerify(const Byte pub[32], const Byte* message,
                       std::size_t length, const Byte signature[64]) {
    Byte expected[64] = {};
    FakeSignature(pub, message, length, expected);
    return Kad6CtEqual(expected, signature, sizeof expected);
}

static Kad6CryptoHooks Hooks() {
    Kad6CryptoHooks hooks;
    hooks.sha256 = &FakeSha;
    hooks.ed25519_sign = &FakeSign;
    hooks.ed25519_verify = &FakeVerify;
    return hooks;
}

static K6RouterRecord Router(Byte seed, std::uint64_t now,
                             const Kad6CryptoHooks& hooks) {
    K6RouterRecord record;
    for (std::size_t i = 0; i < record.kad_id.size(); ++i)
        record.kad_id[i] = static_cast<Byte>(seed + i);
    for (std::size_t i = 0; i < record.node_pub.size(); ++i)
        record.node_pub[i] = static_cast<Byte>(seed ^ (0x80 + i));
    record.epoch = 1000 + seed;
    record.caps = 0x0102030400000000ull | seed;
    record.valid_from = now - 60;
    record.valid_until = now + 3600;
    K6Endpoint endpoint;
    endpoint.addr.family = Kad6Address::Family::IPv6;
    endpoint.addr.addr = {0x20, 0x01, 0x0d, 0xb8, seed, 0, 0, 0,
                          0, 0, 0, 0, 0, 0, 0, seed};
    endpoint.udp_port = static_cast<std::uint16_t>(4600 + seed);
    endpoint.tcp_port = static_cast<std::uint16_t>(4700 + seed);
    endpoint.transport_flags = kK6EpUdpKad6;
    endpoint.valid_until = record.valid_until;
    record.endpoints.push_back(endpoint);
    std::vector<Byte> ignored;
    const Kad6Status status = SignK6RouterRecord(
        hooks, record.node_pub.data(), record.node_pub.size(), record, ignored);
    CHECK(status == Kad6Status::Ok, "fixture router signs");
    return record;
}

static K6BootstrapBundle Bundle(std::uint64_t now,
                                const Kad6CryptoHooks& hooks) {
    K6BootstrapBundle bundle;
    bundle.sequence = 42;
    bundle.valid_from = now - 30;
    bundle.valid_until = now + 1800;
    for (std::size_t i = 0; i < kK6BootstrapMinEntries; ++i)
        bundle.records.push_back(Router(static_cast<Byte>(i + 1), now, hooks));
    return bundle;
}

int main() {
    const std::uint64_t now = 1'800'000'000ull;
    const Kad6CryptoHooks hooks = Hooks();
    Ed25519Pub distributionPub{};
    for (std::size_t i = 0; i < distributionPub.size(); ++i)
        distributionPub[i] = static_cast<Byte>(0x40 + i);
    K6BootstrapBundle bundle = Bundle(now, hooks);
    std::vector<Byte> wire;
    CHECK(SignK6BootstrapBundle(hooks, distributionPub,
                                distributionPub.data(), distributionPub.size(),
                                bundle, wire) == Kad6Status::Ok,
          "bootstrap bundle signs");
    CHECK(wire.size() <= kK6BootstrapMaxWireSize &&
              wire[0] == 'K' && wire[6] == '1' && wire[7] == 0,
          "bootstrap wire bounded and magic exact");

    K6BootstrapBundle decoded;
    CHECK(VerifyAndDecodeK6BootstrapBundle(
              hooks, distributionPub, wire.data(), wire.size(), 41, now,
              decoded) == Kad6Status::Ok,
          "bootstrap bundle verifies");
    CHECK(decoded.sequence == 42 &&
              decoded.records.size() == kK6BootstrapMinEntries &&
              decoded.records.front().kad_id == bundle.records.front().kad_id,
          "bootstrap bundle round trip");
    CHECK(VerifyAndDecodeK6BootstrapBundle(
              hooks, distributionPub, wire.data(), wire.size(), 42, now,
              decoded) == Kad6Status::StaleEpoch,
          "bootstrap anti-rollback sequence");
    CHECK(VerifyAndDecodeK6BootstrapBundle(
              hooks, distributionPub, wire.data(), wire.size(), 0,
              bundle.valid_until, decoded) == Kad6Status::Expired,
          "bootstrap expiry enforced");
    CHECK(VerifyAndDecodeK6BootstrapBundle(
              hooks, distributionPub, wire.data(), wire.size(), 0,
              bundle.valid_from - 1, decoded) == Kad6Status::BadValue,
          "bootstrap not-before enforced");

    std::vector<Byte> tampered = wire;
    tampered[kK6BootstrapHeaderSize + 10] ^= 1;
    CHECK(VerifyAndDecodeK6BootstrapBundle(
              hooks, distributionPub, tampered.data(), tampered.size(), 0,
              now, decoded) == Kad6Status::AuthFailed,
          "entry tamper fails outer hash");
    Ed25519Pub wrongPin = distributionPub;
    wrongPin[0] ^= 1;
    CHECK(VerifyAndDecodeK6BootstrapBundle(
              hooks, wrongPin, wire.data(), wire.size(), 0, now, decoded) ==
              Kad6Status::AuthFailed,
          "wrong distribution pin rejected");

    K6BootstrapBundle badInner = Bundle(now, hooks);
    badInner.records[5].signature[0] ^= 1;
    CHECK(SignK6BootstrapBundle(hooks, distributionPub,
                                distributionPub.data(), distributionPub.size(),
                                badInner, tampered) == Kad6Status::Ok,
          "outer signer can preserve an invalid inner record");
    CHECK(VerifyAndDecodeK6BootstrapBundle(
              hooks, distributionPub, tampered.data(), tampered.size(), 0,
              now, decoded) == Kad6Status::AuthFailed,
          "inner router signature independently verified");

    K6BootstrapBundle tooSmall = Bundle(now, hooks);
    tooSmall.records.pop_back();
    CHECK(SignK6BootstrapBundle(hooks, distributionPub,
                                distributionPub.data(), distributionPub.size(),
                                tooSmall, tampered) == Kad6Status::BadValue &&
              tampered.empty(),
          "bundle minimum candidate count enforced");
    K6BootstrapBundle duplicate = Bundle(now, hooks);
    duplicate.records.back().kad_id = duplicate.records.front().kad_id;
    CHECK(SignK6BootstrapBundle(hooks, distributionPub,
                                distributionPub.data(), distributionPub.size(),
                                duplicate, tampered) == Kad6Status::BadValue,
          "duplicate router identity rejected");

    std::vector<Byte> trailing = wire;
    trailing.push_back(0);
    CHECK(VerifyAndDecodeK6BootstrapBundle(
              hooks, distributionPub, trailing.data(), trailing.size(), 0,
              now, decoded) == Kad6Status::Malformed,
          "bundle trailing byte rejected");
    CHECK(VerifyAndDecodeK6BootstrapBundle(
              hooks, distributionPub, nullptr, 1, 0, now, decoded) ==
              Kad6Status::NullArgument,
          "bundle null input rejected");
    for (std::size_t cut = 0; cut < wire.size(); ++cut) {
        CHECK(VerifyAndDecodeK6BootstrapBundle(
                  hooks, distributionPub, wire.data(), cut, 0, now,
                  decoded) != Kad6Status::Ok,
              "every truncated bundle prefix rejected");
    }

    std::uint32_t state = 0x4b364254u;
    for (int iteration = 0; iteration < 4096; ++iteration) {
        state = state * 1664525u + 1013904223u;
        const std::size_t size = state % 4096;
        std::vector<Byte> input(size);
        for (Byte& value : input) {
            state = state * 1664525u + 1013904223u;
            value = static_cast<Byte>(state >> 24);
        }
        const Kad6Status status = VerifyAndDecodeK6BootstrapBundle(
            hooks, distributionPub, input.empty() ? nullptr : input.data(),
            input.size(), 0, now, decoded);
        CHECK(status != Kad6Status::Ok ||
                  decoded.records.size() <= kK6BootstrapMaxEntries,
              "bounded random bundle decode");
    }

    std::printf("test_kad6_bootstrap: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
