// SPDX-License-Identifier: MIT
#include "fuzz_common.h"
#include "kad6/kad6_bootstrap.h"

#include <cstring>

namespace kad6_fuzz {
namespace {

bool FakeSha(const Byte* data, std::size_t length, Byte out[32]) {
    std::uint32_t state = 2166136261u;
    for (std::size_t i = 0; i < length; ++i)
        state = (state ^ data[i]) * 16777619u;
    for (std::size_t i = 0; i < 32; ++i) {
        state = state * 1664525u + 1013904223u +
                static_cast<std::uint32_t>(i);
        out[i] = static_cast<Byte>(state >> 24);
    }
    return true;
}

void FakeSignature(const Byte pub[32], const Byte* message,
                   std::size_t length, Byte signature[64]) {
    std::vector<Byte> input(pub, pub + 32);
    input.insert(input.end(), message, message + length);
    (void)FakeSha(input.data(), input.size(), signature);
    input.push_back(0xa5);
    (void)FakeSha(input.data(), input.size(), signature + 32);
}

bool FakeSign(const Byte* secret, std::size_t secretLength,
              const Byte* message, std::size_t length, Byte signature[64]) {
    if (secret == nullptr || secretLength != 32)
        return false;
    FakeSignature(secret, message, length, signature);
    return true;
}

bool FakeVerify(const Byte pub[32], const Byte* message,
                std::size_t length, const Byte signature[64]) {
    Byte expected[64] = {};
    FakeSignature(pub, message, length, expected);
    return kad6::Kad6CtEqual(expected, signature, sizeof expected);
}

kad6::Kad6CryptoHooks Hooks() {
    kad6::Kad6CryptoHooks hooks;
    hooks.sha256 = &FakeSha;
    hooks.ed25519_sign = &FakeSign;
    hooks.ed25519_verify = &FakeVerify;
    return hooks;
}

std::vector<Byte> ValidBundle(const kad6::Kad6CryptoHooks& hooks,
                              const kad6::Ed25519Pub& distributionPub,
                              std::uint64_t now) {
    kad6::K6BootstrapBundle bundle;
    bundle.sequence = 7;
    bundle.valid_from = now - 60;
    bundle.valid_until = now + 3600;
    for (std::size_t n = 0; n < kad6::kK6BootstrapMinEntries; ++n) {
        const Byte seed = static_cast<Byte>(n + 1);
        kad6::K6RouterRecord record;
        for (std::size_t i = 0; i < record.kad_id.size(); ++i)
            record.kad_id[i] = static_cast<Byte>(seed + i);
        for (std::size_t i = 0; i < record.node_pub.size(); ++i)
            record.node_pub[i] = static_cast<Byte>(seed ^ (0x80u + i));
        record.epoch = 1000 + seed;
        record.caps = 1;
        record.valid_from = now - 60;
        record.valid_until = now + 1800;
        kad6::K6Endpoint endpoint;
        endpoint.addr.family = kad6::Kad6Address::Family::IPv6;
        endpoint.addr.addr = {0x20, 0x01, 0x0d, 0xb8, seed, 0, 0, 0,
                              0, 0, 0, 0, 0, 0, 0, seed};
        endpoint.udp_port = static_cast<std::uint16_t>(4600 + seed);
        endpoint.transport_flags = kad6::kK6EpUdpKad6;
        endpoint.valid_until = record.valid_until;
        record.endpoints.push_back(endpoint);
        std::vector<Byte> ignored;
        if (kad6::SignK6RouterRecord(
                hooks, record.node_pub.data(), record.node_pub.size(),
                record, ignored) != kad6::Kad6Status::Ok)
            return {};
        bundle.records.push_back(record);
    }
    std::vector<Byte> wire;
    if (kad6::SignK6BootstrapBundle(
            hooks, distributionPub, distributionPub.data(),
            distributionPub.size(), bundle, wire) != kad6::Kad6Status::Ok)
        wire.clear();
    return wire;
}

} // namespace

bool FuzzBootstrap(const Config& config, Report& report) {
    constexpr std::uint64_t now = 1'800'000'000ull;
    const kad6::Kad6CryptoHooks hooks = Hooks();
    kad6::Ed25519Pub distributionPub{};
    for (std::size_t i = 0; i < distributionPub.size(); ++i)
        distributionPub[i] = static_cast<Byte>(0x40 + i);
    const std::vector<Byte> valid = ValidBundle(hooks, distributionPub, now);
    const std::vector<std::vector<Byte>> corpus = {
        {}, valid, {static_cast<Byte>('K'), static_cast<Byte>('6')},
        std::vector<Byte>(4096, 0xff)};
    report.target = "bootstrap";
    Require(report, !valid.empty(), "valid bootstrap fixture");
    Rng rng(config.seed ^ 0x424f4f54u);
    for (std::size_t i = 0; i < config.iterations; ++i) {
        std::vector<Byte> input = Mutate(corpus, rng, i, 64 * 1024);
        kad6::K6BootstrapBundle decoded;
        const kad6::Kad6Status status = kad6::VerifyAndDecodeK6BootstrapBundle(
            hooks, distributionPub, DataOrNull(input), input.size(), 0, now,
            decoded);
        if (status == kad6::Kad6Status::Ok) {
            Require(report,
                    decoded.records.size() >= kad6::kK6BootstrapMinEntries &&
                    decoded.records.size() <= kad6::kK6BootstrapMaxEntries,
                    "bootstrap entry bounds");
            Require(report, decoded.sequence != 0,
                    "bootstrap sequence nonzero");
        }
        report.max_input = std::max(report.max_input, input.size());
        report.max_output = std::max(report.max_output,
            decoded.records.size() * sizeof(kad6::K6RouterRecord));
    }
    report.iterations = config.iterations;
    return report.failures == 0;
}

} // namespace kad6_fuzz
