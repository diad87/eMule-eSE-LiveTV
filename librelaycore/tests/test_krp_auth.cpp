// SPDX-License-Identifier: MIT
#include "relay/krp_auth.h"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

namespace {

int g_pass = 0;
int g_fail = 0;

#define CHECK(condition, message) \
    do { \
        if (condition) { ++g_pass; } \
        else { ++g_fail; std::printf("  FAIL: %s (%s:%d)\n", message, __FILE__, __LINE__); } \
    } while (0)

template <typename Array>
void Fill(Array& value, relay::Byte seed) {
    for (std::size_t i = 0; i < value.size(); ++i)
        value[i] = static_cast<relay::Byte>(seed + i);
}

void MakeSignature(const relay::NodeId& node_id,
                   const relay::Byte* message,
                   std::size_t message_size,
                   relay::KrpAuthSignature& signature) {
    for (std::size_t i = 0; i < signature.size(); ++i)
        signature[i] = static_cast<relay::Byte>(node_id[i % node_id.size()] ^ i);
    for (std::size_t i = 0; i < message_size; ++i)
        signature[i % signature.size()] ^= static_cast<relay::Byte>(message[i] + i * 17u);
}

class FakeSigner final : public relay::INodeIdentitySigner {
public:
    relay::NodeId node_id{};
    bool persistent = true;
    bool succeeds = true;
    std::size_t calls = 0;

    bool IsPersistent() const noexcept override { return persistent; }
    const relay::NodeId& PublicNodeId() const noexcept override { return node_id; }
    bool Sign(const relay::Byte* message,
              std::size_t message_size,
              relay::KrpAuthSignature& signature) noexcept override {
        ++calls;
        if (!succeeds || message == nullptr || message_size == 0)
            return false;
        MakeSignature(node_id, message, message_size, signature);
        return true;
    }
};

class FakeVerifier final : public relay::IKrpIdentityVerifier {
public:
    bool available = true;
    std::size_t calls = 0;

    bool Verify(const relay::NodeId& node_id,
                const relay::Byte* message,
                std::size_t message_size,
                const relay::KrpAuthSignature& signature) noexcept override {
        ++calls;
        if (!available || message == nullptr || message_size == 0)
            return false;
        relay::KrpAuthSignature expected{};
        MakeSignature(node_id, message, message_size, expected);
        return expected == signature;
    }
};

relay::KrpAuthTranscriptContext MakeContext() {
    relay::KrpAuthTranscriptContext context;
    context.carrier_profile = relay::KrpCarrierProfile::WssH1;
    context.challenge_timestamp = 42;
    Fill(context.node_id, 1);
    Fill(context.client_nonce, 0x21);
    Fill(context.relay_id, 0x41);
    Fill(context.relay_nonce, 0x51);
    Fill(context.carrier_binding, 0x81);
    Fill(context.settings_hash, 0xA1);
    return context;
}

void TestTranscriptAndHooks() {
    const relay::KrpAuthTranscriptContext context = MakeContext();
    std::vector<relay::Byte> transcript;
    CHECK(relay::BuildKrpAuthTranscript(context, transcript) == relay::RelayStatus::Ok,
          "valid auth transcript builds");
    static const char domain[] = "eSE-KRP-AUTH-v1";
    CHECK(transcript.size() == 195 &&
              std::equal(domain, domain + sizeof(domain) - 1, transcript.begin()),
          "auth transcript pins domain and exact size");
    CHECK(transcript[15] == 1 && transcript[16] == 0 &&
              transcript[17] == 2 && transcript[18] == 42,
          "auth transcript pins version, carrier and timestamp order");

    relay::KrpAuthTranscriptContext invalid = context;
    invalid.carrier_binding.fill(0);
    std::vector<relay::Byte> sentinel = {9, 9};
    CHECK(relay::BuildKrpAuthTranscript(invalid, sentinel) ==
              relay::RelayStatus::InvalidArgument &&
              sentinel == std::vector<relay::Byte>({9, 9}),
          "missing carrier exporter fails without replacing output");
    invalid = context;
    invalid.version_major = 2;
    CHECK(relay::BuildKrpAuthTranscript(invalid, sentinel) ==
              relay::RelayStatus::UnsupportedVersion,
          "unsupported major version is rejected");
    invalid = context;
    invalid.carrier_profile = static_cast<relay::KrpCarrierProfile>(255);
    CHECK(relay::BuildKrpAuthTranscript(invalid, sentinel) ==
              relay::RelayStatus::UnsupportedOption,
          "unknown carrier profile is rejected");

    FakeSigner signer;
    signer.node_id = context.node_id;
    FakeVerifier verifier;
    relay::KrpAuthResponse response;
    CHECK(relay::SignKrpAuthTranscript(context, signer, response) == relay::RelayStatus::Ok &&
              signer.calls == 1 && response.node_id == context.node_id,
          "persistent NodeIdentity signs canonical transcript");
    CHECK(relay::VerifyKrpAuthTranscript(context, response, verifier) ==
              relay::RelayStatus::Ok && verifier.calls == 1,
          "relay verifies transcript signature");

    relay::KrpAuthTranscriptContext tampered = context;
    tampered.carrier_binding[0] ^= 1;
    CHECK(relay::VerifyKrpAuthTranscript(tampered, response, verifier) ==
              relay::RelayStatus::AuthFailed,
          "signature is bound to carrier exporter");
    tampered = context;
    tampered.settings_hash[4] ^= 1;
    CHECK(relay::VerifyKrpAuthTranscript(tampered, response, verifier) ==
              relay::RelayStatus::AuthFailed,
          "signature is bound to negotiated settings");
    response.signature[0] ^= 1;
    CHECK(relay::VerifyKrpAuthTranscript(context, response, verifier) ==
              relay::RelayStatus::AuthFailed,
          "signature tamper is rejected");

    relay::KrpAuthResponse unchanged;
    unchanged.signature.fill(0xEE);
    signer.persistent = false;
    CHECK(relay::SignKrpAuthTranscript(context, signer, unchanged) ==
              relay::RelayStatus::AuthFailed && unchanged.signature[0] == 0xEE,
          "ephemeral NodeIdentity cannot advertise KRP auth");
    signer.persistent = true;
    signer.node_id[0] ^= 1;
    CHECK(relay::SignKrpAuthTranscript(context, signer, unchanged) ==
              relay::RelayStatus::AuthFailed,
          "signer public key must equal transcript NodeID");
}

std::uint64_t NextRandom(std::uint64_t& state) {
    state ^= state << 13;
    state ^= state >> 7;
    state ^= state << 17;
    return state;
}

void TestDeterministicAuthFuzz() {
    std::uint64_t random = 0x415554485F50315Full;
    FakeSigner signer;
    FakeVerifier verifier;
    relay::KrpAuthTranscriptContext context = MakeContext();
    signer.node_id = context.node_id;
    for (std::size_t iteration = 0; iteration < 10000; ++iteration) {
        context.challenge_timestamp = NextRandom(random) | 1u;
        context.carrier_profile = static_cast<relay::KrpCarrierProfile>(
            1u + (NextRandom(random) % 4u));
        relay::KrpAuthResponse response;
        CHECK(relay::SignKrpAuthTranscript(context, signer, response) ==
                  relay::RelayStatus::Ok,
              "fuzz valid transcript signs");
        CHECK(relay::VerifyKrpAuthTranscript(context, response, verifier) ==
                  relay::RelayStatus::Ok,
              "fuzz valid transcript verifies");
        response.signature[NextRandom(random) % response.signature.size()] ^= 1;
        CHECK(relay::VerifyKrpAuthTranscript(context, response, verifier) ==
                  relay::RelayStatus::AuthFailed,
              "fuzz signature mutation fails");
    }
    std::printf("  deterministic auth fuzz: 10000 transcripts\n");
}

} // namespace

static_assert(sizeof(relay::KrpAuthSignature) == 64, "Ed25519 signature stays 64 bytes");

int main() {
    TestTranscriptAndHooks();
    TestDeterministicAuthFuzz();
    std::printf("test_krp_auth: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
