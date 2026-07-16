// SPDX-License-Identifier: MIT
// Cross-component G1 test: auth -> session -> authority -> flow + EPR lease.
#include "relay/epr_lease.h"
#include "relay/krp_auth.h"
#include "relay/krp_flow.h"

#include <cstddef>
#include <cstdint>
#include <cstdio>

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

void TestSignature(const relay::NodeId& node,
                   const relay::Byte* message,
                   std::size_t message_size,
                   relay::KrpAuthSignature& signature) {
    signature.fill(0);
    for (std::size_t i = 0; i < message_size; ++i)
        signature[i % signature.size()] ^= static_cast<relay::Byte>(message[i] + i);
    for (std::size_t i = 0; i < signature.size(); ++i)
        signature[i] ^= node[i % node.size()];
}

class Signer final : public relay::INodeIdentitySigner {
public:
    relay::NodeId node{};
    bool IsPersistent() const noexcept override { return true; }
    const relay::NodeId& PublicNodeId() const noexcept override { return node; }
    bool Sign(const relay::Byte* message,
              std::size_t message_size,
              relay::KrpAuthSignature& signature) noexcept override {
        TestSignature(node, message, message_size, signature);
        return true;
    }
};

class Verifier final : public relay::IKrpIdentityVerifier {
public:
    bool Verify(const relay::NodeId& node,
                const relay::Byte* message,
                std::size_t message_size,
                const relay::KrpAuthSignature& signature) noexcept override {
        relay::KrpAuthSignature expected{};
        TestSignature(node, message, message_size, expected);
        return signature == expected;
    }
};

class Authority final : public relay::IServiceAuthorityVerifier {
public:
    std::size_t calls = 0;
    relay::RelayStatus VerifyAndConsume(const relay::KrpAuthorityRequest& request,
                                        std::uint64_t now,
                                        relay::KrpAuthorityGrant& grant) noexcept override {
        ++calls;
        relay::KrpAuthorityGrant result;
        Fill(result.grant_id, 0xD0);
        result.service = request.service;
        result.kind = request.kind;
        result.expires_at = now + 100;
        result.max_bytes = 4096;
        result.max_flows = 1;
        result.effective_priority = 4;
        grant = result;
        return relay::RelayStatus::Ok;
    }
};

void TestP1GatePath() {
    relay::KrpAuthTranscriptContext auth;
    auth.carrier_profile = relay::KrpCarrierProfile::WssH1;
    auth.challenge_timestamp = 1000;
    Fill(auth.node_id, 0x21);
    Fill(auth.client_nonce, 0x41);
    Fill(auth.relay_id, 0x61);
    Fill(auth.relay_nonce, 0x71);
    Fill(auth.carrier_binding, 0x91);
    Fill(auth.settings_hash, 0xB1);
    Signer signer;
    signer.node = auth.node_id;
    Verifier verifier;
    relay::KrpAuthResponse response;
    CHECK(relay::SignKrpAuthTranscript(auth, signer, response) == relay::RelayStatus::Ok &&
              relay::VerifyKrpAuthTranscript(auth, response, verifier) == relay::RelayStatus::Ok,
          "G1 transcript authenticates NodeIdentity and carrier binding");

    relay::KrpSessionBinding binding;
    Fill(binding.session_id, 1);
    binding.node_id = response.node_id;
    Fill(binding.owner_edge_id, 0x51);
    Fill(binding.fencing_token, 0x71);
    binding.session_epoch = 7;
    binding.route_generation = 41;
    relay::KrpSession session;
    CHECK(session.BeginAuthentication() == relay::RelayStatus::Ok &&
              session.ActivateNew(binding) == relay::RelayStatus::Ok,
          "G1 verified identity activates one session epoch");

    relay::KrpAuthorityRequest request;
    request.service = relay::KrpService::FileTransfer;
    request.kind = relay::KrpAuthorityKind::FilePeerTicket;
    request.session_id = binding.session_id;
    request.session_epoch = binding.session_epoch;
    request.route_generation = binding.route_generation;
    request.evidence = {1, 2, 3};
    Authority authority;
    relay::KrpAuthorityGrant grant;
    CHECK(relay::AuthorizeKrpService(session,
                                     request,
                                     1000,
                                     relay::KrpTransportPhase::EarlyData0Rtt,
                                     authority,
                                     grant) == relay::RelayStatus::OneRttRequired &&
              authority.calls == 0,
          "G1 replayable early data cannot spend authority");
    CHECK(relay::AuthorizeKrpService(session,
                                     request,
                                     1000,
                                     relay::KrpTransportPhase::Confirmed1Rtt,
                                     authority,
                                     grant) == relay::RelayStatus::Ok && authority.calls == 1,
          "G1 confirmed session consumes service-specific authority");

    relay::KrpFlowIdRegistry flow_ids(binding.session_epoch);
    CHECK(flow_ids.Register(1, binding.session_epoch) == relay::RelayStatus::Ok,
          "G1 FlowID is registered once in session epoch");
    relay::KrpFlowConfig flow_config;
    flow_config.flow_id = 1;
    Fill(flow_config.logical_flow_id, 0x31);
    flow_config.service = request.service;
    flow_config.session_epoch = binding.session_epoch;
    flow_config.route_generation = binding.route_generation;
    flow_config.soft_buffer_bytes = 64;
    flow_config.hard_buffer_bytes = 128;
    flow_config.pressure_timeout_ms = 100;
    relay::KrpFlow flow;
    CHECK(flow.Initialize(flow_config) == relay::RelayStatus::Ok &&
              flow.BeginAuthorization() == relay::RelayStatus::Ok &&
              flow.AcceptAuthority(grant, 1000) == relay::RelayStatus::Ok &&
              flow.ConnectionEstablished() == relay::RelayStatus::Ok,
          "G1 authorized flow reaches OPEN with bounded config");

    relay::EprLeaseRequest lease_request;
    lease_request.lease_id = 9;
    lease_request.generation = 1;
    lease_request.session_id = binding.session_id;
    lease_request.node_id = binding.node_id;
    lease_request.lease_class = relay::EprLeaseClass::PeerShared;
    lease_request.request_tcp = true;
    lease_request.issued_at = 1000;
    lease_request.expires_at = 1900;
    lease_request.grace_expires_at = 1960;
    relay::EprLease lease;
    CHECK(lease.Initialize(lease_request,
                           session,
                           relay::KrpTransportPhase::EarlyData0Rtt) ==
              relay::RelayStatus::OneRttRequired,
          "G1 early data cannot allocate EPR lease");
    CHECK(lease.Initialize(lease_request,
                           session,
                           relay::KrpTransportPhase::Confirmed1Rtt) == relay::RelayStatus::Ok,
          "G1 confirmed authenticated session requests EPR lease");
    relay::EprPublicAddress address;
    address.family = relay::EprAddressFamily::IPv4;
    address.bytes[0] = 8;
    address.bytes[1] = 8;
    address.bytes[2] = 4;
    address.bytes[3] = 4;
    relay::EprProbeNonce probe;
    Fill(probe, 0xE0);
    CHECK(lease.Allocate(1, address, 4662, 0) == relay::RelayStatus::Ok &&
              lease.MarkBound() == relay::RelayStatus::Ok &&
              lease.BeginProbe(probe) == relay::RelayStatus::Ok &&
              !lease.CanAcceptNewTraffic() &&
              lease.CompleteProbe(probe, true) == relay::RelayStatus::Ok &&
              lease.CanAcceptNewTraffic(),
          "G1 EPR only becomes ACTIVE after matching external probe");

    relay::OwnerEdgeId owner;
    relay::FencingToken fencing;
    Fill(owner, 0xA0);
    Fill(fencing, 0xC0);
    CHECK(session.BeginMigration() == relay::RelayStatus::Ok &&
              session.CommitMigration(41, 42, owner, fencing) == relay::RelayStatus::Ok,
          "G1 route migration advances fencing generation");
    CHECK(relay::AuthorizeKrpService(session,
                                     request,
                                     1001,
                                     relay::KrpTransportPhase::Confirmed1Rtt,
                                     authority,
                                     grant) == relay::RelayStatus::StaleGeneration &&
              authority.calls == 1,
          "G1 old route generation cannot open another flow");
    CHECK(lease.Renew(1,
                      2,
                      1500,
                      2400,
                      2460,
                      session,
                      relay::KrpTransportPhase::Confirmed1Rtt) == relay::RelayStatus::Ok &&
              lease.record().route_generation == 42,
          "G1 current owner fences and renews lease generation");

    relay::KrpMemoryBudget budget(256);
    CHECK(flow.Reset(budget) == relay::RelayStatus::Ok &&
              flow_ids.MarkTerminal(1, binding.session_epoch) == relay::RelayStatus::Ok,
          "G1 flow shutdown releases bounded state");
    CHECK(session.BeginDrain() == relay::RelayStatus::Ok &&
              !relay::RelayCoreCanOpenNetwork(),
          "G1 core remains network-disabled after semantic gate");
}

} // namespace

static_assert(relay::kNodeIdSize == 32, "G1 uses full Ed25519 NodeID in every record");

int main() {
    TestP1GatePath();
    std::printf("test_krp_p1_gate: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
