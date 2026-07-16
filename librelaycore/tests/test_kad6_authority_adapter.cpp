// SPDX-License-Identifier: MIT
#include "relay/kad6_authority_adapter.h"

#include <cstddef>
#include <cstdint>
#include <cstdio>
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
void Fill(Array& value, std::uint8_t seed) {
    for (std::size_t i = 0; i < value.size(); ++i)
        value[i] = static_cast<std::uint8_t>(seed + i);
}

bool Hmac(const kad6::Byte* key,
          std::size_t key_size,
          const kad6::Byte* message,
          std::size_t message_size,
          kad6::Byte mac[kad6::kMacSize]) {
    if (key == nullptr || key_size == 0 || message == nullptr)
        return false;
    for (std::size_t i = 0; i < kad6::kMacSize; ++i)
        mac[i] = static_cast<kad6::Byte>(i * 7u);
    for (std::size_t i = 0; i < key_size; ++i)
        mac[i % kad6::kMacSize] ^= static_cast<kad6::Byte>(key[i] + i);
    for (std::size_t i = 0; i < message_size; ++i)
        mac[i % kad6::kMacSize] ^= static_cast<kad6::Byte>(message[i] + i * 13u);
    return true;
}

struct PolicyContext {
    bool consumed = false;
};

bool AllowTarget(void*, kad6::Byte, const kad6::K6Endpoint&) {
    return true;
}

bool ConsumeUse(void* opaque, const kad6::K6TargetTicket&) {
    PolicyContext* context = static_cast<PolicyContext*>(opaque);
    if (context == nullptr || context->consumed)
        return false;
    context->consumed = true;
    return true;
}

relay::KrpSession MakeSession() {
    relay::KrpSessionBinding binding;
    Fill(binding.session_id, 1);
    Fill(binding.node_id, 0x21);
    Fill(binding.owner_edge_id, 0x51);
    Fill(binding.fencing_token, 0x71);
    binding.session_epoch = 7;
    binding.route_generation = 41;
    relay::KrpSession session;
    (void)session.BeginAuthentication();
    (void)session.ActivateNew(binding);
    return session;
}

std::vector<kad6::Byte> IssueTicket(const kad6::Kad6CryptoHooks& crypto,
                                    const kad6::K6TargetPolicy& policy,
                                    const kad6::Byte* secret,
                                    std::size_t secret_size) {
    kad6::K6TargetTicket ticket;
    ticket.lease_id = 77;
    ticket.provenance_session = 1;
    ticket.provenance_stream = 2;
    ticket.provenance_seq = 3;
    ticket.provenance_digest[0] = 1;
    ticket.target_endpoint.addr.family = kad6::Kad6Address::Family::IPv4;
    ticket.target_endpoint.addr.addr[0] = 8;
    ticket.target_endpoint.addr.addr[1] = 8;
    ticket.target_endpoint.addr.addr[2] = 8;
    ticket.target_endpoint.addr.addr[3] = 8;
    ticket.target_endpoint.tcp_port = 4662;
    ticket.target_endpoint.valid_until = 1300;
    ticket.issued_at = 1000;
    ticket.expires_at = 1200;
    ticket.max_bytes = 4096;
    ticket.max_connections = 1;
    Fill(ticket.nonce, 0xA0);
    std::vector<kad6::Byte> wire;
    if (kad6::IssueK6TargetTicket(crypto,
                                  policy,
                                  secret,
                                  secret_size,
                                  ticket,
                                  wire) != kad6::Kad6Status::Ok)
        wire.clear();
    return wire;
}

void TestRealKad6TicketAdapter() {
    kad6::Kad6CryptoHooks crypto;
    crypto.hmac_sha256 = &Hmac;
    PolicyContext policy_context;
    kad6::K6TargetPolicy policy;
    policy.context = &policy_context;
    policy.allow_target = &AllowTarget;
    policy.consume_use = &ConsumeUse;
    const relay::Byte secret[] = {1, 2, 3, 4};
    const std::vector<kad6::Byte> wire = IssueTicket(
        crypto, policy, secret, sizeof(secret));
    CHECK(!wire.empty(), "fixture issues through existing K6TargetTicket codec");

    relay::Kad6TargetAuthorityVerifier verifier(
        crypto, policy, secret, sizeof(secret));
    CHECK(verifier.ready(), "Kad6 authority adapter requires crypto, policy and secret");
    relay::KrpSession session = MakeSession();
    relay::KrpAuthorityRequest request;
    request.service = relay::KrpService::LegacyTcpOutbound;
    request.kind = relay::KrpAuthorityKind::Kad6TargetTicket;
    request.session_id = session.binding().session_id;
    request.session_epoch = session.binding().session_epoch;
    request.route_generation = session.binding().route_generation;
    request.evidence.assign(wire.begin(), wire.end());
    relay::KrpAuthorityGrant grant;
    CHECK(relay::AuthorizeKrpService(session,
                                     request,
                                     1100,
                                     relay::KrpTransportPhase::Confirmed1Rtt,
                                     verifier,
                                     grant) == relay::RelayStatus::Ok &&
              grant.max_bytes == 4096 && grant.max_flows == 1 &&
              grant.kind == relay::KrpAuthorityKind::Kad6TargetTicket,
          "existing Kad6 ticket becomes bounded KRP service grant");
    CHECK(relay::AuthorizeKrpService(session,
                                     request,
                                     1100,
                                     relay::KrpTransportPhase::Confirmed1Rtt,
                                     verifier,
                                     grant) == relay::RelayStatus::AuthFailed,
          "existing atomic consume hook rejects ticket replay");

    relay::Kad6TargetAuthorityVerifier disabled(crypto, policy, nullptr, 0);
    CHECK(!disabled.ready() &&
              disabled.VerifyAndConsume(request, 1100, grant) == relay::RelayStatus::Disabled,
          "adapter without secret fails closed");
}

} // namespace

int main() {
    TestRealKad6TicketAdapter();
    std::printf("test_kad6_authority_adapter: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
