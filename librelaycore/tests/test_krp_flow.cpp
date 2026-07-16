// SPDX-License-Identifier: MIT
#include "relay/krp_flow.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>

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

relay::KrpSessionBinding MakeBinding() {
    relay::KrpSessionBinding binding;
    Fill(binding.session_id, 1);
    Fill(binding.node_id, 0x21);
    Fill(binding.owner_edge_id, 0x51);
    Fill(binding.fencing_token, 0x71);
    binding.session_epoch = 7;
    binding.route_generation = 41;
    return binding;
}

relay::KrpSession MakeActiveSession() {
    relay::KrpSession session;
    (void)session.BeginAuthentication();
    (void)session.ActivateNew(MakeBinding());
    return session;
}

relay::KrpAuthorityGrant MakeGrant(relay::KrpService service,
                                   relay::KrpAuthorityKind kind) {
    relay::KrpAuthorityGrant grant;
    Fill(grant.grant_id, 0xA0);
    grant.service = service;
    grant.kind = kind;
    grant.expires_at = 1200;
    grant.max_bytes = 1000;
    grant.max_flows = 1;
    grant.effective_priority = 3;
    return grant;
}

class FakeAuthorityVerifier final : public relay::IServiceAuthorityVerifier {
public:
    relay::RelayStatus status = relay::RelayStatus::Ok;
    relay::KrpAuthorityGrant result{};
    std::size_t calls = 0;

    relay::RelayStatus VerifyAndConsume(const relay::KrpAuthorityRequest&,
                                        std::uint64_t,
                                        relay::KrpAuthorityGrant& grant) noexcept override {
        ++calls;
        if (status == relay::RelayStatus::Ok)
            grant = result;
        return status;
    }
};

relay::KrpAuthorityRequest MakeAuthorityRequest(const relay::KrpSession& session) {
    relay::KrpAuthorityRequest request;
    request.service = relay::KrpService::LegacyTcpOutbound;
    request.kind = relay::KrpAuthorityKind::Kad6TargetTicket;
    request.session_id = session.binding().session_id;
    request.session_epoch = session.binding().session_epoch;
    request.route_generation = session.binding().route_generation;
    request.evidence = {1, 2, 3, 4};
    return request;
}

void TestServiceAuthority() {
    relay::KrpSession session = MakeActiveSession();
    relay::KrpAuthorityRequest request = MakeAuthorityRequest(session);
    FakeAuthorityVerifier verifier;
    verifier.result = MakeGrant(request.service, request.kind);
    relay::KrpAuthorityGrant grant;

    CHECK(relay::AuthorizeKrpService(session,
                                     request,
                                     1000,
                                     relay::KrpTransportPhase::EarlyData0Rtt,
                                     verifier,
                                     grant) == relay::RelayStatus::OneRttRequired &&
              verifier.calls == 0,
          "0-RTT cannot consume flow authority or open a flow");

    request.kind = relay::KrpAuthorityKind::Administrative;
    CHECK(relay::AuthorizeKrpService(session,
                                     request,
                                     1000,
                                     relay::KrpTransportPhase::Confirmed1Rtt,
                                     verifier,
                                     grant) == relay::RelayStatus::TargetForbidden &&
              verifier.calls == 0,
          "service-authority mismatch cannot become a generic proxy grant");
    request = MakeAuthorityRequest(session);
    request.evidence.clear();
    CHECK(relay::AuthorizeKrpService(session,
                                     request,
                                     1000,
                                     relay::KrpTransportPhase::Confirmed1Rtt,
                                     verifier,
                                     grant) == relay::RelayStatus::AuthFailed,
          "non-internal service requires evidence");
    request = MakeAuthorityRequest(session);
    request.evidence.resize(relay::kKrpMaxAuthorityEvidence + 1);
    CHECK(relay::AuthorizeKrpService(session,
                                     request,
                                     1000,
                                     relay::KrpTransportPhase::Confirmed1Rtt,
                                     verifier,
                                     grant) == relay::RelayStatus::TooLarge,
          "authority evidence is bounded before verifier allocation");

    request = MakeAuthorityRequest(session);
    verifier.status = relay::RelayStatus::ReplayDetected;
    CHECK(relay::AuthorizeKrpService(session,
                                     request,
                                     1000,
                                     relay::KrpTransportPhase::Confirmed1Rtt,
                                     verifier,
                                     grant) == relay::RelayStatus::ReplayDetected,
          "single-use authority replay propagates fail-closed");
    verifier.status = relay::RelayStatus::Ok;
    verifier.result = MakeGrant(request.service, relay::KrpAuthorityKind::FilePeerTicket);
    CHECK(relay::AuthorizeKrpService(session,
                                     request,
                                     1000,
                                     relay::KrpTransportPhase::Confirmed1Rtt,
                                     verifier,
                                     grant) == relay::RelayStatus::AuthFailed,
          "verifier cannot change authority kind");
    verifier.result = MakeGrant(request.service, request.kind);
    verifier.result.expires_at = 1400;
    CHECK(relay::AuthorizeKrpService(session,
                                     request,
                                     1000,
                                     relay::KrpTransportPhase::Confirmed1Rtt,
                                     verifier,
                                     grant) == relay::RelayStatus::Expired,
          "overlong authority TTL is rejected");
    verifier.result = MakeGrant(request.service, request.kind);
    CHECK(relay::AuthorizeKrpService(session,
                                     request,
                                     1000,
                                     relay::KrpTransportPhase::Confirmed1Rtt,
                                     verifier,
                                     grant) == relay::RelayStatus::Ok &&
              grant.kind == relay::KrpAuthorityKind::Kad6TargetTicket,
          "current 1-RTT Kad6 target authority is accepted");

    CHECK(relay::IsAuthorityKindAllowed(relay::KrpService::Ed2kServer,
                                        relay::KrpAuthorityKind::SelectedServer) &&
              !relay::IsAuthorityKindAllowed(relay::KrpService::Ed2kServer,
                                             relay::KrpAuthorityKind::Kad6TargetTicket),
          "selected-server authority stays service-specific");
    CHECK(relay::IsAuthorityKindAllowed(relay::KrpService::LiveControl,
                                        relay::KrpAuthorityKind::PriorityGrant) &&
              !relay::IsAuthorityKindAllowed(relay::KrpService::LiveControl,
                                             relay::KrpAuthorityKind::SelectedServer),
          "priority grant cannot authorize unrelated services");
}

relay::KrpFlowConfig MakeFlowConfig(std::uint64_t flow_id = 1) {
    relay::KrpFlowConfig config;
    config.flow_id = flow_id;
    Fill(config.logical_flow_id, static_cast<relay::Byte>(flow_id));
    config.service = relay::KrpService::LegacyTcpOutbound;
    config.session_epoch = 7;
    config.route_generation = 41;
    config.soft_buffer_bytes = 64;
    config.hard_buffer_bytes = 128;
    config.pressure_timeout_ms = 100;
    return config;
}

relay::KrpFlow MakeOpenFlow(std::uint64_t flow_id = 1) {
    relay::KrpFlow flow;
    (void)flow.Initialize(MakeFlowConfig(flow_id));
    (void)flow.BeginAuthorization();
    (void)flow.AcceptAuthority(MakeGrant(relay::KrpService::LegacyTcpOutbound,
                                         relay::KrpAuthorityKind::Kad6TargetTicket),
                               1000);
    (void)flow.ConnectionEstablished();
    return flow;
}

void TestFlowLifecycleAndPressure() {
    relay::KrpFlow flow;
    relay::KrpFlowConfig invalid;
    CHECK(flow.Initialize(invalid) == relay::RelayStatus::InvalidArgument,
          "zero FlowID and budgets are rejected");
    CHECK(flow.Initialize(MakeFlowConfig()) == relay::RelayStatus::Ok &&
              flow.state() == relay::KrpFlowState::Requested,
          "bounded flow initializes REQUESTED");
    CHECK(flow.BeginAuthorization() == relay::RelayStatus::Ok,
          "flow enters AUTHORIZING");
    relay::KrpAuthorityGrant wrong = MakeGrant(
        relay::KrpService::Ed2kServer, relay::KrpAuthorityKind::SelectedServer);
    CHECK(flow.AcceptAuthority(wrong, 1000) == relay::RelayStatus::AuthFailed,
          "grant for another service is rejected");
    const relay::KrpAuthorityGrant grant = MakeGrant(
        relay::KrpService::LegacyTcpOutbound, relay::KrpAuthorityKind::Kad6TargetTicket);
    CHECK(flow.AcceptAuthority(grant, 1000) == relay::RelayStatus::Ok &&
              flow.ConnectionEstablished() == relay::RelayStatus::Ok &&
              std::strcmp(relay::KrpFlowStateName(flow.state()), "OPEN") == 0,
          "authorized connection reaches OPEN");

    CHECK(flow.AcceptReceiveSequence(0) == relay::RelayStatus::Ok &&
              flow.next_receive_sequence() == 1,
          "first exact receive sequence advances");
    CHECK(flow.AcceptReceiveSequence(0) == relay::RelayStatus::SequenceError &&
              flow.AcceptReceiveSequence(2) == relay::RelayStatus::SequenceError,
          "duplicate and out-of-order sequences fail");
    CHECK(flow.AcceptReceiveSequence(1) == relay::RelayStatus::Ok,
          "next exact sequence remains usable after rejected packets");

    relay::KrpMemoryBudget budget(256);
    CHECK(flow.QueueBytes(64, 1000, budget) == relay::RelayStatus::Ok &&
              !flow.pressure_active() && budget.used() == 64,
          "soft limit is inclusive");
    CHECK(flow.QueueBytes(1, 1000, budget) == relay::RelayStatus::Ok &&
              flow.pressure_active() && flow.state() == relay::KrpFlowState::Pressured,
          "crossing soft limit enters PRESSURED with a deadline");
    CHECK(flow.CheckPressureDeadline(1099, budget) == relay::RelayStatus::Ok,
          "pressure before deadline does not reset");
    CHECK(flow.ConsumeQueuedBytes(1, budget) == relay::RelayStatus::Ok &&
              !flow.pressure_active() && flow.state() == relay::KrpFlowState::Open,
          "draining to soft limit clears pressure");
    CHECK(flow.QueueBytes(65, 1100, budget) == relay::RelayStatus::QuotaExceeded &&
              flow.state() == relay::KrpFlowState::Reset && budget.used() == 0,
          "hard flow limit resets and releases queued session memory");

    relay::KrpFlow stalled = MakeOpenFlow(2);
    CHECK(stalled.QueueBytes(65, 5000, budget) == relay::RelayStatus::Ok &&
              stalled.CheckPressureDeadline(5100, budget) ==
                  relay::RelayStatus::QuotaExceeded &&
              stalled.state() == relay::KrpFlowState::Reset && budget.used() == 0,
          "stalled pressured flow resets at deadline");

    relay::KrpFlow half = MakeOpenFlow(3);
    CHECK(half.QueueBytes(20, 1, budget) == relay::RelayStatus::Ok &&
              half.HalfCloseRemote(budget) == relay::RelayStatus::Ok &&
              half.state() == relay::KrpFlowState::HalfClosed,
          "one direction produces HALF_CLOSED");
    CHECK(half.QueueBytes(10, 2, budget) == relay::RelayStatus::Ok,
          "local sender can drain after remote half-close");
    CHECK(half.HalfCloseLocal(budget) == relay::RelayStatus::Ok &&
              half.state() == relay::KrpFlowState::Closed && budget.used() == 0,
          "second half-close releases buffers and closes");
}

void TestSharedMemoryBudget() {
    relay::KrpMemoryBudget invalid(relay::kKrpMaxBufferPerSession + 1);
    CHECK(invalid.maximum() == 0 && invalid.Reserve(1) == relay::RelayStatus::QuotaExceeded,
          "oversized session budget fails closed");
    relay::KrpMemoryBudget budget(150);
    relay::KrpFlow first = MakeOpenFlow(10);
    relay::KrpFlow second = MakeOpenFlow(11);
    CHECK(first.QueueBytes(100, 1, budget) == relay::RelayStatus::Ok,
          "first flow reserves shared budget");
    CHECK(second.QueueBytes(100, 1, budget) == relay::RelayStatus::QuotaExceeded &&
              second.queued_bytes() == 0 && budget.used() == 100,
          "second flow cannot exceed shared session budget");
    CHECK(first.Reset(budget) == relay::RelayStatus::Ok && budget.used() == 0,
          "reset returns reservation to shared budget");
}

void TestFlowIdRegistry() {
    relay::KrpFlowIdRegistry registry(7, 2);
    CHECK(registry.Register(1, 6) == relay::RelayStatus::StaleEpoch,
          "FlowID registry is scoped to one SessionEpoch");
    CHECK(registry.Register(1, 7) == relay::RelayStatus::Ok &&
              registry.Register(2, 7) == relay::RelayStatus::Ok &&
              registry.active_count() == 2,
          "distinct FlowIDs register within active limit");
    CHECK(registry.Register(1, 7) == relay::RelayStatus::SequenceError,
          "FlowID cannot be reused within a SessionEpoch");
    CHECK(registry.Register(3, 7) == relay::RelayStatus::QuotaExceeded,
          "active flow limit is enforced");
    CHECK(registry.MarkTerminal(1, 7) == relay::RelayStatus::Ok &&
              registry.active_count() == 1,
          "terminal flow returns one active slot");
    CHECK(registry.Register(3, 7) == relay::RelayStatus::Ok &&
              registry.registered_count() == 3,
          "new FlowID may use returned active slot");
    CHECK(registry.Register(1, 7) == relay::RelayStatus::SequenceError,
          "terminal FlowID remains spent until a new SessionEpoch");
    CHECK(registry.MarkTerminal(1, 7) == relay::RelayStatus::InvalidState,
          "terminal notification is not counted twice");
}

std::uint64_t NextRandom(std::uint64_t& state) {
    state ^= state << 13;
    state ^= state >> 7;
    state ^= state << 17;
    return state;
}

void TestDeterministicFlowFuzz() {
    std::uint64_t random = 0x464C4F575F50315Full;
    std::uint64_t flow_id = 100;
    relay::KrpMemoryBudget budget(256);
    relay::KrpFlow flow = MakeOpenFlow(flow_id);
    for (std::size_t iteration = 0; iteration < 100000; ++iteration) {
        if (flow.state() == relay::KrpFlowState::Closed ||
            flow.state() == relay::KrpFlowState::Reset) {
            CHECK(budget.used() == 0, "fuzz terminal flow releases shared memory");
            flow = MakeOpenFlow(++flow_id);
        }
        switch (NextRandom(random) % 7u) {
            case 0:
                (void)flow.QueueBytes(1u + NextRandom(random) % 32u,
                                      NextRandom(random) % 100000u,
                                      budget);
                break;
            case 1:
                if (flow.queued_bytes() != 0)
                    (void)flow.ConsumeQueuedBytes(
                        1u + NextRandom(random) % flow.queued_bytes(), budget);
                break;
            case 2:
                (void)flow.AcceptReceiveSequence(flow.next_receive_sequence());
                break;
            case 3:
                (void)flow.AcceptReceiveSequence(NextRandom(random));
                break;
            case 4:
                (void)flow.HalfCloseLocal(budget);
                break;
            case 5:
                (void)flow.HalfCloseRemote(budget);
                break;
            case 6:
                (void)flow.CheckPressureDeadline((std::numeric_limits<std::uint64_t>::max)(),
                                                 budget);
                break;
        }
        CHECK(flow.queued_bytes() <= flow.config().hard_buffer_bytes,
              "fuzz queue never exceeds per-flow hard limit");
        CHECK(budget.used() == flow.queued_bytes(),
              "fuzz flow and shared budget accounting stay equal");
        CHECK(flow.transferred_bytes() + flow.queued_bytes() <= flow.grant().max_bytes,
              "fuzz flow never exceeds authority byte grant");
    }
    (void)flow.Reset(budget);
    CHECK(budget.used() == 0, "fuzz teardown releases final reservation");
    std::printf("  deterministic flow fuzz: 100000 actions\n");
}

} // namespace

static_assert(sizeof(relay::KrpFlow) < 512, "flow state must remain compact");
static_assert(sizeof(relay::KrpFlowIdRegistry) < 24 * 1024,
              "bounded FlowID registry must fit idle session-state budget");

int main() {
    TestServiceAuthority();
    TestFlowLifecycleAndPressure();
    TestSharedMemoryBudget();
    TestFlowIdRegistry();
    TestDeterministicFlowFuzz();
    std::printf("test_krp_flow: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
