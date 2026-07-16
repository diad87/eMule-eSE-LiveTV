// SPDX-License-Identifier: MIT
#include "relay/krp_session.h"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>

namespace {

int g_pass = 0;
int g_fail = 0;

#define CHECK(condition, message) \
    do { \
        if (condition) { \
            ++g_pass; \
        } else { \
            ++g_fail; \
            std::printf("  FAIL: %s (%s:%d)\n", message, __FILE__, __LINE__); \
        } \
    } while (0)

template <typename Array>
void Fill(Array& value, relay::Byte seed) {
    for (std::size_t index = 0; index < value.size(); ++index)
        value[index] = static_cast<relay::Byte>(seed + index);
}

template <typename Array>
bool IsAllZero(const Array& value) {
    return std::all_of(value.begin(), value.end(), [](relay::Byte byte) {
        return byte == 0;
    });
}

relay::KrpSessionBinding MakeBinding(std::uint64_t epoch = 7,
                                     std::uint64_t generation = 41,
                                     relay::Byte seed = 1) {
    relay::KrpSessionBinding binding;
    Fill(binding.session_id, seed);
    Fill(binding.node_id, static_cast<relay::Byte>(seed + 17));
    Fill(binding.owner_edge_id, static_cast<relay::Byte>(seed + 53));
    Fill(binding.fencing_token, static_cast<relay::Byte>(seed + 89));
    binding.session_epoch = epoch;
    binding.route_generation = generation;
    return binding;
}

relay::KrpSession MakeActiveSession() {
    relay::KrpSession session;
    (void)session.BeginAuthentication();
    (void)session.ActivateNew(MakeBinding());
    return session;
}

class FakeReplayProtector final : public relay::IReplayProtector {
public:
    relay::ReplayConsumeResult result = relay::ReplayConsumeResult::Fresh;
    std::size_t calls = 0;
    relay::ReplayTokenId last_token{};

    relay::ReplayConsumeResult Consume(
        const relay::ReplayTokenId& token_id) noexcept override {
        ++calls;
        last_token = token_id;
        return result;
    }
};

relay::KrpResumeCommit MakeResume(const relay::KrpSessionBinding& binding) {
    relay::KrpResumeCommit commit;
    commit.session_id = binding.session_id;
    commit.session_epoch = binding.session_epoch;
    commit.route_generation = binding.route_generation;
    Fill(commit.token_use_id, 0xC0);
    commit.transport_phase = relay::KrpTransportPhase::Confirmed1Rtt;
    return commit;
}

void TestActivationAndAdmission() {
    relay::KrpSession session;
    CHECK(session.state() == relay::KrpSessionState::New && !session.has_binding(),
          "session starts NEW without authority binding");
    CHECK(std::strcmp(relay::KrpSessionStateName(session.state()), "NEW") == 0,
          "session state diagnostic is stable");
    CHECK(session.ActivateNew(MakeBinding()) == relay::RelayStatus::InvalidState,
          "activation before authentication is rejected");
    CHECK(session.AuthorizeOperation(relay::KrpSessionOperation::EarlyHello,
                                     relay::KrpTransportPhase::EarlyData0Rtt,
                                     0,
                                     0) == relay::RelayStatus::Ok,
          "early HELLO is observation-only in NEW");

    CHECK(session.BeginAuthentication() == relay::RelayStatus::Ok,
          "NEW begins authentication");
    CHECK(session.BeginAuthentication() == relay::RelayStatus::InvalidState,
          "authentication cannot be started twice");
    CHECK(session.AuthorizeOperation(relay::KrpSessionOperation::FlowOpen,
                                     relay::KrpTransportPhase::EarlyData0Rtt,
                                     0,
                                     0) == relay::RelayStatus::OneRttRequired,
          "0-RTT cannot open a flow");
    CHECK(session.AuthorizeOperation(relay::KrpSessionOperation::LeaseMutation,
                                     relay::KrpTransportPhase::Confirmed1Rtt,
                                     0,
                                     0) == relay::RelayStatus::InvalidState,
          "pre-auth 1-RTT cannot mutate a lease");

    relay::KrpSessionBinding invalid;
    CHECK(session.ActivateNew(invalid) == relay::RelayStatus::InvalidArgument,
          "zero identity, epoch and fencing are rejected");

    const relay::KrpSessionBinding binding = MakeBinding();
    CHECK(session.ActivateNew(binding) == relay::RelayStatus::Ok,
          "authenticated binding activates session");
    CHECK(session.state() == relay::KrpSessionState::Active && session.has_binding(),
          "ACTIVE retains authority binding");
    CHECK(session.AuthorizeOperation(relay::KrpSessionOperation::FlowOpen,
                                     relay::KrpTransportPhase::EarlyData0Rtt,
                                     binding.session_epoch,
                                     binding.route_generation) ==
              relay::RelayStatus::OneRttRequired,
          "ACTIVE still rejects a replayable flow open");
    CHECK(session.AuthorizeOperation(relay::KrpSessionOperation::FlowOpen,
                                     relay::KrpTransportPhase::Confirmed1Rtt,
                                     binding.session_epoch - 1,
                                     binding.route_generation) == relay::RelayStatus::StaleEpoch,
          "stale SessionEpoch cannot open a flow");
    CHECK(session.AuthorizeOperation(relay::KrpSessionOperation::LeaseMutation,
                                     relay::KrpTransportPhase::Confirmed1Rtt,
                                     binding.session_epoch,
                                     binding.route_generation - 1) ==
              relay::RelayStatus::StaleGeneration,
          "stale RouteGeneration cannot mutate lease state");
    CHECK(session.AuthorizeOperation(relay::KrpSessionOperation::FlowOpen,
                                     relay::KrpTransportPhase::Confirmed1Rtt,
                                     binding.session_epoch,
                                     binding.route_generation) == relay::RelayStatus::Ok,
          "current 1-RTT binding may request an authorized flow");
    CHECK(session.AuthorizeOperation(static_cast<relay::KrpSessionOperation>(255),
                                     relay::KrpTransportPhase::Confirmed1Rtt,
                                     binding.session_epoch,
                                     binding.route_generation) ==
              relay::RelayStatus::UnsupportedOption,
          "unknown operation class fails closed");
}

void TestMigrationAndPassive() {
    relay::KrpSession session = MakeActiveSession();
    const relay::KrpSessionBinding old_binding = session.binding();
    CHECK(session.BeginMigration() == relay::RelayStatus::Ok,
          "ACTIVE begins owner migration");

    relay::OwnerEdgeId new_owner;
    relay::FencingToken new_fencing;
    Fill(new_owner, 0x70);
    Fill(new_fencing, 0x90);
    CHECK(session.CommitMigration(old_binding.route_generation - 1,
                                  old_binding.route_generation + 1,
                                  new_owner,
                                  new_fencing) == relay::RelayStatus::StaleGeneration,
          "migration CAS rejects stale expected generation");
    CHECK(session.state() == relay::KrpSessionState::Migrating &&
              session.binding().route_generation == old_binding.route_generation,
          "failed migration cannot partially update authority");

    relay::OwnerEdgeId zero_owner{};
    CHECK(session.CommitMigration(old_binding.route_generation,
                                  old_binding.route_generation + 1,
                                  zero_owner,
                                  new_fencing) == relay::RelayStatus::InvalidArgument,
          "migration requires a concrete new owner");
    CHECK(session.CommitMigration(old_binding.route_generation,
                                  old_binding.route_generation + 1,
                                  new_owner,
                                  new_fencing) == relay::RelayStatus::Ok,
          "winning CAS commits a newer route generation");
    CHECK(session.state() == relay::KrpSessionState::Active &&
              session.binding().route_generation == old_binding.route_generation + 1 &&
              session.binding().owner_edge_id == new_owner &&
              session.binding().fencing_token == new_fencing,
          "migration atomically replaces owner, generation and fencing token");

    CHECK(session.BeginMigration() == relay::RelayStatus::Ok,
          "second migration begins");
    CHECK(session.RollbackMigration(old_binding.route_generation) ==
              relay::RelayStatus::StaleGeneration,
          "rollback is fenced by current generation");
    CHECK(session.RollbackMigration(old_binding.route_generation + 1) == relay::RelayStatus::Ok,
          "matching generation may roll back migration");

    CHECK(session.BeginPassivePending() == relay::RelayStatus::Ok,
          "ACTIVE enters PASSIVE_PENDING");
    CHECK(session.CancelPassive() == relay::RelayStatus::Ok &&
              session.state() == relay::KrpSessionState::Active,
          "direct-path rollback restores ACTIVE");
    CHECK(session.BeginPassivePending() == relay::RelayStatus::Ok &&
              session.ConfirmPassive() == relay::RelayStatus::Ok &&
              session.state() == relay::KrpSessionState::Passive,
          "confirmed direct path may produce PASSIVE state");
}

void TestResumeReplayAndNewIncarnation() {
    relay::KrpSession session = MakeActiveSession();
    CHECK(session.BeginPassivePending() == relay::RelayStatus::Ok &&
              session.ConfirmPassive() == relay::RelayStatus::Ok &&
              session.BeginAuthentication() == relay::RelayStatus::Ok,
          "PASSIVE can authenticate a resume");

    FakeReplayProtector replay;
    relay::KrpResumeCommit commit = MakeResume(session.binding());
    commit.transport_phase = relay::KrpTransportPhase::EarlyData0Rtt;
    CHECK(session.CommitResume(commit, replay) == relay::RelayStatus::OneRttRequired &&
              replay.calls == 0,
          "0-RTT resume cannot consume token or mutate session");

    commit.transport_phase = relay::KrpTransportPhase::Confirmed1Rtt;
    --commit.session_epoch;
    CHECK(session.CommitResume(commit, replay) == relay::RelayStatus::StaleEpoch &&
              replay.calls == 0,
          "stale resume epoch is rejected before token consumption");
    ++commit.session_epoch;
    --commit.route_generation;
    CHECK(session.CommitResume(commit, replay) == relay::RelayStatus::StaleGeneration &&
              replay.calls == 0,
          "stale resume route is rejected before token consumption");
    ++commit.route_generation;
    commit.token_use_id.fill(0);
    CHECK(session.CommitResume(commit, replay) == relay::RelayStatus::InvalidArgument &&
              replay.calls == 0,
          "resume requires a non-zero one-time token id");
    Fill(commit.token_use_id, 0xC0);

    replay.result = relay::ReplayConsumeResult::Replayed;
    CHECK(session.CommitResume(commit, replay) == relay::RelayStatus::ReplayDetected &&
              replay.calls == 1 && session.state() == relay::KrpSessionState::Authenticating,
          "replayed token fails without activating session");
    replay.result = relay::ReplayConsumeResult::Unavailable;
    CHECK(session.CommitResume(commit, replay) ==
              relay::RelayStatus::ReplayCheckUnavailable && replay.calls == 2,
          "unavailable replay authority fails closed");
    replay.result = relay::ReplayConsumeResult::Fresh;
    CHECK(session.CommitResume(commit, replay) == relay::RelayStatus::Ok &&
              replay.calls == 3 && session.state() == relay::KrpSessionState::Active,
          "atomic fresh-token consumption commits resume in 1-RTT");
    CHECK(session.CommitResume(commit, replay) == relay::RelayStatus::InvalidState &&
              replay.calls == 3,
          "committed token cannot be consumed twice by the session");

    CHECK(session.BeginPassivePending() == relay::RelayStatus::Ok &&
              session.ConfirmPassive() == relay::RelayStatus::Ok &&
              session.BeginAuthentication() == relay::RelayStatus::Ok,
          "session can attempt a new incarnation from PASSIVE");
    relay::KrpSessionBinding replacement = session.binding();
    CHECK(session.ActivateNew(replacement) == relay::RelayStatus::StaleEpoch,
          "new incarnation must advance SessionEpoch");
    ++replacement.session_epoch;
    replacement.route_generation = 1;
    CHECK(session.ActivateNew(replacement) == relay::RelayStatus::InvalidArgument,
          "new incarnation cannot reuse SessionID");
    Fill(replacement.session_id, 0x31);
    const relay::NodeId correct_node = replacement.node_id;
    replacement.node_id[0] ^= 0xFF;
    CHECK(session.ActivateNew(replacement) == relay::RelayStatus::AuthFailed,
          "new incarnation cannot change authenticated NodeID");
    replacement.node_id = correct_node;
    CHECK(session.ActivateNew(replacement) == relay::RelayStatus::Ok &&
              session.binding().session_epoch == 8 &&
              session.binding().route_generation == 1,
          "same identity may create a newer session incarnation");
}

std::uint64_t NextRandom(std::uint64_t& state) {
    state ^= state << 13;
    state ^= state >> 7;
    state ^= state << 17;
    return state;
}

void TestDeterministicStateFuzz() {
    std::uint64_t random = 0x53455353494F4E31ull;
    relay::KrpSession session;
    FakeReplayProtector replay;
    const relay::KrpSessionBinding binding = MakeBinding();

    for (std::size_t iteration = 0; iteration < 100000; ++iteration) {
        if (session.state() == relay::KrpSessionState::Closed)
            session = relay::KrpSession{};

        switch (NextRandom(random) % 12u) {
            case 0: (void)session.BeginAuthentication(); break;
            case 1: (void)session.ActivateNew(binding); break;
            case 2: (void)session.BeginMigration(); break;
            case 3: {
                relay::OwnerEdgeId owner;
                relay::FencingToken fencing;
                Fill(owner, 0x61);
                Fill(fencing, 0x81);
                const std::uint64_t generation = session.has_binding()
                    ? session.binding().route_generation : 0;
                (void)session.CommitMigration(generation, generation + 1, owner, fencing);
                break;
            }
            case 4: {
                const std::uint64_t generation = session.has_binding()
                    ? session.binding().route_generation : 0;
                (void)session.RollbackMigration(generation);
                break;
            }
            case 5: (void)session.BeginPassivePending(); break;
            case 6: (void)session.ConfirmPassive(); break;
            case 7: (void)session.CancelPassive(); break;
            case 8: (void)session.BeginDrain(); break;
            case 9: (void)session.Close(); break;
            case 10: {
                const std::uint64_t epoch = session.has_binding()
                    ? session.binding().session_epoch : 0;
                const std::uint64_t generation = session.has_binding()
                    ? session.binding().route_generation : 0;
                const relay::KrpTransportPhase phase = (NextRandom(random) & 1u) != 0
                    ? relay::KrpTransportPhase::Confirmed1Rtt
                    : relay::KrpTransportPhase::EarlyData0Rtt;
                (void)session.AuthorizeOperation(relay::KrpSessionOperation::FlowOpen,
                                                 phase,
                                                 epoch,
                                                 generation);
                break;
            }
            case 11: {
                relay::KrpResumeCommit commit = session.has_binding()
                    ? MakeResume(session.binding()) : relay::KrpResumeCommit{};
                (void)session.CommitResume(commit, replay);
                break;
            }
        }

        const relay::KrpSessionState state = session.state();
        const bool requires_binding = state == relay::KrpSessionState::Active ||
            state == relay::KrpSessionState::Migrating ||
            state == relay::KrpSessionState::PassivePending ||
            state == relay::KrpSessionState::Passive ||
            state == relay::KrpSessionState::Draining;
        CHECK(!requires_binding || session.has_binding(),
              "fuzz reachable operational state always has authority binding");
        CHECK(!session.has_binding() ||
                  (session.binding().session_epoch != 0 &&
                   session.binding().route_generation != 0),
              "fuzz bound session never loses epoch or generation");
        CHECK(state != relay::KrpSessionState::Closed ||
                  IsAllZero(session.binding().fencing_token),
              "fuzz CLOSED state always invalidates fencing token");
    }
    std::printf("  deterministic state fuzz: 100000 actions\n");
}

void TestDrainAndClose() {
    relay::KrpSession session = MakeActiveSession();
    CHECK(session.BeginDrain() == relay::RelayStatus::Ok &&
              session.state() == relay::KrpSessionState::Draining,
          "ACTIVE enters DRAINING");
    CHECK(session.AuthorizeOperation(relay::KrpSessionOperation::FlowOpen,
                                     relay::KrpTransportPhase::Confirmed1Rtt,
                                     session.binding().session_epoch,
                                     session.binding().route_generation) ==
              relay::RelayStatus::InvalidState,
          "DRAINING accepts no new flow");
    CHECK(session.Close() == relay::RelayStatus::Ok &&
              session.state() == relay::KrpSessionState::Closed &&
              IsAllZero(session.binding().fencing_token),
          "CLOSED invalidates authority fencing");
    CHECK(session.BeginAuthentication() == relay::RelayStatus::InvalidState,
          "CLOSED object is final; reconnect uses a new incarnation object");

    relay::KrpSession failed;
    CHECK(failed.BeginAuthentication() == relay::RelayStatus::Ok &&
              failed.FailAuthentication() == relay::RelayStatus::Ok &&
              failed.state() == relay::KrpSessionState::Closed,
          "authentication failure closes fail-safe");
}

} // namespace

static_assert(sizeof(relay::OwnerEdgeId) == 16, "OwnerEdgeID must be 128 bits");
static_assert(sizeof(relay::FencingToken) == 16, "fencing token must be 128 bits");
static_assert(sizeof(relay::ReplayTokenId) == 16, "replay token id must be 128 bits");
static_assert(sizeof(relay::KrpSession) < 512,
              "session state must stay far below the 32 KiB idle-state objective");

int main() {
    TestActivationAndAdmission();
    TestMigrationAndPassive();
    TestResumeReplayAndNewIncarnation();
    TestDrainAndClose();
    TestDeterministicStateFuzz();
    std::printf("test_krp_session: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
