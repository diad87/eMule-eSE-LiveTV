// SPDX-License-Identifier: MIT
// Carrier-independent KRP session state, epoch fencing and replay admission.
#pragma once

#include "relay/relay_core.h"

#include <array>
#include <cstddef>
#include <cstdint>

namespace relay {

constexpr std::size_t kOwnerEdgeIdSize = 16;
constexpr std::size_t kFencingTokenSize = 16;
constexpr std::size_t kReplayTokenIdSize = 16;

using OwnerEdgeId = std::array<Byte, kOwnerEdgeIdSize>;
using FencingToken = std::array<Byte, kFencingTokenSize>;
using ReplayTokenId = std::array<Byte, kReplayTokenIdSize>;

enum class KrpSessionState : std::uint8_t {
    New = 0,
    Authenticating,
    Active,
    Migrating,
    PassivePending,
    Passive,
    Draining,
    Closed,
};

enum class KrpTransportPhase : std::uint8_t {
    EarlyData0Rtt = 0,
    Confirmed1Rtt,
};

// EarlyHello, ResumeProbe and StatusQuery are observation-only. The remaining
// classes represent scarce-resource or routing mutations and are never valid
// in 0-RTT.
enum class KrpSessionOperation : std::uint8_t {
    EarlyHello = 0,
    ResumeProbe,
    StatusQuery,
    LeaseMutation,
    FlowOpen,
    RouteMutation,
};

enum class ReplayConsumeResult : std::uint8_t {
    Fresh = 0,
    Replayed,
    Unavailable,
};

class IReplayProtector {
public:
    virtual ~IReplayProtector() = default;

    // The host must implement this as one atomic consume operation. Returning
    // Unavailable fails closed; a separate check-then-insert is not sufficient.
    virtual ReplayConsumeResult Consume(const ReplayTokenId& token_id) noexcept = 0;
};

struct KrpSessionBinding {
    SessionId session_id{};
    NodeId node_id{};
    std::uint64_t session_epoch = 0;
    std::uint64_t route_generation = 0;
    OwnerEdgeId owner_edge_id{};
    FencingToken fencing_token{};
};

struct KrpResumeCommit {
    SessionId session_id{};
    std::uint64_t session_epoch = 0;
    std::uint64_t route_generation = 0;
    ReplayTokenId token_use_id{};
    KrpTransportPhase transport_phase = KrpTransportPhase::EarlyData0Rtt;
};

class KrpSession {
public:
    KrpSession() noexcept = default;

    KrpSessionState state() const noexcept { return state_; }
    bool has_binding() const noexcept { return has_binding_; }
    const KrpSessionBinding& binding() const noexcept { return binding_; }

    RelayStatus BeginAuthentication() noexcept;
    RelayStatus ActivateNew(const KrpSessionBinding& binding) noexcept;
    RelayStatus FailAuthentication() noexcept;
    RelayStatus CommitResume(const KrpResumeCommit& commit,
                             IReplayProtector& replay_protector) noexcept;

    RelayStatus BeginMigration() noexcept;
    RelayStatus CommitMigration(std::uint64_t expected_generation,
                                std::uint64_t new_generation,
                                const OwnerEdgeId& new_owner_edge_id,
                                const FencingToken& new_fencing_token) noexcept;
    RelayStatus RollbackMigration(std::uint64_t expected_generation) noexcept;

    RelayStatus BeginPassivePending() noexcept;
    RelayStatus ConfirmPassive() noexcept;
    RelayStatus CancelPassive() noexcept;
    RelayStatus BeginDrain() noexcept;
    RelayStatus Close() noexcept;

    RelayStatus AuthorizeOperation(KrpSessionOperation operation,
                                   KrpTransportPhase transport_phase,
                                   std::uint64_t session_epoch,
                                   std::uint64_t route_generation) const noexcept;

private:
    KrpSessionState state_ = KrpSessionState::New;
    bool has_binding_ = false;
    KrpSessionBinding binding_{};
};

const char* KrpSessionStateName(KrpSessionState state) noexcept;

} // namespace relay
