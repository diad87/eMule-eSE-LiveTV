// SPDX-License-Identifier: MIT
#include "relay/krp_session.h"

#include <algorithm>

namespace relay {

namespace {

template <typename Array>
bool IsAllZero(const Array& value) noexcept {
    return std::all_of(value.begin(), value.end(), [](Byte byte) {
        return byte == 0;
    });
}

bool IsValidBinding(const KrpSessionBinding& binding) noexcept {
    return binding.session_epoch != 0 && binding.route_generation != 0 &&
           !IsAllZero(binding.session_id) && !IsAllZero(binding.node_id) &&
           !IsAllZero(binding.owner_edge_id) && !IsAllZero(binding.fencing_token);
}

bool IsObservationOnly(KrpSessionOperation operation) noexcept {
    return operation == KrpSessionOperation::EarlyHello ||
           operation == KrpSessionOperation::ResumeProbe ||
           operation == KrpSessionOperation::StatusQuery;
}

} // namespace

RelayStatus KrpSession::BeginAuthentication() noexcept {
    if (state_ != KrpSessionState::New && state_ != KrpSessionState::Passive)
        return RelayStatus::InvalidState;
    state_ = KrpSessionState::Authenticating;
    return RelayStatus::Ok;
}

RelayStatus KrpSession::ActivateNew(const KrpSessionBinding& binding) noexcept {
    if (state_ != KrpSessionState::Authenticating)
        return RelayStatus::InvalidState;
    if (!IsValidBinding(binding))
        return RelayStatus::InvalidArgument;

    if (has_binding_) {
        if (binding.node_id != binding_.node_id)
            return RelayStatus::AuthFailed;
        if (binding.session_epoch <= binding_.session_epoch)
            return RelayStatus::StaleEpoch;
        if (binding.session_id == binding_.session_id)
            return RelayStatus::InvalidArgument;
    }

    binding_ = binding;
    has_binding_ = true;
    state_ = KrpSessionState::Active;
    return RelayStatus::Ok;
}

RelayStatus KrpSession::FailAuthentication() noexcept {
    if (state_ != KrpSessionState::Authenticating)
        return RelayStatus::InvalidState;
    state_ = KrpSessionState::Closed;
    binding_.fencing_token.fill(0);
    return RelayStatus::Ok;
}

RelayStatus KrpSession::CommitResume(const KrpResumeCommit& commit,
                                     IReplayProtector& replay_protector) noexcept {
    if (commit.transport_phase != KrpTransportPhase::Confirmed1Rtt)
        return RelayStatus::OneRttRequired;
    if (state_ != KrpSessionState::Authenticating || !has_binding_)
        return RelayStatus::InvalidState;
    if (commit.session_id != binding_.session_id ||
        commit.session_epoch != binding_.session_epoch)
        return RelayStatus::StaleEpoch;
    if (commit.route_generation != binding_.route_generation)
        return RelayStatus::StaleGeneration;
    if (IsAllZero(commit.token_use_id))
        return RelayStatus::InvalidArgument;

    switch (replay_protector.Consume(commit.token_use_id)) {
        case ReplayConsumeResult::Fresh:
            state_ = KrpSessionState::Active;
            return RelayStatus::Ok;
        case ReplayConsumeResult::Replayed:
            return RelayStatus::ReplayDetected;
        case ReplayConsumeResult::Unavailable:
            return RelayStatus::ReplayCheckUnavailable;
    }
    return RelayStatus::ReplayCheckUnavailable;
}

RelayStatus KrpSession::BeginMigration() noexcept {
    if (state_ != KrpSessionState::Active || !has_binding_)
        return RelayStatus::InvalidState;
    state_ = KrpSessionState::Migrating;
    return RelayStatus::Ok;
}

RelayStatus KrpSession::CommitMigration(
    std::uint64_t expected_generation,
    std::uint64_t new_generation,
    const OwnerEdgeId& new_owner_edge_id,
    const FencingToken& new_fencing_token) noexcept {
    if (state_ != KrpSessionState::Migrating || !has_binding_)
        return RelayStatus::InvalidState;
    if (expected_generation != binding_.route_generation ||
        new_generation <= expected_generation)
        return RelayStatus::StaleGeneration;
    if (IsAllZero(new_owner_edge_id) || IsAllZero(new_fencing_token))
        return RelayStatus::InvalidArgument;

    binding_.route_generation = new_generation;
    binding_.owner_edge_id = new_owner_edge_id;
    binding_.fencing_token = new_fencing_token;
    state_ = KrpSessionState::Active;
    return RelayStatus::Ok;
}

RelayStatus KrpSession::RollbackMigration(std::uint64_t expected_generation) noexcept {
    if (state_ != KrpSessionState::Migrating || !has_binding_)
        return RelayStatus::InvalidState;
    if (expected_generation != binding_.route_generation)
        return RelayStatus::StaleGeneration;
    state_ = KrpSessionState::Active;
    return RelayStatus::Ok;
}

RelayStatus KrpSession::BeginPassivePending() noexcept {
    if (state_ != KrpSessionState::Active || !has_binding_)
        return RelayStatus::InvalidState;
    state_ = KrpSessionState::PassivePending;
    return RelayStatus::Ok;
}

RelayStatus KrpSession::ConfirmPassive() noexcept {
    if (state_ != KrpSessionState::PassivePending)
        return RelayStatus::InvalidState;
    state_ = KrpSessionState::Passive;
    return RelayStatus::Ok;
}

RelayStatus KrpSession::CancelPassive() noexcept {
    if (state_ != KrpSessionState::PassivePending)
        return RelayStatus::InvalidState;
    state_ = KrpSessionState::Active;
    return RelayStatus::Ok;
}

RelayStatus KrpSession::BeginDrain() noexcept {
    if (state_ != KrpSessionState::Active &&
        state_ != KrpSessionState::Migrating &&
        state_ != KrpSessionState::PassivePending)
        return RelayStatus::InvalidState;
    state_ = KrpSessionState::Draining;
    return RelayStatus::Ok;
}

RelayStatus KrpSession::Close() noexcept {
    if (state_ == KrpSessionState::Closed)
        return RelayStatus::InvalidState;
    state_ = KrpSessionState::Closed;
    binding_.fencing_token.fill(0);
    return RelayStatus::Ok;
}

RelayStatus KrpSession::AuthorizeOperation(
    KrpSessionOperation operation,
    KrpTransportPhase transport_phase,
    std::uint64_t session_epoch,
    std::uint64_t route_generation) const noexcept {
    if (IsObservationOnly(operation)) {
        switch (operation) {
            case KrpSessionOperation::EarlyHello:
            case KrpSessionOperation::ResumeProbe:
                return state_ == KrpSessionState::New ||
                               state_ == KrpSessionState::Authenticating
                           ? RelayStatus::Ok
                           : RelayStatus::InvalidState;
            case KrpSessionOperation::StatusQuery:
                return state_ == KrpSessionState::Closed
                           ? RelayStatus::InvalidState
                           : RelayStatus::Ok;
            default:
                break;
        }
    }

    if (operation != KrpSessionOperation::LeaseMutation &&
        operation != KrpSessionOperation::FlowOpen &&
        operation != KrpSessionOperation::RouteMutation)
        return RelayStatus::UnsupportedOption;
    if (transport_phase != KrpTransportPhase::Confirmed1Rtt)
        return RelayStatus::OneRttRequired;
    if (state_ != KrpSessionState::Active || !has_binding_)
        return RelayStatus::InvalidState;
    if (session_epoch != binding_.session_epoch)
        return RelayStatus::StaleEpoch;
    if (route_generation != binding_.route_generation)
        return RelayStatus::StaleGeneration;
    return RelayStatus::Ok;
}

const char* KrpSessionStateName(KrpSessionState state) noexcept {
    switch (state) {
        case KrpSessionState::New:            return "NEW";
        case KrpSessionState::Authenticating: return "AUTHENTICATING";
        case KrpSessionState::Active:         return "ACTIVE";
        case KrpSessionState::Migrating:      return "MIGRATING";
        case KrpSessionState::PassivePending: return "PASSIVE_PENDING";
        case KrpSessionState::Passive:        return "PASSIVE";
        case KrpSessionState::Draining:       return "DRAINING";
        case KrpSessionState::Closed:         return "CLOSED";
    }
    return "UNKNOWN";
}

} // namespace relay
