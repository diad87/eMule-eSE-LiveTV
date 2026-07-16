// SPDX-License-Identifier: MIT
#include "relay/krp_flow.h"

#include <algorithm>
#include <limits>

namespace relay {

namespace {

template <typename Array>
bool IsAllZero(const Array& value) noexcept {
    return std::all_of(value.begin(), value.end(), [](Byte byte) {
        return byte == 0;
    });
}

bool IsKnownService(KrpService service) noexcept {
    return service >= KrpService::Control && service <= KrpService::Diagnostic;
}

bool AddWouldOverflow(std::uint64_t left, std::uint64_t right) noexcept {
    return right > (std::numeric_limits<std::uint64_t>::max)() - left;
}

} // namespace

KrpMemoryBudget::KrpMemoryBudget(std::uint64_t maximum_bytes) noexcept
    : maximum_bytes_(maximum_bytes <= kKrpMaxBufferPerSession ? maximum_bytes : 0) {}

RelayStatus KrpMemoryBudget::Reserve(std::uint64_t bytes) noexcept {
    if (bytes > available())
        return RelayStatus::QuotaExceeded;
    used_bytes_ += bytes;
    return RelayStatus::Ok;
}

RelayStatus KrpMemoryBudget::Release(std::uint64_t bytes) noexcept {
    if (bytes > used_bytes_)
        return RelayStatus::InvalidArgument;
    used_bytes_ -= bytes;
    return RelayStatus::Ok;
}

KrpFlowIdRegistry::KrpFlowIdRegistry(std::uint64_t session_epoch,
                                     std::size_t active_limit) noexcept
    : session_epoch_(session_epoch),
      active_limit_(active_limit <= kKrpSoftActiveFlows ? active_limit : 0) {}

RelayStatus KrpFlowIdRegistry::Register(std::uint64_t flow_id,
                                        std::uint64_t session_epoch) noexcept {
    if (session_epoch_ == 0 || flow_id == 0 || active_limit_ == 0)
        return RelayStatus::InvalidArgument;
    if (session_epoch != session_epoch_)
        return RelayStatus::StaleEpoch;
    for (std::size_t index = 0; index < registered_count_; ++index) {
        if (entries_[index].flow_id == flow_id)
            return RelayStatus::SequenceError;
    }
    if (registered_count_ >= entries_.size() || active_count_ >= active_limit_)
        return RelayStatus::QuotaExceeded;
    entries_[registered_count_].flow_id = flow_id;
    entries_[registered_count_].active = true;
    ++registered_count_;
    ++active_count_;
    return RelayStatus::Ok;
}

RelayStatus KrpFlowIdRegistry::MarkTerminal(std::uint64_t flow_id,
                                            std::uint64_t session_epoch) noexcept {
    if (session_epoch != session_epoch_)
        return RelayStatus::StaleEpoch;
    for (std::size_t index = 0; index < registered_count_; ++index) {
        Entry& entry = entries_[index];
        if (entry.flow_id != flow_id)
            continue;
        if (!entry.active)
            return RelayStatus::InvalidState;
        entry.active = false;
        --active_count_;
        return RelayStatus::Ok;
    }
    return RelayStatus::InvalidArgument;
}

RelayStatus KrpFlow::Initialize(const KrpFlowConfig& config) noexcept {
    if (initialized_)
        return RelayStatus::InvalidState;
    if (config.flow_id == 0 || IsAllZero(config.logical_flow_id) ||
        !IsKnownService(config.service) || config.session_epoch == 0 ||
        config.route_generation == 0 || config.soft_buffer_bytes == 0 ||
        config.hard_buffer_bytes < config.soft_buffer_bytes ||
        config.hard_buffer_bytes > kKrpMaxBufferPerFlow ||
        config.pressure_timeout_ms == 0 ||
        config.pressure_timeout_ms > kKrpMaxPressureTimeoutMs)
        return RelayStatus::InvalidArgument;

    config_ = config;
    initialized_ = true;
    state_ = KrpFlowState::Requested;
    return RelayStatus::Ok;
}

RelayStatus KrpFlow::BeginAuthorization() noexcept {
    if (!initialized_ || state_ != KrpFlowState::Requested)
        return RelayStatus::InvalidState;
    state_ = KrpFlowState::Authorizing;
    return RelayStatus::Ok;
}

RelayStatus KrpFlow::AcceptAuthority(const KrpAuthorityGrant& grant,
                                     std::uint64_t now) noexcept {
    if (state_ != KrpFlowState::Authorizing)
        return RelayStatus::InvalidState;
    if (grant.service != config_.service ||
        !IsAuthorityKindAllowed(grant.service, grant.kind) ||
        IsAllZero(grant.grant_id) || grant.expires_at <= now ||
        grant.expires_at - now > kKrpMaxAuthorityTtlSeconds ||
        grant.max_bytes == 0 || grant.max_bytes > kKrpMaxGrantBytes ||
        grant.max_flows == 0 || grant.max_flows > kKrpMaxGrantFlows ||
        grant.effective_priority > 5)
        return RelayStatus::AuthFailed;
    grant_ = grant;
    authority_accepted_ = true;
    state_ = KrpFlowState::Connecting;
    return RelayStatus::Ok;
}

RelayStatus KrpFlow::ConnectionEstablished() noexcept {
    if (state_ != KrpFlowState::Connecting || !authority_accepted_)
        return RelayStatus::InvalidState;
    state_ = KrpFlowState::Open;
    return RelayStatus::Ok;
}

RelayStatus KrpFlow::ConnectionFailed() noexcept {
    if (state_ != KrpFlowState::Connecting)
        return RelayStatus::InvalidState;
    state_ = KrpFlowState::Reset;
    return RelayStatus::Ok;
}

RelayStatus KrpFlow::QueueBytes(std::uint64_t bytes,
                                std::uint64_t now_ms,
                                KrpMemoryBudget& session_budget) noexcept {
    if (!initialized_ || !authority_accepted_ || !local_send_open_ || bytes == 0)
        return RelayStatus::InvalidState;
    if (state_ != KrpFlowState::Open && state_ != KrpFlowState::Pressured &&
        state_ != KrpFlowState::HalfClosed)
        return RelayStatus::InvalidState;
    if (AddWouldOverflow(queued_bytes_, bytes) ||
        queued_bytes_ + bytes > config_.hard_buffer_bytes ||
        AddWouldOverflow(transferred_bytes_, queued_bytes_ + bytes) ||
        transferred_bytes_ + queued_bytes_ + bytes > grant_.max_bytes) {
        (void)Reset(session_budget);
        return RelayStatus::QuotaExceeded;
    }
    const RelayStatus reserved = session_budget.Reserve(bytes);
    if (reserved != RelayStatus::Ok)
        return reserved;

    queued_bytes_ += bytes;
    if (queued_bytes_ > config_.soft_buffer_bytes && !pressure_active_) {
        if (AddWouldOverflow(now_ms, config_.pressure_timeout_ms)) {
            (void)session_budget.Release(bytes);
            queued_bytes_ -= bytes;
            return RelayStatus::InvalidArgument;
        }
        pressure_active_ = true;
        pressure_deadline_ms_ = now_ms + config_.pressure_timeout_ms;
        if (local_send_open_ && remote_send_open_)
            state_ = KrpFlowState::Pressured;
    }
    return RelayStatus::Ok;
}

RelayStatus KrpFlow::ConsumeQueuedBytes(std::uint64_t bytes,
                                        KrpMemoryBudget& session_budget) noexcept {
    if (bytes == 0 || bytes > queued_bytes_)
        return RelayStatus::InvalidArgument;
    const RelayStatus released = session_budget.Release(bytes);
    if (released != RelayStatus::Ok)
        return released;
    queued_bytes_ -= bytes;
    transferred_bytes_ += bytes;
    if (pressure_active_ && queued_bytes_ <= config_.soft_buffer_bytes) {
        pressure_active_ = false;
        pressure_deadline_ms_ = 0;
        RestoreDataState();
    }
    return RelayStatus::Ok;
}

RelayStatus KrpFlow::CheckPressureDeadline(
    std::uint64_t now_ms,
    KrpMemoryBudget& session_budget) noexcept {
    if (!pressure_active_)
        return RelayStatus::Ok;
    if (now_ms < pressure_deadline_ms_)
        return RelayStatus::Ok;
    (void)Reset(session_budget);
    return RelayStatus::QuotaExceeded;
}

RelayStatus KrpFlow::AcceptReceiveSequence(std::uint64_t sequence) noexcept {
    if (state_ != KrpFlowState::Open && state_ != KrpFlowState::Pressured &&
        state_ != KrpFlowState::HalfClosed)
        return RelayStatus::InvalidState;
    if (!remote_send_open_ || receive_sequence_exhausted_ ||
        sequence != next_receive_sequence_)
        return RelayStatus::SequenceError;
    if (next_receive_sequence_ == (std::numeric_limits<std::uint64_t>::max)())
        receive_sequence_exhausted_ = true;
    else
        ++next_receive_sequence_;
    return RelayStatus::Ok;
}

RelayStatus KrpFlow::HalfCloseLocal(KrpMemoryBudget& session_budget) noexcept {
    if (!local_send_open_ || (state_ != KrpFlowState::Open &&
        state_ != KrpFlowState::Pressured && state_ != KrpFlowState::HalfClosed))
        return RelayStatus::InvalidState;
    local_send_open_ = false;
    return CloseIfBothDirectionsEnded(session_budget);
}

RelayStatus KrpFlow::HalfCloseRemote(KrpMemoryBudget& session_budget) noexcept {
    if (!remote_send_open_ || (state_ != KrpFlowState::Open &&
        state_ != KrpFlowState::Pressured && state_ != KrpFlowState::HalfClosed))
        return RelayStatus::InvalidState;
    remote_send_open_ = false;
    return CloseIfBothDirectionsEnded(session_budget);
}

RelayStatus KrpFlow::CloseIfBothDirectionsEnded(
    KrpMemoryBudget& session_budget) noexcept {
    if (local_send_open_ || remote_send_open_) {
        state_ = KrpFlowState::HalfClosed;
        return RelayStatus::Ok;
    }
    if (session_budget.Release(queued_bytes_) != RelayStatus::Ok)
        return RelayStatus::InvalidState;
    queued_bytes_ = 0;
    pressure_active_ = false;
    pressure_deadline_ms_ = 0;
    state_ = KrpFlowState::Closed;
    return RelayStatus::Ok;
}

RelayStatus KrpFlow::Reset(KrpMemoryBudget& session_budget) noexcept {
    if (!initialized_ || state_ == KrpFlowState::Closed || state_ == KrpFlowState::Reset)
        return RelayStatus::InvalidState;
    if (session_budget.Release(queued_bytes_) != RelayStatus::Ok)
        return RelayStatus::InvalidState;
    queued_bytes_ = 0;
    pressure_active_ = false;
    pressure_deadline_ms_ = 0;
    local_send_open_ = false;
    remote_send_open_ = false;
    state_ = KrpFlowState::Reset;
    return RelayStatus::Ok;
}

void KrpFlow::RestoreDataState() noexcept {
    state_ = local_send_open_ && remote_send_open_
        ? KrpFlowState::Open : KrpFlowState::HalfClosed;
}

const char* KrpFlowStateName(KrpFlowState state) noexcept {
    switch (state) {
        case KrpFlowState::Requested:     return "REQUESTED";
        case KrpFlowState::Authorizing:   return "AUTHORIZING";
        case KrpFlowState::Connecting:    return "CONNECTING";
        case KrpFlowState::Open:          return "OPEN";
        case KrpFlowState::Pressured:     return "PRESSURED";
        case KrpFlowState::HalfClosed:    return "HALF_CLOSED";
        case KrpFlowState::Closed:        return "CLOSED";
        case KrpFlowState::Reset:         return "RESET";
    }
    return "UNKNOWN";
}

} // namespace relay
