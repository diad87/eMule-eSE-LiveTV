// SPDX-License-Identifier: MIT
#include "edge/edge_session_table.h"

#include <algorithm>
#include <limits>

namespace relayedge {

namespace {

template <typename Array>
bool IsAllZero(const Array& value) noexcept {
    return std::all_of(value.begin(), value.end(), [](relay::Byte byte) {
        return byte == 0;
    });
}

} // namespace

relay::RelayStatus EdgeSessionTable::Initialize(const EdgeConfig& config,
                                                 EdgeMetrics* metrics) noexcept {
    if (initialized_)
        return relay::RelayStatus::InvalidState;
    if (ValidateEdgeConfig(config) != relay::RelayStatus::Ok || metrics == nullptr)
        return relay::RelayStatus::InvalidArgument;
    try {
        entries_.resize(config.max_sessions);
    } catch (...) {
        return relay::RelayStatus::TooLarge;
    }
    config_ = config;
    metrics_ = metrics;
    initialized_ = true;
    return relay::RelayStatus::Ok;
}

EdgeSessionTable::Entry* EdgeSessionTable::Find(EdgeSessionHandle handle) noexcept {
    if (!initialized_ || handle.generation == 0 || handle.slot >= entries_.size())
        return nullptr;
    Entry& entry = entries_[handle.slot];
    return entry.generation == handle.generation &&
                   entry.snapshot.phase != EdgeSessionPhase::Free
               ? &entry
               : nullptr;
}

const EdgeSessionTable::Entry* EdgeSessionTable::Find(
    EdgeSessionHandle handle) const noexcept {
    if (!initialized_ || handle.generation == 0 || handle.slot >= entries_.size())
        return nullptr;
    const Entry& entry = entries_[handle.slot];
    return entry.generation == handle.generation &&
                   entry.snapshot.phase != EdgeSessionPhase::Free
               ? &entry
               : nullptr;
}

relay::RelayStatus EdgeSessionTable::Admit(std::uint64_t now_ms,
                                            EdgeSessionHandle& handle) noexcept {
    if (!initialized_ || now_ms == 0)
        return relay::RelayStatus::InvalidArgument;
    for (std::size_t index = 0; index < entries_.size(); ++index) {
        Entry& entry = entries_[index];
        if (entry.snapshot.phase != EdgeSessionPhase::Free)
            continue;
        entry.generation = entry.generation == (std::numeric_limits<std::uint32_t>::max)()
                               ? 1
                               : entry.generation + 1;
        entry.snapshot = {};
        entry.snapshot.phase = EdgeSessionPhase::PreAuth;
        entry.snapshot.accepted_at_ms = now_ms;
        entry.snapshot.last_activity_ms = now_ms;
        entry.session = relay::KrpSession{};
        if (entry.session.BeginAuthentication() != relay::RelayStatus::Ok) {
            entry.snapshot = {};
            return relay::RelayStatus::InvalidState;
        }
        ++occupied_count_;
        metrics_->Increment(EdgeMetric::PreAuthAccepted);
        handle = {static_cast<std::uint32_t>(index), entry.generation};
        return relay::RelayStatus::Ok;
    }
    return relay::RelayStatus::QuotaExceeded;
}

relay::RelayStatus EdgeSessionTable::AddPreAuthBytes(EdgeSessionHandle handle,
                                                     std::size_t bytes,
                                                     std::uint64_t now_ms) noexcept {
    Entry* const entry = Find(handle);
    if (entry == nullptr || entry->snapshot.phase != EdgeSessionPhase::PreAuth)
        return relay::RelayStatus::InvalidState;
    if (bytes > config_.max_preauth_bytes - entry->snapshot.preauth_bytes) {
        metrics_->Increment(EdgeMetric::AuthFailed);
        Free(*entry);
        return relay::RelayStatus::TooLarge;
    }
    entry->snapshot.preauth_bytes += bytes;
    entry->snapshot.last_activity_ms = now_ms;
    return relay::RelayStatus::Ok;
}

bool EdgeSessionTable::IdentityInUse(const relay::KrpSessionBinding& binding,
                                     const Entry* except) const noexcept {
    for (const Entry& entry : entries_) {
        if (&entry == except || entry.snapshot.phase == EdgeSessionPhase::Free ||
            entry.snapshot.phase == EdgeSessionPhase::PreAuth)
            continue;
        if (entry.snapshot.binding.session_id == binding.session_id ||
            entry.snapshot.binding.node_id == binding.node_id)
            return true;
    }
    return false;
}

relay::RelayStatus EdgeSessionTable::Activate(
    EdgeSessionHandle handle,
    const relay::KrpSessionBinding& binding,
    std::uint64_t now_ms) noexcept {
    Entry* const entry = Find(handle);
    if (entry == nullptr || entry->snapshot.phase != EdgeSessionPhase::PreAuth)
        return relay::RelayStatus::InvalidState;
    if (now_ms == 0 || IsAllZero(binding.session_id) || IsAllZero(binding.node_id) ||
        binding.session_epoch == 0 || binding.route_generation == 0 ||
        IdentityInUse(binding, entry)) {
        metrics_->Increment(EdgeMetric::AuthFailed);
        Free(*entry);
        return relay::RelayStatus::AuthFailed;
    }
    const relay::RelayStatus status = entry->session.ActivateNew(binding);
    if (status != relay::RelayStatus::Ok) {
        metrics_->Increment(EdgeMetric::AuthFailed);
        Free(*entry);
        return status;
    }
    entry->snapshot.phase = EdgeSessionPhase::Active;
    entry->snapshot.binding = binding;
    entry->snapshot.last_activity_ms = now_ms;
    ++active_count_;
    metrics_->Increment(EdgeMetric::AuthOk);
    return relay::RelayStatus::Ok;
}

relay::RelayStatus EdgeSessionTable::FailAuthentication(EdgeSessionHandle handle,
                                                         std::uint64_t) noexcept {
    Entry* const entry = Find(handle);
    if (entry == nullptr || entry->snapshot.phase != EdgeSessionPhase::PreAuth)
        return relay::RelayStatus::InvalidState;
    (void)entry->session.FailAuthentication();
    metrics_->Increment(EdgeMetric::AuthFailed);
    Free(*entry);
    return relay::RelayStatus::AuthFailed;
}

relay::RelayStatus EdgeSessionTable::Touch(EdgeSessionHandle handle,
                                            std::uint64_t now_ms) noexcept {
    Entry* const entry = Find(handle);
    if (entry == nullptr || entry->snapshot.phase == EdgeSessionPhase::PreAuth ||
        now_ms < entry->snapshot.last_activity_ms)
        return relay::RelayStatus::InvalidState;
    entry->snapshot.last_activity_ms = now_ms;
    return relay::RelayStatus::Ok;
}

relay::RelayStatus EdgeSessionTable::ReserveFlow(EdgeSessionHandle handle) noexcept {
    Entry* const entry = Find(handle);
    if (entry == nullptr || entry->snapshot.phase != EdgeSessionPhase::Active)
        return relay::RelayStatus::InvalidState;
    if (entry->snapshot.active_flows >= config_.max_flows_per_session) {
        metrics_->Increment(EdgeMetric::FlowRejected);
        return relay::RelayStatus::QuotaExceeded;
    }
    ++entry->snapshot.active_flows;
    metrics_->Increment(EdgeMetric::FlowAccepted);
    return relay::RelayStatus::Ok;
}

relay::RelayStatus EdgeSessionTable::ReleaseFlow(EdgeSessionHandle handle) noexcept {
    Entry* const entry = Find(handle);
    if (entry == nullptr || entry->snapshot.active_flows == 0)
        return relay::RelayStatus::InvalidState;
    --entry->snapshot.active_flows;
    return relay::RelayStatus::Ok;
}

relay::RelayStatus EdgeSessionTable::ReserveLease(EdgeSessionHandle handle) noexcept {
    Entry* const entry = Find(handle);
    if (entry == nullptr || entry->snapshot.phase != EdgeSessionPhase::Active)
        return relay::RelayStatus::InvalidState;
    if (entry->snapshot.active_leases >= config_.max_leases_per_session) {
        metrics_->Increment(EdgeMetric::LeaseRejected);
        return relay::RelayStatus::QuotaExceeded;
    }
    ++entry->snapshot.active_leases;
    metrics_->Increment(EdgeMetric::LeaseAllocated);
    return relay::RelayStatus::Ok;
}

relay::RelayStatus EdgeSessionTable::ReleaseLease(EdgeSessionHandle handle) noexcept {
    Entry* const entry = Find(handle);
    if (entry == nullptr || entry->snapshot.active_leases == 0)
        return relay::RelayStatus::InvalidState;
    --entry->snapshot.active_leases;
    return relay::RelayStatus::Ok;
}

relay::RelayStatus EdgeSessionTable::BeginDrain(EdgeSessionHandle handle) noexcept {
    Entry* const entry = Find(handle);
    if (entry == nullptr || entry->snapshot.phase != EdgeSessionPhase::Active)
        return relay::RelayStatus::InvalidState;
    const relay::RelayStatus status = entry->session.BeginDrain();
    if (status == relay::RelayStatus::Ok)
        entry->snapshot.phase = EdgeSessionPhase::Draining;
    return status;
}

void EdgeSessionTable::Free(Entry& entry) noexcept {
    if (entry.snapshot.phase == EdgeSessionPhase::Active ||
        entry.snapshot.phase == EdgeSessionPhase::Draining) {
        if (active_count_ > 0)
            --active_count_;
    }
    if (entry.snapshot.phase != EdgeSessionPhase::Free && occupied_count_ > 0)
        --occupied_count_;
    entry.snapshot = {};
    entry.session = relay::KrpSession{};
}

relay::RelayStatus EdgeSessionTable::Close(EdgeSessionHandle handle) noexcept {
    Entry* const entry = Find(handle);
    if (entry == nullptr)
        return relay::RelayStatus::InvalidState;
    if (entry->snapshot.phase != EdgeSessionPhase::PreAuth)
        (void)entry->session.Close();
    Free(*entry);
    return relay::RelayStatus::Ok;
}

std::size_t EdgeSessionTable::Tick(std::uint64_t now_ms) noexcept {
    std::size_t closed = 0;
    for (Entry& entry : entries_) {
        const bool preauth_expired = entry.snapshot.phase == EdgeSessionPhase::PreAuth &&
            now_ms >= entry.snapshot.accepted_at_ms &&
            now_ms - entry.snapshot.accepted_at_ms >= config_.preauth_timeout_ms;
        const bool idle_expired = (entry.snapshot.phase == EdgeSessionPhase::Active ||
                                   entry.snapshot.phase == EdgeSessionPhase::Draining) &&
            now_ms >= entry.snapshot.last_activity_ms &&
            now_ms - entry.snapshot.last_activity_ms >= config_.idle_timeout_ms;
        if (!preauth_expired && !idle_expired)
            continue;
        if (entry.snapshot.phase != EdgeSessionPhase::PreAuth)
            (void)entry.session.Close();
        metrics_->Increment(EdgeMetric::SessionTimeout);
        Free(entry);
        ++closed;
    }
    return closed;
}

void EdgeSessionTable::BeginDrainAll() noexcept {
    for (Entry& entry : entries_) {
        if (entry.snapshot.phase == EdgeSessionPhase::Active &&
            entry.session.BeginDrain() == relay::RelayStatus::Ok)
            entry.snapshot.phase = EdgeSessionPhase::Draining;
    }
}

void EdgeSessionTable::CloseAll() noexcept {
    for (Entry& entry : entries_) {
        if (entry.snapshot.phase != EdgeSessionPhase::Free) {
            if (entry.snapshot.phase != EdgeSessionPhase::PreAuth)
                (void)entry.session.Close();
            Free(entry);
        }
    }
}

const EdgeSessionSnapshot* EdgeSessionTable::Get(EdgeSessionHandle handle) const noexcept {
    const Entry* const entry = Find(handle);
    return entry == nullptr ? nullptr : &entry->snapshot;
}

} // namespace relayedge
