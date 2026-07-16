// SPDX-License-Identifier: MIT
#include "edge/edge_allocator.h"

#include <algorithm>
#include <limits>

namespace relayedge {

namespace {

bool NonceIsZero(const relay::EprProbeNonce& nonce) noexcept {
    return std::all_of(nonce.begin(), nonce.end(), [](relay::Byte byte) {
        return byte == 0;
    });
}

} // namespace

relay::RelayStatus EdgeTcpAllocator::Initialize(std::uint16_t first_port,
                                                 std::uint16_t last_port,
                                                 std::uint64_t reuse_delay_ms,
                                                 EdgeMetrics* metrics) noexcept {
    if (initialized_ || first_port < 1024 || last_port < first_port ||
        reuse_delay_ms < 1000 || reuse_delay_ms > 600000 || metrics == nullptr)
        return relay::RelayStatus::InvalidArgument;
    const std::size_t count = static_cast<std::size_t>(last_port - first_port) + 1;
    if (count > 16384)
        return relay::RelayStatus::TooLarge;
    try {
        leases_.resize(count);
    } catch (...) {
        return relay::RelayStatus::TooLarge;
    }
    for (std::size_t index = 0; index < count; ++index)
        leases_[index].port = static_cast<std::uint16_t>(first_port + index);
    reuse_delay_ms_ = reuse_delay_ms;
    metrics_ = metrics;
    initialized_ = true;
    return relay::RelayStatus::Ok;
}

relay::RelayStatus EdgeTcpAllocator::Allocate(EdgeSessionHandle owner,
                                               EdgeSessionTable& sessions,
                                               std::uint64_t lease_id,
                                               std::uint64_t,
                                               EdgePortLease& lease) noexcept {
    const EdgeSessionSnapshot* const session = sessions.Get(owner);
    if (!initialized_ || lease_id == 0 || session == nullptr ||
        session->phase != EdgeSessionPhase::Active)
        return relay::RelayStatus::AuthFailed;
    for (const EdgePortLease& item : leases_) {
        if (item.state != EdgePortState::Free && item.lease_id == lease_id)
            return relay::RelayStatus::ReplayDetected;
    }
    EdgePortLease* free_lease = nullptr;
    for (EdgePortLease& item : leases_) {
        if (item.state == EdgePortState::Free) {
            free_lease = &item;
            break;
        }
    }
    if (free_lease == nullptr) {
        metrics_->Increment(EdgeMetric::LeaseRejected);
        return relay::RelayStatus::QuotaExceeded;
    }
    if (sessions_ != nullptr && sessions_ != &sessions)
        return relay::RelayStatus::InvalidState;
    const relay::RelayStatus quota = sessions.ReserveLease(owner);
    if (quota != relay::RelayStatus::Ok)
        return quota;
    sessions_ = &sessions;
    EdgePortLease& item = *free_lease;
    item.generation = item.generation == (std::numeric_limits<std::uint64_t>::max)()
                          ? 1
                          : item.generation + 1;
    item.lease_id = lease_id;
    item.owner = owner;
    item.state = EdgePortState::Allocated;
    item.probe_nonce.fill(0);
    item.reusable_at_ms = 0;
    ++live_count_;
    lease = item;
    return relay::RelayStatus::Ok;
}

EdgePortLease* EdgeTcpAllocator::FindMutable(std::uint64_t lease_id,
                                             std::uint64_t generation) noexcept {
    for (EdgePortLease& lease : leases_) {
        if (lease.state != EdgePortState::Free && lease.lease_id == lease_id) {
            if (lease.generation != generation)
                return nullptr;
            return &lease;
        }
    }
    return nullptr;
}

const EdgePortLease* EdgeTcpAllocator::Find(std::uint64_t lease_id,
                                            std::uint64_t generation) const noexcept {
    for (const EdgePortLease& lease : leases_) {
        if (lease.state != EdgePortState::Free && lease.lease_id == lease_id &&
            lease.generation == generation)
            return &lease;
    }
    return nullptr;
}

relay::RelayStatus EdgeTcpAllocator::MarkBound(std::uint64_t lease_id,
                                                std::uint64_t generation) noexcept {
    EdgePortLease* const lease = FindMutable(lease_id, generation);
    if (lease == nullptr)
        return relay::RelayStatus::StaleGeneration;
    if (lease->state != EdgePortState::Allocated)
        return relay::RelayStatus::InvalidState;
    lease->state = EdgePortState::Bound;
    return relay::RelayStatus::Ok;
}

relay::RelayStatus EdgeTcpAllocator::BeginProbe(
    std::uint64_t lease_id,
    std::uint64_t generation,
    const relay::EprProbeNonce& nonce) noexcept {
    EdgePortLease* const lease = FindMutable(lease_id, generation);
    if (lease == nullptr)
        return relay::RelayStatus::StaleGeneration;
    if (lease->state != EdgePortState::Bound)
        return relay::RelayStatus::InvalidState;
    if (NonceIsZero(nonce))
        return relay::RelayStatus::InvalidArgument;
    lease->probe_nonce = nonce;
    lease->state = EdgePortState::Probing;
    return relay::RelayStatus::Ok;
}

void EdgeTcpAllocator::EnterReuseDelay(EdgePortLease& lease,
                                       std::uint64_t now_ms) noexcept {
    if (sessions_ != nullptr)
        (void)sessions_->ReleaseLease(lease.owner);
    lease.state = EdgePortState::ReuseDelay;
    lease.probe_nonce.fill(0);
    lease.reusable_at_ms = now_ms > (std::numeric_limits<std::uint64_t>::max)() - reuse_delay_ms_
                               ? (std::numeric_limits<std::uint64_t>::max)()
                               : now_ms + reuse_delay_ms_;
    if (live_count_ > 0)
        --live_count_;
}

relay::RelayStatus EdgeTcpAllocator::CompleteProbe(
    std::uint64_t lease_id,
    std::uint64_t generation,
    const relay::EprProbeNonce& nonce,
    bool succeeded,
    std::uint64_t now_ms) noexcept {
    EdgePortLease* const lease = FindMutable(lease_id, generation);
    if (lease == nullptr)
        return relay::RelayStatus::StaleGeneration;
    if (lease->state != EdgePortState::Probing)
        return relay::RelayStatus::InvalidState;
    if (nonce != lease->probe_nonce)
        return relay::RelayStatus::AuthFailed;
    if (!succeeded) {
        EnterReuseDelay(*lease, now_ms);
        return relay::RelayStatus::TargetForbidden;
    }
    lease->probe_nonce.fill(0);
    lease->state = EdgePortState::Active;
    return relay::RelayStatus::Ok;
}

relay::RelayStatus EdgeTcpAllocator::BeginDrain(std::uint64_t lease_id,
                                                 std::uint64_t generation) noexcept {
    EdgePortLease* const lease = FindMutable(lease_id, generation);
    if (lease == nullptr)
        return relay::RelayStatus::StaleGeneration;
    if (lease->state != EdgePortState::Active)
        return relay::RelayStatus::InvalidState;
    lease->state = EdgePortState::Draining;
    return relay::RelayStatus::Ok;
}

relay::RelayStatus EdgeTcpAllocator::Release(std::uint64_t lease_id,
                                              std::uint64_t generation,
                                              std::uint64_t now_ms) noexcept {
    EdgePortLease* const lease = FindMutable(lease_id, generation);
    if (lease == nullptr)
        return relay::RelayStatus::StaleGeneration;
    if (lease->state == EdgePortState::ReuseDelay)
        return relay::RelayStatus::InvalidState;
    EnterReuseDelay(*lease, now_ms);
    return relay::RelayStatus::Ok;
}

std::size_t EdgeTcpAllocator::ReleaseOwner(EdgeSessionHandle owner,
                                           std::uint64_t now_ms) noexcept {
    std::size_t released = 0;
    for (EdgePortLease& lease : leases_) {
        if (lease.owner == owner && lease.state != EdgePortState::Free &&
            lease.state != EdgePortState::ReuseDelay) {
            EnterReuseDelay(lease, now_ms);
            ++released;
        }
    }
    return released;
}

std::size_t EdgeTcpAllocator::ReleaseAll(std::uint64_t now_ms) noexcept {
    std::size_t released = 0;
    for (EdgePortLease& lease : leases_) {
        if (lease.state != EdgePortState::Free &&
            lease.state != EdgePortState::ReuseDelay) {
            EnterReuseDelay(lease, now_ms);
            ++released;
        }
    }
    return released;
}

std::size_t EdgeTcpAllocator::Tick(std::uint64_t now_ms) noexcept {
    std::size_t reclaimed = 0;
    for (EdgePortLease& lease : leases_) {
        if (lease.state == EdgePortState::ReuseDelay && now_ms >= lease.reusable_at_ms) {
            const std::uint16_t port = lease.port;
            const std::uint64_t generation = lease.generation;
            lease = {};
            lease.port = port;
            lease.generation = generation;
            ++reclaimed;
        }
    }
    return reclaimed;
}

bool EdgeTcpAllocator::CanAnnounce(std::uint64_t lease_id,
                                    std::uint64_t generation) const noexcept {
    const EdgePortLease* const lease = Find(lease_id, generation);
    return lease != nullptr && lease->state == EdgePortState::Active;
}

} // namespace relayedge
