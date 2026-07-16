// SPDX-License-Identifier: MIT
#pragma once

#include "edge/edge_session_table.h"
#include "relay/epr_lease.h"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace relayedge {

enum class EdgePortState : std::uint8_t {
    Free = 0,
    Allocated,
    Bound,
    Probing,
    Active,
    Draining,
    ReuseDelay,
};

struct EdgePortLease {
    std::uint64_t lease_id = 0;
    std::uint64_t generation = 0;
    EdgeSessionHandle owner{};
    std::uint16_t port = 0;
    EdgePortState state = EdgePortState::Free;
    relay::EprProbeNonce probe_nonce{};
    std::uint64_t reusable_at_ms = 0;
};

class EdgeTcpAllocator {
public:
    relay::RelayStatus Initialize(std::uint16_t first_port,
                                  std::uint16_t last_port,
                                  std::uint64_t reuse_delay_ms,
                                  EdgeMetrics* metrics) noexcept;
    relay::RelayStatus Allocate(EdgeSessionHandle owner,
                                EdgeSessionTable& sessions,
                                std::uint64_t lease_id,
                                std::uint64_t now_ms,
                                EdgePortLease& lease) noexcept;
    relay::RelayStatus MarkBound(std::uint64_t lease_id,
                                 std::uint64_t generation) noexcept;
    relay::RelayStatus BeginProbe(std::uint64_t lease_id,
                                  std::uint64_t generation,
                                  const relay::EprProbeNonce& nonce) noexcept;
    relay::RelayStatus CompleteProbe(std::uint64_t lease_id,
                                     std::uint64_t generation,
                                     const relay::EprProbeNonce& nonce,
                                     bool succeeded,
                                     std::uint64_t now_ms) noexcept;
    relay::RelayStatus BeginDrain(std::uint64_t lease_id,
                                  std::uint64_t generation) noexcept;
    relay::RelayStatus Release(std::uint64_t lease_id,
                               std::uint64_t generation,
                               std::uint64_t now_ms) noexcept;
    std::size_t ReleaseOwner(EdgeSessionHandle owner, std::uint64_t now_ms) noexcept;
    std::size_t ReleaseAll(std::uint64_t now_ms) noexcept;
    std::size_t Tick(std::uint64_t now_ms) noexcept;
    const EdgePortLease* Find(std::uint64_t lease_id,
                              std::uint64_t generation) const noexcept;
    bool CanAnnounce(std::uint64_t lease_id,
                     std::uint64_t generation) const noexcept;
    std::size_t live_count() const noexcept { return live_count_; }

private:
    EdgePortLease* FindMutable(std::uint64_t lease_id,
                               std::uint64_t generation) noexcept;
    void EnterReuseDelay(EdgePortLease& lease, std::uint64_t now_ms) noexcept;

    std::vector<EdgePortLease> leases_{};
    std::uint64_t reuse_delay_ms_ = 0;
    EdgeMetrics* metrics_ = nullptr;
    EdgeSessionTable* sessions_ = nullptr;
    std::size_t live_count_ = 0;
    bool initialized_ = false;
};

} // namespace relayedge
