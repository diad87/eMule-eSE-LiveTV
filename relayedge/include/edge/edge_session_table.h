// SPDX-License-Identifier: MIT
#pragma once

#include "edge/edge_runtime.h"
#include "relay/krp_session.h"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace relayedge {

struct EdgeSessionHandle {
    std::uint32_t slot = 0;
    std::uint32_t generation = 0;
};

inline bool operator==(const EdgeSessionHandle& left,
                       const EdgeSessionHandle& right) noexcept {
    return left.slot == right.slot && left.generation == right.generation;
}

enum class EdgeSessionPhase : std::uint8_t {
    Free = 0,
    PreAuth,
    Active,
    Draining,
};

struct EdgeSessionSnapshot {
    EdgeSessionPhase phase = EdgeSessionPhase::Free;
    std::size_t preauth_bytes = 0;
    std::size_t active_flows = 0;
    std::size_t active_leases = 0;
    std::uint64_t accepted_at_ms = 0;
    std::uint64_t last_activity_ms = 0;
    relay::KrpSessionBinding binding{};
};

class EdgeSessionTable {
public:
    relay::RelayStatus Initialize(const EdgeConfig& config,
                                  EdgeMetrics* metrics) noexcept;
    relay::RelayStatus Admit(std::uint64_t now_ms,
                             EdgeSessionHandle& handle) noexcept;
    relay::RelayStatus AddPreAuthBytes(EdgeSessionHandle handle,
                                      std::size_t bytes,
                                      std::uint64_t now_ms) noexcept;
    relay::RelayStatus Activate(EdgeSessionHandle handle,
                                const relay::KrpSessionBinding& binding,
                                std::uint64_t now_ms) noexcept;
    relay::RelayStatus FailAuthentication(EdgeSessionHandle handle,
                                          std::uint64_t now_ms) noexcept;
    relay::RelayStatus Touch(EdgeSessionHandle handle,
                             std::uint64_t now_ms) noexcept;
    relay::RelayStatus ReserveFlow(EdgeSessionHandle handle) noexcept;
    relay::RelayStatus ReleaseFlow(EdgeSessionHandle handle) noexcept;
    relay::RelayStatus ReserveLease(EdgeSessionHandle handle) noexcept;
    relay::RelayStatus ReleaseLease(EdgeSessionHandle handle) noexcept;
    relay::RelayStatus BeginDrain(EdgeSessionHandle handle) noexcept;
    relay::RelayStatus Close(EdgeSessionHandle handle) noexcept;
    std::size_t Tick(std::uint64_t now_ms) noexcept;
    void BeginDrainAll() noexcept;
    void CloseAll() noexcept;

    const EdgeSessionSnapshot* Get(EdgeSessionHandle handle) const noexcept;
    std::size_t active_count() const noexcept { return active_count_; }
    std::size_t occupied_count() const noexcept { return occupied_count_; }

private:
    struct Entry {
        EdgeSessionSnapshot snapshot{};
        relay::KrpSession session{};
        std::uint32_t generation = 0;
    };

    Entry* Find(EdgeSessionHandle handle) noexcept;
    const Entry* Find(EdgeSessionHandle handle) const noexcept;
    void Free(Entry& entry) noexcept;
    bool IdentityInUse(const relay::KrpSessionBinding& binding,
                       const Entry* except) const noexcept;

    EdgeConfig config_{};
    EdgeMetrics* metrics_ = nullptr;
    std::vector<Entry> entries_{};
    std::size_t active_count_ = 0;
    std::size_t occupied_count_ = 0;
    bool initialized_ = false;
};

} // namespace relayedge
