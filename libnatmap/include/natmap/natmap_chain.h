#pragma once

#include "natmap/natmap_policy.h"

#include <array>
#include <cstdint>

namespace natmap {

enum class UpstreamDiscoveryStatus : std::uint8_t {
    NotNeeded = 0,
    CandidateGateways = 1,
    OperatorCgnat = 2,
    InvalidAddress = 3,
};

struct UpstreamGatewayCandidates {
    UpstreamDiscoveryStatus status = UpstreamDiscoveryStatus::InvalidAddress;
    std::array<IpAddress, 2> addresses{};
    std::uint8_t count = 0;
};

UpstreamGatewayCandidates BuildUpstreamGatewayCandidates(
    const IpAddress& mapper_wan_address) noexcept;

class NatChainTransaction {
public:
    static constexpr std::size_t kMaximumLayers = 3;

    bool Begin(std::uint64_t generation) noexcept;
    bool AppendLease(const PortLease& lease, std::uint64_t now_ms) noexcept;
    bool AcceptRenewal(std::size_t layer, const PortLease& lease,
                       std::uint64_t now_ms) noexcept;
    bool ShouldRenew(std::size_t layer, std::uint64_t now_ms) const noexcept;
    std::size_t Rollback(std::array<PortLease, kMaximumLayers>& reverse) noexcept;

    bool IsComplete() const noexcept;
    bool NeedsUpstream() const noexcept;
    bool IsBlockedByCgnat() const noexcept;
    std::uint64_t generation() const noexcept { return generation_; }
    std::size_t layer_count() const noexcept { return layer_count_; }
    const PortLease& layer(std::size_t index) const noexcept;
    Endpoint FinalEndpoint() const noexcept;

private:
    static bool SameEndpoint(const Endpoint& left,
                             const Endpoint& right) noexcept;

    std::array<LeaseController, kMaximumLayers> layers_{};
    std::uint64_t generation_ = 0;
    std::size_t layer_count_ = 0;
};

} // namespace natmap
