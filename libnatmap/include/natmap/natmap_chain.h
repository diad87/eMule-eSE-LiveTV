#pragma once

#include "natmap/address_policy.h"
#include "natmap/natmap_policy.h"

#include <array>
#include <cstdint>

namespace natmap {

enum class UpstreamDiscoveryStatus : std::uint8_t {
    NotNeeded = 0,
    CandidateGateways = 1,
    OperatorCgnat = 2,
    NoAuthorizedCandidate = 3,
    InvalidInput = 4,
};

enum class GatewayCandidateSource : std::uint8_t {
    None = 0,
    InterfaceRoute = 1,
    DhcpOption = 2,
    ExplicitConfiguration = 3,
    OperatorPolicy = 4,
};

struct UpstreamGatewayEvidence {
    IpAddress address{};
    std::uint32_t interface_index = 0;
    GatewayCandidateSource source = GatewayCandidateSource::None;
    bool interface_present = false;
};

struct UpstreamDiscoveryInput {
    static constexpr std::size_t kMaximumEvidence = 4;

    IpAddress mapper_wan_address{};
    NetworkOrigin mapper_origin = NetworkOrigin::Unknown;
    std::uint32_t interface_index = 0;
    std::array<UpstreamGatewayEvidence, kMaximumEvidence> evidence{};
    std::uint8_t evidence_count = 0;
};

struct UpstreamGatewayCandidates {
    UpstreamDiscoveryStatus status = UpstreamDiscoveryStatus::InvalidInput;
    ReasonCode reason = ReasonCode::NoRoute;
    std::array<IpAddress, UpstreamDiscoveryInput::kMaximumEvidence> addresses{};
    std::array<GatewayCandidateSource,
               UpstreamDiscoveryInput::kMaximumEvidence> sources{};
    std::uint8_t count = 0;
};

UpstreamGatewayCandidates BuildUpstreamGatewayCandidates(
    const UpstreamDiscoveryInput& input) noexcept;

enum class NatChainStatus : std::uint8_t {
    Empty = 0,
    NeedsAuthorizedUpstream = 1,
    CompletePublic = 2,
    OperatorCgnat = 3,
    DepthLimitReached = 4,
    NonPublishableEndpoint = 5,
};

class NatChainTransaction {
public:
    static constexpr std::size_t kMaximumLayers = 2;

    bool Begin(std::uint64_t generation, NetworkOrigin origin) noexcept;
    bool AppendLease(const PortLease& lease, std::uint64_t now_ms) noexcept;
    bool AcceptRenewal(std::size_t layer, const PortLease& lease,
                       std::uint64_t now_ms) noexcept;
    bool ShouldRenew(std::size_t layer, std::uint64_t now_ms) const noexcept;
    std::size_t Rollback(std::array<PortLease, kMaximumLayers>& reverse) noexcept;

    bool IsComplete() const noexcept;
    bool NeedsUpstream() const noexcept;
    bool IsBlockedByCgnat() const noexcept;
    NatChainStatus Evaluate() const noexcept;
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
    NetworkOrigin origin_ = NetworkOrigin::Unknown;
};

} // namespace natmap
