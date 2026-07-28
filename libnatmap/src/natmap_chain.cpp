#include "natmap/natmap_chain.h"
#include "natmap/address_policy.h"

namespace natmap {
namespace {

bool SameAddress(const IpAddress& left, const IpAddress& right) noexcept {
    return left.family == right.family && left.bytes == right.bytes;
}

bool IsAuthorizedSource(GatewayCandidateSource source) noexcept {
    switch (source) {
    case GatewayCandidateSource::InterfaceRoute:
    case GatewayCandidateSource::DhcpOption:
    case GatewayCandidateSource::ExplicitConfiguration:
    case GatewayCandidateSource::OperatorPolicy:
        return true;
    case GatewayCandidateSource::None:
        return false;
    }
    return false;
}

}  // namespace

UpstreamGatewayCandidates BuildUpstreamGatewayCandidates(
    const UpstreamDiscoveryInput& input) noexcept {
    UpstreamGatewayCandidates result{};
    if (input.evidence_count > input.evidence.size()) {
        result.status = UpstreamDiscoveryStatus::InvalidInput;
        return result;
    }

    const AddressDecision wan = ClassifyAddress(input.mapper_wan_address);
    if (wan.address_class == AddressClass::SharedCgnat &&
        input.mapper_origin == NetworkOrigin::Native) {
        result.status = UpstreamDiscoveryStatus::OperatorCgnat;
        result.reason = ReasonCode::CgnatWithoutLease;
        return result;
    }
    if (wan.address_class == AddressClass::SharedCgnat) {
        result.status =
            UpstreamDiscoveryStatus::NoAuthorizedCandidate;
        result.reason = ReasonCode::NoRoute;
        return result;
    }
    if (wan.address_class == AddressClass::Public) {
        result.status = UpstreamDiscoveryStatus::NotNeeded;
        result.reason = ReasonCode::None;
        return result;
    }
    if (wan.address_class != AddressClass::Rfc1918 ||
        input.mapper_origin != NetworkOrigin::Native ||
        input.interface_index == 0) {
        result.status = UpstreamDiscoveryStatus::InvalidInput;
        return result;
    }

    for (std::uint8_t i = 0; i < input.evidence_count; ++i) {
        const UpstreamGatewayEvidence& evidence = input.evidence[i];
        if (!evidence.interface_present ||
            evidence.interface_index != input.interface_index ||
            !IsAuthorizedSource(evidence.source) ||
            ClassifyAddress(evidence.address).address_class !=
                AddressClass::Rfc1918 ||
            SameAddress(evidence.address, input.mapper_wan_address))
            continue;

        bool duplicate = false;
        for (std::uint8_t j = 0; j < result.count; ++j)
            if (SameAddress(result.addresses[j], evidence.address)) {
                duplicate = true;
                break;
            }
        if (duplicate)
            continue;

        result.addresses[result.count] = evidence.address;
        result.sources[result.count] = evidence.source;
        ++result.count;
    }
    if (result.count == 0) {
        result.status =
            UpstreamDiscoveryStatus::NoAuthorizedCandidate;
        result.reason = ReasonCode::NoRoute;
        return result;
    }
    result.status = UpstreamDiscoveryStatus::CandidateGateways;
    result.reason = ReasonCode::None;
    return result;
}

bool NatChainTransaction::SameEndpoint(const Endpoint& left,
                                       const Endpoint& right) noexcept {
    return left.port == right.port && left.address.family == right.address.family &&
           left.address.bytes == right.address.bytes;
}

bool NatChainTransaction::Begin(std::uint64_t generation,
                                NetworkOrigin origin) noexcept {
    if (generation == 0 || (generation_ != 0 && generation <= generation_) ||
        (origin != NetworkOrigin::Native &&
         origin != NetworkOrigin::Overlay &&
         origin != NetworkOrigin::Unknown))
        return false;
    layers_ = std::array<LeaseController, kMaximumLayers>{};
    generation_ = generation;
    layer_count_ = 0;
    origin_ = origin;
    return true;
}

bool NatChainTransaction::AppendLease(const PortLease& lease,
                                      std::uint64_t now_ms) noexcept {
    if (generation_ == 0 || layer_count_ >= kMaximumLayers ||
        lease.generation != generation_ || !lease.IsStructurallyValid() ||
        !lease.owned_by_us)
        return false;
    if (layer_count_ != 0 &&
        !SameEndpoint(layers_[layer_count_ - 1].lease().public_endpoint,
                      lease.local))
        return false;
    if (!layers_[layer_count_].Activate(lease, now_ms))
        return false;
    ++layer_count_;
    return true;
}

bool NatChainTransaction::AcceptRenewal(std::size_t layer,
                                        const PortLease& lease,
                                        std::uint64_t now_ms) noexcept {
    return layer < layer_count_ && layers_[layer].AcceptRenewal(lease, now_ms);
}

bool NatChainTransaction::ShouldRenew(std::size_t layer,
                                      std::uint64_t now_ms) const noexcept {
    return layer < layer_count_ && layers_[layer].ShouldRenew(now_ms);
}

std::size_t NatChainTransaction::Rollback(
    std::array<PortLease, kMaximumLayers>& reverse) noexcept {
    std::size_t count = 0;
    while (layer_count_ != 0) {
        const std::size_t index = layer_count_ - 1;
        PortLease lease{};
        if (layers_[index].TakeOwnedForDeletion(generation_, lease))
            reverse[count++] = lease;
        --layer_count_;
    }
    return count;
}

bool NatChainTransaction::IsComplete() const noexcept {
    return Evaluate() == NatChainStatus::CompletePublic;
}

bool NatChainTransaction::NeedsUpstream() const noexcept {
    return Evaluate() == NatChainStatus::NeedsAuthorizedUpstream;
}

bool NatChainTransaction::IsBlockedByCgnat() const noexcept {
    return Evaluate() == NatChainStatus::OperatorCgnat;
}

NatChainStatus NatChainTransaction::Evaluate() const noexcept {
    if (layer_count_ == 0)
        return NatChainStatus::Empty;
    const AddressDecision decision = ClassifyAddress(
        layers_[layer_count_ - 1].lease().public_endpoint.address);
    if (decision.direct_publishable)
        return NatChainStatus::CompletePublic;
    if (decision.address_class == AddressClass::SharedCgnat)
        return origin_ == NetworkOrigin::Native
                   ? NatChainStatus::OperatorCgnat
                   : NatChainStatus::NonPublishableEndpoint;
    if (decision.address_class == AddressClass::Rfc1918)
        return layer_count_ < kMaximumLayers
                   ? NatChainStatus::NeedsAuthorizedUpstream
                   : NatChainStatus::DepthLimitReached;
    return NatChainStatus::NonPublishableEndpoint;
}

const PortLease& NatChainTransaction::layer(std::size_t index) const noexcept {
    static const PortLease empty{};
    return index < layer_count_ ? layers_[index].lease() : empty;
}

Endpoint NatChainTransaction::FinalEndpoint() const noexcept {
    return layer_count_ != 0
        ? layers_[layer_count_ - 1].lease().public_endpoint : Endpoint{};
}

} // namespace natmap
