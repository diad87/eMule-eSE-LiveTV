#include "natmap/natmap_chain.h"

namespace natmap {

UpstreamGatewayCandidates BuildUpstreamGatewayCandidates(
    const IpAddress& mapper_wan_address) noexcept {
    UpstreamGatewayCandidates result{};
    if (!mapper_wan_address.IsSpecified() ||
        mapper_wan_address.family != AddressFamily::IPv4) {
        result.status = UpstreamDiscoveryStatus::InvalidAddress;
        return result;
    }
    if (mapper_wan_address.IsSharedCgnatV4()) {
        result.status = UpstreamDiscoveryStatus::OperatorCgnat;
        return result;
    }
    if (!mapper_wan_address.IsRfc1918V4()) {
        result.status = UpstreamDiscoveryStatus::NotNeeded;
        return result;
    }

    // Deliberately bounded: two conventional gateway addresses in the WAN's
    // observed /24, never a subnet scan or an arbitrary Internet target.
    result.status = UpstreamDiscoveryStatus::CandidateGateways;
    result.addresses[0] = mapper_wan_address;
    result.addresses[0].bytes[3] = 1;
    result.addresses[1] = mapper_wan_address;
    result.addresses[1].bytes[3] = 254;
    result.count = result.addresses[0].bytes == result.addresses[1].bytes ? 1 : 2;
    return result;
}

bool NatChainTransaction::SameEndpoint(const Endpoint& left,
                                       const Endpoint& right) noexcept {
    return left.port == right.port && left.address.family == right.address.family &&
           left.address.bytes == right.address.bytes;
}

bool NatChainTransaction::Begin(std::uint64_t generation) noexcept {
    if (generation == 0 || (generation_ != 0 && generation <= generation_))
        return false;
    layers_ = std::array<LeaseController, kMaximumLayers>{};
    generation_ = generation;
    layer_count_ = 0;
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
    return layer_count_ != 0 &&
           !layers_[layer_count_ - 1].lease().public_endpoint.address
                .IsPrivateOrSharedV4();
}

bool NatChainTransaction::NeedsUpstream() const noexcept {
    return layer_count_ != 0 &&
           layers_[layer_count_ - 1].lease().public_endpoint.address.IsRfc1918V4() &&
           layer_count_ < kMaximumLayers;
}

bool NatChainTransaction::IsBlockedByCgnat() const noexcept {
    return layer_count_ != 0 && layers_[layer_count_ - 1].lease()
        .public_endpoint.address.IsSharedCgnatV4();
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
