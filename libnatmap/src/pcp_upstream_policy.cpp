#include "natmap/pcp_upstream_policy.h"

#include <algorithm>


namespace natmap {
namespace {

bool IsPublicV4(const Endpoint& endpoint) noexcept {
    return endpoint.IsUsable() &&
           endpoint.address.family == AddressFamily::IPv4 &&
           ClassifyAddress(endpoint.address).address_class ==
               AddressClass::Public;
}

bool SameAddress(const IpAddress& left, const IpAddress& right) noexcept {
    return left.family == right.family && left.bytes == right.bytes;
}

bool SameEndpoint(const Endpoint& left,
                  const Endpoint& right) noexcept {
    return left.source == right.source &&
           left.SameSocketEndpoint(right);
}

const TransportMappingResult* FindMapping(const MapperResultData& data,
                                          Transport transport) noexcept {
    for (std::size_t i = 0; i < data.mapping_count; ++i)
        if (data.mappings[i].transport == transport)
            return &data.mappings[i];
    return nullptr;
}

bool IsAuthorizedGateway(const UpstreamGatewayCandidates& gateways,
                         const Endpoint& gateway) noexcept {
    if (!gateway.address.IsSpecified())
        return false;
    for (std::uint8_t i = 0; i < gateways.count; ++i)
        if (SameAddress(gateways.addresses[i], gateway.address))
            return true;
    return false;
}

bool HasPublicAtomicPair(const MapperResultData& data,
                         const NatChainTransaction& cpe_tcp_chain,
                         const NatChainTransaction& cpe_udp_chain) noexcept {
    if (data.mapping_count != 2)
        return false;
    const TransportMappingResult* tcp = FindMapping(data, Transport::Tcp);
    const TransportMappingResult* udp = FindMapping(data, Transport::Udp);
    return tcp != nullptr && udp != nullptr &&
           IsPublicV4(tcp->granted_external_endpoint) &&
           IsPublicV4(udp->granted_external_endpoint) &&
           SameAddress(tcp->granted_external_endpoint.address,
                       udp->granted_external_endpoint.address) &&
           tcp->local_endpoint.SameSocketEndpoint(
               cpe_tcp_chain.FinalEndpoint()) &&
           udp->local_endpoint.SameSocketEndpoint(
               cpe_udp_chain.FinalEndpoint());
}

PcpUpstreamDecision Reject(PcpUpstreamDisposition disposition,
                           ReasonCode reason) noexcept {
    PcpUpstreamDecision decision{};
    decision.disposition = disposition;
    decision.reason = reason;
    return decision;
}

// The publisher's ownership identity is process-local correlation metadata,
// never a wire value or a log value. Fold both PCP layers into a domain-
// separated fingerprint so the final public endpoint can be identical while a
// CPE nonce/digest rotation still forces a topology replacement. Keeping the
// upstream nonce separately preserves exact layer-two DELETE ownership.
std::array<std::uint8_t, 32> FinalPcpLayerIdentity(
    const MapperResultData& cpe,
    const MapperResultData& upstream) noexcept {
    std::array<std::uint64_t, 4> state{{
        1469598103934665603ull,
        1099511628211ull,
        0x9e3779b185ebca87ull,
        0xd6e8feb86659fd93ull}};
    const auto Feed = [&state](std::uint8_t byte) noexcept {
        for (std::size_t index = 0; index < state.size(); ++index) {
            state[index] ^= static_cast<std::uint64_t>(
                byte + static_cast<std::uint8_t>(index * 29));
            state[index] *= 1099511628211ull +
                static_cast<std::uint64_t>(index * 2);
            state[index] ^= state[index] >> (17 + index);
        }
    };
    static const std::uint8_t domain[] = {
        'p', 'c', 'p', '-', 'f', 'i', 'n', 'a', 'l', '-', 'v', '1'};
    for (std::uint8_t byte : domain)
        Feed(byte);
    for (std::uint8_t byte : cpe.ownership_nonce)
        Feed(byte);
    for (std::uint8_t byte : cpe.ownership_identity_digest)
        Feed(byte);
    Feed(0xff);
    for (std::uint8_t byte : upstream.ownership_nonce)
        Feed(byte);
    for (std::uint8_t byte : upstream.ownership_identity_digest)
        Feed(byte);

    std::array<std::uint8_t, 32> fingerprint{};
    for (std::size_t word = 0; word < state.size(); ++word)
        for (std::size_t byte = 0; byte < 8; ++byte)
            fingerprint[word * 8 + byte] =
                static_cast<std::uint8_t>(state[word] >> (byte * 8));
    return fingerprint;
}

} // namespace

PcpMapRequestPolicyStatus ValidatePcpMapRequestPolicy(
    const PcpMapRequestPolicyInput& input) noexcept {
    if (input.request == nullptr)
        return PcpMapRequestPolicyStatus::InvalidRequest;
    const PcpMapRequest& request = *input.request;
    if (request.prefer_failure &&
        (request.suggested_external_port == 0 ||
         input.documented_exact_port != request.suggested_external_port))
        return PcpMapRequestPolicyStatus::
            PreferFailureRequiresDocumentedExactPort;
    if (input.filter_requested &&
        (!input.filter_peer.IsUsable() ||
         input.filter_peer.address.family != AddressFamily::IPv4 ||
         ClassifyAddress(input.filter_peer.address).address_class !=
             AddressClass::Public))
        return PcpMapRequestPolicyStatus::FilterRequiresConcretePeer;
    if (request.port_set_size != 0 && !input.netlab_enabled &&
        request.port_set_size != 1)
        return PcpMapRequestPolicyStatus::PortSetRequiresNetLabOrOne;
    return PcpMapRequestPolicyStatus::Allowed;
}

std::size_t EncodePcpMapRequestForProduction(
    const PcpMapRequest& request,
    const PcpMapRequestPolicyInput& policy,
    std::uint8_t* out, std::size_t capacity) noexcept {
    if (policy.request != &request || policy.filter_requested ||
        ValidatePcpMapRequestPolicy(policy) !=
            PcpMapRequestPolicyStatus::Allowed)
        return 0;
    return EncodePcpMapRequest(request, out, capacity);
}

PcpUpstreamDecision EvaluatePcpUpstreamCandidate(
    const NatChainTransaction& cpe_tcp_chain,
    const NatChainTransaction& cpe_udp_chain,
    const UpstreamGatewayCandidates& upstream_gateways,
    PcpUpstreamOutcome upstream_outcome,
    const MapperResult& upstream_result,
    std::uint64_t current_generation) noexcept {
    if (current_generation == 0 ||
        cpe_tcp_chain.generation() != current_generation ||
        cpe_udp_chain.generation() != current_generation ||
        cpe_tcp_chain.Evaluate() != NatChainStatus::NeedsAuthorizedUpstream ||
        cpe_udp_chain.Evaluate() != NatChainStatus::NeedsAuthorizedUpstream)
        return Reject(PcpUpstreamDisposition::ChainIncomplete,
                      ReasonCode::CgnatWithoutLease);
    if (upstream_gateways.status !=
            UpstreamDiscoveryStatus::CandidateGateways ||
        upstream_gateways.count == 0 ||
        upstream_gateways.count > upstream_gateways.addresses.size())
        return Reject(PcpUpstreamDisposition::NoGlobalCandidate,
                      ReasonCode::NoGateway);
    if (upstream_outcome == PcpUpstreamOutcome::Denied)
        return Reject(PcpUpstreamDisposition::UpstreamDenied,
                      ReasonCode::OperatorDenied);
    if (upstream_outcome == PcpUpstreamOutcome::Absent)
        return Reject(PcpUpstreamDisposition::NoGlobalCandidate,
                      ReasonCode::NoGateway);
    if (upstream_outcome == PcpUpstreamOutcome::Failed)
        return Reject(PcpUpstreamDisposition::NoGlobalCandidate,
                      ReasonCode::NoRoute);
    if (upstream_outcome != PcpUpstreamOutcome::Mapped)
        return Reject(PcpUpstreamDisposition::NoGlobalCandidate,
                      ReasonCode::NoRoute);

    const MapperResultData& data = upstream_result.data();
    if (!upstream_result.IsStructurallyValid() ||
        !upstream_result.IsCurrent(current_generation) ||
        data.mapper != MapperKind::Pcp ||
        data.source != MapperSource::PcpUpstream ||
        data.ownership != OwnershipState::OwnedByUs ||
        !IsAuthorizedGateway(upstream_gateways, data.gateway) ||
        !HasPublicAtomicPair(data, cpe_tcp_chain, cpe_udp_chain))
        return Reject(PcpUpstreamDisposition::EndpointRejected,
                      ReasonCode::NoRoute);

    PcpUpstreamDecision decision{};
    decision.disposition = PcpUpstreamDisposition::Candidate;
    decision.reason = ReasonCode::None;
    return decision;
}

bool ProjectPcpFinalMapperResult(
    const MapperResult& cpe_result,
    const MapperResult& upstream_result,
    MapperResultData& final_result) noexcept {
    if (!cpe_result.IsStructurallyValid() ||
        !upstream_result.IsStructurallyValid())
        return false;
    const MapperResultData& cpe = cpe_result.data();
    const MapperResultData& upstream = upstream_result.data();
    if (cpe.mapper != MapperKind::Pcp ||
        cpe.source != MapperSource::PcpCpe ||
        upstream.mapper != MapperKind::Pcp ||
        upstream.source != MapperSource::PcpUpstream ||
        cpe.ownership != OwnershipState::OwnedByUs ||
        upstream.ownership != OwnershipState::OwnedByUs ||
        cpe.request_id != upstream.request_id ||
        cpe.topology_generation != upstream.topology_generation ||
        cpe.operation != upstream.operation ||
        cpe.request_interface_index !=
            upstream.request_interface_index ||
        !SameAddress(cpe.request_local_address,
                     upstream.request_local_address))
        return false;

    const TransportMappingResult* cpe_tcp =
        FindMapping(cpe, Transport::Tcp);
    const TransportMappingResult* cpe_udp =
        FindMapping(cpe, Transport::Udp);
    const TransportMappingResult* upstream_tcp =
        FindMapping(upstream, Transport::Tcp);
    const TransportMappingResult* upstream_udp =
        FindMapping(upstream, Transport::Udp);
    if (cpe_tcp == nullptr || cpe_udp == nullptr ||
        upstream_tcp == nullptr || upstream_udp == nullptr ||
        ClassifyAddress(cpe_tcp->granted_external_endpoint.address)
                .address_class != AddressClass::Rfc1918 ||
        !SameAddress(
            cpe_tcp->granted_external_endpoint.address,
            cpe_udp->granted_external_endpoint.address) ||
        !upstream_tcp->local_endpoint.SameSocketEndpoint(
            cpe_tcp->granted_external_endpoint) ||
        !upstream_udp->local_endpoint.SameSocketEndpoint(
            cpe_udp->granted_external_endpoint) ||
        !IsPublicV4(upstream_tcp->granted_external_endpoint) ||
        !IsPublicV4(upstream_udp->granted_external_endpoint) ||
        !SameAddress(
            upstream_tcp->granted_external_endpoint.address,
            upstream_udp->granted_external_endpoint.address))
        return false;

    const std::uint32_t lifetime = std::min(
        std::min(cpe_tcp->lifetime_seconds,
                 cpe_udp->lifetime_seconds),
        std::min(upstream_tcp->lifetime_seconds,
                 upstream_udp->lifetime_seconds));
    const std::uint64_t expiry = std::min(
        std::min(cpe_tcp->effective_expiry_monotonic_ms,
                 cpe_udp->effective_expiry_monotonic_ms),
        std::min(upstream_tcp->effective_expiry_monotonic_ms,
                 upstream_udp->effective_expiry_monotonic_ms));
    if (lifetime == 0 || expiry == 0)
        return false;

    MapperResultData projected = upstream;
    projected.request_interface_index =
        cpe.request_interface_index;
    projected.request_local_address =
        cpe.request_local_address;
    projected.ownership_identity_digest =
        FinalPcpLayerIdentity(cpe, upstream);
    const Transport transports[] = {
        Transport::Tcp, Transport::Udp};
    for (Transport transport : transports) {
        const TransportMappingResult* cpe_mapping =
            FindMapping(cpe, transport);
        TransportMappingResult* final_mapping = nullptr;
        for (std::size_t i = 0;
             i < projected.mapping_count; ++i)
            if (projected.mappings[i].transport == transport)
                final_mapping = &projected.mappings[i];
        if (cpe_mapping == nullptr || final_mapping == nullptr)
            return false;
        final_mapping->local_endpoint =
            cpe_mapping->local_endpoint;
        final_mapping->requested_external_port =
            cpe_mapping->requested_external_port;
        final_mapping->lifetime_seconds = lifetime;
        final_mapping->effective_expiry_monotonic_ms = expiry;
    }
    if (!MapperResult(projected).IsStructurallyValid())
        return false;
    final_result = projected;
    return true;
}

bool SamePcpCpeMappingIdentity(
    const MapperResultData& current,
    const MapperResultData& next) noexcept {
    if (next.mapper_epoch_reset ||
        current.mapper != MapperKind::Pcp ||
        next.mapper != MapperKind::Pcp ||
        current.source != MapperSource::PcpCpe ||
        next.source != MapperSource::PcpCpe ||
        current.request_interface_index !=
            next.request_interface_index ||
        !SameAddress(current.request_local_address,
                     next.request_local_address) ||
        !SameEndpoint(current.gateway, next.gateway) ||
        current.ownership_nonce != next.ownership_nonce ||
        current.ownership_identity_digest !=
            next.ownership_identity_digest)
        return false;
    for (Transport transport :
         {Transport::Tcp, Transport::Udp}) {
        const TransportMappingResult* left =
            FindMapping(current, transport);
        const TransportMappingResult* right =
            FindMapping(next, transport);
        if (left == nullptr || right == nullptr ||
            !SameEndpoint(left->local_endpoint,
                          right->local_endpoint) ||
            !SameEndpoint(left->granted_external_endpoint,
                          right->granted_external_endpoint))
            return false;
    }
    return true;
}

PcpUpstreamDecision PublishPcpUpstreamCandidate(
    MappedCandidatePublisher& publisher,
    const NatChainTransaction& cpe_tcp_chain,
    const NatChainTransaction& cpe_udp_chain,
    const UpstreamGatewayCandidates& upstream_gateways,
    PcpUpstreamOutcome upstream_outcome,
    const MapperResult& cpe_result,
    const MapperResult& upstream_result,
    const RouteBindingIdentity& route_binding,
    const MappedCandidateProof* proof,
    std::uint64_t now_monotonic_ms,
    std::uint64_t committed_generation) noexcept {
    PcpUpstreamDecision decision = EvaluatePcpUpstreamCandidate(
        cpe_tcp_chain, cpe_udp_chain, upstream_gateways, upstream_outcome, upstream_result,
        publisher.snapshot().topology_generation());
    if (!decision.allows_global_candidate()) {
        // Every completed negative PCP observation supersedes the prior
        // result. Keeping a formerly verified pair would make it actionable
        // after a denial, identity change or invalid endpoint.
        publisher.WithdrawRejectedObservation();
        return decision;
    }

    MapperResultData final_data{};
    if (!ProjectPcpFinalMapperResult(
            cpe_result, upstream_result, final_data)) {
        publisher.WithdrawRejectedObservation();
        return Reject(PcpUpstreamDisposition::EndpointRejected,
                      ReasonCode::NoRoute);
    }
    decision.update = publisher.ApplyMapping(
        MapperResult(final_data), route_binding,
        now_monotonic_ms, committed_generation);
    if (decision.update != MappedCandidateUpdate::Published &&
        decision.update != MappedCandidateUpdate::Renewed &&
        decision.update != MappedCandidateUpdate::Replaced) {
        publisher.WithdrawRejectedObservation();
        return Reject(PcpUpstreamDisposition::EndpointRejected,
                      ReasonCode::NoRoute);
    }
    if (proof == nullptr)
        return decision;

    decision.promotion = publisher.Promote(*proof, now_monotonic_ms);
    if (decision.promotion == MappedCandidatePromotion::Promoted ||
        decision.promotion == MappedCandidatePromotion::AlreadyVerified) {
        decision.disposition = PcpUpstreamDisposition::Verified;
        return decision;
    }
    // ApplyMapping already published an unverified candidate. Retain that
    // audit fact when proof is stale or malformed; only promotion failed.
    if (decision.promotion == MappedCandidatePromotion::Stale) {
        publisher.WithdrawRejectedObservation();
        decision.disposition = PcpUpstreamDisposition::StaleProof;
        decision.reason = ReasonCode::StaleGeneration;
        return decision;
    }
    publisher.WithdrawRejectedObservation();
    decision.disposition = PcpUpstreamDisposition::ProofFailed;
    decision.reason = ReasonCode::ServerCallbackFailed;
    return decision;
}

} // namespace natmap
