#include "natmap/ipv6_scope_policy.h"

namespace natmap {
namespace {

bool IsCurrentEndpointAndBinding(const Endpoint& endpoint,
                                 Transport transport,
                                 const RouteBindingIdentity& binding,
                                 std::uint64_t generation,
                                 const Ipv6ScopeInput& input) noexcept {
    return generation == input.current_generation &&
           transport == input.transport &&
           endpoint.SameSocketEndpoint(input.current_endpoint) &&
           SameRouteBinding(binding, input.current_route_binding);
}

bool IsEvidenceStale(std::uint64_t generation,
                     const Ipv6ScopeInput& input) noexcept {
    return generation != 0 && generation != input.current_generation;
}

Ipv6ScopeDecision Reject(Ipv6ScopeDisposition disposition,
                         ReasonCode reason,
                         AddressReason address_reason) noexcept {
    Ipv6ScopeDecision result{};
    result.disposition = disposition;
    result.reason = reason;
    result.address_reason = address_reason;
    return result;
}

Ipv6ScopeDecision Candidate(ReasonCode reason,
                            AddressReason address_reason,
                            std::uint64_t generation) noexcept {
    Ipv6ScopeDecision result = Reject(
        Ipv6ScopeDisposition::Candidate, reason, address_reason);
    result.observation.readiness = CandidateReadiness::Candidate;
    result.observation.generation = generation;
    return result;
}

Ipv6ScopeDecision VerifiedGlobal(AddressReason address_reason,
                                 std::uint64_t generation,
                                 Transport transport) noexcept {
    Ipv6ScopeDecision result = Reject(
        Ipv6ScopeDisposition::VerifiedGlobal, ReasonCode::None,
        address_reason);
    result.observation.readiness = CandidateReadiness::Verified;
    result.observation.generation = generation;
    result.may_select_direct_v6 = true;
    result.may_advertise_kad = transport == Transport::Udp;
    result.may_advertise_remote_hello = transport == Transport::Tcp;
    result.may_publish_global = true;
    // The decision is internal only; all externally consumable reports use
    // the existing sanitized snapshot projection, including GLOBAL routes.
    result.may_emit_unsanitized_report = false;
    return result;
}

bool IsPrivateLanClass(AddressClass value) noexcept {
    return value == AddressClass::UniqueLocal ||
           value == AddressClass::Rfc1918 ||
           value == AddressClass::LinkLocal;
}

bool SameIpAddress(const IpAddress& left, const IpAddress& right) noexcept {
    return left.family == right.family && left.bytes == right.bytes;
}

} // namespace

Ipv6ScopeDecision EvaluateIpv6ScopeAdmission(
    const Ipv6ScopeInput& input) noexcept {
    const AddressDecision address = ClassifyAddress(
        input.current_endpoint.address);
    if (input.current_generation == 0 || !input.current_endpoint.IsUsable() ||
        ValidateRouteBinding(input.current_route_binding) !=
            RouteBindingStatus::Valid ||
        !SameIpAddress(input.current_endpoint.address,
                       input.current_route_binding.local_address)) {
        return Reject(Ipv6ScopeDisposition::RejectGlobal, ReasonCode::NoRoute,
                      address.reason);
    }

    if (IsPrivateLanClass(address.address_class)) {
        if (input.requested_scope != Ipv6ScopeRequest::SameLan)
            return Reject(Ipv6ScopeDisposition::RejectGlobal,
                          ReasonCode::NoRoute, address.reason);
		if (input.current_route_binding.origin == NetworkOrigin::Overlay)
			return Reject(Ipv6ScopeDisposition::RejectSameLan,
						  ReasonCode::NoRoute, address.reason);
        const PrivateSameLanEvidence& evidence = input.same_lan;
        if (!evidence.present || !evidence.positive_same_lan_domain)
            return Reject(Ipv6ScopeDisposition::RejectSameLan,
                          ReasonCode::NoRoute, address.reason);
        if (!evidence.endpoint.IsUsable() ||
            !evidence.peer_endpoint.IsUsable() ||
            evidence.endpoint.source == EndpointSource::None ||
            evidence.peer_endpoint.source == EndpointSource::None ||
            evidence.peer_endpoint.address.family !=
                input.current_endpoint.address.family)
            return Reject(Ipv6ScopeDisposition::RejectSameLan,
                          ReasonCode::NoRoute, address.reason);
        if (IsEvidenceStale(evidence.generation, input))
            return Reject(Ipv6ScopeDisposition::RejectSameLan,
                          ReasonCode::StaleGeneration, address.reason);
        if (!IsCurrentEndpointAndBinding(evidence.endpoint, evidence.transport,
                                        evidence.route_binding,
                                        evidence.generation, input) ||
            !AllowsScopedPrivateAddress(
                evidence.scope, input.current_endpoint.address,
                input.current_route_binding.interface_index) ||
            !AllowsScopedPrivateAddress(
                evidence.scope, evidence.peer_endpoint.address,
                input.current_route_binding.interface_index))
            return Reject(Ipv6ScopeDisposition::RejectSameLan,
                          ReasonCode::InterfaceChanged, address.reason);
        if (input.now_monotonic_ms >= evidence.expires_monotonic_ms)
            return Reject(Ipv6ScopeDisposition::RejectSameLan,
                          ReasonCode::LeaseExpired, address.reason);
        Ipv6ScopeDecision result = Reject(Ipv6ScopeDisposition::SameLanOnly,
                                          ReasonCode::None, address.reason);
        result.observation.readiness = CandidateReadiness::Verified;
        result.observation.generation = input.current_generation;
        return result;
    }

    if (input.current_endpoint.address.family != AddressFamily::IPv6 ||
        address.address_class != AddressClass::Global ||
        input.current_route_binding.origin != NetworkOrigin::Native)
        return Reject(Ipv6ScopeDisposition::RejectGlobal, ReasonCode::NoRoute,
                      address.reason);

	const PinholeEvidence& pinhole = input.pinhole;
	ReasonCode pinholeFailure = ReasonCode::None;
	if (pinhole.present) {
		if (IsEvidenceStale(pinhole.generation, input))
			pinholeFailure = ReasonCode::StaleGeneration;
		else if (!IsCurrentEndpointAndBinding(pinhole.endpoint, pinhole.transport,
										pinhole.route_binding,
										pinhole.generation, input))
			pinholeFailure = ReasonCode::InterfaceChanged;
		else if (!pinhole.public_endpoint.SameSocketEndpoint(
				input.current_endpoint))
			pinholeFailure = ReasonCode::MappingConflict;
		else if (input.now_monotonic_ms >= pinhole.expires_monotonic_ms)
			pinholeFailure = ReasonCode::LeaseExpired;
		else if (pinhole.owned_by_us && pinhole.authorized)
			return VerifiedGlobal(address.reason, input.current_generation,
								  input.transport);
	}

    const InboundEvidence& inbound = input.inbound;
    if (inbound.present) {
        if (IsEvidenceStale(inbound.generation, input))
            return Reject(Ipv6ScopeDisposition::Withdraw,
                          ReasonCode::StaleGeneration, address.reason);
        if (!IsCurrentEndpointAndBinding(inbound.endpoint, inbound.transport,
                                        inbound.route_binding,
                                        inbound.generation, input))
            return Reject(Ipv6ScopeDisposition::Withdraw,
                          ReasonCode::InterfaceChanged, address.reason);
        if (input.now_monotonic_ms >= inbound.expires_monotonic_ms)
            return Reject(Ipv6ScopeDisposition::Withdraw,
                          ReasonCode::LeaseExpired, address.reason);
		return VerifiedGlobal(address.reason, input.current_generation,
							  input.transport);
	}
	if (pinholeFailure != ReasonCode::None)
		return Reject(Ipv6ScopeDisposition::Withdraw, pinholeFailure,
					  address.reason);

	return Candidate(ReasonCode::InboundFiltered, address.reason,
                     input.current_generation);
}

CandidateObservation GlobalRouteObservation(
    const Ipv6ScopeDecision& decision) noexcept {
    return decision.disposition == Ipv6ScopeDisposition::Candidate ||
           decision.disposition == Ipv6ScopeDisposition::VerifiedGlobal
        ? decision.observation : CandidateObservation{};
}

bool CanUseSameLanEndpoint(const Ipv6ScopeDecision& decision) noexcept {
    return decision.disposition == Ipv6ScopeDisposition::SameLanOnly &&
           decision.observation.readiness == CandidateReadiness::Verified &&
           !decision.may_select_direct_v6 &&
           !decision.may_advertise_kad &&
           !decision.may_advertise_remote_hello &&
           !decision.may_publish_global &&
           !decision.may_emit_unsanitized_report;
}

bool CanPublishProbeVerdict(const ProbeIncarnation& captured,
                            const ProbeIncarnation& current) noexcept {
    return !captured.shutdown && !current.shutdown &&
           captured.generation != 0 && captured.generation == current.generation &&
           captured.token != 0 && captured.token == current.token;
}

bool MustCleanupPcpNonce(PcpExchangeDisposition disposition) noexcept {
    return disposition == PcpExchangeDisposition::RequestSentNoResponse ||
           disposition == PcpExchangeDisposition::ResponseRejected ||
           disposition == PcpExchangeDisposition::Mapped ||
           disposition == PcpExchangeDisposition::ZeroLifetime;
}

bool IsCurrentPcpLeaseOwner(const PcpLeaseOwnerIdentity& expected,
                            const PcpLeaseOwnerIdentity& current) noexcept {
    return expected.generation != 0 && expected.token != 0 &&
           expected.generation == current.generation &&
           expected.token == current.token && expected.nonce == current.nonce;
}

TopologyApplyDecision EvaluateTopologyGenerationApply(
    std::uint64_t applied_generation,
    std::uint64_t published_generation) noexcept {
    if (published_generation == 0 || published_generation == applied_generation)
        return TopologyApplyDecision::Ignore;
    return applied_generation == 0 ? TopologyApplyDecision::Initialize
                                   : TopologyApplyDecision::Invalidate;
}

ScopedSocketBindDecision EvaluateScopedSocketBind(
    bool same_lan_proof, std::uint32_t interface_index,
    int setsockopt_result) noexcept {
    if (!same_lan_proof)
        return ScopedSocketBindDecision::Connect;
    return interface_index != 0 && setsockopt_result == 0
        ? ScopedSocketBindDecision::Connect
        : ScopedSocketBindDecision::Reject;
}

bool MayPublishCascadeVerdict(PcpCascadeOutcome outcome) noexcept {
    return outcome != PcpCascadeOutcome::Deferred;
}

PcpBusyRetryOwner SelectPcpBusyRetryOwner(
    bool operation_still_active_after_pending) noexcept {
    return operation_still_active_after_pending
        ? PcpBusyRetryOwner::ExistingOwner
        : PcpBusyRetryOwner::WaitingWorker;
}

bool UiPcpCleanupMayScheduleRetry() noexcept {
    return false;
}

} // namespace natmap
