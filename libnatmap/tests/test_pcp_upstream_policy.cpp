#include "natmap/pcp_upstream_policy.h"

#include <cstdio>

using namespace natmap;

namespace {

int checks = 0;
int failures = 0;

#define CHECK(expr) do { ++checks; if (!(expr)) { ++failures; \
    std::printf("FAIL line %d: %s\n", __LINE__, #expr); } } while (0)

Endpoint Ep(std::uint8_t a, std::uint8_t b, std::uint8_t c,
            std::uint8_t d, std::uint16_t port, EndpointSource source) {
    return Endpoint{IpAddress::V4(a, b, c, d), port, source};
}

RouteBindingIdentity UpstreamRoute(std::uint32_t interface_index = 7) {
    RouteBindingIdentity route{};
    route.local_address = IpAddress::V4(192, 168, 68, 54);
    route.interface_index = interface_index;
    route.family = AddressFamily::IPv4;
    route.origin = NetworkOrigin::Native;
    route.interface_present = true;
    return route;
}

PortLease CpeLease(
    Transport transport, std::uint64_t generation = 7,
    const IpAddress& external = IpAddress::V4(10, 0, 0, 9));

MapperResultData CpeMapping(std::uint64_t generation = 7) {
    MapperResultData data{};
    data.mapper = MapperKind::Pcp;
    data.source = MapperSource::PcpCpe;
    data.gateway = Ep(192, 168, 68, 1, 5351,
                      EndpointSource::LocalInterface);
    data.request_interface_index = 7;
    data.request_local_address =
        IpAddress::V4(192, 168, 68, 54);
    data.mapping_count = 2;
    const Transport transports[] = {
        Transport::Tcp, Transport::Udp};
    for (std::size_t index = 0; index < 2; ++index) {
        const PortLease lease =
            CpeLease(transports[index], generation);
        TransportMappingResult& mapping = data.mappings[index];
        mapping.transport = transports[index];
        mapping.local_endpoint = lease.local;
        mapping.requested_external_port =
            lease.requested_external_port;
        mapping.granted_external_endpoint =
            lease.public_endpoint;
        mapping.lifetime_seconds = lease.lifetime_seconds;
        mapping.effective_expiry_monotonic_ms = 3601000;
    }
    data.mapper_epoch = 17;
    data.ownership = OwnershipState::OwnedByUs;
    data.ownership_nonce[0] = 1;
    data.ownership_identity_digest[0] = 3;
    data.request_id = 31;
    data.topology_generation = generation;
    data.operation = MappingOperation::Initial;
    data.status = MappingStatus::Created;
    return data;
}

PortLease CpeLease(Transport transport, std::uint64_t generation,
                   const IpAddress& external) {
    const std::uint16_t internal_port =
        transport == Transport::Tcp ? 4662 : 4672;
    const std::uint16_t mapped_port =
        transport == Transport::Tcp ? 52144 : 52145;
    PortLease lease{};
    lease.mapper = MapperKind::Pcp;
    lease.transport = transport;
    lease.gateway = Ep(192, 168, 68, 1, 5351,
                       EndpointSource::LocalInterface);
    lease.local = Ep(192, 168, 68, 54, internal_port,
                     EndpointSource::LocalInterface);
    lease.public_endpoint = Endpoint{external, mapped_port,
                                     EndpointSource::PcpMap};
    lease.requested_external_port = internal_port;
    lease.granted_external_port = mapped_port;
    lease.lifetime_seconds = 3600;
    lease.ownership_nonce[0] = 1;
    lease.generation = generation;
    lease.owned_by_us = true;
    return lease;
}

NatChainTransaction PrivateCpeChain(Transport transport,
                                    std::uint64_t generation = 7,
                                    const IpAddress& external =
                                        IpAddress::V4(10, 0, 0, 9),
                                    NatChainStatus expected =
                                        NatChainStatus::NeedsAuthorizedUpstream) {
    NatChainTransaction chain;
    CHECK(chain.Begin(generation, NetworkOrigin::Native));
    CHECK(chain.AppendLease(CpeLease(transport, generation, external), 1000));
    CHECK(chain.Evaluate() == expected);
    return chain;
}

UpstreamGatewayCandidates AuthorizedUpstream() {
    UpstreamGatewayCandidates candidates{};
    candidates.status = UpstreamDiscoveryStatus::CandidateGateways;
    candidates.reason = ReasonCode::None;
    candidates.count = 1;
    candidates.addresses[0] = IpAddress::V4(10, 0, 0, 1);
    candidates.sources[0] = GatewayCandidateSource::InterfaceRoute;
    return candidates;
}

MapperResultData UpstreamMapping(
    std::uint64_t generation = 7,
    const IpAddress& external = IpAddress::V4(88, 11, 22, 4)) {
    MapperResultData data{};
    data.mapper = MapperKind::Pcp;
    data.source = MapperSource::PcpUpstream;
    data.gateway = Ep(10, 0, 0, 1, 5351, EndpointSource::LocalInterface);
    data.request_interface_index = 7;
    // The UDP socket remains bound to the original LAN route. The MAP
    // client address and layer-two local endpoints are the CPE intermediate.
    data.request_local_address = IpAddress::V4(192, 168, 68, 54);
    data.mapping_count = 2;
    data.mappings[0].transport = Transport::Tcp;
    data.mappings[0].local_endpoint =
        Ep(10, 0, 0, 9, 52144, EndpointSource::LocalInterface);
    data.mappings[0].requested_external_port = 52144;
    data.mappings[0].granted_external_endpoint =
        Endpoint{external, 52144, EndpointSource::PcpMap};
    data.mappings[0].lifetime_seconds = 3600;
    data.mappings[0].effective_expiry_monotonic_ms = 3601000;
    data.mappings[1].transport = Transport::Udp;
    data.mappings[1].local_endpoint =
        Ep(10, 0, 0, 9, 52145, EndpointSource::LocalInterface);
    data.mappings[1].requested_external_port = 52145;
    data.mappings[1].granted_external_endpoint =
        Endpoint{external, 52145, EndpointSource::PcpMap};
    data.mappings[1].lifetime_seconds = 3600;
    data.mappings[1].effective_expiry_monotonic_ms = 3601000;
    data.mapper_epoch = 19;
    data.ownership = OwnershipState::OwnedByUs;
    data.ownership_nonce[0] = 9;
    data.ownership_identity_digest[0] = 11;
    data.request_id = 31;
    data.topology_generation = generation;
    data.operation = MappingOperation::Initial;
    data.status = MappingStatus::Created;
    return data;
}

PcpUpstreamDecision PublishCandidate(
    MappedCandidatePublisher& publisher,
    const NatChainTransaction& tcp,
    const NatChainTransaction& udp,
    const UpstreamGatewayCandidates& gateways,
    PcpUpstreamOutcome outcome,
    const MapperResult& upstream,
    const RouteBindingIdentity& route,
    const MappedCandidateProof* proof,
    std::uint64_t now,
    std::uint64_t committed_generation = 0) {
    MapperResultData cpe =
        CpeMapping(upstream.data().topology_generation);
    cpe.operation = upstream.data().operation;
    cpe.status = upstream.data().status;
    return PublishPcpUpstreamCandidate(
        publisher, tcp, udp, gateways, outcome,
        MapperResult(cpe), upstream, route, proof, now,
        committed_generation);
}

MappedCandidateProof Proof(const Endpoint& endpoint,
                           std::uint64_t generation = 7) {
    MappedCandidateProof proof{};
    proof.attempt.attempt_id = 99;
    proof.attempt.topology_generation = generation;
    proof.attempt.endpoint = endpoint;
    proof.attempt.transport = Transport::Tcp;
    proof.attempt.path = VerificationPath::Direct;
    proof.attempt.started_monotonic_ms = 1000;
    proof.attempt.deadline_monotonic_ms = 2000;
    proof.primary.kind = EvidenceKind::ServerHighId;
    proof.primary.endpoint = endpoint;
    proof.primary.generation = generation;
    proof.primary.observed_monotonic_ms = 1100;
    proof.primary.verification_attempt_id = 99;
    proof.inbound.kind = EvidenceKind::InboundTcpAccept;
    proof.inbound.endpoint = endpoint;
    proof.inbound.generation = generation;
    proof.inbound.observed_monotonic_ms = 1200;
    proof.inbound.verification_attempt_id = 99;
    return proof;
}

void TestRunbookTableAndReasons() {
    const NatChainTransaction tcp = PrivateCpeChain(Transport::Tcp);
    const NatChainTransaction udp = PrivateCpeChain(Transport::Udp);
    const UpstreamGatewayCandidates gateways = AuthorizedUpstream();
    const MapperResult public_result(UpstreamMapping());
    const PcpUpstreamDecision absent = EvaluatePcpUpstreamCandidate(
        tcp, udp, gateways, PcpUpstreamOutcome::Absent, public_result, 7);
    CHECK(absent.disposition == PcpUpstreamDisposition::NoGlobalCandidate);
    CHECK(absent.reason == ReasonCode::NoGateway);
    const PcpUpstreamDecision denied = EvaluatePcpUpstreamCandidate(
        tcp, udp, gateways, PcpUpstreamOutcome::Denied, public_result, 7);
    CHECK(denied.disposition == PcpUpstreamDisposition::UpstreamDenied);
    CHECK(denied.reason == ReasonCode::OperatorDenied);
    const PcpUpstreamDecision failed = EvaluatePcpUpstreamCandidate(
        tcp, udp, gateways, PcpUpstreamOutcome::Failed, public_result, 7);
    CHECK(failed.disposition == PcpUpstreamDisposition::NoGlobalCandidate);
    CHECK(failed.reason == ReasonCode::NoRoute);
    const MapperResult private_result(
        UpstreamMapping(7, IpAddress::V4(192, 168, 1, 9)));
    const PcpUpstreamDecision private_endpoint = EvaluatePcpUpstreamCandidate(
        tcp, udp, gateways, PcpUpstreamOutcome::Mapped, private_result, 7);
    CHECK(private_endpoint.disposition == PcpUpstreamDisposition::EndpointRejected);
    CHECK(private_endpoint.reason == ReasonCode::NoRoute);
}

void TestCpeIdentityRotationReplacesFinalCandidateAtomically() {
    const NatChainTransaction tcp = PrivateCpeChain(Transport::Tcp);
    const NatChainTransaction udp = PrivateCpeChain(Transport::Udp);
    const UpstreamGatewayCandidates gateways = AuthorizedUpstream();
    MapperResultData cpeInitial = CpeMapping();
    MapperResultData upstreamInitial = UpstreamMapping();
    MapperResultData firstFinal{};
    CHECK(ProjectPcpFinalMapperResult(
        MapperResult(cpeInitial), MapperResult(upstreamInitial), firstFinal));
    CHECK(firstFinal.ownership_identity_digest !=
        cpeInitial.ownership_identity_digest);
    CHECK(firstFinal.ownership_identity_digest !=
        upstreamInitial.ownership_identity_digest);

    MappedCandidatePublisher publisher(7);
    const PcpUpstreamDecision initial = PublishPcpUpstreamCandidate(
        publisher, tcp, udp, gateways, PcpUpstreamOutcome::Mapped,
        MapperResult(cpeInitial), MapperResult(upstreamInitial),
        UpstreamRoute(), nullptr, 1000);
    CHECK(initial.update == MappedCandidateUpdate::Published);
    CHECK(publisher.snapshot().topology_generation() == 7);

    MapperResultData cpeRotated = cpeInitial;
    cpeRotated.operation = MappingOperation::Refresh;
    cpeRotated.status = MappingStatus::Renewed;
    cpeRotated.ownership_nonce[0] = 2;
    cpeRotated.ownership_identity_digest[0] = 4;
    MapperResultData upstreamRenewed = upstreamInitial;
    upstreamRenewed.operation = MappingOperation::Refresh;
    upstreamRenewed.status = MappingStatus::Renewed;
    MapperResultData rotatedFinal{};
    CHECK(ProjectPcpFinalMapperResult(
        MapperResult(cpeRotated), MapperResult(upstreamRenewed),
        rotatedFinal));
    CHECK(rotatedFinal.ownership_identity_digest !=
        firstFinal.ownership_identity_digest);
    CHECK(rotatedFinal.ownership_nonce == upstreamInitial.ownership_nonce);

    const PcpUpstreamDecision rotated = PublishPcpUpstreamCandidate(
        publisher, tcp, udp, gateways, PcpUpstreamOutcome::Mapped,
        MapperResult(cpeRotated), MapperResult(upstreamRenewed),
        UpstreamRoute(), nullptr, 1100, 8);
    CHECK(rotated.update == MappedCandidateUpdate::Replaced);
    CHECK(publisher.snapshot().topology_generation() == 8);
    CHECK(publisher.ApplyMapping(
        MapperResult(firstFinal), UpstreamRoute(), 1200) ==
        MappedCandidateUpdate::Rejected);
}

void TestCandidateThenExactCurrentProofPromotes() {
    const NatChainTransaction tcp = PrivateCpeChain(Transport::Tcp);
    const NatChainTransaction udp = PrivateCpeChain(Transport::Udp);
    const UpstreamGatewayCandidates gateways = AuthorizedUpstream();
    const MapperResult result(UpstreamMapping());
    MappedCandidatePublisher candidate_only(7);
    const PcpUpstreamDecision candidate = PublishCandidate(
        candidate_only, tcp, udp, gateways, PcpUpstreamOutcome::Mapped,
        result, UpstreamRoute(), nullptr, 1300);
    CHECK(candidate.disposition == PcpUpstreamDisposition::Candidate);
    CHECK(candidate_only.snapshot().candidate_count() == 2);
    CHECK(!candidate_only.snapshot().HasVerifiedGlobalCandidate());
    MappedCandidatePublisher verified(7);
    const MappedCandidateProof proof =
        Proof(result.data().mappings[0].granted_external_endpoint);
    const PcpUpstreamDecision promoted = PublishCandidate(
        verified, tcp, udp, gateways, PcpUpstreamOutcome::Mapped,
        result, UpstreamRoute(), &proof, 1300);
    CHECK(promoted.disposition == PcpUpstreamDisposition::Verified);
    CHECK(verified.snapshot().HasVerifiedGlobalCandidate());
}

void TestStaleWrongAndIncompleteNeverPromote() {
    const NatChainTransaction tcp = PrivateCpeChain(Transport::Tcp);
    const NatChainTransaction udp = PrivateCpeChain(Transport::Udp);
    const UpstreamGatewayCandidates gateways = AuthorizedUpstream();
    const MapperResult result(UpstreamMapping());
    const Endpoint external = result.data().mappings[0].granted_external_endpoint;
    MappedCandidatePublisher stale(7);
    const MappedCandidateProof stale_proof = Proof(external, 6);
    const PcpUpstreamDecision stale_decision = PublishCandidate(
        stale, tcp, udp, gateways, PcpUpstreamOutcome::Mapped, result,
        UpstreamRoute(), &stale_proof, 1300);
    CHECK(stale_decision.disposition == PcpUpstreamDisposition::StaleProof);
    CHECK(stale_decision.reason == ReasonCode::StaleGeneration);
    CHECK(!stale.snapshot().HasVerifiedGlobalCandidate());
    MappedCandidatePublisher wrong(7);
    MappedCandidateProof wrong_proof = Proof(external);
    wrong_proof.inbound.endpoint.port = 52146;
    const PcpUpstreamDecision wrong_decision = PublishCandidate(
        wrong, tcp, udp, gateways, PcpUpstreamOutcome::Mapped, result,
        UpstreamRoute(), &wrong_proof, 1300);
    CHECK(wrong_decision.disposition == PcpUpstreamDisposition::ProofFailed);
    CHECK(wrong_decision.reason == ReasonCode::ServerCallbackFailed);
    CHECK(!wrong.snapshot().HasVerifiedGlobalCandidate());
    const NatChainTransaction cgnat_tcp = PrivateCpeChain(
        Transport::Tcp, 7, IpAddress::V4(100, 64, 0, 9),
        NatChainStatus::OperatorCgnat);
    const NatChainTransaction cgnat_udp = PrivateCpeChain(
        Transport::Udp, 7, IpAddress::V4(100, 64, 0, 9),
        NatChainStatus::OperatorCgnat);
    const PcpUpstreamDecision incomplete = EvaluatePcpUpstreamCandidate(
        cgnat_tcp, cgnat_udp, gateways, PcpUpstreamOutcome::Mapped, result, 7);
    CHECK(incomplete.disposition == PcpUpstreamDisposition::ChainIncomplete);
    CHECK(incomplete.reason == ReasonCode::CgnatWithoutLease);
}

void TestNegativeObservationsWithdrawAnAlreadyVerifiedPair() {
    const NatChainTransaction tcp = PrivateCpeChain(Transport::Tcp);
    const NatChainTransaction udp = PrivateCpeChain(Transport::Udp);
    const UpstreamGatewayCandidates gateways = AuthorizedUpstream();
    const MapperResult result(UpstreamMapping());
    const MappedCandidateProof proof =
        Proof(result.data().mappings[0].granted_external_endpoint);

    const auto VerifyPublisher = [&](MappedCandidatePublisher& publisher) {
        const PcpUpstreamDecision verified = PublishCandidate(
            publisher, tcp, udp, gateways, PcpUpstreamOutcome::Mapped,
            result, UpstreamRoute(), &proof, 1300);
        CHECK(verified.disposition == PcpUpstreamDisposition::Verified);
        CHECK(publisher.snapshot().HasVerifiedGlobalCandidate());
    };

    // A new observation is authoritative: neither denial nor absence may
    // leave an earlier verified endpoint actionable.
    MappedCandidatePublisher absent(7);
    VerifyPublisher(absent);
    const PcpUpstreamDecision absentDecision = PublishCandidate(
        absent, tcp, udp, gateways, PcpUpstreamOutcome::Absent,
        result, UpstreamRoute(), nullptr, 1400);
    CHECK(absentDecision.reason == ReasonCode::NoGateway);
    CHECK(absent.snapshot().candidate_count() == 0);
    CHECK(!absent.snapshot().HasVerifiedGlobalCandidate());

    MappedCandidatePublisher denied(7);
    VerifyPublisher(denied);
    const PcpUpstreamDecision deniedDecision = PublishCandidate(
        denied, tcp, udp, gateways, PcpUpstreamOutcome::Denied,
        result, UpstreamRoute(), nullptr, 1400);
    CHECK(deniedDecision.reason == ReasonCode::OperatorDenied);
    CHECK(denied.snapshot().candidate_count() == 0);

    MappedCandidatePublisher foreign(7);
    VerifyPublisher(foreign);
    MapperResultData foreignData = UpstreamMapping();
    foreignData.ownership = OwnershipState::Foreign;
    const PcpUpstreamDecision foreignDecision = PublishCandidate(
        foreign, tcp, udp, gateways, PcpUpstreamOutcome::Mapped,
        MapperResult(foreignData), UpstreamRoute(), nullptr, 1400);
    CHECK(foreignDecision.disposition == PcpUpstreamDisposition::EndpointRejected);
    CHECK(foreign.snapshot().candidate_count() == 0);

    MappedCandidatePublisher changedRoute(7);
    VerifyPublisher(changedRoute);
    const PcpUpstreamDecision routeDecision = PublishCandidate(
        changedRoute, tcp, udp, gateways, PcpUpstreamOutcome::Mapped,
        result, UpstreamRoute(8), nullptr, 1400);
    CHECK(routeDecision.disposition == PcpUpstreamDisposition::EndpointRejected);
    CHECK(changedRoute.snapshot().candidate_count() == 0);

    // A refresh can retain identity only while its renewed proof is exact and
    // current. A stale proof therefore withdraws the old verified pair too.
    MappedCandidatePublisher staleRenewal(7);
    VerifyPublisher(staleRenewal);
    MapperResultData renewalData = UpstreamMapping();
    renewalData.operation = MappingOperation::Refresh;
    renewalData.status = MappingStatus::Renewed;
    const MappedCandidateProof staleProof = Proof(
        renewalData.mappings[0].granted_external_endpoint, 6);
    const PcpUpstreamDecision staleDecision = PublishCandidate(
        staleRenewal, tcp, udp, gateways, PcpUpstreamOutcome::Mapped,
        MapperResult(renewalData), UpstreamRoute(), &staleProof, 1400);
    CHECK(staleDecision.disposition == PcpUpstreamDisposition::StaleProof);
    CHECK(staleRenewal.snapshot().candidate_count() == 0);
    CHECK(!staleRenewal.snapshot().HasVerifiedGlobalCandidate());

    // Retirement is a generation fence, not merely a clear operation. The
    // old proof is still inside its time window but must not promote an
    // identical endpoint published by a later observation.
    MappedCandidatePublisher replay(7);
    VerifyPublisher(replay);
    PublishCandidate(replay, tcp, udp, gateways,
        PcpUpstreamOutcome::Denied, result, UpstreamRoute(), nullptr, 1400);
    CHECK(replay.snapshot().topology_generation() == 8);
    const NatChainTransaction tcp8 = PrivateCpeChain(Transport::Tcp, 8);
    const NatChainTransaction udp8 = PrivateCpeChain(Transport::Udp, 8);
    const MapperResult result8(UpstreamMapping(8));
    const PcpUpstreamDecision replayDecision = PublishCandidate(
        replay, tcp8, udp8, gateways, PcpUpstreamOutcome::Mapped, result8,
        UpstreamRoute(), &proof, 1500);
    CHECK(replayDecision.disposition == PcpUpstreamDisposition::StaleProof);
    CHECK(!replay.snapshot().HasVerifiedGlobalCandidate());
}

void TestGatewayAndTransportContinuityRejectsDisconnectedInputs() {
    const NatChainTransaction tcp = PrivateCpeChain(Transport::Tcp);
    const NatChainTransaction udp = PrivateCpeChain(Transport::Udp);
    const UpstreamGatewayCandidates gateways = AuthorizedUpstream();
    MapperResultData wrong_gateway = UpstreamMapping();
    wrong_gateway.gateway.address = IpAddress::V4(10, 0, 0, 2);
    CHECK(EvaluatePcpUpstreamCandidate(tcp, udp, gateways,
              PcpUpstreamOutcome::Mapped, MapperResult(wrong_gateway), 7)
              .disposition == PcpUpstreamDisposition::EndpointRejected);
    MapperResultData wrong_tcp = UpstreamMapping();
    wrong_tcp.mappings[0].local_endpoint.port = 52146;
    CHECK(EvaluatePcpUpstreamCandidate(tcp, udp, gateways,
              PcpUpstreamOutcome::Mapped, MapperResult(wrong_tcp), 7)
              .disposition == PcpUpstreamDisposition::EndpointRejected);
    MapperResultData wrong_udp = UpstreamMapping();
    wrong_udp.mappings[1].local_endpoint.port = 52146;
    CHECK(EvaluatePcpUpstreamCandidate(tcp, udp, gateways,
              PcpUpstreamOutcome::Mapped, MapperResult(wrong_udp), 7)
              .disposition == PcpUpstreamDisposition::EndpointRejected);
    MapperResultData split_public = UpstreamMapping();
    split_public.mappings[1].granted_external_endpoint.address =
        IpAddress::V4(88, 11, 22, 5);
    CHECK(EvaluatePcpUpstreamCandidate(tcp, udp, gateways,
              PcpUpstreamOutcome::Mapped, MapperResult(split_public), 7)
              .disposition == PcpUpstreamDisposition::EndpointRejected);
    UpstreamGatewayCandidates invalid = gateways;
    invalid.count = static_cast<std::uint8_t>(invalid.addresses.size() + 1);
    const PcpUpstreamDecision denied_without_evidence =
        EvaluatePcpUpstreamCandidate(tcp, udp, invalid,
            PcpUpstreamOutcome::Denied, MapperResult(UpstreamMapping()), 7);
    CHECK(denied_without_evidence.reason == ReasonCode::NoGateway);
}

void TestGenerationRouteOwnershipAndRequestBounds() {
    const NatChainTransaction tcp = PrivateCpeChain(Transport::Tcp);
    const NatChainTransaction udp = PrivateCpeChain(Transport::Udp);
    const UpstreamGatewayCandidates gateways = AuthorizedUpstream();
    CHECK(EvaluatePcpUpstreamCandidate(tcp, udp, gateways,
              PcpUpstreamOutcome::Mapped, MapperResult(UpstreamMapping(6)), 7)
              .disposition == PcpUpstreamDisposition::EndpointRejected);
    MappedCandidatePublisher route_changed(7);
    RouteBindingIdentity wrong_route = UpstreamRoute(8);
    const PcpUpstreamDecision rejected_route = PublishCandidate(
        route_changed, tcp, udp, gateways, PcpUpstreamOutcome::Mapped,
        MapperResult(UpstreamMapping()), wrong_route, nullptr, 1300);
    CHECK(rejected_route.disposition == PcpUpstreamDisposition::EndpointRejected);
    CHECK(route_changed.snapshot().candidate_count() == 0);
    MapperResultData foreign = UpstreamMapping();
    foreign.ownership = OwnershipState::Foreign;
    CHECK(EvaluatePcpUpstreamCandidate(tcp, udp, gateways,
              PcpUpstreamOutcome::Mapped, MapperResult(foreign), 7)
              .disposition == PcpUpstreamDisposition::EndpointRejected);

    PcpMapRequest request{};
    request.protocol = 6;
    request.internal_port = 4662;
    request.suggested_external_port = 443;
    request.prefer_failure = true;
    PcpMapRequestPolicyInput policy{};
    policy.request = &request;
    CHECK(ValidatePcpMapRequestPolicy(policy) ==
          PcpMapRequestPolicyStatus::PreferFailureRequiresDocumentedExactPort);
    policy.documented_exact_port = 443;
    CHECK(ValidatePcpMapRequestPolicy(policy) == PcpMapRequestPolicyStatus::Allowed);
    request.port_set_size = 2;
    CHECK(ValidatePcpMapRequestPolicy(policy) ==
          PcpMapRequestPolicyStatus::PortSetRequiresNetLabOrOne);
    request.port_set_size = 1;
    CHECK(ValidatePcpMapRequestPolicy(policy) == PcpMapRequestPolicyStatus::Allowed);
    policy.filter_requested = true;
    policy.filter_peer = Ep(10, 0, 0, 7, 4662, EndpointSource::PeerProbe);
    CHECK(ValidatePcpMapRequestPolicy(policy) ==
          PcpMapRequestPolicyStatus::FilterRequiresConcretePeer);
    policy.filter_peer = Ep(88, 11, 22, 4, 4662, EndpointSource::PeerProbe);
    CHECK(ValidatePcpMapRequestPolicy(policy) == PcpMapRequestPolicyStatus::Allowed);

    std::array<std::uint8_t, kPcpMaximumMessageSize> encoded{};
    request.protocol = 6;
    request.internal_port = 4662;
    request.lifetime_seconds = 7200;
    request.nonce[0] = 1;
    request.prefer_failure = true;
    request.port_set_size = 0;
    policy.filter_requested = false;
    policy.documented_exact_port = 0;
    CHECK(EncodePcpMapRequestForProduction(request, policy, encoded.data(),
        encoded.size()) == 0);
    policy.documented_exact_port = request.suggested_external_port;
    CHECK(EncodePcpMapRequestForProduction(request, policy, encoded.data(),
        encoded.size()) == kPcpBaseMessageSize + 4);
    request.prefer_failure = false;
    request.port_set_size = 2;
    request.first_internal_port = request.internal_port;
    policy.documented_exact_port = 0;
    policy.netlab_enabled = false;
    CHECK(EncodePcpMapRequestForProduction(request, policy, encoded.data(),
        encoded.size()) == 0);
    policy.netlab_enabled = true;
    CHECK(EncodePcpMapRequestForProduction(request, policy, encoded.data(),
        encoded.size()) == kPcpBaseMessageSize + 12);
    policy.filter_requested = true;
    CHECK(EncodePcpMapRequestForProduction(request, policy, encoded.data(),
        encoded.size()) == 0);
}

void TestProjectionKeepsOriginalLanListeners() {
    const MapperResult cpe(CpeMapping());
    const MapperResult upstream(UpstreamMapping());
    MapperResultData projected{};
    CHECK(ProjectPcpFinalMapperResult(cpe, upstream, projected));
    CHECK(projected.request_local_address.family ==
          AddressFamily::IPv4);
    CHECK(projected.request_local_address.bytes ==
          IpAddress::V4(192, 168, 68, 54).bytes);
    const TransportMappingResult* tcp = nullptr;
    const TransportMappingResult* udp = nullptr;
    for (std::size_t index = 0;
         index < projected.mapping_count; ++index) {
        if (projected.mappings[index].transport == Transport::Tcp)
            tcp = &projected.mappings[index];
        if (projected.mappings[index].transport == Transport::Udp)
            udp = &projected.mappings[index];
    }
    CHECK(tcp != nullptr);
    CHECK(udp != nullptr);
    CHECK(tcp != nullptr &&
          tcp->local_endpoint.SameSocketEndpoint(
              Ep(192, 168, 68, 54, 4662,
                 EndpointSource::LocalInterface)));
    CHECK(udp != nullptr &&
          udp->local_endpoint.SameSocketEndpoint(
              Ep(192, 168, 68, 54, 4672,
                 EndpointSource::LocalInterface)));

    MappedCandidatePublisher publisher(7);
    const NatChainTransaction tcpChain =
        PrivateCpeChain(Transport::Tcp);
    const NatChainTransaction udpChain =
        PrivateCpeChain(Transport::Udp);
    const PcpUpstreamDecision decision =
        PublishPcpUpstreamCandidate(
            publisher, tcpChain, udpChain,
            AuthorizedUpstream(), PcpUpstreamOutcome::Mapped,
            cpe, upstream, UpstreamRoute(), nullptr, 1300);
    CHECK(decision.allows_global_candidate());
    const MappedCandidate* candidate =
        publisher.snapshot().Find(Transport::Tcp);
    CHECK(candidate != nullptr);
    CHECK(candidate != nullptr &&
          candidate->local_endpoint().SameSocketEndpoint(
              Ep(192, 168, 68, 54, 4662,
                 EndpointSource::LocalInterface)));
    CHECK(candidate != nullptr &&
          candidate->published_endpoint().SameSocketEndpoint(
              Ep(88, 11, 22, 4, 52144,
                 EndpointSource::PcpMap)));
}

void TestCpeIdentityChangesRequireReplacement() {
    MapperResultData current = CpeMapping();
    MapperResultData next = current;
    next.mapper_epoch = current.mapper_epoch + 1;
    next.operation = MappingOperation::Refresh;
    next.status = MappingStatus::Renewed;
    CHECK(SamePcpCpeMappingIdentity(current, next));
    next.ownership_nonce[1] = 1;
    CHECK(!SamePcpCpeMappingIdentity(current, next));
    next = current;
    next.ownership_identity_digest[12] = 1;
    CHECK(!SamePcpCpeMappingIdentity(current, next));
    next = current;
    next.gateway.address.bytes[3] = 2;
    CHECK(!SamePcpCpeMappingIdentity(current, next));
    next = current;
    next.mappings[0].granted_external_endpoint.port++;
    CHECK(!SamePcpCpeMappingIdentity(current, next));
    next = current;
    next.mapper_epoch_reset = true;
    CHECK(!SamePcpCpeMappingIdentity(current, next));
}

} // namespace

int main() {
    TestRunbookTableAndReasons();
    TestCpeIdentityRotationReplacesFinalCandidateAtomically();
    TestCandidateThenExactCurrentProofPromotes();
    TestStaleWrongAndIncompleteNeverPromote();
    TestNegativeObservationsWithdrawAnAlreadyVerifiedPair();
    TestGatewayAndTransportContinuityRejectsDisconnectedInputs();
    TestGenerationRouteOwnershipAndRequestBounds();
    TestProjectionKeepsOriginalLanListeners();
    TestCpeIdentityChangesRequireReplacement();
    std::printf("test_pcp_upstream_policy: %d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
