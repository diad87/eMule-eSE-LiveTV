#include "stdafx.h"
#include "DirectReachabilityManager.h"
#include "natmap/address_policy.h"
#include "natmap/legacy_mapper_projection.h"

#include <chrono>
#include <cstring>

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

uint64 CDirectReachabilityManager::MonotonicMilliseconds()
{
	return static_cast<uint64>(std::chrono::duration_cast<
		std::chrono::milliseconds>(std::chrono::steady_clock::now()
			.time_since_epoch()).count());
}

CDirectReachabilityManager::CDirectReachabilityManager()
	: m_dwOwnerThreadId(::GetCurrentThreadId())
	, m_bEnabled(false)
	, m_nLocalTcpPort(0)
	, m_nLocalUdpPort(0)
	, m_nAdvertisedTcpPort(0)
	, m_nAdvertisedUdpPort(0)
	, m_nNextVerificationAttemptId(1)
	, m_nNetworkChangeRediscoveryGeneration(0)
	, m_mappedCandidates(1)
{
}

natmap::Endpoint CDirectReachabilityManager::MakeAnyV4(uint16 nPort)
{
	return natmap::Endpoint{
		natmap::IpAddress::V4(0, 0, 0, 0), nPort,
		natmap::EndpointSource::LocalInterface};
}

natmap::Endpoint CDirectReachabilityManager::MakePublicV4(uint32 nNetworkOrderIP,
	uint16 nPort, natmap::EndpointSource source)
{
	const uint8* bytes = reinterpret_cast<const uint8*>(&nNetworkOrderIP);
	return natmap::Endpoint{
		natmap::IpAddress::V4(bytes[0], bytes[1], bytes[2], bytes[3]),
		nPort, source};
}

bool CDirectReachabilityManager::BuildMappedPlane(natmap::PlaneSnapshot& plane,
	natmap::MapperKind mapper, natmap::Transport transport,
	const natmap::Endpoint& gateway, const natmap::Endpoint& local,
	const natmap::Endpoint& external,
	uint32 nLifetimeSeconds, uint32 nMapperEpoch, uint64 nGeneration)
{
	plane.local = local;
	natmap::TransitionResult result = natmap::ApplyEvent(plane,
		natmap::StateEvent{natmap::EventType::BeginGeneration, nGeneration});
	if (result.disposition != natmap::TransitionDisposition::Applied)
		return false;
	plane = result.snapshot;
	result = natmap::ApplyEvent(plane,
		natmap::StateEvent{natmap::EventType::MappingStarted, nGeneration});
	if (result.disposition != natmap::TransitionDisposition::Applied)
		return false;
	plane = result.snapshot;

	natmap::StateEvent mapped;
	mapped.type = natmap::EventType::MappingSucceeded;
	mapped.generation = nGeneration;
	mapped.lease.mapper = mapper;
	mapped.lease.transport = transport;
	mapped.lease.gateway = gateway;
	mapped.lease.local = local;
	mapped.lease.public_endpoint = external;
	mapped.lease.requested_external_port = local.port;
	mapped.lease.granted_external_port = external.port;
	mapped.lease.lifetime_seconds = nLifetimeSeconds;
	mapped.lease.mapper_epoch = nMapperEpoch;
	mapped.lease.generation = nGeneration;
	mapped.lease.owned_by_us = true;
	result = natmap::ApplyEvent(plane, mapped);
	if (result.disposition != natmap::TransitionDisposition::Applied)
		return false;
	plane = result.snapshot;
	return true;
}

void CDirectReachabilityManager::FailClosedAtGenerationLimit(
	natmap::ReasonCode reason)
{
	const uint64 generation = m_snapshot.topology_generation;
	const auto DisabledPlane =
		[generation, reason](const natmap::Endpoint& local) {
			natmap::PlaneSnapshot plane;
			plane.state = natmap::ReachabilityState::Disabled;
			plane.reason = reason;
			plane.local = local;
			plane.advertised = local;
			plane.generation = generation;
			return plane;
		};
	m_snapshot.ed2k_tcp_v4 = DisabledPlane(MakeAnyV4(
		m_nLocalTcpPort.load(std::memory_order_acquire)));
	m_snapshot.kad_udp_v4 = DisabledPlane(MakeAnyV4(
		m_nLocalUdpPort.load(std::memory_order_acquire)));
	m_snapshot.direct_v6 = DisabledPlane(
		m_snapshot.direct_v6.local);
	m_tcpLease = natmap::LeaseController{};
	m_udpLease = natmap::LeaseController{};
	m_tcpChain = natmap::NatChainTransaction{};
	m_udpChain = natmap::NatChainTransaction{};
	m_mapperRouteBinding = natmap::RouteBindingIdentity{};
	m_mapperTopologyIdentity =
		natmap::MapperTopologyIdentity{};
	m_pcpCpeResult = natmap::MapperResultData{};
	m_nNetworkChangeRediscoveryGeneration = 0;
	m_mappedCandidates.Shutdown();
	m_nAdvertisedTcpPort.store(
		m_nLocalTcpPort.load(std::memory_order_acquire),
		std::memory_order_release);
	m_nAdvertisedUdpPort.store(
		m_nLocalUdpPort.load(std::memory_order_acquire),
		std::memory_order_release);
	m_bEnabled.store(false, std::memory_order_release);
}

void CDirectReachabilityManager::AssertMainThread() const
{
	ASSERT(m_dwOwnerThreadId == ::GetCurrentThreadId());
}

void CDirectReachabilityManager::Initialize(uint16 nLocalTcpPort, uint16 nLocalUdpPort)
{
	AssertMainThread();
	m_bEnabled.store(false, std::memory_order_release);
	m_nLocalTcpPort.store(nLocalTcpPort, std::memory_order_release);
	m_nLocalUdpPort.store(nLocalUdpPort, std::memory_order_release);
	m_nAdvertisedTcpPort.store(nLocalTcpPort, std::memory_order_release);
	m_nAdvertisedUdpPort.store(nLocalUdpPort, std::memory_order_release);
	m_tcpLease = natmap::LeaseController{};
	m_udpLease = natmap::LeaseController{};
	m_tcpChain = natmap::NatChainTransaction{};
	m_udpChain = natmap::NatChainTransaction{};
	m_mapperRouteBinding = natmap::RouteBindingIdentity{};
	m_mapperTopologyIdentity =
		natmap::MapperTopologyIdentity{};
	m_pcpCpeResult = natmap::MapperResultData{};
	m_nNetworkChangeRediscoveryGeneration = 0;
	m_snapshot = natmap::ReachabilitySnapshot{};
	m_snapshot.topology_generation = 1;
	VERIFY(m_mappedCandidates.Reset(1));

	m_snapshot.ed2k_tcp_v4.state = natmap::ReachabilityState::Disabled;
	m_snapshot.ed2k_tcp_v4.reason = natmap::ReasonCode::DisabledByPreference;
	m_snapshot.ed2k_tcp_v4.local = MakeAnyV4(nLocalTcpPort);
	m_snapshot.ed2k_tcp_v4.advertised = m_snapshot.ed2k_tcp_v4.local;
	m_snapshot.ed2k_tcp_v4.generation = 1;

	m_snapshot.kad_udp_v4.state = natmap::ReachabilityState::Disabled;
	m_snapshot.kad_udp_v4.reason = natmap::ReasonCode::DisabledByPreference;
	m_snapshot.kad_udp_v4.local = MakeAnyV4(nLocalUdpPort);
	m_snapshot.kad_udp_v4.advertised = m_snapshot.kad_udp_v4.local;
	m_snapshot.kad_udp_v4.generation = 1;

	m_snapshot.direct_v6.state = natmap::ReachabilityState::Disabled;
	m_snapshot.direct_v6.reason = natmap::ReasonCode::DisabledByPreference;
	m_snapshot.direct_v6.generation = 1;
}

uint16 CDirectReachabilityManager::GetLocalTcpPort() const
{
	return m_nLocalTcpPort.load(std::memory_order_acquire);
}

uint16 CDirectReachabilityManager::GetLocalUdpPort() const
{
	return m_nLocalUdpPort.load(std::memory_order_acquire);
}

uint16 CDirectReachabilityManager::GetAdvertisedTcpPort() const
{
	if (m_bEnabled.load(std::memory_order_acquire))
		return m_nAdvertisedTcpPort.load(std::memory_order_acquire);
	return m_nLocalTcpPort.load(std::memory_order_acquire);
}

uint16 CDirectReachabilityManager::GetAdvertisedUdpPort() const
{
	if (m_bEnabled.load(std::memory_order_acquire))
		return m_nAdvertisedUdpPort.load(std::memory_order_acquire);
	return m_nLocalUdpPort.load(std::memory_order_acquire);
}

uint16 CDirectReachabilityManager::GetAdvertisedV6TcpPort() const
{
	return m_nLocalTcpPort.load(std::memory_order_acquire);
}

uint16 CDirectReachabilityManager::GetAdvertisedV6UdpPort() const
{
	return m_nLocalUdpPort.load(std::memory_order_acquire);
}

const natmap::ReachabilitySnapshot& CDirectReachabilityManager::GetSnapshot() const
{
	AssertMainThread();
	return m_snapshot;
}

const natmap::MappedCandidateSnapshot&
CDirectReachabilityManager::GetMappedCandidateSnapshot() const
{
	AssertMainThread();
	return m_mappedCandidates.snapshot();
}

uint64 CDirectReachabilityManager::GetTopologyGeneration() const
{
	AssertMainThread();
	return m_snapshot.topology_generation;
}

natmap::UpstreamGatewayCandidates
CDirectReachabilityManager::GetUpstreamGatewayCandidates(
	const natmap::UpstreamDiscoveryInput& authorizedEvidence) const
{
	AssertMainThread();
	if (!m_tcpChain.NeedsUpstream())
		return natmap::UpstreamGatewayCandidates{};
	natmap::UpstreamDiscoveryInput input = authorizedEvidence;
	if (natmap::ValidateRouteBinding(m_mapperRouteBinding) !=
		natmap::RouteBindingStatus::Valid)
		return natmap::UpstreamGatewayCandidates{};
	// The accepted mapper observation and the route captured by the UI thread
	// are authoritative. Callers may add candidates, never redefine which
	// interface or network origin produced the mapping.
	input.mapper_wan_address = m_tcpChain.FinalEndpoint().address;
	input.mapper_origin = m_mapperRouteBinding.origin;
	input.interface_index = m_mapperRouteBinding.interface_index;
	return natmap::BuildUpstreamGatewayCandidates(input);
}

bool CDirectReachabilityManager::ObserveMapperResult(
	const natmap::MapperResult& result,
	const natmap::RouteBindingIdentity& routeBinding)
{
	AssertMainThread();
	if (m_mappedCandidates.is_closed())
		return false;
	if (natmap::ValidateRouteBinding(routeBinding) !=
			natmap::RouteBindingStatus::Valid ||
		routeBinding.family != natmap::AddressFamily::IPv4 ||
		result.data().request_interface_index != routeBinding.interface_index ||
		result.data().request_local_address.family != routeBinding.family ||
		result.data().request_local_address.bytes !=
			routeBinding.local_address.bytes)
		return false;
	natmap::LegacyMapperObservation observation;
	if (natmap::AdmitLegacyMapperObservation(
			result, m_snapshot.topology_generation, observation) !=
		natmap::LegacyMapperAdmissionStatus::Accepted)
		return false;

	uint32 externalIP = 0;
	std::memcpy(&externalIP, observation.external_address.bytes.data(),
		sizeof(externalIP));
	const uint64 now = MonotonicMilliseconds();
	const bool forceMappedGenerationAdvance =
		m_mappedCandidates.RequiresReplacement(
			result, routeBinding, now);
	if (!ObserveMappedPorts(
		observation.mapper, observation.mapper_source, externalIP,
		observation.local_tcp_port, observation.external_tcp_port,
		observation.local_udp_port, observation.external_udp_port,
		observation.lifetime_seconds, observation.mapper_epoch,
		natmap::Endpoint{
			observation.gateway_address, 0,
			natmap::EndpointSource::LocalInterface},
		observation.topology_generation,
		observation.mapper_epoch_reset, observation.refresh,
		forceMappedGenerationAdvance, routeBinding))
		return false;

	const natmap::PlaneSnapshot& mapped = m_snapshot.ed2k_tcp_v4;
	const bool hasGlobalCandidate =
		mapped.lease.IsStructurallyValid()
		&& mapped.lease.generation == m_snapshot.topology_generation
		&& mapped.advertised.IsUsable()
		&& mapped.lease.public_endpoint.SameSocketEndpoint(
			mapped.advertised)
		&& natmap::ClassifyAddress(mapped.advertised.address).address_class
			== natmap::AddressClass::Public;
	if (!hasGlobalCandidate) {
		if (m_mappedCandidates.snapshot().topology_generation()
				< m_snapshot.topology_generation)
			m_mappedCandidates.Invalidate(
				m_snapshot.topology_generation);
		return true;
	}

	const natmap::MappedCandidateUpdate update =
		m_mappedCandidates.ApplyMapping(
			result, routeBinding, now,
			m_snapshot.topology_generation);
	if (update == natmap::MappedCandidateUpdate::Published
		|| update == natmap::MappedCandidateUpdate::Renewed
		|| update == natmap::MappedCandidateUpdate::Replaced)
		return true;

	// The actionable process-local snapshot is authoritative for modern
	// routing. If it cannot publish the complete pair, withdraw the legacy
	// projection in the same main-thread turn.
	DisableMappedPlanes(natmap::ReasonCode::InvalidResponse);
	return false;
}

natmap::PcpUpstreamDecision
CDirectReachabilityManager::ObservePcpUpstreamBundle(
	const natmap::PcpUpstreamResultBundle& bundle,
	const natmap::RouteBindingIdentity& lanRouteBinding)
{
	AssertMainThread();
	natmap::PcpUpstreamDecision rejected{};
	rejected.disposition =
		natmap::PcpUpstreamDisposition::EndpointRejected;
	rejected.reason = natmap::ReasonCode::NoRoute;
	if (m_mappedCandidates.is_closed() || !bundle.IsValid() ||
		natmap::ValidateRouteBinding(lanRouteBinding) !=
			natmap::RouteBindingStatus::Valid ||
		lanRouteBinding.family != natmap::AddressFamily::IPv4 ||
		lanRouteBinding.origin != natmap::NetworkOrigin::Native ||
		bundle.cpe.topology_generation !=
			m_snapshot.topology_generation ||
		bundle.cpe.request_interface_index !=
			lanRouteBinding.interface_index ||
		bundle.cpe.request_local_address.bytes !=
			lanRouteBinding.local_address.bytes)
		return rejected;

	const auto RejectCompleted =
		[this](natmap::PcpUpstreamDisposition disposition,
			natmap::ReasonCode reason) {
			natmap::PcpUpstreamDecision decision{};
			decision.disposition = disposition;
			decision.reason = reason;
			m_mappedCandidates.WithdrawRejectedObservation();
			DisableMappedPlanes(reason);
			return decision;
		};
	if (bundle.outcome !=
			natmap::PcpUpstreamResultBundle::Outcome::Mapped) {
		if (bundle.outcome ==
			natmap::PcpUpstreamResultBundle::Outcome::Denied)
			return RejectCompleted(
				natmap::PcpUpstreamDisposition::UpstreamDenied,
				natmap::ReasonCode::OperatorDenied);
		return RejectCompleted(
			natmap::PcpUpstreamDisposition::NoGlobalCandidate,
			bundle.outcome ==
				natmap::PcpUpstreamResultBundle::Outcome::Absent
				? natmap::ReasonCode::NoGateway
				: natmap::ReasonCode::NoRoute);
	}

	const uint64 now = MonotonicMilliseconds();
	const natmap::MapperResult rawCpe(bundle.cpe);
	const natmap::MapperResult rawUpstream(bundle.upstream);
	natmap::MapperResultData rawFinalData{};
	if (!natmap::ProjectPcpFinalMapperResult(
			rawCpe, rawUpstream, rawFinalData))
		return RejectCompleted(
			natmap::PcpUpstreamDisposition::EndpointRejected,
			natmap::ReasonCode::NoRoute);
	const natmap::MapperResult rawFinal(rawFinalData);

	const bool hadPcpCpe = m_pcpCpeResult.request_id != 0;
	const bool sameCpe = hadPcpCpe &&
		natmap::SamePcpCpeMappingIdentity(
			m_pcpCpeResult, bundle.cpe);
	const bool replaceFinal =
		m_mappedCandidates.RequiresReplacement(
			rawFinal, lanRouteBinding, now);
	uint64 generation = m_snapshot.topology_generation;
	if ((hadPcpCpe && !sameCpe) ||
		(m_mapperTopologyIdentity.IsValid() && !hadPcpCpe) ||
		replaceFinal) {
		++generation;
		if (generation == 0) {
			FailClosedAtGenerationLimit(
				natmap::ReasonCode::StaleGeneration);
			rejected.reason = natmap::ReasonCode::StaleGeneration;
			return rejected;
		}
	}

	natmap::MapperResultData cpeData = bundle.cpe;
	natmap::MapperResultData upstreamData = bundle.upstream;
	cpeData.topology_generation = generation;
	upstreamData.topology_generation = generation;
	natmap::MapperResultData finalData{};
	if (!natmap::ProjectPcpFinalMapperResult(
			natmap::MapperResult(cpeData),
			natmap::MapperResult(upstreamData), finalData))
		return RejectCompleted(
			natmap::PcpUpstreamDisposition::EndpointRejected,
			natmap::ReasonCode::NoRoute);

	const auto FindMapping =
		[](const natmap::MapperResultData& data,
			natmap::Transport transport)
			-> const natmap::TransportMappingResult* {
			for (std::size_t index = 0;
				index < data.mapping_count; ++index)
				if (data.mappings[index].transport == transport)
					return &data.mappings[index];
			return NULL;
		};
	const auto MakeLease =
		[generation, &FindMapping](
			const natmap::MapperResultData& data,
			natmap::Transport transport) {
			natmap::PortLease lease;
			const natmap::TransportMappingResult* mapping =
				FindMapping(data, transport);
			if (mapping == NULL)
				return lease;
			lease.mapper = natmap::MapperKind::Pcp;
			lease.transport = transport;
			lease.gateway = data.gateway;
			lease.local = mapping->local_endpoint;
			lease.public_endpoint =
				mapping->granted_external_endpoint;
			lease.requested_external_port =
				mapping->requested_external_port;
			lease.granted_external_port =
				mapping->granted_external_endpoint.port;
			lease.lifetime_seconds = mapping->lifetime_seconds;
			lease.mapper_epoch = data.mapper_epoch;
			lease.ownership_nonce = data.ownership_nonce;
			lease.generation = generation;
			lease.owned_by_us = true;
			return lease;
		};
	const natmap::PortLease cpeTcp =
		MakeLease(cpeData, natmap::Transport::Tcp);
	const natmap::PortLease cpeUdp =
		MakeLease(cpeData, natmap::Transport::Udp);
	const natmap::PortLease upstreamTcp =
		MakeLease(upstreamData, natmap::Transport::Tcp);
	const natmap::PortLease upstreamUdp =
		MakeLease(upstreamData, natmap::Transport::Udp);
	natmap::NatChainTransaction cpeTcpChain;
	natmap::NatChainTransaction cpeUdpChain;
	if (!cpeTcpChain.Begin(generation, lanRouteBinding.origin) ||
		!cpeUdpChain.Begin(generation, lanRouteBinding.origin) ||
		!cpeTcpChain.AppendLease(cpeTcp, now) ||
		!cpeUdpChain.AppendLease(cpeUdp, now))
		return RejectCompleted(
			natmap::PcpUpstreamDisposition::ChainIncomplete,
			natmap::ReasonCode::CgnatWithoutLease);
	const natmap::UpstreamGatewayCandidates gateways =
		natmap::BuildUpstreamGatewayCandidates(
			bundle.authorized_evidence);
	natmap::PcpUpstreamDecision decision =
		natmap::EvaluatePcpUpstreamCandidate(
			cpeTcpChain, cpeUdpChain, gateways,
			natmap::PcpUpstreamOutcome::Mapped,
			natmap::MapperResult(upstreamData), generation);
	if (!decision.allows_global_candidate())
		return RejectCompleted(
			decision.disposition, decision.reason);

	natmap::NatChainTransaction tcpChain = cpeTcpChain;
	natmap::NatChainTransaction udpChain = cpeUdpChain;
	if (!tcpChain.AppendLease(upstreamTcp, now) ||
		!udpChain.AppendLease(upstreamUdp, now) ||
		tcpChain.Evaluate() !=
			natmap::NatChainStatus::CompletePublic ||
		udpChain.Evaluate() !=
			natmap::NatChainStatus::CompletePublic)
		return RejectCompleted(
			natmap::PcpUpstreamDisposition::ChainIncomplete,
			natmap::ReasonCode::NoRoute);

	const natmap::TransportMappingResult* finalTcp =
		FindMapping(finalData, natmap::Transport::Tcp);
	const natmap::TransportMappingResult* finalUdp =
		FindMapping(finalData, natmap::Transport::Udp);
	natmap::PlaneSnapshot tcpPlane;
	natmap::PlaneSnapshot udpPlane;
	if (finalTcp == NULL || finalUdp == NULL ||
		!BuildMappedPlane(tcpPlane, natmap::MapperKind::Pcp,
			natmap::Transport::Tcp, finalData.gateway,
			finalTcp->local_endpoint,
			finalTcp->granted_external_endpoint,
			finalTcp->lifetime_seconds,
			finalData.mapper_epoch, generation) ||
		!BuildMappedPlane(udpPlane, natmap::MapperKind::Pcp,
			natmap::Transport::Udp, finalData.gateway,
			finalUdp->local_endpoint,
			finalUdp->granted_external_endpoint,
			finalUdp->lifetime_seconds,
			finalData.mapper_epoch, generation))
		return RejectCompleted(
			natmap::PcpUpstreamDisposition::EndpointRejected,
			natmap::ReasonCode::InvalidResponse);
	tcpPlane.lease.ownership_nonce =
		finalData.ownership_nonce;
	udpPlane.lease.ownership_nonce =
		finalData.ownership_nonce;
	natmap::LeaseController tcpLease;
	natmap::LeaseController udpLease;
	if (!tcpLease.Activate(tcpPlane.lease, now) ||
		!udpLease.Activate(udpPlane.lease, now))
		return RejectCompleted(
			natmap::PcpUpstreamDisposition::EndpointRejected,
			natmap::ReasonCode::InvalidResponse);

	natmap::LegacyMapperObservation observation;
	if (natmap::AdmitLegacyMapperObservation(
			natmap::MapperResult(finalData), generation,
			observation) !=
			natmap::LegacyMapperAdmissionStatus::Accepted)
		return RejectCompleted(
			natmap::PcpUpstreamDisposition::EndpointRejected,
			natmap::ReasonCode::InvalidResponse);
	natmap::MapperTopologyIdentity topologyIdentity;
	if (!natmap::BuildMapperTopologyIdentity(
			observation, topologyIdentity))
		return RejectCompleted(
			natmap::PcpUpstreamDisposition::EndpointRejected,
			natmap::ReasonCode::InvalidResponse);

	// The publisher is the last fallible write. Every CPE/upstream chain,
	// lease, plane and identity above was prepared in a local copy.
	// ApplyMapping authenticates the worker's result against the *currently*
	// published generation and performs its own replacement transition.  The
	// locally prepared chains/planes already carry that final generation, but
	// feeding it back here would make a valid N result look stale before the
	// publisher can atomically advance to N+1.
	decision.update = m_mappedCandidates.ApplyMapping(
		rawFinal, lanRouteBinding,
		now, generation);
	if (decision.update != natmap::MappedCandidateUpdate::Published &&
		decision.update != natmap::MappedCandidateUpdate::Renewed &&
		decision.update != natmap::MappedCandidateUpdate::Replaced)
		return RejectCompleted(
			natmap::PcpUpstreamDisposition::EndpointRejected,
			natmap::ReasonCode::NoRoute);

	m_snapshot.topology_generation = generation;
	m_snapshot.ed2k_tcp_v4 = tcpPlane;
	m_snapshot.kad_udp_v4 = udpPlane;
	m_tcpLease = tcpLease;
	m_udpLease = udpLease;
	m_tcpChain = tcpChain;
	m_udpChain = udpChain;
	m_mapperRouteBinding = lanRouteBinding;
	m_mapperTopologyIdentity = topologyIdentity;
	m_pcpCpeResult = cpeData;
	m_nNetworkChangeRediscoveryGeneration = 0;
	m_nLocalTcpPort.store(
		finalTcp->local_endpoint.port, std::memory_order_release);
	m_nLocalUdpPort.store(
		finalUdp->local_endpoint.port, std::memory_order_release);
	m_nAdvertisedTcpPort.store(
		finalTcp->granted_external_endpoint.port,
		std::memory_order_release);
	m_nAdvertisedUdpPort.store(
		finalUdp->granted_external_endpoint.port,
		std::memory_order_release);
	m_bEnabled.store(true, std::memory_order_release);
	return decision;
}

bool CDirectReachabilityManager::ObservePcpCpeAtomicityFailure(
	const natmap::MapperResult& result,
	const natmap::RouteBindingIdentity& routeBinding)
{
	AssertMainThread();
	const natmap::MapperResultData& data = result.data();
	if (!result.IsStructurallyValid()
		|| data.mapper != natmap::MapperKind::Pcp
		|| data.source != natmap::MapperSource::PcpCpe
		|| data.status != natmap::MappingStatus::Failed
		|| data.reason != natmap::ReasonCode::CgnatWithoutLease
		|| data.verification != natmap::VerificationState::Failed
		|| data.topology_generation != m_snapshot.topology_generation
		|| natmap::ValidateRouteBinding(routeBinding) !=
			natmap::RouteBindingStatus::Valid
		|| routeBinding.origin != natmap::NetworkOrigin::Native
		|| data.request_interface_index != routeBinding.interface_index
		|| data.request_local_address.bytes !=
			routeBinding.local_address.bytes)
		return false;
	return DisableMappedPlanes(natmap::ReasonCode::CgnatWithoutLease);
}

bool CDirectReachabilityManager::ObserveMapperEpochReset()
{
	AssertMainThread();
	const uint64 generation = m_snapshot.topology_generation + 1;
	if (generation == 0) {
		FailClosedAtGenerationLimit(
			natmap::ReasonCode::StaleGeneration);
		return true;
	}
	const natmap::TransitionResult tcp =
		natmap::InvalidateForMapperEpochReset(
			m_snapshot.ed2k_tcp_v4, generation);
	const natmap::TransitionResult udp =
		natmap::InvalidateForMapperEpochReset(
			m_snapshot.kad_udp_v4, generation);
	if (tcp.disposition != natmap::TransitionDisposition::Applied ||
		udp.disposition != natmap::TransitionDisposition::Applied)
		return false;

	m_snapshot.topology_generation = generation;
	m_snapshot.ed2k_tcp_v4 = tcp.snapshot;
	m_snapshot.kad_udp_v4 = udp.snapshot;
	m_mappedCandidates.Invalidate(generation);
	m_tcpLease = natmap::LeaseController{};
	m_udpLease = natmap::LeaseController{};
	m_tcpChain = natmap::NatChainTransaction{};
	m_udpChain = natmap::NatChainTransaction{};
	m_mapperRouteBinding = natmap::RouteBindingIdentity{};
	m_mapperTopologyIdentity =
		natmap::MapperTopologyIdentity{};
	m_pcpCpeResult = natmap::MapperResultData{};
	m_nNetworkChangeRediscoveryGeneration = 0;
	m_nAdvertisedTcpPort.store(
		m_nLocalTcpPort.load(std::memory_order_acquire),
		std::memory_order_release);
	m_nAdvertisedUdpPort.store(
		m_nLocalUdpPort.load(std::memory_order_acquire),
		std::memory_order_release);
	m_bEnabled.store(false, std::memory_order_release);
	return true;
}

bool CDirectReachabilityManager::DisableMappingsByPreference()
{
	return DisableMappedPlanes(
		natmap::ReasonCode::DisabledByPreference);
}

bool CDirectReachabilityManager::ObserveNetworkRouteChange(
	natmap::NetworkChangeTransition* transition)
{
	AssertMainThread();
	const bool wasEnabled =
		m_bEnabled.load(std::memory_order_acquire);
	const natmap::NetworkChangeTransition prepared =
		natmap::PrepareNetworkChange(m_snapshot);
	if (transition != NULL)
		*transition = prepared;
	if (prepared.status ==
		natmap::NetworkChangeStatus::GenerationExhausted) {
		FailClosedAtGenerationLimit(
			natmap::ReasonCode::InterfaceChanged);
		return wasEnabled;
	}
	if (!prepared.IsApplied()) {
		// A malformed internal snapshot must not leave a previously
		// advertised endpoint enabled after its network identity changed.
		FailClosedAtGenerationLimit(
			natmap::ReasonCode::InterfaceChanged);
		return wasEnabled;
	}

	m_snapshot = prepared.snapshot;
	m_mappedCandidates.Invalidate(
		prepared.current_generation);
	m_tcpLease = natmap::LeaseController{};
	m_udpLease = natmap::LeaseController{};
	m_tcpChain = natmap::NatChainTransaction{};
	m_udpChain = natmap::NatChainTransaction{};
	m_mapperRouteBinding = natmap::RouteBindingIdentity{};
	m_mapperTopologyIdentity =
		natmap::MapperTopologyIdentity{};
	m_pcpCpeResult = natmap::MapperResultData{};
	m_nNetworkChangeRediscoveryGeneration =
		prepared.current_generation;
	m_nAdvertisedTcpPort.store(
		m_nLocalTcpPort.load(std::memory_order_acquire),
		std::memory_order_release);
	m_nAdvertisedUdpPort.store(
		m_nLocalUdpPort.load(std::memory_order_acquire),
		std::memory_order_release);
	m_bEnabled.store(false, std::memory_order_release);
	return wasEnabled;
}

bool CDirectReachabilityManager::DisableMappedPlanes(
	natmap::ReasonCode reason)
{
	AssertMainThread();
	const bool wasEnabled =
		m_bEnabled.load(std::memory_order_acquire);
	const uint64 generation = m_snapshot.topology_generation + 1;
	if (generation == 0) {
		FailClosedAtGenerationLimit(reason);
		return wasEnabled;
	}
	const natmap::TransitionResult tcp = natmap::ApplyEvent(
		m_snapshot.ed2k_tcp_v4,
		natmap::StateEvent{
			natmap::EventType::Disable, generation,
			reason});
	const natmap::TransitionResult udp = natmap::ApplyEvent(
		m_snapshot.kad_udp_v4,
		natmap::StateEvent{
			natmap::EventType::Disable, generation,
			reason});
	if (tcp.disposition != natmap::TransitionDisposition::Applied
		|| udp.disposition != natmap::TransitionDisposition::Applied)
		return false;

	m_snapshot.topology_generation = generation;
	m_snapshot.ed2k_tcp_v4 = tcp.snapshot;
	m_snapshot.kad_udp_v4 = udp.snapshot;
	m_mappedCandidates.Invalidate(generation);
	m_tcpLease = natmap::LeaseController{};
	m_udpLease = natmap::LeaseController{};
	m_tcpChain = natmap::NatChainTransaction{};
	m_udpChain = natmap::NatChainTransaction{};
	m_mapperRouteBinding = natmap::RouteBindingIdentity{};
	m_mapperTopologyIdentity =
		natmap::MapperTopologyIdentity{};
	m_pcpCpeResult = natmap::MapperResultData{};
	m_nNetworkChangeRediscoveryGeneration = 0;
	m_nAdvertisedTcpPort.store(
		m_nLocalTcpPort.load(std::memory_order_acquire),
		std::memory_order_release);
	m_nAdvertisedUdpPort.store(
		m_nLocalUdpPort.load(std::memory_order_acquire),
		std::memory_order_release);
	m_bEnabled.store(false, std::memory_order_release);
	return wasEnabled;
}

bool CDirectReachabilityManager::ObserveFiniteMappingExpiry()
{
	AssertMainThread();
	const bool hasTcpLease = m_tcpLease.HasLease()
		&& m_tcpLease.lease().lifetime_seconds != 0;
	const bool hasUdpLease = m_udpLease.HasLease()
		&& m_udpLease.lease().lifetime_seconds != 0;
	if (!hasTcpLease && !hasUdpLease)
		return false;

	const uint64 generation = m_snapshot.topology_generation + 1;
	if (generation == 0) {
		FailClosedAtGenerationLimit(
			natmap::ReasonCode::LeaseExpired);
		return true;
	}
	const natmap::TransitionResult tcp =
		hasTcpLease
			? natmap::InvalidateForLeaseExpiry(
				m_snapshot.ed2k_tcp_v4, generation)
			: natmap::ApplyEvent(
				m_snapshot.ed2k_tcp_v4,
				natmap::StateEvent{
					natmap::EventType::Disable, generation});
	const natmap::TransitionResult udp =
		hasUdpLease
			? natmap::InvalidateForLeaseExpiry(
				m_snapshot.kad_udp_v4, generation)
			: natmap::ApplyEvent(
				m_snapshot.kad_udp_v4,
				natmap::StateEvent{
					natmap::EventType::Disable, generation});
	if (tcp.disposition != natmap::TransitionDisposition::Applied
		|| udp.disposition != natmap::TransitionDisposition::Applied)
		return false;

	m_snapshot.topology_generation = generation;
	m_snapshot.ed2k_tcp_v4 = tcp.snapshot;
	m_snapshot.kad_udp_v4 = udp.snapshot;
	m_mappedCandidates.Invalidate(generation);
	m_tcpLease = natmap::LeaseController{};
	m_udpLease = natmap::LeaseController{};
	m_tcpChain = natmap::NatChainTransaction{};
	m_udpChain = natmap::NatChainTransaction{};
	m_mapperRouteBinding = natmap::RouteBindingIdentity{};
	m_mapperTopologyIdentity =
		natmap::MapperTopologyIdentity{};
	m_pcpCpeResult = natmap::MapperResultData{};
	m_nNetworkChangeRediscoveryGeneration = 0;
	m_nAdvertisedTcpPort.store(
		m_nLocalTcpPort.load(std::memory_order_acquire),
		std::memory_order_release);
	m_nAdvertisedUdpPort.store(
		m_nLocalUdpPort.load(std::memory_order_acquire),
		std::memory_order_release);
	m_bEnabled.store(false, std::memory_order_release);
	return true;
}

bool CDirectReachabilityManager::ObserveMappingLoss()
{
	return DisableMappedPlanes(natmap::ReasonCode::LeaseExpired);
}

bool CDirectReachabilityManager::ShutdownMappedCandidates()
{
	AssertMainThread();
	if (m_mappedCandidates.is_closed())
		return false;
	m_nAdvertisedTcpPort.store(
		m_nLocalTcpPort.load(std::memory_order_acquire),
		std::memory_order_release);
	m_nAdvertisedUdpPort.store(
		m_nLocalUdpPort.load(std::memory_order_acquire),
		std::memory_order_release);
	m_bEnabled.store(false, std::memory_order_release);
	m_pcpCpeResult = natmap::MapperResultData{};
	const natmap::MappedCandidateRetirement retired =
		m_mappedCandidates.Shutdown();
	return retired == natmap::MappedCandidateRetirement::Retired
		|| retired == natmap::MappedCandidateRetirement::NoChange;
}

natmap::DirectRouteSelection
CDirectReachabilityManager::SelectPreferredRoute(
	const natmap::CandidateObservation& directV6,
	bool bIPv6Enabled, bool bMappingsEnabled,
	bool bPeerSupportsIPv6, uint32 nPublishedV4,
	uint16 nPublishedTcpPort) const
{
	AssertMainThread();
	natmap::DirectRouteSelectionInput input{};
	input.topology_generation = m_snapshot.topology_generation;
	input.direct_v6 = directV6;
	input.direct_v4 = m_directV4Observation;
	input.ipv6_enabled = bIPv6Enabled;
	input.mappings_enabled = bMappingsEnabled;
	input.peer_supports_ipv6 = bPeerSupportsIPv6;
	if (nPublishedV4 != 0 && nPublishedTcpPort != 0
		&& m_directV4Attempt.IsValid()) {
		const natmap::Endpoint publishedDirectV4 = MakePublicV4(
			nPublishedV4, nPublishedTcpPort,
			natmap::EndpointSource::LocalInterface);
		input.direct_v4_endpoint_current =
			publishedDirectV4.SameSocketEndpoint(
				m_directV4Attempt.endpoint);
	}

	const natmap::PlaneSnapshot& mapped =
		m_snapshot.ed2k_tcp_v4;
	const bool hasMappedCandidate =
		mapped.generation != 0
		&& mapped.lease.IsStructurallyValid()
		&& mapped.lease.generation == mapped.generation
		&& mapped.advertised.IsUsable()
		&& mapped.lease.public_endpoint.SameSocketEndpoint(
			mapped.advertised);
	const natmap::MappedCandidate* mappedCandidate =
		m_mappedCandidates.snapshot().Find(
			natmap::Transport::Tcp);
	if (hasMappedCandidate && mappedCandidate != NULL) {
		input.mapped_v4.readiness =
			mapped.HasClassicHighIdEvidence()
				&& mappedCandidate->verification() ==
					natmap::MappedCandidateVerification::Verified
				? natmap::CandidateReadiness::Verified
				: natmap::CandidateReadiness::Candidate;
		input.mapped_v4.generation =
			mappedCandidate->topology_generation();
	}
	return natmap::SelectPreferredDirectRoute(input);
}

bool CDirectReachabilityManager::HasVerifiedEd2kReachability() const
{
	AssertMainThread();
	const auto HasLegacyEvidence = [this]() {
		return m_snapshot.ed2k_tcp_v4.HasClassicHighIdEvidence();
	};
	const natmap::MappedCandidate* mapped =
		m_mappedCandidates.snapshot().Find(
			natmap::Transport::Tcp);
	return mapped != NULL
		&& mapped->verification() ==
			natmap::MappedCandidateVerification::Verified
		&& HasLegacyEvidence();
}

bool CDirectReachabilityManager::PromoteEd2kIfEvidenceComplete()
{
	AssertMainThread();
	if (!m_snapshot.ed2k_tcp_v4.HasCompleteClassicHighIdEvidence()
		|| m_snapshot.ed2k_tcp_v4.state ==
			natmap::ReachabilityState::Reachable)
		return true;
	if (m_snapshot.ed2k_tcp_v4.state !=
		natmap::ReachabilityState::Verifying)
		return false;

	natmap::StateEvent verified;
	verified.type = natmap::EventType::VerificationSucceeded;
	verified.generation = m_snapshot.ed2k_tcp_v4.generation;
	verified.advertised = m_snapshot.ed2k_tcp_v4.advertised;
	verified.verification_attempt =
		m_snapshot.ed2k_tcp_v4.verification_attempt;
	const natmap::TransitionResult result = natmap::ApplyEvent(
		m_snapshot.ed2k_tcp_v4, verified);
	if (result.disposition !=
		natmap::TransitionDisposition::Applied)
		return false;

	natmap::MappedCandidateProof proof;
	proof.attempt =
		m_snapshot.ed2k_tcp_v4.verification_attempt;
	proof.primary =
		m_snapshot.ed2k_tcp_v4.primary_evidence;
	proof.inbound =
		m_snapshot.ed2k_tcp_v4.inbound_evidence;
	const natmap::MappedCandidatePromotion promotion =
		m_mappedCandidates.Promote(
			proof, MonotonicMilliseconds());
	if (promotion != natmap::MappedCandidatePromotion::Promoted
		&& promotion !=
			natmap::MappedCandidatePromotion::AlreadyVerified)
		return false;
	m_snapshot.ed2k_tcp_v4 = result.snapshot;
	return true;
}

bool CDirectReachabilityManager::IsCurrentDirectV4Attempt(
	const natmap::VerificationAttempt& attempt) const
{
	return attempt.IsValid()
		&& m_directV4Attempt.IsValid()
		&& attempt.attempt_id == m_directV4Attempt.attempt_id
		&& attempt.topology_generation
			== m_directV4Attempt.topology_generation
		&& attempt.endpoint.SameSocketEndpoint(
			m_directV4Attempt.endpoint)
		&& attempt.transport == m_directV4Attempt.transport
		&& attempt.path == m_directV4Attempt.path
		&& attempt.started_monotonic_ms
			== m_directV4Attempt.started_monotonic_ms
		&& attempt.deadline_monotonic_ms
			== m_directV4Attempt.deadline_monotonic_ms
		&& attempt.topology_generation
			== m_snapshot.topology_generation;
}

bool CDirectReachabilityManager::PromoteDirectV4IfEvidenceComplete()
{
	AssertMainThread();
	if (!m_directV4Attempt.IsValid()
		|| m_directV4Attempt.topology_generation
			!= m_snapshot.topology_generation
		|| MonotonicMilliseconds()
			> m_directV4Attempt.deadline_monotonic_ms) {
		m_directV4Observation = natmap::CandidateObservation{};
		return false;
	}
	m_directV4Observation = natmap::ObserveDirectV4Evidence(
		natmap::DirectV4EvidenceInput{
			m_snapshot.topology_generation,
			m_directV4Attempt.topology_generation,
			m_directV4ServerEvidence.IsFreshFor(
				m_directV4Attempt),
			m_directV4InboundEvidence.IsFreshFor(
				m_directV4Attempt),
			true,
			true});
	return m_directV4Observation.IsVerifiedFor(
		m_snapshot.topology_generation);
}

bool CDirectReachabilityManager::BeginDirectV4Verification(
	uint32 nSocketLocalIP, uint64 nCapturedGeneration,
	natmap::VerificationAttempt& attempt)
{
	AssertMainThread();
	attempt = natmap::VerificationAttempt{};
	if (nCapturedGeneration == 0
		|| nCapturedGeneration != m_snapshot.topology_generation
		|| nSocketLocalIP == 0
		|| m_nNextVerificationAttemptId == 0)
		return false;

	const uint8* bytes =
		reinterpret_cast<const uint8*>(&nSocketLocalIP);
	const natmap::AddressDecision address =
		natmap::ClassifyAddress(natmap::IpAddress::V4(
			bytes[0], bytes[1], bytes[2], bytes[3]));
	const uint16 localPort =
		m_nLocalTcpPort.load(std::memory_order_acquire);
	if (!address.globally_routable || !address.direct_publishable
		|| localPort == 0)
		return false;

	const uint64 now = MonotonicMilliseconds();
	natmap::VerificationAttempt nextAttempt;
	nextAttempt.attempt_id = m_nNextVerificationAttemptId++;
	nextAttempt.topology_generation = nCapturedGeneration;
	nextAttempt.endpoint = MakePublicV4(
		nSocketLocalIP, localPort,
		natmap::EndpointSource::LocalInterface);
	nextAttempt.transport = natmap::Transport::Tcp;
	nextAttempt.path = natmap::VerificationPath::Direct;
	nextAttempt.started_monotonic_ms = now;
	nextAttempt.deadline_monotonic_ms =
		now + natmap::VerificationAttempt::kMaximumWindowMs;
	if (!nextAttempt.IsValid())
		return false;

	m_directV4Attempt = nextAttempt;
	m_directV4ServerEvidence = natmap::Evidence{};
	m_directV4InboundEvidence = natmap::Evidence{};
	m_directV4Observation = natmap::CandidateObservation{};
	attempt = nextAttempt;
	return true;
}

bool CDirectReachabilityManager::BeginEd2kVerification(
	natmap::VerificationAttempt& attempt)
{
	AssertMainThread();
	if (m_mappedCandidates.is_closed())
		return false;
	if (!IsEnabled())
		return false;
	const natmap::MappedCandidate* mappedCandidate =
		m_mappedCandidates.snapshot().Find(
			natmap::Transport::Tcp);
	if (mappedCandidate == NULL
		|| mappedCandidate->topology_generation()
			!= m_snapshot.topology_generation
		|| !mappedCandidate->published_endpoint().SameSocketEndpoint(
			m_snapshot.ed2k_tcp_v4.advertised))
		return false;
	const uint64 now = MonotonicMilliseconds();
	const natmap::ReachabilityState state =
		m_snapshot.ed2k_tcp_v4.state;
	if (state == natmap::ReachabilityState::Verifying
		&& m_snapshot.ed2k_tcp_v4.verification_attempt.IsValid()
		&& now <= m_snapshot.ed2k_tcp_v4.verification_attempt
			.deadline_monotonic_ms) {
		attempt = m_snapshot.ed2k_tcp_v4.verification_attempt;
		return true;
	}
	if (state == natmap::ReachabilityState::Verifying) {
		natmap::StateEvent expired;
		expired.type = natmap::EventType::VerificationFailed;
		expired.generation = m_snapshot.ed2k_tcp_v4.generation;
		expired.reason = natmap::ReasonCode::VerificationTimeout;
		expired.verification_attempt =
			m_snapshot.ed2k_tcp_v4.verification_attempt;
		const natmap::TransitionResult failed = natmap::ApplyEvent(
			m_snapshot.ed2k_tcp_v4, expired);
		if (failed.disposition !=
			natmap::TransitionDisposition::Applied)
			return false;
		m_snapshot.ed2k_tcp_v4 = failed.snapshot;
	}
	if (m_nNextVerificationAttemptId == 0)
		return false;

	natmap::VerificationAttempt nextAttempt;
	nextAttempt.attempt_id = m_nNextVerificationAttemptId++;
	nextAttempt.topology_generation =
		m_snapshot.ed2k_tcp_v4.generation;
	nextAttempt.endpoint = m_snapshot.ed2k_tcp_v4.advertised;
	nextAttempt.transport = natmap::Transport::Tcp;
	nextAttempt.path = natmap::VerificationPath::Direct;
	nextAttempt.started_monotonic_ms = now;
	nextAttempt.deadline_monotonic_ms =
		now + natmap::VerificationAttempt::kMaximumWindowMs;
	natmap::StateEvent event;
	event.type = natmap::EventType::VerificationStarted;
	event.generation = m_snapshot.ed2k_tcp_v4.generation;
	event.verification_attempt = nextAttempt;
	const natmap::TransitionResult result = natmap::ApplyEvent(
		m_snapshot.ed2k_tcp_v4, event);
	if (result.disposition != natmap::TransitionDisposition::Applied)
		return false;
	m_snapshot.ed2k_tcp_v4 = result.snapshot;
	attempt = nextAttempt;
	return true;
}

bool CDirectReachabilityManager::ObserveServerIdChange(
	bool bHighId, const natmap::VerificationAttempt& attempt)
{
	AssertMainThread();
	if (m_mappedCandidates.is_closed())
		return false;
	if (!IsEnabled())
		return false;

	natmap::StateEvent event;
	event.generation = attempt.topology_generation;
	event.verification_attempt = attempt;
	if (bHighId) {
		event.type = natmap::EventType::ServerEvidenceObserved;
		event.primary_evidence = natmap::Evidence{
			natmap::EvidenceKind::ServerHighId,
			attempt.endpoint, attempt.topology_generation,
			MonotonicMilliseconds(), attempt.attempt_id};
	} else {
		event.type = natmap::EventType::VerificationFailed;
		event.reason = natmap::ReasonCode::ServerCallbackFailed;
	}
	const natmap::TransitionResult result = natmap::ApplyEvent(
		m_snapshot.ed2k_tcp_v4, event);
	if (result.disposition != natmap::TransitionDisposition::Applied)
		return false;
	m_snapshot.ed2k_tcp_v4 = result.snapshot;
	return PromoteEd2kIfEvidenceComplete();
}

bool CDirectReachabilityManager::ObserveDirectV4ServerState(
	bool bHighId, uint32 nPublicIP,
	const natmap::VerificationAttempt& attempt)
{
	AssertMainThread();
	if (!IsCurrentDirectV4Attempt(attempt))
		return false;

	const natmap::Endpoint reported = MakePublicV4(
		nPublicIP, attempt.endpoint.port,
		natmap::EndpointSource::LocalInterface);
	if (!bHighId || nPublicIP == 0
		|| !reported.SameSocketEndpoint(attempt.endpoint)) {
		m_directV4ServerEvidence = natmap::Evidence{};
		m_directV4Observation = natmap::CandidateObservation{};
		return true;
	}
	m_directV4ServerEvidence = natmap::Evidence{
		natmap::EvidenceKind::ServerHighId,
		attempt.endpoint, attempt.topology_generation,
		MonotonicMilliseconds(), attempt.attempt_id};
	PromoteDirectV4IfEvidenceComplete();
	return true;
}

bool CDirectReachabilityManager::ObserveInboundTcpAccept(
	const natmap::VerificationAttempt& attempt)
{
	AssertMainThread();
	if (m_mappedCandidates.is_closed())
		return false;
	if (IsCurrentDirectV4Attempt(attempt)) {
		m_directV4InboundEvidence = natmap::Evidence{
			natmap::EvidenceKind::InboundTcpAccept,
			attempt.endpoint, attempt.topology_generation,
			MonotonicMilliseconds(), attempt.attempt_id};
		return PromoteDirectV4IfEvidenceComplete();
	}
	if (!IsEnabled())
		return false;
	natmap::StateEvent event;
	event.type = natmap::EventType::InboundEvidenceObserved;
	event.generation = attempt.topology_generation;
	event.inbound_evidence = natmap::Evidence{
		natmap::EvidenceKind::InboundTcpAccept,
		attempt.endpoint, attempt.topology_generation,
		MonotonicMilliseconds(), attempt.attempt_id};
	const natmap::TransitionResult result = natmap::ApplyEvent(
		m_snapshot.ed2k_tcp_v4, event);
	if (result.disposition != natmap::TransitionDisposition::Applied)
		return false;
	m_snapshot.ed2k_tcp_v4 = result.snapshot;
	return PromoteEd2kIfEvidenceComplete();
}

bool CDirectReachabilityManager::ObserveMappedPorts(
	natmap::MapperKind mapper, natmap::MapperSource mapperSource,
	uint32 nExternalIP, uint16 nLocalTcpPort, uint16 nExternalTcpPort,
	uint16 nLocalUdpPort, uint16 nExternalUdpPort,
	uint32 nLifetimeSeconds, uint32 nMapperEpoch,
	const natmap::Endpoint& gateway, uint64 resultGeneration,
	bool bMapperEpochReset, bool bRefresh,
	bool bForceGenerationAdvance,
	const natmap::RouteBindingIdentity& routeBinding)
{
	AssertMainThread();
	if (mapper == natmap::MapperKind::None || nExternalIP == 0 ||
		nLocalTcpPort == 0 || nExternalTcpPort == 0 ||
		natmap::ValidateRouteBinding(routeBinding) !=
			natmap::RouteBindingStatus::Valid)
		return false;

	const natmap::EndpointSource source = mapper == natmap::MapperKind::Pcp
		? natmap::EndpointSource::PcpMap
		: mapper == natmap::MapperKind::NatPmp
			? natmap::EndpointSource::NatPmpPublicAddress
			: natmap::EndpointSource::UpnpExternalAddress;
	const natmap::Endpoint localTcp = MakeAnyV4(nLocalTcpPort);
	const natmap::Endpoint publicTcp = MakePublicV4(
		nExternalIP, nExternalTcpPort, source);
	const natmap::Endpoint localUdp = MakeAnyV4(nLocalUdpPort);
	const natmap::Endpoint publicUdp = MakePublicV4(
		nExternalIP, nExternalUdpPort, source);
	const uint64 now = MonotonicMilliseconds();

	natmap::LegacyMapperObservation renewalBoundary{};
	renewalBoundary.mapper = mapper;
	renewalBoundary.mapper_source = mapperSource;
	renewalBoundary.gateway_address = gateway.address;
	renewalBoundary.external_address = publicTcp.address;
	renewalBoundary.local_tcp_port = nLocalTcpPort;
	renewalBoundary.external_tcp_port = nExternalTcpPort;
	renewalBoundary.local_udp_port = nLocalUdpPort;
	renewalBoundary.external_udp_port = nExternalUdpPort;
	renewalBoundary.topology_generation = resultGeneration;
	renewalBoundary.refresh = bRefresh;
	renewalBoundary.mapper_epoch_reset = bMapperEpochReset;
	const bool completesNetworkChange =
		natmap::IsNetworkChangeRediscovery(
			m_nNetworkChangeRediscoveryGeneration,
			m_snapshot.topology_generation,
			resultGeneration,
			m_mapperTopologyIdentity.IsValid(),
			bRefresh);
	natmap::TopologyGenerationDecision generationDecision;
	if (completesNetworkChange) {
		generationDecision.disposition =
			natmap::TopologyGenerationDisposition::Advance;
		generationDecision.generation = resultGeneration;
	} else {
		generationDecision =
			natmap::ResolveTopologyGeneration(
				m_snapshot.topology_generation,
				m_mapperTopologyIdentity, renewalBoundary);
	}
	if (generationDecision.disposition
			== natmap::TopologyGenerationDisposition::RejectInvalid
		|| generationDecision.disposition
			== natmap::TopologyGenerationDisposition::RejectStale)
		return false;
	if (generationDecision.disposition
			== natmap::TopologyGenerationDisposition::RejectOverflow) {
		m_nLocalTcpPort.store(
			nLocalTcpPort, std::memory_order_release);
		m_nLocalUdpPort.store(
			nLocalUdpPort, std::memory_order_release);
		FailClosedAtGenerationLimit(
			natmap::ReasonCode::StaleGeneration);
		// Generation cannot advance past UINT64_MAX, but callers still need
		// an observable change so they can withdraw the previously advertised
		// endpoint after the fail-closed transition.
		return true;
	}
	natmap::MapperTopologyIdentity candidateIdentity{};
	if (!natmap::BuildMapperTopologyIdentity(
			renewalBoundary, candidateIdentity))
		return false;

	if (generationDecision.disposition
			== natmap::TopologyGenerationDisposition::Keep
			&& !bForceGenerationAdvance
			&& m_tcpLease.HasLease()) {
		if (natmap::EvaluateRouteBindingContinuity(
				m_mapperRouteBinding, routeBinding) !=
			natmap::RouteBindingContinuity::Stable)
			return DisableMappedPlanes(
				natmap::ReasonCode::InterfaceChanged);
		natmap::PortLease tcpRenewal = m_tcpLease.lease();
		tcpRenewal.mapper = mapper;
		tcpRenewal.gateway = gateway;
		tcpRenewal.local = localTcp;
		tcpRenewal.public_endpoint = publicTcp;
		tcpRenewal.granted_external_port = nExternalTcpPort;
		tcpRenewal.lifetime_seconds = nLifetimeSeconds;
		tcpRenewal.mapper_epoch = nMapperEpoch;
		natmap::LeaseController tcpLease = m_tcpLease;
		bool renewed = tcpLease.AcceptRenewal(tcpRenewal, now);
		if (renewed && tcpLease.LastRenewalObservedEpochReset())
			renewed = false;
		natmap::LeaseController udpLease = m_udpLease;
		natmap::NatChainTransaction tcpChain = m_tcpChain;
		natmap::NatChainTransaction udpChain = m_udpChain;
		if (renewed)
			renewed = tcpChain.layer_count() != 0 && tcpChain.AcceptRenewal(
				tcpChain.layer_count() - 1, tcpRenewal, now);
		if (renewed && nLocalUdpPort != 0) {
			if (!udpLease.HasLease())
				renewed = false;
			else {
				natmap::PortLease udpRenewal = udpLease.lease();
				udpRenewal.mapper = mapper;
				udpRenewal.gateway = gateway;
				udpRenewal.local = localUdp;
				udpRenewal.public_endpoint = publicUdp;
				udpRenewal.granted_external_port = nExternalUdpPort;
				udpRenewal.lifetime_seconds = nLifetimeSeconds;
				udpRenewal.mapper_epoch = nMapperEpoch;
				renewed = udpLease.AcceptRenewal(udpRenewal, now);
				if (renewed
					&& udpLease.LastRenewalObservedEpochReset())
					renewed = false;
				if (renewed)
					renewed = udpChain.layer_count() != 0 && udpChain.AcceptRenewal(
						udpChain.layer_count() - 1, udpRenewal, now);
			}
		}
		if (renewed) {
			m_tcpLease = tcpLease;
			m_tcpChain = tcpChain;
			m_snapshot.ed2k_tcp_v4.lease = tcpLease.lease();
			if (nLocalUdpPort != 0) {
				m_udpLease = udpLease;
				m_udpChain = udpChain;
				m_snapshot.kad_udp_v4.lease = udpLease.lease();
			}
			m_mapperTopologyIdentity = candidateIdentity;
			m_mapperRouteBinding = routeBinding;
			m_pcpCpeResult = natmap::MapperResultData{};
			return true;
		}
		// A changed endpoint is a new topology generation, never a silent
		// renewal of the identity currently visible to servers and peers.
	}

	uint64 generation = generationDecision.generation;
	if (generationDecision.disposition
			== natmap::TopologyGenerationDisposition::Keep) {
		generation = m_snapshot.topology_generation + 1;
		if (generation == 0) {
			FailClosedAtGenerationLimit(
				natmap::ReasonCode::StaleGeneration);
			return true;
		}
	}
	natmap::PlaneSnapshot tcpPlane = completesNetworkChange
		? natmap::PlaneSnapshot{}
		: m_snapshot.ed2k_tcp_v4;
	natmap::PlaneSnapshot udpPlane = completesNetworkChange
		? natmap::PlaneSnapshot{}
		: m_snapshot.kad_udp_v4;
	const bool tcpOk = BuildMappedPlane(tcpPlane, mapper,
		natmap::Transport::Tcp, gateway, localTcp, publicTcp,
		nLifetimeSeconds, nMapperEpoch, generation);
	bool udpOk = true;
	if (nLocalUdpPort != 0) {
		udpOk = nExternalUdpPort != 0 && BuildMappedPlane(udpPlane,
			mapper, natmap::Transport::Udp, gateway, localUdp, publicUdp,
			nLifetimeSeconds, nMapperEpoch, generation);
	} else {
		udpPlane.local = localUdp;
		const natmap::TransitionResult disabled =
			natmap::ApplyEvent(
				udpPlane,
				natmap::StateEvent{
					natmap::EventType::Disable,
					generation});
		udpOk = disabled.disposition
			== natmap::TransitionDisposition::Applied;
		if (udpOk)
			udpPlane = disabled.snapshot;
	}
	if (!tcpOk || !udpOk)
		return false;

	natmap::LeaseController tcpLease;
	natmap::LeaseController udpLease;
	if (!tcpLease.Activate(tcpPlane.lease, now)
		|| (nLocalUdpPort != 0 && !udpLease.Activate(udpPlane.lease, now)))
		return false;
	natmap::NatChainTransaction tcpChain = m_tcpChain;
	natmap::NatChainTransaction udpChain = m_udpChain;
	if (!tcpChain.Begin(generation, routeBinding.origin) ||
		!tcpChain.AppendLease(tcpPlane.lease, now)
		|| (nLocalUdpPort != 0 && (!udpChain.Begin(
			generation, routeBinding.origin)
			|| !udpChain.AppendLease(udpPlane.lease, now))))
		return false;
	m_snapshot.topology_generation = generation;
	m_snapshot.ed2k_tcp_v4 = tcpPlane;
	m_snapshot.kad_udp_v4 = udpPlane;
	m_nLocalTcpPort.store(
		nLocalTcpPort, std::memory_order_release);
	m_nLocalUdpPort.store(
		nLocalUdpPort, std::memory_order_release);
	m_tcpLease = tcpLease;
	m_tcpChain = tcpChain;
	if (nLocalUdpPort != 0) {
		m_udpLease = udpLease;
		m_udpChain = udpChain;
	} else {
		m_udpLease = natmap::LeaseController{};
		m_udpChain = natmap::NatChainTransaction{};
	}
	m_mapperTopologyIdentity = candidateIdentity;
	m_mapperRouteBinding = routeBinding;
	m_pcpCpeResult = natmap::MapperResultData{};
	m_nNetworkChangeRediscoveryGeneration = 0;

	switch (m_tcpChain.Evaluate()) {
	case natmap::NatChainStatus::OperatorCgnat: {
		natmap::StateEvent blocked;
		blocked.type = natmap::EventType::CgnatDetected;
		blocked.generation = generation;
		blocked.reason = natmap::ReasonCode::CgnatWithoutLease;
		m_snapshot.ed2k_tcp_v4 = natmap::ApplyEvent(
			m_snapshot.ed2k_tcp_v4, blocked).snapshot;
		m_nAdvertisedTcpPort.store(nLocalTcpPort, std::memory_order_release);
		m_nAdvertisedUdpPort.store(nLocalUdpPort, std::memory_order_release);
		m_bEnabled.store(false, std::memory_order_release);
		return true;
	}
	case natmap::NatChainStatus::NeedsAuthorizedUpstream:
	case natmap::NatChainStatus::DepthLimitReached:
	case natmap::NatChainStatus::NonPublishableEndpoint:
	case natmap::NatChainStatus::Empty:
		m_snapshot.ed2k_tcp_v4.reason = natmap::ReasonCode::NoRoute;
		m_nAdvertisedTcpPort.store(nLocalTcpPort, std::memory_order_release);
		m_nAdvertisedUdpPort.store(nLocalUdpPort, std::memory_order_release);
		m_bEnabled.store(false, std::memory_order_release);
		return true;
	case natmap::NatChainStatus::CompletePublic:
		break;
	}
	m_nAdvertisedTcpPort.store(nExternalTcpPort, std::memory_order_release);
	if (nLocalUdpPort != 0)
		m_nAdvertisedUdpPort.store(nExternalUdpPort, std::memory_order_release);
	else
		m_nAdvertisedUdpPort.store(0, std::memory_order_release);
	m_bEnabled.store(true, std::memory_order_release);

	// The candidate must be advertised in the next server login so the classic
	// callback can verify it. Green status still requires both evidence kinds.
	return true;
}
