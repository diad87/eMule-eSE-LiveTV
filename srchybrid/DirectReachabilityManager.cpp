#include "stdafx.h"
#include "DirectReachabilityManager.h"
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
	natmap::PlaneSnapshot tcp = m_snapshot.ed2k_tcp_v4;
	tcp.local = MakeAnyV4(
		m_nLocalTcpPort.load(std::memory_order_acquire));
	natmap::PlaneSnapshot udp = m_snapshot.kad_udp_v4;
	udp.local = MakeAnyV4(
		m_nLocalUdpPort.load(std::memory_order_acquire));
	m_snapshot.ed2k_tcp_v4 = natmap::ApplyEvent(
		tcp, natmap::StateEvent{
			natmap::EventType::Disable, generation,
			reason}).snapshot;
	m_snapshot.kad_udp_v4 = natmap::ApplyEvent(
		udp, natmap::StateEvent{
			natmap::EventType::Disable, generation,
			reason}).snapshot;
	m_tcpLease = natmap::LeaseController{};
	m_udpLease = natmap::LeaseController{};
	m_tcpChain = natmap::NatChainTransaction{};
	m_udpChain = natmap::NatChainTransaction{};
	m_mapperTopologyIdentity =
		natmap::MapperTopologyIdentity{};
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
	m_mapperTopologyIdentity =
		natmap::MapperTopologyIdentity{};
	m_snapshot = natmap::ReachabilitySnapshot{};
	m_snapshot.topology_generation = 1;

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

uint64 CDirectReachabilityManager::GetTopologyGeneration() const
{
	AssertMainThread();
	return m_snapshot.topology_generation;
}

natmap::UpstreamGatewayCandidates
CDirectReachabilityManager::GetUpstreamGatewayCandidates() const
{
	AssertMainThread();
	if (!m_tcpChain.NeedsUpstream())
		return natmap::UpstreamGatewayCandidates{};
	return natmap::BuildUpstreamGatewayCandidates(
		m_tcpChain.FinalEndpoint().address);
}

bool CDirectReachabilityManager::ObserveMapperResult(
	const natmap::MapperResult& result)
{
	AssertMainThread();
	natmap::LegacyMapperObservation observation;
	if (natmap::AdmitLegacyMapperObservation(
			result, m_snapshot.topology_generation, observation) !=
		natmap::LegacyMapperAdmissionStatus::Accepted)
		return false;

	uint32 externalIP = 0;
	std::memcpy(&externalIP, observation.external_address.bytes.data(),
		sizeof(externalIP));
	return ObserveMappedPorts(
		observation.mapper, observation.mapper_source, externalIP,
		observation.local_tcp_port, observation.external_tcp_port,
		observation.local_udp_port, observation.external_udp_port,
		observation.lifetime_seconds, observation.mapper_epoch,
		natmap::Endpoint{
			observation.gateway_address, 0,
			natmap::EndpointSource::LocalInterface},
		observation.topology_generation,
		observation.mapper_epoch_reset, observation.refresh);
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
	m_tcpLease = natmap::LeaseController{};
	m_udpLease = natmap::LeaseController{};
	m_tcpChain = natmap::NatChainTransaction{};
	m_udpChain = natmap::NatChainTransaction{};
	m_mapperTopologyIdentity =
		natmap::MapperTopologyIdentity{};
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

bool CDirectReachabilityManager::ObserveNetworkRouteChange()
{
	return DisableMappedPlanes(
		natmap::ReasonCode::InterfaceChanged);
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
	m_tcpLease = natmap::LeaseController{};
	m_udpLease = natmap::LeaseController{};
	m_tcpChain = natmap::NatChainTransaction{};
	m_udpChain = natmap::NatChainTransaction{};
	m_mapperTopologyIdentity =
		natmap::MapperTopologyIdentity{};
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
	m_tcpLease = natmap::LeaseController{};
	m_udpLease = natmap::LeaseController{};
	m_tcpChain = natmap::NatChainTransaction{};
	m_udpChain = natmap::NatChainTransaction{};
	m_mapperTopologyIdentity =
		natmap::MapperTopologyIdentity{};
	m_nAdvertisedTcpPort.store(
		m_nLocalTcpPort.load(std::memory_order_acquire),
		std::memory_order_release);
	m_nAdvertisedUdpPort.store(
		m_nLocalUdpPort.load(std::memory_order_acquire),
		std::memory_order_release);
	m_bEnabled.store(false, std::memory_order_release);
	return true;
}

bool CDirectReachabilityManager::HasVerifiedEd2kReachability() const
{
	AssertMainThread();
	return m_snapshot.ed2k_tcp_v4.HasClassicHighIdEvidence();
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
	m_snapshot.ed2k_tcp_v4 = result.snapshot;
	return true;
}

bool CDirectReachabilityManager::BeginEd2kVerification(
	natmap::VerificationAttempt& attempt)
{
	AssertMainThread();
	if (!IsEnabled())
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

bool CDirectReachabilityManager::ObserveInboundTcpAccept(
	const natmap::VerificationAttempt& attempt)
{
	AssertMainThread();
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
	bool bMapperEpochReset, bool bRefresh)
{
	AssertMainThread();
	if (mapper == natmap::MapperKind::None || nExternalIP == 0 ||
		nLocalTcpPort == 0 || nExternalTcpPort == 0)
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
	const natmap::TopologyGenerationDecision generationDecision =
		natmap::ResolveTopologyGeneration(
			m_snapshot.topology_generation,
			m_mapperTopologyIdentity, renewalBoundary);
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
		&& m_tcpLease.HasLease()) {
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
	natmap::PlaneSnapshot tcpPlane = m_snapshot.ed2k_tcp_v4;
	natmap::PlaneSnapshot udpPlane = m_snapshot.kad_udp_v4;
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
	if (!tcpChain.Begin(generation) || !tcpChain.AppendLease(tcpPlane.lease, now)
		|| (nLocalUdpPort != 0 && (!udpChain.Begin(generation)
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

	if (publicTcp.address.IsSharedCgnatV4()) {
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
	if (publicTcp.address.IsRfc1918V4()) {
		m_snapshot.ed2k_tcp_v4.reason = natmap::ReasonCode::NoRoute;
		m_nAdvertisedTcpPort.store(nLocalTcpPort, std::memory_order_release);
		m_nAdvertisedUdpPort.store(nLocalUdpPort, std::memory_order_release);
		m_bEnabled.store(false, std::memory_order_release);
		return true;
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
