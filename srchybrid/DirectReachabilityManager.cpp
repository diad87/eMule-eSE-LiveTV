#include "stdafx.h"
#include "DirectReachabilityManager.h"

#include <chrono>

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
	const natmap::Endpoint& local, const natmap::Endpoint& external,
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

bool CDirectReachabilityManager::HasVerifiedEd2kReachability() const
{
	AssertMainThread();
	return m_snapshot.ed2k_tcp_v4.HasClassicHighIdEvidence();
}

bool CDirectReachabilityManager::BeginEd2kVerification()
{
	AssertMainThread();
	if (!IsEnabled())
		return false;
	const natmap::ReachabilityState state = m_snapshot.ed2k_tcp_v4.state;
	if (state == natmap::ReachabilityState::Verifying)
		return true;
	natmap::StateEvent event;
	event.type = natmap::EventType::VerificationStarted;
	event.generation = m_snapshot.ed2k_tcp_v4.generation;
	const natmap::TransitionResult result = natmap::ApplyEvent(
		m_snapshot.ed2k_tcp_v4, event);
	if (result.disposition != natmap::TransitionDisposition::Applied)
		return false;
	m_snapshot.ed2k_tcp_v4 = result.snapshot;
	return true;
}

bool CDirectReachabilityManager::ObserveServerIdChange(bool bHighId)
{
	AssertMainThread();
	if (!IsEnabled())
		return false;
	if (m_snapshot.ed2k_tcp_v4.state != natmap::ReachabilityState::Verifying
		&& !BeginEd2kVerification())
		return false;

	natmap::StateEvent event;
	event.generation = m_snapshot.ed2k_tcp_v4.generation;
	if (bHighId) {
		event.type = natmap::EventType::ServerEvidenceObserved;
		event.primary_evidence = natmap::Evidence{
			natmap::EvidenceKind::ServerHighId,
			m_snapshot.ed2k_tcp_v4.advertised, event.generation,
			MonotonicMilliseconds()};
	} else {
		event.type = natmap::EventType::VerificationFailed;
		event.reason = natmap::ReasonCode::ServerCallbackFailed;
	}
	const natmap::TransitionResult result = natmap::ApplyEvent(
		m_snapshot.ed2k_tcp_v4, event);
	if (result.disposition != natmap::TransitionDisposition::Applied)
		return false;
	m_snapshot.ed2k_tcp_v4 = result.snapshot;
	return true;
}

bool CDirectReachabilityManager::ObserveInboundTcpAccept()
{
	AssertMainThread();
	if (!IsEnabled())
		return false;
	natmap::StateEvent event;
	event.type = natmap::EventType::InboundEvidenceObserved;
	event.generation = m_snapshot.ed2k_tcp_v4.generation;
	event.inbound_evidence = natmap::Evidence{
		natmap::EvidenceKind::InboundTcpAccept,
		m_snapshot.ed2k_tcp_v4.advertised, event.generation,
		MonotonicMilliseconds()};
	const natmap::TransitionResult result = natmap::ApplyEvent(
		m_snapshot.ed2k_tcp_v4, event);
	if (result.disposition != natmap::TransitionDisposition::Applied)
		return false;
	m_snapshot.ed2k_tcp_v4 = result.snapshot;
	return true;
}

bool CDirectReachabilityManager::ObserveMappedPorts(natmap::MapperKind mapper,
	uint32 nExternalIP, uint16 nLocalTcpPort, uint16 nExternalTcpPort,
	uint16 nLocalUdpPort, uint16 nExternalUdpPort,
	uint32 nLifetimeSeconds, uint32 nMapperEpoch, bool bRefresh)
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

	if (bRefresh && m_tcpLease.HasLease()) {
		natmap::PortLease tcpRenewal = m_tcpLease.lease();
		tcpRenewal.mapper = mapper;
		tcpRenewal.local = localTcp;
		tcpRenewal.public_endpoint = publicTcp;
		tcpRenewal.granted_external_port = nExternalTcpPort;
		tcpRenewal.lifetime_seconds = nLifetimeSeconds;
		tcpRenewal.mapper_epoch = nMapperEpoch;
		natmap::LeaseController tcpLease = m_tcpLease;
		bool renewed = tcpLease.AcceptRenewal(tcpRenewal, now);
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
				udpRenewal.local = localUdp;
				udpRenewal.public_endpoint = publicUdp;
				udpRenewal.granted_external_port = nExternalUdpPort;
				udpRenewal.lifetime_seconds = nLifetimeSeconds;
				udpRenewal.mapper_epoch = nMapperEpoch;
				renewed = udpLease.AcceptRenewal(udpRenewal, now);
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
			return true;
		}
		// A changed endpoint is a new topology generation, never a silent
		// renewal of the identity currently visible to servers and peers.
	}

	const uint64 generation = m_snapshot.topology_generation + 1;
	natmap::PlaneSnapshot tcpPlane = m_snapshot.ed2k_tcp_v4;
	natmap::PlaneSnapshot udpPlane = m_snapshot.kad_udp_v4;
	const bool tcpOk = BuildMappedPlane(tcpPlane, mapper,
		natmap::Transport::Tcp, localTcp, publicTcp,
		nLifetimeSeconds, nMapperEpoch, generation);
	bool udpOk = true;
	if (nLocalUdpPort != 0) {
		udpOk = nExternalUdpPort != 0 && BuildMappedPlane(udpPlane,
			mapper, natmap::Transport::Udp, localUdp, publicUdp,
			nLifetimeSeconds, nMapperEpoch, generation);
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
	m_tcpLease = tcpLease;
	m_tcpChain = tcpChain;
	if (nLocalUdpPort != 0)
		m_udpLease = udpLease;
	if (nLocalUdpPort != 0)
		m_udpChain = udpChain;

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
	m_bEnabled.store(true, std::memory_order_release);

	// The candidate must be advertised in the next server login so the classic
	// callback can verify it. Green status still requires both evidence kinds.
	return true;
}
