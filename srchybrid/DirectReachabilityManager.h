#pragma once

#include "natmap/natmap_types.h"
#include "natmap/natmap_state.h"
#include "natmap/natmap_policy.h"
#include "natmap/natmap_chain.h"
#include "natmap/mapper_result.h"
#include "natmap/legacy_mapper_projection.h"
#include <atomic>

// Main-thread owner for direct-reachability state. D1 is deliberately
// default-OFF: advertised ports remain equal to listener ports until D2
// produces a verified mapping candidate.
class CDirectReachabilityManager
{
public:
	CDirectReachabilityManager();

	void Initialize(uint16 nLocalTcpPort, uint16 nLocalUdpPort);
	bool IsEnabled() const noexcept { return m_bEnabled.load(std::memory_order_acquire); }

	uint16 GetLocalTcpPort() const;
	uint16 GetLocalUdpPort() const;
	uint16 GetAdvertisedTcpPort() const;
	uint16 GetAdvertisedUdpPort() const;
	uint16 GetAdvertisedV6TcpPort() const;
	uint16 GetAdvertisedV6UdpPort() const;
	bool BeginEd2kVerification();
	bool ObserveServerIdChange(bool bHighId);
	bool ObserveInboundTcpAccept();
	bool HasVerifiedEd2kReachability() const;
	uint64 GetTopologyGeneration() const;
	natmap::UpstreamGatewayCandidates GetUpstreamGatewayCandidates() const;
	bool ObserveMapperResult(const natmap::MapperResult& result);
	bool ObserveMapperEpochReset();
	// Consumes an expiry already established by the mapper's monotonic
	// scheduler. The scheduler is authoritative because it is armed before
	// this projection receives the successful mapper result.
	bool ObserveFiniteMappingExpiry();

	const natmap::ReachabilitySnapshot& GetSnapshot() const;

private:
	bool ObserveMappedPorts(natmap::MapperKind mapper,
		natmap::MapperSource mapperSource, uint32 nExternalIP,
		uint16 nLocalTcpPort, uint16 nExternalTcpPort,
		uint16 nLocalUdpPort, uint16 nExternalUdpPort,
		uint32 nLifetimeSeconds, uint32 nMapperEpoch,
		const natmap::Endpoint& gateway, uint64 resultGeneration,
		bool bMapperEpochReset, bool bRefresh);
	void AssertMainThread() const;
	static natmap::Endpoint MakeAnyV4(uint16 nPort);
	static natmap::Endpoint MakePublicV4(uint32 nNetworkOrderIP,
		uint16 nPort, natmap::EndpointSource source);
	static bool BuildMappedPlane(natmap::PlaneSnapshot& plane,
		natmap::MapperKind mapper, natmap::Transport transport,
		const natmap::Endpoint& gateway, const natmap::Endpoint& local,
		const natmap::Endpoint& external,
		uint32 nLifetimeSeconds, uint32 nMapperEpoch, uint64 nGeneration);
	void FailClosedAtGenerationLimit(natmap::ReasonCode reason);
	static uint64 MonotonicMilliseconds();

	DWORD m_dwOwnerThreadId;
	std::atomic<bool> m_bEnabled;
	std::atomic<uint16> m_nLocalTcpPort;
	std::atomic<uint16> m_nLocalUdpPort;
	std::atomic<uint16> m_nAdvertisedTcpPort;
	std::atomic<uint16> m_nAdvertisedUdpPort;
	natmap::LeaseController m_tcpLease;
	natmap::LeaseController m_udpLease;
	natmap::NatChainTransaction m_tcpChain;
	natmap::NatChainTransaction m_udpChain;
	natmap::MapperTopologyIdentity m_mapperTopologyIdentity;
	natmap::ReachabilitySnapshot m_snapshot;
};
