#pragma once

#include "natmap/natmap_types.h"
#include "natmap/natmap_state.h"
#include "natmap/natmap_policy.h"
#include "natmap/natmap_chain.h"
#include "natmap/mapper_result.h"
#include "natmap/legacy_mapper_projection.h"
#include "natmap/network_change.h"
#include "natmap/pcp_upstream_policy.h"
#include "natmap/mapping_result_mailbox.h"
#include "natmap/direct_route_selection.h"
#include "natmap/mapped_candidate_adapter.h"
#include <atomic>
#include <mutex>
#include <string>

// Main-thread owner for direct-reachability state. D1 is deliberately
// default-OFF: advertised ports remain equal to listener ports until D2
// produces a verified mapping candidate.
class CDirectReachabilityManager
{
public:
	CDirectReachabilityManager();

	void Initialize(uint16 nLocalTcpPort, uint16 nLocalUdpPort);
	void GetStatusJson(CStringA& json) const;
	bool IsEnabled() const noexcept { return m_bEnabled.load(std::memory_order_acquire); }

	uint16 GetLocalTcpPort() const;
	uint16 GetLocalUdpPort() const;
	uint16 GetAdvertisedTcpPort() const;
	uint16 GetAdvertisedUdpPort() const;
	uint16 GetAdvertisedV6TcpPort() const;
	uint16 GetAdvertisedV6UdpPort() const;
	bool BeginEd2kVerification(natmap::VerificationAttempt& attempt);
	bool BeginDirectV4Verification(
		uint32 nSocketLocalIP, uint64 nCapturedGeneration,
		natmap::VerificationAttempt& attempt);
	bool ObserveServerIdChange(
		bool bHighId, const natmap::VerificationAttempt& attempt);
	bool ObserveInboundTcpAccept(
		const natmap::VerificationAttempt& attempt);
	bool ObserveDirectV4ServerState(
		bool bHighId, uint32 nPublicIP,
		const natmap::VerificationAttempt& attempt);
	bool HasVerifiedEd2kReachability() const;
	uint64 GetTopologyGeneration() const;
	bool BeginMappingAttempt();
	natmap::UpstreamGatewayCandidates GetUpstreamGatewayCandidates(
		const natmap::UpstreamDiscoveryInput& authorizedEvidence) const;
	bool ObserveMapperResult(const natmap::MapperResult& result,
		const natmap::RouteBindingIdentity& routeBinding);
	bool RejectMapperResult(uint64 nExpectedGeneration);
	// MX03 typed bridge. It consumes only an already-authorized, already
	// completed upstream PCP result and keeps the legacy planes withdrawn until
	// the normal proof path validates the candidate. It sends no discovery or
	// PCP traffic and never treats the local CPE MAP as global proof.
	natmap::PcpUpstreamDecision ObservePcpUpstreamBundle(
		const natmap::PcpUpstreamResultBundle& bundle,
		const natmap::RouteBindingIdentity& lanRouteBinding);
	// Correlated terminal PCP-CPE result for the special case where TCP was
	// mapped behind RFC1918 but no UDP listener exists.  It withdraws with the
	// explicit chain-incomplete reason, never as a lease expiry.
	bool ObservePcpCpeAtomicityFailure(
		const natmap::MapperResult& result,
		const natmap::RouteBindingIdentity& routeBinding);
	bool ObserveMapperEpochReset();
	bool DisableMappingsByPreference();
	bool ObserveNetworkRouteChange(
		natmap::NetworkChangeTransition* transition = NULL);
	// Consumes an expiry already established by the mapper's monotonic
	// scheduler. The scheduler is authoritative because it is armed before
	// this projection receives the successful mapper result.
	bool ObserveFiniteMappingExpiry();
	// Consumes positive evidence that a permanent mapping disappeared.
	// Unlike finite expiry, this is intentionally independent of lease
	// lifetime because health probes are authoritative for permanent leases.
	bool ObserveMappingLoss();
	bool ShutdownMappedCandidates();
	natmap::DirectRouteSelection SelectPreferredRoute(
		const natmap::CandidateObservation& directV6,
		bool bIPv6Enabled, bool bMappingsEnabled,
		bool bPeerSupportsIPv6, uint32 nPublishedV4,
		uint16 nPublishedTcpPort) const;

	const natmap::ReachabilitySnapshot& GetSnapshot() const;
	const natmap::MappedCandidateSnapshot&
		GetMappedCandidateSnapshot() const;

private:
	struct StatusCacheRefreshGuard {
		CDirectReachabilityManager& manager;
		~StatusCacheRefreshGuard() noexcept { manager.UpdateStatusCache(); }
	};
	void UpdateStatusCache() noexcept;
	bool ObserveMappedPorts(natmap::MapperKind mapper,
		natmap::MapperSource mapperSource, uint32 nExternalIP,
		uint16 nLocalTcpPort, uint16 nExternalTcpPort,
		uint16 nLocalUdpPort, uint16 nExternalUdpPort,
		uint32 nLifetimeSeconds, uint32 nMapperEpoch,
		const natmap::Endpoint& gateway, uint64 resultGeneration,
		bool bMapperEpochReset, bool bRefresh,
		bool bForceGenerationAdvance,
		const natmap::RouteBindingIdentity& routeBinding);
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
	bool DisableMappedPlanes(natmap::ReasonCode reason);
	bool PromoteEd2kIfEvidenceComplete();
	bool PromoteDirectV4IfEvidenceComplete();
	bool IsCurrentDirectV4Attempt(
		const natmap::VerificationAttempt& attempt) const;
	static uint64 MonotonicMilliseconds();

	DWORD m_dwOwnerThreadId;
	std::atomic<bool> m_bEnabled;
	std::atomic<uint16> m_nLocalTcpPort;
	std::atomic<uint16> m_nLocalUdpPort;
	std::atomic<uint16> m_nAdvertisedTcpPort;
	std::atomic<uint16> m_nAdvertisedUdpPort;
	uint64 m_nNextVerificationAttemptId;
	natmap::LeaseController m_tcpLease;
	natmap::LeaseController m_udpLease;
	natmap::NatChainTransaction m_tcpChain;
	natmap::NatChainTransaction m_udpChain;
	natmap::RouteBindingIdentity m_mapperRouteBinding;
	natmap::MapperTopologyIdentity m_mapperTopologyIdentity;
	natmap::MapperResultData m_pcpCpeResult;
	natmap::CandidateObservation m_directV4Observation;
	natmap::VerificationAttempt m_directV4Attempt;
	natmap::Evidence m_directV4ServerEvidence;
	natmap::Evidence m_directV4InboundEvidence;
	uint64 m_nNetworkChangeRediscoveryGeneration;
	natmap::MappedCandidatePublisher m_mappedCandidates;
	natmap::ReachabilitySnapshot m_snapshot;
	mutable std::mutex m_cacheMutex;
	std::string m_statusJson;
};
