#pragma once

#include "natmap/natmap_types.h"
#include "natmap/natmap_state.h"
#include "natmap/natmap_policy.h"
#include "natmap/natmap_chain.h"
#include "natmap/mapper_result_mailbox.h"
#include "natmap/network_topology_tracker.h"
#include "reach/direct_coordinator.h"
#include "reach/direct_diagnostics.h"
#include "reach/native_direct_request.h"
#include "reach/native_direct_routes.h"
#include "reach/direct_subscribers.h"
#include "reach/part_contributions.h"
#include "reach/direct_event_queue.h"
#include <atomic>
#include <memory>
#include "EseQuicHostLifecycle.h"
#include "EseQuicHostFactory.h"
#include "EseControlEnvelope.h"
#include "EseControlBootstrap.h"
#include "EseQuicRouteOwners.h"
#include "EseDirectBatchConsumer.h"
#include "reach/direct_transport.h"
#include "kad6/kad6_records.h"
#include "EseKad6Resolution.h"
#include "EseKad6LookupCooldown.h"
#include "EseClassicCallbackProof.h"
#include "EseClassicCallbackPolicy.h"
#include "EseKad6PublicContactProof.h"
#include "EseKad6PublicationAttempt.h"
#include "EseKad6DiscoveryOutcome.h"

namespace ese { namespace discovery { class Kad6ContactCache; } }
namespace ese { class QuicDownloadConsumer; }
namespace ese { namespace trust { struct Record; enum class LoadResult; } }
namespace reach { class DirectRouteDispatch; }
class CClientReqSocket;
class CDownloadQueue;
class CKnownFile;
namespace ese { namespace control { class Sessions; class ContactRefreshRequest; } }
namespace ese { namespace discovery { class ContactRefreshReplies; } }
namespace ese { namespace discovery { class Kad6IndexBootstrap; template<std::size_t> class Kad6IndexService; } }
namespace ese { namespace discovery { class PublicationAttempt; class PublicationSerial; } }
namespace ese { namespace discovery { class Kad6Resolution; class Kad6ResolutionHost; } }
namespace ese { namespace control { class InitiatorHost; } }
namespace ese { namespace control { class CookieAuthority; class ChallengeLimit; } }
// Main-thread owner for direct-reachability state. D1 is deliberately
// default-OFF: advertised ports remain equal to listener ports until D2
// produces a verified mapping candidate.
class CDirectReachabilityManager
{
	friend class CNativeDirectSelfTestAccess;
public:
	CDirectReachabilityManager();
	~CDirectReachabilityManager();
	// Factory must use this manager's pool/queue; no automatic activation.
	reach::DirectBufferPool& DirectBuffers() noexcept { return m_directBuffers; }
	bool AdoptQuicHost(std::unique_ptr<ese::QuicSessionHost>& host);
	void ShutdownQuicHost();
	void ShutdownDirectHost();
	bool AdoptDirectConsumer(std::unique_ptr<ese::DirectBatchConsumer>&);
	bool InstallQuicDownloadConsumer(); // no host activation, packets or capability advertisement
	// Explicit isolated pair lab only; exact pinned peer and IPv4 endpoint, never a global LAN switch.
	bool ConfigureIsolatedLanQuicPeer(const std::array<std::uint8_t,32>&,const ese::udp::Endpoint&,uint64 interfaceId,uint64 labDurationMs=120000);
	bool IsIsolatedLanQuicPeer(const std::array<std::uint8_t,32>&,const ese::udp::Endpoint&) const;
	bool AppendIsolatedLanQuicCandidate(reach::NativeDirectCandidateSnapshotV1&) const;
	bool HasPendingDirectUpload(uint64 lifetime) const;
	// Explicit preparation-time profile IO; never called implicitly by a tick.
	bool ConfigureDirectQuicPeerTrust(ese::QuicPeerConfig&,bool allowFirstUse);
	ese::trust::LoadResult LoadDirectQuicPeerTrust(const std::array<std::uint8_t,32>&,ese::trust::Record&) const;
	bool RegisterDirectQuicRoute(reach::DirectHandle,const reach::DirectSessionRoute&,
		const ese::NativeQuicConfig&,const ese::QuicPeerConfig&);
	bool ScheduleDirectQuicRoutes(reach::DirectHandle,const std::vector<reach::DirectSessionRoute>&);
	bool RegisterPreparedDirectLegacyRoute(reach::DirectHandle,const reach::DirectSessionRoute&,CClientReqSocket&,uint64 epoch);
	bool RegisterDirectLegacyRoute(reach::DirectHandle,const reach::DirectSessionRoute&);
	bool RecordDirectTcpObservation(CClientReqSocket&);
    bool QueueAuthenticatedProvisionalPeer(CClientReqSocket&);
	// Selection only, from the subscribed live client's owned source snapshot.
	// Host must supply independently authenticated endpoint return validations.
	reach::NativeDirectRoutes SelectDirectQuicDownloadRoutes(reach::DirectHandle,
		const reach::NativeDirectTransportPolicy&);
	reach::NativeDirectRoutes SelectDirectDownloadRoutes(reach::DirectHandle,
		const reach::NativeDirectTransportPolicy&,uint32 firstRouteId=1);
	// Explicit download negotiation; uses the DCO wire attempt, not a random
	// control-only attempt. Ready/selected0 never authorizes a data route.
	uint64 BeginDirectQuicDownloadBootstrap(reach::DirectHandle,const ese::udp::Endpoint&,uint64 deadline);
	// Explicit profile policy prepared before polling; signed selected4 ACK
	// later schedules the owned route once. No grant is manufactured here.
	bool EnableDirectQuicDownloadHandoff(reach::DirectHandle,bool allowFirstUse);
	uint64 BeginOwnedDirectQuicDownload(reach::DirectHandle,bool allowFirstUse);
	// Recovery reuses only a previously prepared pinned policy; no profile IO/TOFU.
	uint64 BeginOwnedDirectQuicRecovery(reach::DirectHandle,const ese::QuicPeerConfig&);
	enum class DirectTcpStartResult { Unavailable, Scheduled, Failed };
	DirectTcpStartResult BeginOwnedObservedTcpDownload(reach::DirectHandle);
	bool FailOwnedDirectDownload(reach::DirectHandle,reach::DirectReason);
	bool DirectQuicDownloadAvailable() const noexcept;
	bool DirectDownloadAvailable() const noexcept; // consumer/LAB gate, no UDP or QUIC grant
	reach::NativeDirectRoutes SelectOwnedDirectQuicDownloadRoutes(reach::DirectHandle);
	reach::NativeDirectRoutes SelectOwnedDirectDownloadRoutes(reach::DirectHandle,
		uint8 enabledTransports=reach::DirectTcp|reach::DirectQuic);
	std::optional<reach::DirectReason> TakeDirectTerminal(uint64 token,uint64 clientLifetime);
	void TickDirectConnections();
	bool EnableNativeQuicLab();
	uint64 BeginNativeQuicLab(const ese::NativeQuicConfig&, const ese::QuicPeerConfig&,
		reach::DirectHandle, const reach::DirectSessionRoute&);
	ese::QuicTransport* FindNativeQuicLab(uint64 owner);
	bool ReleaseNativeQuicLab(uint64 owner);
	// Explicit profile IO/import only; no tick IO or implicit session restoration.
	bool LoadDirectKad6Contacts(const wchar_t* path);
	bool SaveDirectKad6Contacts(const wchar_t* path, const wchar_t* temporary);
	bool SaveChangedDirectKad6Contacts(const wchar_t* path);
	bool ImportDirectKad6Contact(const std::array<std::uint8_t,32>& expected,
		const std::uint8_t* bytes, std::size_t size);
	// Freshness is not return verification or permission to issue discovery.
	bool FreshDirectKad6Contact(const std::array<std::uint8_t,32>& node,
		kad6::K6RouterRecord& out);
	bool BeginDirectKad6ContactRefresh(const std::array<std::uint8_t,32>& node,
		std::array<std::uint8_t,kad6::kK6RouterRecordMaxSize>& bytes, std::size_t& size);
	bool ApplyDirectKad6ContactRefresh(ese::control::ContactRefreshRequest& pending,
		const ese::control::Sessions& sessions,const ese::udp::Endpoint& endpoint,
		const std::uint8_t* bytes,std::size_t size);
	// Bootstrap adapter must verify cookie/signature/pin before ledger admission.
	ese::control::Sessions& DirectControlSessions();
	// Explicit trusted/pinned peer only. No automatic route or eD2K identity grant.
	uint64 BeginDirectControlBootstrap(const std::array<std::uint8_t,32>& expectedPeer,
		const ese::udp::Endpoint&,uint64 deadline);
	bool DirectControlBootstrapReady(uint64 owner) const noexcept;
	void CancelDirectControlBootstrap();
	uint64 ExpectDirectControlBootstrap(const std::array<std::uint8_t,32>& expectedPeer,
		const ese::udp::Endpoint&,uint64 deadline);
	void CancelDirectControlResponder(uint64 owner);
	// Explicit local consent only after a matching server route is running.
	bool AuthorizeDirectQuicControlResponder(uint64 owner,reach::DirectHandle,uint32 route);
	// Explicit pinned local consent; prepares at most one server after PROVE.
	// Supplying an advertised key is not a substitute for a trusted pin policy.
	bool AuthorizeDirectQuicControlRequest(uint64 owner,uint64 subscriber,
		const std::array<std::uint8_t,32>& trustedPin);
	uint64 RejectedDirectControlReplies() const noexcept { return m_rejectedDirectControlReplies; }
	uint64 RejectedDirectQuicPreparationPolicies() const noexcept { return m_rejectedQuicPreparationPolicies; }
	// One owned file resolution; no source/route admission from creation alone.
	bool BeginDirectKad6Resolution(const std::array<std::uint8_t,16>& file,uint64 size,uint64 maximumSize);
    bool TryBeginQueuedKad6Resolution(const std::array<std::uint8_t,16>& file,uint64 size);
    void RetireInactiveQueuedKad6Resolution(CDownloadQueue& queue);
	void CancelDirectKad6Resolution();
	bool EnableDirectKad6AutomaticGets();
	unsigned DirectKad6AutomaticGetsPrepared() const noexcept { return m_resolutionAutomaticGetsPrepared; }
	ese::QuicUdpSendStatus DirectKad6AutomaticGetLastSend() const noexcept { return m_resolutionAutomaticGetLastSend; }
	bool EnableDirectKad6AutomaticFinds();
	bool EnableDirectKad6LearnedBootstrap();
	bool PopDirectKad6Resolved(ese::discovery::Kad6Resolution::ResolvedCandidate& out);
	unsigned ConsumeDirectKad6DownloadSources(class CDownloadQueue& queue);
	unsigned SnapshotDirectKad6LocatedSources(std::array<ese::discovery::Kad6Resolution::LocatedSource,32>& out);
	uint64 PrepareDirectKad6DescriptorGet(unsigned slot,const std::array<std::uint8_t,32>& witness,
		const ese::udp::Endpoint&,const ese::discovery::Locator&,const ese::control::Datagram&);
	ese::QuicUdpSendResult SendDirectKad6DescriptorGet(uint64 owner);
	uint64 PrepareDirectKad6LocatedGet(unsigned slot,unsigned sourceIndex,const ese::control::Header&);
	uint64 PrepareDirectKad6NextLocatedGet(unsigned slot,unsigned sourceIndex,const ese::control::Header& session,
		ese::control::Header& assigned);
	bool AddDirectKad6ResolutionWitness(const std::array<std::uint8_t,32>& witness,
		const ese::udp::Endpoint&,const ese::control::Header& session,uint64 directIndexBit);
	unsigned BeginDirectKad6FindRound(std::array<ese::discovery::Kad6Lookup::Contact,2>& out);
	uint64 PrepareDirectKad6Find(unsigned slot,const std::array<std::uint8_t,32>& witness,
		const ese::udp::Endpoint&,const ese::control::Datagram&);
	ese::QuicUdpSendResult SendDirectKad6Find(uint64 owner);
	uint64 PrepareDirectKad6NextFind(unsigned slot,const std::array<std::uint8_t,32>& witness,
		const ese::udp::Endpoint&,const ese::control::Header& session,ese::control::Header& assigned);
	uint64 PrepareDirectKad6ContactRefresh(const std::array<std::uint8_t,32>& witness,
		const ese::udp::Endpoint&,const std::array<std::uint8_t,32>& requester,
		const ese::control::Datagram& get,uint64 resolutionDeadline);
	void CancelDirectKad6ContactRefresh(uint64 owner);
	ese::QuicUdpSendResult SendDirectKad6ContactRefresh(uint64 owner);
	bool ReleaseNativeQuicAttempt(reach::DirectHandle); // QUIC-only, terminal and fully drained
	bool ReleaseDirectAttempt(reach::DirectHandle,reach::DirectRouteDispatch&);
	bool AdoptNativeQuicWinner(uint64 owner, reach::DirectHandle handle);
	const ese::binding::Hello* ValidateNativeQuicDelivery(uint64 owner, reach::DirectHandle,
		uint32 route, uint64 epoch);
	bool RecordDirectPartContribution(const reach::DirectFileKey&,uint32 part,
		const reach::DirectPartContributor&,uint64 bytes);
	CClientReqSocket* ValidateLegacyDirectPartDelivery(const reach::DirectPartContributor&);
	std::vector<reach::DirectPartReceipt> SnapshotDirectPartContributions(
		const reach::DirectFileKey&,uint32 part,uint64 hashGeneration) const;
	void DiscardDirectFileContributions(const reach::DirectFileKey&) noexcept;
	void InvalidateDirectPartRange(const reach::DirectFileKey&,uint32 first,uint32 last,bool discard=false) noexcept;
	bool AcceptDirectPartVerification(const reach::DirectPartReceipt&,uint64 hashGeneration,reach::PartVerification);

	void Initialize(uint16 nLocalTcpPort, uint16 nLocalUdpPort);
	bool IsEnabled() const noexcept { return m_bEnabled.load(std::memory_order_acquire); }

	uint16 GetLocalTcpPort() const;
	uint16 GetLocalUdpPort() const;
	uint16 GetAdvertisedTcpPort() const;
	uint16 GetAdvertisedUdpPort() const;
	uint16 GetAdvertisedV6TcpPort() const;
	uint16 GetAdvertisedV6UdpPort() const;
	bool BeginEd2kVerification();
	bool ObserveServerIdChange(bool bHighId, uint64 capturedGeneration);
	bool ObserveInboundTcpAccept(uint64 capturedGeneration,uint16 observedLocalPort,uint32 peerIp=0,uint64 acceptedAt=0);
	bool HasVerifiedEd2kReachability() const;
    bool BeginClassicCallbackVerification(uint32 peerIp);
    bool ObserveClassicCallbackAck(uint32 peerIp);
    bool HasVerifiedClassicCallbackReachability() const;
    bool BeginKad6PublicContactVerification(uint32 peerIp);
    bool ObserveKad6PublicContactVerification(uint32 peerIp,uint16 testedPublicPort,uint16 receivedLocalPort);
    bool GetVerifiedKad6PublicContact(ese::discovery::PublicUdpContact& out) const;
    uint64 GetKad6ServiceCapabilities() const;
    bool TryPublishQueuedKad6File(CKnownFile& file);
    ese::classic::CallbackAvailability GetClassicCallbackAvailability() const;
    ese::discovery::DiscoveryOutcome GetKad6DiscoveryOutcome() const { return m_kad6DiscoveryStatus.State(); }
	uint64 GetTopologyGeneration() const;
	reach::DirectCoordinator& DirectConnections();
	uint64 AcquireDirectSubscriber(uint64 clientLifetime,reach::DirectConsumerKind);
	std::optional<reach::DirectSubscriber> ResolveDirectSubscriber(uint64) const;
	bool ResetConsumedDirectSubscriber(uint64 token,uint64 clientLifetime);
	bool HasDirectTransferSubscription(uint64 clientLifetime,reach::DirectHandle) const;
	std::optional<uint64> DirectTransferClientLifetime(reach::DirectHandle) const;
	// Removes registry record first; caller must deliver returned actions outside callbacks.
	reach::DirectCoordinatorBatch RetireDirectSubscriber(uint64);
	// Destructor path: invalidates tokens now, defers DCO actions to main-loop pump.
	void RetireDirectClient(uint64 clientLifetime) noexcept;
	// Main-thread admission with host CSPRNG ID; does not start a transport.
	reach::NativeDirectRequestResult RequestDirectConnection(
		const reach::NativeDirectCandidateSnapshotV1&,uint64 sourceRecordId,
		uint64 sourceEpoch,uint64 subscriber);
	// Explicit local subscriber + authenticated control context, admission only.
	// ACK0 is not data consent; caller still needs the separate transport grant.
	reach::NativeDirectRequestResult RequestSharedDirectControlAttempt(uint64 subscriber,
		const ese::control::Header&,const ese::udp::Endpoint&);
	// Capture this thread-safe queue for the worker during main-thread setup.
	reach::DirectEventQueue& DirectEvents() noexcept { return m_directEvents; }
	std::vector<reach::DirectCoordinatorBatch> PumpDirectEvents();
	natmap::UpstreamGatewayCandidates GetUpstreamGatewayCandidates() const;

	const natmap::ReachabilitySnapshot& GetSnapshot() const;
    // Thread-safe immutable diagnostic cache; never reads live MFC clients.
    std::string GetDirectStatusJson() const;
    std::string GetDirectStatusLabel() const;
	uint64 BeginMapperOperation(natmap::MapperKind,uint16 tcp,uint16 udp,bool refresh,uint64 timeoutMs);
	std::shared_ptr<natmap::MapperResultMailbox> MapperResults() const { return m_mapperResults; }
	bool TakeMapperResult(uint64 operation,natmap::OwnedMapperResult&);
	void SynchronizeLocalSocketBindings();
	bool ObserveLocalNetworkSignature(uint64 signature);
	void InvalidateLocalTopology();
	bool ConsumeMappingRediscovery();
	bool MappingRediscoveryNeeded() const;
	bool ObserveMappedPorts(natmap::MapperKind mapper, uint32 nExternalIP,
		uint16 nLocalTcpPort, uint16 nExternalTcpPort,
		uint16 nLocalUdpPort, uint16 nExternalUdpPort,
		uint32 nLifetimeSeconds, uint32 nMapperEpoch, bool bRefresh);

private:
    std::optional<ese::QuicPeerConfig> PrepareDirectQuicDownloadPolicy(reach::DirectHandle,bool,const ese::QuicPeerConfig*);
	bool EnableDirectQuicDownloadHandoffWithTrust(reach::DirectHandle,bool,const ese::QuicPeerConfig*);
	uint64 BeginOwnedDirectQuicDownloadWithTrust(reach::DirectHandle,bool,const ese::QuicPeerConfig*);
	uint64 BeginDirectBootstrap(const std::array<std::uint8_t,32>&,
		const ese::udp::Endpoint&,uint64,const reach::DirectAttemptId*,std::uint8_t,bool renewing=false);
	natmap::NetworkTopologyTracker m_localNetworkTracker;
	bool m_mappingRediscoveryNeeded=false;
	void AssertMainThread() const;
	static natmap::Endpoint MakeAnyV4(uint16 nPort);
	static natmap::Endpoint MakePublicV4(uint32 nNetworkOrderIP,
		uint16 nPort, natmap::EndpointSource source);
	static bool BuildMappedPlane(natmap::PlaneSnapshot& plane,
		natmap::MapperKind mapper, natmap::Transport transport,
		const natmap::Endpoint& local, const natmap::Endpoint& external,
		uint32 nLifetimeSeconds, uint32 nMapperEpoch, uint64 nGeneration);
	static uint64 MonotonicMilliseconds();

	DWORD m_dwOwnerThreadId;
	std::atomic<bool> m_bEnabled;
	std::atomic<uint16> m_nLocalTcpPort;
	std::atomic<uint16> m_nLocalUdpPort;
	std::atomic<uint16> m_nAdvertisedTcpPort;
	std::atomic<uint16> m_nAdvertisedUdpPort;
	natmap::LeaseController m_tcpLease;
    ese::classic::CallbackProof m_classicCallbackProof;
    uint64 m_nextClassicCallbackRecheck=0;
    ese::classic::CallbackTcpEndpoint CurrentClassicCallbackEndpoint(uint64 now) const;
    ese::discovery::PublicContactProof m_kad6PublicContactProof;
    uint64 m_nextKad6PublicContactRecheck=0;
    ese::discovery::PublicUdpContact CurrentKad6PublicContact(uint64 now) const;
	natmap::LeaseController m_udpLease;
	natmap::NatChainTransaction m_tcpChain;
	natmap::NatChainTransaction m_udpChain;
	natmap::ReachabilitySnapshot m_snapshot;
    void PublishDirectDiagnostics();
    struct DiagnosticSlot {
        uint32 generation=0;
        uint64 opaqueId=0;
        uint64 lastSeen=0;
        std::unique_ptr<reach::DirectDiagnosticPublisher> publisher;
    };
    std::array<DiagnosticSlot,reach::kDirectMaxAttempts> m_diagnosticSlots{};
    uint64 m_diagnosticId=0,m_diagnosticSequence=0;
    mutable std::mutex m_diagnosticMutex;
    std::string m_diagnosticBody,m_diagnosticJson="{\"schema_version\":2,\"snapshot_sequence\":\"0\",\"available\":false,\"sessions\":[]}";
    std::string m_diagnosticLabel;
	reach::DirectCoordinator m_directConnections;
	std::unique_ptr<reach::DirectSubscribers> m_directSubscribers;
	std::unique_ptr<reach::DirectPartContributions> m_directPartContributions;
	using PendingDirectVerifications=std::array<reach::DirectPartReceipt,reach::DirectPartContributions::Capacity>;
	std::unique_ptr<PendingDirectVerifications> m_pendingDirectVerifications;
	void PumpDirectPartVerifications();
	struct PendingSubscriberRetirement { uint64 token=0; reach::DirectHandle handle; };
	std::array<PendingSubscriberRetirement,reach::DirectSubscribers::Capacity> m_pendingSubscriberRetirements{};
	std::size_t m_pendingSubscriberRetirementCount=0;
	reach::DirectEventQueue m_directEvents;
    struct AuthenticatedProvisionalPeer {
        reach::DirectHandle handle;
        uint32 route=0;
        uint64 epoch=0;
        reach::DirectPeerKey peer;
    };
    std::array<AuthenticatedProvisionalPeer,512> m_authenticatedProvisionalPeers{};
    std::size_t m_authenticatedProvisionalPeerCount=0;
	reach::DirectBufferPool m_directBuffers;
	std::unique_ptr<ese::QuicSessionHost> m_quicHost;
	ese::QuicRouteOwners m_quicOwners;
	std::unique_ptr<ese::DirectBatchConsumer> m_directConsumer;
	ese::QuicDownloadConsumer* m_builtinQuicConsumer=nullptr; // borrowed from m_directConsumer
	ese::DirectBatchPump m_directPump;
	struct DirectTcpObservation { uint64 lifetime=0; std::array<uint8,16> userHash{}; reach::DirectCandidate candidate; };
	std::array<DirectTcpObservation,256> m_directTcpObservations{};
	void ApplyDirectTcpObservations(reach::NativeDirectCandidateSnapshotV1&,uint64 lifetime,uint64 now) const;
	bool GatherDirectTcpObservations(reach::NativeDirectCandidateSnapshotV1&,uint64 lifetime,uint64 now) const;
	bool m_topologyGenerationExhausted=false;
	std::shared_ptr<natmap::MapperResultMailbox> m_mapperResults;
	uint64 m_nextMapperOperation=0;
	std::unique_ptr<ese::discovery::Kad6ContactCache> m_kad6DirectContacts;
	bool m_kad6DirectContactsChanged = false;
	std::unique_ptr<ese::control::Sessions> m_directControlSessions;
	ese::control::PacketBudget m_directControlBudget; // survives host/session restart
    std::unique_ptr<ese::discovery::Kad6IndexBootstrap> m_kad6IndexBootstrap;
    std::unique_ptr<ese::discovery::Kad6IndexService<10000>> m_kad6IndexReceiver;
    uint64 m_kad6IndexOwner=0, m_kad6IndexTopology=0;
    void SynchronizeKad6IndexService();
    void RetireKad6IndexService();
    bool ReceiveKad6IndexService(const ese::QuicUdpRouter::PendingControl&,uint64 now);
    std::unique_ptr<ese::discovery::PublicationSerial> m_kad6PublicationSerial;
    std::array<std::uint8_t,32> m_kad6PublicationSerialNode{};
    std::array<std::uint8_t,16> m_kad6PublicationFile{};
    std::array<std::uint8_t,ese::discovery::DescriptorMax> m_kad6PublicationDescriptor{};
    std::array<std::uint8_t,173> m_kad6PublicationSource{};
    std::size_t m_kad6PublicationLength=0;
    uint64 m_kad6PublicationSize=0,m_kad6PublicationTopology=0,m_kad6PublicationUntil=0,m_nextKad6Publication=0;
    uint64 m_kad6StoredPublications=0; // diagnostic only; never an authority
    ese::discovery::DiscoveryStatus m_kad6DiscoveryStatus;
    struct PublicationWitness {
        std::array<std::uint8_t,32> node{}; ese::udp::Endpoint endpoint;
        uint64 bootstrapOwner=0,replyOwner=0,nextSend=0;
        unsigned sends=0; bool used=false,done=false,descriptorSent=false;
        std::unique_ptr<ese::discovery::PublicationAttempt> attempt;
    };
    std::array<PublicationWitness,3> m_kad6PublicationWitnesses{};
    void PumpKad6Publication();
    void CancelKad6Publication();
	std::unique_ptr<ese::discovery::ContactRefreshReplies> m_directContactRefreshReplies;
	uint64 m_nextDirectContactRefreshOwner = 0;
	uint64 m_rejectedDirectControlReplies = 0; // saturating process diagnostic
	std::unique_ptr<ese::discovery::Kad6Resolution> m_directResolution;
	std::unique_ptr<ese::discovery::Kad6ResolutionHost> m_directResolutionHost;
	uint64 m_directResolutionTopology=0;
	uint64 m_resolutionDirectIndexBit=0;
    ese::discovery::Kad6LookupCooldown m_queuedKad6Cooldown;
    std::array<std::uint8_t,16> m_queuedKad6File{};
    uint64 m_queuedKad6Size=0;
	std::array<ese::discovery::Kad6Resolution::ResolvedCandidate,4> m_directResolved{};
	unsigned m_directResolvedCount=0;
	struct ResolutionWitness { std::array<std::uint8_t,32> node{}; ese::udp::Endpoint endpoint;
		ese::control::Header session; bool used=false; };
	std::array<ResolutionWitness,16> m_resolutionWitnesses{};
	struct AutomaticGet { ese::discovery::DirectSource source; bool used=false; uint64 owner=0; };
	std::array<AutomaticGet,4> m_resolutionAutomaticGetSlots{};
	struct AutomaticGetHistory { ese::discovery::DirectSource source; std::array<std::uint8_t,32> witness{};
		bool completed=false; };
	std::array<AutomaticGetHistory,32> m_resolutionAutomaticGetHistory{};
	unsigned m_resolutionAutomaticGetHistoryCount=0;
	bool m_resolutionAutomaticGets=false;
	unsigned m_resolutionAutomaticGetsPrepared=0;
	ese::QuicUdpSendStatus m_resolutionAutomaticGetLastSend=ese::QuicUdpSendStatus::Invalid;
	void PumpDirectKad6AutomaticGets();
	bool m_resolutionAutomaticFinds=false;
	void PumpDirectKad6AutomaticFinds();
	struct LearnedWitness { std::array<std::uint8_t,32> node{}; ese::udp::Endpoint endpoint;
		uint64 owner=0; bool used=false; bool tried=false;
        bool needsRefresh=false; uint64 refreshOwner=0; uint64 refreshUntil=0; };
	std::array<LearnedWitness,16> m_resolutionLearned{};
	bool m_resolutionLearnedBootstrap=false;
	void PumpDirectKad6LearnedBootstrap();
	std::unique_ptr<ese::control::InitiatorHost> m_directBootstrap;
	ese::control::Header m_directBootstrapContext;
	ese::udp::Endpoint m_directBootstrapEndpoint;
	std::array<std::uint8_t,32> m_directBootstrapPeer{};
	uint64 m_directBootstrapOwner=0;
	uint64 m_directBootstrapIssued=0;
    uint64 m_directBootstrapDeadline=0;
	bool m_directBootstrapReady=false;
	reach::DirectHandle m_directBootstrapDownload;
	uint64 m_directBootstrapDownloadLifetime=0,m_directBootstrapDataUntil=0;
	std::optional<ese::QuicPeerConfig> m_directBootstrapDownloadPolicy;
    uint32 m_directPolicyPreparationSelfTestDelayMs=0; // explicit lab only, no user setting
	void PumpDirectQuicDownloadHandoff();
	struct RetainedControlDownload { reach::DirectHandle handle; uint64 owner=0,topology=0,lifetime=0; };
	std::array<RetainedControlDownload,256> m_retainedControlDownloads{};
	uint64 m_nextControlRetentionOwner=0;
	bool RetainDirectControlDownload(reach::DirectHandle,const std::array<std::uint8_t,32>&,
		const ese::udp::Endpoint&,const ese::control::Header&,uint64 now);
	void PruneDirectControlDownloads();
	struct ControlResponder { std::array<std::uint8_t,32> peer{}; ese::udp::Endpoint endpoint{};
		uint64 owner=0,deadline=0,topology=0;
		ese::control::PendingBootstrapChallenge challenge;
		reach::DirectHandle dataAttempt; uint32 dataRoute=0;
		uint64 dataSubscriber=0; bool dataPreparationAttempted=false; };
	bool PrepareConsentedDirectQuicResponder(ControlResponder&,const ese::control::Header&,uint64 now);
	uint64 m_rejectedQuicPreparationPolicies=0;
	std::array<ControlResponder,16> m_directResponders{};
	std::unique_ptr<ese::control::CookieAuthority> m_directCookieAuthority;
	std::unique_ptr<ese::control::ChallengeLimit> m_directChallengeLimit;
	void PumpDirectControlReplies();
	// Only normal queue admission for a currently shared file can arm an upload.
	struct UploadControlGrant {
		uint64 lifetime=0,subscriber=0,owner=0,topology=0;
		std::array<std::uint8_t,16> file{};
		std::array<std::uint8_t,32> peer{};
		ese::udp::Endpoint endpoint{};
	};
	std::array<UploadControlGrant,16> m_uploadControlGrants{};
	uint64 m_nextUploadAuthorizationAdmission=0;
	std::size_t m_uploadAuthorizationScanOffset=0;
	void PumpDirectUploadAuthorizations();
	void RetireDirectUploadAuthorization(UploadControlGrant&);
	std::optional<reach::DirectPolicy> m_isolatedLanQuicPolicy;
	std::array<std::uint8_t,32> m_isolatedLanQuicPeer{};
	ese::udp::Endpoint m_isolatedLanQuicEndpoint{};
	uint64 m_isolatedLanQuicUntil=0;
};
