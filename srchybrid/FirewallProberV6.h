//this file is part of eMule
// v0.71 IPv6 Sprint 3 — Firewall probe cascade for IPv6 reachability.
//
// An IPv6 host on a residential network is rarely reachable on inbound TCP
// "directly" — most consumer firewalls drop
// unsolicited inbound by default. To classify reachability, we cascade
// through six layers, from cheapest to most invasive:
//
//   1. HighID direct        — bind [::]:port, ask a peer to connect back
//   2. PCP (RFC 6887)       — request gateway pinhole, then HighID test
//   3. UPnP IGDv2 AddPinhole — same as PCP via legacy SOAP, Sprint 9
//   4. Keepalive            — periodic outbound UDP to a supernode keeps
//                             a stateful-firewall conntrack open so inbound
//                             from that supernode arrives
//   5. Hole-punch           — coordinated UDP rendezvous through a 3rd peer
//   6. Buddy relay          — fallback proxy via a v6-reachable peer
//   7. Unreachable          — no inbound, only outbound-initiated flows
//
// Each layer is tried with a timeout; first success wins. The probe runs
// asynchronously after CListenSocket boots and stores its verdict for the
// UI status bar (Sprint 9) and for code that needs to know our reachability
// (e.g. ANSWERSOURCES2 deciding whether to advertise a v6 endpoint).
//
// Sprint 3 ships the SKELETON: enum, single instance, async probe that
// always terminates in Unreachable. Sprint 5 implements Keepalive +
// Hole-punch. Sprint 6 implements PCP. Sprint 9 implements UPnP AddPinhole.
#pragma once

#include "eMuleAI/Address.h"
#include "natmap/direct_route_selection.h"
#include "natmap/ipv6_scope_policy.h"
#include <array>

class CFirewallProberV6 {
public:
    enum ECascadeLayer {
        LayerUnknown      = 0,  // probe hasn't started or is still running
        LayerHighID       = 1,  // direct inbound TCP/UDP works on [::]
        LayerPCP          = 2,  // PCP MAP punched a pinhole
        LayerIGDv2        = 3,  // UPnP IGDv2 AddPinhole punched a pinhole
        LayerKeepalive    = 4,  // outbound keepalive holds conntrack open
        LayerHolePunch    = 5,  // coordinated UDP rendezvous works
        LayerBuddyRelay   = 6,  // proxied through a v6 buddy
        LayerUnreachable  = 7,  // none of the above worked
    };

    static CFirewallProberV6& Instance();

    // Kick off the probe on a worker thread. Idempotent — a second call
    // while a probe is in flight (or already done) is a no-op. Result
    // lands in GetCurrentLayer() once the cascade settles. Kept on a worker
    // thread for headroom (future PCP/UPnP layers can block); the v6 address
    // itself is detected separately, in-band, via SetDetectedV6IP().
    void ProbeAsync();
	// UI/main-thread bridge: workers never query DirectReachabilityManager.
	// Route-change callers publish the one manager generation they observed.
	void PublishTopologyGeneration(uint64 topologyGeneration);
	void OnTopologyGenerationChanged(uint64 topologyGeneration);
	uint64 GetPublishedTopologyGeneration() const;

    // Layer-aware accessors. Until the cascade settles, GetCurrentLayer
    // returns LayerUnknown. Locked: the worker thread writes the verdict
    // while the UI / webserver read it.
    ECascadeLayer GetCurrentLayer() const { CSingleLock l(&m_lock, TRUE); return m_eLayer; }
    bool          IsReachable()     const { ECascadeLayer e = GetCurrentLayer(); return e >= LayerHighID && e <= LayerBuddyRelay; }
	CAddress      GetDetectedV6IP() const { CSingleLock l(&m_lock, TRUE); return m_detectedIP; }
	bool          HasExternallyObservedV6() const { return ::InterlockedCompareExchange(
		const_cast<volatile LONG*>(&m_lDetectedV6ExternallyObserved), 0, 0) != 0; }
	bool          HasInboundV6Observation() const { return ::InterlockedCompareExchange(
		const_cast<volatile LONG*>(&m_lInboundV6Observed), 0, 0) != 0; }
	natmap::CandidateObservation GetDirectRouteObservation(
		uint64 currentGeneration,
		natmap::Transport transport = natmap::Transport::Tcp) const;
	bool          IsPcpMapped() const;
	bool          IsPcpInboundConfirmed() const;
	CAddress      GetPcpExternalIP() const;
	uint16        GetPcpExternalPort() const;
	// Reads an on-link route from the OS and records a short-lived proof only
	// when local source, peer and private prefix are exact and current.
	bool ObserveSameLanRouteToPeer(const CAddress& peerAddress, uint16 peerPort,
		uint64 topologyGeneration);
	bool CanUseSameLanEndpoint(const CAddress& peerAddress, uint16 peerPort,
		uint64 topologyGeneration, ULONG* interfaceIndex = NULL) const;
    const TCHAR*  GetLayerLabel()   const;

	// True when this process can publish a Kad source that has at least one
	// non-classic route (native inbound v6 or the v2 punch path). Centralizing
	// this keeps the scheduler and CKnownFile from reintroducing HighID gates.
	static bool     CanAdvertiseModernKadSource();

    // v0.71 IPv6 Sprint 6 — record our public v6 address as observed by a peer
    // via the in-band OP_PUBLICIP_ANSWER_V6 connect-back (replaces the old
    // api6.ipify.org HTTPS probe — no third party, no correlation point). Called
    // from the network thread when a CAP_FORK_IPV6_WIRE peer answers our
    // OP_PUBLICIP_REQ. Peer observation may refine an unconfirmed local candidate;
    // non-public / non-v6 / null addresses are ignored. Egress proof only — does
    // NOT change the cascade verdict (inbound HighID is separate, later work).
    void          SetDetectedV6IP(
		const CAddress& addr, uint64 topologyGeneration);

    // Called only after the dual-stack TCP listener accepted a native public
    // IPv6 connection and obtained its exact local destination address. Accept is evidence that
    // the host firewall permits unsolicited IPv6 on the eMule port.
	void          ReportInboundV6Reachable(
		const CAddress& localAddress, uint64 topologyGeneration);

    // Manual override from preferences (Sprint 9 UI exposes this).
    void SetOverrideLayer(ECascadeLayer layer);

	// Called from the existing mapping lease timer and from graceful shutdown.
	// Both are idempotent; no work is performed unless a PCP-v6 lease exists.
	void OnTimerTick();
	// Called by the UI shutdown sequence before lease deletion. It permanently
	// fences PCP workers from publishing a late result/capability.
	void BeginShutdownFence();
	void DeletePcpMappingsBestEffort();

private:
	struct ProbeWork {
		CFirewallProberV6* prober = NULL;
		uint64 generation = 0;
		uint64 token = 0;
	};
	struct PcpLeaseV6 {
		bool active = false;
		std::array<uint8, 12> nonce{};
		uint8 protocol = 0;
		uint16 internalPort = 0;
		uint16 externalPort = 0;
		CAddress externalIP;
		uint32 lifetimeSeconds = 0;
		uint32 mapperEpoch = 0;
		uint64 acquiredTick = 0;
		uint64 ownerToken = 0;
	};

    CFirewallProberV6();
    ~CFirewallProberV6() = default;
    CFirewallProberV6(const CFirewallProberV6&) = delete;
    CFirewallProberV6& operator=(const CFirewallProberV6&) = delete;

    // Worker-thread entry: runs the cascade and publishes the verdict.
    static UINT AFX_CDECL ProbeThreadProc(LPVOID pParam);
	static UINT AFX_CDECL PcpRefreshThreadProc(LPVOID pParam);
    void RunCascade(uint64 generation, uint64 token);
    void DetectLocalPublicV6(uint64 generation, uint64 token);
	void RefreshPcpMappings();
	void ReportSameLanV6Evidence(const CAddress& localAddress,
		uint16 localPort, const CAddress& peerAddress, uint16 peerPort,
		ULONG interfaceIndex, uint8 prefixLength, uint64 topologyGeneration,
		uint64 expiresMonotonicMs);

    // Sprint 3 stubs — return early with Unreachable. Sprints 5/6/9 fill in.
    bool TryHighID();
    natmap::PcpCascadeOutcome TryPCP(uint64 generation, uint64 token);
	bool TryClaimPcpOperationOrScheduleRetry();
	bool ReleasePcpOperationAndRetry();
	void ScheduleDeferredPcpRetry();
    bool TryIGDv2();
    bool TryKeepalive();
    bool TryHolePunch();
    bool TryBuddyRelay();

    mutable CCriticalSection m_lock; // guards m_eLayer + m_detectedIP
    ECascadeLayer m_eLayer;
    ECascadeLayer m_eOverrideLayer;
	CAddress      m_detectedIP;
	uint64        m_nDetectedV6Generation;
	uint64        m_nInboundV6Generation;
	ULONG         m_nDetectedV6InterfaceIndex;
	ULONG         m_nInboundV6InterfaceIndex;
	uint64        m_nPcpV6Generation;
	uint64        m_nPublishedTopologyGeneration;
	uint64        m_nAppliedTopologyGeneration;
	uint64        m_nProbeToken;
	uint64        m_nActiveProbeToken;
	natmap::PrivateSameLanEvidence m_sameLanEvidence;
	natmap::Endpoint m_sameLanLocalEndpoint;
	volatile LONG m_lProbeStarted;   // InterlockedExchange re-entry guard
	volatile LONG m_lDetectedV6ExternallyObserved;
	volatile LONG m_lInboundV6Observed;
	volatile LONG m_lPcpOperationActive;
	volatile LONG m_lPcpRetryPending;
	volatile LONG m_lShuttingDown;
	CAddress      m_pcpGatewayV6;
	CAddress      m_pcpClientV6;
	ULONG         m_pcpIfIndex;
	PcpLeaseV6    m_pcpTcp;
	PcpLeaseV6    m_pcpUdp;
	unsigned      m_pcpRefreshFailures;
	// A PCP MAP is not an inbound accept. This records only that the exact,
	// owned pinhole is currently authorized by the v9.2 policy.
	bool          m_pcpPolicyAuthorized;
	bool          m_pcpInboundConfirmed;
    DWORD         m_dwLastProbeTick;
};
