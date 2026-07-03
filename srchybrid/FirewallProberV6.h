//this file is part of eMule
// v0.71 IPv6 Sprint 3 — Firewall probe cascade for IPv6 reachability.
//
// Per docs/IPV6_PLAN.md §8.5: an IPv6 host on a residential network is rarely
// reachable on inbound TCP "directly" — most consumer firewalls drop
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

    // Layer-aware accessors. Until the cascade settles, GetCurrentLayer
    // returns LayerUnknown. Locked: the worker thread writes the verdict
    // while the UI / webserver read it.
    ECascadeLayer GetCurrentLayer() const { CSingleLock l(&m_lock, TRUE); return m_eLayer; }
    bool          IsReachable()     const { ECascadeLayer e = GetCurrentLayer(); return e >= LayerHighID && e <= LayerHolePunch; }
    CAddress      GetDetectedV6IP() const { CSingleLock l(&m_lock, TRUE); return m_detectedIP; }
    const TCHAR*  GetLayerLabel()   const;

    // v0.71 IPv6 Sprint 6 — record our public v6 address as observed by a peer
    // via the in-band OP_PUBLICIP_ANSWER_V6 connect-back (replaces the old
    // api6.ipify.org HTTPS probe — no third party, no correlation point). Called
    // from the network thread when a CAP_FORK_IPV6_WIRE peer answers our
    // OP_PUBLICIP_REQ. First public-v6 answer wins (matches theApp.SetPublicIP);
    // non-public / non-v6 / null addresses are ignored. Egress proof only — does
    // NOT change the cascade verdict (inbound HighID is separate, later work).
    void          SetDetectedV6IP(const CAddress& addr);

    // Manual override from preferences (Sprint 9 UI exposes this).
    void SetOverrideLayer(ECascadeLayer layer);

private:
    CFirewallProberV6();
    ~CFirewallProberV6() = default;
    CFirewallProberV6(const CFirewallProberV6&) = delete;
    CFirewallProberV6& operator=(const CFirewallProberV6&) = delete;

    // Worker-thread entry: runs the cascade and publishes the verdict.
    static UINT AFX_CDECL ProbeThreadProc(LPVOID pParam);
    void RunCascade();

    // Sprint 3 stubs — return early with Unreachable. Sprints 5/6/9 fill in.
    bool TryHighID();
    bool TryPCP();
    bool TryIGDv2();
    bool TryKeepalive();
    bool TryHolePunch();
    bool TryBuddyRelay();

    mutable CCriticalSection m_lock; // guards m_eLayer + m_detectedIP
    ECascadeLayer m_eLayer;
    ECascadeLayer m_eOverrideLayer;
    CAddress      m_detectedIP;
    volatile LONG m_lProbeStarted;   // InterlockedExchange re-entry guard
    DWORD         m_dwLastProbeTick;
};
