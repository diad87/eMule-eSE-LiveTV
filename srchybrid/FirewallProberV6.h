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
#include <afxmt.h>   // v8.0.21 — CCriticalSection / CSingleLock for the
                     // background-thread result guard (see ProbeAsync).

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

    // Kick off the probe in the background. Idempotent. Result lands in
    // GetCurrentLayer() once the cascade settles.
    //
    // v8.0.21 — this is now ACTUALLY asynchronous: it spawns a worker
    // thread and returns immediately. Previously, despite the name, it ran
    // the whole cascade synchronously — including a 5 s WinHTTP GET — and
    // because EmuleDlg calls it from a WM_TIMER (the staggered startup
    // sequence) that froze the UI thread for 2-4 s and delayed the Connect
    // button. The result is now informational-only and arrives a few
    // seconds later without ever blocking the UI.
    void ProbeAsync();

    // Layer-aware accessors. Until the probe completes, GetCurrentLayer
    // returns LayerUnknown. m_eLayer is an int-sized enum — its read/write
    // is atomic on x86/x64, so the UI can poll it lock-free.
    ECascadeLayer GetCurrentLayer() const { return m_eLayer; }
    bool          IsReachable()     const { return m_eLayer >= LayerHighID && m_eLayer <= LayerHolePunch; }
    // v8.0.21 — defined in the .cpp: takes m_csResult so the copy can't tear
    // against the worker thread's write.
    CAddress      GetDetectedV6IP() const;
    const TCHAR*  GetLayerLabel()   const;

    // Manual override from preferences (Sprint 9 UI exposes this).
    void SetOverrideLayer(ECascadeLayer layer);

private:
    CFirewallProberV6();
    ~CFirewallProberV6() = default;
    CFirewallProberV6(const CFirewallProberV6&) = delete;
    CFirewallProberV6& operator=(const CFirewallProberV6&) = delete;

    // Sprint 3 stubs — return early with Unreachable. Sprints 5/6/9 fill in.
    bool TryHighID();
    bool TryPCP();
    bool TryIGDv2();
    bool TryKeepalive();
    bool TryHolePunch();
    bool TryBuddyRelay();

    // v8.0.21 — background-thread plumbing. ProbeAsync() spawns
    // ProbeThreadProc via AfxBeginThread; the thread calls RunCascade(),
    // which is the cascade body that used to live inline in ProbeAsync().
    static UINT AFX_CDECL ProbeThreadProc(LPVOID pParam);
    void RunCascade();

    ECascadeLayer m_eLayer;
    ECascadeLayer m_eOverrideLayer;
    CAddress      m_detectedIP;          // guarded by m_csResult
    bool          m_bProbeStarted;
    DWORD         m_dwLastProbeTick;
    // v8.0.21 — guards m_detectedIP: written by the probe worker thread,
    // read by the UI thread via GetDetectedV6IP(). mutable so the const
    // accessor can lock it.
    mutable CCriticalSection m_csResult;
};
