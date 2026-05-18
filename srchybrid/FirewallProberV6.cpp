//this file is part of eMule
// v0.71 IPv6 Sprint 3 — Firewall probe skeleton. See FirewallProberV6.h.
#include "stdafx.h"
#include "FirewallProberV6.h"
#include "LiveDebugLog.h"
#include "Preferences.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

// v0.71 IPv6 Sprint 6 — runtime fork capability bits OR-ed into every
// CT_FORK_CAPABILITIES emit. The prober updates this once it settles on a
// reachability layer (e.g. CAP_FORK_IPV6_DUALSTACK once HighID is confirmed).
uint32 g_uForkCapsRuntime = 0;

CFirewallProberV6& CFirewallProberV6::Instance()
{
    static CFirewallProberV6 inst;
    return inst;
}

CFirewallProberV6::CFirewallProberV6()
    : m_eLayer(LayerUnknown)
    , m_eOverrideLayer(LayerUnknown)
    , m_bProbeStarted(false)
    , m_dwLastProbeTick(0)
{
}

void CFirewallProberV6::ProbeAsync()
{
    // Sprint 3 — synchronous best-effort cascade. Each Try*() is a stub for
    // now; the real work lands in Sprints 5/6/9. Until those land, the
    // probe always terminates in Unreachable, which is the safe default.
    if (!CPreferences::IsIPv6Enabled()) {
        m_eLayer = LayerUnreachable;
        LIVE_LOG("NETV6", "probe skipped (IPv6 mode = off)");
        return;
    }

    if (m_eOverrideLayer != LayerUnknown) {
        m_eLayer = m_eOverrideLayer;
        LIVE_LOG("NETV6", "probe overridden to layer %s", GetLayerLabel());
        return;
    }

    m_bProbeStarted = true;
    m_dwLastProbeTick = GetTickCount();
    LIVE_LOG("NETV6", "starting IPv6 firewall probe cascade");

    if (TryHighID())     { m_eLayer = LayerHighID;     LIVE_LOG("NETV6", "layer settled: HighID"); return; }
    if (TryPCP())        { m_eLayer = LayerPCP;        LIVE_LOG("NETV6", "layer settled: PCP"); return; }
    if (TryIGDv2())      { m_eLayer = LayerIGDv2;      LIVE_LOG("NETV6", "layer settled: IGDv2"); return; }
    if (TryKeepalive())  { m_eLayer = LayerKeepalive;  LIVE_LOG("NETV6", "layer settled: Keepalive"); return; }
    if (TryHolePunch())  { m_eLayer = LayerHolePunch;  LIVE_LOG("NETV6", "layer settled: HolePunch"); return; }
    if (TryBuddyRelay()) { m_eLayer = LayerBuddyRelay; LIVE_LOG("NETV6", "layer settled: BuddyRelay"); return; }

    m_eLayer = LayerUnreachable;
    LIVE_LOG("NETV6", "layer settled: Unreachable");
}

void CFirewallProberV6::SetOverrideLayer(ECascadeLayer layer)
{
    m_eOverrideLayer = layer;
    LIVE_LOG("NETV6", "override set to layer %d", (int)layer);
}

const TCHAR* CFirewallProberV6::GetLayerLabel() const
{
    switch (m_eLayer) {
    case LayerHighID:       return _T("HighID direct");
    case LayerPCP:          return _T("PCP pinhole");
    case LayerIGDv2:        return _T("UPnP IGDv2 pinhole");
    case LayerKeepalive:    return _T("Keepalive conntrack");
    case LayerHolePunch:    return _T("UDP hole-punch");
    case LayerBuddyRelay:   return _T("Buddy relay");
    case LayerUnreachable:  return _T("Unreachable (egress only)");
    case LayerUnknown:
    default:                return _T("Probing...");
    }
}

// ── Cascade layer stubs ──────────────────────────────────────────────────
// Each returns true if the layer establishes reachability. Sprint 3 only
// has the OS-can-make-a-v6-socket check in TryHighID; the rest are wired
// up in later sprints.

bool CFirewallProberV6::TryHighID()
{
    // Sprint 3 minimal test: can we open AF_INET6 socket at all? Without
    // a peer to connect back this is NOT a real HighID check — Sprint 6
    // adds the connect-back exchange via OP_PUBLICIP_ANSWER_V6.
    SOCKET s = ::socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) {
        LIVE_LOG("NETV6", "TryHighID: AF_INET6 socket() failed err=%d", WSAGetLastError());
        return false;
    }
    sockaddr_in6 sa = {};
    sa.sin6_family = AF_INET6;
    sa.sin6_port   = htons(thePrefs.GetPort());
    // bind to [::] (all interfaces). Note: with IPV6_V6ONLY=0 the same socket
    // accepts v4-mapped too, but we don't enable V6ONLY=0 here because Sprint 3
    // doesn't commit to dual-stack — that's Sprint 6 / S6.6.
    int rc = ::bind(s, (sockaddr*)&sa, sizeof sa);
    int err = (rc == SOCKET_ERROR) ? WSAGetLastError() : 0;
    ::closesocket(s);
    if (rc == SOCKET_ERROR) {
        LIVE_LOG("NETV6", "TryHighID: bind [::]:%u failed err=%d", (unsigned)thePrefs.GetPort(), err);
        return false;
    }
    LIVE_LOG("NETV6", "TryHighID: AF_INET6 socket OK (no peer test yet — Sprint 6)");
    // Returning false until Sprint 6 lands the peer-side connect-back: a
    // successful bind is necessary but not sufficient. Without a peer
    // confirming inbound reachability, we DO NOT claim HighID.
    return false;
}

bool CFirewallProberV6::TryPCP()        { return false; /* Sprint 6 */ }
bool CFirewallProberV6::TryIGDv2()      { return false; /* Sprint 9 */ }
bool CFirewallProberV6::TryKeepalive()  { return false; /* Sprint 5 */ }
bool CFirewallProberV6::TryHolePunch()  { return false; /* Sprint 5 */ }
bool CFirewallProberV6::TryBuddyRelay() { return false; /* Sprint 8 */ }
