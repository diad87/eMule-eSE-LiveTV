//this file is part of eMule
// v0.71 IPv6 Sprint 3 — Firewall probe skeleton. See FirewallProberV6.h.
#include "stdafx.h"
#include "FirewallProberV6.h"
#include "LiveDebugLog.h"
#include "Preferences.h"
#include "emule.h"          // theApp.IsClosing() — shutdown guard for the worker
#include "OtherFunctions.h" // DbgSetThreadName
#include "Opcodes.h"
#include "NodeIdentity.h"
#include "ClientUDPSocket.h"
#include "kademlia/kademlia/Kademlia.h"
#include "kademlia/kademlia/Prefs.h"
#include <iphlpapi.h>

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

// v0.71 IPv6 Sprint 6 — runtime fork capability bits OR-ed into every
// CT_FORK_CAPABILITIES emit. The prober updates this once it settles on a
// reachability layer (e.g. CAP_FORK_IPV6_DUALSTACK once HighID is confirmed).
uint32 g_uForkCapsRuntime = 0;

// v0.71 P0.3 — runtime eSE capability bits (TAG_ESE_CAPS bitmap, see
// Opcodes.h). Set in CemuleDlg startup once the privacy/Kad-v2 modules
// initialise. The Network Info panel and /api/live/privacy/status read
// this so the user can verify which privacy features are actually live.
//
// Important: a bit is set ONLY when the underlying module has been
// instantiated AND its phase-exit criteria pass. Audit 2026-05-19 found
// these bits at 0 because no code ever OR-ed them; P0 fixes that for the
// modules already wired (F1 sharding RX, F3 subscriber pin, F2 sealed
// records / subscriptions store). Bits for features that are still
// skeleton (cover traffic, tunneling) stay at 0 until F5 P3 wires the
// actual TCP send path.
uint32 g_uEseCapsRuntime = 0;

void RefreshEseV9PreviewCaps()
{
    const LONG previewMask = static_cast<LONG>(
        ESE_CAP_TUNNEL_BULK | ESE_CAP_REACH_V2 | ESE_CAP_TUNNEL_AUTH |
        ESE_CAP_TUNNEL_STRICT3 | ESE_CAP_TUNNEL_SHAPED |
        ESE_CAP_KAD6 | ESE_CAP_KAD6_ECONOMY);
    volatile LONG* caps = reinterpret_cast<volatile LONG*>(&g_uEseCapsRuntime);
    ::InterlockedAnd(caps, ~previewMask);
    if (!CPreferences::GetEseV9Experimental())
        return;

    LONG enabled = static_cast<LONG>(ESE_CAP_TUNNEL_BULK | ESE_CAP_REACH_V2);
    if (eSELive::NodeIdentityIsPersistent()) {
        enabled |= static_cast<LONG>(ESE_CAP_TUNNEL_AUTH |
            ESE_CAP_TUNNEL_STRICT3 | ESE_CAP_TUNNEL_SHAPED);
    }
    ::InterlockedOr(caps, enabled);
}

CFirewallProberV6& CFirewallProberV6::Instance()
{
    static CFirewallProberV6 inst;
    return inst;
}

CFirewallProberV6::CFirewallProberV6()
    : m_eLayer(LayerUnknown)
	, m_eOverrideLayer(LayerUnknown)
	, m_lProbeStarted(0)
	, m_lDetectedV6ExternallyObserved(0)
	, m_lInboundV6Observed(0)
    , m_dwLastProbeTick(0)
{
}

void CFirewallProberV6::ProbeAsync()
{
    // Each Try*() is a stub for now; the real work lands in Sprints 5/6/9.
    // Until those land, the probe always terminates in Unreachable, which
    // is the safe default.
    if (!CPreferences::IsIPv6Enabled()) {
        CSingleLock l(&m_lock, TRUE);
        m_eLayer = LayerUnreachable;
        LIVE_LOG("NETV6", "probe skipped (IPv6 mode = off)");
        return;
    }

    if (m_eOverrideLayer != LayerUnknown) {
        {
            CSingleLock l(&m_lock, TRUE);
            m_eLayer = m_eOverrideLayer;
        }
        LIVE_LOG("NETV6", "probe overridden to layer %s", GetLayerLabel());
        return;
    }

    if (::InterlockedExchange(&m_lProbeStarted, 1) != 0)
        return; // already in flight or done

    m_dwLastProbeTick = GetTickCount();
    LIVE_LOG("NETV6", "starting IPv6 firewall probe cascade (worker thread)");
    AfxBeginThread(ProbeThreadProc, this, THREAD_PRIORITY_BELOW_NORMAL);
}

UINT AFX_CDECL CFirewallProberV6::ProbeThreadProc(LPVOID pParam)
{
    DbgSetThreadName("FirewallProberV6");
    static_cast<CFirewallProberV6*>(pParam)->RunCascade();
    return 0;
}

void CFirewallProberV6::RunCascade()
{
    DetectLocalPublicV6();
    ECascadeLayer verdict = LayerUnreachable;
    if (TryHighID())          verdict = LayerHighID;
    else if (TryPCP())        verdict = LayerPCP;
    else if (TryIGDv2())      verdict = LayerIGDv2;
    else if (TryKeepalive())  verdict = LayerKeepalive;
    else if (TryHolePunch())  verdict = LayerHolePunch;
    else if (TryBuddyRelay()) verdict = LayerBuddyRelay;

    // Past this point we only touch our own singleton (static storage) and the
    // thread-safe live log. Re-check the inbound proof while holding the same
    // lock used by ReportInboundV6Reachable: otherwise an accept between the
    // old pre-lock check and this assignment could be overwritten as
    // Unreachable by the one-shot worker.
    {
        CSingleLock l(&m_lock, TRUE);
        if (::InterlockedCompareExchange(&m_lInboundV6Observed, 0, 0) != 0)
            verdict = LayerHighID;
        m_eLayer = verdict;
    }
    if (!theApp.IsClosing())
        LIVE_LOG("NETV6", "layer settled: %s", GetLayerLabel());
}

void CFirewallProberV6::SetOverrideLayer(ECascadeLayer layer)
{
    m_eOverrideLayer = layer;
    LIVE_LOG("NETV6", "override set to layer %d", (int)layer);
}

const TCHAR* CFirewallProberV6::GetLayerLabel() const
{
    switch (GetCurrentLayer()) {
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

// v0.71 IPv6 Sprint 6 — record our public v6 address as observed by a peer.
// See header. Thread-safe; an inbound-proven exact address always wins.
void CFirewallProberV6::SetDetectedV6IP(const CAddress& addr)
{
    // Only a genuine, public, native-v6 address is worth recording. FromSA (the
    // source of the answered CAddress) already folds v4-mapped v6 to IPv4, so a
    // CAddress::IPv6 here is native; the public-IP check rejects link-local /
    // ULA / loopback / Teredo etc. The receiver also validates, but re-check
    // here so no caller can poison the published value.
    if (addr.GetType() != CAddress::IPv6 || !addr.IsPublicIP())
        return;
    {
        CSingleLock l(&m_lock, TRUE);
        if (!m_detectedIP.IsNull())
            return;             // first validated candidate wins — ignore later peers
        m_detectedIP = addr;
    }
    if (!theApp.IsClosing())
        LIVE_LOG("NETV6", "detected public v6 = %hs (peer connect-back, egress OK, inbound unconfirmed)",
            addr.ToString().c_str());
}

bool CFirewallProberV6::CanAdvertiseModernKadSource()
{
	const bool bPunch2 = thePrefs.GetUtpHolePunchEnabled()
		&& theApp.clientudp != NULL && theApp.clientudp->IsUtpReady()
		&& Kademlia::CKademlia::IsConnected()
		&& Kademlia::CKademlia::GetUDPListener() != NULL
		&& Kademlia::CKademlia::GetPrefs()->GetInternKadPort() != 0;
	if (bPunch2)
		return true;

	CFirewallProberV6& prober = Instance();
	const CAddress address = prober.GetDetectedV6IP();
	return thePrefs.IsIPv6Enabled()
		&& address.GetType() == CAddress::IPv6 && address.IsPublicIP()
		&& prober.HasInboundV6Observation();
}

void CFirewallProberV6::DetectLocalPublicV6()
{
    // A configured bind address is authoritative and avoids selecting a
    // privacy/temporary address when the host has several global addresses.
    const CString configured(thePrefs.GetIPv6BindAddr());
    if (!configured.IsEmpty() && configured != _T("::")) {
        CAddress addr(configured, false);
        if (addr.GetType() == CAddress::IPv6 && addr.IsPublicIP()) {
            CSingleLock l(&m_lock, TRUE);
            if (m_detectedIP.IsNull())
                m_detectedIP = addr;
            return;
        }
    }

    ULONG bytes = 16 * 1024;
    std::vector<BYTE> storage(bytes);
    ULONG result = GetAdaptersAddresses(AF_INET6,
        GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
        NULL, reinterpret_cast<PIP_ADAPTER_ADDRESSES>(&storage[0]), &bytes);
    if (result == ERROR_BUFFER_OVERFLOW) {
        storage.resize(bytes);
        result = GetAdaptersAddresses(AF_INET6,
            GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
            NULL, reinterpret_cast<PIP_ADAPTER_ADDRESSES>(&storage[0]), &bytes);
    }
    if (result != NO_ERROR)
        return;

    CAddress randomSuffixFallback;
    PIP_ADAPTER_ADDRESSES adapter = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(&storage[0]);
    for (; adapter != NULL; adapter = adapter->Next) {
        if (adapter->OperStatus != IfOperStatusUp
            || adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK
            || adapter->IfType == IF_TYPE_TUNNEL)
            continue;
        for (PIP_ADAPTER_UNICAST_ADDRESS uni = adapter->FirstUnicastAddress;
            uni != NULL; uni = uni->Next)
        {
            if (uni->Address.lpSockaddr == NULL || uni->Address.lpSockaddr->sa_family != AF_INET6)
                continue;
            // Do not latch tentative, duplicate or deprecated addresses. Prefer
            // a stable suffix; RFC4941/privacy addresses (Random suffix origin)
            // rotate and are only a fallback when the interface exposes no
            // preferred stable global address.
            if (uni->DadState != IpDadStatePreferred || uni->PreferredLifetime == 0)
                continue;
            CAddress addr;
            addr.FromSA(uni->Address.lpSockaddr, uni->Address.iSockaddrLength);
            if (addr.GetType() == CAddress::IPv6 && addr.IsPublicIP()) {
                if (uni->SuffixOrigin == IpSuffixOriginRandom) {
                    if (randomSuffixFallback.IsNull())
                        randomSuffixFallback = addr;
                    continue;
                }
                {
                    CSingleLock l(&m_lock, TRUE);
                    if (!m_detectedIP.IsNull())
                        return;
                    m_detectedIP = addr;
                }
                if (!theApp.IsClosing())
                    LIVE_LOG("NETV6", "local public v6 candidate = %hs", addr.ToString().c_str());
                return;
            }
        }
    }
    if (!randomSuffixFallback.IsNull()) {
        {
            CSingleLock l(&m_lock, TRUE);
            if (!m_detectedIP.IsNull())
                return;
            m_detectedIP = randomSuffixFallback;
        }
        if (!theApp.IsClosing())
            LIVE_LOG("NETV6", "local public v6 privacy fallback = %hs",
                randomSuffixFallback.ToString().c_str());
    }
}

void CFirewallProberV6::ReportInboundV6Reachable(const CAddress& localAddress)
{
	if (localAddress.GetType() != CAddress::IPv6 || !localAddress.IsPublicIP())
		return;
    {
        CSingleLock l(&m_lock, TRUE);
		m_detectedIP = localAddress;
        m_eLayer = LayerHighID;
		// Publish the proof while holding the same lock used by SetDetectedV6IP.
		// This prevents a late advisory answer from replacing the exact local
		// destination address of the accepted native-v6 connection.
		::InterlockedExchange(&m_lInboundV6Observed, 1);
		::InterlockedExchange(&m_lDetectedV6ExternallyObserved, 1);
	}
    ::InterlockedOr(reinterpret_cast<volatile LONG*>(&g_uForkCapsRuntime),
        (LONG)CAP_FORK_IPV6_DUALSTACK);
    if (!theApp.IsClosing())
        LIVE_LOG("NETV6", "native IPv6 inbound TCP observed; direct route confirmed");
}

// ── Cascade layer stubs ──────────────────────────────────────────────────
// Each returns true if the layer establishes reachability. Sprint 3 only
// has the OS-can-make-a-v6-socket check in TryHighID; the rest are wired
// up in later sprints.

bool CFirewallProberV6::TryHighID()
{
    // Single check: can we open an AF_INET6 socket at all? (OS / no v6 stack
    // guard.) This proves nothing about reachability — HighID in eD2K parlance
    // means "peers can connect back to us unsolicited", which only a real
    // peer-initiated connect-back can confirm (later sprint work). So we always
    // return false here (egress-only).
    //
    // Our public v6 *address* is no longer detected here: the old api6.ipify.org
    // HTTPS GET was removed (third-party correlation point + violated the
    // no-third-parties constraint). m_detectedIP is now populated in-band via
    // SetDetectedV6IP() when a CAP_FORK_IPV6_WIRE peer answers our
    // OP_PUBLICIP_REQ with OP_PUBLICIP_ANSWER_V6 (the v6 analogue of the v4
    // OP_PUBLICIP_REQ/ANSWER address-observation path).
    SOCKET s = ::socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) {
        LIVE_LOG("NETV6", "TryHighID: AF_INET6 socket() failed err=%d", WSAGetLastError());
        return false;
    }
    ::closesocket(s);
    return ::InterlockedCompareExchange(&m_lInboundV6Observed, 0, 0) != 0;
}

bool CFirewallProberV6::TryPCP()        { return false; /* Sprint 6 */ }
bool CFirewallProberV6::TryIGDv2()      { return false; /* Sprint 9 */ }
bool CFirewallProberV6::TryKeepalive()  { return false; /* Sprint 5 */ }
bool CFirewallProberV6::TryHolePunch()  { return false; /* Sprint 5 */ }
bool CFirewallProberV6::TryBuddyRelay() { return false; /* Sprint 8 */ }
