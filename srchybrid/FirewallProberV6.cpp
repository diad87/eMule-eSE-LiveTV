//this file is part of eMule
// v0.71 IPv6 Sprint 3 — Firewall probe skeleton. See FirewallProberV6.h.
#include "stdafx.h"
#include "FirewallProberV6.h"
#include "LiveDebugLog.h"
#include "Preferences.h"

// v0.71 IPv6 Sprint 3 follow-up — public v6 detection via WinHTTP.
#include <winhttp.h>
#pragma comment(lib, "winhttp.lib")

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

// v0.71 IPv6 Sprint 3 follow-up — GET https://api6.ipify.org over WinHTTP
// to detect our public v6 address. api6.ipify.org accepts only v6 traffic
// so a successful response proves we have v6 connectivity to the public
// Internet. Returns IP string (e.g. "2001:db8::1") on success, empty on
// failure / timeout. Synchronous with 5 s budget — runs once at startup.
static CStringA HttpGetPublicV6(DWORD timeoutMs = 5000)
{
    CStringA result;
    HINTERNET hSession = WinHttpOpen(L"eMule eSE Live IPv6 prober",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return result;
    WinHttpSetTimeouts(hSession, (int)timeoutMs, (int)timeoutMs, (int)timeoutMs, (int)timeoutMs);

    HINTERNET hConnect = WinHttpConnect(hSession, L"api6.ipify.org",
        INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) { WinHttpCloseHandle(hSession); return result; }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", L"/",
        NULL, WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return result;
    }

    BOOL ok = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
        WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    if (ok) ok = WinHttpReceiveResponse(hRequest, NULL);
    if (ok) {
        char buf[128] = {0};
        DWORD bytesRead = 0;
        if (WinHttpReadData(hRequest, buf, (DWORD)sizeof(buf) - 1, &bytesRead) && bytesRead > 0) {
            buf[bytesRead] = 0;
            // Trim whitespace.
            char* start = buf;
            while (*start == ' ' || *start == '\t' || *start == '\r' || *start == '\n') ++start;
            char* end = start + strlen(start);
            while (end > start && (end[-1] == ' ' || end[-1] == '\t' || end[-1] == '\r' || end[-1] == '\n')) --end;
            *end = 0;
            // Only accept if contains ':' (looks like v6). api6 should never
            // return v4 but defensive: if no ':' the endpoint must have
            // misbehaved.
            if (strchr(start, ':') != NULL)
                result = start;
        }
    }
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return result;
}

bool CFirewallProberV6::TryHighID()
{
    // Two checks:
    //   1. Can we open an AF_INET6 socket at all? (OS / no v6 stack guard)
    //   2. Can we GET a v6-only HTTPS endpoint? If yes, we have v6
    //      egress AND a public v6 address. Store it for the UI panel.
    //
    // Note: HighID in eD2K parlance means "peers can connect back to us
    // unsolicited". A successful HTTPS GET proves egress only, NOT inbound
    // reachability. So we conservatively still return false here — but we
    // DO populate m_detectedIP so the UI shows the user's actual v6
    // address. A real HighID confirmation (peer-initiated connect-back)
    // is Sprint 6 work via OP_PUBLICIP_ANSWER_V6.
    SOCKET s = ::socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) {
        LIVE_LOG("NETV6", "TryHighID: AF_INET6 socket() failed err=%d", WSAGetLastError());
        return false;
    }
    ::closesocket(s);

    const CStringA v6 = HttpGetPublicV6();
    if (!v6.IsEmpty()) {
        LIVE_LOG("NETV6", "TryHighID: detected public v6 = %hs (egress OK, inbound unconfirmed)",
            (LPCSTR)v6);
        // Store in m_detectedIP via the CAddress string constructor.
        m_detectedIP.FromString(std::string((LPCSTR)v6), false);
    } else {
        LIVE_LOG("NETV6", "TryHighID: no public v6 detected (api6.ipify.org timeout or no v6 path)");
    }
    // Still return false until Sprint 6 lands peer-side connect-back proof.
    // The detected IP populates the UI regardless of the cascade verdict.
    return false;
}

bool CFirewallProberV6::TryPCP()        { return false; /* Sprint 6 */ }
bool CFirewallProberV6::TryIGDv2()      { return false; /* Sprint 9 */ }
bool CFirewallProberV6::TryKeepalive()  { return false; /* Sprint 5 */ }
bool CFirewallProberV6::TryHolePunch()  { return false; /* Sprint 5 */ }
bool CFirewallProberV6::TryBuddyRelay() { return false; /* Sprint 8 */ }
