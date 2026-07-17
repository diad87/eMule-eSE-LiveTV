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
#include "natmap/pcp_codec.h"
#include <bcrypt.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <ws2tcpip.h>

#pragma comment(lib, "bcrypt.lib")

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

namespace {

const uint16 kPcpPort = 5351;
const uint8 kPcpProtocolTcp = 6;
const uint8 kPcpProtocolUdp = 17;
const uint32 kPcpRequestedLifetime = 7200;

uint32 EffectivePcpLifetime(uint32 lifetime)
{
	const uint32 maximumLifetime = 24 * 60 * 60;
	return lifetime > maximumLifetime ? maximumLifetime : lifetime;
}

bool GeneratePcpNonce(std::array<uint8, 12>& nonce)
{
	if (BCryptGenRandom(NULL, nonce.data(), static_cast<ULONG>(nonce.size()),
		BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0)
		return false;
	for (size_t i = 0; i < nonce.size(); ++i)
		if (nonce[i] != 0)
			return true;
	return false;
}

bool GetDefaultGatewayV6(const CAddress& clientAddress, CAddress& gateway,
	ULONG& interfaceIndex)
{
	if (clientAddress.GetType() != CAddress::IPv6)
		return false;

	HMODULE ipHelper = GetModuleHandleW(L"iphlpapi.dll");
	if (ipHelper == NULL)
		ipHelper = LoadLibraryW(L"iphlpapi.dll");
	if (ipHelper == NULL)
		return false;

	typedef NETIO_STATUS (WINAPI *GetBestRoute2Fn)(
		NET_LUID*, NET_IFINDEX, const SOCKADDR_INET*, const SOCKADDR_INET*,
		ULONG, PMIB_IPFORWARD_ROW2, SOCKADDR_INET*);
	GetBestRoute2Fn getBestRoute2 = reinterpret_cast<GetBestRoute2Fn>(
		GetProcAddress(ipHelper, "GetBestRoute2"));
	if (getBestRoute2 == NULL)
		return false;

	SOCKADDR_INET source;
	memset(&source, 0, sizeof(source));
	source.Ipv6.sin6_family = AF_INET6;
	memcpy(&source.Ipv6.sin6_addr, clientAddress.Data(), 16);

	SOCKADDR_INET destination;
	memset(&destination, 0, sizeof(destination));
	destination.Ipv6.sin6_family = AF_INET6;
	// This is only a routing-table lookup; no packet is sent to this address.
	// Avoid InetPton because eMule still targets Windows versions whose SDK
	// declarations do not expose it.
	const uint8 routeProbe[16] = {
		0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0x88
	};
	memcpy(&destination.Ipv6.sin6_addr, routeProbe, sizeof(routeProbe));

	MIB_IPFORWARD_ROW2 route;
	SOCKADDR_INET bestSource;
	memset(&route, 0, sizeof(route));
	memset(&bestSource, 0, sizeof(bestSource));
	if (getBestRoute2(NULL, 0, &source, &destination, 0, &route,
		&bestSource) != NO_ERROR
		|| route.NextHop.si_family != AF_INET6
		|| route.InterfaceIndex == 0)
		return false;

	const IN6_ADDR& nextHop = route.NextHop.Ipv6.sin6_addr;
	static const IN6_ADDR unspecified = IN6ADDR_ANY_INIT;
	if (memcmp(&nextHop, &unspecified, sizeof(nextHop)) == 0)
		return false;

	gateway = CAddress(reinterpret_cast<const byte*>(&nextHop));
	if (gateway.GetType() != CAddress::IPv6 || gateway.IsNull())
		return false;
	interfaceIndex = route.InterfaceIndex;
	return true;
}

bool ExchangePcpMapV6(const CAddress& gateway, ULONG interfaceIndex,
	const CAddress& clientAddress, uint16 internalPort,
	uint16 suggestedExternalPort, const CAddress& suggestedExternalIP,
	uint8 protocol, uint32 lifetime, const std::array<uint8, 12>& nonce,
	natmap::PcpMapResponse& response, bool fastDelete)
{
	if (gateway.GetType() != CAddress::IPv6 || gateway.IsNull()
		|| clientAddress.GetType() != CAddress::IPv6
		|| clientAddress.IsNull() || interfaceIndex == 0
		|| internalPort == 0 || (protocol != kPcpProtocolTcp
			&& protocol != kPcpProtocolUdp))
		return false;

	natmap::PcpMapRequest request;
	request.lifetime_seconds = lifetime;
	memcpy(request.client_ip.data(), clientAddress.Data(),
		request.client_ip.size());
	request.nonce = nonce;
	request.protocol = protocol;
	request.internal_port = internalPort;
	request.suggested_external_port = suggestedExternalPort;
	if (suggestedExternalIP.GetType() == CAddress::IPv6)
		memcpy(request.suggested_external_ip.data(),
			suggestedExternalIP.Data(), request.suggested_external_ip.size());

	uint8 packet[natmap::kPcpMaximumMessageSize];
	const size_t packetSize = natmap::EncodePcpMapRequest(request, packet,
		sizeof(packet));
	if (packetSize == 0)
		return false;

	SOCKET sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	if (sock == INVALID_SOCKET)
		return false;

	sockaddr_in6 local;
	memset(&local, 0, sizeof(local));
	local.sin6_family = AF_INET6;
	memcpy(&local.sin6_addr, clientAddress.Data(), 16);
	if (bind(sock, reinterpret_cast<sockaddr*>(&local), sizeof(local)) != 0) {
		LIVE_LOG("NETV6", "PCP-v6 bind failed err=%d", WSAGetLastError());
		closesocket(sock);
		return false;
	}

	sockaddr_in6 destinationAddress;
	memset(&destinationAddress, 0, sizeof(destinationAddress));
	destinationAddress.sin6_family = AF_INET6;
	destinationAddress.sin6_port = htons(kPcpPort);
	destinationAddress.sin6_scope_id = interfaceIndex;
	memcpy(&destinationAddress.sin6_addr, gateway.Data(), 16);

	const DWORD normalTimeouts[] = { 700, 1400, 2800 };
	const size_t attemptCount = fastDelete ? 1 : _countof(normalTimeouts);
	for (size_t attempt = 0; attempt < attemptCount; ++attempt) {
		if (!fastDelete && theApp.IsClosing())
			break;
		if (sendto(sock, reinterpret_cast<const char*>(packet),
			static_cast<int>(packetSize), 0,
			reinterpret_cast<sockaddr*>(&destinationAddress),
			sizeof(destinationAddress)) != static_cast<int>(packetSize))
			continue;

		const DWORD waitTime = fastDelete ? 150 : normalTimeouts[attempt];
		const DWORD started = GetTickCount();
		while (fastDelete || !theApp.IsClosing()) {
			const DWORD elapsed = GetTickCount() - started;
			if (elapsed >= waitTime)
				break;
			const DWORD remaining = waitTime - elapsed;
			fd_set readSet;
			FD_ZERO(&readSet);
			FD_SET(sock, &readSet);
			timeval timeout;
			timeout.tv_sec = remaining / 1000;
			timeout.tv_usec = (remaining % 1000) * 1000;
			if (select(0, &readSet, NULL, NULL, &timeout) <= 0)
				break;

			uint8 raw[natmap::kPcpMaximumMessageSize + 1];
			sockaddr_in6 sourceAddress;
			memset(&sourceAddress, 0, sizeof(sourceAddress));
			int sourceLength = sizeof(sourceAddress);
			const int received = recvfrom(sock,
				reinterpret_cast<char*>(raw), sizeof(raw), 0,
				reinterpret_cast<sockaddr*>(&sourceAddress), &sourceLength);
			if (received <= 0 || sourceAddress.sin6_family != AF_INET6
				|| sourceAddress.sin6_port != htons(kPcpPort)
				|| memcmp(&sourceAddress.sin6_addr, gateway.Data(), 16) != 0)
				continue;

			natmap::PcpMapResponse candidate;
			const natmap::PcpDecodeStatus status =
				natmap::DecodePcpMapResponse(raw,
					static_cast<size_t>(received), request, candidate);
			if (status != natmap::PcpDecodeStatus::Ok) {
				LIVE_LOG("NETV6", "PCP-v6 ignored invalid response status=%u",
					static_cast<unsigned>(status));
				continue;
			}
			response = candidate;
			if (candidate.result != natmap::PcpResultCode::Success) {
				closesocket(sock);
				return false;
			}
			if (lifetime == 0) {
				const bool deleted = candidate.lifetime_seconds == 0;
				closesocket(sock);
				return deleted;
			}

			CAddress external(candidate.external_ip.data());
			const bool mapped = candidate.lifetime_seconds != 0
				&& candidate.external_port != 0
				&& external.GetType() == CAddress::IPv6
				&& external.IsPublicIP();
			if (mapped) {
				closesocket(sock);
				return true;
			}
		}
	}

	closesocket(sock);
	return false;
}

} // namespace

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
        ESE_CAP_TUNNEL_BULK | ESE_CAP_REACH_V2 | ESE_CAP_KAD_KEEPALIVE |
        ESE_CAP_TUNNEL_AUTH |
        ESE_CAP_TUNNEL_STRICT3 | ESE_CAP_TUNNEL_SHAPED |
        ESE_CAP_KAD6 | ESE_CAP_KAD6_ECONOMY | ESE_CAP_NETLAB_V1);
    volatile LONG* caps = reinterpret_cast<volatile LONG*>(&g_uEseCapsRuntime);
    ::InterlockedAnd(caps, ~previewMask);

    // NetLab is a separate beta-consent boundary, not an alias for the broad
    // v9 experimental switch. Installing the beta or supporting these code
    // paths does not advertise participation.
    if (CPreferences::IsEseNetLabActive()) {
        LONG netlab = static_cast<LONG>(ESE_CAP_NETLAB_V1 | ESE_CAP_REACH_V2);
        if (CPreferences::GetEseAutoKeepalive())
            netlab |= static_cast<LONG>(ESE_CAP_KAD_KEEPALIVE);
        ::InterlockedOr(caps, netlab);
    }

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
	, m_lPcpOperationActive(0)
	, m_pcpIfIndex(0)
	, m_pcpRefreshFailures(0)
	, m_pcpInboundConfirmed(false)
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
	CWinThread* thread = AfxBeginThread(ProbeThreadProc, this,
		THREAD_PRIORITY_BELOW_NORMAL);
	if (thread == NULL) {
		::InterlockedExchange(&m_lProbeStarted, 0);
		LIVE_LOG("NETV6", "IPv6 firewall probe thread creation failed");
	}
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
			verdict = m_pcpInboundConfirmed && m_pcpTcp.active
				? LayerPCP : LayerHighID;
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

bool CFirewallProberV6::IsPcpMapped() const
{
	CSingleLock l(&m_lock, TRUE);
	return m_pcpTcp.active;
}

bool CFirewallProberV6::IsPcpInboundConfirmed() const
{
	CSingleLock l(&m_lock, TRUE);
	return m_pcpInboundConfirmed;
}

CAddress CFirewallProberV6::GetPcpExternalIP() const
{
	CSingleLock l(&m_lock, TRUE);
	return m_pcpTcp.externalIP;
}

uint16 CFirewallProberV6::GetPcpExternalPort() const
{
	CSingleLock l(&m_lock, TRUE);
	return m_pcpTcp.externalPort;
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
	bool pcpConfirmed = false;
    {
        CSingleLock l(&m_lock, TRUE);
		m_detectedIP = localAddress;
		pcpConfirmed = m_pcpTcp.active;
		m_pcpInboundConfirmed = pcpConfirmed;
        m_eLayer = pcpConfirmed ? LayerPCP : LayerHighID;
		// Publish the proof while holding the same lock used by SetDetectedV6IP.
		// This prevents a late advisory answer from replacing the exact local
		// destination address of the accepted native-v6 connection.
		::InterlockedExchange(&m_lInboundV6Observed, 1);
		::InterlockedExchange(&m_lDetectedV6ExternallyObserved, 1);
	}
    ::InterlockedOr(reinterpret_cast<volatile LONG*>(&g_uForkCapsRuntime),
        (LONG)CAP_FORK_IPV6_DUALSTACK);
    if (!theApp.IsClosing())
        LIVE_LOG("NETV6", pcpConfirmed
			? "native IPv6 inbound TCP observed; PCP pinhole confirmed"
			: "native IPv6 inbound TCP observed; direct route confirmed");
}

// ── Cascade layer stubs ──────────────────────────────────────────────────
// HighID consumes inbound evidence and PCP can now create IPv6 firewall
// state. The lower-priority fallbacks are still implemented incrementally.

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

bool CFirewallProberV6::TryPCP()
{
	if (!CPreferences::IsIPv6Enabled()
		|| ::InterlockedExchange(&m_lPcpOperationActive, 1) != 0)
		return false;

	CAddress clientAddress;
	{
		CSingleLock l(&m_lock, TRUE);
		clientAddress = m_detectedIP;
	}
	if (clientAddress.GetType() != CAddress::IPv6
		|| !clientAddress.IsPublicIP()) {
		::InterlockedExchange(&m_lPcpOperationActive, 0);
		LIVE_LOG("NETV6", "PCP-v6 skipped: no stable public client address");
		return false;
	}

	CAddress gateway;
	ULONG interfaceIndex = 0;
	if (!GetDefaultGatewayV6(clientAddress, gateway, interfaceIndex)) {
		::InterlockedExchange(&m_lPcpOperationActive, 0);
		LIVE_LOG("NETV6", "PCP-v6 skipped: no IPv6 default gateway");
		return false;
	}

	PcpLeaseV6 tcp;
	PcpLeaseV6 udp;
	tcp.protocol = kPcpProtocolTcp;
	tcp.internalPort = thePrefs.GetPort();
	udp.protocol = kPcpProtocolUdp;
	udp.internalPort = thePrefs.GetUDPPort();
	if (tcp.internalPort == 0 || !GeneratePcpNonce(tcp.nonce)
		|| (udp.internalPort != 0 && !GeneratePcpNonce(udp.nonce))) {
		::InterlockedExchange(&m_lPcpOperationActive, 0);
		LIVE_LOG("NETV6", "PCP-v6 skipped: invalid port or nonce generation failed");
		return false;
	}

	natmap::PcpMapResponse tcpResponse;
	const bool tcpMapped = ExchangePcpMapV6(gateway, interfaceIndex,
		clientAddress, tcp.internalPort, tcp.internalPort, CAddress(),
		tcp.protocol, kPcpRequestedLifetime, tcp.nonce, tcpResponse, false);
	if (!tcpMapped) {
		::InterlockedExchange(&m_lPcpOperationActive, 0);
		LIVE_LOG("NETV6", "PCP-v6 TCP MAP failed result=%u",
			static_cast<unsigned>(tcpResponse.result));
		return false;
	}

	natmap::PcpMapResponse udpResponse;
	bool udpMapped = true;
	if (udp.internalPort != 0) {
		udpMapped = ExchangePcpMapV6(gateway, interfaceIndex,
			clientAddress, udp.internalPort, udp.internalPort, CAddress(),
			udp.protocol, kPcpRequestedLifetime, udp.nonce, udpResponse, false);
	}
	if (!udpMapped && udp.internalPort != 0)
		LIVE_LOG("NETV6",
			"PCP-v6 UDP MAP unavailable result=%u; keeping TCP mapping",
			static_cast<unsigned>(udpResponse.result));

	const DWORD acquired = GetTickCount();
	tcp.active = true;
	tcp.externalPort = tcpResponse.external_port;
	tcp.externalIP = CAddress(tcpResponse.external_ip.data());
	tcp.lifetimeSeconds = EffectivePcpLifetime(
		tcpResponse.lifetime_seconds);
	tcp.mapperEpoch = tcpResponse.epoch;
	tcp.acquiredTick = acquired;
	if (udp.internalPort != 0) {
		udp.active = udpMapped;
		if (udpMapped) {
			udp.externalPort = udpResponse.external_port;
			udp.externalIP = CAddress(udpResponse.external_ip.data());
			udp.lifetimeSeconds = EffectivePcpLifetime(
				udpResponse.lifetime_seconds);
			udp.mapperEpoch = udpResponse.epoch;
		}
		udp.acquiredTick = acquired;
	}
	{
		CSingleLock l(&m_lock, TRUE);
		m_pcpGatewayV6 = gateway;
		m_pcpClientV6 = clientAddress;
		m_pcpIfIndex = interfaceIndex;
		m_pcpTcp = tcp;
		m_pcpUdp = udp;
		m_pcpRefreshFailures = 0;
		m_pcpInboundConfirmed = false;
	}
	::InterlockedExchange(&m_lPcpOperationActive, 0);

	LIVE_LOG("NETV6",
		"PCP-v6 MAP active gateway=%hs%%%lu TCP=%u->%u UDP=%u->%u lease=%us; inbound unconfirmed",
		gateway.ToString().c_str(), interfaceIndex, tcp.internalPort,
		tcp.externalPort, udp.internalPort, udp.externalPort,
		tcp.lifetimeSeconds);
	return ConfirmPcpInboundV6();
}

bool CFirewallProberV6::ConfirmPcpInboundV6()
{
	const bool inbound = ::InterlockedCompareExchange(
		&m_lInboundV6Observed, 0, 0) != 0;
	if (inbound) {
		CSingleLock l(&m_lock, TRUE);
		m_pcpInboundConfirmed = true;
		return true;
	}
	LIVE_LOG("NETV6",
		"PCP-v6 MAP accepted; waiting for native inbound observation before promoting reachability");
	return false;
}

void CFirewallProberV6::OnTimerTick()
{
	if (!CPreferences::IsIPv6Enabled() || theApp.IsClosing())
		return;

	bool renewalDue = false;
	const DWORD now = GetTickCount();
	{
		CSingleLock l(&m_lock, TRUE);
		if (m_pcpTcp.active && m_pcpTcp.lifetimeSeconds != 0) {
			const DWORD renewAfter = static_cast<DWORD>(
				static_cast<uint64>(m_pcpTcp.lifetimeSeconds) * 1000 / 2);
			renewalDue = now - m_pcpTcp.acquiredTick >= renewAfter;
		}
		if (!renewalDue && m_pcpUdp.active
			&& m_pcpUdp.lifetimeSeconds != 0) {
			const DWORD renewAfter = static_cast<DWORD>(
				static_cast<uint64>(m_pcpUdp.lifetimeSeconds) * 1000 / 2);
			renewalDue = now - m_pcpUdp.acquiredTick >= renewAfter;
		}
		// UDP is useful for Kad but not required to make the TCP listener
		// reachable. Retry a failed optional UDP MAP at a low rate.
		if (!renewalDue && m_pcpTcp.active && !m_pcpUdp.active
			&& m_pcpUdp.internalPort != 0)
			renewalDue = now - m_pcpUdp.acquiredTick >= MIN2MS(5);
	}
	if (!renewalDue
		|| ::InterlockedExchange(&m_lPcpOperationActive, 1) != 0)
		return;

	CWinThread* thread = AfxBeginThread(PcpRefreshThreadProc, this,
		THREAD_PRIORITY_BELOW_NORMAL);
	if (thread == NULL) {
		::InterlockedExchange(&m_lPcpOperationActive, 0);
		LIVE_LOG("NETV6", "PCP-v6 refresh thread creation failed");
	}
}

UINT AFX_CDECL CFirewallProberV6::PcpRefreshThreadProc(LPVOID pParam)
{
	DbgSetThreadName("PCP-v6 refresh");
	static_cast<CFirewallProberV6*>(pParam)->RefreshPcpMappings();
	return 0;
}

void CFirewallProberV6::RefreshPcpMappings()
{
	CAddress gateway;
	CAddress clientAddress;
	ULONG interfaceIndex = 0;
	PcpLeaseV6 tcp;
	PcpLeaseV6 udp;
	{
		CSingleLock l(&m_lock, TRUE);
		gateway = m_pcpGatewayV6;
		clientAddress = m_pcpClientV6;
		interfaceIndex = m_pcpIfIndex;
		tcp = m_pcpTcp;
		udp = m_pcpUdp;
	}

	natmap::PcpMapResponse tcpResponse;
	const bool tcpSucceeded = tcp.active && ExchangePcpMapV6(gateway, interfaceIndex,
		clientAddress, tcp.internalPort, tcp.externalPort, tcp.externalIP,
		tcp.protocol, kPcpRequestedLifetime, tcp.nonce, tcpResponse, false);
	natmap::PcpMapResponse udpResponse;
	bool udpSucceeded = true;
	if (udp.internalPort != 0) {
		udpSucceeded = ExchangePcpMapV6(gateway, interfaceIndex, clientAddress,
			udp.internalPort, udp.externalPort, udp.externalIP, udp.protocol,
			kPcpRequestedLifetime, udp.nonce, udpResponse, false);
	}
	const bool tcpEndpointChanged = tcpSucceeded
		&& (tcp.externalPort != tcpResponse.external_port
			|| memcmp(tcp.externalIP.Data(), tcpResponse.external_ip.data(),
				tcpResponse.external_ip.size()) != 0);

	bool restartProbe = false;
	{
		CSingleLock l(&m_lock, TRUE);
		// Shutdown/delete may have invalidated the snapshot while I/O ran.
		if (!m_pcpTcp.active || m_pcpTcp.nonce != tcp.nonce) {
			::InterlockedExchange(&m_lPcpOperationActive, 0);
			return;
		}
		const DWORD acquired = GetTickCount();
		if (tcpSucceeded) {
			if (tcpEndpointChanged && m_pcpInboundConfirmed) {
				m_pcpInboundConfirmed = false;
				if (m_eLayer == LayerPCP)
					m_eLayer = LayerUnreachable;
				::InterlockedExchange(&m_lInboundV6Observed, 0);
				::InterlockedAnd(
					reinterpret_cast<volatile LONG*>(&g_uForkCapsRuntime),
					~static_cast<LONG>(CAP_FORK_IPV6_DUALSTACK));
			}
			m_pcpTcp.externalPort = tcpResponse.external_port;
			m_pcpTcp.externalIP = CAddress(tcpResponse.external_ip.data());
			m_pcpTcp.lifetimeSeconds = EffectivePcpLifetime(
				tcpResponse.lifetime_seconds);
			m_pcpTcp.mapperEpoch = tcpResponse.epoch;
			m_pcpTcp.acquiredTick = acquired;
			m_pcpRefreshFailures = 0;
		} else {
			++m_pcpRefreshFailures;
			if (m_pcpRefreshFailures >= 3) {
				m_pcpTcp.active = false;
				m_pcpUdp.active = false;
				if (m_pcpInboundConfirmed) {
					m_pcpInboundConfirmed = false;
					::InterlockedExchange(&m_lInboundV6Observed, 0);
					::InterlockedAnd(
						reinterpret_cast<volatile LONG*>(&g_uForkCapsRuntime),
						~static_cast<LONG>(CAP_FORK_IPV6_DUALSTACK));
				}
				if (m_eLayer == LayerPCP)
					m_eLayer = LayerUnreachable;
				restartProbe = true;
			}
		}
		if (!restartProbe && udpSucceeded && m_pcpUdp.internalPort != 0) {
			m_pcpUdp.active = true;
			m_pcpUdp.externalPort = udpResponse.external_port;
			m_pcpUdp.externalIP = CAddress(udpResponse.external_ip.data());
			m_pcpUdp.lifetimeSeconds = EffectivePcpLifetime(
				udpResponse.lifetime_seconds);
			m_pcpUdp.mapperEpoch = udpResponse.epoch;
			m_pcpUdp.acquiredTick = acquired;
		} else if (!restartProbe && tcpSucceeded
			&& m_pcpUdp.internalPort != 0) {
			m_pcpUdp.acquiredTick = acquired;
		}
	}
	::InterlockedExchange(&m_lPcpOperationActive, 0);

	if (tcpSucceeded)
		LIVE_LOG("NETV6", tcpEndpointChanged
			? "PCP-v6 TCP endpoint changed; inbound proof invalidated"
			: (udp.internalPort == 0 || udpSucceeded
				? "PCP-v6 leases refreshed"
				: "PCP-v6 TCP refreshed; optional UDP MAP still unavailable"));
	else
		LIVE_LOG("NETV6", "PCP-v6 TCP lease refresh failed");
	if (restartProbe && !theApp.IsClosing()) {
		::InterlockedExchange(&m_lProbeStarted, 0);
		ProbeAsync();
	}
}

void CFirewallProberV6::DeletePcpMappingsBestEffort()
{
	CAddress gateway;
	CAddress clientAddress;
	ULONG interfaceIndex = 0;
	PcpLeaseV6 tcp;
	PcpLeaseV6 udp;
	{
		CSingleLock l(&m_lock, TRUE);
		if (!m_pcpTcp.active && !m_pcpUdp.active)
			return;
		gateway = m_pcpGatewayV6;
		clientAddress = m_pcpClientV6;
		interfaceIndex = m_pcpIfIndex;
		tcp = m_pcpTcp;
		udp = m_pcpUdp;
		m_pcpTcp.active = false;
		m_pcpUdp.active = false;
		if (m_pcpInboundConfirmed) {
			m_pcpInboundConfirmed = false;
			::InterlockedExchange(&m_lInboundV6Observed, 0);
			::InterlockedAnd(
				reinterpret_cast<volatile LONG*>(&g_uForkCapsRuntime),
				~static_cast<LONG>(CAP_FORK_IPV6_DUALSTACK));
		}
		if (m_eLayer == LayerPCP)
			m_eLayer = LayerUnreachable;
	}

	const bool ownsOperationGuard =
		::InterlockedCompareExchange(&m_lPcpOperationActive, 1, 0) == 0;
	natmap::PcpMapResponse ignored;
	if (tcp.active)
		ExchangePcpMapV6(gateway, interfaceIndex, clientAddress,
			tcp.internalPort, 0, CAddress(), tcp.protocol, 0, tcp.nonce,
			ignored, true);
	if (udp.active)
		ExchangePcpMapV6(gateway, interfaceIndex, clientAddress,
			udp.internalPort, 0, CAddress(), udp.protocol, 0, udp.nonce,
			ignored, true);
	if (ownsOperationGuard)
		::InterlockedExchange(&m_lPcpOperationActive, 0);
	LIVE_LOG("NETV6", "PCP-v6 delete requests sent");
}

bool CFirewallProberV6::TryIGDv2()      { return false; /* Sprint 9 */ }
bool CFirewallProberV6::TryKeepalive()  { return false; /* Sprint 5 */ }
bool CFirewallProberV6::TryHolePunch()  { return false; /* Sprint 5 */ }
bool CFirewallProberV6::TryBuddyRelay() { return false; /* Sprint 8 */ }
