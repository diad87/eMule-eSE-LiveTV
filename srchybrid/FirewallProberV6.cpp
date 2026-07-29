//this file is part of eMule
// v0.71 IPv6 Sprint 3 — Firewall probe skeleton. See FirewallProberV6.h.
#include "stdafx.h"
#include "FirewallProberV6.h"
#include "DirectReachabilityManager.h"
#include "natmap/ipv6_scope_policy.h"
#include "natmap/pcp_upstream_policy.h"
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
#include <limits>
#include <string>
#include <vector>

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

// RFC 6887 permits a one-second apparent regression from response ordering.
// Anything beyond it is a mapper reboot/discontinuity and old lease evidence
// must not be renewed across the boundary.
bool IsPcpEpochDiscontinuity(uint32 previous, uint32 current)
{
	return current < previous && previous - current > 1;
}

bool ArePcpPairEpochsCoherent(uint32 tcpEpoch, uint32 udpEpoch)
{
	return udpEpoch >= tcpEpoch || tcpEpoch - udpEpoch <= 1;
}

// A routable IPv6 literal is not by itself a native transport binding.  In
// particular, tunnel and loopback adapters must never become an externally
// advertised v6 route merely because Windows can route through them.
std::string NarrowAdapterText(const WCHAR* value)
{
	if (value == NULL || *value == L'\0')
		return std::string();
	const int size = WideCharToMultiByte(CP_UTF8, 0, value, -1, NULL, 0,
		NULL, NULL);
	if (size <= 1)
		return std::string();
	std::vector<char> bytes(static_cast<size_t>(size));
	if (WideCharToMultiByte(CP_UTF8, 0, value, -1, bytes.data(), size,
		NULL, NULL) != size)
		return std::string();
	return std::string(bytes.data());
}

bool IsNativeV6Interface(ULONG interfaceIndex, bool hasDefaultGateway,
	bool requireNative)
{
	if (interfaceIndex == 0)
		return false;
	ULONG bytes = 0;
	DWORD status = GetAdaptersAddresses(AF_INET6, GAA_FLAG_INCLUDE_PREFIX,
		NULL, NULL, &bytes);
	if (status != ERROR_BUFFER_OVERFLOW || bytes == 0)
		return false;
	std::vector<uint8> buffer(bytes);
	PIP_ADAPTER_ADDRESSES adapters =
		reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());
	if (GetAdaptersAddresses(AF_INET6, GAA_FLAG_INCLUDE_PREFIX, NULL,
		adapters, &bytes) != NO_ERROR)
		return false;
	for (PIP_ADAPTER_ADDRESSES adapter = adapters; adapter != NULL;
		adapter = adapter->Next) {
		if (adapter->Ipv6IfIndex != interfaceIndex)
			continue;
		if (adapter->OperStatus != IfOperStatusUp)
			return false;
		std::string description = NarrowAdapterText(adapter->Description);
		const std::string friendlyName = NarrowAdapterText(adapter->FriendlyName);
		if (!friendlyName.empty()) {
			if (!description.empty())
				description += " ";
			description += friendlyName;
		}
		const natmap::NetworkOriginEvidence originEvidence = {
			adapter->AdapterName, description.empty() ? NULL : description.c_str(),
			adapter->IfType == IF_TYPE_TUNNEL,
			adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK,
			hasDefaultGateway
		};
		const natmap::NetworkOrigin origin =
			natmap::ClassifyNetworkOrigin(originEvidence).origin;
		return requireNative ? origin == natmap::NetworkOrigin::Native
			: origin != natmap::NetworkOrigin::Overlay
				&& !originEvidence.is_tunnel && !originEvidence.is_loopback;
	}
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
	if (!IsNativeV6Interface(route.InterfaceIndex, true, true))
		return false;
	interfaceIndex = route.InterfaceIndex;
	return true;
}

uint64 MonotonicMilliseconds64()
{
	typedef ULONGLONG (WINAPI *GetTickCount64Fn)();
	static GetTickCount64Fn getTickCount64 =
		reinterpret_cast<GetTickCount64Fn>(GetProcAddress(
			GetModuleHandleW(L"kernel32.dll"), "GetTickCount64"));
	if (getTickCount64 != NULL)
		return static_cast<uint64>(getTickCount64());
	// Legacy fallback for old Windows targets: extend the 32-bit monotonic
	// tick under a lock. This function is called from UI, network and PCP
	// worker paths, so unsynchronised static wrap state would be a data race.
	static DWORD previous = 0;
	static uint64 high = 0;
	static CCriticalSection legacyTickLock;
	CSingleLock lock(&legacyTickLock, TRUE);
	const DWORD now = GetTickCount();
	if (now < previous)
		high += (static_cast<uint64>(1) << 32);
	previous = now;
	return high + now;
}

bool GetOnLinkRouteV6(const CAddress& peerAddress, CAddress& localAddress,
	ULONG& interfaceIndex, uint8& prefixLength)
{
	if (peerAddress.GetType() != CAddress::IPv6)
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
	SOCKADDR_INET destination{};
	destination.Ipv6.sin6_family = AF_INET6;
	memcpy(&destination.Ipv6.sin6_addr, peerAddress.Data(), 16);
	MIB_IPFORWARD_ROW2 route{};
	SOCKADDR_INET bestSource{};
	if (getBestRoute2(NULL, 0, NULL, &destination, 0, &route,
		&bestSource) != NO_ERROR ||
		route.NextHop.si_family != AF_INET6 ||
		route.DestinationPrefix.Prefix.si_family != AF_INET6 ||
		route.InterfaceIndex == 0 || bestSource.si_family != AF_INET6)
		return false;
	static const IN6_ADDR unspecified = IN6ADDR_ANY_INIT;
	if (memcmp(&route.NextHop.Ipv6.sin6_addr, &unspecified,
		sizeof(unspecified)) != 0)
		return false; // A gateway route is never positive SAME_LAN proof.
	localAddress = CAddress(reinterpret_cast<const byte*>(
		&bestSource.Ipv6.sin6_addr));
	if (localAddress.GetType() != CAddress::IPv6 || localAddress.IsNull())
		return false;
	// SAME_LAN is allowed on an isolated physical segment without a default
	// gateway. It is intentionally bound as Unknown below, never promoted to
	// a global Native route; known overlays/tunnels/loopback remain excluded.
	if (!IsNativeV6Interface(route.InterfaceIndex, false, false))
		return false;
	interfaceIndex = route.InterfaceIndex;
	prefixLength = route.DestinationPrefix.PrefixLength;
	return prefixLength <= 128;
}

enum class PcpMapExchangeResult {
	RequestNotSent = 0,
	RequestSentNoResponse,
	ProtocolFailure,
	Mapped,
	ZeroLifetime,
	Deleted
};

bool PcpMapResponseReceived(PcpMapExchangeResult result)
{
	return result != PcpMapExchangeResult::RequestNotSent &&
		result != PcpMapExchangeResult::RequestSentNoResponse;
}

natmap::PcpExchangeDisposition ToPcpCleanupDisposition(
	PcpMapExchangeResult result)
{
	switch (result) {
	case PcpMapExchangeResult::RequestNotSent:
		return natmap::PcpExchangeDisposition::RequestNotSent;
	case PcpMapExchangeResult::RequestSentNoResponse:
		return natmap::PcpExchangeDisposition::RequestSentNoResponse;
	case PcpMapExchangeResult::ProtocolFailure:
		return natmap::PcpExchangeDisposition::ResponseRejected;
	case PcpMapExchangeResult::Mapped:
		return natmap::PcpExchangeDisposition::Mapped;
	case PcpMapExchangeResult::ZeroLifetime:
		return natmap::PcpExchangeDisposition::ZeroLifetime;
	case PcpMapExchangeResult::Deleted:
		return natmap::PcpExchangeDisposition::Deleted;
	}
	return natmap::PcpExchangeDisposition::RequestNotSent;
}

bool PcpMapCreated(PcpMapExchangeResult result)
{
	return result == PcpMapExchangeResult::Mapped;
}

PcpMapExchangeResult ExchangePcpMapV6(const CAddress& gateway, ULONG interfaceIndex,
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
		return PcpMapExchangeResult::RequestNotSent;

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
	natmap::PcpMapRequestPolicyInput requestPolicy;
	requestPolicy.request = &request;
	const size_t packetSize = natmap::EncodePcpMapRequestForProduction(
		request, requestPolicy, packet, sizeof(packet));
	if (packetSize == 0)
		return PcpMapExchangeResult::RequestNotSent;

	SOCKET sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	if (sock == INVALID_SOCKET)
		return PcpMapExchangeResult::RequestNotSent;

	sockaddr_in6 local;
	memset(&local, 0, sizeof(local));
	local.sin6_family = AF_INET6;
	memcpy(&local.sin6_addr, clientAddress.Data(), 16);
	if (bind(sock, reinterpret_cast<sockaddr*>(&local), sizeof(local)) != 0) {
		LIVE_LOG("NETV6", "PCP-v6 bind failed err=%d", WSAGetLastError());
		closesocket(sock);
		return PcpMapExchangeResult::RequestNotSent;
	}

	sockaddr_in6 destinationAddress;
	memset(&destinationAddress, 0, sizeof(destinationAddress));
	destinationAddress.sin6_family = AF_INET6;
	destinationAddress.sin6_port = htons(kPcpPort);
	destinationAddress.sin6_scope_id = interfaceIndex;
	memcpy(&destinationAddress.sin6_addr, gateway.Data(), 16);

	const DWORD normalTimeouts[] = { 700, 1400, 2800 };
	const size_t attemptCount = fastDelete ? 1 : _countof(normalTimeouts);
	bool requestSent = false;
	for (size_t attempt = 0; attempt < attemptCount; ++attempt) {
		if (!fastDelete && theApp.IsClosing())
			break;
		if (sendto(sock, reinterpret_cast<const char*>(packet),
			static_cast<int>(packetSize), 0,
			reinterpret_cast<sockaddr*>(&destinationAddress),
			 sizeof(destinationAddress)) != static_cast<int>(packetSize))
			continue;
		requestSent = true;

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
				return PcpMapExchangeResult::ProtocolFailure;
			}
			if (lifetime == 0) {
				const bool deleted = candidate.lifetime_seconds == 0;
				closesocket(sock);
				return deleted ? PcpMapExchangeResult::Deleted
					: PcpMapExchangeResult::ProtocolFailure;
			}

			CAddress external(candidate.external_ip.data());
			const bool mapped = candidate.lifetime_seconds != 0
				&& candidate.external_port != 0
				&& external.GetType() == CAddress::IPv6
				&& external.IsPublicIP();
			if (mapped) {
				closesocket(sock);
				return PcpMapExchangeResult::Mapped;
			}
			if (candidate.lifetime_seconds == 0) {
				closesocket(sock);
				return PcpMapExchangeResult::ZeroLifetime;
			}
		}
	}

	closesocket(sock);
	return requestSent ? PcpMapExchangeResult::RequestSentNoResponse
		: PcpMapExchangeResult::RequestNotSent;
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
        ESE_CAP_KAD6 | ESE_CAP_KAD6_ECONOMY | ESE_CAP_NETLAB_V1 |
        ESE_CAP_HOLEPUNCH_RDV | ESE_CAP_LIVE_RELAY);
    volatile LONG* caps = reinterpret_cast<volatile LONG*>(&g_uEseCapsRuntime);
    ::InterlockedAnd(caps, ~previewMask);

    // NetLab is a separate beta-consent boundary, not an alias for the broad
    // v9 experimental switch. Installing the beta or supporting these code
    // paths does not advertise participation.
    if (CPreferences::IsEseNetLabActive()) {
        LONG netlab = static_cast<LONG>(ESE_CAP_NETLAB_V1 | ESE_CAP_REACH_V2);
        if (CPreferences::GetEseAutoKeepalive())
            netlab |= static_cast<LONG>(ESE_CAP_KAD_KEEPALIVE);
        if (CPreferences::GetUtpHolePunchEnabled()
            && CPreferences::GetEseKad3Rendezvous())
            netlab |= static_cast<LONG>(ESE_CAP_HOLEPUNCH_RDV);
        if (CPreferences::IsEseNetLabContributionActive()
            && CPreferences::GetEseRelayAccept())
            netlab |= static_cast<LONG>(ESE_CAP_LIVE_RELAY);
        ::InterlockedOr(caps, netlab);
    }

    if (!CPreferences::GetEseV9Experimental())
        return;

    LONG enabled = static_cast<LONG>(ESE_CAP_TUNNEL_BULK | ESE_CAP_REACH_V2);
    if (eSELive::NodeIdentityIsPersistent()) {
        enabled |= static_cast<LONG>(ESE_CAP_TUNNEL_AUTH |
            ESE_CAP_TUNNEL_STRICT3 | ESE_CAP_TUNNEL_SHAPED);
        if (CPreferences::IsEseNetLabContributionActive()
            && CPreferences::GetKad6BetaExitOptIn())
            enabled |= static_cast<LONG>(ESE_CAP_KAD6 | ESE_CAP_KAD6_ECONOMY);
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
	, m_nDetectedV6Generation(0)
	, m_nInboundV6Generation(0)
	, m_nDetectedV6InterfaceIndex(0)
	, m_nInboundV6InterfaceIndex(0)
	, m_nPcpV6Generation(0)
	, m_nPublishedTopologyGeneration(0)
	, m_nAppliedTopologyGeneration(0)
	, m_nProbeToken(0)
	, m_nActiveProbeToken(0)
	, m_lProbeStarted(0)
	, m_lDetectedV6ExternallyObserved(0)
	, m_lInboundV6Observed(0)
	, m_lPcpOperationActive(0)
	, m_lPcpRetryPending(0)
	, m_lShuttingDown(0)
	, m_pcpIfIndex(0)
	, m_pcpRefreshFailures(0)
	, m_pcpPolicyAuthorized(false)
	, m_pcpInboundConfirmed(false)
    , m_dwLastProbeTick(0)
{
}

void CFirewallProberV6::BeginShutdownFence()
{
	::InterlockedExchange(&m_lShuttingDown, 1);
	// Synchronize with the final PCP promotion: if it was already in the
	// critical section it completes first, then this clears its cap; if not,
	// the worker observes the fence before it can publish.
	CSingleLock l(&m_lock, TRUE);
	m_pcpPolicyAuthorized = false;
	::InterlockedAnd(reinterpret_cast<volatile LONG*>(&g_uForkCapsRuntime),
		~static_cast<LONG>(CAP_FORK_IPV6_DUALSTACK));
}

void CFirewallProberV6::PublishTopologyGeneration(uint64 topologyGeneration)
{
	if (topologyGeneration == 0)
		return;
	CSingleLock l(&m_lock, TRUE);
	if (topologyGeneration > m_nPublishedTopologyGeneration)
		m_nPublishedTopologyGeneration = topologyGeneration;
}

uint64 CFirewallProberV6::GetPublishedTopologyGeneration() const
{
	CSingleLock l(&m_lock, TRUE);
	return m_nPublishedTopologyGeneration;
}

void CFirewallProberV6::OnTopologyGenerationChanged(uint64 topologyGeneration)
{
	if (topologyGeneration == 0)
		return;
	natmap::TopologyApplyDecision topologyDecision =
		natmap::TopologyApplyDecision::Ignore;
	{
		CSingleLock l(&m_lock, TRUE);
		topologyDecision = natmap::EvaluateTopologyGenerationApply(
			m_nAppliedTopologyGeneration, topologyGeneration);
		m_nPublishedTopologyGeneration = topologyGeneration;
		if (topologyDecision == natmap::TopologyApplyDecision::Initialize) {
			m_nAppliedTopologyGeneration = topologyGeneration;
			return; // First observed generation is a baseline, not a teardown.
		}
		if (topologyDecision == natmap::TopologyApplyDecision::Invalidate) {
			m_nAppliedTopologyGeneration = topologyGeneration;
			m_sameLanEvidence = natmap::PrivateSameLanEvidence{};
			m_sameLanLocalEndpoint = natmap::Endpoint{};
		}
	}
	if (topologyDecision != natmap::TopologyApplyDecision::Invalidate)
		return;
	// Fence leases before re-probing. A PCP worker that started on the old
	// generation sees the published-generation mismatch and can only DELETE.
	DeletePcpMappingsBestEffort();
	{
		CSingleLock l(&m_lock, TRUE);
		// Neither an accepted socket nor a local address observation may cross
		// a route-generation boundary. The new probe must collect fresh proof.
		m_detectedIP = CAddress();
		m_nDetectedV6Generation = 0;
		m_nDetectedV6InterfaceIndex = 0;
		m_nInboundV6Generation = 0;
		m_nInboundV6InterfaceIndex = 0;
		m_nPcpV6Generation = 0;
		m_pcpPolicyAuthorized = false;
		m_pcpInboundConfirmed = false;
		if (m_eLayer == LayerPCP || m_eLayer == LayerHighID)
			m_eLayer = LayerUnreachable;
		::InterlockedExchange(&m_lInboundV6Observed, 0);
	}
	::InterlockedAnd(reinterpret_cast<volatile LONG*>(&g_uForkCapsRuntime),
		~static_cast<LONG>(CAP_FORK_IPV6_DUALSTACK));
	if (!theApp.IsClosing()) {
		::InterlockedExchange(&m_lProbeStarted, 0);
		ProbeAsync();
	}
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
	ProbeWork* work = new ProbeWork;
	{
		CSingleLock l(&m_lock, TRUE);
		work->prober = this;
		work->generation = m_nPublishedTopologyGeneration;
		work->token = ++m_nProbeToken;
		m_nActiveProbeToken = work->token;
	}
	if (work->generation == 0 ||
		::InterlockedCompareExchange(&m_lShuttingDown, 0, 0) != 0) {
		delete work;
		::InterlockedExchange(&m_lProbeStarted, 0);
		return;
	}

    m_dwLastProbeTick = GetTickCount();
    LIVE_LOG("NETV6", "starting IPv6 firewall probe cascade (worker thread)");
	CWinThread* thread = AfxBeginThread(ProbeThreadProc, work,
		THREAD_PRIORITY_BELOW_NORMAL);
	if (thread == NULL) {
		delete work;
		::InterlockedExchange(&m_lProbeStarted, 0);
		LIVE_LOG("NETV6", "IPv6 firewall probe thread creation failed");
	}
}

UINT AFX_CDECL CFirewallProberV6::ProbeThreadProc(LPVOID pParam)
{
    DbgSetThreadName("FirewallProberV6");
	ProbeWork* work = static_cast<ProbeWork*>(pParam);
	CFirewallProberV6* prober = work->prober;
	const uint64 generation = work->generation;
	const uint64 token = work->token;
	delete work;
	prober->RunCascade(generation, token);
    return 0;
}

void CFirewallProberV6::RunCascade(uint64 generation, uint64 token)
{
    DetectLocalPublicV6(generation, token);
    ECascadeLayer verdict = LayerUnreachable;
    if (TryHighID())          verdict = LayerHighID;
    else {
        const natmap::PcpCascadeOutcome pcp = TryPCP(generation, token);
        if (!natmap::MayPublishCascadeVerdict(pcp))
            return; // The PCP owner, not this waiter, will wake one retry.
        if (pcp == natmap::PcpCascadeOutcome::Mapped) verdict = LayerPCP;
        else if (TryIGDv2())      verdict = LayerIGDv2;
        else if (TryKeepalive())  verdict = LayerKeepalive;
        else if (TryHolePunch())  verdict = LayerHolePunch;
        else if (TryBuddyRelay()) verdict = LayerBuddyRelay;
    }

    // Past this point we only touch our own singleton (static storage) and the
    // thread-safe live log. Re-check the inbound proof while holding the same
    // lock used by ReportInboundV6Reachable: otherwise an accept between the
    // old pre-lock check and this assignment could be overwritten as
    // Unreachable by the one-shot worker.
    bool mayPublish = false;
    {
        CSingleLock l(&m_lock, TRUE);
		const natmap::ProbeIncarnation captured = {generation, token, false};
		const natmap::ProbeIncarnation current = {
			m_nPublishedTopologyGeneration, m_nActiveProbeToken,
			::InterlockedCompareExchange(&m_lShuttingDown, 0, 0) != 0};
		mayPublish = natmap::CanPublishProbeVerdict(captured, current);
		if (mayPublish
			&& ::InterlockedCompareExchange(&m_lInboundV6Observed, 0, 0) != 0)
			verdict = m_pcpPolicyAuthorized && m_pcpTcp.active
				? LayerPCP : LayerHighID;
		if (mayPublish)
			m_eLayer = verdict;
    }
	if (!mayPublish)
		return;
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

natmap::IpAddress ToNatmapAddress(const CAddress& address)
{
	natmap::IpAddress result{};
	if (address.GetType() == CAddress::IPv6) {
		result.family = natmap::AddressFamily::IPv6;
		memcpy(result.bytes.data(), address.Data(), 16);
	} else if (address.GetType() == CAddress::IPv4) {
		result.family = natmap::AddressFamily::IPv4;
		memcpy(result.bytes.data(), address.Data(), 4);
	}
	return result;
}

natmap::Endpoint ToNatmapEndpoint(const CAddress& address, uint16 port)
{
	natmap::Endpoint result{};
	result.address = ToNatmapAddress(address);
	result.port = port;
	result.source = natmap::EndpointSource::LocalInterface;
	return result;
}

natmap::RouteBindingIdentity ToNativeV6Binding(
	const CAddress& address, ULONG interfaceIndex,
	natmap::NetworkOrigin origin = natmap::NetworkOrigin::Native)
{
	natmap::RouteBindingIdentity result{};
	result.local_address = ToNatmapAddress(address);
	result.interface_index = interfaceIndex;
	result.family = natmap::AddressFamily::IPv6;
	result.origin = origin;
	result.interface_present = interfaceIndex != 0;
	return result;
}

natmap::IpAddress NetworkForPrefix(natmap::IpAddress address,
	uint8 prefixLength)
{
	const size_t length = address.family == natmap::AddressFamily::IPv4
		? 4u : address.family == natmap::AddressFamily::IPv6 ? 16u : 0u;
	if (length == 0 || prefixLength > length * 8)
		return natmap::IpAddress{};
	const size_t wholeBytes = prefixLength / 8;
	const uint8 remainder = prefixLength % 8;
	if (remainder != 0 && wholeBytes < length)
		address.bytes[wholeBytes] &= static_cast<uint8>(
			0xffu << (8u - remainder));
	for (size_t index = wholeBytes + (remainder != 0 ? 1u : 0u);
		index < length; ++index)
		address.bytes[index] = 0;
	return address;
}

natmap::CandidateObservation
CFirewallProberV6::GetDirectRouteObservation(
	uint64 currentGeneration, natmap::Transport transport) const
{
	if (currentGeneration == 0)
		return natmap::CandidateObservation{};
	CSingleLock l(&m_lock, TRUE);
	if (m_detectedIP.GetType() != CAddress::IPv6
		|| !m_detectedIP.IsPublicIP()
		|| m_nPublishedTopologyGeneration != currentGeneration
		|| m_nDetectedV6Generation != currentGeneration
		|| m_nDetectedV6InterfaceIndex == 0)
		return natmap::CandidateObservation{};

	natmap::Ipv6ScopeInput input{};
	input.current_endpoint = ToNatmapEndpoint(m_detectedIP,
		transport == natmap::Transport::Tcp
			? thePrefs.GetPort() : thePrefs.GetUDPPort());
	input.transport = transport;
	input.current_route_binding = ToNativeV6Binding(
		m_detectedIP, m_nDetectedV6InterfaceIndex);
	input.current_generation = currentGeneration;
	input.now_monotonic_ms = MonotonicMilliseconds64();
	const PcpLeaseV6& lease = transport == natmap::Transport::Tcp
		? m_pcpTcp : m_pcpUdp;
	if (lease.active) {
		input.pinhole.present = true;
		input.pinhole.owned_by_us = true;
		input.pinhole.authorized = true;
		input.pinhole.endpoint = ToNatmapEndpoint(
			m_pcpClientV6, lease.internalPort);
		input.pinhole.public_endpoint = ToNatmapEndpoint(
			lease.externalIP, lease.externalPort);
		input.pinhole.transport = transport;
		input.pinhole.route_binding = ToNativeV6Binding(
			m_pcpClientV6, m_pcpIfIndex);
		input.pinhole.generation = m_nPcpV6Generation;
		input.pinhole.expires_monotonic_ms =
			lease.acquiredTick +
			static_cast<uint64>(lease.lifetimeSeconds) * 1000;
	}
	if (::InterlockedCompareExchange(
		const_cast<volatile LONG*>(&m_lInboundV6Observed), 0, 0) != 0
		&& transport == natmap::Transport::Tcp) {
		input.inbound.present = true;
		input.inbound.endpoint = input.current_endpoint;
		input.inbound.transport = transport;
		input.inbound.route_binding = ToNativeV6Binding(
			m_detectedIP, m_nInboundV6InterfaceIndex);
		input.inbound.generation = m_nInboundV6Generation;
		input.inbound.expires_monotonic_ms =
			(std::numeric_limits<uint64>::max)();
	}
	return natmap::GlobalRouteObservation(
		natmap::EvaluateIpv6ScopeAdmission(input));
}

bool CFirewallProberV6::ObserveSameLanRouteToPeer(
	const CAddress& peerAddress, uint16 peerPort,
	uint64 topologyGeneration)
{
	if (peerAddress.GetType() != CAddress::IPv6 || peerPort == 0 ||
		topologyGeneration == 0 ||
		topologyGeneration != GetPublishedTopologyGeneration())
		return false;
	CAddress localAddress;
	ULONG interfaceIndex = 0;
	uint8 prefixLength = 0;
	if (!GetOnLinkRouteV6(peerAddress, localAddress, interfaceIndex,
		prefixLength))
		return false;
	ReportSameLanV6Evidence(localAddress, thePrefs.GetPort(), peerAddress,
		peerPort, interfaceIndex, prefixLength, topologyGeneration,
		MonotonicMilliseconds64() + MIN2MS(2));
	return CanUseSameLanEndpoint(peerAddress, peerPort, topologyGeneration);
}

void CFirewallProberV6::ReportSameLanV6Evidence(
	const CAddress& localAddress, uint16 localPort,
	const CAddress& peerAddress, uint16 peerPort, ULONG interfaceIndex,
	uint8 prefixLength, uint64 topologyGeneration,
	uint64 expiresMonotonicMs)
{
	natmap::Ipv6ScopeInput input{};
	input.current_endpoint = ToNatmapEndpoint(localAddress, localPort);
	input.transport = natmap::Transport::Tcp;
	input.current_route_binding = ToNativeV6Binding(
		localAddress, interfaceIndex, natmap::NetworkOrigin::Unknown);
	input.current_generation = topologyGeneration;
	input.now_monotonic_ms = MonotonicMilliseconds64();
	input.requested_scope = natmap::Ipv6ScopeRequest::SameLan;
	input.same_lan.present = true;
	input.same_lan.positive_same_lan_domain = true;
	input.same_lan.endpoint = input.current_endpoint;
	input.same_lan.peer_endpoint = ToNatmapEndpoint(peerAddress, peerPort);
	input.same_lan.peer_endpoint.source = natmap::EndpointSource::PeerProbe;
	input.same_lan.transport = input.transport;
	input.same_lan.route_binding = input.current_route_binding;
	input.same_lan.generation = topologyGeneration;
	input.same_lan.expires_monotonic_ms = expiresMonotonicMs;
	input.same_lan.scope.enabled = true;
	input.same_lan.scope.interface_index = interfaceIndex;
	input.same_lan.scope.family = input.current_endpoint.address.family;
	input.same_lan.scope.network = NetworkForPrefix(
		input.current_endpoint.address, prefixLength);
	input.same_lan.scope.prefix_length = prefixLength;

	const natmap::Ipv6ScopeDecision admitted =
		natmap::EvaluateIpv6ScopeAdmission(input);
	CSingleLock l(&m_lock, TRUE);
	if (natmap::CanUseSameLanEndpoint(admitted)) {
		m_sameLanLocalEndpoint = input.current_endpoint;
		m_sameLanEvidence = input.same_lan;
	} else {
		m_sameLanLocalEndpoint = natmap::Endpoint{};
		m_sameLanEvidence = natmap::PrivateSameLanEvidence{};
	}
}

bool CFirewallProberV6::CanUseSameLanEndpoint(
	const CAddress& peerAddress, uint16 peerPort,
	uint64 topologyGeneration, ULONG* interfaceIndex) const
{
	CSingleLock l(&m_lock, TRUE);
	if (!m_sameLanEvidence.present)
		return false;
	const natmap::Endpoint requestedPeer = ToNatmapEndpoint(peerAddress, peerPort);
	if (!m_sameLanEvidence.peer_endpoint.SameSocketEndpoint(requestedPeer)
		|| m_sameLanEvidence.peer_endpoint.source != natmap::EndpointSource::PeerProbe)
		return false; // A LAN proof belongs to one exact remote socket only.
	natmap::Ipv6ScopeInput input{};
	input.current_endpoint = m_sameLanLocalEndpoint;
	input.transport = m_sameLanEvidence.transport;
	input.current_route_binding = m_sameLanEvidence.route_binding;
	input.current_generation = topologyGeneration;
	input.now_monotonic_ms = MonotonicMilliseconds64();
	input.requested_scope = natmap::Ipv6ScopeRequest::SameLan;
	input.same_lan = m_sameLanEvidence;
	// Keep the originally admitted peer evidence intact; replacing it here
	// would let another port/address inherit a bounded LAN exception.
	const bool usable = natmap::CanUseSameLanEndpoint(
		natmap::EvaluateIpv6ScopeAdmission(input));
	if (usable && interfaceIndex != NULL)
		*interfaceIndex = m_sameLanEvidence.route_binding.interface_index;
	return usable;
}

// v0.71 IPv6 Sprint 6 — record our public v6 address as observed by a peer.
// See header. Thread-safe; an inbound-proven exact address always wins.
void CFirewallProberV6::SetDetectedV6IP(
	const CAddress& addr, uint64 topologyGeneration)
{
    // Only a genuine, public, native-v6 address is worth recording. FromSA (the
    // source of the answered CAddress) already folds v4-mapped v6 to IPv4, so a
    // CAddress::IPv6 here is native; the public-IP check rejects link-local /
    // ULA / loopback / Teredo etc. The receiver also validates, but re-check
    // here so no caller can poison the published value.
    if (addr.GetType() != CAddress::IPv6 || !addr.IsPublicIP()
		|| topologyGeneration == 0
		|| topologyGeneration != GetPublishedTopologyGeneration())
        return;
	CAddress gateway;
	ULONG interfaceIndex = 0;
	if (!GetDefaultGatewayV6(addr, gateway, interfaceIndex))
		return;
	if (interfaceIndex == 0)
		return;
    {
        CSingleLock l(&m_lock, TRUE);
		if (m_nDetectedV6Generation > topologyGeneration)
			return;
        if (!m_detectedIP.IsNull()
			&& m_nDetectedV6Generation == topologyGeneration)
            return;             // first validated candidate wins per generation
        m_detectedIP = addr;
		m_nDetectedV6Generation = topologyGeneration;
		m_nDetectedV6InterfaceIndex = interfaceIndex;
		if (m_nInboundV6Generation != topologyGeneration)
			::InterlockedExchange(&m_lInboundV6Observed, 0);
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
	const uint64 currentGeneration = prober.GetPublishedTopologyGeneration();
	const natmap::CandidateObservation observation =
		prober.GetDirectRouteObservation(
			currentGeneration, natmap::Transport::Udp);
	return thePrefs.IsIPv6Enabled()
		&& observation.IsVerifiedFor(currentGeneration);
}

void CFirewallProberV6::DetectLocalPublicV6(uint64 currentGeneration,
	uint64 token)
{
	if (currentGeneration == 0)
		return;
	{
		CSingleLock l(&m_lock, TRUE);
		if (m_nPublishedTopologyGeneration != currentGeneration
			|| m_nActiveProbeToken != token)
			return;
	}
    // A configured bind address is authoritative and avoids selecting a
    // privacy/temporary address when the host has several global addresses.
    const CString configured(thePrefs.GetIPv6BindAddr());
    if (!configured.IsEmpty() && configured != _T("::")) {
        CAddress addr(configured, false);
        if (addr.GetType() == CAddress::IPv6 && addr.IsPublicIP()) {
			SetDetectedV6IP(addr, currentGeneration);
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
				SetDetectedV6IP(addr, currentGeneration);
                if (!theApp.IsClosing())
                    LIVE_LOG("NETV6", "local public v6 candidate = %hs", addr.ToString().c_str());
                return;
            }
        }
    }
    if (!randomSuffixFallback.IsNull()) {
		SetDetectedV6IP(randomSuffixFallback, currentGeneration);
        if (!theApp.IsClosing())
            LIVE_LOG("NETV6", "local public v6 privacy fallback = %hs",
                randomSuffixFallback.ToString().c_str());
    }
}

void CFirewallProberV6::ReportInboundV6Reachable(
	const CAddress& localAddress, uint64 topologyGeneration)
{
	if (localAddress.GetType() != CAddress::IPv6
		|| !localAddress.IsPublicIP() || topologyGeneration == 0)
		return;
	bool pcpConfirmed = false;
    {
        CSingleLock l(&m_lock, TRUE);
		// An accept can have waited in the listener backlog across a topology
		// change. It may only confirm an address independently observed for the
		// current generation; it can never relabel the accepted socket itself.
		if (::InterlockedCompareExchange(&m_lShuttingDown, 0, 0) != 0
			|| m_nPublishedTopologyGeneration != topologyGeneration
			|| m_nDetectedV6Generation != topologyGeneration
			|| m_detectedIP != localAddress
			|| m_nDetectedV6InterfaceIndex == 0)
			return;
		m_nInboundV6Generation = topologyGeneration;
		m_nInboundV6InterfaceIndex = m_nDetectedV6InterfaceIndex;
		pcpConfirmed = m_pcpTcp.active
			&& m_pcpPolicyAuthorized
			&& m_pcpClientV6 == localAddress
			&& m_pcpIfIndex == m_nDetectedV6InterfaceIndex
			&& m_nPcpV6Generation == topologyGeneration
			&& MonotonicMilliseconds64() <
				m_pcpTcp.acquiredTick +
					static_cast<uint64>(m_pcpTcp.lifetimeSeconds) * 1000;
		m_pcpInboundConfirmed = pcpConfirmed;
        m_eLayer = pcpConfirmed ? LayerPCP : LayerHighID;
		// Publish the proof while holding the same lock used by SetDetectedV6IP.
		// This prevents a late advisory answer from replacing the exact local
		// destination address of the accepted native-v6 connection.
		::InterlockedExchange(&m_lInboundV6Observed, 1);
		::InterlockedExchange(&m_lDetectedV6ExternallyObserved, 1);
		// BeginShutdownFence synchronizes on m_lock, so it either observes and
		// clears this CAP or this branch sees the shutdown flag before publish.
		::InterlockedOr(reinterpret_cast<volatile LONG*>(&g_uForkCapsRuntime),
			(LONG)CAP_FORK_IPV6_DUALSTACK);
	}
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

void CFirewallProberV6::ScheduleDeferredPcpRetry()
{
	if (theApp.IsClosing()
		|| ::InterlockedCompareExchange(&m_lShuttingDown, 0, 0) != 0)
		return;
	// The caller has atomically consumed the one pending-retry token.  Reset
	// the one-shot cascade guard before starting its replacement incarnation.
	::InterlockedExchange(&m_lProbeStarted, 0);
	ProbeAsync();
}

bool CFirewallProberV6::TryClaimPcpOperationOrScheduleRetry()
{
	if (::InterlockedExchange(&m_lPcpOperationActive, 1) == 0)
		return true;

	// Publish demand first, then re-read the guard.  This closes the narrow
	// owner-release-before-pending race: either the current owner sees demand,
	// or this waiter consumes the demand and starts exactly one replacement.
	::InterlockedExchange(&m_lPcpRetryPending, 1);
	const bool stillActive =
		::InterlockedCompareExchange(&m_lPcpOperationActive, 0, 0) != 0;
	if (natmap::SelectPcpBusyRetryOwner(stillActive) ==
		natmap::PcpBusyRetryOwner::WaitingWorker
		&& ::InterlockedCompareExchange(&m_lPcpRetryPending, 0, 1) == 1)
		ScheduleDeferredPcpRetry();
	return false;
}

bool CFirewallProberV6::ReleasePcpOperationAndRetry()
{
	if (::InterlockedExchange(&m_lPcpOperationActive, 0) == 0)
		return false;
	// Exactly one caller consumes the retry latch.  A waiting worker can do so
	// only after observing the released guard; otherwise the owner does it here.
	if (::InterlockedCompareExchange(&m_lPcpRetryPending, 0, 1) == 1) {
		ScheduleDeferredPcpRetry();
		return true;
	}
	return false;
}

natmap::PcpCascadeOutcome CFirewallProberV6::TryPCP(uint64 operationGeneration, uint64 token)
{
	if (!CPreferences::IsIPv6Enabled()
		|| ::InterlockedCompareExchange(&m_lShuttingDown, 0, 0) != 0)
		return natmap::PcpCascadeOutcome::Failed;
	if (!TryClaimPcpOperationOrScheduleRetry())
		return natmap::PcpCascadeOutcome::Deferred;
	if (operationGeneration == 0) {
		ReleasePcpOperationAndRetry();
		return natmap::PcpCascadeOutcome::Failed;
	}

	CAddress clientAddress;
	{
		CSingleLock l(&m_lock, TRUE);
		if (m_nPublishedTopologyGeneration != operationGeneration
			|| m_nActiveProbeToken != token) {
			ReleasePcpOperationAndRetry();
			return natmap::PcpCascadeOutcome::Failed;
		}
		clientAddress = m_detectedIP;
	}
	if (clientAddress.GetType() != CAddress::IPv6
		|| !clientAddress.IsPublicIP()) {
		ReleasePcpOperationAndRetry();
		LIVE_LOG("NETV6", "PCP-v6 skipped: no stable public client address");
		return natmap::PcpCascadeOutcome::Failed;
	}

	CAddress gateway;
	ULONG interfaceIndex = 0;
	if (!GetDefaultGatewayV6(clientAddress, gateway, interfaceIndex)) {
		ReleasePcpOperationAndRetry();
		LIVE_LOG("NETV6", "PCP-v6 skipped: no IPv6 default gateway");
		return natmap::PcpCascadeOutcome::Failed;
	}
	{
		CSingleLock l(&m_lock, TRUE);
		if (m_nDetectedV6Generation != operationGeneration ||
			m_detectedIP != clientAddress ||
			m_nDetectedV6InterfaceIndex != interfaceIndex) {
			ReleasePcpOperationAndRetry();
			return natmap::PcpCascadeOutcome::Failed;
		}
	}

	PcpLeaseV6 tcp;
	PcpLeaseV6 udp;
	tcp.protocol = kPcpProtocolTcp;
	tcp.internalPort = thePrefs.GetPort();
	udp.protocol = kPcpProtocolUdp;
	udp.internalPort = thePrefs.GetUDPPort();
	if (tcp.internalPort == 0 || !GeneratePcpNonce(tcp.nonce)
		|| (udp.internalPort != 0 && !GeneratePcpNonce(udp.nonce))) {
		ReleasePcpOperationAndRetry();
		LIVE_LOG("NETV6", "PCP-v6 skipped: invalid port or nonce generation failed");
		return natmap::PcpCascadeOutcome::Failed;
	}

	natmap::PcpMapResponse tcpResponse;
	const PcpMapExchangeResult tcpMapResult = ExchangePcpMapV6(gateway, interfaceIndex,
		clientAddress, tcp.internalPort, tcp.internalPort, CAddress(),
		tcp.protocol, kPcpRequestedLifetime, tcp.nonce, tcpResponse, false);
	const bool tcpMapped = PcpMapCreated(tcpMapResult);
	if (!tcpMapped) {
		if (natmap::MustCleanupPcpNonce(
			ToPcpCleanupDisposition(tcpMapResult))) {
			natmap::PcpMapResponse ignored;
			ExchangePcpMapV6(gateway, interfaceIndex, clientAddress,
				tcp.internalPort, 0, CAddress(), tcp.protocol, 0, tcp.nonce,
				ignored, true);
		}
		ReleasePcpOperationAndRetry();
		LIVE_LOG("NETV6", "PCP-v6 TCP MAP failed/withdrawn received=%d result=%u",
			PcpMapResponseReceived(tcpMapResult) ? 1 : 0,
			static_cast<unsigned>(tcpResponse.result));
		return natmap::PcpCascadeOutcome::Failed;
	}

	natmap::PcpMapResponse udpResponse;
	bool udpMapped = true;
	PcpMapExchangeResult udpMapResult = PcpMapExchangeResult::RequestNotSent;
	if (udp.internalPort != 0) {
		udpMapResult = ExchangePcpMapV6(gateway, interfaceIndex,
			clientAddress, udp.internalPort, udp.internalPort, CAddress(),
			udp.protocol, kPcpRequestedLifetime, udp.nonce, udpResponse, false);
		udpMapped = PcpMapCreated(udpMapResult);
	}
	if (!udpMapped && udp.internalPort != 0)
	{
		if (natmap::MustCleanupPcpNonce(
			ToPcpCleanupDisposition(udpMapResult))) {
			natmap::PcpMapResponse ignored;
			ExchangePcpMapV6(gateway, interfaceIndex, clientAddress,
				udp.internalPort, 0, CAddress(), udp.protocol, 0, udp.nonce,
				ignored, true);
		}
		LIVE_LOG("NETV6",
			"PCP-v6 UDP MAP unavailable result=%u; keeping TCP mapping",
			static_cast<unsigned>(udpResponse.result));
	}
	if (udpMapped && udp.internalPort != 0
		&& !ArePcpPairEpochsCoherent(tcpResponse.epoch, udpResponse.epoch)) {
		// Both MAPs may have succeeded on the wire, but they do not describe
		// one continuous mapper lifetime. Delete the owned nonces and force a
		// fresh generation rather than publishing a mixed-epoch pair.
		natmap::PcpMapResponse ignored;
		ExchangePcpMapV6(gateway, interfaceIndex, clientAddress,
			tcp.internalPort, 0, CAddress(), tcp.protocol, 0, tcp.nonce,
			ignored, true);
		ExchangePcpMapV6(gateway, interfaceIndex, clientAddress,
			udp.internalPort, 0, CAddress(), udp.protocol, 0, udp.nonce,
			ignored, true);
		ReleasePcpOperationAndRetry();
		LIVE_LOG("NETV6", "PCP-v6 MAP pair rejected: mapper epoch discontinuity");
		return natmap::PcpCascadeOutcome::Failed;
	}

	const uint64 acquired = MonotonicMilliseconds64();
	tcp.active = true;
	tcp.externalPort = tcpResponse.external_port;
	tcp.externalIP = CAddress(tcpResponse.external_ip.data());
	tcp.lifetimeSeconds = EffectivePcpLifetime(
		tcpResponse.lifetime_seconds);
	tcp.mapperEpoch = tcpResponse.epoch;
	tcp.acquiredTick = acquired;
	tcp.ownerToken = token;
	if (tcp.lifetimeSeconds == 0) {
		natmap::PcpMapResponse ignored;
		ExchangePcpMapV6(gateway, interfaceIndex, clientAddress,
			tcp.internalPort, 0, CAddress(), tcp.protocol, 0, tcp.nonce,
			ignored, true);
		if (udpMapped && udp.internalPort != 0)
			ExchangePcpMapV6(gateway, interfaceIndex, clientAddress,
				udp.internalPort, 0, CAddress(), udp.protocol, 0, udp.nonce,
				ignored, true);
		ReleasePcpOperationAndRetry();
		LIVE_LOG("NETV6", "PCP-v6 MAP granted zero TCP lifetime; pinhole withdrawn");
		return natmap::PcpCascadeOutcome::Failed;
	}
	if (udp.internalPort != 0) {
		udp.active = udpMapped;
		if (udpMapped) {
			udp.externalPort = udpResponse.external_port;
			udp.externalIP = CAddress(udpResponse.external_ip.data());
			udp.lifetimeSeconds = EffectivePcpLifetime(
				udpResponse.lifetime_seconds);
			udp.mapperEpoch = udpResponse.epoch;
			udp.active = udp.lifetimeSeconds != 0;
		}
		udp.acquiredTick = acquired;
		udp.ownerToken = token;
	}
	bool operationCurrent = false;
	{
		CSingleLock l(&m_lock, TRUE);
		operationCurrent = !theApp.IsClosing()
			&& ::InterlockedCompareExchange(&m_lShuttingDown, 0, 0) == 0
			&& m_nPublishedTopologyGeneration == operationGeneration
			&& m_nActiveProbeToken == token
			&& m_nDetectedV6Generation == operationGeneration
			&& m_detectedIP == clientAddress
			&& m_nDetectedV6InterfaceIndex == interfaceIndex;
	}
	if (!operationCurrent) {
		natmap::PcpMapResponse ignored;
		ExchangePcpMapV6(gateway, interfaceIndex, clientAddress,
			tcp.internalPort, 0, CAddress(), tcp.protocol, 0, tcp.nonce,
			ignored, true);
		if (udp.active || natmap::MustCleanupPcpNonce(
			ToPcpCleanupDisposition(udpMapResult)))
			ExchangePcpMapV6(gateway, interfaceIndex, clientAddress,
				udp.internalPort, 0, CAddress(), udp.protocol, 0, udp.nonce,
				ignored, true);
		ReleasePcpOperationAndRetry();
		LIVE_LOG("NETV6", "discarded stale PCP-v6 MAP result after topology change");
		return natmap::PcpCascadeOutcome::Failed;
	}
	{
		CSingleLock l(&m_lock, TRUE);
		m_pcpGatewayV6 = gateway;
		m_pcpClientV6 = clientAddress;
		m_pcpIfIndex = interfaceIndex;
		m_pcpTcp = tcp;
		m_pcpUdp = udp;
		m_nPcpV6Generation = operationGeneration;
		m_pcpRefreshFailures = 0;
		m_pcpPolicyAuthorized = false;
		m_pcpInboundConfirmed = false;
	}
	const natmap::CandidateObservation pinholeObservation =
		GetDirectRouteObservation(operationGeneration, natmap::Transport::Tcp);
	bool policyAuthorized =
		pinholeObservation.IsVerifiedFor(operationGeneration);
	bool retireOwnedLease = false;
	{
		CSingleLock l(&m_lock, TRUE);
		const natmap::PcpLeaseOwnerIdentity expectedOwner = {
			operationGeneration, token, tcp.nonce};
		const natmap::PcpLeaseOwnerIdentity currentOwner = {
			m_nPcpV6Generation, m_pcpTcp.ownerToken, m_pcpTcp.nonce};
		if (theApp.IsClosing()
			|| ::InterlockedCompareExchange(&m_lShuttingDown, 0, 0) != 0
			|| m_nPublishedTopologyGeneration != operationGeneration
			|| m_nActiveProbeToken != token
			|| m_nPcpV6Generation != operationGeneration
			|| !m_pcpTcp.active || m_pcpTcp.nonce != tcp.nonce)
			policyAuthorized = false;
		m_pcpPolicyAuthorized = policyAuthorized;
		if (policyAuthorized) {
			m_eLayer = LayerPCP;
			// This update shares the shutdown/lease lock. BeginShutdownFence()
			// synchronizes on this same lock and clears any already-published cap.
			::InterlockedOr(reinterpret_cast<volatile LONG*>(&g_uForkCapsRuntime),
				static_cast<LONG>(CAP_FORK_IPV6_DUALSTACK));
		} else if (natmap::IsCurrentPcpLeaseOwner(expectedOwner, currentOwner)) {
			// This worker may retire only the exact generation/token/nonce it
			// installed.  A topology/shutdown UI path is the sole unconditional
			// cleanup owner.
			m_pcpTcp.active = false;
			m_pcpUdp.active = false;
			m_nPcpV6Generation = 0;
			m_pcpPolicyAuthorized = false;
			m_pcpInboundConfirmed = false;
			::InterlockedAnd(reinterpret_cast<volatile LONG*>(&g_uForkCapsRuntime),
				~static_cast<LONG>(CAP_FORK_IPV6_DUALSTACK));
			retireOwnedLease = true;
		}
	}

	if (!policyAuthorized) {
		// A valid MAP that fails endpoint/binding policy is retired only if this
		// exact worker still owns its lease incarnation.
		if (retireOwnedLease) {
			natmap::PcpMapResponse ignored;
			ExchangePcpMapV6(gateway, interfaceIndex, clientAddress,
				tcp.internalPort, 0, CAddress(), tcp.protocol, 0, tcp.nonce,
				ignored, true);
			if (udp.active || natmap::MustCleanupPcpNonce(
				ToPcpCleanupDisposition(udpMapResult)))
				ExchangePcpMapV6(gateway, interfaceIndex, clientAddress,
					udp.internalPort, 0, CAddress(), udp.protocol, 0, udp.nonce,
					ignored, true);
		}
		ReleasePcpOperationAndRetry();
		LIVE_LOG("NETV6", "PCP-v6 MAP rejected by exact pinhole policy");
		return natmap::PcpCascadeOutcome::Failed;
	}
	ReleasePcpOperationAndRetry();
	LIVE_LOG("NETV6",
		"PCP-v6 exact pinhole authorized gateway=%hs%%%lu TCP=%u->%u UDP=%u->%u lease=%us; inbound unconfirmed",
		gateway.ToString().c_str(), interfaceIndex, tcp.internalPort,
		tcp.externalPort, udp.internalPort, udp.externalPort,
		tcp.lifetimeSeconds);
	return natmap::PcpCascadeOutcome::Mapped;
}

void CFirewallProberV6::OnTimerTick()
{
	if (!CPreferences::IsIPv6Enabled() || theApp.IsClosing())
		return;
	uint64 publishedGeneration = 0;
	uint64 appliedGeneration = 0;
	{
		CSingleLock l(&m_lock, TRUE);
		publishedGeneration = m_nPublishedTopologyGeneration;
		appliedGeneration = m_nAppliedTopologyGeneration;
	}
	if (publishedGeneration != 0 && publishedGeneration != appliedGeneration) {
		// Fallback for a route notification delivered while the UI transition
		// handler was unavailable. It cannot advance the manager generation:
		// it applies exactly the generation already published by the UI.
		OnTopologyGenerationChanged(publishedGeneration);
		return;
	}

	bool renewalDue = false;
	bool pinholeExpired = false;
	const uint64 now = MonotonicMilliseconds64();
	{
		CSingleLock l(&m_lock, TRUE);
		const uint64 nowMonotonic = now;
		if (m_pcpTcp.active
			&& nowMonotonic >= static_cast<uint64>(m_pcpTcp.acquiredTick) +
				static_cast<uint64>(m_pcpTcp.lifetimeSeconds) * 1000) {
			m_pcpTcp.active = false;
			m_pcpUdp.active = false;
			m_nPcpV6Generation = 0;
			m_pcpPolicyAuthorized = false;
			m_pcpInboundConfirmed = false;
			const bool independentInbound =
				::InterlockedCompareExchange(&m_lInboundV6Observed, 0, 0) != 0
				&& m_nInboundV6Generation == m_nDetectedV6Generation
				&& m_nInboundV6InterfaceIndex == m_nDetectedV6InterfaceIndex
				&& m_nInboundV6Generation != 0;
			if (m_eLayer == LayerPCP)
				m_eLayer = independentInbound ? LayerHighID : LayerUnreachable;
			pinholeExpired = true;
			if (!independentInbound) {
				::InterlockedExchange(&m_lInboundV6Observed, 0);
			::InterlockedAnd(
				reinterpret_cast<volatile LONG*>(&g_uForkCapsRuntime),
				~static_cast<LONG>(CAP_FORK_IPV6_DUALSTACK));
			}
		}
		if (!pinholeExpired && m_pcpTcp.active
			&& m_pcpTcp.lifetimeSeconds != 0) {
			const uint64 renewAfter =
				static_cast<uint64>(m_pcpTcp.lifetimeSeconds) * 1000 / 2;
			renewalDue = now - m_pcpTcp.acquiredTick >= renewAfter;
		}
		if (!pinholeExpired && !renewalDue && m_pcpUdp.active
			&& m_pcpUdp.lifetimeSeconds != 0) {
			const uint64 renewAfter =
				static_cast<uint64>(m_pcpUdp.lifetimeSeconds) * 1000 / 2;
			renewalDue = now - m_pcpUdp.acquiredTick >= renewAfter;
		}
		// UDP is useful for Kad but not required to make the TCP listener
		// reachable. Retry a failed optional UDP MAP at a low rate.
		if (!pinholeExpired && !renewalDue && m_pcpTcp.active && !m_pcpUdp.active
			&& m_pcpUdp.internalPort != 0)
			renewalDue = now - m_pcpUdp.acquiredTick >= MIN2MS(5);
	}
	if (pinholeExpired) {
		LIVE_LOG("NETV6", "PCP-v6 pinhole expired; direct IPv6 withdrawn");
		return;
	}
	if (!renewalDue
		|| ::InterlockedExchange(&m_lPcpOperationActive, 1) != 0)
		return;

	CWinThread* thread = AfxBeginThread(PcpRefreshThreadProc, this,
		THREAD_PRIORITY_BELOW_NORMAL);
	if (thread == NULL) {
		ReleasePcpOperationAndRetry();
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
	uint64 generation = 0;
	PcpLeaseV6 tcp;
	PcpLeaseV6 udp;
	{
		CSingleLock l(&m_lock, TRUE);
		gateway = m_pcpGatewayV6;
		clientAddress = m_pcpClientV6;
		interfaceIndex = m_pcpIfIndex;
		generation = m_nPcpV6Generation;
		tcp = m_pcpTcp;
		udp = m_pcpUdp;
	}

	natmap::PcpMapResponse tcpResponse;
	const PcpMapExchangeResult tcpRefreshResult = tcp.active
		? ExchangePcpMapV6(gateway, interfaceIndex,
		clientAddress, tcp.internalPort, tcp.externalPort, tcp.externalIP,
		tcp.protocol, kPcpRequestedLifetime, tcp.nonce, tcpResponse, false)
		: PcpMapExchangeResult::RequestNotSent;
	const bool tcpSucceeded = PcpMapCreated(tcpRefreshResult);
	const bool tcpRefreshRequiresImmediateRetirement =
		natmap::MustCleanupPcpNonce(
			ToPcpCleanupDisposition(tcpRefreshResult))
		&& !tcpSucceeded;
	natmap::PcpMapResponse udpResponse;
	bool udpSucceeded = true;
	PcpMapExchangeResult udpRefreshResult = PcpMapExchangeResult::RequestNotSent;
	if (udp.internalPort != 0) {
		udpRefreshResult = ExchangePcpMapV6(gateway, interfaceIndex, clientAddress,
			udp.internalPort, udp.externalPort, udp.externalIP, udp.protocol,
			kPcpRequestedLifetime, udp.nonce, udpResponse, false);
		udpSucceeded = PcpMapCreated(udpRefreshResult);
	}
	const bool tcpEndpointChanged = tcpSucceeded
		&& (tcp.externalPort != tcpResponse.external_port
			|| memcmp(tcp.externalIP.Data(), tcpResponse.external_ip.data(),
				tcpResponse.external_ip.size()) != 0);
	const bool epochDiscontinuity =
		(tcpSucceeded && IsPcpEpochDiscontinuity(
			tcp.mapperEpoch, tcpResponse.epoch))
		|| (udpSucceeded && udp.active && IsPcpEpochDiscontinuity(
			udp.mapperEpoch, udpResponse.epoch))
		|| (tcpSucceeded && udpSucceeded && udp.internalPort != 0
			&& !ArePcpPairEpochsCoherent(tcpResponse.epoch,
				udpResponse.epoch));
	const bool tcpLifetimeZero = tcpRefreshResult == PcpMapExchangeResult::ZeroLifetime;
	const bool udpLifetimeZero = udp.internalPort != 0
		&& udpSucceeded && EffectivePcpLifetime(udpResponse.lifetime_seconds) == 0;

	bool restartProbe = false;
	bool discardRefreshResult = false;
	bool retirePinhole = false;
	bool preservedTcpRefreshResult = false;
	bool preservedUdpRefreshResult = false;
	{
		CSingleLock l(&m_lock, TRUE);
		// No response obtained while I/O ran may overwrite a new topology,
		// address, gateway, interface or nonce incarnation.
		const bool snapshotCurrent = m_pcpTcp.active
			&& natmap::IsCurrentPcpLeaseOwner(
				natmap::PcpLeaseOwnerIdentity{generation, tcp.ownerToken, tcp.nonce},
				natmap::PcpLeaseOwnerIdentity{m_nPcpV6Generation,
					m_pcpTcp.ownerToken, m_pcpTcp.nonce})
			&& m_nPcpV6Generation == generation
			&& m_nDetectedV6Generation == generation
			&& m_detectedIP == clientAddress
			&& m_nDetectedV6InterfaceIndex == interfaceIndex
			&& m_pcpGatewayV6 == gateway && m_pcpClientV6 == clientAddress
			&& m_pcpIfIndex == interfaceIndex
			&& !theApp.IsClosing()
			&& m_nPublishedTopologyGeneration == generation;
		if (!snapshotCurrent) {
			discardRefreshResult = true;
			// Retire the snapshot generation atomically. If a newer generation
			// has already installed its own lease, do not touch that new owner.
			if (m_nPcpV6Generation == generation) {
				retirePinhole = true;
				restartProbe = !theApp.IsClosing();
			}
		} else if (epochDiscontinuity || tcpEndpointChanged || tcpLifetimeZero
			|| tcpRefreshRequiresImmediateRetirement) {
			retirePinhole = true;
			restartProbe = true;
		} else if (tcpSucceeded) {
			const uint64 acquired = MonotonicMilliseconds64();
			m_pcpTcp.externalPort = tcpResponse.external_port;
			m_pcpTcp.externalIP = CAddress(tcpResponse.external_ip.data());
			m_pcpTcp.lifetimeSeconds = EffectivePcpLifetime(
				tcpResponse.lifetime_seconds);
			m_pcpTcp.mapperEpoch = tcpResponse.epoch;
			m_pcpTcp.acquiredTick = acquired;
			preservedTcpRefreshResult = true;
			m_pcpRefreshFailures = 0;
			if (udpSucceeded && m_pcpUdp.internalPort != 0) {
				m_pcpUdp.active = !udpLifetimeZero;
				m_pcpUdp.externalPort = udpResponse.external_port;
				m_pcpUdp.externalIP = CAddress(udpResponse.external_ip.data());
				m_pcpUdp.lifetimeSeconds = EffectivePcpLifetime(
					udpResponse.lifetime_seconds);
				m_pcpUdp.mapperEpoch = udpResponse.epoch;
				m_pcpUdp.acquiredTick = acquired;
				preservedUdpRefreshResult = m_pcpUdp.active;
			} else if (m_pcpUdp.internalPort != 0) {
				m_pcpUdp.active = false;
				m_pcpUdp.acquiredTick = acquired;
			}
		} else if (++m_pcpRefreshFailures >= 3) {
			retirePinhole = true;
			restartProbe = true;
		}

		if (retirePinhole) {
			m_pcpTcp.active = false;
			m_pcpUdp.active = false;
			m_nPcpV6Generation = 0;
			m_pcpPolicyAuthorized = false;
			m_pcpInboundConfirmed = false;
			const bool independentInbound =
				::InterlockedCompareExchange(&m_lInboundV6Observed, 0, 0) != 0
				&& m_nInboundV6Generation == m_nDetectedV6Generation
				&& m_nInboundV6InterfaceIndex == m_nDetectedV6InterfaceIndex
				&& m_nInboundV6Generation != 0;
			if (m_eLayer == LayerPCP)
				m_eLayer = independentInbound ? LayerHighID : LayerUnreachable;
			if (!independentInbound) {
				::InterlockedExchange(&m_lInboundV6Observed, 0);
				::InterlockedAnd(
					reinterpret_cast<volatile LONG*>(&g_uForkCapsRuntime),
					~static_cast<LONG>(CAP_FORK_IPV6_DUALSTACK));
			}
		}
	}
	const bool cleanupTcpRefreshNonce = tcp.internalPort != 0
		&& natmap::MustCleanupPcpNonce(
			ToPcpCleanupDisposition(tcpRefreshResult))
		&& !preservedTcpRefreshResult;
	const bool cleanupUdpRefreshNonce = udp.internalPort != 0
		&& natmap::MustCleanupPcpNonce(
			ToPcpCleanupDisposition(udpRefreshResult))
		&& !preservedUdpRefreshResult;
	if (discardRefreshResult || retirePinhole) {
		// A stale/failed response can still have created our nonce-owned MAP.
		// Best-effort DELETE prevents it from becoming a silent orphan.
		natmap::PcpMapResponse ignored;
		if (tcp.internalPort != 0
			&& (cleanupTcpRefreshNonce
				|| ((retirePinhole || tcpSucceeded) && tcp.active)))
			ExchangePcpMapV6(gateway, interfaceIndex, clientAddress,
				tcp.internalPort, 0, CAddress(), tcp.protocol, 0, tcp.nonce,
				ignored, true);
		if (udp.internalPort != 0
			&& (cleanupUdpRefreshNonce
				|| ((retirePinhole || udpSucceeded) && udp.active)))
			ExchangePcpMapV6(gateway, interfaceIndex, clientAddress,
				udp.internalPort, 0, CAddress(), udp.protocol, 0, udp.nonce,
				ignored, true);
		const bool deferredRetryScheduled = ReleasePcpOperationAndRetry();
		LIVE_LOG("NETV6", discardRefreshResult
			? "discarded stale PCP-v6 refresh result"
			: (epochDiscontinuity
				? "PCP-v6 mapper epoch discontinuity; pinhole withdrawn"
				: (tcpLifetimeZero
					? "PCP-v6 refresh granted zero TCP lifetime; pinhole withdrawn"
					: "PCP-v6 pinhole withdrawn after endpoint change/failures")));
		if (restartProbe && !deferredRetryScheduled && !theApp.IsClosing()) {
			::InterlockedExchange(&m_lProbeStarted, 0);
			ProbeAsync();
		}
		return;
	}
	if (cleanupTcpRefreshNonce) {
		// A TCP MAP that was sent but cannot be preserved must not outlive the
		// local lease state. The refresh guard still owns this exact nonce.
		natmap::PcpMapResponse ignored;
		ExchangePcpMapV6(gateway, interfaceIndex, clientAddress,
			tcp.internalPort, 0, CAddress(), tcp.protocol, 0, tcp.nonce,
			ignored, true);
	}
	if (cleanupUdpRefreshNonce) {
		// This refresh owns the operation guard and therefore its snapshot nonce.
		// The response was not preserved in the current lease (including an
		// ambiguous sent/no-response case), so retire that exact nonce now.
		natmap::PcpMapResponse ignored;
		ExchangePcpMapV6(gateway, interfaceIndex, clientAddress,
			udp.internalPort, 0, CAddress(), udp.protocol, 0, udp.nonce,
			ignored, true);
	}
	const bool deferredRetryScheduled = ReleasePcpOperationAndRetry();

	if (tcpSucceeded)
		LIVE_LOG("NETV6", tcpEndpointChanged
			? "PCP-v6 TCP endpoint changed; inbound proof invalidated"
			: (udp.internalPort == 0 || udpSucceeded
				? "PCP-v6 leases refreshed"
				: "PCP-v6 TCP refreshed; optional UDP MAP still unavailable"));
	else
		LIVE_LOG("NETV6", "PCP-v6 TCP lease refresh failed");
	if (restartProbe && !deferredRetryScheduled && !theApp.IsClosing()) {
		::InterlockedExchange(&m_lProbeStarted, 0);
		ProbeAsync();
	}
}

void CFirewallProberV6::DeletePcpMappingsBestEffort()
{
	// UI cleanup is a terminal consumer of retry demand.  It clears the latch
	// even when a worker owns the guard, so that worker cannot start a duplicate
	// probe after shutdown; OnTopologyGenerationChanged owns the one explicit
	// replacement probe after this method returns.
	ASSERT(!natmap::UiPcpCleanupMayScheduleRetry());
	::InterlockedExchange(&m_lPcpRetryPending, 0);
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
		m_nPcpV6Generation = 0;
		m_pcpPolicyAuthorized = false;
		m_pcpInboundConfirmed = false;
		const bool independentInbound =
			::InterlockedCompareExchange(&m_lInboundV6Observed, 0, 0) != 0
			&& m_nInboundV6Generation == m_nDetectedV6Generation
			&& m_nInboundV6InterfaceIndex == m_nDetectedV6InterfaceIndex
			&& m_nInboundV6Generation != 0;
		if (!independentInbound) {
			::InterlockedExchange(&m_lInboundV6Observed, 0);
			::InterlockedAnd(
				reinterpret_cast<volatile LONG*>(&g_uForkCapsRuntime),
				~static_cast<LONG>(CAP_FORK_IPV6_DUALSTACK));
		}
		if (m_eLayer == LayerPCP)
			m_eLayer = independentInbound ? LayerHighID : LayerUnreachable;
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
	if (ownsOperationGuard) {
		// Keep the latch clear through guard release. A UI caller deliberately
		// never invokes ReleasePcpOperationAndRetry().
		::InterlockedExchange(&m_lPcpRetryPending, 0);
		::InterlockedExchange(&m_lPcpOperationActive, 0);
	}
	LIVE_LOG("NETV6", "PCP-v6 delete requests sent");
}

bool CFirewallProberV6::TryIGDv2()      { return false; /* Sprint 9 */ }
bool CFirewallProberV6::TryKeepalive()  { return false; /* Sprint 5 */ }
bool CFirewallProberV6::TryHolePunch()  { return false; /* Sprint 5 */ }
bool CFirewallProberV6::TryBuddyRelay() { return false; /* Sprint 8 */ }
