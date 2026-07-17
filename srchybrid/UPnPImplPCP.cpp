// PCP (RFC 6887) implementation for automatic IPv4 port forwarding.
#include "StdAfx.h"
#include "emule.h"
#include "UPnPImplPCP.h"
#include "Log.h"
#include "OtherFunctions.h"

#include <bcrypt.h>
#include <iphlpapi.h>

#pragma comment(lib, "bcrypt.lib")

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

CMutex CUPnPImplPCP::m_mutBusy;

namespace {

bool IsZeroNonce(const std::array<uint8, 12>& nonce)
{
	for (size_t i = 0; i < nonce.size(); ++i)
		if (nonce[i] != 0)
			return false;
	return true;
}

DWORD JitteredTimeout(DWORD timeout)
{
	ULONG random = 0;
	if (BCryptGenRandom(NULL, reinterpret_cast<PUCHAR>(&random),
		sizeof(random), BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0)
		random = GetTickCount();
	const LONG spread = static_cast<LONG>(timeout / 10);
	const LONG adjustment = spread == 0 ? 0
		: static_cast<LONG>(random % (2 * spread + 1)) - spread;
	return static_cast<DWORD>(static_cast<LONG>(timeout) + adjustment);
}

uint32 EffectiveLifetime(uint32 grantedLifetime)
{
	// RFC 6887 section 15 recommends treating absurdly long leases as a
	// saner value (for example 24 hours) so removed static mappings recover.
	const uint32 maximumLifetime = 24 * 60 * 60;
	return grantedLifetime > maximumLifetime ? maximumLifetime
		: grantedLifetime;
}

} // namespace

CUPnPImplPCP::CUPnPImplPCP()
	: m_dwGatewayIP(0)
	, m_dwOldGatewayIP(0)
	, m_hThreadHandle(NULL)
	, m_bSucceededOnce(false)
	, m_bAbortDiscovery(false)
{
	m_clientAddress.fill(0);
	m_oldClientAddress.fill(0);
	m_tcpExternalAddress.fill(0);
	m_udpExternalAddress.fill(0);
	m_webExternalAddress.fill(0);
	m_tcpNonce.fill(0);
	m_udpNonce.fill(0);
	m_webNonce.fill(0);
	m_oldTCPNonce.fill(0);
	m_oldUDPNonce.fill(0);
	m_oldWebNonce.fill(0);
}

CUPnPImplPCP::~CUPnPImplPCP()
{
	StopAsyncFind();
}

bool CUPnPImplPCP::IsReady()
{
	if (m_bAbortDiscovery)
		return false;
	CSingleLock lockTest(&m_mutBusy);
	return lockTest.Lock(0);
}

void CUPnPImplPCP::StopAsyncFind()
{
	if (m_hThreadHandle != NULL) {
		m_bAbortDiscovery = true;
		CSingleLock lockTest(&m_mutBusy);
		if (!lockTest.Lock(10000)) {
			DebugLogError(_T("PCP: Waiting for discovery thread to quit failed"));
			if (m_hThreadHandle != NULL)
				DebugLogError(::TerminateThread(m_hThreadHandle, 0)
					? _T("...OK") : _T("...Failed"));
		} else
			DebugLog(_T("PCP: Aborted discovery thread"));
		m_hThreadHandle = NULL;
	}
	m_bAbortDiscovery = false;
}

void CUPnPImplPCP::StartDiscovery(uint16 nTCPPort, uint16 nUDPPort,
	uint16 nTCPWebPort)
{
	DebugLog(_T("PCP: Using RFC 6887 MAP implementation"));

	if (m_bSucceededOnce && m_dwGatewayIP != 0) {
		m_nOldTCPPort = m_nTCPPort;
		m_nOldUDPPort = m_nUDPPort;
		m_nOldTCPWebPort = m_nTCPWebPort;
		m_dwOldGatewayIP = m_dwGatewayIP;
		m_oldClientAddress = m_clientAddress;
		m_oldTCPNonce = m_tcpNonce;
		m_oldUDPNonce = m_udpNonce;
		m_oldWebNonce = m_webNonce;
	} else {
		m_nOldTCPPort = m_nOldUDPPort = m_nOldTCPWebPort = 0;
		m_dwOldGatewayIP = 0;
		m_oldClientAddress.fill(0);
		m_oldTCPNonce.fill(0);
		m_oldUDPNonce.fill(0);
		m_oldWebNonce.fill(0);
	}
	m_bSucceededOnce = false;

	m_nTCPPort = nTCPPort;
	m_nUDPPort = nUDPPort;
	m_nTCPWebPort = nTCPWebPort;
	m_nExternalTCPPort = nTCPPort;
	m_nExternalUDPPort = nUDPPort;
	m_nExternalTCPWebPort = nTCPWebPort;
	m_dwMappingExternalIP = 0;
	m_dwMappingLeaseLifetime = 0;
	m_dwMapperEpoch = 0;
	m_tcpExternalAddress.fill(0);
	m_udpExternalAddress.fill(0);
	m_webExternalAddress.fill(0);
	m_tcpNonce.fill(0);
	m_udpNonce.fill(0);
	m_webNonce.fill(0);
	m_bUPnPPortsForwarded = TRIS_UNKNOWN;
	m_nDiagnosticStage = UPNP_DIAG_DISCOVERING;
	m_bCheckAndRefresh = false;

	if (!m_bAbortDiscovery)
		StartThread();
}

bool CUPnPImplPCP::CheckAndRefresh()
{
	if (m_bAbortDiscovery || !m_bSucceededOnce || m_dwGatewayIP == 0
		|| m_nTCPPort == 0) {
		DebugLog(_T("PCP: Not refreshing ports - not previously mapped"));
		return false;
	}
	if (!IsReady()) {
		DebugLog(_T("PCP: Not refreshing ports - already busy"));
		return false;
	}

	m_bCheckAndRefresh = true;
	m_nDiagnosticStage = UPNP_DIAG_DISCOVERING;
	StartThread();
	return true;
}

void CUPnPImplPCP::DeletePorts()
{
	if (m_bSucceededOnce && m_dwGatewayIP != 0) {
		m_nOldTCPPort = m_nTCPPort;
		m_nOldUDPPort = m_nUDPPort;
		m_nOldTCPWebPort = m_nTCPWebPort;
		m_dwOldGatewayIP = m_dwGatewayIP;
		m_oldClientAddress = m_clientAddress;
		m_oldTCPNonce = m_tcpNonce;
		m_oldUDPNonce = m_udpNonce;
		m_oldWebNonce = m_webNonce;
	}
	m_bSucceededOnce = false;
	m_nTCPPort = m_nUDPPort = m_nTCPWebPort = 0;
	m_nExternalTCPPort = m_nExternalUDPPort = m_nExternalTCPWebPort = 0;
	m_dwMappingExternalIP = 0;
	m_dwMappingLeaseLifetime = 0;
	m_dwMapperEpoch = 0;
	m_tcpExternalAddress.fill(0);
	m_udpExternalAddress.fill(0);
	m_webExternalAddress.fill(0);
	m_bUPnPPortsForwarded = TRIS_FALSE;
	DeletePorts(false);
}

void CUPnPImplPCP::DeletePorts(bool bSkipLock)
{
	CSingleLock lockTest(&m_mutBusy);
	if (bSkipLock || lockTest.Lock(0)) {
		if (m_dwOldGatewayIP != 0) {
			if (m_nOldTCPPort != 0 && !IsZeroNonce(m_oldTCPNonce))
				UnmapPort(m_dwOldGatewayIP, m_oldClientAddress, m_nOldTCPPort,
					true, m_oldTCPNonce);
			if (m_nOldUDPPort != 0 && !IsZeroNonce(m_oldUDPNonce))
				UnmapPort(m_dwOldGatewayIP, m_oldClientAddress, m_nOldUDPPort,
					false, m_oldUDPNonce);
			if (m_nOldTCPWebPort != 0 && !IsZeroNonce(m_oldWebNonce))
				UnmapPort(m_dwOldGatewayIP, m_oldClientAddress,
					m_nOldTCPWebPort,
					true, m_oldWebNonce);
		}
		m_nOldTCPPort = m_nOldUDPPort = m_nOldTCPWebPort = 0;
		m_dwOldGatewayIP = 0;
		m_oldClientAddress.fill(0);
		m_oldTCPNonce.fill(0);
		m_oldUDPNonce.fill(0);
		m_oldWebNonce.fill(0);
	} else
		DebugLogError(_T("PCP: Unable to remove port mappings - busy"));
}

uint32 CUPnPImplPCP::GetDefaultGateway()
{
	MIB_IPFORWARDROW route;
	memset(&route, 0, sizeof(route));
	if (GetBestRoute(0, 0, &route) != NO_ERROR || route.dwForwardNextHop == 0)
		return 0;
	return route.dwForwardNextHop;
}

bool CUPnPImplPCP::GetClientAddress(uint32 nGatewayIP,
	std::array<uint8, 16>& clientAddress)
{
	SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sock == INVALID_SOCKET)
		return false;

	sockaddr_in destination;
	memset(&destination, 0, sizeof(destination));
	destination.sin_family = AF_INET;
	destination.sin_port = htons(PCP_PORT);
	destination.sin_addr.s_addr = nGatewayIP;

	sockaddr_in local;
	memset(&local, 0, sizeof(local));
	int localLength = sizeof(local);
	const bool ok = connect(sock, reinterpret_cast<sockaddr*>(&destination),
		sizeof(destination)) == 0
		&& getsockname(sock, reinterpret_cast<sockaddr*>(&local), &localLength) == 0
		&& local.sin_addr.s_addr != 0;
	closesocket(sock);
	if (!ok)
		return false;

	const uint8* bytes = reinterpret_cast<const uint8*>(&local.sin_addr.s_addr);
	clientAddress = natmap::PcpIpv4Mapped(bytes[0], bytes[1], bytes[2], bytes[3]);
	return true;
}

bool CUPnPImplPCP::GenerateNonce(std::array<uint8, 12>& nonce)
{
	return BCryptGenRandom(NULL, nonce.data(), static_cast<ULONG>(nonce.size()),
		BCRYPT_USE_SYSTEM_PREFERRED_RNG) >= 0 && !IsZeroNonce(nonce);
}

bool CUPnPImplPCP::ExtractIPv4(
	const std::array<std::uint8_t, 16>& address, uint32& ipv4)
{
	for (size_t i = 0; i < 10; ++i)
		if (address[i] != 0)
			return false;
	if (address[10] != 0xFF || address[11] != 0xFF)
		return false;
	memcpy(&ipv4, address.data() + 12, sizeof(ipv4));
	return ipv4 != 0;
}

bool CUPnPImplPCP::ExchangeMap(uint32 nGatewayIP,
	const natmap::PcpMapRequest& request, natmap::PcpMapResponse& response,
	bool bDeletion)
{
	uint8 packet[natmap::kPcpMaximumMessageSize];
	const size_t packetSize = natmap::EncodePcpMapRequest(request, packet,
		sizeof(packet));
	if (packetSize == 0)
		return false;

	SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sock == INVALID_SOCKET)
		return false;

	uint32 clientIP = 0;
	if (!ExtractIPv4(request.client_ip, clientIP)) {
		closesocket(sock);
		return false;
	}
	sockaddr_in local;
	memset(&local, 0, sizeof(local));
	local.sin_family = AF_INET;
	local.sin_addr.s_addr = clientIP;
	if (bind(sock, reinterpret_cast<sockaddr*>(&local), sizeof(local)) != 0) {
		DebugLogWarning(_T("PCP: Unable to bind request to selected interface (error %u)"),
			WSAGetLastError());
		closesocket(sock);
		return false;
	}

	sockaddr_in destination;
	memset(&destination, 0, sizeof(destination));
	destination.sin_family = AF_INET;
	destination.sin_port = htons(PCP_PORT);
	destination.sin_addr.s_addr = nGatewayIP;

	bool succeeded = false;
	// Bounded variant of RFC 6887 section 8.1.1 exponential
	// retransmission. Seven seconds worst case still fits the refresh timer.
	const DWORD timeouts[] = { 1000, 2000, 4000 };
	for (size_t attempt = 0; attempt < _countof(timeouts)
		&& !m_bAbortDiscovery; ++attempt) {
		if (sendto(sock, reinterpret_cast<const char*>(packet),
			static_cast<int>(packetSize), 0,
			reinterpret_cast<sockaddr*>(&destination), sizeof(destination))
			!= static_cast<int>(packetSize))
			continue;

		const DWORD waitTime = JitteredTimeout(timeouts[attempt]);
		const DWORD started = GetTickCount();
		while (!m_bAbortDiscovery) {
			const DWORD elapsed = GetTickCount() - started;
			if (elapsed >= waitTime)
				break;
			const DWORD remaining = waitTime - elapsed;
			fd_set fds;
			FD_ZERO(&fds);
			FD_SET(sock, &fds);
			timeval timeout;
			timeout.tv_sec = remaining / 1000;
			timeout.tv_usec = (remaining % 1000) * 1000;
			if (select(0, &fds, NULL, NULL, &timeout) <= 0)
				break;

			uint8 raw[natmap::kPcpMaximumMessageSize + 1];
			sockaddr_in source;
			memset(&source, 0, sizeof(source));
			int sourceLength = sizeof(source);
			const int received = recvfrom(sock, reinterpret_cast<char*>(raw),
				sizeof(raw), 0, reinterpret_cast<sockaddr*>(&source),
				&sourceLength);
			if (received <= 0 || source.sin_addr.s_addr != nGatewayIP
				|| source.sin_port != htons(PCP_PORT))
				continue;

			natmap::PcpMapResponse candidate;
			const natmap::PcpDecodeStatus decodeStatus =
				natmap::DecodePcpMapResponse(raw,
					static_cast<size_t>(received), request, candidate);
			if (decodeStatus != natmap::PcpDecodeStatus::Ok) {
				DebugLogWarning(_T("PCP: Ignoring invalid MAP response, status=%u"),
					static_cast<unsigned>(decodeStatus));
				continue;
			}
			if (candidate.result != natmap::PcpResultCode::Success) {
				DebugLogWarning(_T("PCP: MAP rejected, result=%u hold=%us"),
					static_cast<unsigned>(candidate.result),
					candidate.lifetime_seconds);
				closesocket(sock);
				return false;
			}
			if (bDeletion) {
				succeeded = candidate.lifetime_seconds == 0;
			} else {
				uint32 externalIP = 0;
				succeeded = candidate.lifetime_seconds != 0
					&& candidate.external_port != 0
					&& ExtractIPv4(candidate.external_ip, externalIP);
			}
			if (succeeded) {
				response = candidate;
				closesocket(sock);
				return true;
			}
		}
	}

	if (!m_bAbortDiscovery)
		DebugLogWarning(_T("PCP: MAP timed out after bounded retransmissions"));
	closesocket(sock);
	return false;
}

bool CUPnPImplPCP::MapPort(uint32 nGatewayIP,
	const std::array<uint8, 16>& clientAddress, uint16 nPrivatePort,
	uint16 nSuggestedExternalPort,
	const std::array<uint8, 16>& suggestedExternalAddress,
	bool bTCP, uint32 nLifetime,
	std::array<uint8, 12>& nonce, natmap::PcpMapResponse& response)
{
	if (IsZeroNonce(nonce) && !GenerateNonce(nonce))
		return false;

	natmap::PcpMapRequest request;
	request.lifetime_seconds = nLifetime;
	request.client_ip = clientAddress;
	request.nonce = nonce;
	request.protocol = bTCP ? PCP_PROTOCOL_TCP : PCP_PROTOCOL_UDP;
	request.internal_port = nPrivatePort;
	request.suggested_external_port = nSuggestedExternalPort;
	request.suggested_external_ip = suggestedExternalAddress;
	if (!ExchangeMap(nGatewayIP, request, response, false))
		return false;

	DebugLog(_T("PCP: Mapped %s port %hu -> %hu (lifetime %us)"),
		bTCP ? _T("TCP") : _T("UDP"), nPrivatePort,
		response.external_port, response.lifetime_seconds);
	return true;
}

bool CUPnPImplPCP::UnmapPort(uint32 nGatewayIP,
	const std::array<uint8, 16>& clientAddress, uint16 nPrivatePort,
	bool bTCP, const std::array<uint8, 12>& nonce)
{
	natmap::PcpMapRequest request;
	request.client_ip = clientAddress;
	request.nonce = nonce;
	request.protocol = bTCP ? PCP_PROTOCOL_TCP : PCP_PROTOCOL_UDP;
	request.internal_port = nPrivatePort;
	natmap::PcpMapResponse response;
	const bool result = ExchangeMap(nGatewayIP, request, response, true);
	if (result)
		DebugLog(_T("PCP: Unmapped %s port %hu"),
			bTCP ? _T("TCP") : _T("UDP"), nPrivatePort);
	return result;
}

typedef CUPnPImplPCP::CStartDiscoveryThread CStartDiscoveryThread;
IMPLEMENT_DYNCREATE(CStartDiscoveryThread, CWinThread)

CUPnPImplPCP::CStartDiscoveryThread::CStartDiscoveryThread()
	: m_pOwner(NULL)
{
}

BOOL CUPnPImplPCP::CStartDiscoveryThread::InitInstance()
{
	InitThreadLocale();
	return TRUE;
}

int CUPnPImplPCP::CStartDiscoveryThread::Run()
{
	DbgSetThreadName("CUPnPImplPCP::CStartDiscoveryThread");
	if (m_pOwner == NULL)
		return 0;

	CSingleLock lock(&m_pOwner->m_mutBusy);
	if (!lock.Lock(0) || m_pOwner->m_bAbortDiscovery)
		return 0;

	if (!m_pOwner->m_bCheckAndRefresh) {
		m_pOwner->m_dwGatewayIP = CUPnPImplPCP::GetDefaultGateway();
		if (m_pOwner->m_dwGatewayIP == 0
			|| !CUPnPImplPCP::GetClientAddress(m_pOwner->m_dwGatewayIP,
				m_pOwner->m_clientAddress)) {
			m_pOwner->m_nDiagnosticStage = UPNP_DIAG_NO_GATEWAY;
			m_pOwner->m_bUPnPPortsForwarded = TRIS_FALSE;
			m_pOwner->SendResultMessage();
			return 0;
		}
		m_pOwner->DeletePorts(true);
	}

	const uint32 leaseTime = 7200;
	bool succeeded = false;
	natmap::PcpMapResponse tcpResponse;
	const uint16 suggestedTCP = m_pOwner->m_bCheckAndRefresh
		? m_pOwner->m_nExternalTCPPort : m_pOwner->m_nTCPPort;
	const std::array<uint8, 16> suggestedTCPAddress =
		m_pOwner->m_bCheckAndRefresh ? m_pOwner->m_tcpExternalAddress
			: std::array<uint8, 16>();
	m_pOwner->m_nDiagnosticStage = UPNP_DIAG_TCP_MAPPING;
	succeeded = m_pOwner->MapPort(m_pOwner->m_dwGatewayIP,
		m_pOwner->m_clientAddress, m_pOwner->m_nTCPPort, suggestedTCP,
		suggestedTCPAddress, true, leaseTime, m_pOwner->m_tcpNonce,
		tcpResponse);
	if (succeeded) {
		m_pOwner->m_nExternalTCPPort = tcpResponse.external_port;
		m_pOwner->m_tcpExternalAddress = tcpResponse.external_ip;
		m_pOwner->m_dwMappingLeaseLifetime =
			EffectiveLifetime(tcpResponse.lifetime_seconds);
		m_pOwner->m_dwMapperEpoch = tcpResponse.epoch;
		CUPnPImplPCP::ExtractIPv4(tcpResponse.external_ip,
			m_pOwner->m_dwMappingExternalIP);
	}

	if (succeeded && m_pOwner->m_nUDPPort != 0) {
		natmap::PcpMapResponse udpResponse;
		const uint16 suggestedUDP = m_pOwner->m_bCheckAndRefresh
			? m_pOwner->m_nExternalUDPPort : m_pOwner->m_nUDPPort;
		const std::array<uint8, 16> suggestedUDPAddress =
			m_pOwner->m_bCheckAndRefresh ? m_pOwner->m_udpExternalAddress
				: std::array<uint8, 16>();
		m_pOwner->m_nDiagnosticStage = UPNP_DIAG_UDP_MAPPING;
		succeeded = m_pOwner->MapPort(m_pOwner->m_dwGatewayIP,
			m_pOwner->m_clientAddress, m_pOwner->m_nUDPPort, suggestedUDP,
			suggestedUDPAddress, false, leaseTime, m_pOwner->m_udpNonce,
			udpResponse);
		if (succeeded) {
			m_pOwner->m_nExternalUDPPort = udpResponse.external_port;
			m_pOwner->m_udpExternalAddress = udpResponse.external_ip;
			m_pOwner->m_dwMappingLeaseLifetime = min(
				m_pOwner->m_dwMappingLeaseLifetime,
				EffectiveLifetime(udpResponse.lifetime_seconds));
			m_pOwner->m_dwMapperEpoch = udpResponse.epoch;
		} else {
			m_pOwner->UnmapPort(m_pOwner->m_dwGatewayIP,
				m_pOwner->m_clientAddress, m_pOwner->m_nTCPPort, true,
				m_pOwner->m_tcpNonce);
			m_pOwner->m_nExternalTCPPort = 0;
			m_pOwner->m_tcpExternalAddress.fill(0);
		}
	}

	if (succeeded && m_pOwner->m_nTCPWebPort != 0) {
		natmap::PcpMapResponse webResponse;
		const uint16 suggestedWeb = m_pOwner->m_bCheckAndRefresh
			? m_pOwner->m_nExternalTCPWebPort : m_pOwner->m_nTCPWebPort;
		const std::array<uint8, 16> suggestedWebAddress =
			m_pOwner->m_bCheckAndRefresh ? m_pOwner->m_webExternalAddress
				: std::array<uint8, 16>();
		if (m_pOwner->MapPort(m_pOwner->m_dwGatewayIP,
			m_pOwner->m_clientAddress, m_pOwner->m_nTCPWebPort, suggestedWeb,
			suggestedWebAddress, true, leaseTime, m_pOwner->m_webNonce,
			webResponse)) {
			m_pOwner->m_nExternalTCPWebPort = webResponse.external_port;
			m_pOwner->m_webExternalAddress = webResponse.external_ip;
		}
	}

	if (!m_pOwner->m_bAbortDiscovery) {
		m_pOwner->m_bUPnPPortsForwarded = succeeded ? TRIS_TRUE : TRIS_FALSE;
		if (succeeded) {
			m_pOwner->m_bSucceededOnce = true;
			m_pOwner->m_nDiagnosticStage = UPNP_DIAG_SUCCESS;
		} else if (m_pOwner->m_nDiagnosticStage == UPNP_DIAG_TCP_MAPPING)
			m_pOwner->m_nDiagnosticStage = UPNP_DIAG_PROTOCOL_UNAVAILABLE;
		m_pOwner->SendResultMessage();
	}
	return 0;
}

void CUPnPImplPCP::StartThread()
{
	CStartDiscoveryThread* thread = static_cast<CStartDiscoveryThread*>(
		AfxBeginThread(RUNTIME_CLASS(CStartDiscoveryThread),
			THREAD_PRIORITY_NORMAL, 0, CREATE_SUSPENDED));
	if (thread == NULL) {
		m_hThreadHandle = NULL;
		m_bUPnPPortsForwarded = TRIS_FALSE;
		m_nDiagnosticStage = UPNP_DIAG_PROTOCOL_UNAVAILABLE;
		DebugLogError(_T("PCP: Unable to create discovery thread"));
		SendResultMessage();
		return;
	}
	m_hThreadHandle = thread->m_hThread;
	thread->SetValues(this);
	thread->ResumeThread();
}
