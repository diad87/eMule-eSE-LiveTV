// PCP (RFC 6887) implementation for automatic IPv4 port forwarding.
#include "StdAfx.h"
#include "emule.h"
#include "UPnPImplPCP.h"
#include "Log.h"
#include "OtherFunctions.h"
#include "natmap/pcp_pair_transaction.h"
#include "natmap/pcp_response_guard.h"

#include <bcrypt.h>
#include <limits>

#pragma comment(lib, "bcrypt.lib")

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

CMutex CUPnPImplPCP::m_mutBusy;

namespace {

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

std::array<uint8, 16> EncodeMappedV4(
	const natmap::IpAddress& address)
{
	if (address.family != natmap::AddressFamily::IPv4)
		return std::array<uint8, 16>();
	return natmap::PcpIpv4Mapped(
		address.bytes[0], address.bytes[1],
		address.bytes[2], address.bytes[3]);
}

uint32 NetworkOrderV4(const natmap::IpAddress& address)
{
	uint32 result = 0;
	if (address.family == natmap::AddressFamily::IPv4)
		memcpy(&result, address.bytes.data(), sizeof(result));
	return result;
}

class ScopedActivePcpExchange
{
public:
	ScopedActivePcpExchange(
		std::atomic<std::uint64_t>& active, std::uint64_t id)
		: m_active(active), m_id(id) {}
	~ScopedActivePcpExchange()
	{
		std::uint64_t expected = m_id;
		m_active.compare_exchange_strong(
			expected, 0, std::memory_order_acq_rel);
	}

private:
	std::atomic<std::uint64_t>& m_active;
	std::uint64_t m_id;
};

} // namespace

CUPnPImplPCP::CUPnPImplPCP()
	: m_dwGatewayIP(0)
	, m_dwOldGatewayIP(0)
	, m_dwInterfaceIndex(0)
	, m_dwOldInterfaceIndex(0)
	, m_nRequestedTCPExternalPort(0)
	, m_nRequestedUDPExternalPort(0)
	, m_nRequestedWebExternalPort(0)
	, m_hThreadHandle(NULL)
	, m_bSucceededOnce(false)
	, m_nextExchangeId(0)
	, m_activeExchangeId(0)
	, m_initialMappingInFlight(false)
	, m_bShuttingDown(false)
	, m_bAbortDiscovery(false)
{
	m_clientAddress.fill(0);
	m_oldClientAddress.fill(0);
	m_tcpExternalAddress.fill(0);
	m_udpExternalAddress.fill(0);
	m_webExternalAddress.fill(0);
	m_tcpIdentity.Clear();
	m_udpIdentity.Clear();
	m_webIdentity.Clear();
	m_oldTCPIdentity.Clear();
	m_oldUDPIdentity.Clear();
	m_oldWebIdentity.Clear();
}

CUPnPImplPCP::~CUPnPImplPCP()
{
	{
		std::lock_guard<std::mutex> lifecycleLock(m_lifecycleMutex);
		m_bShuttingDown.store(true, std::memory_order_release);
		m_activeExchangeId.store(0, std::memory_order_release);
	}
	StopAsyncFind();
}

bool CUPnPImplPCP::IsReady()
{
	if (m_bAbortDiscovery)
		return false;
	CSingleLock lockTest(&m_mutBusy);
	return lockTest.Lock(0);
}

uint16 CUPnPImplPCP::RequestedExternalPort(
	natmap::Transport transport, uint16 localPort) const
{
	if (transport == natmap::Transport::Tcp
		&& m_tcpIdentity.IsValid())
		return m_nRequestedTCPExternalPort;
	if (transport == natmap::Transport::Udp
		&& m_udpIdentity.IsValid())
		return m_nRequestedUDPExternalPort;
	return localPort;
}

bool CUPnPImplPCP::SendResultIfLifecycleLive(
	const MappingOperationContext& operation)
{
	std::lock_guard<std::mutex> lifecycleLock(m_lifecycleMutex);
	if (m_bAbortDiscovery.load(std::memory_order_acquire)
		|| m_bShuttingDown.load(std::memory_order_acquire))
		return false;
	return SendResultMessage(operation);
}

void CUPnPImplPCP::StopAsyncFind()
{
	if (m_hThreadHandle != NULL) {
		{
			std::lock_guard<std::mutex> lifecycleLock(m_lifecycleMutex);
			m_bAbortDiscovery.store(true, std::memory_order_release);
			m_activeExchangeId.store(0, std::memory_order_release);
		}
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
	{
		std::lock_guard<std::mutex> lifecycleLock(m_lifecycleMutex);
		m_bAbortDiscovery.store(false, std::memory_order_release);
	}
	const bool initialMappingWasInFlight =
		m_initialMappingInFlight.exchange(
			false, std::memory_order_acq_rel);
	const bool hasMappingIdentity =
		m_tcpIdentity.IsValid()
		|| m_udpIdentity.IsValid()
		|| m_webIdentity.IsValid();
	if (natmap::PcpInitialMappingNeedsCleanup(
			initialMappingWasInFlight, hasMappingIdentity))
		DeletePorts();
}

void CUPnPImplPCP::StartDiscovery(uint16 nTCPPort, uint16 nUDPPort,
	uint16 nTCPWebPort)
{
	DebugLog(_T("PCP: Using RFC 6887 MAP implementation"));
	if (m_bShuttingDown.load(std::memory_order_acquire))
		return;

	const bool hasCurrentIdentity =
		!m_tcpIdentity.IsEmpty() || !m_udpIdentity.IsEmpty()
		|| !m_webIdentity.IsEmpty();
	const bool hasOldIdentity =
		!m_oldTCPIdentity.IsEmpty() || !m_oldUDPIdentity.IsEmpty()
		|| !m_oldWebIdentity.IsEmpty();
	bool movedCurrentToOld = false;
	if ((m_bSucceededOnce || hasCurrentIdentity)
		&& m_dwGatewayIP != 0 && !hasOldIdentity) {
		m_nOldTCPPort = m_tcpIdentity.internal_port;
		m_nOldUDPPort = m_udpIdentity.internal_port;
		m_nOldTCPWebPort = m_webIdentity.internal_port;
		m_dwOldGatewayIP = m_dwGatewayIP;
		m_dwOldInterfaceIndex = m_dwInterfaceIndex;
		m_oldClientAddress = m_clientAddress;
		m_oldTCPIdentity = m_tcpIdentity;
		m_oldUDPIdentity = m_udpIdentity;
		m_oldWebIdentity = m_webIdentity;
		movedCurrentToOld = true;
	} else if (!hasOldIdentity) {
		m_nOldTCPPort = m_nOldUDPPort = m_nOldTCPWebPort = 0;
		m_dwOldGatewayIP = 0;
		m_dwOldInterfaceIndex = 0;
		m_oldClientAddress.fill(0);
		m_oldTCPIdentity.Clear();
		m_oldUDPIdentity.Clear();
		m_oldWebIdentity.Clear();
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
	m_nRequestedTCPExternalPort = 0;
	m_nRequestedUDPExternalPort = 0;
	m_nRequestedWebExternalPort = 0;
	if (!hasCurrentIdentity || movedCurrentToOld) {
		m_tcpIdentity.Clear();
		m_udpIdentity.Clear();
		m_webIdentity.Clear();
	}
	m_bUPnPPortsForwarded = TRIS_UNKNOWN;
	m_nDiagnosticStage = UPNP_DIAG_DISCOVERING;
	m_bCheckAndRefresh = false;

	if (!m_bAbortDiscovery) {
		m_initialMappingInFlight.store(true, std::memory_order_release);
		StartThread();
	}
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
	const bool hasCurrentIdentity =
		!m_tcpIdentity.IsEmpty() || !m_udpIdentity.IsEmpty()
		|| !m_webIdentity.IsEmpty();
	const bool hasOldIdentity =
		!m_oldTCPIdentity.IsEmpty() || !m_oldUDPIdentity.IsEmpty()
		|| !m_oldWebIdentity.IsEmpty();
	bool movedCurrentToOld = false;
	if ((m_bSucceededOnce || hasCurrentIdentity)
		&& m_dwGatewayIP != 0 && !hasOldIdentity) {
		m_nOldTCPPort = m_tcpIdentity.internal_port;
		m_nOldUDPPort = m_udpIdentity.internal_port;
		m_nOldTCPWebPort = m_webIdentity.internal_port;
		m_dwOldGatewayIP = m_dwGatewayIP;
		m_dwOldInterfaceIndex = m_dwInterfaceIndex;
		m_oldClientAddress = m_clientAddress;
		m_oldTCPIdentity = m_tcpIdentity;
		m_oldUDPIdentity = m_udpIdentity;
		m_oldWebIdentity = m_webIdentity;
		movedCurrentToOld = true;
	}
	if (movedCurrentToOld) {
		m_tcpIdentity.Clear();
		m_udpIdentity.Clear();
		m_webIdentity.Clear();
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
	m_nRequestedTCPExternalPort = 0;
	m_nRequestedUDPExternalPort = 0;
	m_nRequestedWebExternalPort = 0;
	m_bUPnPPortsForwarded = TRIS_FALSE;
	DeletePorts(false);
}

bool CUPnPImplPCP::DeletePorts(bool bSkipLock)
{
	CSingleLock lockTest(&m_mutBusy);
	if (bSkipLock || lockTest.Lock(0)) {
		bool cleaned = true;
		if (m_dwOldGatewayIP != 0) {
			if (natmap::ValidatePcpMappingIdentity(
					m_oldTCPIdentity, natmap::Transport::Tcp,
					m_nOldTCPPort) == natmap::PcpIdentityStatus::Valid) {
				if (UnmapPort(m_dwOldGatewayIP, m_dwOldInterfaceIndex,
						m_oldClientAddress, m_oldTCPIdentity)) {
					m_oldTCPIdentity.Clear();
					m_nOldTCPPort = 0;
				} else
					cleaned = false;
			} else if (!m_oldTCPIdentity.IsEmpty())
				cleaned = false;
			if (natmap::ValidatePcpMappingIdentity(
					m_oldUDPIdentity, natmap::Transport::Udp,
					m_nOldUDPPort) == natmap::PcpIdentityStatus::Valid) {
				if (UnmapPort(m_dwOldGatewayIP, m_dwOldInterfaceIndex,
						m_oldClientAddress, m_oldUDPIdentity)) {
					m_oldUDPIdentity.Clear();
					m_nOldUDPPort = 0;
				} else
					cleaned = false;
			} else if (!m_oldUDPIdentity.IsEmpty())
				cleaned = false;
			if (natmap::ValidatePcpMappingIdentity(
					m_oldWebIdentity, natmap::Transport::Tcp,
					m_nOldTCPWebPort) == natmap::PcpIdentityStatus::Valid) {
				if (UnmapPort(m_dwOldGatewayIP, m_dwOldInterfaceIndex,
						m_oldClientAddress, m_oldWebIdentity)) {
					m_oldWebIdentity.Clear();
					m_nOldTCPWebPort = 0;
				} else
					cleaned = false;
			} else if (!m_oldWebIdentity.IsEmpty())
				cleaned = false;
		} else if (!m_oldTCPIdentity.IsEmpty()
			|| !m_oldUDPIdentity.IsEmpty()
			|| !m_oldWebIdentity.IsEmpty())
			cleaned = false;
		if (cleaned) {
			m_nOldTCPPort = m_nOldUDPPort = m_nOldTCPWebPort = 0;
			m_dwOldGatewayIP = 0;
			m_dwOldInterfaceIndex = 0;
			m_oldClientAddress.fill(0);
		}
		return cleaned;
	}
	else {
		DebugLogError(_T("PCP: Unable to remove port mappings - busy"));
		return false;
	}
}

bool CUPnPImplPCP::GenerateNonce(std::array<uint8, 12>& nonce)
{
	return BCryptGenRandom(NULL, nonce.data(), static_cast<ULONG>(nonce.size()),
		BCRYPT_USE_SYSTEM_PREFERRED_RNG) >= 0;
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

bool CUPnPImplPCP::ExchangeMap(uint32 nGatewayIP, uint32 nInterfaceIndex,
	const natmap::PcpMapRequest& request, natmap::PcpMapResponse& response,
	bool bDeletion)
{
	uint8 packet[natmap::kPcpMaximumMessageSize];
	const size_t packetSize = natmap::EncodePcpMapRequest(request, packet,
		sizeof(packet));
	if (packetSize == 0)
		return false;

	if (m_bAbortDiscovery.load(std::memory_order_acquire)
		|| (!bDeletion
			&& m_bShuttingDown.load(std::memory_order_acquire)))
		return false;

	uint32 clientIP = 0;
	if (!ExtractIPv4(request.client_ip, clientIP))
		return false;

	SOCKET sock = INVALID_SOCKET;
	std::uint64_t exchangeId = 0;
	const DWORD networkInterfaceIndex = htonl(nInterfaceIndex);
	while (sock == INVALID_SOCKET) {
		if (m_bAbortDiscovery.load(std::memory_order_acquire)
			|| (!bDeletion
				&& m_bShuttingDown.load(std::memory_order_acquire)))
			return false;

		std::uint64_t previous =
			m_nextExchangeId.load(std::memory_order_acquire);
		const std::uint64_t maximum =
			(std::numeric_limits<std::uint64_t>::max)();
		while (true) {
			if (previous == maximum)
				return false;
			if (m_nextExchangeId.compare_exchange_weak(
					previous, previous + 1,
					std::memory_order_acq_rel,
					std::memory_order_acquire))
				break;
		}
		exchangeId = previous + 1;
		const std::uint16_t localSourcePort =
			natmap::PcpExchangeLocalPort(exchangeId);
		if (localSourcePort == 0) {
			DebugLogError(_T("PCP: Exhausted non-reusable request endpoints"));
			return false;
		}

		SOCKET candidate = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		if (candidate == INVALID_SOCKET)
			return false;
		if (nInterfaceIndex == 0
			|| setsockopt(candidate, IPPROTO_IP, IP_UNICAST_IF,
				reinterpret_cast<const char*>(&networkInterfaceIndex),
				sizeof(networkInterfaceIndex)) != 0) {
			DebugLogWarning(_T("PCP: Unable to select route interface %u (error %u)"),
				nInterfaceIndex, WSAGetLastError());
			closesocket(candidate);
			return false;
		}

		sockaddr_in local;
		memset(&local, 0, sizeof(local));
		local.sin_family = AF_INET;
		local.sin_port = htons(localSourcePort);
		local.sin_addr.s_addr = clientIP;
		if (bind(candidate, reinterpret_cast<sockaddr*>(&local),
				sizeof(local)) == 0) {
			sock = candidate;
			break;
		}

		const int bindError = WSAGetLastError();
		closesocket(candidate);
		if (bindError == WSAEADDRINUSE || bindError == WSAEACCES) {
			DebugLogWarning(_T("PCP: Local request endpoint %u unavailable; trying next"),
				localSourcePort);
			continue;
		}
		DebugLogWarning(_T("PCP: Unable to bind request to selected interface (error %u)"),
			bindError);
		return false;
	}
	m_activeExchangeId.store(exchangeId, std::memory_order_release);
	ScopedActivePcpExchange activeExchange(
		m_activeExchangeId, exchangeId);

	sockaddr_in destination;
	memset(&destination, 0, sizeof(destination));
	destination.sin_family = AF_INET;
	destination.sin_port = htons(PCP_PORT);
	destination.sin_addr.s_addr = nGatewayIP;
	natmap::PcpResponseExpectation expectation{};
	memcpy(expectation.source_address.data(), &nGatewayIP,
		expectation.source_address.size());
	expectation.source_port = PCP_PORT;
	expectation.request_id = exchangeId;
	expectation.nonce = request.nonce;

	bool succeeded = false;
	// Bounded variant of RFC 6887 section 8.1.1 exponential
	// retransmission. The 7.7-second jittered maximum fits the refresh timer.
	for (uint8 attempt = 0;
		natmap::PcpExchangeTimeoutMilliseconds(attempt) != 0
			&& !m_bAbortDiscovery; ++attempt) {
		if (sendto(sock, reinterpret_cast<const char*>(packet),
			static_cast<int>(packetSize), 0,
			reinterpret_cast<sockaddr*>(&destination), sizeof(destination))
			!= static_cast<int>(packetSize))
			continue;

		const DWORD waitTime = JitteredTimeout(
			natmap::PcpExchangeTimeoutMilliseconds(attempt));
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
			if (received <= 0 || source.sin_family != AF_INET)
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
			natmap::PcpResponseObservation observation{};
			memcpy(observation.source_address.data(),
				&source.sin_addr.s_addr,
				observation.source_address.size());
			observation.source_port = ntohs(source.sin_port);
			observation.active_request_id =
				m_activeExchangeId.load(std::memory_order_acquire);
			observation.nonce = candidate.nonce;
			observation.shutdown =
				m_bAbortDiscovery.load(
					std::memory_order_acquire)
				|| (!bDeletion
					&& m_bShuttingDown.load(
						std::memory_order_acquire));
			const natmap::PcpResponseGuardStatus guardStatus =
				natmap::ValidatePcpResponseObservation(
					expectation, observation);
			if (guardStatus
				!= natmap::PcpResponseGuardStatus::Valid) {
				DebugLogWarning(_T("PCP: Ignoring guarded MAP response, status=%u"),
					static_cast<unsigned>(guardStatus));
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
				succeeded = natmap::EvaluatePcpCleanupCommit(
					true, guardStatus, true,
					candidate.lifetime_seconds)
					== natmap::PcpCleanupCommitStatus::Commit;
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

bool CUPnPImplPCP::MapPort(uint32 nGatewayIP, uint32 nInterfaceIndex,
	const std::array<uint8, 16>& clientAddress,
	natmap::Transport transport, uint16 nPrivatePort,
	uint16 nSuggestedExternalPort,
	const std::array<uint8, 16>& suggestedExternalAddress,
	uint32 nLifetime, natmap::PcpMappingIdentity& identity,
	natmap::PcpMapProjection& projection)
{
	if (identity.IsEmpty()) {
		std::array<uint8, 12> nonce{};
		if (!GenerateNonce(nonce)
			|| natmap::InitializePcpMappingIdentity(
				identity, transport, nPrivatePort, nonce)
				!= natmap::PcpIdentityStatus::Valid)
			return false;
	} else if (natmap::ValidatePcpMappingIdentity(
			identity, transport, nPrivatePort)
		!= natmap::PcpIdentityStatus::Valid)
		return false;

	natmap::PcpMapRequest request;
	request.lifetime_seconds = nLifetime;
	request.client_ip = clientAddress;
	request.nonce = identity.nonce;
	request.protocol = identity.transport == natmap::Transport::Tcp
		? PCP_PROTOCOL_TCP : PCP_PROTOCOL_UDP;
	request.internal_port = identity.internal_port;
	request.suggested_external_port = nSuggestedExternalPort;
	request.suggested_external_ip = suggestedExternalAddress;
	natmap::PcpMapResponse response;
	if (!ExchangeMap(
			nGatewayIP, nInterfaceIndex, request, response, false))
		return false;
	const natmap::PcpMapProjectionResult projected =
		natmap::ProjectPcpMapResponse(
			identity, nSuggestedExternalPort, response);
	if (!projected.IsProjected()) {
		DebugLogWarning(_T("PCP: MAP response failed exact projection (status=%u)"),
			static_cast<unsigned>(projected.status));
		return false;
	}
	projection = projected.value;

	DebugLog(_T("PCP: Mapped %s port %hu -> %hu (lifetime %us)"),
		projection.transport == natmap::Transport::Tcp
			? _T("TCP") : _T("UDP"), identity.internal_port,
		projection.granted_external_port,
		projection.lifetime_seconds);
	return true;
}

bool CUPnPImplPCP::UnmapPort(uint32 nGatewayIP, uint32 nInterfaceIndex,
	const std::array<uint8, 16>& clientAddress,
	const natmap::PcpMappingIdentity& identity)
{
	if (!identity.IsValid())
		return false;
	natmap::PcpMapRequest request;
	request.client_ip = clientAddress;
	request.nonce = identity.nonce;
	request.protocol = identity.transport == natmap::Transport::Tcp
		? PCP_PROTOCOL_TCP : PCP_PROTOCOL_UDP;
	request.internal_port = identity.internal_port;
	natmap::PcpMapResponse response;
	const bool result = ExchangeMap(
		nGatewayIP, nInterfaceIndex, request, response, true);
	if (result)
		DebugLog(_T("PCP: Unmapped %s port %hu"),
			identity.transport == natmap::Transport::Tcp
				? _T("TCP") : _T("UDP"), identity.internal_port);
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
	if (!m_pOwner->IsCurrentMappingOperation(m_operation)
		|| m_pOwner->m_bShuttingDown.load(std::memory_order_acquire))
		return 0;

	CSingleLock lock(&m_pOwner->m_mutBusy);
	if (!lock.Lock(0) || m_pOwner->m_bAbortDiscovery)
		return 0;

	const natmap::PcpRouteBindingSelection route =
		natmap::SelectPcpRouteBinding(
			m_operation.local_address, m_operation.gateway_address,
			m_operation.interface_index);
	uint32 selectedGateway = 0;
	if (!route.IsSelected()) {
		DebugLogWarning(_T("PCP: Request has no valid, atomic IPv4 route pair (status=%u)"),
			static_cast<unsigned>(route.status));
		m_pOwner->m_nDiagnosticStage = UPNP_DIAG_NO_GATEWAY;
		m_pOwner->m_bUPnPPortsForwarded = TRIS_FALSE;
		m_pOwner->SendResultIfLifecycleLive(m_operation);
		return 0;
	}
	memcpy(&selectedGateway, route.binding.gateway_address.data(),
		sizeof(selectedGateway));

	if (m_pOwner->m_bCheckAndRefresh
		&& (m_pOwner->m_dwGatewayIP != selectedGateway
			|| m_pOwner->m_dwInterfaceIndex
				!= route.binding.interface_index
			|| m_pOwner->m_clientAddress != route.binding.client_address)) {
		DebugLogWarning(_T("PCP: Refusing refresh because the route-bound gateway/client pair changed"));
		m_pOwner->m_nDiagnosticStage = UPNP_DIAG_NO_GATEWAY;
		m_pOwner->m_bUPnPPortsForwarded = TRIS_FALSE;
		m_pOwner->SendResultIfLifecycleLive(m_operation);
		return 0;
	}

	if (!m_pOwner->m_bCheckAndRefresh) {
		m_pOwner->m_dwGatewayIP = selectedGateway;
		m_pOwner->m_dwInterfaceIndex =
			route.binding.interface_index;
		m_pOwner->m_clientAddress = route.binding.client_address;
		if (!m_pOwner->DeletePorts(true)) {
			DebugLogWarning(_T("PCP: Refusing a new MAP while exact cleanup remains pending"));
			m_pOwner->m_nDiagnosticStage = UPNP_DIAG_OWNERSHIP_PERSISTENCE;
			m_pOwner->m_bUPnPPortsForwarded = TRIS_FALSE;
			m_pOwner->SendResultIfLifecycleLive(m_operation);
			return 0;
		}
	}

	const uint32 leaseTime = 7200;
	const bool udpRequired = m_pOwner->m_nUDPPort != 0;
	const bool initialOperation = !m_pOwner->m_bCheckAndRefresh;
	natmap::PcpPairTransaction pairTransaction(
		udpRequired, initialOperation);
	natmap::PcpMapProjection tcpProjection;
	const uint16 suggestedTCP = m_pOwner->m_bCheckAndRefresh
		? m_pOwner->m_nExternalTCPPort : m_pOwner->m_nTCPPort;
	const std::array<uint8, 16> suggestedTCPAddress =
		m_pOwner->m_bCheckAndRefresh ? m_pOwner->m_tcpExternalAddress
			: std::array<uint8, 16>();
	m_pOwner->m_nDiagnosticStage = UPNP_DIAG_TCP_MAPPING;
	bool succeeded = m_pOwner->MapPort(m_pOwner->m_dwGatewayIP,
		m_pOwner->m_dwInterfaceIndex,
		m_pOwner->m_clientAddress, natmap::Transport::Tcp,
		m_pOwner->m_nTCPPort, suggestedTCP,
		suggestedTCPAddress, leaseTime, m_pOwner->m_tcpIdentity,
		tcpProjection);
	if (succeeded
		&& !pairTransaction.StageTcp(tcpProjection)) {
		DebugLogWarning(_T("PCP: Refusing a TCP projection that cannot enter the atomic pair"));
		succeeded = false;
	}
	if (!succeeded)
		pairTransaction.RecordTcpFailure();

	if (!succeeded && initialOperation
		&& m_pOwner->m_tcpIdentity.IsValid()) {
		if (m_pOwner->UnmapPort(m_pOwner->m_dwGatewayIP,
			m_pOwner->m_dwInterfaceIndex,
			m_pOwner->m_clientAddress,
			m_pOwner->m_tcpIdentity))
			m_pOwner->m_tcpIdentity.Clear();
	}

	if (succeeded && udpRequired) {
		natmap::PcpMapProjection udpProjection;
		const uint16 suggestedUDP = m_pOwner->m_bCheckAndRefresh
			? m_pOwner->m_nExternalUDPPort : m_pOwner->m_nUDPPort;
		const std::array<uint8, 16> suggestedUDPAddress =
			m_pOwner->m_bCheckAndRefresh ? m_pOwner->m_udpExternalAddress
				: std::array<uint8, 16>();
		m_pOwner->m_nDiagnosticStage = UPNP_DIAG_UDP_MAPPING;
		const bool udpMapped = m_pOwner->MapPort(
			m_pOwner->m_dwGatewayIP,
			m_pOwner->m_dwInterfaceIndex,
			m_pOwner->m_clientAddress, natmap::Transport::Udp,
			m_pOwner->m_nUDPPort, suggestedUDP,
			suggestedUDPAddress, leaseTime, m_pOwner->m_udpIdentity,
			udpProjection);
		succeeded = udpMapped
			&& pairTransaction.StageUdp(udpProjection);
		if (!succeeded) {
			pairTransaction.RecordUdpFailure();
			natmap::PcpMappingIdentity rollbackIdentity{};
			if (pairTransaction.GetTcpRollbackIdentity(
					rollbackIdentity)
				&& m_pOwner->UnmapPort(m_pOwner->m_dwGatewayIP,
				m_pOwner->m_dwInterfaceIndex,
				m_pOwner->m_clientAddress, rollbackIdentity))
				m_pOwner->m_tcpIdentity.Clear();
		}
	}

	const bool operationStale =
		!m_pOwner->IsCurrentMappingOperation(m_operation);
	const bool lifecycleStopping =
		m_pOwner->m_bAbortDiscovery.load(
			std::memory_order_acquire)
		|| m_pOwner->m_bShuttingDown.load(
			std::memory_order_acquire);
	if (succeeded && (operationStale || lifecycleStopping)) {
		if (initialOperation && operationStale
			&& !lifecycleStopping) {
			if (m_pOwner->m_udpIdentity.IsValid()
				&& m_pOwner->UnmapPort(
					m_pOwner->m_dwGatewayIP,
					m_pOwner->m_dwInterfaceIndex,
					m_pOwner->m_clientAddress,
					m_pOwner->m_udpIdentity))
				m_pOwner->m_udpIdentity.Clear();
			if (m_pOwner->m_tcpIdentity.IsValid()
				&& m_pOwner->UnmapPort(
					m_pOwner->m_dwGatewayIP,
					m_pOwner->m_dwInterfaceIndex,
					m_pOwner->m_clientAddress,
					m_pOwner->m_tcpIdentity))
				m_pOwner->m_tcpIdentity.Clear();
		}
		succeeded = false;
	}

	natmap::PcpPairCommit pairCommit{};
	if (succeeded)
		succeeded = pairTransaction.TryCommit(pairCommit);
	if (succeeded) {
		m_pOwner->m_nRequestedTCPExternalPort =
			pairCommit.tcp.requested_external_port;
		m_pOwner->m_nExternalTCPPort =
			pairCommit.tcp.granted_external_port;
		m_pOwner->m_tcpExternalAddress =
			EncodeMappedV4(pairCommit.tcp.external_address);
		m_pOwner->m_dwMappingLeaseLifetime =
			natmap::PcpEffectiveLifetime(
				pairCommit.tcp.lifetime_seconds);
		m_pOwner->m_dwMapperEpoch = pairCommit.tcp.epoch;
		m_pOwner->m_dwMappingExternalIP =
			NetworkOrderV4(pairCommit.tcp.external_address);
		if (pairCommit.has_udp) {
			m_pOwner->m_nRequestedUDPExternalPort =
				pairCommit.udp.requested_external_port;
			m_pOwner->m_nExternalUDPPort =
				pairCommit.udp.granted_external_port;
			m_pOwner->m_udpExternalAddress =
				EncodeMappedV4(pairCommit.udp.external_address);
			m_pOwner->m_dwMappingLeaseLifetime = min(
				m_pOwner->m_dwMappingLeaseLifetime,
				natmap::PcpEffectiveLifetime(
					pairCommit.udp.lifetime_seconds));
			m_pOwner->m_dwMapperEpoch = pairCommit.udp.epoch;
		}
	} else if (initialOperation) {
		m_pOwner->m_nRequestedTCPExternalPort = 0;
		m_pOwner->m_nRequestedUDPExternalPort = 0;
		m_pOwner->m_nExternalTCPPort = 0;
		m_pOwner->m_nExternalUDPPort = 0;
		m_pOwner->m_dwMappingExternalIP = 0;
		m_pOwner->m_dwMappingLeaseLifetime = 0;
		m_pOwner->m_dwMapperEpoch = 0;
		m_pOwner->m_tcpExternalAddress.fill(0);
		m_pOwner->m_udpExternalAddress.fill(0);
	}

	if (succeeded && m_pOwner->m_nTCPWebPort != 0) {
		natmap::PcpMapProjection webProjection;
		const uint16 suggestedWeb = m_pOwner->m_bCheckAndRefresh
			? m_pOwner->m_nExternalTCPWebPort : m_pOwner->m_nTCPWebPort;
		const std::array<uint8, 16> suggestedWebAddress =
			m_pOwner->m_bCheckAndRefresh ? m_pOwner->m_webExternalAddress
				: std::array<uint8, 16>();
		if (m_pOwner->MapPort(m_pOwner->m_dwGatewayIP,
			m_pOwner->m_dwInterfaceIndex,
			m_pOwner->m_clientAddress, natmap::Transport::Tcp,
			m_pOwner->m_nTCPWebPort, suggestedWeb,
			suggestedWebAddress, leaseTime, m_pOwner->m_webIdentity,
			webProjection)) {
			m_pOwner->m_nRequestedWebExternalPort =
				webProjection.requested_external_port;
			m_pOwner->m_nExternalTCPWebPort =
				webProjection.granted_external_port;
			m_pOwner->m_webExternalAddress =
				EncodeMappedV4(webProjection.external_address);
		}
	}

	{
		std::lock_guard<std::mutex> lifecycleLock(
			m_pOwner->m_lifecycleMutex);
		const bool lifecycleLive =
			!m_pOwner->m_bAbortDiscovery.load(
				std::memory_order_acquire)
			&& !m_pOwner->m_bShuttingDown.load(
				std::memory_order_acquire);
		if (lifecycleLive) {
			m_pOwner->m_bUPnPPortsForwarded =
				succeeded ? TRIS_TRUE : TRIS_FALSE;
			if (succeeded) {
				m_pOwner->m_bSucceededOnce = true;
				m_pOwner->m_nDiagnosticStage = UPNP_DIAG_SUCCESS;
			} else if (m_pOwner->m_nDiagnosticStage
				== UPNP_DIAG_TCP_MAPPING)
				m_pOwner->m_nDiagnosticStage =
					UPNP_DIAG_PROTOCOL_UNAVAILABLE;
			const bool partialIdentityRemains =
				m_pOwner->m_tcpIdentity.IsValid()
				|| m_pOwner->m_udpIdentity.IsValid()
				|| m_pOwner->m_webIdentity.IsValid();
			const bool resultPublished =
				m_pOwner->SendResultMessage(m_operation);
			if ((succeeded && resultPublished)
				|| (!succeeded && !partialIdentityRemains))
				m_pOwner->m_initialMappingInFlight.store(
					false, std::memory_order_release);
		}
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
		m_initialMappingInFlight.store(false, std::memory_order_release);
		m_bUPnPPortsForwarded = TRIS_FALSE;
		m_nDiagnosticStage = UPNP_DIAG_PROTOCOL_UNAVAILABLE;
		DebugLogError(_T("PCP: Unable to create discovery thread"));
		SendResultIfLifecycleLive(CaptureMappingOperation());
		return;
	}
	m_hThreadHandle = thread->m_hThread;
	thread->SetValues(this);
	thread->ResumeThread();
}
