//this file is part of eMule
//Copyright (C)2002-2024 Merkur ( strEmail.Format("%s@%s", "devteam", "emule-project.net") / https://www.emule-project.net )
//
//This program is free software; you can redistribute it and/or
//modify it under the terms of the GNU General Public License
//as published by the Free Software Foundation; either
//version 2 of the License, or (at your option) any later version.
//
//This program is distributed in the hope that it will be useful,
//but WITHOUT ANY WARRANTY; without even the implied warranty of
//MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//GNU General Public License for more details.
//
//You should have received a copy of the GNU General Public License
//along with this program; if not, write to the Free Software
//Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

// NAT-PMP (RFC 6886) implementation for automatic port forwarding
// NAT-PMP is a simple UDP-based protocol for configuring NAT port mappings.
// It's more reliable than UPnP for supported routers because:
//   1) No XML/SOAP overhead - just simple binary UDP packets
//   2) No multicast discovery needed - talks directly to the default gateway
//   3) More predictable behavior across different router implementations
//
// Protocol summary (RFC 6886):
//   - Client sends UDP packets to port 5351 on the default gateway
//   - External address request: 2 bytes (version=0, opcode=0)
//   - Port mapping request: 12 bytes (version, opcode, reserved, internal port, 
//     external port suggestion, lifetime in seconds)
//   - Responses include result code, epoch time, and mapped port/lifetime

#include "StdAfx.h"
#include "emule.h"
#include "preferences.h"
#include "UPnPImplNATPMP.h"
#include "Log.h"
#include "OtherFunctions.h"
#include "natmap/natpmp_codec.h"

#include <iphlpapi.h>  // for GetBestRoute / GetAdaptersInfo

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

CMutex CUPnPImplNATPMP::m_mutBusy;

CUPnPImplNATPMP::CUPnPImplNATPMP()
	: m_dwGatewayIP(0)
	, m_dwOldGatewayIP(0)
	, m_pThread(NULL)
	, m_bSucceededOnce(false)
	, m_bAbortDiscovery(false)
{
	m_nOldUDPPort = 0;
	m_nOldTCPPort = 0;
	m_nOldTCPWebPort = 0;
}

CUPnPImplNATPMP::~CUPnPImplNATPMP()
{
	StopAsyncFind();
}

bool CUPnPImplNATPMP::IsReady()
{
	if (m_bAbortDiscovery)
		return false;
	ReleaseFinishedThread();
	if (m_pThread != NULL)
		return false;
	CSingleLock lockTest(&m_mutBusy);
	return lockTest.Lock(0);
}

void CUPnPImplNATPMP::StopAsyncFind()
{
	if (m_pThread != NULL) {
		m_bAbortDiscovery = true;
		DWORD nWaitResult = WaitForSingleObject(m_pThread->m_hThread, 7000);
		if (nWaitResult != WAIT_OBJECT_0) {
			DebugLogError(_T("NAT-PMP: Waiting for discovery thread to quit failed"));
			if (nWaitResult == WAIT_TIMEOUT
				&& ::TerminateThread(m_pThread->m_hThread, 0)) {
				nWaitResult = WaitForSingleObject(m_pThread->m_hThread, 1000);
				DebugLogError(_T("NAT-PMP: Forced discovery thread termination"));
			}
		}
		if (nWaitResult == WAIT_OBJECT_0) {
			DebugLog(_T("NAT-PMP: Aborted discovery thread"));
			delete m_pThread;
			m_pThread = NULL;
		} else {
			DebugLogError(_T("NAT-PMP: Discovery thread is still active"));
		}
	}
	if (m_pThread == NULL)
		m_bAbortDiscovery = false;
}

void CUPnPImplNATPMP::DeletePorts()
{
	if (m_bSucceededOnce && m_dwGatewayIP != 0) {
		m_nOldUDPPort = m_nUDPPort;
		m_nOldTCPPort = m_nTCPPort;
		m_nOldTCPWebPort = m_nTCPWebPort;
		m_dwOldGatewayIP = m_dwGatewayIP;
	}
	m_nUDPPort = 0;
	m_nTCPPort = 0;
	m_nTCPWebPort = 0;
	m_nExternalUDPPort = 0;
	m_nExternalTCPPort = 0;
	m_nExternalTCPWebPort = 0;
	m_dwMappingExternalIP = 0;
	m_dwMappingLeaseLifetime = 0;
	m_dwMapperEpoch = 0;
	m_bUPnPPortsForwarded = TRIS_FALSE;
	DeletePorts(false);
}

void CUPnPImplNATPMP::DeletePorts(bool bSkipLock)
{
	CSingleLock lockTest(&m_mutBusy);
	if (bSkipLock || lockTest.Lock(0)) {
		const uint32 nGatewayIP = m_dwOldGatewayIP != 0
			? m_dwOldGatewayIP : m_dwGatewayIP;
		if (nGatewayIP != 0) {
			if (m_nOldTCPPort != 0)
				UnmapPort(nGatewayIP, m_nOldTCPPort, true);
			if (m_nOldUDPPort != 0)
				UnmapPort(nGatewayIP, m_nOldUDPPort, false);
			if (m_nOldTCPWebPort != 0)
				UnmapPort(nGatewayIP, m_nOldTCPWebPort, true);
		}
		m_nOldTCPPort = 0;
		m_nOldUDPPort = 0;
		m_nOldTCPWebPort = 0;
		m_dwOldGatewayIP = 0;
	} else
		DebugLogError(_T("NAT-PMP: Unable to remove port mappings - busy"));
}

void CUPnPImplNATPMP::StartDiscovery(uint16 nTCPPort, uint16 nUDPPort, uint16 nTCPWebPort)
{
	DebugLog(_T("NAT-PMP: Using NAT-PMP (RFC 6886) implementation"));

	if (m_bSucceededOnce && m_dwGatewayIP != 0) {
		m_nOldUDPPort = m_nUDPPort;
		m_nOldTCPPort = m_nTCPPort;
		m_nOldTCPWebPort = m_nTCPWebPort;
		m_dwOldGatewayIP = m_dwGatewayIP;
	} else {
		m_nOldUDPPort = 0;
		m_nOldTCPPort = 0;
		m_nOldTCPWebPort = 0;
		m_dwOldGatewayIP = 0;
	}

	m_nUDPPort = nUDPPort;
	m_nTCPPort = nTCPPort;
	m_nTCPWebPort = nTCPWebPort;
	m_nExternalUDPPort = nUDPPort;
	m_nExternalTCPPort = nTCPPort;
	m_nExternalTCPWebPort = nTCPWebPort;
	m_dwMappingExternalIP = 0;
	m_dwMappingLeaseLifetime = 0;
	m_dwMapperEpoch = 0;
	m_bUPnPPortsForwarded = TRIS_UNKNOWN;
	m_nDiagnosticStage = UPNP_DIAG_DISCOVERING;
	m_bCheckAndRefresh = false;

	if (!m_bAbortDiscovery && !StartThread()) {
		m_bUPnPPortsForwarded = TRIS_FALSE;
		SendResultMessage();
	}
}

bool CUPnPImplNATPMP::CheckAndRefresh()
{
	if (m_bAbortDiscovery || !m_bSucceededOnce || m_dwGatewayIP == 0 || m_nTCPPort == 0) {
		DebugLog(_T("NAT-PMP: Not refreshing ports - not previously mapped"));
		return false;
	}
	if (!IsReady()) {
		DebugLog(_T("NAT-PMP: Not refreshing ports - already busy"));
		return false;
	}

	DebugLog(_T("NAT-PMP: Checking and refreshing port mappings"));
	m_bCheckAndRefresh = true;
	if (StartThread())
		return true;
	m_bCheckAndRefresh = false;
	return false;
}

//////////////////////////////////////////////////////////////////////////////
// NAT-PMP protocol implementation (RFC 6886)
//////////////////////////////////////////////////////////////////////////////

uint32 CUPnPImplNATPMP::GetDefaultGateway()
{
	// Use GetBestRoute to find the default gateway (route to 0.0.0.0)
	MIB_IPFORWARDROW route;
	memset(&route, 0, sizeof(route));

	DWORD dwResult = GetBestRoute(0, 0, &route); // destination=0.0.0.0, source=any
	if (dwResult == NO_ERROR && route.dwForwardNextHop != 0) {
		IN_ADDR addr;
		addr.S_un.S_addr = route.dwForwardNextHop;
		DebugLog(_T("NAT-PMP: Default gateway detected: %S"), inet_ntoa(addr));
		return route.dwForwardNextHop;
	}

	DebugLogWarning(_T("NAT-PMP: Could not determine default gateway"));
	return 0;
}

bool CUPnPImplNATPMP::SendExternalAddrRequest(SOCKET sock, uint32 gatewayIP)
{
	// External address request: [version=0, opcode=0]
	uint8 request[2];
	if (!natmap::EncodeNatPmpExternalAddressRequest(request, sizeof(request)))
		return false;

	sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(NATPMP_PORT);
	addr.sin_addr.s_addr = gatewayIP;

	int nSent = sendto(sock, (const char*)request, sizeof(request), 0,
		(sockaddr*)&addr, sizeof(addr));
	return (nSent == sizeof(request));
}

CUPnPImplNATPMP::EReceiveResult
CUPnPImplNATPMP::ReceiveExternalAddrResponse(SOCKET sock, uint32 gatewayIP,
	DWORD nTimeoutMs, uint32 &nExternalIP, uint32 &nEpoch)
{
	// Response: [version(1), opcode(1), resultcode(2), epoch(4), externalIP(4)] = 12 bytes
	const DWORD nStarted = GetTickCount();
	while (!m_bAbortDiscovery) {
		const DWORD nElapsed = GetTickCount() - nStarted;
		if (nElapsed >= nTimeoutMs)
			return RECEIVE_TIMEOUT;

		const DWORD nRemaining = nTimeoutMs - nElapsed;
		fd_set fds;
		FD_ZERO(&fds);
		FD_SET(sock, &fds);
		timeval tv;
		tv.tv_sec = nRemaining / 1000;
		tv.tv_usec = (nRemaining % 1000) * 1000;
		const int nReady = select(0, &fds, NULL, NULL, &tv);
		if (nReady == 0)
			return RECEIVE_TIMEOUT;
		if (nReady == SOCKET_ERROR)
			return RECEIVE_TIMEOUT;

		uint8 response[64];
		sockaddr_in source;
		memset(&source, 0, sizeof(source));
		int sourceLen = sizeof(source);
		const int nRecv = recvfrom(sock, (char*)response, sizeof(response), 0,
			(sockaddr*)&source, &sourceLen);
		// RFC 6886 requires validation of the gateway address. Do not reject
		// otherwise valid replies from firmware that uses an ephemeral source
		// port instead of 5351.
		if (nRecv <= 0 || source.sin_addr.s_addr != gatewayIP)
			continue;

		natmap::NatPmpExternalAddressResponse decoded;
		if (natmap::DecodeNatPmpExternalAddressResponse(response,
			static_cast<size_t>(nRecv), decoded) != natmap::NatPmpDecodeStatus::Ok)
			continue;
		if (decoded.result_code != NATPMP_RESULT_SUCCESS) {
			DebugLogWarning(_T("NAT-PMP: External address request rejected - result=%u"),
				(unsigned)decoded.result_code);
			return RECEIVE_REJECTED;
		}
		if (decoded.external_ip_network_order == 0)
			continue;
		nExternalIP = decoded.external_ip_network_order;
		nEpoch = decoded.epoch;
		return RECEIVE_SUCCESS;
	}
	return RECEIVE_ABORTED;
}

bool CUPnPImplNATPMP::QueryExternalAddress(uint32 gatewayIP,
	uint32 &nExternalIP, uint32 &nEpoch)
{
	SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sock == INVALID_SOCKET)
		return false;

	bool bResult = false;
	const DWORD anTimeouts[] = { 250, 500, 1000 };
	for (size_t nAttempt = 0; nAttempt < _countof(anTimeouts)
		&& !m_bAbortDiscovery; ++nAttempt) {
		if (!SendExternalAddrRequest(sock, gatewayIP)) {
			DebugLogWarning(_T("NAT-PMP: Failed to send external address request (error=%d)"),
				WSAGetLastError());
			break;
		}
		const EReceiveResult eResult = ReceiveExternalAddrResponse(sock,
			gatewayIP, anTimeouts[nAttempt], nExternalIP, nEpoch);
		if (eResult == RECEIVE_SUCCESS) {
			bResult = true;
			break;
		}
		if (eResult == RECEIVE_REJECTED || eResult == RECEIVE_ABORTED)
			break;
	}

	closesocket(sock);
	return bResult;
}

bool CUPnPImplNATPMP::SendMapRequest(SOCKET sock, uint32 gatewayIP,
	uint16 nPrivatePort, uint16 nSuggestedExternalPort, bool bTCP, uint32 nLifetime)
{
	// Map request: [version(1), opcode(1), reserved(2), internal_port(2),
	//               suggested_external_port(2), lifetime(4)] = 12 bytes
	uint8 request[12];
	const natmap::NatPmpTransport transport = bTCP
		? natmap::NatPmpTransport::Tcp : natmap::NatPmpTransport::Udp;
	if (!natmap::EncodeNatPmpMapRequest(transport, nPrivatePort,
		nSuggestedExternalPort, nLifetime, request, sizeof(request)))
		return false;

	sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(NATPMP_PORT);
	addr.sin_addr.s_addr = gatewayIP;

	int nSent = sendto(sock, (const char*)request, sizeof(request), 0,
		(sockaddr*)&addr, sizeof(addr));
	return (nSent == sizeof(request));
}

CUPnPImplNATPMP::EReceiveResult
CUPnPImplNATPMP::ReceiveMapResponse(SOCKET sock, uint32 gatewayIP,
	uint16 nPrivatePort, bool bTCP, bool bDeletion, DWORD nTimeoutMs,
	natmap::NatPmpMapResponse &decoded)
{
	// Response: [version(1), opcode(1), resultcode(2), epoch(4),
	//            internal_port(2), mapped_external_port(2), lifetime(4)] = 16 bytes
	const natmap::NatPmpTransport transport = bTCP
		? natmap::NatPmpTransport::Tcp : natmap::NatPmpTransport::Udp;
	const DWORD nStarted = GetTickCount();
	while (!m_bAbortDiscovery) {
		const DWORD nElapsed = GetTickCount() - nStarted;
		if (nElapsed >= nTimeoutMs)
			return RECEIVE_TIMEOUT;

		const DWORD nRemaining = nTimeoutMs - nElapsed;
		fd_set fds;
		FD_ZERO(&fds);
		FD_SET(sock, &fds);
		timeval tv;
		tv.tv_sec = nRemaining / 1000;
		tv.tv_usec = (nRemaining % 1000) * 1000;
		const int nReady = select(0, &fds, NULL, NULL, &tv);
		if (nReady == 0)
			return RECEIVE_TIMEOUT;
		if (nReady == SOCKET_ERROR)
			return RECEIVE_TIMEOUT;

		uint8 response[64];
		sockaddr_in source;
		memset(&source, 0, sizeof(source));
		int sourceLen = sizeof(source);
		const int nRecv = recvfrom(sock, (char*)response, sizeof(response), 0,
			(sockaddr*)&source, &sourceLen);
		// Validate the gateway address as required by RFC 6886, while allowing
		// non-standard response source ports used by some router firmware.
		if (nRecv <= 0 || source.sin_addr.s_addr != gatewayIP)
			continue;

		natmap::NatPmpMapResponse candidate;
		const natmap::NatPmpDecodeStatus status =
			natmap::DecodeNatPmpMapResponse(response,
				static_cast<size_t>(nRecv), transport, nPrivatePort, candidate);
		if (status != natmap::NatPmpDecodeStatus::Ok)
			continue;
		if (candidate.result_code != NATPMP_RESULT_SUCCESS) {
			DebugLogWarning(_T("NAT-PMP: %s response rejected - result=%u"),
				bDeletion ? _T("Unmap") : _T("Map"),
				(unsigned)candidate.result_code);
			if (candidate.result_code == NATPMP_RESULT_OUT_OF_RESOURCES)
				m_nDiagnosticStage = UPNP_DIAG_TABLE_FULL;
			return RECEIVE_REJECTED;
		}

		const bool bValidSuccess = bDeletion
			? candidate.external_port == 0 && candidate.lifetime_seconds == 0
			: candidate.external_port != 0 && candidate.lifetime_seconds != 0;
		if (!bValidSuccess)
			continue;
		decoded = candidate;
		return RECEIVE_SUCCESS;
	}
	return RECEIVE_ABORTED;
}

bool CUPnPImplNATPMP::MapPort(uint32 gatewayIP, uint16 nPrivatePort,
	uint16 nSuggestedExternalPort, bool bTCP, uint32 nLifetime,
	natmap::NatPmpMapResponse &response)
{
	SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sock == INVALID_SOCKET) {
		DebugLogError(_T("NAT-PMP: Failed to create UDP socket"));
		return false;
	}

	bool bResult = false;

	// RFC 6886 section 3.1 starts at 250 ms and doubles the response
	// interval. Four attempts keep a TCP+UDP refresh inside eMule's 10-second
	// refresh deadline while tolerating slow or lossy consumer routers.
	const DWORD anTimeouts[] = { 250, 500, 1000, 2000 };
	for (size_t nAttempt = 0; nAttempt < _countof(anTimeouts)
		&& !m_bAbortDiscovery; ++nAttempt) {
		if (!SendMapRequest(sock, gatewayIP, nPrivatePort,
			nSuggestedExternalPort, bTCP, nLifetime)) {
			DebugLogWarning(_T("NAT-PMP: Failed to send map request for %s port %hu (error=%d)"),
				bTCP ? _T("TCP") : _T("UDP"), nPrivatePort,
				WSAGetLastError());
			break;
		}

		natmap::NatPmpMapResponse candidate;
		const EReceiveResult eResult = ReceiveMapResponse(sock, gatewayIP,
			nPrivatePort, bTCP, false, anTimeouts[nAttempt], candidate);
		if (eResult == RECEIVE_SUCCESS) {
			DebugLog(_T("NAT-PMP: Successfully mapped %s port %hu -> %hu (lifetime %us)"),
				bTCP ? _T("TCP") : _T("UDP"), nPrivatePort,
				candidate.external_port, candidate.lifetime_seconds);
			response = candidate;
			bResult = true;
			break;
		}
		if (eResult == RECEIVE_REJECTED || eResult == RECEIVE_ABORTED)
			break;
	}

	closesocket(sock);
	return bResult;
}

bool CUPnPImplNATPMP::UnmapPort(uint32 gatewayIP, uint16 nPort, bool bTCP)
{
	// Unmap = map request with lifetime=0
	SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sock == INVALID_SOCKET)
		return false;

	bool bResult = false;
	const DWORD anTimeouts[] = { 250, 500 };
	for (size_t nAttempt = 0; nAttempt < _countof(anTimeouts)
		&& !m_bAbortDiscovery; ++nAttempt) {
		if (!SendMapRequest(sock, gatewayIP, nPort, 0, bTCP, 0))
			break;
		natmap::NatPmpMapResponse response;
		const EReceiveResult eResult = ReceiveMapResponse(sock, gatewayIP,
			nPort, bTCP, true, anTimeouts[nAttempt], response);
		if (eResult == RECEIVE_SUCCESS) {
			bResult = true;
			break;
		}
		if (eResult == RECEIVE_REJECTED || eResult == RECEIVE_ABORTED)
			break;
	}
	if (bResult)
		DebugLog(_T("NAT-PMP: Successfully unmapped %s port %hu"),
			bTCP ? _T("TCP") : _T("UDP"), nPort);

	closesocket(sock);
	return bResult;
}

//////////////////////////////////////////////////////////////////////////////
/// CUPnPImplNATPMP::CStartDiscoveryThread
//////////////////////////////////////////////////////////////////////////////
typedef CUPnPImplNATPMP::CStartDiscoveryThread CStartDiscoveryThread;
IMPLEMENT_DYNCREATE(CStartDiscoveryThread, CWinThread)

CUPnPImplNATPMP::CStartDiscoveryThread::CStartDiscoveryThread()
	: m_pOwner(NULL)
{
}

BOOL CUPnPImplNATPMP::CStartDiscoveryThread::InitInstance()
{
	InitThreadLocale();
	return TRUE;
}

int CUPnPImplNATPMP::CStartDiscoveryThread::Run()
{
	DbgSetThreadName("CUPnPImplNATPMP::CStartDiscoveryThread");
	if (!m_pOwner)
		return 0;

	CSingleLock sLock(&m_pOwner->m_mutBusy);
	if (!sLock.Lock(0)) {
		DebugLogWarning(_T("NAT-PMP: Discovery thread failed to acquire lock"));
		return 0;
	}

	if (m_pOwner->m_bAbortDiscovery)
		return 0;

	const bool bWasRefresh = m_pOwner->m_bCheckAndRefresh;
	const uint32 nPreviousGatewayIP = m_pOwner->m_dwGatewayIP;
	const uint32 nGatewayIP = CUPnPImplNATPMP::GetDefaultGateway();
	if (nGatewayIP == 0) {
		DebugLogWarning(_T("NAT-PMP: No default gateway found, aborting"));
		m_pOwner->m_nDiagnosticStage = UPNP_DIAG_NO_GATEWAY;
		m_pOwner->m_bUPnPPortsForwarded = TRIS_FALSE;
		m_pOwner->SendResultMessage();
		return 0;
	}
	if (bWasRefresh && nPreviousGatewayIP != 0
		&& nPreviousGatewayIP != nGatewayIP) {
		IN_ADDR oldAddress;
		oldAddress.S_un.S_addr = nPreviousGatewayIP;
		const CString strOldGateway(inet_ntoa(oldAddress));
		IN_ADDR newAddress;
		newAddress.S_un.S_addr = nGatewayIP;
		DebugLogWarning(_T("NAT-PMP: Default gateway changed from %s to %S during refresh"),
			strOldGateway.GetString(), inet_ntoa(newAddress));
		m_pOwner->m_dwMappingExternalIP = 0;
	}
	m_pOwner->m_dwGatewayIP = nGatewayIP;

	if (m_pOwner->m_bAbortDiscovery)
		return 0;

	// Querying the public address is useful, but a dropped or non-conforming
	// address response must not prevent a valid mapping exchange.
	m_pOwner->m_nDiagnosticStage = UPNP_DIAG_EXTERNAL_ADDRESS;
	uint32 nExternalIP = 0;
	uint32 nExternalEpoch = 0;
	if (m_pOwner->QueryExternalAddress(nGatewayIP, nExternalIP,
		nExternalEpoch)) {
		if (natmap::NatPmpEpochAppearsReset(m_pOwner->m_dwMapperEpoch,
			nExternalEpoch)) {
			DebugLogWarning(_T("NAT-PMP: Gateway epoch reset detected (%u -> %u)"),
				(unsigned)m_pOwner->m_dwMapperEpoch, (unsigned)nExternalEpoch);
		}
		m_pOwner->m_dwMappingExternalIP = nExternalIP;
		m_pOwner->m_dwMapperEpoch = nExternalEpoch;
		IN_ADDR extAddr;
		extAddr.S_un.S_addr = nExternalIP;
		DebugLog(_T("NAT-PMP: External IP: %S"), inet_ntoa(extAddr));
	} else {
		DebugLogWarning(_T("NAT-PMP: No usable external address response; trying MAP directly"));
	}

	if (m_pOwner->m_bAbortDiscovery)
		return 0;

	if (!bWasRefresh)
		m_pOwner->DeletePorts(true);

	// Map ports with the RFC-recommended two-hour lease. Each response's
	// granted lifetime drives the independent application lease scheduler.
	const uint32 nLeaseTime = 7200; // 2 hours

	natmap::NatPmpMapResponse tcpResponse;
	const uint16 nSuggestedTCP = bWasRefresh
		? m_pOwner->m_nExternalTCPPort : m_pOwner->m_nTCPPort;
	m_pOwner->m_nDiagnosticStage = UPNP_DIAG_TCP_MAPPING;
	bool bSucceeded = m_pOwner->MapPort(nGatewayIP,
		m_pOwner->m_nTCPPort, nSuggestedTCP, true, nLeaseTime, tcpResponse);
	if (bSucceeded) {
		if (natmap::NatPmpEpochAppearsReset(m_pOwner->m_dwMapperEpoch,
			tcpResponse.epoch)) {
			DebugLogWarning(_T("NAT-PMP: Mapping table reset before TCP MAP (%u -> %u)"),
				(unsigned)m_pOwner->m_dwMapperEpoch,
				(unsigned)tcpResponse.epoch);
		}
		m_pOwner->m_nExternalTCPPort = tcpResponse.external_port;
		m_pOwner->m_dwMappingLeaseLifetime = tcpResponse.lifetime_seconds;
		m_pOwner->m_dwMapperEpoch = tcpResponse.epoch;
	}
	if (bSucceeded && m_pOwner->m_nUDPPort != 0) {
		natmap::NatPmpMapResponse udpResponse;
		bool bUdpMapped = false;
		const uint16 nSuggestedUDP = bWasRefresh
			? m_pOwner->m_nExternalUDPPort : m_pOwner->m_nUDPPort;
		m_pOwner->m_nDiagnosticStage = UPNP_DIAG_UDP_MAPPING;
		bSucceeded = m_pOwner->MapPort(nGatewayIP,
			m_pOwner->m_nUDPPort, nSuggestedUDP, false, nLeaseTime, udpResponse);
		if (bSucceeded) {
			bUdpMapped = true;
			if (natmap::NatPmpEpochAppearsReset(tcpResponse.epoch,
				udpResponse.epoch)) {
				// The router lost its table after granting TCP but before UDP.
				// Do not report a false success; the normal bounded refresh
				// retry will recreate both mappings.
				DebugLogWarning(_T("NAT-PMP: Mapping table reset between TCP and UDP MAP"));
				bSucceeded = false;
			} else {
				m_pOwner->m_nExternalUDPPort = udpResponse.external_port;
				m_pOwner->m_dwMappingLeaseLifetime = min(
					m_pOwner->m_dwMappingLeaseLifetime,
					udpResponse.lifetime_seconds);
				m_pOwner->m_dwMapperEpoch = udpResponse.epoch;
			}
		}
		// On initial discovery roll back a half-created pair. During a
		// refresh, keep either successfully renewed mapping alive while the
		// lease scheduler retries the full pair.
		if (!bSucceeded && !bWasRefresh) {
			m_pOwner->UnmapPort(nGatewayIP,
				m_pOwner->m_nTCPPort, true);
			if (bUdpMapped)
				m_pOwner->UnmapPort(nGatewayIP,
					m_pOwner->m_nUDPPort, false);
			m_pOwner->m_nExternalTCPPort = 0;
			m_pOwner->m_nExternalUDPPort = 0;
		}
	}

	if (bSucceeded && m_pOwner->m_nTCPWebPort != 0) {
		natmap::NatPmpMapResponse webResponse;
		const uint16 nSuggestedWeb = bWasRefresh
			? m_pOwner->m_nExternalTCPWebPort : m_pOwner->m_nTCPWebPort;
		if (m_pOwner->MapPort(nGatewayIP, m_pOwner->m_nTCPWebPort,
			nSuggestedWeb, true, nLeaseTime, webResponse)) {
			m_pOwner->m_nExternalTCPWebPort = webResponse.external_port;
			m_pOwner->m_dwMappingLeaseLifetime = min(
				m_pOwner->m_dwMappingLeaseLifetime,
				webResponse.lifetime_seconds);
			m_pOwner->m_dwMapperEpoch = webResponse.epoch;
		} else if (!bWasRefresh) {
			m_pOwner->m_nExternalTCPWebPort = 0;
		}
	}

	if (!m_pOwner->m_bAbortDiscovery) {
		if (bSucceeded) {
			m_pOwner->m_bUPnPPortsForwarded = TRIS_TRUE;
			m_pOwner->m_bSucceededOnce = true;
			m_pOwner->m_nDiagnosticStage = UPNP_DIAG_SUCCESS;
		} else {
			m_pOwner->m_bUPnPPortsForwarded = TRIS_FALSE;
			if (m_pOwner->m_nDiagnosticStage != UPNP_DIAG_TABLE_FULL)
				m_pOwner->m_nDiagnosticStage =
					UPNP_DIAG_PROTOCOL_UNAVAILABLE;
		}
		m_pOwner->SendResultMessage();
	}
	return 0;
}

void CUPnPImplNATPMP::ReleaseFinishedThread()
{
	if (m_pThread != NULL
		&& WaitForSingleObject(m_pThread->m_hThread, 0) == WAIT_OBJECT_0) {
		delete m_pThread;
		m_pThread = NULL;
	}
}

bool CUPnPImplNATPMP::StartThread()
{
	ReleaseFinishedThread();
	if (m_pThread != NULL) {
		DebugLogWarning(_T("NAT-PMP: Discovery thread is already running"));
		return false;
	}

	CStartDiscoveryThread *pThread = static_cast<CStartDiscoveryThread*>(
		AfxBeginThread(RUNTIME_CLASS(CStartDiscoveryThread),
			THREAD_PRIORITY_NORMAL, 0, CREATE_SUSPENDED));
	if (pThread == NULL) {
		DebugLogError(_T("NAT-PMP: Unable to create discovery thread"));
		return false;
	}
	pThread->m_bAutoDelete = FALSE;
	pThread->SetValues(this);
	m_pThread = pThread;
	if (pThread->ResumeThread() == static_cast<DWORD>(-1)) {
		DebugLogError(_T("NAT-PMP: Unable to start discovery thread"));
		delete m_pThread;
		m_pThread = NULL;
		return false;
	}
	return true;
}
