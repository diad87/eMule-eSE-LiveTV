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
	, m_hThreadHandle(NULL)
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
	CSingleLock lockTest(&m_mutBusy);
	return lockTest.Lock(0);
}

void CUPnPImplNATPMP::StopAsyncFind()
{
	if (m_hThreadHandle != NULL) {
		m_bAbortDiscovery = true;
		CSingleLock lockTest(&m_mutBusy);
		if (!lockTest.Lock(7000)) {
			DebugLogError(_T("NAT-PMP: Waiting for discovery thread to quit failed"));
			if (m_hThreadHandle != NULL)
				DebugLogError(::TerminateThread(m_hThreadHandle, 0) ? _T("...OK") : _T("...Failed"));
		} else
			DebugLog(_T("NAT-PMP: Aborted discovery thread"));
		m_hThreadHandle = NULL;
	}
	m_bAbortDiscovery = false;
}

void CUPnPImplNATPMP::DeletePorts()
{
	if (m_bSucceededOnce && m_dwGatewayIP != 0) {
		m_nOldUDPPort = m_nUDPPort;
		m_nOldTCPPort = m_nTCPPort;
		m_nOldTCPWebPort = m_nTCPWebPort;
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
		if (m_dwGatewayIP != 0) {
			if (m_nOldTCPPort != 0)
				UnmapPort(m_dwGatewayIP, m_nOldTCPPort, true);
			if (m_nOldUDPPort != 0)
				UnmapPort(m_dwGatewayIP, m_nOldUDPPort, false);
			if (m_nOldTCPWebPort != 0)
				UnmapPort(m_dwGatewayIP, m_nOldTCPWebPort, true);
		}
		m_nOldTCPPort = 0;
		m_nOldUDPPort = 0;
		m_nOldTCPWebPort = 0;
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
	} else {
		m_nOldUDPPort = 0;
		m_nOldTCPPort = 0;
		m_nOldTCPWebPort = 0;
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
	m_bCheckAndRefresh = false;

	if (!m_bAbortDiscovery)
		StartThread();
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
	StartThread();
	return true;
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

bool CUPnPImplNATPMP::ReceiveExternalAddrResponse(SOCKET sock, uint32 gatewayIP,
	uint32 &nExternalIP, uint32 &nEpoch)
{
	// Response: [version(1), opcode(1), resultcode(2), epoch(4), externalIP(4)] = 12 bytes
	uint8 response[12];
	
	// Use select() to wait for response with timeout
	fd_set fds;
	FD_ZERO(&fds);
	FD_SET(sock, &fds);
	timeval tv;
	tv.tv_sec = 3;
	tv.tv_usec = 0;
	
	int nReady = select(0, &fds, NULL, NULL, &tv);
	if (nReady <= 0)
		return false;

	sockaddr_in source;
	memset(&source, 0, sizeof(source));
	int sourceLen = sizeof(source);
	int nRecv = recvfrom(sock, (char*)response, sizeof(response), 0,
		(sockaddr*)&source, &sourceLen);
	if (nRecv < 12)
		return false;
	if (source.sin_addr.s_addr != gatewayIP || source.sin_port != htons(NATPMP_PORT))
		return false;

	natmap::NatPmpExternalAddressResponse decoded;
	if (natmap::DecodeNatPmpExternalAddressResponse(response,
		static_cast<size_t>(nRecv), decoded) != natmap::NatPmpDecodeStatus::Ok
		|| decoded.result_code != NATPMP_RESULT_SUCCESS)
		return false;
	nExternalIP = decoded.external_ip_network_order;
	nEpoch = decoded.epoch;
	return true;
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

bool CUPnPImplNATPMP::ReceiveMapResponse(SOCKET sock, uint32 gatewayIP,
	uint16 nPrivatePort, bool bTCP, natmap::NatPmpMapResponse &decoded)
{
	// Response: [version(1), opcode(1), resultcode(2), epoch(4),
	//            internal_port(2), mapped_external_port(2), lifetime(4)] = 16 bytes
	uint8 response[16];

	fd_set fds;
	FD_ZERO(&fds);
	FD_SET(sock, &fds);
	timeval tv;
	tv.tv_sec = 3;
	tv.tv_usec = 0;

	int nReady = select(0, &fds, NULL, NULL, &tv);
	if (nReady <= 0)
		return false;

	sockaddr_in source;
	memset(&source, 0, sizeof(source));
	int sourceLen = sizeof(source);
	int nRecv = recvfrom(sock, (char*)response, sizeof(response), 0,
		(sockaddr*)&source, &sourceLen);
	if (nRecv < 16)
		return false;
	if (source.sin_addr.s_addr != gatewayIP || source.sin_port != htons(NATPMP_PORT))
		return false;

	const natmap::NatPmpTransport transport = bTCP
		? natmap::NatPmpTransport::Tcp : natmap::NatPmpTransport::Udp;
	const natmap::NatPmpDecodeStatus status = natmap::DecodeNatPmpMapResponse(
		response, static_cast<size_t>(nRecv), transport, nPrivatePort, decoded);
	if (status != natmap::NatPmpDecodeStatus::Ok)
		return false;
	if (decoded.result_code != NATPMP_RESULT_SUCCESS) {
		DebugLogWarning(_T("NAT-PMP: Map response error - result=%u"),
			(unsigned)decoded.result_code);
		return false;
	}
	return decoded.external_port != 0 && decoded.lifetime_seconds != 0;
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

	// RFC 6886 Section 3.3: Retry with doubling timeout (250ms, 500ms, 1s, 2s, 4s...)
	// We try up to 3 times
	for (int retry = 0; retry < 3 && !m_bAbortDiscovery; ++retry) {
		if (!SendMapRequest(sock, gatewayIP, nPrivatePort,
			nSuggestedExternalPort, bTCP, nLifetime)) {
			DebugLogWarning(_T("NAT-PMP: Failed to send map request for %s port %hu (attempt %d)"),
				bTCP ? _T("TCP") : _T("UDP"), nPrivatePort, retry + 1);
			continue;
		}

		natmap::NatPmpMapResponse candidate;
		if (ReceiveMapResponse(sock, gatewayIP, nPrivatePort, bTCP, candidate)) {
			DebugLog(_T("NAT-PMP: Successfully mapped %s port %hu -> %hu (lifetime %us)"),
				bTCP ? _T("TCP") : _T("UDP"), nPrivatePort,
				candidate.external_port, candidate.lifetime_seconds);
			response = candidate;
			bResult = true;
			break;
		}

		// Wait before retry (250ms * 2^retry)
		if (retry < 2)
			Sleep(250 << retry);
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
	if (SendMapRequest(sock, gatewayIP, nPort, 0, bTCP, 0)) {
		natmap::NatPmpMapResponse response;
		// Deletion success intentionally returns external port/lifetime zero,
		// so validate structure here instead of using ReceiveMapResponse().
		uint8 raw[16];
		fd_set fds; FD_ZERO(&fds); FD_SET(sock, &fds);
		timeval tv; tv.tv_sec = 3; tv.tv_usec = 0;
		if (select(0, &fds, NULL, NULL, &tv) > 0) {
			sockaddr_in source; memset(&source, 0, sizeof(source));
			int sourceLen = sizeof(source);
			const int nRecv = recvfrom(sock, (char*)raw, sizeof(raw), 0,
				(sockaddr*)&source, &sourceLen);
			const natmap::NatPmpTransport transport = bTCP
				? natmap::NatPmpTransport::Tcp : natmap::NatPmpTransport::Udp;
			bResult = source.sin_addr.s_addr == gatewayIP
				&& source.sin_port == htons(NATPMP_PORT)
				&& nRecv >= 16
				&& natmap::DecodeNatPmpMapResponse(raw, static_cast<size_t>(nRecv),
					transport, nPort, response) == natmap::NatPmpDecodeStatus::Ok
				&& response.result_code == NATPMP_RESULT_SUCCESS
				&& response.external_port == 0 && response.lifetime_seconds == 0;
		}
		if (bResult)
			DebugLog(_T("NAT-PMP: Successfully unmapped %s port %hu"), bTCP ? _T("TCP") : _T("UDP"), nPort);
	}

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

	bool bSucceeded = false;

	// Step 1: Find the default gateway
	if (!m_pOwner->m_bCheckAndRefresh) {
		m_pOwner->m_dwGatewayIP = CUPnPImplNATPMP::GetDefaultGateway();
		if (m_pOwner->m_dwGatewayIP == 0) {
			DebugLogWarning(_T("NAT-PMP: No default gateway found, aborting"));
			m_pOwner->m_bUPnPPortsForwarded = TRIS_FALSE;
			m_pOwner->SendResultMessage();
			return 0;
		}

		if (m_pOwner->m_bAbortDiscovery)
			return 0;

		// Step 2: Try to get external IP (this also tests if NAT-PMP is supported)
		SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		if (sock != INVALID_SOCKET) {
			if (m_pOwner->SendExternalAddrRequest(sock, m_pOwner->m_dwGatewayIP)) {
				uint32 nExternalIP = 0;
				uint32 nEpoch = 0;
				if (m_pOwner->ReceiveExternalAddrResponse(sock,
					m_pOwner->m_dwGatewayIP, nExternalIP, nEpoch)) {
					IN_ADDR extAddr;
					extAddr.S_un.S_addr = nExternalIP;
					m_pOwner->m_dwMappingExternalIP = nExternalIP;
					m_pOwner->m_dwMapperEpoch = nEpoch;
					DebugLog(_T("NAT-PMP: Gateway supports NAT-PMP! External IP: %S"), inet_ntoa(extAddr));
				} else {
					DebugLog(_T("NAT-PMP: Gateway did not respond to external address request - NAT-PMP may not be supported"));
					closesocket(sock);
					m_pOwner->m_bUPnPPortsForwarded = TRIS_FALSE;
					m_pOwner->SendResultMessage();
					return 0;
				}
			}
			closesocket(sock);
		}

		if (m_pOwner->m_bAbortDiscovery)
			return 0;

		// Delete old port mappings
		m_pOwner->DeletePorts(true);
	}

	// Step 3: Map ports (2-hour lease, will be refreshed by CheckAndRefresh)
	const uint32 nLeaseTime = 7200; // 2 hours

	natmap::NatPmpMapResponse tcpResponse;
	const uint16 nSuggestedTCP = m_pOwner->m_bCheckAndRefresh
		? m_pOwner->m_nExternalTCPPort : m_pOwner->m_nTCPPort;
	bSucceeded = m_pOwner->MapPort(m_pOwner->m_dwGatewayIP,
		m_pOwner->m_nTCPPort, nSuggestedTCP, true, nLeaseTime, tcpResponse);
	if (bSucceeded) {
		m_pOwner->m_nExternalTCPPort = tcpResponse.external_port;
		m_pOwner->m_dwMappingLeaseLifetime = tcpResponse.lifetime_seconds;
		m_pOwner->m_dwMapperEpoch = tcpResponse.epoch;
	}
	if (bSucceeded && m_pOwner->m_nUDPPort != 0) {
		natmap::NatPmpMapResponse udpResponse;
		const uint16 nSuggestedUDP = m_pOwner->m_bCheckAndRefresh
			? m_pOwner->m_nExternalUDPPort : m_pOwner->m_nUDPPort;
		bSucceeded = m_pOwner->MapPort(m_pOwner->m_dwGatewayIP,
			m_pOwner->m_nUDPPort, nSuggestedUDP, false, nLeaseTime, udpResponse);
		if (bSucceeded) {
			m_pOwner->m_nExternalUDPPort = udpResponse.external_port;
			m_pOwner->m_dwMappingLeaseLifetime = min(
				m_pOwner->m_dwMappingLeaseLifetime, udpResponse.lifetime_seconds);
			m_pOwner->m_dwMapperEpoch = udpResponse.epoch;
		} else {
			m_pOwner->UnmapPort(m_pOwner->m_dwGatewayIP, m_pOwner->m_nTCPPort, true);
			m_pOwner->m_nExternalTCPPort = 0;
		}
	}

	if (bSucceeded && m_pOwner->m_nTCPWebPort != 0) {
		natmap::NatPmpMapResponse webResponse;
		const uint16 nSuggestedWeb = m_pOwner->m_bCheckAndRefresh
			? m_pOwner->m_nExternalTCPWebPort : m_pOwner->m_nTCPWebPort;
		if (m_pOwner->MapPort(m_pOwner->m_dwGatewayIP,
			m_pOwner->m_nTCPWebPort, nSuggestedWeb, true, nLeaseTime, webResponse))
			m_pOwner->m_nExternalTCPWebPort = webResponse.external_port;
	}

	if (!m_pOwner->m_bAbortDiscovery) {
		if (bSucceeded) {
			m_pOwner->m_bUPnPPortsForwarded = TRIS_TRUE;
			m_pOwner->m_bSucceededOnce = true;
		} else
			m_pOwner->m_bUPnPPortsForwarded = TRIS_FALSE;
		m_pOwner->SendResultMessage();
	}
	return 0;
}

void CUPnPImplNATPMP::StartThread()
{
	CStartDiscoveryThread *pThread = (CStartDiscoveryThread*)AfxBeginThread(
		RUNTIME_CLASS(CStartDiscoveryThread), THREAD_PRIORITY_NORMAL, 0, CREATE_SUSPENDED);
	m_hThreadHandle = pThread->m_hThread;
	pThread->SetValues(this);
	pThread->ResumeThread();
}
