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
#include "natmap/natpmp_product_policy.h"
#include "Log.h"
#include "OtherFunctions.h"
#include "natmap/natpmp_codec.h"
#include "natmap/natpmp_epoch_policy.h"
#include "natmap/natpmp_gateway_policy.h"
#include "natmap/natpmp_pair_transaction.h"
#include "../cryptopp/sha.h"

#include <bcrypt.h>

#pragma comment(lib, "bcrypt.lib")

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

CMutex CUPnPImplNATPMP::m_mutBusy;

namespace {

uint64 NatPmpMonotonicSeconds()
{
	// Extend the SDK-baseline 32-bit tick count. NAT-PMP operations are
	// serialized by m_mutBusy, so this clock is observed by one worker at a
	// time and remains monotonic across the 49.7-day wrap.
	static DWORD previous = 0;
	static uint64 epoch = 0;
	const DWORD current = ::GetTickCount();
	if (current < previous)
		epoch += (1ull << 32);
	previous = current;
	return (epoch + current) / 1000;
}

}

CUPnPImplNATPMP::CUPnPImplNATPMP()
	: m_dwGatewayIP(0)
	, m_dwOldGatewayIP(0)
	, m_dwInterfaceIndex(0)
	, m_dwOldInterfaceIndex(0)
	, m_pThread(NULL)
	, m_bSucceededOnce(false)
	, m_bAbortDiscovery(false)
	, m_bMapperEpochObservationValid(false)
	, m_nMapperEpochObservedAtSeconds(0)
	, m_ownerToken(0)
{
	for (unsigned attempt = 0;
		attempt < 2 && m_ownerToken == 0; ++attempt) {
		if (BCryptGenRandom(NULL,
			reinterpret_cast<PUCHAR>(&m_ownerToken),
			static_cast<ULONG>(sizeof(m_ownerToken)),
			BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) {
			m_ownerToken = 0;
			continue;
		}
	}
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
	DeletePortsForGeneration(0);
}

void CUPnPImplNATPMP::DeletePortsForGeneration(uint64 generation)
{
	DeletePorts(false, generation);
	m_nUDPPort = 0;
	m_nTCPPort = 0;
	m_nTCPWebPort = 0;
	m_nExternalUDPPort = 0;
	m_nExternalTCPPort = 0;
	m_nExternalTCPWebPort = 0;
	m_dwMappingExternalIP = 0;
	m_dwMappingLeaseLifetime = 0;
	m_dwMapperEpoch = 0;
	m_bMapperEpochReset = false;
	m_bMapperEpochObservationValid = false;
	m_nMapperEpochObservedAtSeconds = 0;
	m_bUPnPPortsForwarded = TRIS_FALSE;
}

void CUPnPImplNATPMP::DeletePorts(
	bool bSkipLock, uint64 generation)
{
	CSingleLock lockTest(&m_mutBusy);
	if (bSkipLock || lockTest.Lock(0)) {
		std::array<std::uint8_t, 4> gatewayAddress{};
		memcpy(gatewayAddress.data(), &m_dwGatewayIP,
			gatewayAddress.size());
		natmap::NatPmpCleanupContext context{};
		context.gateway_address = gatewayAddress;
		context.interface_index = m_dwInterfaceIndex;
		context.generation = natmap::ResolveNatPmpCleanupGeneration(
			m_cleanupProof, generation);
		context.observed_monotonic_seconds =
			NatPmpMonotonicSeconds();
		const natmap::NatPmpCleanupPlan cleanup =
			natmap::TakeNatPmpCleanupPlan(
				m_cleanupProof, context);
		for (size_t index = 0;
			index < cleanup.mapping_count; ++index) {
			const natmap::NatPmpCleanupMapping& mapping =
				cleanup.mappings[index];
			UnmapPort(
				m_dwGatewayIP, m_dwInterfaceIndex,
				mapping.internal_port,
				mapping.transport
					== natmap::NatPmpTransport::Tcp);
		}
		m_nOldTCPPort = 0;
		m_nOldUDPPort = 0;
		m_nOldTCPWebPort = 0;
		m_dwOldGatewayIP = 0;
		m_dwOldInterfaceIndex = 0;
	} else
		DebugLogError(_T("NAT-PMP: Unable to remove port mappings - busy"));
}

natmap::MapperResultData CUPnPImplNATPMP::BuildMapperResultData(
	const MappingOperationContext& operation) const
{
	natmap::MapperResultData data =
		CUPnPImpl::BuildMapperResultData(operation);
	if (data.status == natmap::MappingStatus::Created
			|| data.status == natmap::MappingStatus::Renewed) {
		const natmap::NatPmpOwnershipPreimage preimage =
			natmap::BuildNatPmpOwnershipPreimage(
				m_cleanupProof, data,
				operation.request.topology_generation,
				m_ownerToken);
		if (!preimage.valid)
			return data;
		CryptoPP::SHA256 hash;
		hash.Update(reinterpret_cast<const CryptoPP::byte*>(
			preimage.bytes.data()), preimage.size);
		std::array<std::uint8_t, 32> digest = {};
		hash.Final(reinterpret_cast<CryptoPP::byte*>(digest.data()));
		natmap::ApplyNatPmpOwnershipDigest(
			preimage, digest, m_cleanupProof,
			operation.request.topology_generation, data);
	}
	return data;
}

void CUPnPImplNATPMP::StartDiscovery(uint16 nTCPPort, uint16 nUDPPort, uint16 nTCPWebPort)
{
	UNREFERENCED_PARAMETER(nTCPWebPort);
	DebugLog(_T("NAT-PMP: Using NAT-PMP (RFC 6886) implementation"));

	if (m_bSucceededOnce && m_dwGatewayIP != 0) {
		m_nOldUDPPort = m_nUDPPort;
		m_nOldTCPPort = m_nTCPPort;
		m_nOldTCPWebPort = m_nTCPWebPort;
		m_dwOldGatewayIP = m_dwGatewayIP;
		m_dwOldInterfaceIndex = m_dwInterfaceIndex;
	} else {
		m_nOldUDPPort = 0;
		m_nOldTCPPort = 0;
		m_nOldTCPWebPort = 0;
		m_dwOldGatewayIP = 0;
		m_dwOldInterfaceIndex = 0;
	}

	m_nUDPPort = nUDPPort;
	m_nTCPPort = nTCPPort;
	m_nTCPWebPort = 0;
	m_nExternalUDPPort = nUDPPort;
	m_nExternalTCPPort = nTCPPort;
	m_nExternalTCPWebPort = 0;
	m_dwMappingExternalIP = 0;
	m_dwMappingLeaseLifetime = 0;
	m_dwMapperEpoch = 0;
	m_bMapperEpochReset = false;
	m_bMapperEpochObservationValid = false;
	m_nMapperEpochObservedAtSeconds = 0;
	m_bUPnPPortsForwarded = TRIS_UNKNOWN;
	m_nDiagnosticStage = UPNP_DIAG_DISCOVERING;
	m_bCheckAndRefresh = false;

	if (!m_bAbortDiscovery && !StartThread()) {
		m_bUPnPPortsForwarded = TRIS_FALSE;
		SendResultMessage(CaptureMappingOperation());
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

SOCKET CUPnPImplNATPMP::CreateRoutedSocket(uint32 interfaceIndex)
{
	if (interfaceIndex == 0
		|| interfaceIndex > natmap::kNatPmpMaximumInterfaceIndex)
		return INVALID_SOCKET;
	SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sock == INVALID_SOCKET)
		return INVALID_SOCKET;
	const DWORD networkInterfaceIndex = htonl(interfaceIndex);
	if (setsockopt(sock, IPPROTO_IP, IP_UNICAST_IF,
			reinterpret_cast<const char*>(&networkInterfaceIndex),
			sizeof(networkInterfaceIndex)) != 0) {
		DebugLogWarning(_T("NAT-PMP: Unable to bind request to interface %u (error=%u)"),
			interfaceIndex, WSAGetLastError());
		closesocket(sock);
		return INVALID_SOCKET;
	}
	return sock;
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
	DWORD nTimeoutMs, natmap::NatPmpExternalAddressResponse &decoded)
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

		natmap::NatPmpExternalAddressResponse candidate;
		if (natmap::DecodeNatPmpExternalAddressResponse(response,
			static_cast<size_t>(nRecv), candidate)
				!= natmap::NatPmpDecodeStatus::Ok)
			continue;
		decoded = candidate;
		if (candidate.result_code != NATPMP_RESULT_SUCCESS) {
			DebugLogWarning(_T("NAT-PMP: External address request rejected - result=%u"),
				(unsigned)candidate.result_code);
			return RECEIVE_REJECTED;
		}
		return RECEIVE_SUCCESS;
	}
	return RECEIVE_ABORTED;
}

natmap::NatPmpExternalAddressDecision
CUPnPImplNATPMP::QueryExternalAddress(
	uint32 gatewayIP, uint32 interfaceIndex)
{
	SOCKET sock = CreateRoutedSocket(interfaceIndex);
	if (sock == INVALID_SOCKET)
		return natmap::ClassifyNatPmpExternalAddress(false, {});

	bool responseReceived = false;
	natmap::NatPmpExternalAddressResponse response;
	const DWORD anTimeouts[] = { 250, 500, 1000 };
	for (size_t nAttempt = 0; nAttempt < _countof(anTimeouts)
		&& !m_bAbortDiscovery; ++nAttempt) {
		if (!SendExternalAddrRequest(sock, gatewayIP)) {
			DebugLogWarning(_T("NAT-PMP: Failed to send external address request (error=%d)"),
				WSAGetLastError());
			break;
		}
		const EReceiveResult eResult = ReceiveExternalAddrResponse(
			sock, gatewayIP, anTimeouts[nAttempt], response);
		if (eResult == RECEIVE_SUCCESS
			|| eResult == RECEIVE_REJECTED) {
			responseReceived = true;
			break;
		}
		if (eResult == RECEIVE_ABORTED)
			break;
	}

	closesocket(sock);
	return natmap::ClassifyNatPmpExternalAddress(
		responseReceived, response);
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
		// Preserve correlated epoch evidence even when the operation is
		// rejected or the success payload is semantically unusable.
		decoded = candidate;
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
		return RECEIVE_SUCCESS;
	}
	return RECEIVE_ABORTED;
}

bool CUPnPImplNATPMP::MapPort(
	uint32 gatewayIP, uint32 interfaceIndex,
	uint16 nPrivatePort, uint16 nSuggestedExternalPort,
	bool bTCP, uint32 nLifetime,
	natmap::NatPmpMapResponse &response)
{
	response = natmap::NatPmpMapResponse{};
	SOCKET sock = CreateRoutedSocket(interfaceIndex);
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

		natmap::NatPmpMapResponse candidate{};
		const EReceiveResult eResult = ReceiveMapResponse(sock, gatewayIP,
			nPrivatePort, bTCP, false, anTimeouts[nAttempt], candidate);
		if (natmap::HasCorrelatedNatPmpMapObservation(
			candidate, nPrivatePort))
			response = candidate;
		if (eResult == RECEIVE_SUCCESS) {
			DebugLog(_T("NAT-PMP: Successfully mapped %s port %hu -> %hu (lifetime %us)"),
				bTCP ? _T("TCP") : _T("UDP"), nPrivatePort,
				candidate.external_port, candidate.lifetime_seconds);
			bResult = true;
			break;
		}
		if (eResult == RECEIVE_REJECTED || eResult == RECEIVE_ABORTED)
			break;
	}

	closesocket(sock);
	return bResult;
}

bool CUPnPImplNATPMP::UnmapPort(
	uint32 gatewayIP, uint32 interfaceIndex,
	uint16 nPort, bool bTCP)
{
	// Unmap = map request with lifetime=0
	SOCKET sock = CreateRoutedSocket(interfaceIndex);
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

	// The marker belongs to one completed mapper result only. Recompute it
	// for every attempt so an early failure cannot inherit a prior reset.
	m_pOwner->m_bMapperEpochReset = false;
	const bool bWasRefresh = m_pOwner->m_bCheckAndRefresh;
	const uint32 nPreviousGatewayIP = m_pOwner->m_dwGatewayIP;
	const uint32 nPreviousInterfaceIndex =
		m_pOwner->m_dwInterfaceIndex;
	const natmap::NatPmpGatewaySelection route =
		natmap::SelectNatPmpGateway(
			m_operation.gateway_address,
			m_operation.interface_index);
	uint32 nGatewayIP = 0;
	if (!route.IsSelected()) {
		DebugLogWarning(_T("NAT-PMP: Request has no valid route-bound gateway (status=%u)"),
			static_cast<unsigned>(route.status));
		m_pOwner->m_nDiagnosticStage = UPNP_DIAG_NO_GATEWAY;
		m_pOwner->m_bUPnPPortsForwarded = TRIS_FALSE;
		m_pOwner->SendResultMessage(m_operation);
		return 0;
	}
	memcpy(&nGatewayIP, route.gateway_address.data(),
		sizeof(nGatewayIP));
	const uint32 nInterfaceIndex = route.interface_index;
	if (bWasRefresh && nPreviousGatewayIP != 0
		&& (nPreviousGatewayIP != nGatewayIP
			|| nPreviousInterfaceIndex != nInterfaceIndex)) {
		IN_ADDR oldAddress;
		oldAddress.S_un.S_addr = nPreviousGatewayIP;
		const CString strOldGateway(inet_ntoa(oldAddress));
		IN_ADDR newAddress;
		newAddress.S_un.S_addr = nGatewayIP;
		DebugLogWarning(_T("NAT-PMP: Route changed from %s/%u to %S/%u during refresh"),
			strOldGateway.GetString(), nPreviousInterfaceIndex,
			inet_ntoa(newAddress), nInterfaceIndex);
		m_pOwner->m_nDiagnosticStage = UPNP_DIAG_NO_GATEWAY;
		m_pOwner->m_bUPnPPortsForwarded = TRIS_FALSE;
		m_pOwner->SendResultMessage(m_operation);
		return 0;
	}
	m_pOwner->m_dwGatewayIP = nGatewayIP;
	m_pOwner->m_dwInterfaceIndex = nInterfaceIndex;

	if (m_pOwner->m_bAbortDiscovery)
		return 0;

	// Snapshot the last address before querying. A refresh may reuse a
	// previously verified public address only when this query is lost or
	// rejected and the mapper epoch remains continuous.
	natmap::NatPmpExternalAddressResponse retainedResponse{};
	retainedResponse.result_code = NATPMP_RESULT_SUCCESS;
	retainedResponse.epoch = m_pOwner->m_dwMapperEpoch;
	retainedResponse.external_ip_network_order =
		m_pOwner->m_dwMappingExternalIP;
	const natmap::NatPmpExternalAddressDecision retainedAddress =
		natmap::ClassifyNatPmpExternalAddress(
			m_pOwner->m_dwMappingExternalIP != 0,
			retainedResponse);
	natmap::NatPmpEpochSequence epochSequence{};
	epochSequence.udp_required = m_pOwner->m_nUDPPort != 0;
	if (bWasRefresh && m_pOwner->m_bSucceededOnce
		&& m_pOwner->m_bMapperEpochObservationValid) {
		epochSequence.previous_snapshot.observed = true;
		epochSequence.previous_snapshot.accepted = true;
		epochSequence.previous_snapshot.epoch =
			retainedResponse.epoch;
		epochSequence.previous_snapshot.observed_at_seconds =
			m_pOwner->m_nMapperEpochObservedAtSeconds;
	}
	const uint64 nPreviousMappingEpochObservedAtSeconds =
		m_pOwner->m_nMapperEpochObservedAtSeconds;

	// Querying the public address is useful, but a dropped or non-conforming
	// address response must not prevent a valid mapping exchange.
	m_pOwner->m_nDiagnosticStage = UPNP_DIAG_EXTERNAL_ADDRESS;
	const natmap::NatPmpExternalAddressDecision externalAddress =
		m_pOwner->QueryExternalAddress(
			nGatewayIP, nInterfaceIndex);
	if (externalAddress.status
		!= natmap::NatPmpExternalAddressStatus::Missing) {
		epochSequence.external_address.observed = true;
		epochSequence.external_address.accepted =
			externalAddress.HasAddress();
		epochSequence.external_address.epoch =
			externalAddress.epoch;
		epochSequence.external_address.observed_at_seconds =
			NatPmpMonotonicSeconds();
	}
	const natmap::NatPmpEpochDecision externalEpochDecision =
		natmap::EvaluateNatPmpEpochSequence(epochSequence);
	if (externalEpochDecision.strongest_boundary
		== natmap::NatPmpEpochBoundary::ResetBeforeExternalAddress) {
		DebugLogWarning(_T("NAT-PMP: Gateway epoch reset detected before external-address (%u -> %u)"),
			(unsigned)retainedResponse.epoch,
			(unsigned)externalAddress.epoch);
	}
	if (externalAddress.HasAddress()) {
		uint32 nExternalIP = 0;
		memcpy(&nExternalIP, externalAddress.address.bytes.data(),
			sizeof(nExternalIP));
		m_pOwner->m_dwMappingExternalIP = nExternalIP;
		IN_ADDR extAddr;
		extAddr.S_un.S_addr = nExternalIP;
		DebugLog(_T("NAT-PMP: External IP: %S (status=%u)"),
			inet_ntoa(extAddr),
			static_cast<unsigned>(externalAddress.status));
	} else {
		DebugLogWarning(_T("NAT-PMP: External address unavailable (status=%u); trying MAP directly"),
			static_cast<unsigned>(externalAddress.status));
		if (externalAddress.status
			== natmap::NatPmpExternalAddressStatus::Invalid)
			m_pOwner->m_dwMappingExternalIP = 0;
	}
	if (externalEpochDecision.has_continuity_epoch) {
		m_pOwner->m_dwMapperEpoch =
			externalEpochDecision.continuity_epoch;
		m_pOwner->m_nMapperEpochObservedAtSeconds =
			externalEpochDecision.continuity_observed_at_seconds;
		m_pOwner->m_bMapperEpochObservationValid = true;
	}
	if (!externalAddress.should_attempt_map)
		return 0;

	if (m_pOwner->m_bAbortDiscovery)
		return 0;

	if (!bWasRefresh)
		m_pOwner->DeletePorts(
			true, m_operation.request.topology_generation);

	// Map ports with the RFC-recommended two-hour lease. Each response's
	// granted lifetime drives the independent application lease scheduler.
	const uint32 nLeaseTime = 7200; // 2 hours

	const uint16 nPreviousExternalTCPPort =
		m_pOwner->m_nExternalTCPPort;
	const uint16 nPreviousExternalUDPPort =
		m_pOwner->m_nExternalUDPPort;
	const uint32 nPreviousLeaseLifetime =
		m_pOwner->m_dwMappingLeaseLifetime;
	const uint32 nPreviousMappingEpoch =
		retainedResponse.epoch;
	const bool bUdpRequired = epochSequence.udp_required;
	const bool bInitialOperation = !bWasRefresh;
	natmap::NatPmpPairTransaction pairTransaction(
		bUdpRequired, bInitialOperation);

	natmap::NatPmpMapResponse tcpResponse;
	const uint16 nSuggestedTCP = bWasRefresh
		? m_pOwner->m_nExternalTCPPort : m_pOwner->m_nTCPPort;
	m_pOwner->m_nDiagnosticStage = UPNP_DIAG_TCP_MAPPING;
	const uint64 nTcpMapStartedAt = NatPmpMonotonicSeconds();
	const bool bTcpMapped = m_pOwner->MapPort(
		nGatewayIP, nInterfaceIndex,
		m_pOwner->m_nTCPPort, nSuggestedTCP, true, nLeaseTime, tcpResponse);
	const uint64 nTcpLeaseDeadline = bTcpMapped
		? natmap::ConservativeNatPmpLeaseDeadline(
			nTcpMapStartedAt, tcpResponse.lifetime_seconds)
		: 0;
	bool bSucceeded = bTcpMapped;
	if (natmap::HasCorrelatedNatPmpMapObservation(
		tcpResponse, m_pOwner->m_nTCPPort)) {
		epochSequence.tcp_map.observed = true;
		epochSequence.tcp_map.accepted = bTcpMapped;
		epochSequence.tcp_map.epoch = tcpResponse.epoch;
		epochSequence.tcp_map.observed_at_seconds =
			NatPmpMonotonicSeconds();
	}
	natmap::NatPmpEpochDecision epochDecision =
		natmap::EvaluateNatPmpEpochSequence(epochSequence);
	if (bSucceeded) {
		if (epochDecision.strongest_boundary
			== natmap::NatPmpEpochBoundary::ResetBeforeTcpMap) {
			DebugLogWarning(_T("NAT-PMP: Mapping table reset before TCP MAP (%u -> %u)"),
				(unsigned)m_pOwner->m_dwMapperEpoch,
				(unsigned)tcpResponse.epoch);
			// A retained address belongs to the old mapping table. Even a
			// fresh address response cannot be paired safely across this reset.
			m_pOwner->m_dwMappingExternalIP = 0;
		}
		natmap::NatPmpMapProjection tcpProjection{};
		tcpProjection.transport = natmap::NatPmpTransport::Tcp;
		tcpProjection.requested_external_port = nSuggestedTCP;
		tcpProjection.response = tcpResponse;
		bSucceeded = pairTransaction.StageTcp(tcpProjection);
	}
	if (!bSucceeded)
		pairTransaction.RecordTcpFailure();

	bool bUdpMapped = false;
	uint64 nUdpLeaseDeadline = 0;
	if (bSucceeded && bUdpRequired) {
		natmap::NatPmpMapResponse udpResponse;
		const uint16 nSuggestedUDP = bWasRefresh
			? m_pOwner->m_nExternalUDPPort : m_pOwner->m_nUDPPort;
		m_pOwner->m_nDiagnosticStage = UPNP_DIAG_UDP_MAPPING;
		const uint64 nUdpMapStartedAt = NatPmpMonotonicSeconds();
		bUdpMapped = m_pOwner->MapPort(
			nGatewayIP, nInterfaceIndex,
			m_pOwner->m_nUDPPort, nSuggestedUDP, false, nLeaseTime, udpResponse);
		if (bUdpMapped)
			nUdpLeaseDeadline =
				natmap::ConservativeNatPmpLeaseDeadline(
					nUdpMapStartedAt,
					udpResponse.lifetime_seconds);
		bSucceeded = bUdpMapped;
		const bool bUdpResponseObserved =
			natmap::HasCorrelatedNatPmpMapObservation(
				udpResponse, m_pOwner->m_nUDPPort);
		if (bUdpResponseObserved) {
			epochSequence.udp_map.observed = true;
			epochSequence.udp_map.accepted = bUdpMapped;
			epochSequence.udp_map.epoch = udpResponse.epoch;
			epochSequence.udp_map.observed_at_seconds =
				NatPmpMonotonicSeconds();
		}
		epochDecision =
			natmap::EvaluateNatPmpEpochSequence(epochSequence);
		if (bUdpMapped) {
			if (!epochDecision.pair_can_commit) {
				// The router lost its table after granting TCP but before UDP.
				// Do not report a false success; the normal bounded refresh
				// retry will recreate both mappings.
				DebugLogWarning(_T("NAT-PMP: Mapping table reset between TCP and UDP MAP"));
				bSucceeded = false;
			} else {
				natmap::NatPmpMapProjection udpProjection{};
				udpProjection.transport =
					natmap::NatPmpTransport::Udp;
				udpProjection.requested_external_port =
					nSuggestedUDP;
				udpProjection.response = udpResponse;
				bSucceeded =
					pairTransaction.StageUdp(udpProjection);
			}
		}
		if (!bSucceeded)
			pairTransaction.RecordUdpFailure();
	}
	epochDecision =
		natmap::EvaluateNatPmpEpochSequence(epochSequence);
	if (bSucceeded && !epochDecision.pair_can_commit) {
		pairTransaction.RecordUdpFailure();
		bSucceeded = false;
	}

	if (!bSucceeded) {
		const bool bResetBetweenPair =
			epochDecision.strongest_boundary
				== natmap::NatPmpEpochBoundary::ResetBetweenTcpAndUdp;
		if (bInitialOperation && !bResetBetweenPair) {
			natmap::NatPmpRollbackTarget tcpRollback{};
			if (pairTransaction.GetTcpRollbackTarget(tcpRollback)) {
				m_pOwner->UnmapPort(
					nGatewayIP, nInterfaceIndex,
					tcpRollback.internal_port,
					tcpRollback.transport
						== natmap::NatPmpTransport::Tcp);
			} else if (bTcpMapped) {
				m_pOwner->UnmapPort(
					nGatewayIP, nInterfaceIndex,
					m_pOwner->m_nTCPPort, true);
			}
		}
		if (bUdpMapped
			&& (bInitialOperation || bResetBetweenPair))
			m_pOwner->UnmapPort(
				nGatewayIP, nInterfaceIndex,
				m_pOwner->m_nUDPPort, false);
	}

	natmap::NatPmpPairCommit pairCommit{};
	if (bSucceeded)
		bSucceeded = pairTransaction.TryCommit(pairCommit);
	if (bSucceeded) {
		m_pOwner->m_nExternalTCPPort =
			pairCommit.tcp.response.external_port;
		m_pOwner->m_dwMappingLeaseLifetime =
			pairCommit.tcp.response.lifetime_seconds;
		m_pOwner->m_dwMapperEpoch =
			pairCommit.tcp.response.epoch;
		if (pairCommit.has_udp) {
			m_pOwner->m_nExternalUDPPort =
				pairCommit.udp.response.external_port;
			m_pOwner->m_dwMappingLeaseLifetime = min(
				m_pOwner->m_dwMappingLeaseLifetime,
				pairCommit.udp.response.lifetime_seconds);
		}
		if (epochDecision.has_continuity_epoch) {
			m_pOwner->m_dwMapperEpoch =
				epochDecision.continuity_epoch;
			m_pOwner->m_nMapperEpochObservedAtSeconds =
				epochDecision.continuity_observed_at_seconds;
			m_pOwner->m_bMapperEpochObservationValid = true;
		}
	} else {
		switch (natmap::ResolveNatPmpPairFailureDisposition(
			bInitialOperation,
			epochDecision.previous_pair_invalidated)) {
		case natmap::NatPmpPairFailureDisposition::PreservePrevious:
			m_pOwner->m_nExternalTCPPort =
				nPreviousExternalTCPPort;
			m_pOwner->m_nExternalUDPPort =
				nPreviousExternalUDPPort;
			m_pOwner->m_dwMappingLeaseLifetime =
				nPreviousLeaseLifetime;
			m_pOwner->m_dwMapperEpoch =
				epochDecision.has_continuity_epoch
					? epochDecision.continuity_epoch
					: nPreviousMappingEpoch;
			m_pOwner->m_nMapperEpochObservedAtSeconds =
				epochDecision.has_continuity_epoch
					? epochDecision.continuity_observed_at_seconds
					: nPreviousMappingEpochObservedAtSeconds;
			m_pOwner->m_bMapperEpochObservationValid =
				epochDecision.has_continuity_epoch ||
				epochSequence.previous_snapshot.observed;
			break;
		case natmap::NatPmpPairFailureDisposition::InvalidatePrevious:
			m_pOwner->m_cleanupProof =
				natmap::NatPmpCleanupProof{};
			m_pOwner->m_nExternalTCPPort = 0;
			m_pOwner->m_nExternalUDPPort = 0;
			m_pOwner->m_nExternalTCPWebPort = 0;
			m_pOwner->m_dwMappingLeaseLifetime = 0;
			m_pOwner->m_dwMappingExternalIP = 0;
			m_pOwner->m_dwMapperEpoch =
				epochDecision.has_continuity_epoch
					? epochDecision.continuity_epoch
					: nPreviousMappingEpoch;
			m_pOwner->m_nMapperEpochObservedAtSeconds =
				epochDecision.has_continuity_epoch
					? epochDecision.continuity_observed_at_seconds
					: nPreviousMappingEpochObservedAtSeconds;
			m_pOwner->m_bMapperEpochObservationValid =
				epochDecision.has_continuity_epoch ||
				epochSequence.previous_snapshot.observed;
			break;
		case natmap::NatPmpPairFailureDisposition::ClearProvisional:
		default:
			m_pOwner->m_nExternalTCPPort = 0;
			m_pOwner->m_nExternalUDPPort = 0;
			m_pOwner->m_dwMappingLeaseLifetime = 0;
			break;
		}
	}

	bool bWebEpochReset = false;
	bool bWebMappedForCleanup = false;
	uint64 nWebLeaseDeadline = 0;
	if (bSucceeded && m_pOwner->m_nTCPWebPort != 0) {
		natmap::NatPmpMapResponse webResponse;
		const uint16 nSuggestedWeb = bWasRefresh
			? m_pOwner->m_nExternalTCPWebPort : m_pOwner->m_nTCPWebPort;
		const uint64 nWebMapStartedAt = NatPmpMonotonicSeconds();
		const bool bWebMapped = m_pOwner->MapPort(
			nGatewayIP, nInterfaceIndex,
			m_pOwner->m_nTCPWebPort,
			nSuggestedWeb, true, nLeaseTime, webResponse);
		bWebMappedForCleanup = bWebMapped;
		if (bWebMapped)
			nWebLeaseDeadline =
				natmap::ConservativeNatPmpLeaseDeadline(
					nWebMapStartedAt,
					webResponse.lifetime_seconds);
		const bool bWebResponseObserved =
			natmap::HasCorrelatedNatPmpMapObservation(
				webResponse, m_pOwner->m_nTCPWebPort);
		natmap::NatPmpEpochDecision webEpochDecision{};
		if (bWebResponseObserved) {
			natmap::NatPmpEpochSequence webEpochSequence{};
			webEpochSequence.udp_required = false;
			if (m_pOwner->m_bMapperEpochObservationValid) {
				webEpochSequence.previous_snapshot.observed = true;
				webEpochSequence.previous_snapshot.accepted = true;
				webEpochSequence.previous_snapshot.epoch =
					m_pOwner->m_dwMapperEpoch;
				webEpochSequence.previous_snapshot.observed_at_seconds =
					m_pOwner->m_nMapperEpochObservedAtSeconds;
			}
			webEpochSequence.tcp_map.observed = true;
			webEpochSequence.tcp_map.accepted = bWebMapped;
			webEpochSequence.tcp_map.epoch = webResponse.epoch;
			webEpochSequence.tcp_map.observed_at_seconds =
				NatPmpMonotonicSeconds();
			webEpochDecision =
				natmap::EvaluateNatPmpEpochSequence(webEpochSequence);
			bWebEpochReset =
				webEpochDecision.strongest_boundary
					== natmap::NatPmpEpochBoundary::ResetBeforeTcpMap;
			if (webEpochDecision.has_continuity_epoch) {
				m_pOwner->m_dwMapperEpoch =
					webEpochDecision.continuity_epoch;
				m_pOwner->m_nMapperEpochObservedAtSeconds =
					webEpochDecision.continuity_observed_at_seconds;
				m_pOwner->m_bMapperEpochObservationValid = true;
			}
		}
		if (bWebEpochReset) {
				// The reset erased the already granted TCP/UDP mappings.
				// Remove the lone post-reset web mapping and fail the whole
				// attempt so no stale direct result can be published.
				DebugLogWarning(_T("NAT-PMP: Mapping table reset before web MAP"));
				bSucceeded = false;
				if (bWebMapped)
					m_pOwner->UnmapPort(
					nGatewayIP, nInterfaceIndex,
					m_pOwner->m_nTCPWebPort, true);
				m_pOwner->m_cleanupProof =
					natmap::NatPmpCleanupProof{};
				m_pOwner->m_nExternalTCPPort = 0;
				m_pOwner->m_nExternalUDPPort = 0;
				m_pOwner->m_nExternalTCPWebPort = 0;
				m_pOwner->m_dwMappingLeaseLifetime = 0;
		} else if (bWebMapped) {
				m_pOwner->m_nExternalTCPWebPort =
					webResponse.external_port;
				m_pOwner->m_dwMappingLeaseLifetime = min(
					m_pOwner->m_dwMappingLeaseLifetime,
					webResponse.lifetime_seconds);
		} else {
			if (!bWasRefresh)
				m_pOwner->m_nExternalTCPWebPort = 0;
		}
	}

	const bool bEpochInvalidatesAddress =
		bWebEpochReset ||
		(externalAddress.HasAddress()
			? !epochDecision.external_address_current
			: epochDecision.previous_pair_invalidated);
	const natmap::NatPmpExternalAddressDecision publishAddress =
		natmap::ResolveNatPmpPublishAddress(
			externalAddress, retainedAddress,
			bEpochInvalidatesAddress);
	m_pOwner->m_dwMappingExternalIP = 0;
	if (publishAddress.HasAddress())
		memcpy(&m_pOwner->m_dwMappingExternalIP,
			publishAddress.address.bytes.data(),
			sizeof(m_pOwner->m_dwMappingExternalIP));
	const bool bCanPublishDirect = publishAddress.can_publish_direct;
	const bool bObservedMapperReset =
		bWasRefresh &&
		(epochDecision.previous_pair_invalidated ||
		 bWebEpochReset);
	if (bSucceeded) {
		const bool bVisibleEndpointChange =
			!bWasRefresh ||
			nPreviousExternalTCPPort
				!= m_pOwner->m_nExternalTCPPort ||
			nPreviousExternalUDPPort
				!= m_pOwner->m_nExternalUDPPort ||
			retainedResponse.external_ip_network_order
				!= m_pOwner->m_dwMappingExternalIP;
		const uint64 cleanupGeneration =
			natmap::ResolveNatPmpCleanupGeneration(
				m_operation.request.topology_generation,
				pairCommit.has_udp, bCanPublishDirect,
				bObservedMapperReset, bVisibleEndpointChange);

		natmap::NatPmpCleanupProof proof{};
		proof.gateway_address = route.gateway_address;
		proof.interface_index = nInterfaceIndex;
		proof.generation = cleanupGeneration;
		proof.expires_monotonic_seconds = nTcpLeaseDeadline;
		if (pairCommit.has_udp)
			proof.expires_monotonic_seconds = min(
				proof.expires_monotonic_seconds,
				nUdpLeaseDeadline);
		if (bWebMappedForCleanup)
			proof.expires_monotonic_seconds = min(
				proof.expires_monotonic_seconds,
				nWebLeaseDeadline);
		proof.mappings[proof.mapping_count++] =
			natmap::NatPmpCleanupMapping{
				natmap::NatPmpTransport::Tcp,
				m_pOwner->m_nTCPPort,
				m_pOwner->m_nExternalTCPPort};
		if (pairCommit.has_udp)
			proof.mappings[proof.mapping_count++] =
				natmap::NatPmpCleanupMapping{
					natmap::NatPmpTransport::Udp,
					m_pOwner->m_nUDPPort,
					m_pOwner->m_nExternalUDPPort};
		if (bWebMappedForCleanup)
			proof.mappings[proof.mapping_count++] =
				natmap::NatPmpCleanupMapping{
					natmap::NatPmpTransport::Tcp,
					m_pOwner->m_nTCPWebPort,
					m_pOwner->m_nExternalTCPWebPort};
		proof.in_process_proof = true;
		m_pOwner->m_cleanupProof = proof.IsValid()
			? proof : natmap::NatPmpCleanupProof{};
	}
	m_pOwner->m_bMapperEpochReset = bObservedMapperReset;

	if (!m_pOwner->m_bAbortDiscovery) {
		if (bSucceeded)
			m_pOwner->m_bSucceededOnce = true;
		if (bSucceeded && bCanPublishDirect) {
			m_pOwner->m_bUPnPPortsForwarded = TRIS_TRUE;
			m_pOwner->m_nDiagnosticStage = UPNP_DIAG_SUCCESS;
		} else {
			m_pOwner->m_bUPnPPortsForwarded = TRIS_FALSE;
			if (bSucceeded)
				m_pOwner->m_nDiagnosticStage =
					UPNP_DIAG_EXTERNAL_ADDRESS;
			else if (m_pOwner->m_nDiagnosticStage
				!= UPNP_DIAG_TABLE_FULL)
				m_pOwner->m_nDiagnosticStage =
					UPNP_DIAG_PROTOCOL_UNAVAILABLE;
		}
		m_pOwner->SendResultMessage(m_operation);
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
