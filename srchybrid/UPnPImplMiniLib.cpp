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
//MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	See the
//GNU General Public License for more details.
//
//You should have received a copy of the GNU General Public License
//along with this program; if not, write to the Free Software
//Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
#include "StdAfx.h"
#include "emule.h"
#include "preferences.h"
#include "UPnPImplMiniLib.h"
#include "Log.h"
#include "Otherfunctions.h"
#include "miniupnpc\include\miniupnpc.h"
#include "miniupnpc\include\upnpcommands.h"
#include "miniupnpc\include\upnperrors.h"
#include "opcodes.h"

#include <bcrypt.h>
#include <ctime>

#pragma comment(lib, "bcrypt.lib")

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

CMutex CUPnPImplMiniLib::m_mutBusy;

static LPCSTR const sTCPa = "TCP";
static LPCSTR const sUDPa = "UDP";
static LPCTSTR const sTCP = _T("TCP");
static LPCTSTR const sUDP = _T("UDP");

static unsigned CountReadablePortMappings(const UPNPUrls *pURLs,
	const IGDdatas *pIGDData)
{
	if (pURLs == NULL || pURLs->controlURL == NULL || pIGDData == NULL)
		return 0;
	unsigned count = 0;
	for (; count < 128; ++count) {
		char index[12] = {};
		_snprintf_s(index, _countof(index), _TRUNCATE, "%u", count);
		char external[8] = {}, internalClient[40] = {}, internalPort[8] = {};
		char protocol[8] = {}, description[80] = {}, enabled[8] = {};
		char remote[40] = {}, duration[16] = {};
		if (UPNP_GetGenericPortMappingEntry(pURLs->controlURL,
			pIGDData->first.servicetype, index, external, internalClient,
			internalPort, protocol, description, enabled, remote, duration)
			!= UPNPCOMMAND_SUCCESS)
			break;
	}
	return count;
}

bool CUPnPImplMiniLib::GenerateOwnerToken(std::uint64_t& token)
{
	token = 0;
	for (unsigned attempt = 0; attempt < 2 && token == 0; ++attempt) {
		if (BCryptGenRandom(NULL, reinterpret_cast<PUCHAR>(&token),
			static_cast<ULONG>(sizeof(token)), BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0)
			return false;
	}
	return token != 0;
}

bool CUPnPImplMiniLib::ParseIPv4(const char* text,
	natmap::IpAddress& address)
{
	address = natmap::IpAddress{};
	if (text == NULL || text[0] == 0)
		return false;
	const unsigned long binary = inet_addr(text);
	if (binary == INADDR_NONE || binary == 0)
		return false;
	const unsigned char* bytes =
		reinterpret_cast<const unsigned char*>(&binary);
	address = natmap::IpAddress::V4(bytes[0], bytes[1], bytes[2], bytes[3]);
	return true;
}

std::uint64_t CUPnPImplMiniLib::CurrentGatewayFingerprint() const
{
	if (m_pURLs == NULL || m_pURLs->controlURL == NULL
		|| m_pIGDData == NULL || m_pIGDData->first.servicetype[0] == 0)
		return 0;

	std::uint64_t hash = 14695981039346656037ull;
	const auto add = [&hash](const char* value) {
		if (value != NULL) {
			for (const unsigned char* cursor =
				reinterpret_cast<const unsigned char*>(value);
				*cursor != 0; ++cursor) {
				hash ^= *cursor;
				hash *= 1099511628211ull;
			}
		}
		hash ^= 0xffu;
		hash *= 1099511628211ull;
	};
	add(m_pURLs->rootdescURL);
	add(m_pURLs->controlURL);
	add(m_pIGDData->first.servicetype);
	return hash == 0 ? 1 : hash;
}

void CUPnPImplMiniLib::LoadOwnershipLedger()
{
	if (m_bOwnershipLedgerLoaded)
		return;
	m_bOwnershipLedgerLoaded = true;
	m_ownershipLedger = natmap::OwnershipLedger{};
	const CString path = thePrefs.GetMuleDirectory(EMULE_CONFIGDIR)
		+ _T("natmap-ownership.dat");
	HANDLE file = ::CreateFile(path, GENERIC_READ, FILE_SHARE_READ, NULL,
		OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (file == INVALID_HANDLE_VALUE) {
		if (::GetLastError() != ERROR_FILE_NOT_FOUND)
			DebugLogWarning(_T("UPNP ownership: cannot open journal '%s'"),
				(LPCTSTR)path);
		return;
	}

	LARGE_INTEGER size = {};
	std::array<std::uint8_t, natmap::kOwnershipLedgerMaxEncodedSize> bytes{};
	DWORD read = 0;
	const bool readable = ::GetFileSizeEx(file, &size) != FALSE
		&& size.QuadPart >= 0
		&& static_cast<unsigned long long>(size.QuadPart) <= bytes.size()
		&& ::ReadFile(file, bytes.data(), static_cast<DWORD>(size.QuadPart),
			&read, NULL) != FALSE
		&& read == static_cast<DWORD>(size.QuadPart);
	::CloseHandle(file);

	const natmap::OwnershipLedgerDecodeStatus status = readable
		? natmap::DecodeOwnershipLedger(bytes.data(), read, m_ownershipLedger)
		: natmap::OwnershipLedgerDecodeStatus::BadLength;
	if (status != natmap::OwnershipLedgerDecodeStatus::Ok) {
		m_ownershipLedger = natmap::OwnershipLedger{};
		DebugLogWarning(_T("UPNP ownership: invalid journal ignored (status=%u)"),
			static_cast<unsigned>(status));
		::DeleteFile(path);
	} else if (m_ownershipLedger.count != 0)
		DebugLog(_T("UPNP ownership: loaded %u mapping proof(s) for crash recovery"),
			static_cast<unsigned>(m_ownershipLedger.count));
}

bool CUPnPImplMiniLib::SaveOwnershipLedger()
{
	const CString path = thePrefs.GetMuleDirectory(EMULE_CONFIGDIR)
		+ _T("natmap-ownership.dat");
	const CString temporary = path + _T(".new");
	if (m_ownershipLedger.count == 0) {
		::DeleteFile(temporary);
		return ::DeleteFile(path) != FALSE
			|| ::GetLastError() == ERROR_FILE_NOT_FOUND;
	}

	std::array<std::uint8_t, natmap::kOwnershipLedgerMaxEncodedSize> bytes{};
	const size_t length = natmap::EncodeOwnershipLedger(
		m_ownershipLedger, bytes.data(), bytes.size());
	if (length == 0)
		return false;

	HANDLE file = ::CreateFile(temporary, GENERIC_WRITE, 0, NULL,
		CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (file == INVALID_HANDLE_VALUE)
		return false;
	DWORD written = 0;
	const bool wrote = ::WriteFile(file, bytes.data(),
		static_cast<DWORD>(length), &written, NULL) != FALSE
		&& written == static_cast<DWORD>(length)
		&& ::FlushFileBuffers(file) != FALSE;
	::CloseHandle(file);
	const bool replaced = wrote && ::MoveFileEx(temporary, path,
		MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != FALSE;
	if (!replaced)
		::DeleteFile(temporary);
	return replaced;
}

void CUPnPImplMiniLib::RemoveOwnershipRecord(std::size_t index)
{
	if (index >= m_ownershipLedger.count)
		return;
	for (size_t i = index + 1; i < m_ownershipLedger.count; ++i)
		m_ownershipLedger.records[i - 1] = m_ownershipLedger.records[i];
	--m_ownershipLedger.count;
	m_ownershipLedger.records[m_ownershipLedger.count] =
		natmap::UpnpOwnershipRecord{};
}

bool CUPnPImplMiniLib::RecordOwnedMapping(uint16 nLocalPort,
	uint16 nExternalPort, bool bTCP, const char* pachLANIP,
	uint32 nLifetimeSeconds,
	const natmap::OwnershipDescription& description)
{
	if (m_ownerToken == 0 || nLocalPort == 0 || nExternalPort == 0)
		return false;
	natmap::UpnpOwnershipRecord record{};
	record.owner_token = m_ownerToken;
	record.gateway_fingerprint = CurrentGatewayFingerprint();
	record.transport = bTCP ? natmap::Transport::Tcp : natmap::Transport::Udp;
	if (!ParseIPv4(pachLANIP, record.local_address))
		return false;
	record.local_port = nLocalPort;
	record.external_port = nExternalPort;
	record.lifetime_seconds = nLifetimeSeconds;
	const time_t now = std::time(NULL);
	if (now <= 0)
		return false;
	record.acquired_unix_seconds = static_cast<std::uint64_t>(now);
	record.generation = m_mappingGeneration;
	record.description = description;
	if (!record.IsStructurallyValid())
		return false;

	const natmap::OwnershipLedger previous = m_ownershipLedger;
	size_t index = m_ownershipLedger.count;
	for (size_t i = 0; i < m_ownershipLedger.count; ++i) {
		const natmap::UpnpOwnershipRecord& existing =
			m_ownershipLedger.records[i];
		if (existing.gateway_fingerprint == record.gateway_fingerprint
			&& existing.transport == record.transport
			&& existing.external_port == record.external_port) {
			index = i;
			break;
		}
	}
	if (index == m_ownershipLedger.count) {
		if (m_ownershipLedger.count >= m_ownershipLedger.records.size())
			return false;
		++m_ownershipLedger.count;
	}
	m_ownershipLedger.records[index] = record;
	if (SaveOwnershipLedger())
		return true;
	m_ownershipLedger = previous;
	return false;
}

void CUPnPImplMiniLib::RecoverOwnedMappings()
{
	const natmap::OwnershipLedger pending = m_ownershipLedger;
	for (size_t i = 0; i < pending.count; ++i) {
		const natmap::UpnpOwnershipRecord& record = pending.records[i];
		DeletePort(record.external_port,
			record.transport == natmap::Transport::Tcp ? sTCP : sUDP);
	}
}

CUPnPImplMiniLib::CUPnPImplMiniLib()
	: m_pURLs()
	, m_pIGDData()
	, m_hThreadHandle()
	, m_ownerToken()
	, m_mappingGeneration()
	, m_bOwnershipLedgerLoaded()
	, m_bSucceededOnce()
	, m_bAbortDiscovery()
{
	m_nOldUDPPort = 0;
	m_nOldTCPPort = 0;
	m_nOldTCPWebPort = 0;
	m_achLanIP[0] = 0;
	m_achWanIP[0] = 0;
}

CUPnPImplMiniLib::~CUPnPImplMiniLib()
{
	Cleanup();
}

bool CUPnPImplMiniLib::IsReady()
{
	if (m_bAbortDiscovery)
		return false;
	// the only check we need to do is if we are already busy with some async/threaded function
	CSingleLock lockTest(&m_mutBusy);
	return lockTest.Lock(0);
}

void CUPnPImplMiniLib::StopAsyncFind()
{
	if (m_hThreadHandle != NULL) {
		m_bAbortDiscovery = true;	// if there is a thread, tell it to abort as soon as possible - he won't sent a Result message when aborted
		CSingleLock lockTest(&m_mutBusy);
		if (!lockTest.Lock(SEC2MS(7))) {	// give the thread 7 seconds to exit gracefully - it should never really take that long
			// that is quite bad, something seems to be locked up. There isn't a good solution here, we need the thread to quit
			// or it might try to access the object later, but terminating is quite bad too. Well.
			DebugLogError(_T("Waiting for UPnP StartDiscoveryThread to quit failed, trying to terminate the thread..."));

			if (m_hThreadHandle != NULL)
				DebugLogError(::TerminateThread(m_hThreadHandle, 0) ? _T("...OK") : _T("...Failed"));
			else
				ASSERT(0);
		} else
			DebugLog(_T("Aborted any possible UPnP StartDiscoveryThread"));
		m_hThreadHandle = NULL;
	}
	m_bAbortDiscovery = false;
}

void CUPnPImplMiniLib::DeletePorts()
{
	GetOldPorts();
	m_nUDPPort = 0;
	m_nTCPPort = 0;
	m_nTCPWebPort = 0;
	m_nExternalUDPPort = 0;
	m_nExternalTCPPort = 0;
	m_nExternalTCPWebPort = 0;
	m_bUPnPPortsForwarded = TRIS_FALSE;
	DeletePorts(false);
}

void CUPnPImplMiniLib::DeletePort(uint16 port, LPCTSTR prot)
{
	if (port == 0 || m_pURLs == NULL || m_pURLs->controlURL == NULL
		|| m_pIGDData == NULL)
		return;

	const natmap::Transport transport = _tcscmp(prot, sUDP) == 0
		? natmap::Transport::Udp : natmap::Transport::Tcp;
	const std::uint64_t gateway = CurrentGatewayFingerprint();
	size_t index = m_ownershipLedger.count;
	for (size_t i = 0; i < m_ownershipLedger.count; ++i) {
		const natmap::UpnpOwnershipRecord& candidate =
			m_ownershipLedger.records[i];
		if (candidate.transport == transport
			&& candidate.external_port == port) {
			if (index == m_ownershipLedger.count
				|| candidate.gateway_fingerprint == gateway)
				index = i;
			if (candidate.gateway_fingerprint == gateway)
				break;
		}
	}
	if (index == m_ownershipLedger.count) {
		DebugLogWarning(_T("UPNP ownership: refusing to remove unjournaled %s port %hu"),
			prot, port);
		return;
	}

	const natmap::UpnpOwnershipRecord record =
		m_ownershipLedger.records[index];
	if (gateway == 0 || record.gateway_fingerprint != gateway) {
		DebugLogWarning(_T("UPNP ownership: stale %s port %hu belongs to a different gateway; dropping local proof only"),
			prot, port);
		RemoveOwnershipRecord(index);
		SaveOwnershipLedger();
		return;
	}

	char achPort[8] = {};
	char achOutIP[40] = {};
	char achOutPort[8] = {};
	char achDescription[80] = {};
	char achLeaseDuration[16] = {};
	_snprintf_s(achPort, _countof(achPort), _TRUNCATE, "%hu", port);
	const int queryResult = UPNP_GetSpecificPortMappingEntry(
		m_pURLs->controlURL, m_pIGDData->first.servicetype, achPort,
		transport == natmap::Transport::Tcp ? sTCPa : sUDPa, NULL,
		achOutIP, achOutPort, achDescription, NULL, achLeaseDuration);
	if (queryResult != UPNPCOMMAND_SUCCESS) {
		if (queryResult == 714) {
			RemoveOwnershipRecord(index);
			SaveOwnershipLedger();
			DebugLog(_T("UPNP ownership: %s port %hu is already absent"),
				prot, port);
		} else
			DebugLogWarning(_T("UPNP ownership: cannot verify %s port %hu (%d: %S); mapping was not removed"),
				prot, port, queryResult, strupnperror(queryResult));
		return;
	}

	natmap::ObservedUpnpMapping observed{};
	observed.transport = transport;
	observed.local_port = static_cast<uint16>(strtoul(achOutPort, NULL, 10));
	observed.external_port = port;
	ParseIPv4(achOutIP, observed.local_address);
	strncpy_s(observed.description.data(), observed.description.size(),
		achDescription, _TRUNCATE);
	const natmap::OwnershipDecision decision =
		natmap::EvaluateOwnershipForDeletion(record, gateway, observed);
	if (decision != natmap::OwnershipDecision::Owned) {
		DebugLogWarning(_T("UPNP ownership: %s port %hu no longer matches proof (decision=%u); mapping was not removed"),
			prot, port, static_cast<unsigned>(decision));
		RemoveOwnershipRecord(index);
		SaveOwnershipLedger();
		return;
	}

	const int nResult = UPNP_DeletePortMapping(m_pURLs->controlURL,
		m_pIGDData->first.servicetype, achPort, CStringA(prot), NULL);
	if (nResult == UPNPCOMMAND_SUCCESS) {
		DebugLog(_T("Successfully removed owned mapping for %s port %hu"),
			prot, port);
		RemoveOwnershipRecord(index);
		if (!SaveOwnershipLedger())
			DebugLogWarning(_T("UPNP ownership: mapping removed but journal update failed"));
	} else
		DebugLogWarning(_T("Failed to remove owned mapping for %s port %hu"),
			prot, port);
}

void CUPnPImplMiniLib::GetOldPorts()
{
	if (ArePortsForwarded() == TRIS_TRUE) {
		// DeletePortMapping addresses the external port. It may differ from
		// the listener after an IGDv2 AddAnyPortMapping reservation.
		m_nOldUDPPort = m_nExternalUDPPort;
		m_nOldTCPPort = m_nExternalTCPPort;
		m_nOldTCPWebPort = m_nExternalTCPWebPort;
	} else {
		m_nOldUDPPort = 0;
		m_nOldTCPPort = 0;
		m_nOldTCPWebPort = 0;
	}
}

void CUPnPImplMiniLib::DeletePorts(bool bSkipLock)
{
	// this function can be blocking when called when eMule exits, and we need to wait for it to finish
	// before going on anyway. It might be called from the non-blocking StartDiscovery() function too however
	CSingleLock lockTest(&m_mutBusy);
	if (bSkipLock || lockTest.Lock(0)) {
		if (m_pURLs == NULL || m_pURLs->controlURL == NULL || m_pIGDData == NULL)
			ASSERT(!thePrefs.IsUPnPEnabled());
		else {
			DeletePort(m_nOldTCPPort, sTCP);
			DeletePort(m_nOldUDPPort, sUDP);
			DeletePort(m_nOldTCPWebPort, sTCP);
			// Also retry any exact owned record left by a partial transaction or
			// an earlier transient delete failure.
			RecoverOwnedMappings();
		}
		m_nOldTCPPort = 0;
		m_nOldUDPPort = 0;
		m_nOldTCPWebPort = 0;
	} else
		DebugLogError(_T("Unable to remove port mappings - implementation still busy"));
}

void CUPnPImplMiniLib::StartDiscovery(uint16 nTCPPort, uint16 nUDPPort, uint16 nTCPWebPort)
{
	DebugLog(_T("Using MiniUPnPLib based implementation"));
	DebugLog(_T("miniupnpc (c) 2005-2024 Thomas Bernard - http://miniupnp.free.fr/"));
	LoadOwnershipLedger();
	if (!GenerateOwnerToken(m_ownerToken)) {
		DebugLogError(_T("UPNP ownership: unable to generate a secure owner token"));
		m_ownerToken = 0;
	}
	if (++m_mappingGeneration == 0)
		++m_mappingGeneration;
	GetOldPorts();
	m_nUDPPort = nUDPPort;
	m_nTCPPort = nTCPPort;
	m_nTCPWebPort = nTCPWebPort;
	m_nExternalUDPPort = nUDPPort;
	m_nExternalTCPPort = nTCPPort;
	m_nExternalTCPWebPort = nTCPWebPort;
	m_dwMappingLeaseLifetime = 0;
	m_dwMapperEpoch = 0;
	m_nDiagnosticStage = UPNP_DIAG_DISCOVERING;
	m_bUPnPPortsForwarded = TRIS_UNKNOWN;
	m_bCheckAndRefresh = false;

	Cleanup();
	if (!m_bAbortDiscovery)
		StartThread();
}

bool CUPnPImplMiniLib::CheckAndRefresh()
{
	// in CheckAndRefresh we don't do any new time consuming discovery tries, we expect to find the same router like the first time
	// and of course we also don't delete old ports (this was done in Discovery) but only check that our current mappings still exist
	// and refresh them if not
	if (m_bAbortDiscovery || !m_bSucceededOnce || m_pURLs == NULL || m_pIGDData == NULL
	    || m_pURLs->controlURL == NULL || m_nTCPPort == 0)
	{
		DebugLog(_T("Not refreshing UPnP ports because they don't seem to be forwarded in the first place"));
		return false;
	}
//>>> WiZaRd
	if (!IsReady()) {
		DebugLog(_T("Not refreshing UPnP ports because they are already in the process of being refreshed"));
		return false;
	}
//<<< WiZaRd

	DebugLog(_T("Checking and refreshing UPnP ports"));
	m_bCheckAndRefresh = true;
	StartThread();
	return true;
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////
/// CUPnPImplMiniLib::CStartDiscoveryThread Implementation
typedef CUPnPImplMiniLib::CStartDiscoveryThread CStartDiscoveryThread;
IMPLEMENT_DYNCREATE(CStartDiscoveryThread, CWinThread)

CUPnPImplMiniLib::CStartDiscoveryThread::CStartDiscoveryThread()
{
	m_pOwner = NULL;
}

BOOL CUPnPImplMiniLib::CStartDiscoveryThread::InitInstance()
{
	InitThreadLocale();
	return TRUE;
}

int CUPnPImplMiniLib::CStartDiscoveryThread::Run()
{
	DbgSetThreadName("CUPnPImplMiniLib::CStartDiscoveryThread");
	if (!m_pOwner)
		return 0;

	CSingleLock sLock(&m_pOwner->m_mutBusy);
	if (!sLock.Lock(0)) {
		DebugLogWarning(_T("CUPnPImplMiniLib::CStartDiscoveryThread::Run, failed to acquire Lock, another Mapping try might be running already"));
		return 0;
	}

	if (m_pOwner->m_bAbortDiscovery)// requesting to abort ASAP?
		return 0;
	if (m_pOwner->m_bCheckAndRefresh)
		m_pOwner->m_dwMappingLeaseLifetime = 0;

	bool bSucceeded = false;
#if !(defined(_DEBUG) || defined(_BETA) || defined(_DEVBUILD))
	try
#endif
	{
		if (!m_pOwner->m_bCheckAndRefresh) {
			int error = 0;
			// Increased discovery timeout from 2000ms to 4000ms for slower routers
			// Many modern routers (especially mesh/WiFi 6) need more time to respond
			UPNPDev *structDeviceList = upnpDiscover(4000, thePrefs.GetBindAddrA(), NULL, 0, 0, 2, &error);
			if (structDeviceList == NULL) {
				// Retry with longer timeout before giving up
				DebugLog(_T("UPNP: First discovery attempt failed (error %d), retrying with longer timeout..."), error);
				if (!m_pOwner->m_bAbortDiscovery)
					structDeviceList = upnpDiscover(6000, thePrefs.GetBindAddrA(), NULL, 0, 0, 2, &error);
			}
			if (structDeviceList == NULL) {
				DebugLog(_T("UPNP: No Internet Gateway Devices found after retry, aborting: %d"), error);
				m_pOwner->m_nDiagnosticStage = UPNP_DIAG_NO_GATEWAY;
				m_pOwner->m_bUPnPPortsForwarded = TRIS_FALSE;
				m_pOwner->SendResultMessage();
				return 0;
			}

			if (m_pOwner->m_bAbortDiscovery) {	// requesting to abort ASAP?
				freeUPNPDevlist(structDeviceList);
				return 0;
			}

			DebugLog(_T("List of UPNP devices found on the network:"));
			for (UPNPDev *pDevice = structDeviceList; pDevice != NULL; pDevice = pDevice->pNext)
				DebugLog(_T("Desc: %S, st: %S"), pDevice->descURL, pDevice->st);

			m_pOwner->m_pURLs = new UPNPUrls();
			m_pOwner->m_pIGDData = new IGDdatas();
			*m_pOwner->m_achLanIP = 0;
			*m_pOwner->m_achWanIP = 0;
			int iResult = UPNP_GetValidIGD(structDeviceList, m_pOwner->m_pURLs, m_pOwner->m_pIGDData
							, m_pOwner->m_achLanIP, sizeof m_pOwner->m_achLanIP
							, m_pOwner->m_achWanIP, sizeof m_pOwner->m_achWanIP);
			freeUPNPDevlist(structDeviceList);
			bool bNotFound = false;
			switch (iResult) {
			case 1:
				DebugLog(_T("Found valid IGD : %S"), m_pOwner->m_pURLs->controlURL);
				break;
			case 2:
				DebugLog(_T("Found an IGD with a reserved IP address (%S) : %S"), m_pOwner->m_achWanIP, m_pOwner->m_pURLs->controlURL);
				// This is a valid inner layer in a double-NAT topology. Keep the
				// mapping and let DirectReachabilityManager decide whether an
				// upstream lease is needed; never claim it is already public.
				break;
			case 3:
				DebugLog(_T("Found a (not connected?) IGD : %S - Trying to continue anyway"), m_pOwner->m_pURLs->controlURL);
				break;
			case 4:
				DebugLog(_T("UPnP device found. Is it an IGD? : %S - Trying to continue anyway"), m_pOwner->m_pURLs->controlURL);
				break;
			default:
				DebugLog(_T("Found device (IGD?) : %S - Aborting"), m_pOwner->m_pURLs->controlURL != NULL ? m_pOwner->m_pURLs->controlURL : "(none)");
				bNotFound = true;
			}
			if (bNotFound || m_pOwner->m_pURLs->controlURL == NULL) {
				m_pOwner->m_nDiagnosticStage = UPNP_DIAG_PROTOCOL_UNAVAILABLE;
				m_pOwner->m_bUPnPPortsForwarded = TRIS_FALSE;
				m_pOwner->SendResultMessage();
				return 0;
			}
			DebugLog(_T("Our LAN IP: %S"), m_pOwner->m_achLanIP);

			// Log external IP for double-NAT detection
			m_pOwner->m_nDiagnosticStage = UPNP_DIAG_EXTERNAL_ADDRESS;
			char achExternalIP[16] = {};
			if (UPNP_GetExternalIPAddress(m_pOwner->m_pURLs->controlURL,
					m_pOwner->m_pIGDData->first.servicetype, achExternalIP) == UPNPCOMMAND_SUCCESS
				&& achExternalIP[0] != 0)
			{
				DebugLog(_T("External IP reported by router: %S"), achExternalIP);
				// Check for double NAT (external IP is also private)
				unsigned long ulExtIP = inet_addr(achExternalIP);
				if (ulExtIP != INADDR_NONE) {
					m_pOwner->m_dwMappingExternalIP = ulExtIP;
					unsigned char b1 = (unsigned char)(ulExtIP & 0xFF);
					unsigned char b2 = (unsigned char)((ulExtIP >> 8) & 0xFF);
					if (b1 == 10 || (b1 == 172 && b2 >= 16 && b2 <= 31) || (b1 == 192 && b2 == 168) || b1 == 100) {
						DebugLogWarning(_T("UPNP WARNING: External IP %S is a private/CGNAT address - possible double NAT detected! UPnP may not help achieve High ID."), achExternalIP);
					}
				}
			} else
				DebugLogWarning(_T("UPNP: Could not retrieve external IP address from router"));

			if (m_pOwner->m_bAbortDiscovery)// requesting to abort ASAP?
				return 0;

			// Recover crash leftovers and same-process stale rules only after the
			// current IGD has been identified. Every deletion is ownership-gated.
			m_pOwner->RecoverOwnedMappings();
			m_pOwner->m_nOldTCPPort = 0;
			m_pOwner->m_nOldUDPPort = 0;
			m_pOwner->m_nOldTCPWebPort = 0;
		}

		m_pOwner->m_nDiagnosticStage = UPNP_DIAG_TCP_MAPPING;
		bSucceeded = OpenPort(m_pOwner->m_nTCPPort, true, m_pOwner->m_achLanIP, m_pOwner->m_bCheckAndRefresh);
		if (bSucceeded && m_pOwner->m_nUDPPort != 0) {
			m_pOwner->m_nDiagnosticStage = UPNP_DIAG_UDP_MAPPING;
			bSucceeded = OpenPort(m_pOwner->m_nUDPPort, false, m_pOwner->m_achLanIP, m_pOwner->m_bCheckAndRefresh);
			if (!bSucceeded) {
				// TCP+UDP is one direct-reachability transaction. Do not leave
				// a half-created mapping when Kad UDP creation fails.
				m_pOwner->DeletePort(m_pOwner->m_nExternalTCPPort, sTCP);
				m_pOwner->m_nExternalTCPPort = 0;
			}
		}
		if (bSucceeded) {
			if (m_pOwner->m_nOldTCPWebPort)
				m_pOwner->DeletePort(m_pOwner->m_nOldTCPWebPort, sTCP);	//unmap WebServer port (late binding)
			if (m_pOwner->m_nTCPWebPort)
				OpenPort(m_pOwner->m_nTCPWebPort, true, m_pOwner->m_achLanIP, m_pOwner->m_bCheckAndRefresh);	// don't fail if only the Web Interface port fails for some reason
			m_pOwner->m_nDiagnosticStage = UPNP_DIAG_SUCCESS;
		}
#if !(defined(_DEBUG) || defined(_BETA) || defined(_DEVBUILD))
	} catch (...) {
		DebugLogError(_T("Unknown Exception in CUPnPImplMiniLib::CStartDiscoveryThread::Run()"));
#endif
	}
	if (!m_pOwner->m_bAbortDiscovery) {	// don't send the result on an abort request
		if (bSucceeded) {
			m_pOwner->m_bUPnPPortsForwarded = TRIS_TRUE;
			m_pOwner->m_bSucceededOnce = true;
		} else
			m_pOwner->m_bUPnPPortsForwarded = TRIS_FALSE;
		m_pOwner->SendResultMessage();
	}
	return 0;
}

bool CUPnPImplMiniLib::CStartDiscoveryThread::OpenPort(uint16 nPort, bool bTCP, char *pachLANIP, bool bCheckAndRefresh)
{
	if (m_pOwner->m_bAbortDiscovery)
		return false;

	if (m_pOwner->m_ownerToken == 0)
		return false;
	const natmap::OwnershipDescription ownershipDescription =
		natmap::BuildOwnershipDescription(m_pOwner->m_ownerToken,
			bTCP ? natmap::Transport::Tcp : natmap::Transport::Udp);
	const char* const pachDescription = ownershipDescription.data();
	char achPort[8];
	_snprintf_s(achPort, _countof(achPort), _TRUNCATE, "%hu", nPort);
	uint16* pExternalPort = bTCP
		? (nPort == m_pOwner->m_nTCPPort
			? &m_pOwner->m_nExternalTCPPort : &m_pOwner->m_nExternalTCPWebPort)
		: &m_pOwner->m_nExternalUDPPort;
	char achExternalPort[8];
	_snprintf_s(achExternalPort, _countof(achExternalPort), _TRUNCATE,
		"%hu", *pExternalPort != 0 ? *pExternalPort : nPort);

	int nResult;
	// if we are refreshing ports, check first if the mapping is still fine and only try to open if not
	char achOutIP[20] = {};
	char achOutPort[8] = {};
	char achOutDescription[80] = {};
	char achLeaseDuration[16] = {};
	if (bCheckAndRefresh) {
		nResult = UPNP_GetSpecificPortMappingEntry(m_pOwner->m_pURLs->controlURL, m_pOwner->m_pIGDData->first.servicetype
												 , achExternalPort
												 , (bTCP ? sTCPa : sUDPa)
												 , NULL
												 , achOutIP, achOutPort
												 , achOutDescription, NULL, achLeaseDuration);

		if (nResult == UPNPCOMMAND_SUCCESS && achOutIP[0] != 0
			&& atoi(achOutPort) == nPort && strcmp(achOutIP, pachLANIP) == 0
			&& strcmp(achOutDescription, pachDescription) == 0) {
			const unsigned long remaining = strtoul(achLeaseDuration, NULL, 10);
			if (remaining == 0) {
				// Do not clear the aggregate lifetime here: TCP, UDP and the web
				// mapping may have different lease semantics. If any sibling is
				// finite, the shared scheduler must remain armed.
				DebugLog(_T("Checking UPnP: Permanent mapping %hu -> %hu (%s) on local IP %S still exists"), *pExternalPort, nPort, (bTCP ? sTCP : sUDP), achOutIP);
				return true;
			}
			// Merely observing a finite mapping does not extend it. Continue to
			// AddPortMapping with the same tuple so the router grants a fresh lease.
			DebugLog(_T("Checking UPnP: Finite mapping %hu -> %hu (%s) has %lu seconds left; renewing it now"), *pExternalPort, nPort, (bTCP ? sTCP : sUDP), remaining);
		}
		else
			DebugLogWarning(_T("Checking UPnP: Mapping for port %hu (%s) on local IP %S is gone, trying to reopen port"), nPort, (bTCP ? sTCP : sUDP), achOutIP);
	}


	// Try with a 2-hour lease first. Many routers reject permanent (0) mappings
	// but accept time-limited ones. The lease will be refreshed by CheckAndRefresh().
	nResult = UPNP_AddPortMapping(m_pOwner->m_pURLs->controlURL
								, m_pOwner->m_pIGDData->first.servicetype
								, achExternalPort, achPort, pachLANIP
								, pachDescription
								, (bTCP ? sTCPa : sUDPa)
								, NULL, "7200"); // 2 hour lease duration

	if (nResult != UPNPCOMMAND_SUCCESS) {
		// Some routers only accept permanent mappings (lease=0), retry without lease
		DebugLog(_T("Adding PortMapping with lease failed (%d: %S), retrying with permanent mapping..."),
			nResult, strupnperror(nResult));
		nResult = UPNP_AddPortMapping(m_pOwner->m_pURLs->controlURL
									, m_pOwner->m_pIGDData->first.servicetype
									, achExternalPort, achPort, pachLANIP
									, pachDescription
									, (bTCP ? sTCPa : sUDPa)
									, NULL, NULL); // permanent (no lease)
	}

	// IGDv2 can reserve a different free external port. This is preferable to
	// declaring failure merely because the listener port is occupied upstream.
	const bool bDirectMapping = bTCP
		? nPort == m_pOwner->m_nTCPPort : nPort == m_pOwner->m_nUDPPort;
	if (nResult != UPNPCOMMAND_SUCCESS && bDirectMapping) {
		char achReservedPort[8] = {};
		DebugLog(_T("Adding fixed UPnP mapping failed (%d: %S), trying IGDv2 AddAnyPortMapping..."),
			nResult, strupnperror(nResult));
		nResult = UPNP_AddAnyPortMapping(m_pOwner->m_pURLs->controlURL,
			m_pOwner->m_pIGDData->first.servicetype, achExternalPort, achPort,
			pachLANIP, pachDescription,
			(bTCP ? sTCPa : sUDPa), NULL, "7200", achReservedPort);
		const unsigned long reserved = strtoul(achReservedPort, NULL, 10);
		if (nResult == UPNPCOMMAND_SUCCESS && reserved > 0 && reserved <= 65535) {
			*pExternalPort = static_cast<uint16>(reserved);
			_snprintf_s(achExternalPort, _countof(achExternalPort), _TRUNCATE,
				"%hu", *pExternalPort);
		} else if (nResult == UPNPCOMMAND_SUCCESS)
			nResult = UPNPCOMMAND_INVALID_RESPONSE;
	}

	if (nResult != UPNPCOMMAND_SUCCESS) {
		const unsigned mappingCount = CountReadablePortMappings(
			m_pOwner->m_pURLs, m_pOwner->m_pIGDData);
		if (mappingCount >= 64) {
			m_pOwner->m_nDiagnosticStage = UPNP_DIAG_TABLE_FULL;
			DebugLogWarning(_T("UPNP: Router mapping table appears full (%u readable entries); no foreign mappings were modified"), mappingCount);
		}
		DebugLog(_T("Adding PortMapping failed: %d (%S)"), nResult, strupnperror(nResult));
		return false;
	}
	if (*pExternalPort == 0)
		*pExternalPort = nPort;
	if (m_pOwner->m_bAbortDiscovery)
		return false;

	// make sure it really worked
	m_pOwner->m_nDiagnosticStage = UPNP_DIAG_VERIFY_MAPPING;
	achOutIP[0] = 0;
	achOutPort[0] = 0;
	achOutDescription[0] = 0;
	achLeaseDuration[0] = 0;
	nResult = UPNP_GetSpecificPortMappingEntry(m_pOwner->m_pURLs->controlURL
											 , m_pOwner->m_pIGDData->first.servicetype
											 , achExternalPort
											 , (bTCP ? sTCPa : sUDPa)
											 , NULL
											 , achOutIP, achOutPort
												 , achOutDescription, NULL, achLeaseDuration);

	if (nResult == UPNPCOMMAND_SUCCESS && achOutIP[0] != 0
		&& atoi(achOutPort) == nPort && strcmp(achOutIP, pachLANIP) == 0
		&& strcmp(achOutDescription, pachDescription) == 0) {
		const uint32 verifiedLifetime = static_cast<uint32>(
			strtoul(achLeaseDuration, NULL, 10));
		if (verifiedLifetime != 0
			&& (m_pOwner->m_dwMappingLeaseLifetime == 0
				|| verifiedLifetime < m_pOwner->m_dwMappingLeaseLifetime))
			m_pOwner->m_dwMappingLeaseLifetime = verifiedLifetime;
		if (!m_pOwner->RecordOwnedMapping(nPort, *pExternalPort, bTCP,
			pachLANIP, verifiedLifetime, ownershipDescription)) {
			m_pOwner->m_nDiagnosticStage = UPNP_DIAG_OWNERSHIP_PERSISTENCE;
			DebugLogError(_T("UPNP ownership: could not persist proof for %s port %hu; rolling mapping back"),
				(bTCP ? sTCP : sUDP), *pExternalPort);
			UPNP_DeletePortMapping(m_pOwner->m_pURLs->controlURL,
				m_pOwner->m_pIGDData->first.servicetype, achExternalPort,
				(bTCP ? sTCPa : sUDPa), NULL);
			return false;
		}
		DebugLog(_T("Successfully added mapping %hu -> %hu (%s) on local IP %S"), *pExternalPort, nPort, (bTCP ? sTCP : sUDP), achOutIP);
		return true;
	}

	DebugLogWarning(_T("Failed to verify mapping for port %hu (%s) on local IP %S - considering as failed"), nPort, (bTCP ? sTCP : sUDP), achOutIP);
	// maybe counting this as error is a bit harsh as this may lead to false negatives, however if we would risk false positives
	// this would mean that the fallback implementations are not tried because eMule thinks it worked out fine
	return false;
}

void CUPnPImplMiniLib::Cleanup()
{
	FreeUPNPUrls(m_pURLs);
	delete m_pURLs;
	m_pURLs = NULL;

	delete m_pIGDData;
	m_pIGDData = NULL;
}

void CUPnPImplMiniLib::StartThread()
{
	CStartDiscoveryThread *pStartDiscoveryThread = (CStartDiscoveryThread*)AfxBeginThread(RUNTIME_CLASS(CStartDiscoveryThread), THREAD_PRIORITY_NORMAL, 0, CREATE_SUSPENDED);
	m_hThreadHandle = pStartDiscoveryThread->m_hThread;
	pStartDiscoveryThread->SetValues(this);
	pStartDiscoveryThread->ResumeThread();
}
