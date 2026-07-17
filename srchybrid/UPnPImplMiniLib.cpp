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
#include <iphlpapi.h>
#include <vector>

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

namespace {

constexpr uint32 kPreferredLeaseSeconds = 7200;
constexpr unsigned kMaximumDiscoveryInterfaces = 5;

struct DiscoveryTarget {
	CStringA address;
};

class SelectedIgd {
public:
	SelectedIgd()
		: state()
	{
		memset(&urls, 0, sizeof urls);
		memset(&data, 0, sizeof data);
		lanAddress[0] = 0;
		wanAddress[0] = 0;
	}

	~SelectedIgd()
	{
		FreeUPNPUrls(&urls);
	}

	void ReleaseUrls(UPNPUrls& destination)
	{
		destination = urls;
		memset(&urls, 0, sizeof urls);
	}

	UPNPUrls urls;
	IGDdatas data;
	char lanAddress[40];
	char wanAddress[40];
	int state;
};

static bool IsBetterIgdState(int candidate, int current)
{
	return candidate >= UPNP_CONNECTED_IGD
		&& candidate <= UPNP_UNKNOWN_DEVICE
		&& (current == UPNP_NO_IGD || candidate < current);
}

static void ConsiderDiscoveredDevices(UPNPDev* devices,
	SelectedIgd& selected)
{
	if (devices == NULL)
		return;

	DebugLog(_T("List of UPnP devices found on the network:"));
	for (UPNPDev* device = devices; device != NULL; device = device->pNext)
		DebugLog(_T("Desc: %S, st: %S"), device->descURL, device->st);

	UPNPUrls candidateUrls = {};
	IGDdatas candidateData = {};
	char candidateLan[40] = {};
	char candidateWan[40] = {};
	const int candidateState = UPNP_GetValidIGD(devices, &candidateUrls,
		&candidateData, candidateLan, sizeof candidateLan,
		candidateWan, sizeof candidateWan);
	const bool usable = candidateState != UPNP_NO_IGD
		&& candidateUrls.controlURL != NULL
		&& candidateData.first.servicetype[0] != 0;
	if (usable && IsBetterIgdState(candidateState, selected.state)) {
		FreeUPNPUrls(&selected.urls);
		selected.urls = candidateUrls;
		memset(&candidateUrls, 0, sizeof candidateUrls);
		selected.data = candidateData;
		strncpy_s(selected.lanAddress, candidateLan, _TRUNCATE);
		strncpy_s(selected.wanAddress, candidateWan, _TRUNCATE);
		selected.state = candidateState;
	}
	FreeUPNPUrls(&candidateUrls);
}

static UPNPDev* DiscoverIgdDevices(const char* multicastInterface,
	int delayMilliseconds, int localPort, bool searchAll, int& error)
{
	if (searchAll)
		return upnpDiscoverAll(delayMilliseconds, multicastInterface, NULL,
			localPort, 0, 2, &error);

	// Some IGDv2-only devices do not answer the legacy IGD:1 search used by
	// upnpDiscover(). Query both generations and both WAN services explicitly.
	static const char* const deviceTypes[] = {
		"urn:schemas-upnp-org:device:InternetGatewayDevice:2",
		"urn:schemas-upnp-org:service:WANIPConnection:2",
		"urn:schemas-upnp-org:device:InternetGatewayDevice:1",
		"urn:schemas-upnp-org:service:WANIPConnection:1",
		"urn:schemas-upnp-org:service:WANPPPConnection:1",
		"upnp:rootdevice",
		NULL
	};
	return upnpDiscoverDevices(deviceTypes, delayMilliseconds,
		multicastInterface, NULL, localPort, 0, 2, &error, 1);
}

static void AddDiscoveryTarget(std::vector<DiscoveryTarget>& targets,
	const char* address)
{
	if (address == NULL || address[0] == 0)
		return;
	for (const DiscoveryTarget& target : targets) {
		if (target.address.CompareNoCase(address) == 0)
			return;
	}
	DiscoveryTarget target;
	target.address = address;
	targets.push_back(target);
}

static std::vector<DiscoveryTarget> GetDiscoveryTargets()
{
	std::vector<DiscoveryTarget> targets;
	const char* const configuredAddress = thePrefs.GetBindAddrA();
	if (configuredAddress != NULL && configuredAddress[0] != 0) {
		AddDiscoveryTarget(targets, configuredAddress);
		return targets;
	}

	// An empty first target lets Windows select its preferred/default route.
	targets.push_back(DiscoveryTarget());

	ULONG bytes = 16 * 1024;
	std::vector<BYTE> storage(bytes);
	ULONG result = GetAdaptersAddresses(AF_INET,
		GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST
			| GAA_FLAG_SKIP_DNS_SERVER,
		NULL, reinterpret_cast<PIP_ADAPTER_ADDRESSES>(storage.data()), &bytes);
	if (result == ERROR_BUFFER_OVERFLOW) {
		storage.resize(bytes);
		result = GetAdaptersAddresses(AF_INET,
			GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST
				| GAA_FLAG_SKIP_DNS_SERVER,
			NULL, reinterpret_cast<PIP_ADAPTER_ADDRESSES>(storage.data()),
			&bytes);
	}
	if (result != NO_ERROR)
		return targets;

	for (PIP_ADAPTER_ADDRESSES adapter =
		reinterpret_cast<PIP_ADAPTER_ADDRESSES>(storage.data());
		adapter != NULL; adapter = adapter->Next) {
		if (adapter->OperStatus != IfOperStatusUp
			|| adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK
			|| adapter->IfType == IF_TYPE_TUNNEL)
			continue;
		for (PIP_ADAPTER_UNICAST_ADDRESS unicast =
			adapter->FirstUnicastAddress; unicast != NULL;
			unicast = unicast->Next) {
			if (unicast->Address.lpSockaddr == NULL
				|| unicast->Address.lpSockaddr->sa_family != AF_INET)
				continue;
			const sockaddr_in* address = reinterpret_cast<const sockaddr_in*>(
				unicast->Address.lpSockaddr);
			if (address->sin_addr.s_addr == INADDR_ANY
				|| (ntohl(address->sin_addr.s_addr) >> 24) == 127)
				continue;
			const char* const text = inet_ntoa(address->sin_addr);
			if (text != NULL)
				AddDiscoveryTarget(targets, text);
		}
	}

	if (targets.size() > kMaximumDiscoveryInterfaces)
		targets.resize(kMaximumDiscoveryInterfaces);
	return targets;
}

static bool SameIPv4Address(const char* left, const char* right)
{
	if (left == NULL || right == NULL || left[0] == 0 || right[0] == 0)
		return false;
	if (strcmp(left, right) == 0)
		return true;
	const unsigned long leftAddress = inet_addr(left);
	const unsigned long rightAddress = inet_addr(right);
	return leftAddress != INADDR_NONE && rightAddress != INADDR_NONE
		&& leftAddress == rightAddress;
}

static bool MappingTargetsLocalSocket(const char* internalClient,
	const char* internalPort, const char* enabled, const char* lanAddress,
	uint16 localPort)
{
	char* end = NULL;
	const unsigned long parsedPort = strtoul(internalPort, &end, 10);
	const bool mappingEnabled = enabled == NULL || enabled[0] == 0
		|| (strcmp(enabled, "0") != 0 && _stricmp(enabled, "false") != 0);
	return end != internalPort && *end == 0 && parsedPort == localPort
		&& mappingEnabled && SameIPv4Address(internalClient, lanAddress);
}

static uint32 ParseLeaseDuration(const char* text, uint32 fallback)
{
	if (text == NULL || text[0] == 0)
		return fallback;
	char* end = NULL;
	const unsigned long value = strtoul(text, &end, 10);
	return end != text && *end == 0
		? static_cast<uint32>(value) : fallback;
}

static bool IsTransientUpnpError(int result)
{
	return result == UPNPCOMMAND_HTTP_ERROR
		|| result == UPNPCOMMAND_UNKNOWN_ERROR
		|| result == UPNPCOMMAND_INVALID_RESPONSE;
}

} // namespace

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
			const std::vector<DiscoveryTarget> targets =
				GetDiscoveryTargets();
			SelectedIgd selected;
			int lastError = UPNPDISCOVER_UNKNOWN_ERROR;

			// First use an ephemeral SSDP source port. It avoids colliding with
			// the Windows SSDP service and is accepted by standards-compliant
			// IGD v1/v2 devices.
			for (size_t i = 0; i < targets.size()
				&& (selected.state == UPNP_NO_IGD
					|| selected.state > UPNP_PRIVATEIP_IGD)
				&& !m_pOwner->m_bAbortDiscovery; ++i) {
				const char* const multicastInterface =
					targets[i].address.IsEmpty()
					? NULL : targets[i].address.GetString();
				const int delay = i == 0 ? 2500 : 1200;
				UPNPDev* devices = DiscoverIgdDevices(multicastInterface,
					delay, UPNP_LOCAL_PORT_ANY, false, lastError);
				ConsiderDiscoveredDevices(devices, selected);
				freeUPNPDevlist(devices);
			}

			// A minority of old IGDs reply only when M-SEARCH originates from
			// UDP/1900. Retry that exact legacy behavior on every useful LAN
			// interface, but only when no connected gateway was selected.
			for (size_t i = 0; i < targets.size()
				&& (selected.state == UPNP_NO_IGD
					|| selected.state > UPNP_PRIVATEIP_IGD)
				&& !m_pOwner->m_bAbortDiscovery; ++i) {
				const char* const multicastInterface =
					targets[i].address.IsEmpty()
					? NULL : targets[i].address.GetString();
				UPNPDev* devices = DiscoverIgdDevices(multicastInterface,
					1200, UPNP_LOCAL_PORT_SAME, false, lastError);
				ConsiderDiscoveredDevices(devices, selected);
				freeUPNPDevlist(devices);
			}

			// Broken firmware sometimes ignores every targeted ST while still
			// answering ssdp:all. Keep this as the final, broader discovery
			// pass so normal networks do not download unrelated descriptions.
			for (size_t i = 0; i < targets.size()
				&& (selected.state == UPNP_NO_IGD
					|| selected.state > UPNP_PRIVATEIP_IGD)
				&& !m_pOwner->m_bAbortDiscovery; ++i) {
				const char* const multicastInterface =
					targets[i].address.IsEmpty()
					? NULL : targets[i].address.GetString();
				UPNPDev* devices = DiscoverIgdDevices(multicastInterface,
					1200, UPNP_LOCAL_PORT_ANY, true, lastError);
				ConsiderDiscoveredDevices(devices, selected);
				freeUPNPDevlist(devices);
			}

			if (m_pOwner->m_bAbortDiscovery)
				return 0;
			if (selected.state == UPNP_NO_IGD) {
				DebugLog(_T("UPNP: No Internet Gateway Device found across %u interface candidate(s), last error %d"),
					static_cast<unsigned>(targets.size()), lastError);
				m_pOwner->m_nDiagnosticStage = UPNP_DIAG_NO_GATEWAY;
				m_pOwner->m_bUPnPPortsForwarded = TRIS_FALSE;
				m_pOwner->SendResultMessage();
				return 0;
			}

			m_pOwner->m_pURLs = new UPNPUrls();
			m_pOwner->m_pIGDData = new IGDdatas();
			selected.ReleaseUrls(*m_pOwner->m_pURLs);
			*m_pOwner->m_pIGDData = selected.data;
			strncpy_s(m_pOwner->m_achLanIP, selected.lanAddress, _TRUNCATE);
			strncpy_s(m_pOwner->m_achWanIP, selected.wanAddress, _TRUNCATE);
			const int iResult = selected.state;
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

	char achOutIP[40] = {};
	char achOutPort[8] = {};
	char achOutDescription[80] = {};
	char achEnabled[8] = {};
	char achLeaseDuration[16] = {};
	const auto noteFiniteLease = [this](uint32 lifetime) {
		if (lifetime != 0
			&& (m_pOwner->m_dwMappingLeaseLifetime == 0
				|| lifetime < m_pOwner->m_dwMappingLeaseLifetime))
			m_pOwner->m_dwMappingLeaseLifetime = lifetime;
	};
	const auto queryMapping = [&]() {
		achOutIP[0] = 0;
		achOutPort[0] = 0;
		achOutDescription[0] = 0;
		achEnabled[0] = 0;
		achLeaseDuration[0] = 0;
		return UPNP_GetSpecificPortMappingEntry(
			m_pOwner->m_pURLs->controlURL,
			m_pOwner->m_pIGDData->first.servicetype, achExternalPort,
			(bTCP ? sTCPa : sUDPa), NULL, achOutIP, achOutPort,
			achOutDescription, achEnabled, achLeaseDuration);
	};
	const auto observedTargetMatches = [&]() {
		return MappingTargetsLocalSocket(achOutIP, achOutPort, achEnabled,
			pachLANIP, nPort);
	};

	// Look before adding, not only during refresh. A manual rule or a mapping
	// left by another eMule instance is already sufficient when it targets the
	// exact same local socket. Adopting it avoids false 718 conflicts and never
	// grants this process permission to delete that foreign rule.
	int nResult = queryMapping();
	if (nResult == UPNPCOMMAND_SUCCESS && observedTargetMatches()) {
		const uint32 remaining = ParseLeaseDuration(achLeaseDuration, 0);
		const bool ownedDescription =
			strcmp(achOutDescription, pachDescription) == 0;
		if (!bCheckAndRefresh || !ownedDescription || remaining == 0) {
			noteFiniteLease(remaining);
			DebugLog(_T("UPNP: Reusing compatible mapping %hu -> %hu (%s) on %S%s"),
				*pExternalPort, nPort, (bTCP ? sTCP : sUDP), achOutIP,
				ownedDescription ? _T("") : _T(" (router-managed description)"));
			return true;
		}
		// Observing a finite rule does not renew it. Only renew rules whose
		// ownership description survived the router unchanged.
		DebugLog(_T("Checking UPnP: Owned finite mapping %hu -> %hu (%s) has %u seconds left; renewing it now"),
			*pExternalPort, nPort, (bTCP ? sTCP : sUDP), remaining);
	} else if (bCheckAndRefresh) {
		DebugLogWarning(_T("Checking UPnP: Mapping for port %hu (%s) is absent or incompatible (result %d); reopening"),
			nPort, (bTCP ? sTCP : sUDP), nResult);
	}

	const auto addFixedMapping = [&](const char* leaseDuration) {
		return UPNP_AddPortMapping(m_pOwner->m_pURLs->controlURL,
			m_pOwner->m_pIGDData->first.servicetype, achExternalPort,
			achPort, pachLANIP, pachDescription, (bTCP ? sTCPa : sUDPa),
			NULL, leaseDuration);
	};
	const auto adoptMappingAfterFailedAdd = [&]() {
		const int queryResult = queryMapping();
		if (queryResult != UPNPCOMMAND_SUCCESS || !observedTargetMatches())
			return false;
		const uint32 remaining = ParseLeaseDuration(achLeaseDuration, 0);
		noteFiniteLease(remaining);
		DebugLog(_T("UPNP: Add returned an error but the requested mapping %hu -> %hu (%s) already exists; reusing it"),
			*pExternalPort, nPort, (bTCP ? sTCP : sUDP));
		return true;
	};

	// Prefer a finite lease. A retry of the same fixed tuple is idempotent and
	// covers routers which apply the SOAP action but lose the HTTP response.
	uint32 requestedLifetime = kPreferredLeaseSeconds;
	nResult = addFixedMapping("7200");
	if (IsTransientUpnpError(nResult) && !m_pOwner->m_bAbortDiscovery) {
		::Sleep(150);
		nResult = addFixedMapping("7200");
	}
	if (nResult != UPNPCOMMAND_SUCCESS && adoptMappingAfterFailedAdd())
		return true;

	if (nResult != UPNPCOMMAND_SUCCESS) {
		// Error 725 explicitly requires this, while a number of non-compliant
		// IGD v1 routers report only 402/501 for the same lease restriction.
		DebugLog(_T("Adding finite PortMapping failed (%d: %S), retrying with lease 0..."),
			nResult, strupnperror(nResult));
		requestedLifetime = 0;
		nResult = addFixedMapping("0");
		if (IsTransientUpnpError(nResult) && !m_pOwner->m_bAbortDiscovery) {
			::Sleep(150);
			nResult = addFixedMapping("0");
		}
		if (nResult != UPNPCOMMAND_SUCCESS && adoptMappingAfterFailedAdd())
			return true;
	}

	// IGDv2 can reserve a different free external port. Try both a suggested
	// port and a true wildcard because deployed IGDv2 firmware disagrees on
	// which form AddAnyPortMapping accepts.
	const bool bDirectMapping = bTCP
		? nPort == m_pOwner->m_nTCPPort : nPort == m_pOwner->m_nUDPPort;
	if (nResult != UPNPCOMMAND_SUCCESS && bDirectMapping) {
		DebugLog(_T("Adding fixed UPnP mapping failed (%d: %S), trying IGDv2 AddAnyPortMapping..."),
			nResult, strupnperror(nResult));
		const CStringA suggestedExternalPort(achExternalPort);
		const auto addAnyMapping = [&](const char* externalPort,
			const char* leaseDuration, uint32 lifetime) {
			char reservedPort[8] = {};
			int result = UPNP_AddAnyPortMapping(
				m_pOwner->m_pURLs->controlURL,
				m_pOwner->m_pIGDData->first.servicetype, externalPort,
				achPort, pachLANIP, pachDescription,
				(bTCP ? sTCPa : sUDPa), NULL, leaseDuration, reservedPort);
			char* end = NULL;
			const unsigned long reserved = strtoul(reservedPort, &end, 10);
			if (result == UPNPCOMMAND_SUCCESS
				&& end != reservedPort && *end == 0
				&& reserved > 0 && reserved <= 65535) {
				*pExternalPort = static_cast<uint16>(reserved);
				_snprintf_s(achExternalPort, _countof(achExternalPort),
					_TRUNCATE, "%hu", *pExternalPort);
				requestedLifetime = lifetime;
			} else if (result == UPNPCOMMAND_SUCCESS)
				result = UPNPCOMMAND_INVALID_RESPONSE;
			return result;
		};

		requestedLifetime = kPreferredLeaseSeconds;
		nResult = addAnyMapping(suggestedExternalPort, "7200",
			kPreferredLeaseSeconds);
		if (nResult != UPNPCOMMAND_SUCCESS
			&& !IsTransientUpnpError(nResult)) {
			nResult = addAnyMapping(suggestedExternalPort, "0", 0);
		}
		if (nResult != UPNPCOMMAND_SUCCESS
			&& !IsTransientUpnpError(nResult)
			&& suggestedExternalPort != "0") {
			nResult = addAnyMapping("0", "7200",
				kPreferredLeaseSeconds);
			if (nResult != UPNPCOMMAND_SUCCESS
				&& !IsTransientUpnpError(nResult))
				nResult = addAnyMapping("0", "0", 0);
		}
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

	// Query up to three times: some routers acknowledge AddPortMapping before
	// their mapping table becomes readable. Description changes are tolerated
	// for reachability, but only an exact ownership description is journalled
	// and later eligible for deletion.
	m_pOwner->m_nDiagnosticStage = UPNP_DIAG_VERIFY_MAPPING;
	bool querySucceeded = false;
	bool targetMatches = false;
	for (unsigned attempt = 0; attempt < 3; ++attempt) {
		nResult = queryMapping();
		if (nResult == UPNPCOMMAND_SUCCESS) {
			querySucceeded = true;
			targetMatches = observedTargetMatches();
			break;
		}
		if (attempt != 2 && !m_pOwner->m_bAbortDiscovery)
			::Sleep(150u + attempt * 200u);
	}

	if (querySucceeded && targetMatches) {
		const uint32 verifiedLifetime = ParseLeaseDuration(achLeaseDuration,
			requestedLifetime);
		noteFiniteLease(verifiedLifetime);
		if (strcmp(achOutDescription, pachDescription) != 0) {
			DebugLogWarning(_T("UPNP: Router changed or omitted the mapping description for %hu (%s); mapping accepted but excluded from ownership-based deletion"),
				*pExternalPort, (bTCP ? sTCP : sUDP));
			DebugLog(_T("Successfully added compatible mapping %hu -> %hu (%s) on local IP %S"),
				*pExternalPort, nPort, (bTCP ? sTCP : sUDP), achOutIP);
			return true;
		}
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

	if (querySucceeded) {
		DebugLogWarning(_T("UPNP: Router acknowledged AddPortMapping but reports a different target for external port %hu (%s); rejecting it"),
			*pExternalPort, (bTCP ? sTCP : sUDP));
		return false;
	}

	// GetSpecificPortMappingEntry is optional in practice: a substantial set
	// of ISP routers implements AddPortMapping but returns 401/501 or malformed
	// XML for the readback action. The successful Add SOAP response remains the
	// authoritative result. Such a rule is usable but deliberately not written
	// to the ownership journal, so eMule can never delete an unverified rule.
	noteFiniteLease(requestedLifetime);
	DebugLogWarning(_T("UPNP: AddPortMapping succeeded for %hu -> %hu (%s), but readback is unsupported (%d: %S); accepting without deletion ownership"),
		*pExternalPort, nPort, (bTCP ? sTCP : sUDP), nResult,
		strupnperror(nResult));
	return true;
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
