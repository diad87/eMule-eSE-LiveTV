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
#include "UPnPWorkerLifecycle.h"
#include "UPnPDeferredReaperCore.h"
#include "natmap/ownership_cleanup_policy.h"
#include "natmap/upnp_discovery.h"
#include "natmap/upnp_lease_policy.h"
#include "natmap/upnp_mapping_result.h"
#include "natmap/upnp_recovery_policy.h"
#include "Log.h"
#include "Otherfunctions.h"
#include "miniupnpc\include\miniupnpc.h"
#include "miniupnpc\include\upnpcommands.h"
#include "miniupnpc\include\upnperrors.h"
#include "opcodes.h"
#include "../cryptopp/sha.h"

#include <algorithm>
#include <array>
#include <bcrypt.h>
#include <chrono>
#include <ctime>
#include <iphlpapi.h>
#include <vector>

#pragma comment(lib, "bcrypt.lib")

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

namespace {
thread_local std::atomic_bool* g_upnpWorkerCancelled = NULL;
thread_local CRITICAL_SECTION* g_upnpWorkerGlobalGate = NULL;

class UPnPWorkerGlobalAccess
{
public:
	UPnPWorkerGlobalAccess() : m_locked(false), m_allowed(true)
	{
		if (g_upnpWorkerGlobalGate != NULL) {
			::EnterCriticalSection(g_upnpWorkerGlobalGate);
			m_locked = true;
			m_allowed = g_upnpWorkerCancelled != NULL
				&& !g_upnpWorkerCancelled->load(std::memory_order_acquire);
		}
	}
	~UPnPWorkerGlobalAccess()
	{
		if (m_locked)
			::LeaveCriticalSection(g_upnpWorkerGlobalGate);
	}
	operator bool() const { return m_allowed; }
private:
	bool m_locked;
	bool m_allowed;
};
}

// On the UI thread these remain ordinary diagnostics. On the worker they are
// serialized with the cancellation fence and become inert after it.
#define ESE_UPNP_GATED_LOG(call) do { UPnPWorkerGlobalAccess access; \
	if (access) { call; } } while (0)
#define DebugLog(...) ESE_UPNP_GATED_LOG(DebugLog(__VA_ARGS__))
#define DebugLogWarning(...) ESE_UPNP_GATED_LOG(DebugLogWarning(__VA_ARGS__))
#define DebugLogError(...) ESE_UPNP_GATED_LOG(DebugLogError(__VA_ARGS__))

class CUPnPMiniLibDeferredReaper
{
public:
	static CUPnPMiniLibDeferredReaper* TryInstance() noexcept
	{
		// Deliberately never destroyed: static destruction order must not race a
		// worker retained for process teardown.
		static CUPnPMiniLibDeferredReaper* const instance =
			new (std::nothrow) CUPnPMiniLibDeferredReaper();
		return instance;
	}

	bool Adopt(CUPnPImplMiniLib* impl)
	{
		if (impl == NULL)
			return false;
		if (m_core.Adopt(impl, impl->m_hThreadHandle, Destroy)) {
			if (m_wake != NULL)
				::SetEvent(m_wake);
			return true;
		}
		// Capacity exhaustion is fail-safe: wrapper ownership was transferred,
		// so the still-active object becomes an intentional process-lifetime leak.
		return true;
	}

private:
	CUPnPMiniLibDeferredReaper() noexcept : m_wake(), m_thread()
	{
		if (StartUPnPDeferredReaperThread(
				m_wake, m_thread, ThreadProc, this)) {
			::CloseHandle(m_thread);
			m_thread = NULL;
		}
	}

	static DWORD WINAPI ThreadProc(void* context) noexcept
	{
		try {
			return static_cast<CUPnPMiniLibDeferredReaper*>(context)->Run();
		} catch (...) {
			// Never unwind through the Win32 thread ABI. Retained entries remain
			// safely process-lifetime owned if the reaper itself cannot continue.
			return ERROR_UNHANDLED_EXCEPTION;
		}
	}

	DWORD Run()
	{
		for (;;) {
			::WaitForSingleObject(m_wake, 250);
			m_core.PollOnce();
		}
	}

	static void Destroy(void* value)
	{
		delete static_cast<CUPnPImplMiniLib*>(value);
	}

	HANDLE m_wake;
	HANDLE m_thread;
	UPnPDeferredReaperCore<8> m_core;
};

static LPCSTR const sTCPa = "TCP";
static LPCSTR const sUDPa = "UDP";
static LPCTSTR const sTCP = _T("TCP");
static LPCTSTR const sUDP = _T("UDP");

namespace {

constexpr uint32 kPreferredLeaseSeconds = 7200;
constexpr unsigned kMaximumDiscoveryInterfaces = 5;
static_assert(UPNP_CONNECTED_IGD
	== static_cast<int>(natmap::UpnpIgdQuality::Connected),
	"miniupnpc connected-IGD value changed");
static_assert(UPNP_PRIVATEIP_IGD
	== static_cast<int>(natmap::UpnpIgdQuality::PrivateAddress),
	"miniupnpc private-IGD value changed");
static_assert(UPNP_DISCONNECTED_IGD
	== static_cast<int>(natmap::UpnpIgdQuality::Disconnected),
	"miniupnpc disconnected-IGD value changed");
static_assert(UPNP_UNKNOWN_DEVICE
	== static_cast<int>(natmap::UpnpIgdQuality::UnknownDevice),
	"miniupnpc unknown-device value changed");

static std::uint64_t MonotonicMilliseconds()
{
	return static_cast<std::uint64_t>(
		std::chrono::duration_cast<std::chrono::milliseconds>(
			std::chrono::steady_clock::now().time_since_epoch()).count());
}

struct DiscoveryTarget {
	std::string address;
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

static void ConsiderDiscoveredDevices(UPNPDev* devices,
	SelectedIgd& selected,
	natmap::UpnpDiscoverySelection& selection,
	const std::atomic_bool& cancelled)
{
	if (devices == NULL)
		return;

	DebugLog(_T("List of UPnP devices found on the network:"));
	for (UPNPDev* device = devices; device != NULL; device = device->pNext)
		DebugLog(_T("Desc: %S, st: %S"), device->descURL, device->st);

	// UPNP_GetValidIGD can perform several HTTP requests per device. Feed one
	// node at a time so cancellation is observed between bounded HTTP groups
	// instead of after an unbounded device list.
	for (UPNPDev* device = devices;
		device != NULL && !cancelled && selection.should_continue();) {
		UPNPDev* const next = device->pNext;
		device->pNext = NULL;
		UPNPUrls candidateUrls = {};
		IGDdatas candidateData = {};
		char candidateLan[40] = {};
		char candidateWan[40] = {};
		const int candidateState = UPNP_GetValidIGD(device, &candidateUrls,
			&candidateData, candidateLan, sizeof candidateLan,
			candidateWan, sizeof candidateWan);
		device->pNext = next;
		const natmap::UpnpIgdObservation observation = {
			static_cast<natmap::UpnpIgdQuality>(candidateState),
			candidateUrls.controlURL != NULL,
			candidateData.first.servicetype[0] != 0
		};
		if (selection.Consider(observation)) {
			FreeUPNPUrls(&selected.urls);
			selected.urls = candidateUrls;
			memset(&candidateUrls, 0, sizeof candidateUrls);
			selected.data = candidateData;
			strncpy_s(selected.lanAddress, candidateLan, _TRUNCATE);
			strncpy_s(selected.wanAddress, candidateWan, _TRUNCATE);
			selected.state = candidateState;
		}
		FreeUPNPUrls(&candidateUrls);
		device = next;
	}
}

static UPNPDev* DiscoverIgdDevice(const char* deviceType,
	const char* multicastInterface, int delayMilliseconds, int localPort,
	int& error)
{
	return upnpDiscoverDevice(deviceType, delayMilliseconds,
		multicastInterface, NULL, localPort, 0, 2, &error);
}

static const char* const s_discoveryDeviceTypes[] = {
	"urn:schemas-upnp-org:device:InternetGatewayDevice:2",
	"urn:schemas-upnp-org:service:WANIPConnection:2",
	"urn:schemas-upnp-org:device:InternetGatewayDevice:1",
	"urn:schemas-upnp-org:service:WANIPConnection:1",
	"urn:schemas-upnp-org:service:WANPPPConnection:1",
	"upnp:rootdevice"
};

static void AddDiscoveryTarget(std::vector<DiscoveryTarget>& targets,
	const char* address)
{
	if (address == NULL || address[0] == 0)
		return;
	for (const DiscoveryTarget& target : targets) {
		if (_stricmp(target.address.c_str(), address) == 0)
			return;
	}
	DiscoveryTarget target;
	target.address = address;
	targets.push_back(target);
}

static std::vector<DiscoveryTarget> GetDiscoveryTargets(
	const std::string& configuredAddress)
{
	std::vector<DiscoveryTarget> targets;
	if (!configuredAddress.empty()) {
		AddDiscoveryTarget(targets, configuredAddress.c_str());
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

static natmap::IpAddress NatmapIPv4(uint32 networkOrderAddress)
{
	const uint8* bytes = reinterpret_cast<const uint8*>(
		&networkOrderAddress);
	return natmap::IpAddress::V4(
		bytes[0], bytes[1], bytes[2], bytes[3]);
}

static bool SameNatmapAddress(
	const natmap::IpAddress& left,
	const natmap::IpAddress& right)
{
	return left.family == right.family && left.bytes == right.bytes;
}

static std::array<std::uint8_t, 32> UpnpOwnershipDigest(
	std::uint64_t ownerToken)
{
	std::array<std::uint8_t, 32> digest = {};
	if (ownerToken == 0)
		return digest;
	static const CryptoPP::byte domain[] = {
		'e', 's', 'e', '.', 'u', 'p', 'n', 'p', '.',
		'o', 'w', 'n', 'e', 'r', '.', 'v', '1'
	};
	CryptoPP::byte token[8] = {};
	for (size_t i = 0; i < _countof(token); ++i) {
		token[_countof(token) - 1 - i] = static_cast<CryptoPP::byte>(
			ownerToken >> (i * 8));
	}
	CryptoPP::SHA256 hash;
	hash.Update(domain, _countof(domain));
	hash.Update(token, _countof(token));
	hash.Final(reinterpret_cast<CryptoPP::byte*>(digest.data()));
	return digest;
}

static bool MappingTargetsLocalSocket(const char* internalClient,
	const char* internalPort, const char* enabled, const char* lanAddress,
	uint16 localPort)
{
	uint16 parsedPort = 0;
	const bool mappingEnabled = enabled == NULL || enabled[0] == 0
		|| (strcmp(enabled, "0") != 0 && _stricmp(enabled, "false") != 0);
	return natmap::ParseUpnpDecimalPort(internalPort, parsedPort)
		&& parsedPort == localPort
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
	const IGDdatas *pIGDData, const std::atomic_bool& cancelled)
{
	if (pURLs == NULL || pURLs->controlURL == NULL || pIGDData == NULL)
		return 0;
	unsigned count = 0;
	for (; count < 128 && !cancelled; ++count) {
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
	if (m_journalPathSnapshot.empty())
		return;
	const wchar_t* const path = m_journalPathSnapshot.c_str();
	HANDLE file = ::CreateFile(path, GENERIC_READ, FILE_SHARE_READ, NULL,
		OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (file == INVALID_HANDLE_VALUE) {
		if (::GetLastError() != ERROR_FILE_NOT_FOUND)
			DebugLogWarning(_T("UPNP ownership: cannot open journal '%s'"),
				path);
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
	if (m_journalPathSnapshot.empty())
		return false;
	const std::wstring& path = m_journalPathSnapshot;
	const std::wstring temporary = path + L".new";
	std::array<std::uint8_t, natmap::kOwnershipLedgerMaxEncodedSize> bytes{};
	const size_t length = natmap::EncodeOwnershipLedger(
		m_ownershipLedger, bytes.data(), bytes.size());
	if (length == 0)
		return false;
	natmap::OwnershipJournalCommit commit;
	if (!commit.Complete(natmap::OwnershipJournalStep::Encoded))
		return false;

	HANDLE file = ::CreateFile(temporary.c_str(), GENERIC_WRITE, 0, NULL,
		CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, NULL);
	if (file == INVALID_HANDLE_VALUE)
		return false;
	DWORD written = 0;
	const bool wrote = ::WriteFile(file, bytes.data(),
		static_cast<DWORD>(length), &written, NULL) != FALSE
		&& written == static_cast<DWORD>(length);
	if (!wrote
		|| !commit.Complete(
			natmap::OwnershipJournalStep::TemporaryWritten)) {
		commit.Fail();
		::CloseHandle(file);
		::DeleteFile(temporary.c_str());
		return false;
	}
	if (::FlushFileBuffers(file) == FALSE
		|| !commit.Complete(
			natmap::OwnershipJournalStep::TemporaryFlushed)) {
		commit.Fail();
		::CloseHandle(file);
		::DeleteFile(temporary.c_str());
		return false;
	}
	if (::CloseHandle(file) == FALSE
		|| !commit.Complete(
			natmap::OwnershipJournalStep::TemporaryClosed)) {
		commit.Fail();
		::DeleteFile(temporary.c_str());
		return false;
	}
	if (::MoveFileEx(temporary.c_str(), path.c_str(),
			MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) == FALSE
		|| !commit.Complete(
			natmap::OwnershipJournalStep::FinalReplaced)) {
		commit.Fail();
		::DeleteFile(temporary.c_str());
		return false;
	}

	std::array<std::uint8_t,
		natmap::kOwnershipLedgerMaxEncodedSize> persistedBytes{};
	HANDLE persisted = ::CreateFile(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
		NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (persisted == INVALID_HANDLE_VALUE) {
		commit.Fail();
		return false;
	}
	LARGE_INTEGER persistedSize = {};
	DWORD persistedRead = 0;
	const bool readBack =
		::GetFileSizeEx(persisted, &persistedSize) != FALSE
		&& persistedSize.QuadPart
			== static_cast<LONGLONG>(length)
		&& ::ReadFile(persisted, persistedBytes.data(),
			static_cast<DWORD>(length), &persistedRead, NULL) != FALSE
		&& persistedRead == static_cast<DWORD>(length);
	const bool closed = ::CloseHandle(persisted) != FALSE;
	natmap::OwnershipLedger decoded;
	const bool verified = readBack && closed
		&& std::equal(bytes.begin(), bytes.begin() + length,
			persistedBytes.begin())
		&& natmap::DecodeOwnershipLedger(
			persistedBytes.data(), length, decoded)
			== natmap::OwnershipLedgerDecodeStatus::Ok;
	if (!verified
		|| !commit.Complete(
			natmap::OwnershipJournalStep::FinalVerified)) {
		commit.Fail();
		DebugLogError(_T("UPNP ownership: atomically replaced journal failed readback verification"));
		return false;
	}
	return commit.IsPersisted();
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

bool CUPnPImplMiniLib::RemoveOwnershipRecordDurably(std::size_t index)
{
	if (index >= m_ownershipLedger.count)
		return false;
	const natmap::OwnershipLedger previous = m_ownershipLedger;
	RemoveOwnershipRecord(index);
	if (SaveOwnershipLedger())
		return true;
	m_ownershipLedger = previous;
	DebugLogWarning(_T("UPNP ownership: journal removal did not commit; restored in-memory proof for safe retry"));
	return false;
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

bool CUPnPImplMiniLib::DeleteEphemeralOwnedMapping(
	uint16 nLocalPort, uint16 nExternalPort, bool bTCP,
	const char* pachLANIP, uint32 nLifetimeSeconds,
	const natmap::OwnershipDescription& description,
	const char* observedClient, const char* observedPort,
	const char* observedDescription,
	std::size_t observedDescriptionCapacity)
{
	natmap::UpnpOwnershipRecord record{};
	record.owner_token = m_ownerToken;
	record.gateway_fingerprint = CurrentGatewayFingerprint();
	record.transport =
		bTCP ? natmap::Transport::Tcp : natmap::Transport::Udp;
	if (!ParseIPv4(pachLANIP, record.local_address))
		return false;
	record.local_port = nLocalPort;
	record.external_port = nExternalPort;
	record.lifetime_seconds = nLifetimeSeconds;
	const time_t now = std::time(NULL);
	if (now <= 0)
		return false;
	record.acquired_unix_seconds =
		static_cast<std::uint64_t>(now);
	record.generation = m_mappingGeneration;
	record.description = description;

	natmap::ObservedUpnpMapping observed{};
	observed.transport = record.transport;
	observed.external_port = nExternalPort;
	if (!ParseIPv4(observedClient, observed.local_address)
		|| !natmap::ParseUpnpDecimalPort(
			observedPort, observed.local_port)
		|| !natmap::ParseOwnershipDescription(
			observedDescription,
			observedDescriptionCapacity,
			observed.description)
		|| !natmap::IsUpnpCleanupAuthorized(
			record, record.gateway_fingerprint, observed)) {
		DebugLogWarning(_T("UPNP ownership: refusing rollback without complete ephemeral ownership proof"));
		return false;
	}
	// Cancellation after Add is the one case where beginning a journal write
	// is required: it makes the exact rollback crash-recoverable. Never issue
	// Delete unless that proof reached durable storage.
	if (!RecordOwnedMapping(nLocalPort, nExternalPort, bTCP, pachLANIP,
			nLifetimeSeconds, description)) {
		DebugLogWarning(_T("UPNP ownership: refusing rollback because durable proof could not be recorded"));
		return false;
	}

	char externalPort[8] = {};
	_snprintf_s(externalPort, _countof(externalPort), _TRUNCATE,
		"%hu", nExternalPort);
	const int result = UPNP_DeletePortMapping(
		m_pURLs->controlURL, m_pIGDData->first.servicetype,
		externalPort, bTCP ? sTCPa : sUDPa, NULL);
	if (result != UPNPCOMMAND_SUCCESS) {
		DebugLogWarning(_T("UPNP ownership: strict rollback failed for %s port %hu"),
			bTCP ? sTCP : sUDP, nExternalPort);
		return false;
	}
	char verifyClient[40] = {};
	char verifyPort[8] = {};
	char verifyDescription[80] = {};
	char verifyLease[16] = {};
	const int verify = UPNP_GetSpecificPortMappingEntryChecked(
		m_pURLs->controlURL, m_pIGDData->first.servicetype,
		externalPort, bTCP ? sTCPa : sUDPa, NULL,
		verifyClient, _countof(verifyClient), verifyPort,
		_countof(verifyPort), verifyDescription,
		_countof(verifyDescription), NULL, 0, verifyLease,
		_countof(verifyLease));
	if (verify != 714) {
		DebugLogWarning(_T("UPNP ownership: rollback absence could not be verified; retaining durable proof"));
		return false;
	}
	for (size_t i = 0; i < m_ownershipLedger.count; ++i) {
		const natmap::UpnpOwnershipRecord& current = m_ownershipLedger.records[i];
		if (current.transport == record.transport
				&& current.external_port == record.external_port
				&& current.owner_token == record.owner_token
				&& current.generation == record.generation)
			return RemoveOwnershipRecordDurably(i);
	}
	return false;
}

void CUPnPImplMiniLib::RecoverOwnedMappings()
{
	const natmap::OwnershipLedger pending = m_ownershipLedger;
	// A single record is the durable marker of a previously partial pair
	// cleanup. Retry it independently, still behind the exact product gate.
	if (pending.count == 1) {
		natmap::OwnershipCleanupSnapshot cleanup{};
		cleanup.state = natmap::OwnershipCleanupState::Partial;
		const int pendingIndex = pending.records[0].transport
			== natmap::Transport::Tcp ? 0 : 1;
		cleanup.absent[1 - pendingIndex] = true;
		while (!m_bAbortDiscovery && cleanup.may_delete()
			&& cleanup.delete_attempts[pendingIndex] < 2) {
			bool deleted = false;
			bool absent = false;
			CleanupOwnedRecordAttempt(
				pending.records[0], deleted, absent);
			natmap::RecordOwnershipCleanupAttempt(cleanup,
				pending.records[0].transport, deleted, absent);
		}
		return;
	}
	if (pending.count != 2) {
		DebugLogWarning(_T("UPNP ownership: cleanup pair preflight blocked by journal cardinality"));
		return;
	}
	if (!natmap::IsCoherentOwnershipPair(pending)) {
		DebugLogWarning(_T("UPNP ownership: cleanup pair identity mismatch; zero mappings removed"));
		return;
	}
	std::array<natmap::OwnershipCleanupAuthorization, 2> authorizations{};
	for (size_t i = 0; i < pending.count; ++i) {
		if (m_bAbortDiscovery)
			return;
		authorizations[i].transport = pending.records[i].transport;
		authorizations[i].decision = PreflightOwnedMapping(pending.records[i]);
	}
	natmap::OwnershipCleanupSnapshot cleanup =
		natmap::BeginOwnershipCleanup(authorizations);
	if (!cleanup.may_delete()) {
		DebugLogWarning(_T("UPNP ownership: cleanup pair preflight rejected; zero mappings removed"));
		return;
	}
	for (size_t i = 0; i < pending.count && cleanup.may_delete()
		&& !m_bAbortDiscovery; ++i) {
		const natmap::UpnpOwnershipRecord& record = pending.records[i];
		const int index = record.transport == natmap::Transport::Tcp ? 0 : 1;
		while (!m_bAbortDiscovery && cleanup.may_delete()
			&& cleanup.delete_attempts[index] < 2) {
			bool deleted = false;
			bool absent = false;
			CleanupOwnedRecordAttempt(record, deleted, absent);
			natmap::RecordOwnershipCleanupAttempt(
				cleanup, record.transport, deleted, absent);
		}
	}
	if (cleanup.state == natmap::OwnershipCleanupState::Partial)
		DebugLogWarning(_T("UPNP ownership: cleanup pair partial; durable retry retained"));
	else if (cleanup.state == natmap::OwnershipCleanupState::RetryExhausted)
		DebugLogWarning(_T("UPNP ownership: cleanup pair retry exhausted; durable proof retained"));
}

natmap::OwnershipDecision CUPnPImplMiniLib::PreflightOwnedMapping(
	const natmap::UpnpOwnershipRecord& record) const
{
	bool absent = false;
	return ObserveOwnedMapping(record, absent);
}

natmap::OwnershipDecision CUPnPImplMiniLib::ObserveOwnedMapping(
	const natmap::UpnpOwnershipRecord& record, bool& absent) const
{
	absent = false;
	if (!record.IsStructurallyValid() || m_pURLs == NULL
		|| m_pURLs->controlURL == NULL || m_pIGDData == NULL)
		return natmap::OwnershipDecision::InvalidRecord;
	const std::uint64_t gateway = CurrentGatewayFingerprint();
	if (gateway == 0 || record.gateway_fingerprint != gateway)
		return natmap::OwnershipDecision::GatewayMismatch;
	char externalPort[8] = {};
	char internalClient[40] = {};
	char internalPort[8] = {};
	char description[80] = {};
	char leaseDuration[16] = {};
	_snprintf_s(externalPort, _countof(externalPort), _TRUNCATE,
		"%hu", record.external_port);
	const int query = UPNP_GetSpecificPortMappingEntryChecked(
		m_pURLs->controlURL, m_pIGDData->first.servicetype,
		externalPort,
		record.transport == natmap::Transport::Tcp ? sTCPa : sUDPa,
		NULL, internalClient, _countof(internalClient),
		internalPort, _countof(internalPort),
		description, _countof(description), NULL, 0,
		leaseDuration, _countof(leaseDuration));
	if (m_bAbortDiscovery)
		return natmap::OwnershipDecision::InvalidObservation;
	if (query == 714) {
		absent = true;
		return natmap::OwnershipDecision::Owned;
	}
	if (query != UPNPCOMMAND_SUCCESS)
		return natmap::OwnershipDecision::InvalidObservation;
	natmap::ObservedUpnpMapping observed{};
	observed.transport = record.transport;
	observed.external_port = record.external_port;
	if (!natmap::ParseUpnpDecimalPort(internalPort, observed.local_port)
		|| !ParseIPv4(internalClient, observed.local_address)
		|| !natmap::ParseOwnershipDescription(description,
			_countof(description), observed.description))
		return natmap::OwnershipDecision::InvalidObservation;
	return natmap::EvaluateOwnershipForDeletion(record, gateway, observed);
}

bool CUPnPImplMiniLib::CleanupOwnedRecordAttempt(
	const natmap::UpnpOwnershipRecord& record,
	bool& deleteSucceeded, bool& absenceVerified)
{
	deleteSucceeded = false;
	absenceVerified = false;
	bool absent = false;
	if (ObserveOwnedMapping(record, absent)
		!= natmap::OwnershipDecision::Owned)
		return false;
	if (!absent) {
		char externalPort[8] = {};
		_snprintf_s(externalPort, _countof(externalPort), _TRUNCATE,
			"%hu", record.external_port);
		deleteSucceeded = UPNP_DeletePortMapping(
			m_pURLs->controlURL, m_pIGDData->first.servicetype,
			externalPort,
			record.transport == natmap::Transport::Tcp ? sTCPa : sUDPa,
			NULL) == UPNPCOMMAND_SUCCESS;
		if (m_bAbortDiscovery)
			return true;
		if (ObserveOwnedMapping(record, absent)
			!= natmap::OwnershipDecision::Owned || !absent)
			return true;
	}
	for (size_t i = 0; i < m_ownershipLedger.count; ++i) {
		const natmap::UpnpOwnershipRecord& current =
			m_ownershipLedger.records[i];
		if (current.transport == record.transport
			&& current.external_port == record.external_port
			&& current.owner_token == record.owner_token
			&& current.generation == record.generation) {
			absenceVerified = RemoveOwnershipRecordDurably(i);
			return true;
		}
	}
	return true;
}

CUPnPImplMiniLib::CUPnPImplMiniLib()
	: m_hBusyMutex(::CreateMutex(NULL, FALSE, NULL))
	, m_pURLs()
	, m_pIGDData()
	, m_hThreadHandle()
	, m_pWorkerThread()
	, m_ownerToken()
	, m_mappingGeneration()
	, m_mappingLocalAddress()
	, m_mappingGatewayAddress()
	, m_bOwnershipLedgerLoaded()
	, m_bSucceededOnce()
	, m_bDeferredReap()
	, m_stopTimeoutMilliseconds(kUPnPWorkerStopBoundMilliseconds)
	, m_testDeletionEvent()
	, m_bAbortDiscovery()
{
	::InitializeCriticalSection(&m_workerGlobalGate);
	m_nOldUDPPort = 0;
	m_nOldTCPPort = 0;
	m_nOldTCPWebPort = 0;
	m_achLanIP[0] = 0;
	m_achWanIP[0] = 0;
}

CUPnPImplMiniLib::~CUPnPImplMiniLib()
{
	if (!m_bDeferredReap)
		StopAsyncFind();
	else
		ReapCompletedWorker();
	// The owning wrapper transfers active instances before invoking delete.
	// Therefore destruction is reachable only after the worker is reaped.
	Cleanup();
	if (m_hBusyMutex != NULL)
		::CloseHandle(m_hBusyMutex);
	::DeleteCriticalSection(&m_workerGlobalGate);
	if (m_testDeletionEvent != NULL)
		::SetEvent(m_testDeletionEvent);
}

bool CUPnPImplMiniLib::DeferDestructionIfWorkerActive()
{
	StopAsyncFind();
	if (m_hThreadHandle == NULL)
		return false;
	// Callback fencing and cancellation happened in StopAsyncFind. Transfer
	// the complete owner before its destructor can run.
	m_bDeferredReap = true;
	CUPnPMiniLibDeferredReaper* const reaper =
		CUPnPMiniLibDeferredReaper::TryInstance();
	return reaper == NULL || reaper->Adopt(this);
}

namespace {
DWORD WINAPI DeferredReaperSelfTestWorker(void* eventHandle) noexcept
{
	for (;;) {
		const DWORD state = ::WaitForSingleObject(
			static_cast<HANDLE>(eventHandle), 100);
		if (state == WAIT_OBJECT_0)
			return 0;
		if (state != WAIT_TIMEOUT)
			return 1;
	}
}
}

bool CUPnPImplMiniLib::RunDeferredReaperSelfTest()
{
	HANDLE release = ::CreateEvent(NULL, TRUE, FALSE, NULL);
	HANDLE deleted = ::CreateEvent(NULL, TRUE, FALSE, NULL);
	if (release == NULL || deleted == NULL) {
		if (release != NULL) ::CloseHandle(release);
		if (deleted != NULL) ::CloseHandle(deleted);
		return false;
	}
	CUPnPImplMiniLib* impl = new (std::nothrow) CUPnPImplMiniLib();
	if (impl == NULL) {
		::CloseHandle(release);
		::CloseHandle(deleted);
		return false;
	}
	impl->m_stopTimeoutMilliseconds = 1;
	impl->m_testDeletionEvent = deleted;
	impl->m_pWorkerThread = new (std::nothrow) CStartDiscoveryThread(impl);
	impl->m_hThreadHandle = impl->m_pWorkerThread != NULL
		? ::CreateThread(NULL, 0, DeferredReaperSelfTestWorker,
			release, 0, NULL) : NULL;
	if (impl->m_hThreadHandle == NULL) {
		impl->m_testDeletionEvent = NULL;
		delete impl;
		::CloseHandle(release);
		::CloseHandle(deleted);
		return false;
	}
	CUPnPImpl* owned = impl;
	ReleaseUPnPOwnedImplementation(owned);
	const bool notDeletedWhileActive =
		::WaitForSingleObject(deleted, 0) == WAIT_TIMEOUT;
	const bool released = ::SetEvent(release) != FALSE;
	const bool deletedOnceSignalled =
		::WaitForSingleObject(deleted, SEC2MS(5)) == WAIT_OBJECT_0;
	::CloseHandle(release);
	::CloseHandle(deleted);
	return notDeletedWhileActive && released && deletedOnceSignalled;
}

bool CUPnPImplMiniLib::IsReady()
{
	ReapCompletedWorker();
	if (m_bAbortDiscovery)
		return false;
	// the only check we need to do is if we are already busy with some async/threaded function
	if (m_hBusyMutex == NULL)
		return false;
	const DWORD acquired = ::WaitForSingleObject(m_hBusyMutex, 0);
	if (acquired != WAIT_OBJECT_0)
		return false;
	::ReleaseMutex(m_hBusyMutex);
	return true;
}

bool CUPnPImplMiniLib::ReapCompletedWorker()
{
	if (m_hThreadHandle == NULL)
		return true;
	const DWORD state = ::WaitForSingleObject(m_hThreadHandle, 0);
	if (state == WAIT_OBJECT_0) {
		::CloseHandle(m_hThreadHandle);
		delete m_pWorkerThread;
		m_pWorkerThread = NULL;
		m_hThreadHandle = NULL;
		m_bAbortDiscovery = false;
		return true;
	}
	return false;
}

void CUPnPImplMiniLib::StopAsyncFind()
{
	// Fence callback/mailbox publication before signalling. A delivery already
	// queued is rejected later by the request gate/mailbox clear; no new post
	// can acquire the cleared callback under CUPnPImpl::m_resultMutex.
	if (ReapCompletedWorker()) {
		SetMessageOnResult(NULL, 0);
		return;
	}
	// Never wait on the worker-owned busy mutex.
	// SSDP waits are <=600ms and miniupnpc HTTP connect/send/receive waits are
	// The wait is a UI patience bound, not a claim about completion time of
	// third-party DNS/HTTP or journal I/O.
	const UPnPWorkerStopResult result = RequestCooperativeUPnPWorkerStop(
		m_hThreadHandle, m_bAbortDiscovery,
		m_stopTimeoutMilliseconds,
		[this]() {
			::EnterCriticalSection(&m_workerGlobalGate);
			SetMessageOnResult(NULL, 0);
			m_bAbortDiscovery.store(true, std::memory_order_release);
			::LeaveCriticalSection(&m_workerGlobalGate);
		});
	if (result == UPnPWorkerStopResult::Stopped) {
		::CloseHandle(m_hThreadHandle);
		delete m_pWorkerThread;
		m_pWorkerThread = NULL;
		m_hThreadHandle = NULL;
		m_bAbortDiscovery = false;
		DebugLog(_T("UPNP worker stopped cooperatively"));
	} else {
		// Fail safe: keep the stable join handle and cancellation asserted.
		// Repeated StopAsyncFind calls can reap it; never kill a thread while it
		// owns heap, mutex or durable ownership-ledger state.
		DebugLogError(_T("UPNP worker cooperative stop timed out; cancellation remains asserted"));
	}
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
	if (prot == NULL
		|| (_tcscmp(prot, sTCP) != 0
			&& _tcscmp(prot, sUDP) != 0)) {
		DebugLogWarning(_T("UPNP ownership: refusing cleanup for unknown protocol"));
		return;
	}

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
	if (!record.IsStructurallyValid()) {
		DebugLogWarning(_T("UPNP ownership: refusing cleanup for invalid local %s proof on port %hu"),
			prot, port);
		return;
	}
	if (gateway == 0) {
		DebugLogWarning(_T("UPNP ownership: current gateway identity is unavailable; retaining %s proof for port %hu"),
			prot, port);
		return;
	}
	if (record.gateway_fingerprint != gateway) {
		DebugLogWarning(_T("UPNP ownership: stale %s port %hu belongs to a different gateway; dropping local proof only"),
			prot, port);
		if (natmap::EvaluateUpnpRecovery(
				natmap::UpnpRecoveryObservation::GatewayMismatch)
			== natmap::UpnpRecoveryAction::DropLocalProof)
			RemoveOwnershipRecordDurably(index);
		return;
	}

	char achPort[8] = {};
	char achOutIP[40] = {};
	char achOutPort[8] = {};
	char achDescription[80] = {};
	char achLeaseDuration[16] = {};
	_snprintf_s(achPort, _countof(achPort), _TRUNCATE, "%hu", port);
	const int queryResult = UPNP_GetSpecificPortMappingEntryChecked(
		m_pURLs->controlURL, m_pIGDData->first.servicetype, achPort,
		transport == natmap::Transport::Tcp ? sTCPa : sUDPa, NULL,
		achOutIP, _countof(achOutIP),
		achOutPort, _countof(achOutPort),
		achDescription, _countof(achDescription),
		NULL, 0,
		achLeaseDuration, _countof(achLeaseDuration));
	if (queryResult != UPNPCOMMAND_SUCCESS) {
		const natmap::UpnpRecoveryAction recoveryAction =
			natmap::EvaluateUpnpRecovery(queryResult == 714
				? natmap::UpnpRecoveryObservation::MappingAbsent
				: natmap::UpnpRecoveryObservation::
					TransientReadbackFailure);
		if (recoveryAction
			== natmap::UpnpRecoveryAction::DropLocalProof) {
			RemoveOwnershipRecordDurably(index);
			DebugLog(_T("UPNP ownership: %s port %hu is already absent"),
				prot, port);
		} else {
			if (recoveryAction
					!= natmap::UpnpRecoveryAction::KeepLocalProof)
				return;
			DebugLogWarning(_T("UPNP ownership: cannot verify %s port %hu (%d: %S); mapping was not removed"),
				prot, port, queryResult, strupnperror(queryResult));
		}
		return;
	}

	natmap::ObservedUpnpMapping observed{};
	observed.transport = transport;
	natmap::ParseUpnpDecimalPort(achOutPort, observed.local_port);
	observed.external_port = port;
	ParseIPv4(achOutIP, observed.local_address);
	if (!natmap::ParseOwnershipDescription(
			achDescription, _countof(achDescription),
			observed.description)) {
		DebugLogWarning(_T("UPNP ownership: router returned an overlong, unterminated or non-printable description for %s port %hu; retaining proof"),
			prot, port);
		return;
	}
	const natmap::OwnershipDecision decision =
		natmap::EvaluateOwnershipForDeletion(record, gateway, observed);
	const bool cleanupAuthorized =
		natmap::IsUpnpCleanupAuthorized(record, gateway, observed);
	const natmap::UpnpRecoveryAction recoveryAction =
		natmap::EvaluateUpnpRecovery(decision);
	if (!cleanupAuthorized) {
		DebugLogWarning(_T("UPNP ownership: %s port %hu no longer matches proof (decision=%u); mapping was not removed"),
			prot, port, static_cast<unsigned>(decision));
		if (recoveryAction
			== natmap::UpnpRecoveryAction::DropLocalProof)
			RemoveOwnershipRecordDurably(index);
		return;
	}
	if (recoveryAction
			!= natmap::UpnpRecoveryAction::DeleteOwnedMapping)
		return;

	const int nResult = UPNP_DeletePortMapping(m_pURLs->controlURL,
		m_pIGDData->first.servicetype, achPort,
		transport == natmap::Transport::Tcp ? sTCPa : sUDPa, NULL);
	if (nResult == UPNPCOMMAND_SUCCESS) {
		DebugLog(_T("Successfully removed owned mapping for %s port %hu"),
			prot, port);
		if (!RemoveOwnershipRecordDurably(index))
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
	const DWORD acquired = bSkipLock ? WAIT_OBJECT_0
		: ::WaitForSingleObject(m_hBusyMutex, 0);
	if (acquired == WAIT_OBJECT_0) {
		if (m_pURLs != NULL && m_pURLs->controlURL != NULL
				&& m_pIGDData != NULL) {
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
		if (!bSkipLock)
			::ReleaseMutex(m_hBusyMutex);
	} else
		DebugLogError(_T("Unable to remove port mappings - implementation still busy"));
}

void CUPnPImplMiniLib::StartDiscovery(uint16 nTCPPort, uint16 nUDPPort, uint16 nTCPWebPort)
{
	UNREFERENCED_PARAMETER(nTCPWebPort);
	DebugLog(_T("Using MiniUPnPLib based implementation"));
	DebugLog(_T("miniupnpc (c) 2005-2024 Thomas Bernard - http://miniupnp.free.fr/"));
	// Snapshot every preference-derived input before the worker exists. These
	// immutable standard-library values remain valid if application globals are
	// subsequently torn down while cancellation compensation finishes.
	const char* const bindAddress = thePrefs.GetBindAddrA();
	m_bindAddressSnapshot = bindAddress != NULL ? bindAddress : "";
	const CString journalPath = thePrefs.GetMuleDirectory(EMULE_CONFIGDIR)
		+ _T("natmap-ownership.dat");
	m_journalPathSnapshot.assign(
		static_cast<LPCTSTR>(journalPath), journalPath.GetLength());
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
	m_nTCPWebPort = 0;
	m_nExternalUDPPort = nUDPPort;
	m_nExternalTCPPort = nTCPPort;
	m_nExternalTCPWebPort = 0;
	m_dwMappingLeaseLifetime = 0;
	m_dwMappingExternalIP = 0;
	m_dwMapperEpoch = 0;
	m_nDiagnosticStage = UPNP_DIAG_DISCOVERING;
	m_bUPnPPortsForwarded = TRIS_UNKNOWN;
	m_bSucceededOnce = false;
	m_bCheckAndRefresh = false;
	m_mappingLocalAddress = natmap::IpAddress{};
	m_mappingGatewayAddress = natmap::IpAddress{};

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

CUPnPImplMiniLib::CStartDiscoveryThread::CStartDiscoveryThread(
	CUPnPImplMiniLib* owner)
	: m_pOwner(owner)
	, m_operation(owner != NULL
		? owner->CaptureMappingOperation() : MappingOperationContext())
{
}

DWORD WINAPI CUPnPImplMiniLib::CStartDiscoveryThread::ThreadProc(
	void* context) noexcept
{
	CStartDiscoveryThread* worker =
		static_cast<CStartDiscoveryThread*>(context);
	if (worker == NULL || worker->m_pOwner == NULL)
		return ERROR_INVALID_PARAMETER;
	g_upnpWorkerCancelled = &worker->m_pOwner->m_bAbortDiscovery;
	g_upnpWorkerGlobalGate = &worker->m_pOwner->m_workerGlobalGate;
	DWORD result = ERROR_UNHANDLED_EXCEPTION;
	try {
		result = worker->Run();
	} catch (...) {
		// No exception may cross the raw Win32 thread ABI. Cancellation/reaper
		// ownership still keeps every referenced allocation alive.
	}
	g_upnpWorkerGlobalGate = NULL;
	g_upnpWorkerCancelled = NULL;
	return result;
}

void CUPnPImplMiniLib::CStartDiscoveryThread::SendFailure(
	natmap::ReasonCode reason)
{
	UPnPWorkerGlobalAccess globalAccess;
	if (!globalAccess || m_pOwner == NULL || m_pOwner->m_bAbortDiscovery)
		return;
	natmap::UpnpPairResultInput input;
	input.request = m_operation.request;
	input.gateway_address = m_operation.gateway_address;
	input.local_address = m_operation.local_address;
	input.failure_reason = reason;
	m_pOwner->SendMapperResultMessage(
		m_operation, natmap::BuildUpnpPairMapperResult(input));
}

DWORD CUPnPImplMiniLib::CStartDiscoveryThread::Run()
{
	if (!m_pOwner)
		return 0;

	const DWORD busy = ::WaitForSingleObject(m_pOwner->m_hBusyMutex, 0);
	if (busy != WAIT_OBJECT_0) {
		DebugLogWarning(_T("CUPnPImplMiniLib::CStartDiscoveryThread::Run, failed to acquire Lock, another Mapping try might be running already"));
		return 0;
	}
	struct MutexRelease {
		HANDLE value;
		~MutexRelease() { if (value != NULL) ::ReleaseMutex(value); }
	} releaseBusy = { m_pOwner->m_hBusyMutex };

	if (m_pOwner->m_bAbortDiscovery)// requesting to abort ASAP?
		return 0;
	if (m_pOwner->m_bCheckAndRefresh)
		m_pOwner->m_dwMappingLeaseLifetime = 0;

	bool bSucceeded = false;
	bool tcpReadbackMatches = false;
	bool tcpOwnershipMatches = false;
	bool tcpCreatedByOperation = false;
	bool udpReadbackMatches = false;
	bool udpOwnershipMatches = false;
	bool udpCreatedByOperation = false;
#if !(defined(_DEBUG) || defined(_BETA) || defined(_DEVBUILD))
	try
#endif
	{
		if (!m_pOwner->m_bCheckAndRefresh) {
			const std::vector<DiscoveryTarget> targets =
				GetDiscoveryTargets(m_pOwner->m_bindAddressSnapshot);
			SelectedIgd selected;
			natmap::UpnpDiscoverySelection discoverySelection;
			int lastError = UPNPDISCOVER_UNKNOWN_ERROR;

			// First use an ephemeral SSDP source port. It avoids colliding with
			// the Windows SSDP service and is accepted by standards-compliant
			// IGD v1/v2 devices.
			for (size_t i = 0; i < targets.size()
				&& discoverySelection.should_continue()
				&& !m_pOwner->m_bAbortDiscovery; ++i) {
				const char* const multicastInterface =
					targets[i].address.empty()
						? NULL : targets[i].address.c_str();
				for (size_t type = 0;
					type < _countof(s_discoveryDeviceTypes)
					&& discoverySelection.should_continue()
					&& !m_pOwner->m_bAbortDiscovery; ++type) {
					UPNPDev* devices = DiscoverIgdDevice(
						s_discoveryDeviceTypes[type], multicastInterface,
						400, UPNP_LOCAL_PORT_ANY, lastError);
					ConsiderDiscoveredDevices(devices, selected,
						discoverySelection, m_pOwner->m_bAbortDiscovery);
					freeUPNPDevlist(devices);
				}
			}

			// A minority of old IGDs reply only when M-SEARCH originates from
			// UDP/1900. Retry that exact legacy behavior on every useful LAN
			// interface, but only when no connected gateway was selected.
			for (size_t i = 0; i < targets.size()
				&& discoverySelection.should_continue()
				&& !m_pOwner->m_bAbortDiscovery; ++i) {
				const char* const multicastInterface =
					targets[i].address.empty()
						? NULL : targets[i].address.c_str();
				for (size_t type = 0;
					type < _countof(s_discoveryDeviceTypes)
					&& discoverySelection.should_continue()
					&& !m_pOwner->m_bAbortDiscovery; ++type) {
					UPNPDev* devices = DiscoverIgdDevice(
						s_discoveryDeviceTypes[type], multicastInterface,
						250, UPNP_LOCAL_PORT_SAME, lastError);
					ConsiderDiscoveredDevices(devices, selected,
						discoverySelection, m_pOwner->m_bAbortDiscovery);
					freeUPNPDevlist(devices);
				}
			}

			// Broken firmware sometimes ignores every targeted ST while still
			// answering ssdp:all. Keep this as the final, broader discovery
			// pass so normal networks do not download unrelated descriptions.
			for (size_t i = 0; i < targets.size()
				&& discoverySelection.should_continue()
				&& !m_pOwner->m_bAbortDiscovery; ++i) {
				const char* const multicastInterface =
					targets[i].address.empty()
						? NULL : targets[i].address.c_str();
				UPNPDev* devices = DiscoverIgdDevice("ssdp:all",
					multicastInterface, 600, UPNP_LOCAL_PORT_ANY, lastError);
				ConsiderDiscoveredDevices(devices, selected,
					discoverySelection, m_pOwner->m_bAbortDiscovery);
				freeUPNPDevlist(devices);
			}

			if (m_pOwner->m_bAbortDiscovery) {
				discoverySelection.Cancel();
				return 0;
			}
			discoverySelection.Complete();
			if (discoverySelection.status()
				== natmap::UpnpDiscoveryStatus::TimedOut) {
				DebugLog(_T("UPNP: No Internet Gateway Device found across %u interface candidate(s), last error %d"),
					static_cast<unsigned>(targets.size()), lastError);
				m_pOwner->m_nDiagnosticStage = UPNP_DIAG_NO_GATEWAY;
				m_pOwner->m_bUPnPPortsForwarded = TRIS_FALSE;
				SendFailure(natmap::ReasonCode::NoGateway);
				return 0;
			}

			m_pOwner->m_pURLs = new UPNPUrls();
			m_pOwner->m_pIGDData = new IGDdatas();
			selected.ReleaseUrls(*m_pOwner->m_pURLs);
			*m_pOwner->m_pIGDData = selected.data;
			strncpy_s(m_pOwner->m_achLanIP, selected.lanAddress, _TRUNCATE);
			strncpy_s(m_pOwner->m_achWanIP, selected.wanAddress, _TRUNCATE);
			natmap::IpAddress selectedLocalAddress;
			if (!CUPnPImplMiniLib::ParseIPv4(
					m_pOwner->m_achLanIP, selectedLocalAddress)
				|| !SameNatmapAddress(
					selectedLocalAddress,
					m_operation.local_address)) {
				DebugLogWarning(_T("UPNP: selected IGD uses a different local interface than the correlated route; rejecting it"));
				m_pOwner->m_nDiagnosticStage = UPNP_DIAG_NO_GATEWAY;
				m_pOwner->m_bUPnPPortsForwarded = TRIS_FALSE;
				SendFailure(natmap::ReasonCode::InterfaceChanged);
				return 0;
			}
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
				SendFailure(natmap::ReasonCode::NoMappingProtocol);
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
		} else {
			natmap::IpAddress refreshLocalAddress;
			const bool sameRoute =
				CUPnPImplMiniLib::ParseIPv4(
					m_pOwner->m_achLanIP, refreshLocalAddress)
				&& SameNatmapAddress(
					refreshLocalAddress,
					m_operation.local_address)
				&& SameNatmapAddress(
					m_pOwner->m_mappingLocalAddress,
					m_operation.local_address)
				&& SameNatmapAddress(
					m_pOwner->m_mappingGatewayAddress,
					m_operation.gateway_address);
			if (!sameRoute) {
				DebugLogWarning(_T("UPNP: active local interface or gateway changed since initial mapping; refusing refresh on the stale IGD"));
				m_pOwner->m_nDiagnosticStage = UPNP_DIAG_NO_GATEWAY;
				m_pOwner->m_bUPnPPortsForwarded = TRIS_FALSE;
				SendFailure(natmap::ReasonCode::InterfaceChanged);
				return 0;
			}
		}

		m_pOwner->m_nDiagnosticStage = UPNP_DIAG_TCP_MAPPING;
		bSucceeded = OpenPort(
			m_pOwner->m_nTCPPort, true, m_pOwner->m_achLanIP,
			m_pOwner->m_bCheckAndRefresh,
			&tcpReadbackMatches, &tcpOwnershipMatches,
			&tcpCreatedByOperation);
		natmap::UpnpTransportObservation tcpObservation = {
			natmap::Transport::Tcp,
			m_pOwner->m_nTCPPort,
			m_pOwner->m_nTCPPort,
			m_pOwner->m_nExternalTCPPort,
			tcpReadbackMatches,
			tcpOwnershipMatches,
			tcpCreatedByOperation
		};
		if (m_pOwner->m_bAbortDiscovery)
			bSucceeded = false;
		if (bSucceeded
			&& (!tcpReadbackMatches || !tcpOwnershipMatches)) {
			DebugLogWarning(_T("UPNP: TCP mapping is usable but lacks exact owned readback; refusing to create the UDP half"));
			bSucceeded = false;
		}
		if (bSucceeded && m_pOwner->m_nUDPPort != 0) {
			m_pOwner->m_nDiagnosticStage = UPNP_DIAG_UDP_MAPPING;
			bSucceeded = OpenPort(
				m_pOwner->m_nUDPPort, false, m_pOwner->m_achLanIP,
				m_pOwner->m_bCheckAndRefresh,
				&udpReadbackMatches, &udpOwnershipMatches,
				&udpCreatedByOperation);
		} else if (bSucceeded)
			bSucceeded = false;
		const natmap::UpnpTransportObservation udpObservation = {
			natmap::Transport::Udp,
			m_pOwner->m_nUDPPort,
			m_pOwner->m_nUDPPort,
			m_pOwner->m_nExternalUDPPort,
			udpReadbackMatches,
			udpOwnershipMatches,
			udpCreatedByOperation
		};
		if (m_pOwner->m_bAbortDiscovery)
			bSucceeded = false;
		if (bSucceeded) {
			natmap::UpnpPairResultInput pairInput;
			pairInput.request = m_operation.request;
			pairInput.gateway_address = m_operation.gateway_address;
			pairInput.local_address = m_operation.local_address;
			pairInput.external_address =
				NatmapIPv4(m_pOwner->m_dwMappingExternalIP);
			pairInput.tcp = tcpObservation;
			pairInput.udp = udpObservation;
			pairInput.lifetime_seconds =
				m_pOwner->m_dwMappingLeaseLifetime;
			pairInput.now_monotonic_ms = MonotonicMilliseconds();
			pairInput.ownership_identity_digest =
				UpnpOwnershipDigest(m_pOwner->m_ownerToken);
			pairInput.failure_reason =
				natmap::ReasonCode::InvalidResponse;
			const natmap::MapperResultData pairResult =
				natmap::BuildUpnpPairMapperResult(pairInput);
			bSucceeded = pairResult.status
				== (m_operation.request.operation
					== natmap::MappingOperation::Refresh
					? natmap::MappingStatus::Renewed
					: natmap::MappingStatus::Created);
		}
		if (!bSucceeded) {
			// TCP+UDP is one direct-reachability transaction. Remove only
			// mappings proven to have been created by this exact operation;
			// pre-existing and refreshed rules are never transaction rollback
			// candidates.
			if (natmap::ShouldRollbackUpnpMappingAfterAtomicFailure(
					tcpObservation)) {
				m_pOwner->DeletePort(
					m_pOwner->m_nExternalTCPPort, sTCP);
				m_pOwner->m_nExternalTCPPort = 0;
			}
			if (natmap::ShouldRollbackUpnpMappingAfterAtomicFailure(
					udpObservation)) {
				m_pOwner->DeletePort(
					m_pOwner->m_nExternalUDPPort, sUDP);
				m_pOwner->m_nExternalUDPPort = 0;
			}
		}
		if (bSucceeded) {
			if (m_operation.request.operation
				== natmap::MappingOperation::Initial) {
				m_pOwner->m_mappingLocalAddress =
					m_operation.local_address;
				m_pOwner->m_mappingGatewayAddress =
					m_operation.gateway_address;
			}
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
		natmap::UpnpPairResultInput pairInput;
		pairInput.request = m_operation.request;
		pairInput.gateway_address = m_operation.gateway_address;
		pairInput.local_address = m_operation.local_address;
		pairInput.external_address =
			NatmapIPv4(m_pOwner->m_dwMappingExternalIP);
		pairInput.tcp = natmap::UpnpTransportObservation{
			natmap::Transport::Tcp,
			m_pOwner->m_nTCPPort,
			m_pOwner->m_nTCPPort,
			m_pOwner->m_nExternalTCPPort,
			tcpReadbackMatches,
			tcpOwnershipMatches,
			tcpCreatedByOperation
		};
		pairInput.udp = natmap::UpnpTransportObservation{
			natmap::Transport::Udp,
			m_pOwner->m_nUDPPort,
			m_pOwner->m_nUDPPort,
			m_pOwner->m_nExternalUDPPort,
			udpReadbackMatches,
			udpOwnershipMatches,
			udpCreatedByOperation
		};
		pairInput.lifetime_seconds =
			m_pOwner->m_dwMappingLeaseLifetime;
		pairInput.now_monotonic_ms = MonotonicMilliseconds();
		pairInput.ownership_identity_digest =
			UpnpOwnershipDigest(m_pOwner->m_ownerToken);
		pairInput.failure_reason =
			m_pOwner->m_nDiagnosticStage == UPNP_DIAG_NO_GATEWAY
				? natmap::ReasonCode::NoGateway
				: m_pOwner->m_nDiagnosticStage
					== UPNP_DIAG_PROTOCOL_UNAVAILABLE
					? natmap::ReasonCode::NoMappingProtocol
					: m_pOwner->m_nDiagnosticStage
						== UPNP_DIAG_TABLE_FULL
						? natmap::ReasonCode::MappingConflict
						: natmap::ReasonCode::InvalidResponse;
		if (!bSucceeded)
			pairInput.udp.readback_matches = false;
		const natmap::MapperResultData pairResult =
			natmap::BuildUpnpPairMapperResult(pairInput);
		if (bSucceeded) {
			m_pOwner->m_bUPnPPortsForwarded = TRIS_TRUE;
			m_pOwner->m_bSucceededOnce = true;
		} else
			m_pOwner->m_bUPnPPortsForwarded = TRIS_FALSE;
		UPnPWorkerGlobalAccess globalAccess;
		if (globalAccess && !m_pOwner->m_bAbortDiscovery)
			m_pOwner->SendMapperResultMessage(m_operation, pairResult);
	}
	return 0;
}

bool CUPnPImplMiniLib::CStartDiscoveryThread::OpenPort(
	uint16 nPort,
	bool bTCP,
	char *pachLANIP,
	bool bCheckAndRefresh,
	bool *pReadbackMatches,
	bool *pOwnershipMatches,
	bool *pCreatedByOperation)
{
	if (pReadbackMatches != NULL)
		*pReadbackMatches = false;
	if (pOwnershipMatches != NULL)
		*pOwnershipMatches = false;
	if (pCreatedByOperation != NULL)
		*pCreatedByOperation = false;
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
		return UPNP_GetSpecificPortMappingEntryChecked(
			m_pOwner->m_pURLs->controlURL,
			m_pOwner->m_pIGDData->first.servicetype, achExternalPort,
			(bTCP ? sTCPa : sUDPa), NULL,
			achOutIP, _countof(achOutIP),
			achOutPort, _countof(achOutPort),
			achOutDescription, _countof(achOutDescription),
			achEnabled, _countof(achEnabled),
			achLeaseDuration, _countof(achLeaseDuration));
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
	if (m_pOwner->m_bAbortDiscovery)
		return false;
	const bool mappingProvenAbsentBeforeAdd = nResult == 714;
	const bool existingTargetMatches =
		nResult == UPNPCOMMAND_SUCCESS && observedTargetMatches();
	const uint32 remaining = existingTargetMatches
		? ParseLeaseDuration(achLeaseDuration, 0) : 0;
	const bool ownedDescription = existingTargetMatches
		&& strcmp(achOutDescription, pachDescription) == 0;
	const natmap::UpnpExistingLeaseAction existingAction =
		natmap::EvaluateUpnpExistingLease(
			natmap::UpnpExistingLeaseObservation{
				bCheckAndRefresh,
				nResult == UPNPCOMMAND_SUCCESS,
				existingTargetMatches,
				ownedDescription,
				remaining
			});
	if (existingAction == natmap::UpnpExistingLeaseAction::Reuse) {
		noteFiniteLease(remaining);
		const bool ownershipPersisted = !ownedDescription
			|| m_pOwner->RecordOwnedMapping(
				nPort, *pExternalPort, bTCP, pachLANIP,
				remaining, ownershipDescription);
		if (pReadbackMatches != NULL)
			*pReadbackMatches = true;
		if (pOwnershipMatches != NULL)
			*pOwnershipMatches =
				ownedDescription && ownershipPersisted;
		if (!ownershipPersisted) {
			m_pOwner->m_nDiagnosticStage =
				UPNP_DIAG_OWNERSHIP_PERSISTENCE;
			return false;
		}
		DebugLog(_T("UPNP: Reusing compatible mapping %hu -> %hu (%s) on %S%s"),
			*pExternalPort, nPort, (bTCP ? sTCP : sUDP), achOutIP,
			ownedDescription ? _T("") : _T(" (router-managed description)"));
		return true;
	}
	if (existingAction == natmap::UpnpExistingLeaseAction::RenewFinite) {
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
		if (m_pOwner->m_bAbortDiscovery)
			return false;
		const int queryResult = queryMapping();
		if (m_pOwner->m_bAbortDiscovery)
			return false;
		if (queryResult != UPNPCOMMAND_SUCCESS || !observedTargetMatches())
			return false;
		const uint32 remaining = ParseLeaseDuration(achLeaseDuration, 0);
		noteFiniteLease(remaining);
		const bool ownedDescription =
			strcmp(achOutDescription, pachDescription) == 0;
		const bool ownershipPersisted = !ownedDescription
			|| m_pOwner->RecordOwnedMapping(
				nPort, *pExternalPort, bTCP, pachLANIP,
				remaining, ownershipDescription);
		if (pReadbackMatches != NULL)
			*pReadbackMatches = true;
		if (pOwnershipMatches != NULL)
			*pOwnershipMatches =
				ownedDescription && ownershipPersisted;
		if (!ownershipPersisted) {
			m_pOwner->m_nDiagnosticStage =
				UPNP_DIAG_OWNERSHIP_PERSISTENCE;
			if (mappingProvenAbsentBeforeAdd && ownedDescription) {
				DebugLogError(_T("UPNP ownership: add response was lost and proof persistence failed for newly created %s port %hu; rolling mapping back"),
					(bTCP ? sTCP : sUDP), *pExternalPort);
				m_pOwner->DeleteEphemeralOwnedMapping(
					nPort, *pExternalPort, bTCP, pachLANIP,
					remaining, ownershipDescription,
					achOutIP, achOutPort, achOutDescription,
					_countof(achOutDescription));
			}
			return false;
		}
		if (pCreatedByOperation != NULL)
			*pCreatedByOperation =
				mappingProvenAbsentBeforeAdd && ownedDescription;
		DebugLog(_T("UPNP: Add returned an error but the requested mapping %hu -> %hu (%s) already exists; reusing it"),
			*pExternalPort, nPort, (bTCP ? sTCP : sUDP));
		return true;
	};
	const auto rollbackExactMappingAfterCancel = [&](uint32 lifetime) {
		if (!m_pOwner->m_bAbortDiscovery)
			return false;
		// Only an external port proven absent before Add can be attributed to
		// this attempt. The readback is intentionally allowed after cancel: it
		// is part of the bounded Get/Delete/Get compensation transaction.
		if (!mappingProvenAbsentBeforeAdd)
			return true;
		const int queryResult = queryMapping();
		if (queryResult == UPNPCOMMAND_SUCCESS
				&& observedTargetMatches()
				&& strcmp(achOutDescription, pachDescription) == 0) {
			m_pOwner->DeleteEphemeralOwnedMapping(
				nPort, *pExternalPort, bTCP, pachLANIP, lifetime,
				ownershipDescription, achOutIP, achOutPort,
				achOutDescription, _countof(achOutDescription));
		}
		return true;
	};

	// Prefer a finite lease. A retry of the same fixed tuple is idempotent and
	// covers routers which apply the SOAP action but lose the HTTP response.
	uint32 requestedLifetime = kPreferredLeaseSeconds;
	nResult = addFixedMapping("7200");
	if (rollbackExactMappingAfterCancel(requestedLifetime))
		return false;
	if (IsTransientUpnpError(nResult) && !m_pOwner->m_bAbortDiscovery) {
		::Sleep(150);
		nResult = addFixedMapping("7200");
		if (rollbackExactMappingAfterCancel(requestedLifetime))
			return false;
	}
	if (nResult != UPNPCOMMAND_SUCCESS && adoptMappingAfterFailedAdd())
		return true;

	if (!m_pOwner->m_bAbortDiscovery
		&& natmap::EvaluateUpnpLeaseAttempt(
			natmap::UpnpLeaseRequestKind::Finite,
			nResult == UPNPCOMMAND_SUCCESS)
		== natmap::UpnpLeaseAttemptAction::TryPermanent) {
		// Error 725 explicitly requires this, while a number of non-compliant
		// IGD v1 routers report only 402/501 for the same lease restriction.
		DebugLog(_T("Adding finite PortMapping failed (%d: %S), retrying with lease 0..."),
			nResult, strupnperror(nResult));
		requestedLifetime = 0;
		nResult = addFixedMapping("0");
		if (rollbackExactMappingAfterCancel(requestedLifetime))
			return false;
		if (IsTransientUpnpError(nResult) && !m_pOwner->m_bAbortDiscovery) {
			::Sleep(150);
			nResult = addFixedMapping("0");
			if (rollbackExactMappingAfterCancel(requestedLifetime))
				return false;
		}
		if (nResult != UPNPCOMMAND_SUCCESS && adoptMappingAfterFailedAdd())
			return true;
		const natmap::UpnpLeaseAttemptAction permanentAction =
			natmap::EvaluateUpnpLeaseAttempt(
				natmap::UpnpLeaseRequestKind::Permanent,
				nResult == UPNPCOMMAND_SUCCESS);
		if (permanentAction
			== natmap::UpnpLeaseAttemptAction::AcceptPermanent)
			requestedLifetime = 0;
	}

	// Do not use AddAnyPortMapping here. If its HTTP response is lost during
	// cancellation, the selected external port is unknowable and therefore
	// cannot be rolled back with exact ownership proof.

	if (nResult != UPNPCOMMAND_SUCCESS) {
		const unsigned mappingCount = CountReadablePortMappings(
			m_pOwner->m_pURLs, m_pOwner->m_pIGDData,
			m_pOwner->m_bAbortDiscovery);
		if (m_pOwner->m_bAbortDiscovery)
			return false;
		if (mappingCount >= 64) {
			m_pOwner->m_nDiagnosticStage = UPNP_DIAG_TABLE_FULL;
			DebugLogWarning(_T("UPNP: Router mapping table appears full (%u readable entries); no foreign mappings were modified"), mappingCount);
		}
		DebugLog(_T("Adding PortMapping failed: %d (%S)"), nResult, strupnperror(nResult));
		return false;
	}
	if (*pExternalPort == 0)
		*pExternalPort = nPort;
	// Query up to three times: some routers acknowledge AddPortMapping before
	// their mapping table becomes readable. Description changes are tolerated
	// for reachability, but only an exact ownership description is journalled
	// and later eligible for deletion.
	m_pOwner->m_nDiagnosticStage = UPNP_DIAG_VERIFY_MAPPING;
	bool querySucceeded = false;
	bool targetMatches = false;
	for (unsigned attempt = 0; attempt < 3; ++attempt) {
		if (m_pOwner->m_bAbortDiscovery) {
			rollbackExactMappingAfterCancel(requestedLifetime);
			return false;
		}
		nResult = queryMapping();
		if (m_pOwner->m_bAbortDiscovery) {
			rollbackExactMappingAfterCancel(requestedLifetime);
			return false;
		}
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
		if (rollbackExactMappingAfterCancel(verifiedLifetime))
			return false;
		noteFiniteLease(verifiedLifetime);
		if (strcmp(achOutDescription, pachDescription) != 0) {
			if (pReadbackMatches != NULL)
				*pReadbackMatches = true;
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
			m_pOwner->DeleteEphemeralOwnedMapping(
				nPort, *pExternalPort, bTCP, pachLANIP,
				verifiedLifetime, ownershipDescription,
				achOutIP, achOutPort, achOutDescription,
				_countof(achOutDescription));
			return false;
		}
		if (rollbackExactMappingAfterCancel(verifiedLifetime))
			return false;
		if (pReadbackMatches != NULL)
			*pReadbackMatches = true;
		if (pOwnershipMatches != NULL)
			*pOwnershipMatches = true;
		if (pCreatedByOperation != NULL)
			*pCreatedByOperation =
				mappingProvenAbsentBeforeAdd;
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
	if (!ReapCompletedWorker() || m_hThreadHandle != NULL) {
		m_bUPnPPortsForwarded = TRIS_FALSE;
		m_nDiagnosticStage = UPNP_DIAG_PROTOCOL_UNAVAILABLE;
		return;
	}
	CStartDiscoveryThread* pStartDiscoveryThread =
		new (std::nothrow) CStartDiscoveryThread(this);
	if (pStartDiscoveryThread == NULL) {
		m_hThreadHandle = NULL;
		m_bUPnPPortsForwarded = TRIS_FALSE;
		m_nDiagnosticStage = UPNP_DIAG_PROTOCOL_UNAVAILABLE;
		const MappingOperationContext operation =
			CaptureMappingOperation();
		natmap::UpnpPairResultInput input;
		input.request = operation.request;
		input.gateway_address = operation.gateway_address;
		input.local_address = operation.local_address;
		input.failure_reason =
			natmap::ReasonCode::NoMappingProtocol;
		SendMapperResultMessage(
			operation, natmap::BuildUpnpPairMapperResult(input));
		return;
	}
	m_pWorkerThread = pStartDiscoveryThread;
	m_hThreadHandle = ::CreateThread(NULL, 0,
		&CStartDiscoveryThread::ThreadProc, pStartDiscoveryThread,
		0, NULL);
	if (m_hThreadHandle == NULL) {
		delete m_pWorkerThread;
		m_pWorkerThread = NULL;
		m_bUPnPPortsForwarded = TRIS_FALSE;
		m_nDiagnosticStage = UPNP_DIAG_PROTOCOL_UNAVAILABLE;
		return;
	}
	// The heap context is owned before CreateThread; handle ownership is
	// acquired atomically from CreateThread, with no suspended-thread failure
	// mode and no secondary handle duplication.
}
