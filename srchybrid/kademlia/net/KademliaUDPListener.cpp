/*
Copyright (C)2003 Barry Dunne (https://www.emule-project.net)
Copyright (C)2007-2024 Merkur ( strEmail.Format("%s@%s", "devteam", "emule-project.net") / https://www.emule-project.net )


This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either
version 2 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

// Note To Mods //
/*
Please do not change anything here and release it.
There is going to be a new forum created just for the Kademlia side of the client.
If you feel there is an error or a way to improve something, please
post it in the forum first and let us look at it. If it is a real improvement,
it will be added to the official client. Changing something without knowing
what all it does, can cause great harm to the network if released in mass form.
Any mod that changes anything within the Kademlia side will not be allowed to advertise
their client on the eMule forum.
*/

#include "stdafx.h"
#include "../../LiveDebugLog.h"
#include "../../KadKeepalive.h"     // R.2: CKadKeepalive::OnPong (PONG -> supernode health)
#include "HolePunchCookie.h"        // eSE P0: return-routability cookie (anti-reflection)
#include "clientlist.h"
#include "ClientUDPSocket.h"
#include "emule.h"
#include "emuledlg.h"
#include "ipfilter.h"
#include "KadContactListCtrl.h"
#include "kademliawnd.h"
#include "listensocket.h"
#include "Log.h"
#include "opcodes.h"
#include "Packets.h"
#include "Statistics.h"
#include "updownclient.h"
#include "KademliaUDPListener.h"
#include "kademlia/io/ByteIO.h"
#include "kademlia/kademlia/Prefs.h"
#include "kademlia/kademlia/Kademlia.h"
#include "kademlia/kademlia/SearchManager.h"
#include "kademlia/kademlia/Indexed.h"
#include "kademlia/kademlia/Defines.h"
#include "kademlia/kademlia/Entry.h"
#include "kademlia/kademlia/KadV2Defines.h"    // F1: Kad Search v2 M3/M5/M6
#include "kademlia/kademlia/KadV2Sharding.h"
#include "kademlia/kademlia/KadV2BloomFilter.h"
#include "kademlia/kademlia/KadV2KEffective.h"
#include "kademlia/kademlia/KadV2Stats.h"
#include "kademlia/kademlia/UDPFirewallTester.h"
#include "kademlia/routing/RoutingZone.h"
#include "kademlia/routing/Contact.h"
#include "kademlia/routing/Kad6RoutingTable.h"
#include "Kad6CryptoHost.h"
#include "LiveTunnel.h"
#include "NodeIdentity.h"
#include "FirewallProberV6.h"   // [eSE v9] root link: GetDetectedV6IP() for the HELLO v6 tag
#include "eMuleAI/Address.h"     // [eSE v9] CAddress::Data()/GetType()/IsPublicIP()
#include "kademlia/utils/KadUDPKey.h"
#include "kademlia/utils/KadClientSearcher.h"
#include "LiveProtocol.h"
#include "cryptopp/osrng.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

extern LPCSTR g_aszInvKadKeywordCharsA;
extern LPCWSTR g_awszInvKadKeywordChars;

using namespace Kademlia;

static bool EseHolePunchTransportReady()
{
	return thePrefs.GetUtpHolePunchEnabled()
		&& theApp.clientudp != NULL && theApp.clientudp->IsUtpReady();
}

struct SEsePendingHolePunch {
	uint32 uIP;
	uint16 uUDPPort;
	uint32 uNonce;
	DWORD dwCreated;
	uint8 byChallengeResends;   // eSE P0: CHALLENGEs answered for this punch (anti-flood cap)
	uchar abyExpectedKadID[16]; // exact identity; public IP is not unique behind CGNAT
	bool bHasExpectedKadID;
	CUpDownClient* pExpectedClient; // compared against the live client list before dereference
	uint32 uExpectedClientIP;
	uint16 uExpectedClientTCPPort;
};

static CArray<SEsePendingHolePunch, SEsePendingHolePunch&> s_esePendingHolePunches;
static CCriticalSection s_eseHolePunchLock;
static const DWORD ESE_HOLEPUNCH_NONCE_TTL_MS = 30000;
static const INT_PTR ESE_HOLEPUNCH_MAX_PENDING = 1024;
static const INT_PTR ESE_RDV_MAX_PENDING = 256;

// eSE 8.12.1: CSPRNG for hole-punch nonce generation (anti-Sybil prediction).
// Dedicated static instance to avoid lock contention with EncryptedDatagramSocket's cryptRandomGen.
static CryptoPP::AutoSeededRandomPool s_eseHolePunchRng;

// eSE P0 — thread-safe wrapper for the shared hole-punch CSPRNG. CryptoPP's
// AutoSeededRandomPool is NOT thread-safe, yet SendEseHolePunchReq can be reached
// off the Kad/main thread (e.g. the WebServer worker in WebServer.cpp). Serialise
// EVERY GenerateBlock under the lock that already guards the pending-nonce list:
// the RNG's single call site is co-located with EseRememberHolePunchNonce, so a
// dedicated mutex would only add a second back-to-back acquisition for no benefit.
// All future randomness from this pool MUST go through here, never the raw object.
static void EseHolePunchRandomBlock(byte* pOut, size_t nLen)
{
	CSingleLock lock(&s_eseHolePunchLock, TRUE);
	s_eseHolePunchRng.GenerateBlock(pOut, nLen);
}

static void EsePrunePendingHolePunches(DWORD now)
{
	for (INT_PTR i = s_esePendingHolePunches.GetCount() - 1; i >= 0; --i) {
		if (now - s_esePendingHolePunches[i].dwCreated > ESE_HOLEPUNCH_NONCE_TTL_MS) {
			// eSE Telemetry: Nonce expired without a matching ACK — likely symmetric NAT
			// prevented the remote's reply from reaching us (port prediction miss).
			InterlockedIncrement(&CStatistics::m_dwHolePunchSymNATFail);
			s_esePendingHolePunches.RemoveAt(i);
		}
	}
}

static void EseRememberHolePunchNonce(uint32 uIP, uint16 uUDPPort, uint32 uNonce,
	CUpDownClient* pExpectedClient)
{
	CSingleLock lock(&s_eseHolePunchLock, TRUE);
	const DWORD now = GetTickCount();
	EsePrunePendingHolePunches(now);
	if (s_esePendingHolePunches.GetCount() >= ESE_HOLEPUNCH_MAX_PENDING) {
		// Bound memory even if a local/API caller floods attempts faster than the TTL.
		s_esePendingHolePunches.RemoveAt(0);
		InterlockedIncrement(&CStatistics::m_dwHolePunchSymNATFail);
	}

	SEsePendingHolePunch entry = {};
	entry.uIP = uIP;
	entry.uUDPPort = uUDPPort;
	entry.uNonce = uNonce;
	entry.dwCreated = now;
	entry.pExpectedClient = pExpectedClient;
	if (pExpectedClient != NULL) {
		entry.uExpectedClientIP = pExpectedClient->GetConnectIP() != 0
			? pExpectedClient->GetConnectIP() : pExpectedClient->GetIP();
		entry.uExpectedClientTCPPort = pExpectedClient->GetUserPort();
	}
	// The ACK carries the responder's Kad node ID, never its eD2K user hash.
	// Bind that identity only when the routing table can supply it for the
	// target endpoint.  A CUpDownClient has no Kad-ID field: copying its user
	// hash here made every legitimate ACK fail because the two 128-bit
	// identities are independently generated.
	if (CKademlia::GetRoutingZone() != NULL) {
		const uint16 uIdentityPort = pExpectedClient != NULL && pExpectedClient->GetKadPort() != 0
			? pExpectedClient->GetKadPort() : uUDPPort;
		CContact* pIdentityContact = CKademlia::GetRoutingZone()->GetContact(uIP, uIdentityPort, false);
		if (pIdentityContact != NULL) {
			pIdentityContact->GetClientID().ToByteArray(entry.abyExpectedKadID);
			entry.bHasExpectedKadID = true;
		}
	}
	s_esePendingHolePunches.Add(entry);
}

static bool EseConsumeHolePunchNonce(uint32 uIP, uint32 uNonce,
	const CUInt128& uResponderKadID, CUpDownClient** ppExpectedClient)
{
	if (ppExpectedClient != NULL)
		*ppExpectedClient = NULL;
	CSingleLock lock(&s_eseHolePunchLock, TRUE);
	const DWORD now = GetTickCount();
	EsePrunePendingHolePunches(now);

	for (INT_PTR i = s_esePendingHolePunches.GetCount() - 1; i >= 0; --i) {
		const SEsePendingHolePunch& entry = s_esePendingHolePunches[i];
		if (entry.uIP == uIP && entry.uNonce == uNonce) {
			if (entry.bHasExpectedKadID) {
				uchar abyResponderKadID[16];
				uResponderKadID.ToByteArray(abyResponderKadID);
				if (!md4equ(entry.abyExpectedKadID, abyResponderKadID))
					return false;
			}
			if (ppExpectedClient != NULL && entry.pExpectedClient != NULL
				&& theApp.clientlist != NULL
				&& theApp.clientlist->IsValidClient(entry.pExpectedClient)
				&& entry.uExpectedClientIP == htonl(uIP)
				&& entry.pExpectedClient->GetUserPort() == entry.uExpectedClientTCPPort)
			{
				*ppExpectedClient = entry.pExpectedClient;
			}
			s_esePendingHolePunches.RemoveAt(i);
			return true;
		}
	}
	return false;
}

// eSE P0: authorize acting on a CHALLENGE for (uIP, uNonce). Returns true iff we
// have a matching pending punch WE started AND have not already answered too many
// CHALLENGEs for it. Does NOT remove the entry — the final ACK consumes it
// (EseConsumeHolePunchNonce). The bounded resend budget lets a lost expanded-REQ
// be re-driven by a duplicate CHALLENGE without letting a spoofed/duplicated
// CHALLENGE make us spam expanded REQs.
static const uint8 ESE_HOLEPUNCH_MAX_CHALLENGE_RESENDS = 3;
static bool EseAuthorizeHolePunchChallenge(uint32 uIP, uint32 uNonce)
{
	CSingleLock lock(&s_eseHolePunchLock, TRUE);
	const DWORD now = GetTickCount();
	EsePrunePendingHolePunches(now);

	for (INT_PTR i = s_esePendingHolePunches.GetCount() - 1; i >= 0; --i) {
		SEsePendingHolePunch& entry = s_esePendingHolePunches[i];
		if (entry.uIP == uIP && entry.uNonce == uNonce) {
			if (entry.byChallengeResends >= ESE_HOLEPUNCH_MAX_CHALLENGE_RESENDS)
				return false;
			++entry.byChallengeResends;
			return true;
		}
	}
	return false;
}

// ─── R.1 (3-way rendezvous) — A-side pending state ────────────────────────────
// Mirrors s_esePendingHolePunches but also remembers the TARGET (B), so that when
// rendezvous R answers with a CHALLENGE (re-send REQ+cookie) or a PROCEED (start
// punching B), A knows whom it was trying to reach. Keyed by (R's IP, nonce). R and
// B are STATELESS — only the initiator A keeps state. Shares the 2-way lock + TTL.
struct SKad3RdvPending {
	uint32 uRdvIP;
	uint16 uRdvPort;
	uint32 uNonce;
	uint32 uTargetIP;
	uint16 uTargetPort;
	DWORD  dwCreated;
	uint8  byChallengeResends;
};
static CArray<SKad3RdvPending, SKad3RdvPending&> s_kad3RdvPending;

static void Kad3PruneRdv(DWORD now)
{
	for (INT_PTR i = s_kad3RdvPending.GetCount() - 1; i >= 0; --i)
		if (now - s_kad3RdvPending[i].dwCreated > ESE_HOLEPUNCH_NONCE_TTL_MS)
			s_kad3RdvPending.RemoveAt(i);
}

static void Kad3RememberRdv(uint32 uRdvIP, uint16 uRdvPort, uint32 uNonce, uint32 uTargetIP, uint16 uTargetPort)
{
	CSingleLock lock(&s_eseHolePunchLock, TRUE);
	const DWORD now = GetTickCount();
	Kad3PruneRdv(now);
	if (s_kad3RdvPending.GetCount() >= ESE_RDV_MAX_PENDING)
		s_kad3RdvPending.RemoveAt(0);
	SKad3RdvPending e = {};
	e.uRdvIP = uRdvIP; e.uRdvPort = uRdvPort; e.uNonce = uNonce;
	e.uTargetIP = uTargetIP; e.uTargetPort = uTargetPort; e.dwCreated = now;
	s_kad3RdvPending.Add(e);
}

// CHALLENGE: confirm WE started this punch (bounded resends), return the target so A
// re-sends REQ+cookie. Does NOT remove — the later PROCEED still needs the entry.
static bool Kad3AuthorizeRdvChallenge(uint32 uRdvIP, uint16 uRdvPort, uint32 uNonce, uint32 &uOutTargetIP, uint16 &uOutTargetPort)
{
	CSingleLock lock(&s_eseHolePunchLock, TRUE);
	const DWORD now = GetTickCount();
	Kad3PruneRdv(now);
	for (INT_PTR i = s_kad3RdvPending.GetCount() - 1; i >= 0; --i) {
		SKad3RdvPending &e = s_kad3RdvPending[i];
		if (e.uRdvIP == uRdvIP && e.uRdvPort == uRdvPort && e.uNonce == uNonce) {
			if (e.byChallengeResends >= ESE_HOLEPUNCH_MAX_CHALLENGE_RESENDS)
				return false;
			++e.byChallengeResends;
			uOutTargetIP = e.uTargetIP; uOutTargetPort = e.uTargetPort;
			return true;
		}
	}
	return false;
}

// PROCEED: consume the entry, return the target so A punches B directly.
static bool Kad3ConsumeRdvProceed(uint32 uRdvIP, uint16 uRdvPort, uint32 uNonce, uint32 &uOutTargetIP, uint16 &uOutTargetPort)
{
	CSingleLock lock(&s_eseHolePunchLock, TRUE);
	const DWORD now = GetTickCount();
	Kad3PruneRdv(now);
	for (INT_PTR i = s_kad3RdvPending.GetCount() - 1; i >= 0; --i) {
		const SKad3RdvPending &e = s_kad3RdvPending[i];
		if (e.uRdvIP == uRdvIP && e.uRdvPort == uRdvPort && e.uNonce == uNonce) {
			uOutTargetIP = e.uTargetIP; uOutTargetPort = e.uTargetPort;
			s_kad3RdvPending.RemoveAt(i);
			return true;
		}
	}
	return false;
}

static CString Kad6RouterEpochPath()
{
	return thePrefs.GetMuleDirectory(EMULE_CONFIGDIR) + _T("kad6_router_epoch.dat");
}

static bool LoadKad6RouterEpoch(std::uint64_t& epoch)
{
	epoch = 0;
	try {
		CFile file;
		if (!file.Open(Kad6RouterEpochPath(), CFile::modeRead | CFile::shareDenyWrite))
			return false;
		if (file.GetLength() != 16) {
			file.Close();
			return false;
		}
		byte bytes[16] = {};
		const bool ok = file.Read(bytes, sizeof bytes) == sizeof bytes;
		file.Close();
		if (!ok || bytes[0] != 'K' || bytes[1] != '6' || bytes[2] != 'E'
			|| bytes[3] != 'P' || bytes[4] != 1 || bytes[5] != 0
			|| bytes[6] != 0 || bytes[7] != 0)
			return false;
		for (std::size_t i = 0; i < 8; ++i)
			epoch |= static_cast<std::uint64_t>(bytes[8 + i]) << (8 * i);
		return epoch != 0;
	}
	catch (CFileException* error) {
		error->Delete();
		return false;
	}
}

static bool SaveKad6RouterEpoch(std::uint64_t epoch)
{
	if (epoch == 0)
		return false;
	byte bytes[16] = {'K', '6', 'E', 'P', 1, 0, 0, 0};
	for (std::size_t i = 0; i < 8; ++i)
		bytes[8 + i] = static_cast<byte>(epoch >> (8 * i));
	const CString path = Kad6RouterEpochPath();
	const CString temporary = path + _T(".new");
	try {
		CFile file(temporary, CFile::modeCreate | CFile::modeWrite
			| CFile::shareExclusive);
		file.Write(bytes, sizeof bytes);
		file.Flush();
		file.Close();
		if (!MoveFileEx(temporary, path,
			MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
			DeleteFile(temporary);
			return false;
		}
		return true;
	}
	catch (CFileException* error) {
		error->Delete();
		DeleteFile(temporary);
		return false;
	}
}

CKademliaUDPListener::CKademliaUDPListener()
	: m_kad6Epoch(static_cast<std::uint64_t>(time(NULL)))
	, m_kad6LocalRecordReady(false)
	, m_lastKad6Maintenance(0)
	, m_lastKad6Import(0)
	, m_lastKad6Challenge(0)
	, m_lastKad6Lookup(0)
{
	if (m_kad6Epoch == 0)
		m_kad6Epoch = 1;
	std::uint64_t persistedEpoch = 0;
	if (LoadKad6RouterEpoch(persistedEpoch))
		m_kad6Epoch = (std::max)(m_kad6Epoch, persistedEpoch);
}

namespace
{
	const std::size_t KAD6_ROUTING_K = 10;
	const std::size_t KAD6_LOOKUP_ALPHA = 3;
	const std::size_t KAD6_RESPONSE_PROBATION_LIMIT = KAD6_ROUTING_K / 2;

	kad6::Kad6Address Kad6AddressFromRaw(const byte address[16])
	{
		kad6::Kad6Address result;
		result.family = kad6::Kad6Address::Family::IPv6;
		std::memcpy(result.addr.data(), address, result.addr.size());
		return result;
	}

	bool Kad6IsLocalId(const kad6::KadId& nodeId)
	{
		CPrefs* prefs = CKademlia::GetPrefs();
		if (prefs == NULL)
			return true;
		kad6::KadId localId;
		prefs->GetKadID().ToByteArray(localId.data());
		return localId == nodeId;
	}

	bool Kad6HeaderMatchesSource(const kad6::K6RouteHeader& header,
		const kad6::Kad6Address& source, uint16 port)
	{
		if (header.sender_endpoint.addr != source
			|| header.sender_endpoint.udp_port != port)
			return false;
		return !Kad6IsLocalId(header.sender_id);
	}

	bool SameKad6Endpoint(const kad6::K6Endpoint& a,
		const kad6::K6Endpoint& b)
	{
		return a.addr == b.addr && a.udp_port == b.udp_port
			&& a.tcp_port == b.tcp_port
			&& a.transport_flags == b.transport_flags
			&& a.priority == b.priority && a.observed == b.observed
			&& a.valid_until == b.valid_until;
	}

	std::string Kad6StoredSourceKey(const kad6::K6SourceRecord& record)
	{
		std::string key(reinterpret_cast<const char*>(record.object_hash.data()),
			record.object_hash.size());
		key.append(reinterpret_cast<const char*>(record.source_pseudonym.data()),
			record.source_pseudonym.size());
		return key;
	}

	std::string Kad6NodeKey(const kad6::KadId& nodeId)
	{
		return std::string(reinterpret_cast<const char*>(nodeId.data()),
			nodeId.size());
	}
}

bool CKademliaUDPListener::BuildKad6Header(uint32 txid,
	kad6::K6RouteHeader& out)
{
	out = kad6::K6RouteHeader{};
	if (txid == 0 || !thePrefs.IsIPv6Enabled() || theApp.clientudp == NULL
		|| !theApp.clientudp->IsDualStack() || CKademlia::GetPrefs() == NULL
		|| !eSELive::NodeIdentityIsPersistent()
		|| eSELive::NodeIdentityPub() == NULL)
		return false;
	const CAddress publicV6 = CFirewallProberV6::Instance().GetDetectedV6IP();
	if (publicV6.GetType() != CAddress::IPv6 || !publicV6.IsPublicIP())
		return false;
	const uint16 kadPort = CPrefs::GetInternKadPort();
	if (kadPort == 0)
		return false;

	const std::uint64_t now = static_cast<std::uint64_t>(time(NULL));
	if (now == 0)
		return false;
	kad6::K6Endpoint endpoint;
	endpoint.addr.family = kad6::Kad6Address::Family::IPv6;
	std::memcpy(endpoint.addr.addr.data(), publicV6.Data(), 16);
	endpoint.udp_port = kadPort;
	endpoint.tcp_port = theApp.GetAdvertisedV6TcpPort();
	endpoint.transport_flags = kad6::kK6EpUdpKad6;
	endpoint.observed = 0;

	const bool endpointChanged = !m_kad6LocalRecordReady
		|| m_kad6LocalRecord.endpoints.empty()
		|| m_kad6LocalRecord.endpoints[0].addr != endpoint.addr
		|| m_kad6LocalRecord.endpoints[0].udp_port != endpoint.udp_port
		|| m_kad6LocalRecord.endpoints[0].tcp_port != endpoint.tcp_port
		|| m_kad6LocalRecord.endpoints[0].transport_flags
			!= endpoint.transport_flags;
	const bool expiring = !m_kad6LocalRecordReady
		|| m_kad6LocalRecord.valid_until <= now + 10 * 60;
	if (endpointChanged || expiring) {
		const std::uint64_t nextEpoch =
			std::max<std::uint64_t>(m_kad6Epoch + 1, now);
		if (nextEpoch <= m_kad6Epoch || !SaveKad6RouterEpoch(nextEpoch))
			return false;
		m_kad6Epoch = nextEpoch;
		m_kad6LocalRecord = kad6::K6RouterRecord{};
		CUInt128 localId = CKademlia::GetPrefs()->GetKadID();
		localId.ToByteArray(m_kad6LocalRecord.kad_id.data());
		std::memcpy(m_kad6LocalRecord.node_pub.data(),
			eSELive::NodeIdentityPub(), m_kad6LocalRecord.node_pub.size());
		m_kad6LocalRecord.epoch = m_kad6Epoch;
		m_kad6LocalRecord.caps = CAP_FORK_IPV6_WIRE | CAP_FORK_IPV6_KAD;
		m_kad6LocalRecord.valid_from = now > 60 ? now - 60 : 1;
		m_kad6LocalRecord.valid_until = now + 2 * 60 * 60;
		endpoint.valid_until = m_kad6LocalRecord.valid_until;
		m_kad6LocalRecord.endpoints.push_back(endpoint);
		std::vector<kad6::Byte> signedWire;
		if (kad6::SignK6RouterRecord(MakeKad6HostCryptoHooks(), NULL, 0,
			m_kad6LocalRecord, signedWire) != kad6::Kad6Status::Ok) {
			m_kad6LocalRecord = kad6::K6RouterRecord{};
			m_kad6LocalRecordReady = false;
			return false;
		}
		m_kad6LocalRecordReady = true;
	} else {
		endpoint = m_kad6LocalRecord.endpoints[0];
	}

	out.txid = txid;
	CUInt128 localId = CKademlia::GetPrefs()->GetKadID();
	localId.ToByteArray(out.sender_id.data());
	out.sender_caps = CAP_FORK_IPV6_WIRE | CAP_FORK_IPV6_KAD;
	out.sender_epoch = m_kad6LocalRecord.epoch;
	out.sender_endpoint = endpoint;
	out.sender_record = m_kad6LocalRecord;
	return SameKad6Endpoint(out.sender_endpoint,
		out.sender_record.endpoints[0]);
}

uint32 CKademliaUDPListener::NextKad6Transaction()
{
	for (unsigned attempt = 0; attempt < 16; ++attempt) {
		uint32 txid = 0;
		EseHolePunchRandomBlock(reinterpret_cast<byte*>(&txid), sizeof txid);
		if (txid == 0)
			continue;
		bool collision = false;
		for (const SKad6Pending& pending : m_kad6Pending)
			if (pending.txid == txid) {
				collision = true;
				break;
			}
		if (!collision)
			return txid;
	}
	return 0;
}

bool CKademliaUDPListener::SendKad6Payload(byte opcode,
	const std::vector<kad6::Byte>& payload, const byte address[16], uint16 port)
{
	if (theApp.clientudp == NULL || address == NULL || port == 0
		|| payload.size() > kad6::kK6StoreMaxPayloadSize)
		return false;
	Packet* packet = new Packet(OP_KADEMLIAHEADER);
	packet->opcode = opcode;
	packet->size = static_cast<uint32>(payload.size());
	packet->pBuffer = new char[payload.size()];
	if (!payload.empty())
		std::memcpy(packet->pBuffer, payload.data(), payload.size());
	theStats.AddUpDataOverheadKad(packet->size);
	return theApp.clientudp->SendPacketV6(packet, address, port);
}

void CKademliaUDPListener::RememberKad6Pending(const SKad6Pending& pending)
{
	if (m_kad6Pending.size() >= 256)
		m_kad6Pending.erase(m_kad6Pending.begin());
	m_kad6Pending.push_back(pending);
}

int CKademliaUDPListener::FindKad6Pending(uint32 txid, byte expectedOpcode,
	const byte address[16], uint16 port) const
{
	for (std::size_t i = 0; i < m_kad6Pending.size(); ++i) {
		const SKad6Pending& pending = m_kad6Pending[i];
		if (pending.txid == txid && pending.expectedOpcode == expectedOpcode
			&& pending.port == port
			&& std::memcmp(pending.address, address, 16) == 0)
			return static_cast<int>(i);
	}
	return -1;
}

bool CKademliaUDPListener::HasKad6PendingFor(const kad6::KadId& nodeId) const
{
	for (const SKad6Pending& pending : m_kad6Pending)
		if (pending.hasExpectedNode && pending.expectedNode == nodeId)
			return true;
	return false;
}

kad6::K6RouteContact CKademliaUDPListener::Kad6ContactFromHeader(
	const kad6::K6RouteHeader& header)
{
	kad6::K6RouteContact contact;
	contact.node_id = header.sender_id;
	contact.endpoint = header.sender_endpoint;
	contact.caps = header.sender_caps;
	contact.epoch = header.sender_epoch;
	return contact;
}

bool CKademliaUDPListener::SendKad6HelloChallenge(
	const kad6::K6RouteContact& contact, EKad6AfterVerify afterVerify,
	uint32 originalTxid, const kad6::KadId* target, byte maximum)
{
	if (HasKad6PendingFor(contact.node_id))
		return false;
	const uint32 txid = NextKad6Transaction();
	kad6::K6HelloRequest request;
	if (!BuildKad6Header(txid, request.header))
		return false;
	std::vector<kad6::Byte> wire;
	if (kad6::EncodeK6HelloRequest(request, wire) != kad6::Kad6Status::Ok
		|| !SendKad6Payload(KADEMLIA3_HELLO_REQ, wire,
			contact.endpoint.addr.addr.data(), contact.endpoint.udp_port))
		return false;

	SKad6Pending pending = {};
	pending.txid = txid;
	pending.expectedOpcode = KADEMLIA3_HELLO_RES;
	std::memcpy(pending.address, contact.endpoint.addr.addr.data(), 16);
	pending.port = contact.endpoint.udp_port;
	pending.expectedNode = contact.node_id;
	pending.hasExpectedNode = true;
	pending.created = GetTickCount();
	pending.afterVerify = afterVerify;
	pending.originalTxid = originalTxid;
	if (target != NULL)
		pending.target = *target;
	pending.maximum = maximum;
	RememberKad6Pending(pending);
	return true;
}

void CKademliaUDPListener::SendKad6BootstrapResponse(uint32 txid,
	const byte address[16], uint16 port)
{
	kad6::K6BootstrapResponse response;
	if (!BuildKad6Header(txid, response.header))
		return;
	CKad6RoutingTable* table = CKademlia::GetKad6RoutingTable();
	if (table == NULL)
		return;
	response.contacts = table->Closest(response.header.sender_id,
		KAD6_ROUTING_K, true);
	std::vector<kad6::Byte> wire;
	if (kad6::EncodeK6BootstrapResponse(response, wire) == kad6::Kad6Status::Ok)
		SendKad6Payload(KADEMLIA3_BOOTSTRAP_RES, wire, address, port);
}

void CKademliaUDPListener::SendKad6FindResponse(uint32 txid,
	const kad6::KadId& target, byte maximum, const byte address[16], uint16 port)
{
	kad6::K6FindNodeResponse response;
	if (!BuildKad6Header(txid, response.header))
		return;
	response.target_id = target;
	CKad6RoutingTable* table = CKademlia::GetKad6RoutingTable();
	if (table == NULL)
		return;
	response.contacts = table->Closest(target,
		maximum < KAD6_ROUTING_K ? maximum : KAD6_ROUTING_K, true);
	std::vector<kad6::Byte> wire;
	if (kad6::EncodeK6FindNodeResponse(response, wire) == kad6::Kad6Status::Ok)
		SendKad6Payload(KADEMLIA3_RES, wire, address, port);
}

void CKademliaUDPListener::SendKad6SourceResponse(uint32 txid,
	const kad6::Hash16& target, byte maximum, const byte address[16], uint16 port)
{
	kad6::K6FindSourceResponse response;
	if (!BuildKad6Header(txid, response.header)) return;
	response.target_hash = target;
	const std::uint64_t now = static_cast<std::uint64_t>(time(NULL));
	std::vector<const SKad6StoredSource*> matches;
	for (const auto& item : m_kad6StoredSources)
		if (item.second.record.object_hash == target &&
			item.second.record.expires_at > now)
			matches.push_back(&item.second);
	std::sort(matches.begin(), matches.end(),
		[](const SKad6StoredSource* a, const SKad6StoredSource* b) {
			if (a->record.source_epoch != b->record.source_epoch)
				return a->record.source_epoch > b->record.source_epoch;
			return a->record.expires_at > b->record.expires_at;
		});
	const size_t limit = (std::min<size_t>)(matches.size(),
		(std::min<size_t>)(maximum, kad6::kK6FindSourceMaxRecords));
	std::vector<kad6::Byte> wire;
	for (size_t i = 0; i < limit; ++i) {
		response.records.push_back(matches[i]->record);
		if (kad6::EncodeK6FindSourceResponse(response, wire) ==
				kad6::Kad6Status::TooLarge) {
			response.records.pop_back();
			break;
		}
	}
	if (kad6::EncodeK6FindSourceResponse(response, wire) == kad6::Kad6Status::Ok)
		SendKad6Payload(KADEMLIA3_FIND_SOURCE_RES, wire, address, port);
}

bool CKademliaUDPListener::DispatchKad6MaintenanceRound()
{
	if (!m_kad6AdaptiveLookup.active || m_kad6AdaptiveLookup.totalSent >= 24)
		return false;
	CKad6RoutingTable* table = CKademlia::GetKad6RoutingTable();
	if (!table) return false;
	const std::vector<kad6::K6RouteContact> contacts = table->Closest(
		m_kad6AdaptiveLookup.target, 64, true);
	byte sent = 0;
	for (const kad6::K6RouteContact& destination : contacts) {
		if (sent >= m_kad6AdaptiveLookup.alpha ||
			m_kad6AdaptiveLookup.totalSent >= 24) break;
		const std::string key = Kad6NodeKey(destination.node_id);
		if (m_kad6AdaptiveLookup.queried.find(key) !=
				m_kad6AdaptiveLookup.queried.end()) continue;
		const uint32 txid = NextKad6Transaction();
		kad6::K6FindNodeRequest request;
		request.target_id = m_kad6AdaptiveLookup.target;
		request.max_results = static_cast<byte>(KAD6_ROUTING_K);
		std::vector<kad6::Byte> wire;
		if (!BuildKad6Header(txid, request.header) ||
			kad6::EncodeK6FindNodeRequest(request, wire) != kad6::Kad6Status::Ok ||
			!SendKad6Payload(KADEMLIA3_REQ, wire,
				destination.endpoint.addr.addr.data(), destination.endpoint.udp_port))
			continue;
		SKad6Pending pending = {};
		pending.txid = txid;
		pending.expectedOpcode = KADEMLIA3_RES;
		std::memcpy(pending.address, destination.endpoint.addr.addr.data(), 16);
		pending.port = destination.endpoint.udp_port;
		pending.expectedNode = destination.node_id;
		pending.hasExpectedNode = true;
		pending.created = GetTickCount();
		pending.target = request.target_id;
		pending.maximum = request.max_results;
		pending.adaptiveLookup = true;
		RememberKad6Pending(pending);
		m_kad6AdaptiveLookup.queried.insert(key);
		++m_kad6AdaptiveLookup.totalSent;
		++sent;
	}
	m_kad6AdaptiveLookup.roundStarted = GetTickCount();
	return sent != 0;
}

bool CKademliaUDPListener::DispatchKad6SourceRound(uint64 lookupKey)
{
	auto found = m_kad6SourceLookups.find(lookupKey);
	if (found == m_kad6SourceLookups.end() || found->second.totalSent >= 24)
		return false;
	SKad6SourceLookup& lookup = found->second;
	CKad6RoutingTable* table = CKademlia::GetKad6RoutingTable();
	if (!table) return false;
	const std::vector<kad6::K6RouteContact> contacts = table->Closest(
		lookup.target, 64, true);
	byte sent = 0;
	for (const kad6::K6RouteContact& destination : contacts) {
		if (sent >= lookup.alpha || lookup.totalSent >= 24) break;
		const std::string nodeKey = Kad6NodeKey(destination.node_id);
		if (lookup.queried.find(nodeKey) != lookup.queried.end()) continue;
		const uint32 txid = NextKad6Transaction();
		kad6::K6FindSourceRequest request;
		request.target_hash = lookup.target;
		request.max_records = static_cast<byte>((std::min<uint16>)(
			kad6::kK6FindSourceMaxRecords,
			(std::max<uint16>)(1, lookup.maximum - lookup.received)));
		std::vector<kad6::Byte> wire;
		if (!BuildKad6Header(txid, request.header) ||
			kad6::EncodeK6FindSourceRequest(request, wire) != kad6::Kad6Status::Ok ||
			!SendKad6Payload(KADEMLIA3_FIND_SOURCE_REQ, wire,
				destination.endpoint.addr.addr.data(), destination.endpoint.udp_port)) {
			eSELive::CLiveTunnel::Get().OnKad6SourceLookupRpc(lookup.alpha, 2);
			continue;
		}
		SKad6Pending pending = {};
		pending.txid = txid;
		pending.expectedOpcode = KADEMLIA3_FIND_SOURCE_RES;
		std::memcpy(pending.address, destination.endpoint.addr.addr.data(), 16);
		pending.port = destination.endpoint.udp_port;
		pending.expectedNode = destination.node_id;
		pending.hasExpectedNode = true;
		pending.created = GetTickCount();
		pending.target = lookup.target;
		pending.maximum = request.max_records;
		pending.sourceCircuitId = lookup.circuitId;
		pending.sourceRequestId = lookup.requestId;
		pending.sourceAlpha = lookup.alpha;
		RememberKad6Pending(pending);
		lookup.queried.insert(nodeKey);
		++lookup.totalSent;
		++sent;
	}
	lookup.roundStarted = GetTickCount();
	return sent != 0;
}

bool CKademliaUDPListener::StartKad6SourceLookup(
	const kad6::Hash16& targetHash, uint32 circuitId, uint32 requestId,
	uint16 maximum)
{
	if (circuitId == 0 || requestId == 0 || maximum == 0 ||
		m_kad6SourceLookups.size() >= 64) return false;
	kad6::Byte any = 0;
	for (kad6::Byte value : targetHash) any = static_cast<kad6::Byte>(any | value);
	CKad6RoutingTable* table = CKademlia::GetKad6RoutingTable();
	if (any == 0 || !table || table->VerifiedSize() == 0) return false;
	const uint64 key = (static_cast<uint64>(circuitId) << 32) | requestId;
	if (m_kad6SourceLookups.find(key) != m_kad6SourceLookups.end()) return false;
	SKad6SourceLookup lookup;
	lookup.target = targetHash;
	lookup.circuitId = circuitId;
	lookup.requestId = requestId;
	lookup.maximum = (std::min<uint16>)(maximum, 100);
	lookup.started = GetTickCount();
	lookup.deadline = lookup.started + 12000;
	m_kad6SourceLookups[key] = lookup;
	if (!DispatchKad6SourceRound(key)) {
		m_kad6SourceLookups.erase(key);
		return false;
	}
	return true;
}

bool CKademliaUDPListener::PublishKad6SourceRecord(uint64 publishLeaseId,
	const kad6::K6SourceRecord& record)
{
	if (publishLeaseId == 0 ||
		kad6::VerifyK6SourceRecord(MakeKad6HostCryptoHooks(), record) != kad6::Kad6Status::Ok ||
		kad6::K6SourceRecordCheckFresh(record,
			static_cast<std::uint64_t>(time(NULL))) != kad6::Kad6Status::Ok)
		return false;
	CKad6RoutingTable* table = CKademlia::GetKad6RoutingTable();
	if (table == NULL)
		return false;
	const std::vector<kad6::K6RouteContact> contacts = table->Closest(
		record.object_hash, KAD6_ROUTING_K, true);
	bool sent = false;
	for (const kad6::K6RouteContact& destination : contacts) {
		const uint32 txid = NextKad6Transaction();
		kad6::K6StoreSourceRequest request;
		request.target_hash = record.object_hash;
		request.record = record;
		std::vector<kad6::Byte> wire;
		if (!BuildKad6Header(txid, request.header) ||
			kad6::EncodeK6StoreSourceRequest(request, wire) != kad6::Kad6Status::Ok ||
			!SendKad6Payload(KADEMLIA3_STORE_SOURCE_REQ, wire,
				destination.endpoint.addr.addr.data(), destination.endpoint.udp_port))
			continue;
		SKad6Pending pending = {};
		pending.txid = txid;
		pending.expectedOpcode = KADEMLIA3_STORE_SOURCE_RES;
		std::memcpy(pending.address, destination.endpoint.addr.addr.data(), 16);
		pending.port = destination.endpoint.udp_port;
		pending.expectedNode = destination.node_id;
		pending.hasExpectedNode = true;
		pending.created = GetTickCount();
		pending.publishLeaseId = publishLeaseId;
		pending.target = record.object_hash;
		RememberKad6Pending(pending);
		sent = true;
	}
	return sent;
}

bool CKademliaUDPListener::BootstrapV6(const byte address[16], uint16 port)
{
	if (address == NULL || port == 0)
		return false;
	CAddress hostAddress(address);
	if (hostAddress.GetType() != CAddress::IPv6 || !hostAddress.IsPublicIP())
		return false;
	const uint32 txid = NextKad6Transaction();
	kad6::K6BootstrapRequest request;
	if (!BuildKad6Header(txid, request.header))
		return false;
	std::vector<kad6::Byte> wire;
	if (kad6::EncodeK6BootstrapRequest(request, wire) != kad6::Kad6Status::Ok
		|| !SendKad6Payload(KADEMLIA3_BOOTSTRAP_REQ, wire, address, port))
		return false;

	SKad6Pending pending = {};
	pending.txid = txid;
	pending.expectedOpcode = KADEMLIA3_BOOTSTRAP_RES;
	std::memcpy(pending.address, address, 16);
	pending.port = port;
	pending.created = GetTickCount();
	pending.afterVerify = K6_AFTER_NONE;
	RememberKad6Pending(pending);
	return true;
}

CKademliaUDPListener::~CKademliaUDPListener()
{
// report timeout to all pending FetchNodeIDRequests
	for (POSITION pos = listFetchNodeIDRequests.GetHeadPosition(); pos != NULL;)
		listFetchNodeIDRequests.GetNext(pos).pRequester->KadSearchNodeIDByIPResult(KCSR_TIMEOUT, NULL);
}

// Used by Kad1.0 and Kad 2.0
void CKademliaUDPListener::Bootstrap(LPCTSTR szHost, uint16 uUDPPort)
{
	if (szHost == NULL || szHost[0] == 0 || uUDPPort == 0)
		return;
	if (_tcschr(szHost, _T(':')) != NULL) {
		CAddress literal(szHost, false);
		if (literal.GetType() == CAddress::IPv6) {
			BootstrapV6(literal.Data(), uUDPPort);
			return;
		}
	}
	const CStringA sHost(szHost);
	uint32 uRetVal = inet_addr(sHost);
	if (uRetVal == INADDR_NONE) {
		addrinfo hints = {};
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_DGRAM;
		addrinfo *resolved = NULL;
		if (getaddrinfo(sHost, NULL, &hints, &resolved) != 0)
			return;
		bool kad6Started = false;
		for (const addrinfo* candidate = resolved; candidate != NULL;
			candidate = candidate->ai_next) {
			if (candidate->ai_family == AF_INET && uRetVal == INADDR_NONE) {
				uRetVal = reinterpret_cast<const SOCKADDR_IN*>(
					candidate->ai_addr)->sin_addr.s_addr;
			} else if (candidate->ai_family == AF_INET6
				&& thePrefs.IsIPv6Enabled() && !kad6Started) {
				const SOCKADDR_IN6* address =
					reinterpret_cast<const SOCKADDR_IN6*>(candidate->ai_addr);
				kad6Started = BootstrapV6(
					reinterpret_cast<const byte*>(&address->sin6_addr), uUDPPort);
			}
		}
		freeaddrinfo(resolved);
		if (uRetVal == INADDR_NONE) {
			if (!kad6Started && thePrefs.GetVerbose())
				DebugLogWarning(_T("Kad6 bootstrap rejected for %s:%u"),
					szHost, uUDPPort);
			return;
		}
	}
	Bootstrap(ntohl(uRetVal), uUDPPort);
}

// Used by Kad1.0 and Kad 2.0
void CKademliaUDPListener::Bootstrap(uint32 uIP, uint16 uUDPPort, uint8 byKadVersion, const CUInt128 *uCryptTargetID)
{
	if (thePrefs.GetDebugClientKadUDPLevel() > 0)
		DebugSend("KADEMLIA2_BOOTSTRAP_REQ", uIP, uUDPPort);
	CSafeMemFile fileIO(0);
	SendPacket(fileIO, KADEMLIA2_BOOTSTRAP_REQ, uIP, uUDPPort, CKadUDPKey()
		, (byKadVersion >= KADEMLIA_VERSION6_49aBETA) ? uCryptTargetID : NULL);
}

// Used by Kad1.0 and Kad 2.0
void CKademliaUDPListener::SendMyDetails(byte byOpcode, uint32 uIP, uint16 uUDPPort, uint8 byKadVersion, const CKadUDPKey &targetUDPKey, const CUInt128 *uCryptTargetID, bool bRequestAckPackage)
{
	if (byKadVersion > 1) {
		byte byPacket[1024];
		CByteIO byteIOResponse(byPacket, sizeof(byPacket));
		byteIOResponse.WriteByte(OP_KADEMLIAHEADER);
		byteIOResponse.WriteByte(byOpcode);
		byteIOResponse.WriteUInt128(CKademlia::GetPrefs()->GetKadID());
		byteIOResponse.WriteUInt16(theApp.GetAdvertisedTcpPort());
		byteIOResponse.WriteUInt8(KADEMLIA_VERSION);

		// Tag Count.
		uint8 byTagCount = static_cast<uint8>(!CKademlia::GetPrefs()->GetUseExternKadPort());
		if (byKadVersion >= KADEMLIA_VERSION8_49b
			&& (bRequestAckPackage || CKademlia::GetPrefs()->GetFirewalled() || CUDPFirewallTester::IsFirewalledUDP(true)))
		{
			++byTagCount;
		}
		// Kad6 root link: emit our public IPv6 once the native K6-2 runtime is
		// live. The old preference remains as a manual developer override.
		// Compute ONCE (myV6 captured once — re-calling GetDetectedV6IP would be racy w.r.t. the
		// ++byTagCount / WriteTag pair). v8+ only; upstream ignores the unknown tag (additive).
		const CAddress myV6 = CFirewallProberV6::Instance().GetDetectedV6IP();
		extern uint32 g_uForkCapsRuntime;
		const LONG forkCaps = ::InterlockedCompareExchange(
			reinterpret_cast<volatile LONG*>(&g_uForkCapsRuntime), 0, 0);
		const bool bSendV6 = (thePrefs.GetEseKadV6Tag()
				|| (forkCaps & CAP_FORK_IPV6_KAD) != 0)
			&& byKadVersion >= KADEMLIA_VERSION8_49b
			&& myV6.GetType() == CAddress::IPv6 && myV6.IsPublicIP();
		if (bSendV6)
			++byTagCount;
		byteIOResponse.WriteUInt8(byTagCount);
		if (!CKademlia::GetPrefs()->GetUseExternKadPort())
			byteIOResponse.WriteTag(CKadTagUInt16(TAG_SOURCEUPORT, CKademlia::GetPrefs()->GetInternKadPort()));

		if (byKadVersion >= KADEMLIA_VERSION8_49b
			&& (bRequestAckPackage || CKademlia::GetPrefs()->GetFirewalled() || CUDPFirewallTester::IsFirewalledUDP(true)))
		{
			// if we are firewalled we sent this tag, so the other client doesn't add us to his routing table (if UDP firewalled) and for statistics reasons (TCP firewalled)
			// 5 - reserved (!)
			// 1 - Requesting HELLO_RES_ACK
			// 1 - TCP firewalled
			// 1 - UDP firewalled
			const uint8 uUDPFirewalled = static_cast<uint8>(CUDPFirewallTester::IsFirewalledUDP(true));
			const uint8 uTCPFirewalled = static_cast<uint8>(CKademlia::GetPrefs()->GetFirewalled());
			const uint8 uRequestACK = static_cast<uint8>(bRequestAckPackage);
			const uint8 byMiscOptions = (uRequestACK << 2) | (uTCPFirewalled << 1) | (uUDPFirewalled << 0);
			byteIOResponse.WriteTag(CKadTagUInt8(TAG_KADMISCOPTIONS, byMiscOptions));
		}
		if (bSendV6)   // [eSE v9] root link: 16 raw network-order bytes of our public IPv6
			byteIOResponse.WriteTag(CKadTagBsob(TAG_ESE_KADIP_V6, myV6.Data(), 16));
		//byteIOResponse.WriteTag(&CKadTagUInt(TAG_USER_COUNT, CKademlia::GetPrefs()->GetKademliaUsers()));
		//byteIOResponse.WriteTag(&CKadTagUInt(TAG_FILE_COUNT, CKademlia::GetPrefs()->GetKademliaFiles()));

		uint32 uLen = (uint32)(sizeof byPacket - byteIOResponse.GetAvailable());
		if (byKadVersion >= KADEMLIA_VERSION6_49aBETA) {
			if (uCryptTargetID && isnulmd4(uCryptTargetID->GetDataPtr())) {
				DebugLogWarning(_T("Sending hello response to crypt enabled Kad Node which provided an empty NodeID: %s (%u)"), (LPCTSTR)ipstr(htonl(uIP)), byKadVersion);
				SendPacket(byPacket, uLen, uIP, uUDPPort, targetUDPKey, NULL);
			} else
				SendPacket(byPacket, uLen, uIP, uUDPPort, targetUDPKey, uCryptTargetID);
		} else {
			SendPacket(byPacket, uLen, uIP, uUDPPort, CKadUDPKey(), NULL);
			ASSERT(targetUDPKey.IsEmpty());
		}
	}
	//else
	//	ASSERT(0);
}

// Kad1.0 & Kad2.0 currently.
void CKademliaUDPListener::FirewalledCheck(uint32 uIP, uint16 uUDPPort, const CKadUDPKey &senderUDPKey, uint8 byKadVersion)
{
	if (byKadVersion > KADEMLIA_VERSION6_49aBETA) {
		// new Opcode since 0.49a with extended informations to support obfuscated connections properly
		CSafeMemFile fileIO(19);
		fileIO.WriteUInt16(theApp.GetAdvertisedTcpPort());
		fileIO.WriteUInt128(CKademlia::GetPrefs()->GetClientHash());
		fileIO.WriteUInt8(CKademlia::GetPrefs()->GetMyConnectOptions(true, false));
		if (thePrefs.GetDebugClientKadUDPLevel() > 0)
			DebugSend("KADEMLIA_FIREWALLED2_REQ", uIP, uUDPPort);
		SendPacket(fileIO, KADEMLIA_FIREWALLED2_REQ, uIP, uUDPPort, senderUDPKey, NULL);
	} else {
		CSafeMemFile fileIO(2);
		fileIO.WriteUInt16(theApp.GetAdvertisedTcpPort());
		if (thePrefs.GetDebugClientKadUDPLevel() > 0)
			DebugSend("KADEMLIA_FIREWALLED_REQ", uIP, uUDPPort);
		SendPacket(fileIO, KADEMLIA_FIREWALLED_REQ, uIP, uUDPPort, senderUDPKey, NULL);
	}
	theApp.clientlist->AddKadFirewallRequest(ntohl(uIP));
}

void CKademliaUDPListener::SendNullPacket(byte byOpcode, uint32 uIP, uint16 uUDPPort, const CKadUDPKey &targetUDPKey, const CUInt128 *uCryptTargetID)
{
	CSafeMemFile fileIO(0);
	SendPacket(fileIO, byOpcode, uIP, uUDPPort, targetUDPKey, uCryptTargetID);
}

void CKademliaUDPListener::SendPublishSourcePacket(CContact *pContact, const CUInt128 &uTargetID, const CUInt128 &uContactID, const TagList &tags)
{
	//We need to get the tag lists working with CSafeMemFiles.
	LPCSTR pszOper;
	byte byPacket[1024];
	CByteIO byteIO(byPacket, sizeof byPacket);
	byteIO.WriteByte(OP_KADEMLIAHEADER);
	if (pContact->GetVersion() >= KADEMLIA_VERSION4_47c) {
		pszOper = "KADEMLIA2_PUBLISH_SOURCE_REQ";
		byteIO.WriteByte(KADEMLIA2_PUBLISH_SOURCE_REQ);
		byteIO.WriteUInt128(uTargetID);
	} else {
		pszOper = "KADEMLIA_PUBLISH_REQ";
		byteIO.WriteByte(KADEMLIA_PUBLISH_REQ);
		byteIO.WriteUInt128(uTargetID);
		//We only use this for publishing sources now. So we always send one here.
		byteIO.WriteUInt16(1);
	}
	byteIO.WriteUInt128(uContactID);
	byteIO.WriteTagList(tags);
	if (thePrefs.GetDebugClientKadUDPLevel() > 0)
		DebugSend(pszOper, pContact->GetIPAddress(), pContact->GetUDPPort());
	uint32 uLen = (uint32)(sizeof byPacket - byteIO.GetAvailable());
	if (pContact->GetVersion() >= KADEMLIA_VERSION6_49aBETA) { // obfuscated?
		CUInt128 uClientID = pContact->GetClientID();
		SendPacket(byPacket, uLen, pContact->GetIPAddress(), pContact->GetUDPPort(), pContact->GetUDPKey(), &uClientID);
	} else
		SendPacket(byPacket, uLen, pContact->GetIPAddress(), pContact->GetUDPPort(), CKadUDPKey(), NULL);
}

void CKademliaUDPListener::ProcessPacket(const byte *pbyData, uint32 uLenData, uint32 uIP, uint16 uUDPPort, bool bValidReceiverKey, const CKadUDPKey &senderUDPKey)
{
	// we do not accept (<= 0.48a) unencrypted incoming packets from port 53 (DNS) to avoid attacks based on DNS protocol confusion
	if (uUDPPort == 53 && senderUDPKey.IsEmpty()) {
		DEBUG_ONLY(DebugLog(_T("Dropping incoming unencrypted packet on port 53 (DNS), IP: %s"), (LPCTSTR)ipstr(htonl(uIP))));
		return;
	}

	//Update connection state only when it changes.
	bool bCurCon = CKademlia::GetPrefs()->HasHadContact();
	CKademlia::GetPrefs()->SetLastContact();
	CUDPFirewallTester::Connected();
	if (bCurCon != CKademlia::GetPrefs()->HasHadContact())
		theApp.emuledlg->ShowConnectionState();

	uint8 byOpcode = pbyData[1];
	switch (InTrackListIsAllowedPacket(uIP, uUDPPort, byOpcode, bValidReceiverKey)) {
	case 2: //massive flood
		{
			CContact *pContact = CKademlia::GetRoutingZone()->GetContact(uIP, uUDPPort, false);
			if (pContact)
				pContact->Expire(); //to be deleted from routing zone
			//AddDebugLogLine(false, _T("KAD massive flood: IP=%s:%hu, opcode 0x%02x, in routing zone: %s"), (LPCTSTR)ipstr(htonl(uIP)), uUDPPort, byOpcode, pContact ? _T("yes") : _T("no"));
		}
		return;
	case 1: //flood
		//AddDebugLogLine(false, _T("KAD flood: IP=%s:%hu, opcode: 0x%02x"), (LPCTSTR)ipstr(htonl(uIP)), uUDPPort, byOpcode);
		return;
	}

	const byte *pbyPacketData = pbyData + 2;
	uLenData -= 2;
	//AddDebugLogLine( false, _T("Processing UDP Packet from %s port %ld : opcode length %ld", (LPCTSTR)ipstr(senderAddress->sin_addr), ntohs(senderAddress->sin_port), uLenData);
	//CMiscUtils::debugHexDump(pbyPacketData, uLenData);
	switch (byOpcode) {
	case KADEMLIA2_BOOTSTRAP_REQ:
		if (thePrefs.GetDebugClientKadUDPLevel() > 0)
			DebugRecv("KADEMLIA2_BOOTSTRAP_REQ", uIP, uUDPPort);
		Process_KADEMLIA2_BOOTSTRAP_REQ(uIP, uUDPPort, senderUDPKey);
		break;
	case KADEMLIA2_BOOTSTRAP_RES:
		if (thePrefs.GetDebugClientKadUDPLevel() > 0)
			DebugRecv("KADEMLIA2_BOOTSTRAP_RES", uIP, uUDPPort);
		Process_KADEMLIA2_BOOTSTRAP_RES(pbyPacketData, uLenData, uIP, uUDPPort, senderUDPKey, bValidReceiverKey);
		break;
	case KADEMLIA2_HELLO_REQ:
		if (thePrefs.GetDebugClientKadUDPLevel() > 0)
			DebugRecv("KADEMLIA2_HELLO_REQ", uIP, uUDPPort);
		Process_KADEMLIA2_HELLO_REQ(pbyPacketData, uLenData, uIP, uUDPPort, senderUDPKey, bValidReceiverKey);
		break;
	case KADEMLIA2_HELLO_RES:
		if (thePrefs.GetDebugClientKadUDPLevel() > 0)
			DebugRecv("KADEMLIA2_HELLO_RES", uIP, uUDPPort);
		Process_KADEMLIA2_HELLO_RES(pbyPacketData, uLenData, uIP, uUDPPort, senderUDPKey, bValidReceiverKey);
		break;
	case KADEMLIA2_HELLO_RES_ACK:
		if (thePrefs.GetDebugClientKadUDPLevel() > 0)
			DebugRecv("KADEMLIA2_HELLO_RES_ACK", uIP, uUDPPort);
		Process_KADEMLIA2_HELLO_RES_ACK(pbyPacketData, uLenData, uIP, bValidReceiverKey);
		break;
	case KADEMLIA2_REQ:
		if (thePrefs.GetDebugClientKadUDPLevel() > 0)
			DebugRecv("KADEMLIA2_REQ", uIP, uUDPPort);
		Process_KADEMLIA2_REQ(pbyPacketData, uLenData, uIP, uUDPPort, senderUDPKey);
		break;
	case KADEMLIA2_RES:
		if (thePrefs.GetDebugClientKadUDPLevel() > 0)
			DebugRecv("KADEMLIA2_RES", uIP, uUDPPort);
		Process_KADEMLIA2_RES(pbyPacketData, uLenData, uIP, uUDPPort, senderUDPKey);
		break;
	case KADEMLIA2_SEARCH_NOTES_REQ:
		if (thePrefs.GetDebugClientKadUDPLevel() > 0)
			DebugRecv("KADEMLIA2_SEARCH_NOTES_REQ", uIP, uUDPPort);
		Process_KADEMLIA2_SEARCH_NOTES_REQ(pbyPacketData, uLenData, uIP, uUDPPort, senderUDPKey);
		break;
	case KADEMLIA2_SEARCH_KEY_REQ:
		if (thePrefs.GetDebugClientKadUDPLevel() > 0)
			DebugRecv("KADEMLIA2_SEARCH_KEY_REQ", uIP, uUDPPort);
		Process_KADEMLIA2_SEARCH_KEY_REQ(pbyPacketData, uLenData, uIP, uUDPPort, senderUDPKey);
		break;
	case KADEMLIA2_SEARCH_SOURCE_REQ:
		if (thePrefs.GetDebugClientKadUDPLevel() > 0)
			DebugRecv("KADEMLIA2_SEARCH_SOURCE_REQ", uIP, uUDPPort);
		Process_KADEMLIA2_SEARCH_SOURCE_REQ(pbyPacketData, uLenData, uIP, uUDPPort, senderUDPKey);
		break;
	case KADEMLIA_SEARCH_RES:
		if (thePrefs.GetDebugClientKadUDPLevel() > 0)
			DebugRecv("KADEMLIA_SEARCH_RES", uIP, uUDPPort);
		Process_KADEMLIA_SEARCH_RES(pbyPacketData, uLenData, uIP, uUDPPort);
		break;
	case KADEMLIA_SEARCH_NOTES_RES:
		if (thePrefs.GetDebugClientKadUDPLevel() > 0)
			DebugRecv("KADEMLIA_SEARCH_NOTES_RES", uIP, uUDPPort);
		Process_KADEMLIA_SEARCH_NOTES_RES(pbyPacketData, uLenData, uIP, uUDPPort);
		break;
	case KADEMLIA2_SEARCH_RES:
		if (thePrefs.GetDebugClientKadUDPLevel() > 0)
			DebugRecv("KADEMLIA2_SEARCH_RES", uIP, uUDPPort);
		Process_KADEMLIA2_SEARCH_RES(pbyPacketData, uLenData, senderUDPKey, uIP, uUDPPort);
		break;
	case KADEMLIA2_PUBLISH_KEY_REQ:
		if (thePrefs.GetDebugClientKadUDPLevel() > 0)
			DebugRecv("KADEMLIA2_PUBLISH_KEY_REQ", uIP, uUDPPort);
		Process_KADEMLIA2_PUBLISH_KEY_REQ(pbyPacketData, uLenData, uIP, uUDPPort, senderUDPKey);
		break;
	case KADEMLIA2_PUBLISH_SOURCE_REQ:
		if (thePrefs.GetDebugClientKadUDPLevel() > 0)
			DebugRecv("KADEMLIA2_PUBLISH_SOURCE_REQ", uIP, uUDPPort);
		Process_KADEMLIA2_PUBLISH_SOURCE_REQ(pbyPacketData, uLenData, uIP, uUDPPort, senderUDPKey);
		break;
	case KADEMLIA2_PUBLISH_NOTES_REQ:
		if (thePrefs.GetDebugClientKadUDPLevel() > 0)
			DebugRecv("KADEMLIA2_PUBLISH_NOTES_REQ", uIP, uUDPPort);
		Process_KADEMLIA2_PUBLISH_NOTES_REQ(pbyPacketData, uLenData, uIP, uUDPPort, senderUDPKey);
		break;
	case KADEMLIA_PUBLISH_RES:
		if (thePrefs.GetDebugClientKadUDPLevel() > 0)
			DebugRecv("KADEMLIA_PUBLISH_RES", uIP, uUDPPort);
		Process_KADEMLIA_PUBLISH_RES(pbyPacketData, uLenData, uIP);
		break;
	case KADEMLIA2_PUBLISH_RES:
		if (thePrefs.GetDebugClientKadUDPLevel() > 0)
			DebugRecv("KADEMLIA2_PUBLISH_RES", uIP, uUDPPort);
		Process_KADEMLIA2_PUBLISH_RES(pbyPacketData, uLenData, uIP, uUDPPort, senderUDPKey);
		break;
	case KADEMLIA_FIREWALLED_REQ:
		if (thePrefs.GetDebugClientKadUDPLevel() > 0)
			DebugRecv("KADEMLIA_FIREWALLED_REQ", uIP, uUDPPort);
		Process_KADEMLIA_FIREWALLED_REQ(pbyPacketData, uLenData, uIP, uUDPPort, senderUDPKey);
		break;
	case KADEMLIA_FIREWALLED2_REQ:
		if (thePrefs.GetDebugClientKadUDPLevel() > 0)
			DebugRecv("KADEMLIA_FIREWALLED2_REQ", uIP, uUDPPort);
		Process_KADEMLIA_FIREWALLED2_REQ(pbyPacketData, uLenData, uIP, uUDPPort, senderUDPKey);
		break;
	case KADEMLIA_FIREWALLED_RES:
		if (thePrefs.GetDebugClientKadUDPLevel() > 0)
			DebugRecv("KADEMLIA_FIREWALLED_RES", uIP, uUDPPort);
		Process_KADEMLIA_FIREWALLED_RES(pbyPacketData, uLenData, uIP, senderUDPKey);
		break;
	case KADEMLIA_FIREWALLED_ACK_RES:
		if (thePrefs.GetDebugClientKadUDPLevel() > 0)
			DebugRecv("KADEMLIA_FIREWALLED_ACK_RES", uIP, uUDPPort);
		Process_KADEMLIA_FIREWALLED_ACK_RES(uLenData);
		break;
	case KADEMLIA_FINDBUDDY_REQ:
		if (thePrefs.GetDebugClientKadUDPLevel() > 0)
			DebugRecv("KADEMLIA_FINDBUDDY_REQ", uIP, uUDPPort);
		Process_KADEMLIA_FINDBUDDY_REQ(pbyPacketData, uLenData, uIP, uUDPPort, senderUDPKey);
		break;
	case KADEMLIA_FINDBUDDY_RES:
		if (thePrefs.GetDebugClientKadUDPLevel() > 0)
			DebugRecv("KADEMLIA_FINDBUDDY_RES", uIP, uUDPPort);
		Process_KADEMLIA_FINDBUDDY_RES(pbyPacketData, uLenData, uIP, uUDPPort, senderUDPKey);
		break;
	case KADEMLIA_CALLBACK_REQ:
		if (thePrefs.GetDebugClientKadUDPLevel() > 0)
			DebugRecv("KADEMLIA_CALLBACK_REQ", uIP, uUDPPort);
		Process_KADEMLIA_CALLBACK_REQ(pbyPacketData, uLenData, uIP, senderUDPKey);
		break;
	case KADEMLIA2_PING:
		if (thePrefs.GetDebugClientKadUDPLevel() > 0)
			DebugRecv("KADEMLIA2_PING", uIP, uUDPPort);
		Process_KADEMLIA2_PING(uIP, uUDPPort, senderUDPKey);
		break;
	case KADEMLIA2_PONG:
		if (thePrefs.GetDebugClientKadUDPLevel() > 0)
			DebugRecv("KADEMLIA2_PONG", uIP, uUDPPort);
		Process_KADEMLIA2_PONG(pbyPacketData, uLenData, uIP, uUDPPort, senderUDPKey);
		break;
	case KADEMLIA2_FIREWALLUDP:
		if (thePrefs.GetDebugClientKadUDPLevel() > 0)
			DebugRecv("KADEMLIA2_FIREWALLUDP", uIP, uUDPPort);
		Process_KADEMLIA2_FIREWALLUDP(pbyPacketData, uLenData, uIP, senderUDPKey);
		break;

	// eSE Fase 3: uTP Hole Punching opcodes
	case KADEMLIA_ESE_HOLEPUNCH_REQ:
		if (thePrefs.GetDebugClientKadUDPLevel() > 0)
			DebugRecv("KADEMLIA_ESE_HOLEPUNCH_REQ", uIP, uUDPPort);
		Process_ESE_HOLEPUNCH_REQ(pbyPacketData, uLenData, uIP, uUDPPort, senderUDPKey);
		break;
	case KADEMLIA_ESE_HOLEPUNCH_ACK:
		if (thePrefs.GetDebugClientKadUDPLevel() > 0)
			DebugRecv("KADEMLIA_ESE_HOLEPUNCH_ACK", uIP, uUDPPort);
		Process_ESE_HOLEPUNCH_ACK(pbyPacketData, uLenData, uIP, uUDPPort, senderUDPKey);
		break;
	case KADEMLIA_ESE_HOLEPUNCH_CHALLENGE:
		if (thePrefs.GetDebugClientKadUDPLevel() > 0)
			DebugRecv("KADEMLIA_ESE_HOLEPUNCH_CHALLENGE", uIP, uUDPPort);
		Process_ESE_HOLEPUNCH_CHALLENGE(pbyPacketData, uLenData, uIP, uUDPPort, senderUDPKey);
		break;

	// v0.71 IPv6 Sprint 4 — Kad3 v6-aware opcodes (parse-and-drop until
	// a v6 routing zone exists). See KademliaUDPListener.h comment block.
	case KADEMLIA3_BOOTSTRAP_REQ:
		Process_KADEMLIA3_GENERIC("KADEMLIA3_BOOTSTRAP_REQ", pbyPacketData, uLenData, uIP, uUDPPort);
		break;
	case KADEMLIA3_BOOTSTRAP_RES:
		Process_KADEMLIA3_GENERIC("KADEMLIA3_BOOTSTRAP_RES", pbyPacketData, uLenData, uIP, uUDPPort);
		break;
	case KADEMLIA3_HELLO_REQ:
		Process_KADEMLIA3_GENERIC("KADEMLIA3_HELLO_REQ", pbyPacketData, uLenData, uIP, uUDPPort);
		break;
	case KADEMLIA3_HELLO_RES:
		Process_KADEMLIA3_GENERIC("KADEMLIA3_HELLO_RES", pbyPacketData, uLenData, uIP, uUDPPort);
		break;
	case KADEMLIA3_REQ:
		Process_KADEMLIA3_GENERIC("KADEMLIA3_REQ", pbyPacketData, uLenData, uIP, uUDPPort);
		break;
	case KADEMLIA3_RES:
		Process_KADEMLIA3_GENERIC("KADEMLIA3_RES", pbyPacketData, uLenData, uIP, uUDPPort);
		break;
	case KADEMLIA3_PING_REQ:   // R.2 keepalive: a peer holds its conntrack open — answer a PONG.
		Process_KADEMLIA3_PING_REQ(pbyPacketData, uLenData, uIP, uUDPPort, senderUDPKey);
		break;
	case KADEMLIA3_PING_RES:   // R.2 keepalive: our supernode replied — refresh its health.
		Process_KADEMLIA3_PING_RES(pbyPacketData, uLenData, uIP, uUDPPort, senderUDPKey);
		break;
	// R.1 (3-way rendezvous) — real handlers (replace the parse-and-drop stubs).
	case KADEMLIA3_HOLEPUNCH_REQ:
		if (thePrefs.GetDebugClientKadUDPLevel() > 0)
			DebugRecv("KADEMLIA3_HOLEPUNCH_REQ", uIP, uUDPPort);
		Process_KADEMLIA3_HOLEPUNCH_REQ(pbyPacketData, uLenData, uIP, uUDPPort, senderUDPKey);
		break;
	case KADEMLIA3_HOLEPUNCH_FWD:
		if (thePrefs.GetDebugClientKadUDPLevel() > 0)
			DebugRecv("KADEMLIA3_HOLEPUNCH_FWD", uIP, uUDPPort);
		Process_KADEMLIA3_HOLEPUNCH_FWD(pbyPacketData, uLenData, uIP, uUDPPort, senderUDPKey);
		break;
	case KADEMLIA3_HOLEPUNCH_CHALLENGE:
		if (thePrefs.GetDebugClientKadUDPLevel() > 0)
			DebugRecv("KADEMLIA3_HOLEPUNCH_CHALLENGE", uIP, uUDPPort);
		Process_KADEMLIA3_HOLEPUNCH_CHALLENGE(pbyPacketData, uLenData, uIP, uUDPPort, senderUDPKey);
		break;
	case KADEMLIA3_HOLEPUNCH_PROCEED:
		if (thePrefs.GetDebugClientKadUDPLevel() > 0)
			DebugRecv("KADEMLIA3_HOLEPUNCH_PROCEED", uIP, uUDPPort);
		Process_KADEMLIA3_HOLEPUNCH_PROCEED(pbyPacketData, uLenData, uIP, uUDPPort, senderUDPKey);
		break;
	case KADEMLIA3_HOLEPUNCH_ACK:
		// Not sent in the current design — the hole is confirmed by the reused 2-way
		// 0x63/0x64 exchange between A and B. Kept registered (parse-and-drop) so the
		// opcode never falls through to the flood 'default'.
		Process_KADEMLIA3_GENERIC("KADEMLIA3_HOLEPUNCH_ACK", pbyPacketData, uLenData, uIP, uUDPPort);
		break;

	// === F1 (unified plan) — Kad Search v2 M3/M5 wire handlers ============
	// M3 sharding announce parses payload and feeds CKadV2Sharding cache.
	// M5 bloom digest and local query are not yet wired to the actual file
	// index (file index integration is F1.5 work); for now we count
	// receipts so /api/live/debug reflects activity.
	// M4 trigrams (PUBLISH/SEARCH) stay as stubs — F8 implements them.
	case KADEMLIA2_KEY_SHARD_ANNOUNCE:
		{
			Kademlia::CUInt128 uTarget;
			uint8 sNew = 0;
			uint32 validUntil = 0;
			if (Kademlia::CKadV2Sharding::ParseAnnounce(pbyPacketData, uLenData, uTarget, sNew, validUntil)) {
				Kademlia::CKadV2Sharding::Get().OnShardAnnounceReceived(uTarget, sNew, validUntil);
				DebugLog(_T("KadV2 M3: shard announce s=%u valid_until=%u from %s"),
					(unsigned)sNew, (unsigned)validUntil, (LPCTSTR)ipstr(htonl(uIP)));
			} else {
				DebugLog(_T("KadV2 M3: malformed KEY_SHARD_ANNOUNCE from %s (len=%u)"),
					(LPCTSTR)ipstr(htonl(uIP)), (unsigned)uLenData);
			}
		}
		break;
	case KADEMLIA2_BLOOM_DIGEST_REQ:
		{
			// F1: count + log; full reception path (per-neighbour quota,
			// CKadV2BloomFilter::DeserializeFrom + cache by senderID) is
			// F1.5 work. Currently we tally receipts for visibility.
			Kademlia::CKadV2Stats::Get().OnBloomRx();
			DebugLog(_T("KadV2 M5: BLOOM_DIGEST_REQ from %s (len=%u) — cache integration pending F1.5"),
				(LPCTSTR)ipstr(htonl(uIP)), (unsigned)uLenData);
		}
		break;
	case KADEMLIA2_LOCAL_QUERY_REQ:
		{
			Kademlia::CKadV2Stats::Get().OnLocalQueryRx();
			DebugLog(_T("KadV2 M5: LOCAL_QUERY_REQ from %s (len=%u) — index lookup pending F1.5"),
				(LPCTSTR)ipstr(htonl(uIP)), (unsigned)uLenData);
		}
		break;
	case KADEMLIA2_LOCAL_QUERY_RES:
		{
			// Receiving a response without having issued the query is
			// invalid; ignore quietly.
			DebugLog(_T("KadV2 M5: unsolicited LOCAL_QUERY_RES from %s — dropping"),
				(LPCTSTR)ipstr(htonl(uIP)));
		}
		break;
	case KADEMLIA2_PUBLISH_TRIGRAM_REQ:
		Process_KADEMLIA3_GENERIC("[STUB F8] KADEMLIA2_PUBLISH_TRIGRAM_REQ", pbyPacketData, uLenData, uIP, uUDPPort);
		break;
	case KADEMLIA2_SEARCH_TRIGRAM_REQ:
		Process_KADEMLIA3_GENERIC("[STUB F8] KADEMLIA2_SEARCH_TRIGRAM_REQ", pbyPacketData, uLenData, uIP, uUDPPort);
		break;

	// old Kad1 opcodes which we don't handle any more
	case KADEMLIA_BOOTSTRAP_REQ_DEPRECATED:
	case KADEMLIA_BOOTSTRAP_RES_DEPRECATED:
	case KADEMLIA_HELLO_REQ_DEPRECATED:
	case KADEMLIA_HELLO_RES_DEPRECATED:
	case KADEMLIA_REQ_DEPRECATED:
	case KADEMLIA_RES_DEPRECATED:
	case KADEMLIA_PUBLISH_NOTES_REQ_DEPRECATED:
	case KADEMLIA_PUBLISH_NOTES_RES_DEPRECATED:
	case KADEMLIA_SEARCH_REQ:
	case KADEMLIA_PUBLISH_REQ:
	case KADEMLIA_SEARCH_NOTES_REQ:
		break;
	default:
		{
			CString strError;
			strError.Format(_T("Unknown opcode %02x"), byOpcode);
			throw strError;
		}
	}
}

// Used only for Kad2.0
bool CKademliaUDPListener::AddContact_KADEMLIA2(const byte *pbyData, uint32 uLenData, uint32 uIP, uint16 &uUDPPort, uint8 *pnOutVersion, const CKadUDPKey &cUDPKey, bool &rbIPVerified, bool bUpdate, bool bFromHelloReq, bool *pbOutRequestsACK, CUInt128 *puOutContactID)
{
	if (pbOutRequestsACK != NULL)
		*pbOutRequestsACK = false;

	CByteIO byteIO(pbyData, uLenData);
	CUInt128 uID;
	byteIO.ReadUInt128(uID);
	if (puOutContactID != NULL)
		*puOutContactID = uID;
	uint16 uTCPPort = byteIO.ReadUInt16();
	uint8 uVersion = byteIO.ReadByte();
	if (pnOutVersion != NULL)
		*pnOutVersion = uVersion;

	bool bUDPFirewalled = false;
	bool bTCPFirewalled = false;
	bool bHasV6 = false; uint8 byV6[16];   // [eSE v9] root link: peer-observed public IPv6 (network order)
	for (unsigned uTags = byteIO.ReadByte(); uTags > 0; --uTags) {
		const CKadTag *pTag = byteIO.ReadTag();

		if (!pTag->m_name.Compare(TAG_SOURCEUPORT)) {
			if (pTag->IsInt() && (uint16)pTag->GetInt() > 0)
				uUDPPort = (uint16)pTag->GetInt();
			else
				ASSERT(0);
		} else if (!pTag->m_name.Compare(TAG_KADMISCOPTIONS)) {
			if (pTag->IsInt() && (uint16)pTag->GetInt() > 0) {
				bUDPFirewalled = (pTag->GetInt() & 0x01) > 0;
				bTCPFirewalled = (pTag->GetInt() & 0x02) > 0;
				if ((pTag->GetInt() & 0x04) > 0) {
					// A peer may legally set the "requests ACK" bit on a packet whose
					// caller didn't ask for it (pbOutRequestsACK == NULL) or from an
					// older version — that is valid remote input, not a local invariant,
					// so ignore the bit instead of ASSERT()ing. No remote-controlled
					// value should ever be able to trip an assertion (aMule PR #268).
					if (pbOutRequestsACK != NULL && uVersion >= KADEMLIA_VERSION8_49b)
						*pbOutRequestsACK = true;
				}
			} else
				ASSERT(0);
		} else if (!pTag->m_name.Compare(TAG_ESE_KADIP_V6)) {
			// [eSE v9] root link: a peer-observed public IPv6 (BSOB 16, network order).
			if (pTag->IsBsob() && pTag->GetBsobSize() == 16) {
				memcpy(byV6, pTag->GetBsob(), 16);
				bHasV6 = true;
			}
		}

		delete pTag;
	}
	// check if we are waiting for informations (nodeid) about this client and if so inform the requester
	for (POSITION pos = listFetchNodeIDRequests.GetHeadPosition(); pos != NULL;) {
		POSITION pos2 = pos;
		const FetchNodeID_Struct &fnode = listFetchNodeIDRequests.GetNext(pos);
		if (fnode.dwIP == uIP && fnode.dwTCPPort == uTCPPort) {
			CString strID;
			uID.ToHexString(strID);
			DebugLog(_T("Result Addcontact: %s"), (LPCTSTR)strID);
			uchar uchID[16];
			uID.ToByteArray(uchID);
			fnode.pRequester->KadSearchNodeIDByIPResult(KCSR_SUCCEEDED, uchID);
			listFetchNodeIDRequests.RemoveAt(pos2);
			break;
		}
	}

	if (bFromHelloReq && uVersion >= KADEMLIA_VERSION8_49b) {
		// This is just for statistic calculations. We try to determine the ratio of (UDP) firewalled users,
		// by counting how many of all nodes, which have us in their routing table (our own routing table is supposed
		// to have no UDP firewalled nodes at all) and support the firewalled tag, are firewalled themselves.
		// Obviously this only works if we are not firewalled ourselves
		CKademlia::GetPrefs()->StatsIncUDPFirewalledNodes(bUDPFirewalled);
		CKademlia::GetPrefs()->StatsIncTCPFirewalledNodes(bTCPFirewalled);
	}

	if (!bUDPFirewalled) // do not add (or update) UDP firewalled sources to our routing table
		return CKademlia::GetRoutingZone()->Add(uID, uIP, uUDPPort, uTCPPort, uVersion, cUDPKey, rbIPVerified, bUpdate, false, true, bHasV6 ? byV6 : NULL);

	//DEBUG_ONLY( AddDebugLogLine(DLP_LOW, false, _T("Kad: Not adding firewalled client to routing table (%s)"), (LPCTSTR)ipstr(htonl(uIP))) );
	return false;
}

// Used only for Kad2.0
void CKademliaUDPListener::Process_KADEMLIA2_BOOTSTRAP_REQ(uint32 uIP, uint16 uUDPPort, const CKadUDPKey &senderUDPKey)
{
	// Get some contacts to return
	ContactArray contacts;
	uint16 uNumContacts = (uint16)CKademlia::GetRoutingZone()->GetBootstrapContacts(contacts, 20);

	// Create response packet
	//We only collect a max of 20 contacts here. Max size is 521.
	//2 + 25*20 + 19
	CSafeMemFile fileIO(521);

	fileIO.WriteUInt128(CKademlia::GetPrefs()->GetKadID());
	fileIO.WriteUInt16(theApp.GetAdvertisedTcpPort());
	fileIO.WriteUInt8(KADEMLIA_VERSION);

	// Write packet info
	fileIO.WriteUInt16(uNumContacts);
	for (ContactArray::const_iterator itContact = contacts.begin(); itContact != contacts.end(); ++itContact) {
		const CContact &rContact(**itContact);
		fileIO.WriteUInt128(rContact.GetClientID());
		fileIO.WriteUInt32(rContact.GetIPAddress());
		fileIO.WriteUInt16(rContact.GetUDPPort());
		fileIO.WriteUInt16(rContact.GetTCPPort());
		fileIO.WriteUInt8(rContact.GetVersion());
	}

	// Send response
	if (thePrefs.GetDebugClientKadUDPLevel() > 0)
		DebugSend("KADEMLIA2_BOOTSTRAP_RES", uIP, uUDPPort);

	SendPacket(fileIO, KADEMLIA2_BOOTSTRAP_RES, uIP, uUDPPort, senderUDPKey, NULL);
}

// Used only for Kad2.0
void CKademliaUDPListener::Process_KADEMLIA2_BOOTSTRAP_RES(const byte *pbyPacketData, uint32 uLenPacket, uint32 uIP, uint16 uUDPPort, const CKadUDPKey &senderUDPKey, bool bValidReceiverKey)
{
	if (!IsOnOutTrackList(uIP, KADEMLIA2_BOOTSTRAP_REQ)) {
		CString strError;
		strError.Format(_T("***NOTE: Received unrequested response packet, size (%u) in %hs"), uLenPacket, __FUNCTION__);
		throw strError;
	}
	CRoutingZone *pRoutingZone = CKademlia::GetRoutingZone();

	// How many contacts were given
	CSafeMemFile fileIO(pbyPacketData, uLenPacket);
	CUInt128 uContactID;
	fileIO.ReadUInt128(uContactID);
	uint16 uTCPPort = fileIO.ReadUInt16();
	uint8 uVersion = fileIO.ReadUInt8();
	// If we don't know any Contacts yet and try to Bootstrap, we assume that all contacts are verified,
	// in order to speed up the connecting process. The attack vectors to exploit this are very small
	// with no major effects, so that's a good trade-off
	bool bAssumeVerified = CKademlia::GetRoutingZone()->GetNumContacts() == 0;

	if (CKademlia::s_liBootstrapList.IsEmpty())
		pRoutingZone->Add(uContactID, uIP, uUDPPort, uTCPPort, uVersion, senderUDPKey, bValidReceiverKey, true, false, false);

	DEBUG_ONLY(AddDebugLogLine(DLP_LOW, false, _T("Inc Kad2 Bootstrap Packet from %s"), (LPCTSTR)ipstr(htonl(uIP))));

	for (unsigned uNumContacts = fileIO.ReadUInt16(); uNumContacts > 0; --uNumContacts) {
		fileIO.ReadUInt128(uContactID);
		uIP = fileIO.ReadUInt32();
		uUDPPort = fileIO.ReadUInt16();
		uTCPPort = fileIO.ReadUInt16();
		uVersion = fileIO.ReadUInt8();
		bool bVerified = bAssumeVerified;
		pRoutingZone->Add(uContactID, uIP, uUDPPort, uTCPPort, uVersion, CKadUDPKey(), bVerified, false, false, false);
	}
}

// Used in Kad2.0 only
void CKademliaUDPListener::Process_KADEMLIA2_HELLO_REQ(const byte *pbyPacketData, uint32 uLenPacket, uint32 uIP, uint16 uUDPPort, const CKadUDPKey &senderUDPKey, bool bValidReceiverKey)
{
	//uint16 dbgOldUDPPort = uUDPPort;
	uint8 byContactVersion;
	CUInt128 uContactID;
	bool bAddedOrUpdated = AddContact_KADEMLIA2(pbyPacketData, uLenPacket, uIP, uUDPPort, &byContactVersion, senderUDPKey, bValidReceiverKey, true, true, NULL, &uContactID); // might change uUDPPort, bValidReceiverKey

	if (thePrefs.GetDebugClientKadUDPLevel() > 0)
		DebugSend("KADEMLIA2_HELLO_RES", uIP, uUDPPort);
	// if this contact was added or updated (in other words, not filtered or invalid) to our routing table and did not already sent a valid
	// receiver key or is already verified in the routing table, we request an additional ACK package to complete a three-way-handshake and
	// verify the remotes IP
	SendMyDetails(KADEMLIA2_HELLO_RES, uIP, uUDPPort, byContactVersion, senderUDPKey, &uContactID, bAddedOrUpdated && !bValidReceiverKey);

	if (bAddedOrUpdated && !bValidReceiverKey && byContactVersion == KADEMLIA_VERSION7_49a && !HasActiveLegacyChallenge(uIP)) {
		// Kad Version 7 doesn't support HELLO_RES_ACK, but sender/receiver keys, so send a ping to validate
		AddLegacyChallenge(uContactID, CUInt128(0ul), uIP, KADEMLIA2_PING);
		SendNullPacket(KADEMLIA2_PING, uIP, uUDPPort, senderUDPKey, NULL);
#ifdef _DEBUG
		CContact *pContact = CKademlia::GetRoutingZone()->GetContact(uContactID);
		if (pContact != NULL) {
			if (pContact->GetType() < 2)
				DebugLogWarning(_T("Process_KADEMLIA2_HELLO_REQ: Sending (ping) challenge to a long known contact (should be verified already) - %s"), (LPCTSTR)ipstr(htonl(uIP)));
		} else
			ASSERT(0);
#endif
	} else if (CKademlia::GetPrefs()->FindExternKadPort(false) && byContactVersion > KADEMLIA_VERSION5_48a) // do we need to find out our extern port?
		SendNullPacket(KADEMLIA2_PING, uIP, uUDPPort, senderUDPKey, NULL);

	if (bAddedOrUpdated && !bValidReceiverKey && byContactVersion < KADEMLIA_VERSION7_49a && !HasActiveLegacyChallenge(uIP)) {
		// we need to verify this contact but it doesn't support HELLO_RES_ACK nor Keys, do a little work around
		SendLegacyChallenge(uIP, uUDPPort, uContactID);
	}

	// Check if firewalled
	if (CKademlia::GetPrefs()->GetRecheckIP())
		FirewalledCheck(uIP, uUDPPort, senderUDPKey, byContactVersion);
}

// Used in Kad2.0 only
void CKademliaUDPListener::Process_KADEMLIA2_HELLO_RES_ACK(const byte *pbyPacketData, uint32 uLenPacket, uint32 uIP, bool bValidReceiverKey)
{
	if (uLenPacket < 17) {
		CString strError;
		strError.Format(_T("***NOTE: Received wrong size (%u) packet in %hs"), uLenPacket, __FUNCTION__);
		throw strError;
	}
	if (!IsOnOutTrackList(uIP, KADEMLIA2_HELLO_RES)) {
		CString strError;
		strError.Format(_T("***NOTE: Received unrequested response packet, size (%u) in %hs"), uLenPacket, __FUNCTION__);
		throw strError;
	}
	if (!bValidReceiverKey) {
		DebugLogWarning(_T("Kad: Process_KADEMLIA2_HELLO_RES_ACK: Receiver key is invalid! (sender: %s)"), (LPCTSTR)ipstr(htonl(uIP)));
		return;
	}
	// additional packet to complete a three-way-handshake, making sure the remote contact is not using a spoofed IP
	CSafeMemFile fileIO(pbyPacketData, uLenPacket);
	CUInt128 uRemoteID;
	fileIO.ReadUInt128(uRemoteID);
	if (!CKademlia::GetRoutingZone()->VerifyContact(uRemoteID, uIP))
		DebugLogWarning(_T("Kad: Process_KADEMLIA2_HELLO_RES_ACK: Unable to find valid sender in routing table (sender: %s)"), (LPCTSTR)ipstr(htonl(uIP)));
	//else
	//	DEBUG_ONLY( AddDebugLogLine(DLP_LOW, false, _T("Verified contact (%s) by HELLO_RES_ACK"), (LPCTSTR)ipstr(htonl(uIP))) );
}

// Used in Kad2.0 only
void CKademliaUDPListener::Process_KADEMLIA2_HELLO_RES(const byte *pbyPacketData, uint32 uLenPacket, uint32 uIP, uint16 uUDPPort, const CKadUDPKey &senderUDPKey, bool bValidReceiverKey)
{
	if (!IsOnOutTrackList(uIP, KADEMLIA2_HELLO_REQ)) {
		CString strError;
		strError.Format(_T("***NOTE: Received unrequested response packet, size (%u) in %hs"), uLenPacket, __FUNCTION__);
		throw strError;
	}

	// Add or Update contact.
	uint8 byContactVersion;
	CUInt128 uContactID;
	bool bSendACK;
	bool bAddedOrUpdated = AddContact_KADEMLIA2(pbyPacketData, uLenPacket, uIP, uUDPPort, &byContactVersion, senderUDPKey, bValidReceiverKey, true, false, &bSendACK, &uContactID);

	if (bSendACK) {
		// the client requested us to send an ACK package, which proves that we are not a spoofed fake contact
		// fulfill his wish
		if (senderUDPKey.IsEmpty()) {
			// but we don't have a valid senderkey - there is no point to reply in this case
			// most likely a bug in the remote client:
			DebugLogWarning(_T("Kad: Process_KADEMLIA2_HELLO_RES: Remote clients demands ACK, but didn't send any Senderkey! (%s)"), (LPCTSTR)ipstr(htonl(uIP)));
		} else {
			CSafeMemFile fileIO(17);
			CUInt128 uID(CKademlia::GetPrefs()->GetKadID());
			fileIO.WriteUInt128(uID);
			fileIO.WriteUInt8(0); // no tags at this time
			if (thePrefs.GetDebugClientKadUDPLevel() > 0)
				DebugSend("KADEMLIA2_HELLO_RES_ACK", uIP, uUDPPort);
			SendPacket(fileIO, KADEMLIA2_HELLO_RES_ACK, uIP, uUDPPort, senderUDPKey, NULL);
			//DEBUG_ONLY( AddDebugLogLine(DLP_LOW, false, _T("Sent HELLO_RES_ACK to %s"), (LPCTSTR)ipstr(htonl(uIP))) );
		}
	} else if (bAddedOrUpdated && !bValidReceiverKey && byContactVersion < KADEMLIA_VERSION7_49a) {
		// even through this is supposedly an answer to a request from us,
		// there are still possibilities to spoof it, as long as the attacker knows
		// that we would send a HELLO_REQ (which is the case quite often),
		// so for old Kad Version which don't support keys, we need
		SendLegacyChallenge(uIP, uUDPPort, uContactID);
	}

	// do we need to find out our extern port?
	if (CKademlia::GetPrefs()->FindExternKadPort(false) && byContactVersion > KADEMLIA_VERSION5_48a)
		SendNullPacket(KADEMLIA2_PING, uIP, uUDPPort, senderUDPKey, NULL);

	// Check if firewalled
	if (CKademlia::GetPrefs()->GetRecheckIP())
		FirewalledCheck(uIP, uUDPPort, senderUDPKey, byContactVersion);
}

// Used in Kad2.0 only
void CKademliaUDPListener::Process_KADEMLIA2_REQ(const byte *pbyPacketData, uint32 uLenPacket, uint32 uIP, uint16 uUDPPort, const CKadUDPKey &senderUDPKey)
{
	// Get target and type
	CSafeMemFile fileIO(pbyPacketData, uLenPacket);
	byte byType = fileIO.ReadUInt8();
	byType = byType & 0x1F;
	if (byType == 0) {
		CString strError;
		strError.Format(_T("***NOTE: Received wrong type (0x%02x) in %hs"), byType, __FUNCTION__);
		throw strError;
	}

	//This is the target node trying to be found.
	CUInt128 uTarget;
	fileIO.ReadUInt128(uTarget);
	//Convert Target to Distance as this is how we store contacts.
	CUInt128 uDistance(CKademlia::GetPrefs()->GetKadID());
	uDistance.Xor(uTarget);

	//This makes sure we are not mistaken identify. Some client may have fresh installed and have a new KadID.
	CUInt128 uCheck;
	fileIO.ReadUInt128(uCheck);
	if (CKademlia::GetPrefs()->GetKadID() == uCheck) {
		// Get required number closest to target
		ContactMap results;
		CKademlia::GetRoutingZone()->GetClosestTo(2, uTarget, uDistance, (uint32)byType, results);
		uint8 uCount = static_cast<uint8>(results.size());

		// Write response
		// Max count is 32, size 817.
		// 16 + 1 + 25*32
		CSafeMemFile fileIO2(817);
		fileIO2.WriteUInt128(uTarget);
		fileIO2.WriteUInt8(uCount);
		for (ContactMap::const_iterator itContactMap = results.begin(); itContactMap != results.end(); ++itContactMap) {
			CUInt128 uID;
			CContact *pContact = itContactMap->second;
			pContact->GetClientID(uID);
			fileIO2.WriteUInt128(uID);
			fileIO2.WriteUInt32(pContact->GetIPAddress());
			fileIO2.WriteUInt16(pContact->GetUDPPort());
			fileIO2.WriteUInt16(pContact->GetTCPPort());
			fileIO2.WriteUInt8(pContact->GetVersion()); //<- Kad Version inserted to allow backward compatibility.
		}

		if (thePrefs.GetDebugClientKadUDPLevel() > 0)
			DebugSendF("KADEMLIA2_RES", uIP, uUDPPort, _T("Count=%u"), uCount);

		SendPacket(fileIO2, KADEMLIA2_RES, uIP, uUDPPort, senderUDPKey, NULL);
	}
}

// Used in Kad2.0 only
void CKademliaUDPListener::Process_KADEMLIA2_RES(const byte *pbyPacketData, uint32 uLenPacket, uint32 uIP, uint16 uUDPPort, const CKadUDPKey& /*senderUDPKey*/)
{
	if (!IsOnOutTrackList(uIP, KADEMLIA2_REQ)) {
		CString strError;
		strError.Format(_T("***NOTE: Received unrequested response packet, size (%u) in %hs"), uLenPacket, __FUNCTION__);
		throw strError;
	}

	//Used Pointers
	CRoutingZone *pRoutingZone = CKademlia::GetRoutingZone();

	// don't do firewall checks on this opcode any more, since we need the contacts kad version - hello opcodes are good enough
	/*if(CKademlia::GetPrefs()->GetRecheckIP())
	{
		FirewalledCheck(uIP, uUDPPort, senderUDPKey);
		if (thePrefs.GetDebugClientKadUDPLevel() > 0)
			DebugSend("KADEMLIA2_HELLO_REQ", uIP, uUDPPort);
		SendMyDetails(KADEMLIA2_HELLO_REQ, uIP, uUDPPort, KADEMLIA_VERSION, senderUDPKey, NULL);
	}*/

	// What search does this relate to
	CSafeMemFile fileIO(pbyPacketData, uLenPacket);
	CUInt128 uTarget;
	fileIO.ReadUInt128(uTarget);
	uint8 uNumContacts = fileIO.ReadUInt8();

	// is this one of our legacy challenge packets?
	CUInt128 uContactID;
	if (IsLegacyChallenge(uTarget, uIP, KADEMLIA2_REQ, uContactID)) {
		// yup it is, set the contact as verified
		if (!CKademlia::GetRoutingZone()->VerifyContact(uContactID, uIP))
			DebugLogWarning(_T("Kad: KADEMLIA2_RES: Unable to find valid sender in routing table (sender: %s)"), (LPCTSTR)ipstr(htonl(uIP)));
		else
			DEBUG_ONLY(AddDebugLogLine(DLP_VERYLOW, false, _T("Verified contact with legacy challenge (KADEMLIA2_REQ) - %s"), (LPCTSTR)ipstr(htonl(uIP))));
		return; // we do not actually care for its other content
	}

	// Verify packet is expected size
	if (uLenPacket != (uint32)(16 + 1 + (16 + 4 + 2 + 2 + 1)*uNumContacts)) {
		CString strError;
		strError.Format(_T("***NOTE: Received wrong size (%u) packet in %hs"), uLenPacket, __FUNCTION__);
		throw strError;
	}

	// Verify that the search is still active and contains no more than the requested numbers of contacts
	if (uNumContacts > CSearchManager::GetExpectedResponseContactCount(uTarget)) {
		if (CSearchManager::GetExpectedResponseContactCount(uTarget) == 0)
			DebugLogWarning(_T("Kad: KADEMLIA2_RES: Search already expired, ignoring answer (sender: %s)"), (LPCTSTR)ipstr(htonl(uIP)));
		else
			DebugLogWarning(_T("Kad: KADEMLIA2_RES: Contact sent more nodes (%u) than requested (%u), ignoring answer (sender: %s)")
				, uNumContacts, CSearchManager::GetExpectedResponseContactCount(uTarget), (LPCTSTR)ipstr(htonl(uIP)));
		return;
	}


	// is this a search for firewall check ips?
	bool bIsFirewallUDPCheckSearch = false;
	if (CUDPFirewallTester::IsFWCheckUDPRunning() && CSearchManager::IsFWCheckUDPSearch(uTarget))
		bIsFirewallUDPCheckSearch = true;

	ContactArray cResults;
	CUInt128 uIDResult;
	uint32 nIgnoredCount = 0;
	try {
		for (uint8 iIndex = 0; iIndex < uNumContacts; ++iIndex) {
			fileIO.ReadUInt128(uIDResult);
			uint32 uIPResult = fileIO.ReadUInt32();
			uint16 uUDPPortResult = fileIO.ReadUInt16();
			uint16 uTCPPortResult = fileIO.ReadUInt16();
			uint8 uVersion = fileIO.ReadUInt8();
			uint32 uhostIPResult = htonl(uIPResult);
			if (uVersion >= KADEMLIA_VERSION2_47a) { // Kad1 nodes are no longer accepted, and are ignored
				if (IsGoodIPPort(uhostIPResult, uUDPPortResult)) {
					if (!theApp.ipfilter->IsFiltered(uhostIPResult) && !(uUDPPortResult == 53 && uVersion <= KADEMLIA_VERSION5_48a)  /*No DNS Port without encryption*/) {
						if (bIsFirewallUDPCheckSearch) {
							// UDP FirewallCheck searches are special. The point is we need an IP which we didn't send a UDP message yet
							// (or in the near future), so we do not try to add those contacts to our routing zone, and we also don't
							// deliver them back to the search manager (because it would UDP-ask them for further results), but only report
							// them to FirewallCheck - this will of course cripple the search but that's not the point, since we only
							// care for IPs and not the randomly set target
							CUDPFirewallTester::AddPossibleTestContact(uIDResult, uIPResult, uUDPPortResult, uTCPPortResult, uTarget, uVersion, CKadUDPKey(), false);
						} else {
							bool bVerified = false;
							bool bWasAdded = pRoutingZone->AddUnfiltered(uIDResult, uIPResult, uUDPPortResult, uTCPPortResult, uVersion, CKadUDPKey(), bVerified, false, false, false);
							CContact *pTemp = new CContact(uIDResult, uIPResult, uUDPPortResult, uTCPPortResult, uTarget, uVersion, CKadUDPKey(), false);
							if (bWasAdded || pRoutingZone->IsAcceptableContact(pTemp))
								cResults.push_back(pTemp);
							else {
								++nIgnoredCount;
								delete pTemp;
							}
						}
					} else if (!(uUDPPortResult == 53 && uVersion <= KADEMLIA_VERSION5_48a) && thePrefs.GetLogFilteredIPs())
						AddDebugLogLine(false, _T("Ignored kad contact (IP=%s:%u) - IP filter (%s)"), (LPCTSTR)ipstr(uhostIPResult), uUDPPortResult, (LPCTSTR)theApp.ipfilter->GetLastHit());
					else if (thePrefs.GetLogFilteredIPs())
						AddDebugLogLine(false, _T("Ignored kad contact (IP=%s:%u) - Bad port (Kad2_Res)"), (LPCTSTR)ipstr(uhostIPResult), uUDPPortResult);
				} else if (thePrefs.GetLogFilteredIPs())
					AddDebugLogLine(false, _T("Ignored kad contact (IP=%s) - Bad IP"), (LPCTSTR)ipstr(uhostIPResult));
			}
		}
	} catch (...) {
		for (ContactArray::const_iterator itContact = cResults.begin(); itContact != cResults.end(); ++itContact)
			delete *itContact;
		throw;
	}
	if (nIgnoredCount > 0)
		DebugLogWarning(_T("Ignored %u bad contacts in routing answer from %s"), nIgnoredCount, (LPCTSTR)ipstr(htonl(uIP)));
	CSearchManager::ProcessResponse(uTarget, uIP, uUDPPort, cResults);
}

void CKademliaUDPListener::Free(SSearchTerm *pSearchTerms)
{
	if (pSearchTerms) {
		if (pSearchTerms->m_pLeft)
			Free(pSearchTerms->m_pLeft);
		if (pSearchTerms->m_pRight)
			Free(pSearchTerms->m_pRight);
		delete pSearchTerms;
	}
}

static void TokenizeOptQuotedSearchTerm(LPCTSTR pszString, CStringWArray *lst)
{
	for (LPCTSTR pch = pszString; *pch != _T('\0');) {
		if (*pch == _T('"')) {
			// Start of quoted string found. If there is no terminating quote character found,
			// the start quote character is just skipped. If the quoted string is empty, no
			// new entry is added to 'list'.
			//
			++pch;
			LPCTSTR pchNextQuote = _tcschr(pch, _T('"'));
			if (pchNextQuote) {
				size_t nLenQuoted = pchNextQuote - pch;
				if (nLenQuoted)
					lst->Add(CString(pch, (int)nLenQuoted));
				pch = pchNextQuote + 1;
			}
		} else {
			// Search for next delimiter or quote character
			//
			size_t nNextDelimiter = _tcscspn(pch, _T(INV_KAD_KEYWORD_CHARS));
			if (nNextDelimiter) {
				lst->Add(CString(pch, (int)nNextDelimiter));
				pch += nNextDelimiter;
				if (*pch == _T('\0'))
					break;
				if (*pch == _T('"'))
					continue;
			}
			++pch;
		}
	}
}

static CString *s_pstrDbgSearchExpr;

SSearchTerm* CKademliaUDPListener::CreateSearchExpressionTree(CSafeMemFile &fileIO, int iLevel)
{
	// the max. depth has to match our own limit for creating the search expression
	// (see also 'ParsedSearchExpression' and 'GetSearchPacket')
	if (iLevel >= 24) {
		AddDebugLogLine(false, _T("***NOTE: Search expression tree exceeds depth limit!"));
		return NULL;
	}
	++iLevel;

	uint8 uOp = fileIO.ReadUInt8();
	switch (uOp) {
	case 0x00: // boolean op
		{
			uint8 uBoolOp = fileIO.ReadUInt8();
			switch (uBoolOp) {
			case 0x00: // AND
				{
					SSearchTerm *pSearchTerm = new SSearchTerm;
					pSearchTerm->m_type = SSearchTerm::AND;
					if (s_pstrDbgSearchExpr)
						s_pstrDbgSearchExpr->Append(_T(" AND"));
					if ((pSearchTerm->m_pLeft = CreateSearchExpressionTree(fileIO, iLevel)) == NULL) {
						ASSERT(0);
						delete pSearchTerm;
						return NULL;
					}
					if ((pSearchTerm->m_pRight = CreateSearchExpressionTree(fileIO, iLevel)) == NULL) {
						ASSERT(0);
						Free(pSearchTerm->m_pLeft);
						delete pSearchTerm;
						return NULL;
					}
					return pSearchTerm;
				}
			case 0x01: // OR
				{
					SSearchTerm *pSearchTerm = new SSearchTerm;
					pSearchTerm->m_type = SSearchTerm::OR;
					if (s_pstrDbgSearchExpr)
						s_pstrDbgSearchExpr->Append(_T(" OR"));
					if ((pSearchTerm->m_pLeft = CreateSearchExpressionTree(fileIO, iLevel)) == NULL) {
						ASSERT(0);
						delete pSearchTerm;
						return NULL;
					}
					if ((pSearchTerm->m_pRight = CreateSearchExpressionTree(fileIO, iLevel)) == NULL) {
						ASSERT(0);
						Free(pSearchTerm->m_pLeft);
						delete pSearchTerm;
						return NULL;
					}
					return pSearchTerm;
				}
			case 0x02: // NOT
				{
					SSearchTerm *pSearchTerm = new SSearchTerm;
					pSearchTerm->m_type = SSearchTerm::NOT;
					if (s_pstrDbgSearchExpr)
						s_pstrDbgSearchExpr->Append(_T(" NOT"));
					if ((pSearchTerm->m_pLeft = CreateSearchExpressionTree(fileIO, iLevel)) == NULL) {
						ASSERT(0);
						delete pSearchTerm;
						return NULL;
					}
					if ((pSearchTerm->m_pRight = CreateSearchExpressionTree(fileIO, iLevel)) == NULL) {
						ASSERT(0);
						Free(pSearchTerm->m_pLeft);
						delete pSearchTerm;
						return NULL;
					}
					return pSearchTerm;
				}
			}
			AddDebugLogLine(false, _T("*** Unknown boolean search operator 0x%02x (CreateSearchExpressionTree)"), uBoolOp);
			return NULL;
		}
	case 0x01: // string
		{
			CKadTagValueString str(fileIO.ReadStringUTF8());

			KadTagStrMakeLower(str); // make lower case, the search code expects lower case strings!
			if (s_pstrDbgSearchExpr)
				s_pstrDbgSearchExpr->AppendFormat(_T(" \"%ls\""), (LPCTSTR)str);

			SSearchTerm *pSearchTerm = new SSearchTerm;
			pSearchTerm->m_type = SSearchTerm::String;
			pSearchTerm->m_pastr = new CStringWArray;

			// pre-tokenize the string term (care about quoted parts)
			TokenizeOptQuotedSearchTerm(str, pSearchTerm->m_pastr);

			return pSearchTerm;
		}
	case 0x02: // Meta tag
		{
			// read tag value
			CKadTagValueString strValue(fileIO.ReadStringUTF8());

			KadTagStrMakeLower(strValue); // make lower case, the search code expects lower case strings!

			// read tag name
			CStringA strTagName;
			uint16 lenTagName = fileIO.ReadUInt16();
			fileIO.Read(strTagName.GetBuffer(lenTagName), lenTagName);
			strTagName.ReleaseBuffer(lenTagName);

			SSearchTerm *pSearchTerm = new SSearchTerm;
			pSearchTerm->m_type = SSearchTerm::MetaTag;
			pSearchTerm->m_pTag = new Kademlia::CKadTagStr(strTagName, strValue);
			if (s_pstrDbgSearchExpr) {
				if (lenTagName == 1)
					s_pstrDbgSearchExpr->AppendFormat(_T(" Tag%02X=\"%ls\""), (BYTE)strTagName[0], (LPCTSTR)strValue);
				else
					s_pstrDbgSearchExpr->AppendFormat(_T(" \"%hs\"=\"%ls\""), (LPCSTR)strTagName, (LPCTSTR)strValue);
			}
			return pSearchTerm;
		}
	case 0x03: // Numeric Relation 32-bit
	case 0x08: // Numeric Relation 64-bit
		{
			static const struct
			{
				SSearchTerm::ESearchTermType eSearchTermOp;
				LPCTSTR pszOp;
			}
			_aOps[] =
			{
				{ SSearchTerm::OpEqual,			_T("=")	 }, // mmop=0x00
				{ SSearchTerm::OpGreater,		_T(">")	 }, // mmop=0x01
				{ SSearchTerm::OpLess,			_T("<")	 }, // mmop=0x02
				{ SSearchTerm::OpGreaterEqual,	_T(">=") }, // mmop=0x03
				{ SSearchTerm::OpLessEqual,		_T("<=") }, // mmop=0x04
				{ SSearchTerm::OpNotEqual,		_T("<>") }  // mmop=0x05
			};

			// read tag value
			uint64 ullValue = (uOp == 0x03) ? fileIO.ReadUInt32() : fileIO.ReadUInt64();

			// read integer operator
			uint8 mmop = fileIO.ReadUInt8();
			if (mmop >= _countof(_aOps)) {
				AddDebugLogLine(false, _T("*** Unknown integer search op=0x%02x (CreateSearchExpressionTree)"), mmop);
				return NULL;
			}

			// read tag name
			CStringA strTagName;
			uint16 uLenTagName = fileIO.ReadUInt16();
			fileIO.Read(strTagName.GetBuffer(uLenTagName), uLenTagName);
			strTagName.ReleaseBuffer(uLenTagName);

			SSearchTerm *pSearchTerm = new SSearchTerm;
			pSearchTerm->m_type = _aOps[mmop].eSearchTermOp;
			pSearchTerm->m_pTag = new Kademlia::CKadTagUInt64(strTagName, ullValue);

			if (s_pstrDbgSearchExpr)
				if (uLenTagName == 1)
					s_pstrDbgSearchExpr->AppendFormat(_T(" Tag%02X%s%I64u"), (BYTE)strTagName[0], _aOps[mmop].pszOp, ullValue);
				else
					s_pstrDbgSearchExpr->AppendFormat(_T(" \"%hs\"%s%I64u"), (LPCSTR)strTagName, _aOps[mmop].pszOp, ullValue);

			return pSearchTerm;
		}
	}
	AddDebugLogLine(false, _T("*** Unknown search op=0x%02x (CreateSearchExpressionTree)"), uOp);
	return NULL;
}

// Used in Kad2.0 only
void CKademliaUDPListener::Process_KADEMLIA2_SEARCH_KEY_REQ(const byte *pbyPacketData, uint32 uLenPacket, uint32 uIP, uint16 uUDPPort, const CKadUDPKey &senderUDPKey)
{
	CSafeMemFile fileIO(pbyPacketData, uLenPacket);
	CUInt128 uTarget;
	fileIO.ReadUInt128(uTarget);
	uint16 uStartPosition = fileIO.ReadUInt16();
	bool bRestrictive = ((uStartPosition & 0x8000) != 0);
	uStartPosition &= ~0x8000;
	SSearchTerm *pSearchTerms = NULL;
	if (bRestrictive) {
		try {
#if defined(_DEBUG) || defined(USE_DEBUG_DEVICE)
			s_pstrDbgSearchExpr = (thePrefs.GetDebugServerSearchesLevel() > 0) ? new CString() : NULL;
#endif
			pSearchTerms = CreateSearchExpressionTree(fileIO, 0);
			if (s_pstrDbgSearchExpr) {
				Debug(_T("KadSearchTerm=%s\n"), (LPCTSTR)*s_pstrDbgSearchExpr);
				delete s_pstrDbgSearchExpr;
				s_pstrDbgSearchExpr = NULL;
			}
		} catch (...) {
			delete s_pstrDbgSearchExpr;
			s_pstrDbgSearchExpr = NULL;
			Free(pSearchTerms);
			throw;
		}
		if (pSearchTerms == NULL)
			throwCStr(_T("Invalid search expression"));
	}
	CKademlia::GetIndexed()->SendValidKeywordResult(uTarget, pSearchTerms, uIP, uUDPPort, false, uStartPosition, senderUDPKey);
	Free(pSearchTerms);
}

// Used in Kad2.0 only
void CKademliaUDPListener::Process_KADEMLIA2_SEARCH_SOURCE_REQ(const byte *pbyPacketData, uint32 uLenPacket, uint32 uIP, uint16 uUDPPort, const CKadUDPKey &senderUDPKey)
{
	CSafeMemFile fileIO(pbyPacketData, uLenPacket);
	CUInt128 uTarget;
	fileIO.ReadUInt128(uTarget);
	uint16 uStartPosition = (fileIO.ReadUInt16() & 0x7FFF);
	uint64 uFileSize = fileIO.ReadUInt64();
	CKademlia::GetIndexed()->SendValidSourceResult(uTarget, uIP, uUDPPort, uStartPosition, uFileSize, senderUDPKey);
}

// Used in Kad1.0 only
void CKademliaUDPListener::Process_KADEMLIA_SEARCH_RES(const byte *pbyPacketData, uint32 uLenPacket, uint32 uIP, uint16 uUDPPort)
{
	// Verify packet is expected size
	if (uLenPacket < 37) {
		CString strError;
		strError.Format(_T("***NOTE: Received wrong size (%u) packet in %hs"), uLenPacket, __FUNCTION__);
		throw strError;
	}

	// What search does this relate to
	CByteIO byteIO(pbyPacketData, uLenPacket);
	CUInt128 uTarget;
	byteIO.ReadUInt128(uTarget);

	// How many results. Not supported yet.
	CUInt128 uAnswer;
	for (unsigned uCount = byteIO.ReadUInt16(); uCount > 0; --uCount) {
		// What is the answer
		byteIO.ReadUInt128(uAnswer);

		// Get info about answer
		// NOTE: this is the one and only place in Kad where we allow string conversion to local code page in
		// case we did not receive a UTF-8 string. This is for backward compatibility for search results which are
		// supposed to be 'viewed' by user only and not fed into the Kad engine again!
		// If that tag list is once used for something else than for viewing, special care has to be taken for any
		// string conversion!
		TagList lTags;
		try {
			byteIO.ReadTagList(lTags, true);
		} catch (...) {
			deleteTagListEntries(lTags);
			throw;
		}
		CSearchManager::ProcessResult(uTarget, uAnswer, lTags, uIP, uUDPPort);
		deleteTagListEntries(lTags);
	}
}

// Used in Kad2.0 only
void CKademliaUDPListener::Process_KADEMLIA2_SEARCH_RES(const byte *pbyPacketData, uint32 uLenPacket, const CKadUDPKey& /*senderUDPKey*/, uint32 uIP, uint16 uUDPPort)
{
	CByteIO byteIO(pbyPacketData, uLenPacket);

	// Who sent this packet.
	CUInt128 uSource;
	byteIO.ReadUInt128(uSource);

	// What search does this relate to
	CUInt128 uTarget;
	byteIO.ReadUInt128(uTarget);

	// Total results.
	CUInt128 uAnswer;
	for (unsigned uCount = byteIO.ReadUInt16(); uCount > 0; --uCount) {
		// What is the answer
		byteIO.ReadUInt128(uAnswer);

		// Get info about answer
		// NOTE: this is the one and only place in Kad where we allow string conversion to local code page in
		// case we did not receive a UTF-8 string. this is for backward compatibility for search results which are
		// supposed to be 'viewed' by user only and not feed into the Kad engine again!
		// If that tag list is once used for something else than for viewing, special care has to be taken for any
		// string conversion!
		TagList lTags;
		try {
			byteIO.ReadTagList(lTags, true);
		} catch (...) {
			deleteTagListEntries(lTags);
			throw;
		}
		CSearchManager::ProcessResult(uTarget, uAnswer, lTags, uIP, uUDPPort);
		deleteTagListEntries(lTags);
	}
}

// Used in Kad2.0 only
void CKademliaUDPListener::Process_KADEMLIA2_PUBLISH_KEY_REQ(const byte *pbyPacketData, uint32 uLenPacket, uint32 uIP, uint16 uUDPPort, const CKadUDPKey &senderUDPKey)
{
	// check if we are UDP firewalled
	if (CUDPFirewallTester::IsFirewalledUDP(true))
		//We are firewalled. We should not index this entry and give publisher a false report.
		return;

	CByteIO byteIO(pbyPacketData, uLenPacket);
	CUInt128 uFile;
	byteIO.ReadUInt128(uFile);

	CUInt128 uDistance(CKademlia::GetPrefs()->GetKadID());
	uDistance.Xor(uFile);

	// Shouldn't LAN IPs already be filtered?
	if (uDistance.Get32BitChunk(0) > SEARCHTOLERANCE && !IsLANIP(ntohl(uIP)))
		return;

	bool bDbgInfo = (thePrefs.GetDebugClientKadUDPLevel() > 0);
	uint8 uLoad = 0;
	CUInt128 uTarget;
	for (unsigned uCount = byteIO.ReadUInt16(); uCount > 0; --uCount) {
		CKadTag *pTag = NULL;
		CKeyEntry *pEntry = NULL;
		bool bEseLiveEntry = false;
		try {
			CString sInfo;
			byteIO.ReadUInt128(uTarget);
			pEntry = new Kademlia::CKeyEntry();
			pEntry->m_uIP = uIP;
			pEntry->m_uUDPPort = uUDPPort;
			pEntry->m_uKeyID.SetValue(uFile);
			pEntry->m_uSourceID.SetValue(uTarget);
			pEntry->m_tLifetime = time(NULL) + KADEMLIAREPUBLISHTIMEK;
			pEntry->m_bSource = false;
			for (unsigned uTags = byteIO.ReadByte(); uTags > 0; --uTags) {
				pTag = byteIO.ReadTag();
				if (pTag) {
					if (!pTag->m_name.Compare(TAG_FILENAME)) {
						if (pEntry->GetCommonFileName().IsEmpty()) {
							pEntry->SetFileName(pTag->GetStr());
							if (bDbgInfo)
								sInfo.AppendFormat(_T("  Name=\"%ls\""), (LPCTSTR)pEntry->GetCommonFileName());
						}
					} else if (!pTag->m_name.Compare(TAG_FILESIZE)) {
						if (pEntry->m_uSize == 0) {
							if (pTag->IsBsob() && pTag->GetBsobSize() == 8)
								pEntry->m_uSize = *((uint64*)pTag->GetBsob());
							else
								pEntry->m_uSize = pTag->GetInt();
							if (bDbgInfo)
								sInfo.AppendFormat(_T("  Size=%I64u"), pEntry->m_uSize);
						}
					} else if (!pTag->m_name.Compare(TAG_KADAICHHASHPUB)) {
						if (pTag->IsBsob() && pTag->GetBsobSize() == CAICHHash::GetHashSize()) {
							if (pEntry->GetAICHHashCount() == 0) {
								pEntry->AddRemoveAICHHash(CAICHHash((uchar*)pTag->GetBsob()), true);
								if (bDbgInfo)
									sInfo.AppendFormat(_T("  AICH Hash=%s"), (LPCTSTR)CAICHHash((uchar*)pTag->GetBsob()).GetString());
							} else
								DebugLogWarning(_T("Multiple TAG_KADAICHHASHPUB tags received for single file from %s"), (LPCTSTR)ipstr(htonl(uIP)));
						} else
							DEBUG_ONLY(DebugLogWarning(_T("Bad TAG_KADAICHHASHPUB received from %s"), (LPCTSTR)ipstr(htonl(uIP))));
					} else if (pTag->m_name.Compare(TAG_ESE_LIVE_MARKER) == 0) {
						bEseLiveEntry = pTag->IsInt() && pTag->GetInt() == 1;
						pEntry->AddTag(pTag);
						pTag = NULL;
					} else if (pTag->m_name.Compare(TAG_SOURCEIP) == 0) {
						pEntry->AddTag(pTag);
						pTag = NULL;
					} else {
						//TODO: Filter tags - we do some basic filtering already within this function, might want to do more at some point
						pEntry->AddTag(pTag);
						pTag = NULL;
					}
					delete pTag; //tag is no longer stored, but membervar is used
					pTag = NULL;
				}
			}
			if (bDbgInfo && !sInfo.IsEmpty())
				Debug(_T("%s\n"), (LPCTSTR)sInfo);
		} catch (...) {
			delete pTag;
			delete pEntry;
			throw;
		}

		// eSE Live: derive TAG_SOURCEIP from packet source ONLY if we have a
		// valid uIP. If uIP is 0 (self-publish via loopback, broken NAT, etc.)
		// the holder must NOT override the publisher's own TAG_SOURCEIP tag
		// with 0 — that would set viewer-side uLiveIP=0 and cause every
		// result to be REJECTED at LiveKadBridge.cpp:523 as invalid endpoint.
		// Pair this guard with Search.cpp's explicit TAG_SOURCEIP in the
		// publish so the entry stays reachable end-to-end.
		if (bEseLiveEntry && uIP != 0)
			pEntry->AddTag(new CKadTagUInt(TAG_SOURCEIP, htonl(uIP)));

		// H8 fix (2026-06-11): v8.1 clean-namespace publishes carry no
		// TAG_FILENAME at all, and CIndexed::AddKeyword rejects entries
		// whose common filename is empty — those publishes were silently
		// dropped here (and on every upstream holder). Synthesize the same
		// constant name current publishers send so prior-fork broadcasters
		// stay indexable by us. The constant carries nothing stream-derived,
		// so the title leak H8 closed stays closed.
		if (bEseLiveEntry && pEntry->GetCommonFileName().IsEmpty())
			pEntry->SetFileName(Kademlia::CKadTagValueString(ESE_LIVE_CLEAN_NS_FILENAME));

		if (!CKademlia::GetIndexed()->AddKeyword(uFile, uTarget, pEntry, uLoad)) {
			//We already indexed the maximum number of keywords.
			//We do not index any more but we still send a success.
			//Reason: Because if a VERY busy node tells the publisher it failed,
			//this busy node will spread to all the surrounding nodes causing popular
			//keywords to be stored on MANY nodes.
			//So, once we are full, we will periodically clean our list until we can
			//begin storing again.
			delete pEntry;
		}
	}
	CSafeMemFile fileIO2(17);
	fileIO2.WriteUInt128(uFile);
	fileIO2.WriteUInt8(uLoad);
	if (thePrefs.GetDebugClientKadUDPLevel() > 0)
		DebugSend("KADEMLIA2_PUBLISH_RES", uIP, uUDPPort);
	SendPacket(fileIO2, KADEMLIA2_PUBLISH_RES, uIP, uUDPPort, senderUDPKey, NULL);
}

// Used in Kad2.0 only
void CKademliaUDPListener::Process_KADEMLIA2_PUBLISH_SOURCE_REQ(const byte *pbyPacketData, uint32 uLenPacket, uint32 uIP, uint16 uUDPPort, const CKadUDPKey &senderUDPKey)
{
	// check if we are UDP firewalled
	if (CUDPFirewallTester::IsFirewalledUDP(true))
		//We are firewalled. We should not index this entry and give publisher a false report.
		return;

	CByteIO byteIO(pbyPacketData, uLenPacket);
	CUInt128 uFile;
	byteIO.ReadUInt128(uFile);

	CUInt128 uDistance(CKademlia::GetPrefs()->GetKadID());
	uDistance.Xor(uFile);

	if (uDistance.Get32BitChunk(0) > SEARCHTOLERANCE && !IsLANIP(ntohl(uIP)))
		return;

	bool bDbgInfo = (thePrefs.GetDebugClientKadUDPLevel() > 0);
	uint8 uLoad = 0;
	CUInt128 uTarget;
	byteIO.ReadUInt128(uTarget);
	CKadTag *pTag = NULL;
	CEntry *pEntry = NULL;
	try {
		CString sInfo;
		pEntry = new Kademlia::CEntry();
		pEntry->m_uIP = uIP;
		pEntry->m_uUDPPort = uUDPPort;
		pEntry->m_uKeyID.SetValue(uFile);
		pEntry->m_uSourceID.SetValue(uTarget);
		pEntry->m_bSource = false;
		pEntry->m_tLifetime = time(NULL) + KADEMLIAREPUBLISHTIMES;
		bool bAddUDPPortTag = true;
		for (unsigned uTags = byteIO.ReadByte(); uTags > 0; --uTags) {
			pTag = byteIO.ReadTag();
			if (pTag) {
				if (!pTag->m_name.Compare(TAG_SOURCETYPE)) {
					if (!pEntry->m_bSource) {
						pEntry->AddTag(new CKadTagUInt(TAG_SOURCEIP, pEntry->m_uIP));
						pEntry->m_bSource = true;
						pEntry->AddTag(pTag);
						pTag = NULL;
					}
				} else if (!pTag->m_name.Compare(TAG_FILESIZE)) {
					if (pEntry->m_uSize == 0) {
						if (pTag->IsBsob() && pTag->GetBsobSize() == 8)
							pEntry->m_uSize = *((uint64*)pTag->GetBsob());
						else
							pEntry->m_uSize = pTag->GetInt();
						if (bDbgInfo)
							sInfo.AppendFormat(_T("  Size=%I64u"), pEntry->m_uSize);
					}
				} else if (!pTag->m_name.Compare(TAG_SOURCEPORT)) {
					if (pEntry->m_uTCPPort == 0) {
						pEntry->m_uTCPPort = (uint16)pTag->GetInt();
						pEntry->AddTag(pTag);
						pTag = NULL;
					}
				} else if (!pTag->m_name.Compare(TAG_SOURCEUPORT)) {
					if (bAddUDPPortTag && pTag->IsInt() && (uint16)pTag->GetInt() > 0) {
						pEntry->m_uUDPPort = (uint16)pTag->GetInt();
						bAddUDPPortTag = false;
						pEntry->AddTag(pTag);
						pTag = NULL;
					}
				} else if (!pTag->m_name.Compare(TAG_SERVERIP)) {
					//drop lowID sources with unreachable buddy (Enig123)
					if (pTag->IsInt()) {
						LPCTSTR p = NULL;
						uint32 buddyip = (uint32)pTag->GetInt();
						//if (!IsGoodIP(buddyip)) {
						//	if (thePrefs.GetLogFilteredIPs())
						//		p = _T("bad");
						//} else
						if (theApp.ipfilter->IsFiltered(buddyip)) {
							if (thePrefs.GetLogFilteredIPs())
								p = _T("IP-filtered");
						} else if (theApp.clientlist->IsBannedClient(buddyip)) {
							if (thePrefs.GetLogBannedClients())
								p = _T("banned");
						} else {
							pEntry->AddTag(pTag);
							pTag = NULL;
						}

						if (pTag) {
							pEntry->m_bSource = false;
							if (p)
								AddDebugLogLine(false, _T("Publish request from source %s with %s buddy IP=%s"), (LPCTSTR)ipstr(htonl(uIP)), p, (LPCTSTR)ipstr(buddyip));
						}
					}
				} else {
					//TODO: Filter tags
					pEntry->AddTag(pTag);
					pTag = NULL; //do not delete
				}
				delete pTag;
				pTag = NULL;
			}
		}
		if (bAddUDPPortTag)
			pEntry->AddTag(new CKadTagUInt(TAG_SOURCEUPORT, pEntry->m_uUDPPort));

		if (bDbgInfo && !sInfo.IsEmpty())
			Debug(_T("%s\n"), (LPCTSTR)sInfo);
	} catch (...) {
		delete pTag;
		delete pEntry;
		throw;
	}

	if (pEntry->m_bSource && CKademlia::GetIndexed()->AddSources(uFile, uTarget, pEntry, uLoad)) {
		CSafeMemFile fileIO2(17);
		fileIO2.WriteUInt128(uFile);
		fileIO2.WriteUInt8(uLoad);
		if (thePrefs.GetDebugClientKadUDPLevel() > 0)
			DebugSend("KADEMLIA2_PUBLISH_RES", uIP, uUDPPort);
		SendPacket(fileIO2, KADEMLIA2_PUBLISH_RES, uIP, uUDPPort, senderUDPKey, NULL);
	} else
		delete pEntry;
}

// Used only by Kad1.0
void CKademliaUDPListener::Process_KADEMLIA_PUBLISH_RES(const byte *pbyPacketData, uint32 uLenPacket, uint32 uIP)
{
	// Verify packet is expected size
	if (uLenPacket < 16) {
		CString strError;
		strError.Format(_T("***NOTE: Received wrong size (%u) packet in %hs"), uLenPacket, __FUNCTION__);
		throw strError;
	}
	if (!IsOnOutTrackList(uIP, KADEMLIA_PUBLISH_REQ)) {
		CString strError;
		strError.Format(_T("***NOTE: Received unrequested response packet, size (%u) in %hs"), uLenPacket, __FUNCTION__);
		throw strError;
	}

	CSafeMemFile fileIO(pbyPacketData, uLenPacket);
	CUInt128 uFile;
	fileIO.ReadUInt128(uFile);

	bool bLoadResponse = false;
	uint8 uLoad = 0;
	if (fileIO.GetLength() > fileIO.GetPosition()) {
		bLoadResponse = true;
		uLoad = fileIO.ReadUInt8();
	}

	CSearchManager::ProcessPublishResult(uFile, uLoad, bLoadResponse);
}

// Used only by Kad2.0
void CKademliaUDPListener::Process_KADEMLIA2_PUBLISH_RES(const byte *pbyPacketData, uint32 uLenPacket, uint32 uIP, uint16 uUDPPort, const CKadUDPKey &senderUDPKey)
{
	if (!IsOnOutTrackList(uIP, KADEMLIA2_PUBLISH_KEY_REQ) && !IsOnOutTrackList(uIP, KADEMLIA2_PUBLISH_SOURCE_REQ) && !IsOnOutTrackList(uIP, KADEMLIA2_PUBLISH_NOTES_REQ)) {
		CString strError;
		strError.Format(_T("***NOTE: Received unrequested response packet, size (%u) in %hs"), uLenPacket, __FUNCTION__);
		throw strError;
	}
	CSafeMemFile fileIO(pbyPacketData, uLenPacket);
	CUInt128 uFile;
	fileIO.ReadUInt128(uFile);
	uint8 uLoad = fileIO.ReadUInt8();
	CSearchManager::ProcessPublishResult(uFile, uLoad, true);
	if (fileIO.GetLength() > fileIO.GetPosition()) {
		// for future use
		uint8 byOptions = fileIO.ReadUInt8();
		bool bRequestACK = (byOptions & 0x01) > 0;
		if (bRequestACK && !senderUDPKey.IsEmpty()) {
			DEBUG_ONLY(DebugLogWarning(_T("KADEMLIA2_PUBLISH_RES_ACK requested (%s)"), (LPCTSTR)ipstr(htonl(uIP))));
			if (thePrefs.GetDebugClientKadUDPLevel() > 0)
				DebugSend("KADEMLIA2_PUBLISH_RES_ACK", uIP, uUDPPort);
			SendNullPacket(KADEMLIA2_PUBLISH_RES_ACK, uIP, uUDPPort, senderUDPKey, NULL);
		}
	}
}

// Used only by Kad2.0
void CKademliaUDPListener::Process_KADEMLIA2_SEARCH_NOTES_REQ(const byte *pbyPacketData, uint32 uLenPacket, uint32 uIP, uint16 uUDPPort, const CKadUDPKey &senderUDPKey)
{
	CSafeMemFile fileIO(pbyPacketData, uLenPacket);
	CUInt128 uTarget;
	fileIO.ReadUInt128(uTarget);
	uint64 uFileSize = fileIO.ReadUInt64();
	CKademlia::GetIndexed()->SendValidNoteResult(uTarget, uIP, uUDPPort, uFileSize, senderUDPKey);
}

// Used only by Kad1.0
void CKademliaUDPListener::Process_KADEMLIA_SEARCH_NOTES_RES(const byte *pbyPacketData, uint32 uLenPacket, uint32 uIP, uint16 uUDPPort)
{
	// Verify packet is expected size
	if (uLenPacket < 37) {
		CString strError;
		strError.Format(_T("***NOTE: Received wrong size (%u) packet in %hs"), uLenPacket, __FUNCTION__);
		throw strError;
	}
	if (!IsOnOutTrackList(uIP, KADEMLIA_SEARCH_NOTES_REQ, true)) {
		CString strError;
		strError.Format(_T("***NOTE: Received unrequested response packet, size (%u) in %hs"), uLenPacket, __FUNCTION__);
		throw strError;
	}

	// What search does this relate to
	CByteIO byteIO(pbyPacketData, uLenPacket);
	CUInt128 uTarget;
	byteIO.ReadUInt128(uTarget);

	CUInt128 uAnswer;
	for (unsigned uCount = byteIO.ReadUInt16(); uCount > 0; --uCount) {
		// What is the answer
		byteIO.ReadUInt128(uAnswer);

		// Get info about answer
		// NOTE: this is the one and only place in Kad where we allow string conversion to local code page in
		// case we did not receive a UTF-8 string. This is for backward compatibility for search results
		// which are supposed to be 'viewed' by user only and not feed into the Kad engine again!
		// If that tag list is once used for something else than for viewing, special care has to be taken
		// for any string conversion!
		TagList lTags;
		try {
			byteIO.ReadTagList(lTags, true);
		} catch (...) {
			deleteTagListEntries(lTags);
			throw;
		}
		CSearchManager::ProcessResult(uTarget, uAnswer, lTags, uIP, uUDPPort);
		deleteTagListEntries(lTags);
	}
}

// Used only by Kad2.0
void CKademliaUDPListener::Process_KADEMLIA2_PUBLISH_NOTES_REQ(const byte *pbyPacketData, uint32 uLenPacket, uint32 uIP, uint16 uUDPPort, const CKadUDPKey &senderUDPKey)
{
	// check if we are UDP firewalled
	if (CUDPFirewallTester::IsFirewalledUDP(true)) {
		//We are firewalled. We should not index this entry and give publisher a false report.
		return;
	}

	CByteIO byteIO(pbyPacketData, uLenPacket);
	CUInt128 uTarget;
	byteIO.ReadUInt128(uTarget);

	CUInt128 uDistance(CKademlia::GetPrefs()->GetKadID());
	uDistance.Xor(uTarget);

	// Shouldn't LAN IPs already be filtered?
	if (uDistance.Get32BitChunk(0) > SEARCHTOLERANCE && !IsLANIP(ntohl(uIP)))
		return;

	CUInt128 uSource;
	byteIO.ReadUInt128(uSource);

	CKadTag *pTag = NULL;
	Kademlia::CEntry *pEntry = new Kademlia::CEntry();
	try {
		pEntry->m_uIP = uIP;
		pEntry->m_uUDPPort = uUDPPort;
		pEntry->m_uKeyID.SetValue(uTarget);
		pEntry->m_uSourceID.SetValue(uSource);
		pEntry->m_bSource = false;
		for (unsigned uTags = byteIO.ReadByte(); uTags > 0; --uTags) {
			pTag = byteIO.ReadTag();
			if (pTag) {
				if (!pTag->m_name.Compare(TAG_FILENAME)) {
					if (pEntry->GetCommonFileName().IsEmpty())
						pEntry->SetFileName(pTag->GetStr());
				} else if (!pTag->m_name.Compare(TAG_FILESIZE)) {
					if (pEntry->m_uSize == 0)
						pEntry->m_uSize = pTag->GetInt();
				} else {
					//TODO: Filter tags
					pEntry->AddTag(pTag);
					pTag = NULL;
				}
				delete pTag;
				pTag = NULL;
			}
		}
	} catch (...) {
		delete pTag;
		delete pEntry;
		throw;
	}

	uint8 uLoad = 0;
	if (CKademlia::GetIndexed()->AddNotes(uTarget, uSource, pEntry, uLoad)) {
		CSafeMemFile fileIO2(17);
		fileIO2.WriteUInt128(uTarget);
		fileIO2.WriteUInt8(uLoad);
		if (thePrefs.GetDebugClientKadUDPLevel() > 0)
			DebugSend("KADEMLIA2_PUBLISH_RES", uIP, uUDPPort);

		SendPacket(fileIO2, KADEMLIA2_PUBLISH_RES, uIP, uUDPPort, senderUDPKey, NULL);
	} else
		delete pEntry;
}

// Used by Kad1.0 and Kad2.0
void CKademliaUDPListener::Process_KADEMLIA_FIREWALLED_REQ(const byte *pbyPacketData, uint32 uLenPacket, uint32 uIP, uint16 uUDPPort, const CKadUDPKey &senderUDPKey)
{
	// Verify packet is expected size
	if (uLenPacket != 2) {
		CString strError;
		strError.Format(_T("***NOTE: Received wrong size (%u) packet in %hs"), uLenPacket, __FUNCTION__);
		throw strError;
	}

	CSafeMemFile fileIO(pbyPacketData, uLenPacket);
	uint16 uTCPPort = fileIO.ReadUInt16();

	CContact contact;
	contact.SetIPAddress(uIP);
	contact.SetTCPPort(uTCPPort);
	contact.SetUDPPort(uUDPPort);
	if (!theApp.clientlist->RequestTCP(&contact, 0))
		return; // cancelled for some reason, don't send a response

	// Send response
	CSafeMemFile fileIO2(4);
	fileIO2.WriteUInt32(uIP);
	if (thePrefs.GetDebugClientKadUDPLevel() > 0)
		DebugSend("KADEMLIA_FIREWALLED_RES", uIP, uUDPPort);

	SendPacket(fileIO2, KADEMLIA_FIREWALLED_RES, uIP, uUDPPort, senderUDPKey, NULL);
}

// Used by Kad2.0 Prot.Version 7+
void CKademliaUDPListener::Process_KADEMLIA_FIREWALLED2_REQ(const byte *pbyPacketData, uint32 uLenPacket, uint32 uIP, uint16 uUDPPort, const CKadUDPKey &senderUDPKey)
{
	// Verify packet is expected size
	if (uLenPacket < 19) {
		CString strError;
		strError.Format(_T("***NOTE: Received wrong size (%u) packet in %hs"), uLenPacket, __FUNCTION__);
		throw strError;
	}

	CSafeMemFile fileIO(pbyPacketData, uLenPacket);
	uint16 uTCPPort = fileIO.ReadUInt16();
	CUInt128 userID;
	fileIO.ReadUInt128(userID);
	uint8 byConnectOptions = fileIO.ReadUInt8();

	CContact contact;
	contact.SetIPAddress(uIP);
	contact.SetTCPPort(uTCPPort);
	contact.SetUDPPort(uUDPPort);
	contact.SetClientID(userID);
	if (!theApp.clientlist->RequestTCP(&contact, byConnectOptions))
		return;  // cancelled for some reason, don't send a response

	// Send response
	CSafeMemFile fileIO2(4);
	fileIO2.WriteUInt32(uIP);
	if (thePrefs.GetDebugClientKadUDPLevel() > 0)
		DebugSend("KADEMLIA_FIREWALLED_RES", uIP, uUDPPort);

	SendPacket(fileIO2, KADEMLIA_FIREWALLED_RES, uIP, uUDPPort, senderUDPKey, NULL);
}

// Used by Kad1.0 and Kad2.0
void CKademliaUDPListener::Process_KADEMLIA_FIREWALLED_RES(const byte *pbyPacketData, uint32 uLenPacket, uint32 uIP, const CKadUDPKey& /*senderUDPKey*/)
{
	// Verify packet is expected size
	if (uLenPacket != 4) {
		CString strError;
		strError.Format(_T("***NOTE: Received wrong size (%u) packet in %hs"), uLenPacket, __FUNCTION__);
		throw strError;
	}
	if (!theApp.clientlist->IsKadFirewallCheckIP(ntohl(uIP))) { /*KADEMLIA_FIREWALLED2_REQ + KADEMLIA_FIREWALLED_REQ*/
		CString strError;
		strError.Format(_T("Received unrequested firewall response packet in %hs"), __FUNCTION__);
		throw strError;
	}

	CSafeMemFile fileIO(pbyPacketData, uLenPacket);
	uint32 uFirewalledIP = fileIO.ReadUInt32();

	//Update con state only if something changes.
	if (CKademlia::GetPrefs()->GetIPAddress() != uFirewalledIP) {
		CKademlia::GetPrefs()->SetIPAddress(uFirewalledIP);
		theApp.emuledlg->ShowConnectionState();
	}
	CKademlia::GetPrefs()->IncRecheckIP();
}

// Used by Kad1.0 and Kad2.0
void CKademliaUDPListener::Process_KADEMLIA_FIREWALLED_ACK_RES(uint32 uLenPacket)
{
	// deprecated since KadVersion 7+, the result is now sent per TCP instead of UDP, because this will fail if our intern UDP port is unreachable.
	// But we want the TCP test result regardless if UDP is firewalled, the new UDP state and test takes care of the rest
	// Verify packet is expected size
	if (uLenPacket != 0) {
		CString strError;
		strError.Format(_T("***NOTE: Received wrong size (%u) packet in %hs"), uLenPacket, __FUNCTION__);
		throw strError;
	}

	CKademlia::GetPrefs()->IncFirewalled();
}

// Used by Kad1.0 and Kad2.0
void CKademliaUDPListener::Process_KADEMLIA_FINDBUDDY_REQ(const byte *pbyPacketData, uint32 uLenPacket, uint32 uIP, uint16 uUDPPort, const CKadUDPKey &senderUDPKey)
{
	// Verify packet is expected size
	if (uLenPacket < 34) {
		CString strError;
		strError.Format(_T("***NOTE: Received wrong size (%u) packet in %hs"), uLenPacket, __FUNCTION__);
		throw strError;
	}

	if (CKademlia::GetPrefs()->GetFirewalled() || CUDPFirewallTester::IsFirewalledUDP(true) || !CUDPFirewallTester::IsVerified())
		//We are firewalled but somehow we still got this packet. Don't send a response.
		return;
	if (theApp.clientlist->GetBuddyStatus() == Connected)
		// we already have a buddy
		return;

	CSafeMemFile fileIO(pbyPacketData, uLenPacket);
	CUInt128 BuddyID;
	fileIO.ReadUInt128(BuddyID);
	CUInt128 userID;
	fileIO.ReadUInt128(userID);
	uint16 uTCPPort = fileIO.ReadUInt16();

	CContact contact;
	contact.SetIPAddress(uIP);
	contact.SetTCPPort(uTCPPort);
	contact.SetUDPPort(uUDPPort);
	contact.SetClientID(userID);
	if (!theApp.clientlist->IncomingBuddy(&contact, &BuddyID))
		return; // cancelled for some reason, don't send a response

	CSafeMemFile fileIO2(34);
	fileIO2.WriteUInt128(BuddyID);
	fileIO2.WriteUInt128(CKademlia::GetPrefs()->GetClientHash());
	fileIO2.WriteUInt16(theApp.GetAdvertisedTcpPort());
	if (!senderUDPKey.IsEmpty()) // remove check for later versions
		fileIO2.WriteUInt8(CKademlia::GetPrefs()->GetMyConnectOptions(true, false)); // new since 0.49a, old mules will ignore it (hopefully ;) )
	if (thePrefs.GetDebugClientKadUDPLevel() > 0)
		DebugSend("KADEMLIA_FINDBUDDY_RES", uIP, uUDPPort);

	SendPacket(fileIO2, KADEMLIA_FINDBUDDY_RES, uIP, uUDPPort, senderUDPKey, NULL);
}

// Used by Kad1.0 and Kad2.0
void CKademliaUDPListener::Process_KADEMLIA_FINDBUDDY_RES(const byte *pbyPacketData, uint32 uLenPacket, uint32 uIP, uint16 uUDPPort, const CKadUDPKey& /*senderUDPKey*/)
{
	// Verify packet is expected size
	if (uLenPacket < 34) {
		CString strError;
		strError.Format(_T("***NOTE: Received wrong size (%u) packet in %hs"), uLenPacket, __FUNCTION__);
		throw strError;
	}
	if (!IsOnOutTrackList(uIP, KADEMLIA_FINDBUDDY_REQ)) {
		CString strError;
		strError.Format(_T("***NOTE: Received unrequested response packet, size (%u) in %hs"), uLenPacket, __FUNCTION__);
		throw strError;
	}


	CSafeMemFile fileIO(pbyPacketData, uLenPacket);
	CUInt128 uCheck;
	fileIO.ReadUInt128(uCheck);
	uCheck.Xor(CUInt128(true));
	if (CKademlia::GetPrefs()->GetKadID() == uCheck) {
		CUInt128 userID;
		fileIO.ReadUInt128(userID);
		uint16 uTCPPort = fileIO.ReadUInt16();
		uint8 byConnectOptions = 0;
		if (uLenPacket > 34)
			// 0.49+ (kad version 7) sends its additional connect options so we know if to use an obfuscated connection
			byConnectOptions = fileIO.ReadUInt8();

		CContact contact;
		contact.SetIPAddress(uIP);
		contact.SetTCPPort(uTCPPort);
		contact.SetUDPPort(uUDPPort);
		contact.SetClientID(userID);

		theApp.clientlist->RequestBuddy(&contact, byConnectOptions);
	}
}

// Used by Kad1.0 and Kad2.0
void CKademliaUDPListener::Process_KADEMLIA_CALLBACK_REQ(const byte *pbyPacketData, uint32 uLenPacket, uint32 uIP, const CKadUDPKey& /*senderUDPKey*/)
{
	// Verify packet is expected size
	if (uLenPacket < 34) {
		CString strError;
		strError.Format(_T("***NOTE: Received wrong size (%u) packet in %hs"), uLenPacket, __FUNCTION__);
		throw strError;
	}

	CUpDownClient *pBuddy = theApp.clientlist->GetBuddy();
	if (pBuddy != NULL) {
		CSafeMemFile fileIO(pbyPacketData, uLenPacket);
		CUInt128 uCheck;
		fileIO.ReadUInt128(uCheck);
		//JOHNTODO: Begin filtering bad buddy ID's.
		//CUInt128 bud(pBuddy->GetBuddyID());
		CUInt128 uFile;
		fileIO.ReadUInt128(uFile);
		uint16 uTCP = fileIO.ReadUInt16();

		if (pBuddy->socket == NULL)
			throw CString(__FUNCTION__ ": Buddy has no valid socket.");
		CSafeMemFile fileIO2(uLenPacket + 6);
		fileIO2.WriteUInt128(uCheck);
		fileIO2.WriteUInt128(uFile);
		fileIO2.WriteUInt32(uIP);
		fileIO2.WriteUInt16(uTCP);
		Packet *pPacket = new Packet(fileIO2, OP_EMULEPROT, OP_CALLBACK);
		if (thePrefs.GetDebugClientKadUDPLevel() > 0 || thePrefs.GetDebugClientTCPLevel() > 0)
			DebugSend("OP_CALLBACK", pBuddy);
		theStats.AddUpDataOverheadFileRequest(pPacket->size);
		pBuddy->socket->SendPacket(pPacket);
	}
}

void CKademliaUDPListener::Process_KADEMLIA2_PING(uint32 uIP, uint16 uUDPPort, const CKadUDPKey &senderUDPKey)
{
// can be used just as PING, currently it is however only used to determine ones external port
	CSafeMemFile fileIO2(2);
	fileIO2.WriteUInt16(uUDPPort);
	if (thePrefs.GetDebugClientKadUDPLevel() > 0)
		DebugSend("KADEMLIA2_PONG", uIP, uUDPPort);
	SendPacket(fileIO2, KADEMLIA2_PONG, uIP, uUDPPort, senderUDPKey, NULL);
}

void CKademliaUDPListener::Process_KADEMLIA2_PONG(const byte *pbyPacketData, uint32 uLenPacket, uint32 uIP, uint16 /*uUDPPort*/, const CKadUDPKey& /*senderUDPKey*/)
{
	if (uLenPacket < 2) {
		CString strError;
		strError.Format(_T("***NOTE: Received wrong size (%u) packet in %hs"), uLenPacket, __FUNCTION__);
		throw strError;
	}
	if (!IsOnOutTrackList(uIP, KADEMLIA2_PING)) {
		CString strError;
		strError.Format(_T("***NOTE: Received unrequested response packet, size (%u) in %hs"), uLenPacket, __FUNCTION__);
		throw strError;
	}

	// is this one of our legacy challenge packets?
	CUInt128 uContactID;
	if (IsLegacyChallenge(CUInt128(0ul), uIP, KADEMLIA2_PING, uContactID)) {
		// yup it is, set the contact as verified
		if (!CKademlia::GetRoutingZone()->VerifyContact(uContactID, uIP))
			DebugLogWarning(_T("Kad: KADEMLIA2_PONG: Unable to find valid sender in routing table (sender: %s)"), (LPCTSTR)ipstr(htonl(uIP)));
		else
			DEBUG_ONLY(AddDebugLogLine(DLP_LOW, false, _T("Verified contact with legacy challenge (KADEMLIA2_PING) - %s"), (LPCTSTR)ipstr(htonl(uIP))));
		// we might care for its other content
	}

	if (CKademlia::GetPrefs()->FindExternKadPort(false)) {
		// the reported port doesn't always have to be our true external port, esp. if we used our intern
		// port and communicated recently with the client some routers might remember this and assign
		// the intern port as source but this shouldn't be a problem because we prefer intern ports anyway.
		// might have to be reviewed in later versions when more data is available
		CKademlia::GetPrefs()->SetExternKadPort(PeekUInt16(pbyPacketData), uIP);
		if (CUDPFirewallTester::IsFWCheckUDPRunning())
			CUDPFirewallTester::QueryNextClient();
	}
	theApp.emuledlg->ShowConnectionState();
}

void CKademliaUDPListener::Process_KADEMLIA2_FIREWALLUDP(const byte *pbyPacketData, uint32 uLenPacket, uint32 uIP, const CKadUDPKey& /*senderUDPKey*/)
{
	// Verify packet is expected size
	if (uLenPacket < 3) {
		CString strError;
		strError.Format(_T("***NOTE: Received wrong size (%u) packet in %hs"), uLenPacket, __FUNCTION__);
		throw strError;
	}
	uint8 byErrorCode = PeekUInt8(pbyPacketData);
	uint16 nIncomingPort = PeekUInt16(pbyPacketData + 1);

	if ((nIncomingPort != CKademlia::GetPrefs()->GetExternalKadPort() && nIncomingPort != CKademlia::GetPrefs()->GetInternKadPort())
		|| nIncomingPort == 0)
	{
		DebugLogWarning(_T("Received UDP FirewallCheck on unexpected incoming port %u (%s)"), nIncomingPort, (LPCTSTR)ipstr(htonl(uIP)));
		CUDPFirewallTester::SetUDPFWCheckResult(false, true, uIP, 0);
	} else if (byErrorCode == 0) {
		DebugLog(_T("Received UDP FirewallCheck packet from %s with incoming port %u"), (LPCTSTR)ipstr(htonl(uIP)), nIncomingPort);
		CUDPFirewallTester::SetUDPFWCheckResult(true, false, uIP, nIncomingPort);
	} else {
		DebugLog(_T("Received UDP FirewallCheck packet from %s with incoming port %u with remote error code %u - ignoring result"), (LPCTSTR)ipstr(htonl(uIP)), nIncomingPort, byErrorCode);
		CUDPFirewallTester::SetUDPFWCheckResult(false, true, uIP, 0);
	}
}

void CKademliaUDPListener::SendPacket(const byte *pbyData, uint32 uLenData, uint32 uDestinationHost, uint16 uDestinationPort, const CKadUDPKey &targetUDPKey, const CUInt128 *uCryptTargetID)
{
	if (uLenData < 2) {
		ASSERT(0);
		return;
	}
	Packet *pPacket = new Packet(OP_KADEMLIAHEADER);
	pPacket->opcode = pbyData[1];
	pPacket->pBuffer = new char[uLenData + 8];
	memcpy(pPacket->pBuffer, pbyData + 2, uLenData - 2);
	pPacket->size = uLenData - 2;
	if (uLenData > 200)
		pPacket->PackPacket();
	theStats.AddUpDataOverheadKad(pPacket->size);
	AddTrackedOutPacket(uDestinationHost, pbyData[1]);
	theApp.clientudp->SendPacket(pPacket, ntohl(uDestinationHost), uDestinationPort, true
		, (uCryptTargetID != NULL) ? uCryptTargetID->GetData() : NULL
		, true, targetUDPKey.GetKeyValue(theApp.GetPublicIP()));
}

void CKademliaUDPListener::SendPacket(const byte *pbyData, uint32 uLenData, byte byOpcode, uint32 uDestinationHost, uint16 uDestinationPort, const CKadUDPKey &targetUDPKey, const CUInt128 *uCryptTargetID)
{
	Packet *pPacket = new Packet(OP_KADEMLIAHEADER);
	pPacket->opcode = byOpcode;
	pPacket->pBuffer = new char[uLenData];
	memcpy(pPacket->pBuffer, pbyData, uLenData);
	pPacket->size = uLenData;
	if (uLenData > 200)
		pPacket->PackPacket();
	theStats.AddUpDataOverheadKad(pPacket->size);
	AddTrackedOutPacket(uDestinationHost, byOpcode);
	theApp.clientudp->SendPacket(pPacket, ntohl(uDestinationHost), uDestinationPort, true
		, (uCryptTargetID != NULL) ? uCryptTargetID->GetData() : NULL
		, true, targetUDPKey.GetKeyValue(theApp.GetPublicIP()));
}

void CKademliaUDPListener::SendPacket(CSafeMemFile &pbyData, byte byOpcode, uint32 uDestinationHost, uint16 uDestinationPort, const CKadUDPKey &targetUDPKey, const CUInt128 *uCryptTargetID)
{
	Packet *pPacket = new Packet(pbyData, OP_KADEMLIAHEADER);
	pPacket->opcode = byOpcode;
	if (pPacket->size > 200)
		pPacket->PackPacket();
	theStats.AddUpDataOverheadKad(pPacket->size);
	AddTrackedOutPacket(uDestinationHost, byOpcode);
	theApp.clientudp->SendPacket(pPacket, htonl(uDestinationHost), uDestinationPort, true
		, (uCryptTargetID != NULL) ? uCryptTargetID->GetData() : NULL
		, true, targetUDPKey.GetKeyValue(theApp.GetPublicIP()));
}

bool CKademliaUDPListener::FindNodeIDByIP(CKadClientSearcher *pRequester, uint32 dwIP, uint16 nTCPPort, uint16 nUDPPort)
{
	// send a hello packet to the given IP in order to get a HELLO_RES with the NodeID

	// we will drop support for Kad1 soon, so don't bother sending two packets in case we don't know if kad2 is supported
	// (if we know that it's not, this function isn't called in the first place)
	DebugLog(_T("FindNodeIDByIP: Requesting NodeID from %s by sending KADEMLIA2_HELLO_REQ"), (LPCTSTR)ipstr(htonl(dwIP)));
	if (thePrefs.GetDebugClientKadUDPLevel() > 0)
		DebugSend("KADEMLIA2_HELLO_REQ", dwIP, nUDPPort);
	SendMyDetails(KADEMLIA2_HELLO_REQ, dwIP, nUDPPort, KADEMLIA_VERSION, CKadUDPKey(), NULL, false); // todo: we send this unobfuscated, which is not perfect, see if this can be avoided in the future
	FetchNodeID_Struct sRequest = {dwIP, nTCPPort, ::GetTickCount() + SEC2MS(60), pRequester};
	listFetchNodeIDRequests.AddTail(sRequest);
	return true;
}

void CKademliaUDPListener::ExpireClientSearch(const CKadClientSearcher *pExpireImmediately)
{
	for (POSITION pos = listFetchNodeIDRequests.GetHeadPosition(); pos != NULL;) {
		POSITION pos2 = pos;
		const FetchNodeID_Struct &sRequest = listFetchNodeIDRequests.GetNext(pos);
		if (sRequest.pRequester == pExpireImmediately)
			listFetchNodeIDRequests.RemoveAt(pos2);
		else if (::GetTickCount() >= sRequest.dwExpire) {
			sRequest.pRequester->KadSearchNodeIDByIPResult(KCSR_TIMEOUT, NULL);
			listFetchNodeIDRequests.RemoveAt(pos2);
		}
	}
}

void CKademliaUDPListener::SendLegacyChallenge(uint32 uIP, uint16 uUDPPort, const CUInt128 &uContactID)
{
	// We want to verify that a pre-0.49a contact is valid and not sent from a spoofed IP.
	// Because those versions don't support any direct validating, we sent a KAD_REQ with a random ID,
	// which is our challenge. If we receive an answer packet for this request, we can be sure the
	// contact is not spoofed
#ifdef _DEBUG
	CContact *pContact = CKademlia::GetRoutingZone()->GetContact(uContactID);
	if (pContact != NULL) {
		if (pContact->GetType() < 2)
			DebugLogWarning(_T("Process_KADEMLIA_HELLO_RES: Sending challenge to a long known contact (should be verified already) - %s"), (LPCTSTR)ipstr(htonl(uIP)));
	} else
		ASSERT(0);
#endif
	if (HasActiveLegacyChallenge(uIP)) // don't sent more than one challenge at a time
		return;
	CSafeMemFile fileIO(33);
	fileIO.WriteUInt8(KADEMLIA_FIND_VALUE);
	CUInt128 uChallenge;
	uChallenge.SetValueRandom();
	if (uChallenge == 0) {
		// hey there is a 2^128 chance that this happens ;)
		ASSERT(0);
		uChallenge = 1;
	}
	// Put the target we want into the packet. This is our challenge
	fileIO.WriteUInt128(uChallenge);
	// Add the ID of the contact we are contacting for sanity checks on the other end.
	fileIO.WriteUInt128(uContactID);
	// those versions we send those requests to don't support encryption / obfuscation
	CKademlia::GetUDPListener()->SendPacket(fileIO, KADEMLIA2_REQ, uIP, uUDPPort, CKadUDPKey(), NULL);
	if (thePrefs.GetDebugClientKadUDPLevel() > 0)
		DebugSend("KADEMLIA2_REQ(SendLegacyChallenge)", uIP, uUDPPort);
	AddLegacyChallenge(uContactID, uChallenge, uIP, KADEMLIA2_REQ);
}

// eSE Fase 3: Process an incoming uTP Hole Punch Request
// Packet format: <SenderKadID 16><SenderUDPPort 2><Nonce 4> = 22 bytes
void CKademliaUDPListener::Process_ESE_HOLEPUNCH_REQ(const byte *pbyPacketData, uint32 uLenPacket, uint32 uIP, uint16 uUDPPort, const CKadUDPKey &senderUDPKey)
{
	// Kill-Switch: silently ignore if hole punching is disabled
	if (!EseHolePunchTransportReady()) {
		DebugLog(_T("eSE: Ignoring HOLEPUNCH_REQ from %s — Kill-Switch OFF"), (LPCTSTR)ipstr(htonl(uIP)));
		return;
	}

	// Three on-wire shapes, discriminated purely by length. A pre-cookie fork
	// only ever sends the classic 22-byte form:
	//   classic  : <KadID 16><port 2><nonce 4>            = 22
	//   capable  : <KadID 16><port 2><nonce 4><caps 4>   = 26
	//   expanded : <KadID 16><port 2><nonce 4><cookie 16> = 38  (return-routability echo)
	// Exact-equality length gate FIRST, before reading any field. CSafeMemFile
	// then bounds every read and throws CFileException on over-read (caught by the
	// dispatch guard), so an OOB walk is structurally impossible — no pointer math.
	const bool bExpanded = (uLenPacket == 38);
	const bool bCapabilityAdvertised = (uLenPacket == 26);
	if (uLenPacket != 22 && !bCapabilityAdvertised && !bExpanded) {
		CString strError;
		strError.Format(_T("***NOTE: Received wrong size (%u) packet in %hs"), uLenPacket, __FUNCTION__);
		throw strError;
	}

	CSafeMemFile fileIO(pbyPacketData, uLenPacket);
	CUInt128 uSenderKadID;
	fileIO.ReadUInt128(uSenderKadID);
	uint16 uSenderUDPPort = fileIO.ReadUInt16();
	uint32 uNonce = fileIO.ReadUInt32();
	uint32 uSenderCaps = 0;
	if (bCapabilityAdvertised) {
		uSenderCaps = fileIO.ReadUInt32();
		if ((uSenderCaps & ESE_CAP_HOLEPUNCH_COOKIE) == 0) {
			DebugLogWarning(_T("eSE: HOLEPUNCH_REQ capability shape without cookie cap from %s:%u - dropped"),
				(LPCTSTR)ipstr(htonl(uIP)), (unsigned)uUDPPort);
			return;
		}
	}
	CContact* pObservedContact = NULL;
	if (CKademlia::GetRoutingZone() != NULL)
		pObservedContact = CKademlia::GetRoutingZone()->GetContact(uIP, uUDPPort, false);
	if (pObservedContact != NULL && pObservedContact->GetClientID() != uSenderKadID) {
		DebugLogWarning(_T("eSE: HOLEPUNCH_REQ identity mismatch at %s:%u - dropped"),
			(LPCTSTR)ipstr(htonl(uIP)), (unsigned)uUDPPort);
		return;
	}

	// Our 16-byte Kad ID binds the cookie to this node identity.
	uint8 abyNodeHash[16];
	CKademlia::GetPrefs()->GetKadID().ToByteArray(abyNodeHash);

	if (bExpanded) {
		// P0 return-routability: an echoed cookie is present. Verify it (epoch e /
		// e-1) BEFORE doing any work; a mismatch is dropped with ZERO state (no
		// ACK, no seed). The cookie is read LAST, at a fixed 16 bytes, bounded.
		uint8 abyCookie[eSE::HP_COOKIE_SIZE];
		fileIO.Read(abyCookie, eSE::HP_COOKIE_SIZE);
		if (!eSE::EseHolePunchCookie::Verify(abyNodeHash, ::GetTickCount(), uIP, uNonce, abyCookie)) {
			DebugLogWarning(_T("eSE: HOLEPUNCH_REQ from %s:%u — cookie MISMATCH, dropped (no seed)"),
				(LPCTSTR)ipstr(htonl(uIP)), uSenderUDPPort);
			return;
		}
		DebugLog(_T("eSE: HOLEPUNCH_REQ from %s:%u nonce=0x%08X — cookie OK (return-routability proven)"),
			(LPCTSTR)ipstr(htonl(uIP)), uSenderUDPPort, uNonce);
		// verified -> fall through to ACK + seed
	} else {
		// Classic 22B REQ. UNIFIED RETURN-ROUTABILITY GATE (PUNTO 1.1, 2026-06) — a
		// two-tier guard that reconciles strict anti-reflection with the mandatory
		// back-compat for legacy peers:
		//   TIER 1 (fast path): the sender is a routing-zone contact whose IP we have
		//     already verified in-band (IsIpVerified()). Reachability is proven, so go
		//     straight to the legacy ACK+seed — no extra RTT.
		//   TIER 2 (gray zone): unknown source OR a known-but-UNVERIFIED contact (these
		//     enter via third-party HELLO_RES referrals, and a spoofed source can also
		//     collide with a known endpoint's IP:port). We have no IP proof, so:
		//       - if the sender advertised ESE_CAP_HOLEPUNCH_COOKIE in the 26B
		//         request (or in a known HELLO), escalate to a stateless CHALLENGE
		//         and seed NOTHING; only the echoed cookie (38B REQ)
		//         earns the ACK+seed;
		//       - otherwise it is a legacy/vanilla peer that cannot answer a 0x65
		//         CHALLENGE (forcing it would break their hole-punch), so fall through
		//         to the legacy ACK+seed — floored against spoofed floods by the per-IP
		//         token bucket (PacketTracking) and the g_expectedPeers per-IP/global cap.
		// bit 19 (ESE_CAP_HOLEPUNCH_COOKIE) is LOAD-BEARING here: it gates the stateless
		// challenge for unverified entries (informational only for verified ones).
		CContact* pKnownContact = NULL;
		if (CKademlia::GetRoutingZone() != NULL)
			pKnownContact = CKademlia::GetRoutingZone()->GetContact(uIP, uUDPPort, false); // host-order uIP (Kad convention)
		const bool bIsSafeLegacy = (pKnownContact != NULL && pKnownContact->IsIpVerified());

		if (!bIsSafeLegacy) {
			// Gray zone: challenge only a peer we can positively confirm speaks the
			// cookie protocol. Unknown classic senders retain the rate-limited legacy
			// path; modern first-dial senders identify themselves with the 26B shape.
			bool bSenderCookieCapable = bCapabilityAdvertised;
			if (!bSenderCookieCapable && theApp.clientlist != NULL) {
				// Kad UDP runs on the main thread, so this clientlist read is race-free
				// (pointer used synchronously, never stored). htonl: uIP is host-order
				// (Kad), FindClientByIP_KadPort wants network-order.
				CUpDownClient* pSender = theApp.clientlist->FindClientByIP_KadPort(htonl(uIP), uUDPPort);
				bSenderCookieCapable = (pSender != NULL && pSender->SupportsEseHolePunchCookie());
			}
			if (bSenderCookieCapable) {
				uint8 abyCookie[eSE::HP_COOKIE_SIZE];
				eSE::EseHolePunchCookie::Compute(abyNodeHash, uIP, uNonce, abyCookie);
				SendEseHolePunchChallenge(uIP, uUDPPort, uNonce, abyCookie, senderUDPKey);
				InterlockedIncrement(&CStatistics::m_dwHolePunchChallengeSent);
				CLiveDebugLog::Get().Append("HOLE",
					"CHALLENGE -> %S:%u nonce=0x%08X  (cookie return-routability, no seed)",
					(LPCWSTR)ipstr(htonl(uIP)), (unsigned)uSenderUDPPort, (unsigned)uNonce);
				DebugLog(_T("eSE: HOLEPUNCH_REQ from UNVERIFIED cookie-capable %s:%u nonce=0x%08X — sent CHALLENGE (no seed yet)"),
					(LPCTSTR)ipstr(htonl(uIP)), uSenderUDPPort, uNonce);
				return;
			}
		}
		DebugLog(_T("eSE: HOLEPUNCH_REQ from %hs %s:%u nonce=0x%08X — legacy ACK+seed (floored)"),
			bIsSafeLegacy ? "verified-known" : "legacy/unverified",
			(LPCTSTR)ipstr(htonl(uIP)), uSenderUDPPort, uNonce);
		// TIER 1 verified-known, OR TIER 2 non-cookie-capable -> legacy ACK + seed
	}

	// eSE v9 GATE telemetry: we have committed to ACK+seed. Count the inbound REQ on the
	// RESPONDER side — the outbound-only m_dwHolePunchAttempts never fires here, so without
	// this a 2-PC test sees Attempts:0/Success:0 on PC-B and can't tell whether the REQ even
	// arrived (A->B path) vs the ACK getting lost (B->A path). The always-on LiveDebugLog line
	// timestamps the inbound REQ on PC-B's snapshot for exactly that localization.
	InterlockedIncrement(&CStatistics::m_dwHolePunchReqRecv);
	CLiveDebugLog::Get().Append("HOLE",
		"REQ recv from %S:%u nonce=0x%08X -> ACK+seed",
		(LPCWSTR)ipstr(htonl(uIP)), (unsigned)uUDPPort, (unsigned)uNonce);

	// Respond with ACK containing our own KadID and the echoed nonce
	CSafeMemFile fileIOResp(22);
	fileIOResp.WriteUInt128(CKademlia::GetPrefs()->GetKadID());
	fileIOResp.WriteUInt16(theApp.GetAdvertisedUdpPort());
	fileIOResp.WriteUInt32(uNonce); // Echo the nonce for correlation

	if (thePrefs.GetDebugClientKadUDPLevel() > 0)
		DebugSend("KADEMLIA_ESE_HOLEPUNCH_ACK", uIP, uUDPPort);
	// eSE 8.12.2: Reply with encryption if we can identify the sender in our routing table.
	// Tier 1: Lookup sender's KadID for NodeID-based encryption (strongest).
	// Tier 2: Echo back with the senderUDPKey from the incoming packet (ReceiverKey-based).
	// Tier 3: Plaintext fallback (same as pre-8.12.2).
	CContact* pSenderContact = NULL;
	if (CKademlia::GetRoutingZone() != NULL)
		pSenderContact = CKademlia::GetRoutingZone()->GetContact(uIP, uUDPPort, false);

	if (pSenderContact != NULL) {
		CKadUDPKey replyKey = pSenderContact->GetUDPKey();
		CUInt128 senderCryptID = pSenderContact->GetClientID();
		SendPacket(fileIOResp, KADEMLIA_ESE_HOLEPUNCH_ACK, uIP, uUDPPort, replyKey, &senderCryptID);
	} else if (!senderUDPKey.IsEmpty()) {
		SendPacket(fileIOResp, KADEMLIA_ESE_HOLEPUNCH_ACK, uIP, uUDPPort, senderUDPKey, NULL);
	} else {
		SendPacket(fileIOResp, KADEMLIA_ESE_HOLEPUNCH_ACK, uIP, uUDPPort, CKadUDPKey(), NULL);
	}

	// The responder also seeds a NAT expectation — the initiator will send a uTP SYN
	// back to us once it processes our ACK, so we need to be ready to accept it.
	if (theApp.clientudp != NULL)
		theApp.clientudp->SeedNatTraversalExpectation(NULL, uIP, uUDPPort);
}

// eSE P0: responder -> initiator return-routability CHALLENGE. Carries the echoed
// nonce + a stateless cookie bound to (our node id, initiator IP, nonce) for the
// current epoch. We do NOT seed any NAT state here — only once the initiator proves
// return-routability by echoing the cookie in a 38-byte REQ.
// Packet: <Nonce 4><Cookie 16> = 20 bytes.
void CKademliaUDPListener::SendEseHolePunchChallenge(uint32 uIP, uint16 uUDPPort, uint32 uNonce, const uint8 *pbyCookie, const CKadUDPKey &senderUDPKey)
{
	CSafeMemFile fileIO(4 + eSE::HP_COOKIE_SIZE);
	fileIO.WriteUInt32(uNonce);                       // echo for correlation
	fileIO.Write(pbyCookie, eSE::HP_COOKIE_SIZE);

	if (thePrefs.GetDebugClientKadUDPLevel() > 0)
		DebugSend("KADEMLIA_ESE_HOLEPUNCH_CHALLENGE", uIP, uUDPPort);
	// Same encryption tiering as the ACK path (the sender is unknown by definition
	// here, so this is normally the receiver-key or plaintext branch).
	CContact* pSenderContact = NULL;
	if (CKademlia::GetRoutingZone() != NULL)
		pSenderContact = CKademlia::GetRoutingZone()->GetContact(uIP, uUDPPort, false);
	if (pSenderContact != NULL) {
		CKadUDPKey replyKey = pSenderContact->GetUDPKey();
		CUInt128 senderCryptID = pSenderContact->GetClientID();
		SendPacket(fileIO, KADEMLIA_ESE_HOLEPUNCH_CHALLENGE, uIP, uUDPPort, replyKey, &senderCryptID);
	} else if (!senderUDPKey.IsEmpty()) {
		SendPacket(fileIO, KADEMLIA_ESE_HOLEPUNCH_CHALLENGE, uIP, uUDPPort, senderUDPKey, NULL);
	} else {
		SendPacket(fileIO, KADEMLIA_ESE_HOLEPUNCH_CHALLENGE, uIP, uUDPPort, CKadUDPKey(), NULL);
	}
}

// eSE P0: initiator side — we sent a REQ and got a CHALLENGE back. Echo the cookie
// in a 38-byte expanded REQ so the responder can prove our return-routability and
// then ACK + seed. We only act if we actually have a pending punch for this
// (IP, nonce) — a peek (EseAuthorizeHolePunchChallenge), NOT a consume: the eventual
// ACK still needs the entry. The authorize call also bounds resends (anti-flood).
void CKademliaUDPListener::Process_ESE_HOLEPUNCH_CHALLENGE(const byte *pbyPacketData, uint32 uLenPacket, uint32 uIP, uint16 uUDPPort, const CKadUDPKey & /*senderUDPKey*/)
{
	if (!EseHolePunchTransportReady())
		return;

	if (uLenPacket != 4 + eSE::HP_COOKIE_SIZE) {
		CString strError;
		strError.Format(_T("***NOTE: Received wrong size (%u) packet in %hs"), uLenPacket, __FUNCTION__);
		throw strError;
	}

	CSafeMemFile fileIO(pbyPacketData, uLenPacket);
	uint32 uNonce = fileIO.ReadUInt32();
	uint8 abyCookie[eSE::HP_COOKIE_SIZE];
	fileIO.Read(abyCookie, eSE::HP_COOKIE_SIZE);

	// Anti-injection + anti-flood: only respond to a CHALLENGE for a punch WE
	// started, and only a bounded number of times per pending entry.
	if (!EseAuthorizeHolePunchChallenge(uIP, uNonce)) {
		DebugLogWarning(_T("eSE: Dropping unsolicited/overused HOLEPUNCH_CHALLENGE from %s:%u nonce=0x%08X"),
			(LPCTSTR)ipstr(htonl(uIP)), uUDPPort, uNonce);
		return;
	}

	DebugLog(_T("eSE: HOLEPUNCH_CHALLENGE from %s:%u nonce=0x%08X — echoing cookie in expanded REQ"),
		(LPCTSTR)ipstr(htonl(uIP)), uUDPPort, uNonce);
	SendEseHolePunchReqWithCookie(uIP, uUDPPort, uNonce, abyCookie);
}

// eSE P0: re-send our REQ as a 38-byte expanded packet echoing the cookie the
// responder handed us. Reuses the existing pending nonce (already remembered by
// SendEseHolePunchReq), so we do NOT re-remember or re-seed.
void CKademliaUDPListener::SendEseHolePunchReqWithCookie(uint32 uIP, uint16 uUDPPort, uint32 uNonce, const uint8 *pbyCookie)
{
	if (!EseHolePunchTransportReady())
		return;
	if (uIP == 0 || uUDPPort == 0)
		return;

	// <OurKadID 16><OurUDPPort 2><Nonce 4><Cookie 16> = 38 bytes
	CSafeMemFile fileIO(38);
	fileIO.WriteUInt128(CKademlia::GetPrefs()->GetKadID());
	fileIO.WriteUInt16(theApp.GetAdvertisedUdpPort());
	fileIO.WriteUInt32(uNonce);
	fileIO.Write(pbyCookie, eSE::HP_COOKIE_SIZE);

	if (thePrefs.GetDebugClientKadUDPLevel() > 0)
		DebugSend("KADEMLIA_ESE_HOLEPUNCH_REQ", uIP, uUDPPort);

	CContact* pContact = NULL;
	if (CKademlia::GetRoutingZone() != NULL)
		pContact = CKademlia::GetRoutingZone()->GetContact(uIP, uUDPPort, false);

	if (pContact != NULL && pContact->GetUDPKey().GetKeyValue(theApp.GetPublicIP()) != 0) {
		CKadUDPKey targetKey = pContact->GetUDPKey();
		CUInt128 targetCryptID = pContact->GetClientID();
		SendPacket(fileIO, KADEMLIA_ESE_HOLEPUNCH_REQ, uIP, uUDPPort, targetKey, &targetCryptID);
	} else {
		CKadUDPKey emptyKey;
		SendPacket(fileIO, KADEMLIA_ESE_HOLEPUNCH_REQ, uIP, uUDPPort, emptyKey, NULL);
	}
	DebugLog(_T("eSE: Sent expanded HOLEPUNCH_REQ (cookie) to %s:%u nonce=0x%08X"),
		(LPCTSTR)ipstr(htonl(uIP)), uUDPPort, uNonce);
}

// eSE: Initiate a uTP hole-punch toward a known Kad peer.
// Called from CUpDownClient::TryToConnect when we know the peer's IP:port
// but cannot do a direct TCP connection (both behind NAT).
// uIP = host-order, uUDPPort = host-order (Kad convention).
void CKademliaUDPListener::SendEseHolePunchReq(uint32 uIP, uint16 uUDPPort,
	bool bAdvertiseCookie, CUpDownClient* pExpectedClient)
{
	if (!EseHolePunchTransportReady())
		return;
	if (uIP == 0 || uUDPPort == 0)
		return;

	// Capability-aware peers get an initial 26B request. The original 22B form
	// remains byte-identical for older peers and receives the bounded legacy ACK.
	CSafeMemFile fileIO(bAdvertiseCookie ? 26 : 22);
	fileIO.WriteUInt128(CKademlia::GetPrefs()->GetKadID());
	fileIO.WriteUInt16(theApp.GetAdvertisedUdpPort());
	// eSE 8.12.1: Cryptographically secure nonce (anti-Sybil prediction attack)
	// eSE P0: via the thread-safe wrapper (AutoSeededRandomPool is not thread-safe;
	// this site is reachable from the WebServer worker as well as the Kad thread).
	uint32 uNonce;
	EseHolePunchRandomBlock(reinterpret_cast<byte*>(&uNonce), sizeof(uNonce));
	fileIO.WriteUInt32(uNonce);
	if (bAdvertiseCookie)
		fileIO.WriteUInt32(g_uEseCapsRuntime | ESE_CAP_HOLEPUNCH_COOKIE);
	EseRememberHolePunchNonce(uIP, uUDPPort, uNonce, pExpectedClient);

	if (thePrefs.GetDebugClientKadUDPLevel() > 0)
		DebugSend("KADEMLIA_ESE_HOLEPUNCH_REQ", uIP, uUDPPort);

	// eSE 8.12.2: Send encrypted using the remote's CKadUDPKey from our routing table.
	// If the peer is a known Kad contact, we use their key for full RC4 obfuscation.
	// Fallback: If unknown (e.g., indirect referral), send unencrypted — acceptable because
	// the nonce is already CSPRNG-secured (8.12.1) and worst case is "same as before".
	CContact* pContact = NULL;
	if (CKademlia::GetRoutingZone() != NULL)
		pContact = CKademlia::GetRoutingZone()->GetContact(uIP, uUDPPort, false);

	if (pContact != NULL && pContact->GetUDPKey().GetKeyValue(theApp.GetPublicIP()) != 0) {
		CKadUDPKey targetKey = pContact->GetUDPKey();
		CUInt128 targetCryptID = pContact->GetClientID();
		SendPacket(fileIO, KADEMLIA_ESE_HOLEPUNCH_REQ, uIP, uUDPPort, targetKey, &targetCryptID);
		InterlockedIncrement(&CStatistics::m_dwHolePunchEncrypted);
		DebugLog(_T("eSE: HOLEPUNCH_REQ sent ENCRYPTED to %s:%u"), (LPCTSTR)ipstr(htonl(uIP)), uUDPPort);
	} else {
		CKadUDPKey emptyKey;
		SendPacket(fileIO, KADEMLIA_ESE_HOLEPUNCH_REQ, uIP, uUDPPort, emptyKey, NULL);
		InterlockedIncrement(&CStatistics::m_dwHolePunchPlaintext);
		DebugLog(_T("eSE: HOLEPUNCH_REQ sent UNENCRYPTED to %s:%u (peer not in routing table)"),
			(LPCTSTR)ipstr(htonl(uIP)), uUDPPort);
	}
	InterlockedIncrement(&CStatistics::m_dwHolePunchAttempts);


	// Also seed our own NAT expectation so we're ready to accept the peer's uTP SYN
	// if the remote responds with its own connection attempt.
	if (theApp.clientudp != NULL)
		theApp.clientudp->SeedNatTraversalExpectation(NULL, uIP, uUDPPort);

	DebugLog(_T("eSE: Sent HOLEPUNCH_REQ to %s:%u nonce=0x%08X (encrypted=%s)"),
		(LPCTSTR)ipstr(htonl(uIP)), uUDPPort, uNonce,
		(pContact != NULL && pContact->GetUDPKey().GetKeyValue(theApp.GetPublicIP()) != 0) ? _T("yes") : _T("no"));
}

// eSE v9 (anti-CGNAT port prediction / "birthday spray"): a symmetric NAT assigns a
// different external port per destination, so the peer's advertised Kad port is NOT the
// port its NAT opens toward us. Fire the REQ at a small window of candidate ports around
// the observed one to raise the odds one lands on the real mapping. Each sprayed REQ is a
// full SendEseHolePunchReq: it carries its own nonce, is remembered per-(IP,nonce), and
// seeds a uTP accept expectation for that port. The CHALLENGE/ACK match is IP+nonce and
// port-agnostic (EseAuthorizeHolePunchChallenge / EseConsumeHolePunchNonce), so a hit on
// ANY sprayed port completes the punch even though the reply arrives from a third port.
// uSpread==0 (default; pref EseHolePunchPortPredict OFF) => exact single-shot legacy path.
// Forward-biased (sequential-allocation NATs step upward), clamped so a misconfig can't
// flood: at most ESE_HP_SPRAY_MAX ports each side (2*8+1 = 17 packets worst case).
void CKademliaUDPListener::SendEseHolePunchReqSpray(uint32 uIP, uint16 uBasePort,
	uint16 uSpread, bool bAdvertiseCookie, CUpDownClient* pExpectedClient)
{
	if (!EseHolePunchTransportReady() || uIP == 0 || uBasePort == 0)
		return;

	// The base port is always tried (this is the unchanged legacy behavior).
	SendEseHolePunchReq(uIP, uBasePort, bAdvertiseCookie, pExpectedClient);
	if (uSpread == 0)
		return;

	const uint16 ESE_HP_SPRAY_MAX = 8;
	if (uSpread > ESE_HP_SPRAY_MAX)
		uSpread = ESE_HP_SPRAY_MAX;

	for (uint16 d = 1; d <= uSpread; ++d) {
		if ((uint32)uBasePort + d <= 65535) {
			SendEseHolePunchReq(uIP, (uint16)(uBasePort + d), bAdvertiseCookie, pExpectedClient);
			InterlockedIncrement(&CStatistics::m_dwHolePunchSprayReqs);
		}
		if ((int)uBasePort - (int)d >= 1) {
			SendEseHolePunchReq(uIP, (uint16)(uBasePort - d), bAdvertiseCookie, pExpectedClient);
			InterlockedIncrement(&CStatistics::m_dwHolePunchSprayReqs);
		}
	}
	DebugLog(_T("eSE: HOLEPUNCH port-predict spray base=%u spread=%u to %s"),
		uBasePort, uSpread, (LPCTSTR)ipstr(htonl(uIP)));
}

// ─── R.1 (3-way rendezvous) outbound — Kad3 hole-punch send primitives ────────
// IPv4 wire (uint32 host-order), mirroring the validated 2-way path; a v6/CAddress
// variant is a later increment. Kill-switch gated; the CALLER gates on the peer
// advertising ESE_CAP_HOLEPUNCH_RDV. Encryption tiering mirrors SendEseHolePunchReq.
// NOTE: not yet called by anyone — the receive handlers + dispatch that drive these
// land in R.1 increment 2b-recv (they need A-side pending-rendezvous state).

void CKademliaUDPListener::SendKad3HolepunchPacket(CSafeMemFile &fileIO, byte byOpcode, uint32 uIP, uint16 uUDPPort)
{
	CContact* pContact = NULL;
	if (CKademlia::GetRoutingZone() != NULL)
		pContact = CKademlia::GetRoutingZone()->GetContact(uIP, uUDPPort, false);
	if (pContact != NULL && pContact->GetUDPKey().GetKeyValue(theApp.GetPublicIP()) != 0) {
		CKadUDPKey targetKey = pContact->GetUDPKey();
		CUInt128 targetCryptID = pContact->GetClientID();
		SendPacket(fileIO, byOpcode, uIP, uUDPPort, targetKey, &targetCryptID);
	} else {
		CKadUDPKey emptyKey;
		SendPacket(fileIO, byOpcode, uIP, uUDPPort, emptyKey, NULL);
	}
}

// A -> R: ask rendezvous R to help reach target B. Classic 10B; expanded 26B echoes
// R's CHALLENGE cookie to prove A's return-routability (only then does R forward).
void CKademliaUDPListener::SendKad3HolepunchReq(uint32 uRdvIP, uint16 uRdvPort, uint32 uNonce, uint32 uTargetIP, uint16 uTargetPort, const uint8 *pbyCookie /*=NULL*/)
{
	if (!EseHolePunchTransportReady() || !thePrefs.GetEseKad3Rendezvous()
		|| uRdvIP == 0 || uRdvPort == 0)
		return;
	CSafeMemFile fileIO(pbyCookie ? 26 : 10);
	fileIO.WriteUInt32(uNonce);
	fileIO.WriteUInt32(uTargetIP);
	fileIO.WriteUInt16(uTargetPort);
	if (pbyCookie != NULL)
		fileIO.Write(pbyCookie, eSE::HP_COOKIE_SIZE);
	SendKad3HolepunchPacket(fileIO, KADEMLIA3_HOLEPUNCH_REQ, uRdvIP, uRdvPort);
	InterlockedIncrement(&CStatistics::m_dwKad3RdvReqSent);
}

// R -> A: anti-reflection cookie. A must echo it (expanded REQ) before R forwards to B.
void CKademliaUDPListener::SendKad3HolepunchChallenge(uint32 uIP, uint16 uUDPPort, uint32 uNonce, const uint8 *pbyCookie)
{
	if (!EseHolePunchTransportReady() || !thePrefs.GetEseKad3Rendezvous())
		return;
	CSafeMemFile fileIO(4 + eSE::HP_COOKIE_SIZE);
	fileIO.WriteUInt32(uNonce);
	fileIO.Write(pbyCookie, eSE::HP_COOKIE_SIZE);
	SendKad3HolepunchPacket(fileIO, KADEMLIA3_HOLEPUNCH_CHALLENGE, uIP, uUDPPort);
	InterlockedIncrement(&CStatistics::m_dwKad3RdvChallengeSent);
}

// R -> B: A (origin) wants to punch; B should start sending toward A.
void CKademliaUDPListener::SendKad3HolepunchFwd(uint32 uIP_B, uint16 uPort_B, uint32 uNonce, uint32 uOriginIP, uint16 uOriginPort)
{
	if (!EseHolePunchTransportReady() || !thePrefs.GetEseKad3Rendezvous()
		|| uIP_B == 0 || uPort_B == 0)
		return;
	CSafeMemFile fileIO(10);
	fileIO.WriteUInt32(uNonce);
	fileIO.WriteUInt32(uOriginIP);
	fileIO.WriteUInt16(uOriginPort);
	SendKad3HolepunchPacket(fileIO, KADEMLIA3_HOLEPUNCH_FWD, uIP_B, uPort_B);
	InterlockedIncrement(&CStatistics::m_dwKad3RdvFwd);
}

// R -> A: FWD relayed to B; A may start punching toward B now.
void CKademliaUDPListener::SendKad3HolepunchProceed(uint32 uIP_A, uint16 uPort_A, uint32 uNonce)
{
	if (!EseHolePunchTransportReady() || !thePrefs.GetEseKad3Rendezvous())
		return;
	CSafeMemFile fileIO(4);
	fileIO.WriteUInt32(uNonce);
	SendKad3HolepunchPacket(fileIO, KADEMLIA3_HOLEPUNCH_PROCEED, uIP_A, uPort_A);
}

// R.2 keepalive: send a minimal KADEMLIA3_PING_REQ to a supernode so the stateful
// firewall conntrack on our outbound flow stays open. IPv4 path (the validated Kad
// UDP socket); a 0 IP is skipped (e.g. a v6-only CAddress reduced to 0). Reuses the
// R.1 encryption-tiered send helper. The far side answers via Process_KADEMLIA3_PING_REQ
// (PONG below); the supernode pool is filled from the routing table in CKadKeepalive::Tick().
void CKademliaUDPListener::SendKad3PingReq(uint32 uIP, uint16 uUDPPort)
{
	// uIP==0xFFFFFFFF guards a v6-only CAddress whose ToUInt32 collapses to UINT_MAX
	// (adversarial review 2026-06-14, latent finding) — never ping 255.255.255.255.
	if (uIP == 0 || uIP == 0xFFFFFFFF || uUDPPort == 0)
		return;
	// Minimal tickle: <OurKadID 16> so the responder can correlate a PONG.
	CSafeMemFile fileIO(16);
	fileIO.WriteUInt128(CKademlia::GetPrefs()->GetKadID());
	SendKad3HolepunchPacket(fileIO, KADEMLIA3_PING_REQ, uIP, uUDPPort);
}

// R.2 keepalive: reply a KADEMLIA3_PING_RES (PONG) to a peer that pinged us, so the
// round trip completes and they can keep us in their active set. Carries <OurKadID 16>
// for symmetry with the REQ. Reuses the R.1 encryption-tiered send helper.
void CKademliaUDPListener::SendKad3PingRes(uint32 uIP, uint16 uUDPPort)
{
	if (uIP == 0 || uIP == 0xFFFFFFFF || uUDPPort == 0)
		return;
	CSafeMemFile fileIO(16);
	fileIO.WriteUInt128(CKademlia::GetPrefs()->GetKadID());
	SendKad3HolepunchPacket(fileIO, KADEMLIA3_PING_RES, uIP, uUDPPort);
}

// R.2 keepalive responder: an inbound ping just refreshed the sender's NAT mapping
// toward us — answer with a PONG. The payload (<SenderKadID 16>) is advisory; we reply
// to the socket source (uIP), which is the return-routable address.
void CKademliaUDPListener::Process_KADEMLIA3_PING_REQ(const byte *pbyPacketData, uint32 uLenPacket, uint32 uIP, uint16 uUDPPort, const CKadUDPKey & /*senderUDPKey*/)
{
	if (uLenPacket != 16 || CKademlia::GetRoutingZone() == NULL)
		return;
	CContact* pContact = CKademlia::GetRoutingZone()->GetContact(uIP, uUDPPort, false);
	if (pContact == NULL)
		return;
	CSafeMemFile fileIO(pbyPacketData, uLenPacket);
	CUInt128 uSenderKadID;
	fileIO.ReadUInt128(uSenderKadID);
	if (uSenderKadID != pContact->GetClientID())
		return;
	SendKad3PingRes(uIP, uUDPPort);
}

// R.2 keepalive receiver: a supernode answered our ping. Refresh its health so Tick()'s
// miss-detector keeps it active. Matched on the socket source IP (host-order), never on
// anything self-reported in the payload.
void CKademliaUDPListener::Process_KADEMLIA3_PING_RES(const byte *pbyPacketData, uint32 uLenPacket, uint32 uIP, uint16 uUDPPort, const CKadUDPKey & /*senderUDPKey*/)
{
	if (uLenPacket != 16 || CKademlia::GetRoutingZone() == NULL)
		return;
	CContact* pContact = CKademlia::GetRoutingZone()->GetContact(uIP, uUDPPort, false);
	if (pContact == NULL)
		return;
	CSafeMemFile fileIO(pbyPacketData, uLenPacket);
	CUInt128 uResponderKadID;
	fileIO.ReadUInt128(uResponderKadID);
	if (uResponderKadID != pContact->GetClientID())
		return;
	CKadKeepalive::Instance().OnPong(uIP, uUDPPort, uResponderKadID);
}

// ─── R.1 (3-way rendezvous) — A-side initiator ────────────────────────────────
// Begin a rendezvous to reach (uTargetIP:uTargetPort) via R. Remembers the pending
// punch so the CHALLENGE/PROCEED from R can be matched, then sends the classic REQ.
// The caller chose R (must advertise ESE_CAP_HOLEPUNCH_RDV); this is the entry point
// the manual /api endpoint and the auto-selector (increment 3) call.
void CKademliaUDPListener::InitiateKad3Rendezvous(uint32 uRdvIP, uint16 uRdvPort, uint32 uTargetIP, uint16 uTargetPort)
{
	if (!EseHolePunchTransportReady() || !thePrefs.GetEseKad3Rendezvous()
		|| uRdvIP == 0 || uRdvPort == 0 || uTargetIP == 0 || uTargetPort == 0)
		return;
	if (!IsGoodIP(htonl(uRdvIP), true) || !IsGoodIP(htonl(uTargetIP), true))
		return;
	uint32 uNonce;
	EseHolePunchRandomBlock(reinterpret_cast<byte*>(&uNonce), sizeof(uNonce));
	Kad3RememberRdv(uRdvIP, uRdvPort, uNonce, uTargetIP, uTargetPort);
	EseRememberHolePunchNonce(uTargetIP, uTargetPort, uNonce, NULL);
	SendKad3HolepunchReq(uRdvIP, uRdvPort, uNonce, uTargetIP, uTargetPort);  // classic (no cookie yet)
	CLiveDebugLog::Get().Append("KAD3", "RDV: initiating via R %S -> target %S",
		(LPCWSTR)ipstr(htonl(uRdvIP)), (LPCWSTR)ipstr(htonl(uTargetIP)));
}

// R role: A asks us to help it reach B. ANTI-REFLECTION: we never forward to B until
// A proves return-routability by echoing our cookie. A's address is OBSERVED
// (uIP,uUDPPort) — never self-reported — so a spoofed A never receives the cookie.
void CKademliaUDPListener::Process_KADEMLIA3_HOLEPUNCH_REQ(const byte *pbyPacketData, uint32 uLenPacket, uint32 uIP, uint16 uUDPPort, const CKadUDPKey & /*senderUDPKey*/)
{
	if (!EseHolePunchTransportReady() || !thePrefs.GetEseKad3Rendezvous())
		return;
	// classic <nonce 4><targetIP 4><targetPort 2> = 10; expanded +<cookie 16> = 26.
	const bool bExpanded = (uLenPacket == 26);
	if (uLenPacket != 10 && !bExpanded) {
		CString strError;
		strError.Format(_T("***NOTE: Received wrong size (%u) packet in %hs"), uLenPacket, __FUNCTION__);
		throw strError;
	}
	CSafeMemFile fileIO(pbyPacketData, uLenPacket);
	uint32 uNonce = fileIO.ReadUInt32();
	uint32 uTargetIP = fileIO.ReadUInt32();
	uint16 uTargetPort = fileIO.ReadUInt16();
	if (uTargetPort == 0 || !IsGoodIP(htonl(uTargetIP), true))
		return;
	CContact* pTargetContact = NULL;
	if (CKademlia::GetRoutingZone() != NULL)
		pTargetContact = CKademlia::GetRoutingZone()->GetContact(uTargetIP, uTargetPort, false);
	if (pTargetContact == NULL || !pTargetContact->IsIpVerified()) {
		DebugLogWarning(_T("R.1: refusing rendezvous to unknown/unverified target %s:%u"),
			(LPCTSTR)ipstr(htonl(uTargetIP)), (unsigned)uTargetPort);
		return;
	}
	InterlockedIncrement(&CStatistics::m_dwKad3RdvReqRecv);

	uint8 abyNodeHash[16];
	CKademlia::GetPrefs()->GetKadID().ToByteArray(abyNodeHash);

	if (bExpanded) {
		uint8 abyCookie[eSE::HP_COOKIE_SIZE];
		fileIO.Read(abyCookie, eSE::HP_COOKIE_SIZE);
		if (!eSE::EseHolePunchCookie::Verify(abyNodeHash, ::GetTickCount(), uIP, uNonce, abyCookie)) {
			DebugLogWarning(_T("R.1: HOLEPUNCH_REQ from %s — cookie MISMATCH, NOT forwarding"),
				(LPCTSTR)ipstr(htonl(uIP)));
			return;
		}
		// Return-routability proven → relay to B + tell A to start punching.
		SendKad3HolepunchFwd(uTargetIP, uTargetPort, uNonce, uIP, uUDPPort);
		SendKad3HolepunchProceed(uIP, uUDPPort, uNonce);
		CLiveDebugLog::Get().Append("KAD3", "RDV(as R): A %S proven -> FWD to B %S",
			(LPCWSTR)ipstr(htonl(uIP)), (LPCWSTR)ipstr(htonl(uTargetIP)));
		return;
	}
	// Classic REQ — we have no proof A owns its IP yet. Send a CHALLENGE; A must echo
	// the cookie in an expanded REQ before we forward (mirrors the 2-way 0x65 path).
	uint8 abyCookie[eSE::HP_COOKIE_SIZE];
	eSE::EseHolePunchCookie::Compute(abyNodeHash, uIP, uNonce, abyCookie);
	SendKad3HolepunchChallenge(uIP, uUDPPort, uNonce, abyCookie);
}

// B role: rendezvous R forwarded A's request. Punch toward A (open our NAT) so A's
// simultaneous punch lands. Reflection floor: only act on a FWD from a KNOWN Kad
// contact (R), and the punch goes to the FWD-stated origin — per-IP rate-limited.
void CKademliaUDPListener::Process_KADEMLIA3_HOLEPUNCH_FWD(const byte *pbyPacketData, uint32 uLenPacket, uint32 uIP, uint16 uUDPPort, const CKadUDPKey & /*senderUDPKey*/)
{
	if (!EseHolePunchTransportReady() || !thePrefs.GetEseKad3Rendezvous())
		return;
	if (uLenPacket != 10) {
		CString strError;
		strError.Format(_T("***NOTE: Received wrong size (%u) packet in %hs"), uLenPacket, __FUNCTION__);
		throw strError;
	}
	// Only honor a forward vouched for by a rendezvous we already know in our routing
	// table — bounds who can make us punch an arbitrary origin.
	CContact* pRendezvous = CKademlia::GetRoutingZone() != NULL
		? CKademlia::GetRoutingZone()->GetContact(uIP, uUDPPort, false) : NULL;
	if (pRendezvous == NULL || !pRendezvous->IsIpVerified()) {
		DebugLogWarning(_T("R.1: HOLEPUNCH_FWD from UNKNOWN rendezvous %s — ignored"),
			(LPCTSTR)ipstr(htonl(uIP)));
		return;
	}
	CSafeMemFile fileIO(pbyPacketData, uLenPacket);
	uint32 uNonce = fileIO.ReadUInt32();
	uint32 uOriginIP = fileIO.ReadUInt32();
	uint16 uOriginPort = fileIO.ReadUInt16();
	if (uOriginPort == 0 || !IsGoodIP(htonl(uOriginIP), true))
		return;
	// Punch toward A (origin) — reuse the validated 2-way primitive (opens our NAT,
	// seeds the uTP accept expectation). The 0x63/0x64 exchange then confirms the hole.
	uint8 abyNodeHash[16];
	CKademlia::GetPrefs()->GetKadID().ToByteArray(abyNodeHash);
	uint8 abyCookie[eSE::HP_COOKIE_SIZE];
	eSE::EseHolePunchCookie::Compute(abyNodeHash, uOriginIP, uNonce, abyCookie);
	SendEseHolePunchChallenge(uOriginIP, uOriginPort, uNonce, abyCookie, CKadUDPKey());
	InterlockedIncrement(&CStatistics::m_dwHolePunchChallengeSent);
	CLiveDebugLog::Get().Append("KAD3", "RDV(as B): FWD from R %S -> challenging A %S nonce=0x%08X",
		(LPCWSTR)ipstr(htonl(uIP)), (LPCWSTR)ipstr(htonl(uOriginIP)), (unsigned)uNonce);
}

// A role: R challenged us. Re-send the REQ echoing the cookie (proves we own our IP).
void CKademliaUDPListener::Process_KADEMLIA3_HOLEPUNCH_CHALLENGE(const byte *pbyPacketData, uint32 uLenPacket, uint32 uIP, uint16 uUDPPort, const CKadUDPKey & /*senderUDPKey*/)
{
	if (!EseHolePunchTransportReady() || !thePrefs.GetEseKad3Rendezvous())
		return;
	if (uLenPacket != 4 + eSE::HP_COOKIE_SIZE) {
		CString strError;
		strError.Format(_T("***NOTE: Received wrong size (%u) packet in %hs"), uLenPacket, __FUNCTION__);
		throw strError;
	}
	CSafeMemFile fileIO(pbyPacketData, uLenPacket);
	uint32 uNonce = fileIO.ReadUInt32();
	uint8 abyCookie[eSE::HP_COOKIE_SIZE];
	fileIO.Read(abyCookie, eSE::HP_COOKIE_SIZE);

	// Anti-injection: only act on a CHALLENGE for a rendezvous WE started (matched by
	// R's IP + nonce), bounded resends. Returns the remembered target.
	uint32 uTargetIP = 0; uint16 uTargetPort = 0;
	if (!Kad3AuthorizeRdvChallenge(uIP, uUDPPort, uNonce, uTargetIP, uTargetPort)) {
		DebugLogWarning(_T("R.1: unsolicited/overused HOLEPUNCH_CHALLENGE from %s nonce=0x%08X"),
			(LPCTSTR)ipstr(htonl(uIP)), uNonce);
		return;
	}
	SendKad3HolepunchReq(uIP, uUDPPort, uNonce, uTargetIP, uTargetPort, abyCookie);  // expanded, cookie echoed
}

// A role: R relayed our REQ to B and says go. Start punching B (open our NAT toward
// B); B is doing the same after its FWD, so the same packet pair opens both NATs.
void CKademliaUDPListener::Process_KADEMLIA3_HOLEPUNCH_PROCEED(const byte *pbyPacketData, uint32 uLenPacket, uint32 uIP, uint16 uUDPPort, const CKadUDPKey & /*senderUDPKey*/)
{
	if (!EseHolePunchTransportReady() || !thePrefs.GetEseKad3Rendezvous())
		return;
	if (uLenPacket != 4) {
		CString strError;
		strError.Format(_T("***NOTE: Received wrong size (%u) packet in %hs"), uLenPacket, __FUNCTION__);
		throw strError;
	}
	CSafeMemFile fileIO(pbyPacketData, uLenPacket);
	uint32 uNonce = fileIO.ReadUInt32();

	uint32 uTargetIP = 0; uint16 uTargetPort = 0;
	if (!Kad3ConsumeRdvProceed(uIP, uUDPPort, uNonce, uTargetIP, uTargetPort)) {
		DebugLogWarning(_T("R.1: unsolicited HOLEPUNCH_PROCEED from %s nonce=0x%08X"),
			(LPCTSTR)ipstr(htonl(uIP)), uNonce);
		return;
	}
	// Punch B directly via the validated 2-way primitive (the 0x63/0x64 exchange
	// between A and B confirms the hole and increments m_dwHolePunchSuccess).
	InterlockedIncrement(&CStatistics::m_dwKad3RdvSuccess);  // rendezvous reached the punch stage
	CLiveDebugLog::Get().Append("KAD3", "RDV(as A): PROCEED -> awaiting B check %S nonce=0x%08X",
		(LPCWSTR)ipstr(htonl(uTargetIP)), (unsigned)uNonce);
}

// eSE Fase 3: Process an incoming uTP Hole Punch Acknowledgement
// Packet format: <ResponderKadID 16><ResponderUDPPort 2><Nonce 4> = 22 bytes
void CKademliaUDPListener::Process_ESE_HOLEPUNCH_ACK(const byte *pbyPacketData, uint32 uLenPacket, uint32 uIP, uint16 uUDPPort, const CKadUDPKey& /*senderUDPKey*/)
{
	if (!EseHolePunchTransportReady())
		return;

	if (uLenPacket != 22) {
		CString strError;
		strError.Format(_T("***NOTE: Received wrong size (%u) packet in %hs"), uLenPacket, __FUNCTION__);
		throw strError;
	}

	CSafeMemFile fileIO(pbyPacketData, uLenPacket);
	CUInt128 uResponderKadID;
	fileIO.ReadUInt128(uResponderKadID);
	uint16 uResponderUDPPort = fileIO.ReadUInt16();
	uint32 uNonce = fileIO.ReadUInt32();
	CContact* pAckContact = NULL;
	if (CKademlia::GetRoutingZone() != NULL)
		pAckContact = CKademlia::GetRoutingZone()->GetContact(uIP, uUDPPort, false);
	if (pAckContact != NULL && pAckContact->GetClientID() != uResponderKadID) {
		DebugLogWarning(_T("eSE: HOLEPUNCH_ACK identity mismatch at %s:%u - dropped"),
			(LPCTSTR)ipstr(htonl(uIP)), (unsigned)uUDPPort);
		return;
	}

	CUpDownClient* pExpectedClient = NULL;
	if (!EseConsumeHolePunchNonce(uIP, uNonce, uResponderKadID, &pExpectedClient)) {
		DebugLogWarning(_T("eSE: Dropping unsolicited HOLEPUNCH_ACK from %s:%u nonce=0x%08X"),
			(LPCTSTR)ipstr(htonl(uIP)), uResponderUDPPort, uNonce);
		return;
	}
	InterlockedIncrement(&CStatistics::m_dwHolePunchSuccess);
	DebugLog(_T("eSE: HOLEPUNCH_ACK from %s:%u nonce=0x%08X — pinhole ready (total: %u/%u)"),
		(LPCTSTR)ipstr(htonl(uIP)), uUDPPort, uNonce,
		CStatistics::m_dwHolePunchSuccess, CStatistics::m_dwHolePunchAttempts);
	CLiveDebugLog::Get().Append("HOLE",
		"SUCCESS pinhole to %S:%u  total %u/%u",
		(LPCWSTR)ipstr(htonl(uIP)), (unsigned)uUDPPort,
		(unsigned)CStatistics::m_dwHolePunchSuccess,
		(unsigned)CStatistics::m_dwHolePunchAttempts);

	// Hint the UtpSocket layer that we expect a uTP connection from this endpoint.
	// This allows the uTP accept logic to match the incoming SYN to this peer.
	if (theApp.clientudp != NULL) {
		theApp.clientudp->SeedNatTraversalExpectation(pExpectedClient, uIP, uUDPPort);
		DebugLog(_T("eSE: HOLEPUNCH_ACK — seeded NAT expectation for %s:%u"),
			(LPCTSTR)ipstr(htonl(uIP)), uUDPPort);

		// CRITICAL: Actively initiate the uTP connection NOW.
		// The REQ→ACK exchange punched NAT pinholes on both sides.
		// The INITIATOR (us) must send the uTP SYN to complete the connection.
		// The RESPONDER is passively waiting via on_utp_accept.
		if (!theApp.clientudp->InitiateUtpConnect(uIP, uUDPPort, pExpectedClient))
			DebugLogWarning(_T("eSE: HOLEPUNCH_ACK opened the pinhole but no matching eD2K client was available for uTP"));
	}
}

// Native K6-2 routing dispatch. This entry point is reached only for native
// public-IPv6 datagrams selected by CClientUDPSocket. IPv4 packets carrying
// the same numeric opcodes remain isolated in Process_KADEMLIA3_GENERIC.
void CKademliaUDPListener::ProcessPacketV6(const byte* data, uint32 length,
	const byte address[16], uint16 port)
{
	if (data == NULL || address == NULL || length < 2
		|| data[0] != OP_KADEMLIAHEADER || port == 0)
		return;
	CKad6RoutingTable* table = CKademlia::GetKad6RoutingTable();
	if (table == NULL)
		return;
	const kad6::Kad6Address source = Kad6AddressFromRaw(address);
	const kad6::Byte* payload = data + 2;
	const std::size_t payloadLength = length - 2;
	const std::uint64_t now = static_cast<std::uint64_t>(time(NULL));

	switch (data[1]) {
		case KADEMLIA3_HELLO_REQ: {
			kad6::K6HelloRequest request;
			if (kad6::DecodeK6HelloRequest(payload, payloadLength, request)
				!= kad6::Kad6Status::Ok
				|| !Kad6HeaderMatchesSource(request.header, source, port)
				|| request.header.version != kad6::kK6RouteWireVersion)
				return;
			const kad6::K6RouteContact contact = Kad6ContactFromHeader(request.header);
			if (!table->AddSignedProbation(contact,
				request.header.sender_record, now))
				return;

			kad6::K6HelloResponse response;
			if (BuildKad6Header(request.header.txid, response.header)) {
				std::vector<kad6::Byte> wire;
				if (kad6::EncodeK6HelloResponse(response, wire) == kad6::Kad6Status::Ok)
					SendKad6Payload(KADEMLIA3_HELLO_RES, wire, address, port);
			}
			// Exactly one same-sized response. A reciprocal challenge is left to
			// the paced probation scheduler so spoofed HELLOs cannot cause 2x
			// immediate reflection.
			break;
		}

		case KADEMLIA3_HELLO_RES: {
			kad6::K6HelloResponse response;
			if (kad6::DecodeK6HelloResponse(payload, payloadLength, response)
				!= kad6::Kad6Status::Ok
				|| !Kad6HeaderMatchesSource(response.header, source, port)
				|| response.header.version != kad6::kK6RouteWireVersion)
				return;
			const int index = FindKad6Pending(response.header.txid,
				KADEMLIA3_HELLO_RES, address, port);
			if (index < 0)
				return;
			const SKad6Pending pending = m_kad6Pending[index];
			if (pending.hasExpectedNode
				&& pending.expectedNode != response.header.sender_id)
				return;
			const kad6::K6RouteContact contact = Kad6ContactFromHeader(response.header);
			if (!table->MarkVerified(contact,
				response.header.sender_record, now))
				return;
			m_kad6Pending.erase(m_kad6Pending.begin() + index);
			if (pending.afterVerify == K6_AFTER_BOOTSTRAP_RESPONSE)
				SendKad6BootstrapResponse(pending.originalTxid, address, port);
			else if (pending.afterVerify == K6_AFTER_FIND_RESPONSE)
				SendKad6FindResponse(pending.originalTxid, pending.target,
					pending.maximum, address, port);
			else if (pending.afterVerify == K6_AFTER_FIND_SOURCE_RESPONSE)
				SendKad6SourceResponse(pending.originalTxid, pending.target,
					pending.maximum, address, port);
			break;
		}

		case KADEMLIA3_BOOTSTRAP_REQ: {
			kad6::K6BootstrapRequest request;
			if (kad6::DecodeK6BootstrapRequest(payload, payloadLength, request)
				!= kad6::Kad6Status::Ok
				|| !Kad6HeaderMatchesSource(request.header, source, port)
				|| request.header.version != kad6::kK6RouteWireVersion)
				return;
			const kad6::K6RouteContact contact = Kad6ContactFromHeader(request.header);
			if (!table->AddSignedProbation(contact,
				request.header.sender_record, now))
				return;
			// The response is larger than the request. Require a fresh,
			// transaction-bound return-routability proof even for a contact which
			// was verified earlier; historical state is not packet authentication.
			if (!HasKad6PendingFor(contact.node_id))
				SendKad6HelloChallenge(contact, K6_AFTER_BOOTSTRAP_RESPONSE,
					request.header.txid);
			break;
		}

		case KADEMLIA3_BOOTSTRAP_RES: {
			kad6::K6BootstrapResponse response;
			if (kad6::DecodeK6BootstrapResponse(payload, payloadLength, response)
				!= kad6::Kad6Status::Ok
				|| !Kad6HeaderMatchesSource(response.header, source, port)
				|| response.header.version != kad6::kK6RouteWireVersion)
				return;
			const int index = FindKad6Pending(response.header.txid,
				KADEMLIA3_BOOTSTRAP_RES, address, port);
			if (index < 0)
				return;
			const SKad6Pending pending = m_kad6Pending[index];
			if (pending.hasExpectedNode
				&& pending.expectedNode != response.header.sender_id)
				return;
			if (!table->MarkVerified(Kad6ContactFromHeader(response.header),
				response.header.sender_record, now))
				return;
			m_kad6Pending.erase(m_kad6Pending.begin() + index);
			std::size_t accepted = 0;
			for (const kad6::K6RouteContact& contact : response.contacts) {
				if (accepted >= KAD6_RESPONSE_PROBATION_LIMIT)
					break;
				if (!Kad6IsLocalId(contact.node_id)
					&& table->AddProbation(contact, now))
					++accepted;
			}
			break;
		}

		case KADEMLIA3_REQ: {
			kad6::K6FindNodeRequest request;
			if (kad6::DecodeK6FindNodeRequest(payload, payloadLength, request)
				!= kad6::Kad6Status::Ok
				|| !Kad6HeaderMatchesSource(request.header, source, port)
				|| request.header.version != kad6::kK6RouteWireVersion)
				return;
			const kad6::K6RouteContact contact = Kad6ContactFromHeader(request.header);
			if (!table->AddSignedProbation(contact,
				request.header.sender_record, now))
				return;
			// FIND responses are amplified too, so every request gets a fresh
			// return-routability challenge before a contact list is emitted.
			if (!HasKad6PendingFor(contact.node_id))
				SendKad6HelloChallenge(contact, K6_AFTER_FIND_RESPONSE,
					request.header.txid, &request.target_id, request.max_results);
			break;
		}

		case KADEMLIA3_STORE_SOURCE_REQ: {
			kad6::K6StoreSourceRequest request;
			if (kad6::DecodeK6StoreSourceRequest(payload, payloadLength, request)
				!= kad6::Kad6Status::Ok ||
				!Kad6HeaderMatchesSource(request.header, source, port) ||
				request.header.version != kad6::kK6RouteWireVersion ||
				!table->IsVerified(request.header.sender_id, source, port))
				return;
			const kad6::K6RouteContact sender = Kad6ContactFromHeader(request.header);
			if (!table->MarkVerified(sender, request.header.sender_record, now) ||
				kad6::VerifyK6SourceRecord(MakeKad6HostCryptoHooks(), request.record)
					!= kad6::Kad6Status::Ok ||
				kad6::K6SourceRecordCheckFresh(request.record, now)
					!= kad6::Kad6Status::Ok)
				return;

			for (auto it = m_kad6StoredSources.begin(); it != m_kad6StoredSources.end(); )
				it = it->second.record.expires_at <= now
					? m_kad6StoredSources.erase(it) : std::next(it);

			kad6::K6StoreStatus storeStatus = kad6::K6StoreStatus::Rejected;
			std::uint64_t acceptedEpoch = 0;
			std::vector<kad6::Byte> canonical;
			if (kad6::EncodeK6SourceRecord(request.record, canonical) == kad6::Kad6Status::Ok) {
				const std::string key = Kad6StoredSourceKey(request.record);
				auto existing = m_kad6StoredSources.find(key);
				if (existing != m_kad6StoredSources.end()) {
					if (request.record.source_epoch < existing->second.record.source_epoch ||
						(request.record.source_epoch == existing->second.record.source_epoch &&
						 canonical != existing->second.canonicalWire)) {
						storeStatus = kad6::K6StoreStatus::Stale;
						acceptedEpoch = existing->second.record.source_epoch;
					} else {
						existing->second.record = request.record;
						existing->second.canonicalWire = canonical;
						storeStatus = kad6::K6StoreStatus::Stored;
						acceptedEpoch = request.record.source_epoch;
					}
				} else if (m_kad6StoredSources.size() >= 4096) {
					storeStatus = kad6::K6StoreStatus::Overloaded;
				} else {
					std::size_t sameHash = 0;
					for (const auto& pair : m_kad6StoredSources)
						if (pair.second.record.object_hash == request.record.object_hash)
							++sameHash;
					if (sameHash >= 1000) {
						storeStatus = kad6::K6StoreStatus::Overloaded;
					} else {
						SKad6StoredSource stored;
						stored.record = request.record;
						stored.canonicalWire = canonical;
						m_kad6StoredSources[key] = std::move(stored);
						storeStatus = kad6::K6StoreStatus::Stored;
						acceptedEpoch = request.record.source_epoch;
					}
				}
			}

			kad6::K6StoreSourceResponse response;
			response.target_hash = request.target_hash;
			response.status = storeStatus;
			response.load = static_cast<byte>((std::min<std::size_t>)(100,
				(m_kad6StoredSources.size() * 100u) / 4096u));
			response.accepted_epoch = acceptedEpoch;
			if (BuildKad6Header(request.header.txid, response.header)) {
				std::vector<kad6::Byte> wire;
				if (kad6::EncodeK6StoreSourceResponse(response, wire) == kad6::Kad6Status::Ok)
					SendKad6Payload(KADEMLIA3_STORE_SOURCE_RES, wire, address, port);
			}
			break;
		}

		case KADEMLIA3_FIND_SOURCE_REQ: {
			kad6::K6FindSourceRequest request;
			if (kad6::DecodeK6FindSourceRequest(payload, payloadLength, request)
					!= kad6::Kad6Status::Ok ||
				!Kad6HeaderMatchesSource(request.header, source, port) ||
				request.header.version != kad6::kK6RouteWireVersion)
				return;
			const kad6::K6RouteContact contact = Kad6ContactFromHeader(request.header);
			if (!table->AddSignedProbation(contact, request.header.sender_record, now))
				return;
			// The answer can be much larger than the request. Require a fresh,
			// transaction-bound return-routability proof before emitting records.
			if (!HasKad6PendingFor(contact.node_id))
				SendKad6HelloChallenge(contact, K6_AFTER_FIND_SOURCE_RESPONSE,
					request.header.txid, &request.target_hash, request.max_records);
			break;
		}

		case KADEMLIA3_FIND_SOURCE_RES: {
			kad6::K6FindSourceResponse response;
			if (kad6::DecodeK6FindSourceResponse(payload, payloadLength, response)
					!= kad6::Kad6Status::Ok ||
				!Kad6HeaderMatchesSource(response.header, source, port) ||
				response.header.version != kad6::kK6RouteWireVersion)
				return;
			const int index = FindKad6Pending(response.header.txid,
				KADEMLIA3_FIND_SOURCE_RES, address, port);
			if (index < 0) return;
			const SKad6Pending pending = m_kad6Pending[index];
			if ((pending.hasExpectedNode &&
				 pending.expectedNode != response.header.sender_id) ||
				pending.target != response.target_hash ||
				response.records.size() > pending.maximum)
				return;
			if (!table->MarkVerified(Kad6ContactFromHeader(response.header),
				response.header.sender_record, now))
				return;
			m_kad6Pending.erase(m_kad6Pending.begin() + index);
			uint16 accepted = 0;
			for (const kad6::K6SourceRecord& record : response.records) {
				if (record.object_hash != pending.target ||
					kad6::VerifyK6SourceRecord(MakeKad6HostCryptoHooks(), record) !=
						kad6::Kad6Status::Ok ||
					kad6::K6SourceRecordCheckFresh(record, now) != kad6::Kad6Status::Ok)
					continue;
				if (eSELive::CLiveTunnel::Get().OnKad6NativeSourceRecord(
						pending.sourceCircuitId, pending.sourceRequestId, record))
					++accepted;
			}
			eSELive::CLiveTunnel::Get().OnKad6SourceLookupRpc(
				pending.sourceAlpha, accepted != 0 ? 0 : 1);
			const uint64 lookupKey = (static_cast<uint64>(pending.sourceCircuitId) << 32) |
				pending.sourceRequestId;
			auto lookup = m_kad6SourceLookups.find(lookupKey);
			if (lookup != m_kad6SourceLookups.end()) {
				lookup->second.received = static_cast<uint16>((std::min<unsigned>)(
					lookup->second.maximum, lookup->second.received + accepted));
				lookup->second.roundReceived = static_cast<uint16>(
					lookup->second.roundReceived + accepted);
			}
			break;
		}

		case KADEMLIA3_STORE_SOURCE_RES: {
			kad6::K6StoreSourceResponse response;
			if (kad6::DecodeK6StoreSourceResponse(payload, payloadLength, response)
				!= kad6::Kad6Status::Ok ||
				!Kad6HeaderMatchesSource(response.header, source, port) ||
				response.header.version != kad6::kK6RouteWireVersion)
				return;
			const int index = FindKad6Pending(response.header.txid,
				KADEMLIA3_STORE_SOURCE_RES, address, port);
			if (index < 0)
				return;
			const SKad6Pending pending = m_kad6Pending[index];
			if ((pending.hasExpectedNode && pending.expectedNode != response.header.sender_id) ||
				pending.target != response.target_hash)
				return;
			if (!table->MarkVerified(Kad6ContactFromHeader(response.header),
				response.header.sender_record, now))
				return;
			m_kad6Pending.erase(m_kad6Pending.begin() + index);
			eSELive::CLiveTunnel::Get().OnKad6NativePublishAck(
				pending.publishLeaseId, response.status, response.load,
				response.accepted_epoch);
			break;
		}

		case KADEMLIA3_RES: {
			kad6::K6FindNodeResponse response;
			if (kad6::DecodeK6FindNodeResponse(payload, payloadLength, response)
				!= kad6::Kad6Status::Ok
				|| !Kad6HeaderMatchesSource(response.header, source, port)
				|| response.header.version != kad6::kK6RouteWireVersion)
				return;
			const int index = FindKad6Pending(response.header.txid,
				KADEMLIA3_RES, address, port);
			if (index < 0)
				return;
			const SKad6Pending pending = m_kad6Pending[index];
			if ((pending.hasExpectedNode
				&& pending.expectedNode != response.header.sender_id)
				|| pending.target != response.target_id)
				return;
			if (response.contacts.size() > pending.maximum) {
				table->NoteFailure(response.header.sender_id);
				m_kad6Pending.erase(m_kad6Pending.begin() + index);
				return;
			}
			if (!table->MarkVerified(Kad6ContactFromHeader(response.header),
				response.header.sender_record, now))
				return;
			m_kad6Pending.erase(m_kad6Pending.begin() + index);
			std::size_t accepted = 0;
			for (const kad6::K6RouteContact& contact : response.contacts) {
				if (accepted >= KAD6_RESPONSE_PROBATION_LIMIT)
					break;
				if (!Kad6IsLocalId(contact.node_id)
					&& table->AddProbation(contact, now))
					++accepted;
			}
			if (pending.adaptiveLookup && m_kad6AdaptiveLookup.active)
				m_kad6AdaptiveLookup.roundAccepted = static_cast<uint16>(
					m_kad6AdaptiveLookup.roundAccepted + accepted);
			break;
		}
	}
}

void CKademliaUDPListener::ProcessKad6()
{
	const DWORD tick = GetTickCount();
	if (tick - m_lastKad6Maintenance < 1000)
		return;
	m_lastKad6Maintenance = tick;
	CKad6RoutingTable* table = CKademlia::GetKad6RoutingTable();
	if (table == NULL)
		return;

	extern uint32 g_uForkCapsRuntime;
	::InterlockedAnd(reinterpret_cast<volatile LONG*>(&g_uForkCapsRuntime),
		~static_cast<LONG>(CAP_FORK_IPV6_KAD));
	kad6::K6RouteHeader localHeader;
	if (BuildKad6Header(1, localHeader))
		::InterlockedOr(reinterpret_cast<volatile LONG*>(&g_uForkCapsRuntime),
			static_cast<LONG>(CAP_FORK_IPV6_KAD));
	else
		return;

	const std::uint64_t now = static_cast<std::uint64_t>(time(NULL));
	table->Expire(now);
	for (auto it = m_kad6StoredSources.begin(); it != m_kad6StoredSources.end(); )
		it = it->second.record.expires_at <= now
			? m_kad6StoredSources.erase(it) : std::next(it);
	for (std::size_t i = m_kad6Pending.size(); i > 0; --i) {
		const SKad6Pending& pending = m_kad6Pending[i - 1];
		if (tick - pending.created > 10000) {
			if (pending.sourceCircuitId != 0 && pending.sourceRequestId != 0)
				eSELive::CLiveTunnel::Get().OnKad6SourceLookupRpc(
					pending.sourceAlpha, 3);
			if (pending.hasExpectedNode)
				table->NoteFailure(pending.expectedNode);
			if (pending.publishLeaseId != 0)
				eSELive::CLiveTunnel::Get().OnKad6NativePublishAck(
					pending.publishLeaseId, kad6::K6StoreStatus::Overloaded, 100, 0);
			m_kad6Pending.erase(m_kad6Pending.begin() + (i - 1));
		}
	}

	// Advance every native source lookup only after its current alpha-sized
	// round has settled. No-progress rounds widen 3 -> 5 -> 8, while the
	// overall 24-RPC/12-second budget prevents amplification and queue growth.
	for (auto it = m_kad6SourceLookups.begin(); it != m_kad6SourceLookups.end(); ) {
		const uint64 lookupKey = it->first;
		SKad6SourceLookup& lookup = it->second;
		bool pendingRound = false;
		for (const SKad6Pending& pending : m_kad6Pending)
			if (pending.sourceCircuitId == lookup.circuitId &&
				pending.sourceRequestId == lookup.requestId) {
				pendingRound = true;
				break;
			}
		if ((int)(tick - lookup.deadline) >= 0 ||
			lookup.received >= lookup.maximum || lookup.totalSent >= 24) {
			it = m_kad6SourceLookups.erase(it);
			continue;
		}
		if (!pendingRound && tick - lookup.roundStarted >= 1000) {
			if (lookup.roundReceived == 0)
				lookup.alpha = lookup.alpha < 5 ? 5 : 8;
			else
				lookup.alpha = static_cast<byte>(KAD6_LOOKUP_ALPHA);
			lookup.roundReceived = 0;
			if (!DispatchKad6SourceRound(lookupKey)) {
				it = m_kad6SourceLookups.erase(it);
				continue;
			}
		}
		++it;
	}

	// Classic contacts carrying an additive v6 address are hints only. They
	// enter probation and require a native HELLO round trip before use.
	if (tick - m_lastKad6Import >= 60000 && CKademlia::GetRoutingZone() != NULL) {
		m_lastKad6Import = tick;
		ContactArray contacts;
		CKademlia::GetRoutingZone()->GetAllEntries(contacts);
		for (CContact* legacy : contacts) {
			if (legacy == NULL || !legacy->HasIPv6())
				continue;
			kad6::K6RouteContact contact;
			legacy->GetClientID().ToByteArray(contact.node_id.data());
			if (Kad6IsLocalId(contact.node_id))
				continue;
			contact.endpoint.addr.family = kad6::Kad6Address::Family::IPv6;
			std::memcpy(contact.endpoint.addr.addr.data(),
				legacy->GetIPv6Address(), 16);
			contact.endpoint.udp_port = legacy->GetUDPPort();
			contact.endpoint.tcp_port = legacy->GetTCPPort();
			contact.endpoint.transport_flags = kad6::kK6EpUdpKad6;
			contact.endpoint.valid_until = now + 60 * 60;
			contact.caps = CAP_FORK_IPV6_WIRE | CAP_FORK_IPV6_KAD;
			contact.epoch = std::max<std::uint64_t>(1,
				static_cast<std::uint64_t>(legacy->GetCreatedTime()));
			table->AddProbation(contact, now);
		}
	}

	if (tick - m_lastKad6Challenge >= 5000) {
		CKad6RoutingTable::Entry probation;
		if (table->NextProbation(probation)
			&& !HasKad6PendingFor(probation.contact.node_id)) {
			m_lastKad6Challenge = tick;
			SendKad6HelloChallenge(probation.contact);
		}
	}

	bool adaptivePending = false;
	for (const SKad6Pending& pending : m_kad6Pending)
		if (pending.adaptiveLookup) { adaptivePending = true; break; }
	if (m_kad6AdaptiveLookup.active && !adaptivePending &&
		tick - m_kad6AdaptiveLookup.roundStarted >= 1000) {
		if ((int)(tick - m_kad6AdaptiveLookup.deadline) >= 0 ||
			m_kad6AdaptiveLookup.totalSent >= 24) {
			m_kad6AdaptiveLookup = SKad6AdaptiveLookup{};
		} else {
			m_kad6AdaptiveLookup.alpha = m_kad6AdaptiveLookup.roundAccepted == 0
				? (m_kad6AdaptiveLookup.alpha < 5 ? 5 : 8)
				: static_cast<byte>(KAD6_LOOKUP_ALPHA);
			m_kad6AdaptiveLookup.roundAccepted = 0;
			if (!DispatchKad6MaintenanceRound())
				m_kad6AdaptiveLookup = SKad6AdaptiveLookup{};
		}
	}

	if (!m_kad6AdaptiveLookup.active &&
		tick - m_lastKad6Lookup >= 5 * 60 * 1000 &&
		table->VerifiedSize() != 0) {
		m_lastKad6Lookup = tick;
		m_kad6AdaptiveLookup = SKad6AdaptiveLookup{};
		m_kad6AdaptiveLookup.active = true;
		CKademlia::GetPrefs()->GetKadID().ToByteArray(
			m_kad6AdaptiveLookup.target.data());
		m_kad6AdaptiveLookup.alpha = static_cast<byte>(KAD6_LOOKUP_ALPHA);
		m_kad6AdaptiveLookup.started = tick;
		m_kad6AdaptiveLookup.deadline = tick + 12000;
		if (!DispatchKad6MaintenanceRound())
			m_kad6AdaptiveLookup = SKad6AdaptiveLookup{};
	}
}

void CKademliaUDPListener::Process_KADEMLIA3_GENERIC(const char *szOpcodeName,
    const byte * /*pbyPacketData*/, uint32 uLenPacket,
    uint32 uIP, uint16 uUDPPort)
{
    if (thePrefs.GetDebugClientKadUDPLevel() > 0) {
        DebugRecv(szOpcodeName, uIP, uUDPPort);
    }
    DebugLog(_T("Kad3: %hs from %s:%u (len=%u) - native K6-2 is IPv6-only; dropping IPv4-carried routing opcode"),
        szOpcodeName, (LPCTSTR)ipstr(htonl(uIP)), uUDPPort, uLenPacket);
}
