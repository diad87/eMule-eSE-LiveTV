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
#include "stdafx.h"
#include "clientlist.h"
#include "emule.h"
#include "Log.h"
#include "opcodes.h"
#include "kademlia/kademlia/Kademlia.h"
#include "kademlia/net/PacketTracking.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

using namespace Kademlia;

CPacketTracking::CPacketTracking()
	: dwLastTrackInCleanup()
{
}

CPacketTracking::~CPacketTracking()
{
	m_mapTrackPacketsIn.RemoveAll();
	while (!m_liTrackPacketsIn.IsEmpty())
		delete m_liTrackPacketsIn.RemoveHead();
}

void CPacketTracking::AddTrackedOutPacket(uint32 dwIP, uint8 byOpcode)
{
	// this tracklist monitors _outgoing_ request packets, to make sure incoming answer packets were requested
	// later we will check only tracked packets
	if (IsTrackedOutListRequestPacket(byOpcode)) {
		const DWORD curTick = ::GetTickCount();
		listTrackedRequests.AddHead(TrackPackets_Struct{ curTick, dwIP, byOpcode });
		while (!listTrackedRequests.IsEmpty() && curTick >= listTrackedRequests.GetTail().dwInserted + SEC2MS(180))
			listTrackedRequests.RemoveTail();
	}
}

bool CPacketTracking::IsTrackedOutListRequestPacket(uint8 byOpcode)
{
	switch (byOpcode) {
	case KADEMLIA2_BOOTSTRAP_REQ:
	case KADEMLIA2_HELLO_REQ:
	case KADEMLIA2_HELLO_RES:
	case KADEMLIA2_REQ:
	case KADEMLIA_SEARCH_NOTES_REQ:
	case KADEMLIA2_SEARCH_NOTES_REQ:
	case KADEMLIA_PUBLISH_REQ:
	case KADEMLIA2_PUBLISH_KEY_REQ:
	case KADEMLIA2_PUBLISH_SOURCE_REQ:
	case KADEMLIA2_PUBLISH_NOTES_REQ:
	case KADEMLIA_FINDBUDDY_REQ:
	case KADEMLIA_CALLBACK_REQ:
	case KADEMLIA2_PING:
		return true;
	}
	return false;
}

bool CPacketTracking::IsOnOutTrackList(uint32 dwIP, uint8 byOpcode, bool bDontRemove)
{
#ifdef _DEBUG
	if (!IsTrackedOutListRequestPacket(byOpcode))
		ASSERT(0); // code error / bug
#endif
	const DWORD curTick = ::GetTickCount();
	for (POSITION pos = listTrackedRequests.GetHeadPosition(); pos != NULL;) {
		POSITION pos2 = pos;
		const TrackPackets_Struct &req = listTrackedRequests.GetNext(pos);
		if (curTick >= req.dwInserted + SEC2MS(180))
			break;
		if (req.dwIP == dwIP && req.byOpcode == byOpcode) {
			if (!bDontRemove)
				listTrackedRequests.RemoveAt(pos2);
			return true;
		}
	}
	return false;
}

//return codes: 0 - no error; 1 - flood; 2 - massive flood
static bool IsEndpointScopedEseOpcode(uint8 byOpcode)
{
	switch (byOpcode) {
	case KADEMLIA_ESE_HOLEPUNCH_REQ:
	case KADEMLIA_ESE_HOLEPUNCH_ACK:
	case KADEMLIA_ESE_HOLEPUNCH_CHALLENGE:
	case KADEMLIA3_PING_REQ:
	case KADEMLIA3_PING_RES:
	case KADEMLIA3_HOLEPUNCH_REQ:
	case KADEMLIA3_HOLEPUNCH_FWD:
	case KADEMLIA3_HOLEPUNCH_ACK:
	case KADEMLIA3_HOLEPUNCH_CHALLENGE:
	case KADEMLIA3_HOLEPUNCH_PROCEED:
		return true;
	default:
		return false;
	}
}

int CPacketTracking::InTrackListIsAllowedPacket(uint32 uIP, uint16 uUDPPort, uint8 byOpcode, bool /*bValidSenderkey*/)
{
	// this tracklist monitors _incoming_ request packets and acts as a general flood protection
	// by dropping too frequent requests from a single IP, thus avoiding response floods, saving CPU time,
	// preventing DoS attacks and slowing down other possible attacks/behaviour
	// (scanning indexed files, fake publish floods, etc)

	// first figure out if this is a request packet to be tracked
	// time limits are chosen by estimating the max. frequency of such packets in normal operation (+ buffer)
	// (those limits are not meant be fine for normal usage, but only supposed to be a flood detection)
	//
	// Tokens are calculated as the number of milliseconds corresponding to the allowed quantity of packets per minute.
	int token;
	switch (byOpcode) {
	case KADEMLIA2_BOOTSTRAP_REQ:
		token = MIN2MS(1) / 2;
		break;
	case KADEMLIA2_HELLO_REQ:
		token = MIN2MS(1) / 3;
		break;
	case KADEMLIA2_REQ:
		token = MIN2MS(1) / 10;
		break;
	case KADEMLIA2_SEARCH_NOTES_REQ:
	case KADEMLIA2_SEARCH_KEY_REQ:
	case KADEMLIA2_SEARCH_SOURCE_REQ:
		token = MIN2MS(1) / 3;
		break;
	case KADEMLIA2_PUBLISH_KEY_REQ:
		token = MIN2MS(1) / 4;
		break;
	case KADEMLIA2_PUBLISH_SOURCE_REQ:
		token = MIN2MS(1) / 3;
		break;
	case KADEMLIA2_PUBLISH_NOTES_REQ:
		token = MIN2MS(1) / 2;
		break;
	case KADEMLIA_FIREWALLED2_REQ:
		byOpcode = KADEMLIA_FIREWALLED_REQ;
	case KADEMLIA_FIREWALLED_REQ:
	case KADEMLIA_FINDBUDDY_REQ:
		token = MIN2MS(1) / 2;
		break;
	case KADEMLIA_CALLBACK_REQ:
		token = MIN2MS(1) / 1;
		break;
	case KADEMLIA2_PING:
		token = MIN2MS(1) / 2;
		break;
	// eSE 8.12.x — UDP reflector hardening (PUNTO 1.1).
	// Hole-punch REQ/ACK previously fell through to the default 'return 0',
	// bypassing the per-IP flood token-bucket entirely. A flood of 0x63 from a
	// real source made any patched node reflect a (possibly plaintext) ACK and
	// seed an expensive NAT expectation, with no rate cap. Give them the same
	// per-IP budget as FINDBUDDY/FIREWALLED (~2/min/IP): legitimate hole-punching
	// is rare (one exchange per stalled peer), so this is far above normal usage
	// but bounds a non-spoofed flood and reuses the existing ban path below.
	// NOTE: this per-IP bucket does NOT stop a SPOOFED-source flood (each forged
	// IP is "new"); closing that fully needs return-routability (cookie), now
	// wired via eSE::EseHolePunchCookie (Process_ESE_HOLEPUNCH_CHALLENGE).
	case KADEMLIA_ESE_HOLEPUNCH_REQ:
	case KADEMLIA_ESE_HOLEPUNCH_ACK:
	// 0x65 CHALLENGE shares the budget so an inbound challenge flood can't bypass
	// the per-IP choke (same ~2/min/IP + massive-flood ban path as REQ/ACK).
	case KADEMLIA_ESE_HOLEPUNCH_CHALLENGE:
	// Kad3 (IPv6) hole-punch band — same ~2/min/IP choke so it never silently falls
	// to 'return 0' once those handlers are wired. Punching is rare (one exchange per
	// stalled peer), so 2/min is far above normal usage but bounds a non-spoofed flood
	// and reuses the ban path below. (Cookie/proceed included: an inbound 0x6B/0x6C
	// flood can't bypass the choke either.)
	case KADEMLIA3_HOLEPUNCH_REQ:
	case KADEMLIA3_HOLEPUNCH_FWD:
	case KADEMLIA3_HOLEPUNCH_ACK:
	case KADEMLIA3_HOLEPUNCH_CHALLENGE:
	case KADEMLIA3_HOLEPUNCH_PROCEED:
		token = MIN2MS(1) / 2;
		break;
	// R.2 keepalive ping band. Unlike punching, these flow CONTINUOUSLY at the
	// keepalive cadence: one PING_REQ per supernode every 25s (= 2.4/min) plus the
	// matching PONG. That is ABOVE the 2/min punch budget, so once the InTrackList
	// lookup below is fixed (== -> !=) a shared 2/min bucket would throttle and then
	// ban a legitimate sustained keepalive after ~18 min. Give the ping band its own
	// ~8/min bucket: still a hard flood ceiling for a 16-byte packet, but comfortably
	// above the real cadence + jitter. (See KadKeepalive.cpp KEEPALIVE_PING_INTERVAL_MS;
	// a semantic "PING_RES only if it matches a pending ping" belongs in the keepalive
	// layer, not here.)
	case KADEMLIA3_PING_REQ:
	case KADEMLIA3_PING_RES:
		token = MIN2MS(1) / 8;
		break;
	default:
		// not a request packets, but a response - no further checks at this point
		return 0;
	}
	const DWORD curTick = ::GetTickCount();
	// time for cleaning up?
	// Unsigned subtraction is wrap-safe as long as the interval is < 2^31 ms.
	if (curTick - dwLastTrackInCleanup >= MIN2MS(12))
		InTrackListCleanup();

	const bool bEndpointScoped = IsEndpointScopedEseOpcode(byOpcode);
	if (bEndpointScoped) {
		// Keep a generous aggregate ceiling per public IP to stop source-port hopping,
		// but never ban a whole household/CGNAT address for one endpoint's behaviour.
		// 120/min/opcode supports many legitimate clients sharing one public address.
		const ULONGLONG uAggregateKey = (static_cast<ULONGLONG>(uIP) << 16);
		if (ChargeIncomingBucket(uAggregateKey, uIP, 0, byOpcode,
			MIN2MS(1) / 120, false, false) != 0)
			return 1;

		const ULONGLONG uEndpointKey = uAggregateKey | uUDPPort;
		return ChargeIncomingBucket(uEndpointKey, uIP, uUDPPort, byOpcode,
			token, false, true);
	}

	// Preserve the established stock behaviour for legacy Kad opcodes: a bucket
	// is shared by the public IP and massive floods may still trigger an IP ban.
	const ULONGLONG uLegacyKey = (static_cast<ULONGLONG>(uIP) << 16);
	return ChargeIncomingBucket(uLegacyKey, uIP, 0, byOpcode, token, true, false);
}

int CPacketTracking::ChargeIncomingBucket(ULONGLONG uTrackKey, uint32 uIP, uint16 uUDPPort,
	uint8 byOpcode, int token, bool bAllowIPBan, bool bExpireEndpointOnMassive)
{
	const DWORD curTick = ::GetTickCount();

	// check for existing entries
	TrackPacketsIn_Struct *pTrackEntry;
	if (!m_mapTrackPacketsIn.Lookup(uTrackKey, pTrackEntry)) {
		pTrackEntry = new TrackPacketsIn_Struct();
		pTrackEntry->m_uIP = uIP;
		pTrackEntry->m_uUDPPort = uUDPPort;
		pTrackEntry->m_dwLastActivity = curTick;
		m_mapTrackPacketsIn[uTrackKey] = pTrackEntry;
		m_liTrackPacketsIn.AddHead(pTrackEntry);
	}
	pTrackEntry->m_dwLastActivity = curTick;

	INT_PTR i = pTrackEntry->m_aTrackedRequests.GetCount();
	// Search backwards for THIS opcode's tracked entry: keep going while the opcode
	// does NOT match, stop on the first match (or i == -1 if none). The '==' here was a
	// long-standing fork regression (stock eMule uses a forward for-loop + break): it
	// stopped on the first NON-match, so it charged one opcode's tokens against another
	// entry and, for a repeated same-opcode flood, spawned a fresh duplicate entry every
	// packet — meaning the per-opcode limiter never accumulated and never actually fired.
	while (--i >= 0 && pTrackEntry->m_aTrackedRequests[i].m_byOpcode != byOpcode);

	if (i >= 0) {
		// already tracking requests with this opcode
		TrackPacketsIn_Struct::TrackedRequestIn_Struct &TrackedRequest = pTrackEntry->m_aTrackedRequests[i];
		const DWORD dwElapsed = curTick - TrackedRequest.m_dwLatest;
		if (dwElapsed >= (DWORD)MIN2MS(1))
			TrackedRequest.m_tokens = MIN2MS(1);
		else {
			TrackedRequest.m_tokens += (int)dwElapsed;
			if (TrackedRequest.m_tokens > MIN2MS(1))
				TrackedRequest.m_tokens = MIN2MS(1);
		}
		TrackedRequest.m_tokens -= token;
		TrackedRequest.m_dwLatest = curTick;

		if (CKademlia::IsRunningInLANMode() && IsLANIP(ntohl(uIP))) // no flood detection in LanMode
			return 0;

		// now the actual check if this request is allowed
		if (TrackedRequest.m_tokens < 0) {
			if (TrackedRequest.m_tokens < MIN2MS(-3)) {
				if (bAllowIPBan) {
					DebugLogWarning(_T("Kad: Massive request flood detected for opcode 0x%X from IP %s - Banning IP"), byOpcode, (LPCTSTR)ipstr(htonl(uIP)));
					theApp.clientlist->AddBannedClient(ntohl(uIP));
					return 2;
				}
				DebugLogWarning(_T("Kad: Massive endpoint flood detected for opcode 0x%X from %s:%u - dropping endpoint traffic"),
					byOpcode, (LPCTSTR)ipstr(htonl(uIP)), (unsigned)uUDPPort);
				return bExpireEndpointOnMassive ? 2 : 1;
			}
			// over the limit, drop the packet but do nothing else
			if (!TrackedRequest.m_bDbgLogged) {
				TrackedRequest.m_bDbgLogged = true;
				if (uUDPPort != 0)
					DebugLog(_T("Kad: Request flood detected for opcode 0x%X from %s:%u - Dropping endpoint packets"),
						byOpcode, (LPCTSTR)ipstr(htonl(uIP)), (unsigned)uUDPPort);
				else
					DebugLog(_T("Kad: Request flood detected for opcode 0x%X from IP %s - Dropping packets"),
						byOpcode, (LPCTSTR)ipstr(htonl(uIP)));
			}
			return 1; // drop the packet
		}
		TrackedRequest.m_bDbgLogged = false;
	} else {
		// add a new entry for this request
		TrackPacketsIn_Struct::TrackedRequestIn_Struct TrackedRequest =	{ curTick, MIN2MS(1) - token, byOpcode, false };
		pTrackEntry->m_aTrackedRequests.Add(TrackedRequest);
	}
	return 0;
}

void CPacketTracking::InTrackListCleanup()
{
	const DWORD curTick = ::GetTickCount();
	const INT_PTR dbgOldSize = m_liTrackPacketsIn.GetCount();
	dwLastTrackInCleanup = curTick;
	for (POSITION pos = m_liTrackPacketsIn.GetHeadPosition(); pos != NULL;) {
		POSITION pos2 = pos;
		const TrackPacketsIn_Struct *curEntry = m_liTrackPacketsIn.GetNext(pos);
		if (curTick - curEntry->m_dwLastActivity >= MIN2MS(12)) {
			const ULONGLONG uTrackKey = (static_cast<ULONGLONG>(curEntry->m_uIP) << 16) | curEntry->m_uUDPPort;
			VERIFY(m_mapTrackPacketsIn.RemoveKey(uTrackKey));
			m_liTrackPacketsIn.RemoveAt(pos2);
			delete curEntry;
		}
	}
	DebugLog(_T("Cleaned up Kad Incoming Requests Tracklist, entries before: %u, after %u"), (uint32)dbgOldSize, (uint32)m_liTrackPacketsIn.GetCount());
}

void CPacketTracking::AddLegacyChallenge(const CUInt128 &uContactID, const CUInt128 &uChallengeID, uint32 uIP, uint8 byOpcode)
{
	const DWORD curTick = ::GetTickCount();
	listChallengeRequests.AddHead(TrackChallenge_Struct{ curTick, uIP, uContactID, uChallengeID, byOpcode });
	while (!listChallengeRequests.IsEmpty() && curTick >= listChallengeRequests.GetTail().dwInserted + SEC2MS(180)) {
		DEBUG_ONLY(DebugLog(_T("Challenge timed out, client not verified - %s"), (LPCTSTR)ipstr(htonl(listChallengeRequests.GetTail().uIP))));
		listChallengeRequests.RemoveTail();
	}
}

bool CPacketTracking::IsLegacyChallenge(const CUInt128 &uChallengeID, uint32 uIP, uint8 byOpcode, CUInt128 &ruContactID)
{
	bool bDbgWarning = false;
	const DWORD curTick = ::GetTickCount();
	for (POSITION pos = listChallengeRequests.GetHeadPosition(); pos != NULL;) {
		POSITION pos2 = pos;
		const TrackChallenge_Struct &tc = listChallengeRequests.GetNext(pos);
		if (curTick >= tc.dwInserted + SEC2MS(180))
			break;
		if (tc.uIP == uIP && tc.byOpcode == byOpcode) {
			ASSERT(tc.uChallenge != 0 || byOpcode == KADEMLIA2_PING);
			if (tc.uChallenge == 0 || tc.uChallenge == uChallengeID) {
				ruContactID = tc.uContactID;
				listChallengeRequests.RemoveAt(pos2);
				return true;
			}
			bDbgWarning = true;
		}
	}
	if (bDbgWarning)
		DebugLogWarning(_T("Kad: IsLegacyChallenge: Wrong challenge answer received, client not verified (%s)"), (LPCTSTR)ipstr(htonl(uIP)));
	return false;
}

bool CPacketTracking::HasActiveLegacyChallenge(uint32 uIP) const
{
	const DWORD curTick = ::GetTickCount();
	for (POSITION pos = listChallengeRequests.GetHeadPosition(); pos != NULL;) {
		const TrackChallenge_Struct &tcstruct = listChallengeRequests.GetNext(pos);
		if (curTick >= tcstruct.dwInserted + SEC2MS(180))
			break;
		if (tcstruct.uIP == uIP)
			return true;
	}
	return false;
}
