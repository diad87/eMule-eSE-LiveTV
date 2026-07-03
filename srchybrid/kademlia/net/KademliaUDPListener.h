/*
Copyright (C)2003 Barry Dunne (https://www.emule-project.net)

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

#pragma once
#include "kademlia/routing/Maps.h"
#include "kademlia/net/PacketTracking.h"

class CSafeMemFile;
struct SSearchTerm;

namespace Kademlia
{
	class CKadUDPKey;
	class CKadClientSearcher;

	struct FetchNodeID_Struct
	{
		uint32 dwIP;
		uint32 dwTCPPort;
		uint32 dwExpire;
		CKadClientSearcher *pRequester;
	};

	class CKademliaUDPListener : public CPacketTracking
	{
		friend class CSearch;
	public:
		~CKademliaUDPListener();
		void Bootstrap(LPCTSTR szHost, uint16 uUDPPort);
		void Bootstrap(uint32 uIP, uint16 uUDPPort, uint8 byKadVersion = 0, const CUInt128 *uCryptTargetID = NULL);
		void FirewalledCheck(uint32 uIP, uint16 uUDPPort, const CKadUDPKey &senderUDPKey, uint8 byKadVersion);
		void SendMyDetails(byte byOpcode, uint32 uIP, uint16 uUDPPort, uint8 byKadVersion, const CKadUDPKey &targetUDPKey, const CUInt128 *uCryptTargetID, bool bRequestAckPackage);
		void SendPublishSourcePacket(CContact *pContact, const CUInt128 &uTargetID, const CUInt128 &uContactID, const TagList &tags);
		void SendNullPacket(byte byOpcode, uint32 uIP, uint16 uUDPPort, const CKadUDPKey &targetUDPKey, const CUInt128 *uCryptTargetID);
		virtual void ProcessPacket(const byte *pbyData, uint32 uLenData, uint32 uIP, uint16 uUDPPort, bool bValidReceiverKey, const CKadUDPKey &senderUDPKey);
		void SendPacket(const byte *pbyData, uint32 uLenData, uint32 uDestinationHost, uint16 uDestinationPort, const CKadUDPKey &targetUDPKey, const CUInt128 *uCryptTargetID);
		void SendPacket(const byte *pbyData, uint32 uLenData, byte byOpcode, uint32 uDestinationHost, uint16 uDestinationPort, const CKadUDPKey &targetUDPKey, const CUInt128 *uCryptTargetID);
		void SendPacket(CSafeMemFile &pbyData, byte byOpcode, uint32 uDestinationHost, uint16 uDestinationPort, const CKadUDPKey &targetUDPKey, const CUInt128 *uCryptTargetID);

		bool FindNodeIDByIP(CKadClientSearcher *pRequester, uint32 dwIP, uint16 nTCPPort, uint16 nUDPPort);
		void ExpireClientSearch(const CKadClientSearcher *pExpireImmediately = NULL);

		// eSE: Initiate a uTP hole-punch by sending HOLEPUNCH_REQ to a remote peer.
		// uIP = host-order (Kad convention), uUDPPort = host-order.
		void SendEseHolePunchReq(uint32 uIP, uint16 uUDPPort);
		// [eSE v9] anti-CGNAT: fire the REQ at a small window of ports around uBasePort
		// (birthday spray) so a symmetric NAT's per-destination external port can be hit.
		// uSpread==0 => single-shot (exact SendEseHolePunchReq behavior). Clamped internally.
		void SendEseHolePunchReqSpray(uint32 uIP, uint16 uBasePort, uint16 uSpread);
		// R.1 (3-way rendezvous) outbound primitives — IPv4 wire, kill-switch gated.
		// The CALLER gates on the peer advertising ESE_CAP_HOLEPUNCH_RDV (bit 15).
		void SendKad3HolepunchReq(uint32 uRdvIP, uint16 uRdvPort, uint32 uNonce, uint32 uTargetIP, uint16 uTargetPort, const uint8 *pbyCookie = NULL);
		void SendKad3HolepunchChallenge(uint32 uIP, uint16 uUDPPort, uint32 uNonce, const uint8 *pbyCookie);
		void SendKad3HolepunchFwd(uint32 uIP_B, uint16 uPort_B, uint32 uNonce, uint32 uOriginIP, uint16 uOriginPort);
		void SendKad3HolepunchProceed(uint32 uIP_A, uint16 uPort_A, uint32 uNonce);
		// R.1 A-side initiator: begin a 3-way rendezvous to reach (uTargetIP) via R.
		void InitiateKad3Rendezvous(uint32 uRdvIP, uint16 uRdvPort, uint32 uTargetIP, uint16 uTargetPort);
		// R.2 keepalive: minimal KADEMLIA3_PING_REQ to a supernode (holds NAT conntrack open).
		void SendKad3PingReq(uint32 uIP, uint16 uUDPPort);
		// R.2 keepalive: reply a KADEMLIA3_PING_RES (PONG) to a peer that pinged us.
		void SendKad3PingRes(uint32 uIP, uint16 uUDPPort);
	private:
		bool AddContact_KADEMLIA2(const byte *pbyData, uint32 uLenData, uint32 uIP, uint16 &uUDPPort, uint8 *pnOutVersion, const CKadUDPKey &cUDPKey, bool &rbIPVerified, bool bUpdate, bool bFromHelloReq, bool *pbOutRequestsACK, CUInt128 *puOutContactID);
		void SendLegacyChallenge(uint32 uIP, uint16 uUDPPort, const CUInt128 &uContactID);
		static SSearchTerm* CreateSearchExpressionTree(CSafeMemFile &fileIO, int iLevel);
		static void Free(SSearchTerm *pSearchTerms);
		void Process_KADEMLIA2_BOOTSTRAP_REQ(uint32 uIP, uint16 uUDPPort, const CKadUDPKey &senderUDPKey);
		void Process_KADEMLIA2_BOOTSTRAP_RES(const byte *pbyPacketData, uint32 uLenPacket, uint32 uIP, uint16 uUDPPort, const CKadUDPKey &senderUDPKey, bool bValidReceiverKey);
		void Process_KADEMLIA2_HELLO_REQ(const byte *pbyPacketData, uint32 uLenPacket, uint32 uIP, uint16 uUDPPort, const CKadUDPKey &senderUDPKey, bool bValidReceiverKey);
		void Process_KADEMLIA2_HELLO_RES(const byte *pbyPacketData, uint32 uLenPacket, uint32 uIP, uint16 uUDPPort, const CKadUDPKey &senderUDPKey, bool bValidReceiverKey);
		void Process_KADEMLIA2_HELLO_RES_ACK(const byte *pbyPacketData, uint32 uLenPacket, uint32 uIP, bool bValidReceiverKey);
		void Process_KADEMLIA2_REQ(const byte *pbyPacketData, uint32 uLenPacket, uint32 uIP, uint16 uUDPPort, const CKadUDPKey &senderUDPKey);
		void Process_KADEMLIA2_RES(const byte *pbyPacketData, uint32 uLenPacket, uint32 uIP, uint16 uUDPPort, const CKadUDPKey &senderUDPKey);
		static void Process_KADEMLIA2_SEARCH_KEY_REQ(const byte *pbyPacketData, uint32 uLenPacket, uint32 uIP, uint16 uUDPPort, const CKadUDPKey &senderUDPKey);
		static void Process_KADEMLIA2_SEARCH_SOURCE_REQ(const byte *pbyPacketData, uint32 uLenPacket, uint32 uIP, uint16 uUDPPort, const CKadUDPKey &senderUDPKey);
		static void Process_KADEMLIA_SEARCH_RES(const byte *pbyPacketData, uint32 uLenPacket, uint32 uIP, uint16 uUDPPort);
		static void Process_KADEMLIA2_SEARCH_RES(const byte *pbyPacketData, uint32 uLenPacket, const CKadUDPKey &senderUDPKey, uint32 uIP, uint16 uUDPPort);
		void Process_KADEMLIA2_PUBLISH_KEY_REQ(const byte *pbyPacketData, uint32 uLenPacket, uint32 uIP, uint16 uUDPPort, const CKadUDPKey &senderUDPKey);
		void Process_KADEMLIA2_PUBLISH_SOURCE_REQ(const byte *pbyPacketData, uint32 uLenPacket, uint32 uIP, uint16 uUDPPort, const CKadUDPKey &senderUDPKey);
		void Process_KADEMLIA_PUBLISH_RES(const byte *pbyPacketData, uint32 uLenPacket, uint32 uIP);
		void Process_KADEMLIA2_PUBLISH_RES(const byte *pbyPacketData, uint32 uLenPacket, uint32 uIP, uint16 uUDPPort, const CKadUDPKey &senderUDPKey);
		static void Process_KADEMLIA2_SEARCH_NOTES_REQ(const byte *pbyPacketData, uint32 uLenPacket, uint32 uIP, uint16 uUDPPort, const CKadUDPKey &senderUDPKey);
		void Process_KADEMLIA_SEARCH_NOTES_RES(const byte *pbyPacketData, uint32 uLenPacket, uint32 uIP, uint16 uUDPPort);
		void Process_KADEMLIA2_PUBLISH_NOTES_REQ(const byte *pbyPacketData, uint32 uLenPacket, uint32 uIP, uint16 uUDPPort, const CKadUDPKey &senderUDPKey);
		void Process_KADEMLIA_FIREWALLED_REQ(const byte *pbyPacketData, uint32 uLenPacket, uint32 uIP, uint16 uUDPPort, const CKadUDPKey &senderUDPKey);
		void Process_KADEMLIA_FIREWALLED2_REQ(const byte *pbyPacketData, uint32 uLenPacket, uint32 uIP, uint16 uUDPPort, const CKadUDPKey &senderUDPKey);
		static void Process_KADEMLIA_FIREWALLED_RES(const byte *pbyPacketData, uint32 uLenPacket, uint32 uIP, const CKadUDPKey &senderUDPKey);
		static void Process_KADEMLIA_FIREWALLED_ACK_RES(uint32 uLenPacket);
		void Process_KADEMLIA_FINDBUDDY_REQ(const byte *pbyPacketData, uint32 uLenPacket, uint32 uIP, uint16 uUDPPort, const CKadUDPKey &senderUDPKey);
		void Process_KADEMLIA_FINDBUDDY_RES(const byte *pbyPacketData, uint32 uLenPacket, uint32 uIP, uint16 uUDPPort, const CKadUDPKey &senderUDPKey);
		static void Process_KADEMLIA_CALLBACK_REQ(const byte *pbyPacketData, uint32 uLenPacket, uint32 uIP, const CKadUDPKey &senderUDPKey);
		void Process_KADEMLIA2_PING(uint32 uIP, uint16 uUDPPort, const CKadUDPKey &senderUDPKey);
		void Process_KADEMLIA2_PONG(const byte *pbyPacketData, uint32 uLenPacket, uint32 uIP, uint16 uUDPPort, const CKadUDPKey &senderUDPKey);
		static void Process_KADEMLIA2_FIREWALLUDP(const byte *pbyPacketData, uint32 uLenPacket, uint32 uIP, const CKadUDPKey &senderUDPKey);

		// eSE Fase 3: uTP Hole Punching
		void Process_ESE_HOLEPUNCH_REQ(const byte *pbyPacketData, uint32 uLenPacket, uint32 uIP, uint16 uUDPPort, const CKadUDPKey &senderUDPKey);
		void Process_ESE_HOLEPUNCH_ACK(const byte *pbyPacketData, uint32 uLenPacket, uint32 uIP, uint16 uUDPPort, const CKadUDPKey &senderUDPKey);
		// eSE P0: return-routability cookie handshake (anti-reflection hardening).
		void Process_ESE_HOLEPUNCH_CHALLENGE(const byte *pbyPacketData, uint32 uLenPacket, uint32 uIP, uint16 uUDPPort, const CKadUDPKey &senderUDPKey);
		void SendEseHolePunchChallenge(uint32 uIP, uint16 uUDPPort, uint32 uNonce, const uint8 *pbyCookie, const CKadUDPKey &senderUDPKey);
		void SendEseHolePunchReqWithCookie(uint32 uIP, uint16 uUDPPort, uint32 uNonce, const uint8 *pbyCookie);
		// R.1: encryption-tiered Kad3 send helper (contact key if known, else plaintext).
		void SendKad3HolepunchPacket(CSafeMemFile &fileIO, byte byOpcode, uint32 uIP, uint16 uUDPPort);
		// R.1: 3-way rendezvous receive handlers. R/B are stateless; A keeps the
		// pending table (Kad3*Rdv* in the .cpp). Hole confirmation reuses 2-way 0x63/0x64.
		void Process_KADEMLIA3_HOLEPUNCH_REQ(const byte *pbyPacketData, uint32 uLenPacket, uint32 uIP, uint16 uUDPPort, const CKadUDPKey &senderUDPKey);
		void Process_KADEMLIA3_HOLEPUNCH_FWD(const byte *pbyPacketData, uint32 uLenPacket, uint32 uIP, uint16 uUDPPort, const CKadUDPKey &senderUDPKey);
		void Process_KADEMLIA3_HOLEPUNCH_CHALLENGE(const byte *pbyPacketData, uint32 uLenPacket, uint32 uIP, uint16 uUDPPort, const CKadUDPKey &senderUDPKey);
		void Process_KADEMLIA3_HOLEPUNCH_PROCEED(const byte *pbyPacketData, uint32 uLenPacket, uint32 uIP, uint16 uUDPPort, const CKadUDPKey &senderUDPKey);
		// R.2 keepalive PING/PONG: an inbound ping is answered with a PONG; an inbound
		// PONG refreshes the supernode health in CKadKeepalive (out of the GENERIC drop).
		void Process_KADEMLIA3_PING_REQ(const byte *pbyPacketData, uint32 uLenPacket, uint32 uIP, uint16 uUDPPort, const CKadUDPKey &senderUDPKey);
		void Process_KADEMLIA3_PING_RES(const byte *pbyPacketData, uint32 uLenPacket, uint32 uIP, uint16 uUDPPort, const CKadUDPKey &senderUDPKey);

		// v0.71 IPv6 Sprint 4 — Kad3 (v6-aware) opcode handlers.
		// Currently shallow: parse just enough to consume the bytes, log
		// the contact, and drop the packet. Adding the contact to the v4
		// routing zone would corrupt its v4 view; a real v6 routing zone
		// is a larger subsystem that ships in a follow-up sprint. Wire is
		// reserved, dispatch is non-crashing, upstream 0.70b doesn't know
		// these opcodes so packets never reach unsuspecting upstream nodes
		// (we never send 0x12..0x65 in this band unless we know the peer
		// advertises CAP_FORK_IPV6_WIRE).
		static void Process_KADEMLIA3_GENERIC(const char *szOpcodeName,
			const byte *pbyPacketData, uint32 uLenPacket,
			uint32 uIP, uint16 uUDPPort);

		CList<FetchNodeID_Struct> listFetchNodeIDRequests;
		//uint32	m_nOpenHellos;
		//uint32	m_nFirewalledHellos;
	};
}