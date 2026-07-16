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
#include "kademlia/kademlia/Tag.h"

class CKnownFile;
class CSafeMemFile;
struct SSearchTerm;

namespace Kademlia
{
	class CByteIO;
	class CKadClientSearcher;
	class CLookupHistory;

	class CSearch
	{
		friend class CSearchManager;
	public:
		uint32	GetSearchID() const									{ return m_uSearchID; }
		uint32	GetSearchType() const								{ return m_uType; }
		void	SetSearchType(uint32 uVal);
		void	SetTargetID(const CUInt128 &uVal)					{ m_uTarget = uVal; }
		const CUInt128& GetTarget() const							{ return m_uTarget; }
		uint32	GetAnswers() const;
		uint32	GetKadPacketSent() const							{ return m_uKadPacketSent; }
		uint32	GetRequestAnswer() const							{ return m_uTotalRequestAnswers; }
		uint32	GetNodeLoad() const;
		uint32	GetNodeLoadResponse() const							{ return m_uTotalLoadResponses; }
		uint32	GetNodeLoadTotal() const							{ return m_uTotalLoad; }
		const CStringW& GetGUIName() const;
		void	SetGUIName(LPCWSTR sGUIName);
		void	SetSearchTermData(uint32 uSearchTermDataSize, LPBYTE pucSearchTermsData);
		// altIP (NAT-reach 2026-06): optional overlay IPv4 (TAG_ESE_LIVE_ALTIP,
		// e.g. Tailscale 100.64/10) published alongside the public IP so
		// viewers behind the same overlay can dial an endpoint NAT can't block.
		// 0 = don't publish the tag.
		void	SetLiveStreamPublish(const uchar *streamKey, LPCWSTR title, LPCWSTR category,
					LPCWSTR language, uint32 bitrate, uint32 viewerCount,
					uint32 startedAt, uint16 broadcasterPort, uint32 altIP = 0);
		// H8 — marks this publish as targeting the eSE-dedicated keyword
		// namespace (MD4("\x00eSE\x00" || utf8(kw))). When set,
		// PrepareLivePacketForTags omits TAG_FILENAME and TAG_FILETYPE
		// to deny eSE-aware crawlers a human-readable title from the Kad
		// entry. Default false (legacy / namespace-shared publish keeps
		// those tags for back-compat with 0.70b parsers).
		void	SetLivePublishCleanNs(bool bClean)						{ m_bLivePublishCleanNs = bClean; }
		bool	IsLivePublishCleanNs() const							{ return m_bLivePublishCleanNs; }
		void	SetK6ShadowSource(uint64 publishLeaseId, uint64 fileSize,
							 const uchar compatUserHash[16], uint16 tcpPort, uint16 udpPort);
		bool	IsK6ShadowSource() const							{ return m_bK6ShadowSource; }
		uint64	GetK6PublishLeaseId() const						{ return m_uK6PublishLeaseId; }
		void	SetK6VisibilityProbe(uint64 publishLeaseId,
							 const uchar compatUserHash[16], uint32 ip,
							 uint16 tcpPort, uint16 udpPort);
		// K6-4 source-hash lookup executed by an exit. Results are returned to
		// the exact tunnel request instead of entering the exit's download queue.
		void	SetK6GatewaySourceLookup(uint32 circuitId, uint32 requestId);
		static CString GetTypeName(uint32 uType);

		void	AddFileID(const CUInt128 &uID);
		static void	PreparePacketForTags(CByteIO *byIO, CKnownFile *pFile, uint8 byTargetKadVersion);
		bool	Stoping() const										{ return m_bStoping; }
		void	UpdateNodeLoad(uint8 uLoad);

		CKadClientSearcher*	GetNodeSpecialSearchRequester() const	{ return pNodeSpecialSearchRequester; }
		void	SetNodeSpecialSearchRequester(CKadClientSearcher *pNew)	{ pNodeSpecialSearchRequester = pNew; }

		CLookupHistory* GetLookupHistory() const					{ return m_pLookupHistory; }
		enum
		{
			NODE,
			NODECOMPLETE,
			FILE,
			KEYWORD,
			NOTES,
			STOREFILE,
			STOREKEYWORD,
			STORENOTES,
			FINDBUDDY,
			FINDSOURCE,
			NODESPECIAL, // node search request from requester "outside" of kad to find the IP of a given nodeid
			NODEFWCHECKUDP // find new unknown IPs for a UDP firewall check
		};

		CSearch();
		~CSearch();
		CSearch(const CSearch&) = delete;
		CSearch& operator=(const CSearch&) = delete;

	private:
		void Go();
		void ProcessResponse(uint32 uFromIP, uint16 uFromPort, const ContactArray &rlistResults);
		void ProcessResult(const CUInt128 &uAnswer, TagList &rlistInfo, uint32 uFromIP, uint16 uFromPort);
		void ProcessResultFile(const CUInt128 &uAnswer, TagList &rlistInfo);
		void ProcessResultKeyword(const CUInt128 &uAnswer, TagList &rlistInfo, uint32 uFromIP, uint16 uFromPort);
		void ProcessResultNotes(const CUInt128 &uAnswer, TagList &rlistInfo);
		void JumpStart();
		void SendFindValue(CContact *pContact, bool bReAskMore = false);
		void PrepareToStop();
		void StorePacket();
		void PrepareLivePacketForTags(CByteIO *byIO) const;
		uint8 GetRequestContactCount() const;

		WordList m_listWords;
		UIntList m_listFileIDs;
		std::map<Kademlia::CUInt128, bool> m_mapResponded;
		ContactMap m_mapPossible;
		ContactMap m_mapTried;
		// eSE: GetTickCount stamp of the last KADEMLIA2_REQ sent to each contact,
		// keyed by IP (same key CFastKad uses), so ProcessResponse can feed the
		// real round-trip time to the FastKad adaptive-timeout estimator.
		std::map<uint32, DWORD> m_mapEseReqSendTick;
		ContactMap m_mapBest;
		ContactMap m_mapInUse;
		ContactArray m_listDelete;
		CUInt128 m_uTarget;
		CUInt128 m_uClosestDistantFound; // not used for the search itself, but for statistical data collecting
		CUInt128 m_uLiveStreamID;
		CStringW m_strLiveTitle;
		CStringW m_strLiveCategory;
		CStringW m_strLiveLanguage;
		SSearchTerm *m_pSearchTerm; // cached from m_pucSearchTermsData, used for verifying results later on
		CKadClientSearcher *pNodeSpecialSearchRequester; // used to callback on result for NODESPECIAL searches
		CLookupHistory *m_pLookupHistory;
		CContact *pRequestedMoreNodesContact;
		LPBYTE m_pucSearchTermsData;
		time_t m_uLastResponse;
		time_t m_tCreated;
		uint32 m_uType;
		uint32 m_uAnswers;
		uint32 m_uTotalRequestAnswers;
		uint32 m_uKadPacketSent; //Used for GUI, but might not be needed later.
		uint32 m_uTotalLoad;
		uint32 m_uTotalLoadResponses;
		uint32 m_uSearchID;
		uint32 m_uSearchTermsDataSize;
		uint32 m_uLiveBitrate;
		uint32 m_uLiveViewerCount;
		uint32 m_uLiveStartedAt;
		uint32 m_uLiveAltIP;          // NAT-reach: overlay IPv4 for TAG_ESE_LIVE_ALTIP (0 = omit)
		uint16 m_uLiveBroadcasterPort;
		uint64 m_uK6PublishLeaseId;
		uint64 m_uK6ShadowFileSize;
		CUInt128 m_uK6CompatUserHash;
		uint16 m_uK6ShadowTcpPort;
		uint16 m_uK6ShadowUdpPort;
		uint32 m_uK6VisibilityIP;
		uint32 m_uK6GatewayCircuitId;
		uint32 m_uK6GatewayRequestId;
		bool m_bStoping;
		bool m_bLiveStreamPublish;
		bool m_bK6ShadowSource;
		bool m_bK6VisibilityProbe;
		bool m_bK6GatewaySourceLookup;
		bool m_bLivePublishCleanNs;   // H8 — see SetLivePublishCleanNs
	};
}

void KadGetKeywordHash(const Kademlia::CKadTagValueString &rstrKeywordW, Kademlia::CUInt128 *puKadID);
void KadGetKeywordHash(const CStringA &rstrKeywordA, Kademlia::CUInt128 *puKadID);
CStringA KadGetKeywordBytes(const Kademlia::CKadTagValueString &rstrKeywordW);

// eSE Live — dedicated keyword-hash namespace for live streams.
//
// Rationale: KadGetKeywordHash(kw) = MD4(utf8(kw)) lives in the SAME DHT
// region that any legacy 0.70b client reaches when typing the keyword in
// search. That means our live publishes share the index nodes with every
// regular search, which (a) leaks broadcaster presence to legacy clients
// that have no business knowing, and (b) lets a hostile legacy node fill
// the bucket with garbage that pushes our live entries out.
//
// EseLiveGetKeywordHash(kw) = MD4(prefix || utf8(kw)) where prefix is a
// 5-byte sentinel containing NUL bytes — impossible to produce through
// the keyboard. Therefore:
//   - Two eSE clients hashing the same keyword land on the same Kad
//     node deterministically (discovery works).
//   - No legacy client typing the keyword can ever reach that node
//     (isolation works).
//
// Compatibility constraint (project_backward_compat memory): we cannot
// break interop with 0.70b upstream or earlier forks that publish under
// the legacy hash. Hence: publish under BOTH namespaces during the
// transition, search BOTH, and gate the legacy half behind a pref so a
// future release can flip the default off without touching code.
//
// Same MD4 cost, same wire format, same opcodes — only the input bytes
// to the hash change. From any non-eSE node's perspective this is an
// ordinary STOREKEYWORD with an unfamiliar target hash; nothing else
// to interpret.
#define ESE_LIVE_KEYWORD_PREFIX      "\x00""eSE""\x00"
#define ESE_LIVE_KEYWORD_PREFIX_LEN  5

void EseLiveGetKeywordHash(const Kademlia::CKadTagValueString &rstrKeywordW, Kademlia::CUInt128 *puKadID);
void EseLiveGetKeywordHash(const CStringA &rstrKeywordA, Kademlia::CUInt128 *puKadID);
