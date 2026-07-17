/*
Copyright (C)2003 Barry Dunne (https://www.emule-project.net)
Copyright (C)2004-2024 Merkur ( strEmail.Format("%s@%s", "devteam", "emule-project.net") / https://www.emule-project.net )

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
#include "ClientList.h"
#include "DownloadQueue.h"
#include "emule.h"
#include "emuledlg.h"
#include "kademliawnd.h"
#include "KadSearchListCtrl.h"
#include "Log.h"
#include "Packets.h"
#include "partfile.h"
#include "SearchList.h"
#include "sharedfilelist.h"
#include "UpDownClient.h"
#include "KnownFileList.h"
#include "kademlia/io/ByteIO.h"
#include "kademlia/io/IOException.h"
#include "kademlia/kademlia/Defines.h"
#include "kademlia/kademlia/Entry.h"
#include "kademlia/kademlia/Indexed.h"
#include "kademlia/kademlia/Kademlia.h"
#include "kademlia/kademlia/Prefs.h"
#include "kademlia/kademlia/Search.h"
#include "kademlia/kademlia/SearchManager.h"
#include "kademlia/kademlia/UDPFirewallTester.h"
#include "kademlia/net/KademliaUDPListener.h"
#include "kademlia/routing/RoutingZone.h"
#include "kademlia/utils/KadClientSearcher.h"
#include "kademlia/utils/LookupHistory.h"
#include "LiveStreamManager.h"
#include "LiveTunnel.h"
#include "eMuleAI/FastKad.h" // eSE: Adaptive Kad response time estimation
#include "eMuleAI/Address.h"
#include "FirewallProberV6.h"
#include "ReachabilityWire.h"
#include "ClientUDPSocket.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

using namespace Kademlia;

//void DebugSend(LPCTSTR pszMsg, uint32 uIP, uint16 uUDPPort);

static CStringW EseLiveKeyToHexW(const uchar* key)
{
	CStringW out;
	for (int i = 0; i < 16; ++i)
		out.AppendFormat(L"%02X", key[i]);
	return out;
}

static int EseLiveHexNibble(wchar_t c)
{
	if (c >= L'0' && c <= L'9')
		return c - L'0';
	if (c >= L'a' && c <= L'f')
		return 10 + c - L'a';
	if (c >= L'A' && c <= L'F')
		return 10 + c - L'A';
	return -1;
}

static bool EseLiveHexToKey(const CStringW& hex, uchar* key)
{
	if (hex.GetLength() != 32 || key == NULL)
		return false;
	for (int i = 0; i < 16; ++i) {
		int hi = EseLiveHexNibble(hex[i * 2]);
		int lo = EseLiveHexNibble(hex[i * 2 + 1]);
		if (hi < 0 || lo < 0)
			return false;
		key[i] = (uchar)((hi << 4) | lo);
	}
	return true;
}

CSearch::CSearch()
	: m_uTarget()
	, m_uClosestDistantFound()
	, m_uLiveStreamID()
	, m_pSearchTerm()
	, pNodeSpecialSearchRequester()
	, pRequestedMoreNodesContact()
	, m_pucSearchTermsData()
	, m_uLastResponse(time(NULL))
	, m_tCreated(m_uLastResponse)
	, m_uType(_UI32_MAX)
	, m_uAnswers()
	, m_uTotalRequestAnswers()
	, m_uKadPacketSent()
	, m_uTotalLoad()
	, m_uTotalLoadResponses()
	, m_uSearchID(_UI32_MAX)
	, m_uSearchTermsDataSize()
	, m_uLiveBitrate()
	, m_uLiveViewerCount()
	, m_uLiveStartedAt()
	, m_uLiveAltIP()
	, m_uLiveBroadcasterPort()
	, m_uK6PublishLeaseId()
	, m_uK6ShadowFileSize()
	, m_uK6CompatUserHash()
	, m_uK6ShadowTcpPort()
	, m_uK6ShadowUdpPort()
	, m_uK6VisibilityIP()
	, m_uK6GatewayCircuitId()
	, m_uK6GatewayRequestId()
	, m_bStoping()
	, m_bLiveStreamPublish()
	, m_bK6ShadowSource(false)
	, m_bK6VisibilityProbe(false)
	, m_bK6GatewaySourceLookup(false)
	, m_bLivePublishCleanNs(false)   // H8 — opt-in for clean-namespace publishes
{
	m_pLookupHistory = new CLookupHistory();
	theApp.emuledlg->kademliawnd->searchList->SearchAdd(this);
}

void CSearch::SetK6ShadowSource(uint64 publishLeaseId, uint64 fileSize,
	const uchar compatUserHash[16], uint16 tcpPort, uint16 udpPort)
{
	m_uK6PublishLeaseId = publishLeaseId;
	m_uK6ShadowFileSize = fileSize;
	if (compatUserHash != NULL)
	m_uK6CompatUserHash = CUInt128(compatUserHash);
	m_uK6ShadowTcpPort = tcpPort;
	m_uK6ShadowUdpPort = udpPort;
	m_bK6ShadowSource = publishLeaseId != 0 && fileSize != 0 &&
		compatUserHash != NULL && tcpPort != 0;
}

void CSearch::SetK6VisibilityProbe(uint64 publishLeaseId,
	const uchar compatUserHash[16], uint32 ip, uint16 tcpPort, uint16 udpPort)
{
	m_uK6PublishLeaseId = publishLeaseId;
	if (compatUserHash != NULL)
		m_uK6CompatUserHash = CUInt128(compatUserHash);
	m_uK6VisibilityIP = ip;
	m_uK6ShadowTcpPort = tcpPort;
	m_uK6ShadowUdpPort = udpPort;
	m_bK6VisibilityProbe = publishLeaseId != 0 && compatUserHash != NULL &&
		ip != 0 && tcpPort != 0;
}

void CSearch::SetK6GatewaySourceLookup(uint32 circuitId, uint32 requestId)
{
	m_uK6GatewayCircuitId = circuitId;
	m_uK6GatewayRequestId = requestId;
	m_bK6GatewaySourceLookup = circuitId != 0 && requestId != 0 && m_uType == FILE;
}

CSearch::~CSearch()
{
	// remember the closest node we found and tried to contact (if any) during this search
	// for statistical calculations, but only if it's a certain type
	switch (m_uType) {
	case NODECOMPLETE:
	case FILE:
	case KEYWORD:
	case NOTES:
	case STOREFILE:
	case STOREKEYWORD:
	case STORENOTES:
	case FINDSOURCE: // maybe also exclude
		if (m_uClosestDistantFound != 0)
			CKademlia::StatsAddClosestDistance(m_uClosestDistantFound);
	default: // NODE, NODESPECIAL, NODEFWCHECKUDP, FINDBUDDY
		break;
	}

	if (pNodeSpecialSearchRequester != NULL) {
		// inform requester that our search failed
		pNodeSpecialSearchRequester->KadSearchIPByNodeIDResult(KCSR_NOTFOUND, 0, 0);
		pNodeSpecialSearchRequester = NULL;
	}

	// Remove search from GUI
	theApp.emuledlg->kademliawnd->searchList->SearchRem(this);

	// delete and dereference search history (will delete itself if not used by the GUI)
	if (m_pLookupHistory != NULL) {
		m_pLookupHistory->SetSearchDeleted();
		m_pLookupHistory = NULL;
	}
	theApp.emuledlg->kademliawnd->UpdateSearchGraph(NULL);

	// Check if a source search is currently being done.
	CPartFile *pPartFile = theApp.downloadqueue->GetFileByKadFileSearchID(GetSearchID());

	// Reset the searchID if a source search is currently being done.
	if (pPartFile)
		pPartFile->SetKadFileSearchID(0);

	if (m_uType == NOTES) {
		CAbstractFile *pAbstractFile = theApp.knownfiles->FindKnownFileByID(CUInt128(GetTarget().GetData()).GetData());
		if (pAbstractFile != NULL)
			pAbstractFile->SetKadCommentSearchRunning(false);

		pAbstractFile = theApp.downloadqueue->GetFileByID(CUInt128(GetTarget().GetData()).GetData());
		if (pAbstractFile != NULL)
			pAbstractFile->SetKadCommentSearchRunning(false);

		theApp.searchlist->SetNotesSearchStatus(CUInt128(GetTarget().GetData()).GetData(), false);
	}

	// Decrease the use count for any contacts that are in your contact list.
	for (ContactMap::const_iterator itInUseMap = m_mapInUse.begin(); itInUseMap != m_mapInUse.end(); ++itInUseMap)
		itInUseMap->second->DecUse();

	// Delete any temp contacts.
	for (ContactArray::const_iterator itContact = m_listDelete.begin(); itContact != m_listDelete.end(); ++itContact)
		if (!(*itContact)->InUse())
			delete *itContact;

	// Check if this search was contacting an overloaded node and adjust time of next time we use that node.
	if (CKademlia::IsRunning() && GetNodeLoad() > 20 && GetSearchType() == CSearch::STOREKEYWORD)
		Kademlia::CKademlia::GetIndexed()->AddLoad(GetTarget(), time(NULL) + (time_t)(DAY2S(7) * (GetNodeLoad() / 100.0)));
	delete[] m_pucSearchTermsData;

	CKademlia::GetUDPListener()->Free(m_pSearchTerm);
	m_pSearchTerm = NULL;
}

void CSearch::Go()
{
	// Start with a lot of possible contacts, this is a fallback in case search stalls due to dead contacts
	if (m_mapPossible.empty()) {
		CUInt128 uDistance(CKademlia::GetPrefs()->GetKadID());
		uDistance.Xor(m_uTarget);
		CKademlia::GetRoutingZone()->GetClosestTo(3, m_uTarget, uDistance, 50, m_mapPossible, true, true);

		for (ContactMap::const_iterator itPossibleMap = m_mapPossible.begin(); itPossibleMap != m_mapPossible.end(); ++itPossibleMap)
			m_pLookupHistory->ContactReceived(itPossibleMap->second, NULL, itPossibleMap->first, false);
		theApp.emuledlg->kademliawnd->UpdateSearchGraph(m_pLookupHistory);
	}
	if (!m_mapPossible.empty()) {
		//Lets keep our contact list entries in mind to dec the inUse flag.
		for (ContactMap::const_iterator itPossibleMap = m_mapPossible.begin(); itPossibleMap != m_mapPossible.end(); ++itPossibleMap)
			m_mapInUse[itPossibleMap->first] = itPossibleMap->second;

		ASSERT(m_mapPossible.size() == m_mapInUse.size());

		// Take top ALPHA_QUERY to start search with.
		int iCount = (m_uType == NODE) ? 1 : min(ALPHA_QUERY, (int)m_mapPossible.size());

		ContactMap::const_iterator itPossibleMap = m_mapPossible.begin();
		// Send initial packets to start the search.
		while (iCount-- > 0) {
			CContact *pContact = itPossibleMap->second;
			// Move to tried
			m_mapTried[itPossibleMap->first] = pContact;
			// Send the KadID so other side can check if I think it has the right KadID. (Safety net)
			// Send request
			SendFindValue(pContact);
			++itPossibleMap;
		}
	}
	// Update search for the GUI
	theApp.emuledlg->kademliawnd->searchList->SearchRef(this);
}

//If we allow about a 15 sec delay before deleting, we won't miss a lot of delayed returning packets.
void CSearch::PrepareToStop()
{
	// Check if already stopping.
	if (m_bStoping)
		return;

	// Set base time by search type.
	uint32 uBaseTime;
	switch (m_uType) {
	case NODE:
	case NODECOMPLETE:
	case NODESPECIAL:
	case NODEFWCHECKUDP:
		uBaseTime = SEARCHNODE_LIFETIME;
		break;
	case FILE:
		uBaseTime = SEARCHFILE_LIFETIME;
		break;
	case KEYWORD:
		uBaseTime = SEARCHKEYWORD_LIFETIME;
		break;
	case NOTES:
		uBaseTime = SEARCHNOTES_LIFETIME;
		break;
	case STOREFILE:
		uBaseTime = SEARCHSTOREFILE_LIFETIME;
		break;
	case STOREKEYWORD:
		uBaseTime = SEARCHSTOREKEYWORD_LIFETIME;
		break;
	case STORENOTES:
		uBaseTime = SEARCHSTORENOTES_LIFETIME;
		break;
	case FINDBUDDY:
		uBaseTime = SEARCHFINDBUDDY_LIFETIME;
		break;
	case FINDSOURCE:
		uBaseTime = SEARCHFINDSOURCE_LIFETIME;
		break;
	default:
		uBaseTime = SEARCH_LIFETIME;
	}

	// Adjust created time so that search will be deleted within 15 seconds.
	// This gives late results time to be processed.
	m_tCreated = time(NULL) - uBaseTime + SEC(15);
	m_bStoping = true;

	//Update search within GUI.
	theApp.emuledlg->kademliawnd->searchList->SearchRef(this);
	if (m_pLookupHistory != NULL) {
		m_pLookupHistory->SetSearchStopped();
		theApp.emuledlg->kademliawnd->UpdateSearchGraph(m_pLookupHistory);
	}
}

void CSearch::JumpStart()
{
	// eSE: Use adaptive timeout from FastKad instead of fixed 3 seconds.
	// fastKad.GetEstMaxResponseTime() returns mean + 2*stddev (95% confidence), capped at 3s.
	// Round up: m_uLastResponse only has whole-second granularity, and truncating
	// would under-wait the estimated max response time by up to a second.
	time_t uAdaptiveTimeoutSec = max(1, static_cast<time_t>((fastKad.GetEstMaxResponseTime() + CLOCKS_PER_SEC - 1) / CLOCKS_PER_SEC));
	if (time(NULL) < m_uLastResponse + uAdaptiveTimeoutSec)
		return;

	// If we ran out of contacts, stop search.
	if (m_mapPossible.empty()) {
		PrepareToStop();
		return;
	}

	// Is this a find lookup and are the best two (=KADEMLIA_FIND_VALUE) nodes dead/unreachable?
	// In this case try to discover more close nodes before using our other results
	// The reason for this is that we may not have found the closest node alive due to results being limited
	// to 2 contacts, which could very well have been the duplicates of our dead closest nodes [link paper]
	if (pRequestedMoreNodesContact == NULL && GetRequestContactCount() == KADEMLIA_FIND_VALUE && m_mapTried.size() >= 3 * KADEMLIA_FIND_VALUE) {
		ContactMap::const_iterator itTriedMap = m_mapTried.begin();
		bool bLookupCloserNodes = true;
		for (int i = KADEMLIA_FIND_VALUE; --i >= 0;) {
			if (m_mapResponded.find(itTriedMap->first) != m_mapResponded.end()) {
				bLookupCloserNodes = false;
				break;
			}
			++itTriedMap;
		}
		if (bLookupCloserNodes)
			for (; itTriedMap != m_mapTried.end(); ++itTriedMap)
				if (m_mapResponded.find(itTriedMap->first) != m_mapResponded.end()) {
					DEBUG_ONLY(DebugLogWarning(_T("Best KADEMLIA_FIND_VALUE nodes for LookUp (%s) were unreachable or dead, re-asking closest for more"), (LPCTSTR)(CString)GetGUIName()));
					SendFindValue(itTriedMap->second, true);
					return;
				}
	}

	// Search for contacts that can be used to jump-start a stalled search.
	while (!m_mapPossible.empty()) {
		const ContactMap::const_iterator itPossibleMap = m_mapPossible.begin();
		// Get a contact closest to our target.
		CContact *pContact = itPossibleMap->second;

		// Have we already tried to contact this node?
		if (m_mapTried.find(itPossibleMap->first) == m_mapTried.end()) {
			// Add to tried list.
			m_mapTried[itPossibleMap->first] = pContact;
			// Send the KadID so other side can check if I think it has the right KadID. (Safety net)
			// Send request
			SendFindValue(pContact);
			return;
		}
		// Did we get a response from this node? if so, try to store or get info.
		if (m_mapResponded.find(itPossibleMap->first) != m_mapResponded.end())
			StorePacket();

		// Remove from possible list.
		m_mapPossible.erase(itPossibleMap);
	}
}

void CSearch::ProcessResponse(uint32 uFromIP, uint16 uFromPort, const ContactArray &rlistResults)
{
	// Remember the contacts to be deleted when finished
	m_listDelete.insert(m_listDelete.end(), rlistResults.begin(), rlistResults.end());

	m_uLastResponse = time(NULL);

	//Find contact that is responding.
	CUInt128 uFromDistance;
	CContact *pFromContact = NULL;
	for (ContactMap::const_iterator itTriedMap = m_mapTried.begin(); itTriedMap != m_mapTried.end(); ++itTriedMap) {
		CContact *pTmpContact = itTriedMap->second;
		if ((pTmpContact->GetIPAddress() == uFromIP) && (pTmpContact->GetUDPPort() == uFromPort)) {
			uFromDistance = itTriedMap->first;
			pFromContact = pTmpContact;
			break;
		}
	}

	// Make sure the node is not sending more results than we requested, which is not only
	// a protocol violation, but most likely a malicious answer
	if (rlistResults.size() > GetRequestContactCount() && !(pRequestedMoreNodesContact == pFromContact && rlistResults.size() <= KADEMLIA_FIND_VALUE_MORE)) {
		DebugLogWarning(_T("Node %s sent more contacts than requested on a routing query, ignoring response"), (LPCTSTR)ipstr(htonl(uFromIP)));
		return;
	}

	// eSE: feed the real round-trip time (SendFindValue stamp -> now) to the
	// FastKad adaptive-timeout estimator. Erase the stamp so a duplicate
	// response cannot re-feed a stale sample.
	if (pFromContact != NULL) {
		const std::map<uint32, DWORD>::iterator itSendTick = m_mapEseReqSendTick.find(uFromIP);
		if (itSendTick != m_mapEseReqSendTick.end()) {
			const DWORD dwRttMs = ::GetTickCount() - itSendTick->second; // unsigned delta, wrap-safe
			m_mapEseReqSendTick.erase(itSendTick);
			fastKad.AddResponseTime(uFromIP, static_cast<clock_t>(static_cast<ULONGLONG>(dwRttMs) * CLOCKS_PER_SEC / 1000));
		}
	}

	if (m_uType == NODE || m_uType == NODEFWCHECKUDP) {
		// Note we got an answer
		++m_uAnswers;

		if (m_uType == NODE) {
			// Not interested in responses for FIND_NODE.
			// Once we get the results, we stop the search.
			// These contacts are added to contacts by UDPListener.

			// Add contacts to the History for GUI
			for (ContactArray::const_iterator itResultsList = rlistResults.begin(); itResultsList != rlistResults.end(); ++itResultsList) {
				CUInt128 uDistance((*itResultsList)->GetClientID().Xor(m_uTarget));
				m_pLookupHistory->ContactReceived(*itResultsList, pFromContact, uDistance, uDistance < uFromDistance, true);
			}
			theApp.emuledlg->kademliawnd->UpdateSearchGraph(m_pLookupHistory);
			// We clear the possible list to force the search to stop.
			// We do this so the user has time to see the visualised results.
			m_mapPossible.clear();
		} else {
			// Results are not passed to the search and not much point in changing this,
			// but make sure we show on the graph that the contact responded
			m_pLookupHistory->ContactReceived(NULL, pFromContact, CUInt128(), true);
			theApp.emuledlg->kademliawnd->UpdateSearchGraph(m_pLookupHistory);
		}

		// Update search in the GUI.
		theApp.emuledlg->kademliawnd->searchList->SearchRef(this);
		return;
	}

	try {
		if (pFromContact != NULL) {
			bool bProvidedCloserContacts = false;
			std::map<uint32, uint32> mapReceivedIPs;
			std::map<uint32, uint32> mapReceivedSubnets;
			mapReceivedIPs[uFromIP] = 1; // A node is not allowed to answer with contacts to itself
			mapReceivedSubnets[uFromIP & ~0xFF] = 1;
			// Loop through their responses
			for (ContactArray::const_iterator itContact = rlistResults.begin(); itContact != rlistResults.end(); ++itContact) {
				// Get next result
				CContact *pContact = *itContact;

				// Calc distance from this result to the target.
				CUInt128 uDistance(pContact->GetClientID());
				uDistance.Xor(m_uTarget);

				if (uDistance < uFromDistance)
					bProvidedCloserContacts = true;

				m_pLookupHistory->ContactReceived(pContact, pFromContact, uDistance, bProvidedCloserContacts);
				theApp.emuledlg->kademliawnd->UpdateSearchGraph(m_pLookupHistory);

				// Ignore this contact if already know or tried it.
				if (m_mapPossible.find(uDistance) != m_mapPossible.end() || m_mapTried.find(uDistance) != m_mapTried.end())
					continue;
				// we only accept unique IPs in the answer, having multiple IDs pointing to one IP in the routing tables
				// is no longer allowed since 0.49a anyway
				if (mapReceivedIPs.find(pContact->GetIPAddress()) != mapReceivedIPs.end()) {
					DebugLogWarning(_T("Multiple KadIDs pointing to same IP (%s) in KADEMLIA(2)_RES answer - ignored, sent by %s")
						, (LPCTSTR)ipstr(pContact->GetNetIP()), (LPCTSTR)ipstr(pFromContact->GetNetIP()));
					continue;
				}

				mapReceivedIPs[pContact->GetIPAddress()] = 1;

				// and no more than 2 IPs from the same /24 block
				const uint32 subnetIP = pContact->GetIPAddress() & ~0xFF;
				std::map<uint32, uint32>::iterator it = IsLANIP(pContact->GetNetIP()) ? mapReceivedSubnets.end() : mapReceivedSubnets.find(subnetIP);
				if (it == mapReceivedSubnets.end())
					mapReceivedSubnets[subnetIP] = 1;
				else {
					if (it->second >= 2) {
						DebugLogWarning(_T("More than 2 KadIDs pointing to same Subnet (%s) in KADEMLIA(2)_RES answer - ignored, sent by %s")
							, (LPCTSTR)ipstr(htonl(subnetIP)), (LPCTSTR)ipstr(pFromContact->GetNetIP()));
						continue;
					}
					++it->second;
				}

				// Add to possible
				m_mapPossible[uDistance] = pContact;

				// Verify if the result is closer to the target then the one we just checked.
				if (uDistance < uFromDistance) {
					// The top APLPHA_QUERY of results are used to determine if we send a request.
					bool bTop = (m_mapBest.size() < ALPHA_QUERY);
					if (bTop)
						m_mapBest[uDistance] = pContact;
					else {
						ContactMap::const_iterator itContactMapBest = m_mapBest.end();
						--itContactMapBest;
						if (uDistance < itContactMapBest->first) {
							// Prevent having more then ALPHA_QUERY within the Best list.
							m_mapBest.erase(itContactMapBest);
							m_mapBest[uDistance] = pContact;
							bTop = true;
						}
					}

					if (bTop) {
						// We determined this contact is a candidate for a request.
						// Add to the tried list.
						m_mapTried[uDistance] = pContact;
						// Send the KadID so other side can check if I think it has the right KadID. (Safety net)
						// Send request
						SendFindValue(pContact);
					}
				}
			}

			// Add to the list of contacts that responded
			m_mapResponded[uFromDistance] = bProvidedCloserContacts;

			// Complete node search, just increase the answers and update the GUI
			if (m_uType == NODECOMPLETE || m_uType == NODESPECIAL) {
				++m_uAnswers;
				theApp.emuledlg->kademliawnd->searchList->SearchRef(this);
			}
		}
	} catch (...) {
		AddDebugLogLine(false, _T("Exception in CSearch::ProcessResponse"));
	}
}

void CSearch::StorePacket()
{
	ASSERT(!m_mapPossible.empty());

	// This method is currently only called by jump-start so only use best possible.
	ContactMap::const_iterator itPossibleMap = m_mapPossible.begin();
	CUInt128 uFromDistance(itPossibleMap->first);
	CContact *pFromContact = itPossibleMap->second;

	if (uFromDistance < m_uClosestDistantFound || m_uClosestDistantFound == 0)
		m_uClosestDistantFound = uFromDistance;
	// Make sure this is a valid Node to store too.
	if (uFromDistance.Get32BitChunk(0) > SEARCHTOLERANCE && !IsLANIP(pFromContact->GetNetIP()))
		return;
	m_pLookupHistory->ContactAskedKeyword(pFromContact);
	theApp.emuledlg->kademliawnd->UpdateSearchGraph(m_pLookupHistory);
	// What kind of search are we doing?
	switch (m_uType) {
	case FILE:
		{
			CSafeMemFile m_pfileSearchTerms;
			m_pfileSearchTerms.WriteUInt128(m_uTarget);
			if (pFromContact->GetVersion() >= KADEMLIA_VERSION3_47b) {
				// Find file we are storing info about.
				uchar ucharFileid[MDX_DIGEST_SIZE];
				m_uTarget.ToByteArray(ucharFileid);
				CKnownFile *pFile = theApp.downloadqueue->GetFileByID(ucharFileid);
				if (!pFile) {
					PrepareToStop();
					break;
				}
				// JOHNTODO -- Add start position
				// Start Position range (0x0 to 0x7FFF)
				m_pfileSearchTerms.WriteUInt16(0);
				m_pfileSearchTerms.WriteUInt64(pFile->GetFileSize());
				if (thePrefs.GetDebugClientKadUDPLevel() > 0)
					DebugSend("KADEMLIA2_SEARCH_SOURCE_REQ", pFromContact->GetIPAddress(), pFromContact->GetUDPPort());
				if (pFromContact->GetVersion() >= KADEMLIA_VERSION6_49aBETA) {
					CUInt128 uClientID = pFromContact->GetClientID();
					CKademlia::GetUDPListener()->SendPacket(m_pfileSearchTerms, KADEMLIA2_SEARCH_SOURCE_REQ, pFromContact->GetIPAddress(), pFromContact->GetUDPPort(), pFromContact->GetUDPKey(), &uClientID);
				} else {
					CKademlia::GetUDPListener()->SendPacket(m_pfileSearchTerms, KADEMLIA2_SEARCH_SOURCE_REQ, pFromContact->GetIPAddress(), pFromContact->GetUDPPort(), CKadUDPKey(), NULL);
					ASSERT(CKadUDPKey() == pFromContact->GetUDPKey());
				}
			} else {
				m_pfileSearchTerms.WriteUInt8(1);
				if (thePrefs.GetDebugClientKadUDPLevel() > 0)
					DebugSend("KADEMLIA_SEARCH_REQ(File)", pFromContact->GetIPAddress(), pFromContact->GetUDPPort());
				CKademlia::GetUDPListener()->SendPacket(m_pfileSearchTerms, KADEMLIA_SEARCH_REQ, pFromContact->GetIPAddress(), pFromContact->GetUDPPort(), CKadUDPKey(), NULL);
			}
			// Inc total request answers
			++m_uTotalRequestAnswers;
			// Update search in the GUI
			theApp.emuledlg->kademliawnd->searchList->SearchRef(this);
		}
		break;
	case KEYWORD:
		{
			//JOHNTODO -- We cannot pre-create these packets as we do not know
			// beforehand if we are talking to Kad1.0 or Kad2.0
			CSafeMemFile m_pfileSearchTerms;
			m_pfileSearchTerms.WriteUInt128(m_uTarget);
			if (pFromContact->GetVersion() >= KADEMLIA_VERSION3_47b) {
				if (m_uSearchTermsDataSize == 0) {
					// JOHNTODO - Need to add ability to change start position.
					// Start position range (0x0 to 0x7fff)
					m_pfileSearchTerms.WriteUInt16(0x0000ui16);
				} else {
					// JOHNTODO - Need to add ability to change start position.
					// Start position range (0x8000 to 0xffff)
					m_pfileSearchTerms.WriteUInt16(0x8000ui16);
					m_pfileSearchTerms.Write(m_pucSearchTermsData, m_uSearchTermsDataSize);
				}
			} else {
				if (m_uSearchTermsDataSize == 0) {
					m_pfileSearchTerms.WriteUInt8(0);
					// We send this extra byte to flag we handle large files.
					m_pfileSearchTerms.WriteUInt8(0);
				} else {
					// Set to 2 to flag we handle large files.
					m_pfileSearchTerms.WriteUInt8(2);
					m_pfileSearchTerms.Write(m_pucSearchTermsData, m_uSearchTermsDataSize);
				}
			}

			if (pFromContact->GetVersion() >= KADEMLIA_VERSION6_49aBETA) {
				if (thePrefs.GetDebugClientKadUDPLevel() > 0)
					DebugSend("KADEMLIA2_SEARCH_KEY_REQ", pFromContact->GetIPAddress(), pFromContact->GetUDPPort());
				CUInt128 uClientID = pFromContact->GetClientID();
				CKademlia::GetUDPListener()->SendPacket(m_pfileSearchTerms, KADEMLIA2_SEARCH_KEY_REQ, pFromContact->GetIPAddress(), pFromContact->GetUDPPort(), pFromContact->GetUDPKey(), &uClientID);
			} else if (pFromContact->GetVersion() >= KADEMLIA_VERSION3_47b) {
				if (thePrefs.GetDebugClientKadUDPLevel() > 0)
					DebugSend("KADEMLIA2_SEARCH_KEY_REQ", pFromContact->GetIPAddress(), pFromContact->GetUDPPort());
				CKademlia::GetUDPListener()->SendPacket(m_pfileSearchTerms, KADEMLIA2_SEARCH_KEY_REQ, pFromContact->GetIPAddress(), pFromContact->GetUDPPort(), CKadUDPKey(), NULL);
				ASSERT(CKadUDPKey() == pFromContact->GetUDPKey());
			} else {
				if (thePrefs.GetDebugClientKadUDPLevel() > 0)
					DebugSend("KADEMLIA_SEARCH_REQ(KEYWORD)", pFromContact->GetIPAddress(), pFromContact->GetUDPPort());
				CKademlia::GetUDPListener()->SendPacket(m_pfileSearchTerms, KADEMLIA_SEARCH_REQ, pFromContact->GetIPAddress(), pFromContact->GetUDPPort(), CKadUDPKey(), NULL);
			}
			// Inc total request answers
			++m_uTotalRequestAnswers;
			// Update search in the GUI
			theApp.emuledlg->kademliawnd->searchList->SearchRef(this);
		}
		break;
	case NOTES:
		{
			// Write complete packet
			CSafeMemFile m_pfileSearchTerms;
			m_pfileSearchTerms.WriteUInt128(m_uTarget);

			if (pFromContact->GetVersion() >= KADEMLIA_VERSION3_47b) {
				// Find file we are storing info about.
				uchar ucharFileid[MDX_DIGEST_SIZE];
				m_uTarget.ToByteArray(ucharFileid);
				CKnownFile *pFile = theApp.sharedfiles->GetFileByID(ucharFileid);
				if (!pFile) {
					PrepareToStop();
					break;
				}
				m_pfileSearchTerms.WriteUInt64(pFile->GetFileSize());
				if (thePrefs.GetDebugClientKadUDPLevel() > 0)
					DebugSend("KADEMLIA2_SEARCH_NOTES_REQ", pFromContact->GetIPAddress(), pFromContact->GetUDPPort());
				if (pFromContact->GetVersion() >= KADEMLIA_VERSION6_49aBETA) {
					CUInt128 uClientID = pFromContact->GetClientID();
					CKademlia::GetUDPListener()->SendPacket(m_pfileSearchTerms, KADEMLIA2_SEARCH_NOTES_REQ, pFromContact->GetIPAddress(), pFromContact->GetUDPPort(), pFromContact->GetUDPKey(), &uClientID);
				} else {
					CKademlia::GetUDPListener()->SendPacket(m_pfileSearchTerms, KADEMLIA2_SEARCH_NOTES_REQ, pFromContact->GetIPAddress(), pFromContact->GetUDPPort(), CKadUDPKey(), NULL);
					ASSERT(CKadUDPKey() == pFromContact->GetUDPKey());
				}
			} else {
				m_pfileSearchTerms.WriteUInt128(CKademlia::GetPrefs()->GetKadID());
				if (thePrefs.GetDebugClientKadUDPLevel() > 0)
					DebugSend("KADEMLIA_SEARCH_NOTES_REQ", pFromContact->GetIPAddress(), pFromContact->GetUDPPort());
				CKademlia::GetUDPListener()->SendPacket(m_pfileSearchTerms, KADEMLIA_SEARCH_NOTES_REQ, pFromContact->GetIPAddress(), pFromContact->GetUDPPort(), CKadUDPKey(), NULL);
			}
			// Inc total request answers
			++m_uTotalRequestAnswers;
			// Update search in the GUI
			theApp.emuledlg->kademliawnd->searchList->SearchRef(this);
		}
		break;
	case STOREFILE:
		{
			// Try to store yourself as a source to a Node.
			// As a safeguard, check to see if we already stored to the Max Nodes
			if (m_uAnswers > SEARCHSTOREFILE_TOTAL) {
				PrepareToStop();
				break;
			}

			// K6-3 shadow source: the backing file belongs to a SourceLease,
			// not this exit's SharedFiles. The Kad2 holder stamps the datagram's
			// source IP (the exit), while the lease supplies the only permitted
			// UserHash, size and virtual endpoint ports.
			if (m_bK6ShadowSource) {
				uint8 custodian[16];
				pFromContact->GetClientID().ToByteArray(custodian);
				if (!eSELive::CLiveTunnel::Get().AllowKad6ShadowPublishContact(
					m_uK6PublishLeaseId, custodian)) {
					PrepareToStop();
					break;
				}
				TagList tags;
				tags.push_back(new CKadTagUInt(TAG_SOURCETYPE,
					m_uK6ShadowFileSize > OLD_MAX_EMULE_FILE_SIZE ? 4 : 1));
				tags.push_back(new CKadTagUInt(TAG_SOURCEPORT, m_uK6ShadowTcpPort));
				if (m_uK6ShadowUdpPort != 0)
					tags.push_back(new CKadTagUInt16(TAG_SOURCEUPORT, m_uK6ShadowUdpPort));
				if (pFromContact->GetVersion() >= KADEMLIA_VERSION2_47a)
					tags.push_back(new CKadTagUInt(TAG_FILESIZE, m_uK6ShadowFileSize));
				tags.push_back(new CKadTagUInt8(TAG_ENCRYPTION,
					CKademlia::GetPrefs()->GetMyConnectOptions(true, true)));
				CKademlia::GetUDPListener()->SendPublishSourcePacket(
					pFromContact, m_uTarget, m_uK6CompatUserHash, tags);
				++m_uTotalRequestAnswers;
				eSELive::CLiveTunnel::Get().OnKad6ShadowPublishSent(m_uK6PublishLeaseId);
				theApp.emuledlg->kademliawnd->searchList->SearchRef(this);
				deleteTagListEntries(tags);
				break;
			}

			// Find the file we are trying to store as a source too.
			uchar ucharFileid[MDX_DIGEST_SIZE];
			m_uTarget.ToByteArray(ucharFileid);
			CKnownFile *pFile = theApp.sharedfiles->GetFileByID(ucharFileid);
			if (!pFile) {
				PrepareToStop();
				break;
			}

			// We set this mostly for GUI response.
			SetGUIName((CStringW)pFile->GetFileName());

			// Get our clientID for the packet.
			CUInt128 uID(CKademlia::GetPrefs()->GetClientHash());

			//We can use type for different types of sources.
			//1 HighID Sources.
			//2 cannot be used as older clients will not work.
			//3 Firewalled Kad Source.
			//4 >4GB file HighID Source.
			//5 >4GB file Firewalled Kad source.
			//6 Firewalled Source with Direct Callback (supports >4GB)

			// Reachability is published as additive metadata.  The classic source
			// type below remains present for byte-level compatibility with eMule and
			// aMule; modern readers can select a route before HELLO exists.
			uint16 uReachCaps = 0;
			const bool bUdpVerified = Kademlia::CKademlia::IsRunning()
				&& !Kademlia::CUDPFirewallTester::IsFirewalledUDP(true)
				&& Kademlia::CUDPFirewallTester::IsVerified();
			if (!theApp.IsFirewalled())
				uReachCaps |= KAD_REACH_CAP_V4_TCP_IN;
			if (bUdpVerified)
				uReachCaps |= KAD_REACH_CAP_V4_UDP_IN;

			const CAddress publicV6 = CFirewallProberV6::Instance().GetDetectedV6IP();
			const bool bHasPublicV6 = thePrefs.IsIPv6Enabled()
				&& publicV6.GetType() == CAddress::IPv6 && publicV6.IsPublicIP();
			const bool bV6Inbound = bHasPublicV6
				&& CFirewallProberV6::Instance().HasInboundV6Observation();
			if (bHasPublicV6)
				uReachCaps |= KAD_REACH_CAP_V6_OUT;
			if (bV6Inbound)
				uReachCaps |= KAD_REACH_CAP_V6_IN;

			const bool bPunch2 = thePrefs.GetUtpHolePunchEnabled()
				&& theApp.clientudp != NULL && theApp.clientudp->IsUtpReady()
				&& Kademlia::CKademlia::IsConnected()
				&& Kademlia::CKademlia::GetUDPListener() != NULL
				&& CKademlia::GetPrefs()->GetInternKadPort() != 0;
			if (bPunch2)
				uReachCaps |= KAD_REACH_CAP_PUNCH_2W;
			// A source result exists before any TCP HELLO, so the reach vector
			// must carry the target-side R.1 capability. Without this bit the
			// downloader can never escalate punch2 -> punch3: the HELLO which
			// previously supplied ESE_CAP_HOLEPUNCH_RDV only exists after a
			// successful connection. Advertise only while the complete
			// target-side protocol and its kill switches are live.
			const bool bPunch3 = bPunch2
				&& thePrefs.GetEseEd2kPunch3()
				&& thePrefs.GetEseKad3Rendezvous()
				&& (g_uEseCapsRuntime & ESE_CAP_HOLEPUNCH_RDV) != 0;
			if (bPunch3)
				uReachCaps |= KAD_REACH_CAP_PUNCH_3W;
			if (bPunch3 && (g_uEseCapsRuntime & ESE_CAP_KAD_KEEPALIVE) != 0)
				uReachCaps |= KAD_REACH_CAP_KEEPALIVE;
			const bool bHasModernRoute = bPunch2 || bV6Inbound;
			// A punch-capable source must let each indexer stamp the UDP port it
			// actually observes. This stays correct with a buddy or open TCP and is
			// the useful value for endpoint-dependent CGNAT mappings.
			const bool bPublishInternalKadPort = !bPunch2
				&& !CKademlia::GetPrefs()->GetUseExternKadPort();

			TagList listTag;
			if (theApp.IsFirewalled()) {
				const bool bDirectCallback = bUdpVerified;
				if (!bDirectCallback && !theApp.clientlist->GetBuddy() && !bHasModernRoute) {
					// We are firewalled, no direct callback and no buddy. Stop everything.
					PrepareToStop();
					break;
				}

				if (bDirectCallback) {
					// firewalled, but direct UDP callback is possible without buddies
					listTag.push_back(new CKadTagUInt(TAG_SOURCETYPE, 6));
					listTag.push_back(new CKadTagUInt(TAG_SOURCEPORT, theApp.GetAdvertisedTcpPort()));
					if (bPublishInternalKadPort)
						listTag.push_back(new CKadTagUInt16(TAG_SOURCEUPORT, CKademlia::GetPrefs()->GetInternKadPort()));
					if (pFromContact->GetVersion() >= KADEMLIA_VERSION2_47a)
						listTag.push_back(new CKadTagUInt(TAG_FILESIZE, pFile->GetFileSize()));
				} else if (theApp.clientlist->GetBuddy() != NULL) { // We are firewalled, but do have a buddy.
					// We send the ID to our buddy so they can do a callback.
					CUInt128 uBuddyID(true);
					uBuddyID.Xor(CKademlia::GetPrefs()->GetKadID());
					listTag.push_back(new CKadTagUInt8(TAG_SOURCETYPE, (pFile->GetFileSize() > OLD_MAX_EMULE_FILE_SIZE ? 5 : 3)));
					listTag.push_back(new CKadTagUInt(TAG_SERVERIP, theApp.clientlist->GetBuddy()->GetIP()));
					listTag.push_back(new CKadTagUInt(TAG_SERVERPORT, theApp.clientlist->GetBuddy()->GetUDPPort()));
					listTag.push_back(new CKadTagStr(TAG_BUDDYHASH, (CStringW)md4str(uBuddyID.GetData())));
					listTag.push_back(new CKadTagUInt(TAG_SOURCEPORT, theApp.GetAdvertisedTcpPort()));
					if (bPublishInternalKadPort)
						listTag.push_back(new CKadTagUInt16(TAG_SOURCEUPORT, CKademlia::GetPrefs()->GetInternKadPort()));

					if (pFromContact->GetVersion() >= KADEMLIA_VERSION2_47a)
						listTag.push_back(new CKadTagUInt(TAG_FILESIZE, pFile->GetFileSize()));
				} else {
					// Modern-only source. Type 6 is the least surprising classic shell for
					// punch-capable peers; type 3/5 makes an IPv6-only source harmlessly
					// unusable to old clients while retaining it for modern readers.
					if (bPunch2)
						listTag.push_back(new CKadTagUInt(TAG_SOURCETYPE, 6));
					else
						listTag.push_back(new CKadTagUInt8(TAG_SOURCETYPE,
							(pFile->GetFileSize() > OLD_MAX_EMULE_FILE_SIZE ? 5 : 3)));
					listTag.push_back(new CKadTagUInt(TAG_SOURCEPORT, theApp.GetAdvertisedTcpPort()));
					// Do not send TAG_SOURCEUPORT here: the indexing node will add the
					// actually observed UDP source port, which is essential behind CGNAT.
					if (pFromContact->GetVersion() >= KADEMLIA_VERSION2_47a)
						listTag.push_back(new CKadTagUInt(TAG_FILESIZE, pFile->GetFileSize()));
				}
			} else {
				// We are not firewalled.
				if (pFile->GetFileSize() > OLD_MAX_EMULE_FILE_SIZE)
					listTag.push_back(new CKadTagUInt(TAG_SOURCETYPE, 4));
				else
					listTag.push_back(new CKadTagUInt(TAG_SOURCETYPE, 1));
				listTag.push_back(new CKadTagUInt(TAG_SOURCEPORT, theApp.GetAdvertisedTcpPort()));
				if (bPublishInternalKadPort)
					listTag.push_back(new CKadTagUInt16(TAG_SOURCEUPORT, CKademlia::GetPrefs()->GetInternKadPort()));

				if (pFromContact->GetVersion() >= KADEMLIA_VERSION2_47a)
					listTag.push_back(new CKadTagUInt(TAG_FILESIZE, pFile->GetFileSize()));
			}

			BYTE reachWire[255];
			uint8 reachWireLength = 0;
			if (uReachCaps != 0 && EseEncodeReachVectorV2(uReachCaps,
				reachWire, sizeof reachWire, &reachWireLength))
			{
				listTag.push_back(new CKadTagBsob(TAG_ESE_REACH,
					reachWire, reachWireLength));
			}
			if (bHasPublicV6) {
				CSafeMemFile v6Wire(18);
				publicV6.WriteToBuffer(&v6Wire);
				if (v6Wire.GetLength() == 18)
					listTag.push_back(new CKadTagBsob(TAG_SOURCEIP_V6,
						v6Wire.GetBuffer(), (uint8)v6Wire.GetLength()));
			}

			listTag.push_back(new CKadTagUInt8(TAG_ENCRYPTION, CKademlia::GetPrefs()->GetMyConnectOptions(true, true)));

			// Send packet
			CKademlia::GetUDPListener()->SendPublishSourcePacket(pFromContact, m_uTarget, uID, listTag);
			// Inc total request answers
			++m_uTotalRequestAnswers;
			// Update search in the GUI
			theApp.emuledlg->kademliawnd->searchList->SearchRef(this);
			// Delete all tags.
			deleteTagListEntries(listTag);
		}
		break;
	case STOREKEYWORD:
		{
			if (m_bLiveStreamPublish) {
				if (m_uAnswers > SEARCHSTOREKEYWORD_TOTAL) {
					PrepareToStop();
					break;
				}

				byte byPacket[1024 * 4];
				CByteIO byIO(byPacket, sizeof(byPacket));
				byIO.WriteUInt128(m_uTarget);
				byIO.WriteUInt16(1);
				byIO.WriteUInt128(m_uLiveStreamID);
				PrepareLivePacketForTags(&byIO);

				if (pFromContact->GetVersion() >= KADEMLIA_VERSION6_49aBETA) {
					if (thePrefs.GetDebugClientKadUDPLevel() > 0)
						DebugSend("KADEMLIA2_PUBLISH_KEY_REQ(eSELive)", pFromContact->GetIPAddress(), pFromContact->GetUDPPort());
					CUInt128 uClientID = pFromContact->GetClientID();
					CKademlia::GetUDPListener()->SendPacket(byPacket, (uint32)(sizeof byPacket - byIO.GetAvailable()), KADEMLIA2_PUBLISH_KEY_REQ, pFromContact->GetIPAddress(), pFromContact->GetUDPPort(), pFromContact->GetUDPKey(), &uClientID);
				} else if (pFromContact->GetVersion() >= KADEMLIA_VERSION2_47a) {
					if (thePrefs.GetDebugClientKadUDPLevel() > 0)
						DebugSend("KADEMLIA2_PUBLISH_KEY_REQ(eSELive)", pFromContact->GetIPAddress(), pFromContact->GetUDPPort());
					CKademlia::GetUDPListener()->SendPacket(byPacket, (uint32)(sizeof byPacket - byIO.GetAvailable()), KADEMLIA2_PUBLISH_KEY_REQ, pFromContact->GetIPAddress(), pFromContact->GetUDPPort(), CKadUDPKey(), NULL);
					ASSERT(CKadUDPKey() == pFromContact->GetUDPKey());
				} else
					ASSERT(0);

				++m_uTotalRequestAnswers;
				theApp.emuledlg->kademliawnd->searchList->SearchRef(this);
				break;
			}

			// Try to store keywords to a Node.
			INT_PTR iCount = m_listFileIDs.GetSize();
			// As a safeguard, check to see if we already stored to the Max Nodes
			if (iCount <= 0 || m_uAnswers > SEARCHSTOREKEYWORD_TOTAL) {
				PrepareToStop();
				break;
			}
			if (iCount > 150)
				iCount = 150;

			for (INT_PTR i = 0; i < iCount;) {
				uchar ucharFileid[MDX_DIGEST_SIZE];
				uint16 iPacketCount = 0;
				byte byPacket[1024 * 50];
				CByteIO byIO(byPacket, sizeof(byPacket));
				byIO.WriteUInt128(m_uTarget);
				byIO.WriteUInt16(0); // Will be corrected before sending.
				for (; iPacketCount < 50 && i < m_listFileIDs.GetSize(); ++i) {
					const CUInt128 &iID(m_listFileIDs[i]);
					iID.ToByteArray(ucharFileid);
					CKnownFile *pFile = theApp.sharedfiles->GetFileByID(ucharFileid);
					if (pFile) {
						--iCount;
						++iPacketCount;
						byIO.WriteUInt128(iID);
						PreparePacketForTags(&byIO, pFile, pFromContact->GetVersion());
					}
				}

				// Correct file count.
				uint32 current_pos = byIO.GetUsed();
				byIO.Seek(16);
				byIO.WriteUInt16(iPacketCount);
				byIO.Seek(current_pos);

				// Send packet
				if (pFromContact->GetVersion() >= KADEMLIA_VERSION6_49aBETA) {
					if (thePrefs.GetDebugClientKadUDPLevel() > 0)
						DebugSend("KADEMLIA2_PUBLISH_KEY_REQ", pFromContact->GetIPAddress(), pFromContact->GetUDPPort());
					CUInt128 uClientID = pFromContact->GetClientID();
					CKademlia::GetUDPListener()->SendPacket(byPacket, (uint32)(sizeof byPacket - byIO.GetAvailable()), KADEMLIA2_PUBLISH_KEY_REQ, pFromContact->GetIPAddress(), pFromContact->GetUDPPort(), pFromContact->GetUDPKey(), &uClientID);
				} else if (pFromContact->GetVersion() >= KADEMLIA_VERSION2_47a) {
					if (thePrefs.GetDebugClientKadUDPLevel() > 0)
						DebugSend("KADEMLIA2_PUBLISH_KEY_REQ", pFromContact->GetIPAddress(), pFromContact->GetUDPPort());
					CKademlia::GetUDPListener()->SendPacket(byPacket, (uint32)(sizeof byPacket - byIO.GetAvailable()), KADEMLIA2_PUBLISH_KEY_REQ, pFromContact->GetIPAddress(), pFromContact->GetUDPPort(), CKadUDPKey(), NULL);
					ASSERT(CKadUDPKey() == pFromContact->GetUDPKey());
				} else
					ASSERT(0);
			}
			// Inc total request answers
			++m_uTotalRequestAnswers;
			// Update search in the GUI
			theApp.emuledlg->kademliawnd->searchList->SearchRef(this);
		}
		break;
	case STORENOTES:
		{
			// Find file we are storing info about.
			uchar ucharFileid[MDX_DIGEST_SIZE];
			m_uTarget.ToByteArray(ucharFileid);
			CKnownFile *pFile = theApp.sharedfiles->GetFileByID(ucharFileid);
			if (!pFile) {
				PrepareToStop();
				break;
			}
			byte byPacket[1024 * 2];
			CByteIO byIO(byPacket, sizeof byPacket);

			// Send the Hash of the file we are storing info about.
			byIO.WriteUInt128(m_uTarget);
			// Send our ID with the info.
			byIO.WriteUInt128(CKademlia::GetPrefs()->GetKadID());

			// Create our taglist
			TagList listTag;
			listTag.push_back(new CKadTagStr(TAG_FILENAME, pFile->GetFileName()));
			if (pFile->GetFileRating() > 0)
				listTag.push_back(new CKadTagUInt(TAG_FILERATING, pFile->GetFileRating()));
			if (!pFile->GetFileComment().IsEmpty())
				listTag.push_back(new CKadTagStr(TAG_DESCRIPTION, pFile->GetFileComment()));
			if (pFromContact->GetVersion() >= KADEMLIA_VERSION2_47a)
				listTag.push_back(new CKadTagUInt(TAG_FILESIZE, pFile->GetFileSize()));
			byIO.WriteTagList(listTag);

			// Send packet
			if (pFromContact->GetVersion() >= KADEMLIA_VERSION6_49aBETA) {
				if (thePrefs.GetDebugClientKadUDPLevel() > 0)
					DebugSend("KADEMLIA2_PUBLISH_NOTES_REQ", pFromContact->GetIPAddress(), pFromContact->GetUDPPort());
				CUInt128 uClientID = pFromContact->GetClientID();
				CKademlia::GetUDPListener()->SendPacket(byPacket, (uint32)(sizeof byPacket - byIO.GetAvailable()), KADEMLIA2_PUBLISH_NOTES_REQ, pFromContact->GetIPAddress(), pFromContact->GetUDPPort(), pFromContact->GetUDPKey(), &uClientID);
			} else if (pFromContact->GetVersion() >= KADEMLIA_VERSION2_47a) {
				if (thePrefs.GetDebugClientKadUDPLevel() > 0)
					DebugSend("KADEMLIA2_PUBLISH_NOTES_REQ", pFromContact->GetIPAddress(), pFromContact->GetUDPPort());
				CKademlia::GetUDPListener()->SendPacket(byPacket, (uint32)(sizeof byPacket - byIO.GetAvailable()), KADEMLIA2_PUBLISH_NOTES_REQ, pFromContact->GetIPAddress(), pFromContact->GetUDPPort(), CKadUDPKey(), NULL);
				ASSERT(CKadUDPKey() == pFromContact->GetUDPKey());
			} else
				ASSERT(0);
			// Inc total request answers
			++m_uTotalRequestAnswers;
			// Update search in the GUI
			theApp.emuledlg->kademliawnd->searchList->SearchRef(this);
			// Delete all tags.
			deleteTagListEntries(listTag);
		}
		break;
	case FINDBUDDY:
		{
			// Send a buddy request as we are firewalled.
			// As a safe guard, check to see if we already requested the Max Nodes
			if (m_uAnswers > SEARCHFINDBUDDY_TOTAL) {
				PrepareToStop();
				break;
			}

			CSafeMemFile m_pfileSearchTerms;
			// Send the ID we used to find our buddy. Used for checks later and allows users to callback someone if they change buddies.
			m_pfileSearchTerms.WriteUInt128(m_uTarget);
			// Send client hash so they can do a callback.
			m_pfileSearchTerms.WriteUInt128(CKademlia::GetPrefs()->GetClientHash());
			// Send client port so they can do a callback
			m_pfileSearchTerms.WriteUInt16(theApp.GetAdvertisedTcpPort());

			// Do a keyword/source search request to this Node.
			// Send packet
			if (thePrefs.GetDebugClientKadUDPLevel() > 0)
				DebugSend("KADEMLIA_FINDBUDDY_REQ", pFromContact->GetIPAddress(), pFromContact->GetUDPPort());
			if (pFromContact->GetVersion() >= KADEMLIA_VERSION6_49aBETA) {
				CUInt128 uClientID = pFromContact->GetClientID();
				CKademlia::GetUDPListener()->SendPacket(m_pfileSearchTerms, KADEMLIA_FINDBUDDY_REQ, pFromContact->GetIPAddress(), pFromContact->GetUDPPort(), pFromContact->GetUDPKey(), &uClientID);
			} else {
				CKademlia::GetUDPListener()->SendPacket(m_pfileSearchTerms, KADEMLIA_FINDBUDDY_REQ, pFromContact->GetIPAddress(), pFromContact->GetUDPPort(), CKadUDPKey(), NULL);
				ASSERT(CKadUDPKey() == pFromContact->GetUDPKey());
			}
			// Inc total request answers
			++m_uAnswers;
			// Update search in the GUI
			theApp.emuledlg->kademliawnd->searchList->SearchRef(this);
		}
		break;
	case FINDSOURCE:
		{
			// Try to find if this is a buddy to someone we want to contact.
			// As a safe guard, check to see if we already requested the Max Nodes
			if (m_uAnswers > SEARCHFINDSOURCE_TOTAL) {
				PrepareToStop();
				break;
			}

			CSafeMemFile fileIO(34);
			// This is the ID the person we want to contact used to find a buddy.
			fileIO.WriteUInt128(m_uTarget);
			if (m_listFileIDs.GetSize() != 1)
				throwCStr(_T("Kademlia.CSearch.StorePacket: m_listFileIDs.size() != 1"));
			// Currently, we limit they type of callbacks for sources. We must know a file it person has for it to work.
			fileIO.WriteUInt128(m_listFileIDs[0]);
			// Send our port so the callback works.
			fileIO.WriteUInt16(theApp.GetAdvertisedTcpPort());
			// Send packet
			if (thePrefs.GetDebugClientKadUDPLevel() > 0)
				DebugSend("KADEMLIA_CALLBACK_REQ", pFromContact->GetIPAddress(), pFromContact->GetUDPPort());
			if (pFromContact->GetVersion() >= KADEMLIA_VERSION6_49aBETA) {
				CUInt128 uClientID = pFromContact->GetClientID();
				CKademlia::GetUDPListener()->SendPacket(fileIO, KADEMLIA_CALLBACK_REQ, pFromContact->GetIPAddress(), pFromContact->GetUDPPort(), pFromContact->GetUDPKey(), &uClientID);
			} else {
				CKademlia::GetUDPListener()->SendPacket(fileIO, KADEMLIA_CALLBACK_REQ, pFromContact->GetIPAddress(), pFromContact->GetUDPPort(), CKadUDPKey(), NULL);
				ASSERT(CKadUDPKey() == pFromContact->GetUDPKey());
			}
			// Inc total request answers
			++m_uAnswers;
			// Update search in the GUI
			theApp.emuledlg->kademliawnd->searchList->SearchRef(this);
		}
		break;
	case NODESPECIAL:
		// we are looking for the IP of a given nodeid, so we just check if we 0 distance and if so, report the
		// tip to the requester
		if (uFromDistance == CUInt128(0ul)) {
			pNodeSpecialSearchRequester->KadSearchIPByNodeIDResult(KCSR_SUCCEEDED, pFromContact->GetNetIP(), pFromContact->GetTCPPort());
			pNodeSpecialSearchRequester = NULL;
			PrepareToStop();
		}
	}
}

void CSearch::ProcessResult(const CUInt128 &uAnswer, TagList &rlistInfo, uint32 uFromIP, uint16 uFromPort)
{
	if (m_bK6VisibilityProbe) {
		uint32 sourceIP = 0;
		uint16 sourceTCP = 0, sourceUDP = 0;
		for (TagList::const_iterator it = rlistInfo.begin(); it != rlistInfo.end(); ++it) {
			const CKadTag& tag(**it);
			if (tag.m_name == TAG_SOURCEIP) sourceIP = static_cast<uint32>(tag.GetInt());
			else if (tag.m_name == TAG_SOURCEPORT) sourceTCP = static_cast<uint16>(tag.GetInt());
			else if (tag.m_name == TAG_SOURCEUPORT) sourceUDP = static_cast<uint16>(tag.GetInt());
		}
		if (uAnswer == m_uK6CompatUserHash && sourceIP == m_uK6VisibilityIP &&
			sourceTCP == m_uK6ShadowTcpPort &&
			(m_uK6ShadowUdpPort == 0 || sourceUDP == m_uK6ShadowUdpPort)) {
			++m_uAnswers;
			eSELive::CLiveTunnel::Get().OnKad6ShadowVerified(m_uK6PublishLeaseId);
			PrepareToStop();
		}
		return; // a visibility probe never materializes a download-queue source
	}
	// We received a result, process it based on type.
	uint32 iAnswerBefore = m_uAnswers;
	switch (m_uType) {
	case FILE:
		ProcessResultFile(uAnswer, rlistInfo);
		break;
	case KEYWORD:
		ProcessResultKeyword(uAnswer, rlistInfo, uFromIP, uFromPort);
		break;
	case NOTES:
		ProcessResultNotes(uAnswer, rlistInfo);
	}
	if (iAnswerBefore < m_uAnswers) {
		m_pLookupHistory->ContactRespondedKeyword(uFromIP, uFromPort, m_uAnswers - iAnswerBefore);
		theApp.emuledlg->kademliawnd->UpdateSearchGraph(m_pLookupHistory);
	}
	// Update search for the GUI
	theApp.emuledlg->kademliawnd->searchList->SearchRef(this);
}

void CSearch::ProcessResultFile(const CUInt128 &uAnswer, TagList &rlistInfo)
{
	// Process a possible source to a file.
	// Set of data we could receive from the result.
	uint8 uType = 0;
	uint32 uIP = 0;
	uint16 uTCPPort = 0;
	uint16 uUDPPort = 0;
	uint32 uBuddyIP = 0;
	uint16 uBuddyPort = 0;
	//uint32 uClientID = 0;
	CUInt128 uBuddy;
	uint8 byCryptOptions = 0; // 0 = not supported
	uint16 uReachCaps = 0;
	bool bReachTagSeen = false;
	bool bReachValid = false;
	CAddress sourceV6;
	bool bV6TagSeen = false;
	bool bV6Valid = false;

	for (TagList::const_iterator itInfoList = rlistInfo.begin(); itInfoList != rlistInfo.end(); ++itInfoList) {
		const CKadTag &cTag(**itInfoList);
		if (cTag.m_name == TAG_SOURCETYPE)
			uType = (uint8)cTag.GetInt();
		else if (cTag.m_name == TAG_SOURCEIP)
			uIP = (uint32)cTag.GetInt();
		else if (cTag.m_name == TAG_SOURCEPORT)
			uTCPPort = (uint16)cTag.GetInt();
		else if (cTag.m_name == TAG_SOURCEUPORT)
			uUDPPort = (uint16)cTag.GetInt();
		else if (cTag.m_name == TAG_SERVERIP)
			uBuddyIP = (uint32)cTag.GetInt();
		else if (cTag.m_name == TAG_SERVERPORT)
			uBuddyPort = (uint16)cTag.GetInt();
		else if (cTag.m_name == TAG_ESE_REACH) {
			// Duplicate route metadata is ambiguous and therefore ignored as a
			// whole. Structural/version/TLV checks live in libreach.
			if (bReachTagSeen) {
				bReachValid = false;
				uReachCaps = 0;
			} else {
				bReachTagSeen = true;
				uint8 version = 0;
				bReachValid = cTag.IsBsob()
					&& EseDecodeReachVector(cTag.GetBsob(), cTag.GetBsobSize(),
						&version, &uReachCaps);
			}
		} else if (cTag.m_name == TAG_SOURCEIP_V6) {
			if (bV6TagSeen) {
				bV6Valid = false;
				sourceV6 = CAddress();
			} else {
				bV6TagSeen = true;
				if (cTag.IsBsob() && cTag.GetBsobSize() == 18) {
					CSafeMemFile wire(cTag.GetBsob(), cTag.GetBsobSize());
					CAddress candidate;
					bV6Valid = candidate.ReadFromBuffer(&wire)
						&& wire.GetPosition() == wire.GetLength()
						&& candidate.GetType() == CAddress::IPv6
						&& candidate.IsPublicIP();
					if (bV6Valid)
						sourceV6 = candidate;
				}
			}
		}
		//else if (cTag.m_name == TAG_CLIENTLOWID)
		//  uClientID = cTag.GetInt();
		else if (cTag.m_name == TAG_BUDDYHASH) {
			uchar ucharBuddyHash[MDX_DIGEST_SIZE];
			if (cTag.IsStr() && strmd4(cTag.GetStr(), ucharBuddyHash))
				md4cpy(uBuddy.GetDataPtr(), ucharBuddyHash);
			else
				TRACE("+++ Invalid TAG_BUDDYHASH tag\n");
		} else if (cTag.m_name == TAG_ENCRYPTION)
			byCryptOptions = (uint8)cTag.GetInt();
	}

	// A K6 exit lookup must not materialize the discovered source in X's own
	// download queue. It hands the normalized result to the exact circuit/job;
	// LiveTunnel then issues destination authority and returns it to A.
	if (m_bK6GatewaySourceLookup) {
		byte userHash[16];
		uAnswer.ToByteArray(userHash);
		const uint8* sourceV6Bytes = bV6Valid ? sourceV6.Data() : NULL;
		if (eSELive::CLiveTunnel::Get().OnKad6GatewaySourceResult(
				m_uK6GatewayCircuitId, m_uK6GatewayRequestId, userHash, uType,
				uIP, uTCPPort, uUDPPort, byCryptOptions,
				bReachValid ? uReachCaps : 0, sourceV6Bytes)) {
			++m_uAnswers;
		}
		return;
	}

	// Process source based on its type. Currently only one method is needed to process all types.
	switch (uType) {
	case 1:
	case 3:
	case 4:
	case 5:
	case 6:
		++m_uAnswers;
		theApp.emuledlg->kademliawnd->searchList->SearchRef(this);
		theApp.downloadqueue->KademliaSearchFile(m_uSearchID, &uAnswer, &uBuddy,
			uType, uIP, uTCPPort, uUDPPort, uBuddyIP, uBuddyPort, byCryptOptions,
			bReachValid ? uReachCaps : 0, bV6Valid ? &sourceV6 : NULL);
		break;
	}
}

void CSearch::ProcessResultNotes(const CUInt128 &uAnswer, TagList &rlistInfo)
{
	// Process a received Note to a file.
	// Create a Note and set the ID's.
	CEntry cEntry;
	cEntry.m_uKeyID.SetValue(m_uTarget);
	cEntry.m_uSourceID.SetValue(uAnswer);

	// Loop through tags and pull wanted into. Currently we only keep Filename, Rating, Comment.
	for (TagList::iterator itInfoList = rlistInfo.begin(); itInfoList != rlistInfo.end(); ++itInfoList) {
		const CKadTag &cTag(**itInfoList);
		if (cTag.m_name == TAG_SOURCEIP)
			cEntry.m_uIP = (uint32)cTag.GetInt();
		else if (cTag.m_name == TAG_SOURCEPORT)
			cEntry.m_uTCPPort = (uint16)cTag.GetInt();
		else if (cTag.m_name == TAG_FILENAME || cTag.m_name == TAG_DESCRIPTION) {
			const CString &cfilter(thePrefs.GetCommentFilter());
			// Run the filter against the comment as well as against the filename since both values could be misused
			if (!cfilter.IsEmpty()) {
				CString strCommentLower(cTag.GetStr());
				// Verified Locale Dependency: Locale dependent string conversion (OK)
				strCommentLower.MakeLower();

				for (int iPos = 0; iPos >= 0;) {
					const CString &strFilter(cfilter.Tokenize(_T("|"), iPos));
					// comment filters are already in lower case, compare with temp. lower cased received comment
					if (!strFilter.IsEmpty() && strCommentLower.Find(strFilter) >= 0)
						return;
				}
			}
			if (cTag.m_name == TAG_FILENAME)
				cEntry.SetFileName(cTag.GetStr());
			else {
				ASSERT(cTag.m_name == TAG_DESCRIPTION);
				if (cTag.GetStr().GetLength() <= MAXFILECOMMENTLEN) {
					cEntry.AddTag(*itInfoList); //move pointer
					*itInfoList = NULL; //do not delete this tag
				} else
					cEntry.AddTag(new CKadTagStr(cTag.m_name, cTag.GetStr().Left(MAXFILECOMMENTLEN)));
			}
		} else if (cTag.m_name == TAG_FILERATING) {
			cEntry.AddTag(*itInfoList); //move pointer
			*itInfoList = NULL; //do not delete this tag
		}
	}

	uchar ucharFileid[MDX_DIGEST_SIZE];
	m_uTarget.ToByteArray(ucharFileid);

	// Add notes to any searches we have done.
	bool bAddedToSearches = theApp.searchlist->AddNotes(cEntry, ucharFileid);

	// Check if this hash is in our shared files.
	CAbstractFile *pFile = static_cast<CAbstractFile*>(theApp.sharedfiles->GetFileByID(ucharFileid));

	// If we didn't find a file in the shares, check in our download queue.
	if (!pFile)
		pFile = static_cast<CAbstractFile*>(theApp.downloadqueue->GetFileByID(ucharFileid));

	// If we have found a file, try to add the Note to the file -
	// though pFile->AddNote still may fail
	if ((pFile && pFile->AddNote(cEntry)) || bAddedToSearches) {
		// Inc the number of answers.
		++m_uAnswers;
		// Update the search in the GUI
		theApp.emuledlg->kademliawnd->searchList->SearchRef(this);
	}
}

void CSearch::ProcessResultKeyword(const CUInt128 &uAnswer, TagList &rlistInfo, uint32 uFromIP, uint16 uFromPort)
{
	// Find the contact who sent the answer - we need to know its protocol version
	// Special publish answer tags need to be filtered based on its remote protocol version,
	// because if an old node is not aware of those special tags, it doesn't know
	// it is not supposed to accept and store such tags on publish request, so a malicious
	// publisher could fake them and our remote node would relay them in answers
	CContact *pFromContact = NULL;
	for (ContactMap::const_iterator itTriedMap = m_mapTried.begin(); itTriedMap != m_mapTried.end(); ++itTriedMap) {
		CContact *pTmpContact = itTriedMap->second;
		if (pTmpContact->GetIPAddress() == uFromIP && pTmpContact->GetUDPPort() == uFromPort) {
			pFromContact = pTmpContact;
			break;
		}
	}
	uint8 uFromKadVersion;
	if (pFromContact == NULL) {
		uFromKadVersion = 0;
		DebugLogWarning(_T("Unable to find answering contact in ProcessResultKeyword - %s"), (LPCTSTR)ipstr(htonl(uFromIP)));
	} else
		uFromKadVersion = pFromContact->GetVersion();
	// Process the received keyword
	// Set of data we can use for the keyword result
	uint64 uSize = 0;
	CKadTagValueString sName;
	CKadTagValueString sType;
	CKadTagValueString sFormat;
	CKadTagValueString sArtist;
	CKadTagValueString sAlbum;
	CKadTagValueString sTitle;
	CKadTagValueString sCodec;
	uint32 uLength = 0;
	uint32 uBitrate = 0;
	uint32 uAvailability = 0;
	uint32 uPublishInfo = 0;
	bool bLiveMarker = false;
	CStringW sLiveKey;
	CStringW sLiveTitle;
	CStringW sLiveCategory;
	CStringW sLiveLanguage;
	uint32 uLiveBitrate = 0;
	uint32 uLiveViewers = 0;
	uint32 uLiveStartedAt = 0;
	uint32 uLiveIP = 0;
	uint16 uLivePort = 0;
	uint16 uLiveUDPPort = 0;  // A.4 Sprint 1: broadcaster's Kad UDP port for hole-punching
	uint32 uLiveAltIP = 0;    // NAT-reach: broadcaster's overlay IPv4 (TAG_ESE_LIVE_ALTIP)
	CArray<CAICHHash> aAICHHashes;
	CArray<uint8, uint8> aAICHHashPopularity;
	// Flags that are set if we want this keyword.
	bool bFileName = false;
	bool bFileSize = false;

	for (TagList::const_iterator itInfoList = rlistInfo.begin(); itInfoList != rlistInfo.end(); ++itInfoList) {
		const CKadTag &cTag(**itInfoList);
		if (cTag.m_name == TAG_FILENAME) {
			// Set flag based on last tag we saw.
			sName = cTag.GetStr();
			bFileName = !sName.IsEmpty();
		} else if (cTag.m_name == TAG_FILESIZE) {
			if (cTag.IsBsob() && cTag.GetBsobSize() == 8)
				uSize = *((uint64*)cTag.GetBsob());
			else
				uSize = cTag.GetInt();

			// Set flag based on last tag we saw.
			bFileSize = (uSize > 0);
		} else if (cTag.m_name == TAG_FILETYPE)
			sType = cTag.GetStr();
		else if (cTag.m_name == TAG_FILEFORMAT)
			sFormat = cTag.GetStr();
		else if (cTag.m_name == TAG_MEDIA_ARTIST)
			sArtist = cTag.GetStr();
		else if (cTag.m_name == TAG_MEDIA_ALBUM)
			sAlbum = cTag.GetStr();
		else if (cTag.m_name == TAG_MEDIA_TITLE)
			sTitle = cTag.GetStr();
		else if (cTag.m_name == TAG_MEDIA_LENGTH)
			uLength = (uint32)cTag.GetInt();
		else if (cTag.m_name == TAG_MEDIA_BITRATE)
			uBitrate = (uint32)cTag.GetInt();
		else if (cTag.m_name == TAG_MEDIA_CODEC)
			sCodec = cTag.GetStr();
		else if (cTag.m_name == TAG_SOURCES) {
			// Some rouge client was setting an invalid availability, just set it to 0
			uAvailability = (uint32)cTag.GetInt();
			if (uAvailability > 65500)
				uAvailability = 0;
		} else if (cTag.m_name == TAG_SOURCEIP)
			uLiveIP = (uint32)cTag.GetInt();
		else if (cTag.m_name == TAG_SOURCEPORT)
			uLivePort = (uint16)cTag.GetInt();
		// v0.71 IPv6 Sprint 8 — forward-compat TAG_SOURCEIP_V6 reader.
		// Until CEntry/CLiveKadBridge learn v6, we accept-and-log the tag
		// so we can observe v6-aware forks publishing once they exist. No
		// behavioural change: dial still falls back to uLiveIP (v4). The
		// emit side is deliberately not wired yet because CemuleApp has no
		// v6 public IP source (Sprint 3 firewall prober TryHighID is a
		// stub). When that lands, mirror the v4 emit at line ~1623.
		else if (cTag.m_name == TAG_SOURCEIP_V6) {
			// Tag value is BSOB carrying CAddress wire form (18 bytes for v6).
			// We don't dispatch on it yet — see comment block above.
			AddDebugLogLine(false,
				_T("eSE Live: received TAG_SOURCEIP_V6 from peer (v6 dial-path pending Sprint 3/6 v6 source)"));
		}
		// A.4 Sprint 1: capture broadcaster's Kad UDP port for hole-punching.
		// Without it, LowID broadcasters are unreachable from LowID viewers.
		else if (cTag.m_name == TAG_SOURCEUPORT)
			uLiveUDPPort = (uint16)cTag.GetInt();
		else if (cTag.m_name.Compare(TAG_ESE_LIVE_MARKER) == 0)
			bLiveMarker = cTag.IsInt() && cTag.GetInt() == 1;
		else if (cTag.m_name.Compare(TAG_ESE_LIVE_STREAM_KEY) == 0 && cTag.IsStr())
			sLiveKey = cTag.GetStr();
		else if (cTag.m_name.Compare(TAG_ESE_LIVE_TITLE) == 0 && cTag.IsStr())
			sLiveTitle = cTag.GetStr();
		else if (cTag.m_name.Compare(TAG_ESE_LIVE_CATEGORY) == 0 && cTag.IsStr())
			sLiveCategory = cTag.GetStr();
		else if (cTag.m_name.Compare(TAG_ESE_LIVE_LANGUAGE) == 0 && cTag.IsStr())
			sLiveLanguage = cTag.GetStr();
		else if (cTag.m_name.Compare(TAG_ESE_LIVE_BITRATE) == 0)
			uLiveBitrate = (uint32)cTag.GetInt();
		else if (cTag.m_name.Compare(TAG_ESE_LIVE_VIEWERS) == 0)
			uLiveViewers = (uint32)cTag.GetInt();
		else if (cTag.m_name.Compare(TAG_ESE_LIVE_STARTED_AT) == 0)
			uLiveStartedAt = (uint32)cTag.GetInt();
		else if (cTag.m_name.Compare(TAG_ESE_LIVE_ALTIP) == 0)
			uLiveAltIP = (uint32)cTag.GetInt();
		else if (cTag.m_name == TAG_PUBLISHINFO) {
			if (uFromKadVersion >= KADEMLIA_VERSION6_49aBETA) {
				// we don't keep this as a tag, but as a member property of the search file,
				// because we only need its information in the search list and don't want to carry
				// the tag over when downloading the file (and maybe even wrongly publishing it)
				uPublishInfo = (uint32)cTag.GetInt();
/*
#ifdef _DEBUG
				uint32 byDifferentNames = (uPublishInfo >> 24) & 0xFF;
				uint32 byPublishersKnown = (uPublishInfo >> 16) & 0xFF;
				uint32 wTrustValue = uPublishInfo & 0xFFFF;
				DebugLog(_T("Received PublishInfoTag: %u different names, %u Publishers, %.2f Trustvalue"), byDifferentNames, byPublishersKnown, (float)wTrustValue / 100.0f);
#endif
*/
			} else
				DebugLogWarning(_T("ProcessResultKeyword: Received special publish tag (TAG_PUBLISHINFO) from node (version %u, ip: %s) which is not aware of it, filtering")
					, uFromKadVersion, (LPCTSTR)ipstr(htonl(uFromIP)));
		} else if (cTag.m_name == TAG_KADAICHHASHRESULT) {
			if (uFromKadVersion >= KADEMLIA_VERSION9_50a && cTag.IsBsob()) {
				CSafeMemFile fileAICHTag(cTag.GetBsob(), cTag.GetBsobSize());
				try {
					for (uint8 byCount = fileAICHTag.ReadUInt8(); byCount > 0; --byCount) {
						uint8 byPopularity = fileAICHTag.ReadUInt8();
						if (byPopularity > 0) {
							aAICHHashPopularity.Add(byPopularity);
							aAICHHashes.Add(CAICHHash(fileAICHTag));
						}
					}
				} catch (CFileException *ex) {
					DebugLogError(_T("ProcessResultKeyword: Corrupt or invalid TAG_KADAICHHASHRESULT received - ip: %s)"), (LPCTSTR)ipstr(htonl(uFromIP)));
					ex->Delete();
					aAICHHashPopularity.RemoveAll();
					aAICHHashes.RemoveAll();
				}
			} else
				DebugLogWarning(_T("ProcessResultKeyword: Received special publish tag (TAG_KADAICHHASHRESULT) from node (version %u, ip: %s) which is not aware of it, filtering")
					, uFromKadVersion, (LPCTSTR)ipstr(htonl(uFromIP)));
		}
	}

	// H8 fix (2026-06-11): dispatch live-stream results BEFORE the
	// filename/size gate below. Clean-namespace publishes may carry no
	// TAG_FILENAME (v8.1 broadcasters omit it entirely; current ones send
	// a constant), so gating the live dispatch on bFileName silently
	// dropped every clean-namespace result — H8 discovery never reached
	// the bridge and the H5 ESE_NS_CLEAN attribution could not fire. Live
	// entries are identified by TAG_ESE_LIVE_MARKER and keyed by
	// TAG_ESE_LIVE_STREAM_KEY; they don't need a filename. The
	// keyword-words check below is name-based too, so it must not gate
	// live results either (bridge searches carry no words anyway —
	// m_listWords is empty for PrepareLookup searches).
	bool bLiveDispatched = false;
	if (bLiveMarker && !sLiveKey.IsEmpty() && theApp.liveStreamManager != NULL) {
		uchar liveKey[MDX_DIGEST_SIZE];
		if (EseLiveHexToKey(sLiveKey, liveKey)) {
			CString liveTitle(sLiveTitle.IsEmpty() ? sName : sLiveTitle);
			CString liveCategory(sLiveCategory.IsEmpty() ? L"General" : sLiveCategory);
			theApp.liveStreamManager->GetKadBridge().OnKadSearchResult(
				liveKey,
				liveTitle,
				liveCategory,
				uLiveIP,
				uLivePort,
				uLiveUDPPort,                                  // A.4: pass Kad UDP for hole-punch
				(uint16)min(uLiveBitrate, 65535u),
				uLiveViewers,
				m_uSearchID,                                   // H5: namespace attribution
				uLiveAltIP);                                   // NAT-reach: overlay endpoint
			bLiveDispatched = true;
		}
	}

	// If we don't have a valid filename or file size, drop this keyword.
	if (!bFileName || !bFileSize) {
		// ...unless it was a live entry (already dispatched above) — count
		// it as an answer so the clean-namespace search terminates on the
		// same answer-count lifecycle as the legacy one, then skip the
		// file-result path, which has nothing to do with live entries.
		if (bLiveDispatched) {
			++m_uAnswers;
			theApp.emuledlg->kademliawnd->searchList->SearchRef(this);
		}
		return;
	}

	// Check that this result matches the original criteria
	WordList listTestWords;
	CSearchManager::GetWords(sName, listTestWords);
	CKadTagValueString keyword;
	for (WordList::const_iterator itWordListWords = m_listWords.begin(); itWordListWords != m_listWords.end(); ++itWordListWords) {
		keyword = *itWordListWords;
		bool bInterested = false;
		for (WordList::const_iterator itWordListTestWords = listTestWords.begin(); itWordListTestWords != listTestWords.end(); ++itWordListTestWords)
			if (EqualKadTagStr(keyword, *itWordListTestWords)) {
				bInterested = true;
				break;
			}

		if (!bInterested)
			return;
	}

	if (m_pSearchTerm == NULL && m_pucSearchTermsData != NULL && m_uSearchTermsDataSize != 0) {
		// we create this to pass on to the search list, which will check it against the result to filter bad ones
		CSafeMemFile tmpFile(m_pucSearchTermsData, m_uSearchTermsDataSize);
		m_pSearchTerm = CKademliaUDPListener::CreateSearchExpressionTree(tmpFile, 0);
		ASSERT(m_pSearchTerm != NULL);
	}

	// Inc the number of answers.
	++m_uAnswers;
	// Update the search in the GUI
	theApp.emuledlg->kademliawnd->searchList->SearchRef(this);
	// Send the keyword to search list for processing.
	// This method is still legacy from the multithreaded Kad, maybe this can be changed for better handling.
	theApp.searchlist->KademliaSearchKeyword(m_uSearchID, &uAnswer, sName, uSize, sType, uPublishInfo
		, aAICHHashes, aAICHHashPopularity, m_pSearchTerm
		, 8
		, TAGTYPE_STRING, TAG_FILEFORMAT, (LPCTSTR)sFormat
		, TAGTYPE_STRING, TAG_MEDIA_ARTIST, (LPCTSTR)sArtist
		, TAGTYPE_STRING, TAG_MEDIA_ALBUM, (LPCTSTR)sAlbum
		, TAGTYPE_STRING, TAG_MEDIA_TITLE, (LPCTSTR)sTitle
		, TAGTYPE_UINT32, TAG_MEDIA_LENGTH, uLength
		, TAGTYPE_UINT32, TAG_MEDIA_BITRATE, uBitrate
		, TAGTYPE_STRING, TAG_MEDIA_CODEC, (LPCTSTR)sCodec
		, TAGTYPE_UINT32, TAG_SOURCES, uAvailability);
}

void CSearch::SendFindValue(CContact *pContact, bool bReAskMore)
{
	// Found a Node that we think has contacts closer to our target.
	try {
		// Make sure we are not in the process of stopping.
		if (m_bStoping)
			return;
		CSafeMemFile fileIO(33);
		// The number of returned contacts is based on the type of search.
		uint8 byContactCount = GetRequestContactCount();
		if (bReAskMore)
			if (pRequestedMoreNodesContact == NULL) {
				pRequestedMoreNodesContact = pContact;
				ASSERT(byContactCount == KADEMLIA_FIND_VALUE);
				byContactCount = KADEMLIA_FIND_VALUE_MORE;
			} else
				ASSERT(0);

			if (byContactCount <= 0)
				return;

			fileIO.WriteUInt8(byContactCount);
			// Put the target we want into the packet.
			fileIO.WriteUInt128(m_uTarget);
			// Add the ID of the contact we are contacting for sanity checks on the other end.
			fileIO.WriteUInt128(pContact->GetClientID());
			// Inc the number of packets sent.
			++m_uKadPacketSent;
			// Update the search for the GUI.
			theApp.emuledlg->kademliawnd->searchList->SearchRef(this);

			if (pContact->GetVersion() >= KADEMLIA_VERSION2_47a) {
				// eSE: stamp the ask so ProcessResponse can measure this contact's RTT
				m_mapEseReqSendTick[pContact->GetIPAddress()] = ::GetTickCount();
				m_pLookupHistory->ContactAskedKad(pContact);
				theApp.emuledlg->kademliawnd->UpdateSearchGraph(m_pLookupHistory);
				if (pContact->GetVersion() >= KADEMLIA_VERSION6_49aBETA) {
					CUInt128 uClientID = pContact->GetClientID();
					CKademlia::GetUDPListener()->SendPacket(fileIO, KADEMLIA2_REQ, pContact->GetIPAddress(), pContact->GetUDPPort(), pContact->GetUDPKey(), &uClientID);
				} else {
					CKademlia::GetUDPListener()->SendPacket(fileIO, KADEMLIA2_REQ, pContact->GetIPAddress(), pContact->GetUDPPort(), CKadUDPKey(), NULL);
					ASSERT(CKadUDPKey() == pContact->GetUDPKey());
				}
				if (thePrefs.GetDebugClientKadUDPLevel() > 0) {
					LPCSTR pszOp;
					switch (m_uType) {
					case NODE:
						pszOp = "KADEMLIA2_REQ(NODE)";
						break;
					case NODECOMPLETE:
						pszOp = "KADEMLIA2_REQ(NODECOMPLETE)";
						break;
					case NODESPECIAL:
						pszOp = "KADEMLIA2_REQ(NODESPECIAL)";
						break;
					case NODEFWCHECKUDP:
						pszOp = "KADEMLIA2_REQ(NODEFWCHECKUDP)";
						break;
					case FILE:
						pszOp = "KADEMLIA2_REQ(FILE)";
						break;
					case KEYWORD:
						pszOp = "KADEMLIA2_REQ(KEYWORD)";
						break;
					case STOREFILE:
						pszOp = "KADEMLIA2_REQ(STOREFILE)";
						break;
					case STOREKEYWORD:
						pszOp = "KADEMLIA2_REQ(STOREKEYWORD)";
						break;
					case STORENOTES:
						pszOp = "KADEMLIA2_REQ(STORENOTES)";
						break;
					case NOTES:
						pszOp = "KADEMLIA2_REQ(NOTES)";
						break;
					default:
						pszOp = "KADEMLIA2_REQ()";
					}
					DebugSend(pszOp, pContact->GetIPAddress(), pContact->GetUDPPort());
				}
			} else
				ASSERT(0);
	} catch (CIOException *ex) {
		AddDebugLogLine(false, _T("Exception in CSearch::SendFindValue (IO error(%i))"), ex->m_iCause);
		ex->Delete();
	} catch (...) {
		AddDebugLogLine(false, _T("Exception in CSearch::SendFindValue"));
	}
}

void CSearch::AddFileID(const CUInt128 &uID)
{
	// Add a file hash to the search list.
	// This is used mainly for storing keywords, but was also reused for storing notes.
	m_listFileIDs.Add(uID);
}

void CSearch::SetLiveStreamPublish(const uchar *streamKey, LPCWSTR title, LPCWSTR category,
	LPCWSTR language, uint32 bitrate, uint32 viewerCount, uint32 startedAt, uint16 broadcasterPort,
	uint32 altIP)
{
	if (streamKey == NULL)
		return;

	m_bLiveStreamPublish = true;
	m_uLiveStreamID.SetValueBE(streamKey);
	m_strLiveTitle = title != NULL ? title : L"eSE Live";
	m_strLiveCategory = category != NULL ? category : L"General";
	m_strLiveLanguage = language != NULL ? language : L"";
	m_uLiveBitrate = bitrate;
	m_uLiveViewerCount = viewerCount;
	m_uLiveStartedAt = startedAt;
	m_uLiveBroadcasterPort = broadcasterPort;
	m_uLiveAltIP = altIP;
	m_listFileIDs.RemoveAll();
	m_listFileIDs.Add(m_uLiveStreamID);
}

static INT_PTR GetMetaDataWords(CStringArray &rastrWords, const CString &rstrData)
{
	// Create a list of the 'words' found in 'data'. This is somewhat similar
	// to the 'CSearchManager::GetWords' function which needs to follow some other rules.
	for (int iPos = 0; iPos >= 0;) {
		const CString &strWord(rstrData.Tokenize(g_aszInvKadKeywordChars, iPos));
		if (!strWord.IsEmpty())
			rastrWords.Add(strWord);
	}
	return rastrWords.GetCount();
}

static bool IsRedundantMetaData(const CStringArray &rastrFileNameWords, const CString &rstrMetaData)
{
	// Verify if the meta data string 'rstrMetaData' is already contained within the filename.
	if (rstrMetaData.IsEmpty())
		return true;

	int iMetaDataWords = 0;
	int iFoundInFileName = 0;
	for (int iPos = 0; iPos >= 0;) {
		const CString &strMetaDataWord(rstrMetaData.Tokenize(g_aszInvKadKeywordChars, iPos));
		if (strMetaDataWord.IsEmpty())
			break;
		++iMetaDataWords;
		for (INT_PTR i = rastrFileNameWords.GetCount(); --i >= 0;) {
			// Verified Locale Dependency: Locale dependent string comparison (OK)
			if (rastrFileNameWords[i].CompareNoCase(strMetaDataWord) == 0) {
				++iFoundInFileName;
				break;
			}
		}
		if (iFoundInFileName < iMetaDataWords)
			return false;
	}
	return (iMetaDataWords == 0 || iMetaDataWords == iFoundInFileName);
}

void CSearch::PreparePacketForTags(CByteIO *byIO, CKnownFile *pFile, uint8 byTargetKadVersion)
{
	// We are going to publish a keyword, setup the tag list.
	TagList listTag;
	try {
		if (pFile && byIO) {
			// Name, Size
			listTag.push_back(new CKadTagStr(TAG_FILENAME, pFile->GetFileName()));
			//if (pFile->GetFileSize() > OLD_MAX_EMULE_FILE_SIZE) {
			//	// TODO: As soon as we drop Kad1 support, we should switch to Int64 tags (we could do now already for kad2 nodes only but no advantage in that)
			//	uint64 uSize = (uint64)pFile->GetFileSize();
			//	listTag.push_back(new CKadTagBsob(TAG_FILESIZE, (BYTE*)&uSize, sizeof(uint64)));
			//} else
			listTag.push_back(new CKadTagUInt(TAG_FILESIZE, (uint64)pFile->GetFileSize()));

			listTag.push_back(new CKadTagUInt(TAG_SOURCES, pFile->m_nCompleteSourcesCount));

			if (byTargetKadVersion >= KADEMLIA_VERSION9_50a && pFile->GetFileIdentifier().HasAICHHash())
				listTag.push_back(new CKadTagBsob(TAG_KADAICHHASHPUB, pFile->GetFileIdentifier().GetAICHHash().GetRawHashC()
					, (uint8)CAICHHash::GetHashSize()));

			// eD2K file type (Audio, Video, ...)
			// NOTE: Archives and CD-Images are published with file type "Pro"
			const CString &strED2KFileType(GetED2KFileTypeSearchTerm(GetED2KFileTypeID(pFile->GetFileName())));
			if (!strED2KFileType.IsEmpty())
				listTag.push_back(new CKadTagStr(TAG_FILETYPE, strED2KFileType));

			// file format (filename extension)
			// 21-Sep-2006 []: TAG_FILEFORMAT is no longer explicitly published nor stored as
			// it is already a part of the filename.
			/*LPCTSTR pDot = ::PathFindExtension(pFile->GetFileName());
			if (pDot && pDot[1]) // not empty
				listTag.push_back(new CKadTagStr(TAG_FILEFORMAT, CString(pDot + 1)));
			*/

			// additional meta data (Artist, Album, Codec, Length, ...)
			// only send verified meta data to nodes
			if (pFile->GetMetaDataVer() > 0) {
				static const struct
				{
					uint8 uName;
					uint8 uType;
				}
				_aMetaTags[] =
				{
					{ FT_MEDIA_ARTIST,  TAGTYPE_STRING },
					{ FT_MEDIA_ALBUM,   TAGTYPE_STRING },
					{ FT_MEDIA_TITLE,   TAGTYPE_STRING },
					{ FT_MEDIA_LENGTH,  TAGTYPE_UINT32 },
					{ FT_MEDIA_BITRATE, TAGTYPE_UINT32 },
					{ FT_MEDIA_CODEC,   TAGTYPE_STRING }
				};
				CStringArray astrFileNameWords;
				for (unsigned iIndex = 0; iIndex < _countof(_aMetaTags); ++iIndex) {
					const CTag *pTag = pFile->GetTag(_aMetaTags[iIndex].uName, _aMetaTags[iIndex].uType);
					if (pTag) {
						// skip string tags with empty string values
						if (pTag->IsStr() && pTag->GetStr().IsEmpty())
							continue;
						// skip integer tags with '0' values
						if (pTag->IsInt() && pTag->GetInt() == 0)
							continue;
						char szKadTagName[2];
						szKadTagName[0] = (char)pTag->GetNameID();
						szKadTagName[1] = '\0';
						if (pTag->IsStr()) {
							bool bIsRedundant = false;
							switch (pTag->GetNameID()) {
							case FT_MEDIA_ARTIST:
							case FT_MEDIA_ALBUM:
							case FT_MEDIA_TITLE:
								if (astrFileNameWords.IsEmpty())
									GetMetaDataWords(astrFileNameWords, pFile->GetFileName());
								bIsRedundant = IsRedundantMetaData(astrFileNameWords, pTag->GetStr());
								//if (bIsRedundant)
								//	TRACE(_T("Skipping meta data tag \"%s\" for file \"%s\"\n"), pTag->GetStr(), pFile->GetFileName());
							}
							if (!bIsRedundant)
								listTag.push_back(new CKadTagStr(szKadTagName, pTag->GetStr()));
						} else
							listTag.push_back(new CKadTagUInt(szKadTagName, pTag->GetInt()));
					}
				}
			}
			byIO->WriteTagList(listTag);
		} else {
			//If we get here, bad things happened. Will fix this later if it is a real issue.
			ASSERT(0);
		}
	} catch (CIOException *ex) {
		AddDebugLogLine(false, _T("Exception in CSearch::PreparePacketForTags (IO error(%i))"), ex->m_iCause);
		ex->Delete();
	} catch (...) {
		AddDebugLogLine(false, _T("Exception in CSearch::PreparePacketForTags"));
	}
	deleteTagListEntries(listTag);
}

void CSearch::PrepareLivePacketForTags(CByteIO *byIO) const
{
	TagList listTag;
	try {
		if (byIO) {
			uchar streamKey[MDX_DIGEST_SIZE];
			m_uLiveStreamID.ToByteArray(streamKey);

			CStringW title(m_strLiveTitle);
			title.Trim();
			if (title.IsEmpty())
				title = L"eSE Live";

			// H8 — TAG_FILENAME ("eselive <title>") and TAG_FILETYPE
			// ("eSELive") are the only tags in this publish that are
			// human-readable AND understood by a vanilla 0.70b parser.
			// In the clean namespace (MD4("\x00eSE\x00" || utf8(kw))),
			// no legacy client can reach this entry, so they're pure
			// title-leak surface for any eSE-aware crawler that learns
			// the prefix. eSE viewers use TAG_ESE_LIVE_TITLE /
			// TAG_ESE_LIVE_MARKER instead, which non-eSE parsers don't
			// recognise. TAG_FILESIZE stays at 1 because some Kad
			// implementations sanity-check filesize > 0 before keeping
			// the entry.
			//
			// H8 fix (2026-06-11): the clean publish must still carry a
			// TAG_FILENAME — every holder (upstream 0.70b's
			// CIndexed::AddKeyword included) drops keyword entries whose
			// filename is empty, so the original "omit it entirely"
			// design made clean publishes silently unstorable anywhere.
			// A CONSTANT name keeps the holder check happy without
			// leaking the title: all per-stream data stays in the
			// TAG_ESE_LIVE_* tags. It also keeps v8.1 viewers working,
			// whose result parser drops nameless entries before the
			// live dispatch.
			if (m_bLivePublishCleanNs) {
				listTag.push_back(new CKadTagStr(TAG_FILENAME, ESE_LIVE_CLEAN_NS_FILENAME));
			} else {
				CStringW fileName;
				fileName.Format(L"eselive %ls", (LPCWSTR)title);
				listTag.push_back(new CKadTagStr(TAG_FILENAME, fileName));
			}
			listTag.push_back(new CKadTagUInt(TAG_FILESIZE, 1));
			if (!m_bLivePublishCleanNs) {
				listTag.push_back(new CKadTagStr(TAG_FILETYPE, L"eSELive"));
			}
			listTag.push_back(new CKadTagUInt(TAG_ESE_LIVE_MARKER, 1));
			listTag.push_back(new CKadTagStr(TAG_ESE_LIVE_STREAM_KEY, EseLiveKeyToHexW(streamKey)));
			listTag.push_back(new CKadTagStr(TAG_ESE_LIVE_TITLE, title));
			listTag.push_back(new CKadTagStr(TAG_ESE_LIVE_CATEGORY, m_strLiveCategory));
			listTag.push_back(new CKadTagStr(TAG_ESE_LIVE_LANGUAGE, m_strLiveLanguage));
			listTag.push_back(new CKadTagUInt(TAG_ESE_LIVE_BITRATE, m_uLiveBitrate));
			listTag.push_back(new CKadTagUInt(TAG_ESE_LIVE_VIEWERS, m_uLiveViewerCount));
			listTag.push_back(new CKadTagUInt(TAG_ESE_LIVE_STARTED_AT, m_uLiveStartedAt));
			listTag.push_back(new CKadTagUInt(TAG_SOURCEPORT, m_uLiveBroadcasterPort));
			// eSE Live: ship our public IP IN the publish itself. The holder code
			// at KademliaUDPListener.cpp:1341 also tries to derive TAG_SOURCEIP
			// from the UDP packet source, but that only works when the holder is
			// running this fork. Upstream-eMule holders store the publish without
			// the IP tag — viewers then read uLiveIP=0 (the default) and our
			// "REJECTED — invalid endpoint" filter at LiveKadBridge.cpp:523 drops
			// every result. Adding the tag explicitly makes the publish
			// self-contained regardless of holder version.
			//
			// Byte order — IMPORTANT: theApp.GetPublicIP() returns HOST byte
			// order (it does ntohl internally). Both the receiver's `uLiveIP =
			// cTag.GetInt()` at Search.cpp:1200 and the final `ipstr(uLiveIP)`
			// display in LiveKadBridge.cpp:539 ALSO expect host byte order on
			// Intel. Storing the value directly (no htonl) keeps it consistent
			// end-to-end. The line-1341 holder code does `htonl(uIP)` because
			// IT receives uIP in network byte order from the UDP packet, so
			// the byte-swap there gets the value into host order too.
			uint32 ourPublicIP = theApp.GetPublicIP();
			if (ourPublicIP != 0) {
				listTag.push_back(new CKadTagUInt(TAG_SOURCEIP, ourPublicIP));
			} else {
				// One-shot warning per publish so it's visible when a broadcast
				// goes out without a usable IP (the entry will still publish
				// fine and the holder may fill TAG_SOURCEIP from the UDP source,
				// but if it doesn't, viewers reject the entry).
				AddDebugLogLine(false,
					_T("eSE Live: publishing without TAG_SOURCEIP — public IP not yet known"));
			}
			// NAT-reach (2026-06): ship the overlay/alt IP (Tailscale 100.64/10
			// or INI override) when the publisher has one. Viewers dial both
			// endpoints; the overlay one works across home NAT for peers on
			// the same overlay network. Additive tag — old parsers ignore it.
			if (m_uLiveAltIP != 0)
				listTag.push_back(new CKadTagUInt(TAG_ESE_LIVE_ALTIP, m_uLiveAltIP));
			// NAT-reach (2026-06): ALWAYS include TAG_SOURCEUPORT in live
			// publishes. The stock-eMule conditional (`only when not using the
			// extern Kad port`) made sense for SOURCE entries, where the reader
			// can derive the UDP endpoint from the holder contact — but a live
			// entry is read by viewers who have no other way to learn the
			// broadcaster's Kad UDP port. Publishing with uport=0 disabled the
			// A.4 UDP hole-punch fallback entirely (the "uport:0" bug): NATed
			// broadcasters were unreachable even though the punch path existed.
			// Prefer the externally-visible port when the prefs say to use it.
			{
				uint16 uLiveKadUDP = CKademlia::GetPrefs()->GetUseExternKadPort()
					? CKademlia::GetPrefs()->GetExternalKadPort() : (uint16)0;
				if (uLiveKadUDP == 0)
					uLiveKadUDP = CKademlia::GetPrefs()->GetInternKadPort();
				if (uLiveKadUDP != 0)
					listTag.push_back(new CKadTagUInt16(TAG_SOURCEUPORT, uLiveKadUDP));
			}

			byIO->WriteTagList(listTag);
		} else
			ASSERT(0);
	} catch (CIOException *ex) {
		AddDebugLogLine(false, _T("Exception in CSearch::PrepareLivePacketForTags (IO error(%i))"), ex->m_iCause);
		ex->Delete();
	} catch (...) {
		AddDebugLogLine(false, _T("Exception in CSearch::PrepareLivePacketForTags"));
	}
	deleteTagListEntries(listTag);
}

uint32 CSearch::GetNodeLoad() const
{
	// Node load is the average of all node load responses.
	return m_uTotalLoadResponses ? m_uTotalLoad / m_uTotalLoadResponses : 0;
}

void CSearch::SetSearchType(uint32 uVal)
{
	m_uType = uVal;
	m_pLookupHistory->SetSearchType(uVal);
}

uint32 CSearch::GetAnswers() const
{
	if (m_listFileIDs.IsEmpty())
		return m_uAnswers;
	// If we sent more then one packet per node, we have to average the answers for the real count.
	return (uint32)(m_uAnswers / ((m_listFileIDs.GetSize() + 49) / 50));
}

void CSearch::UpdateNodeLoad(uint8 uLoad)
{
	// Since all nodes do not return a load value, keep track of total responses and total load.
	m_uTotalLoad += uLoad;
	++m_uTotalLoadResponses;
}

const CStringW& Kademlia::CSearch::GetGUIName() const
{
	return m_pLookupHistory->GetGUIName();
}

void Kademlia::CSearch::SetGUIName(LPCWSTR sGUIName)
{
	m_pLookupHistory->SetGUIName(sGUIName);
}

void CSearch::SetSearchTermData(uint32 uSearchTermDataSize, LPBYTE pucSearchTermsData)
{
	m_uSearchTermsDataSize = uSearchTermDataSize;
	m_pucSearchTermsData = new BYTE[uSearchTermDataSize];
	memcpy(m_pucSearchTermsData, pucSearchTermsData, uSearchTermDataSize);
}

CString CSearch::GetTypeName(uint32 uType)
{
	UINT uid;
	switch (uType) {
	case CSearch::FILE:
		uid = IDS_KAD_SEARCHSRC;
		break;
	case CSearch::KEYWORD:
		uid = IDS_KAD_SEARCHKW;
		break;
	case CSearch::NODE:
	case CSearch::NODECOMPLETE:
	case CSearch::NODESPECIAL:
	case CSearch::NODEFWCHECKUDP:
		uid = IDS_KAD_NODE;
		break;
	case CSearch::STOREFILE:
		uid = IDS_KAD_STOREFILE;
		break;
	case CSearch::STOREKEYWORD:
		uid = IDS_KAD_STOREKW;
		break;
	case CSearch::FINDBUDDY:
		uid = IDS_FINDBUDDY;
		break;
	case CSearch::STORENOTES:
		uid = IDS_STORENOTES;
		break;
	case CSearch::NOTES:
		uid = IDS_NOTES;
		break;
	default:
		uid = IDS_KAD_UNKNOWN;
	}
	return GetResString(uid);
}

uint8 CSearch::GetRequestContactCount() const
{
	// Returns the amount of contacts we request on routing queries based on the search type
	switch (m_uType) {
	case NODE:
	case NODECOMPLETE:
	case NODESPECIAL:
	case NODEFWCHECKUDP:
		return KADEMLIA_FIND_NODE;
	case FILE:
	case KEYWORD:
	case FINDSOURCE:
	case NOTES:
		return KADEMLIA_FIND_VALUE;
	case FINDBUDDY:
	case STOREFILE:
	case STOREKEYWORD:
	case STORENOTES:
		return KADEMLIA_STORE;
	default:
		DebugLogError(LOG_DEFAULT, _T("Invalid search type. (CSearch::GetRequestContactCount())"));
		ASSERT(0);
	}
	return 0;
}
