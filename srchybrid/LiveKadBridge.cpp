//this file is part of eMule
// eSE — Kad Bridge for Live Stream Discovery Implementation
#include "stdafx.h"
#include "LiveKadBridge.h"
#include "LiveStreamManager.h"  // For KadDebugSnapshot struct
#include "emule.h"
#include "opcodes.h"
#include "OtherFunctions.h"
#include "Log.h"
#include "Preferences.h"
#include "md4.h"
#include "LiveStreamManager.h"
#include "IPFilter.h"
#include "kademlia/kademlia/Kademlia.h"
#include "kademlia/kademlia/Search.h"
#include "kademlia/kademlia/SearchManager.h"
#include "kademlia/kademlia/Tag.h"
#include "kademlia/kademlia/Defines.h"
#include "kademlia/kademlia/prefs.h"
#include "kademlia/utils/UInt128.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

// Constants
#define ESE_KAD_REPUBLISH_INTERVAL  ESE_LIVE_KAD_PUBLISH_INTERVAL
#define ESE_KAD_PRUNE_INTERVAL      (60 * 1000)        // 1 minute
#define ESE_KAD_ENTRY_TTL           (10 * 60 * 1000)   // 10 minutes
#define ESE_KAD_SEARCH_COOLDOWN     (30 * 1000)        // 30 seconds

// Tag names for live stream metadata in Kad
// Using non-conflicting custom tag IDs above 0xF0
#define TAG_LIVE_STREAM_KEY     0xF1
#define TAG_LIVE_TITLE          0xF2
#define TAG_LIVE_CATEGORY       0xF3
#define TAG_LIVE_BITRATE        0xF4
#define TAG_LIVE_VIEWERS        0xF5
#define TAG_LIVE_STARTED_AT     0xF6
#define TAG_LIVE_LANGUAGE       0xF7
#define TAG_LIVE_MARKER         0xF8   // Identifies this as a live stream entry


CLiveKadBridge::CLiveKadBridge()
    : m_bPublished(false)
    , m_dwLastPublishTime(0)
    , m_dwLastSearchTime(0)
    , m_dwLastPruneTime(0)
    , m_dwLastResultIP(0)
    , m_wLastResultPort(0)
    , m_dwLastResultTime(0)
{
}

CLiveKadBridge::~CLiveKadBridge()
{
    m_streamDirectory.RemoveAll();
}


// ============================================================
// PUBLISHING (Broadcaster side)
// ============================================================

bool CLiveKadBridge::PublishStream(const LiveStreamInfo& info)
{
    CSingleLock lock(&m_lock, TRUE);

#if 0
        AddLogLine(false, _T("eSE Kad: Cannot publish — Kad not connected"));

#endif
    LiveStreamInfo previousInfo = m_publishedInfo;
    bool wasSameStream = m_bPublished && memcmp(previousInfo.streamKey, info.streamKey, 16) == 0;
    m_publishedInfo = info;
    m_bPublished = true;
    if (!wasSameStream)
        m_dwLastPublishTime = 0;  // Force immediate publish when Kad is available

    // Add to our own directory
    LiveStreamEntry entry;
    memcpy(entry.streamKey, info.streamKey, 16);
    entry.title = info.title;
    entry.category = info.category;
    entry.language = info.language;
    entry.bitrate = info.bitrate;
    entry.viewerCount = info.viewerCount;
    entry.broadcasterIP = 0;  // Will be filled by Kad
    entry.broadcasterPort = thePrefs.GetPort();
    entry.lastSeen = GetTickCount();
    entry.startedAt = info.startedAt;
    entry.isOwnStream = true;

    CString strKey = StreamKeyToString(info.streamKey);
    m_streamDirectory[strKey] = entry;

    if (!Kademlia::CKademlia::IsConnected()) {
        AddLogLine(false, _T("eSE Kad: Stream \"%s\" queued; Kad is not connected yet"),
            (LPCTSTR)info.title);
        return false;
    }

    AddLogLine(true, _T("eSE Kad: Publishing stream \"%s\" to Kad DHT"),
        (LPCTSTR)info.title);

    return true;
}

void CLiveKadBridge::UnpublishStream(const uchar* streamKey)
{
    CSingleLock lock(&m_lock, TRUE);

    CString strKey = StreamKeyToString(streamKey);
    m_streamDirectory.RemoveKey(strKey);
    m_bPublished = false;

    AddLogLine(true, _T("eSE Kad: Stream unpublished from directory"));
}

void CLiveKadBridge::RepublishIfNeeded()
{
    CSingleLock lock(&m_lock, TRUE);

    if (!m_bPublished) return;
    if (!Kademlia::CKademlia::IsConnected()) return;

    DWORD now = GetTickCount();
    if (now - m_dwLastPublishTime < ESE_KAD_REPUBLISH_INTERVAL) return;

    // === Phase 1 KAD-1: Multi-keyword publishing ===
    // We publish under multiple keywords to maximize discoverability:
    //   1. "eselive" — global browse keyword (always)
    //   2. First significant title word (if >= 3 chars)
    //   3. Category keyword (if non-empty and >= 3 chars)
    //   4. Language keyword (if non-empty and >= 2 chars, prefixed "lang:")

    CString titleLower(m_publishedInfo.title);
    titleLower.MakeLower();
    titleLower.Trim();
    // Fix 3: If title is empty, use fallback. "eselive" MUST always be published.
    if (titleLower.IsEmpty())
        titleLower = _T("ese live");

    // Extract first significant keyword (>= 3 chars)
    CString firstKeyword;
    int pos = 0;
    while (pos < titleLower.GetLength()) {
        int end = titleLower.Find(_T(' '), pos);
        if (end < 0) end = titleLower.GetLength();
        CString word = titleLower.Mid(pos, end - pos);
        word.Trim();
        if (word.GetLength() >= 3) {
            firstKeyword = word;
            break;
        }
        pos = end + 1;
    }
    if (firstKeyword.IsEmpty()) firstKeyword = titleLower;

    // Collect all keywords to publish under (deduplicated)
    CStringArray keywords;
    keywords.Add(_T("eselive"));  // Always publish under global keyword

    if (!firstKeyword.IsEmpty() && firstKeyword != _T("eselive"))
        keywords.Add(firstKeyword);

    // Category keyword (Phase 1 KAD-1)
    CString catLower(m_publishedInfo.category);
    catLower.MakeLower();
    catLower.Trim();
    if (catLower.GetLength() >= 3 && catLower != _T("eselive") && catLower != firstKeyword)
        keywords.Add(catLower);

    // Language keyword (Phase 1 KAD-1) — prefixed to avoid collisions
    CString langLower(m_publishedInfo.language);
    langLower.MakeLower();
    langLower.Trim();
    if (langLower.GetLength() >= 2) {
        CString langKeyword;
        langKeyword.Format(_T("eselang:%s"), (LPCTSTR)langLower);
        keywords.Add(langKeyword);
    }

    // Publish under each keyword
    int publishCount = 0;
    for (INT_PTR i = 0; i < keywords.GetCount(); i++) {
        Kademlia::CUInt128 uTarget;
        Kademlia::CKadTagValueString wstrKw(keywords[i]);
        KadGetKeywordHash(wstrKw, &uTarget);

        Kademlia::CSearch* pSearch = Kademlia::CSearchManager::PrepareLookup(
            Kademlia::CSearch::STOREKEYWORD, false, uTarget);

        if (pSearch) {
            CString guiName;
            guiName.Format(_T("eSE Live: %s"), (LPCTSTR)keywords[i]);
            pSearch->SetGUIName(guiName);
            pSearch->SetLiveStreamPublish(m_publishedInfo.streamKey,
                m_publishedInfo.title, m_publishedInfo.category, m_publishedInfo.language,
                m_publishedInfo.bitrate, m_publishedInfo.viewerCount,
                m_publishedInfo.startedAt, thePrefs.GetPort());
            Kademlia::CSearchManager::StartSearch(pSearch);
            publishCount++;
        }
    }

    AddLogLine(false, _T("eSE Kad: Published stream under %d keywords (eselive + %d extra)"),
        publishCount, publishCount - 1);

    m_dwLastPublishTime = now;

    // Update viewer count in our entry
    CString strKey = StreamKeyToString(m_publishedInfo.streamKey);
    LiveStreamEntry entry;
    if (m_streamDirectory.Lookup(strKey, entry)) {
        entry.viewerCount = m_publishedInfo.viewerCount;
        entry.lastSeen = now;
        m_streamDirectory[strKey] = entry;
    }
}


// ============================================================
// DISCOVERY (Viewer side)
// ============================================================

bool CLiveKadBridge::SearchStreams(const CString& keyword)
{
    CSingleLock lock(&m_lock, TRUE);

    if (!Kademlia::CKademlia::IsConnected()) {
        AddLogLine(false, _T("eSE Kad: Cannot search — Kad not connected"));
        return false;
    }

    // Use "eselive" as the default search keyword to find all streams
    CString searchWord = keyword.IsEmpty() ? _T("eselive") : keyword;
    searchWord.MakeLower();
    searchWord.Trim();

    DWORD now = GetTickCount();
    if (now - m_dwLastSearchTime < ESE_KAD_SEARCH_COOLDOWN
        && searchWord.CompareNoCase(m_strLastSearchKeyword) == 0)
    {
        AddLogLine(false, _T("eSE Kad: Search cooldown active, try again shortly"));
        return false;
    }

    Kademlia::CUInt128 uTarget;
    Kademlia::CKadTagValueString wstrKeyword(searchWord);
    KadGetKeywordHash(wstrKeyword, &uTarget);

    // Start a KEYWORD search
    Kademlia::CSearch* pSearch = Kademlia::CSearchManager::PrepareLookup(
        Kademlia::CSearch::KEYWORD, true, uTarget);

    if (pSearch) {
        // Phase 0: Instrument search counter (via parent manager)
        if (theApp.liveStreamManager != NULL)
            InterlockedIncrement(&theApp.liveStreamManager->GetCountersMut().kadSearches);

        AddLogLine(true, _T("eSE Kad: Searching for live streams (keyword=\"%s\", SearchID=%u)"),
            (LPCTSTR)searchWord, pSearch->GetSearchID());
        m_dwLastSearchTime = now;
        m_strLastSearchKeyword = searchWord;
        return true;
    }

    AddLogLine(false, _T("eSE Kad: Search already in progress for \"%s\""),
        (LPCTSTR)searchWord);
    return false;
}

void CLiveKadBridge::GetKnownStreams(CArray<LiveStreamEntry>& outList) const
{
    CSingleLock lock(&m_lock, TRUE);

    outList.RemoveAll();
    CString key;
    LiveStreamEntry entry;
    POSITION pos = m_streamDirectory.GetStartPosition();
    while (pos) {
        m_streamDirectory.GetNextAssoc(pos, key, entry);
        outList.Add(entry);
    }
}

bool CLiveKadBridge::GetStreamInfo(const uchar* streamKey, LiveStreamEntry& outEntry) const
{
    CSingleLock lock(&m_lock, TRUE);

    CString strKey = StreamKeyToString(streamKey);
    return m_streamDirectory.Lookup(strKey, outEntry) != FALSE;
}


// ============================================================
// NETWORK CALLBACKS
// ============================================================

void CLiveKadBridge::OnKadSearchResult(const uchar* streamKey,
    const CString& title, const CString& category,
    uint32 broadcasterIP, uint16 broadcasterPort,
    uint16 bitrate, uint32 viewerCount)
{
    CSingleLock lock(&m_lock, TRUE);

    // === Phase 1 KAD-3: Strict IP/port validation ===
    // Reject results with missing endpoint data — they can't be connected to.
    if (broadcasterIP == 0 || broadcasterPort == 0) {
        AddLogLine(false, _T("eSE Kad: REJECTED result — invalid endpoint (IP=%u, port=%u, title=\"%s\")"),
            broadcasterIP, broadcasterPort, (LPCTSTR)title);
        if (theApp.liveStreamManager != NULL)
            InterlockedIncrement(&theApp.liveStreamManager->GetCountersMut().kadResultsRejected);
        return;
    }

    // === Fix 15 (BAJA): Force LAN rejection for Kad public DHT ===
    // IsGoodIPPort() delegates to IsGoodIP() which respects FilterLANIPs() pref.
    // For Kad-discovered broadcasters, LAN IPs (10.x, 192.168.x, 172.16-31.x)
    // must ALWAYS be rejected since Kad is a public network.
    // Use IsGoodIP(ip, true) to force the LAN check regardless of preferences.
    if (!IsGoodIP(broadcasterIP, true) || broadcasterPort == 0) {
        AddLogLine(false, _T("eSE Kad: REJECTED result — non-routable IP (%s:%u, title=\"%s\")"),
            (LPCTSTR)ipstr(broadcasterIP), broadcasterPort, (LPCTSTR)title);
        if (theApp.liveStreamManager != NULL)
            InterlockedIncrement(&theApp.liveStreamManager->GetCountersMut().kadResultsRejected);
        return;
    }

    // === Phase 1 KAD-4: IPFilter check ===
    // Reject IPs blocked by the user's IPFilter configuration.
    if (theApp.ipfilter->IsFiltered(broadcasterIP)) {
        AddLogLine(false, _T("eSE Kad: REJECTED result — IP filtered (%s, title=\"%s\")"),
            (LPCTSTR)ipstr(broadcasterIP), (LPCTSTR)title);
        if (theApp.liveStreamManager != NULL)
            InterlockedIncrement(&theApp.liveStreamManager->GetCountersMut().kadResultsRejected);
        return;
    }

    // === Phase 1 KAD-4: Self-connection guard ===
    // Don't try to connect to our own broadcast.
    if (m_bPublished && memcmp(streamKey, m_publishedInfo.streamKey, 16) == 0) {
        // This is our own stream echoed back; update viewer count only
        CString strKey = StreamKeyToString(streamKey);
        LiveStreamEntry entry;
        if (m_streamDirectory.Lookup(strKey, entry)) {
            entry.viewerCount = viewerCount;
            entry.lastSeen = GetTickCount();
            m_streamDirectory[strKey] = entry;
        }
        return;  // Don't try to connect to ourselves
    }

    CString strKey = StreamKeyToString(streamKey);

    LiveStreamEntry entry;
    if (m_streamDirectory.Lookup(strKey, entry)) {
        // Update existing entry
        entry.viewerCount = viewerCount;
        entry.lastSeen = GetTickCount();
        if (!title.IsEmpty()) entry.title = title;
    } else {
        // New stream discovered
        memcpy(entry.streamKey, streamKey, 16);
        entry.title = title;
        entry.category = category;
        entry.language = _T("??"); // Will be updated when language tag arrives
        entry.bitrate = bitrate;
        entry.viewerCount = viewerCount;
        entry.broadcasterIP = broadcasterIP;
        entry.broadcasterPort = broadcasterPort;
        entry.lastSeen = GetTickCount();
        entry.startedAt = (uint32)time(NULL);
        entry.isOwnStream = false;

        AddLogLine(false, _T("eSE Kad: Discovered stream \"%s\" from %s:%u (%u viewers, %ukbps)"),
            (LPCTSTR)title, (LPCTSTR)ipstr(broadcasterIP), broadcasterPort,
            viewerCount, bitrate);
    }

    m_streamDirectory[strKey] = entry;

    // Phase 0: Track last discovery result for /api/live/debug
    m_dwLastResultIP   = broadcasterIP;
    m_wLastResultPort  = broadcasterPort;
    m_dwLastResultTime = GetTickCount();

    // Phase 0: Count accepted result
    if (theApp.liveStreamManager != NULL)
        InterlockedIncrement(&theApp.liveStreamManager->GetCountersMut().kadResultsAccepted);

    lock.Unlock();

    // Phase 1 KAD-5: Connect to discovered source
    if (theApp.liveStreamManager != NULL)
        theApp.liveStreamManager->TryConnectToStreamSource(streamKey, broadcasterIP, broadcasterPort);
}


// ============================================================
// PERIODIC MAINTENANCE
// ============================================================

void CLiveKadBridge::Process()
{
    DWORD now = GetTickCount();

    // Republish if broadcasting
    if (m_bPublished) {
        RepublishIfNeeded();
    }

    // Prune stale entries
    if (now - m_dwLastPruneTime >= ESE_KAD_PRUNE_INTERVAL) {
        PruneStaleEntries();
        m_dwLastPruneTime = now;
    }
}

void CLiveKadBridge::PruneStaleEntries()
{
    CSingleLock lock(&m_lock, TRUE);

    DWORD now = GetTickCount();
    CStringArray toRemove;

    CString key;
    LiveStreamEntry entry;
    POSITION pos = m_streamDirectory.GetStartPosition();
    while (pos) {
        m_streamDirectory.GetNextAssoc(pos, key, entry);
        // Don't prune our own stream
        if (entry.isOwnStream) continue;
        // Prune if not seen in TTL
        if (now - entry.lastSeen > ESE_KAD_ENTRY_TTL) {
            toRemove.Add(key);
        }
    }

    for (INT_PTR i = 0; i < toRemove.GetCount(); i++) {
        m_streamDirectory.RemoveKey(toRemove[i]);
    }

    if (toRemove.GetCount() > 0) {
        AddLogLine(false, _T("eSE Kad: Pruned %d stale stream entries"),
            (int)toRemove.GetCount());
    }
}

int CLiveKadBridge::GetDirectoryCount() const
{
    CSingleLock lock(&m_lock, TRUE);
    return (int)m_streamDirectory.GetCount();
}


// ============================================================
// HELPERS
// ============================================================

CString CLiveKadBridge::StreamKeyToString(const uchar* streamKey) const
{
    CString str;
    for (int i = 0; i < 16; i++)
        str.AppendFormat(_T("%02X"), streamKey[i]);
    return str;
}

void CLiveKadBridge::EncodeStreamTags(const LiveStreamInfo& info, CByteArray& outData) const
{
    // Encode stream metadata into a byte array for Kad publishing
    // This follows the Kad tag format but with custom tag IDs
    // Format: TAG_LIVE_MARKER=1 + TAG_LIVE_TITLE=string + TAG_LIVE_CATEGORY=string
    //         + TAG_LIVE_BITRATE=uint16 + TAG_LIVE_VIEWERS=uint32

    outData.RemoveAll();

    // For now this is unused — Kad keyword store uses the existing
    // CSearch::STOREKEYWORD mechanism with file metadata tags.
    // When we integrate deeper with Kad in Phase 3b, we'll use
    // custom tags for richer stream metadata.
}


// ============================================================
// THREAD-SAFE DEBUG SNAPSHOT (Fix 6)
// ============================================================

KadDebugSnapshot CLiveKadBridge::BuildDebugKadSnapshot() const
{
    CSingleLock lock(&m_lock, TRUE);

    KadDebugSnapshot snap;
    snap.kadConnected   = Kademlia::CKademlia::IsConnected();
    snap.knownStreams   = (int)m_streamDirectory.GetCount();
    snap.lastPublishTime = m_dwLastPublishTime;
    snap.lastSearchTime  = m_dwLastSearchTime;
    snap.lastResultTime  = m_dwLastResultTime;
    snap.lastResultIP    = m_dwLastResultIP;
    snap.lastResultPort  = m_wLastResultPort;
    return snap;
}
