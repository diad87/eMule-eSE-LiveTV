//this file is part of eMule
// eSE — Kad Bridge for Live Stream Discovery Implementation
#include "stdafx.h"
#include "LiveKadBridge.h"
#include "LiveDebugLog.h"
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
// DISC-S02: aggressive freshness. A broadcaster republishes every 60 s
// (ESE_KAD_REPUBLISH_INTERVAL), so any entry older than 180 s without a
// fresh sighting is almost certainly a fantasma — evict locally.
#define ESE_KAD_PRUNE_INTERVAL      (30 * 1000)        // 30 s
#define ESE_KAD_ENTRY_TTL           (180 * 1000)       // 3 min (was 10)
// Phase 2 LAT-1: adaptive search cooldown.
// The viewer needs to retry quickly while it has no results yet (Kad propagation
// can take 1-5 minutes). Once results start coming in, we relax to 30 s to avoid
// hammering the DHT.
#define ESE_KAD_SEARCH_COOLDOWN_FAST (5 * 1000)        // 5 s while empty
#define ESE_KAD_SEARCH_COOLDOWN_SLOW (30 * 1000)       // 30 s once we have results
#define ESE_KAD_SEARCH_COOLDOWN     ESE_KAD_SEARCH_COOLDOWN_SLOW  // legacy alias

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
    , m_nPublishBurstCount(0)
    , m_dwBurstStartTime(0)
    , m_bDeferredFirstPublish(false)        // DISC-S03
    , m_bKadWasConnectedLastTick(false)     // DISC-S03
    , m_nSearchTokens(10)                   // DISC-S08
    , m_dwLastSearchTokenRefill(0)          // DISC-S08
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
    if (!wasSameStream) {
        m_dwLastPublishTime = 0;  // Force immediate publish when Kad is available
        // Phase 2 LAT-2: arm accelerated publish burst for the new stream.
        m_nPublishBurstCount = 0;
        m_dwBurstStartTime   = GetTickCount();
    }

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
        CLiveDebugLog::Get().Append("KAD",
            "PublishStream QUEUED \"%S\" — Kad not connected", (LPCWSTR)info.title);
        // DISC-S03: arm the deferred-publish flag so Process() forces an
        // immediate burst when Kad transitions to connected.
        m_bDeferredFirstPublish = true;
        return false;
    }

    AddLogLine(true, _T("eSE Kad: Publishing stream \"%s\" to Kad DHT"),
        (LPCTSTR)info.title);
    CLiveDebugLog::Get().Append("KAD",
        "PublishStream OK \"%S\" port=%u",
        (LPCWSTR)info.title, (unsigned)thePrefs.GetPort());

    return true;
}

void CLiveKadBridge::UnpublishStream(const uchar* streamKey)
{
    CSingleLock lock(&m_lock, TRUE);

    // DISC-S01: publish a TOMBSTONE before clearing local state. Other Kad
    // nodes still hold our publish until their own TTL expires (~10 min);
    // republishing with bitrate=0 lets viewers identify the entry as
    // "broadcaster gone" and skip it. OnKadSearchResult treats bitrate==0
    // as a deprecation marker.
    if (m_bPublished && Kademlia::CKademlia::IsConnected()) {
        CString hashKeyword(_T("livehash:"));
        for (int i = 0; i < 16; ++i) {
            CString h; h.Format(_T("%02x"), streamKey[i]);
            hashKeyword += h;
        }
        Kademlia::CUInt128 uTarget;
        Kademlia::CKadTagValueString wstrKw(hashKeyword);
        KadGetKeywordHash(wstrKw, &uTarget);
        Kademlia::CSearch* pSearch = Kademlia::CSearchManager::PrepareLookup(
            Kademlia::CSearch::STOREKEYWORD, false, uTarget);
        if (pSearch) {
            pSearch->SetGUIName(_T("eSE Live tombstone"));
            pSearch->SetLiveStreamPublish(streamKey,
                m_publishedInfo.title, m_publishedInfo.category, m_publishedInfo.language,
                /*bitrate=*/0,         // sentinel: broadcaster gone
                /*viewerCount=*/0,
                m_publishedInfo.startedAt, thePrefs.GetPort());
            Kademlia::CSearchManager::StartSearch(pSearch);
            AddLogLine(false, _T("eSE Kad: Stream tombstone published (bitrate=0)"));
        }
    }

    CString strKey = StreamKeyToString(streamKey);
    m_streamDirectory.RemoveKey(strKey);
    m_bPublished = false;
    // Phase 2 LAT-2: reset burst state so next StartBroadcast re-arms.
    m_nPublishBurstCount = 0;
    m_dwBurstStartTime   = 0;

    AddLogLine(true, _T("eSE Kad: Stream unpublished from directory"));
}

bool CLiveKadBridge::PublishTombstoneFor(const uchar* streamKey)
{
    // DISC-S04: stateless tombstone publish, used at startup to evict a
    // ghost left by a previous crashed session.
    CSingleLock lock(&m_lock, TRUE);
    if (!Kademlia::CKademlia::IsConnected()) return false;

    CString hashKeyword(_T("livehash:"));
    for (int i = 0; i < 16; ++i) {
        CString h; h.Format(_T("%02x"), streamKey[i]);
        hashKeyword += h;
    }
    Kademlia::CUInt128 uTarget;
    Kademlia::CKadTagValueString wstrKw(hashKeyword);
    KadGetKeywordHash(wstrKw, &uTarget);
    Kademlia::CSearch* pSearch = Kademlia::CSearchManager::PrepareLookup(
        Kademlia::CSearch::STOREKEYWORD, false, uTarget);
    if (!pSearch) return false;
    pSearch->SetGUIName(_T("eSE Live ghost-tombstone"));
    pSearch->SetLiveStreamPublish(streamKey, L"", L"", L"",
        /*bitrate=*/0, /*viewerCount=*/0,
        /*startedAt=*/(uint32)time(NULL), thePrefs.GetPort());
    Kademlia::CSearchManager::StartSearch(pSearch);
    AddLogLine(false, _T("eSE Kad: Ghost tombstone published for streamKey %s"),
        (LPCTSTR)hashKeyword);
    return true;
}

bool CLiveKadBridge::PublishAsRelay(const uchar* streamKey, LPCWSTR title,
    LPCWSTR category, LPCWSTR language, uint16 bitrate)
{
    // V2-S17 — Anonymous relay/secondary-source publish.
    // Only publishes under livehash:HASH (not eselive/title/category) so the
    // global directory does not fill up with duplicate stream entries; only
    // joiners that explicitly look up the streamKey via JoinStream find us.
    CSingleLock lock(&m_lock, TRUE);
    if (!Kademlia::CKademlia::IsConnected()) return false;

    CString hashKeyword(_T("livehash:"));
    for (int i = 0; i < 16; ++i) {
        CString byteHex; byteHex.Format(_T("%02x"), streamKey[i]);
        hashKeyword += byteHex;
    }

    Kademlia::CUInt128 uTarget;
    Kademlia::CKadTagValueString wstrKw(hashKeyword);
    KadGetKeywordHash(wstrKw, &uTarget);

    Kademlia::CSearch* pSearch = Kademlia::CSearchManager::PrepareLookup(
        Kademlia::CSearch::STOREKEYWORD, false, uTarget);
    if (!pSearch) return false;

    CString guiName;
    guiName.Format(_T("eSE Live (relay): %s"), (LPCTSTR)hashKeyword);
    pSearch->SetGUIName(guiName);
    pSearch->SetLiveStreamPublish(streamKey, title ? title : L"",
        category ? category : L"", language ? language : L"",
        (uint32)bitrate, /*viewerCount*/ 0,
        /*startedAt*/ (uint32)time(NULL), thePrefs.GetPort());
    Kademlia::CSearchManager::StartSearch(pSearch);

    AddLogLine(false, _T("eSE Kad: Secondary-source publish under %s"),
        (LPCTSTR)hashKeyword);
    return true;
}

void CLiveKadBridge::RepublishIfNeeded()
{
    CSingleLock lock(&m_lock, TRUE);

    if (!m_bPublished) return;
    if (!Kademlia::CKademlia::IsConnected()) return;

    DWORD now = GetTickCount();
    // Phase 2 LAT-2: accelerated publish for the first 20 seconds.
    // Schedule:  t=0  → first publish (forced by m_dwLastPublishTime=0)
    //            t=5  → second publish (burst #1)
    //            t=20 → third publish  (burst #2)
    //            t≥80 → 60 s steady state
    DWORD interval = ESE_KAD_REPUBLISH_INTERVAL;  // default 60 s
    if (m_nPublishBurstCount == 0)      interval = 5  * 1000;   // first follow-up
    else if (m_nPublishBurstCount == 1) interval = 15 * 1000;   // second follow-up
    if (now - m_dwLastPublishTime < interval) return;

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

    // Hash keyword (eSE: anonymous-link bootstrap). The anonymous link form
    // ed2k://|live|HASH||TITLE|/ carries the streamKey but no IP. Without
    // this, the viewer searches by "eselive" / title and depends on title
    // matching exactly + Kad propagation reaching the right nodes — flaky
    // first 30-90 s. By indexing under the hash itself the viewer can do
    // SearchStreams("livehash:<HASH>") and get a guaranteed direct match.
    {
        CString hashKeyword(_T("livehash:"));
        for (int i = 0; i < 16; ++i) {
            CString byteHex;
            byteHex.Format(_T("%02x"), m_publishedInfo.streamKey[i]);
            hashKeyword += byteHex;
        }
        keywords.Add(hashKeyword);
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

    AddLogLine(false, _T("eSE Kad: Published stream under %d keywords (eselive + %d extra) [burst %d]"),
        publishCount, publishCount - 1, m_nPublishBurstCount);

    m_dwLastPublishTime = now;
    if (m_nPublishBurstCount < 2) m_nPublishBurstCount++;

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
        CLiveDebugLog::Get().Append("KAD",
            "Search SKIPPED keyword=\"%S\" — Kad not connected", (LPCWSTR)keyword);
        return false;
    }

    // Use "eselive" as the default search keyword to find all streams
    CString searchWord = keyword.IsEmpty() ? _T("eselive") : keyword;
    searchWord.MakeLower();
    searchWord.Trim();

    DWORD now = GetTickCount();

    // DISC-S08: global token-bucket rate limit. Refill 1 token every 6 s,
    // capacity 10 -> sustained 10 searches/minute regardless of keyword.
    // This complements the per-keyword cooldown below and prevents any
    // pathological caller (UI auto-refresh, bug, attacker) from saturating
    // the DHT with our node's searches.
    if (m_dwLastSearchTokenRefill == 0) m_dwLastSearchTokenRefill = now;
    DWORD elapsed = now - m_dwLastSearchTokenRefill;
    if (elapsed >= 6000) {
        int tokensToAdd = (int)(elapsed / 6000);
        m_nSearchTokens = min(10, m_nSearchTokens + tokensToAdd);
        m_dwLastSearchTokenRefill += (DWORD)(tokensToAdd * 6000);
    }
    if (m_nSearchTokens <= 0) {
        CLiveDebugLog::Get().Append("KAD",
            "Search RATE-LIMITED keyword=\"%S\" (10/min cap reached)",
            (LPCWSTR)searchWord);
        // DISC-S11: count rate-limited drops for /api/live/metrics
        if (theApp.liveStreamManager)
            InterlockedIncrement(&theApp.liveStreamManager->GetCountersMut().kadSearchesRateLimited);
        return false;
    }
    m_nSearchTokens--;

    // Phase 2 LAT-1: adaptive cooldown. While the local directory is empty
    // (no peer found yet) we retry every 5 s; once we have at least one entry
    // we slow to 30 s to be neighbourly to the DHT.
    DWORD cooldown = (m_streamDirectory.GetCount() == 0)
        ? ESE_KAD_SEARCH_COOLDOWN_FAST
        : ESE_KAD_SEARCH_COOLDOWN_SLOW;
    if (now - m_dwLastSearchTime < cooldown
        && searchWord.CompareNoCase(m_strLastSearchKeyword) == 0)
    {
        AddLogLine(false,
            _T("eSE Kad: Search cooldown active (%ums), try again shortly"),
            cooldown - (now - m_dwLastSearchTime));
        CLiveDebugLog::Get().Append("KAD",
            "Search COOLDOWN keyword=\"%S\" wait %ums", (LPCWSTR)searchWord,
            (unsigned)(cooldown - (now - m_dwLastSearchTime)));
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
        CLiveDebugLog::Get().Append("KAD",
            "Search BEGIN keyword=\"%S\" SearchID=%u",
            (LPCWSTR)searchWord, (unsigned)pSearch->GetSearchID());
        m_dwLastSearchTime = now;
        m_strLastSearchKeyword = searchWord;
        return true;
    }

    AddLogLine(false, _T("eSE Kad: Search already in progress for \"%s\""),
        (LPCTSTR)searchWord);
    CLiveDebugLog::Get().Append("KAD",
        "Search ALREADY IN PROGRESS keyword=\"%S\"", (LPCWSTR)searchWord);
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
    uint16 broadcasterUDPPort,
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

    // DISC-S01 tombstone filter: bitrate==0 is the sentinel a broadcaster
    // publishes from UnpublishStream() so peers can recognise "I left" even
    // before the DHT TTL expires (~10 min). Also evict any local cached
    // entry so the directory reflects the takedown immediately.
    if (bitrate == 0) {
        CString strKey = StreamKeyToString(streamKey);
        m_streamDirectory.RemoveKey(strKey);
        AddLogLine(false, _T("eSE Kad: TOMBSTONE received for %s:%u — evicting local entry"),
            (LPCTSTR)ipstr(broadcasterIP), broadcasterPort);
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

    // DISC-S14: sanity-clamp values that came from an untrusted Kad entry.
    // Bitrate > 50 Mbps is unrealistic for any v2/v3 use case and likely
    // spam or a malformed publish. ViewerCount > 100k is clamped because
    // pure-P2P v2 isn't expected to exceed that — V3+ may raise the cap.
    if (bitrate > 50000) {
        AddLogLine(false, _T("eSE Kad: REJECTED result — bogus bitrate %u kbps from %s"),
            bitrate, (LPCTSTR)ipstr(broadcasterIP));
        CLiveDebugLog::Get().Append("KAD",
            "DISC-S14: discard result %S:%u bogus bitrate=%u",
            (LPCWSTR)ipstr(broadcasterIP), broadcasterPort, bitrate);
        if (theApp.liveStreamManager != NULL)
            InterlockedIncrement(&theApp.liveStreamManager->GetCountersMut().kadResultsRejected);
        return;
    }
    if (viewerCount > 100000) {
        CLiveDebugLog::Get().Append("KAD",
            "DISC-S14: clamp suspicious viewerCount %u -> 100000 for %S:%u",
            viewerCount, (LPCWSTR)ipstr(broadcasterIP), broadcasterPort);
        viewerCount = 100000;
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
        entry.broadcasterUDPPort = broadcasterUDPPort;  // A.4 Sprint 1
        entry.lastSeen = GetTickCount();
        entry.startedAt = (uint32)time(NULL);
        entry.isOwnStream = false;

        AddLogLine(false, _T("eSE Kad: Discovered stream \"%s\" from %s:%u (%u viewers, %ukbps)"),
            (LPCTSTR)title, (LPCTSTR)ipstr(broadcasterIP), broadcasterPort,
            viewerCount, bitrate);
        CLiveDebugLog::Get().Append("KAD",
            "Discovered \"%S\" src=%S:%u udp=%u %ukbps",
            (LPCWSTR)title, (LPCWSTR)ipstr(broadcasterIP),
            (unsigned)broadcasterPort, (unsigned)broadcasterUDPPort, (unsigned)bitrate);
    }

    m_streamDirectory[strKey] = entry;

    // Phase 0: Track last discovery result for /api/live/debug
    m_dwLastResultIP   = broadcasterIP;
    m_wLastResultPort  = broadcasterPort;
    m_dwLastResultTime = GetTickCount();

    // Phase 0: Count accepted result
    if (theApp.liveStreamManager != NULL)
        InterlockedIncrement(&theApp.liveStreamManager->GetCountersMut().kadResultsAccepted);

    // DISC-S06: enqueue for throttled dialing instead of immediate connect.
    // A popular keyword can return 100+ results — auto-dialing each one
    // synchronously would burst-open 100 sockets. Process() drains at
    // kDialsPerTick (3/s) so the dial rate stays civil. FIFO-drop if the
    // queue exceeds kMaxPendingDials to bound memory.
    if (theApp.liveStreamManager != NULL) {
        if (m_pendingDials.GetCount() >= kMaxPendingDials) {
            m_pendingDials.RemoveAt(0);  // drop oldest
            // DISC-S11: count FIFO-drops for visibility
            InterlockedIncrement(&theApp.liveStreamManager->GetCountersMut().pendingDialsDropped);
        }
        PendingDial pd;
        memcpy(pd.streamKey, streamKey, 16);
        pd.ip      = broadcasterIP;
        pd.port    = broadcasterPort;
        pd.udpPort = broadcasterUDPPort;
        m_pendingDials.Add(pd);
    }
}


// ============================================================
// PERIODIC MAINTENANCE
// ============================================================

void CLiveKadBridge::Process()
{
    DWORD now = GetTickCount();

    // DISC-S03: detect Kad off->on transition. If we deferred a publish
    // because Kad was disconnected, fire an immediate burst NOW so the
    // broadcaster appears in the DHT within seconds of Kad coming up
    // (instead of waiting up to 60 s for the regular republish cadence).
    {
        bool kadNow = Kademlia::CKademlia::IsConnected();
        if (kadNow && !m_bKadWasConnectedLastTick && m_bDeferredFirstPublish && m_bPublished) {
            AddLogLine(false, _T("eSE Kad: connected — flushing deferred publish for \"%s\""),
                (LPCTSTR)m_publishedInfo.title);
            CLiveDebugLog::Get().Append("KAD",
                "Kad ONLINE — deferred publish flush, resetting burst");
            // Force RepublishIfNeeded() to publish on this tick by resetting
            // the cadence counters.
            m_dwLastPublishTime = 0;
            m_nPublishBurstCount = 0;
            m_dwBurstStartTime   = now;
            m_bDeferredFirstPublish = false;
        }
        m_bKadWasConnectedLastTick = kadNow;
    }

    // Republish if broadcasting
    if (m_bPublished) {
        RepublishIfNeeded();
    }

    // Prune stale entries
    if (now - m_dwLastPruneTime >= ESE_KAD_PRUNE_INTERVAL) {
        PruneStaleEntries();
        m_dwLastPruneTime = now;
    }

    // DISC-S06: drain pending dial queue up to kDialsPerTick per tick.
    if (theApp.liveStreamManager != NULL && m_pendingDials.GetCount() > 0) {
        CSingleLock dialLock(&m_lock, TRUE);
        int drained = 0;
        while (drained < kDialsPerTick && m_pendingDials.GetCount() > 0) {
            PendingDial pd = m_pendingDials[0];
            m_pendingDials.RemoveAt(0);
            dialLock.Unlock();   // TryConnectToStreamSource takes its own lock
            theApp.liveStreamManager->TryConnectToStreamSource(
                pd.streamKey, pd.ip, pd.port, pd.udpPort);
            dialLock.Lock();
            drained++;
        }
        if (drained > 0) {
            CLiveDebugLog::Get().Append("KAD",
                "Drained %d dial(s); %d still queued",
                drained, (int)m_pendingDials.GetCount());
        }
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
