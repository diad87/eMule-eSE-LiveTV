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
#define ESE_KAD_ENTRY_TTL           (120 * 1000)       // v7.1.9: 2 min (was 3; original 10). Broadcaster republishes every 60 s, so 2 misses = dead.
// Phase 2 LAT-1: adaptive search cooldown.
// The viewer needs to retry quickly while it has no results yet (Kad propagation
// can take 1-5 minutes). Once results start coming in, we relax to 30 s to avoid
// hammering the DHT.
#define ESE_KAD_SEARCH_COOLDOWN_FAST (5 * 1000)        // 5 s while empty
#define ESE_KAD_SEARCH_COOLDOWN_SLOW (30 * 1000)       // 30 s once we have results
#define ESE_KAD_SEARCH_COOLDOWN     ESE_KAD_SEARCH_COOLDOWN_SLOW  // legacy alias
// Disk snapshot: persist the channel directory across eMule restarts so
// /live is not empty on the first second after launch (Kad takes time to
// repopulate organically). Snapshot file uses a versioned plain-text
// format — additive, never breaks older readers.
#define ESE_KAD_DISK_SAVE_INTERVAL  (5 * 60 * 1000)    // every 5 min
#define ESE_KAD_DIRECTORY_FILENAME  _T("eselive_directory.dat")
#define ESE_KAD_DIRECTORY_VERSION   1

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
    , m_bLoadedFromDisk(false)              // disk persistence
    , m_dwLastDiskSaveTime(0)               // disk persistence
    , m_dwLastNsMapPrune(0)                 // H5 — namespace attribution map
{
}

CLiveKadBridge::~CLiveKadBridge()
{
    // Flush the directory to disk so the next eMule run can prefill /live
    // before Kad has had a chance to reconnect.
    try {
        CSingleLock lock(&m_lock, TRUE);
        if (m_bLoadedFromDisk)
            SaveDirectoryToDisk();
    } catch (...) {
        // never throw from destructor
    }
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

    // v7.1.9 — when the streamKey changes (new broadcast supersedes old),
    // sweep any prior isOwnStream entries from the directory before adding
    // the new one. Without this, every key change leaves the previous own
    // entry hanging around forever (PruneStaleEntries explicitly skipped
    // own entries until the v7.1.9 fix below), so the channel list slowly
    // fills with the broadcaster's past streamKeys.
    if (!wasSameStream) {
        POSITION pos = m_streamDirectory.GetStartPosition();
        while (pos) {
            CString k; LiveStreamEntry e;
            m_streamDirectory.GetNextAssoc(pos, k, e);
            if (e.isOwnStream) {
                m_streamDirectory.RemoveKey(k);
            }
        }
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
        // H7 — dual-publish tombstone. The clean half tells eSE-aware
        // viewers the stream is gone even after legacy is turned off in
        // a future release; the legacy half tells old forks the same.
        CString hashKeyword(_T("livehash:"));
        for (int i = 0; i < 16; ++i) {
            CString h; h.Format(_T("%02x"), streamKey[i]);
            hashKeyword += h;
        }
        Kademlia::CKadTagValueString wstrKw(hashKeyword);

        int nPublished = 0;
        Kademlia::CUInt128 uClean;
        EseLiveGetKeywordHash(wstrKw, &uClean);
        if (StartKeywordPublish(uClean, _T("eSE Live tombstone [clean]"),
                streamKey, m_publishedInfo.title,
                m_publishedInfo.category, m_publishedInfo.language,
                /*bitrate=*/0, /*viewerCount=*/0, m_publishedInfo.startedAt,
                /*bCleanNs=*/true))
            nPublished++;
        if (thePrefs.GetEseLivePublishLegacy()) {
            Kademlia::CUInt128 uLegacy;
            KadGetKeywordHash(wstrKw, &uLegacy);
            if (StartKeywordPublish(uLegacy, _T("eSE Live tombstone [legacy]"),
                    streamKey, m_publishedInfo.title,
                    m_publishedInfo.category, m_publishedInfo.language,
                    /*bitrate=*/0, /*viewerCount=*/0, m_publishedInfo.startedAt,
                    /*bCleanNs=*/false))
                nPublished++;
        }
        AddLogLine(false,
            _T("eSE Kad: Stream tombstone published (bitrate=0, %d namespace(s))"),
            nPublished);
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
    // H7 — dual-namespace so clients with legacy=false also evict the
    // ghost from their directory (otherwise it lingers until Kad TTL).
    CSingleLock lock(&m_lock, TRUE);
    if (!Kademlia::CKademlia::IsConnected()) return false;

    CString hashKeyword(_T("livehash:"));
    for (int i = 0; i < 16; ++i) {
        CString h; h.Format(_T("%02x"), streamKey[i]);
        hashKeyword += h;
    }
    Kademlia::CKadTagValueString wstrKw(hashKeyword);
    const uint32 now = (uint32)time(NULL);

    int nPublished = 0;
    Kademlia::CUInt128 uClean;
    EseLiveGetKeywordHash(wstrKw, &uClean);
    if (StartKeywordPublish(uClean, _T("eSE Live ghost-tombstone [clean]"),
            streamKey, L"", L"", L"",
            /*bitrate=*/0, /*viewerCount=*/0, /*startedAt=*/now,
            /*bCleanNs=*/true))
        nPublished++;
    if (thePrefs.GetEseLivePublishLegacy()) {
        Kademlia::CUInt128 uLegacy;
        KadGetKeywordHash(wstrKw, &uLegacy);
        if (StartKeywordPublish(uLegacy, _T("eSE Live ghost-tombstone [legacy]"),
                streamKey, L"", L"", L"",
                /*bitrate=*/0, /*viewerCount=*/0, /*startedAt=*/now,
                /*bCleanNs=*/false))
            nPublished++;
    }
    AddLogLine(false,
        _T("eSE Kad: Ghost tombstone published for streamKey %s (%d namespace(s))"),
        (LPCTSTR)hashKeyword, nPublished);
    return nPublished > 0;
}

bool CLiveKadBridge::PublishAsRelay(const uchar* streamKey, LPCWSTR title,
    LPCWSTR category, LPCWSTR language, uint16 bitrate)
{
    // V2-S17 — Anonymous relay/secondary-source publish.
    // Only publishes under livehash:HASH (not eselive/title/category) so the
    // global directory does not fill up with duplicate stream entries; only
    // joiners that explicitly look up the streamKey via JoinStream find us.
    // H7 — dual-namespace so legacy=false viewers still discover relays
    // (otherwise the topology degenerates to all-vs-broadcaster).
    CSingleLock lock(&m_lock, TRUE);
    if (!Kademlia::CKademlia::IsConnected()) return false;

    CString hashKeyword(_T("livehash:"));
    for (int i = 0; i < 16; ++i) {
        CString byteHex; byteHex.Format(_T("%02x"), streamKey[i]);
        hashKeyword += byteHex;
    }
    Kademlia::CKadTagValueString wstrKw(hashKeyword);
    const uint32 now = (uint32)time(NULL);
    LPCWSTR sTitle    = title    ? title    : L"";
    LPCWSTR sCategory = category ? category : L"";
    LPCWSTR sLanguage = language ? language : L"";

    int nPublished = 0;
    Kademlia::CUInt128 uClean;
    EseLiveGetKeywordHash(wstrKw, &uClean);
    CString guiClean; guiClean.Format(_T("eSE Live (relay) [clean]: %s"), (LPCTSTR)hashKeyword);
    if (StartKeywordPublish(uClean, guiClean,
            streamKey, sTitle, sCategory, sLanguage,
            bitrate, /*viewerCount*/ 0, /*startedAt*/ now,
            /*bCleanNs=*/true))
        nPublished++;
    if (thePrefs.GetEseLivePublishLegacy()) {
        Kademlia::CUInt128 uLegacy;
        KadGetKeywordHash(wstrKw, &uLegacy);
        CString guiLegacy; guiLegacy.Format(_T("eSE Live (relay) [legacy]: %s"), (LPCTSTR)hashKeyword);
        if (StartKeywordPublish(uLegacy, guiLegacy,
                streamKey, sTitle, sCategory, sLanguage,
                bitrate, /*viewerCount*/ 0, /*startedAt*/ now,
                /*bCleanNs=*/false))
            nPublished++;
    }
    AddLogLine(false,
        _T("eSE Kad: Secondary-source publish under %s (%d namespace(s))"),
        (LPCTSTR)hashKeyword, nPublished);
    return nPublished > 0;
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

    // Publish under each keyword in BOTH namespaces during the transition
    // (project_backward_compat): clean = MD4("\x00eSE\x00" || utf8(kw)),
    // legacy = MD4(utf8(kw)). New clients find each other on the clean
    // hash; old forks still find us on legacy. Legacy half can be turned
    // off via thePrefs.GetEseLivePublishLegacy() once adoption metrics
    // (knownStreamsClean ≥ knownStreamsLegacy) say it's safe.
    int publishCleanCount = 0;
    int publishLegacyCount = 0;
    const bool bPublishLegacy = thePrefs.GetEseLivePublishLegacy();
    for (INT_PTR i = 0; i < keywords.GetCount(); i++) {
        Kademlia::CKadTagValueString wstrKw(keywords[i]);

        // (A) Clean namespace — primary discovery for eSE-aware clients.
        Kademlia::CUInt128 uTargetClean;
        EseLiveGetKeywordHash(wstrKw, &uTargetClean);
        if (StartLivePublishSearch(uTargetClean, keywords[i], _T("clean")))
            publishCleanCount++;

        // (B) Legacy namespace — interop with 0.70b upstream + older forks.
        // Gated by pref so we can amputate the leak path in a future
        // release without rebuilding the protocol.
        if (bPublishLegacy) {
            Kademlia::CUInt128 uTargetLegacy;
            KadGetKeywordHash(wstrKw, &uTargetLegacy);
            if (StartLivePublishSearch(uTargetLegacy, keywords[i], _T("legacy")))
                publishLegacyCount++;
        }
    }

    AddLogLine(false,
        _T("eSE Kad: Published stream under %d clean + %d legacy keywords [burst %d]"),
        publishCleanCount, publishLegacyCount, m_nPublishBurstCount);

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

// H7 — primitive helper. STOREKEYWORD + SetLiveStreamPublish + StartSearch
// with all parameters explicit. Calling code holds m_lock already.
// H8 — bCleanNs gates omission of TAG_FILENAME/TAG_FILETYPE so eSE-aware
// crawlers can't harvest titles from the dedicated namespace.
bool CLiveKadBridge::StartKeywordPublish(const Kademlia::CUInt128& uTarget,
    LPCTSTR displayName, const uchar* streamKey, LPCWSTR title,
    LPCWSTR category, LPCWSTR language,
    uint16 bitrate, uint32 viewerCount, uint32 startedAt,
    bool bCleanNs)
{
    Kademlia::CSearch* pSearch = Kademlia::CSearchManager::PrepareLookup(
        Kademlia::CSearch::STOREKEYWORD, false, uTarget);
    if (!pSearch)
        return false;
    pSearch->SetGUIName(displayName);
    pSearch->SetLiveStreamPublish(streamKey, title, category, language,
        bitrate, viewerCount, startedAt, thePrefs.GetPort());
    pSearch->SetLivePublishCleanNs(bCleanNs);
    Kademlia::CSearchManager::StartSearch(pSearch);
    return true;
}

// Dual-namespace publish helper for RepublishIfNeeded. Pulls all the
// stream parameters from m_publishedInfo so the loop in RepublishIfNeeded
// stays tight. Caller holds m_lock. The `clean` vs `legacy` choice for
// H8 is inferred from namespaceTag — the caller already encodes it there.
bool CLiveKadBridge::StartLivePublishSearch(const Kademlia::CUInt128& uTarget,
                                            LPCTSTR keyword, LPCTSTR namespaceTag)
{
    const bool bCleanNs = (_tcscmp(namespaceTag, _T("clean")) == 0);
    CString guiName;
    guiName.Format(_T("eSE Live: %s [%s]"), keyword, namespaceTag);
    return StartKeywordPublish(uTarget, guiName,
        m_publishedInfo.streamKey,
        m_publishedInfo.title, m_publishedInfo.category, m_publishedInfo.language,
        m_publishedInfo.bitrate, m_publishedInfo.viewerCount,
        m_publishedInfo.startedAt, bCleanNs);
}


// ============================================================
// DISCOVERY (Viewer side)
// ============================================================

bool CLiveKadBridge::SearchStreams(const CString& keyword)
{
    CSingleLock lock(&m_lock, TRUE);

    if (!Kademlia::CKademlia::IsConnected()) {
        // v0.71 P3.8 — log once per disconnected stretch, not every poll.
        // ASCII hyphen instead of em-dash to avoid CP1252/UTF-8 mojibake
        // ("â€"") when the log is rendered by a CP1252-decoding viewer.
        if (!m_bLoggedKadNotConnected) {
            AddLogLine(false, _T("eSE Kad: Cannot search - Kad not connected"));
            m_bLoggedKadNotConnected = true;
        }
        CLiveDebugLog::Get().Append("KAD",
            "Search SKIPPED keyword=\"%S\" - Kad not connected", (LPCWSTR)keyword);
        return false;
    }
    // Kad is connected now — reset the "not connected" log gate so the
    // next disconnect prints again. Same pattern below for the other
    // throttled states.
    m_bLoggedKadNotConnected = false;

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
        // v0.71 P3.8 — log AddLogLine only once per cooldown window.
        // The web UI polls every 3-5 s; without this gate the user sees
        // ~10 identical lines per cooldown. CLiveDebugLog still gets
        // every event for diagnostics.
        if (!m_bLoggedSearchCooldown) {
            AddLogLine(false,
                _T("eSE Kad: Search cooldown active (%ums), waiting"),
                cooldown - (now - m_dwLastSearchTime));
            m_bLoggedSearchCooldown = true;
        }
        CLiveDebugLog::Get().Append("KAD",
            "Search COOLDOWN keyword=\"%S\" wait %ums", (LPCWSTR)searchWord,
            (unsigned)(cooldown - (now - m_dwLastSearchTime)));
        return false;
    }
    // Past cooldown — reset the gate.
    m_bLoggedSearchCooldown = false;

    // Dual-namespace search: launch one KEYWORD search per hash domain.
    // (A) Clean — finds streams that current/future eSE clients publish
    //     under EseLiveGetKeywordHash. Discovery primary.
    // (B) Legacy — finds streams that earlier forks (and our own legacy
    //     half during the transition) publish under KadGetKeywordHash.
    // Both feed OnKadSearchResult; m_streamDirectory dedupes by streamKey.
    //
    // Cooldown is applied to the PAIR as a single logical refresh — one
    // consumed token, one m_dwLastSearchTime stamp — so the user pressing
    // refresh does not pay 2× the rate-limit budget.
    Kademlia::CKadTagValueString wstrKeyword(searchWord);

    Kademlia::CUInt128 uTargetClean;
    EseLiveGetKeywordHash(wstrKeyword, &uTargetClean);
    Kademlia::CSearch* pSearchClean = Kademlia::CSearchManager::PrepareLookup(
        Kademlia::CSearch::KEYWORD, true, uTargetClean);

    Kademlia::CUInt128 uTargetLegacy;
    KadGetKeywordHash(wstrKeyword, &uTargetLegacy);
    Kademlia::CSearch* pSearchLegacy = Kademlia::CSearchManager::PrepareLookup(
        Kademlia::CSearch::KEYWORD, true, uTargetLegacy);

    if (pSearchClean == NULL && pSearchLegacy == NULL) {
        // v0.71 P3.8 — throttle: log once per "already in progress" stretch.
        if (!m_bLoggedAlreadyInProgress) {
            AddLogLine(false, _T("eSE Kad: Search already in progress for \"%s\""),
                (LPCTSTR)searchWord);
            m_bLoggedAlreadyInProgress = true;
        }
        CLiveDebugLog::Get().Append("KAD",
            "Search ALREADY IN PROGRESS keyword=\"%S\"", (LPCWSTR)searchWord);
        return false;
    }
    // A new search actually started — reset the gate.
    m_bLoggedAlreadyInProgress = false;

    // Phase 0: count the search as one logical operation, regardless of
    // how many namespaces actually fired (we don't want the kadSearches
    // counter to drift by 2× and break dashboard heuristics).
    if (theApp.liveStreamManager != NULL)
        InterlockedIncrement(&theApp.liveStreamManager->GetCountersMut().kadSearches);

    if (pSearchClean != NULL) {
        AddLogLine(true,
            _T("eSE Kad: Searching live streams [clean] (keyword=\"%s\", SearchID=%u)"),
            (LPCTSTR)searchWord, pSearchClean->GetSearchID());
        CLiveDebugLog::Get().Append("KAD",
            "Search BEGIN [clean] keyword=\"%S\" SearchID=%u",
            (LPCWSTR)searchWord, (unsigned)pSearchClean->GetSearchID());
        PendingSearchTag pst { ESE_NS_CLEAN, now };
        m_pendingSearchNamespaces[pSearchClean->GetSearchID()] = pst;
    }
    if (pSearchLegacy != NULL) {
        AddLogLine(true,
            _T("eSE Kad: Searching live streams [legacy] (keyword=\"%s\", SearchID=%u)"),
            (LPCTSTR)searchWord, pSearchLegacy->GetSearchID());
        CLiveDebugLog::Get().Append("KAD",
            "Search BEGIN [legacy] keyword=\"%S\" SearchID=%u",
            (LPCWSTR)searchWord, (unsigned)pSearchLegacy->GetSearchID());
        PendingSearchTag pst { ESE_NS_LEGACY, now };
        m_pendingSearchNamespaces[pSearchLegacy->GetSearchID()] = pst;
    }

    m_dwLastSearchTime = now;
    m_strLastSearchKeyword = searchWord;
    return true;
}

void CLiveKadBridge::GetKnownStreams(CArray<LiveStreamEntry>& outList) const
{
    outList.RemoveAll();

    // Copy the directory under m_lock, then release it before filtering.
    // IsStreamTombstoned() locks CLiveStreamManager::m_lock, and that class's
    // BuildDebugSnapshot() locks our m_lock the other way round — calling it
    // while still holding m_lock is the A-B/B-A deadlock that froze the UI.
    CArray<LiveStreamEntry> candidates;
    {
        CSingleLock lock(&m_lock, TRUE);
        CString key;
        LiveStreamEntry entry;
        POSITION pos = m_streamDirectory.GetStartPosition();
        while (pos) {
            m_streamDirectory.GetNextAssoc(pos, key, entry);
            candidates.Add(entry);
        }
    }

    // v7.2.0 — drop entries we've tombstoned. Even if a stale Kad echo from
    // another node refreshed the lastSeen of this entry, we know the broadcast
    // is dead because either (a) we received OP_LIVE_END for this streamKey,
    // or (b) our watchdog declared it dead. Hide from any caller (channel
    // grid, mesh dialer, search results) until the tombstone expires.
    for (INT_PTR i = 0; i < candidates.GetCount(); ++i) {
        if (theApp.liveStreamManager
            && theApp.liveStreamManager->IsStreamTombstoned(candidates[i].streamKey))
        {
            continue;
        }
        outList.Add(candidates[i]);
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
    uint16 bitrate, uint32 viewerCount,
    uint32 fromSearchID)
{
    CSingleLock lock(&m_lock, TRUE);

    // H5 — namespace attribution. Look up the search ID against the map
    // we populated in SearchStreams. Synthetic callers (PEX/bootstrap)
    // pass fromSearchID=0 which doesn't exist in the map → unknown.
    uint8 nsTag = ESE_NS_UNKNOWN;
    if (fromSearchID != 0) {
        PendingSearchTag tag;
        if (m_pendingSearchNamespaces.Lookup(fromSearchID, tag))
            nsTag = tag.nsTag;
    }

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

    // v7.2.0 — local tombstone filter: if WE already know this stream
    // is dead (via OP_LIVE_END or our watchdog), drop the Kad result
    // even though some other node's cache is still echoing it. Without
    // this, dead streams resurrect themselves every ~5 min when a fresh
    // Kad echo arrives from a node that never got the gossip.
    if (theApp.liveStreamManager != NULL
        && theApp.liveStreamManager->IsStreamTombstoned(streamKey))
    {
        AddLogLine(false, _T("eSE Kad: ignored Kad echo for tombstoned stream \"%s\""), (LPCTSTR)title);
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

        AddLogLine(false, _T("eSE Kad: Discovered stream \"%s\" from %s:%u (%u viewers, %ukbps) [%s]"),
            (LPCTSTR)title, (LPCTSTR)ipstr(broadcasterIP), broadcasterPort,
            viewerCount, bitrate,
            nsTag == ESE_NS_CLEAN  ? _T("clean")
          : nsTag == ESE_NS_LEGACY ? _T("legacy")
          :                          _T("synthetic"));
        CLiveDebugLog::Get().Append("KAD",
            "Discovered \"%S\" src=%S:%u udp=%u %ukbps ns=%u",
            (LPCWSTR)title, (LPCWSTR)ipstr(broadcasterIP),
            (unsigned)broadcasterPort, (unsigned)broadcasterUDPPort,
            (unsigned)bitrate, (unsigned)nsTag);
    }

    // H5 — Upgrade-only tag update. clean > legacy > unknown. Once seen
    // on clean, stay on clean even if a legacy echo arrives later (so the
    // adoption counter doesn't flicker downward on every legacy refresh).
    if (nsTag == ESE_NS_CLEAN ||
        (nsTag == ESE_NS_LEGACY && entry.discoveryNamespace == ESE_NS_UNKNOWN))
    {
        entry.discoveryNamespace = nsTag;
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

    // Lazy disk load on first tick: restores last-seen channel directory so
    // /live shows known broadcasters immediately on startup (subject to TTL).
    if (!m_bLoadedFromDisk) {
        CSingleLock lock(&m_lock, TRUE);
        if (!m_bLoadedFromDisk) {
            LoadDirectoryFromDisk();
            m_bLoadedFromDisk = true;
            m_dwLastDiskSaveTime = now;  // don't immediately re-save what we just loaded
        }
    }

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

    // Periodically snapshot the directory so it survives eMule restarts.
    if (now - m_dwLastDiskSaveTime >= ESE_KAD_DISK_SAVE_INTERVAL) {
        CSingleLock lock(&m_lock, TRUE);
        SaveDirectoryToDisk();
        m_dwLastDiskSaveTime = now;
    }

    // H5 — prune stale entries from m_pendingSearchNamespaces. A Kad
    // search completes in 5-10 s; anything older than kNsMapEntryTTL
    // (30 s) is either finished + already attributed every result it
    // is going to attribute, or it was lost — either way the entry is
    // dead weight. Bounds map size in the worst case (UI auto-refresh).
    if (now - m_dwLastNsMapPrune >= kNsMapPruneInterval) {
        CSingleLock lock(&m_lock, TRUE);
        CArray<uint32> toRemove;
        POSITION pos = m_pendingSearchNamespaces.GetStartPosition();
        while (pos) {
            uint32 sid;
            PendingSearchTag tag;
            m_pendingSearchNamespaces.GetNextAssoc(pos, sid, tag);
            if (now - tag.createdAt > kNsMapEntryTTL)
                toRemove.Add(sid);
        }
        for (INT_PTR i = 0; i < toRemove.GetCount(); ++i)
            m_pendingSearchNamespaces.RemoveKey(toRemove[i]);
        m_dwLastNsMapPrune = now;
    }
}

void CLiveKadBridge::PruneStaleEntries()
{
    CSingleLock lock(&m_lock, TRUE);

    DWORD now = GetTickCount();
    CStringArray toRemove;

    // v7.1.9 — figure out which streamKey (if any) is the broadcaster's
    // ACTIVE one right now. Own entries from prior broadcasts (different
    // streamKey, or any leftover when m_bPublished is false) get pruned
    // like remote ones. Without this, killing emule mid-broadcast or
    // changing streamKey left orphan isOwnStream entries forever, since
    // the old code skipped every entry.isOwnStream unconditionally.
    CString activeOwnKey;
    if (m_bPublished) {
        activeOwnKey = StreamKeyToString(m_publishedInfo.streamKey);
    }

    CString key;
    LiveStreamEntry entry;
    POSITION pos = m_streamDirectory.GetStartPosition();
    while (pos) {
        m_streamDirectory.GetNextAssoc(pos, key, entry);
        if (entry.isOwnStream) {
            // Keep only the currently-published own entry; stale own
            // entries (prior streamKeys, broadcaster stopped) are dropped.
            if (m_bPublished && key.CompareNoCase(activeOwnKey) == 0)
                continue;
            toRemove.Add(key);
            continue;
        }
        // Remote entries: prune if not seen in TTL
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

    // H5 — adoption tally. Iterate the directory under the lock we are
    // already holding. Own streams and unknown-tagged entries are NOT
    // counted in either bucket; sum can therefore be less than
    // knownStreams (the difference is "synthetic + our own broadcasts").
    snap.knownStreamsClean  = 0;
    snap.knownStreamsLegacy = 0;
    {
        POSITION pos = m_streamDirectory.GetStartPosition();
        CString k;
        LiveStreamEntry e;
        while (pos) {
            m_streamDirectory.GetNextAssoc(pos, k, e);
            if (e.isOwnStream) continue;
            if (e.discoveryNamespace == ESE_NS_CLEAN)  snap.knownStreamsClean++;
            else if (e.discoveryNamespace == ESE_NS_LEGACY) snap.knownStreamsLegacy++;
        }
    }
    return snap;
}


// ============================================================
// DISK PERSISTENCE
// ============================================================
// On-disk format (versioned, plain-text, one record per line so a future
// version can read older snapshots without breaking compatibility):
//
//   ESELIVE_DIR v1
//   <streamKey-hex32>\t<title>\t<category>\t<language>\t<bitrate>\t
//                <viewerCount>\t<broadcasterIP>\t<broadcasterPort>\t
//                <broadcasterUDPPort>\t<startedAt>\t<lastSeenUnix>\n
//
// Own-stream entries are skipped on save (they get repopulated at runtime
// when the broadcaster starts again). Entries older than 2x the TTL are
// dropped at load time — the broadcaster has almost certainly stopped.

CString CLiveKadBridge::GetDirectoryFilePath()
{
    return thePrefs.GetMuleDirectory(EMULE_CONFIGDIR) + ESE_KAD_DIRECTORY_FILENAME;
}

void CLiveKadBridge::LoadDirectoryFromDisk()
{
    // Caller must hold m_lock.
    CString path = GetDirectoryFilePath();
    CStdioFile file;
    CFileException ex;
    if (!file.Open(path, CFile::modeRead | CFile::typeText | CFile::shareDenyWrite, &ex))
        return;  // file doesn't exist yet — fine on first run

    try {
        CString line;
        if (!file.ReadString(line) || line.Find(_T("ESELIVE_DIR v")) != 0) {
            file.Close();
            return;
        }
        int version = _ttoi((LPCTSTR)line + 13);
        if (version < 1 || version > ESE_KAD_DIRECTORY_VERSION) {
            file.Close();
            return;  // unknown future version — leave file untouched
        }

        uint32 nowUnix = (uint32)time(NULL);
        int loaded = 0;
        int skipped = 0;
        while (file.ReadString(line)) {
            line.TrimRight(_T("\r\n"));
            if (line.IsEmpty()) continue;

            // Tab-separated fields (11 in v1).
            CString fields[11];
            int fIdx = 0;
            int pos = 0;
            CString tok;
            while (fIdx < 11) {
                tok = line.Tokenize(_T("\t"), pos);
                if (tok.IsEmpty() && pos < 0) break;
                fields[fIdx++] = tok;
            }
            if (fIdx < 11) { skipped++; continue; }

            if (fields[0].GetLength() != 32) { skipped++; continue; }

            LiveStreamEntry entry;
            bool keyOk = true;
            for (int i = 0; i < 16 && keyOk; i++) {
                int hi, lo;
                TCHAR ch = fields[0].GetAt(i * 2);
                if      (ch >= _T('0') && ch <= _T('9')) hi = ch - _T('0');
                else if (ch >= _T('a') && ch <= _T('f')) hi = 10 + (ch - _T('a'));
                else if (ch >= _T('A') && ch <= _T('F')) hi = 10 + (ch - _T('A'));
                else { keyOk = false; break; }
                ch = fields[0].GetAt(i * 2 + 1);
                if      (ch >= _T('0') && ch <= _T('9')) lo = ch - _T('0');
                else if (ch >= _T('a') && ch <= _T('f')) lo = 10 + (ch - _T('a'));
                else if (ch >= _T('A') && ch <= _T('F')) lo = 10 + (ch - _T('A'));
                else { keyOk = false; break; }
                entry.streamKey[i] = (uchar)((hi << 4) | lo);
            }
            if (!keyOk) { skipped++; continue; }

            entry.title              = fields[1];
            entry.category           = fields[2];
            entry.language           = fields[3];
            entry.bitrate            = (uint16)_ttoi(fields[4]);
            entry.viewerCount        = (uint32)_ttoi(fields[5]);
            entry.broadcasterIP      = (uint32)_ttoi64(fields[6]);
            entry.broadcasterPort    = (uint16)_ttoi(fields[7]);
            entry.broadcasterUDPPort = (uint16)_ttoi(fields[8]);
            entry.startedAt          = (uint32)_ttoi64(fields[9]);
            uint32 lastSeenUnix      = (uint32)_ttoi64(fields[10]);
            entry.isOwnStream        = false;  // broadcaster repopulates on start

            // Drop anything older than 2x the TTL — almost certainly gone.
            if (nowUnix > lastSeenUnix
                && (nowUnix - lastSeenUnix) * 1000 > (ESE_KAD_ENTRY_TTL * 2))
            {
                skipped++;
                continue;
            }
            uint32 ageMs = (nowUnix > lastSeenUnix) ? (nowUnix - lastSeenUnix) * 1000 : 0;
            DWORD nowTicks = GetTickCount();
            entry.lastSeen = (ageMs < nowTicks) ? (nowTicks - ageMs) : 0;

            CString strKey = StreamKeyToString(entry.streamKey);
            m_streamDirectory[strKey] = entry;
            loaded++;
        }
        file.Close();
        AddLogLine(false, _T("eSE Kad: Loaded %d cached stream entries from disk (%d skipped)"),
            loaded, skipped);
    } catch (CFileException* fex) {
        fex->Delete();
        try { file.Close(); } catch (...) {}
    }
}

void CLiveKadBridge::SaveDirectoryToDisk()
{
    // Caller must hold m_lock.
    CString path = GetDirectoryFilePath();
    CString tmpPath = path + _T(".tmp");

    CStdioFile file;
    CFileException ex;
    if (!file.Open(tmpPath,
            CFile::modeCreate | CFile::modeWrite | CFile::typeText | CFile::shareExclusive,
            &ex))
    {
        return;  // can't write — silently skip, retry later
    }

    try {
        CString hdr;
        hdr.Format(_T("ESELIVE_DIR v%d\n"), ESE_KAD_DIRECTORY_VERSION);
        file.WriteString(hdr);

        uint32 nowUnix = (uint32)time(NULL);
        DWORD nowTicks = GetTickCount();

        CString key;
        LiveStreamEntry entry;
        POSITION pos = m_streamDirectory.GetStartPosition();
        int written = 0;
        while (pos) {
            m_streamDirectory.GetNextAssoc(pos, key, entry);
            if (entry.isOwnStream) continue;  // re-registered on broadcaster start
            if (entry.broadcasterIP == 0 || entry.broadcasterPort == 0) continue;

            uint32 ageMs = (nowTicks > entry.lastSeen) ? (nowTicks - entry.lastSeen) : 0;
            uint32 lastSeenUnix = (ageMs / 1000 < nowUnix) ? (nowUnix - ageMs / 1000) : nowUnix;

            // Sanitize strings to keep the tab format intact
            CString title    = entry.title;    title.Replace(_T("\t"), _T(" ")); title.Replace(_T("\n"), _T(" "));
            CString category = entry.category; category.Replace(_T("\t"), _T(" ")); category.Replace(_T("\n"), _T(" "));
            CString language = entry.language; language.Replace(_T("\t"), _T(" ")); language.Replace(_T("\n"), _T(" "));

            CString hex = StreamKeyToString(entry.streamKey);

            CString row;
            row.Format(_T("%s\t%s\t%s\t%s\t%u\t%u\t%u\t%u\t%u\t%u\t%u\n"),
                (LPCTSTR)hex, (LPCTSTR)title, (LPCTSTR)category, (LPCTSTR)language,
                entry.bitrate, entry.viewerCount,
                entry.broadcasterIP, entry.broadcasterPort, entry.broadcasterUDPPort,
                entry.startedAt, lastSeenUnix);
            file.WriteString(row);
            written++;
        }
        file.Close();

        MoveFileEx(tmpPath, path, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);

        AddDebugLogLine(false, _T("eSE Kad: Persisted %d stream entries to disk"), written);
    } catch (CFileException* fex) {
        fex->Delete();
        try { file.Close(); } catch (...) {}
        try { DeleteFile(tmpPath); } catch (...) {}
    }
}
