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
#include "LiveTunnel.h"                          // v8.1 D1 - route discovery through the tunnel
#include "kademlia/kademlia/KadV2TunnelPool.h"   // v8.1 D5 - Acquire() picks the circuit
#include "kademlia/kademlia/KadV2ModeSelector.h" // v8.1 D1/D3 - fallback policy on no circuit
#include <iphlpapi.h>   // NAT-reach: GetIpAddrTable for overlay-IP detection
#pragma comment(lib, "iphlpapi.lib")

extern UINT g_uMainThreadId;   // v8.1 D1 - main-thread assertions on the new cross-lock paths

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
#define ESE_KAD_DIRECTORY_VERSION   2

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
        AddLogLine(false, GetResString(IDS_LIVEKAD_CANNOT_PUBLISH));

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
    // IP=0 fix (v8.1): carry OUR public IP (HOST byte order — same value we
    // publish in TAG_SOURCEIP, see Search.cpp:1706) instead of 0. When WE act
    // as a tunnel exit and serialize this entry for a tunneled keyword search
    // (CLiveTunnel::SerializeSearchResults), a 0 here went out on the wire and
    // the originator rejected the result as "invalid endpoint (IP=0)". The
    // direct/legacy path was unaffected (it reads TAG_SOURCEIP off the wire,
    // not this field). 0 if the public IP isn't known yet — no worse than
    // before; SerializeSearchResults has a serialize-time fallback for that.
    entry.broadcasterIP = theApp.GetPublicIP();
    entry.broadcasterPort = theApp.GetAdvertisedTcpPort();
    entry.lastSeen = GetTickCount();
    entry.startedAt = info.startedAt;
    entry.isOwnStream = true;

    CString strKey = StreamKeyToString(info.streamKey);
    m_streamDirectory[strKey] = entry;

    if (!Kademlia::CKademlia::IsConnected()) {
        AddLogLine(false, GetResString(IDS_LIVEKAD_QUEUED_FMT),
            (LPCTSTR)info.title);
        CLiveDebugLog::Get().Append("KAD",
            "PublishStream QUEUED \"%S\" — Kad not connected", (LPCWSTR)info.title);
        // DISC-S03: arm the deferred-publish flag so Process() forces an
        // immediate burst when Kad transitions to connected.
        m_bDeferredFirstPublish = true;
        return false;
    }

    // NAT-reach: surface what reach info the publish will carry, so a
    // broadcaster can verify at a glance that viewers will be able to dial
    // (overlay endpoint and/or UDP hole-punch port).
    uint32 altIP = GetLocalOverlayIP();
    if (altIP != 0) {
        AddLogLine(true, GetResString(IDS_LIVEKAD_PUBLISHING_OVERLAY_FMT),
            (LPCTSTR)info.title, (LPCTSTR)ipstr(altIP));
    } else {
        AddLogLine(true, GetResString(IDS_LIVEKAD_PUBLISHING_FMT),
            (LPCTSTR)info.title);
    }
    CLiveDebugLog::Get().Append("KAD",
        "PublishStream OK \"%S\" port=%u alt=%S",
        (LPCWSTR)info.title, (unsigned)theApp.GetAdvertisedTcpPort(),
        altIP ? (LPCWSTR)ipstr(altIP) : L"-");

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
        if (StartKeywordPublish(uClean, GetResString(IDS_LIVEKAD_GUI_TOMBSTONE_CLEAN),
                streamKey, m_publishedInfo.title,
                m_publishedInfo.category, m_publishedInfo.language,
                /*bitrate=*/0, /*viewerCount=*/0, m_publishedInfo.startedAt,
                /*bCleanNs=*/true))
            nPublished++;
        if (thePrefs.GetEseLivePublishLegacy()) {
            Kademlia::CUInt128 uLegacy;
            KadGetKeywordHash(wstrKw, &uLegacy);
            if (StartKeywordPublish(uLegacy, GetResString(IDS_LIVEKAD_GUI_TOMBSTONE_LEGACY),
                    streamKey, m_publishedInfo.title,
                    m_publishedInfo.category, m_publishedInfo.language,
                    /*bitrate=*/0, /*viewerCount=*/0, m_publishedInfo.startedAt,
                    /*bCleanNs=*/false))
                nPublished++;
        }
        AddLogLine(false,
            GetResString(IDS_LIVEKAD_TOMBSTONE_PUBLISHED_FMT),
            nPublished);
    }

    CString strKey = StreamKeyToString(streamKey);
    m_streamDirectory.RemoveKey(strKey);
    m_bPublished = false;
    // Phase 2 LAT-2: reset burst state so next StartBroadcast re-arms.
    m_nPublishBurstCount = 0;
    m_dwBurstStartTime   = 0;

    AddLogLine(true, GetResString(IDS_LIVEKAD_UNPUBLISHED));
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
    if (StartKeywordPublish(uClean, GetResString(IDS_LIVEKAD_GUI_GHOST_TOMBSTONE_CLEAN),
            streamKey, L"", L"", L"",
            /*bitrate=*/0, /*viewerCount=*/0, /*startedAt=*/now,
            /*bCleanNs=*/true))
        nPublished++;
    if (thePrefs.GetEseLivePublishLegacy()) {
        Kademlia::CUInt128 uLegacy;
        KadGetKeywordHash(wstrKw, &uLegacy);
        if (StartKeywordPublish(uLegacy, GetResString(IDS_LIVEKAD_GUI_GHOST_TOMBSTONE_LEGACY),
                streamKey, L"", L"", L"",
                /*bitrate=*/0, /*viewerCount=*/0, /*startedAt=*/now,
                /*bCleanNs=*/false))
            nPublished++;
    }
    AddLogLine(false,
        GetResString(IDS_LIVEKAD_GHOST_TOMBSTONE_FMT),
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
    CString guiClean; guiClean.Format(GetResString(IDS_LIVEKAD_GUI_RELAY_CLEAN_FMT), (LPCTSTR)hashKeyword);
    if (StartKeywordPublish(uClean, guiClean,
            streamKey, sTitle, sCategory, sLanguage,
            bitrate, /*viewerCount*/ 0, /*startedAt*/ now,
            /*bCleanNs=*/true))
        nPublished++;
    if (thePrefs.GetEseLivePublishLegacy()) {
        Kademlia::CUInt128 uLegacy;
        KadGetKeywordHash(wstrKw, &uLegacy);
        CString guiLegacy; guiLegacy.Format(GetResString(IDS_LIVEKAD_GUI_RELAY_LEGACY_FMT), (LPCTSTR)hashKeyword);
        if (StartKeywordPublish(uLegacy, guiLegacy,
                streamKey, sTitle, sCategory, sLanguage,
                bitrate, /*viewerCount*/ 0, /*startedAt*/ now,
                /*bCleanNs=*/false))
            nPublished++;
    }
    AddLogLine(false,
        GetResString(IDS_LIVEKAD_SECONDARY_PUBLISH_FMT),
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
        GetResString(IDS_LIVEKAD_PUBLISHED_KEYWORDS_FMT),
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

// NAT-reach (2026-06) — local overlay IPv4 for TAG_ESE_LIVE_ALTIP.
// A broadcaster behind home NAT publishes a public IP nobody can dial; if
// the machine is also on an overlay network (Tailscale & friends hand out
// CGNAT 100.64.0.0/10 addresses), that address IS reachable by any viewer
// on the same overlay. Publish it alongside the public IP so the viewer's
// dial drain can race both endpoints. INI override for other overlays:
//   [eMule] LiveAltIP=<dotted IPv4>
// Returns network byte order (same convention as theApp.GetPublicIP() /
// TAG_SOURCEIP). 0 when there is nothing to advertise. Cached 60 s.
uint32 CLiveKadBridge::GetLocalOverlayIP()
{
    static uint32 s_cachedIP = 0;
    static DWORD  s_cachedAt = 0;
    DWORD now = GetTickCount();
    if (s_cachedAt != 0 && (now - s_cachedAt) < 60u * 1000u)
        return s_cachedIP;
    s_cachedAt = now;
    s_cachedIP = 0;

    // 1) Explicit INI override wins (lets Tor/other-overlay setups inject
    //    whatever endpoint they want without code changes).
    CString iniIP = theApp.GetProfileString(_T("eMule"), _T("LiveAltIP"), _T(""));
    iniIP.Trim();
    if (!iniIP.IsEmpty()) {
        uint32 ip = inet_addr(CT2CA(iniIP));
        if (ip != INADDR_NONE && ip != 0) {
            s_cachedIP = ip;
            return s_cachedIP;
        }
    }

    // 2) Auto-detect: first local interface address in 100.64.0.0/10.
    BYTE stackBuf[2048];
    ULONG size = sizeof stackBuf;
    PMIB_IPADDRTABLE table = (PMIB_IPADDRTABLE)stackBuf;
    DWORD ret = GetIpAddrTable(table, &size, FALSE);
    BYTE* heapBuf = NULL;
    if (ret == ERROR_INSUFFICIENT_BUFFER) {
        heapBuf = new BYTE[size];
        table = (PMIB_IPADDRTABLE)heapBuf;
        ret = GetIpAddrTable(table, &size, FALSE);
    }
    if (ret == NO_ERROR) {
        for (DWORD i = 0; i < table->dwNumEntries; ++i) {
            uint32 addr = table->table[i].dwAddr;   // network byte order
            uint8 first  = (uint8)addr;
            uint8 second = (uint8)(addr >> 8);
            if (first == 100 && second >= 64 && second <= 127) {  // 100.64.0.0/10
                s_cachedIP = addr;
                break;
            }
        }
    }
    delete[] heapBuf;
    return s_cachedIP;
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
        bitrate, viewerCount, startedAt, theApp.GetAdvertisedTcpPort(),
        GetLocalOverlayIP());   // NAT-reach: advertise overlay endpoint too
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
    guiName.Format(GetResString(IDS_LIVEKAD_GUI_SEARCH_FMT), keyword, namespaceTag);
    return StartKeywordPublish(uTarget, guiName,
        m_publishedInfo.streamKey,
        m_publishedInfo.title, m_publishedInfo.category, m_publishedInfo.language,
        m_publishedInfo.bitrate, m_publishedInfo.viewerCount,
        m_publishedInfo.startedAt, bCleanNs);
}


// ============================================================
// DISCOVERY (Viewer side)
// ============================================================

bool CLiveKadBridge::SearchStreams(const CString& keyword,
                                   std::vector<uint32>* outSearchIds,
                                   bool bForceDirect)
{
    CSingleLock lock(&m_lock, TRUE);
    if (outSearchIds) outSearchIds->clear();

    if (!Kademlia::CKademlia::IsConnected()) {
        // v0.71 P3.8 — log once per disconnected stretch, not every poll.
        // ASCII hyphen instead of em-dash to avoid CP1252/UTF-8 mojibake
        // ("â€"") when the log is rendered by a CP1252-decoding viewer.
        if (!m_bLoggedKadNotConnected) {
            AddLogLine(false, GetResString(IDS_LIVEKAD_CANNOT_SEARCH));
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
                GetResString(IDS_LIVEKAD_SEARCH_COOLDOWN_FMT),
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

    // v8.1 D1 - route discovery THROUGH THE TUNNEL when the mode wants it (Tunneled, or
    // Adaptive + a sensitive keyword) AND a circuit is available: the exit runs the real Kad
    // search on our behalf and the results return via the tunnel into our directory
    // (FeedTunneledSearchResults), so our IP + keyword never hit the public DHT. The token
    // bucket + cooldown above already rate-limited this call, so tunneled searches are capped too.
    // The EXIT (bForceDirect) MUST query Kad from its OWN IP; it must never re-enter the tunnel
    // branch (that would cascade a tunneled search out the exit's own circuit and return
    // stale-cache only). So the gate is skipped entirely for the exit.
    // LOCK NOTE: this gate calls tunnel / pool / selector methods while holding
    // CLiveKadBridge::m_lock => kadbridge -> {tunnel, pool[leaf], selector[leaf]}. That is the
    // REVERSE of the tunnel->kadbridge feed in HandleRelay_Originator (FeedTunneledSearchResults).
    // It is deadlock-free ONLY because both legs run on the MAIN thread (all SearchStreams callers
    // are main-thread / marshaled via UM_LIVE_KAD_REFRESH; the feed runs under OnCellReceived on
    // the main message pump). Never call SearchStreams or FeedTunneledSearchResults off the main thread.
    if (!bForceDirect) {
        ASSERT(GetCurrentThreadId() == g_uMainThreadId);
        eSELive::CLiveTunnel& tun = eSELive::CLiveTunnel::Get();
        const bool wantTunnel = tun.ShouldRouteThroughTunnel((LPCWSTR)searchWord,
            (uint8_t)Kademlia::CKadV2ModeSelector::QueryContext::KAD_SEARCH);
        if (wantTunnel) {
            // D5 - the PST pool picks the XOR-closest circuit to the real Kad keyword target
            // (Acquire now ranks by the exit's Kad node-ID). NOTE: the send path
            // (SendKadSearchV2NoWait -> SendMessagePinned) still round-robins, so Acquire here
            // drives availability + PST reuse; per-search traffic-steering through the exact
            // XOR-closest circuit is a soft follow-up (the XOR is a heuristic anyway).
            Kademlia::CKadTagValueString wstrKwTarget(searchWord);
            Kademlia::CUInt128 uXorTarget;
            EseLiveGetKeywordHash(wstrKwTarget, &uXorTarget);
            const bool haveTunnel =
                Kademlia::CKadV2TunnelPool::Get().Acquire(uXorTarget) != nullptr
                || tun.ActiveCircuitCount() > 0;
            // wide -> UTF-8 (already lowercased) for the tunnel search body.
            std::string kwUtf8;
            int blen = WideCharToMultiByte(CP_UTF8, 0, (LPCWSTR)searchWord,
                                           searchWord.GetLength(), NULL, 0, NULL, NULL);
            if (blen > 0) {
                kwUtf8.resize((size_t)blen);
                WideCharToMultiByte(CP_UTF8, 0, (LPCWSTR)searchWord, searchWord.GetLength(),
                                    &kwUtf8[0], blen, NULL, NULL);
            }
            if (haveTunnel && !kwUtf8.empty()) {
                tun.SendKadSearchV2NoWait(kwUtf8);
                m_dwLastSearchTime = now;
                m_strLastSearchKeyword = searchWord;
                AddLogLine(true, GetResString(IDS_LIVEKAD_SEARCH_TUNNELED_FMT),
                    (LPCTSTR)searchWord);
                CLiveDebugLog::Get().Append("KAD", "Search BEGIN [tunneled] keyword=\"%S\"",
                    (LPCWSTR)searchWord);
                return true;
            }
            // Wanted a tunnel but no circuit (or keyword unencodable) -> D3 fallback policy
            // (same as the subscribe path).
            const Kademlia::CKadV2ModeSelector::FallbackPolicy fb =
                Kademlia::CKadV2ModeSelector::Get().GetFallbackPolicy();
            if (fb == Kademlia::CKadV2ModeSelector::STRICT_PRIVACY) {
                AddLogLine(false, GetResString(IDS_LIVEKAD_SEARCH_STRICT_ABORT));
                CLiveDebugLog::Get().Append("KAD",
                    "Search ABORT [strict] keyword=\"%S\" - no tunnel circuit", (LPCWSTR)searchWord);
                return false;
            }
            // BALANCED / BEST_EFFORT -> fall through to the direct search below (warn IP visible).
            AddLogLine(false, GetResString(IDS_LIVEKAD_SEARCH_DIRECT_FALLBACK));
        }
    }

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
            AddLogLine(false, GetResString(IDS_LIVEKAD_SEARCH_IN_PROGRESS_FMT),
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
            GetResString(IDS_LIVEKAD_SEARCH_CLEAN_FMT),
            (LPCTSTR)searchWord, pSearchClean->GetSearchID());
        CLiveDebugLog::Get().Append("KAD",
            "Search BEGIN [clean] keyword=\"%S\" SearchID=%u",
            (LPCWSTR)searchWord, (unsigned)pSearchClean->GetSearchID());
        PendingSearchTag pst { ESE_NS_CLEAN, now };
        m_pendingSearchNamespaces[pSearchClean->GetSearchID()] = pst;
        if (outSearchIds) outSearchIds->push_back(pSearchClean->GetSearchID());
    }
    if (pSearchLegacy != NULL) {
        AddLogLine(true,
            GetResString(IDS_LIVEKAD_SEARCH_LEGACY_FMT),
            (LPCTSTR)searchWord, pSearchLegacy->GetSearchID());
        CLiveDebugLog::Get().Append("KAD",
            "Search BEGIN [legacy] keyword=\"%S\" SearchID=%u",
            (LPCWSTR)searchWord, (unsigned)pSearchLegacy->GetSearchID());
        PendingSearchTag pst { ESE_NS_LEGACY, now };
        m_pendingSearchNamespaces[pSearchLegacy->GetSearchID()] = pst;
        if (outSearchIds) outSearchIds->push_back(pSearchLegacy->GetSearchID());
    }

    m_dwLastSearchTime = now;
    m_strLastSearchKeyword = searchWord;
    return true;
}

// v8.1 D1 - UTF-8 wire string -> CString (CStringW in this Unicode build).
static CString Ese_Utf8ToCString(const std::string& u)
{
    if (u.empty()) return CString();
    int wlen = MultiByteToWideChar(CP_UTF8, 0, u.data(), (int)u.size(), NULL, 0);
    if (wlen <= 0) return CString();
    CStringW w;
    MultiByteToWideChar(CP_UTF8, 0, u.data(), (int)u.size(), w.GetBufferSetLength(wlen), wlen);
    w.ReleaseBuffer(wlen);
    return CString((LPCWSTR)w);
}

void CLiveKadBridge::FeedTunneledSearchResults(const std::vector<uint8_t>& in)
{
    // v8.1 D1 - MAIN THREAD ONLY. Reached under the tunnel m_lock (HandleRelay_Originator <-
    // OnCellReceived) and takes CLiveKadBridge::m_lock via OnKadSearchResult (tunnel->kadbridge).
    // Deadlock-free only because the reverse kadbridge->tunnel edge in the SearchStreams gate is
    // also main-thread. Do not call from a worker.
    ASSERT(GetCurrentThreadId() == g_uMainThreadId);
    // Wire format (Sprint B breakdown 2.3): [count u16 LE][2 reserved] then count *
    //   { recLen u16 LE, fixed 35B [streamKey16, ip u32 LE, port u16, uport u16, brate u16,
    //     views u32, start u32, ns u8], then 3 length-prefixed UTF-8 strings title/cat/lang }.
    // Every read is bounds-checked; OnKadSearchResult does NOT need m_lock held by us (it
    // takes its own), so we call it per record without holding it across the loop.
    const size_t n = in.size();
    if (n < 4) return;
    auto rd16 = [&](size_t o)->uint16_t { return (uint16_t)in[o] | ((uint16_t)in[o+1] << 8); };
    auto rd32 = [&](size_t o)->uint32_t {
        return (uint32_t)in[o] | ((uint32_t)in[o+1] << 8)
             | ((uint32_t)in[o+2] << 16) | ((uint32_t)in[o+3] << 24); };
    const uint16_t count = rd16(0);
    size_t p = 4;
    int fed = 0;
    for (uint16_t r = 0; r < count && p + 2 <= n; ++r) {
        const uint16_t recLen = rd16(p); p += 2;
        const size_t recEnd = p + recLen;
        if (recEnd > n) break;
        if (recLen < 35) { p = recEnd; continue; }   // fixed part = 35 B
        const size_t rec = p;
        uchar streamKey[16];
        memcpy(streamKey, &in[rec], 16);
        size_t q = rec + 16;
        const uint32_t ip    = rd32(q); q += 4;
        const uint16_t port  = rd16(q); q += 2;
        const uint16_t uport = rd16(q); q += 2;
        const uint16_t brate = rd16(q); q += 2;
        const uint32_t views = rd32(q); q += 4;
        q += 4;   // started_at (unused here)
        q += 1;   // ns tag (tunneled results attribute as UNKNOWN namespace)
        std::string title, cat, lang;
        auto rdstr = [&](std::string& o)->bool {
            if (q + 1 > recEnd) return false;
            uint8_t len = in[q]; q += 1;
            if (q + len > recEnd) return false;
            o.assign((const char*)&in[q], len); q += len; return true;
        };
        if (!rdstr(title) || !rdstr(cat) || !rdstr(lang)) { p = recEnd; continue; }
        // Same sink as the direct path (Search.cpp): OnKadSearchResult runs all the
        // validation / tombstone / clamp / dedupe logic and writes m_streamDirectory.
        // fromSearchID/altIP default to 0 (UNKNOWN namespace; no overlay endpoint over the tunnel).
        OnKadSearchResult(streamKey, Ese_Utf8ToCString(title), Ese_Utf8ToCString(cat),
                          ip, port, uport, brate, views, 0, 0,
                          ESE_PRIV_ORIGIN_KAD6_TUNNEL);
        ++fed;
        p = recEnd;
    }
    if (fed > 0)
        CLiveDebugLog::Get().Append("KAD", "Tunneled search fed %d result(s) into directory", fed);
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

bool CLiveKadBridge::AuthorizesExitProxy(const uchar* streamKey,
    uint32 broadcasterIP, uint16 broadcasterPort,
    uint16 broadcasterUDPPort) const
{
    if (streamKey == NULL || broadcasterIP == 0 || broadcasterPort == 0)
        return false;

    LiveStreamEntry entry;
    {
        CSingleLock lock(&m_lock, TRUE);
        const CString strKey = StreamKeyToString(streamKey);
        if (!m_streamDirectory.Lookup(strKey, entry)) return false;
    }

    // Check expiry after releasing m_lock.  The unsigned subtraction is
    // GetTickCount-wrap safe for this short (120 s) authorization window.
    if ((DWORD)(GetTickCount() - entry.lastSeen) > ESE_KAD_ENTRY_TTL)
        return false;
    if (theApp.liveStreamManager &&
        theApp.liveStreamManager->IsStreamTombstoned(entry.streamKey))
        return false;

    uint32 expectedIP = entry.broadcasterIP;
    if (expectedIP == 0 && entry.isOwnStream)
        expectedIP = theApp.GetPublicIP();
    return expectedIP != 0 && broadcasterIP == expectedIP &&
           broadcasterPort == entry.broadcasterPort &&
           broadcasterUDPPort == entry.broadcasterUDPPort;
}


// ============================================================
// NETWORK CALLBACKS
// ============================================================

void CLiveKadBridge::OnKadSearchResult(const uchar* streamKey,
    const CString& title, const CString& category,
    uint32 broadcasterIP, uint16 broadcasterPort,
    uint16 broadcasterUDPPort,
    uint16 bitrate, uint32 viewerCount,
    uint32 fromSearchID,
    uint32 broadcasterAltIP,
    uint8 privacyOrigin)
{
    CSingleLock lock(&m_lock, TRUE);
    const bool opaqueKad6Endpoint = privacyOrigin == ESE_PRIV_ORIGIN_KAD6_TUNNEL &&
        broadcasterIP == 0 && broadcasterPort == 0;

    // NAT-reach: sanitize the optional overlay endpoint up front. It is a
    // bonus dial target, never a reason to reject the whole result — zero
    // it on any doubt. IsGoodIP(_, true) forces the LAN check (10.x/172.16/
    // 192.168 stay out of the public DHT) while CGNAT overlay addresses
    // (100.64.0.0/10, e.g. Tailscale) pass.
    if (broadcasterAltIP != 0
        && (broadcasterAltIP == broadcasterIP
            || !IsGoodIP(broadcasterAltIP, true)
            || theApp.ipfilter->IsFiltered(broadcasterAltIP)))
        broadcasterAltIP = 0;

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
    if (!opaqueKad6Endpoint && (broadcasterIP == 0 || broadcasterPort == 0)) {
        AddLogLine(false, GetResString(IDS_LIVEKAD_REJECTED_INVALID_FMT),
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
        AddLogLine(false, GetResString(IDS_LIVEKAD_TOMBSTONE_RECEIVED_FMT),
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
        AddLogLine(false, GetResString(IDS_LIVEKAD_IGNORED_ECHO_FMT), (LPCTSTR)title);
        InterlockedIncrement(&theApp.liveStreamManager->GetCountersMut().kadResultsRejected);
        return;
    }

    // === Fix 15 (BAJA): Force LAN rejection for Kad public DHT ===
    // IsGoodIPPort() delegates to IsGoodIP() which respects FilterLANIPs() pref.
    // For Kad-discovered broadcasters, LAN IPs (10.x, 192.168.x, 172.16-31.x)
    // must ALWAYS be rejected since Kad is a public network.
    // Use IsGoodIP(ip, true) to force the LAN check regardless of preferences.
    if (!opaqueKad6Endpoint &&
        (!IsGoodIP(broadcasterIP, true) || broadcasterPort == 0)) {
        AddLogLine(false, GetResString(IDS_LIVEKAD_REJECTED_NONROUTABLE_FMT),
            (LPCTSTR)ipstr(broadcasterIP), broadcasterPort, (LPCTSTR)title);
        if (theApp.liveStreamManager != NULL)
            InterlockedIncrement(&theApp.liveStreamManager->GetCountersMut().kadResultsRejected);
        return;
    }

    // === Phase 1 KAD-4: IPFilter check ===
    // Reject IPs blocked by the user's IPFilter configuration.
    if (!opaqueKad6Endpoint && theApp.ipfilter->IsFiltered(broadcasterIP)) {
        AddLogLine(false, GetResString(IDS_LIVEKAD_REJECTED_FILTERED_FMT),
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
        AddLogLine(false, GetResString(IDS_LIVEKAD_REJECTED_BITRATE_FMT),
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
        // NAT-reach: a republish echo may carry endpoint extras an earlier
        // (legacy / synthetic) sighting lacked — merge them in.
        if (broadcasterUDPPort != 0) entry.broadcasterUDPPort = broadcasterUDPPort;
        if (broadcasterAltIP  != 0) entry.broadcasterAltIP  = broadcasterAltIP;
        // Privacy provenance is upgrade-only: once an endpoint was learned via
        // Kad6, a later direct/cache echo must not silently authorize a STRICT
        // direct dial of the same result.
        if (privacyOrigin == ESE_PRIV_ORIGIN_KAD6_TUNNEL)
            entry.privacyOrigin = privacyOrigin;
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
        entry.broadcasterAltIP = broadcasterAltIP;      // NAT-reach
        entry.lastSeen = GetTickCount();
        entry.startedAt = (uint32)time(NULL);
        entry.isOwnStream = false;
        entry.privacyOrigin = privacyOrigin == ESE_PRIV_ORIGIN_KAD6_TUNNEL
            ? ESE_PRIV_ORIGIN_KAD6_TUNNEL : ESE_PRIV_ORIGIN_DIRECT;

        AddLogLine(false, GetResString(IDS_LIVEKAD_DISCOVERED_FMT),
            (LPCTSTR)title, (LPCTSTR)ipstr(broadcasterIP), broadcasterPort,
            viewerCount, bitrate,
            nsTag == ESE_NS_CLEAN  ? (LPCTSTR)GetResString(IDS_LIVEKAD_TAG_CLEAN)
          : nsTag == ESE_NS_LEGACY ? (LPCTSTR)GetResString(IDS_LIVEKAD_TAG_LEGACY)
          :                          (LPCTSTR)GetResString(IDS_LIVEKAD_TAG_SYNTHETIC));
        CLiveDebugLog::Get().Append("KAD",
            "Discovered \"%S\" src=%S:%u udp=%u alt=%S %ukbps ns=%u",
            (LPCWSTR)title, (LPCWSTR)ipstr(broadcasterIP),
            (unsigned)broadcasterPort, (unsigned)broadcasterUDPPort,
            broadcasterAltIP ? (LPCWSTR)ipstr(broadcasterAltIP) : L"-",
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
        // Churn fix (2026-06): only a VIEWER needs to dial discovered sources.
        // On a non-viewing node (a pure broadcaster acting as tunnel exit, which
        // runs "eselive" searches on viewers' behalf) every dial is a no-op
        // (TryConnectToStreamSource bails on !m_bViewing) but still grows the
        // queue to its 50 cap and, worse, would have the broadcaster dial back
        // the very viewer it is serving (the viewer's V2-S17 relay republish) —
        // a reverse AttachToAlreadyKnown collision. Gate the enqueue on viewing.
        if (!theApp.liveStreamManager->IsViewingLive())
            return;
        // Dedup at enqueue: skip if this (ip,port) is already queued (results
        // arrive in bursts faster than the 3/tick drain, so the same endpoint
        // piles up and keeps re-triggering dials). The dial-time cooldown in
        // TryConnectToStreamSource is the second line of defense.
        for (INT_PTR i = 0; i < m_pendingDials.GetCount(); ++i) {
            if ((opaqueKad6Endpoint &&
                 memcmp(m_pendingDials[i].streamKey, streamKey, 16) == 0) ||
                (!opaqueKad6Endpoint && m_pendingDials[i].ip == broadcasterIP &&
                 m_pendingDials[i].port == broadcasterPort))
                return;
        }
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
        // NAT-reach: use the merged entry value so a legacy echo without the
        // tag still dials the overlay endpoint learned from an earlier result.
        pd.altIP   = entry.broadcasterAltIP;
        pd.privacyOrigin = entry.privacyOrigin;
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
            AddLogLine(false, GetResString(IDS_LIVEKAD_FLUSH_DEFERRED_FMT),
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
                pd.streamKey, pd.ip, pd.port, pd.udpPort, pd.altIP,
                pd.privacyOrigin == ESE_PRIV_ORIGIN_KAD6_TUNNEL);
            // NAT-reach: race the overlay endpoint too (happy-eyeballs). A
            // NATed broadcaster's public IP never answers; its 100.64/10
            // overlay address does. Whichever TCP connect lands first sends
            // the heartbeat. We pass each call its SIBLING address so that once
            // one endpoint is a live view-peer, TryConnectToStreamSource
            // suppresses re-dialing the other (dual-dial churn fix: a 2nd
            // session would recycle the working socket via AttachToAlreadyKnown).
            // Dedupe/caps inside TryConnectToStreamSource keep this bounded.
            if (pd.altIP != 0 && pd.altIP != pd.ip)
                theApp.liveStreamManager->TryConnectToStreamSource(
                    pd.streamKey, pd.altIP, pd.port, pd.udpPort, pd.ip,
                    pd.privacyOrigin == ESE_PRIV_ORIGIN_KAD6_TUNNEL);
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
        AddLogLine(false, GetResString(IDS_LIVEKAD_PRUNED_FMT),
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
//   ESELIVE_DIR v2
//   <streamKey-hex32>\t<title>\t<category>\t<language>\t<bitrate>\t
//                <viewerCount>\t<broadcasterIP>\t<broadcasterPort>\t
//                <broadcasterUDPPort>\t<startedAt>\t<lastSeenUnix>\t
//                <privacyOrigin>\n
// v1 (11 fields) remains readable and defaults privacyOrigin to DIRECT.
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

            // Tab-separated fields: 11 in v1, 12 in v2.
            CString fields[12];
            const int expectedFields = version >= 2 ? 12 : 11;
            int fIdx = 0;
            int pos = 0;
            CString tok;
            while (fIdx < expectedFields) {
                tok = line.Tokenize(_T("\t"), pos);
                if (tok.IsEmpty() && pos < 0) break;
                fields[fIdx++] = tok;
            }
            if (fIdx < expectedFields) { skipped++; continue; }

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
            entry.privacyOrigin      = (version >= 2 && _ttoi(fields[11]) ==
                                         ESE_PRIV_ORIGIN_KAD6_TUNNEL)
                ? ESE_PRIV_ORIGIN_KAD6_TUNNEL : ESE_PRIV_ORIGIN_DIRECT;

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
        AddLogLine(false, GetResString(IDS_LIVEKAD_LOADED_CACHE_FMT),
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
            row.Format(_T("%s\t%s\t%s\t%s\t%u\t%u\t%u\t%u\t%u\t%u\t%u\t%u\n"),
                (LPCTSTR)hex, (LPCTSTR)title, (LPCTSTR)category, (LPCTSTR)language,
                entry.bitrate, entry.viewerCount,
                entry.broadcasterIP, entry.broadcasterPort, entry.broadcasterUDPPort,
                entry.startedAt, lastSeenUnix, entry.privacyOrigin);
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
