//this file is part of eMule
// eSE — Kad Bridge for Live Stream Discovery
// Publishes and discovers live streams using the Kad DHT network
// without modifying the Kad core code.
#pragma once

#include "LiveProtocol.h"

struct KadDebugSnapshot;  // Forward declaration (defined in LiveStreamManager.h)

class CUpDownClient;
namespace Kademlia { class CUInt128; }  // for StartLivePublishSearch helper

// DISC-S15 NOTE (deferred to V3): a true wire-level "role" tag distinguishing
// broadcaster origin from secondary relay requires extending the Kad core
// (new TAG_ESE_LIVE_ROLE, new field in CSearch::SetLiveStreamPublish, new
// read path in OnKadSearchResult inside Search.cpp). The change touches the
// Kad serialization format and risks breaking compatibility with non-eSE Kad
// nodes. Better tackled together with the V3 protocol versioning sprint
// (SPRINTS_V3.md A.* and Search.cpp restructure). For v2 we live with the
// minor cost: the parent selector (V2-S20 RTT-bias + V2-S19 multi-parent)
// already prefers low-RTT peers regardless of role, so the absence of an
// explicit "origin" preference is functionally invisible in practice.

// eSE Live keyword-namespace attribution tags. Carried on each
// LiveStreamEntry to track which hash domain it was discovered through.
// 'clean'  = MD4("\x00eSE\x00" || utf8(kw))  — new dedicated namespace.
// 'legacy' = MD4(utf8(kw))                   — old shared namespace.
// 'unknown'= synthetic (PEX, bootstrap cache, MFC-side hand-injected).
enum EseLiveNamespace : uint8 {
    ESE_NS_UNKNOWN = 0,
    ESE_NS_CLEAN   = 1,
    ESE_NS_LEGACY  = 2
};

// Discovery entry for a found live stream
struct LiveStreamEntry {
    uchar       streamKey[16] = {};
    CString     title;
    CString     category;
    CString     language;
    uint16      bitrate = 0;
    uint32      viewerCount = 0;
    uint32      broadcasterIP = 0;
    uint16      broadcasterPort = 0;
    uint16      broadcasterUDPPort = 0;  // A.4 Sprint 1: Kad UDP port for hole-punch
    DWORD       lastSeen = 0;            // GetTickCount() when last seen/refreshed
    uint32      startedAt = 0;           // Unix timestamp
    bool        isOwnStream = false;
    // H5 — dual-namespace adoption telemetry. Upgrade-only: once an
    // entry has been seen on the clean namespace we keep that tag even
    // if a later legacy result for the same streamKey arrives.
    uint8       discoveryNamespace = ESE_NS_UNKNOWN;
};

class CLiveKadBridge
{
public:
    CLiveKadBridge();
    ~CLiveKadBridge();

    // === Publishing (Broadcaster side) ===

    // Publish a live stream to the Kad network
    // Creates keyword entries based on the stream title
    // Returns true if publish was initiated
    bool PublishStream(const LiveStreamInfo& info);

    // Remove a published stream from the local directory
    void UnpublishStream(const uchar* streamKey);

    // DISC-S04: publish a tombstone for `streamKey` WITHOUT requiring local
    // state (no m_bPublished, no m_publishedInfo). Used at startup to evict
    // a ghost entry left by the previous session that crashed.
    bool PublishTombstoneFor(const uchar* streamKey);

    // Re-publish (called periodically, e.g. every 5 min)
    void RepublishIfNeeded();

    // V2-S17 — Viewer announces itself as a SECONDARY source for streamKey
    // under the livehash:HASH keyword only. Joiners doing a livehash search
    // discover us alongside the original broadcaster, enabling tree topology.
    // Idempotent on the Kad side; called every 30 s by the manager Process().
    bool PublishAsRelay(const uchar* streamKey, LPCWSTR title,
        LPCWSTR category, LPCWSTR language, uint16 bitrate);

    // === Discovery (Viewer side) ===

    // Search for live streams by keyword
    // Results arrive asynchronously via OnStreamFound callback
    bool SearchStreams(const CString& keyword);

    // Get current directory of known streams
    void GetKnownStreams(CArray<LiveStreamEntry>& outList) const;

    // Lookup a specific stream by key
    bool GetStreamInfo(const uchar* streamKey, LiveStreamEntry& outEntry) const;

    // === Network Callbacks ===

    // Called when we receive a Kad search result that's a live stream.
    // A.4 Sprint 1: broadcasterUDPPort is the Kad UDP port (TAG_SOURCEUPORT)
    // — needed for uTP hole-punching when both peers are LowID. Pass 0 if
    // not advertised (legacy clients); we'll skip hole-punch in that case.
    // H5: fromSearchID is the CSearch ID that produced this result, used
    // for clean-vs-legacy namespace attribution. 0 = synthetic (PEX,
    // bootstrap cache, MFC-side hand-injected) — counts as unknown.
    void OnKadSearchResult(const uchar* streamKey, const CString& title,
        const CString& category, uint32 broadcasterIP, uint16 broadcasterPort,
        uint16 broadcasterUDPPort,
        uint16 bitrate, uint32 viewerCount,
        uint32 fromSearchID = 0);

    // === Periodic Maintenance ===

    // Called from CLiveStreamManager::Process()
    void Process();

    // Prune stale entries (not seen in > 5 min)
    void PruneStaleEntries();

    // === Accessors ===
    int GetDirectoryCount() const;

    // Phase 0: Debug accessors
    DWORD GetLastPublishTime() const { return m_dwLastPublishTime; }
    DWORD GetLastSearchTime() const  { return m_dwLastSearchTime; }
    uint32 GetLastResultIP() const   { return m_dwLastResultIP; }
    uint16 GetLastResultPort() const { return m_wLastResultPort; }
    DWORD GetLastResultTime() const  { return m_dwLastResultTime; }

    // Thread-safe snapshot of all debug fields (takes m_lock)
    KadDebugSnapshot BuildDebugKadSnapshot() const;

private:
    // Local directory of known streams
    CMap<CString, LPCTSTR, LiveStreamEntry, LiveStreamEntry&> m_streamDirectory;

    // Publish state
    bool    m_bPublished;
    DWORD   m_dwLastPublishTime;
    DWORD   m_dwLastSearchTime;
    DWORD   m_dwLastPruneTime;
    CString m_strLastSearchKeyword;

    LiveStreamInfo m_publishedInfo;  // Info of our own stream (if broadcasting)

    mutable CCriticalSection m_lock;

    // Phase 0: Last discovery result tracking
    uint32  m_dwLastResultIP;
    uint16  m_wLastResultPort;
    DWORD   m_dwLastResultTime;

    // Phase 2 LAT-2: accelerated publish at broadcast start.
    // Tracks how many "fast" publishes (5 s, then 15 s) we have done since
    // the last UnpublishStream(); after the second fast burst we settle into
    // the normal 60 s republish cadence. Resets to 0 on Unpublish.
    int     m_nPublishBurstCount;
    DWORD   m_dwBurstStartTime;

    // DISC-S03: when PublishStream() is called while Kad is offline, we set
    // this flag so Process() detects the off->on transition and forces an
    // immediate burst publish (instead of waiting up to 60 s for the regular
    // republish cadence). Cleared when the publish actually goes out.
    bool    m_bDeferredFirstPublish;
    bool    m_bKadWasConnectedLastTick;

    // DISC-S08: token bucket for global SearchStreams rate limit.
    // Capacity 10, refills 1 token every 6 s -> sustained 10 searches/min.
    int     m_nSearchTokens;
    DWORD   m_dwLastSearchTokenRefill;

    // DISC-S06: pending dial queue. OnKadSearchResult enqueues here instead
    // of dialing synchronously; Process() drains at most 3 per tick so a
    // search that returns 100 hits doesn't burst-open 100 sockets.
    struct PendingDial {
        uchar  streamKey[16];
        uint32 ip;
        uint16 port;
        uint16 udpPort;
    };
    CArray<PendingDial> m_pendingDials;
    static const int    kMaxPendingDials   = 50;   // FIFO drop beyond this
    static const int    kDialsPerTick      = 3;

    // H5 — Kad search ID → namespace attribution map.
    // Populated by SearchStreams when a KEYWORD search is created;
    // read by OnKadSearchResult to tag the resulting LiveStreamEntry.
    // Pruned in Process() after 30 s — Kad searches complete in 5-10 s
    // so 30 s is generous and bounds map size in the worst case.
    struct PendingSearchTag {
        uint8 nsTag;       // ESE_NS_CLEAN or ESE_NS_LEGACY
        DWORD createdAt;   // GetTickCount() at insertion
    };
    CMap<uint32, uint32, PendingSearchTag, PendingSearchTag&> m_pendingSearchNamespaces;
    DWORD m_dwLastNsMapPrune;
    static const DWORD kNsMapEntryTTL = 30u * 1000u;
    static const DWORD kNsMapPruneInterval = 10u * 1000u;

    // Disk persistence: keep a snapshot of the discovered-streams directory
    // so the viewer doesn't start /live empty after every eMule restart
    // (Kad takes a while to repopulate it organically).
    bool    m_bLoadedFromDisk;          // false until first lazy load attempt
    DWORD   m_dwLastDiskSaveTime;       // throttles SaveDirectoryToDisk()

    // Disk persistence helpers (versioned, plain-text key=value lines).
    // Path: <ConfigDir>\eselive_directory.dat
    void LoadDirectoryFromDisk();
    void SaveDirectoryToDisk();
    static CString GetDirectoryFilePath();

    // Helper: generate Kad keyword hash from stream title
    CString StreamKeyToString(const uchar* streamKey) const;

    // Helper: encode stream info into Kad-compatible tag format
    void EncodeStreamTags(const LiveStreamInfo& info, CByteArray& outData) const;

    // eSE Live dual-namespace publish helper. Builds a CSearch::STOREKEYWORD
    // for `uTarget` and seeds it with m_publishedInfo + thePrefs.GetPort().
    // `keyword` is only used for the GUI name and log line; the actual
    // Kad target is `uTarget` (caller picks clean vs legacy hash).
    // `namespaceTag` is a short literal ("clean" | "legacy") that ends up
    // in the GUI name + log so dual-publish operations are distinguishable
    // by eye when grepping logs. Returns true if the search was started.
    bool StartLivePublishSearch(const Kademlia::CUInt128& uTarget,
                                LPCTSTR keyword, LPCTSTR namespaceTag);

    // H7 — primitive STOREKEYWORD publish with all SetLiveStreamPublish
    // parameters explicit. Used by tombstones, ghost-cleanup, and relay
    // announcements where the params don't come from m_publishedInfo and
    // can't share StartLivePublishSearch's m_publishedInfo bindings.
    // Port is always thePrefs.GetPort(). Returns true on success.
    // bCleanNs (H8): when true, the publish targets the eSE-dedicated
    // namespace and TAG_FILENAME/TAG_FILETYPE will be omitted to deny a
    // human-readable title to eSE-aware crawlers.
    bool StartKeywordPublish(const Kademlia::CUInt128& uTarget, LPCTSTR displayName,
                             const uchar* streamKey, LPCWSTR title,
                             LPCWSTR category, LPCWSTR language,
                             uint16 bitrate, uint32 viewerCount, uint32 startedAt,
                             bool bCleanNs);
};
