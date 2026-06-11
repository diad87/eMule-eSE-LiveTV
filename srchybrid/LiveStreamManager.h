//this file is part of eMule
// eSE — Live Stream Manager
// Manages P2P live streaming: broadcasting, viewing, peer scoring, anti-Sybil.
#pragma once

#include "LiveProtocol.h"
#include "LiveChunkBuffer.h"
#include "LiveKadBridge.h"
#include "LiveMeshManager.h"
#include "LiveDebugLog.h"        // V2-S05: LatencyHistogram
#include "RTMPIngest.h"

// C6 (2026-06): CMap hash for the durable LivePeerId key. `inline` keeps it
// ODR-safe across the TUs that include this header (same idiom as MapKey.h's
// HashKey<CSKey>). operator== for LivePeerId is in LiveProtocol.h.
template<> inline UINT AFXAPI HashKey(const LivePeerId& key)
{
    UINT h = 2166136261u ^ (UINT)key.kind;   // FNV-1a over kind + 32 id bytes
    for (int i = 0; i < 32; ++i) { h ^= key.bytes[i]; h *= 16777619u; }
    return h;
}

// eSE Phase 0: Per-stream observability counters (OBS-1)
// All counters are LONG for InterlockedIncrement/InterlockedExchange thread safety.
// These are incremented from multiple threads (network callbacks, timer, UI)
// without guaranteed lock coverage, so atomic operations are mandatory.
struct LiveStreamCounters {
    LONG kadPublishes;          // Kad publish operations queued
    LONG kadSearches;           // Kad search requests issued
    LONG kadResultsAccepted;    // Kad results that passed validation (in KadBridge)
    LONG kadResultsRejected;    // Kad results discarded (invalid/filtered)
    LONG sourceDialAttempts;    // TryConnectToStreamSource() calls (was duplicate kadResultsAccepted)
    LONG subscribeSent;         // OP_LIVE_SUBSCRIBE packets sent
    LONG subscribeAccepted;     // Subscribe responses received
    LONG chunksRequested;       // OP_LIVE_REQUEST packets sent
    LONG chunksReceived;        // OP_LIVE_CHUNK packets received
    LONG chunksMissing;         // Chunk timeouts / missing detections
    LONG hlsSegmentsWritten;    // HLS .ts files written to disk
    LONG hlsPlaylistRefresh;    // HLS .m3u8 regenerations
    LONG peerDisconnects;       // Peer disconnect events
    LONG lastChunkReceivedAt;   // GetTickCount() of last chunk arrival (via InterlockedExchange)
    // v7.3.0 — observability for the security/efficiency passes.
    LONG skippedInitialPushes;  // Initial pushes skipped by (IP,port) cooldown (v7.2.2)
    LONG subscribesRateLimited; // SUBSCRIBE rejects by per-IP rate limit (v7.3.0)
    LONG endsRejectedNoAuth;    // OP_LIVE_END rejected because sender wasn't in our mesh
    LONG tombstonesEvicted;     // Tombstones forcibly evicted to keep map under cap
    // DISC-S11: visibility into Kad discovery health
    LONG kadSearchesEmpty;      // searches that returned 0 hits (timeout / propagation)
    LONG kadSearchesRateLimited;// searches dropped by token bucket (DISC-S08)
    LONG pendingDialsDropped;   // results dropped because dial queue was full (DISC-S06)
    // DISC-S12: time-to-first-chunk (single histogram populated in OnChunkReceived
    // on the first chunk of a JoinStream session). Total/count -> mean.
    LONG joinToFirstChunkSamples;
    LONG joinToFirstChunkSumMs;
    // Phase-1 stabilization (2026-06): waste visibility for the pull path.
    LONG duplicateChunksReceived;     // chunks the buffer rejected (dup/stale) — wasted download
    LONG requestsSuppressedInflight;  // re-requests skipped because one was already in flight

    LiveStreamCounters()
        : kadPublishes(0), kadSearches(0)
        , kadResultsAccepted(0), kadResultsRejected(0)
        , sourceDialAttempts(0)
        , subscribeSent(0), subscribeAccepted(0)
        , chunksRequested(0), chunksReceived(0), chunksMissing(0)
        , hlsSegmentsWritten(0), hlsPlaylistRefresh(0)
        , peerDisconnects(0), lastChunkReceivedAt(0)
        , skippedInitialPushes(0), subscribesRateLimited(0)
        , endsRejectedNoAuth(0), tombstonesEvicted(0)
        , kadSearchesEmpty(0), kadSearchesRateLimited(0)
        , pendingDialsDropped(0)
        , joinToFirstChunkSamples(0), joinToFirstChunkSumMs(0)
        , duplicateChunksReceived(0), requestsSuppressedInflight(0)
    {}
};

// V2-S12 — Auto-tier classification of THIS peer based on upload capacity vs
// the active stream bitrate. Drives upload caps (S13), throttle policy (S14),
// and (later) tree topology decisions.
enum PeerTier {
    TIER_LEAF_RESTRICTED = 0,  // Capacity < 0.5x stream bitrate: receive only
    TIER_LEAF             = 1, // 0.5x..1.5x: serve at most 1 child
    TIER_MID              = 2, // 1.5x..4x:  up to 3 children
    TIER_SUPER_SEEDER     = 3, // 4x..10x:   up to 10 children
    TIER_MEGA_SEEDER      = 4  // >= 10x:    up to 25 children (broadcaster-class)
};

// V2-S01/S02/S03: Per-peer counters for ratio enforcement and parent selection.
// Used by ratio throttle (S14), tier classification (S12) and best-parent picker.
// All updates happen under CLiveStreamManager::m_lock; reads in BuildDebugSnapshot
// also hold the same lock so plain (non-atomic) members are safe.
struct PeerCounters {
    uint64 bytes_in_total;        // bytes received from this peer (cumulative)
    uint64 bytes_out_total;       // bytes sent to this peer (cumulative)
    uint64 bytes_in_window_60s;   // bytes in current 60-s ratio window
    uint64 bytes_out_window_60s;  // bytes out in current 60-s ratio window
    DWORD  window_start_tick;     // GetTickCount() when current window opened
    DWORD  rtt_ms_ewma;           // EWMA(alpha=1/8) of round-trip latency, ms
    DWORD  last_chunk_recv_ms;    // GetTickCount() of last chunk received from peer
    DWORD  last_chunk_sent_ms;    // GetTickCount() of last chunk we sent to peer
    DWORD  last_ping_sent_ms;     // GetTickCount() of last PING we issued
    int    chunks_served;         // chunks we sent to this peer
    int    chunks_received;       // chunks we received from this peer
    int    pings_sent;            // total PINGs issued (for loss detection)
    int    pongs_received;        // total PONGs received

    static const DWORD WINDOW_MS = 60000;

    PeerCounters()
        : bytes_in_total(0), bytes_out_total(0)
        , bytes_in_window_60s(0), bytes_out_window_60s(0)
        , window_start_tick(0), rtt_ms_ewma(0)
        , last_chunk_recv_ms(0), last_chunk_sent_ms(0), last_ping_sent_ms(0)
        , chunks_served(0), chunks_received(0)
        , pings_sent(0), pongs_received(0)
    {}

    // V2-S02: roll the 60-s window if expired. Call before incrementing window_*.
    void MaybeResetWindow(DWORD now) {
        if (window_start_tick == 0 || (now - window_start_tick) > WINDOW_MS) {
            bytes_in_window_60s  = 0;
            bytes_out_window_60s = 0;
            window_start_tick    = now;
        }
    }

    // V2-S02: ratio = bytes_out / bytes_in over last 60 s.
    // Returns 1.0 (= "neutral") if no inbound data yet to avoid bootstrap throttle.
    float Ratio60s() const {
        if (bytes_in_window_60s == 0) return 1.0f;
        return (float)bytes_out_window_60s / (float)bytes_in_window_60s;
    }
};

// eSE: Kad discovery snapshot (read under CLiveKadBridge::m_lock)
struct KadDebugSnapshot {
    bool   kadConnected;
    int    knownStreams;
    DWORD  lastPublishTime;
    DWORD  lastSearchTime;
    DWORD  lastResultTime;
    uint32 lastResultIP;
    uint16 lastResultPort;
    // H5 — dual-namespace adoption: count of entries in the directory
    // tagged as clean / legacy / unknown (synthetic) by source. Sum can
    // be less than knownStreams when own-streams or stale entries lack
    // a discovery tag yet. Used by /api/live/debug to decide when it
    // is safe to flip GetEseLivePublishLegacy() to false.
    int    knownStreamsClean;
    int    knownStreamsLegacy;
};

// eSE: Thread-safe debug snapshot for /api/live/debug.
// All fields are plain copies — no pointers, no CMap iterators.
struct LiveDebugSnapshot {
    // Stream state
    bool     broadcasting;
    bool     viewing;
    bool     emergencyMode;
    uint32   uptimeMs;

    // Kad discovery
    KadDebugSnapshot kad;

    // Peers
    int      viewPeers;
    int      broadcastPeers;
    int      meshPeers;
    int      pendingRequests;
    int      chunksServed;
    int      superSeeders;
    int      middlePeers;
    int      leafPeers;

    // Chunk buffer
    int      bufCount;
    uint32   oldestSeq;
    uint32   newestSeq;
    uint16   bitmap;
    int      missingChunks;

    // Mesh
    uint64   totalRedistributed;
    uint32   minUploadRequired;   // upload floor for the throttler (/api/live/mesh)

    // Counters (atomic snapshot)
    LiveStreamCounters counters;
};

// eSE: Thread-safe snapshot for /api/live/channels — copied under m_lock so
// the WebServer worker never reads m_streamInfo (incl. its CString title)
// while the main thread mutates it.
struct LiveChannelSnapshot {
    bool    broadcasting;
    uchar   streamKey[16];
    CString title;
    uint32  bitrate;
    uint32  viewerCount;
};

// eSE: worker -> main-thread marshaling block for /api/live/join and
// /api/live/direct_join (UM_LIVE_WEB_JOIN). The webserver worker fills the
// inputs and SendMessage's a pointer to this struct (synchronous, so it stays
// alive for the call); the main thread runs JoinStream + the optional
// TryConnectToStreamSource and writes the results back.
struct LiveWebJoinReq {
    const uchar *streamKey;   // -> caller's uchar[16], stable during SendMessage
    LPCTSTR      title;       // -> caller's CString buffer
    uint32       ip;          // 0 => Kad-only join, no direct dial
    uint16       port;        // 0 => Kad-only join, no direct dial
    bool         joined;      // [out] JoinStream accepted the request
    bool         dialed;      // [out] TryConnectToStreamSource dialed a source
};

// eSE: worker -> main-thread marshaling block for /api/live/broadcast/start
// and /api/live/broadcast/stop (UM_LIVE_WEB_BROADCAST). Only the launch /
// stop runs on the main thread; the webserver worker does the prebuffer wait
// itself via GetBroadcastLivenessStatus().
enum LiveWebBroadcastAction { LIVE_WEB_BC_LAUNCH = 0, LIVE_WEB_BC_STOP = 1 };
struct LiveWebBroadcastReq {
    int     action;          // LiveWebBroadcastAction
    LPCTSTR sourceType;      // launch inputs (-> caller's CString buffers)
    LPCTSTR title;
    LPCTSTR category;
    LPCTSTR language;
    LPCTSTR mediaFilePath;
    uint16  bitrate;
    bool    ok;              // [out] launch: armed; stop: was broadcasting
};

// eSE: worker -> main-thread marshaling block for /api/live/leave
// (UM_LIVE_WEB_LEAVE, ghost-viewer fix 2026-06).
struct LiveWebLeaveReq {
    bool wasViewing;         // [out] true if a viewing session was actually ended
};

class CUpDownClient;

class CLiveStreamManager {
public:
    CLiveStreamManager();
    ~CLiveStreamManager();

    // === Broadcaster API ===
    // Start broadcasting a stream (called when HLS segments start generating)
    bool StartBroadcast(const CString& title, const CString& category,
                        const CString& language, uint16 bitrate);
    // Stop broadcasting
    void StopBroadcast();
    // Feed a new HLS segment into the buffer (called by RTMPIngest or file watcher)
    void FeedSegment(const BYTE* data, uint32 dataSize);
    // Is currently broadcasting?
    bool IsBroadcasting() const { return m_bBroadcasting; }

    // Tier 2.2: One-shot broadcast launcher for the web UI.
    // sourceType: "testpattern" | "screen" | "file" | "rtmp"
    // mediaFilePath only required when sourceType=="file".
    // Performs FFmpeg launch + 2 s liveness probe + StartBroadcast() in the
    // correct order (PRE-WARM ordering). Returns false on any failure.
    bool StartBroadcastWithSource(const CString& sourceType,
                                  const CString& title,
                                  const CString& category,
                                  const CString& language,
                                  uint16 bitrate,
                                  const CString& mediaFilePath = _T(""),
                                  bool waitForPrebuffer = true);
    // Lock-correct liveness probe for the web API's prebuffer wait: reads
    // FFmpeg-running + chunk-buffer count under m_lock. Worker-thread safe.
    void GetBroadcastLivenessStatus(bool& outFFmpegRunning, int& outChunkCount);
    // Stop both the FFmpeg ingest AND the P2P broadcast in one call.
    void StopBroadcastFull();
    // Read access to the shared ingest (MFC dialog uses it for status text).
    CRTMPIngest& GetRTMPIngest() { return m_rtmpIngest; }

    // === Viewer API ===
    // Join a remote stream by its streamKey
    bool JoinStream(const uchar* streamKey, const CString& title);
    // Leave the current stream
    void LeaveStream();
    // Is currently viewing a live stream?
    bool IsViewingLive() const { return m_bViewing; }
    // Connect to a discovered broadcaster/relay for the stream we are viewing.
    // A.4 Sprint 1: udpPort optional — when non-zero, populates CUpDownClient
    // KadPort so TryToConnect can hole-punch via SendEseHolePunchReq if TCP
    // direct fails (LowID broadcaster).
    bool TryConnectToStreamSource(const uchar* streamKey, uint32 ip, uint16 port, uint16 udpPort = 0);

    // v8.1 Sprint C (C2) — exit-side proxy subscribe. Called on the main thread
    // by the tunnel exit handler (ExitHandle_LiveSubscribe) when a tunneled
    // subscribe arrives: dial the broadcaster and send OP_LIVE_SUBSCRIBE from
    // THIS node (the exit) on the viewer's behalf, WITHOUT entering our own
    // viewing state (m_bViewing / m_viewPeers untouched). The broadcaster thus
    // sees the exit, never the viewer. altIP is tried if the public endpoint is
    // non-routable. Returns true if the subscribe packet was sent. The heartbeat
    // / announce relay back to the viewer is C3.
    bool ExitProxySubscribe(const uchar* streamKey, uint32 ip, uint16 port,
                            uint16 udpPort, uint32 altIP);

    // v8.1 Sprint C (C4 zombie fix) — exit-side proxy UNSUBSCRIBE. Called from
    // the tunnel sweep when the last tunneled viewer of a stream leaves: tells
    // the broadcaster to drop us from m_broadcastPeers so we stop occupying an
    // upload slot with zero downstream viewers. Main thread.
    void ExitProxyUnsubscribe(const uchar* streamKey, uint32 ip, uint16 port);

    // v8.1 Sprint C (C3) — viewer side: the exit relayed the broadcaster's
    // control update (a heartbeat's bitmap+oldestSeq, and/or an announce's
    // pubkey) over the tunnel. Pin the pubkey, and in Tunelizado mode bridge the
    // live-edge bitmap onto our DIRECT view peer(s) so the existing pull path
    // (SelectPeerForSegment) works with chunks staying direct. Called from the
    // tunnel originator demux (main thread). pubkeyOrNull may be NULL.
    void OnTunneledLiveControl(const uchar* streamKey, bool hasBitmap,
                               uint16 bitmap, uint32 oldestSeq,
                               const uchar* pubkeyOrNull);

    // === Peer Management ===
    // Called when a peer sends OP_LIVE_JOIN
    void OnPeerJoin(CUpDownClient* peer, const uchar* streamKey, uint32 uploadCapacity);
    // Called when a peer sends OP_LIVE_REQUEST
    void OnPeerRequest(CUpDownClient* peer, const uchar* streamKey, uint32 seqNum);
    // Called when we receive OP_LIVE_CHUNK from a peer
    void OnChunkReceived(CUpDownClient* peer, const uchar* streamKey,
                         uint32 seqNum, uint32 timestamp, const BYTE* data, uint32 dataSize);
    // Called when a peer sends OP_LIVE_BITMAP
    void OnPeerBitmap(CUpDownClient* peer, const uchar* streamKey,
                      uint32 oldestSeq, uint16 bitmap);
    // Called when a peer sends OP_LIVE_PEER_LIST
    void OnPeerListReceived(CUpDownClient* peer, const uchar* streamKey,
                            const CArray<DWORD>& ips, const CArray<uint16>& ports);
    // v0.71 IPv6 Sprint 7 follow-up — OP_LIVE_PEER_LIST_V2 receiver path.
    // The v4 entries are passed through to the uint32 overload; v6 entries
    // are logged and dropped until CUpDownClient learns a v6 socket path
    // (Sprint 4 Kad-v6 routing zone integration). When that lands, the
    // method dials v6 peers directly via TryConnectToStreamSource(CAddress).
    void OnPeerListReceivedV6(CUpDownClient* peer, const uchar* streamKey,
                              const CArray<class CAddress>& addrs,
                              const CArray<uint16>& ports);
    // Called when a peer disconnects
    void OnPeerDisconnected(CUpDownClient* peer);

    // v7.2.0 — Called when a peer sends OP_LIVE_END (or when the local
    // watchdog declares a stream dead). Tombstones the streamKey for
    // ~30 min so Kad echoes from cached nodes can't resurrect it, then
    // gossips the END to our mesh peers (one hop is enough; receivers
    // re-gossip iff not already tombstoned, so propagation is bounded
    // and storms self-limit). If we were viewing this stream, we leave
    // it. `fromPeer` is the peer that informed us — we don't gossip
    // back to them. NULL means "self-detected via watchdog".
    void OnStreamEnded(const uchar* streamKey, uint8 reason, CUpDownClient* fromPeer);

    // v7.2.0 — Tombstone check used by the Kad bridge to discard Kad
    // search results for streams we already know are dead.
    bool IsStreamTombstoned(const uchar* streamKey) const;

    // === Anti-Sybil ===
    // Calculate trust level for a peer based on response rate (NOT volume)
    int CalculateTrustLevel(CUpDownClient* peer);
    // Measure peer response rate and promote/demote
    void MeasurePeerRatio(CUpDownClient* peer);
    // Send a probe request to test if peer responds
    void ProbeTestPeer(CUpDownClient* peer);
    // Check subnet diversity before promoting to super-seeder
    bool CanPromoteToSuperSeeder(CUpDownClient* peer);
    // Monitor for mass disconnection (possible attack)
    void MonitorPeerHealth();

    // === Periodic Tasks (called from timer) ===
    void Process();     // Main timer tick (every 1 second)

    // === State ===
    const CLiveChunkBuffer& GetBuffer() const { return m_chunkBuffer; }
    const LiveStreamInfo& GetStreamInfo() const { return m_streamInfo; }
    uint32 GetViewerCount() const;
    uint32 GetMinUploadRequired() const;  // For UploadBandwidthThrottler
    CLiveKadBridge& GetKadBridge() { return m_kadBridge; }
    CLiveMeshManager& GetMeshManager() { return m_meshManager; }

    // v7.7.0 — pubkey pin accessors. PinStreamPubkey is idempotent: once a
    // streamKey is pinned to a pubkey, subsequent calls with a different
    // pubkey for the same streamKey are rejected (returns false). Used by
    // OP_LIVE_ANNOUNCE handler and Kad search result to record the binding,
    // and by OP_LIVE_CHUNK_V2 / signed OP_LIVE_END handlers to verify.
    bool PinStreamPubkey(const uchar streamKey[16], const uchar pubkey[32]);
    // Returns true and fills outPubkey if a pin exists for streamKey.
    bool GetPinnedPubkey(const uchar streamKey[16], uchar outPubkey[32]) const;

    // Accessors for WebServer and UI
    const uchar* GetStreamKey() const { return m_streamInfo.streamKey; }
    CString GetStreamTitle() const { return m_streamInfo.title; }
    uint32 GetBitrate() const { return m_streamInfo.bitrate; }
    uint32 GetBroadcastStartTime() const { return m_streamInfo.startedAt; }
    bool IsEmergencyMode() const { return m_bEmergencyMode; }

    // Ghost-viewer watchdog (2026-06). A web player session that stops
    // fetching HLS (tab closed or crashed without the pagehide leave beacon)
    // used to leave m_bViewing latched forever: the viewer machinery kept
    // re-dialing/re-subscribing for the whole life of the broadcast — the
    // JOIN/DISCONNECT loop visible on the broadcaster's status page.
    // NotePlayerFetch() is an atomic tick write, safe from webserver worker
    // threads (same class as the OBS-1 Interlocked counters); it is stamped
    // by eMule's own /hls + /api/live/{hash}/* handlers and by the
    // /api/live/player-alive heartbeat that ese-server relays while it
    // serves /hls-local to a browser. MarkWebPlayerSession() arms the
    // watchdog and is only called for web-originated joins (OnLiveWebJoin)
    // so MFC/VLC-from-disk flows, which produce no HTTP fetches, are never
    // auto-left. Process() leaves the stream after 60 s of player silence.
    void NotePlayerFetch() { InterlockedExchange(&m_lastPlayerFetchTick, (LONG)::GetTickCount()); }
    void MarkWebPlayerSession() { InterlockedExchange(&m_bWebPlayerSession, 1); NotePlayerFetch(); }

    // Thread-safe debug snapshot (takes m_lock, copies all state)
    LiveDebugSnapshot BuildDebugSnapshot() const;

    // Thread-safe snapshot for /api/live/channels (takes m_lock).
    LiveChannelSnapshot GetChannelSnapshot() const;

    // Accessors for mesh manager (bitmap and trust data) — use ONLY under m_lock.
    // C6 (2026-06): per-peer state is now keyed by LivePeerId (durable identity),
    // not the CUpDownClient* pointer. These accessors keep their CUpDownClient*
    // signatures and convert internally (defined in the .cpp where CUpDownClient
    // is complete), so the mesh manager is unchanged. GetPeerBitmaps() (raw-map
    // exposure) is replaced by GetPeerBitmap(peer,out) — the mesh can't hold a
    // LivePeerId map reference without leaking the key type.
    bool GetPeerBitmap(CUpDownClient* peer, PeerBitmapInfo& outInfo) const;
    bool GetPeerTrust(CUpDownClient* peer, PeerTrust& outTrust) const;
    void SetPeerTrust(CUpDownClient* peer, const PeerTrust& trust);

    // Phase 0: Observability counters
    const LiveStreamCounters& GetCounters() const { return m_counters; }
    LiveStreamCounters& GetCountersMut() { return m_counters; }
    int GetViewPeerCount() const { return (int)m_viewPeers.GetCount(); }
    int GetBroadcastPeerCount() const { return (int)m_broadcastPeers.GetCount(); }

    // V2-S01: Per-peer counter accessors. Both reader+writer paths must hold
    // m_lock externally (callers from WebServer go through BuildDebugSnapshot
    // which already takes the lock). The non-const accessor returns a reference
    // to the map entry so writers can `++c.chunks_received` etc. without a
    // second lookup.
    // C6: re-keyed by LivePeerId. Not iterated by any external consumer.
    const CMap<LivePeerId, const LivePeerId&, PeerCounters, PeerCounters&>& GetPeerCounters() const
        { return m_peerCounters; }
    PeerCounters& GetOrCreatePeerCounters(CUpDownClient* peer);

    // V2-S03: PING/PONG handlers, dispatched from ListenSocket.cpp.
    void OnLivePing(CUpDownClient* peer, const uchar* streamKey, uint32 pingId, uint64 sendTick);
    void OnLivePong(CUpDownClient* peer, const uchar* streamKey, uint32 pingId, uint64 echoTick);

    // Decentralized Capa 1 (PEX): a peer told us about a stream they have
    // recently seen. Treat it equivalently to a Kad search result so the
    // existing validation, dedupe, throttled-dial and stats paths apply.
    void OnPexEntry(const uchar* streamKey, uint32 broadcasterIP, uint16 broadcasterPort);

    // V2-S05: chunk-arrival latency histogram (samples seq-driven recv vs broadcast)
    LatencyHistogram& ChunkArrivalLatency() { return m_chunkArrivalLatency; }
    const LatencyHistogram& ChunkArrivalLatency() const { return m_chunkArrivalLatency; }

    // V2-S11/S12: upload capacity probe + tier classification.
    // MeasureUploadCapacity is invoked from the constructor and (on demand)
    // from /api/live/preflight; reads thePrefs.GetMaxUpload() as a proxy
    // until V3-S01 introduces real bandwidth probing.
    void   MeasureUploadCapacity();
    DWORD  GetMeasuredUploadKbps() const { return m_measuredUploadKbps; }
    PeerTier ComputeMyTier(uint16 streamBitrateKbps) const;
    static const char* TierName(PeerTier t);
    int    MaxConcurrentUploads() const;            // V2-S13: tier -> max children
    int    EffectiveMaxConcurrentUploads() const;   // S13 + S16 broadcaster cap

private:
    // Stream state
    bool                m_bBroadcasting;
    bool                m_bViewing;
    LiveStreamInfo      m_streamInfo;
    // v7.6.0 — broadcaster's Ed25519 private key. Generated freshly on every
    // StartBroadcast(); never serialized to disk; zeroed on StopBroadcast.
    // The matching public key lives in m_streamInfo.pubkey and IS published.
    uint8_t             m_broadcasterPrivkey[32];
    CLiveChunkBuffer    m_chunkBuffer;
    uint32              m_nNextSeqNum;      // Next segment sequence number

    // Peer lists
    CTypedPtrList<CPtrList, CUpDownClient*> m_broadcastPeers;   // Peers watching our stream
    CTypedPtrList<CPtrList, CUpDownClient*> m_viewPeers;        // Peers we get stream from

    // Trust data. C6 (2026-06): keyed by LivePeerId (durable user-hash/pubkey
    // identity), NOT the CUpDownClient* pointer — so it survives the ~6 s LowID
    // AttachToAlreadyKnown swap that used to orphan it and cause the micro-cut.
    CMap<LivePeerId, const LivePeerId&, PeerTrust, PeerTrust&> m_peerTrust;

    // Peer bitmaps. C6: keyed by LivePeerId (durable identity).
    // Phase 1 BOOT-1: stores both bitmap and oldestSeq, so bit positions are
    // interpreted against the peer's anchor (not the viewer's).
    CMap<LivePeerId, const LivePeerId&, PeerBitmapInfo, PeerBitmapInfo&> m_peerBitmaps;

    // Timers
    DWORD               m_dwLastBitmapSend;
    DWORD               m_dwLastAnnounceSend;
    DWORD               m_dwLastKadPublish;
    DWORD               m_dwLastHealthCheck;
    DWORD               m_dwLastStatsSend;

    // Emergency mode
    bool                m_bEmergencyMode;
    DWORD               m_dwEmergencyStart;

    mutable CCriticalSection m_lock;  // mutable: locking is logically const (Fix 12)

    // Kad discovery bridge
    CLiveKadBridge      m_kadBridge;

    // Mesh topology manager
    CLiveMeshManager    m_meshManager;

    // Phase 0: Observability counters (OBS-1)
    LiveStreamCounters  m_counters;

    // V2-S01/S02/S03: per-peer state (counters + RTT EWMA + window).
    // C6: keyed by LivePeerId (durable identity); pruned by TTL, not scrubbed
    // on every disconnect (a disconnect is usually just a pointer swap).
    CMap<LivePeerId, const LivePeerId&, PeerCounters, PeerCounters&> m_peerCounters;

    // V2-S03: outstanding pings (peer -> map<pingId, sendTick>) waiting for PONG.
    // Stale entries (>30 s) are reaped each Process() tick to bound memory.
    struct PendingPing { uint64 sendTick; };
    typedef CMap<uint32, uint32, PendingPing, PendingPing&> PendingPingMap;
    CMap<CUpDownClient*, CUpDownClient*, PendingPingMap*, PendingPingMap*> m_pendingPings;
    DWORD               m_dwLastPingTick;
    uint32              m_nNextPingId;

    // V2-S05: latency distribution (chunk timestamp -> arrival, ms)
    LatencyHistogram    m_chunkArrivalLatency;

    // v7.2.0 — Tombstones for streams we've been informed are dead
    // (OP_LIVE_END received OR watchdog declared them so). Key = hex
    // streamKey; value = GetTickCount() expiration. TTL ~30 min: long
    // enough to outlast any reasonable Kad echo that could resurrect
    // the entry, short enough that legitimate restarts of the same
    // streamKey within the hour will be missed for a while (acceptable
    // because StartBroadcast generates a NEW streamKey every time).
    // Pruned each Process() tick.
    CMap<CString, LPCTSTR, DWORD, DWORD&> m_streamTombstones;
    DWORD               m_dwLastTombstonePrune;

    // v7.2.2 — Recent initial-PUSH timestamps by (IP, port). Key =
    // (uint64)ip << 16 | port. Value = GetTickCount() when we last
    // pushed the 3-chunk initial burst to that endpoint. Used to
    // skip duplicate pushes on rapid re-SUBSCRIBE (LowID viewers
    // cycle every 6 s due to CClientList::AttachToAlreadyKnown).
    // Without this we burn ~4.5 MB on every re-subscribe with chunks
    // the viewer already has, which saturates their TCP recv buffer
    // and produces the very stalls the push was supposed to prevent.
    CMap<uint64, uint64, DWORD, DWORD&> m_recentInitialPushes;

    // Churn fix (2026-06): per-endpoint dial cooldown for the VIEWER side.
    // Re-dialing a source we dialed seconds ago recycles its CUpDownClient via
    // CClientList::AttachToAlreadyKnown, which drops the live TCP socket
    // mid-transfer — the JOIN/DISCONNECT churn + micro-cuts seen in 2-PC tests.
    // The m_viewPeers dedup is defeated when the recycle briefly removes the
    // peer from the list, so we cooldown by endpoint (key = ip<<16|port),
    // surviving the transient disconnect. Fed by the Kad dial-queue drain,
    // EnsureMultiParent and the failover, which all re-dial known sources.
    // Pruned in Process(); cleared on Join/Leave.
    CMap<uint64, uint64, DWORD, DWORD&> m_recentDials;

    // v7.3.0 — Per-IP SUBSCRIBE rate limit. Key = IP (uint32). Value =
    // tick of the SUBSCRIBE_RATE_WINDOW most recent SUBSCRIBE for this
    // IP, with the count packed in. Tracks the 30 most recent ticks; if
    // all 30 fall inside the 60 s window, the 31st SUBSCRIBE is rejected
    // with OP_LIVE_DENY before doing any state change. Headroom accounts
    // for legitimate LowID viewers cycling through CClientList swaps every
    // ~6 s (~10/min) plus brief reconnect bursts. Prevents a single IP from
    // amplifying broadcaster work (per-/24 limit in ListenSocket is too
    // coarse: 256 IPs share one /24 budget).
    struct SubRateState {
        DWORD ticks[30];       // ring buffer of last 30 SUBSCRIBE ticks
        int   nextSlot;        // 0..29
        DWORD lastSeen;        // for pruning
    };
    CMap<uint32, uint32, SubRateState, SubRateState&> m_subscribeRate;
    // Watchdog: per-viewing-session timestamp of the last chunk or
    // heartbeat we received from ANY peer for the active stream. If
    // (now - this) > 90 s while m_bViewing, declare end + gossip.
    DWORD               m_dwLastLiveActivity;

    // DISC-S04: pending ghost-cleanup. Loaded from preferences at startup;
    // if non-empty, Process() will try to publish a tombstone once Kad
    // connects, then clear it. Avoids a previous-session crash leaving an
    // entry in the DHT for ~3 min (the new ESE_KAD_ENTRY_TTL).
    uchar               m_pendingGhostKey[16];
    bool                m_bHasPendingGhostKey;

    // v7.7.0 — streamKey → broadcaster pubkey pin. Populated the first time
    // we see a self-certifying ANNOUNCE / Kad result for a given streamKey
    // (sha1(pubkey) == streamKey). Future chunks and END packets for that
    // streamKey are validated against this pubkey. A peer can't switch the
    // identity of a stream mid-flight: once pinned, the pin stays for the
    // lifetime of m_streamPubkeyPin (cleared on Clear() / process exit).
    // Key: hex(streamKey) — CString-friendly for the existing CMap pattern.
    // Value: 32-byte pubkey (heap-allocated; deleted in destructor / Clear).
    struct PubkeyPin {
        uchar pubkey[32];
        DWORD pinnedAt;       // GetTickCount() — for staleness pruning if ever needed
    };
    CMap<CString, LPCTSTR, PubkeyPin, PubkeyPin&> m_streamPubkeyPin;

    // V2-S11: result of upload-capacity probe in kbps (0 = leaf-restricted).
    DWORD               m_measuredUploadKbps;

    // V2-S17: last time we re-published as a secondary source for the stream
    // we are currently viewing. 0 means "not yet" (forces a publish on the
    // first eligible Process tick).
    DWORD               m_dwLastSecondaryPublish;

    // DISC-S05: periodic re-search while viewing with zero source peers.
    // m_dwLastJoinSearchTick = last time we re-fired the 3 Kad searches;
    // m_nJoinSearchRetries  = total retries this JoinStream session, capped.
    DWORD               m_dwLastJoinSearchTick;
    int                 m_nJoinSearchRetries;

    // DISC-S12: time-to-first-chunk measurement.
    // m_dwJoinTick = the GetTickCount() of the latest JoinStream call.
    // m_bFirstChunkLogged = whether OnChunkReceived has already recorded
    // the delta into the counter (only the FIRST chunk per JoinStream
    // counts; subsequent ones don't reset the measurement).
    DWORD               m_dwJoinTick;
    bool                m_bFirstChunkLogged;

    // V2-S19: last time EnsureMultiParent dialed extra sources.
    DWORD               m_dwLastMultiParentTick;

    // Phase-1 fix #2 (2026-06) — in-flight pull-request tracking. Without it,
    // RequestMissingSegments re-sent OP_LIVE_REQUEST for every missing seq on
    // every 1 s Process() tick: a 500 KB segment takes 1.5-2 s to transfer at
    // 2-3 Mbps, so the same segment was requested (and served) 2-3 times —
    // wasting bandwidth exactly when the link is congested. Keyed by seqNum;
    // bounded by the 16-segment ring + lookahead. Peer identity is stored as
    // IP+port (NOT CUpDownClient* — pointers are unstable, cf. §13.1) so an
    // expired entry can bias the retry away from the unresponsive peer.
    // Fulfilled entries are erased in OnChunkReceived; evicted/stale ones are
    // pruned at the top of RequestMissingSegments. All access under m_lock.
    struct InflightSegReq {
        DWORD  sentTick;    // GetTickCount() when the request went out
        uint32 peerIp;      // peer we asked
        uint16 peerPort;
        int    attempts;    // total requests sent for this seq this session
    };
    CMap<uint32, uint32, InflightSegReq, InflightSegReq&> m_inflightSegReqs;

    // Phase-1 fix #1 (2026-06) — the HLS buffer-minimum gate applies only
    // until the FIRST playlist write of the session. Set true after the
    // first successful stream.m3u8 write; reset in ResetViewerHlsOutput().
    bool                m_bHlsPlaylistStarted;

    // Ghost-viewer watchdog state (see NotePlayerFetch/MarkWebPlayerSession).
    // LONG + Interlocked because writers include webserver worker threads.
    volatile LONG       m_lastPlayerFetchTick;  // GetTickCount() of last player sign of life
    volatile LONG       m_bWebPlayerSession;    // 1 = current viewing session came from the web API

    // Tier 2.2: shared FFmpeg ingest. Owned by the manager so both the MFC
    // dialog and the web API can drive broadcast start/stop. Only one source
    // can be active at a time (CRTMPIngest enforces this internally).
    CRTMPIngest         m_rtmpIngest;

    // C6: durable peer identity from a CUpDownClient. Uses the eD2K user-hash
    // (LPID_USERHASH) — stable across the AttachToAlreadyKnown swap. Falls back
    // to a pointer-derived key (LPID_INVALID kind) only for a hashless/pre-HELLO
    // peer, which degrades to the old per-pointer behavior for that peer alone.
    LivePeerId PeerId(CUpDownClient* peer) const;
    // C6: drop durable per-peer entries (trust/bitmap/counters) whose LivePeerId
    // hasn't been touched within the TTL — replaces the per-disconnect scrub.
    void PrunePeerState(DWORD now);

    // Internal helpers
    void SendBitmapToAll();
    void SendAnnounceToAll();
    void RequestMissingSegments();
    void PublishToKad();
    CString GetLiveHlsDir() const;
    void ResetViewerHlsOutput();
    void WriteViewerHlsSegment(uint32 seqNum, const BYTE* data, uint32 dataSize);
    void RefreshViewerHlsPlaylist();
    void DemotePeer(CUpDownClient* peer);
    void BanPeer(CUpDownClient* peer);
    PeerTrust& GetOrCreateTrust(CUpDownClient* peer);

    // Select best peer to request a segment from. excludeIp != 0 skips that
    // peer — used to retry a timed-out in-flight request somewhere else.
    CUpDownClient* SelectPeerForSegment(uint32 seqNum, uint32 excludeIp = 0);

    // V2-S03 helpers
    void PingAllPeers();           // periodic, called from Process()
    void PingPeer(CUpDownClient* peer);
    void ReapStalePings(DWORD now); // delete pending pings older than 30 s

    // V2-S19 multi-parent: keep >= 3 active sources by dialing extras from
    // the Kad-discovered set. Called from Process() every 10 s while viewing.
    void EnsureMultiParent();

    // Decentralized Capa 3 — bootstrap cache. Persists the last N
    // successfully-dialed broadcasters to %APPDATA%\eMule\last_streams.json
    // so the next launch can ping them BEFORE Kad has bootstrapped. Cuts
    // cold-start discovery from "minutes" to "seconds" for known streams.
    void BootstrapPingCachedStreams();    // called from Process() once after startup
    void RememberStreamForBootstrap(const uchar* streamKey, uint32 ip, uint16 port,
                                    const CString& title);
    CString BootstrapCachePath() const;
    bool                m_bBootstrapAttempted;
    DWORD               m_dwBootstrapTick;

    // C6: last durable-state TTL sweep (PrunePeerState), throttled in Process().
    DWORD               m_dwLastPeerPrune;

    // C5/C3 (Sprint C review fix): endpoint of the broadcaster we tunnel-
    // subscribed to this session (0 = not in Tunelizado / not dialed). The C3
    // relayed heartbeat carries the broadcaster's live edge; OnTunneledLiveControl
    // applies it ONLY to the view peer matching this endpoint, so secondary
    // sources (dialed via OP_LIVE_PEER_LIST, with their own real bitmaps) are
    // not clobbered. Set in TryConnectToStreamSource's tunnel branch; cleared in
    // JoinStream/LeaveStream.
    uint32              m_tunnelSourceIP;
    uint16              m_tunnelSourcePort;
    // C5/C6 review fix: self-heal a lost tunneled subscribe (dropped send,
    // broadcaster DENY of the exit, or a circuit-death TOCTOU). Re-issue the
    // tunneled subscribe from Process() if no live edge appears within a grace
    // window. Bounded by m_tunnelResubCount.
    DWORD               m_tunnelSubscribeTick;
    int                 m_tunnelResubCount;
};
