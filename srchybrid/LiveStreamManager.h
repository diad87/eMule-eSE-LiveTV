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
    // DISC-S11: visibility into Kad discovery health
    LONG kadSearchesEmpty;      // searches that returned 0 hits (timeout / propagation)
    LONG kadSearchesRateLimited;// searches dropped by token bucket (DISC-S08)
    LONG pendingDialsDropped;   // results dropped because dial queue was full (DISC-S06)
    // DISC-S12: time-to-first-chunk (single histogram populated in OnChunkReceived
    // on the first chunk of a JoinStream session). Total/count -> mean.
    LONG joinToFirstChunkSamples;
    LONG joinToFirstChunkSumMs;

    LiveStreamCounters()
        : kadPublishes(0), kadSearches(0)
        , kadResultsAccepted(0), kadResultsRejected(0)
        , sourceDialAttempts(0)
        , subscribeSent(0), subscribeAccepted(0)
        , chunksRequested(0), chunksReceived(0), chunksMissing(0)
        , hlsSegmentsWritten(0), hlsPlaylistRefresh(0)
        , peerDisconnects(0), lastChunkReceivedAt(0)
        , kadSearchesEmpty(0), kadSearchesRateLimited(0)
        , pendingDialsDropped(0)
        , joinToFirstChunkSamples(0), joinToFirstChunkSumMs(0)
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

    // Counters (atomic snapshot)
    LiveStreamCounters counters;
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
                                  const CString& mediaFilePath = _T(""));
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
    // Called when a peer disconnects
    void OnPeerDisconnected(CUpDownClient* peer);

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

    // Accessors for WebServer and UI
    const uchar* GetStreamKey() const { return m_streamInfo.streamKey; }
    CString GetStreamTitle() const { return m_streamInfo.title; }
    uint32 GetBitrate() const { return m_streamInfo.bitrate; }
    uint32 GetBroadcastStartTime() const { return m_streamInfo.startedAt; }
    bool IsEmergencyMode() const { return m_bEmergencyMode; }

    // Thread-safe debug snapshot (takes m_lock, copies all state)
    LiveDebugSnapshot BuildDebugSnapshot() const;

    // Accessors for mesh manager (bitmap and trust data) — use ONLY under m_lock
    // Phase 1 BOOT-1: now exposes bitmap + oldestSeq anchor per peer.
    const CMap<CUpDownClient*, CUpDownClient*, PeerBitmapInfo, PeerBitmapInfo&>& GetPeerBitmaps() const
        { return m_peerBitmaps; }
    bool GetPeerTrust(CUpDownClient* peer, PeerTrust& outTrust) const
        { return m_peerTrust.Lookup(peer, outTrust) != FALSE; }
    void SetPeerTrust(CUpDownClient* peer, const PeerTrust& trust)
        { m_peerTrust[peer] = trust; }

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
    const CMap<CUpDownClient*, CUpDownClient*, PeerCounters, PeerCounters&>& GetPeerCounters() const
        { return m_peerCounters; }
    PeerCounters& GetOrCreatePeerCounters(CUpDownClient* peer) { return m_peerCounters[peer]; }

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
    CLiveChunkBuffer    m_chunkBuffer;
    uint32              m_nNextSeqNum;      // Next segment sequence number

    // Peer lists
    CTypedPtrList<CPtrList, CUpDownClient*> m_broadcastPeers;   // Peers watching our stream
    CTypedPtrList<CPtrList, CUpDownClient*> m_viewPeers;        // Peers we get stream from

    // Trust data (keyed by client pointer for fast lookup)
    CMap<CUpDownClient*, CUpDownClient*, PeerTrust, PeerTrust&> m_peerTrust;

    // Peer bitmaps (keyed by client pointer)
    // Phase 1 BOOT-1: stores both bitmap and oldestSeq, so bit positions are
    // interpreted against the peer's anchor (not the viewer's).
    CMap<CUpDownClient*, CUpDownClient*, PeerBitmapInfo, PeerBitmapInfo&> m_peerBitmaps;

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
    // Cleaned up in OnPeerDisconnected to avoid dangling pointer keys.
    CMap<CUpDownClient*, CUpDownClient*, PeerCounters, PeerCounters&> m_peerCounters;

    // V2-S03: outstanding pings (peer -> map<pingId, sendTick>) waiting for PONG.
    // Stale entries (>30 s) are reaped each Process() tick to bound memory.
    struct PendingPing { uint64 sendTick; };
    typedef CMap<uint32, uint32, PendingPing, PendingPing&> PendingPingMap;
    CMap<CUpDownClient*, CUpDownClient*, PendingPingMap*, PendingPingMap*> m_pendingPings;
    DWORD               m_dwLastPingTick;
    uint32              m_nNextPingId;

    // V2-S05: latency distribution (chunk timestamp -> arrival, ms)
    LatencyHistogram    m_chunkArrivalLatency;

    // DISC-S04: pending ghost-cleanup. Loaded from preferences at startup;
    // if non-empty, Process() will try to publish a tombstone once Kad
    // connects, then clear it. Avoids a previous-session crash leaving an
    // entry in the DHT for ~3 min (the new ESE_KAD_ENTRY_TTL).
    uchar               m_pendingGhostKey[16];
    bool                m_bHasPendingGhostKey;

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

    // Tier 2.2: shared FFmpeg ingest. Owned by the manager so both the MFC
    // dialog and the web API can drive broadcast start/stop. Only one source
    // can be active at a time (CRTMPIngest enforces this internally).
    CRTMPIngest         m_rtmpIngest;

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

    // Select best peer to request a segment from
    CUpDownClient* SelectPeerForSegment(uint32 seqNum);

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
};
