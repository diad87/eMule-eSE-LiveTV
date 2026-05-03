//this file is part of eMule
// eSE — Live Stream Manager
// Manages P2P live streaming: broadcasting, viewing, peer scoring, anti-Sybil.
#pragma once

#include "LiveProtocol.h"
#include "LiveChunkBuffer.h"
#include "LiveKadBridge.h"
#include "LiveMeshManager.h"

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

    LiveStreamCounters()
        : kadPublishes(0), kadSearches(0)
        , kadResultsAccepted(0), kadResultsRejected(0)
        , sourceDialAttempts(0)
        , subscribeSent(0), subscribeAccepted(0)
        , chunksRequested(0), chunksReceived(0), chunksMissing(0)
        , hlsSegmentsWritten(0), hlsPlaylistRefresh(0)
        , peerDisconnects(0), lastChunkReceivedAt(0)
    {}
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

    // === Viewer API ===
    // Join a remote stream by its streamKey
    bool JoinStream(const uchar* streamKey, const CString& title);
    // Leave the current stream
    void LeaveStream();
    // Is currently viewing a live stream?
    bool IsViewingLive() const { return m_bViewing; }
    // Connect to a discovered broadcaster/relay for the stream we are viewing
    bool TryConnectToStreamSource(const uchar* streamKey, uint32 ip, uint16 port);

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
    const CMap<CUpDownClient*, CUpDownClient*, uint16, uint16>& GetPeerBitmaps() const
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
    CMap<CUpDownClient*, CUpDownClient*, uint16, uint16> m_peerBitmaps;

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
};
