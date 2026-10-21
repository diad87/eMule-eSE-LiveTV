//this file is part of eMule
// eSE — Mesh Topology Manager for Live Streaming
// Manages N-peer connections, rarest-first scheduling, and P2P redistribution.
#pragma once

#include "LiveProtocol.h"

class CUpDownClient;
class CLiveStreamManager;

// Request tracking: pending segment requests with timeout
struct PendingRequest {
    uint32  seqNum;
    CUpDownClient* peer;
    DWORD   sentAt;         // GetTickCount() when request was sent
    int     retryCount;
};

// Segment rarity: how many peers have each segment
struct SegmentRarity {
    uint32  seqNum;
    int     peerCount;      // How many peers have this segment
    bool    haveIt;         // Do we already have it?
};

class CLiveMeshManager
{
public:
    CLiveMeshManager();
    ~CLiveMeshManager();

    // Initialize with reference to parent manager
    void Init(CLiveStreamManager* pManager);

    // === Mesh Topology ===

    // Add a peer to our mesh (viewer connects to a peer)
    void AddMeshPeer(CUpDownClient* peer);

    // Remove a peer from mesh
    void RemoveMeshPeer(CUpDownClient* peer);

    // Drop role-specific topology/request state when the manager switches
    // between broadcast and viewer sessions. Cumulative counters remain.
    void ResetSessionPeers();

    // Get current mesh peer count
    int GetMeshPeerCount() const;

    // Is this peer in our mesh?
    bool IsMeshPeer(CUpDownClient* peer) const;

    // === Rarest-First Scheduling ===

    // Calculate rarity of each segment based on all peers' bitmaps
    void CalculateRarities(CArray<SegmentRarity>& outRarities);

    // Select the best peer for a specific segment (rarest-first + trust)
    CUpDownClient* SelectBestPeerForSegment(uint32 seqNum);

    // Schedule next batch of requests (called from Process())
    void ScheduleRequests();

    // === Request Tracking ===

    // Track a request we sent
    void TrackRequest(uint32 seqNum, CUpDownClient* peer);

    // Mark a request as fulfilled (chunk received)
    void FulfillRequest(uint32 seqNum);

    // Check for timed-out requests and retry
    void CheckTimeouts();

    // Is this segment currently being requested?
    bool IsRequested(uint32 seqNum) const;

    // === Upload Redistribution ===

    // Can we serve this segment to a requesting peer?
    bool CanServeSegment(uint32 seqNum) const;

    // Track upload to a peer (for ratio calculation)
    void TrackUpload(CUpDownClient* peer, uint32 bytes);

    // === Periodic Processing ===

    // Main tick (called from CLiveStreamManager::Process())
    void Process();

    // Broadcaster announced a new segment — trigger immediate request
    void OnSegmentAnnounced(uint32 seqNum);

    // === Stats ===
    int GetPendingRequestCount() const;
    int GetChunksServedCount() const;
    uint64 GetTotalBytesRedistributed() const;

    // Fix 13: Cumulative counter — chunks sent to peers (not a gauge)
    void IncrementChunksServed() { InterlockedIncrement((LONG*)&m_nChunksServed); }

private:
    CLiveStreamManager* m_pManager;

    // Active mesh peers (peers we exchange data with)
    CTypedPtrList<CPtrList, CUpDownClient*> m_meshPeers;

    // Pending requests (segment requests we're waiting for)
    CArray<PendingRequest> m_pendingRequests;

    // Upload tracking per peer
    CMap<CUpDownClient*, CUpDownClient*, uint64, uint64> m_uploadTracker;

    // Stats
    uint64 m_nTotalRedistributed;
    int    m_nChunksServed;  // Fix 13: cumulative chunks served (not active gauge)

    // Timers
    DWORD  m_dwLastSchedule;
    DWORD  m_dwLastTimeoutCheck;
    DWORD  m_dwLastPeerCheck;

    // Constants
    static const DWORD REQUEST_TIMEOUT_MS   = 3000;   // 3 seconds
    static const int   MAX_PENDING_REQUESTS = 5;       // Max concurrent requests
    static const int   MAX_RETRIES          = 2;       // Max retries per segment
    static const int   TARGET_MESH_PEERS    = 5;       // Target peer connections
    static const int   MIN_MESH_PEERS       = 3;       // Minimum before requesting more
    static const DWORD SCHEDULE_INTERVAL_MS = 500;     // Schedule every 500ms
    static const DWORD TIMEOUT_CHECK_MS     = 1000;    // Check timeouts every 1s
    static const DWORD PEER_CHECK_MS        = 30000;   // Check peer count every 30s (was 5s: with
                                                       // MIN_MESH_PEERS=3 unreachable in tiny meshes the
                                                       // 5s re-SUBSCRIBE churned the broadcaster — re-JOIN
                                                       // every ~6s + initial-PUSH/ASK dup. 30s cuts it 6x.)

    mutable CCriticalSection m_lock;

    // Internal helpers
    int CountPeersWithSegment(uint32 seqNum) const;
    void RequestMorePeers();
};
