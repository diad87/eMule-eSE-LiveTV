//this file is part of eMule
// eSE — Mesh Topology Manager Implementation
#include "stdafx.h"
#include "LiveMeshManager.h"
#include "LiveStreamManager.h"
#include "LivePackets.h"
#include "emule.h"
#include "opcodes.h"
#include "OtherFunctions.h"
#include "Log.h"
#include "UpDownClient.h"
#include "Packets.h"
#include "Statistics.h"
#include "preferences.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif


CLiveMeshManager::CLiveMeshManager()
    : m_pManager(NULL)
    , m_nTotalRedistributed(0)
    , m_nChunksServed(0)
    , m_dwLastSchedule(0)
    , m_dwLastTimeoutCheck(0)
    , m_dwLastPeerCheck(0)
{
}

CLiveMeshManager::~CLiveMeshManager()
{
    m_meshPeers.RemoveAll();
    m_pendingRequests.RemoveAll();
    m_uploadTracker.RemoveAll();
}

void CLiveMeshManager::Init(CLiveStreamManager* pManager)
{
    m_pManager = pManager;
}


// ============================================================
// MESH TOPOLOGY
// ============================================================

void CLiveMeshManager::AddMeshPeer(CUpDownClient* peer)
{
    CSingleLock lock(&m_lock, TRUE);

    if (!IsMeshPeer(peer)) {
        m_meshPeers.AddTail(peer);
        AddLogLine(false, _T("eSE Mesh: Peer added (total=%d)"),
            (int)m_meshPeers.GetCount());
    }
}

void CLiveMeshManager::RemoveMeshPeer(CUpDownClient* peer)
{
    CSingleLock lock(&m_lock, TRUE);

    POSITION pos = m_meshPeers.Find(peer);
    if (pos) {
        m_meshPeers.RemoveAt(pos);
        m_uploadTracker.RemoveKey(peer);

        // Cancel any pending requests to this peer
        for (INT_PTR i = m_pendingRequests.GetCount() - 1; i >= 0; i--) {
            if (m_pendingRequests[i].peer == peer) {
                m_pendingRequests.RemoveAt(i);
            }
        }

        AddLogLine(false, _T("eSE Mesh: Peer removed (total=%d)"),
            (int)m_meshPeers.GetCount());
    }
}

int CLiveMeshManager::GetMeshPeerCount() const
{
    CSingleLock lock(&m_lock, TRUE);
    return (int)m_meshPeers.GetCount();
}

bool CLiveMeshManager::IsMeshPeer(CUpDownClient* peer) const
{
    CSingleLock lock(&m_lock, TRUE);
    return m_meshPeers.Find(peer) != NULL;
}


// ============================================================
// RAREST-FIRST SCHEDULING
// ============================================================

void CLiveMeshManager::CalculateRarities(CArray<SegmentRarity>& outRarities)
{
    CSingleLock lock(&m_lock, TRUE);

    if (!m_pManager) return;

    const CLiveChunkBuffer& buffer = m_pManager->GetBuffer();
    uint32 oldest = buffer.GetOldestSeq();
    uint32 newest = buffer.GetNewestSeq();

    outRarities.RemoveAll();

    // For each possible segment in the window
    for (uint32 seq = oldest; seq <= newest + 2; seq++) {
        SegmentRarity rarity;
        rarity.seqNum = seq;
        rarity.haveIt = buffer.HasSegment(seq);
        rarity.peerCount = CountPeersWithSegment(seq);
        outRarities.Add(rarity);
    }

    // Sort by rarity (fewest peers first) — simple insertion sort since N is small
    for (INT_PTR i = 1; i < outRarities.GetCount(); i++) {
        SegmentRarity key = outRarities[i];
        INT_PTR j = i - 1;
        while (j >= 0 && outRarities[j].peerCount > key.peerCount) {
            outRarities[j + 1] = outRarities[j];
            j--;
        }
        outRarities[j + 1] = key;
    }
}

int CLiveMeshManager::CountPeersWithSegment(uint32 seqNum) const
{
    if (!m_pManager) return 0;

    const CLiveChunkBuffer& buffer = m_pManager->GetBuffer();
    uint32 oldest = buffer.GetOldestSeq();
    uint32 bit = seqNum - oldest;
    if (bit >= 16) return 0;

    int count = 0;
    POSITION pos = m_meshPeers.GetHeadPosition();
    while (pos) {
        CUpDownClient* peer = m_meshPeers.GetNext(pos);
        uint16 bitmap = 0;
        CMap<CUpDownClient*, CUpDownClient*, uint16, uint16>& bitmaps =
            const_cast<CMap<CUpDownClient*, CUpDownClient*, uint16, uint16>&>(
                m_pManager->GetPeerBitmaps());
        if (bitmaps.Lookup(peer, bitmap)) {
            if (bitmap & (1 << bit)) {
                count++;
            }
        }
    }
    return count;
}

CUpDownClient* CLiveMeshManager::SelectBestPeerForSegment(uint32 seqNum)
{
    CSingleLock lock(&m_lock, TRUE);

    if (!m_pManager) return NULL;

    const CLiveChunkBuffer& buffer = m_pManager->GetBuffer();
    uint32 oldest = buffer.GetOldestSeq();
    uint32 bit = seqNum - oldest;
    if (bit >= 16) return NULL;

    CUpDownClient* bestPeer = NULL;
    int bestScore = -1;

    POSITION pos = m_meshPeers.GetHeadPosition();
    while (pos) {
        CUpDownClient* peer = m_meshPeers.GetNext(pos);
        uint16 bitmap = 0;

        CMap<CUpDownClient*, CUpDownClient*, uint16, uint16>& bitmaps =
            const_cast<CMap<CUpDownClient*, CUpDownClient*, uint16, uint16>&>(
                m_pManager->GetPeerBitmaps());
        if (!bitmaps.Lookup(peer, bitmap))
            continue;

        if (!(bitmap & (1 << bit)))
            continue;

        // Score: trust-based + load-balanced
        int score = 50; // base score

        // Bonus for trust level
        PeerTrust trust;
        if (m_pManager->GetPeerTrust(peer, trust)) {
            score += (int)(trust.GetResponseRate() * 50);
            score -= trust.failCount * 15;
            // Prefer middle-tier and super-seeders
            if (trust.currentLevel <= ESE_TRUST_MIDDLE) score += 20;
            if (trust.currentLevel == ESE_TRUST_SUPERSEEDER) score += 40;
        }

        // Penalty for already having too many pending requests to this peer
        int peerPending = 0;
        for (INT_PTR i = 0; i < m_pendingRequests.GetCount(); i++) {
            if (m_pendingRequests[i].peer == peer) peerPending++;
        }
        score -= peerPending * 25;

        if (score > bestScore) {
            bestScore = score;
            bestPeer = peer;
        }
    }

    return bestPeer;
}

void CLiveMeshManager::ScheduleRequests()
{
    CSingleLock lock(&m_lock, TRUE);

    if (!m_pManager || !m_pManager->IsViewingLive()) return;
    if (m_meshPeers.GetCount() == 0) return;

    // Don't exceed max concurrent requests
    if (m_pendingRequests.GetCount() >= MAX_PENDING_REQUESTS) return;

    // Calculate rarities
    CArray<SegmentRarity> rarities;
    CalculateRarities(rarities);

    const LiveStreamInfo& info = m_pManager->GetStreamInfo();
    int slotsAvailable = MAX_PENDING_REQUESTS - (int)m_pendingRequests.GetCount();

    // Request rarest segments first (that we don't have and aren't already requested)
    for (INT_PTR i = 0; i < rarities.GetCount() && slotsAvailable > 0; i++) {
        const SegmentRarity& seg = rarities[i];

        // Skip if we have it or nobody has it
        if (seg.haveIt || seg.peerCount == 0) continue;

        // Skip if already requested
        if (IsRequested(seg.seqNum)) continue;

        // Find best peer for this segment
        CUpDownClient* peer = SelectBestPeerForSegment(seg.seqNum);
        if (!peer) continue;

        // Send request
        Packet* pkt = eSELive::CreateRequestPacket(info.streamKey, seg.seqNum);
        if (pkt) {
            theStats.AddUpDataOverheadOther(pkt->size);
            peer->SendPacket(pkt);
            TrackRequest(seg.seqNum, peer);
            slotsAvailable--;
        }
    }
}


void CLiveMeshManager::OnSegmentAnnounced(uint32 seqNum)
{
    CSingleLock lock(&m_lock, TRUE);

    if (!m_pManager || !m_pManager->IsViewingLive()) return;
    if (m_meshPeers.GetCount() == 0) return;

    // Skip if already requested or already have it
    if (IsRequested(seqNum)) return;
    if (m_pManager->GetBuffer().GetSegment(seqNum) != NULL) return;

    // Don't exceed max concurrent requests
    if (m_pendingRequests.GetCount() >= MAX_PENDING_REQUESTS) return;

    // Immediately select best peer and request
    CUpDownClient* peer = SelectBestPeerForSegment(seqNum);
    if (!peer) return;

    const LiveStreamInfo& info = m_pManager->GetStreamInfo();
    Packet* pkt = eSELive::CreateRequestPacket(info.streamKey, seqNum);
    if (pkt) {
        theStats.AddUpDataOverheadOther(pkt->size);
        peer->SendPacket(pkt);
        TrackRequest(seqNum, peer);

        AddLogLine(false, _T("eSE Mesh: Immediate request for announced seg #%u"),
            seqNum);
    }
}


// ============================================================
// REQUEST TRACKING
// ============================================================

void CLiveMeshManager::TrackRequest(uint32 seqNum, CUpDownClient* peer)
{
    CSingleLock lock(&m_lock, TRUE);

    PendingRequest req;
    req.seqNum = seqNum;
    req.peer = peer;
    req.sentAt = GetTickCount();
    req.retryCount = 0;
    m_pendingRequests.Add(req);
}

void CLiveMeshManager::FulfillRequest(uint32 seqNum)
{
    CSingleLock lock(&m_lock, TRUE);

    for (INT_PTR i = 0; i < m_pendingRequests.GetCount(); i++) {
        if (m_pendingRequests[i].seqNum == seqNum) {
            m_pendingRequests.RemoveAt(i);
            return;
        }
    }
}

void CLiveMeshManager::CheckTimeouts()
{
    CSingleLock lock(&m_lock, TRUE);

    if (!m_pManager) return;

    DWORD now = GetTickCount();
    const LiveStreamInfo& info = m_pManager->GetStreamInfo();

    for (INT_PTR i = m_pendingRequests.GetCount() - 1; i >= 0; i--) {
        PendingRequest& req = m_pendingRequests[i];

        if (now - req.sentAt < REQUEST_TIMEOUT_MS) continue;

        // Timeout! Record failure for the peer
        PeerTrust trust;
        if (m_pManager->GetPeerTrust(req.peer, trust)) {
            trust.failCount++;
            m_pManager->SetPeerTrust(req.peer, trust);
        }

        if (req.retryCount < MAX_RETRIES) {
            // Retry with a different peer
            CUpDownClient* newPeer = SelectBestPeerForSegment(req.seqNum);
            if (newPeer && newPeer != req.peer) {
                Packet* pkt = eSELive::CreateRequestPacket(info.streamKey, req.seqNum);
                if (pkt) {
                    theStats.AddUpDataOverheadOther(pkt->size);
                    newPeer->SendPacket(pkt);
                    req.peer = newPeer;
                    req.sentAt = now;
                    req.retryCount++;
                    AddLogLine(false, _T("eSE Mesh: Retry #%d for seg %u → new peer"),
                        req.retryCount, req.seqNum);
                    continue;
                }
            }
        }

        // Max retries exceeded or no alternative peer: give up
        AddLogLine(false, _T("eSE Mesh: Gave up on seg %u after %d retries"),
            req.seqNum, req.retryCount);
        m_pendingRequests.RemoveAt(i);
    }
}

bool CLiveMeshManager::IsRequested(uint32 seqNum) const
{
    CSingleLock lock(&m_lock, TRUE);

    for (INT_PTR i = 0; i < m_pendingRequests.GetCount(); i++) {
        if (m_pendingRequests[i].seqNum == seqNum) return true;
    }
    return false;
}


// ============================================================
// UPLOAD REDISTRIBUTION
// ============================================================

bool CLiveMeshManager::CanServeSegment(uint32 seqNum) const
{
    if (!m_pManager) return false;
    return m_pManager->GetBuffer().HasSegment(seqNum);
}

void CLiveMeshManager::TrackUpload(CUpDownClient* peer, uint32 bytes)
{
    CSingleLock lock(&m_lock, TRUE);

    uint64 total = 0;
    m_uploadTracker.Lookup(peer, total);
    total += bytes;
    m_uploadTracker[peer] = total;
    m_nTotalRedistributed += bytes;
}


// ============================================================
// PERIODIC PROCESSING
// ============================================================

void CLiveMeshManager::Process()
{
    DWORD now = GetTickCount();

    // Schedule new segment requests (rarest-first)
    if (now - m_dwLastSchedule >= SCHEDULE_INTERVAL_MS) {
        ScheduleRequests();
        m_dwLastSchedule = now;
    }

    // Check for timed-out requests
    if (now - m_dwLastTimeoutCheck >= TIMEOUT_CHECK_MS) {
        CheckTimeouts();
        m_dwLastTimeoutCheck = now;
    }

    // Check if we need more peers
    if (now - m_dwLastPeerCheck >= PEER_CHECK_MS) {
        if (m_meshPeers.GetCount() < MIN_MESH_PEERS) {
            RequestMorePeers();
        }
        m_dwLastPeerCheck = now;
    }
}

void CLiveMeshManager::RequestMorePeers()
{
    if (!m_pManager || !m_pManager->IsViewingLive()) return;

    // Ask the broadcaster/known peers for more peers
    const LiveStreamInfo& info = m_pManager->GetStreamInfo();

    POSITION pos = m_meshPeers.GetHeadPosition();
    if (pos) {
        // Ask the first known peer for a peer list
        CUpDownClient* peer = m_meshPeers.GetHead();
        Packet* pkt = eSELive::CreateSubscribePacket(
            info.streamKey, thePrefs.GetUserHash(), 0);  // 0 = unknown capacity
        if (pkt) {
            theStats.AddUpDataOverheadOther(pkt->size);
            peer->SendPacket(pkt);
            AddLogLine(false, _T("eSE Mesh: Requesting more peers (currently %d)"),
                (int)m_meshPeers.GetCount());
        }
    }
}


// ============================================================
// STATS
// ============================================================

int CLiveMeshManager::GetPendingRequestCount() const
{
    CSingleLock lock(&m_lock, TRUE);
    return (int)m_pendingRequests.GetCount();
}

int CLiveMeshManager::GetChunksServedCount() const
{
    CSingleLock lock(&m_lock, TRUE);
    return m_nChunksServed;
}

uint64 CLiveMeshManager::GetTotalBytesRedistributed() const
{
    CSingleLock lock(&m_lock, TRUE);
    return m_nTotalRedistributed;
}
