//this file is part of eMule
// eSE — Live Stream Manager Implementation
#include "stdafx.h"
#include "LiveStreamManager.h"
#include "LivePackets.h"
#include "emule.h"
#include "opcodes.h"
#include "OtherFunctions.h"
#include "Log.h"
#include "UpDownClient.h"
#include "Packets.h"
#include "SafeFile.h"
#include "Statistics.h"
#include "Preferences.h"
#include "IPFilter.h"
#include "md4.h"
#include "ClientList.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif


CLiveStreamManager::CLiveStreamManager()
    : m_bBroadcasting(false)
    , m_bViewing(false)
    , m_nNextSeqNum(0)
    , m_dwLastBitmapSend(0)
    , m_dwLastAnnounceSend(0)
    , m_dwLastKadPublish(0)
    , m_dwLastHealthCheck(0)
    , m_dwLastStatsSend(0)
    , m_bEmergencyMode(false)
    , m_dwEmergencyStart(0)
{
    m_meshManager.Init(this);
}

CLiveStreamManager::~CLiveStreamManager()
{
    StopBroadcast();
    LeaveStream();
}


// ============================================================
// BROADCASTER API
// ============================================================

bool CLiveStreamManager::StartBroadcast(const CString& title, const CString& category,
    const CString& language, uint16 bitrate)
{
    CSingleLock lock(&m_lock, TRUE);

    if (m_bBroadcasting) {
        AddLogLine(true, _T("eSE Live: Already broadcasting"));
        return false;
    }

    // Generate unique stream key from title + timestamp
    CMD4 md4;
    CStringA titleA(title);
    uint32 now = (uint32)time(NULL);
    md4.Add((const BYTE*)(LPCSTR)titleA, titleA.GetLength());
    md4.Add((const BYTE*)&now, sizeof(now));
    md4.Finish();
    md4cpy(m_streamInfo.streamKey, md4.GetHash());

    m_streamInfo.title = title;
    m_streamInfo.category = category;
    m_streamInfo.language = language;
    m_streamInfo.bitrate = bitrate;
    m_streamInfo.viewerCount = 0;
    m_streamInfo.startedAt = now;
    m_streamInfo.isBroadcaster = true;

    m_nNextSeqNum = 0;
    m_chunkBuffer.Clear();
    m_bBroadcasting = true;
    m_dwLastKadPublish = 0;

    // Make the stream visible immediately; RepublishIfNeeded handles Kad timing.
    InterlockedIncrement(&m_counters.kadPublishes);  // Phase 0: OBS-1 (atomic)
    m_kadBridge.PublishStream(m_streamInfo);

    AddLogLine(true, _T("eSE Live: Broadcasting \"%s\" [%s] %ukbps"),
        (LPCTSTR)title, (LPCTSTR)category, bitrate);

    return true;
}

void CLiveStreamManager::StopBroadcast()
{
    CSingleLock lock(&m_lock, TRUE);

    if (!m_bBroadcasting) return;

    // Notify all peers: stream ended normally
    POSITION pos = m_broadcastPeers.GetHeadPosition();
    while (pos) {
        CUpDownClient* peer = m_broadcastPeers.GetNext(pos);
        Packet* pkt = eSELive::CreateEndPacket(m_streamInfo.streamKey, ESE_END_NORMAL);
        if (pkt) {
            theStats.AddUpDataOverheadOther(pkt->size);
            peer->SendPacket(pkt);
        }
    }

    m_kadBridge.UnpublishStream(m_streamInfo.streamKey);

    m_bBroadcasting = false;
    m_chunkBuffer.Clear();
    m_broadcastPeers.RemoveAll();
    m_peerTrust.RemoveAll();
    m_peerBitmaps.RemoveAll();

    AddLogLine(true, _T("eSE Live: Broadcast stopped"));
}

void CLiveStreamManager::FeedSegment(const BYTE* data, uint32 dataSize)
{
    CSingleLock lock(&m_lock, TRUE);

    if (!m_bBroadcasting) return;

    uint32 seqNum = m_nNextSeqNum++;
    uint32 timestamp = (uint32)time(NULL);

    m_chunkBuffer.AddSegment(m_streamInfo.streamKey, seqNum, timestamp,
        data, dataSize, m_streamInfo.bitrate);
    WriteViewerHlsSegment(seqNum, data, dataSize);

    // Will trigger announce in next Process() tick
}


// ============================================================
// VIEWER API
// ============================================================

bool CLiveStreamManager::JoinStream(const uchar* streamKey, const CString& title)
{
    CSingleLock lock(&m_lock, TRUE);

    if (m_bViewing) {
        LeaveStream();
    }

    memcpy(m_streamInfo.streamKey, streamKey, 16);
    m_streamInfo.title = title;
    m_streamInfo.isBroadcaster = false;
    m_bViewing = true;
    m_chunkBuffer.Clear();
    m_viewPeers.RemoveAll();
    m_peerBitmaps.RemoveAll();
    ResetViewerHlsOutput();

    AddLogLine(true, _T("eSE Live: Joining stream \"%s\""), (LPCTSTR)title);

    // Kick off Kad discovery. "eselive" browses all streams; title helps targeted links.
    // Note: kadSearches counter is incremented inside KadBridge::SearchStreams only (Fix 4).
    m_kadBridge.SearchStreams(_T("eselive"));
    if (!title.IsEmpty() && title.CompareNoCase(_T("eselive")) != 0)
        m_kadBridge.SearchStreams(title);

    return true;
}

void CLiveStreamManager::LeaveStream()
{
    CSingleLock lock(&m_lock, TRUE);

    if (!m_bViewing) return;

    // Send OP_LIVE_UNSUBSCRIBE to all peers we were viewing from
    POSITION pos = m_viewPeers.GetHeadPosition();
    while (pos) {
        CUpDownClient* peer = m_viewPeers.GetNext(pos);
        if (peer) {
            Packet* pkt = eSELive::CreateUnsubscribePacket(
                m_streamInfo.streamKey, thePrefs.GetUserHash());
            if (pkt) {
                theStats.AddUpDataOverheadOther(pkt->size);
                peer->SendPacket(pkt);
            }
        }
    }

    m_bViewing = false;
    m_chunkBuffer.Clear();
    m_viewPeers.RemoveAll();
    m_peerBitmaps.RemoveAll();
    ResetViewerHlsOutput();

    AddLogLine(true, _T("eSE Live: Left stream"));
}

bool CLiveStreamManager::TryConnectToStreamSource(const uchar* streamKey, uint32 ip, uint16 port)
{
    CSingleLock lock(&m_lock, TRUE);

    if (!m_bViewing) return false;
    if (streamKey == NULL || memcmp(m_streamInfo.streamKey, streamKey, 16) != 0) return false;
    if (ip == 0 || port == 0) return false;
    if (ip == theApp.GetPublicIP()) return false;
    if (theApp.ipfilter->IsFiltered(ip)) return false;

    // Fix 2 (ALTA): Block loopback, LAN, multicast, broadcast via IsGoodIPPort.
    if (!IsGoodIPPort(ip, port)) {
        AddLogLine(false, _T("eSE Live: Rejected non-routable source %s:%u"),
            (LPCTSTR)ipstr(ip), port);
        return false;
    }

    POSITION pos = m_viewPeers.GetHeadPosition();
    while (pos) {
        CUpDownClient* existing = m_viewPeers.GetNext(pos);
        if (existing && existing->GetIP() == ip && existing->GetUserPort() == port)
            return true;
    }

    CUpDownClient* client = theApp.clientlist->FindClientByIP(ip, port);
    if (client == NULL) {
        client = new CUpDownClient(NULL, port, ntohl(ip), 0, 0, false);
        client->SetIP(ip);
        theApp.clientlist->AddClient(client);
    }

    Packet* pkt = eSELive::CreateSubscribePacket(m_streamInfo.streamKey, thePrefs.GetUserHash(), 0);
    if (pkt) {
        theStats.AddUpDataOverheadOther(pkt->size);
        client->SafeConnectAndSendPacket(pkt);
        InterlockedIncrement(&m_counters.subscribeSent);  // Phase 0: OBS-1 (atomic)
    }

    m_viewPeers.AddTail(client);
    m_meshManager.AddMeshPeer(client);
    // Fix 4: Use dedicated sourceDialAttempts instead of duplicate kadResultsAccepted
    InterlockedIncrement(&m_counters.sourceDialAttempts);

    AddLogLine(false, _T("eSE Live: Dialing discovered source %s:%u"),
        (LPCTSTR)ipstr(ip), port);
    return true;
}

CString CLiveStreamManager::GetLiveHlsDir() const
{
    TCHAR tmpPath[MAX_PATH];
    GetTempPath(MAX_PATH, tmpPath);
    CString dir;
    dir.Format(_T("%seMule_RTMP"), tmpPath);

    // Per-stream subdirectory prevents collisions between broadcaster HLS
    // output and reconstructed viewer HLS for different stream hashes.
    bool hasKey = false;
    for (int i = 0; i < 16; ++i) {
        if (m_streamInfo.streamKey[i] != 0) { hasKey = true; break; }
    }
    if (hasKey) {
        CString hexSub;
        for (int i = 0; i < 16; ++i) {
            CString byteHex;
            byteHex.Format(_T("%02x"), m_streamInfo.streamKey[i]);
            hexSub += byteHex;
        }
        dir.AppendFormat(_T("\\%s"), (LPCTSTR)hexSub);
    }
    return dir;
}

static void EseEnsureDirectoryTree(const CString& dir)
{
    int slash = dir.ReverseFind(_T('\\'));
    if (slash > 0) {
        CString parent = dir.Left(slash);
        CreateDirectory(parent, NULL);
    }
    CreateDirectory(dir, NULL);
}

void CLiveStreamManager::ResetViewerHlsOutput()
{
    CString dir = GetLiveHlsDir();
    EseEnsureDirectoryTree(dir);

    CString pattern;
    pattern.Format(_T("%s\\seg_*.ts"), (LPCTSTR)dir);
    WIN32_FIND_DATA fd;
    HANDLE hFind = FindFirstFile(pattern, &fd);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            CString filePath;
            filePath.Format(_T("%s\\%s"), (LPCTSTR)dir, fd.cFileName);
            DeleteFile(filePath);
        } while (FindNextFile(hFind, &fd));
        FindClose(hFind);
    }

    CString playlist;
    playlist.Format(_T("%s\\stream.m3u8"), (LPCTSTR)dir);
    DeleteFile(playlist);
}

void CLiveStreamManager::WriteViewerHlsSegment(uint32 seqNum, const BYTE* data, uint32 dataSize)
{
    if ((!m_bViewing && !m_bBroadcasting) || data == NULL || dataSize == 0)
        return;

    CString dir = GetLiveHlsDir();
    EseEnsureDirectoryTree(dir);

    CString segFile;
    segFile.Format(_T("%s\\seg_%05u.ts"), (LPCTSTR)dir, seqNum);

    CFile file;
    if (file.Open(segFile, CFile::modeCreate | CFile::modeWrite | CFile::typeBinary | CFile::shareDenyNone)) {
        file.Write(data, dataSize);
        InterlockedIncrement(&m_counters.hlsSegmentsWritten);  // Phase 0: OBS-1 (atomic)
        file.Close();
        RefreshViewerHlsPlaylist();
    }
}

void CLiveStreamManager::RefreshViewerHlsPlaylist()
{
    if (m_chunkBuffer.GetCount() == 0)
        return;

    CString dir = GetLiveHlsDir();
    EseEnsureDirectoryTree(dir);
    uint32 oldest = m_chunkBuffer.GetOldestSeq();
    uint32 newest = m_chunkBuffer.GetNewestSeq();

    // Phase 3 HLS-2: Buffer minimum gate — do not generate playlist until
    // we have at least 3 contiguous segments. This prevents premature playback
    // that causes stuttering and immediate re-buffering on the client.
    const uint32 ESE_HLS_MIN_BUFFER_SEGMENTS = 3;
    uint32 contiguous = 0;
    for (uint32 seq = oldest; seq <= newest; ++seq) {
        if (m_chunkBuffer.HasSegment(seq))
            contiguous++;
        else
            contiguous = 0;  // reset on gap
    }
    if (contiguous < ESE_HLS_MIN_BUFFER_SEGMENTS) {
        AddDebugLogLine(false, _T("eSE HLS: Waiting for buffer (%u/%u contiguous segments)"),
            contiguous, ESE_HLS_MIN_BUFFER_SEGMENTS);
        return;  // Not enough buffered — wait
    }

    // Phase 3 HLS-4: Stale segment cleanup with margin.
    // Delete .ts files that are outside the [oldest-2, newest] range.
    // The 2-segment margin prevents race conditions with slow disk I/O.
    CString pattern;
    pattern.Format(_T("%s\\seg_*.ts"), (LPCTSTR)dir);
    WIN32_FIND_DATA fd;
    HANDLE hFind = FindFirstFile(pattern, &fd);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            CString name(fd.cFileName);
            int uscore = name.Find(_T('_'));
            int dot = name.Find(_T('.'));
            if (uscore >= 0 && dot > uscore) {
                uint32 seq = (uint32)_ttoi(name.Mid(uscore + 1, dot - uscore - 1));
                const uint32 cleanupMargin = 2;
                if (seq + cleanupMargin < oldest || seq > newest) {
                    CString filePath;
                    filePath.Format(_T("%s\\%s"), (LPCTSTR)dir, fd.cFileName);
                    DeleteFile(filePath);
                }
            }
        } while (FindNextFile(hFind, &fd));
        FindClose(hFind);
    }

    // Phase 3 HLS-3 FIX: Build playlist with only segments that actually exist.
    // Use #EXT-X-DISCONTINUITY at gap boundaries for standards compliance.
    // Set EXT-X-MEDIA-SEQUENCE to the first actually-present segment,
    // not the oldest buffered seq (which may be missing in P2P).
    uint32 firstPresentSeq = 0;
    bool foundFirst = false;
    for (uint32 seq = oldest; seq <= newest; ++seq) {
        if (m_chunkBuffer.HasSegment(seq)) {
            firstPresentSeq = seq;
            foundFirst = true;
            break;
        }
    }
    if (!foundFirst)
        return;  // No segments at all — nothing to write

    CStringA playlist;
    playlist.Format(
        "#EXTM3U\n"
        "#EXT-X-VERSION:3\n"
        "#EXT-X-TARGETDURATION:%u\n"
        "#EXT-X-MEDIA-SEQUENCE:%u\n",
        ESE_LIVE_SEGMENT_DURATION,
        firstPresentSeq);

    uint32 gapCount = 0;
    bool lastWasPresent = true;
    for (uint32 seq = firstPresentSeq; seq <= newest; ++seq) {
        if (m_chunkBuffer.HasSegment(seq)) {
            if (!lastWasPresent) {
                // Insert discontinuity tag after a gap
                playlist += "#EXT-X-DISCONTINUITY\n";
            }
            CStringA line;
            line.Format("#EXTINF:%u.000,\nseg_%05u.ts\n", ESE_LIVE_SEGMENT_DURATION, seq);
            playlist += line;
            lastWasPresent = true;
        } else {
            // Phase 3 HLS-5: Track gaps for diagnostics — but DO NOT emit
            // a segment entry for missing data (prevents 404 cascade).
            gapCount++;
            lastWasPresent = false;
        }
    }

    if (gapCount > 0) {
        AddDebugLogLine(false, _T("eSE HLS: Playlist has %u gaps in range [%u..%u]"),
            gapCount, oldest, newest);
    }

    CString playlistPath;
    playlistPath.Format(_T("%s\\stream.m3u8"), (LPCTSTR)dir);
    CFile file;
    if (file.Open(playlistPath, CFile::modeCreate | CFile::modeWrite | CFile::typeBinary | CFile::shareDenyNone)) {
        file.Write((const void*)(LPCSTR)playlist, playlist.GetLength());
        file.Close();
        InterlockedIncrement(&m_counters.hlsPlaylistRefresh);  // Phase 0: OBS-1 (atomic)
    }
}


// ============================================================
// PEER MANAGEMENT
// ============================================================

void CLiveStreamManager::OnPeerJoin(CUpDownClient* peer, const uchar* streamKey,
    uint32 uploadCapacity)
{
    CSingleLock lock(&m_lock, TRUE);

    if (!m_bBroadcasting && !m_bViewing) return;
    if (memcmp(m_streamInfo.streamKey, streamKey, 16) != 0) return;

    // Register peer
    if (m_broadcastPeers.Find(peer) == NULL)
        m_broadcastPeers.AddTail(peer);
    PeerTrust& trust = GetOrCreateTrust(peer);
    trust.joinedAt = GetTickCount();
    trust.currentLevel = ESE_TRUST_LEAF;  // Everyone starts as leaf

    m_streamInfo.viewerCount = (uint32)m_broadcastPeers.GetCount();
    InterlockedIncrement(&m_counters.subscribeAccepted);  // Phase 0: OBS-1 (atomic)

    AddLogLine(false, _T("eSE Live: Peer joined/relayed (upload=%u KB/s, viewers=%u)"),
        uploadCapacity / 1024, m_streamInfo.viewerCount);

    // Track in mesh manager for topology
    m_meshManager.AddMeshPeer(peer);

    // Send recent peers list to the new joiner
    // Collect up to 5 peers IPs/ports
    CArray<DWORD> peerIPs;
    CArray<uint16> peerPorts;
    POSITION pos2 = m_broadcastPeers.GetHeadPosition();
    while (pos2 && peerIPs.GetCount() < ESE_LIVE_MAX_PEERS) {
        CUpDownClient* existing = m_broadcastPeers.GetNext(pos2);
        if (existing != peer && existing->GetIP() != 0) {
            peerIPs.Add(existing->GetIP());
            peerPorts.Add(existing->GetUserPort());
        }
    }
    pos2 = m_viewPeers.GetHeadPosition();
    while (pos2 && peerIPs.GetCount() < ESE_LIVE_MAX_PEERS) {
        CUpDownClient* existing = m_viewPeers.GetNext(pos2);
        if (existing != peer && existing->GetIP() != 0) {
            peerIPs.Add(existing->GetIP());
            peerPorts.Add(existing->GetUserPort());
        }
    }
    if (peerIPs.GetCount() > 0) {
        Packet* peerListPkt = eSELive::CreatePeerListPacket(
            m_streamInfo.streamKey,
            peerIPs.GetData(), peerPorts.GetData(),
            (uint16)peerIPs.GetCount());
        if (peerListPkt) {
            theStats.AddUpDataOverheadOther(peerListPkt->size);
            peer->SendPacket(peerListPkt);
        }
    }

    Packet* bitmapPkt = eSELive::CreateHeartbeatPacket(
        m_streamInfo.streamKey, m_chunkBuffer.GetBitmap(), m_chunkBuffer.GetOldestSeq());
    if (bitmapPkt) {
        theStats.AddUpDataOverheadOther(bitmapPkt->size);
        peer->SendPacket(bitmapPkt);
    }
}

void CLiveStreamManager::OnPeerRequest(CUpDownClient* peer, const uchar* streamKey,
    uint32 seqNum)
{
    CSingleLock lock(&m_lock, TRUE);

    if (memcmp(m_streamInfo.streamKey, streamKey, 16) != 0) return;

    const LiveChunk* chunk = m_chunkBuffer.GetSegment(seqNum);
    if (!chunk) return;

    // Update trust tracking
    PeerTrust& trust = GetOrCreateTrust(peer);
    trust.requestsReceived++;
    trust.requestsServed++;

    // Send the chunk data to the peer
    Packet* pkt = eSELive::CreateChunkPacket(chunk);
    if (pkt) {
        theStats.AddUpDataOverheadOther(pkt->size);
        peer->SendPacket(pkt);
        m_meshManager.TrackUpload(peer, chunk->dataSize);
        // Fix 5: Actually count active uploads so /api/live/debug isn't always 0
        m_meshManager.IncrementChunksServed();
    }
}

void CLiveStreamManager::OnChunkReceived(CUpDownClient* peer, const uchar* streamKey,
    uint32 seqNum, uint32 timestamp, const BYTE* data, uint32 dataSize)
{
    CSingleLock lock(&m_lock, TRUE);

    if (!m_bViewing) return;
    if (memcmp(m_streamInfo.streamKey, streamKey, 16) != 0) return;

    // Store in our buffer
    // Phase 0: Counter instrumentation (OBS-1)
    InterlockedIncrement(&m_counters.chunksReceived);  // Phase 0: OBS-1 (atomic)
    InterlockedExchange((LONG*)&m_counters.lastChunkReceivedAt, (LONG)GetTickCount());
    m_chunkBuffer.AddSegment(streamKey, seqNum, timestamp,
        data, dataSize, m_streamInfo.bitrate);
    WriteViewerHlsSegment(seqNum, data, dataSize);

    // Update trust for the sending peer
    PeerTrust& trust = GetOrCreateTrust(peer);
    trust.bytesServed += dataSize;  // Peer served us these bytes

    // Notify mesh manager that this request is fulfilled
    m_meshManager.FulfillRequest(seqNum);
}

void CLiveStreamManager::OnPeerBitmap(CUpDownClient* peer, const uchar* streamKey,
    uint32 oldestSeq, uint16 bitmap)
{
    CSingleLock lock(&m_lock, TRUE);

    if (memcmp(m_streamInfo.streamKey, streamKey, 16) != 0) return;

    m_peerBitmaps[peer] = bitmap;
}

void CLiveStreamManager::OnPeerListReceived(CUpDownClient* /*peer*/,
    const uchar* streamKey,
    const CArray<DWORD>& ips, const CArray<uint16>& ports)
{
    CSingleLock lock(&m_lock, TRUE);

    if (!m_bViewing) return;
    if (memcmp(m_streamInfo.streamKey, streamKey, 16) != 0) return;

    for (INT_PTR i = 0; i < ips.GetCount(); i++) {
        DWORD ip = ips[i];
        uint16 port = ports[i];

        // Skip our own IP
        if (ip == theApp.GetPublicIP()) continue;

        // Skip if already connected to this peer
        bool alreadyConnected = false;
        POSITION pos2 = m_viewPeers.GetHeadPosition();
        while (pos2) {
            CUpDownClient* existing = m_viewPeers.GetNext(pos2);
            if (existing && existing->GetIP() == ip) {
                alreadyConnected = true;
                break;
            }
        }
        if (alreadyConnected) continue;

        // Check IPFilter
        if (theApp.ipfilter->IsFiltered(ip)) continue;

        // Try to find or create a client for this peer. Peer-list IPs are stored in network order.
        CUpDownClient* newClient = theApp.clientlist->FindClientByIP(ip, port);
        if (newClient) {
            // Send OP_LIVE_SUBSCRIBE to join the stream via this peer
            Packet* pkt = eSELive::CreateSubscribePacket(
                m_streamInfo.streamKey, thePrefs.GetUserHash(), 0);
            if (pkt) {
                theStats.AddUpDataOverheadOther(pkt->size);
                newClient->SafeConnectAndSendPacket(pkt);
            }
            if (m_viewPeers.Find(newClient) == NULL)
                m_viewPeers.AddTail(newClient);
            m_meshManager.AddMeshPeer(newClient);

            AddLogLine(false, _T("eSE Live: Connected to peer %s:%u from peer list"),
                (LPCTSTR)ipstr(ip), port);
        } else {
            CUpDownClient* created = new CUpDownClient(NULL, port, ntohl(ip), 0, 0, false);
            created->SetIP(ip);
            theApp.clientlist->AddClient(created);
            Packet* pkt = eSELive::CreateSubscribePacket(
                m_streamInfo.streamKey, thePrefs.GetUserHash(), 0);
            if (pkt) {
                theStats.AddUpDataOverheadOther(pkt->size);
                created->SafeConnectAndSendPacket(pkt);
            }
            m_viewPeers.AddTail(created);
            m_meshManager.AddMeshPeer(created);

            AddLogLine(false, _T("eSE Live: Dialing new peer %s:%u from peer list"),
                (LPCTSTR)ipstr(ip), port);
        }
    }
}

void CLiveStreamManager::OnPeerDisconnected(CUpDownClient* peer)
{
    CSingleLock lock(&m_lock, TRUE);

    // Remove from broadcast peers
    POSITION pos = m_broadcastPeers.Find(peer);
    if (pos) {
        m_broadcastPeers.RemoveAt(pos);
        m_streamInfo.viewerCount = (uint32)m_broadcastPeers.GetCount();
    }

    // Remove from view peers
    pos = m_viewPeers.Find(peer);
    if (pos) {
        m_viewPeers.RemoveAt(pos);
        // Request more peers if below minimum
        if (m_bViewing && m_viewPeers.GetCount() < ESE_LIVE_MIN_PEERS) {
            // TODO: Request more peers from broadcaster
        }
    }

    // Remove trust data
    m_peerTrust.RemoveKey(peer);
    m_peerBitmaps.RemoveKey(peer);

    InterlockedIncrement(&m_counters.peerDisconnects);  // Phase 0: OBS-1 (atomic)
    // Remove from mesh manager
    m_meshManager.RemoveMeshPeer(peer);
}


// ============================================================
// ANTI-SYBIL
// ============================================================

int CLiveStreamManager::CalculateTrustLevel(CUpDownClient* peer)
{
    PeerTrust& trust = GetOrCreateTrust(peer);

    if (trust.isBanned) return ESE_TRUST_LEAF;

    DWORD uptime = trust.GetUptime();
    float responseRate = trust.GetResponseRate();

    // New peer: always leaf
    if (uptime < ESE_PROMOTE_MIDDLE_TIME) return ESE_TRUST_LEAF;

    // Low response rate (but only if enough requests to judge)
    if (trust.requestsReceived > 5 && responseRate < ESE_PROMOTE_MIDDLE_RATE)
        return ESE_TRUST_LEAF;

    // Failed too many times
    if (trust.failCount > 2) return ESE_TRUST_LEAF;

    // Not enough time for super-seeder
    if (uptime < ESE_PROMOTE_SUPER_TIME) return ESE_TRUST_MIDDLE;

    // High response rate required for super-seeder
    if (trust.requestsReceived > 10 && responseRate < ESE_PROMOTE_SUPER_RATE)
        return ESE_TRUST_MIDDLE;

    // Check subnet diversity
    if (!CanPromoteToSuperSeeder(peer)) return ESE_TRUST_MIDDLE;

    return ESE_TRUST_SUPERSEEDER;
}

void CLiveStreamManager::MeasurePeerRatio(CUpDownClient* peer)
{
    PeerTrust& trust = GetOrCreateTrust(peer);
    DWORD uptime = trust.GetUptime();

    // If nobody has asked this peer for anything, we can't judge them
    // Send a probe test instead
    if (trust.requestsReceived == 0) {
        if (uptime > ESE_PROMOTE_MIDDLE_TIME &&
            GetTickCount() - trust.lastProbeTime > ESE_LIVE_PROBE_TIMEOUT * 2) {
            ProbeTestPeer(peer);
        }
        return;
    }

    float responseRate = trust.GetResponseRate();

    // Only judge after enough requests
    if (uptime > ESE_PROMOTE_MIDDLE_TIME) {
        if (trust.requestsReceived > 10 && responseRate < ESE_BAN_RESPONSE_RATE) {
            // Confirmed: refuses to serve requests
            BanPeer(peer);
            return;
        }
        if (trust.requestsReceived > 5 && responseRate < ESE_DEGRADE_RESPONSE_RATE) {
            DemotePeer(peer);
        }
    }

    // Try to promote
    int newLevel = CalculateTrustLevel(peer);
    if (newLevel < trust.currentLevel) {
        trust.currentLevel = newLevel;
        trust.lastPromotionTime = GetTickCount();
        AddLogLine(false, _T("eSE Live: Peer promoted to level %d (response rate: %.0f%%)"),
            newLevel, responseRate * 100.0f);
    }
}

void CLiveStreamManager::ProbeTestPeer(CUpDownClient* peer)
{
    PeerTrust& trust = GetOrCreateTrust(peer);

    // Find a segment we know this peer has (from their bitmap)
    uint16 bitmap = 0;
    if (!m_peerBitmaps.Lookup(peer, bitmap) || bitmap == 0) return;

    // Find any set bit in the bitmap
    uint32 oldestSeq = m_chunkBuffer.GetOldestSeq();
    for (int bit = 0; bit < ESE_LIVE_MAX_SEGMENTS; bit++) {
        if (bitmap & (1 << bit)) {
            uint32 testSeq = oldestSeq + bit;
            // Send probe request
            Packet* pkt = eSELive::CreateRequestPacket(m_streamInfo.streamKey, testSeq);
            if (pkt) {
                theStats.AddUpDataOverheadOther(pkt->size);
                peer->SendPacket(pkt);
            }
            trust.lastProbeTime = GetTickCount();
            trust.requestsReceived++;
            // If they respond: requestsServed++ in OnChunkReceived
            // If they don't: ratio drops naturally
            break;
        }
    }
}

bool CLiveStreamManager::CanPromoteToSuperSeeder(CUpDownClient* peer)
{
    // Anti-botnet: prevent a single datacenter from dominating as super-seeders.
    // Rules:
    //   1. Max 5 super-seeders from the same /24 subnet
    //   2. Max 20% of super-seeders from the same /16 subnet

    if (!peer) return false;

    uint32 peerIP = peer->GetIP();
    if (peerIP == 0) return true;  // Can't check, allow

    uint32 peer24 = peerIP & 0xFFFFFF00;  // /24 mask
    uint32 peer16 = peerIP & 0xFFFF0000;  // /16 mask

    int sameSubnet24 = 0;
    int sameSubnet16 = 0;
    int totalSuper = 0;

    POSITION pos = m_broadcastPeers.GetHeadPosition();
    while (pos) {
        CUpDownClient* other = m_broadcastPeers.GetNext(pos);
        if (other == peer) continue;

        PeerTrust trust;
        if (!m_peerTrust.Lookup(other, trust)) continue;
        if (trust.currentLevel != ESE_TRUST_SUPERSEEDER) continue;

        totalSuper++;
        uint32 otherIP = other->GetIP();
        if ((otherIP & 0xFFFFFF00) == peer24) sameSubnet24++;
        if ((otherIP & 0xFFFF0000) == peer16) sameSubnet16++;
    }

    // Rule 1: Max 5 super-seeders per /24
    if (sameSubnet24 >= 5) {
        AddLogLine(false, _T("eSE Anti-Sybil: Blocked promotion — too many super-seeders in /24 (%d)"),
            sameSubnet24);
        return false;
    }

    // Rule 2: Max 20% of super-seeders per /16
    if (totalSuper > 10 && sameSubnet16 > totalSuper / 5) {
        AddLogLine(false, _T("eSE Anti-Sybil: Blocked promotion — /16 concentration too high (%d/%d)"),
            sameSubnet16, totalSuper);
        return false;
    }

    return true;
}

void CLiveStreamManager::MonitorPeerHealth()
{
    // Count active super-seeders and check connectivity
    int totalSuper = 0;
    int aliveSuper = 0;
    CArray<uint32> droppedSubnets;  // /24 subnets of dropped super-seeders

    POSITION pos = m_broadcastPeers.GetHeadPosition();
    while (pos) {
        CUpDownClient* peer = m_broadcastPeers.GetNext(pos);
        PeerTrust trust;
        if (m_peerTrust.Lookup(peer, trust)) {
            if (trust.currentLevel == ESE_TRUST_SUPERSEEDER) {
                totalSuper++;
                // Check if peer is still connected (socket exists and is valid)
                if (peer->GetIP() != 0 && peer->socket != NULL) {
                    aliveSuper++;
                } else {
                    // Track the subnet of the dropped peer
                    droppedSubnets.Add(peer->GetIP() & 0xFFFFFF00);
                }
            }
        }
    }

    if (totalSuper == 0) return;

    float dropRate = 1.0f - (float)aliveSuper / totalSuper;

    if (dropRate > ESE_EMERGENCY_DROP_THRESHOLD && !m_bEmergencyMode) {
        m_bEmergencyMode = true;
        m_dwEmergencyStart = GetTickCount();
        AddLogLine(true, _T("eSE Live: EMERGENCY — %.0f%% super-seeders dropped (%d/%d)"),
            dropRate * 100.0f, totalSuper - aliveSuper, totalSuper);

        // === Emergency Action 1: Promote trusted middle-tier peers ===
        int promoted = 0;
        pos = m_broadcastPeers.GetHeadPosition();
        while (pos && promoted < 5) {
            CUpDownClient* peer = m_broadcastPeers.GetNext(pos);
            PeerTrust trust;
            if (!m_peerTrust.Lookup(peer, trust)) continue;
            if (trust.currentLevel != ESE_TRUST_MIDDLE) continue;

            // Only promote if good response rate and subnet-diverse
            if (trust.GetResponseRate() >= ESE_PROMOTE_SUPER_RATE &&
                trust.failCount == 0 &&
                CanPromoteToSuperSeeder(peer))
            {
                trust.currentLevel = ESE_TRUST_SUPERSEEDER;
                trust.lastPromotionTime = GetTickCount();
                m_peerTrust[peer] = trust;
                promoted++;
                AddLogLine(false, _T("eSE Emergency: Promoted peer to super-seeder (emergency promotion #%d)"),
                    promoted);
            }
        }

        // === Emergency Action 2: Ban peers from same subnet as dropped ===
        // If multiple super-seeders from the same /24 dropped simultaneously,
        // it's likely a coordinated attack. Ban other peers from that subnet.
        CMap<uint32, uint32, int, int> subnetDropCounts;
        for (INT_PTR i = 0; i < droppedSubnets.GetCount(); i++) {
            int count = 0;
            subnetDropCounts.Lookup(droppedSubnets[i], count);
            subnetDropCounts[droppedSubnets[i]] = count + 1;
        }

        uint32 subnet;
        int count;
        POSITION mapPos = subnetDropCounts.GetStartPosition();
        while (mapPos) {
            subnetDropCounts.GetNextAssoc(mapPos, subnet, count);
            if (count >= 2) {
                // 2+ super-seeders from same /24 dropped → ban others from that subnet
                AddLogLine(true, _T("eSE Anti-Sybil: Banning peers from suspicious /24 subnet (%d drops)"),
                    count);
                pos = m_broadcastPeers.GetHeadPosition();
                while (pos) {
                    POSITION curPos = pos;
                    CUpDownClient* peer = m_broadcastPeers.GetNext(pos);
                    if ((peer->GetIP() & 0xFFFFFF00) == subnet) {
                        BanPeer(peer);
                    }
                }
            }
        }
    }

    // End emergency after timeout
    if (m_bEmergencyMode &&
        GetTickCount() - m_dwEmergencyStart > ESE_EMERGENCY_DURATION)
    {
        m_bEmergencyMode = false;
        AddLogLine(true, _T("eSE Live: Emergency mode ended (recovered)"));
    }
}


// ============================================================
// PERIODIC PROCESSING
// ============================================================

void CLiveStreamManager::Process()
{
    CSingleLock lock(&m_lock, TRUE);

    DWORD now = GetTickCount();

    if (m_bBroadcasting) {
        // Send bitmap to all peers
        if (now - m_dwLastBitmapSend >= ESE_LIVE_BITMAP_INTERVAL) {
            SendBitmapToAll();
            m_dwLastBitmapSend = now;
        }

        // Announce new segments
        if (now - m_dwLastAnnounceSend >= ESE_LIVE_ANNOUNCE_INTERVAL) {
            SendAnnounceToAll();
            m_dwLastAnnounceSend = now;
        }

        // Publish to Kad
        if (now - m_dwLastKadPublish >= ESE_LIVE_KAD_PUBLISH_INTERVAL) {
            PublishToKad();
            m_dwLastKadPublish = now;
        }

        // Check peer health
        if (now - m_dwLastHealthCheck >= ESE_LIVE_STATS_INTERVAL) {
            MonitorPeerHealth();
            // Measure ratios for all peers
            POSITION pos = m_broadcastPeers.GetHeadPosition();
            while (pos) {
                CUpDownClient* peer = m_broadcastPeers.GetNext(pos);
                MeasurePeerRatio(peer);
            }
            m_dwLastHealthCheck = now;
        }
    }

    if (m_bViewing) {
        // Send our bitmap to peers
        if (now - m_dwLastBitmapSend >= ESE_LIVE_BITMAP_INTERVAL) {
            SendBitmapToAll();
            m_dwLastBitmapSend = now;
        }

        // Request missing segments
        RequestMissingSegments();
    }

    // Kad discovery maintenance (works for both broadcaster and viewer)
    m_kadBridge.Process();

    // Mesh topology maintenance
    m_meshManager.Process();
}


// ============================================================
// INTERNAL HELPERS
// ============================================================

void CLiveStreamManager::SendBitmapToAll()
{
    uint16 bitmap = m_chunkBuffer.GetBitmap();
    uint32 oldestSeq = m_chunkBuffer.GetOldestSeq();

    // Send to broadcast peers (if we're broadcasting)
    if (m_bBroadcasting) {
        POSITION pos = m_broadcastPeers.GetHeadPosition();
        while (pos) {
            CUpDownClient* peer = m_broadcastPeers.GetNext(pos);
            Packet* pkt = eSELive::CreateHeartbeatPacket(
                m_streamInfo.streamKey, bitmap, oldestSeq);
            if (pkt) {
                theStats.AddUpDataOverheadOther(pkt->size);
                peer->SendPacket(pkt);
            }
        }
    }

    // Send to view peers (if we're viewing)
    if (m_bViewing) {
        POSITION pos = m_viewPeers.GetHeadPosition();
        while (pos) {
            CUpDownClient* peer = m_viewPeers.GetNext(pos);
            Packet* pkt = eSELive::CreateHeartbeatPacket(
                m_streamInfo.streamKey, bitmap, oldestSeq);
            if (pkt) {
                theStats.AddUpDataOverheadOther(pkt->size);
                peer->SendPacket(pkt);
            }
        }

        pos = m_broadcastPeers.GetHeadPosition();
        while (pos) {
            CUpDownClient* peer = m_broadcastPeers.GetNext(pos);
            Packet* pkt = eSELive::CreateHeartbeatPacket(
                m_streamInfo.streamKey, bitmap, oldestSeq);
            if (pkt) {
                theStats.AddUpDataOverheadOther(pkt->size);
                peer->SendPacket(pkt);
            }
        }
    }
}

void CLiveStreamManager::SendAnnounceToAll()
{
    if (!m_bBroadcasting || m_chunkBuffer.GetCount() == 0) return;

    uint32 newestSeq = m_chunkBuffer.GetNewestSeq();

    POSITION pos = m_broadcastPeers.GetHeadPosition();
    while (pos) {
        CUpDownClient* peer = m_broadcastPeers.GetNext(pos);
        Packet* pkt = eSELive::CreateAnnouncePacket(
            m_streamInfo.streamKey, newestSeq, m_streamInfo.bitrate);
        if (pkt) {
            theStats.AddUpDataOverheadOther(pkt->size);
            peer->SendPacket(pkt);
        }
    }
}

void CLiveStreamManager::RequestMissingSegments()
{
    if (!m_bViewing || m_viewPeers.GetCount() == 0) return;

    // Find our newest segment and request the next ones
    uint32 newestSeq = m_chunkBuffer.GetNewestSeq();
    uint32 oldestSeq = m_chunkBuffer.GetOldestSeq();

    // Phase 3 HLS-5: Request up to 5 missing segments with extended lookahead.
    // The +3 lookahead beyond newest ensures we can pre-fetch upcoming segments
    // from peers that are slightly ahead of us in the stream timeline.
    int requested = 0;
    const int maxRequestsPerCycle = 5;
    const uint32 lookahead = 3;
    for (uint32 seq = oldestSeq; seq <= newestSeq + lookahead && requested < maxRequestsPerCycle; seq++) {
        if (!m_chunkBuffer.HasSegment(seq)) {
            InterlockedIncrement(&m_counters.chunksMissing);  // Phase 3 HLS-5: gap detection
            CUpDownClient* peer = SelectPeerForSegment(seq);
            if (peer) {
                Packet* pkt = eSELive::CreateRequestPacket(
                    m_streamInfo.streamKey, seq);
                if (pkt) {
                    theStats.AddUpDataOverheadOther(pkt->size);
                    peer->SendPacket(pkt);
                    InterlockedIncrement(&m_counters.chunksRequested);  // Phase 0: OBS-1 (atomic)
                    requested++;
                }
            } else {
                // Phase 3 HLS-5: No peer available for this segment
                AddDebugLogLine(false, _T("eSE HLS: No peer has segment %u (gap recovery failed)"), seq);
            }
        }
    }
}

void CLiveStreamManager::PublishToKad()
{
    if (!m_bBroadcasting) return;

    m_streamInfo.viewerCount = (uint32)m_broadcastPeers.GetCount();
    InterlockedIncrement(&m_counters.kadPublishes);  // Phase 0: OBS-1 (atomic)
    m_kadBridge.PublishStream(m_streamInfo);
    m_kadBridge.RepublishIfNeeded();
}

void CLiveStreamManager::DemotePeer(CUpDownClient* peer)
{
    PeerTrust& trust = GetOrCreateTrust(peer);
    if (trust.currentLevel < ESE_TRUST_LEAF) {
        trust.currentLevel++;
        AddLogLine(false, _T("eSE Live: Peer demoted to level %d (response: %.0f%%)"),
            trust.currentLevel, trust.GetResponseRate() * 100.0f);
    }
}

void CLiveStreamManager::BanPeer(CUpDownClient* peer)
{
    PeerTrust& trust = GetOrCreateTrust(peer);
    trust.isBanned = true;
    AddLogLine(true, _T("eSE Live: Peer banned (response rate: %.0f%% after %u requests)"),
        trust.GetResponseRate() * 100.0f, trust.requestsReceived);

    // Send deny packet and disconnect
    Packet* pkt = eSELive::CreateDenyPacket(m_streamInfo.streamKey, ESE_DENY_BANNED);
    if (pkt) {
        theStats.AddUpDataOverheadOther(pkt->size);
        peer->SendPacket(pkt);
    }
}

PeerTrust& CLiveStreamManager::GetOrCreateTrust(CUpDownClient* peer)
{
    PeerTrust trust;
    if (!m_peerTrust.Lookup(peer, trust)) {
        trust.joinedAt = GetTickCount();
        m_peerTrust[peer] = trust;
    }
    return m_peerTrust[peer];
}

CUpDownClient* CLiveStreamManager::SelectPeerForSegment(uint32 seqNum)
{
    // Find peers that have this segment (check bitmaps)
    CUpDownClient* bestPeer = NULL;
    int bestScore = -1;

    POSITION pos = m_viewPeers.GetHeadPosition();
    while (pos) {
        CUpDownClient* peer = m_viewPeers.GetNext(pos);
        uint16 bitmap = 0;
        if (!m_peerBitmaps.Lookup(peer, bitmap)) continue;

        uint32 oldest = m_chunkBuffer.GetOldestSeq();
        uint32 bit = seqNum - oldest;
        if (bit < 16 && (bitmap & (1 << bit))) {
            // This peer has the segment
            PeerTrust trust;
            int score = 0;
            if (m_peerTrust.Lookup(peer, trust)) {
                score = (int)(trust.GetResponseRate() * 100);
                score -= trust.failCount * 20;
            }
            if (score > bestScore) {
                bestScore = score;
                bestPeer = peer;
            }
        }
    }

    return bestPeer;
}

uint32 CLiveStreamManager::GetViewerCount() const
{
    return m_streamInfo.viewerCount;
}

uint32 CLiveStreamManager::GetMinUploadRequired() const
{
    if (!m_bViewing) return 0;

    // Bitrate del stream en bytes/s, multiplicado por ratio 1:5
    uint32 streamBytesPerSec = m_streamInfo.bitrate * 1000 / 8;
    return streamBytesPerSec * 5;
}


// ============================================================
// THREAD-SAFE DEBUG SNAPSHOT (Fix 1)
// ============================================================

LiveDebugSnapshot CLiveStreamManager::BuildDebugSnapshot() const
{
    CSingleLock lock(&m_lock, TRUE);

    LiveDebugSnapshot snap;
    memset(&snap, 0, sizeof(snap));

    // Stream state
    snap.broadcasting  = m_bBroadcasting;
    snap.viewing       = m_bViewing;
    snap.emergencyMode = m_bEmergencyMode;
    snap.uptimeMs      = (m_streamInfo.startedAt > 0)
        ? ((uint32)time(NULL) - m_streamInfo.startedAt) * 1000 : 0;

    // Kad — delegate to KadBridge's own lock
    snap.kad = m_kadBridge.BuildDebugKadSnapshot();

    // Peers (counted under our lock)
    snap.viewPeers      = (int)m_viewPeers.GetCount();
    snap.broadcastPeers = (int)m_broadcastPeers.GetCount();
    snap.meshPeers      = m_meshManager.GetMeshPeerCount();
    snap.pendingRequests = m_meshManager.GetPendingRequestCount();
    snap.chunksServed    = m_meshManager.GetChunksServedCount();

    // Trust tier census (iterate bitmaps under our lock)
    snap.superSeeders = 0;
    snap.middlePeers  = 0;
    snap.leafPeers    = 0;
    {
        POSITION pos = m_peerBitmaps.GetStartPosition();
        while (pos) {
            CUpDownClient* peer = NULL;
            uint16 bm = 0;
            m_peerBitmaps.GetNextAssoc(pos, peer, bm);
            PeerTrust trust;
            if (m_peerTrust.Lookup(peer, trust)) {
                if (trust.currentLevel == ESE_TRUST_SUPERSEEDER)
                    snap.superSeeders++;
                else if (trust.currentLevel == ESE_TRUST_MIDDLE)
                    snap.middlePeers++;
                else
                    snap.leafPeers++;
            } else {
                snap.leafPeers++;
            }
        }
    }

    // Chunk buffer
    snap.bufCount  = m_chunkBuffer.GetCount();
    snap.oldestSeq = m_chunkBuffer.GetOldestSeq();
    snap.newestSeq = m_chunkBuffer.GetNewestSeq();
    snap.bitmap    = m_chunkBuffer.GetBitmap();
    if (snap.bufCount > 0 && snap.newestSeq >= snap.oldestSeq) {
        int expected = (int)(snap.newestSeq - snap.oldestSeq + 1);
        snap.missingChunks = expected - snap.bufCount;
        if (snap.missingChunks < 0) snap.missingChunks = 0;
    } else {
        snap.missingChunks = 0;
    }

    // Mesh
    snap.totalRedistributed = m_meshManager.GetTotalBytesRedistributed();

    // Atomic counters — plain copy (all LONG fields, atomic reads on x86)
    snap.counters = m_counters;

    return snap;
}
