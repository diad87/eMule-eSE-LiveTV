//this file is part of eMule
// eSE — Live Stream Manager Implementation
#include "stdafx.h"
#include "LiveStreamManager.h"
#include "LiveCrypto.h"        // v7.6.0 — Ed25519 keypair helpers
#include "LiveDebugLog.h"
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
#include <deque>
#include <shlobj.h>     // Capa 3: SHGetFolderPath for %APPDATA%
#include "ClientList.h"
#include "eMuleAI/Address.h"  // v0.71 IPv6 Sprint 7 — CAddress in OnPeerListReceivedV6

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif


// v7.2.0 — Tombstone / watchdog constants. Forward of the helper below.
// TTL after which a tombstone is forgotten. 30 min: long enough to
// outlive Kad echo cascades, short enough that same-key re-broadcasts
// within the hour are rare (StartBroadcast generates fresh streamKeys).
static const DWORD ESE_TOMBSTONE_TTL_MS    = 30u * 60u * 1000u;
static const DWORD ESE_TOMBSTONE_PRUNE_MS  = 60u * 1000u;
// Watchdog threshold: 180 s. v7.2.0 had 90 s which was too aggressive
// for bandwidth-limited viewers (4G CGN saturated by a too-high
// variant) — chunks arrive in bursts with multi-tens-of-seconds gaps,
// the 90 s timer expired, viewer gossipped a (false) END for the
// stream, broadcaster cascaded the END to all OTHER viewers, mass
// disconnect. v7.2.2 raises to 180 s AND additionally gates on
// m_viewPeers.GetCount() == 0 so we only declare dead when we are
// genuinely alone, not just slow.
static const DWORD ESE_LIVE_WATCHDOG_MS    = 180u * 1000u;

static CString HexStreamKey(const uchar* streamKey)
{
    CString out;
    for (int i = 0; i < 16; ++i)
        out.AppendFormat(_T("%02x"), streamKey[i]);
    return out;
}

// v7.7.0 — pin the pubkey for a streamKey. Idempotent: if already pinned to
// the same pubkey, returns true; if pinned to a DIFFERENT pubkey, rejects.
// The caller MUST have already verified sha1(pubkey)[:16] == streamKey;
// this function does not re-check that (cheap to call, no cryptography).
bool CLiveStreamManager::PinStreamPubkey(const uchar streamKey[16], const uchar pubkey[32])
{
    CSingleLock lock(&m_lock, TRUE);
    CString hex = HexStreamKey(streamKey);
    PubkeyPin existing;
    if (m_streamPubkeyPin.Lookup(hex, existing)) {
        if (memcmp(existing.pubkey, pubkey, 32) == 0)
            return true;  // same key — idempotent
        LIVE_LOG("PIN", "REJECT pubkey switch for stream %s — keeping original",
            (LPCSTR)CStringA(hex));
        return false;
    }
    PubkeyPin pin;
    memcpy(pin.pubkey, pubkey, 32);
    pin.pinnedAt = GetTickCount();
    m_streamPubkeyPin[hex] = pin;
    LIVE_LOG("PIN", "PIN pubkey for stream %s", (LPCSTR)CStringA(hex));
    return true;
}

bool CLiveStreamManager::GetPinnedPubkey(const uchar streamKey[16], uchar outPubkey[32]) const
{
    CSingleLock lock(&m_lock, TRUE);
    CString hex = HexStreamKey(streamKey);
    PubkeyPin pin;
    if (!const_cast<CMap<CString, LPCTSTR, PubkeyPin, PubkeyPin&>&>(m_streamPubkeyPin).Lookup(hex, pin))
        return false;
    memcpy(outPubkey, pin.pubkey, 32);
    return true;
}


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
    , m_dwLastPingTick(0)         // V2-S03
    , m_nNextPingId(0)            // V2-S03
    , m_measuredUploadKbps(0)     // V2-S11
    , m_dwLastSecondaryPublish(0) // V2-S17
    , m_dwLastMultiParentTick(0)  // V2-S19
    , m_dwLastJoinSearchTick(0)   // DISC-S05
    , m_nJoinSearchRetries(0)     // DISC-S05
    , m_dwJoinTick(0)             // DISC-S12
    , m_bFirstChunkLogged(false)  // DISC-S12
    , m_bHasPendingGhostKey(false) // DISC-S04
    , m_bBootstrapAttempted(false) // Capa 3
    , m_dwBootstrapTick(0)         // Capa 3
    , m_dwLastTombstonePrune(0)    // v7.2.0
    , m_dwLastLiveActivity(0)      // v7.2.0
{
    memset(m_pendingGhostKey, 0, sizeof m_pendingGhostKey);
    memset(m_broadcasterPrivkey, 0, sizeof m_broadcasterPrivkey);
    m_meshManager.Init(this);
    MeasureUploadCapacity();      // V2-S11: initial classification at startup

    // DISC-S04: load any persisted ghost streamKey from preferences.
    // If found, Process() will publish a tombstone once Kad is up.
    CString hex = theApp.GetProfileString(_T("eMule"), _T("LiveLastStreamKey"), _T(""));
    if (hex.GetLength() == 32) {
        bool ok = true;
        for (int i = 0; i < 16 && ok; ++i) {
            auto h2n = [](TCHAR c) -> int {
                if (c >= _T('0') && c <= _T('9')) return c - _T('0');
                if (c >= _T('a') && c <= _T('f')) return c - _T('a') + 10;
                if (c >= _T('A') && c <= _T('F')) return c - _T('A') + 10;
                return -1;
            };
            int hi = h2n(hex[i*2]);
            int lo = h2n(hex[i*2 + 1]);
            if (hi < 0 || lo < 0) { ok = false; break; }
            m_pendingGhostKey[i] = (uchar)((hi << 4) | lo);
        }
        if (ok) {
            m_bHasPendingGhostKey = true;
            LIVE_LOG("MGR", "DISC-S04: ghost streamKey loaded (prev session crashed?), awaiting Kad to publish tombstone");
        }
    }
}

CLiveStreamManager::~CLiveStreamManager()
{
    StopBroadcast();
    LeaveStream();

    // V2-S03: free heap-allocated PendingPingMap entries to avoid leaks.
    POSITION pos = m_pendingPings.GetStartPosition();
    while (pos) {
        CUpDownClient* k = NULL;
        PendingPingMap* v = NULL;
        m_pendingPings.GetNextAssoc(pos, k, v);
        delete v;
    }
    m_pendingPings.RemoveAll();
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

    // v7.6.0 — generate a fresh Ed25519 keypair for this broadcast. The
    // streamKey is the first 16 bytes of sha1(pubkey), so any peer that knows
    // the streamKey can derive the expected pubkey hash and reject forgeries.
    // The old key-from-title-and-timestamp design (#1 in audit) was easily
    // predictable: attacker pre-computes streamKey for popular titles and
    // races the legitimate broadcaster to claim the Kad slot.
    if (!eSELive::GenerateBroadcasterKeypair(m_streamInfo.pubkey, m_broadcasterPrivkey)) {
        AddLogLine(true, _T("eSE Live: Failed to generate Ed25519 keypair"));
        return false;
    }
    eSELive::DeriveStreamKey(m_streamInfo.pubkey, m_streamInfo.streamKey);
    uint32 now = (uint32)time(NULL);

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

    char keyHex[33] = {0};
    for (int i = 0; i < 16; ++i)
        sprintf_s(keyHex + i*2, 3, "%02x", m_streamInfo.streamKey[i]);
    LIVE_LOG("MGR", "StartBroadcast key=%s title=\"%S\" %ukbps", keyHex, (LPCWSTR)title, bitrate);

    // DISC-S04: persist the active streamKey so a subsequent eMule startup
    // (after brutal kill / OS crash / power loss) can publish a tombstone
    // to evict the ghost from the DHT before resuming normal operation.
    theApp.WriteProfileString(_T("eMule"), _T("LiveLastStreamKey"), CString(keyHex));

    return true;
}

bool CLiveStreamManager::StartBroadcastWithSource(const CString& sourceType,
    const CString& title, const CString& category, const CString& language,
    uint16 bitrate, const CString& mediaFilePath, bool waitForPrebuffer)
{
    // Tier 2.2: unified broadcast launcher reusable from web + MFC.
    // Order: FFmpeg first (PRE-WARM), 2 s liveness probe, then Kad publish.

    if (m_bBroadcasting) {
        AddLogLine(true, _T("eSE Live: Broadcast already running"));
        return false;
    }
    if (m_rtmpIngest.IsRunning()) {
        AddLogLine(true, _T("eSE Live: FFmpeg ingest already running"));
        return false;
    }

    // Build the HLS output dir (same path RefreshViewerHlsPlaylist uses for
    // the broadcaster's own copy — that's how localhost can watch the stream).
    CString tempDir;
    TCHAR tmpPath[MAX_PATH];
    GetTempPath(MAX_PATH, tmpPath);
    tempDir.Format(_T("%seMule_RTMP"), tmpPath);

    // Callback feeds chunks into our buffer when FFmpeg writes a .ts file.
    auto chunkCb = [](const BYTE* data, DWORD size, UINT /*seq*/) {
        if (theApp.liveStreamManager)
            theApp.liveStreamManager->FeedSegment(data, size);
    };

    bool started = false;
    if (sourceType.CompareNoCase(_T("testpattern")) == 0) {
        started = m_rtmpIngest.StartTestPattern(bitrate, tempDir, chunkCb);
    } else if (sourceType.CompareNoCase(_T("screen")) == 0) {
        started = m_rtmpIngest.StartScreenCapture(bitrate, tempDir, chunkCb);
    } else if (sourceType.CompareNoCase(_T("file")) == 0) {
        if (mediaFilePath.IsEmpty()
            || GetFileAttributes(mediaFilePath) == INVALID_FILE_ATTRIBUTES) {
            AddLogLine(true, _T("eSE Live: Media file not found: %s"),
                (LPCTSTR)mediaFilePath);
            return false;
        }
        started = m_rtmpIngest.StartMediaFile(mediaFilePath, bitrate, tempDir, chunkCb);
    } else if (sourceType.CompareNoCase(_T("rtmp")) == 0) {
        started = m_rtmpIngest.Start(1935, bitrate, tempDir, chunkCb);
    } else {
        AddLogLine(true, _T("eSE Live: Unknown source type \"%s\""),
            (LPCTSTR)sourceType);
        return false;
    }

    if (!started) {
        AddLogLine(true, _T("eSE Live: FFmpeg failed to start (check ffmpeg.exe and source)"));
        LIVE_LOG("MGR", "StartBroadcastWithSource FAIL: FFmpeg refused source=%S",
            (LPCWSTR)sourceType);
        return false;
    }

    // V2-S07+ ordering: enable the P2P broadcast state BEFORE we wait for
    // the prebuffer to fill. Without this, the chunkCb -> FeedSegment path
    // sees m_bBroadcasting=false and drops every incoming chunk during the
    // wait window — we'd time out with an empty buffer and the very problem
    // we were trying to prevent (VLC starves at live edge).
    if (!StartBroadcast(title, category, language, bitrate)) {
        m_rtmpIngest.Stop();
        AddLogLine(true, _T("eSE Live: P2P StartBroadcast failed; rolling back FFmpeg"));
        return false;
    }
    LIVE_LOG("MGR", "FFmpeg launched source=%S bitrate=%u, broadcast state ARMED, waiting up to 14s for prebuffer",
        (LPCWSTR)sourceType, bitrate);

    // Web API path: the launch (FFmpeg + Kad publish) is marshaled to the
    // main thread, but the prebuffer wait below would block it — the caller
    // runs that wait itself on a webserver worker via GetBroadcastLivenessStatus().
    if (!waitForPrebuffer)
        return true;

    // Phase 3.4 ROB-FFmpeg + V2-S07+ prebuffer: wait until either FFmpeg
    // dies (early crash) OR the ring buffer has >= 3 chunks (~12 s of
    // content) so when VLC connects it always finds segments ready to play.
    DWORD t0 = GetTickCount();
    const DWORD kMaxWaitMs   = 14000;
    const int   kMinChunks   = 3;
    while (GetTickCount() - t0 < kMaxWaitMs && m_rtmpIngest.IsRunning()) {
        if ((int)m_chunkBuffer.GetCount() >= kMinChunks) break;
        Sleep(100);
    }
    if (!m_rtmpIngest.IsRunning()) {
        AddLogLine(true, _T("eSE Live: FFmpeg died within liveness window (codec/port/file error)"));
        LIVE_LOG("MGR", "FFmpeg DIED in liveness window — abort broadcast");
        StopBroadcast();
        return false;
    }
    LIVE_LOG("MGR", "Prebuffer ready: %d chunks in buffer after %u ms",
        (int)m_chunkBuffer.GetCount(), GetTickCount() - t0);

    AddLogLine(true, _T("eSE Live: Broadcast started (source=%s, bitrate=%u kbps, title=\"%s\")"),
        (LPCTSTR)sourceType, bitrate, (LPCTSTR)title);
    return true;
}

void CLiveStreamManager::StopBroadcastFull()
{
    if (m_rtmpIngest.IsRunning())
        m_rtmpIngest.Stop();
    StopBroadcast();
}

void CLiveStreamManager::GetBroadcastLivenessStatus(bool& outFFmpegRunning, int& outChunkCount)
{
    CSingleLock lock(&m_lock, TRUE);
    outFFmpegRunning = m_rtmpIngest.IsRunning();
    outChunkCount    = (int)m_chunkBuffer.GetCount();
}

void CLiveStreamManager::StopBroadcast()
{
    CSingleLock lock(&m_lock, TRUE);

    if (!m_bBroadcasting) return;
    LIVE_LOG("MGR", "StopBroadcast");

    // v7.2.0 — Tombstone our own streamKey locally first. That way if
    // the gossip below results in a duplicate END coming back at us via
    // the mesh, OnStreamEnded short-circuits at the tombstone-check and
    // we don't bounce it again.
    CString hexKey = HexStreamKey(m_streamInfo.streamKey);
    m_streamTombstones[hexKey] = GetTickCount() + ESE_TOMBSTONE_TTL_MS;

    // Notify all direct viewers + mesh peers: stream ended normally.
    // Before v7.2.0, only m_broadcastPeers was notified, so secondary
    // relays / super-seeders that we redistributed to never got the
    // memo and kept advertising the stream until their own watchdog
    // (which didn't exist) fired. Now we cast wide: broadcast peers
    // first, then any additional mesh peer we know.
    // v7.7.0 — sign the END so peers can verify origin. Message format:
    // streamKey (16) || reason (1). Compact; receiver reconstructs the same
    // bytes on the wire side before verifying.
    uchar endSig[64] = {0};
    bool haveSig = false;
    {
        uchar msg[17];
        memcpy(msg, m_streamInfo.streamKey, 16);
        msg[16] = (uchar)ESE_END_NORMAL;
        haveSig = eSELive::SignMessage(m_broadcasterPrivkey, m_streamInfo.pubkey,
                                       msg, sizeof msg, endSig);
    }

    auto sendEnd = [&](CUpDownClient* peer) {
        if (!peer) return;
        Packet* pkt = eSELive::CreateEndPacket(m_streamInfo.streamKey, ESE_END_NORMAL,
                                               haveSig ? endSig : NULL);
        if (pkt) {
            theStats.AddUpDataOverheadOther(pkt->size);
            peer->SendPacket(pkt);
        }
    };
    {
        POSITION pos = m_broadcastPeers.GetHeadPosition();
        while (pos) sendEnd(m_broadcastPeers.GetNext(pos));
    }
    // m_viewPeers is empty on a pure broadcaster, but defensive: if the
    // user was both viewing and broadcasting (relay scenario), notify
    // those too. m_peerCounters keys are also a set of "peers we know"
    // — covers any mesh participant not in either list. The send is
    // de-duped by SendPacket since each peer has its own send-queue.
    {
        POSITION pos = m_viewPeers.GetHeadPosition();
        while (pos) sendEnd(m_viewPeers.GetNext(pos));
    }
    {
        POSITION pos = m_peerCounters.GetStartPosition();
        CUpDownClient* peer = NULL;
        PeerCounters pc;
        while (pos) {
            m_peerCounters.GetNextAssoc(pos, peer, pc);
            sendEnd(peer);
        }
    }

    m_kadBridge.UnpublishStream(m_streamInfo.streamKey);

    m_bBroadcasting = false;
    m_chunkBuffer.Clear();
    m_broadcastPeers.RemoveAll();
    m_peerTrust.RemoveAll();
    m_peerBitmaps.RemoveAll();

    // v7.6.0 — wipe the Ed25519 private key from memory. The pubkey can
    // stick around in m_streamInfo until the next StartBroadcast() overwrites
    // it; only the secret half matters.
    memset(m_broadcasterPrivkey, 0, sizeof m_broadcasterPrivkey);

    // DISC-S04: clear the persisted streamKey marker — graceful shutdown
    // means there's no ghost to clean up on next start.
    theApp.WriteProfileString(_T("eMule"), _T("LiveLastStreamKey"), _T(""));

    AddLogLine(true, _T("eSE Live: Broadcast stopped"));
}

void CLiveStreamManager::FeedSegment(const BYTE* data, uint32 dataSize)
{
    CSingleLock lock(&m_lock, TRUE);

    if (!m_bBroadcasting) {
        LIVE_LOG("MGR", "FeedSegment DROP %u bytes — not broadcasting", dataSize);
        return;
    }

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

    // DISC-S05: reset re-search counters for the new JoinStream session.
    m_dwLastJoinSearchTick = GetTickCount();
    m_nJoinSearchRetries   = 0;

    // DISC-S12: mark this JoinStream's start time so OnChunkReceived can
    // compute time-to-first-chunk on the first inbound chunk.
    m_dwJoinTick = GetTickCount();
    m_bFirstChunkLogged = false;

    // v7.2.0 — arm the watchdog from JoinStream so the 90 s clock starts
    // counting from "joined" rather than from "first chunk". If the
    // discovery + dial never produces any activity at all, we still
    // catch it and declare the stream unfindable instead of leaving the
    // viewer hanging on "Buscando…" forever.
    m_dwLastLiveActivity = m_dwJoinTick;

    AddLogLine(true, _T("eSE Live: Joining stream \"%s\""), (LPCTSTR)title);

    char keyHex[33] = {0};
    for (int i = 0; i < 16; ++i) sprintf_s(keyHex + i*2, 3, "%02x", streamKey[i]);
    LIVE_LOG("MGR", "JoinStream key=%s title=\"%S\"", keyHex, (LPCWSTR)title);

    // Kick off Kad discovery. Three searches:
    //   - "eselive": global browse (every broadcaster publishes here too)
    //   - "<title>": targeted by title (works if titles match)
    //   - "livehash:<HASH>": targeted by streamKey itself — the anonymous link
    //     ed2k://|live|HASH||TITLE|/ has no IP, so this is the deterministic
    //     way to find a specific broadcast without relying on title matching.
    m_kadBridge.SearchStreams(_T("eselive"));
    if (!title.IsEmpty() && title.CompareNoCase(_T("eselive")) != 0)
        m_kadBridge.SearchStreams(title);

    CString hashSearch(_T("livehash:"));
    hashSearch.AppendFormat(_T("%s"), CString(keyHex));
    m_kadBridge.SearchStreams(hashSearch);

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
    LIVE_LOG("MGR", "LeaveStream");
}

bool CLiveStreamManager::TryConnectToStreamSource(const uchar* streamKey, uint32 ip, uint16 port, uint16 udpPort)
{
    CSingleLock lock(&m_lock, TRUE);

    if (!m_bViewing) return false;
    if (streamKey == NULL || memcmp(m_streamInfo.streamKey, streamKey, 16) != 0) return false;
    if (ip == 0 || port == 0) return false;
    if (ip == theApp.GetPublicIP()) return false;
    if (theApp.ipfilter->IsFiltered(ip)) return false;

    // Fix 2 (ALTA): Block loopback, LAN, multicast, broadcast via IsGoodIPPort.
    // V2-S07+: in headless mode (stress test on one host) we allow loopback
    // and LAN so all spawned viewers can reach the local broadcaster.
    if (!IsGoodIPPort(ip, port) && !theApp.m_bHeadless) {
        AddLogLine(false, _T("eSE Live: Rejected non-routable source %s:%u"),
            (LPCTSTR)ipstr(ip), port);
        return false;
    }

    POSITION pos = m_viewPeers.GetHeadPosition();
    while (pos) {
        CUpDownClient* existing = m_viewPeers.GetNext(pos);
        if (existing && existing->GetIP() == ip && existing->GetUserPort() == port) {
            // A.4: even if we already have this peer, refresh its Kad UDP port
            // in case it just became known (Live result vs earlier dial)
            if (udpPort != 0 && existing->GetKadPort() == 0)
                existing->SetKadPort(udpPort);
            return true;
        }
    }

    // DISC-S07: hard cap on simultaneous source connections. Without this,
    // a popular stream with dozens of secondary sources can grow m_viewPeers
    // unboundedly, consuming sockets and memory. 8 is plenty: V2-S19 only
    // targets 3, and mesh fallback (V2-S20) prefers low-RTT peers anyway.
    static const int kMaxViewPeers = 8;
    if ((int)m_viewPeers.GetCount() >= kMaxViewPeers) {
        LIVE_LOG("CAP", "DISC-S07: viewPeers full (%d/%d), skip dial %S:%u",
            (int)m_viewPeers.GetCount(), kMaxViewPeers,
            (LPCWSTR)ipstr(ip), port);
        return false;
    }

    CUpDownClient* client = theApp.clientlist->FindClientByIP(ip, port);
    if (client == NULL) {
        client = new CUpDownClient(NULL, port, ntohl(ip), 0, 0, false);
        client->SetIP(ip);
        theApp.clientlist->AddClient(client);
    }

    // A.4 Sprint 1: populate Kad UDP port so TryToConnect can fire
    // SendEseHolePunchReq when this source is LowID. Without this, the
    // hole-punch path in BaseClient.cpp:1475 never triggers for Live sources.
    if (udpPort != 0)
        client->SetKadPort(udpPort);

    Packet* pkt = eSELive::CreateSubscribePacket(m_streamInfo.streamKey, thePrefs.GetUserHash(), 0);
    bool subSent = false;
    if (pkt) {
        theStats.AddUpDataOverheadOther(pkt->size);
        client->SafeConnectAndSendPacket(pkt);
        InterlockedIncrement(&m_counters.subscribeSent);  // Phase 0: OBS-1 (atomic)
        subSent = true;
    }

    m_viewPeers.AddTail(client);
    m_meshManager.AddMeshPeer(client);
    // Fix 4: Use dedicated sourceDialAttempts instead of duplicate kadResultsAccepted
    InterlockedIncrement(&m_counters.sourceDialAttempts);

    AddLogLine(false, _T("eSE Live: Dialing discovered source %s:%u (kadUDP=%u)"),
        (LPCTSTR)ipstr(ip), port, udpPort);
    LIVE_LOG("DIAL", "src %S:%u kadUDP=%u  subscribePkt=%s",
        (LPCWSTR)ipstr(ip), port, udpPort, subSent ? "sent" : "FAILED-to-create");
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

    // Phase 3 HLS-2 / Phase 2 LAT-3: Buffer minimum gate.
    // Lowered from 3 → 2 segments. With 4 s/segment that's still 8 s of
    // buffered material before playback, enough to absorb a single chunk
    // gap, while cutting time-to-first-frame by 4 s. Combined with the
    // broadcaster's proactive 3-segment push (BOOT-5), the viewer sees
    // playback start within ~8-10 s of pressing JOIN.
    const uint32 ESE_HLS_MIN_BUFFER_SEGMENTS = 2;
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

    // v7.3.0 — Per-IP SUBSCRIBE rate limit. Cap: 30 SUBSCRIBEs/60 s from
    // the same IP. Prevents subscribe-flood DoS where a single IP
    // forces the broadcaster into 3-chunk PUSH cycles repeatedly. The
    // /24 rate limit in ListenSocket is too coarse — 256 distinct IPs
    // share one budget; with that the attacker just sweeps the /24.
    // This is per individual IP. Cap was 5 in v7.3.0 RC but legitimate
    // LowID viewers cycle through CClientList swaps every ~6 s (~10/min)
    // and were being blocked; 30 leaves headroom while still rejecting
    // genuine floods (real attackers fire 100s/sec).
    if (peer != NULL && peer->GetIP() != 0) {
        const DWORD SUB_RATE_WINDOW_MS = 60u * 1000u;
        const int   SUB_RATE_CAP       = 30;
        DWORD now = GetTickCount();
        SubRateState st;
        if (!m_subscribeRate.Lookup(peer->GetIP(), st)) {
            memset(&st, 0, sizeof(st));
        }
        // Count ticks within the window.
        int recentCount = 0;
        for (int i = 0; i < SUB_RATE_CAP; ++i) {
            if (st.ticks[i] != 0 && (now - st.ticks[i]) < SUB_RATE_WINDOW_MS)
                recentCount++;
        }
        if (recentCount >= SUB_RATE_CAP) {
            InterlockedIncrement(&m_counters.subscribesRateLimited);
            LIVE_LOG("CAP", "RATE-LIMIT SUBSCRIBE from %S:%u (%d in last %us)",
                (LPCWSTR)ipstr(peer->GetIP()), (unsigned)peer->GetUserPort(),
                recentCount, SUB_RATE_WINDOW_MS / 1000);
            Packet* deny = eSELive::CreateDenyPacket(m_streamInfo.streamKey, ESE_DENY_FULL);
            if (deny) {
                theStats.AddUpDataOverheadOther(deny->size);
                peer->SendPacket(deny);
            }
            return;
        }
        // Record this SUBSCRIBE tick.
        st.ticks[st.nextSlot] = now;
        st.nextSlot = (st.nextSlot + 1) % SUB_RATE_CAP;
        st.lastSeen = now;
        m_subscribeRate[peer->GetIP()] = st;
    }

    // V2-S13/S16: enforce concurrent-upload cap (tier-derived + broadcaster
    // hard cap). Reply with a peer list of alternative sources so the
    // requester can fan out instead of bouncing between us and the broadcaster.
    int cap = EffectiveMaxConcurrentUploads();
    if (cap > 0 && (int)m_broadcastPeers.GetCount() >= cap
        && m_broadcastPeers.Find(peer) == NULL)
    {
        LIVE_LOG("CAP", "REJECT %S:%u — cap=%d already reached (viewers=%u)",
            peer ? (LPCWSTR)ipstr(peer->GetIP()) : L"?",
            peer ? (unsigned)peer->GetUserPort() : 0,
            cap, (unsigned)m_broadcastPeers.GetCount());

        // Send up to ESE_LIVE_MAX_PEERS alternative sources so the rejected
        // viewer does not just retry against us. We pull from both lists so
        // mesh peers get advertised too.
        CArray<DWORD>  altIPs;
        CArray<uint16> altPorts;
        POSITION posA = m_broadcastPeers.GetHeadPosition();
        while (posA && altIPs.GetCount() < ESE_LIVE_MAX_PEERS) {
            CUpDownClient* alt = m_broadcastPeers.GetNext(posA);
            if (alt && alt != peer && alt->GetIP() != 0) {
                altIPs.Add(alt->GetIP());
                altPorts.Add(alt->GetUserPort());
            }
        }
        posA = m_viewPeers.GetHeadPosition();
        while (posA && altIPs.GetCount() < ESE_LIVE_MAX_PEERS) {
            CUpDownClient* alt = m_viewPeers.GetNext(posA);
            if (alt && alt != peer && alt->GetIP() != 0) {
                altIPs.Add(alt->GetIP());
                altPorts.Add(alt->GetUserPort());
            }
        }
        if (altIPs.GetCount() > 0) {
            Packet* redirect = eSELive::CreatePeerListPacket(
                m_streamInfo.streamKey,
                altIPs.GetData(), altPorts.GetData(),
                (uint16)altIPs.GetCount());
            if (redirect) {
                theStats.AddUpDataOverheadOther(redirect->size);
                peer->SendPacket(redirect);
            }
        }
        Packet* deny = eSELive::CreateDenyPacket(m_streamInfo.streamKey, ESE_DENY_FULL);
        if (deny) {
            theStats.AddUpDataOverheadOther(deny->size);
            peer->SendPacket(deny);
        }
        return;
    }

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
    LIVE_LOG("PEER", "JOIN viewer=%S:%u upload=%uKB/s  total_viewers=%u",
        peer ? (LPCWSTR)ipstr(peer->GetIP()) : L"?",
        peer ? (unsigned)peer->GetUserPort() : 0,
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

    // Phase 1 BOOT-5 (refined): proactive push of the most recent segments.
    // SAFETY: we BUILD the packets under m_lock (so the chunk pointers stay
    // valid against concurrent FeedSegment/Clear), then RELEASE m_lock and
    // send them outside. SendPacket() with bVerifyConnection=true checks the
    // socket is still alive before queuing — handles the race where SUBSCRIBE
    // arrives but the viewer's TCP closes before our push goes out.
    //
    // We only push when broadcasting; when relaying as a mesh peer, the
    // requester will fetch what it needs via REQUEST (avoids amplifying
    // unsolicited traffic to mesh hops).
    //
    // v7.2.2 — Skip the initial push if we already pushed to this
    // (IP, port) in the last 10 seconds. LowID viewers cycle SUBSCRIBE
    // every ~6 s through CClientList::AttachToAlreadyKnown, and a
    // 3-chunk re-push of ~4.5 MB the viewer already has saturates
    // their TCP recv buffer + delays NEW chunks → microcuts. The
    // cooldown is keyed by endpoint (not by CUpDownClient pointer)
    // because the pointer changes on every swap.
    const DWORD ESE_INITIAL_PUSH_COOLDOWN_MS = 10000;
    uint64 pushKey = ((uint64)(peer ? peer->GetIP() : 0) << 16)
                   | (uint64)(peer ? peer->GetUserPort() : 0);
    bool skipInitialPush = false;
    if (pushKey != 0) {
        DWORD lastTick = 0;
        if (m_recentInitialPushes.Lookup(pushKey, lastTick)
            && (GetTickCount() - lastTick) < ESE_INITIAL_PUSH_COOLDOWN_MS)
        {
            skipInitialPush = true;
            InterlockedIncrement(&m_counters.skippedInitialPushes);  // v7.3.0
            LIVE_LOG("PUSH", "SKIP initial push to %S:%u (pushed %u ms ago, cooldown)",
                (LPCWSTR)ipstr(peer->GetIP()), (unsigned)peer->GetUserPort(),
                GetTickCount() - lastTick);
        }
    }

    int pushed = 0;
    uint32 startSeq = 0, newest = 0;
    if (!skipInitialPush && m_bBroadcasting && m_chunkBuffer.GetCount() > 0) {
        const uint32 pushCount = 3;
        newest = m_chunkBuffer.GetNewestSeq();
        uint32 oldest = m_chunkBuffer.GetOldestSeq();
        startSeq = (newest >= pushCount - 1) ? (newest - (pushCount - 1)) : oldest;
        if (startSeq < oldest) startSeq = oldest;

        // v7.5.0 — WithSegment serializes the read against AddSegment; previous
        // code held the LiveStreamManager m_lock but NOT the chunk buffer's
        // own m_lock, so AddSegment from the broadcaster thread could free
        // the slot between GetSegment() and CreateChunkPacket()'s memcpy.
        // CreateChunkPacket copies the bytes, so once it returns the Packet is
        // self-contained and safe to use after the buffer's lock releases.
        CArray<Packet*> pushBatch;
        uint64 totalBytes = 0;
        for (uint32 seq = startSeq; seq <= newest; ++seq) {
            Packet* chunkPkt = NULL;
            uint32 chunkSize = 0;
            m_chunkBuffer.WithSegment(seq, [&](const LiveChunk& chunk) {
                // v7.7.0 — if we're broadcasting our own stream, emit signed V2.
                // Otherwise (relay of someone else's chunk) emit legacy V1.
                if (m_bBroadcasting &&
                    memcmp(chunk.streamKey, m_streamInfo.streamKey, 16) == 0) {
                    chunkPkt = eSELive::CreateChunkPacketV2(&chunk,
                        m_broadcasterPrivkey, m_streamInfo.pubkey);
                }
                if (!chunkPkt)
                    chunkPkt = eSELive::CreateChunkPacket(&chunk);
                chunkSize = chunk.dataSize;
            });
            if (!chunkPkt) continue;
            pushBatch.Add(chunkPkt);
            totalBytes += chunkSize;
        }

        // Update trust + mesh counters under the lock (they read m_peerTrust).
        trust.requestsServed += (uint32)pushBatch.GetCount();
        for (INT_PTR i = 0; i < pushBatch.GetCount(); ++i) {
            m_meshManager.IncrementChunksServed();
        }
        if (pushBatch.GetCount() > 0)
            m_meshManager.TrackUpload(peer, (uint32)totalBytes);

        pushed = (int)pushBatch.GetCount();

        // RELEASE THE MANAGER LOCK before doing socket I/O. This prevents
        // FeedSegment (called from the FFmpeg watcher thread) from blocking
        // on m_lock while we drain ~4.5 MB of chunk data into the socket.
        if (pushed > 0) {
            lock.Unlock();
            for (INT_PTR i = 0; i < pushBatch.GetCount(); ++i) {
                Packet* pkt = pushBatch[i];
                theStats.AddUpDataOverheadOther(pkt->size);
                // bVerifyConnection=true → SendPacket deletes the packet and
                // returns false if the socket died between SUBSCRIBE and now.
                peer->SendPacket(pkt, true);
            }
            // Note: do NOT re-lock — function exit, CSingleLock dtor is a no-op
            // when already unlocked. There is nothing else to do after the push.
        }
    }
    if (pushed > 0) {
        AddLogLine(false,
            _T("eSE Live: Pushed %d initial seg(s) [%u..%u] to new viewer"),
            pushed, startSeq, newest);
        LIVE_LOG("PUSH", "PUSH %d seg(s) [%u..%u] to viewer %S:%u (initial)",
            pushed, startSeq, newest,
            peer ? (LPCWSTR)ipstr(peer->GetIP()) : L"?",
            peer ? (unsigned)peer->GetUserPort() : 0);
        // v7.2.2 — record this push so a rapid re-SUBSCRIBE within
        // 10 s gets the skip-path above. Map grows bounded by unique
        // endpoints we've served, pruned in Process() once a minute.
        if (pushKey != 0)
            m_recentInitialPushes[pushKey] = GetTickCount();
    }
}

// Sprint 4 F.4 — DDoS protection: rate-limit OP_LIVE_REQUEST per /24 subnet.
// Stops a single IP block from saturating the broadcaster with chunk requests.
// Limit: 50 requests / 5 s window per /24 (= 10 req/s sustained per subnet).
// Static so all peer-request paths share the same accounting.
namespace {
    struct SubnetReqRate {
        uint32 subnet24;       // ip & 0x00FFFFFF (network order's lower 3 bytes)
        uint16 count;
        DWORD  windowStart;
    };
    static SubnetReqRate s_subnetRates[64] = {};  // small open-addressed cache
    static CRITICAL_SECTION s_subnetRatesLock;
    static bool s_subnetRatesInit = false;
    bool IsRateLimited(uint32 ipNet) {
        if (!s_subnetRatesInit) {
            InitializeCriticalSection(&s_subnetRatesLock);
            s_subnetRatesInit = true;
        }
        const DWORD WINDOW_MS = 5000;
        const uint16 MAX_REQS = 50;
        uint32 subnet = ipNet & 0x00FFFFFF;  // /24 in network byte order's lower octets
        DWORD now = ::GetTickCount();
        EnterCriticalSection(&s_subnetRatesLock);
        // Find slot: hash + linear probe (cache is tiny, so this is O(1) amortized)
        int slot = -1, freeSlot = -1;
        uint32 h = (subnet * 0x9E3779B1u) % _countof(s_subnetRates);
        for (uint32 i = 0; i < _countof(s_subnetRates); ++i) {
            uint32 idx = (h + i) % _countof(s_subnetRates);
            if (s_subnetRates[idx].subnet24 == subnet && s_subnetRates[idx].windowStart != 0) {
                slot = (int)idx; break;
            }
            if (s_subnetRates[idx].windowStart == 0 && freeSlot == -1) freeSlot = (int)idx;
            // Reuse expired slots
            if (s_subnetRates[idx].windowStart != 0 && now - s_subnetRates[idx].windowStart > WINDOW_MS * 4) {
                if (freeSlot == -1) freeSlot = (int)idx;
            }
        }
        bool limited = false;
        if (slot >= 0) {
            if (now - s_subnetRates[slot].windowStart > WINDOW_MS) {
                s_subnetRates[slot].windowStart = now;
                s_subnetRates[slot].count = 1;
            } else {
                s_subnetRates[slot].count++;
                if (s_subnetRates[slot].count > MAX_REQS) limited = true;
            }
        } else if (freeSlot >= 0) {
            s_subnetRates[freeSlot].subnet24 = subnet;
            s_subnetRates[freeSlot].windowStart = now;
            s_subnetRates[freeSlot].count = 1;
        }
        LeaveCriticalSection(&s_subnetRatesLock);
        return limited;
    }
}

void CLiveStreamManager::OnPeerRequest(CUpDownClient* peer, const uchar* streamKey,
    uint32 seqNum)
{
    CSingleLock lock(&m_lock, TRUE);

    if (memcmp(m_streamInfo.streamKey, streamKey, 16) != 0) return;

    // Sprint 4 F.4 — DDoS rate-limit by /24 subnet.
    if (peer && IsRateLimited(peer->GetIP())) {
        static DWORD s_lastDdosLog = 0;
        if (::GetTickCount() - s_lastDdosLog > 30000) {
            s_lastDdosLog = ::GetTickCount();
            AddLogLine(false, _T("eSE Live: rate-limit hit for subnet of %s (DDoS protection)"),
                (LPCTSTR)ipstr(peer->GetIP()));
        }
        return;
    }

    // v7.5.0 — snapshot what we need from the chunk under the buffer's lock.
    // The legacy GetSegment() returned a raw pointer that could be freed
    // before we finished using it (UAF #7).
    Packet*  chunkPkt   = NULL;
    uint32   chunkSize  = 0;
    bool     chunkFound = m_chunkBuffer.WithSegment(seqNum, [&](const LiveChunk& c) {
        // v7.7.0 — sign if we own this stream; else V1 for relays.
        if (m_bBroadcasting &&
            memcmp(c.streamKey, m_streamInfo.streamKey, 16) == 0) {
            chunkPkt = eSELive::CreateChunkPacketV2(&c,
                m_broadcasterPrivkey, m_streamInfo.pubkey);
        }
        if (!chunkPkt)
            chunkPkt = eSELive::CreateChunkPacket(&c);
        chunkSize = c.dataSize;
    });
    if (!chunkFound) {
        LIVE_LOG("REQ", "MISS seq=%u from %S:%u — not in buffer",
            seqNum,
            peer ? (LPCWSTR)ipstr(peer->GetIP()) : L"?",
            peer ? (unsigned)peer->GetUserPort() : 0);
        return;
    }

    // V2-S14/S15: ratio gradient throttle with bootstrap grace.
    //
    // Policy (computed against the 60-s upload/download ratio of the requester):
    //   - First 5 viewers   -> no throttle (bootstrap grace, S15)
    //   - 6..20 viewers     -> linear ramp of required ratio 0.0 -> 0.7
    //   - >20 viewers       -> require ratio >= 0.7 for full speed
    // For each request we then pick a drop probability:
    //   ratio < required - 0.3 -> drop 80% (strong throttle)
    //   ratio < required       -> drop 20% (medium throttle)
    //   ratio >= required      -> serve
    PeerCounters& pcReq = m_peerCounters[peer];
    pcReq.MaybeResetWindow(GetTickCount());
    float ratio = pcReq.Ratio60s();

    int total_viewers = (int)m_broadcastPeers.GetCount();
    float required;
    if (total_viewers <= 5)       required = 0.0f;
    else if (total_viewers <= 20) required = (float)(total_viewers - 5) / 15.0f * 0.7f;
    else                          required = 0.7f;

    if (required > 0.0f) {
        // Per-peer rotating counter so drops are spread, not bursty.
        // Stored as chunks_served % 5 to avoid extra state.
        int slot = pcReq.chunks_served % 5;
        if (ratio < required - 0.3f) {
            // Strong: drop 4 of every 5 -> serve only when slot == 0
            if (slot != 0) {
                LIVE_LOG("RATIO", "DROP-strong seq=%u peer=%S:%u ratio=%.2f need=%.2f",
                    seqNum,
                    (LPCWSTR)ipstr(peer->GetIP()), peer->GetUserPort(),
                    ratio, required);
                return;
            }
        } else if (ratio < required) {
            // Medium: drop 1 of every 5 -> skip when slot == 0
            if (slot == 0) {
                LIVE_LOG("RATIO", "DROP-medium seq=%u peer=%S:%u ratio=%.2f need=%.2f",
                    seqNum,
                    (LPCWSTR)ipstr(peer->GetIP()), peer->GetUserPort(),
                    ratio, required);
                return;
            }
        }
    }

    // Update trust tracking
    PeerTrust& trust = GetOrCreateTrust(peer);
    trust.requestsReceived++;
    trust.requestsServed++;

    // Send the chunk data to the peer. v7.5.0: chunkPkt was built inside the
    // WithSegment lambda above using a now-released copy of the bytes, so it's
    // safe to use without any buffer lock; chunkSize is a captured uint32.
    if (chunkPkt) {
        theStats.AddUpDataOverheadOther(chunkPkt->size);
        peer->SendPacket(chunkPkt);
        m_meshManager.TrackUpload(peer, chunkSize);
        // Fix 5: Actually count active uploads so /api/live/debug isn't always 0
        m_meshManager.IncrementChunksServed();

        // V2-S01/S02: per-peer counters (under m_lock — already held).
        DWORD nowTick = GetTickCount();
        PeerCounters& pc = m_peerCounters[peer];
        pc.MaybeResetWindow(nowTick);
        pc.bytes_out_total      += chunkSize;
        pc.bytes_out_window_60s += chunkSize;
        pc.chunks_served++;
        pc.last_chunk_sent_ms = nowTick;

        LIVE_LOG("REQ", "SERVE seq=%u (%u KB) -> %S:%u",
            seqNum, chunkSize / 1024,
            peer ? (LPCWSTR)ipstr(peer->GetIP()) : L"?",
            peer ? (unsigned)peer->GetUserPort() : 0);
    }
}

void CLiveStreamManager::OnChunkReceived(CUpDownClient* peer, const uchar* streamKey,
    uint32 seqNum, uint32 timestamp, const BYTE* data, uint32 dataSize)
{
    CSingleLock lock(&m_lock, TRUE);

    if (!m_bViewing) {
        LIVE_LOG("RECV", "DROP chunk seq=%u — not viewing", seqNum);
        return;
    }
    if (memcmp(m_streamInfo.streamKey, streamKey, 16) != 0) {
        LIVE_LOG("RECV", "DROP chunk seq=%u — wrong key", seqNum);
        return;
    }

    LIVE_LOG("RECV", "chunk seq=%u size=%u from peer", seqNum, dataSize);

    // Store in our buffer
    // Phase 0: Counter instrumentation (OBS-1)
    DWORD nowTick = GetTickCount();
    InterlockedIncrement(&m_counters.chunksReceived);  // Phase 0: OBS-1 (atomic)
    InterlockedExchange((LONG*)&m_counters.lastChunkReceivedAt, (LONG)nowTick);
    // v7.2.0 — feed the crash-watchdog. Any chunk arrival proves the
    // broadcast chain is still pumping; reset the "stream alive" clock.
    m_dwLastLiveActivity = nowTick;

    // DISC-S12: record time-to-first-chunk on the first chunk of this
    // JoinStream session. Helps measure how long discovery + dial took
    // end-to-end (target: p50 < 5 s, p95 < 15 s).
    if (!m_bFirstChunkLogged && m_dwJoinTick != 0) {
        DWORD elapsed = nowTick - m_dwJoinTick;
        InterlockedIncrement(&m_counters.joinToFirstChunkSamples);
        InterlockedExchangeAdd(&m_counters.joinToFirstChunkSumMs, (LONG)elapsed);
        m_bFirstChunkLogged = true;
        LIVE_LOG("MGR", "DISC-S12: first chunk arrived %u ms after JoinStream", elapsed);

        // Capa 3: this broadcaster works — remember it for next boot. We use
        // the connecting peer's IP+port (peer->GetIP/GetUserPort) because
        // the local m_streamInfo doesn't carry the broadcaster endpoint.
        if (peer && peer->GetIP() != 0 && peer->GetUserPort() != 0) {
            RememberStreamForBootstrap(m_streamInfo.streamKey,
                peer->GetIP(), peer->GetUserPort(),
                m_streamInfo.title);
        }
    }
    m_chunkBuffer.AddSegment(streamKey, seqNum, timestamp,
        data, dataSize, m_streamInfo.bitrate);
    WriteViewerHlsSegment(seqNum, data, dataSize);

    // Update trust for the sending peer
    PeerTrust& trust = GetOrCreateTrust(peer);
    trust.bytesServed += dataSize;  // Peer served us these bytes

    // V2-S01/S02: per-peer counters (we already hold m_lock).
    PeerCounters& pc = m_peerCounters[peer];
    pc.MaybeResetWindow(nowTick);
    pc.bytes_in_total      += dataSize;
    pc.bytes_in_window_60s += dataSize;
    pc.chunks_received++;
    pc.last_chunk_recv_ms = nowTick;

    // V2-S05: chunk-arrival latency. The chunk timestamp is wall-clock seconds
    // (time(NULL)) set by the broadcaster when it generated the segment, so
    // delta = ((wall now) - timestamp) seconds. Clamp negatives (clock skew).
    if (timestamp > 0) {
        time_t wallNow = time(NULL);
        if ((time_t)timestamp <= wallNow) {
            DWORD latencyMs = (DWORD)((wallNow - (time_t)timestamp) * 1000);
            m_chunkArrivalLatency.Record(latencyMs);
        }
    }

    // V2-S21: push the chunk to any subscribed children without waiting for
    // them to REQUEST. This cuts one round trip per hop in tree topologies.
    // Subject to the same EffectiveMaxConcurrentUploads cap (no fan-out
    // amplification beyond what S13/S16 already authorize).
    //
    // v7.5.0 — was reading `stored->dataSize` and passing `stored` to
    // CreateChunkPacket across N iterations while AddSegment from the encoder
    // thread could free that slot. Pre-build the packets and snapshot the size
    // inside one WithSegment lambda, then send outside the buffer lock.
    if (!m_broadcastPeers.IsEmpty()) {
        uint32 storedSize = 0;
        bool   storedFound = false;
        // We can't build N packets inside the lambda without knowing N — we
        // don't know how many children will receive yet. So copy the bytes
        // into a local buffer under the lock and rebuild a packet per child
        // afterwards. CreateChunkPacket takes a LiveChunk* with an owned data
        // pointer; we pass a stack-local LiveChunk view of our copy.
        std::vector<BYTE> bodyCopy;
        uchar localStreamKey[16] = {0};
        uint32 localTs = 0;
        uint16 localBitrate = 0;
        m_chunkBuffer.WithSegment(seqNum, [&](const LiveChunk& c) {
            storedFound = true;
            storedSize  = c.dataSize;
            bodyCopy.assign(c.data, c.data + c.dataSize);
            memcpy(localStreamKey, c.streamKey, 16);
            localTs      = c.timestamp;
            localBitrate = c.bitrate;
        });
        if (storedFound) {
            LiveChunk localView;
            memcpy(localView.streamKey, localStreamKey, 16);
            localView.sequenceNumber = seqNum;
            localView.timestamp      = localTs;
            localView.dataSize       = storedSize;
            localView.bitrate        = localBitrate;
            localView.data           = bodyCopy.data();   // points into bodyCopy, valid for this scope

            int relayMax = EffectiveMaxConcurrentUploads();
            int relayed = 0;
            POSITION cpos = m_broadcastPeers.GetHeadPosition();
            while (cpos && (relayMax <= 0 || relayed < relayMax)) {
                CUpDownClient* child = m_broadcastPeers.GetNext(cpos);
                if (!child) continue;
                if (child == peer) continue;  // do not bounce back to source
                // v7.7.0 — sign if we own this stream; else V1 for relays.
                Packet* pkt = NULL;
                if (m_bBroadcasting &&
                    memcmp(localView.streamKey, m_streamInfo.streamKey, 16) == 0) {
                    pkt = eSELive::CreateChunkPacketV2(&localView,
                        m_broadcasterPrivkey, m_streamInfo.pubkey);
                }
                if (!pkt)
                    pkt = eSELive::CreateChunkPacket(&localView);
                if (!pkt) continue;
                theStats.AddUpDataOverheadOther(pkt->size);
                child->SendPacket(pkt, true);  // bVerifyConnection: skip dead sockets
                m_meshManager.TrackUpload(child, storedSize);
                m_meshManager.IncrementChunksServed();

                // Update per-child counters as if they had requested.
                PeerCounters& ccp = m_peerCounters[child];
                ccp.MaybeResetWindow(nowTick);
                ccp.bytes_out_total      += storedSize;
                ccp.bytes_out_window_60s += storedSize;
                ccp.chunks_served++;
                ccp.last_chunk_sent_ms = nowTick;
                relayed++;
            }
            localView.data = NULL;  // disown so LiveChunk dtor doesn't free
            if (relayed > 0)
                LIVE_LOG("RELAY", "PUSH seq=%u to %d child(ren)", seqNum, relayed);
        }
    }

    // Notify mesh manager that this request is fulfilled
    m_meshManager.FulfillRequest(seqNum);
}

void CLiveStreamManager::OnPeerBitmap(CUpDownClient* peer, const uchar* streamKey,
    uint32 oldestSeq, uint16 bitmap)
{
    CSingleLock lock(&m_lock, TRUE);

    if (memcmp(m_streamInfo.streamKey, streamKey, 16) != 0) return;
    if (peer == NULL) return;

    // v7.2.1 — Self-heal peer lists. v7.1.8 added ~CUpDownClient ->
    // OnPeerDisconnected to scrub dangling pointers, but that ALSO fires
    // when CClientList::AttachToAlreadyKnown merges two CUpDownClient
    // objects for the same peer (e.g. on second OP_HELLO). The new
    // instance keeps the TCP socket alive but isn't in m_broadcastPeers
    // because no OP_LIVE_JOIN is resent — only OP_LIVE_BITMAP heartbeats
    // arrive. Effect before this fix: 4 active TCP connections, internal
    // viewer count stuck at 0. Heartbeats fire every 1 s, so we just
    // re-add the peer here whenever it's the matching key + matching role.
    if (m_bBroadcasting && m_broadcastPeers.Find(peer) == NULL) {
        m_broadcastPeers.AddTail(peer);
        m_streamInfo.viewerCount = (uint32)m_broadcastPeers.GetCount();
        LIVE_LOG("PEER", "REJOIN viewer=%S:%u (heartbeat after ClientList swap) total=%u",
            (LPCWSTR)ipstr(peer->GetIP()), (unsigned)peer->GetUserPort(),
            m_streamInfo.viewerCount);
    }
    if (m_bViewing && m_viewPeers.Find(peer) == NULL) {
        m_viewPeers.AddTail(peer);
        LIVE_LOG("PEER", "REJOIN source=%S:%u (heartbeat after ClientList swap) total=%d",
            (LPCWSTR)ipstr(peer->GetIP()), (unsigned)peer->GetUserPort(),
            (int)m_viewPeers.GetCount());
    }

    // Phase 1 BOOT-1: persist BOTH bitmap and oldestSeq.
    // The bitmap bit positions are anchored at the peer's oldestSeq, not ours.
    PeerBitmapInfo info;
    info.bitmap     = bitmap;
    info.oldestSeq  = oldestSeq;
    info.lastUpdate = GetTickCount();
    m_peerBitmaps[peer] = info;
    // v7.2.0 — bitmap heartbeats also count as proof-of-life for the
    // watchdog: the upstream is still alive even if it has nothing new
    // to send yet. Without this, slow streams (e.g. test pattern at
    // very low bitrate) could spuriously trip the 90 s timeout.
    if (m_bViewing) m_dwLastLiveActivity = info.lastUpdate;

    // Phase 1 BOOT-2: if we are a viewer with an empty buffer, this is our
    // bootstrap signal. The viewer's chunkBuffer starts with oldest=0, but the
    // broadcaster is somewhere in the middle of the stream (e.g. seq 47).
    // We can't request seq 0..3 because the broadcaster doesn't have them
    // anymore. Instead, jump ahead so RequestMissingSegments targets the
    // live edge as advertised by this peer.
    if (m_bViewing && m_chunkBuffer.GetCount() == 0 && bitmap != 0) {
        AddLogLine(false,
            _T("eSE Live: Bootstrap from peer bitmap (oldestSeq=%u, bitmap=0x%04x)"),
            oldestSeq, bitmap);
    }
    LIVE_LOG("BMP", "from %S:%u  oldest=%u bitmap=0x%04x",
        peer ? (LPCWSTR)ipstr(peer->GetIP()) : L"?",
        peer ? (unsigned)peer->GetUserPort() : 0,
        oldestSeq, bitmap);
}

void CLiveStreamManager::OnPeerListReceived(CUpDownClient* /*peer*/,
    const uchar* streamKey,
    const CArray<DWORD>& ips, const CArray<uint16>& ports)
{
    CSingleLock lock(&m_lock, TRUE);

    if (!m_bViewing) return;
    if (memcmp(m_streamInfo.streamKey, streamKey, 16) != 0) return;
    LIVE_LOG("MESH", "Received peer-list (%d entries)", (int)ips.GetCount());

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

// v0.71 IPv6 Sprint 7 follow-up — OP_LIVE_PEER_LIST_V2 receiver.
// Splits CAddress entries: IPv4 ones go through the legacy uint32 path so
// the dial/IPFilter/clientlist logic stays single-sourced; IPv6 ones are
// logged and counted but NOT dialed yet. CUpDownClient still keys peers by
// network-order uint32 (CClientList::FindClientByIP), so wiring a real
// v6 dial path requires Sprint 4 Kad-v6 to land first (routing zone + a
// v6-aware connection helper). Until then, advertising v6 peers in v2
// lists is harmless because the receiver simply ignores them — that's
// also the back-compat story for upstream 0.70b which never sees these
// entries because it never asks for OP_LIVE_PEER_LIST_V2 (it has neither
// the opcode nor the CAP_FORK_IPV6_WIRE handshake).
void CLiveStreamManager::OnPeerListReceivedV6(CUpDownClient* peer,
    const uchar* streamKey,
    const CArray<CAddress>& addrs, const CArray<uint16>& ports)
{
    // Fast path: separate v4 and v6, then delegate the v4 set to the
    // uint32 overload (which already takes m_lock). We don't take m_lock
    // around the partition because addrs/ports are local CArrays owned
    // by the caller on its stack.
    CArray<DWORD> v4ips;
    CArray<uint16> v4ports;
    int v6Count = 0;
    for (INT_PTR i = 0; i < addrs.GetCount() && i < ports.GetCount(); ++i) {
        const CAddress& a = addrs[i];
        switch (a.GetType()) {
            case CAddress::IPv4: {
                v4ips.Add(a.ToUInt32(/*bReverse=*/false));  // network-order DWORD
                v4ports.Add(ports[i]);
                break;
            }
            case CAddress::IPv6: {
                ++v6Count;
                LIVE_LOG("MESHv6",
                    "v6 peer-list entry from %S:%u — %S:%u (dial pending Sprint-4 Kad-v6)",
                    peer ? (LPCWSTR)ipstr(peer->GetIP()) : L"?",
                    peer ? (unsigned)peer->GetUserPort() : 0,
                    (LPCWSTR)a.ToStringC(),
                    (unsigned)ports[i]);
                break;
            }
            case CAddress::None:
            default:
                // Malformed/empty entry — silently skip; the wire reader
                // already rejected truly bad frames, this is just defense
                // in depth against future readers.
                break;
        }
    }
    if (v6Count > 0) {
        AddDebugLogLine(false,
            _T("eSE Live: OP_LIVE_PEER_LIST_V2 carried %d v6 entries (dial deferred until Sprint-4 Kad-v6 lands)"),
            v6Count);
    }
    if (v4ips.GetCount() > 0)
        OnPeerListReceived(peer, streamKey, v4ips, v4ports);
}

void CLiveStreamManager::OnPeerDisconnected(CUpDownClient* peer)
{
    CSingleLock lock(&m_lock, TRUE);

    // Remove from broadcast peers
    POSITION pos = m_broadcastPeers.Find(peer);
    if (pos) {
        m_broadcastPeers.RemoveAt(pos);
        m_streamInfo.viewerCount = (uint32)m_broadcastPeers.GetCount();
        LIVE_LOG("PEER", "DISCONNECT viewer=%S:%u  remaining=%u",
            peer ? (LPCWSTR)ipstr(peer->GetIP()) : L"?",
            peer ? (unsigned)peer->GetUserPort() : 0,
            m_streamInfo.viewerCount);
    }

    // Remove from view peers
    pos = m_viewPeers.Find(peer);
    if (pos) {
        m_viewPeers.RemoveAt(pos);
        LIVE_LOG("PEER", "DISCONNECT source=%S:%u  remaining_sources=%d",
            peer ? (LPCWSTR)ipstr(peer->GetIP()) : L"?",
            peer ? (unsigned)peer->GetUserPort() : 0,
            (int)m_viewPeers.GetCount());
        // Request more peers if below minimum
        if (m_bViewing && m_viewPeers.GetCount() < ESE_LIVE_MIN_PEERS) {
            // TODO: Request more peers from broadcaster
        }
    }

    // Remove trust data
    m_peerTrust.RemoveKey(peer);
    m_peerBitmaps.RemoveKey(peer);

    // V2-S01/S03: drop per-peer counters and pending pings to prevent
    // dangling-pointer keys (peer is being freed by ClientList).
    m_peerCounters.RemoveKey(peer);
    PendingPingMap* pings = NULL;
    if (m_pendingPings.Lookup(peer, pings) && pings) {
        delete pings;
        m_pendingPings.RemoveKey(peer);
    }

    InterlockedIncrement(&m_counters.peerDisconnects);  // Phase 0: OBS-1 (atomic)
    // Remove from mesh manager
    m_meshManager.RemoveMeshPeer(peer);
}


// ============================================================
// v7.2.0 — STREAM END NOTIFICATION (tombstone + gossip + watchdog)
// (Constants + HexStreamKey helper hoisted to top of file so StopBroadcast
// can see them. Definitions used in this section follow.)
// ============================================================

void CLiveStreamManager::OnStreamEnded(const uchar* streamKey, uint8 reason, CUpDownClient* fromPeer)
{
    if (streamKey == NULL) return;

    CSingleLock lock(&m_lock, TRUE);

    // v7.2.2 — CRITICAL: if WE are broadcasting this exact stream, ignore
    // the END completely. The remote peer is wrong (their watchdog
    // probably misfired on a bandwidth-induced stall, or someone in their
    // mesh gossiped a stale END). We KNOW the stream is alive — we're
    // serving it. Tombstoning would block our own viewers from finding
    // us; gossiping to our broadcastPeers would cascade-kick every viewer
    // we have. Both of those are exactly the cascade that produced the
    // 94:90 subscribe:disconnect ratio in 7.2.0/7.2.1 testing.
    if (m_bBroadcasting && memcmp(m_streamInfo.streamKey, streamKey, 16) == 0) {
        LIVE_LOG("MGR", "Ignored OP_LIVE_END for our own active broadcast (from=%S)",
            fromPeer ? L"peer" : L"watchdog");
        return;
    }

    // v7.3.0 — Authenticate the sender. Honor END only from:
    //   - Self-watchdog (fromPeer == NULL)
    //   - A peer we are CURRENTLY viewing from (m_viewPeers) — they are
    //     in a position to legitimately report the broadcaster died, OR
    //   - A peer we are currently SERVING (m_broadcastPeers) — relay path
    //     where they are forwarding gossip from the actual broadcaster.
    // Reject random peers gossiping END for streamKeys we know nothing
    // about; otherwise an attacker can poison every receiver's tombstone
    // map for 30 min by spamming OP_LIVE_END for popular streamKeys.
    if (fromPeer != NULL
        && m_viewPeers.Find(fromPeer) == NULL
        && m_broadcastPeers.Find(fromPeer) == NULL)
    {
        InterlockedIncrement(&m_counters.endsRejectedNoAuth);
        LIVE_LOG("MGR", "Rejected unauthenticated OP_LIVE_END from %S:%u",
            (LPCWSTR)ipstr(fromPeer->GetIP()),
            (unsigned)fromPeer->GetUserPort());
        return;
    }

    CString hexKey = HexStreamKey(streamKey);

    // Idempotency: if already tombstoned and still in TTL, drop. Stops
    // gossip loops dead at the second hop (every receiver re-gossips
    // only the FIRST time it learns).
    DWORD now = GetTickCount();
    DWORD expire = 0;
    if (m_streamTombstones.Lookup(hexKey, expire) && expire > now) {
        return;
    }

    // v7.3.0 — Cap tombstone map at ESE_TOMBSTONE_MAX_ENTRIES. If full,
    // evict the entry with the smallest (= oldest) expire tick before
    // inserting. Prevents memory-exhaustion DoS where an attacker spams
    // OP_LIVE_END for random streamKeys; without the cap, every accepted
    // END allocates a CString + DWORD pair that lives 30 min.
    const INT_PTR ESE_TOMBSTONE_MAX_ENTRIES = 10000;
    if (m_streamTombstones.GetCount() >= ESE_TOMBSTONE_MAX_ENTRIES) {
        CString oldestKey;
        DWORD   oldestExpire = 0xFFFFFFFFu;
        CString k;
        DWORD   v;
        POSITION p = m_streamTombstones.GetStartPosition();
        while (p) {
            m_streamTombstones.GetNextAssoc(p, k, v);
            if (v < oldestExpire) { oldestExpire = v; oldestKey = k; }
        }
        if (!oldestKey.IsEmpty()) {
            m_streamTombstones.RemoveKey(oldestKey);
            InterlockedIncrement(&m_counters.tombstonesEvicted);
        }
    }

    // Record tombstone with absolute expiration tick.
    m_streamTombstones[hexKey] = now + ESE_TOMBSTONE_TTL_MS;
    LIVE_LOG("MGR", "Tombstone %S reason=%u from=%S (mesh size now %d)",
        (LPCWSTR)hexKey, (unsigned)reason,
        fromPeer ? L"peer" : L"watchdog",
        (int)m_streamTombstones.GetCount());

    // Note: we don't proactively evict from m_kadBridge.m_streamDirectory
    // here because IsStreamTombstoned() is checked at READ time
    // (OnKadSearchResult / GetKnownStreams iteration), and the existing
    // PruneStaleEntries handles eviction within ESE_KAD_ENTRY_TTL=120s.
    // Tombstone-driven read filtering is sufficient and avoids exposing
    // a public Remove on the bridge.

    // If WE were viewing this stream, leave it. LeaveStream sends
    // UNSUBSCRIBE to our source peers but that's harmless — they'll
    // tombstone the same stream key on their side via their own watchdog
    // or via the gossip below.
    if (m_bViewing && memcmp(m_streamInfo.streamKey, streamKey, 16) == 0) {
        AddLogLine(true, _T("eSE Live: stream ended, leaving"));
        // Inline-leave so we don't recurse OnStreamEnded.
        m_bViewing = false;
        m_chunkBuffer.Clear();
        m_viewPeers.RemoveAll();
        m_peerBitmaps.RemoveAll();
        m_dwLastLiveActivity = 0;
    }

    // Gossip to OUR mesh peers (anyone we exchange chunks with for this
    // stream, viewer- or broadcaster-side). Don't bounce back to the
    // peer that just told us. Each receiver tombstones first, so a
    // duplicate from another path is dropped at line ~early-return above.
    auto gossip = [&](CUpDownClient* peer) {
        if (!peer || peer == fromPeer) return;
        Packet* pkt = eSELive::CreateEndPacket(streamKey, reason);
        if (pkt) {
            theStats.AddUpDataOverheadOther(pkt->size);
            peer->SendPacket(pkt);
        }
    };
    {
        POSITION pos = m_broadcastPeers.GetHeadPosition();
        while (pos) gossip(m_broadcastPeers.GetNext(pos));
    }
    {
        POSITION pos = m_viewPeers.GetHeadPosition();
        while (pos) gossip(m_viewPeers.GetNext(pos));
    }
}

bool CLiveStreamManager::IsStreamTombstoned(const uchar* streamKey) const
{
    if (streamKey == NULL) return false;
    CSingleLock lock(&m_lock, TRUE);

    CString hexKey = HexStreamKey(streamKey);
    DWORD expire = 0;
    if (!m_streamTombstones.Lookup(hexKey, expire)) return false;
    return expire > GetTickCount();
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

    // Find a segment we know this peer has (from their bitmap).
    // Phase 1 BOOT-3: bitmap is anchored at the PEER's oldestSeq.
    PeerBitmapInfo info;
    if (!m_peerBitmaps.Lookup(peer, info) || info.bitmap == 0) return;

    for (int bit = 0; bit < ESE_LIVE_MAX_SEGMENTS; bit++) {
        if (info.bitmap & (1 << bit)) {
            uint32 testSeq = info.oldestSeq + (uint32)bit;
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

    // v7.2.0 — prune expired tombstones once a minute. Cheap; the map
    // is small (a tombstone per dead stream we've personally heard
    // about, capped naturally by ESE_TOMBSTONE_TTL_MS=30 min).
    if (now - m_dwLastTombstonePrune > ESE_TOMBSTONE_PRUNE_MS) {
        m_dwLastTombstonePrune = now;
        CStringArray dead;
        CString k; DWORD expire = 0;
        POSITION pos = m_streamTombstones.GetStartPosition();
        while (pos) {
            m_streamTombstones.GetNextAssoc(pos, k, expire);
            if (expire <= now) dead.Add(k);
        }
        for (INT_PTR i = 0; i < dead.GetCount(); ++i)
            m_streamTombstones.RemoveKey(dead[i]);

        // v7.2.2 — same cadence: prune recent-push tracking older than
        // 60 s. The cooldown window is 10 s so anything older is dead
        // weight. Caps map size at one entry per distinct endpoint
        // that subscribed in the last minute.
        CArray<uint64> deadKeys;
        uint64 pk; DWORD pt = 0;
        POSITION pp = m_recentInitialPushes.GetStartPosition();
        while (pp) {
            m_recentInitialPushes.GetNextAssoc(pp, pk, pt);
            if (now - pt > 60000) deadKeys.Add(pk);
        }
        for (INT_PTR i = 0; i < deadKeys.GetCount(); ++i)
            m_recentInitialPushes.RemoveKey(deadKeys[i]);
    }

    // v7.2.2 — crash-detect watchdog (stricter than 7.2.0). Only fires
    // when ALL of:
    //   1. We are viewing
    //   2. >180 s since last chunk OR heartbeat (was 90 s, false-fired
    //      on bandwidth-throttled viewers receiving high-variant
    //      streams in bursts)
    //   3. m_viewPeers is empty — i.e. nobody left to receive from
    // The third condition is critical: if we still have peers we're
    // talking to, we might just be slow (their bandwidth, our
    // bandwidth, intermediate NAT). Only when EVERY source peer has
    // dropped AND we've had 180 s of silence is it really dead.
    if (m_bViewing
        && m_viewPeers.GetCount() == 0
        && m_dwLastLiveActivity != 0
        && (now - m_dwLastLiveActivity) > ESE_LIVE_WATCHDOG_MS)
    {
        LIVE_LOG("MGR", "Watchdog: %u ms silence + 0 view peers, declaring stream dead",
            now - m_dwLastLiveActivity);
        uchar deadKey[16];
        memcpy(deadKey, m_streamInfo.streamKey, 16);
        // OnStreamEnded leaves the stream and gossips. NULL fromPeer
        // marks this as a self-detected (not relayed) END.
        OnStreamEnded(deadKey, /*reason*/ ESE_END_ERROR, /*fromPeer*/ NULL);
    }

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

        // V2-S17: re-publish as secondary source every 30 s once we have at
        // least 5 segments buffered (= meaningful upload capacity to relay).
        // Only the LeafRestricted tier opts out (uplink too thin to help).
        if (m_chunkBuffer.GetCount() >= 5
            && (now - m_dwLastSecondaryPublish > 30000)
            && ComputeMyTier((uint16)m_streamInfo.bitrate) > TIER_LEAF_RESTRICTED)
        {
            // Use ASCII -> wide for the title (avoids passing CString through
            // the wchar_t LiveStreamPublish API one extra time).
            m_kadBridge.PublishAsRelay(m_streamInfo.streamKey,
                (LPCWSTR)m_streamInfo.title,
                (LPCWSTR)m_streamInfo.category,
                (LPCWSTR)m_streamInfo.language,
                (uint16)m_streamInfo.bitrate);
            m_dwLastSecondaryPublish = now;
        }

        // V2-S19: keep at least 3 active source connections (warm spares).
        // Spaced out at 10 s so we don't hammer Kad results that are still
        // resolving — one EnsureMultiParent per tick is plenty.
        if (now - m_dwLastMultiParentTick > 10000) {
            EnsureMultiParent();
            m_dwLastMultiParentTick = now;
        }

        // DISC-S05: if viewing with zero source peers, re-fire the 3 Kad
        // searches every 15 s. Hard cap at 10 retries per session so a
        // permanently-unfindable stream eventually stops spamming the DHT.
        // Kad propagation can take 1-5 min on cold bootstrap; without this
        // retry the viewer is "blind" if Kad results arrived after JoinStream.
        if (m_viewPeers.GetCount() == 0
            && m_nJoinSearchRetries < 10
            && (now - m_dwLastJoinSearchTick) > 15000)
        {
            char keyHex[33] = {0};
            for (int i = 0; i < 16; ++i)
                sprintf_s(keyHex + i*2, 3, "%02x", m_streamInfo.streamKey[i]);
            CString hashSearch(_T("livehash:"));
            hashSearch.AppendFormat(_T("%S"), keyHex);
            m_kadBridge.SearchStreams(_T("eselive"));
            if (!m_streamInfo.title.IsEmpty()
                && m_streamInfo.title.CompareNoCase(_T("eselive")) != 0)
                m_kadBridge.SearchStreams(m_streamInfo.title);
            m_kadBridge.SearchStreams(hashSearch);
            m_nJoinSearchRetries++;
            m_dwLastJoinSearchTick = now;
            LIVE_LOG("MGR", "DISC-S05: re-search attempt %d/10 (no viewPeers yet)",
                m_nJoinSearchRetries);
        }

        // V2-S22: anycast for spare capacity when totally orphaned.
        // If we have zero source peers AND haven't received a chunk in 10 s
        // we fire an aggressive livehash search every 5 s (vs the 30 s cool
        // down used for the regular failover path). Burst-mode discovery.
        if (m_viewPeers.GetCount() == 0) {
            static DWORD s_lastAnycast = 0;
            if (now - s_lastAnycast > 5000) {
                s_lastAnycast = now;
                char keyHexA[33] = {0};
                for (int i = 0; i < 16; ++i)
                    sprintf_s(keyHexA + i*2, 3, "%02x", m_streamInfo.streamKey[i]);
                CString hashSearch(_T("livehash:"));
                hashSearch.AppendFormat(_T("%S"), keyHexA);
                m_kadBridge.SearchStreams(hashSearch);
                LIVE_LOG("ANYCAST", "Orphan: re-searching %s", (LPCSTR)CT2A(hashSearch));
            }
        }

        // Request missing segments
        RequestMissingSegments();

        // Phase 3.3 ROB-Failover: if we haven't received a chunk in 20 s,
        // either our broadcaster died or our peers all dropped us. Re-trigger
        // Kad discovery and dial any known mesh peer for the same streamKey
        // that we're not already connected to. This is the only path back
        // when the original broadcaster's TCP socket goes down silently
        // (NAT timeout, transient ISP outage, app crash on their side).
        LONG lastChunk = (LONG)InterlockedCompareExchange(
            (LONG*)&m_counters.lastChunkReceivedAt, 0, 0);
        const DWORD STALL_THRESHOLD_MS = 20000;
        if (lastChunk != 0 && (DWORD)((LONG)now - lastChunk) > STALL_THRESHOLD_MS) {
            // Avoid spamming: only retry once per stall window
            static DWORD s_lastFailoverRun = 0;
            if (now - s_lastFailoverRun > STALL_THRESHOLD_MS) {
                s_lastFailoverRun = now;
                AddLogLine(true,
                    _T("eSE Live: Stream stalled %u s, attempting failover"),
                    (DWORD)((LONG)now - lastChunk) / 1000);

                // 1. Re-search Kad (cooldown was set to 5 s in LAT-1).
                m_kadBridge.SearchStreams(_T("eselive"));

                // 2. Try every other known broadcaster for the same streamKey.
                CArray<LiveStreamEntry> known;
                m_kadBridge.GetKnownStreams(known);
                for (INT_PTR i = 0; i < known.GetCount(); i++) {
                    if (memcmp(known[i].streamKey, m_streamInfo.streamKey, 16) != 0)
                        continue;
                    if (known[i].broadcasterIP == 0 || known[i].broadcasterPort == 0)
                        continue;
                    // Skip peers we are already viewing from (same IP+port).
                    bool alreadyConnected = false;
                    POSITION pos = m_viewPeers.GetHeadPosition();
                    while (pos) {
                        CUpDownClient* existing = m_viewPeers.GetNext(pos);
                        if (existing
                            && existing->GetIP()       == known[i].broadcasterIP
                            && existing->GetUserPort() == known[i].broadcasterPort)
                        {
                            alreadyConnected = true;
                            break;
                        }
                    }
                    if (alreadyConnected) continue;

                    // Dial. TryConnectToStreamSource takes the lock recursively
                    // through the same CSingleLock — we already hold it here,
                    // so release briefly to avoid self-deadlock.
                    // A.4 Sprint 1: pass Kad UDP port too for hole-punch fallback.
                    lock.Unlock();
                    TryConnectToStreamSource(m_streamInfo.streamKey,
                        known[i].broadcasterIP, known[i].broadcasterPort,
                        known[i].broadcasterUDPPort);
                    lock.Lock();
                }
            }
        }
    }

    // V2-S03: ping all peers every 5 s for RTT EWMA + reap stale pings.
    // Done outside broadcasting/viewing branches so we get RTT in any role.
    if (now - m_dwLastPingTick >= 5000) {
        PingAllPeers();
        ReapStalePings(now);
        m_dwLastPingTick = now;
    }

    // Capa 3 bootstrap: 5 s after startup, ping all cached streams via
    // the throttled dial queue. Gives the viewer an instant directory
    // before Kad has even bootstrapped. One-shot per process lifetime.
    if (!m_bBootstrapAttempted) {
        if (m_dwBootstrapTick == 0) m_dwBootstrapTick = now;
        if (now - m_dwBootstrapTick >= 5000) {
            BootstrapPingCachedStreams();
        }
    }

    // DISC-S04: try to clear any pending ghost streamKey from a previous
    // crashed session. PublishTombstoneFor returns false if Kad isn't ready;
    // we retry every tick until it succeeds (then unset the flag).
    if (m_bHasPendingGhostKey) {
        if (m_kadBridge.PublishTombstoneFor(m_pendingGhostKey)) {
            theApp.WriteProfileString(_T("eMule"), _T("LiveLastStreamKey"), _T(""));
            m_bHasPendingGhostKey = false;
            LIVE_LOG("MGR", "DISC-S04: ghost tombstone published, flag cleared");
        }
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

    // Capa 1 PEX: build a top-5 of streams we've recently learned about
    // (from Kad results) and piggy-back them onto every heartbeat. Every
    // peer receiving the heartbeat learns those streams instantly without
    // its own Kad search — viral O(log N) propagation across the mesh.
    eSELive::LivePexEntry pex[5];
    uint8 pexCount = 0;
    {
        CArray<LiveStreamEntry> known;
        m_kadBridge.GetKnownStreams(known);
        // Sort: most-recently-seen first; skip own stream + invalid IPs.
        DWORD nowTick = GetTickCount();
        struct Cand { int idx; DWORD age; };
        CArray<Cand> cands;
        for (INT_PTR i = 0; i < known.GetCount(); i++) {
            const LiveStreamEntry& e = known[i];
            if (e.isOwnStream) continue;
            if (e.broadcasterIP == 0 || e.broadcasterPort == 0) continue;
            Cand c; c.idx = (int)i; c.age = nowTick - e.lastSeen;
            cands.Add(c);
        }
        // Insertion sort top-5 by age ascending (smallest age = freshest)
        for (INT_PTR i = 1; i < cands.GetCount(); ++i) {
            Cand t = cands[i]; INT_PTR j = i - 1;
            while (j >= 0 && cands[j].age > t.age) { cands[j+1] = cands[j]; --j; }
            cands[j+1] = t;
        }
        for (INT_PTR i = 0; i < cands.GetCount() && pexCount < 5; ++i) {
            const LiveStreamEntry& e = known[cands[i].idx];
            memcpy(pex[pexCount].streamKey, e.streamKey, 16);
            pex[pexCount].broadcasterIP   = e.broadcasterIP;
            pex[pexCount].broadcasterPort = e.broadcasterPort;
            pexCount++;
        }
    }

    auto sendOne = [&](CUpDownClient* peer) {
        if (!peer) return;
        Packet* pkt = eSELive::CreateHeartbeatPacket(
            m_streamInfo.streamKey, bitmap, oldestSeq, pex, pexCount);
        if (pkt) {
            theStats.AddUpDataOverheadOther(pkt->size);
            peer->SendPacket(pkt);
        }
    };

    if (m_bBroadcasting) {
        POSITION pos = m_broadcastPeers.GetHeadPosition();
        while (pos) sendOne(m_broadcastPeers.GetNext(pos));
    }
    if (m_bViewing) {
        POSITION pos = m_viewPeers.GetHeadPosition();
        while (pos) sendOne(m_viewPeers.GetNext(pos));
        pos = m_broadcastPeers.GetHeadPosition();
        while (pos) sendOne(m_broadcastPeers.GetNext(pos));
    }
}

void CLiveStreamManager::SendAnnounceToAll()
{
    if (!m_bBroadcasting || m_chunkBuffer.GetCount() == 0) return;

    uint32 newestSeq = m_chunkBuffer.GetNewestSeq();

    POSITION pos = m_broadcastPeers.GetHeadPosition();
    while (pos) {
        CUpDownClient* peer = m_broadcastPeers.GetNext(pos);
        // v7.6.0 — include pubkey so receivers can pin the streamKey→pubkey
        // binding before chunks/end arrive with signatures (T4/T5).
        Packet* pkt = eSELive::CreateAnnouncePacket(
            m_streamInfo.streamKey, newestSeq, m_streamInfo.bitrate,
            m_streamInfo.pubkey);
        if (pkt) {
            theStats.AddUpDataOverheadOther(pkt->size);
            peer->SendPacket(pkt);
        }
    }
}

void CLiveStreamManager::RequestMissingSegments()
{
    if (!m_bViewing || m_viewPeers.GetCount() == 0) return;

    uint32 oldestSeq;
    uint32 newestSeq;

    if (m_chunkBuffer.GetCount() == 0) {
        // Phase 1 BOOT-4: viewer has not received any chunk yet.
        // Cannot use the empty buffer's seq=0 as anchor (broadcaster long ago
        // evicted those). Instead, snap to the "live edge": the highest
        // newestSeq advertised by any peer, then back up so we have a small
        // pre-roll buffer before playback starts.
        uint32 bestEdge = 0;
        uint32 bestOldest = 0;
        bool   haveAny = false;
        POSITION pos = m_peerBitmaps.GetStartPosition();
        while (pos) {
            CUpDownClient* peer = NULL;
            PeerBitmapInfo info;
            m_peerBitmaps.GetNextAssoc(pos, peer, info);
            if (info.bitmap == 0) continue;
            uint32 peerNewest = info.NewestSeq();
            if (!haveAny || peerNewest > bestEdge) {
                bestEdge   = peerNewest;
                bestOldest = info.oldestSeq;
                haveAny    = true;
            }
        }
        if (!haveAny) {
            // No peer has sent a heartbeat yet. Nothing to request — wait
            // for OP_LIVE_HEARTBEAT to arrive (sent immediately after SUBSCRIBE).
            return;
        }
        // Pull a small pre-roll (last 3 segments before the live edge) so
        // the HLS playlist reaches its 2-segment minimum quickly without
        // chasing the absolute latest.
        const uint32 preroll = 3;
        oldestSeq = (bestEdge >= preroll) ? (bestEdge - preroll) : bestEdge;
        if (oldestSeq < bestOldest) oldestSeq = bestOldest;
        newestSeq = bestEdge;
        AddDebugLogLine(false,
            _T("eSE Live: Bootstrap pull seg %u..%u (live edge from peers)"),
            oldestSeq, newestSeq);
    } else {
        // Normal in-stream gap recovery anchored at our own buffer.
        oldestSeq = m_chunkBuffer.GetOldestSeq();
        newestSeq = m_chunkBuffer.GetNewestSeq();
    }

    // Request up to 5 missing segments with extended lookahead.
    int requested = 0;
    int noPeer    = 0;
    const int maxRequestsPerCycle = 5;
    const uint32 lookahead = 3;
    for (uint32 seq = oldestSeq; seq <= newestSeq + lookahead && requested < maxRequestsPerCycle; seq++) {
        if (m_chunkBuffer.HasSegment(seq)) continue;
        InterlockedIncrement(&m_counters.chunksMissing);
        CUpDownClient* peer = SelectPeerForSegment(seq);
        if (peer) {
            Packet* pkt = eSELive::CreateRequestPacket(
                m_streamInfo.streamKey, seq);
            if (pkt) {
                theStats.AddUpDataOverheadOther(pkt->size);
                peer->SendPacket(pkt);
                InterlockedIncrement(&m_counters.chunksRequested);
                requested++;
                LIVE_LOG("REQ", "ASK seq=%u -> %S:%u",
                    seq,
                    (LPCWSTR)ipstr(peer->GetIP()),
                    (unsigned)peer->GetUserPort());
            }
        } else {
            AddDebugLogLine(false,
                _T("eSE HLS: No peer has segment %u (gap recovery failed)"), seq);
            noPeer++;
        }
    }
    if (noPeer > 0) {
        LIVE_LOG("REQ", "NO_PEER for %d gap segments (range %u..%u, viewPeers=%d)",
            noPeer, oldestSeq, newestSeq, (int)m_viewPeers.GetCount());
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
    // V2-S20 — Mesh fallback peer selection.
    // Score = response_rate * 100  - failCount * 20  - RTT_penalty.
    // RTT penalty: floor(rtt_ms_ewma / 50). 100ms -> -2, 500ms -> -10, 1s -> -20.
    // This biases toward low-latency parents while preserving the existing
    // trust-based ordering. Both broadcaster and any secondary-source viewers
    // are considered (we already added them to m_viewPeers via JoinStream).
    CUpDownClient* bestPeer = NULL;
    int bestScore = -1;

    POSITION pos = m_viewPeers.GetHeadPosition();
    while (pos) {
        CUpDownClient* peer = m_viewPeers.GetNext(pos);
        PeerBitmapInfo info;
        if (!m_peerBitmaps.Lookup(peer, info)) continue;
        if (!info.Has(seqNum)) continue;

        PeerTrust trust;
        int score = 50;
        if (m_peerTrust.Lookup(peer, trust)) {
            score = (int)(trust.GetResponseRate() * 100);
            score -= trust.failCount * 20;
        }
        // V2-S20: RTT bias. Only counts when we have a measured EWMA.
        PeerCounters pc;
        if (m_peerCounters.Lookup(peer, pc) && pc.rtt_ms_ewma > 0) {
            int rttPenalty = (int)(pc.rtt_ms_ewma / 50);
            if (rttPenalty > 50) rttPenalty = 50;  // cap so 5s RTT != totally banned
            score -= rttPenalty;
        }
        if (score > bestScore) {
            bestScore = score;
            bestPeer  = peer;
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
    // Snapshot the KadBridge BEFORE taking our m_lock. BuildDebugKadSnapshot
    // locks CLiveKadBridge::m_lock; CLiveKadBridge::GetKnownStreams locks that
    // same lock and then calls IsStreamTombstoned() -> our m_lock. Holding our
    // m_lock across this call is the B-A half of an A-B/B-A deadlock that
    // froze the UI thread when two /api/live/* worker threads raced.
    const KadDebugSnapshot kadSnap = m_kadBridge.BuildDebugKadSnapshot();

    CSingleLock lock(&m_lock, TRUE);

    LiveDebugSnapshot snap;
    memset(&snap, 0, sizeof(snap));

    // Stream state
    snap.broadcasting  = m_bBroadcasting;
    snap.viewing       = m_bViewing;
    snap.emergencyMode = m_bEmergencyMode;
    snap.uptimeMs      = (m_streamInfo.startedAt > 0)
        ? ((uint32)time(NULL) - m_streamInfo.startedAt) * 1000 : 0;

    snap.kad = kadSnap;

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
            PeerBitmapInfo bm;
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
    snap.minUploadRequired  = GetMinUploadRequired();

    // Atomic counters — plain copy (all LONG fields, atomic reads on x86)
    snap.counters = m_counters;

    return snap;
}

LiveChannelSnapshot CLiveStreamManager::GetChannelSnapshot() const
{
    CSingleLock lock(&m_lock, TRUE);
    LiveChannelSnapshot s;
    s.broadcasting = m_bBroadcasting;
    memcpy(s.streamKey, m_streamInfo.streamKey, sizeof s.streamKey);
    s.title        = m_streamInfo.title;
    s.bitrate      = m_streamInfo.bitrate;
    s.viewerCount  = GetViewerCount();
    return s;
}


// ============================================================
// V2-S03 — RTT measurement (PING/PONG)
// ============================================================

void CLiveStreamManager::PingPeer(CUpDownClient* peer)
{
    // Caller must hold m_lock.
    if (!peer) return;

    uint32 id = ++m_nNextPingId;
    uint64 sendTick = (uint64)GetTickCount();

    Packet* pkt = eSELive::CreatePingPacket(m_streamInfo.streamKey, id, sendTick);
    if (!pkt) return;
    theStats.AddUpDataOverheadOther(pkt->size);
    peer->SendPacket(pkt);

    PendingPingMap* pings = NULL;
    if (!m_pendingPings.Lookup(peer, pings) || pings == NULL) {
        pings = new PendingPingMap();
        m_pendingPings[peer] = pings;
    }
    PendingPing pp;
    pp.sendTick = sendTick;
    (*pings)[id] = pp;

    PeerCounters& pc = m_peerCounters[peer];
    pc.last_ping_sent_ms = (DWORD)sendTick;
    pc.pings_sent++;
}

void CLiveStreamManager::PingAllPeers()
{
    // Caller holds m_lock. Iterate both directions (we may want RTT to viewers
    // we're serving AND to peers we're pulling from).
    POSITION pos = m_viewPeers.GetHeadPosition();
    while (pos) PingPeer(m_viewPeers.GetNext(pos));
    pos = m_broadcastPeers.GetHeadPosition();
    while (pos) PingPeer(m_broadcastPeers.GetNext(pos));
}

void CLiveStreamManager::ReapStalePings(DWORD now)
{
    // Drop pending pings older than 30 s. This bounds memory if a peer never
    // PONGs back (broken NAT, stale TCP) without affecting RTT updates.
    const DWORD STALE_MS = 30000;
    POSITION pos = m_pendingPings.GetStartPosition();
    while (pos) {
        CUpDownClient* peer = NULL;
        PendingPingMap* pings = NULL;
        m_pendingPings.GetNextAssoc(pos, peer, pings);
        if (!pings) continue;

        // Build a list of stale ids (cannot RemoveKey while iterating CMap).
        CArray<uint32> stale;
        POSITION ipos = pings->GetStartPosition();
        while (ipos) {
            uint32 id = 0; PendingPing pp;
            pings->GetNextAssoc(ipos, id, pp);
            if (now - (DWORD)pp.sendTick > STALE_MS) stale.Add(id);
        }
        for (INT_PTR i = 0; i < stale.GetCount(); i++)
            pings->RemoveKey(stale[i]);
    }
}

void CLiveStreamManager::OnLivePing(CUpDownClient* peer, const uchar* streamKey,
    uint32 pingId, uint64 sendTick)
{
    CSingleLock lock(&m_lock, TRUE);
    if (!peer) return;
    // Echo PONG with the original sendTick. Stream key match is not strict;
    // we PONG even if the streams differ to keep the protocol simple.
    Packet* pkt = eSELive::CreatePongPacket(streamKey, pingId, sendTick);
    if (!pkt) return;
    theStats.AddUpDataOverheadOther(pkt->size);
    peer->SendPacket(pkt);
}

// ============================================================
// Decentralized Capa 3 — Bootstrap cache (last_streams.json)
// ============================================================

CString CLiveStreamManager::BootstrapCachePath() const
{
    // %APPDATA%\eMule\last_streams.json — small JSON (<10 KB), no extra deps.
    TCHAR appData[MAX_PATH] = {0};
    if (!SUCCEEDED(SHGetFolderPath(NULL, CSIDL_APPDATA, NULL, 0, appData)))
        return CString();
    CString dir; dir.Format(_T("%s\\eMule"), appData);
    CreateDirectory(dir, NULL);
    CString file; file.Format(_T("%s\\last_streams.json"), (LPCTSTR)dir);
    return file;
}

void CLiveStreamManager::RememberStreamForBootstrap(const uchar* streamKey,
    uint32 ip, uint16 port, const CString& title)
{
    if (!streamKey || ip == 0 || port == 0) return;
    CString path = BootstrapCachePath();
    if (path.IsEmpty()) return;

    // Read existing JSON (lenient parse — we wrote it ourselves so format
    // is predictable). Each line is a self-contained record:
    //   {"k":"HEX32","i":"1.2.3.4","p":4662,"t":"Title","ts":1234567890}
    // We keep last 20 entries (FIFO drop oldest), dedupe by streamKey.
    const int MAX_ENTRIES = 20;
    char keyHex[33] = {0};
    for (int i = 0; i < 16; ++i) sprintf_s(keyHex + i*2, 3, "%02x", streamKey[i]);

    // Build new line.
    CStringA titleA = (LPCSTR)CT2A(title);
    titleA.Replace("\\", "\\\\");
    titleA.Replace("\"", "\\\"");
    // Truncate title to 80 chars to bound file size.
    if (titleA.GetLength() > 80) titleA = titleA.Left(80);
    CStringA newLine;
    newLine.Format("{\"k\":\"%s\",\"i\":\"%lu.%lu.%lu.%lu\",\"p\":%u,\"t\":\"%s\",\"ts\":%lld}\n",
        keyHex,
        (unsigned long)(ip & 0xFF), (unsigned long)((ip >> 8) & 0xFF),
        (unsigned long)((ip >> 16) & 0xFF), (unsigned long)((ip >> 24) & 0xFF),
        (unsigned)port, (LPCSTR)titleA, (long long)time(NULL));

    // Read existing, drop entry with same key, keep most recent 19.
    std::deque<CStringA> kept;
    FILE* f = NULL;
    if (_tfopen_s(&f, path, _T("rt")) == 0 && f) {
        char line[512];
        while (fgets(line, sizeof(line), f)) {
            CStringA L(line);
            // Skip our existing key (so the new line goes to the front)
            CStringA marker;
            marker.Format("\"k\":\"%s\"", keyHex);
            if (L.Find(marker) >= 0) continue;
            kept.push_back(L);
            if ((int)kept.size() >= MAX_ENTRIES - 1) break;
        }
        fclose(f);
    }

    // Write new line first, then preserved older entries.
    if (_tfopen_s(&f, path, _T("wt")) == 0 && f) {
        fputs((LPCSTR)newLine, f);
        for (const auto& L : kept) fputs((LPCSTR)L, f);
        fclose(f);
    }
}

void CLiveStreamManager::BootstrapPingCachedStreams()
{
    if (m_bBootstrapAttempted) return;
    m_bBootstrapAttempted = true;

    CString path = BootstrapCachePath();
    if (path.IsEmpty()) return;
    FILE* f = NULL;
    if (_tfopen_s(&f, path, _T("rt")) != 0 || !f) {
        LIVE_LOG("BOOTSTRAP", "No cache file (%S) — first run, skipping",
            (LPCWSTR)path);
        return;
    }

    int dialed = 0;
    char line[512];
    while (fgets(line, sizeof(line), f) && dialed < 20) {
        // Parse a single-line JSON record produced by RememberStreamForBootstrap.
        // We use plain string finds — no JSON parser dependency for a format
        // we wrote ourselves.
        CStringA L(line);
        int kPos = L.Find("\"k\":\"");
        int iPos = L.Find("\"i\":\"");
        int pPos = L.Find("\"p\":");
        if (kPos < 0 || iPos < 0 || pPos < 0) continue;

        kPos += 5;
        int kEnd = L.Find("\"", kPos);
        if (kEnd < 0) continue;
        CStringA hex = L.Mid(kPos, kEnd - kPos);
        if (hex.GetLength() != 32) continue;

        iPos += 5;
        int iEnd = L.Find("\"", iPos);
        if (iEnd < 0) continue;
        CStringA ipStr = L.Mid(iPos, iEnd - iPos);

        pPos += 4;
        int port = atoi(L.Mid(pPos, 6));
        if (port <= 0 || port > 65535) continue;

        uchar key[16] = {0};
        bool keyOk = true;
        for (int i = 0; i < 16; ++i) {
            auto h2n = [](char c) -> int {
                if (c >= '0' && c <= '9') return c - '0';
                if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                if (c >= 'A' && c <= 'F') return c - 'A' + 10;
                return -1;
            };
            int hi = h2n(hex[i*2]);
            int lo = h2n(hex[i*2 + 1]);
            if (hi < 0 || lo < 0) { keyOk = false; break; }
            key[i] = (uchar)((hi << 4) | lo);
        }
        if (!keyOk) continue;

        uint32 ipNet = (uint32)inet_addr((LPCSTR)ipStr);
        if (ipNet == INADDR_NONE || ipNet == 0) continue;

        // Inject as a Kad-style discovery result. Reuses the same throttle +
        // validation pipeline (DISC-S06 dial queue, IsGoodIP, dedupe).
        // bitrate=1 sentinel: NOT the DISC-S01 tombstone (==0).
        LIVE_LOG("BOOTSTRAP", "Cached stream: dial %s:%u for key=%s",
            (LPCSTR)ipStr, (unsigned)port, (LPCSTR)hex);
        m_kadBridge.OnKadSearchResult(key, _T(""), _T(""),
            ipNet, (uint16)port, /*udpPort*/ 0,
            /*bitrate*/ 1, /*viewerCount*/ 0);
        dialed++;
    }
    fclose(f);
    LIVE_LOG("BOOTSTRAP", "Replayed %d cached streams from %S",
        dialed, (LPCWSTR)path);
}

void CLiveStreamManager::OnPexEntry(const uchar* streamKey, uint32 broadcasterIP, uint16 broadcasterPort)
{
    // Decentralized Capa 1: gossip-discovered stream piggy-backed in a peer's
    // HEARTBEAT. Route through OnKadSearchResult so all the existing checks
    // apply (port != 0, IsGoodIP, IPFilter, self-IP guard, viewerCount clamp,
    // bitrate sanity, dedupe by streamKey, DISC-S06 dial throttle).
    // Title/category/language are empty — they'll be filled in when the
    // dialed broadcaster sends its own HEARTBEAT or when Kad eventually
    // returns the rich entry.
    if (!streamKey || broadcasterIP == 0 || broadcasterPort == 0) return;
    // bitrate=1 is a "unknown bitrate, NOT a tombstone" sentinel — the
    // tombstone filter from DISC-S01 only matches bitrate==0 exactly. The
    // dialed broadcaster will overwrite with the real bitrate via its own
    // HEARTBEAT/ANNOUNCE soon after we connect.
    m_kadBridge.OnKadSearchResult(streamKey, _T(""), _T(""),
        broadcasterIP, broadcasterPort, /*broadcasterUDPPort*/ 0,
        /*bitrate*/ 1, /*viewerCount*/ 0);
}

void CLiveStreamManager::OnLivePong(CUpDownClient* peer, const uchar* /*streamKey*/,
    uint32 pingId, uint64 echoTick)
{
    CSingleLock lock(&m_lock, TRUE);
    if (!peer) return;

    PendingPingMap* pings = NULL;
    if (!m_pendingPings.Lookup(peer, pings) || !pings) return;
    PendingPing pp;
    if (!pings->Lookup(pingId, pp)) return;
    pings->RemoveKey(pingId);

    DWORD rtt = (DWORD)((uint64)GetTickCount() - echoTick);
    if (rtt > 60000) return; // sanity cap (network glitch / clock skew)

    PeerCounters& pc = m_peerCounters[peer];
    pc.pongs_received++;
    if (pc.rtt_ms_ewma == 0) pc.rtt_ms_ewma = rtt;
    else pc.rtt_ms_ewma = (pc.rtt_ms_ewma * 7 + rtt) / 8; // alpha = 1/8

    LIVE_LOG("RTT", "peer=%S:%u rtt=%ums ewma=%ums",
        (LPCWSTR)ipstr(peer->GetIP()), peer->GetUserPort(), rtt, pc.rtt_ms_ewma);
}


// ============================================================
// V2-S11/S12/S13 — Upload-capacity probe + tier classification + caps
// ============================================================

void CLiveStreamManager::MeasureUploadCapacity()
{
    // V2-S11: probe approximation. We use thePrefs.GetMaxUpload() (KB/s) as the
    // ceiling because the user has already told us their upload budget. A real
    // STUN-aware probe is V3-S01 (libnice).
    //
    // Edge cases:
    //   - 0  in eMule prefs = explicit "0 KB/s"  -> leaf-restricted (no upload).
    //   - UINT_MAX (0xFFFFFFFF) = "unlimited" sentinel -> map to 999999 kbps
    //     (mega-seeder). Without this clamp, kbs*8 overflows DWORD.
    DWORD kbs = thePrefs.GetMaxUpload();   // KB/s
    DWORD kbps;
    if (kbs == 0)                       kbps = 0;
    else if (kbs >= 0x20000000u /* >2 Gbps */) kbps = 999999u; // unlimited / nonsense
    else                                kbps = kbs * 8;
    m_measuredUploadKbps = kbps;
    LIVE_LOG("TIER", "Measured upload capacity: %u kbps (from prefs MaxUpload=%u KB/s)",
        kbps, kbs);
}

PeerTier CLiveStreamManager::ComputeMyTier(uint16 streamBitrateKbps) const
{
    if (streamBitrateKbps == 0) streamBitrateKbps = 1000; // safe default
    if (m_measuredUploadKbps == 0) return TIER_LEAF_RESTRICTED;
    float ratio = (float)m_measuredUploadKbps / (float)streamBitrateKbps;
    if (ratio < 0.5f)  return TIER_LEAF_RESTRICTED;
    if (ratio < 1.5f)  return TIER_LEAF;
    if (ratio < 4.0f)  return TIER_MID;
    if (ratio < 10.0f) return TIER_SUPER_SEEDER;
    return TIER_MEGA_SEEDER;
}

const char* CLiveStreamManager::TierName(PeerTier t)
{
    switch (t) {
    case TIER_LEAF_RESTRICTED: return "leaf-restricted";
    case TIER_LEAF:            return "leaf";
    case TIER_MID:             return "mid";
    case TIER_SUPER_SEEDER:    return "super-seeder";
    case TIER_MEGA_SEEDER:     return "mega-seeder";
    }
    return "unknown";
}

int CLiveStreamManager::MaxConcurrentUploads() const
{
    PeerTier t = ComputeMyTier(
        m_streamInfo.bitrate ? (uint16)m_streamInfo.bitrate : (uint16)1000);
    switch (t) {
    case TIER_LEAF_RESTRICTED: return 0;
    case TIER_LEAF:            return 1;
    case TIER_MID:             return 3;
    case TIER_SUPER_SEEDER:    return 10;
    case TIER_MEGA_SEEDER:     return 25;
    }
    return 0;
}

int CLiveStreamManager::EffectiveMaxConcurrentUploads() const
{
    // V2-S16: when we are the original broadcaster, hard-cap direct viewers at
    // 10 regardless of tier. Higher than that defeats the tree topology — we
    // want the rest pulled by the super-seeders, not us.
    int byTier = MaxConcurrentUploads();
    if (m_bBroadcasting) {
        const int BROADCASTER_MAX_DIRECT_VIEWERS = 10;
        return (byTier == 0 || byTier > BROADCASTER_MAX_DIRECT_VIEWERS)
            ? BROADCASTER_MAX_DIRECT_VIEWERS
            : byTier;
    }
    return byTier;
}


// ============================================================
// V2-S19 — Multi-parent maintenance
// ============================================================

void CLiveStreamManager::EnsureMultiParent()
{
    // Caller holds m_lock. Goal: viewer keeps >= 3 active source connections
    // so a single parent disconnect (NAT timeout, peer drop) does not stall
    // the stream — failover is sub-second because spare(s) are warm.
    if (!m_bViewing) return;
    const int TARGET = 3;
    if (m_viewPeers.GetCount() >= TARGET) return;

    // Pull candidates from KadBridge — entries we discovered for OUR streamKey.
    // Skip ones we already have, ones we are (LAN/loopback), or filtered IPs.
    CArray<LiveStreamEntry> known;
    m_kadBridge.GetKnownStreams(known);

    int dialed = 0;
    for (INT_PTR i = 0; i < known.GetCount(); i++) {
        if (m_viewPeers.GetCount() + dialed >= TARGET) break;
        if (memcmp(known[i].streamKey, m_streamInfo.streamKey, 16) != 0) continue;
        if (known[i].broadcasterIP == 0 || known[i].broadcasterPort == 0) continue;

        // Dedupe — already viewing from this IP+port?
        bool already = false;
        POSITION pos = m_viewPeers.GetHeadPosition();
        while (pos) {
            CUpDownClient* p = m_viewPeers.GetNext(pos);
            if (p && p->GetIP() == known[i].broadcasterIP
                  && p->GetUserPort() == known[i].broadcasterPort) {
                already = true;
                break;
            }
        }
        if (already) continue;

        LIVE_LOG("PARENT", "EnsureMultiParent: dial %S:%u (have %d, target %d)",
            (LPCWSTR)ipstr(known[i].broadcasterIP), known[i].broadcasterPort,
            (int)m_viewPeers.GetCount(), TARGET);

        // TryConnectToStreamSource takes m_lock recursively; release ours
        // briefly to avoid self-deadlock with the inner CSingleLock.
        m_lock.Unlock();
        TryConnectToStreamSource(m_streamInfo.streamKey,
            known[i].broadcasterIP, known[i].broadcasterPort,
            known[i].broadcasterUDPPort);
        m_lock.Lock();
        dialed++;
    }
}
