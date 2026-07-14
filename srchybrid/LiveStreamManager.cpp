//this file is part of eMule
// eSE — Live Stream Manager Implementation
#include "stdafx.h"
#include "LiveStreamManager.h"
#include "LiveCrypto.h"        // v7.6.0 — Ed25519 keypair helpers
#include "LiveDebugLog.h"
#include "LivePackets.h"
#include "LiveTunnel.h"        // v8.1 Sprint C — C5 mode handoff (CLiveTunnel)
#include "LiveBuddyRelay.h"    // R.3 — relay egress (buddy push: StartAsBroadcaster/GetActiveBuddy)
#include "kademlia/kademlia/KadV2ModeSelector.h"  // v8.1 D3 — fallback policy
#include "kademlia/kademlia/Kademlia.h"           // Milestone 1 — CKademlia::IsConnected/GetUDPListener
#include "kademlia/net/KademliaUDPListener.h"     // Milestone 1 — SendEseHolePunchReq (LowID hole-punch)
#include "kademlia/routing/RoutingZone.h"         // [eSE v9] selector — GetRandomContact (R-node pick)
#include "kademlia/routing/Contact.h"             // [eSE v9] selector — CContact (IsIpVerified/GetIPAddress)
#include "emule.h"
#include "opcodes.h"
#include "OtherFunctions.h"
#include "Log.h"
#include "UpDownClient.h"
#include "ListenSocket.h"   // CClientReqSocket::IsConnected (dual-dial dedup gate)
#include "LiveCrypto.h"     // v8.1.x — VerifySignature for reassembled V2 chunks
#include "../cryptopp/sha.h" // v8.1.x — SHA256 integrity check for reassembled chunks
#include "Packets.h"
#include "SafeFile.h"
#include "Statistics.h"
#include "Preferences.h"
#include "IPFilter.h"
#include "md4.h"
#include <deque>
#include <shlobj.h>     // Capa 3: SHGetFolderPath for %APPDATA%
#include "ClientList.h"
#include "ClientUDPSocket.h"
#include "eMuleAI/Address.h"  // v0.71 IPv6 Sprint 7 — CAddress in OnPeerListReceivedV6

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

#ifdef ESE_TEST_HOOKS
// eSE TEST-ONLY (rogue node R) — selective live-edge sabotage switches, toggled
// at runtime via /api/live/test/edge_sabotage. Default OFF. Compiled ONLY when
// ESE_TEST_HOOKS is defined project-wide for the attacker build; the honest /
// production binary never defines it and is byte-for-byte unaffected. See
// docs/VALIDATION_3PC_EDGE_PUNCTUALITY.md.
bool  g_eseTestSabotageOn      = false;
int   g_eseTestSabotageMode    = 0;     // 0 = drop, 1 = delay
DWORD g_eseTestSabotageDelayMs = 6000;
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


// R.3 egress + reachability selector gates are now driven by the runtime prefs EseRelayEgress /
// EseReachSelector (default OFF) — see thePrefs. Byte-for-byte dormant until an operator opts in.

CLiveStreamManager::CLiveStreamManager()
    : m_bBroadcasting(false)
    , m_bViewing(false)
    , m_nNextSeqNum(0)
    , m_lastRelayedSeq(UINT_MAX)   // R.3: nothing relayed yet
    , m_dwLastRelaySetup(0)        // R.3
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
    , m_bHlsPlaylistStarted(false) // Phase-1 fix #1
    , m_lastPlayerFetchTick(0)     // ghost-viewer watchdog
    , m_bWebPlayerSession(0)       // ghost-viewer watchdog
    , m_dwLastPeerPrune(0)         // C6 durable-state TTL sweep
    , m_tunnelSourceIP(0)          // C5/C3 tunneled-source endpoint
    , m_tunnelSourcePort(0)
    , m_tunnelSubscribeTick(0)     // C5/C6 self-heal
    , m_tunnelResubCount(0)
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
        AddLogLine(true, GetResString(IDS_LIVEMGR_ALREADY_BROADCASTING));
        return false;
    }

    // v7.6.0 — generate a fresh Ed25519 keypair for this broadcast. The
    // streamKey is the first 16 bytes of sha1(pubkey), so any peer that knows
    // the streamKey can derive the expected pubkey hash and reject forgeries.
    // The old key-from-title-and-timestamp design (#1 in audit) was easily
    // predictable: attacker pre-computes streamKey for popular titles and
    // races the legitimate broadcaster to claim the Kad slot.
    if (!eSELive::GenerateBroadcasterKeypair(m_streamInfo.pubkey, m_broadcasterPrivkey)) {
        AddLogLine(true, GetResString(IDS_LIVEMGR_KEYGEN_FAILED));
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
    // R.3: fresh relay-egress state for this broadcast (clears any stale buddy from a
    // previous stream so RelayPushNewSegments re-negotiates before pushing).
    m_lastRelayedSeq = UINT_MAX;
    m_dwLastRelaySetup = 0;
    CLiveBuddyRelay::Instance().ResetBroadcasterEgress();

    // Make the stream visible immediately; RepublishIfNeeded handles Kad timing.
    InterlockedIncrement(&m_counters.kadPublishes);  // Phase 0: OBS-1 (atomic)
    m_kadBridge.PublishStream(m_streamInfo);

    AddLogLine(true, GetResString(IDS_LIVEMGR_BROADCASTING_FMT),
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
        AddLogLine(true, GetResString(IDS_LIVEMGR_BC_ALREADY_RUNNING));
        return false;
    }
    if (m_rtmpIngest.IsRunning()) {
        AddLogLine(true, GetResString(IDS_LIVEMGR_FFMPEG_ALREADY_RUNNING));
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
            AddLogLine(true, GetResString(IDS_LIVEMGR_MEDIA_NOT_FOUND_FMT),
                (LPCTSTR)mediaFilePath);
            return false;
        }
        started = m_rtmpIngest.StartMediaFile(mediaFilePath, bitrate, tempDir, chunkCb);
    } else if (sourceType.CompareNoCase(_T("rtmp")) == 0) {
        started = m_rtmpIngest.Start(1935, bitrate, tempDir, chunkCb);
    } else {
        AddLogLine(true, GetResString(IDS_LIVEMGR_UNKNOWN_SOURCE_FMT),
            (LPCTSTR)sourceType);
        return false;
    }

    if (!started) {
        AddLogLine(true, GetResString(IDS_LIVEMGR_FFMPEG_START_FAILED));
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
        AddLogLine(true, GetResString(IDS_LIVEMGR_P2P_START_FAILED));
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
    const bool  isRtmpInput  = sourceType.CompareNoCase(_T("rtmp")) == 0;
    const DWORD kMaxWaitMs   = isRtmpInput ? 1500 : 14000;
    const int   kMinChunks   = 3;
    while (GetTickCount() - t0 < kMaxWaitMs && m_rtmpIngest.IsRunning()) {
        if ((int)m_chunkBuffer.GetCount() >= kMinChunks) break;
        Sleep(100);
    }
    if (!m_rtmpIngest.IsRunning()) {
        AddLogLine(true, GetResString(IDS_LIVEMGR_FFMPEG_DIED));
        LIVE_LOG("MGR", "FFmpeg DIED in liveness window — abort broadcast");
        StopBroadcast();
        return false;
    }
    const int bufferedChunks = (int)m_chunkBuffer.GetCount();
    if (bufferedChunks < kMinChunks) {
        if (isRtmpInput) {
            // RTMP is a listener: being alive without chunks means it is
            // correctly armed and waiting for OBS, not that playback is ready.
            LIVE_LOG("MGR", "RTMP ingest armed; waiting for OBS (chunks=%d)", bufferedChunks);
            AddLogLine(true, GetResString(IDS_LIVEMGR_RTMP_WAITING_OBS));
            return true;
        }

        LIVE_LOG("MGR", "Prebuffer TIMEOUT: only %d/%d chunks after %u ms; rolling back",
            bufferedChunks, kMinChunks, GetTickCount() - t0);
        AddLogLine(true, GetResString(IDS_LIVEMGR_PREBUFFER_TIMEOUT));
        m_rtmpIngest.Stop();
        StopBroadcast();
        return false;
    }
    LIVE_LOG("MGR", "Prebuffer ready: %d chunks in buffer after %u ms",
        bufferedChunks, GetTickCount() - t0);

    AddLogLine(true, GetResString(IDS_LIVEMGR_BROADCAST_STARTED_FMT),
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
    // user was both viewing and broadcasting (relay scenario), notify those too.
    {
        POSITION pos = m_viewPeers.GetHeadPosition();
        while (pos) sendEnd(m_viewPeers.GetNext(pos));
    }
    // C6: the old third loop swept m_peerCounters keys as "peers we know" to
    // catch mesh participants in neither list. That map is now keyed by
    // LivePeerId (no recoverable CUpDownClient* to send to), and the two lists
    // above already cover every connected peer, so the sweep is dropped.

    m_kadBridge.UnpublishStream(m_streamInfo.streamKey);

    // Remove the per-stream HLS mirror before the stream key is reused.
    // ResetViewerHlsOutput used to delete only the files and leaked one
    // directory per session under %TEMP%\eMule_RTMP.
    ResetViewerHlsOutput(true);

    m_bBroadcasting = false;
    m_chunkBuffer.Clear();
    m_broadcastPeers.RemoveAll();
    CLiveBuddyRelay::Instance().ResetBroadcasterEgress();   // R.3: drop the relay buddy on stop
    m_peerTrust.RemoveAll();
    m_peerBitmaps.RemoveAll();

    // v7.6.0 — wipe the Ed25519 private key from memory. The pubkey can
    // stick around in m_streamInfo until the next StartBroadcast() overwrites
    // it; only the secret half matters.
    memset(m_broadcasterPrivkey, 0, sizeof m_broadcasterPrivkey);

    // DISC-S04: clear the persisted streamKey marker — graceful shutdown
    // means there's no ghost to clean up on next start.
    theApp.WriteProfileString(_T("eMule"), _T("LiveLastStreamKey"), _T(""));

    AddLogLine(true, GetResString(IDS_LIVEMGR_BROADCAST_STOPPED));
}

void CLiveStreamManager::FeedSegment(const BYTE* data, uint32 dataSize)
{
    CSingleLock lock(&m_lock, TRUE);

    if (!m_bBroadcasting) {
        LIVE_LOG("MGR", "FeedSegment DROP %u bytes — not broadcasting", dataSize);
        return;
    }

    uint32 seqNum = m_nNextSeqNum++;
    // Threat-model vector #4 (clock-skew / wall-clock leak): do NOT stamp the
    // broadcaster's UNIX wall clock onto the wire. seqNum already provides a
    // monotonic, frame-relative ordering. The ts field is kept on the wire
    // (4 bytes — wire compat with vanilla 0.70b-eSE and prior fork builds) but
    // zeroed. Receivers gate the V2-S05 arrival-latency telemetry on
    // `timestamp > 0` (OnChunkReceived), so 0 cleanly self-disables that metric
    // on every version instead of poisoning it with a huge bogus delta — no
    // misbehaviour on old receivers. Cost: chunk-arrival latency telemetry goes
    // dark for new broadcasters; seqNum lag + RTT EWMA still cover liveness. The
    // hardware wall clock no longer leaks to the wire at all.
    uint32 timestamp = 0;

    if (m_chunkBuffer.AddSegment(m_streamInfo.streamKey, seqNum, timestamp,
            data, dataSize, m_streamInfo.bitrate))
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
    m_inflightSegReqs.RemoveAll();  // Phase-1 fix #2
    m_recentDials.RemoveAll();      // churn fix: fresh dial-cooldown table
    m_tunnelSourceIP = 0;           // C3 fix: fresh session, no tunneled source yet
    m_tunnelSourcePort = 0;
    m_tunnelSubscribeTick = 0;      // C5/C6 self-heal
    m_tunnelResubCount = 0;
    // Ghost-viewer watchdog: fresh session — disarm (OnLiveWebJoin re-arms
    // for web joins) and stamp "now" as the grace anchor so discovery +
    // buffering time never counts as player silence.
    InterlockedExchange(&m_bWebPlayerSession, 0);
    InterlockedExchange(&m_lastPlayerFetchTick, (LONG)GetTickCount());
    ResetViewerHlsOutput(true);

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

    AddLogLine(true, GetResString(IDS_LIVEMGR_JOINING_FMT), (LPCTSTR)title);

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
    m_inflightSegReqs.RemoveAll();  // Phase-1 fix #2
    m_recentDials.RemoveAll();      // churn fix
    m_tunnelSourceIP = 0;           // C3 fix
    m_tunnelSourcePort = 0;
    m_tunnelSubscribeTick = 0;      // C5/C6 self-heal
    m_tunnelResubCount = 0;
    InterlockedExchange(&m_bWebPlayerSession, 0);   // ghost-viewer watchdog
    InterlockedExchange(&m_lastPlayerFetchTick, 0);
    ResetViewerHlsOutput(true);

    AddLogLine(true, GetResString(IDS_LIVEMGR_LEFT_STREAM));
    LIVE_LOG("MGR", "LeaveStream");
}

bool CLiveStreamManager::TryConnectToStreamSource(const uchar* streamKey, uint32 ip, uint16 port, uint16 udpPort, uint32 siblingIP)
{
    // v8.1 Sprint C (C5) — privacy-mode handoff. Decide BEFORE taking m_lock:
    // these tunnel calls take the TUNNEL lock with NO manager lock held, so the
    // only cross-lock order in the system stays tunnel->manager (no A-B/B-A).
    // In Tunelizado (and a circuit is up) the SUBSCRIBE is sent through the
    // tunnel — the broadcaster sees the exit, not us — and we suppress the
    // direct subscribe. The chunk DATA plane stays DIRECT in Tunelizado (full
    // data-plane tunneling is Máxima privacidad / Sprint E): we still open a
    // direct socket for OP_LIVE_REQUEST, and the live edge arrives via the C3
    // tunneled-heartbeat relay. Default mode is Adaptive with no keyword ->
    // Direct, so this path is dormant until the Sprint D mode UI enables it.
    // v8.1 D3 — fallback policy when the mode wants a tunnel. Separating "want"
    // from "can" (a circuit is Active) gives the fallback its meaning:
    //   STRICT      -> no circuit means abort (never expose the viewer directly)
    //   BALANCED    -> direct PRIMARY subscribe like BEST_EFFORT, but the SECONDARY
    //                  peer-list fanout is capped (see OnPeerListReceived, D3) so the
    //                  viewer's IP reaches far fewer sources than BEST_EFFORT's full mesh
    //   BEST_EFFORT -> fall to a direct subscribe, but WARN (IP visible to emisor)
    bool useTunnel = false;
    {
        eSELive::CLiveTunnel& tun = eSELive::CLiveTunnel::Get();
        const bool wantTunnel = (streamKey != NULL && ip != 0 && port != 0
                                 && tun.ShouldRouteThroughTunnel(NULL));
        if (wantTunnel) {
            if (tun.ActiveCircuitCount() > 0) {
                useTunnel = true;
                tun.SendLiveSubscribeNoWait(streamKey, ip, port, udpPort, /*altIP*/0);
            } else {
                Kademlia::CKadV2ModeSelector::FallbackPolicy fb =
                    Kademlia::CKadV2ModeSelector::Get().GetFallbackPolicy();
                if (fb == Kademlia::CKadV2ModeSelector::STRICT_PRIVACY) {
                    AddLogLine(true, GetResString(IDS_LIVEMGR_STRICT_NO_TUNNEL));
                    LIVE_LOG("TUN", "D3 STRICT: no tunnel circuit -> abort subscribe (privacy)");
                    return false;
                }
                AddLogLine(true, GetResString(IDS_LIVEMGR_TUNNELED_FALLBACK_DIRECT));
                LIVE_LOG("TUN", "D3 %s: no tunnel circuit -> direct fallback (warned)",
                    fb == Kademlia::CKadV2ModeSelector::BALANCED ? "BALANCED" : "BEST_EFFORT");
            }
        }
    }

    CSingleLock lock(&m_lock, TRUE);

    if (!m_bViewing) return false;

    // C3 fix: remember the tunneled broadcaster endpoint so OnTunneledLiveControl
    // applies the relayed bitmap ONLY to this source, not every view peer.
    // C5/C6 fix: arm the self-heal window for the tunneled subscribe.
    if (useTunnel) {
        m_tunnelSourceIP      = ip;
        m_tunnelSourcePort    = port;
        m_tunnelSubscribeTick = GetTickCount();
        m_tunnelResubCount    = 0;
    }
    if (streamKey == NULL || memcmp(m_streamInfo.streamKey, streamKey, 16) != 0) return false;
    if (ip == 0 || port == 0) return false;
    if (ip == theApp.GetPublicIP()) return false;
    if (theApp.ipfilter->IsFiltered(ip)) return false;

    // Fix 2 (ALTA): Block loopback, LAN, multicast, broadcast via IsGoodIPPort.
    // V2-S07+: in headless mode (stress test on one host) we allow loopback
    // and LAN so all spawned viewers can reach the local broadcaster.
    if (!IsGoodIPPort(ip, port) && !theApp.m_bHeadless) {
        AddLogLine(false, GetResString(IDS_LIVEMGR_REJECTED_NONROUTABLE_FMT),
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
        // Dual-dial churn fix (2026-06): one Kad live record advertises a
        // broadcaster's public IP AND its overlay alt IP (TAG_ESE_LIVE_ALTIP) —
        // ONE machine, ONE user-hash. If we are ALREADY connected on the sibling
        // address, do NOT dial this one: a 2nd inbound session lands on the
        // broadcaster and CClientList::AttachToAlreadyKnown recycles the WORKING
        // socket (the ~6 s JOIN/DISCONNECT churn that rolls segments out of the
        // 16-slot ring -> NO_PEER stalls -> playback cuts). Gate on a LIVE socket
        // so first-contact still races both endpoints; once one is up the other
        // is suppressed; if it later dies IsConnected() goes false and the
        // failover/EnsureMultiParent path re-dials it. siblingIP==0 => no-op,
        // so direct-join callers that don't know the pair are unaffected.
        if (siblingIP != 0 && existing
            && existing->GetIP() == siblingIP
            && existing->GetUserPort() == port
            && existing->socket && existing->socket->IsConnected()) {
            return true;
        }
    }

    // Churn fix (2026-06): per-endpoint dial cooldown. If we dialed this exact
    // (ip,port) within the cooldown, DON'T dial again — re-dialing recycles the
    // peer's CUpDownClient (AttachToAlreadyKnown), tearing down the live socket
    // and truncating the chunk in flight (the JOIN/DISCONNECT churn). This
    // survives the brief m_viewPeers removal during a recycle, which defeats the
    // dedup above. 15 s < the 20 s failover, so a genuinely dead source still
    // gets re-dialed in time. Return true = "we're already handling this source".
    const DWORD ESE_DIAL_COOLDOWN_MS = 15000;
    const uint64 dialKey = ((uint64)ip << 16) | port;
    DWORD lastDial = 0;
    if (m_recentDials.Lookup(dialKey, lastDial)
        && (GetTickCount() - lastDial) < ESE_DIAL_COOLDOWN_MS) {
        return true;
    }
    m_recentDials[dialKey] = GetTickCount();

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

    // UAF FIX (Sprint C adversarial review): add the client to the peer lists
    // BEFORE the connect attempt. SafeConnectAndSendPacket / TryToConnect can
    // `delete this` on a hard-failure path (e.g. LowID with no callback,
    // BaseClient.cpp ~1485) and return. The ~CUpDownClient destructor scrubs
    // these lists via OnPeerDisconnected (the v7.1.8 UAF guard) — but only if
    // the pointer is already IN the lists when the delete happens. The old order
    // (add AFTER connect) inserted a freed pointer that crashed on the next
    // iteration over m_viewPeers/mesh. Adding first makes a delete-during-connect
    // self-cleaning. Pre-existing in the direct path; C5 added a 2nd call site.
    m_viewPeers.AddTail(client);
    m_meshManager.AddMeshPeer(client);
    // Fix 4: Use dedicated sourceDialAttempts instead of duplicate kadResultsAccepted
    InterlockedIncrement(&m_counters.sourceDialAttempts);

    // v8.1 Milestone 1 (LOWID_NAT_TRAVERSAL_PLAN Fase 0) — eSE uTP hole-punch on
    // the Live dial, for a broadcaster that can't open a port (LowID/CGNAT). A
    // Live source is built with the broadcaster's PUBLIC IP, so HasLowID()=false
    // and CUpDownClient::TryToConnect returns at its HighID-TCP branch BEFORE the
    // in-tree punch block (BaseClient.cpp:1556); and that block's SupportsUTP()
    // gate is false at first contact (m_strModVersion/m_nUDPPort are Hello-set,
    // the dial only SetKadPort'd). So the punch never fires for a Live source via
    // TryToConnect. We kick it directly here — the proven WebServer.cpp debug
    // path — BEFORE the connect below (client is still alive; the connect may
    // delete it). Safe to fire for ANY source: InitiateUtpConnect skips a client
    // whose socket is already connected (ClientUDPSocket.cpp:672), so a reachable
    // HighID broadcaster keeps its working TCP socket (no double-socket churn).
    // The queued OP_LIVE_SUBSCRIBE lives in the client's m_WaitingPackets_list
    // (not the socket), so it survives the socket swap and flushes on the HELLO
    // that InitiateUtpConnect sends over the punched pinhole — no re-subscribe.
    // Reuse the client's NAT-rendezvous counter: it auto-resets to 0 on a
    // successful uTP accept (UtpSocket.cpp), so ">=4" means 4 *failed* attempts.
    // The per-endpoint 15 s m_recentDials cooldown above already rate-limits
    // re-entry here, so no extra adaptive cooldown is needed.
    //
    // BUT: never punch an OVERLAY address (Tailscale/CGNAT-shared 100.64.0.0/10).
    // Those are already routable, so the direct TCP connect succeeds — firing the
    // punch there just races a uTP socket in via InitiateUtpConnect, and eMule's
    // uTP uses LEDBAT congestion control that deliberately YIELDS bandwidth,
    // throttling a high-bitrate Live pull (the observed cut at 8000 kbps over
    // Tailscale: fluid on TCP, stalls once uTP grafts). The punch is only needed
    // for a firewalled PUBLIC IP, which is never in 100.64/10 (the broadcaster
    // publishes its real public IP as TAG_SOURCEIP; the overlay is the altIP).
    const uint32 hpHostIP = ntohl(ip);
    const bool hpIsOverlay = ((hpHostIP >> 24) == 100u)
        && (((hpHostIP >> 16) & 0xFFu) >= 64u)
        && (((hpHostIP >> 16) & 0xFFu) <= 127u);
    // [eSE v9] selector key: HOST-order ip (hpHostIP), matching m_escalation / the tick.
    const uint64 escKey = ((uint64)hpHostIP << 16) | port;
	if (udpPort != 0 && !hpIsOverlay
		&& Kademlia::CKademlia::IsConnected()
		&& Kademlia::CKademlia::GetUDPListener() != NULL
		&& thePrefs.GetUtpHolePunchEnabled()
		&& theApp.clientudp != NULL && theApp.clientudp->IsUtpReady())
    {
        if (!thePrefs.GetEseReachSelector()) {
            // LEGACY (pref EseReachSelector OFF) — unchanged parallel 2-way punch. Byte-identical.
            const uint8 ESE_LIVE_SYM_NAT_GIVEUP = 4;
            if (client->m_uNatRendezvousAttempts >= ESE_LIVE_SYM_NAT_GIVEUP) {
                InterlockedIncrement(&CStatistics::m_dwHolePunchSymNATFail);
                LIVE_LOG("HOLE", "Live dial GIVE UP on %S:%u after %u attempts (symmetric NAT?)",
                    (LPCWSTR)ipstr(ip), udpPort, (unsigned)client->m_uNatRendezvousAttempts);
            } else {
                // ip is NETWORK order here; SendEseHolePunchReq wants HOST order
                // (cf. WebServer.cpp / BaseClient.cpp:1596). udpPort is host order.
                if (client->m_uNatRendezvousAttempts < 255) client->m_uNatRendezvousAttempts++;
                client->m_uLastNatRendezvousTick = ::GetTickCount();
                uint16 hpSpread = thePrefs.GetEseHolePunchPortPredict() ? (uint16)thePrefs.GetEseHolePunchPortSpread() : 0;
				Kademlia::CKademlia::GetUDPListener()->SendEseHolePunchReqSpray(ntohl(ip), udpPort, hpSpread,
					client->SupportsReachPunch2() || client->SupportsEseHolePunchCookie(), client);
                LIVE_LOG("HOLE", "Live dial hole-punch attempt #%u to %S:%u",
                    (unsigned)client->m_uNatRendezvousAttempts, (LPCWSTR)ipstr(ip), udpPort);
            }
        } else {
            // SELECTOR (kill-switch ON) — arm the escalation machine at DIRECT (the direct
            // TCP connect below IS stage 0's action). TickReachabilitySelector then drives
            // punch2->punch3->relay on later Process() ticks. Seed once per source.
            ReachState st;
            if (!m_escalation.Lookup(escKey, st)) {
                st.stage = REACH_DIRECT; st.stageEnteredTick = ::GetTickCount(); st.udpPort = udpPort;
                m_escalation[escKey] = st;
                LIVE_LOG("REACH", "selector arm %S:%u stage=DIRECT udp=%u", (LPCWSTR)ipstr(ip), port, udpPort);
            }
        }
    } else if (hpIsOverlay && thePrefs.GetEseReachSelector()) {
        // Overlay (100.64/10) is already routable — never punch/rdv it; mark DONE so the
        // selector ignores it (the cut-at-8000kbps-over-Tailscale lesson).
        ReachState st; st.stage = REACH_DONE; st.stageEnteredTick = ::GetTickCount(); st.udpPort = udpPort;
        m_escalation[escKey] = st;
    }

    bool subSent = false;
    if (!useTunnel) {
        // Direct mode: subscribe directly (broadcaster sees us).
        Packet* pkt = eSELive::CreateSubscribePacket(m_streamInfo.streamKey, thePrefs.GetUserHash(), 0);
        if (pkt) {
            theStats.AddUpDataOverheadOther(pkt->size);
            client->SafeConnectAndSendPacket(pkt);   // may delete client -> destructor scrubs lists
            InterlockedIncrement(&m_counters.subscribeSent);  // Phase 0: OBS-1 (atomic)
            subSent = true;
        }
    } else {
        // C5 Tunelizado: the subscribe went through the tunnel (above). Do NOT
        // send a direct subscribe — only open the socket so RequestMissingSegments
        // can pull chunks directly. The live edge arrives via the C3 relay.
        client->TryToConnect(true);                  // may delete client -> destructor scrubs lists
    }
    // IMPORTANT: `client` may have been freed by the connect above; do NOT touch
    // it past this point. The logging below uses ip/port/udpPort locals only.

    AddLogLine(false, GetResString(IDS_LIVEMGR_DIALING_FMT),
        (LPCTSTR)ipstr(ip), port, udpPort);
    LIVE_LOG("DIAL", "src %S:%u kadUDP=%u  subscribePkt=%s",
        (LPCWSTR)ipstr(ip), port, udpPort, subSent ? "sent" : "FAILED-to-create");
    return true;
}

bool CLiveStreamManager::ExitProxySubscribe(const uchar* streamKey, uint32 ip,
    uint16 port, uint16 udpPort, uint32 altIP)
{
    CSingleLock lock(&m_lock, TRUE);

    if (streamKey == NULL || ip == 0 || port == 0) return false;
    // Never proxy to our own broadcast (we ARE the broadcaster) — that is C7's
    // job (exit-as-multicast-proxy), not a self-dial.
    if (m_bBroadcasting && memcmp(m_streamInfo.streamKey, streamKey, 16) == 0)
        return false;
    if (ip == theApp.GetPublicIP()) return false;

    // Prefer the public endpoint; if it is non-routable, fall back to the
    // overlay endpoint (Tailscale 100.64/10 etc.) the broadcaster published.
    if (!IsGoodIPPort(ip, port) && !theApp.m_bHeadless) {
        if (altIP != 0 && IsGoodIPPort(altIP, port))
            ip = altIP;
        else
            return false;
    }
    if (theApp.ipfilter->IsFiltered(ip)) return false;

    CUpDownClient* client = theApp.clientlist->FindClientByIP(ip, port);
    if (client == NULL) {
        client = new CUpDownClient(NULL, port, ntohl(ip), 0, 0, false);
        client->SetIP(ip);
        theApp.clientlist->AddClient(client);
    }
    if (udpPort != 0)
        client->SetKadPort(udpPort);

    // Subscribe with OUR user-hash: the broadcaster sees the exit, never V.
    // NOT added to m_viewPeers / m_meshManager — this node is not viewing the
    // stream for itself; it is only relaying the subscribe on V's behalf.
    Packet* pkt = eSELive::CreateSubscribePacket(streamKey, thePrefs.GetUserHash(), 0);
    if (!pkt) return false;
    theStats.AddUpDataOverheadOther(pkt->size);
    client->SafeConnectAndSendPacket(pkt);
    InterlockedIncrement(&m_counters.subscribeSent);

    LIVE_LOG("TUN", "C2 exit-proxy SUBSCRIBE -> %S:%u (on viewer's behalf, kadUDP=%u)",
        (LPCWSTR)ipstr(ip), (unsigned)port, (unsigned)udpPort);
    return true;
}

void CLiveStreamManager::ExitProxyUnsubscribe(const uchar* streamKey, uint32 ip, uint16 port)
{
    CSingleLock lock(&m_lock, TRUE);
    if (streamKey == NULL || ip == 0 || port == 0) return;
    CUpDownClient* client = theApp.clientlist->FindClientByIP(ip, port);
    if (client == NULL) return;   // connection already gone — nothing to do
    Packet* pkt = eSELive::CreateUnsubscribePacket(streamKey, thePrefs.GetUserHash());
    if (!pkt) return;
    theStats.AddUpDataOverheadOther(pkt->size);
    client->SafeConnectAndSendPacket(pkt);   // may delete client; we don't touch it after
    LIVE_LOG("TUN", "C4 exit-proxy UNSUBSCRIBE -> %S:%u (last tunneled viewer left)",
        (LPCWSTR)ipstr(ip), (unsigned)port);
}

void CLiveStreamManager::OnTunneledLiveControl(const uchar* streamKey,
    bool hasBitmap, uint16 bitmap, uint32 oldestSeq, const uchar* pubkeyOrNull)
{
    CSingleLock lock(&m_lock, TRUE);
    if (streamKey == NULL) return;

    // Pin the broadcaster pubkey relayed from an announce, so signed chunks /
    // END packets verify against it (same as the direct OP_LIVE_ANNOUNCE path).
    if (pubkeyOrNull && eSELive::StreamKeyMatchesPubkey(streamKey, pubkeyOrNull))
        PinStreamPubkey(streamKey, pubkeyOrNull);

    if (!hasBitmap) return;
    if (!m_bViewing || memcmp(m_streamInfo.streamKey, streamKey, 16) != 0) return;

    // C3 bridge (Tunelizado): the subscribe was tunneled, so the broadcaster
    // sends its heartbeats to the EXIT, not to us — we'd otherwise never learn
    // the live edge. Apply the relayed bitmap to our DIRECT view peer(s) for
    // this stream so SelectPeerForSegment can pull chunks directly (data plane
    // stays direct in Tunelizado; full-tunnel data is Sprint E). Feed the
    // watchdog and kick a pull at the new edge.
    PeerBitmapInfo info;
    info.bitmap     = bitmap;
    info.oldestSeq  = oldestSeq;
    info.lastUpdate = GetTickCount();
    m_dwLastLiveActivity = info.lastUpdate;

    // C3 fix: apply the relayed broadcaster edge ONLY to the tunneled source
    // peer (matched by the endpoint we tunnel-subscribed to), NOT to every view
    // peer. Secondary sources dialed via OP_LIVE_PEER_LIST carry their OWN real,
    // per-peer-anchored bitmaps via OnPeerBitmap; stamping the broadcaster's
    // window onto them would misrepresent what they hold and waste requests.
    int applied = 0;
    POSITION pos = m_viewPeers.GetHeadPosition();
    while (pos) {
        CUpDownClient* peer = m_viewPeers.GetNext(pos);
        if (!peer) continue;
        // Only the tunneled broadcaster source. If we never recorded an endpoint
        // (shouldn't happen when a tunneled heartbeat arrives), apply to none.
        if (m_tunnelSourceIP == 0
            || peer->GetIP() != m_tunnelSourceIP
            || peer->GetUserPort() != m_tunnelSourcePort)
            continue;
        m_peerBitmaps[PeerId(peer)] = info;
        GetOrCreateTrust(peer);    // stamp lastSeen for the C6 prune
        applied++;
    }
    if (applied > 0) {
        uint32 newest = info.NewestSeq();
        if (newest > 0) m_meshManager.OnSegmentAnnounced(newest);
        LIVE_LOG("TUN", "C3 tunneled heartbeat bitmap=0x%04x oldest=%u -> %d source peer(s)",
            bitmap, oldestSeq, applied);
    }
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

void CLiveStreamManager::ResetViewerHlsOutput(bool removeDirectory)
{
    CString dir = GetLiveHlsDir();
    if (!removeDirectory)
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

    if (removeDirectory) {
        // The directory should now contain only files unknown to this version
        // (if any). In that case RemoveDirectory safely fails and preserves
        // them; normal LiveTV directories are removed completely.
        RemoveDirectory(dir);
    }

    // Phase-1 fix #1: new session, re-arm the startup-only buffer gate.
    m_bHlsPlaylistStarted = false;
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

    // Phase 3 HLS-2 / Phase 2 LAT-3 / Phase-1 fix #1 (2026-06): buffer
    // minimum gate, STARTUP-ONLY. Require 2 contiguous trailing segments
    // (2 s each = 4 s of material) before the FIRST playlist write, so the
    // player doesn't start on a sliver. Once playback has started the gate
    // no longer applies: it used to run on every refresh, and because
    // `contiguous` resets to 0 on each hole it measured the TRAILING run —
    // any gap near the live edge froze the playlist for 2-4 s even with a
    // full buffer behind it. VLC, playing at the live edge, saw a stalled
    // playlist => micro-cut with no network cause. Post-start gaps are
    // handled below via #EXT-X-DISCONTINUITY instead.
    if (!m_bHlsPlaylistStarted) {
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
        m_bHlsPlaylistStarted = true;  // Phase-1 fix #1: gate is startup-only
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

    AddLogLine(false, GetResString(IDS_LIVEMGR_PEER_JOINED_FMT),
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

        // PUSH/PULL dedup (2026-06): the viewer already PULLs missing segments
        // (ASK -> OP_LIVE_REQUEST). On a RE-subscribe (~12 s cadence, past the
        // push cooldown) the live-edge segments we'd push are ones it already has
        // and ACK'd, so the push is a wasted ~2-3 MB burst that competes with the
        // live pull (the periodic ms stutter). Consult the viewer's last-known
        // bitmap (recorded every ~1 s by OnPeerBitmap; GetPeerBitmap is a lockless
        // map lookup) and skip segments it reports having. First subscribe = no
        // recorded bitmap -> haveVbm false -> push all (bootstrap preserved). A
        // stale/missing bitmap degrades to today's push, and the viewer's own PULL
        // still fetches anything truly missing, so this never withholds data.
        PeerBitmapInfo vbm;
        const bool haveVbm = GetPeerBitmap(peer, vbm);

        // v7.5.0 — WithSegment serializes the read against AddSegment; previous
        // code held the LiveStreamManager m_lock but NOT the chunk buffer's
        // own m_lock, so AddSegment from the broadcaster thread could free
        // the slot between GetSegment() and CreateChunkPacket()'s memcpy.
        // CreateChunkPacket copies the bytes, so once it returns the Packet is
        // self-contained and safe to use after the buffer's lock releases.
        // v8.1.x — fragment oversized segments if the viewer can reassemble.
        const bool peerFrag = peer && (peer->GetEseCapabilities() & ESE_CAP_LIVE_CHUNK_FRAG) != 0;
        CArray<Packet*> pushBatch;   // may hold >1 packet per segment when fragmented
        uint64 totalBytes = 0;
        int segsPushed = 0;
        for (uint32 seq = startSeq; seq <= newest; ++seq) {
            if (haveVbm && vbm.Has(seq)) continue;   // viewer already has it -> don't re-push
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
            eSELive::AppendChunkSendPackets(chunkPkt, peerFrag, pushBatch);  // takes ownership
            totalBytes += chunkSize;
            segsPushed++;
        }

        // Update trust + mesh counters under the lock (per SEGMENT, not per packet).
        trust.requestsServed += (uint32)segsPushed;
        for (int i = 0; i < segsPushed; ++i) {
            m_meshManager.IncrementChunksServed();
        }
        if (segsPushed > 0)
            m_meshManager.TrackUpload(peer, (uint32)totalBytes);

        pushed = segsPushed;

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
            GetResString(IDS_LIVEMGR_PUSHED_INITIAL_FMT),
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
            AddLogLine(false, GetResString(IDS_LIVEMGR_RATELIMIT_FMT),
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
    PeerCounters& pcReq = m_peerCounters[PeerId(peer)];
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

#ifdef ESE_TEST_HOOKS
    // TEST-ONLY: selective live-edge sabotage. Drops or defers serving any
    // segment within ESE_LIVE_EDGE_GUARD of OUR live edge — exactly the blocks
    // the victim needs imminently — while serving backfill normally so we keep
    // earning trust. Reproduces the "earn trust, then drop the critical block"
    // attack (threat-model vector #3) for the 3-PC validation recipe.
    if (chunkPkt && g_eseTestSabotageOn) {
        const uint32 myEdge = m_chunkBuffer.GetNewestSeq();
        if (seqNum + ESE_LIVE_EDGE_GUARD >= myEdge) {           // edge-critical
            if (g_eseTestSabotageMode == 0) {                   // DROP
                LIVE_LOG("TEST", "SABOTAGE-DROP edge seq=%u -> %S", seqNum,
                    peer ? (LPCWSTR)ipstr(peer->GetIP()) : L"?");
                delete chunkPkt;                                // we still own it here
                return;
            }
            // DELAY: hand ownership to the deferred queue (flushed in Process()).
            TestDeferredSend d;
            d.peer = peer; d.pkt = chunkPkt;
            d.fireTick = GetTickCount() + g_eseTestSabotageDelayMs;
            m_testDeferredSends.push_back(d);
            LIVE_LOG("TEST", "SABOTAGE-DELAY edge seq=%u +%ums -> %S", seqNum,
                g_eseTestSabotageDelayMs, peer ? (LPCWSTR)ipstr(peer->GetIP()) : L"?");
            return;
        }
    }
#endif

    // Send the chunk data to the peer. v7.5.0: chunkPkt was built inside the
    // WithSegment lambda above using a now-released copy of the bytes, so it's
    // safe to use without any buffer lock; chunkSize is a captured uint32.
    if (chunkPkt) {
        // v8.1.x — fragment if oversized and the peer can reassemble; else send
        // the single packet unchanged. AppendChunkSendPackets takes ownership of
        // chunkPkt (do NOT touch it after this call).
        const bool peerFrag = peer && (peer->GetEseCapabilities() & ESE_CAP_LIVE_CHUNK_FRAG) != 0;
        CArray<Packet*> sendBatch;
        eSELive::AppendChunkSendPackets(chunkPkt, peerFrag, sendBatch);
        for (INT_PTR si = 0; si < sendBatch.GetCount(); ++si) {
            theStats.AddUpDataOverheadOther(sendBatch[si]->size);
            peer->SendPacket(sendBatch[si]);
        }
        m_meshManager.TrackUpload(peer, chunkSize);
        // Fix 5: Actually count active uploads so /api/live/debug isn't always 0
        m_meshManager.IncrementChunksServed();

        // V2-S01/S02: per-peer counters (under m_lock — already held).
        DWORD nowTick = GetTickCount();
        PeerCounters& pc = m_peerCounters[PeerId(peer)];
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

// v8.1.x — verify+ingest one WHOLE inner chunk payload (V1 OP_LIVE_CHUNK or V2
// OP_LIVE_CHUNK_V2), whether it arrived as a single packet (ListenSocket) or was
// reassembled from OP_LIVE_CHUNK_FRAG fragments. The verify path is identical to
// (and supersedes) the inline ListenSocket handlers, so signature/integrity
// checks run exactly ONCE over the full segment.
void CLiveStreamManager::IngestChunkPayload(CUpDownClient* peer, uint8 innerOpcode,
    const BYTE* body, uint32 bodyLen)
{
    if (body == NULL) return;

    // v8.1.2 E3.1 — if we exit-proxy this stream for tunneled viewers, capture the WHOLE
    // signed record and hand it to the bulk data plane (FEC-encode + push) instead of the
    // viewer/HLS path. streamKey is the first 16 bytes of the record (both V1 and V2). The
    // exit forwards opaque bytes — the verify runs once on the viewer (IngestChunkPayload).
    // GUARD: do NOT divert a stream WE are viewing ourselves — otherwise the viewer's own
    // bulk re-inject (DeliverBulkData -> IngestChunkPayload) would re-divert in an infinite
    // loop, AND a node that is both exit+viewer would stop playing. Only PURE exits divert.
    if (bodyLen >= 16
        && !(m_bViewing && memcmp(m_streamInfo.streamKey, body, 16) == 0)
        && eSELive::CLiveTunnel::Get().IsExitProxying(body)) {
        eSELive::CLiveTunnel::Get().ExitProxyOnWholeChunk(body, body, bodyLen);
        return;
    }

    if (innerOpcode == OP_LIVE_CHUNK) {
        // V1: streamKey(16)+seqNum(4)+ts(4)+chunkSize(4)+data
        if (bodyLen < 28) return;
        CSafeMemFile data(const_cast<BYTE*>(body), bodyLen);
        uchar streamKey[16];
        data.ReadHash16(streamKey);
        uint32 seqNum    = data.ReadUInt32();
        uint32 timestamp = data.ReadUInt32();
        uint32 chunkSize = data.ReadUInt32();
        if (chunkSize > bodyLen - 28 || chunkSize > eSELive::ESE_FRAG_MAX_TOTAL) return;
        OnChunkReceived(peer, streamKey, seqNum, timestamp, body + 28, chunkSize);
        return;
    }

    if (innerOpcode == OP_LIVE_CHUNK_V2) {
        // V2: streamKey(16)+seqNum(4)+ts(4)+dataSize(4)+bitrate(2)+sha256(32)+sig(64)+data
        if (bodyLen < 126) return;
        CSafeMemFile data(const_cast<BYTE*>(body), bodyLen);
        uchar streamKey[16];
        data.ReadHash16(streamKey);
        uint32 seqNum    = data.ReadUInt32();
        uint32 timestamp = data.ReadUInt32();
        uint32 chunkSize = data.ReadUInt32();
        /*uint16 bitrate =*/ data.ReadUInt16();
        uchar digest[32]; data.Read(digest, 32);
        uchar sig[64];    data.Read(sig, 64);
        if (chunkSize > bodyLen - 126 || chunkSize > eSELive::ESE_FRAG_MAX_TOTAL) return;
        const BYTE* chunkData = body + 126;

        uchar pubkey[32];
        if (!GetPinnedPubkey(streamKey, pubkey)) return;

        // Integrity: sha256(data) == digest (cheap; amortises the signature cost).
        {
            CryptoPP::SHA256 hash;
            uchar computed[32];
            hash.CalculateDigest(computed, chunkData, chunkSize);
            if (memcmp(computed, digest, 32) != 0) {
                AddLogLine(true, GetResString(IDS_LIVEMGR_DIGEST_MISMATCH_FMT), seqNum);
                return;
            }
        }
        // Signature over (streamKey || seqNum || digest).
        {
            uchar signMsg[16 + 4 + 32];
            memcpy(signMsg, streamKey, 16);
            memcpy(signMsg + 16, &seqNum, 4);
            memcpy(signMsg + 20, digest, 32);
            if (!eSELive::VerifySignature(pubkey, signMsg, sizeof signMsg, sig)) {
                AddLogLine(true, GetResString(IDS_LIVEMGR_BAD_SIGNATURE_FMT), seqNum);
                return;
            }
        }
        OnChunkReceived(peer, streamKey, seqNum, timestamp, chunkData, chunkSize);
        return;
    }
    // Unknown inner opcode — drop silently.
}

// v8.1.x — accumulate a fragment of an oversized chunk. On the last fragment,
// the reassembled buffer is byte-identical to the inner V1/V2 payload, fed to
// IngestChunkPayload (verify runs once). Bounded + TTL-swept; a lost fragment
// just drops the segment and the normal pull re-requests it.
void CLiveStreamManager::OnChunkFragmentReceived(CUpDownClient* peer, const uchar* streamKey,
    uint32 seqNum, uint16 fragIndex, uint16 fragCount, uint8 innerOpcode,
    uint32 totalLen, const BYTE* fragData, uint32 fragLen)
{
    CSingleLock lock(&m_lock, TRUE);

    // v8.1.2 E3.1 — exit-proxy divert BEFORE the viewer gate: a fragment for a stream we
    // exit-proxy goes to the tunnel's own headless reassembler (the viewer path below is
    // m_bViewing-gated + single-stream). Touches only the tunnel's leaf-locked queue, so the
    // documented tunnel->manager lock order is preserved (no tunnel m_lock taken here).
    // GUARD: never divert a stream WE are viewing (see OnChunkReceived/IngestChunkPayload) —
    // a node that is both exit+viewer keeps playing normally; only PURE exits divert.
    if (!(m_bViewing && memcmp(m_streamInfo.streamKey, streamKey, 16) == 0)
        && eSELive::CLiveTunnel::Get().IsExitProxying(streamKey)) {
        eSELive::CLiveTunnel::Get().ExitProxyOnFragment(streamKey, seqNum, fragIndex, fragCount,
            totalLen, fragData, fragLen);
        return;
    }

    if (!m_bViewing) return;
    if (memcmp(m_streamInfo.streamKey, streamKey, 16) != 0) {
        LIVE_LOG("FRAG", "DROP seq=%u — wrong key", seqNum);
        return;
    }

    // Validate the header BEFORE allocating anything (defends against a peer
    // announcing a huge totalLen / fragCount to exhaust memory).
    if (fragCount < 1 || fragCount > eSELive::ESE_FRAG_MAX_COUNT) return;
    if (fragIndex >= fragCount) return;
    if (totalLen == 0 || totalLen > eSELive::ESE_FRAG_MAX_TOTAL) return;
    if (innerOpcode != OP_LIVE_CHUNK_V2 && innerOpcode != OP_LIVE_CHUNK) return;
    const uint32 expectCount = (totalLen + eSELive::ESE_FRAG_PAYLOAD - 1) / eSELive::ESE_FRAG_PAYLOAD;
    if ((uint32)fragCount != expectCount) return;
    const uint32 expectLen = (fragIndex == fragCount - 1)
        ? (totalLen - (uint32)(fragCount - 1) * eSELive::ESE_FRAG_PAYLOAD)
        : eSELive::ESE_FRAG_PAYLOAD;
    if (fragLen != expectLen || fragLen > eSELive::ESE_FRAG_PAYLOAD || fragData == NULL) return;

    const DWORD now = GetTickCount();
    std::pair<LivePeerId, uint32> key(PeerId(peer), seqNum);
    std::map<std::pair<LivePeerId, uint32>, FragReasm, FragKeyLess>::iterator it = m_fragReasm.find(key);

    if (it != m_fragReasm.end()) {
        // Broadcaster re-sent this seq with a different shape (VBR restart) — reset.
        if (it->second.fragCount != fragCount || it->second.totalLen != totalLen
            || it->second.innerOpcode != innerOpcode) {
            m_fragReasm.erase(it);
            it = m_fragReasm.end();
        }
    }
    if (it == m_fragReasm.end()) {
        // Bound concurrent reassemblies — evict the oldest partial first.
        if ((int)m_fragReasm.size() >= eSELive::ESE_FRAG_MAX_CONCURRENT) {
            std::map<std::pair<LivePeerId, uint32>, FragReasm, FragKeyLess>::iterator oldest = m_fragReasm.begin();
            for (std::map<std::pair<LivePeerId, uint32>, FragReasm, FragKeyLess>::iterator i2 = m_fragReasm.begin();
                 i2 != m_fragReasm.end(); ++i2)
                if ((LONG)(i2->second.firstSeenTick - oldest->second.firstSeenTick) < 0)
                    oldest = i2;
            m_fragReasm.erase(oldest);
        }
        FragReasm fr;
        fr.innerOpcode   = innerOpcode;
        fr.totalLen      = totalLen;
        fr.fragCount     = fragCount;
        fr.haveCount     = 0;
        fr.buf.resize(totalLen);
        fr.got.assign(fragCount, false);
        fr.firstSeenTick = now;
        it = m_fragReasm.insert(std::make_pair(key, std::move(fr))).first;
    }

    FragReasm& fr = it->second;
    if (fr.got[fragIndex]) {
        LIVE_LOG("FRAG", "DUP-FRAG seq=%u idx=%u", seqNum, (unsigned)fragIndex);
        return;
    }
    memcpy(fr.buf.data() + (uint32)fragIndex * eSELive::ESE_FRAG_PAYLOAD, fragData, fragLen);
    fr.got[fragIndex] = true;
    fr.haveCount++;

    if (fr.haveCount == fr.fragCount) {
        // Complete: move the buffer out, drop the map entry, verify+ingest once.
        std::vector<uint8> full(std::move(fr.buf));
        const uint8  innerOp = fr.innerOpcode;
        const uint32 len     = fr.totalLen;
        m_fragReasm.erase(it);
        LIVE_LOG("FRAG", "COMPLETE seq=%u (%u bytes, %u frags)", seqNum, len, (unsigned)fragCount);
        IngestChunkPayload(peer, innerOp, full.data(), len);
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
    // Phase-1 fix #2: whatever pull was pending for this seq is now moot —
    // the chunk arrived (requested or pushed). Clear it so the next
    // RequestMissingSegments cycle doesn't count it as in flight.
    // Threat-model vector #3: snapshot whether this segment was edge-critical
    // before we drop the in-flight record, so we can reward on-time delivery.
    bool wasEdgeCritical = false;
    {
        InflightSegReq doneReq;
        if (m_inflightSegReqs.Lookup(seqNum, doneReq))
            wasEdgeCritical = doneReq.edgeCritical;
    }
    m_inflightSegReqs.RemoveKey(seqNum);

    // Phase-1 fix #3: AddSegment now reports whether the chunk was actually
    // stored. A rejected chunk (duplicate or stale late arrival) is wasted
    // bytes: don't rewrite the HLS file, don't credit the sender's trust,
    // and above all do NOT re-relay it — the V2-S21 push below would fan
    // the duplicate out to every child again (amplification per dup).
    if (!m_chunkBuffer.AddSegment(streamKey, seqNum, timestamp,
            data, dataSize, m_streamInfo.bitrate)) {
        InterlockedIncrement(&m_counters.duplicateChunksReceived);
        m_meshManager.FulfillRequest(seqNum);
        LIVE_LOG("RECV", "DUP seq=%u — dropped (no HLS rewrite, no relay)", seqNum);
        return;
    }
    WriteViewerHlsSegment(seqNum, data, dataSize);

    // Update trust for the sending peer
    PeerTrust& trust = GetOrCreateTrust(peer);
    trust.bytesServed += dataSize;  // Peer served us these bytes

    // Threat-model vector #3: reward on-time delivery of a CRITICAL (near-
    // playhead) block — the ONLY way a peer works off accumulated punctuality
    // failures. Backfill deliveries earn nothing, so a peer that serves cheap
    // far-ahead blocks but keeps dropping the imminent one cannot decay its way
    // back to a clean failCount.
    if (wasEdgeCritical && trust.failCount > 0)
        trust.failCount--;

    // V2-S01/S02: per-peer counters (we already hold m_lock).
    PeerCounters& pc = m_peerCounters[PeerId(peer)];
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
    //
    // Phase-1 fix #4 (2026-06) — packets are built and accounting updated
    // under m_lock, but the socket sends are deferred to after the lock is
    // released (same snapshot-then-act pattern as the initial push in
    // OnPeerJoin and the BuildDebugSnapshot deadlock fix): N sends of a
    // ~500 KB chunk under the manager lock stalled FeedSegment/Process on
    // contention. Child pointers stay valid across the unlock because
    // CUpDownClient deletion only happens on this same (main) thread.
    struct RelayOut { CUpDownClient* child; Packet* pkt; };
    std::vector<RelayOut> relayPkts;
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
            POSITION cpos = m_broadcastPeers.GetHeadPosition();
            while (cpos && (relayMax <= 0 || (int)relayPkts.size() < relayMax)) {
                CUpDownClient* child = m_broadcastPeers.GetNext(cpos);
                if (!child) continue;
                if (child == peer) continue;  // do not bounce back to source
                // v8.1.1 dedup — skip the proactive relay-push to a child that is
                // ALSO one of OUR sources (m_viewPeers). In a mutual mesh (V<->X both
                // pull from each other) that child independently PULLs the same stream,
                // so this push just races its own pull and lands as a "REJECT duplicate"
                // — about half the bandwidth wasted at high bitrate. It still PULLs from
                // us anything it genuinely lacks (failover intact), so data is never
                // withheld. Children that are NOT our sources (pure leaves) still get
                // the proactive push.
                if (m_viewPeers.Find(child) != NULL) continue;
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
                m_meshManager.TrackUpload(child, storedSize);
                m_meshManager.IncrementChunksServed();

                // Update per-child counters as if they had requested.
                PeerCounters& ccp = m_peerCounters[PeerId(child)];
                ccp.MaybeResetWindow(nowTick);
                ccp.bytes_out_total      += storedSize;
                ccp.bytes_out_window_60s += storedSize;
                ccp.chunks_served++;
                ccp.last_chunk_sent_ms = nowTick;

                // Defer the actual send to after m_lock is released. The
                // packet owns its own serialized copy of the chunk, so it
                // stays valid after bodyCopy goes out of scope.
                // v8.1.x — fragment for this child if it can reassemble; else one
                // packet as today. AppendChunkSendPackets takes ownership of pkt.
                const bool childFrag = (child->GetEseCapabilities() & ESE_CAP_LIVE_CHUNK_FRAG) != 0;
                CArray<Packet*> childBatch;
                eSELive::AppendChunkSendPackets(pkt, childFrag, childBatch);
                for (INT_PTR bi = 0; bi < childBatch.GetCount(); ++bi) {
                    RelayOut out;
                    out.child = child;
                    out.pkt   = childBatch[bi];
                    relayPkts.push_back(out);
                }
            }
            localView.data = NULL;  // disown so LiveChunk dtor doesn't free
        }
    }

    // Notify mesh manager that this request is fulfilled
    m_meshManager.FulfillRequest(seqNum);

    // Phase-1 fix #4: sends happen with m_lock released.
    lock.Unlock();
    for (size_t i = 0; i < relayPkts.size(); ++i) {
        theStats.AddUpDataOverheadOther(relayPkts[i].pkt->size);
        relayPkts[i].child->SendPacket(relayPkts[i].pkt, true);  // bVerifyConnection: skip dead sockets
    }
    if (!relayPkts.empty())
        LIVE_LOG("RELAY", "PUSH seq=%u to %d child(ren)", seqNum, (int)relayPkts.size());
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
        // C6 finish: OnPeerDisconnected (fires on the AttachToAlreadyKnown swap)
        // also evicted this peer from the pointer-keyed mesh via RemoveMeshPeer,
        // but only m_broadcastPeers was restored above. Restore mesh membership
        // too so GetMeshPeerCount / the (dormant) rarest-first scheduler stay
        // consistent. AddMeshPeer is idempotent (IsMeshPeer guard, no counter
        // resets), so this cannot double-add.
        m_meshManager.AddMeshPeer(peer);
        LIVE_LOG("PEER", "REJOIN viewer=%S:%u (heartbeat after ClientList swap) total=%u",
            (LPCWSTR)ipstr(peer->GetIP()), (unsigned)peer->GetUserPort(),
            m_streamInfo.viewerCount);
    }
    if (m_bViewing && m_viewPeers.Find(peer) == NULL) {
        m_viewPeers.AddTail(peer);
        // C6 finish: restore mesh membership lost to the swap's RemoveMeshPeer
        // (see the broadcaster branch above). Idempotent, side-effect-free on add.
        m_meshManager.AddMeshPeer(peer);
        LIVE_LOG("PEER", "REJOIN source=%S:%u (heartbeat after ClientList swap) total=%d",
            (LPCWSTR)ipstr(peer->GetIP()), (unsigned)peer->GetUserPort(),
            (int)m_viewPeers.GetCount());
    }

    // Phase 1 BOOT-1: persist BOTH bitmap and oldestSeq.
    // The bitmap bit positions are anchored at the peer's oldestSeq, not ours.
    // C6: keyed by durable LivePeerId so the bitmap survives the AttachToAlready
    // Known pointer swap (the new object's heartbeats land on the SAME entry,
    // so the viewer never goes "blind" and re-requests everything = micro-cut).
    PeerBitmapInfo info;
    info.bitmap     = bitmap;
    info.oldestSeq  = oldestSeq;
    info.lastUpdate = GetTickCount();
    m_peerBitmaps[PeerId(peer)] = info;
    // C6: ensure a durable trust record exists and stamp its lastSeen so the
    // TTL prune treats this identity as alive (covers bitmap-only peers).
    GetOrCreateTrust(peer);
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
            GetResString(IDS_LIVEMGR_BOOTSTRAP_FMT),
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
    // C2/C3 (Sprint C finish): if THIS node is an exit proxying `streamKey` for
    // tunneled viewers, relay the broadcaster's peer-list down their circuits
    // BEFORE taking m_lock. The tunnel call takes tunnel locks; holding the
    // manager m_lock here would invert the tunnel->manager-only order. ExitRelay
    // PeerList is a no-op if we proxy no one for this stream, so this is cheap on
    // a normal (non-exit) viewer too. ips are net-order DWORDs (value-preserving).
    {
        int n = (int)ips.GetCount();
        if (n > (int)ports.GetCount()) n = (int)ports.GetCount();
        if (n > 16) n = 16;
        if (n > 0) {
            uint32_t ipBuf[16]; uint16_t portBuf[16];
            for (int i = 0; i < n; ++i) { ipBuf[i] = (uint32_t)ips[i]; portBuf[i] = ports[i]; }
            eSELive::CLiveTunnel::Get().ExitRelayPeerList(streamKey, ipBuf, portBuf, (uint8_t)n);
        }
    }

    CSingleLock lock(&m_lock, TRUE);

    if (!m_bViewing) return;
    if (memcmp(m_streamInfo.streamKey, streamKey, 16) != 0) return;
    LIVE_LOG("MESH", "Received peer-list (%d entries)", (int)ips.GetCount());

    // C2/C3 finish: in Tunelizado the SUBSCRIBE to each secondary source must be
    // tunneled too (the exit proxy-subscribes on our behalf), symmetric with the C5
    // primary path — otherwise we would hand every secondary source a direct
    // user-hash<->stream<->IP association that the primary deliberately withholds.
    // SendLiveSubscribeNoWait only takes the leaf m_mtLock, so it is safe to call
    // under m_lock (exactly as the C5 self-heal does). NOTE: the DATA plane stays
    // DIRECT in Tunelizado, so V's IP is still visible to every source it fetches
    // chunks from (primary and secondary) — full data-plane tunneling is Sprint E.
    // In Direct mode this is unchanged (direct subscribe).
    auto& tun = eSELive::CLiveTunnel::Get();
    const bool wantTunnel  = tun.ShouldRouteThroughTunnel(NULL);
    const bool haveCircuit = tun.ActiveCircuitCount() > 0;
    const bool tunMode = wantTunnel && haveCircuit;
    // v8.1 D3 BALANCED - "Tunelizado wanted, no circuit, BALANCED fallback policy": the
    // viewer must still watch (direct primary), but must NOT amplify its IP exposure across
    // the whole peer-list. Cap the secondary fanout to the resilience floor so BALANCED stays
    // narrow while BEST_EFFORT expands to the full mesh. (STRICT never reaches here — it aborts
    // the primary in TryConnectToStreamSource before any view peer exists.)
    const bool balancedDegraded = wantTunnel && !haveCircuit
        && Kademlia::CKadV2ModeSelector::Get().GetFallbackPolicy()
               == Kademlia::CKadV2ModeSelector::BALANCED;
    static const int kBalancedFanoutCap = 3;

    for (INT_PTR i = 0; i < ips.GetCount(); i++) {
        DWORD ip = ips[i];
        uint16 port = ports[i];

        // v8.1 D3 BALANCED - stop amplifying fanout past the cap in the degraded state, so a
        // BALANCED viewer with no circuit exposes its IP to far fewer secondary sources than
        // a BEST_EFFORT viewer (which keeps the full peer-list mesh).
        if (balancedDegraded && (int)m_viewPeers.GetCount() >= kBalancedFanoutCap) {
            LIVE_LOG("TUN", "D3 BALANCED: secondary-fanout cap (%d) reached, skip rest of peer-list",
                kBalancedFanoutCap);
            break;
        }

        // Skip our own IP
        if (ip == theApp.GetPublicIP()) continue;

        // Skip only this exact endpoint. Several independent peers may share
        // one public address behind CGNAT; IP alone is not an identity.
        bool alreadyConnected = false;
        POSITION pos2 = m_viewPeers.GetHeadPosition();
        while (pos2) {
            CUpDownClient* existing = m_viewPeers.GetNext(pos2);
            if (existing && existing->GetIP() == ip && existing->GetUserPort() == port) {
                alreadyConnected = true;
                break;
            }
        }
        if (alreadyConnected) continue;

        // Check IPFilter
        if (theApp.ipfilter->IsFiltered(ip)) continue;

        // Try to find or create a client for this peer. Peer-list IPs are stored in network order.
        CUpDownClient* newClient = theApp.clientlist->FindClientByIP(ip, port);
        if (newClient == NULL) {
            newClient = new CUpDownClient(NULL, port, ntohl(ip), 0, 0, false);
            newClient->SetIP(ip);
            theApp.clientlist->AddClient(newClient);
        }
        // UAF-safe ordering (matches the C5 fix in TryConnectToStreamSource): add to
        // the view/mesh lists BEFORE the connect, because SafeConnectAndSendPacket /
        // TryToConnect can `delete this` on a LowID hard-fail and ~CUpDownClient ->
        // OnPeerDisconnected scrubs these lists — self-cleaning only if the pointer is
        // already IN them. The old order (add after connect) inserted a freed pointer.
        if (m_viewPeers.Find(newClient) == NULL)
            m_viewPeers.AddTail(newClient);
        m_meshManager.AddMeshPeer(newClient);

        if (tunMode) {
            // Tunelizado: tunnel the subscribe to this secondary source (exit
            // subscribes on our behalf — the source sees the exit, not us), then open
            // the direct data socket so chunks can be pulled (data plane direct).
            eSELive::CLiveTunnel::Get().SendLiveSubscribeNoWait(
                m_streamInfo.streamKey, ip, port, 0, 0);
            newClient->TryToConnect(true);   // may delete newClient -> destructor scrubs lists
        } else {
            // Direct: subscribe directly (the source sees us).
            Packet* pkt = eSELive::CreateSubscribePacket(
                m_streamInfo.streamKey, thePrefs.GetUserHash(), 0);
            if (pkt) {
                theStats.AddUpDataOverheadOther(pkt->size);
                newClient->SafeConnectAndSendPacket(pkt);   // may delete newClient
            }
        }
        // do NOT touch newClient past this point (it may have been freed by the connect)
        AddLogLine(false, GetResString(IDS_LIVEMGR_SUBSCRIBED_FMT),
            (LPCTSTR)ipstr(ip), port, tunMode ? (LPCTSTR)GetResString(IDS_LIVEMGR_MODE_TUNNELED) : (LPCTSTR)GetResString(IDS_LIVEMGR_MODE_DIRECT));
    }
}

// v8.1 Sprint C (C2/C3 finish) — a tunneled viewer received the broadcaster's
// peer-list relayed by the exit (TUN_OP_LIVE_PEER_LIST). Reuse the single-sourced
// OnPeerListReceived dial/IPFilter/clientlist path (it takes m_lock itself). The
// peer arg is unused, so NULL is safe; chunks then flow DIRECT per the Tunelizado
// contract. Re-entering OnPeerListReceived runs its exit-relay hook again, but a
// viewer is not an exit for this stream so that is a cheap no-op (no relay loop).
void CLiveStreamManager::OnTunneledPeerList(const uchar* streamKey,
    const uint32_t* ips, const uint16_t* ports, uint8_t count)
{
    if (streamKey == NULL || ips == NULL || ports == NULL) return;
    if (count > 16) count = 16;
    CArray<DWORD> ipArr;
    CArray<uint16> portArr;
    for (uint8_t i = 0; i < count; ++i) {
        ipArr.Add((DWORD)ips[i]);
        portArr.Add(ports[i]);
    }
    OnPeerListReceived(NULL, streamKey, ipArr, portArr);
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

    // C6 (2026-06): do NOT scrub trust / bitmap / counters here. Most
    // "disconnects" are the AttachToAlreadyKnown pointer swap, after which the
    // SAME logical peer keeps streaming under a fresh CUpDownClient — scrubbing
    // its durable state (keyed by LivePeerId / user-hash, not this pointer) is
    // exactly what caused the micro-cut. Those maps are reaped by PrunePeerState
    // once the identity has truly been silent for the TTL. We still drop the
    // transport-bound state below (lists, pending-pings heap, mesh membership).

    // V2-S03: pending pings ARE pointer-keyed (heap value, transient RTT) — drop
    // them on disconnect to avoid a dangling-pointer key + leak.
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
        AddLogLine(true, GetResString(IDS_LIVEMGR_STREAM_ENDED));
        // Inline-leave so we don't recurse OnStreamEnded.
        m_bViewing = false;
        m_chunkBuffer.Clear();
        m_viewPeers.RemoveAll();
        m_peerBitmaps.RemoveAll();
        m_dwLastLiveActivity = 0;
        ResetViewerHlsOutput(true);
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
        AddLogLine(false, GetResString(IDS_LIVEMGR_PEER_PROMOTED_FMT),
            newLevel, responseRate * 100.0f);
    }
}

void CLiveStreamManager::ProbeTestPeer(CUpDownClient* peer)
{
    PeerTrust& trust = GetOrCreateTrust(peer);

    // Find a segment we know this peer has (from their bitmap).
    // Phase 1 BOOT-3: bitmap is anchored at the PEER's oldestSeq.
    PeerBitmapInfo info;
    if (!m_peerBitmaps.Lookup(PeerId(peer), info) || info.bitmap == 0) return;

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
        if (!m_peerTrust.Lookup(PeerId(other), trust)) continue;
        if (trust.currentLevel != ESE_TRUST_SUPERSEEDER) continue;

        totalSuper++;
        uint32 otherIP = other->GetIP();
        if ((otherIP & 0xFFFFFF00) == peer24) sameSubnet24++;
        if ((otherIP & 0xFFFF0000) == peer16) sameSubnet16++;
    }

    // Rule 1: Max 5 super-seeders per /24
    if (sameSubnet24 >= 5) {
        AddLogLine(false, GetResString(IDS_LIVEMGR_SYBIL_BLOCKED24_FMT),
            sameSubnet24);
        return false;
    }

    // Rule 2: Max 20% of super-seeders per /16
    if (totalSuper > 10 && sameSubnet16 > totalSuper / 5) {
        AddLogLine(false, GetResString(IDS_LIVEMGR_SYBIL_BLOCKED16_FMT),
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
        if (m_peerTrust.Lookup(PeerId(peer), trust)) {
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
        AddLogLine(true, GetResString(IDS_LIVEMGR_EMERGENCY_DROP_FMT),
            dropRate * 100.0f, totalSuper - aliveSuper, totalSuper);

        // === Emergency Action 1: Promote trusted middle-tier peers ===
        int promoted = 0;
        pos = m_broadcastPeers.GetHeadPosition();
        while (pos && promoted < 5) {
            CUpDownClient* peer = m_broadcastPeers.GetNext(pos);
            PeerTrust trust;
            if (!m_peerTrust.Lookup(PeerId(peer), trust)) continue;
            if (trust.currentLevel != ESE_TRUST_MIDDLE) continue;

            // Only promote if good response rate and subnet-diverse
            if (trust.GetResponseRate() >= ESE_PROMOTE_SUPER_RATE &&
                trust.failCount == 0 &&
                CanPromoteToSuperSeeder(peer))
            {
                trust.currentLevel = ESE_TRUST_SUPERSEEDER;
                trust.lastPromotionTime = GetTickCount();
                m_peerTrust[PeerId(peer)] = trust;
                promoted++;
                AddLogLine(false, GetResString(IDS_LIVEMGR_EMERGENCY_PROMOTED_FMT),
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
                AddLogLine(true, GetResString(IDS_LIVEMGR_SYBIL_BANNING_FMT),
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
        AddLogLine(true, GetResString(IDS_LIVEMGR_EMERGENCY_ENDED));
    }
}


// ============================================================
// PERIODIC PROCESSING
// ============================================================

void CLiveStreamManager::Process()
{
    CSingleLock lock(&m_lock, TRUE);

    DWORD now = GetTickCount();

#ifdef ESE_TEST_HOOKS
    // TEST-ONLY: flush delayed sabotage sends whose timer elapsed (DELAY mode).
    for (std::vector<TestDeferredSend>::iterator it = m_testDeferredSends.begin();
         it != m_testDeferredSends.end(); ) {
        if ((int)(now - it->fireTick) >= 0) {
            if (it->peer && it->pkt) {
                theStats.AddUpDataOverheadOther(it->pkt->size);
                it->peer->SendPacket(it->pkt);      // takes ownership of pkt
            }
            it = m_testDeferredSends.erase(it);
        } else {
            ++it;
        }
    }
#endif

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

        // Churn fix: prune the viewer-side dial cooldown table the same way
        // (cooldown window is 15 s, so drop entries older than 60 s).
        CArray<uint64> deadDials;
        uint64 dk; DWORD dt = 0;
        POSITION dp = m_recentDials.GetStartPosition();
        while (dp) {
            m_recentDials.GetNextAssoc(dp, dk, dt);
            if (now - dt > 60000) deadDials.Add(dk);
        }
        for (INT_PTR i = 0; i < deadDials.GetCount(); ++i)
            m_recentDials.RemoveKey(deadDials[i]);
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

    // Ghost-viewer watchdog (2026-06): the 180 s watchdog above detects a
    // dead UPSTREAM; this one detects an absent LOCAL PLAYER. Without it,
    // closing the player tab left m_bViewing latched forever — the viewer
    // kept re-dialing/re-subscribing for the life of the broadcast (the
    // JOIN/DISCONNECT loop on the broadcaster's status page). Armed only
    // for web-originated joins (MarkWebPlayerSession); fed by HLS fetches
    // on eMule's own endpoints, the /api/live/player-alive heartbeat that
    // ese-server relays, and the JoinStream grace stamp. The pagehide
    // beacon in the player pages handles the fast path; this is the
    // backstop for killed tabs and crashed browsers.
    {
        const DWORD ESE_PLAYER_IDLE_LEAVE_MS = 60u * 1000u;
        DWORD lastFetch = (DWORD)m_lastPlayerFetchTick;
        if (m_bViewing
            && m_bWebPlayerSession != 0
            && lastFetch != 0
            && (now - lastFetch) > ESE_PLAYER_IDLE_LEAVE_MS)
        {
            AddLogLine(true, GetResString(IDS_LIVEMGR_GHOST_VIEWER_FMT),
                (now - lastFetch) / 1000);
            LIVE_LOG("MGR", "Ghost-viewer watchdog: %u ms without player fetch/heartbeat, auto LeaveStream",
                now - lastFetch);
            // m_lock is held by Process(); LeaveStream re-enters it on this
            // same thread — fine (CCriticalSection is recursive; JoinStream
            // already does the same at the top of its body).
            LeaveStream();
        }
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

        // v8.1.x — drop fragment reassembly buffers that never completed within
        // the TTL; a lost fragment just loses that seq, and RequestMissingSegments
        // below re-requests it from any peer like any other missing chunk.
        for (std::map<std::pair<LivePeerId, uint32>, FragReasm, FragKeyLess>::iterator fit = m_fragReasm.begin();
             fit != m_fragReasm.end(); ) {
            if ((DWORD)(now - fit->second.firstSeenTick) > eSELive::ESE_FRAG_REASM_TTL) {
                LIVE_LOG("FRAG", "TIMEOUT seq=%u have=%u/%u", fit->first.second,
                    (unsigned)fit->second.haveCount, (unsigned)fit->second.fragCount);
                fit = m_fragReasm.erase(fit);
            } else {
                ++fit;
            }
        }

        // Request missing segments
        RequestMissingSegments();

        // [eSE v9] reachability escalation (dormant unless m_bReachSelectorOn)
        TickReachabilitySelector(now);

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
                    GetResString(IDS_LIVEMGR_STALLED_FMT),
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
                    // Skip peers we are already viewing from — match EITHER
                    // address of this broadcaster (public IP or overlay alt IP),
                    // both carried in one Kad entry = one machine. Matching only
                    // broadcasterIP re-dialed the dead public address of an
                    // already-connected broadcaster (dual-dial churn).
                    bool alreadyConnected = false;
                    POSITION pos = m_viewPeers.GetHeadPosition();
                    while (pos) {
                        CUpDownClient* existing = m_viewPeers.GetNext(pos);
                        if (existing
                            && existing->GetUserPort() == known[i].broadcasterPort
                            && (existing->GetIP() == known[i].broadcasterIP
                                || (known[i].broadcasterAltIP != 0
                                    && existing->GetIP() == known[i].broadcasterAltIP)))
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
                    // NAT-reach: race the overlay endpoint too (see drain in
                    // CLiveKadBridge::Process). Pass each call its sibling so the
                    // inner backstop drops the redundant dial once one connects.
                    TryConnectToStreamSource(m_streamInfo.streamKey,
                        known[i].broadcasterIP, known[i].broadcasterPort,
                        known[i].broadcasterUDPPort, known[i].broadcasterAltIP);
                    if (known[i].broadcasterAltIP != 0
                        && known[i].broadcasterAltIP != known[i].broadcasterIP)
                        TryConnectToStreamSource(m_streamInfo.streamKey,
                            known[i].broadcasterAltIP, known[i].broadcasterPort,
                            known[i].broadcasterUDPPort, known[i].broadcasterIP);
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

    // C6: sweep durable per-peer state for identities gone silent past the TTL
    // (every 30 s). Replaces the per-disconnect scrub that orphaned live peers.
    if (now - m_dwLastPeerPrune >= 30000) {
        PrunePeerState(now);
        m_dwLastPeerPrune = now;
    }

    // C5/C6 review fix — self-heal a lost tunneled subscribe. The first tunneled
    // subscribe is fire-and-forget: a dropped send, a circuit-death TOCTOU, or a
    // broadcaster DENY of the exit leaves the viewer with no live edge and no
    // recovery (the failover loop skips already-connected sources). If we are
    // tunneling a source and after a grace window still have no bitmap for it,
    // re-issue the tunneled subscribe (privacy preserved — no direct fallback).
    if (m_bViewing && m_tunnelSourceIP != 0 && m_tunnelResubCount < 5
        && m_tunnelSubscribeTick != 0 && (now - m_tunnelSubscribeTick) > 8000)
    {
        bool haveEdge = false;
        POSITION tp = m_viewPeers.GetHeadPosition();
        while (tp && !haveEdge) {
            CUpDownClient* p = m_viewPeers.GetNext(tp);
            if (p && p->GetIP() == m_tunnelSourceIP
                  && p->GetUserPort() == m_tunnelSourcePort) {
                PeerBitmapInfo bi;
                if (m_peerBitmaps.Lookup(PeerId(p), bi) && bi.bitmap != 0)
                    haveEdge = true;
            }
        }
        if (!haveEdge) {
            m_tunnelResubCount++;
            m_tunnelSubscribeTick = now;
            // EnqueueSendMsg takes only m_mtLock (leaf) — safe under our m_lock.
            eSELive::CLiveTunnel::Get().SendLiveSubscribeNoWait(
                m_streamInfo.streamKey, m_tunnelSourceIP, m_tunnelSourcePort, 0, 0);
            LIVE_LOG("TUN", "C5 self-heal: re-issuing tunneled subscribe (retry %d/5)",
                m_tunnelResubCount);
        } else {
            m_tunnelSubscribeTick = 0;   // edge arrived — stop watching
        }
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

    // R.3 egress (dormant unless s_relayEgressEnabled): release the manager lock, then
    // proactively forward any new segments to the active relay buddy on this (main) thread.
    // Lock-free by design — WithSegment guards the chunk buffer with its own lock, and
    // m_streamInfo / the buddy pointer are main-thread-only. Unlock-before-send mirrors the
    // initial-push pattern (~:1396) so a big relay drain never blocks FeedSegment on m_lock.
    lock.Unlock();
    RelayPushNewSegments();
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

// R.3 egress: forward every NEW segment to the active relay buddy as OP_LIVE_RELAY_FWD/
// CHUNK. Runs on the main thread AFTER Process() released m_lock (so a big relay drain
// never blocks FeedSegment). Lock-free: WithSegment provides chunk-buffer safety; the
// buddy pointer + m_streamInfo are main-thread-only. Dormant unless s_relayEgressEnabled.
void CLiveStreamManager::RelayPushNewSegments()
{
    if (!thePrefs.GetEseRelayEgress() || !m_bBroadcasting)   // gate: pref EseRelayEgress (default OFF)
        return;
    CUpDownClient* buddy = CLiveBuddyRelay::Instance().GetActiveBuddy();
    if (buddy == NULL) {
        // No active relay yet — (re)negotiate one (sends SETUP; non-blocking). Throttled so
        // we don't spam SETUP every tick while a candidate is still connecting / replying.
        if (GetTickCount() - m_dwLastRelaySetup > 5000) {
            CLiveBuddyRelay::Instance().StartAsBroadcaster();
            m_dwLastRelaySetup = GetTickCount();
        }
        return;
    }
    // Build the relay packets UNDER m_lock so the chunk-buffer window (GetOldest/NewestSeq)
    // + WithSegment read are consistent against FeedSegment's AddSegment/eviction on the
    // FFmpeg watcher thread; then RELEASE m_lock and send — a big relay drain must never run
    // under m_lock (mirrors the initial-push pattern ~:1396). `buddy` is main-thread-stable:
    // the main loop is run-to-completion and SendPacket only queues to the socket buffer (it
    // does NOT pump the message loop), so g_activeBuddy cannot change across this call.
    CArray<Packet*> outBatch;
    {
        CSingleLock lock(&m_lock, TRUE);
        if (!m_bBroadcasting || m_chunkBuffer.GetCount() == 0)
            return;
        const uint32 newest = m_chunkBuffer.GetNewestSeq();
        const uint32 oldest = m_chunkBuffer.GetOldestSeq();
        uint32 from = (m_lastRelayedSeq == UINT_MAX) ? oldest : (m_lastRelayedSeq + 1);
        if (from < oldest) from = oldest;        // segments before `oldest` were already evicted
        for (uint32 seq = from; seq <= newest; ++seq) {
            Packet* v2 = NULL;
            m_chunkBuffer.WithSegment(seq, [&](const LiveChunk& c) {
                if (memcmp(c.streamKey, m_streamInfo.streamKey, 16) == 0)
                    v2 = eSELive::CreateChunkPacketV2(&c, m_broadcasterPrivkey, m_streamInfo.pubkey);
            });
            if (v2 == NULL)
                continue;
            // RELAY_FWD/CHUNK payload = the V2 record body verbatim: the relay ingests it via
            // ExitProxyOnWholeChunk and re-emits it to its 0xCE downstream as OP_LIVE_CHUNK_V2.
            Packet* fwd = eSELive::CreateRelayFwdPacket(CLiveBuddyRelay::RELAY_SUB_CHUNK,
                              m_streamInfo.streamKey, (const uint8*)v2->pBuffer, v2->size);
            delete v2;
            if (fwd != NULL)
                outBatch.Add(fwd);
        }
        m_lastRelayedSeq = newest;
    }   // m_lock released before the socket drain
    for (INT_PTR i = 0; i < outBatch.GetCount(); ++i) {
        theStats.AddUpDataOverheadOther(outBatch[i]->size);
        buddy->SendPacket(outBatch[i], true);   // bVerifyConnection: drops cleanly if the buddy died
    }
}

// [eSE v9] R-node auto-picker for the 3-way rendezvous (punch3). Prefer a connected fork
// peer that ADVERTISED the RDV cap (known-capable); else a verified Kad v6 contact. Returns
// HOST-order R ip + Kad UDP port. Skips R==target and R==self.
bool CLiveStreamManager::PickRendezvous(uint32 targetIpHost, uint16 /*targetUdp*/, uint32& outRipHost, uint16& outRport)
{
    outRipHost = 0; outRport = 0;
    const uint32 myIpHost = ntohl(theApp.GetPublicIP());   // GetPublicIP() is NET order
    // Preferred R: a connected fork peer with the RDV cap + a known Kad UDP port.
    std::vector<CUpDownClient*> cands;
    if (theApp.clientlist != NULL)
        theApp.clientlist->GetConnectedSnapshot(cands, 10, false);
    for (size_t i = 0; i < cands.size(); ++i) {
        CUpDownClient* c = cands[i];
        if (c == NULL || !c->SupportsEseHolePunchRdv() || c->GetKadPort() == 0) continue;
        const uint32 cipHost = ntohl(c->GetIP());          // GetIP() is NET order
        if (cipHost == 0 || cipHost == targetIpHost || cipHost == myIpHost) continue;
        outRipHost = cipHost; outRport = c->GetKadPort();
        return true;
    }
    // Fallback R: a verified Kad v6 contact (proven recipe, Kademlia.cpp:308).
    if (Kademlia::CKademlia::GetRoutingZone() == NULL)
        return false;
    for (int tries = 0; tries < 8; ++tries) {
        Kademlia::CContact* pR = Kademlia::CKademlia::GetRoutingZone()->GetRandomContact(3, KADEMLIA_VERSION6_49aBETA);
        if (pR == NULL) break;
        if (!pR->IsIpVerified()) continue;
        const uint32 ripHost = pR->GetIPAddress();         // GetIPAddress() is HOST order
        if (ripHost == 0 || ripHost == targetIpHost || ripHost == myIpHost) continue;
        outRipHost = ripHost; outRport = pR->GetUDPPort();
        return true;
    }
    return false;
}

// [eSE v9] reachability escalation driver. Per tracked source, after STAGE_TIMEOUT_MS in the
// current stage with no live socket, advance to the next mechanism: Direct->2way-punch->
// 3way-rdv->relay. Runs under Process()'s m_lock (control sends are small). Dormant unless
// m_bReachSelectorOn. Prunes settled / no-longer-wanted entries.
void CLiveStreamManager::TickReachabilitySelector(DWORD now)
{
	if (!thePrefs.GetEseReachSelector() || !thePrefs.GetUtpHolePunchEnabled())
		return;
	if (theApp.clientudp == NULL || !theApp.clientudp->IsUtpReady())
		return;
    if (!Kademlia::CKademlia::IsConnected() || Kademlia::CKademlia::GetUDPListener() == NULL)
        return;
    // < 5s/stage so all 4 stages (Direct->punch2->punch3->relay = 18s) complete within one
    // 20s stall-failover window (~:3028) — every reachability method is tried before failover
    // re-discovers the source.
    const DWORD STAGE_TIMEOUT_MS = 4500;
    // CMap iteration safety: below we only update the value of the CURRENT (already-present)
    // key via m_escalation[key]=st. operator[] on an EXISTING key returns the node's value ref
    // WITHOUT inserting/rehashing, so the POSITION stays valid. No new keys are added during
    // iteration; removals are deferred to toErase and applied after the loop.
    CList<uint64, uint64> toErase;
    for (POSITION p = m_escalation.GetStartPosition(); p != NULL; ) {
        uint64 key; ReachState st;
        m_escalation.GetNextAssoc(p, key, st);
        const uint32 ipHost = (uint32)(key >> 16);
        const uint16 port   = (uint16)(key & 0xFFFF);
        // Reachable once the source has a live socket -> done.
        CUpDownClient* c = (theApp.clientlist != NULL)
            ? theApp.clientlist->FindClientByIP(htonl(ipHost), port) : NULL;   // FindClientByIP wants NET order
        if (c != NULL && c->socket != NULL && c->socket->IsConnected()) {
            if (st.stage != REACH_DONE) {
                // Record WHICH mechanism actually won at the connect edge (once per source) before
                // collapsing to DONE, so a 2-3 PC run can attribute the connect to Direct/Punch2/
                // Punch3/Relay instead of guessing from interleaved logs.
                switch (st.stage) {
                    case REACH_DIRECT: InterlockedIncrement(&CStatistics::m_dwReachConnDirect); break;
                    case REACH_PUNCH2: InterlockedIncrement(&CStatistics::m_dwReachConnPunch2); break;
                    case REACH_PUNCH3: InterlockedIncrement(&CStatistics::m_dwReachConnPunch3); break;
                    case REACH_RELAY:  InterlockedIncrement(&CStatistics::m_dwReachConnRelay);  break;
                }
                LIVE_LOG("REACH", "%S:%u CONNECTED at stage=%s", (LPCWSTR)ipstr(htonl(ipHost)), port,
                    st.stage == REACH_DIRECT ? "DIRECT" : st.stage == REACH_PUNCH2 ? "PUNCH2"
                    : st.stage == REACH_PUNCH3 ? "PUNCH3" : "RELAY");
                st.stage = REACH_DONE; st.stageEnteredTick = now; m_escalation[key] = st;
            }
        }
        if (st.stage == REACH_DONE) {
            if ((DWORD)(now - st.stageEnteredTick) > 60000) toErase.AddTail(key);   // GC long-settled
            continue;
        }
        // Drop tracking for sources we are no longer trying to view.
        bool stillWanted = false;
        for (POSITION vp = m_viewPeers.GetHeadPosition(); vp != NULL; ) {
            CUpDownClient* v = m_viewPeers.GetNext(vp);
            if (v != NULL && ntohl(v->GetIP()) == ipHost && v->GetUserPort() == port) { stillWanted = true; break; }
        }
        if (!stillWanted) { toErase.AddTail(key); continue; }
        if ((DWORD)(now - st.stageEnteredTick) < STAGE_TIMEOUT_MS) continue;   // give the stage its window
        // Advance to the next mechanism.
        if (st.stage == REACH_DIRECT) {
            st.stage = REACH_PUNCH2; st.stageEnteredTick = now;
            uint16 hpSpread = thePrefs.GetEseHolePunchPortPredict() ? (uint16)thePrefs.GetEseHolePunchPortSpread() : 0;
			Kademlia::CKademlia::GetUDPListener()->SendEseHolePunchReqSpray(ipHost, st.udpPort, hpSpread,
				c != NULL && (c->SupportsReachPunch2() || c->SupportsEseHolePunchCookie()), c);   // HOST order
            if (c != NULL && c->m_uNatRendezvousAttempts < 255) c->m_uNatRendezvousAttempts++;
            LIVE_LOG("REACH", "%S:%u DIRECT->PUNCH2 (2-way punch)", (LPCWSTR)ipstr(htonl(ipHost)), port);
        } else if (st.stage == REACH_PUNCH2) {
            st.stage = REACH_PUNCH3; st.stageEnteredTick = now;
            uint32 rIP = 0; uint16 rPort = 0;
			if (thePrefs.GetEseKad3Rendezvous() && PickRendezvous(ipHost, st.udpPort, rIP, rPort)) {
                Kademlia::CKademlia::GetUDPListener()->InitiateKad3Rendezvous(rIP, rPort, ipHost, st.udpPort);
                LIVE_LOG("REACH", "%S:%u PUNCH2->PUNCH3 via R %S", (LPCWSTR)ipstr(htonl(ipHost)), port, (LPCWSTR)ipstr(htonl(rIP)));
            } else {
                LIVE_LOG("REACH", "%S:%u PUNCH2->PUNCH3 (no R available)", (LPCWSTR)ipstr(htonl(ipHost)), port);
            }
        } else if (st.stage == REACH_PUNCH3) {
            st.stage = REACH_RELAY; st.stageEnteredTick = now;
            // R.3: route the SUBSCRIBE through an active onion circuit (an exit peer subscribes
            // on our behalf). Reuses the proven tunnel path; bIP is NET order (cf. :617). If no
            // circuit, fall through to DONE and let the 20 s stall failover re-discover.
            eSELive::CLiveTunnel& tun = eSELive::CLiveTunnel::Get();
            if (tun.ActiveCircuitCount() > 0) {
                tun.SendLiveSubscribeNoWait(m_streamInfo.streamKey, htonl(ipHost), port, st.udpPort, 0);
                LIVE_LOG("REACH", "%S:%u PUNCH3->RELAY (tunneled subscribe)", (LPCWSTR)ipstr(htonl(ipHost)), port);
            } else {
                st.stage = REACH_DONE;
                LIVE_LOG("REACH", "%S:%u RELAY skipped (no circuit) -> DONE", (LPCWSTR)ipstr(htonl(ipHost)), port);
            }
        } else {   // REACH_RELAY window elapsed -> give up; the failover re-discovers
            st.stage = REACH_DONE;
        }
        m_escalation[key] = st;
    }
    for (POSITION ep = toErase.GetHeadPosition(); ep != NULL; )
        m_escalation.RemoveKey(toErase.GetNext(ep));
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
            LivePeerId pid;                 // C6: map key is now a durable id
            PeerBitmapInfo info;
            m_peerBitmaps.GetNextAssoc(pos, pid, info);
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

    DWORD now = GetTickCount();

    // Phase-1 fix #2 — prune in-flight entries that no longer matter:
    // fulfilled (safety net; OnChunkReceived already erases those) or fallen
    // behind the buffer window (the ring would reject them as stale anyway).
    // MFC CMap allows removing the key GetNextAssoc just returned.
    POSITION ppos = m_inflightSegReqs.GetStartPosition();
    while (ppos) {
        uint32 iseq;
        InflightSegReq ireq;
        m_inflightSegReqs.GetNextAssoc(ppos, iseq, ireq);
        if (m_chunkBuffer.HasSegment(iseq)
            || (m_chunkBuffer.GetCount() > 0 && iseq < m_chunkBuffer.GetOldestSeq()))
            m_inflightSegReqs.RemoveKey(iseq);
    }

    // Request up to 5 missing segments with extended lookahead.
    // Phase-1 fix #2: skip segments with a request already in flight. The
    // old code re-sent OP_LIVE_REQUEST for every missing seq on every 1 s
    // tick; a ~500 KB segment needs 1.5-2 s at 2-3 Mbit/s, so most segments
    // were requested (and served) 2-3 times — duplicate downloads exactly
    // when the link is congested. On timeout, retry biased AWAY from the
    // unresponsive peer. chunksMissing now counts request attempts, not
    // missing-per-tick (it was inflated by the window size each second).
    int requested  = 0;
    int noPeer     = 0;
    int suppressed = 0;
    const int    maxRequestsPerCycle = 5;
    const uint32 lookahead = 3;
    const DWORD  ESE_LIVE_INFLIGHT_TIMEOUT_MS = 4000;
    for (uint32 seq = oldestSeq; seq <= newestSeq + lookahead && requested < maxRequestsPerCycle; seq++) {
        if (m_chunkBuffer.HasSegment(seq)) continue;

        uint32 excludeIp = 0;
        int    attempts  = 0;
        InflightSegReq prev;
        if (m_inflightSegReqs.Lookup(seq, prev)) {
            if ((now - prev.sentTick) < ESE_LIVE_INFLIGHT_TIMEOUT_MS) {
                suppressed++;
                continue;  // request outstanding — don't duplicate it
            }
            // Timed out. If this was a CRITICAL (near-playhead) block, charge a
            // punctuality failure to the peer we asked — exactly once per
            // outstanding request. failCharged guards against re-charging on
            // later ticks when no replacement peer is found and the entry below
            // is not overwritten (threat-model vector #3).
            if (prev.edgeCritical && !prev.failCharged) {
                ChargePunctualityFailure(prev.peerIp, prev.peerPort);
                prev.failCharged = true;
                m_inflightSegReqs[seq] = prev;  // persist the flag
            }
            excludeIp = prev.peerIp;   // timed out: prefer another peer
            attempts  = prev.attempts;
        }

        InterlockedIncrement(&m_counters.chunksMissing);
        CUpDownClient* peer = SelectPeerForSegment(seq, excludeIp);
        if (peer == NULL && excludeIp != 0)
            peer = SelectPeerForSegment(seq);  // only the slow peer has it — re-ask it
        if (peer) {
            Packet* pkt = eSELive::CreateRequestPacket(
                m_streamInfo.streamKey, seq);
            if (pkt) {
                theStats.AddUpDataOverheadOther(pkt->size);
                peer->SendPacket(pkt);
                InterlockedIncrement(&m_counters.chunksRequested);
                InflightSegReq req;
                req.sentTick     = now;
                req.peerIp       = peer->GetIP();
                req.peerPort     = peer->GetUserPort();
                req.attempts     = attempts + 1;
                // Critical = close to the playback head (the low end of the
                // request window). The player consumes oldest-first, so a late
                // block here is what actually freezes playback; far-ahead blocks
                // are recoverable. Classified at request time and read back on
                // both timeout (charge) and receipt (reward).
                req.edgeCritical = (seq < oldestSeq + ESE_LIVE_EDGE_GUARD);
                req.failCharged  = false;
                m_inflightSegReqs[seq] = req;
                requested++;
                LIVE_LOG("REQ", "ASK seq=%u -> %S:%u (attempt %d)",
                    seq,
                    (LPCWSTR)ipstr(peer->GetIP()),
                    (unsigned)peer->GetUserPort(),
                    req.attempts);
            }
        } else {
            AddDebugLogLine(false,
                _T("eSE HLS: No peer has segment %u (gap recovery failed)"), seq);
            noPeer++;
        }
    }
    if (suppressed > 0)
        InterlockedExchangeAdd(&m_counters.requestsSuppressedInflight, suppressed);
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
        AddLogLine(false, GetResString(IDS_LIVEMGR_PEER_DEMOTED_FMT),
            trust.currentLevel, trust.GetResponseRate() * 100.0f);
    }
}

void CLiveStreamManager::BanPeer(CUpDownClient* peer)
{
    PeerTrust& trust = GetOrCreateTrust(peer);
    trust.isBanned = true;
    AddLogLine(true, GetResString(IDS_LIVEMGR_PEER_BANNED_FMT),
        trust.GetResponseRate() * 100.0f, trust.requestsReceived);

    // Send deny packet and disconnect
    Packet* pkt = eSELive::CreateDenyPacket(m_streamInfo.streamKey, ESE_DENY_BANNED);
    if (pkt) {
        theStats.AddUpDataOverheadOther(pkt->size);
        peer->SendPacket(pkt);
    }
}

// Threat-model vector #3 (piece starvation / malicious churn): a peer that
// times out on a block the player needs imminently is sabotaging the live edge,
// whether maliciously or via a genuinely bad link — either way we should stop
// asking it for critical blocks. Charge failCount (weighted), which demotes it
// (CalculateTrustLevel: >2 -> leaf) and tanks its selection score
// (SelectPeerForSegment: -= failCount*20). It recovers only by serving critical
// blocks on time (failCount-- in OnChunkReceived). Caller (RequestMissingSegments
// via Process) holds m_lock.
void CLiveStreamManager::ChargePunctualityFailure(uint32 ip, uint16 port)
{
    if (ip == 0) return;
    CUpDownClient* peer = NULL;
    POSITION pos = m_viewPeers.GetHeadPosition();
    while (pos != NULL) {
        CUpDownClient* p = m_viewPeers.GetNext(pos);
        if (p != NULL && p->GetIP() == ip && p->GetUserPort() == port) { peer = p; break; }
    }
    if (peer == NULL) return;  // peer already gone — nothing left to penalise

    PeerTrust& trust = GetOrCreateTrust(peer);
    trust.failCount += ESE_EDGE_FAIL_WEIGHT;
    if (trust.failCount > ESE_FAIL_COUNT_CAP) trust.failCount = ESE_FAIL_COUNT_CAP;
    trust.lastSeen = GetTickCount();
    LIVE_LOG("TRUST", "edge-miss ip=%S port=%u failCount=%d",
        (LPCWSTR)ipstr(ip), (unsigned)port, trust.failCount);
}

// ============================================================
// C6 (2026-06) — durable peer identity + keyed accessors.
// ============================================================

LivePeerId CLiveStreamManager::PeerId(CUpDownClient* peer) const
{
    LivePeerId id;  // default = LPID_INVALID, zeroed
    if (peer == NULL)
        return id;
    const uchar* uh = peer->GetUserHash();
    bool hasHash = false;
    if (uh != NULL) {
        for (int i = 0; i < 16; ++i) { if (uh[i] != 0) { hasHash = true; break; } }
    }
    if (hasHash) {
        id.kind = LPID_USERHASH;
        memcpy(id.bytes, uh, 16);        // user-hash is stable across the swap
    } else {
        // Hashless / pre-HELLO peer: synthesize a per-pointer key so the maps
        // still work for this one peer (no cross-swap durability — same as the
        // pre-C6 behavior). kind stays LPID_INVALID so it never collides with a
        // real user-hash or pubkey identity.
        DWORD_PTR p = (DWORD_PTR)peer;
        memcpy(id.bytes, &p, sizeof p);
    }
    return id;
}

bool CLiveStreamManager::GetPeerBitmap(CUpDownClient* peer, PeerBitmapInfo& outInfo) const
{
    return m_peerBitmaps.Lookup(PeerId(peer), outInfo) != FALSE;
}

// v8.1.2 B6 — co-seeder check for the tunnel's 2-hop builder. m_viewPeers are the peers we
// pull THIS stream from; routing a circuit through one of them would let it learn we watch
// the channel. Main-thread read (no lock — m_viewPeers is mutated on the main thread too).
bool CLiveStreamManager::IsStreamSourcePeer(CUpDownClient* peer) const
{
    if (!peer || !m_bViewing) return false;
    POSITION pos = m_viewPeers.GetHeadPosition();
    while (pos != NULL)
        if (m_viewPeers.GetNext(pos) == peer) return true;
    return false;
}

bool CLiveStreamManager::GetPeerTrust(CUpDownClient* peer, PeerTrust& outTrust) const
{
    return m_peerTrust.Lookup(PeerId(peer), outTrust) != FALSE;
}

void CLiveStreamManager::SetPeerTrust(CUpDownClient* peer, const PeerTrust& trust)
{
    m_peerTrust[PeerId(peer)] = trust;
}

PeerCounters& CLiveStreamManager::GetOrCreatePeerCounters(CUpDownClient* peer)
{
    return m_peerCounters[PeerId(peer)];
}

PeerTrust& CLiveStreamManager::GetOrCreateTrust(CUpDownClient* peer)
{
    LivePeerId id = PeerId(peer);
    PeerTrust trust;
    if (!m_peerTrust.Lookup(id, trust)) {
        trust.joinedAt = GetTickCount();
        m_peerTrust[id] = trust;
    }
    // C6: stamp last-seen on every touch — drives the durable-state TTL prune.
    m_peerTrust[id].lastSeen = GetTickCount();
    return m_peerTrust[id];
}

// C6: drop durable per-peer state for identities unseen within the TTL. This
// replaces the old "scrub on every OnPeerDisconnected" — most disconnects are
// just the AttachToAlreadyKnown pointer swap, and scrubbing there is exactly
// what orphaned live peers' state (the micro-cut). A truly-departed peer stops
// refreshing its trust.lastSeen and gets reaped here. TTL comfortably exceeds
// the ~6 s LowID swap cycle.
void CLiveStreamManager::PrunePeerState(DWORD now)
{
    const DWORD ESE_PEER_STATE_TTL_MS = 120u * 1000u;  // 2 min
    CArray<LivePeerId> dead;
    POSITION pos = m_peerTrust.GetStartPosition();
    while (pos) {
        LivePeerId id;
        PeerTrust tr;
        m_peerTrust.GetNextAssoc(pos, id, tr);
        DWORD anchor = (tr.lastSeen != 0) ? tr.lastSeen : tr.joinedAt;
        if (anchor != 0 && (now - anchor) > ESE_PEER_STATE_TTL_MS)
            dead.Add(id);
    }
    for (INT_PTR i = 0; i < dead.GetCount(); ++i) {
        m_peerTrust.RemoveKey(dead[i]);
        m_peerBitmaps.RemoveKey(dead[i]);
        m_peerCounters.RemoveKey(dead[i]);
    }
    if (dead.GetCount() > 0)
        LIVE_LOG("MESH", "C6 prune: reaped %d stale durable peer record(s)", (int)dead.GetCount());
}

CUpDownClient* CLiveStreamManager::SelectPeerForSegment(uint32 seqNum, uint32 excludeIp)
{
    // V2-S20 — Mesh fallback peer selection.
    // Score = response_rate * 100  - failCount * 20  - RTT_penalty.
    // RTT penalty: floor(rtt_ms_ewma / 50). 100ms -> -2, 500ms -> -10, 1s -> -20.
    // This biases toward low-latency parents while preserving the existing
    // trust-based ordering. Both broadcaster and any secondary-source viewers
    // are considered (we already added them to m_viewPeers via JoinStream).
    // Phase-1 fix #2: excludeIp != 0 skips that peer (timed-out request retry).
    CUpDownClient* bestPeer = NULL;
    int bestScore = -1;

    POSITION pos = m_viewPeers.GetHeadPosition();
    while (pos) {
        CUpDownClient* peer = m_viewPeers.GetNext(pos);
        if (excludeIp != 0 && peer != NULL && peer->GetIP() == excludeIp) continue;
        PeerBitmapInfo info;
        if (!m_peerBitmaps.Lookup(PeerId(peer), info)) continue;
        if (!info.Has(seqNum)) continue;

        PeerTrust trust;
        int score = 50;
        if (m_peerTrust.Lookup(PeerId(peer), trust)) {
            score = (int)(trust.GetResponseRate() * 100);
            score -= trust.failCount * 20;
        }
        // V2-S20: RTT bias. Only counts when we have a measured EWMA.
        PeerCounters pc;
        if (m_peerCounters.Lookup(PeerId(peer), pc) && pc.rtt_ms_ewma > 0) {
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

#ifdef ESE_TEST_HOOKS
// TEST-ONLY: format a Live-mesh peer's address into a fixed worst-case buffer
// for the /api/live/debug peerDetail array. Overflow-safety BY CONSTRUCTION:
//   * 'out' is sized 46 (== INET6_ADDRSTRLEN) by the caller — the worst-case
//     IPv6 textual form (<=45 visible chars) + NUL fits; we NEVER size for the
//     IPv4 max (16). So the buffer cannot be too small even for a full v6 string.
//   * _snprintf_s(..., _TRUNCATE, ...) is a BOUNDED writer: it writes at most
//     outLen-1 chars and always NUL-terminates, so it physically cannot overflow
//     regardless of address family or string length.
// The Live mesh peer identity is IPv4 today (CUpDownClient::GetIP() -> uint32,
// network byte order — same as ipstr()/inet_ntoa), so we emit dotted-quad here.
// When dual-stack reaches the mesh, swap the body for eMuleAI's
// _inet_ntop(AF_INET6, &addr, out, outLen) (Address.h) — also bounded by outLen —
// and nothing else changes: the HTTP response is an auto-growing CStringA, so
// there is no fixed-size response buffer anywhere in the chain to overrun.
static void FillPeerIpSafe(char* out, size_t outLen, uint32 ipv4)
{
    _snprintf_s(out, outLen, _TRUNCATE, "%u.%u.%u.%u",
        (unsigned)(ipv4 & 0xFF),         (unsigned)((ipv4 >> 8)  & 0xFF),
        (unsigned)((ipv4 >> 16) & 0xFF), (unsigned)((ipv4 >> 24) & 0xFF));
}
#endif

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
            LivePeerId pid;                 // C6: map key is now a durable id
            PeerBitmapInfo bm;
            m_peerBitmaps.GetNextAssoc(pos, pid, bm);
            PeerTrust trust;
            if (m_peerTrust.Lookup(pid, trust)) {
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

#ifdef ESE_TEST_HOOKS
    // TEST-ONLY: per-peer trust detail (bounded by MAX_PEER_DBG). Iterate
    // m_viewPeers (gives CUpDownClient* -> IP/port) under the m_lock we already
    // hold. snap.peerDetail layout is unconditional; only this fill is gated, so
    // production keeps peerDetailCount == 0 and emits nothing.
    snap.peerDetailCount = 0;
    {
        POSITION vpos = m_viewPeers.GetHeadPosition();
        while (vpos && snap.peerDetailCount < LiveDebugSnapshot::MAX_PEER_DBG) {
            CUpDownClient* p = m_viewPeers.GetNext(vpos);
            if (p == NULL) continue;
            LiveDebugSnapshot::PeerDbg& d = snap.peerDetail[snap.peerDetailCount++];
            FillPeerIpSafe(d.ip, sizeof(d.ip), p->GetIP());   // bounded, v4/v6-safe
            d.port = p->GetUserPort();
            PeerTrust t;
            if (m_peerTrust.Lookup(PeerId(p), t)) {
                d.level    = t.currentLevel;
                d.failCount = t.failCount;
                d.respPct  = (int)(t.GetResponseRate() * 100.0f);
            } else {
                d.level = ESE_TRUST_LEAF; d.failCount = 0; d.respPct = 100;
            }
            PeerCounters pc;
            d.rttMs = m_peerCounters.Lookup(PeerId(p), pc) ? pc.rtt_ms_ewma : 0;
        }
    }
#endif

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
    s.category     = m_streamInfo.category;
    s.language     = m_streamInfo.language;
    s.bitrate      = m_streamInfo.bitrate;
    s.viewerCount  = GetViewerCount();
    s.startedAt    = m_streamInfo.startedAt;
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

    PeerCounters& pc = m_peerCounters[PeerId(peer)];
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

    PeerCounters& pc = m_peerCounters[PeerId(peer)];
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

        // Dedupe — already viewing from EITHER address of this broadcaster?
        // One Kad entry binds the public IP and the overlay alt IP (same
        // machine); being connected on either one means this broadcaster is NOT
        // a missing parent. Matching only broadcasterIP (the old code) made us
        // re-dial the dead public address of an already-connected broadcaster
        // every cycle -> AttachToAlreadyKnown recycled the working socket -> the
        // JOIN churn. Counting the alt address as "have it" stops that.
        bool already = false;
        POSITION pos = m_viewPeers.GetHeadPosition();
        while (pos) {
            CUpDownClient* p = m_viewPeers.GetNext(pos);
            if (p && p->GetUserPort() == known[i].broadcasterPort
                  && (p->GetIP() == known[i].broadcasterIP
                      || (known[i].broadcasterAltIP != 0
                          && p->GetIP() == known[i].broadcasterAltIP))) {
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
        // NAT-reach: race the overlay endpoint too (see drain in
        // CLiveKadBridge::Process for rationale). Pass each call its sibling so
        // that once one endpoint connects, the inner backstop suppresses the
        // other (belt-and-braces with the pair-aware pre-check above).
        TryConnectToStreamSource(m_streamInfo.streamKey,
            known[i].broadcasterIP, known[i].broadcasterPort,
            known[i].broadcasterUDPPort, known[i].broadcasterAltIP);
        if (known[i].broadcasterAltIP != 0
            && known[i].broadcasterAltIP != known[i].broadcasterIP)
            TryConnectToStreamSource(m_streamInfo.streamKey,
                known[i].broadcasterAltIP, known[i].broadcasterPort,
                known[i].broadcasterUDPPort, known[i].broadcasterIP);
        m_lock.Lock();
        dialed++;
    }
}
