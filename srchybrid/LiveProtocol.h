//this file is part of eMule
// eSE — Live Streaming Protocol Definitions
// Structs, constants, and types for P2P live streaming.
#pragma once

#include "types.h"

// eSE Live — Protocol constants
// Sprint 2 C.1: HLS segments 4s → 2s. Halves time-to-first-frame.
// MAX_SEGMENTS stays at 16 (limit: PeerBitmap uint16). With 2s segments
// the buffer window shrinks from 60s → 32s, still plenty for live viewing.
#define ESE_LIVE_MAX_SEGMENTS       16      // Ring buffer: matches uint16 bitmap
#define ESE_LIVE_SEGMENT_DURATION   2       // Seconds per HLS segment
#define ESE_LIVE_BITMAP_INTERVAL    1000    // Bitmap exchange every 1s (was 2s)
#define ESE_LIVE_ANNOUNCE_INTERVAL  2000    // Announce every 2s (was 4s)
#define ESE_LIVE_STATS_INTERVAL     10000   // Stats report every 10s (ms)
#define ESE_LIVE_KAD_PUBLISH_INTERVAL 60000 // Kad publish every 60s (ms)
#define ESE_LIVE_MAX_PEERS          5       // Max peers per viewer
#define ESE_LIVE_MIN_PEERS          3       // Min peers before requesting more
#define ESE_LIVE_PROBE_TIMEOUT      5000    // Probe test timeout (ms)
#define ESE_LIVE_REQUEST_TIMEOUT    2000    // Chunk request timeout before retry (ms)

// A slow viewer must not turn the otherwise unbounded socket queues into
// unbounded RAM use. Above this per-peer backlog, live chunks are dropped and
// recovered later through the normal missing-segment request path.
#define ESE_LIVE_MAX_PEER_QUEUE_BYTES   (8u * 1024u * 1024u)

// Kad keyword tags for eSE Live entries.
// Use multi-byte names to avoid collisions with standard one-byte eD2K/Kad tags.
#define TAG_ESE_LIVE_MARKER         "ese.live.marker"      // <uint32> 1
#define TAG_ESE_LIVE_STREAM_KEY     "ese.live.key"         // <string> 32 hex chars
#define TAG_ESE_LIVE_TITLE          "ese.live.title"       // <string>
#define TAG_ESE_LIVE_CATEGORY       "ese.live.category"    // <string>
#define TAG_ESE_LIVE_LANGUAGE       "ese.live.language"    // <string>
#define TAG_ESE_LIVE_BITRATE        "ese.live.bitrate"     // <uint32> kbps
#define TAG_ESE_LIVE_VIEWERS        "ese.live.viewers"     // <uint32>
#define TAG_ESE_LIVE_STARTED_AT     "ese.live.started"     // <uint32> unix time
// NAT-reach (2026-06): broadcaster's overlay/alternative IPv4 (e.g. a
// Tailscale CGNAT 100.64/10 address, or the [eMule] LiveAltIP INI override).
// Same byte order as TAG_SOURCEIP. Viewers dial BOTH the public IP and this
// one (happy-eyeballs); whichever connects first wins. Additive tag: vanilla
// 0.70b and older forks store/ignore it like any unknown keyword tag.
#define TAG_ESE_LIVE_ALTIP          "ese.live.altip"       // <uint32> overlay IPv4

// H8 fix (2026-06): constant TAG_FILENAME value for clean-namespace live
// publishes. Every Kad holder — upstream 0.70b included — rejects a keyword
// entry whose filename is empty (CIndexed::AddKeyword), so a publish with NO
// name is silently unstorable anywhere. A CONSTANT name satisfies that check
// while carrying zero per-stream information, so the title leak H8 closed
// stays closed. Used by the publisher (PrepareLivePacketForTags) and by the
// holder (Process_KADEMLIA2_PUBLISH_KEY_REQ) to repair nameless publishes
// from prior fork versions. Do not put anything stream-derived in here.
#define ESE_LIVE_CLEAN_NS_FILENAME  L"eselive"

// Trust levels
#define ESE_TRUST_LEAF              2       // Default: new peer
#define ESE_TRUST_MIDDLE            1       // 5 min + response rate > 80%
#define ESE_TRUST_SUPERSEEDER       0       // 15 min + response rate > 90%

// Promotion thresholds
// Sprint 2 G.1: super-seeder promotion 15min → 5min, middle 5min → 2min.
// Helps the mesh ramp up upload capacity faster on flash crowds.
#define ESE_PROMOTE_MIDDLE_TIME     (2 * 60 * 1000)     // 2 minutes (was 5)
#define ESE_PROMOTE_SUPER_TIME      (5 * 60 * 1000)     // 5 minutes (was 15)
#define ESE_PROMOTE_MIDDLE_RATE     0.80f               // 80% response rate
#define ESE_PROMOTE_SUPER_RATE      0.90f               // 90% response rate
#define ESE_BAN_RESPONSE_RATE       0.20f               // < 20% after 10+ requests = ban
#define ESE_DEGRADE_RESPONSE_RATE   0.50f               // < 50% after 5+ requests = degrade

// Live-edge punctuality (anti piece-starvation — threat-model vector #3).
// A request that times out for a segment within ESE_LIVE_EDGE_GUARD of the
// playback head is a CRITICAL miss: the player is about to stall on it. A
// timeout on a far-ahead segment is recoverable and is NOT charged. This wires
// up failCount, which upstream already penalised (CalculateTrustLevel: >2 -> leaf;
// SelectPeerForSegment: score -= failCount*20) but never actually incremented.
// A peer works the penalty off ONLY by delivering critical blocks on time
// (failCount-- on edge-critical receipt), so it cannot mask edge defection
// behind cheap backfill volume — the volume-based response rate can't detect
// "serves segs 1-4 fast, drops the imminent seg 5".
#define ESE_LIVE_EDGE_GUARD         3       // segments from the playhead treated as "critical"
#define ESE_EDGE_FAIL_WEIGHT        2       // failCount added per critical-block timeout
#define ESE_FAIL_COUNT_CAP          10      // upper bound so failCount can't run away

// Subnet limits (anti-Sybil)
#define ESE_MAX_SUPER_PER_SUBNET24  5       // Max super-seeders from same /24
#define ESE_MAX_SUPER_PCT_SUBNET16  20      // Max % of super-seeders from same /16

// Emergency mode
#define ESE_EMERGENCY_DROP_THRESHOLD 0.30f  // >30% super-seeders drop = emergency
#define ESE_EMERGENCY_DURATION      (2 * 60 * 1000) // 2 minutes

// Deny reasons
#define ESE_DENY_RATIO              0x01
#define ESE_DENY_BANNED             0x02
#define ESE_DENY_FULL               0x03
#define ESE_DENY_FIREWALLED         0x04

// End reasons
#define ESE_END_NORMAL              0x00
#define ESE_END_ERROR               0x01
#define ESE_END_KICKED              0x02


//
// LiveChunk — A single HLS segment ready for P2P distribution
//
struct LiveChunk {
    uchar   streamKey[16];      // MD4 hash identifying the stream
    uint32  sequenceNumber;     // Monotonically increasing segment index
    uint32  timestamp;          // Unix timestamp when segment was generated
    uint32  dataSize;           // Size of the segment data in bytes
    uint16  bitrate;            // Bitrate in kbps
    BYTE*   data;               // Raw .ts segment data (owned by buffer)

    LiveChunk()
        : sequenceNumber(0)
        , timestamp(0)
        , dataSize(0)
        , bitrate(0)
        , data(NULL)
    {
        memset(streamKey, 0, 16);
    }

    ~LiveChunk() {
        delete[] data;
        data = NULL;
    }

    // No copy (owns data pointer)
    LiveChunk(const LiveChunk&) = delete;
    LiveChunk& operator=(const LiveChunk&) = delete;

    // Move semantics
    LiveChunk(LiveChunk&& other) noexcept
        : sequenceNumber(other.sequenceNumber)
        , timestamp(other.timestamp)
        , dataSize(other.dataSize)
        , bitrate(other.bitrate)
        , data(other.data)
    {
        memcpy(streamKey, other.streamKey, 16);
        other.data = NULL;
        other.dataSize = 0;
    }
};


//
// LivePeerId — durable peer identity for the Live mesh (C6, 2026-06).
//
// Keys per-peer mesh state (trust, bitmap, counters) so it SURVIVES the
// CClientList::AttachToAlreadyKnown pointer swap that recycles a peer's
// CUpDownClient object every ~6 s for LowID peers. That swap (delete old
// object -> ~CUpDownClient -> OnPeerDisconnected scrubs pointer-keyed state)
// was orphaning the bitmap/trust/counters of a peer that is still streaming,
// forcing a re-subscribe + re-push + blind re-request = the micro-cut.
//
// kind=LPID_USERHASH uses bytes[0..16): the eD2K user-hash, which
// AttachToAlreadyKnown ITSELF matches on (ClientList.cpp:219), so it is stable
// across the swap. kind=LPID_PUBKEY uses bytes[0..32): the channel/circuit
// Ed25519 key, used by the tunneled control plane (C2). NEVER key on IP or raw
// pointer — NAT/LowID/lifetime-unstable (thesis §13.1).
//
enum LivePeerIdKind : uint8 { LPID_INVALID = 0, LPID_USERHASH = 1, LPID_PUBKEY = 2 };
struct LivePeerId {
    uint8 kind;
    uint8 bytes[32];
    LivePeerId() : kind(LPID_INVALID) { memset(bytes, 0, sizeof bytes); }
};
inline bool operator==(const LivePeerId& a, const LivePeerId& b) {
    return a.kind == b.kind && memcmp(a.bytes, b.bytes, sizeof a.bytes) == 0;
}

//
// PeerTrust — Trust and performance data for a connected peer
//
// NOTE: Anti-Sybil uses RESPONSE RATE (requests answered / requests received),
// NOT volume ratio. A peer with zero uploads because nobody asked is NOT a vampire.
// We use "probe tests" to force a request and measure willingness.
//
struct PeerTrust {
    DWORD   joinedAt;           // GetTickCount() when peer connected
    uint64  bytesServed;        // Bytes sent TO other peers (measured)
    uint64  bytesReceived;      // Bytes received FROM stream
    uint32  requestsReceived;   // Total OP_LIVE_REQUEST received by this peer
    uint32  requestsServed;     // Total OP_LIVE_CHUNK sent in response
    int     currentLevel;       // 0=super-seeder, 1=middle, 2=leaf
    int     failCount;          // Consecutive failures to respond
    DWORD   lastPromotionTime;  // When last promoted
    DWORD   lastProbeTime;      // When last probe test was sent
    bool    isBanned;           // Banned for bad behavior
    DWORD   lastSeen;           // C6: GetTickCount() of last interaction — drives the durable-state TTL prune

    PeerTrust()
        : joinedAt(0)
        , bytesServed(0)
        , bytesReceived(0)
        , requestsReceived(0)
        , requestsServed(0)
        , currentLevel(ESE_TRUST_LEAF)
        , failCount(0)
        , lastPromotionTime(0)
        , lastProbeTime(0)
        , isBanned(false)
        , lastSeen(0)
    {}

    // Response rate: what matters for anti-Sybil
    float GetResponseRate() const {
        if (requestsReceived == 0) return 1.0f;  // No requests = innocent
        return (float)requestsServed / requestsReceived;
    }

    // Volume ratio: informational only
    float GetVolumeRatio() const {
        if (bytesReceived == 0) return 0.0f;
        return (float)bytesServed / bytesReceived;
    }

    // Uptime in milliseconds
    DWORD GetUptime() const {
        return GetTickCount() - joinedAt;
    }
};


//
// PeerBitmapInfo — Bitmap + anchor reported by a remote peer's HEARTBEAT.
//
// IMPORTANT: `bitmap` bits are indexed relative to THIS peer's `oldestSeq`,
// NOT our local viewer's oldest seq. Bit 0 = oldestSeq, bit N = oldestSeq + N.
// Fixing the previous bug where the viewer used its own oldestSeq as anchor.
//
struct PeerBitmapInfo {
    uint16  bitmap;       // 16-bit availability map relative to oldestSeq
    uint32  oldestSeq;    // Peer's oldest segment number (anchor for bitmap)
    DWORD   lastUpdate;   // GetTickCount() when last received (staleness)

    PeerBitmapInfo()
        : bitmap(0), oldestSeq(0), lastUpdate(0)
    {}

    // True if this peer claims to have the given segment number.
    bool Has(uint32 seqNum) const {
        if (seqNum < oldestSeq) return false;
        uint32 bit = seqNum - oldestSeq;
        if (bit >= 16) return false;
        return (bitmap & (1 << bit)) != 0;
    }

    // Highest segment number the peer reports as available, or 0 if empty.
    uint32 NewestSeq() const {
        if (bitmap == 0) return 0;
        for (int i = 15; i >= 0; --i) {
            if (bitmap & (1 << i)) return oldestSeq + (uint32)i;
        }
        return 0;
    }
};


//
// LiveStreamInfo — Metadata about a live stream (for Kad publishing)
//
struct LiveStreamInfo {
    uchar   streamKey[16];      // Unique stream identifier; v7.6.0: sha1(pubkey)[:16]
    CString title;              // Stream title
    CString category;           // Category (Cine, Deportes, etc.)
    CString language;           // Language code (es, en, fr...)
    uint32  bitrate;            // Bitrate in kbps
    uint32  viewerCount;        // Current viewers
    uint32  startedAt;          // Unix timestamp when broadcast started
    bool    isMultiAudio;       // Has multiple audio tracks
    bool    isBroadcaster;      // Am I the original source?

    // v7.6.0 — Ed25519 public key of the broadcaster. The streamKey above is
    // sha1(pubkey)[:16] so any peer can verify that the pubkey is authentic
    // for a given streamKey, then verify signatures on chunks/announces/end.
    // Zeroed for streams discovered from v7.5- peers (back-compat).
    uchar   pubkey[32];

    LiveStreamInfo()
        : bitrate(0)
        , viewerCount(0)
        , startedAt(0)
        , isMultiAudio(false)
        , isBroadcaster(false)
    {
        memset(streamKey, 0, 16);
        memset(pubkey, 0, 32);
    }
};
