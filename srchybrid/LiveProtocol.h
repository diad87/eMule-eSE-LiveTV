//this file is part of eMule
// eSE — Live Streaming Protocol Definitions
// Structs, constants, and types for P2P live streaming.
#pragma once

#include "types.h"

// eSE Live — Protocol constants
#define ESE_LIVE_MAX_SEGMENTS       15      // Ring buffer: 60s / 4s = 15 segments
#define ESE_LIVE_SEGMENT_DURATION   4       // Seconds per HLS segment
#define ESE_LIVE_BITMAP_INTERVAL    2000    // Bitmap exchange every 2s (ms)
#define ESE_LIVE_ANNOUNCE_INTERVAL  4000    // Announce every 4s (ms)
#define ESE_LIVE_STATS_INTERVAL     10000   // Stats report every 10s (ms)
#define ESE_LIVE_KAD_PUBLISH_INTERVAL 60000 // Kad publish every 60s (ms)
#define ESE_LIVE_MAX_PEERS          5       // Max peers per viewer
#define ESE_LIVE_MIN_PEERS          3       // Min peers before requesting more
#define ESE_LIVE_PROBE_TIMEOUT      5000    // Probe test timeout (ms)
#define ESE_LIVE_REQUEST_TIMEOUT    2000    // Chunk request timeout before retry (ms)

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

// Trust levels
#define ESE_TRUST_LEAF              2       // Default: new peer
#define ESE_TRUST_MIDDLE            1       // 5 min + response rate > 80%
#define ESE_TRUST_SUPERSEEDER       0       // 15 min + response rate > 90%

// Promotion thresholds
#define ESE_PROMOTE_MIDDLE_TIME     (5 * 60 * 1000)     // 5 minutes
#define ESE_PROMOTE_SUPER_TIME      (15 * 60 * 1000)    // 15 minutes
#define ESE_PROMOTE_MIDDLE_RATE     0.80f               // 80% response rate
#define ESE_PROMOTE_SUPER_RATE      0.90f               // 90% response rate
#define ESE_BAN_RESPONSE_RATE       0.20f               // < 20% after 10+ requests = ban
#define ESE_DEGRADE_RESPONSE_RATE   0.50f               // < 50% after 5+ requests = degrade

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
// LiveStreamInfo — Metadata about a live stream (for Kad publishing)
//
struct LiveStreamInfo {
    uchar   streamKey[16];      // Unique stream identifier
    CString title;              // Stream title
    CString category;           // Category (Cine, Deportes, etc.)
    CString language;           // Language code (es, en, fr...)
    uint32  bitrate;            // Bitrate in kbps
    uint32  viewerCount;        // Current viewers
    uint32  startedAt;          // Unix timestamp when broadcast started
    bool    isMultiAudio;       // Has multiple audio tracks
    bool    isBroadcaster;      // Am I the original source?

    LiveStreamInfo()
        : bitrate(0)
        , viewerCount(0)
        , startedAt(0)
        , isMultiAudio(false)
        , isBroadcaster(false)
    {
        memset(streamKey, 0, 16);
    }
};
