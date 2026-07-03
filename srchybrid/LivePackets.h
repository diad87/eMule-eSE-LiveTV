//this file is part of eMule
// eSE — Live Packet Serialization
// Functions to create and send OP_LIVE_* packets.
#pragma once

#include "LiveProtocol.h"
#include "eMuleAI/Address.h"   // v0.71 IPv6 Sprint 7 — CAddress in CreatePeerListPacketV2

class CUpDownClient;
class Packet;

namespace eSELive {

// Create OP_LIVE_SUBSCRIBE packet: viewer wants to join a stream
// Format: <StreamKey 16><ViewerHash 16>[<UploadCapacity 4>]
Packet* CreateSubscribePacket(const uchar* streamKey, const uchar* viewerHash, uint32 uploadCapacity);

// Create OP_LIVE_UNSUBSCRIBE packet
// Format: <StreamKey 16><ViewerHash 16>
Packet* CreateUnsubscribePacket(const uchar* streamKey, const uchar* viewerHash);

// Create OP_LIVE_REQUEST packet: ask a peer for a specific segment
// Format: <StreamKey 16><SequenceNumber 4>
Packet* CreateRequestPacket(const uchar* streamKey, uint32 seqNum);

// Create OP_LIVE_CHUNK_V2: signed segment data.
// Format: <StreamKey 16><SeqNum 4><Timestamp 4><DataSize 4><Bitrate 2><sha256 32><Sig 64><Data DataSize>
// Signed message: streamKey || seqNum || sha256(data). Receiver verifies sig
// against pinned pubkey; mismatched chunks are dropped.
// LiveChunk is defined in LiveProtocol.h (global namespace) — no fwd decl needed.
Packet* CreateChunkPacketV2(const ::LiveChunk* chunk,
                            const uint8_t* privkey32, const uint8_t* pubkey32);

// Create OP_LIVE_CHUNK packet: send segment data to a peer
// Format: <StreamKey 16><SequenceNumber 4><Timestamp 4><ChunkSize 4><Data ChunkSize>
Packet* CreateChunkPacket(const LiveChunk* chunk);

// R.3 (relay floor) — OP_LIVE_RELAY_FWD builder (broadcaster<->relay link).
// Format: <SubOp 1><StreamKey 16><Payload len>. Sub-ops live in LiveBuddyRelay.cpp.
// Consumed by ListenSocket OP_LIVE_RELAY_FWD -> CLiveBuddyRelay::OnRelayFwd.
Packet* CreateRelayFwdPacket(uint8 subop, const uchar* streamKey, const uint8* payload, uint32 len);

// ── v8.1.x Live chunk fragmentation ───────────────────────────────────────
// eMule's socket rejects any packet > 2,000,000 bytes (EMSocket.cpp:261,
// ERR_TOOBIG). A whole HLS segment at >=8000 kbps exceeds that, so we split it.
// Fragment header (29 bytes) precedes each slice of the byte-identical inner
// chunk payload; the receiver reassembles the full payload and runs the EXISTING
// verify once. Below FRAG_THRESHOLD nothing is fragmented (byte-identical wire).
const uint32 ESE_FRAG_HEADER      = 29;          // streamKey16+seq4+idx2+cnt2+innerOp1+totalLen4
const uint32 ESE_FRAG_PAYLOAD     = 1400000;     // per-fragment slice cap (packet stays << 2MB)
const uint32 ESE_FRAG_THRESHOLD   = 1800000;     // inner-payload size above which we fragment
const uint32 ESE_FRAG_MAX_TOTAL   = 12582912;    // 12MB hard cap on a reassembled payload (DoS bound; covers ~12000-15000 kbps 4s VBR peaks)
const uint16 ESE_FRAG_MAX_COUNT   = 64;          // max fragments per segment
const int    ESE_FRAG_MAX_CONCURRENT = 8;        // concurrent partial reassemblies (8*8MB worst case)
const DWORD  ESE_FRAG_REASM_TTL   = 4000;        // ms; drop a partial that hasn't completed

// Take ownership of an already-built chunk packet (V1 OP_LIVE_CHUNK or V2
// OP_LIVE_CHUNK_V2). If its payload <= ESE_FRAG_THRESHOLD or !peerSupportsFrag,
// appends it unchanged to `out` (byte-identical wire). Otherwise slices its
// payload into N OP_LIVE_CHUNK_FRAG packets (each << 2MB) appended to `out`, and
// deletes the original. streamKey/seqNum/innerOpcode are read from the packet
// itself, so the slices reassemble to exactly the original payload. The V2
// signature was computed once when the inner packet was built — fragments are
// pure transport slicing, never re-signed.
void AppendChunkSendPackets(Packet* innerPkt, bool peerSupportsFrag, CArray<Packet*>& out);

// Create OP_LIVE_PEER_LIST packet: broadcaster sends list of peers
// Format: <StreamKey 16><Count 2>(<IP 4><Port 2>)[Count]
Packet* CreatePeerListPacket(const uchar* streamKey,
    const DWORD* ips, const uint16* ports, uint16 count);

// v0.71 IPv6 Sprint 7 — OP_LIVE_PEER_LIST_V2 (0xCD) with CAddress payload.
// Each peer is serialized via CAddress::WriteToBuffer (6 or 18 bytes) +
// port (2 bytes) instead of the legacy 4+2 fixed format. Count is still
// uint16 but receiver caps to ESE_LIVE_MAX_PEER_LIST=16 (v7.5.0 §16) to
// prevent FD exhaustion / SYN-flood reflection. Sent only to peers that
// advertise CAP_FORK_IPV6_WIRE. CAddress is in global namespace.
Packet* CreatePeerListPacketV2(const uchar* streamKey,
    const ::CAddress* addrs, const uint16* ports, uint16 count);

// PEX entry piggy-backed inside OP_LIVE_HEARTBEAT (Decentralized Capa 1).
// Each entry advertises a stream the sender has recently seen so receivers
// can populate their local directory without a Kad search.
struct LivePexEntry {
    uchar  streamKey[16];
    uint32 broadcasterIP;
    uint16 broadcasterPort;
};

// Create OP_LIVE_HEARTBEAT packet, optionally with PEX entries.
// Format: <StreamKey 16><Bitmap 2><OldestSeq 4>
//        [<PexCount 1><PexEntry[PexCount]>]   (each PexEntry = 22 bytes)
// Backward-compat: peers that parse only the first 22 bytes ignore PEX.
Packet* CreateHeartbeatPacket(const uchar* streamKey, uint16 bitmap, uint32 oldestSeq,
    const LivePexEntry* pex = NULL, uint8 pexCount = 0);

// Create OP_LIVE_ANNOUNCE packet: broadcaster notifies new segment
// Format: <StreamKey 16><NewestSeq 4><Bitrate 2> [<Pubkey 32>]
// v7.6.0: optional 32-byte pubkey trailer. Old peers ignore it; new peers
// verify sha1(pubkey)[:16] == streamKey.
Packet* CreateAnnouncePacket(const uchar* streamKey, uint32 newestSeq, uint16 bitrate,
                             const uchar* pubkey32 = NULL);

// Create OP_LIVE_DENY packet
// Format: <StreamKey 16><Reason 1>
Packet* CreateDenyPacket(const uchar* streamKey, uint8 reason);

// Create OP_LIVE_END packet
// Format: <StreamKey 16><Reason 1> [<Sig 64>]
// v7.7.0: optional 64-byte Ed25519 signature trailer over (streamKey || reason).
// Old peers ignore trailing bytes; new peers verify against pinned pubkey.
Packet* CreateEndPacket(const uchar* streamKey, uint8 reason,
                        const uchar* sig64 = NULL);

// V2-S03: Create OP_LIVE_PING packet (RTT measurement, request).
// Format: <StreamKey 16><PingId 4><SendTick 8>
Packet* CreatePingPacket(const uchar* streamKey, uint32 pingId, uint64 sendTick);

// V2-S03: Create OP_LIVE_PONG packet (RTT echo back).
// Format: <StreamKey 16><PingId 4><EchoTick 8>  (EchoTick = original sendTick)
Packet* CreatePongPacket(const uchar* streamKey, uint32 pingId, uint64 echoTick);

} // namespace eSELive
