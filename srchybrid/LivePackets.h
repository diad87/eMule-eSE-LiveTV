//this file is part of eMule
// eSE — Live Packet Serialization
// Functions to create and send OP_LIVE_* packets.
#pragma once

#include "LiveProtocol.h"

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

// Create OP_LIVE_CHUNK packet: send segment data to a peer
// Format: <StreamKey 16><SequenceNumber 4><Timestamp 4><ChunkSize 4><Data ChunkSize>
Packet* CreateChunkPacket(const LiveChunk* chunk);

// Create OP_LIVE_PEER_LIST packet: broadcaster sends list of peers
// Format: <StreamKey 16><Count 2>(<IP 4><Port 2>)[Count]
Packet* CreatePeerListPacket(const uchar* streamKey,
    const DWORD* ips, const uint16* ports, uint16 count);

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
// Format: <StreamKey 16><NewestSeq 4><Bitrate 2>
Packet* CreateAnnouncePacket(const uchar* streamKey, uint32 newestSeq, uint16 bitrate);

// Create OP_LIVE_DENY packet
// Format: <StreamKey 16><Reason 1>
Packet* CreateDenyPacket(const uchar* streamKey, uint8 reason);

// Create OP_LIVE_END packet
// Format: <StreamKey 16><Reason 1>
Packet* CreateEndPacket(const uchar* streamKey, uint8 reason);

// V2-S03: Create OP_LIVE_PING packet (RTT measurement, request).
// Format: <StreamKey 16><PingId 4><SendTick 8>
Packet* CreatePingPacket(const uchar* streamKey, uint32 pingId, uint64 sendTick);

// V2-S03: Create OP_LIVE_PONG packet (RTT echo back).
// Format: <StreamKey 16><PingId 4><EchoTick 8>  (EchoTick = original sendTick)
Packet* CreatePongPacket(const uchar* streamKey, uint32 pingId, uint64 echoTick);

} // namespace eSELive
