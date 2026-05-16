//this file is part of eMule
// eSE — Live Packet Serialization Implementation
#include "stdafx.h"
#include "LivePackets.h"
#include "opcodes.h"
#include "Packets.h"
#include "SafeFile.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif


namespace eSELive {

Packet* CreateSubscribePacket(const uchar* streamKey, const uchar* viewerHash, uint32 uploadCapacity)
{
    CSafeMemFile data(36);
    data.WriteHash16(streamKey);
    data.WriteHash16(viewerHash);
    data.WriteUInt32(uploadCapacity);

    Packet* pkt = new Packet(data, OP_EMULEPROT);
    pkt->opcode = OP_LIVE_SUBSCRIBE;
    return pkt;
}

Packet* CreateUnsubscribePacket(const uchar* streamKey, const uchar* viewerHash)
{
    CSafeMemFile data(32);
    data.WriteHash16(streamKey);
    data.WriteHash16(viewerHash);

    Packet* pkt = new Packet(data, OP_EMULEPROT);
    pkt->opcode = OP_LIVE_UNSUBSCRIBE;
    return pkt;
}

Packet* CreateRequestPacket(const uchar* streamKey, uint32 seqNum)
{
    CSafeMemFile data(20);
    data.WriteHash16(streamKey);
    data.WriteUInt32(seqNum);

    Packet* pkt = new Packet(data, OP_EMULEPROT);
    pkt->opcode = OP_LIVE_REQUEST;
    return pkt;
}

Packet* CreateChunkPacket(const LiveChunk* chunk)
{
    if (!chunk || !chunk->data || chunk->dataSize == 0)
        return NULL;

    // Header: streamKey(16) + seqNum(4) + timestamp(4) + chunkSize(4) = 28 bytes
    CSafeMemFile data(28 + chunk->dataSize);
    data.WriteHash16(chunk->streamKey);
    data.WriteUInt32(chunk->sequenceNumber);
    data.WriteUInt32(chunk->timestamp);
    data.WriteUInt32(chunk->dataSize);
    data.Write(chunk->data, chunk->dataSize);

    Packet* pkt = new Packet(data, OP_EMULEPROT);
    pkt->opcode = OP_LIVE_CHUNK;
    return pkt;
}

Packet* CreatePeerListPacket(const uchar* streamKey,
    const DWORD* ips, const uint16* ports, uint16 count)
{
    CSafeMemFile data(18 + count * 6);
    data.WriteHash16(streamKey);
    data.WriteUInt16(count);

    for (uint16 i = 0; i < count; i++) {
        data.WriteUInt32(ips[i]);
        data.WriteUInt16(ports[i]);
    }

    Packet* pkt = new Packet(data, OP_EMULEPROT);
    pkt->opcode = OP_LIVE_PEER_LIST;
    return pkt;
}

Packet* CreateHeartbeatPacket(const uchar* streamKey, uint16 bitmap, uint32 oldestSeq,
    const LivePexEntry* pex, uint8 pexCount)
{
    // PEX block (optional): <pexCount 1><entries pexCount*22>.
    // Cap at 5 to bound per-packet overhead at ~133 bytes total.
    if (pex == NULL) pexCount = 0;
    if (pexCount > 5) pexCount = 5;
    const UINT bodySize = 22 + (pexCount > 0 ? 1U + (UINT)pexCount * 22U : 0U);

    CSafeMemFile data(bodySize);
    data.WriteHash16(streamKey);
    data.WriteUInt16(bitmap);
    data.WriteUInt32(oldestSeq);
    if (pexCount > 0) {
        data.WriteUInt8(pexCount);
        for (uint8 i = 0; i < pexCount; ++i) {
            data.WriteHash16(pex[i].streamKey);
            data.WriteUInt32(pex[i].broadcasterIP);
            data.WriteUInt16(pex[i].broadcasterPort);
        }
    }

    Packet* pkt = new Packet(data, OP_EMULEPROT);
    pkt->opcode = OP_LIVE_HEARTBEAT;
    return pkt;
}

Packet* CreateAnnouncePacket(const uchar* streamKey, uint32 newestSeq, uint16 bitrate)
{
    CSafeMemFile data(22);
    data.WriteHash16(streamKey);
    data.WriteUInt32(newestSeq);
    data.WriteUInt16(bitrate);

    Packet* pkt = new Packet(data, OP_EMULEPROT);
    pkt->opcode = OP_LIVE_ANNOUNCE;
    return pkt;
}

Packet* CreateDenyPacket(const uchar* streamKey, uint8 reason)
{
    CSafeMemFile data(17);
    data.WriteHash16(streamKey);
    data.WriteUInt8(reason);

    Packet* pkt = new Packet(data, OP_EMULEPROT);
    pkt->opcode = OP_LIVE_DENY;
    return pkt;
}

Packet* CreateEndPacket(const uchar* streamKey, uint8 reason)
{
    CSafeMemFile data(17);
    data.WriteHash16(streamKey);
    data.WriteUInt8(reason);

    Packet* pkt = new Packet(data, OP_EMULEPROT);
    pkt->opcode = OP_LIVE_END;
    return pkt;
}

// V2-S03: PING/PONG for RTT measurement.
// Body layout (28 bytes): <streamKey 16><pingId 4><tick 8>
Packet* CreatePingPacket(const uchar* streamKey, uint32 pingId, uint64 sendTick)
{
    CSafeMemFile data(28);
    data.WriteHash16(streamKey);
    data.WriteUInt32(pingId);
    data.WriteUInt64(sendTick);

    Packet* pkt = new Packet(data, OP_EMULEPROT);
    pkt->opcode = OP_LIVE_PING;
    return pkt;
}

Packet* CreatePongPacket(const uchar* streamKey, uint32 pingId, uint64 echoTick)
{
    CSafeMemFile data(28);
    data.WriteHash16(streamKey);
    data.WriteUInt32(pingId);
    data.WriteUInt64(echoTick);

    Packet* pkt = new Packet(data, OP_EMULEPROT);
    pkt->opcode = OP_LIVE_PONG;
    return pkt;
}

} // namespace eSELive
