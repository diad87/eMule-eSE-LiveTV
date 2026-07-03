//this file is part of eMule
// eSE — Live Packet Serialization Implementation
#include "stdafx.h"
#include "LivePackets.h"
#include "LiveCrypto.h"        // v7.7.0 — SignMessage for OP_LIVE_CHUNK_V2
#include "../cryptopp/sha.h"   // v7.7.0 — SHA256 for chunk integrity hash
#include "eMuleAI/Address.h"   // v0.71 IPv6 Sprint 7 — CAddress in peer list V2
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

// R.3 (relay floor) — OP_LIVE_RELAY_FWD: the broadcaster<->relay control+data link.
// Format: <SubOp 1><StreamKey 16><Payload ...>. Sub-ops (SETUP/SETUP_OK/SETUP_DENY/CHUNK)
// are file-private in LiveBuddyRelay.cpp. For CHUNK the payload is a whole V1/V2 chunk
// record (the relay ingests it via CLiveTunnel::ExitProxyOnWholeChunk). This mirrors the
// receive framing in ListenSocket OP_LIVE_RELAY_FWD (subop + streamKey16, then payload).
Packet* CreateRelayFwdPacket(uint8 subop, const uchar* streamKey, const uint8* payload, uint32 len)
{
    CSafeMemFile data(17 + (payload != NULL ? len : 0));
    data.WriteUInt8(subop);
    data.WriteHash16(streamKey);
    if (payload != NULL && len > 0)
        data.Write(payload, len);

    Packet* pkt = new Packet(data, OP_EMULEPROT);
    pkt->opcode = OP_LIVE_RELAY_FWD;
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

// v7.7.0 — signed chunk packet. The signed message is:
//   streamKey(16) || seqNum(4 LE) || sha256(data)(32)
// We don't include the payload itself in the signed message because we
// already include sha256(data); that lets the verifier check integrity
// cheaply (32 bytes hash) and then validate the signature without doing
// any work proportional to payload size beyond the one hash pass.
Packet* CreateChunkPacketV2(const ::LiveChunk* chunk,
                            const uint8_t* privkey32, const uint8_t* pubkey32)
{
    if (!chunk || !chunk->data || chunk->dataSize == 0 || !privkey32 || !pubkey32)
        return NULL;

    // Compute sha256(data) via CryptoPP (avoid a new include here — use the
    // already-included CryptoPP::SHA256 transitively if available, else use
    // a tiny inline impl. eSE already pulls cryptopp/sha.h in LiveCrypto.cpp,
    // and CryptoPP::SHA256 lives in <cryptopp/sha.h>.
    uint8_t digest[32];
    {
        CryptoPP::SHA256 hash;
        hash.CalculateDigest(digest, chunk->data, chunk->dataSize);
    }

    // Build the signed message buffer.
    uint8_t signMsg[16 + 4 + 32];
    memcpy(signMsg, chunk->streamKey, 16);
    uint32 seqLE = chunk->sequenceNumber;  // LE on x86 already
    memcpy(signMsg + 16, &seqLE, 4);
    memcpy(signMsg + 20, digest, 32);

    uint8_t sig[64];
    if (!eSELive::SignMessage(privkey32, pubkey32, signMsg, sizeof signMsg, sig))
        return NULL;

    // Pack on wire. Header: 16+4+4+4+2+32+64 = 126 bytes; then data.
    CSafeMemFile data(126 + chunk->dataSize);
    data.WriteHash16(chunk->streamKey);
    data.WriteUInt32(chunk->sequenceNumber);
    data.WriteUInt32(chunk->timestamp);
    data.WriteUInt32(chunk->dataSize);
    data.WriteUInt16(chunk->bitrate);
    data.Write(digest, 32);
    data.Write(sig, 64);
    data.Write(chunk->data, chunk->dataSize);

    Packet* pkt = new Packet(data, OP_EMULEPROT);
    pkt->opcode = OP_LIVE_CHUNK_V2;
    return pkt;
}

// v8.1.x — take ownership of an already-built V1/V2 chunk packet and append
// either it (unchanged) or its fragment packets to `out`. See LivePackets.h.
void AppendChunkSendPackets(Packet* innerPkt, bool peerSupportsFrag, CArray<Packet*>& out)
{
    if (innerPkt == NULL)
        return;

    // Below threshold, or the peer can't reassemble -> send the single packet
    // exactly as today (byte-identical wire). A too-big packet to a non-frag
    // peer will ERR_TOOBIG on their side — no worse than before this feature.
    if (innerPkt->size <= ESE_FRAG_THRESHOLD || !peerSupportsFrag) {
        out.Add(innerPkt);
        return;
    }

    // Slice the inner payload. streamKey(16) + seqNum(4) sit at the front of
    // every chunk payload (both V1 CreateChunkPacket and V2 CreateChunkPacketV2),
    // so the reassembled buffer is byte-identical to innerPkt->pBuffer.
    const uint8* body         = (const uint8*)innerPkt->pBuffer;
    const uint32 totalLen     = innerPkt->size;
    const uint8  innerOpcode  = innerPkt->opcode;
    const uint32 fragCount    = (totalLen + ESE_FRAG_PAYLOAD - 1) / ESE_FRAG_PAYLOAD;

    // If it would need more fragments than the receiver accepts, fall back to the
    // single packet (ERR_TOOBIG on their side — no regression).
    if (fragCount == 0 || fragCount > ESE_FRAG_MAX_COUNT) {
        out.Add(innerPkt);
        return;
    }

    for (uint32 i = 0; i < fragCount; ++i) {
        const uint32 off     = i * ESE_FRAG_PAYLOAD;
        const uint32 fragLen = min(ESE_FRAG_PAYLOAD, totalLen - off);

        CSafeMemFile data(ESE_FRAG_HEADER + fragLen);
        data.Write(body, 20);                  // streamKey(16) + seqNum(4) — copied from the payload
        data.WriteUInt16((uint16)i);           // fragIndex
        data.WriteUInt16((uint16)fragCount);   // fragCount
        data.WriteUInt8(innerOpcode);          // innerOpcode (0xCC V2 / 0xC2 V1)
        data.WriteUInt32(totalLen);            // totalLen (length of the whole inner payload)
        data.Write(body + off, fragLen);       // this fragment's slice

        Packet* fp = new Packet(data, OP_EMULEPROT);
        fp->opcode = OP_LIVE_CHUNK_FRAG;
        out.Add(fp);
    }

    delete innerPkt;   // its bytes have been copied into the fragments
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

// v0.71 IPv6 Sprint 7 — peer list V2 with CAddress. Each entry is variable-
// width: 6 bytes for v4 (1 family + 1 length + 4 addr) + 2 port = 8 bytes,
// or 18+2=20 bytes for v6. Max payload assuming all v6 + cap = 16:
// 16+2 (header) + 16 entries * 20 bytes = 338 bytes. Well under any
// reasonable packet ceiling.
Packet* CreatePeerListPacketV2(const uchar* streamKey,
    const ::CAddress* addrs, const uint16* ports, uint16 count)
{
    // Pre-compute size to size the SafeMemFile correctly. Each addr is
    // 6 or 18 bytes via WriteToBuffer; we walk once for sizing then again
    // for writing — cleaner than reallocs.
    size_t totalBytes = 16 + 2;  // streamKey + count
    for (uint16 i = 0; i < count; ++i) {
        size_t addrBytes = 2;  // family + length prefix
        switch (addrs[i].GetType()) {
            case ::CAddress::IPv4: addrBytes += 4;  break;
            case ::CAddress::IPv6: addrBytes += 16; break;
            case ::CAddress::None:                  break;
        }
        totalBytes += addrBytes + 2;  // port
    }
    CSafeMemFile data(totalBytes);
    data.WriteHash16(streamKey);
    data.WriteUInt16(count);
    for (uint16 i = 0; i < count; ++i) {
        addrs[i].WriteToBuffer(&data);
        data.WriteUInt16(ports[i]);
    }
    Packet* pkt = new Packet(data, OP_EMULEPROT);
    pkt->opcode = OP_LIVE_PEER_LIST_V2;
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

Packet* CreateAnnouncePacket(const uchar* streamKey, uint32 newestSeq, uint16 bitrate,
                             const uchar* pubkey32)
{
    // v7.6.0 — append optional 32-byte pubkey. Total: 22 or 54 bytes.
    CSafeMemFile data(pubkey32 ? 54 : 22);
    data.WriteHash16(streamKey);
    data.WriteUInt32(newestSeq);
    data.WriteUInt16(bitrate);
    if (pubkey32)
        data.Write(pubkey32, 32);

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

Packet* CreateEndPacket(const uchar* streamKey, uint8 reason, const uchar* sig64)
{
    // v7.7.0 — total: 17 bytes (legacy) or 81 bytes (with sig).
    CSafeMemFile data(sig64 ? 81 : 17);
    data.WriteHash16(streamKey);
    data.WriteUInt8(reason);
    if (sig64)
        data.Write(sig64, 64);

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
