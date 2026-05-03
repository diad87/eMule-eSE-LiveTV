#pragma once
#ifndef LIVE_CHUNK_BUFFER_H
#define LIVE_CHUNK_BUFFER_H

#include "../stdafx.h"
#include "../kademlia/utils/UInt128.h"
#include <afxmt.h>

struct LiveChunk {
    uchar   streamKey[16];      // MD4 del stream (identificador unico)
    uint32  sequenceNumber;     // Numero de segmento (0, 1, 2, 3...)
    uint32  timestamp;          // Timestamp unix del segmento
    uint32  dataSize;           // Tamano en bytes del segmento .ts
    uint16  bitrate;            // Bitrate en kbps
    byte*   data;               // Datos raw del segmento .ts

    LiveChunk() {
        memset(streamKey, 0, 16);
        sequenceNumber = 0;
        timestamp = 0;
        dataSize = 0;
        bitrate = 0;
        data = NULL;
    }
};

class CLiveChunkBuffer {
public:
    CLiveChunkBuffer();
    ~CLiveChunkBuffer();

    static const int MAX_SEGMENTS = 15;  // 60s de ventana (4s x 15)

    void AddSegment(const LiveChunk& chunk);
    const LiveChunk* GetSegment(uint32 seqNum) const;
    bool HasSegment(uint32 seqNum) const;
    uint32 GetOldestSeq() const;
    uint32 GetNewestSeq() const;
    uint16 GetBitmap() const; // Representa que segmentos de (Newest - 14) a (Newest) tenemos

private:
    LiveChunk m_segments[MAX_SEGMENTS];
    int m_writePos;
    uint32 m_latestSeq;
    mutable CCriticalSection m_lock;

    void FreeSegment(int index);
};

#endif
