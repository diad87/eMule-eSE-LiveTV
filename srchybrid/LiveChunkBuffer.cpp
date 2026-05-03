//this file is part of eMule
// eSE — Live Chunk Buffer Implementation
#include "stdafx.h"
#include "LiveChunkBuffer.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif


CLiveChunkBuffer::CLiveChunkBuffer()
    : m_writePos(0)
    , m_oldestSeq(0)
    , m_newestSeq(0)
    , m_count(0)
{
    memset(m_streamKey, 0, 16);
    for (int i = 0; i < ESE_LIVE_MAX_SEGMENTS; i++)
        m_segments[i] = NULL;
}

CLiveChunkBuffer::~CLiveChunkBuffer()
{
    Clear();
}

void CLiveChunkBuffer::AddSegment(const uchar* streamKey, uint32 seqNum,
    uint32 timestamp, const BYTE* data, uint32 dataSize, uint16 bitrate)
{
    CSingleLock lock(&m_lock, TRUE);

    // Set stream key on first segment
    if (m_count == 0)
        memcpy(m_streamKey, streamKey, 16);

    // Don't accept segments for a different stream
    if (memcmp(m_streamKey, streamKey, 16) != 0)
        return;

    // Don't accept old segments (already evicted from window)
    if (m_count > 0 && seqNum <= m_newestSeq - ESE_LIVE_MAX_SEGMENTS)
        return;

    // Don't accept duplicates
    if (HasSegment(seqNum))
        return;

    // Delete old segment in this slot
    delete m_segments[m_writePos];

    // Create new chunk
    LiveChunk* chunk = new LiveChunk();
    memcpy(chunk->streamKey, streamKey, 16);
    chunk->sequenceNumber = seqNum;
    chunk->timestamp = timestamp;
    chunk->dataSize = dataSize;
    chunk->bitrate = bitrate;

    // Copy data
    chunk->data = new BYTE[dataSize];
    memcpy(chunk->data, data, dataSize);

    // Store in ring buffer
    m_segments[m_writePos] = chunk;
    m_writePos = (m_writePos + 1) % ESE_LIVE_MAX_SEGMENTS;

    // Update bookkeeping
    if (seqNum > m_newestSeq || m_count == 0)
        m_newestSeq = seqNum;

    if (m_count < ESE_LIVE_MAX_SEGMENTS) {
        m_count++;
        if (m_count == 1)
            m_oldestSeq = seqNum;
    } else {
        // Buffer full: oldest moves forward
        m_oldestSeq = m_newestSeq - ESE_LIVE_MAX_SEGMENTS + 1;
    }
}

const LiveChunk* CLiveChunkBuffer::GetSegment(uint32 seqNum) const
{
    CSingleLock lock(&m_lock, TRUE);
    int slot = FindSlot(seqNum);
    if (slot < 0) return NULL;
    return m_segments[slot];
}

bool CLiveChunkBuffer::HasSegment(uint32 seqNum) const
{
    CSingleLock lock(&m_lock, TRUE);
    return FindSlot(seqNum) >= 0;
}

uint32 CLiveChunkBuffer::GetOldestSeq() const
{
    CSingleLock lock(&m_lock, TRUE);
    return m_oldestSeq;
}

uint32 CLiveChunkBuffer::GetNewestSeq() const
{
    CSingleLock lock(&m_lock, TRUE);
    return m_newestSeq;
}

int CLiveChunkBuffer::GetCount() const
{
    CSingleLock lock(&m_lock, TRUE);
    return m_count;
}

uint16 CLiveChunkBuffer::GetBitmap() const
{
    CSingleLock lock(&m_lock, TRUE);

    if (m_count == 0) return 0;

    uint16 bitmap = 0;
    // Bit 0 = m_oldestSeq, Bit N = m_oldestSeq + N
    for (uint32 seq = m_oldestSeq; seq <= m_newestSeq; seq++) {
        if (FindSlot(seq) >= 0) {
            uint32 bit = seq - m_oldestSeq;
            if (bit < 16)
                bitmap |= (1 << bit);
        }
    }
    return bitmap;
}

void CLiveChunkBuffer::Clear()
{
    CSingleLock lock(&m_lock, TRUE);

    for (int i = 0; i < ESE_LIVE_MAX_SEGMENTS; i++) {
        delete m_segments[i];
        m_segments[i] = NULL;
    }
    m_writePos = 0;
    m_oldestSeq = 0;
    m_newestSeq = 0;
    m_count = 0;
    memset(m_streamKey, 0, 16);
}

int CLiveChunkBuffer::FindSlot(uint32 seqNum) const
{
    // No lock here — called by methods that already hold the lock
    for (int i = 0; i < ESE_LIVE_MAX_SEGMENTS; i++) {
        if (m_segments[i] && m_segments[i]->sequenceNumber == seqNum)
            return i;
    }
    return -1;
}

// trigger rebuild
