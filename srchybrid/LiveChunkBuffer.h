//this file is part of eMule
// eSE — Live Chunk Buffer (Ring Buffer)
// Thread-safe circular buffer for HLS segments.
#pragma once

#include "LiveProtocol.h"

class CLiveChunkBuffer {
public:
    CLiveChunkBuffer();
    ~CLiveChunkBuffer();

    // Add a new segment to the buffer (overwrites oldest if full)
    void AddSegment(const uchar* streamKey, uint32 seqNum, uint32 timestamp,
                    const BYTE* data, uint32 dataSize, uint16 bitrate);

    // Get a segment by sequence number (returns NULL if not in buffer)
    // Caller must NOT delete the returned pointer.
    const LiveChunk* GetSegment(uint32 seqNum) const;

    // Check if a specific segment is available
    bool HasSegment(uint32 seqNum) const;

    // Get the oldest/newest sequence numbers currently in buffer
    uint32 GetOldestSeq() const;
    uint32 GetNewestSeq() const;

    // Get number of segments currently stored
    int GetCount() const;

    // Generate a 16-bit bitmap of available segments
    // Bit 0 = oldest, Bit 14 = newest
    uint16 GetBitmap() const;

    // Clear all segments
    void Clear();

    // Get the stream key of the current stream
    const uchar* GetStreamKey() const { return m_streamKey; }

private:
    LiveChunk*          m_segments[ESE_LIVE_MAX_SEGMENTS];
    int                 m_writePos;         // Next write position (circular)
    uint32              m_oldestSeq;        // Oldest sequence number in buffer
    uint32              m_newestSeq;        // Newest sequence number in buffer
    int                 m_count;            // Number of valid segments
    uchar               m_streamKey[16];    // Stream identifier
    mutable CCriticalSection m_lock;

    // Find the slot index for a given sequence number (-1 if not found)
    int FindSlot(uint32 seqNum) const;
};
