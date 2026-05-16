#include "stdafx.h"
#include "LiveChunkBuffer.h"

CLiveChunkBuffer::CLiveChunkBuffer() : m_writePos(0), m_latestSeq(0) {
    for (int i = 0; i < MAX_SEGMENTS; i++) {
        m_segments[i].dataSize = 0;
        m_segments[i].sequenceNumber = 0;
        m_segments[i].data = NULL;
    }
}

CLiveChunkBuffer::~CLiveChunkBuffer() {
    CSingleLock lock(&m_lock, TRUE);
    for (int i = 0; i < MAX_SEGMENTS; i++) {
        FreeSegment(i);
    }
}

void CLiveChunkBuffer::FreeSegment(int index) {
    if (m_segments[index].data != NULL) {
        delete[] m_segments[index].data;
        m_segments[index].data = NULL;
    }
    m_segments[index].dataSize = 0;
}

void CLiveChunkBuffer::AddSegment(const LiveChunk& chunk) {
    CSingleLock lock(&m_lock, TRUE);

    // Verificar si es mas reciente
    if (chunk.sequenceNumber > m_latestSeq || m_latestSeq == 0) {
        m_latestSeq = chunk.sequenceNumber;
    } else if (m_latestSeq > chunk.sequenceNumber + MAX_SEGMENTS) {
        // Demasiado antiguo, se descarta (cayó fuera del ring buffer de MAX_SEGMENTS)
        return;
    }

    // Calcular bucket fisico en el ring modulo MAX_SEGMENTS
    int index = chunk.sequenceNumber % MAX_SEGMENTS;

    // Liberar si ya hay un segmento muy antiguo ahí
    FreeSegment(index);

    // Clonar
    m_segments[index] = chunk;
    if (chunk.dataSize > 0 && chunk.data != NULL) {
        m_segments[index].data = new byte[chunk.dataSize];
        memcpy(m_segments[index].data, chunk.data, chunk.dataSize);
    }
}

const LiveChunk* CLiveChunkBuffer::GetSegment(uint32 seqNum) const {
    CSingleLock lock(&m_lock, TRUE);
    
    // Si pedir algo mas viejo de 15 secuencias atras, no lo tenemos logicamente
    if (m_latestSeq >= MAX_SEGMENTS && seqNum < m_latestSeq - MAX_SEGMENTS + 1)
        return NULL;
        
    int index = seqNum % MAX_SEGMENTS;
    
    if (m_segments[index].sequenceNumber == seqNum && m_segments[index].dataSize > 0) {
        return &m_segments[index];
    }
    return NULL;
}

bool CLiveChunkBuffer::HasSegment(uint32 seqNum) const {
    return GetSegment(seqNum) != NULL;
}

uint32 CLiveChunkBuffer::GetOldestSeq() const {
    CSingleLock lock(&m_lock, TRUE);
    if (m_latestSeq < MAX_SEGMENTS) {
        return m_latestSeq > 0 ? 1 : 0;
    }
    return m_latestSeq - MAX_SEGMENTS + 1;
}

uint32 CLiveChunkBuffer::GetNewestSeq() const {
    CSingleLock lock(&m_lock, TRUE);
    return m_latestSeq;
}

uint16 CLiveChunkBuffer::GetBitmap() const {
    CSingleLock lock(&m_lock, TRUE);
    uint16 bitmap = 0;
    
    uint32 newest = m_latestSeq;
    if (newest == 0) return 0;
    
    int elements = min(newest, (uint32)MAX_SEGMENTS);
    for (int i = 0; i < elements; i++) {
        uint32 seqToCheck = newest - i;
        int index = seqToCheck % MAX_SEGMENTS;
        if (m_segments[index].sequenceNumber == seqToCheck && m_segments[index].dataSize > 0) {
            bitmap |= (1 << i);
        }
    }
    
    return bitmap;
}
