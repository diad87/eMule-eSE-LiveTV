// this file is part of eMule eSE — Tunnel cell wire format + queue impl (F4)
#include "stdafx.h"
#include "LiveCellQueue.h"
#include "LiveOnionCrypto.h"   // SecureRandomBytes for padding

#include <array>
#include <deque>

namespace eSELive {

bool CellPack(uint32_t circ_id, uint8_t cmd,
              const uint8_t* payload, size_t payloadLen,
              uint8_t outCell[CELL_TOTAL_BYTES])
{
    if (!outCell) return false;
    if (payloadLen > CELL_PAYLOAD_MAX) return false;
    if (payloadLen > 0 && !payload) return false;

    // Header (little-endian)
    outCell[0] = (uint8_t)(circ_id & 0xFF);
    outCell[1] = (uint8_t)((circ_id >> 8) & 0xFF);
    outCell[2] = (uint8_t)((circ_id >> 16) & 0xFF);
    outCell[3] = (uint8_t)((circ_id >> 24) & 0xFF);
    outCell[4] = cmd;
    const uint16_t len16 = (uint16_t)payloadLen;
    outCell[5] = (uint8_t)(len16 & 0xFF);
    outCell[6] = (uint8_t)((len16 >> 8) & 0xFF);

    // Payload bytes
    if (payloadLen > 0)
        memcpy(outCell + CELL_HEADER_BYTES, payload, payloadLen);

    // Random padding for the rest. Important: random not zero, otherwise
    // an observer can guess length from trailing zeros.
    const size_t padLen = CELL_PAYLOAD_MAX - payloadLen;
    if (padLen > 0)
        SecureRandomBytes(outCell + CELL_HEADER_BYTES + payloadLen, padLen);
    return true;
}

bool CellUnpack(const uint8_t cell[CELL_TOTAL_BYTES],
                uint32_t& outCircId, uint8_t& outCmd,
                const uint8_t*& outPayload, uint16_t& outPayloadLen)
{
    if (!cell) return false;
    outCircId = (uint32_t)cell[0]
              | ((uint32_t)cell[1] << 8)
              | ((uint32_t)cell[2] << 16)
              | ((uint32_t)cell[3] << 24);
    outCmd = cell[4];
    outPayloadLen = (uint16_t)cell[5] | ((uint16_t)cell[6] << 8);
    if (outPayloadLen > CELL_PAYLOAD_MAX) return false;
    outPayload = cell + CELL_HEADER_BYTES;
    return true;
}

// === Queue ===============================================================

CCellQueue::CCellQueue(size_t maxCells)
    : m_max(maxCells)
{}

bool CCellQueue::Push(const uint8_t cell[CELL_TOTAL_BYTES])
{
    CSingleLock lock(&m_lock, TRUE);
    if (m_q.size() >= m_max) return false;
    std::array<uint8_t, CELL_TOTAL_BYTES> a;
    memcpy(a.data(), cell, CELL_TOTAL_BYTES);
    m_q.push_back(a);
    return true;
}

bool CCellQueue::Pop(uint8_t outCell[CELL_TOTAL_BYTES])
{
    CSingleLock lock(&m_lock, TRUE);
    if (m_q.empty()) return false;
    memcpy(outCell, m_q.front().data(), CELL_TOTAL_BYTES);
    m_q.pop_front();
    return true;
}

size_t CCellQueue::Count() const
{
    CSingleLock lock(&m_lock, TRUE);
    return m_q.size();
}

bool CCellQueue::IsFull() const
{
    CSingleLock lock(&m_lock, TRUE);
    return m_q.size() >= m_max;
}

}  // namespace eSELive
