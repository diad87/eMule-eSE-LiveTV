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

// === Tunnel sub-protocol framing (v8.1 Sprint A) =========================

void PackSubHeader(uint8_t sub_cmd, uint32_t req_id, uint16_t bodyLen,
                   uint8_t out[SUB_HEADER_BYTES])
{
    out[0] = sub_cmd;
    out[1] = (uint8_t)(req_id & 0xFF);
    out[2] = (uint8_t)((req_id >> 8) & 0xFF);
    out[3] = (uint8_t)((req_id >> 16) & 0xFF);
    out[4] = (uint8_t)((req_id >> 24) & 0xFF);
    out[5] = (uint8_t)(bodyLen & 0xFF);
    out[6] = (uint8_t)((bodyLen >> 8) & 0xFF);
}

bool ParseSubHeader(const uint8_t* plain, size_t len,
                    uint8_t& outSubCmd, uint32_t& outReqId,
                    uint16_t& outBodyLen, const uint8_t*& outBody)
{
    if (!plain || len < SUB_HEADER_BYTES) return false;
    outSubCmd = plain[0];
    outReqId  = (uint32_t)plain[1]
              | ((uint32_t)plain[2] << 8)
              | ((uint32_t)plain[3] << 16)
              | ((uint32_t)plain[4] << 24);
    outBodyLen = (uint16_t)plain[5] | ((uint16_t)plain[6] << 8);
    // The declared body must actually fit within the peeled plaintext.
    if (SUB_HEADER_BYTES + (size_t)outBodyLen > len) return false;
    outBody = plain + SUB_HEADER_BYTES;
    return true;
}

void PackFragHeader(uint16_t fragIndex, uint16_t fragCount, uint32_t msgTotal,
                    uint8_t out[FRAG_HEADER_BYTES])
{
    out[0] = (uint8_t)(fragIndex & 0xFF);
    out[1] = (uint8_t)((fragIndex >> 8) & 0xFF);
    out[2] = (uint8_t)(fragCount & 0xFF);
    out[3] = (uint8_t)((fragCount >> 8) & 0xFF);
    out[4] = (uint8_t)(msgTotal & 0xFF);
    out[5] = (uint8_t)((msgTotal >> 8) & 0xFF);
    out[6] = (uint8_t)((msgTotal >> 16) & 0xFF);
    out[7] = (uint8_t)((msgTotal >> 24) & 0xFF);
}

bool ParseFragHeader(const uint8_t* body, size_t bodyLen,
                     uint16_t& outFragIndex, uint16_t& outFragCount,
                     uint32_t& outMsgTotal,
                     const uint8_t*& outFragData, size_t& outFragDataLen)
{
    if (!body || bodyLen < FRAG_HEADER_BYTES) return false;
    outFragIndex = (uint16_t)body[0] | ((uint16_t)body[1] << 8);
    outFragCount = (uint16_t)body[2] | ((uint16_t)body[3] << 8);
    outMsgTotal  = (uint32_t)body[4]
                 | ((uint32_t)body[5] << 8)
                 | ((uint32_t)body[6] << 16)
                 | ((uint32_t)body[7] << 24);
    outFragData    = body + FRAG_HEADER_BYTES;
    outFragDataLen = bodyLen - FRAG_HEADER_BYTES;
    return true;
}

// === Multi-cell message layer (v8.1 Sprint A1.3 / A1.4) ==================

bool SplitIntoCells(uint8_t sub_cmd, uint32_t req_id,
                    const uint8_t* message, size_t messageLen,
                    size_t fragDataMax,
                    std::vector<std::vector<uint8_t>>& outCells)
{
    outCells.clear();
    if (fragDataMax == 0 || fragDataMax > CELL_PAYLOAD_MAX) return false;
    if (messageLen > TUN_MSG_MAX_BYTES) return false;
    if (messageLen > 0 && !message) return false;

    // A 0-byte message is still carried as one (empty) fragment.
    const size_t fragCount = (messageLen == 0)
                           ? 1
                           : (messageLen + fragDataMax - 1) / fragDataMax;
    if (fragCount > TUN_MSG_MAX_FRAGS) return false;

    outCells.reserve(fragCount);
    for (size_t idx = 0; idx < fragCount; ++idx) {
        const size_t off   = idx * fragDataMax;
        const size_t chunk = (messageLen - off < fragDataMax)
                           ? (messageLen - off) : fragDataMax;
        std::vector<uint8_t> cell(SUB_HEADER_BYTES + FRAG_HEADER_BYTES + chunk);
        PackSubHeader(sub_cmd, req_id,
                      (uint16_t)(FRAG_HEADER_BYTES + chunk), cell.data());
        PackFragHeader((uint16_t)idx, (uint16_t)fragCount,
                       (uint32_t)messageLen, cell.data() + SUB_HEADER_BYTES);
        if (chunk > 0)
            memcpy(cell.data() + SUB_HEADER_BYTES + FRAG_HEADER_BYTES,
                   message + off, chunk);
        outCells.push_back(std::move(cell));
    }
    return true;
}

ReassemblyResult ReassemblyIngest(ReassemblyEntry& e,
                                  uint16_t fragIndex, uint16_t fragCount,
                                  uint32_t msgTotal,
                                  const uint8_t* fragData, size_t fragDataLen)
{
    // A1.6 -- sanity / anti-DoS caps.
    if (fragCount == 0 || fragCount > TUN_MSG_MAX_FRAGS)
        return ReassemblyResult::Error;
    if (msgTotal > TUN_MSG_MAX_BYTES || fragDataLen > TUN_MSG_MAX_BYTES)
        return ReassemblyResult::Error;
    if (fragIndex >= fragCount)
        return ReassemblyResult::Error;
    if (fragDataLen > 0 && !fragData)
        return ReassemblyResult::Error;

    if (!e.started) {
        e.expected_total = msgTotal;
        e.frag_count     = fragCount;
        e.got_count      = 0;
        e.frags.assign(fragCount, std::vector<uint8_t>());
        e.got.assign(fragCount, false);
        e.started        = true;
    } else if (fragCount != e.frag_count || msgTotal != e.expected_total) {
        // All fragments of one message must agree on count + total.
        return ReassemblyResult::Error;
    }

    if (!e.got[fragIndex]) {
        e.frags[fragIndex].assign(fragData, fragData + fragDataLen);
        e.got[fragIndex] = true;
        ++e.got_count;
    }
    // A duplicate fragment (same index) is silently ignored.

    if (e.got_count < e.frag_count)
        return ReassemblyResult::Incomplete;

    // All fragments present -> concatenate in frag_index order.
    size_t total = 0;
    for (size_t i = 0; i < e.frags.size(); ++i)
        total += e.frags[i].size();
    if (total != e.expected_total)
        return ReassemblyResult::Error;   // declared size != actual

    e.message.clear();
    e.message.reserve(total);
    for (size_t i = 0; i < e.frags.size(); ++i)
        e.message.insert(e.message.end(), e.frags[i].begin(), e.frags[i].end());
    return ReassemblyResult::Complete;
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
