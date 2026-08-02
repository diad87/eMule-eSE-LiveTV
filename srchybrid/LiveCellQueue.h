// this file is part of eMule eSE — Tunnel cell packing + queue (F4)
//
// Cell layout and command constants live in LiveTunnelFraming.h. CellPack
// stays here because its random padding depends on the crypto boundary;
// CCellQueue remains the synchronized bounded transport queue.
#pragma once

#include "LiveTunnelFraming.h"

#include <array>
#include <deque>

namespace eSELive {

// Pack a cell into 512 bytes. `payload` must be ≤ CELL_PAYLOAD_MAX (≤505).
// Padding bytes are filled with cryptographically random bytes so length
// is not leaked by trailing zeros.
// Returns true on success.
bool CellPack(uint32_t circ_id, uint8_t cmd,
              const uint8_t* payload, size_t payloadLen,
              uint8_t outCell[CELL_TOTAL_BYTES]);

// Unpack the header of a cell. `outPayload` is a pointer INTO `cell` (no
// copy) and `outPayloadLen` is what the sender declared.
// Returns false if the declared length > CELL_PAYLOAD_MAX (malformed).
bool CellUnpack(const uint8_t cell[CELL_TOTAL_BYTES],
                uint32_t& outCircId, uint8_t& outCmd,
                const uint8_t*& outPayload, uint16_t& outPayloadLen);

// === Cell queue ==========================================================
// Bounded FIFO of cells waiting to be sent on a TCP socket. New cells are
// added by the tunnel layer; the socket writer pulls them out in order.
// Padding (CELL_PADDING) is inserted by LiveCoverTraffic.
class CCellQueue {
public:
    explicit CCellQueue(size_t maxCells = 256);
    bool Push(const uint8_t cell[CELL_TOTAL_BYTES]);
    bool Pop(uint8_t outCell[CELL_TOTAL_BYTES]);
    size_t Count() const;
    bool IsFull() const;

private:
    mutable CCriticalSection m_lock;
    std::deque<std::array<uint8_t, CELL_TOTAL_BYTES>> m_q;
    size_t m_max;
};

}  // namespace eSELive
