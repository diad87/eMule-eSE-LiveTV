// this file is part of eMule eSE — Tunnel cell wire format + queue (F4)
//
// Cell layout (Cap 5 §5.7.3 thesis): 512 bytes fixed.
//   [0..3]   circ_id          uint32 LE
//   [4]      cmd              uint8
//   [5..6]   length           uint16 LE  (useful payload bytes)
//   [7..511] payload+padding  505 bytes; bytes after `length` are random
//
// Cell commands (Cap 5 §5.5.2):
//   0x01 CELL_CREATE     — start a new circuit (handshake 1)
//   0x02 CELL_CREATED    — handshake 2
//   0x03 CELL_EXTEND     — extend circuit to next hop
//   0x04 CELL_EXTENDED   — extend confirmation
//   0x05 CELL_RELAY      — data cell (onion-encrypted)
//   0x06 CELL_DESTROY    — close circuit
//   0x10 CELL_PADDING    — cover-traffic dummy
#pragma once

#include <array>
#include <deque>

namespace eSELive {

const size_t CELL_TOTAL_BYTES   = 512;
const size_t CELL_HEADER_BYTES  = 7;       // circ_id(4) + cmd(1) + length(2)
const size_t CELL_PAYLOAD_MAX   = CELL_TOTAL_BYTES - CELL_HEADER_BYTES;  // 505

enum CellCmd : uint8_t {
    CELL_CREATE    = 0x01,
    CELL_CREATED   = 0x02,
    CELL_EXTEND    = 0x03,
    CELL_EXTENDED  = 0x04,
    CELL_RELAY     = 0x05,
    CELL_DESTROY   = 0x06,
    CELL_PADDING   = 0x10
};

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
