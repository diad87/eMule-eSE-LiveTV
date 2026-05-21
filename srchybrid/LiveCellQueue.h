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
#include <vector>

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

// === Tunnel sub-protocol framing (v8.1 Sprint A) =========================
// Two headers ride INSIDE the AEAD-decrypted CELL_RELAY payload, above the
// 512-byte cell layer. Neither changes the cell wire format -> a v8.0.0
// peer is unaffected.
//
// Sub-header (7 B) -- at the start of every CELL_RELAY plaintext:
//   [0]     sub_cmd   uint8       (TunnelOpCmd)
//   [1..4]  req_id    uint32 LE   correlates request <-> reply / message id
//   [5..6]  body_len  uint16 LE   useful body bytes in THIS cell
//
// Fragment header (8 B) -- present in the body of every v8.1 multi-cell op
// (sub_cmd >= TUN_MULTICELL_OP_MIN). Absent for legacy single-cell ops.
//   [0..1]  frag_index  uint16 LE   0-based
//   [2..3]  frag_count  uint16 LE   total fragments (1 = single-cell message)
//   [4..7]  msg_total   uint32 LE   bytes of the whole reassembled message
const size_t  SUB_HEADER_BYTES     = 7;
const size_t  FRAG_HEADER_BYTES    = 8;
const uint8_t TUN_MULTICELL_OP_MIN = 0x40;   // sub_cmd >= this carries a frag header

// Caps on a logical (reassembled) tunnel message + lifetimes (Sprint A5).
const size_t   TUN_MSG_MAX_BYTES       = 65536;
const uint32_t TUN_REASSEMBLY_TTL_MS   = 8000;
const uint32_t TUN_REQUEST_HARD_TTL_MS = 60000;
const int      TUN_SEND_RETRIES        = 2;

// Pack the 7-byte sub-header into `out` (must hold >= SUB_HEADER_BYTES).
void PackSubHeader(uint8_t sub_cmd, uint32_t req_id, uint16_t bodyLen,
                   uint8_t out[SUB_HEADER_BYTES]);

// Parse + validate the 7-byte sub-header. `plain`/`len` is the peeled
// CELL_RELAY plaintext. On success outBody points INTO `plain` and
// outBodyLen bytes are guaranteed present. Returns false if the buffer is
// too short or the declared body overruns `len`.
bool ParseSubHeader(const uint8_t* plain, size_t len,
                    uint8_t& outSubCmd, uint32_t& outReqId,
                    uint16_t& outBodyLen, const uint8_t*& outBody);

// Pack the 8-byte fragment header into `out` (must hold >= FRAG_HEADER_BYTES).
void PackFragHeader(uint16_t fragIndex, uint16_t fragCount, uint32_t msgTotal,
                    uint8_t out[FRAG_HEADER_BYTES]);

// Parse the 8-byte fragment header from the start of a multi-cell op body.
// outFragData points INTO `body`. Returns false if `body` is shorter than
// FRAG_HEADER_BYTES.
bool ParseFragHeader(const uint8_t* body, size_t bodyLen,
                     uint16_t& outFragIndex, uint16_t& outFragCount,
                     uint32_t& outMsgTotal,
                     const uint8_t*& outFragData, size_t& outFragDataLen);

// === Multi-cell message layer (v8.1 Sprint A1.3 / A1.4) ==================
// A logical tunnel message larger than one cell is split into fragments;
// each fragment is one CELL_RELAY plaintext = sub-header + fragment header +
// frag data. Reassembly concatenates the fragments in frag_index order.

// Anti-DoS bound: max fragments accumulated for one logical message.
const uint16_t TUN_MSG_MAX_FRAGS = 256;

// A1.3 -- Split a logical message into ready CELL_RELAY plaintexts.
// `fragDataMax` = frag-data bytes per cell (e.g. 458 on a 2-hop circuit).
// Each outCells[i] is sub-header + fragment header + a slice of `message`;
// the caller onion-encrypts and CellPacks each one. Returns false if the
// message exceeds TUN_MSG_MAX_BYTES / TUN_MSG_MAX_FRAGS, or fragDataMax is
// out of range (0 or > CELL_PAYLOAD_MAX).
bool SplitIntoCells(uint8_t sub_cmd, uint32_t req_id,
                    const uint8_t* message, size_t messageLen,
                    size_t fragDataMax,
                    std::vector<std::vector<uint8_t>>& outCells);

// Reassembly outcome for a single ingested fragment.
enum class ReassemblyResult : uint8_t {
    Incomplete = 0,   // fragment accepted; message not yet complete
    Complete   = 1,   // all fragments in; ReassemblyEntry::message is filled
    Error      = 2,   // malformed / inconsistent / over-cap -> drop the entry
};

// Accumulates the fragments of one multi-cell message. The caller keys these
// by req_id (e.g. in a std::map) and feeds fragments to ReassemblyIngest.
struct ReassemblyEntry {
    uint32_t expected_total  = 0;   // msg_total declared by the fragments
    uint16_t frag_count      = 0;   // total fragments expected
    uint16_t got_count       = 0;   // distinct fragments received so far
    bool     started         = false;
    uint32_t first_seen_tick = 0;   // GetTickCount() of 1st fragment (TTL, A1.5)
    std::vector<std::vector<uint8_t>> frags;    // frags[i] = fragment i's bytes
    std::vector<bool>                 got;      // got[i] = fragment i received
    std::vector<uint8_t>              message;  // reassembled msg (on Complete)
};

// A1.4 + A1.6 -- Ingest one parsed fragment into `e`. On Complete, `e.message`
// holds the fully reassembled logical message. On Error the caller must
// discard the entry (do not feed it more fragments).
ReassemblyResult ReassemblyIngest(ReassemblyEntry& e,
                                  uint16_t fragIndex, uint16_t fragCount,
                                  uint32_t msgTotal,
                                  const uint8_t* fragData, size_t fragDataLen);

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
