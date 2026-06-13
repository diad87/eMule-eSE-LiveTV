//
// LiveBulk.h — Sprint E-α (v8.1.1) bulk data plane: wire format + multi-block FEC
// serialization. Self-contained: depends only on <cstdint>/<vector>/<cstring> and LiveFec.h
// (NO MFC, NO CryptoPP, NO sockets) so the unit tests run with no network, exactly like
// LiveFec. The onion AEAD that wraps a bulk cell lives at the circuit layer (LiveCircuit,
// E1.4) — this header is only the byte framing + the segment <-> symbols mapping (E8.2).
//
// Layering (outermost first):
//   OP_LIVE_BULK_CELL (0xD9) wire  =  BulkCellHeader (§2.1) + AEAD( payload )
//   payload (after onion-decrypt)  =  BULK_DATA (§2.2)  |  BULK_ACK (§2.3)
//   BULK_DATA.symbol               =  one FEC symbol of a (seq, block_idx) RS block
//
// A whole signed OP_LIVE_CHUNK_V2 record (the "record") is the FEC INPUT: it is padded to a
// multiple of BULK_SYMBOL_BYTES, split into ceil(symbols / BULK_MAX_K) independent RS blocks
// (B1 — a 12000 kbps / 3 MB segment is ~184 symbols = 3 blocks of k<=64), and each block is
// RS(k_b, r) encoded by LiveFec. The decoder needs any k_b symbols PER block, concatenates
// the decoded blocks, truncates to msg_len, and yields the record byte-identical — so the
// existing sha256+Ed25519 verify downstream is unchanged.
//
#pragma once
#include <cstdint>
#include <vector>
#include "LiveFec.h"

namespace eSELive { namespace Bulk {

// ---- Constants (§2.5, calibrated to the validated 12000 kbps deployment) ----
static const int      BULK_SYMBOL_BYTES   = 16384;          // 1 FEC symbol = 1 bulk cell payload unit
static const int      BULK_MAX_K          = Fec::FEC_MAX_K; // 64 — data symbols PER BLOCK (<=1 MB/block)
static const int      BULK_MAX_R          = Fec::FEC_MAX_R; // 8
static const int      BULK_MAX_GENS       = 12;             // max FEC blocks/segment (12 MB = ESE_FRAG_MAX_TOTAL)
static const int      BULK_DEFAULT_R      = 3;              // parity/block; adaptive 2..5 (E4')
static const int      BULK_WINDOW_SYMBOLS = 96;             // initial credits/circuit (~1.5 MB); floor, EWMA-BDP at runtime
static const uint32_t BULK_SUB_TTL_MS     = 30000;
static const int      BULK_EXIT_MAX_PROXIED_STREAMS = 2;
static const int      BULK_EXIT_MAX_SUBS_PER_STREAM = 4;

// bcmd values (BulkCellHeader.bcmd)
enum BulkCmd : uint8_t {
    BULK_DATA = 0x01,
    BULK_ACK  = 0x02,
};

// ============================ §2.1 OP_LIVE_BULK_CELL wire ============================
// [0..3] circ_id u32 | [4] bcmd u8 | [5..12] nonce_seq u64 | [13..16] length u32 | [17..] payload
struct BulkCellHeader {
    uint32_t circ_id   = 0;
    uint8_t  bcmd      = 0;
    uint64_t nonce_seq = 0;   // explicit AEAD nonce (B2) — never derived from a local counter
    uint32_t length    = 0;   // bytes of (encrypted) payload that follow
};
static const size_t BULK_CELL_HEADER_BYTES = 17;

// Serialize header + payload into `out` (resized). `payload` may be NULL iff payloadLen==0.
void BulkCellPack(const BulkCellHeader& h, const uint8_t* payload, size_t payloadLen,
                  std::vector<uint8_t>& out);
// Parse a bulk cell. `outPayload` points INTO `buf`. Returns false if truncated/inconsistent.
bool BulkCellParse(const uint8_t* buf, size_t len,
                   BulkCellHeader& outH, const uint8_t*& outPayload);

// ============================ §2.2 BULK_DATA payload ================================
// stream_key 16 | seq u32 | block_idx u8 | n_blocks u8 | symbol_idx u8 | k u8 | r u8 |
// flags u8 | msg_len u32 | symbol[BULK_SYMBOL_BYTES]
struct BulkDataHeader {
    uint8_t  stream_key[16] = {0};
    uint32_t seq        = 0;
    uint8_t  block_idx  = 0;
    uint8_t  n_blocks   = 0;
    uint8_t  symbol_idx = 0;   // 0..k+r-1 WITHIN the block (>=k = parity)
    uint8_t  k          = 0;   // data symbols of THIS block
    uint8_t  r          = 0;   // parity symbols of THIS block
    uint8_t  flags      = 0;
    uint32_t msg_len    = 0;   // real CHUNK_V2 record bytes (pre-padding, whole segment)
};
static const size_t BULK_DATA_HEADER_BYTES = 30;

// Serialize header + a BULK_SYMBOL_BYTES symbol into `out` (resized to header+symbol).
void BulkDataPack(const BulkDataHeader& h, const uint8_t* symbol, std::vector<uint8_t>& out);
// Parse BULK_DATA. `outSymbol` points INTO `buf` and is guaranteed BULK_SYMBOL_BYTES long.
bool BulkDataParse(const uint8_t* buf, size_t len,
                   BulkDataHeader& outH, const uint8_t*& outSymbol);

// ============================ §2.3 BULK_ACK payload =================================
// stream_key 16 | credits u32 | highest_seq u32
struct BulkAck {
    uint8_t  stream_key[16] = {0};
    uint32_t credits     = 0;
    uint32_t highest_seq = 0;
};
static const size_t BULK_ACK_BYTES = 24;
void BulkAckPack(const BulkAck& a, std::vector<uint8_t>& out);
bool BulkAckParse(const uint8_t* buf, size_t len, BulkAck& outA);

// ============================ B2 anti-replay window ================================
// Sliding-window replay guard over nonce_seq, per (circuit, direction). Because the bulk
// path accepts out-of-order cells (FEC/NACK/stripe), the monotonic counter no longer
// protects against replay — this does. Classic IPsec-style window: accept a seq once iff
// it is newer than the window OR inside the window and not yet seen. Header-only so the
// receiver (LiveTunnel) and the unit tests share one implementation.
class BulkReplayWindow {
public:
    static const uint64_t WINDOW_BITS = 1024;     // tolerate deep reorder across stripes
    BulkReplayWindow() : m_highest(0), m_started(false), m_bits(WINDOW_BITS / 64, 0) {}

    // Returns true if `seq` is fresh and should be accepted (and records it);
    // false if it is a replay or has fallen out of the window (too old).
    bool Check(uint64_t seq) {
        if (!m_started) { m_started = true; m_highest = seq; setBit(seq); return true; }
        if (seq > m_highest) {
            uint64_t shift = seq - m_highest;
            if (shift >= WINDOW_BITS) {
                for (auto& w : m_bits) w = 0;      // window fully advanced past everything
            } else {
                for (uint64_t i = 1; i <= shift; ++i) clearBit(m_highest + i);
            }
            m_highest = seq; setBit(seq); return true;
        }
        if (m_highest - seq >= WINDOW_BITS) return false;   // too old
        if (getBit(seq)) return false;                      // replay
        setBit(seq); return true;
    }

private:
    void setBit(uint64_t s)   { uint64_t p = s % WINDOW_BITS; m_bits[p >> 6] |=  (1ull << (p & 63)); }
    void clearBit(uint64_t s) { uint64_t p = s % WINDOW_BITS; m_bits[p >> 6] &= ~(1ull << (p & 63)); }
    bool getBit(uint64_t s) const { uint64_t p = s % WINDOW_BITS; return (m_bits[p >> 6] >> (p & 63)) & 1ull; }

    uint64_t              m_highest;
    bool                  m_started;
    std::vector<uint64_t> m_bits;
};

// ============================ E8.2 multi-block FEC layout ===========================
// Deterministic split of a segment of `msg_len` bytes into FEC blocks. Encoder and decoder
// MUST agree on this purely from msg_len, so it is carried implicitly (no extra wire).
struct BulkLayout {
    int      totalSymbols = 0;
    int      n_blocks     = 0;
    int      k[BULK_MAX_GENS]     = {0};   // data symbols per block
    int      start[BULK_MAX_GENS] = {0};   // first GLOBAL symbol index of each block
};
// Returns false if msg_len==0 or the segment exceeds BULK_MAX_K*BULK_MAX_GENS symbols (>12 MB).
bool BulkComputeLayout(uint32_t msg_len, BulkLayout& out);

// One encoded symbol ready to be wrapped as BULK_DATA and onion-sent (E3.3).
struct BulkSymbol {
    uint8_t              block_idx  = 0;
    uint8_t              symbol_idx = 0;   // 0..k_b+r-1
    uint8_t              k          = 0;   // k of this block
    std::vector<uint8_t> data;            // BULK_SYMBOL_BYTES
};

// E8.2 encode: a whole CHUNK_V2 `record` -> all (k_b + r) symbols of every block.
// `r` is the uniform parity count per block (2..BULK_MAX_R). Returns false on bad params.
bool BulkEncodeSegment(const uint8_t* record, size_t recordLen, int r,
                       std::vector<BulkSymbol>& outSymbols);

// E8.2 decode: from any >=k_b received symbols PER block, rebuild the record byte-identical.
// `recv` carries (block_idx, symbol_idx, data) for each received symbol; `msg_len`/`r` pin
// the layout (same as encode). `outRecord` is resized to msg_len. Returns false if any block
// has < k_b symbols or params are inconsistent.
bool BulkDecodeSegment(const std::vector<BulkSymbol>& recv, uint32_t msg_len, int r,
                       std::vector<uint8_t>& outRecord);

}} // namespace eSELive::Bulk
