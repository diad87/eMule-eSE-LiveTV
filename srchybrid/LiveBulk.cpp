//
// LiveBulk.cpp — Sprint E-α bulk data plane wire + multi-block FEC serialization. See LiveBulk.h.
//
#include "LiveBulk.h"
#include <cstring>

// Self-contained TU (no stdafx.h) -> misses stdafx's suppression of these purely
// informational warnings: C4710/C4711 (function [not] inlined), C5045 (Spectre note).
#pragma warning(disable : 4710 4711 5045)

namespace eSELive { namespace Bulk {
namespace {

inline void putU32(std::vector<uint8_t>& v, uint32_t x) {
    v.push_back((uint8_t)(x & 0xFF)); v.push_back((uint8_t)((x >> 8) & 0xFF));
    v.push_back((uint8_t)((x >> 16) & 0xFF)); v.push_back((uint8_t)((x >> 24) & 0xFF));
}
inline void putU64(std::vector<uint8_t>& v, uint64_t x) {
    for (int i = 0; i < 8; ++i) v.push_back((uint8_t)((x >> (i * 8)) & 0xFF));
}
inline uint32_t getU32(const uint8_t* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
inline uint64_t getU64(const uint8_t* p) {
    uint64_t x = 0; for (int i = 0; i < 8; ++i) x |= (uint64_t)p[i] << (i * 8); return x;
}

} // anonymous namespace

// ============================ §2.1 BULK_CELL ============================
void BulkCellPack(const BulkCellHeader& h, const uint8_t* payload, size_t payloadLen,
                  std::vector<uint8_t>& out) {
    out.clear();
    out.reserve(BULK_CELL_HEADER_BYTES + payloadLen);
    putU32(out, h.circ_id);
    out.push_back(h.bcmd);
    putU64(out, h.nonce_seq);
    putU32(out, (uint32_t)payloadLen);
    if (payload && payloadLen) out.insert(out.end(), payload, payload + payloadLen);
}

bool BulkCellParse(const uint8_t* buf, size_t len,
                   BulkCellHeader& outH, const uint8_t*& outPayload) {
    if (len < BULK_CELL_HEADER_BYTES) return false;
    outH.circ_id   = getU32(buf);
    outH.bcmd      = buf[4];
    outH.nonce_seq = getU64(buf + 5);
    outH.length    = getU32(buf + 13);
    if ((size_t)outH.length > len - BULK_CELL_HEADER_BYTES) return false;
    outPayload = buf + BULK_CELL_HEADER_BYTES;
    return true;
}

// ============================ §2.2 BULK_DATA ============================
void BulkDataPack(const BulkDataHeader& h, const uint8_t* symbol, std::vector<uint8_t>& out) {
    out.clear();
    out.reserve(BULK_DATA_HEADER_BYTES + BULK_SYMBOL_BYTES);
    out.insert(out.end(), h.stream_key, h.stream_key + 16);
    putU32(out, h.seq);
    out.push_back(h.block_idx);
    out.push_back(h.n_blocks);
    out.push_back(h.symbol_idx);
    out.push_back(h.k);
    out.push_back(h.r);
    out.push_back(h.flags);
    putU32(out, h.msg_len);
    out.insert(out.end(), symbol, symbol + BULK_SYMBOL_BYTES);
}

bool BulkDataParse(const uint8_t* buf, size_t len,
                   BulkDataHeader& outH, const uint8_t*& outSymbol) {
    if (len < BULK_DATA_HEADER_BYTES + (size_t)BULK_SYMBOL_BYTES) return false;
    memcpy(outH.stream_key, buf, 16);
    outH.seq        = getU32(buf + 16);
    outH.block_idx  = buf[20];
    outH.n_blocks   = buf[21];
    outH.symbol_idx = buf[22];
    outH.k          = buf[23];
    outH.r          = buf[24];
    outH.flags      = buf[25];
    outH.msg_len    = getU32(buf + 26);
    outSymbol = buf + BULK_DATA_HEADER_BYTES;
    return true;
}

// ============================ §2.3 BULK_ACK ============================
void BulkAckPack(const BulkAck& a, std::vector<uint8_t>& out) {
    out.clear();
    out.reserve(BULK_ACK_BYTES);
    out.insert(out.end(), a.stream_key, a.stream_key + 16);
    putU32(out, a.credits);
    putU32(out, a.highest_seq);
}

bool BulkAckParse(const uint8_t* buf, size_t len, BulkAck& outA) {
    if (len < BULK_ACK_BYTES) return false;
    memcpy(outA.stream_key, buf, 16);
    outA.credits     = getU32(buf + 16);
    outA.highest_seq = getU32(buf + 20);
    return true;
}

// ============================ E8.2 multi-block layout ============================
bool BulkComputeLayout(uint32_t msg_len, BulkLayout& out) {
    if (msg_len == 0) return false;
    int totalSymbols = (int)((msg_len + BULK_SYMBOL_BYTES - 1) / BULK_SYMBOL_BYTES);
    int n_blocks = (totalSymbols + BULK_MAX_K - 1) / BULK_MAX_K;
    if (n_blocks > BULK_MAX_GENS) return false;     // segment too large (>12 MB)

    out.totalSymbols = totalSymbols;
    out.n_blocks = n_blocks;
    int acc = 0;
    for (int b = 0; b < n_blocks; ++b) {
        // distribute totalSymbols as evenly as possible across blocks
        int k = totalSymbols / n_blocks + (b < totalSymbols % n_blocks ? 1 : 0);
        out.k[b] = k;
        out.start[b] = acc;
        acc += k;
    }
    return acc == totalSymbols;
}

bool BulkEncodeSegment(const uint8_t* record, size_t recordLen, int r,
                       std::vector<BulkSymbol>& outSymbols) {
    if (!record || recordLen == 0 || r < 0 || r > BULK_MAX_R) return false;
    BulkLayout L;
    if (!BulkComputeLayout((uint32_t)recordLen, L)) return false;

    // Pad the record to totalSymbols * SYM.
    std::vector<uint8_t> padded((size_t)L.totalSymbols * BULK_SYMBOL_BYTES, 0);
    memcpy(padded.data(), record, recordLen);

    outSymbols.clear();
    for (int b = 0; b < L.n_blocks; ++b) {
        const int k = L.k[b];
        // data symbol pointers into the padded buffer
        std::vector<const uint8_t*> dptr(k);
        for (int j = 0; j < k; ++j)
            dptr[j] = padded.data() + (size_t)(L.start[b] + j) * BULK_SYMBOL_BYTES;

        // encode r parity symbols for this block
        std::vector<std::vector<uint8_t> > parity(r > 0 ? r : 0);
        std::vector<uint8_t*> pptr(r > 0 ? r : 0);
        for (int i = 0; i < r; ++i) { parity[i].resize(BULK_SYMBOL_BYTES); pptr[i] = parity[i].data(); }
        if (r > 0 && !Fec::Encode(dptr.data(), k, r, pptr.data(), BULK_SYMBOL_BYTES))
            return false;

        // emit k data symbols + r parity symbols
        for (int j = 0; j < k; ++j) {
            BulkSymbol s;
            s.block_idx = (uint8_t)b; s.symbol_idx = (uint8_t)j; s.k = (uint8_t)k;
            s.data.assign(dptr[j], dptr[j] + BULK_SYMBOL_BYTES);
            outSymbols.push_back(std::move(s));
        }
        for (int i = 0; i < r; ++i) {
            BulkSymbol s;
            s.block_idx = (uint8_t)b; s.symbol_idx = (uint8_t)(k + i); s.k = (uint8_t)k;
            s.data = std::move(parity[i]);
            outSymbols.push_back(std::move(s));
        }
    }
    return true;
}

bool BulkDecodeSegment(const std::vector<BulkSymbol>& recv, uint32_t msg_len, int r,
                       std::vector<uint8_t>& outRecord) {
    if (msg_len == 0 || r < 0 || r > BULK_MAX_R) return false;
    BulkLayout L;
    if (!BulkComputeLayout(msg_len, L)) return false;

    std::vector<uint8_t> padded((size_t)L.totalSymbols * BULK_SYMBOL_BYTES, 0);

    // bucket received symbols by block
    std::vector<std::vector<const BulkSymbol*> > byBlock(L.n_blocks);
    for (const BulkSymbol& s : recv) {
        if (s.block_idx >= L.n_blocks) continue;        // stale/foreign block — ignore
        byBlock[s.block_idx].push_back(&s);
    }

    for (int b = 0; b < L.n_blocks; ++b) {
        const int k = L.k[b];
        if ((int)byBlock[b].size() < k) return false;   // not enough symbols for this block

        std::vector<const uint8_t*> rptr;
        std::vector<int>            ridx;
        rptr.reserve(byBlock[b].size());
        ridx.reserve(byBlock[b].size());
        for (const BulkSymbol* s : byBlock[b]) {
            if ((int)s->data.size() != BULK_SYMBOL_BYTES) return false;
            rptr.push_back(s->data.data());
            ridx.push_back(s->symbol_idx);
        }

        // decode the k data symbols straight into the padded record
        std::vector<uint8_t*> optr(k);
        for (int j = 0; j < k; ++j)
            optr[j] = padded.data() + (size_t)(L.start[b] + j) * BULK_SYMBOL_BYTES;

        if (!Fec::Decode(rptr.data(), ridx.data(), (int)rptr.size(), k, r,
                         optr.data(), BULK_SYMBOL_BYTES))
            return false;
    }

    outRecord.assign(padded.begin(), padded.begin() + msg_len);
    return true;
}

}} // namespace eSELive::Bulk
