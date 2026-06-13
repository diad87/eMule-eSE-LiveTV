//
// LiveFec.cpp — Reed-Solomon SYSTEMATIC erasure code over GF(256). See LiveFec.h.
// Sprint E-alpha (v8.1.1) task E8.1.
//
#include "LiveFec.h"
#include <cstring>

// This TU does not use the precompiled header (self-contained, no stdafx.h), so it
// misses stdafx's project-wide suppression of these purely informational warnings:
//   C4710/C4711 (function [not] inlined), C5045 (Spectre /Qspectre note).
#pragma warning(disable : 4710 4711 5045)

namespace eSELive { namespace Fec {
namespace {

// ----------------------------------------------------------------------------
// GF(256) with primitive polynomial 0x11D (x^8 + x^4 + x^3 + x^2 + 1), generator 2.
// Standard field (same as QR codes / jerasure default). Tables built once at first use.
// ----------------------------------------------------------------------------
struct GfTables {
    uint8_t exp[512];      // exp[i] = 2^i (period 255, doubled so log[a]+log[b] never overruns)
    uint8_t log[256];      // log[exp[i]] = i; log[0] unused
    uint8_t mul[256][256]; // full product table (64 KB) — one lookup per byte in the hot loop

    GfTables() {
        int x = 1;
        for (int i = 0; i < 255; ++i) {
            exp[i] = (uint8_t)x;
            log[x] = (uint8_t)i;
            x <<= 1;
            if (x & 0x100) x ^= 0x11D;
        }
        for (int i = 255; i < 512; ++i) exp[i] = exp[i - 255];
        log[0] = 0; // sentinel; never read for a real product

        for (int a = 0; a < 256; ++a) { mul[a][0] = 0; mul[0][a] = 0; }
        for (int a = 1; a < 256; ++a)
            for (int b = 1; b < 256; ++b)
                mul[a][b] = exp[log[a] + log[b]];
    }
};

// C++11 magic statics: thread-safe one-time init (VS2015+). Encode/Decode are main-thread
// per the breakdown, but this is safe regardless.
inline const GfTables& GF() { static const GfTables t; return t; }

inline uint8_t gmul(uint8_t a, uint8_t b) { return GF().mul[a][b]; }

inline uint8_t ginv(uint8_t a) {            // a != 0 required: a^-1 = 2^(255 - log a)
    return GF().exp[255 - GF().log[a]];
}

// dst[i] ^= coef * src[i]  over `len` bytes — the FEC inner loop.
inline void mulAddRow(uint8_t* dst, const uint8_t* src, uint8_t coef, int len) {
    if (coef == 0) return;
    const uint8_t* row = GF().mul[coef];
    for (int i = 0; i < len; ++i) dst[i] ^= row[src[i]];
}

// Cauchy parity matrix element C[i][j] = 1 / ( (128 + i) XOR j ).
//   X_i = 128 + i (i < r <= 8  -> 128..135, bit7 set)
//   Y_j = j       (j < k <= 64 ->   0..63,  bit7 clear)
// => X_i XOR Y_j always has bit7 set => never 0; X's distinct, Y's distinct
// => valid Cauchy matrix => every square submatrix invertible.
inline uint8_t cauchy(int i, int j) {
    return ginv((uint8_t)((128 + i) ^ j));
}

// Invert n x n GF(256) matrix `in` into `out` (Gauss-Jordan). n <= FEC_MAX_K.
// Returns false if singular (defensive; the MDS construction never produces one).
bool invertMatrix(const uint8_t* in, uint8_t* out, int n) {
    uint8_t a[FEC_MAX_K * FEC_MAX_K];
    memcpy(a, in, (size_t)n * n);
    memset(out, 0, (size_t)n * n);
    for (int i = 0; i < n; ++i) out[i * n + i] = 1;

    for (int col = 0; col < n; ++col) {
        int piv = -1;
        for (int row = col; row < n; ++row)
            if (a[row * n + col] != 0) { piv = row; break; }
        if (piv < 0) return false;

        if (piv != col) {
            for (int j = 0; j < n; ++j) {
                uint8_t t1 = a[piv * n + j];   a[piv * n + j]   = a[col * n + j];   a[col * n + j]   = t1;
                uint8_t t2 = out[piv * n + j]; out[piv * n + j] = out[col * n + j]; out[col * n + j] = t2;
            }
        }

        uint8_t inv = ginv(a[col * n + col]);
        for (int j = 0; j < n; ++j) {
            a[col * n + j]   = gmul(a[col * n + j], inv);
            out[col * n + j] = gmul(out[col * n + j], inv);
        }

        for (int row = 0; row < n; ++row) {
            if (row == col) continue;
            uint8_t f = a[row * n + col];
            if (f == 0) continue;
            for (int j = 0; j < n; ++j) {
                a[row * n + j]   ^= gmul(f, a[col * n + j]);
                out[row * n + j] ^= gmul(f, out[col * n + j]);
            }
        }
    }
    return true;
}

} // anonymous namespace

// ----------------------------------------------------------------------------
bool Encode(const uint8_t* const* data, int k, int r,
            uint8_t* const* parityOut, int symbolBytes) {
    if (k < 1 || k > FEC_MAX_K || r < 0 || r > FEC_MAX_R || symbolBytes < 1) return false;

    for (int i = 0; i < r; ++i) {
        uint8_t* p = parityOut[i];
        memset(p, 0, symbolBytes);
        for (int j = 0; j < k; ++j)
            mulAddRow(p, data[j], cauchy(i, j), symbolBytes);   // p += C[i][j] * data[j]
    }
    return true;
}

// ----------------------------------------------------------------------------
bool Decode(const uint8_t* const* recv, const int* recvIdx, int numRecv,
            int k, int r, uint8_t* const* dataOut, int symbolBytes) {
    if (k < 1 || k > FEC_MAX_K || r < 0 || r > FEC_MAX_R || symbolBytes < 1) return false;
    if (numRecv < k) return false;

    const int n = k + r;

    // Pass 1: take every available DATA symbol (idx < k). Identity rows make the decode
    // matrix sparse and, when all k are present, exactly the identity (memcpy fast path).
    const uint8_t* haveData[FEC_MAX_K];
    for (int j = 0; j < k; ++j) haveData[j] = NULL;

    const uint8_t* srcPtr[FEC_MAX_K];
    int            srcIdx[FEC_MAX_K];
    int            nsrc = 0;
    bool           usedIdx[FEC_MAX_N];
    for (int i = 0; i < n; ++i) usedIdx[i] = false;

    for (int t = 0; t < numRecv; ++t) {
        int id = recvIdx[t];
        if (id < 0 || id >= n) return false;
        if (id < k && haveData[id] == NULL) {
            haveData[id] = recv[t];
            usedIdx[id]  = true;
            srcPtr[nsrc] = recv[t]; srcIdx[nsrc] = id; ++nsrc;
        }
    }

    // Copy present data symbols straight through; record the missing ones.
    bool missing[FEC_MAX_K];
    int  numMissing = 0;
    for (int j = 0; j < k; ++j) {
        missing[j] = (haveData[j] == NULL);
        if (missing[j]) ++numMissing;
        else            memcpy(dataOut[j], haveData[j], symbolBytes);
    }
    if (numMissing == 0) return true;   // systematic fast path: all data survived

    // Pass 2: fill the source set up to k using parity symbols (idx >= k).
    for (int t = 0; t < numRecv && nsrc < k; ++t) {
        int id = recvIdx[t];
        if (id < k || usedIdx[id]) continue;
        usedIdx[id]  = true;
        srcPtr[nsrc] = recv[t]; srcIdx[nsrc] = id; ++nsrc;
    }
    if (nsrc < k) return false;          // not enough distinct symbols to decode

    // Build the k x k encoding matrix A for the chosen source rows:
    //   idx <  k -> identity row e_idx ; idx >= k -> Cauchy row (idx - k).
    uint8_t A[FEC_MAX_K * FEC_MAX_K];
    for (int s = 0; s < k; ++s) {
        uint8_t* rowp = &A[s * k];
        memset(rowp, 0, k);
        int id = srcIdx[s];
        if (id < k) rowp[id] = 1;
        else for (int j = 0; j < k; ++j) rowp[j] = cauchy(id - k, j);
    }

    uint8_t invA[FEC_MAX_K * FEC_MAX_K];
    if (!invertMatrix(A, invA, k)) return false;

    // Reconstruct ONLY the missing data symbols: data[j] = sum_s invA[j][s] * src[s].
    for (int j = 0; j < k; ++j) {
        if (!missing[j]) continue;
        uint8_t* out = dataOut[j];
        memset(out, 0, symbolBytes);
        const uint8_t* invRow = &invA[j * k];
        for (int s = 0; s < k; ++s)
            mulAddRow(out, srcPtr[s], invRow[s], symbolBytes);
    }
    return true;
}

}} // namespace eSELive::Fec
