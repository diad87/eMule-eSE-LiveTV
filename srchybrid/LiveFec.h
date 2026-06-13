//
// LiveFec.h — Reed-Solomon SYSTEMATIC erasure code over GF(256) for eSE LiveTV.
//
// Sprint E-alpha (v8.1.1), task E8.1. Self-contained: depends only on <cstdint>.
// No eMule, STL container, threading or socket dependency — pure arithmetic, so the
// unit tests (E8.4) run with no network and the encode/decode can live on the main
// thread (see V8.1.1_SPRINT_E_BREAKDOWN.md gotchas: ~2-5 ms per 500 KB segment).
//
// Model: systematic RS(k, r). Encode takes k data symbols and produces r parity
// symbols. The k+r symbols are transported as bulk cells (one symbol = one cell,
// BULK_SYMBOL_BYTES). The decoder reconstructs the original k data symbols from ANY
// k of the k+r received symbols. Because the code is SYSTEMATIC, when all k data
// symbols survive the decode is a plain memcpy (no field math) — the common case.
//
// Construction: the (k+r) x k encoding matrix is [ I_k ; C ], where I_k is the
// identity (the systematic part: data passes through unchanged) and C is an r x k
// Cauchy matrix. Every square submatrix of a Cauchy matrix is invertible, which makes
// [ I_k ; C ] MDS: any k of its rows are linearly independent, so any k received
// symbols decode. (Proof sketch: expanding the chosen k x k matrix along its identity
// rows leaves a square submatrix of C, which is nonsingular.)
//
// The caller is responsible for padding the payload to a multiple of `symbolBytes`
// BEFORE encoding (E8.2): the padding travels inside the symbols, and the true byte
// length is carried out-of-band in the BULK_DATA header (msg_len, breakdown S2.2).
//
#pragma once
#include <cstdint>

namespace eSELive { namespace Fec {

// Dimension limits — mirror LiveCellQueue.h BULK_MAX_K / BULK_MAX_R.
// k+r must stay <= 255 so every symbol index fits a GF(256) element (it does: 72).
static const int FEC_MAX_K = 64;
static const int FEC_MAX_R = 8;
static const int FEC_MAX_N = FEC_MAX_K + FEC_MAX_R;

// Encode r parity symbols from k data symbols (systematic — data is NOT copied here;
// the systematic symbols 0..k-1 are the caller's `data` pointers unchanged).
//   data       : k input pointers, each `symbolBytes` long.
//   parityOut  : r output pointers, each `symbolBytes` long (caller-allocated).
// Returns false on invalid params (k<1 || k>FEC_MAX_K || r<0 || r>FEC_MAX_R || symbolBytes<1).
// r == 0 is valid (no parity) and is a no-op — used for the E3 demo milestone.
bool Encode(const uint8_t* const* data, int k, int r,
            uint8_t* const* parityOut, int symbolBytes);

// Decode the k data symbols from `numRecv` received symbols (numRecv >= k).
//   recv     : numRecv input pointers, each `symbolBytes` long.
//   recvIdx  : numRecv original symbol indices in [0 .. k+r-1] (which symbol each recv[] is).
//              Indices >= k are parity. Duplicate indices are tolerated (extra copies ignored).
//   dataOut  : k output pointers, each `symbolBytes` long (caller-allocated).
// Returns false on invalid params, numRecv < k, an out-of-range index, or (defensively)
// a singular decode matrix — which the MDS construction guarantees cannot happen for
// k distinct valid indices.
bool Decode(const uint8_t* const* recv, const int* recvIdx, int numRecv,
            int k, int r, uint8_t* const* dataOut, int symbolBytes);

}} // namespace eSELive::Fec
