//
// test_livefec.cpp — deterministic unit tests for LiveFec (Sprint E-alpha, task E8.4).
//
// No network, no eMule headers. Build standalone (from srchybrid/):
//   cl /EHsc /O2 /Fe:test_livefec.exe tests\test_livefec.cpp LiveFec.cpp
//   test_livefec.exe        (exit 0 = all pass, non-zero = failure count)
//
// Coverage:
//   1. GF(256) field axioms (a * a^-1 == 1, distributivity spot-check).
//   2. RS round-trip for a grid of (k, r) with EVERY erasure pattern of size 0..r
//      (exhaustive for small k+r; randomized for large) — recovered data byte-identical.
//   3. Worst case: drop exactly r symbols, including r drops all in the data part.
//   4. numRecv > k (extra/duplicate symbols ignored correctly).
//   5. A realistic ~500 KB "CHUNK_V2 segment": pad -> split into k -> encode r ->
//      drop r at random -> decode -> reconstructed buffer byte-identical (incl. padding).
//
#include "../LiveFec.h"
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <vector>

using namespace eSELive::Fec;

static int g_fail = 0;
static int g_pass = 0;
#define CHECK(cond, msg) do { if (cond) { ++g_pass; } else { ++g_fail; \
    printf("  FAIL: %s  (%s:%d)\n", msg, __FILE__, __LINE__); } } while (0)

// Deterministic PRNG (xorshift32) — reproducible across runs/platforms.
struct Rng {
    uint32_t s;
    explicit Rng(uint32_t seed) : s(seed ? seed : 0xC0FFEEu) {}
    uint32_t next() { s ^= s << 13; s ^= s >> 17; s ^= s << 5; return s; }
    int range(int n) { return (int)(next() % (uint32_t)n); }
    uint8_t byte() { return (uint8_t)(next() >> 24); }
};

static int popcount32(uint32_t v) { int c = 0; while (v) { v &= v - 1; ++c; } return c; }

// Re-derive GF(256) here (mirror of LiveFec.cpp) only to validate the field axioms
// independently of the library's internal tables.
static uint8_t T_exp[512], T_log[256];
static void buildField() {
    int x = 1;
    for (int i = 0; i < 255; ++i) { T_exp[i] = (uint8_t)x; T_log[x] = (uint8_t)i; x <<= 1; if (x & 0x100) x ^= 0x11D; }
    for (int i = 255; i < 512; ++i) T_exp[i] = T_exp[i - 255];
}
static uint8_t mul(uint8_t a, uint8_t b) { return (a && b) ? T_exp[T_log[a] + T_log[b]] : 0; }
static uint8_t inv(uint8_t a) { return T_exp[255 - T_log[a]]; }

static void testField() {
    printf("[1] GF(256) field axioms\n");
    for (int a = 1; a < 256; ++a)
        CHECK(mul((uint8_t)a, inv((uint8_t)a)) == 1, "a * a^-1 == 1");
    // distributivity: a*(b+c) == a*b + a*c  (+ is XOR)
    Rng rng(1);
    for (int t = 0; t < 5000; ++t) {
        uint8_t a = rng.byte(), b = rng.byte(), c = rng.byte();
        CHECK(mul(a, (uint8_t)(b ^ c)) == (uint8_t)(mul(a, b) ^ mul(a, c)), "distributivity");
    }
}

// One encode + decode round-trip with the given dropped indices. Returns true if the
// recovered data matches the original byte-for-byte.
static bool roundTrip(int k, int r, int symBytes, const std::vector<int>& drop, Rng& rng) {
    std::vector<std::vector<uint8_t> > data(k, std::vector<uint8_t>(symBytes));
    std::vector<std::vector<uint8_t> > parity(r, std::vector<uint8_t>(symBytes));
    for (int j = 0; j < k; ++j) for (int b = 0; b < symBytes; ++b) data[j][b] = rng.byte();

    std::vector<const uint8_t*> dptr(k);
    std::vector<uint8_t*>       pptr(r > 0 ? r : 1);
    for (int j = 0; j < k; ++j) dptr[j] = data[j].data();
    for (int i = 0; i < r; ++i) pptr[i] = parity[i].data();
    if (!Encode(dptr.data(), k, r, r > 0 ? pptr.data() : NULL, symBytes)) return false;

    // All k+r symbols (0..k-1 = data, k..k+r-1 = parity), minus the dropped set.
    bool dropped[FEC_MAX_N] = { false };
    for (size_t i = 0; i < drop.size(); ++i) dropped[drop[i]] = true;

    std::vector<const uint8_t*> recv;
    std::vector<int>            ridx;
    for (int idx = 0; idx < k + r; ++idx) {
        if (dropped[idx]) continue;
        recv.push_back(idx < k ? data[idx].data() : parity[idx - k].data());
        ridx.push_back(idx);
    }
    if ((int)recv.size() < k) return false; // dropped more than r -> not recoverable

    std::vector<std::vector<uint8_t> > out(k, std::vector<uint8_t>(symBytes));
    std::vector<uint8_t*> optr(k);
    for (int j = 0; j < k; ++j) optr[j] = out[j].data();
    if (!Decode(recv.data(), ridx.data(), (int)recv.size(), k, r, optr.data(), symBytes))
        return false;

    for (int j = 0; j < k; ++j)
        if (memcmp(out[j].data(), data[j].data(), symBytes) != 0) return false;
    return true;
}

static void testRoundTrips() {
    printf("[2] RS encode/decode round-trips (exhaustive small, randomized large)\n");
    Rng rng(0xBADC0DE);
    const int ks[] = { 1, 2, 3, 4, 7, 8, 16, 31, 32, 63, 64 };
    const int rs[] = { 0, 1, 2, 3, 5, 8 };

    for (size_t ki = 0; ki < sizeof(ks)/sizeof(ks[0]); ++ki) {
        for (size_t ri = 0; ri < sizeof(rs)/sizeof(rs[0]); ++ri) {
            int k = ks[ki], r = rs[ri];
            if (k + r > FEC_MAX_N) continue;
            int symBytes = 32; // small for the sweep
            // r == 0: only the no-drop case is recoverable.
            // Try every erasure pattern of size e = 0..r among the k+r symbols.
            // Exhaustive when k+r is small; otherwise sample random patterns.
            int n = k + r;
            for (int e = 0; e <= r; ++e) {
                bool exhaustive = (n <= 12);
                if (exhaustive) {
                    // all C(n, e) subsets via bit masks
                    for (uint32_t mask = 0; mask < (1u << n); ++mask) {
                        if (popcount32(mask) != e) continue;
                        std::vector<int> drop;
                        for (int b = 0; b < n; ++b) if (mask & (1u << b)) drop.push_back(b);
                        CHECK(roundTrip(k, r, symBytes, drop, rng), "round-trip (exhaustive)");
                    }
                } else {
                    for (int rep = 0; rep < 40; ++rep) {
                        // pick e distinct indices
                        bool chosen[FEC_MAX_N] = { false };
                        std::vector<int> drop;
                        int guard = 0;
                        while ((int)drop.size() < e && guard++ < 1000) {
                            int idx = rng.range(n);
                            if (!chosen[idx]) { chosen[idx] = true; drop.push_back(idx); }
                        }
                        CHECK(roundTrip(k, r, symBytes, drop, rng), "round-trip (random)");
                    }
                }
            }
        }
    }
}

static void testWorstCaseAndExtras() {
    printf("[3] worst case (drop exactly r, incl. all-in-data) + [4] extra symbols\n");
    Rng rng(0x5EED);

    // Drop the first r DATA symbols (forces full parity use, no identity rows for them).
    {
        int k = 32, r = 5, symBytes = 64;
        std::vector<int> drop;
        for (int i = 0; i < r; ++i) drop.push_back(i); // data symbols 0..r-1
        CHECK(roundTrip(k, r, symBytes, drop, rng), "drop r data symbols");
    }
    // Drop r symbols straddling data and parity.
    {
        int k = 16, r = 4, symBytes = 64;
        int dd[] = { 0, 7, 15, 18 }; // two data, two parity (16,18 -> parity 0,2)
        std::vector<int> drop(dd, dd + 4);
        CHECK(roundTrip(k, r, symBytes, drop, rng), "drop r straddling data/parity");
    }
    // numRecv > k: feed ALL k+r symbols (no drops) — decoder must ignore the surplus.
    {
        int k = 10, r = 4, symBytes = 48;
        std::vector<int> noDrop;
        CHECK(roundTrip(k, r, symBytes, noDrop, rng), "numRecv > k (all symbols)");
    }
}

static void testRealisticSegment() {
    printf("[5] realistic ~500 KB CHUNK_V2 segment through FEC\n");
    Rng rng(0xABCDEF01);
    const int SYM = 16384;              // BULK_SYMBOL_BYTES
    const int payloadLen = 500003;      // odd size -> exercises padding
    std::vector<uint8_t> payload(payloadLen);
    for (int i = 0; i < payloadLen; ++i) payload[i] = rng.byte();

    int k = (payloadLen + SYM - 1) / SYM;          // 31 symbols
    int r = 3;
    CHECK(k <= FEC_MAX_K, "k within bound");

    // Pad to k*SYM and split into k data symbols.
    std::vector<uint8_t> padded(static_cast<size_t>(k) * SYM, 0);
    memcpy(padded.data(), payload.data(), payloadLen);

    std::vector<const uint8_t*> dptr(k);
    for (int j = 0; j < k; ++j) dptr[j] = padded.data() + (size_t)j * SYM;
    std::vector<std::vector<uint8_t> > parity(r, std::vector<uint8_t>(SYM));
    std::vector<uint8_t*> pptr(r);
    for (int i = 0; i < r; ++i) pptr[i] = parity[i].data();
    CHECK(Encode(dptr.data(), k, r, pptr.data(), SYM), "encode segment");

    // Drop r random distinct symbols out of k+r.
    int n = k + r;
    bool dropped[FEC_MAX_N] = { false };
    int got = 0;
    while (got < r) { int idx = rng.range(n); if (!dropped[idx]) { dropped[idx] = true; ++got; } }

    std::vector<const uint8_t*> recv;
    std::vector<int> ridx;
    for (int idx = 0; idx < n; ++idx) {
        if (dropped[idx]) continue;
        recv.push_back(idx < k ? (padded.data() + (size_t)idx * SYM) : parity[idx - k].data());
        ridx.push_back(idx);
    }
    std::vector<uint8_t> outBuf(static_cast<size_t>(k) * SYM);
    std::vector<uint8_t*> optr(k);
    for (int j = 0; j < k; ++j) optr[j] = outBuf.data() + (size_t)j * SYM;
    CHECK(Decode(recv.data(), ridx.data(), (int)recv.size(), k, r, optr.data(), SYM),
          "decode segment");

    // The reconstructed first payloadLen bytes must be byte-identical to the original.
    CHECK(memcmp(outBuf.data(), payload.data(), payloadLen) == 0, "segment byte-identical");
}

// [6] Multi-block segment (the REAL 12000 kbps operating point, B1): a ~3 MB segment is
// split into ceil(totalSymbols / FEC_MAX_K) RS blocks, each k<=64, encoded/decoded
// independently, then concatenated — exactly how E8.2 will use the per-block primitive.
static void testMultiBlockSegment() {
    printf("[6] multi-block 3 MB segment (12000 kbps operating point)\n");
    Rng rng(0x3B05EED);
    const int SYM = 16384;              // BULK_SYMBOL_BYTES
    const int payloadLen = 3000003;     // ~12000 kbps * 2 s, odd -> exercises padding
    const int r = 3;
    std::vector<uint8_t> payload(payloadLen);
    for (int i = 0; i < payloadLen; ++i) payload[i] = rng.byte();

    int totalSymbols = (payloadLen + SYM - 1) / SYM;          // 184
    int numBlocks    = (totalSymbols + FEC_MAX_K - 1) / FEC_MAX_K; // 3
    CHECK(numBlocks == 3, "3 blocks for a 3 MB segment");

    std::vector<uint8_t> padded(static_cast<size_t>(totalSymbols) * SYM, 0);
    memcpy(padded.data(), payload.data(), payloadLen);
    std::vector<uint8_t> outBuf(static_cast<size_t>(totalSymbols) * SYM, 0xFF);

    int placed = 0;
    for (int b = 0; b < numBlocks; ++b) {
        // even distribution: 184 -> 62/61/61
        int k = totalSymbols / numBlocks + (b < totalSymbols % numBlocks ? 1 : 0);
        int blockStart = placed; placed += k;

        std::vector<const uint8_t*> dptr(k);
        for (int j = 0; j < k; ++j) dptr[j] = padded.data() + (size_t)(blockStart + j) * SYM;
        std::vector<std::vector<uint8_t> > parity(r, std::vector<uint8_t>(SYM));
        std::vector<uint8_t*> pptr(r);
        for (int i = 0; i < r; ++i) pptr[i] = parity[i].data();
        CHECK(Encode(dptr.data(), k, r, pptr.data(), SYM), "encode block");

        // drop r distinct random symbols out of this block's k+r
        int n = k + r;
        bool dropped[FEC_MAX_N] = { false };
        int got = 0;
        while (got < r) { int idx = rng.range(n); if (!dropped[idx]) { dropped[idx] = true; ++got; } }

        std::vector<const uint8_t*> recv; std::vector<int> ridx;
        for (int idx = 0; idx < n; ++idx) {
            if (dropped[idx]) continue;
            recv.push_back(idx < k ? padded.data() + (size_t)(blockStart + idx) * SYM
                                   : parity[idx - k].data());
            ridx.push_back(idx);
        }
        std::vector<uint8_t*> optr(k);
        for (int j = 0; j < k; ++j) optr[j] = outBuf.data() + (size_t)(blockStart + j) * SYM;
        CHECK(Decode(recv.data(), ridx.data(), (int)recv.size(), k, r, optr.data(), SYM),
              "decode block");
    }
    CHECK(placed == totalSymbols, "all symbols placed across blocks");
    CHECK(memcmp(outBuf.data(), payload.data(), payloadLen) == 0,
          "3 MB segment byte-identical after multi-block FEC");
}

int main() {
    buildField();
    printf("=== LiveFec unit tests (E8.4) ===\n");
    testField();
    testRoundTrips();
    testWorstCaseAndExtras();
    testRealisticSegment();
    testMultiBlockSegment();
    printf("\n%d checks passed, %d failed.\n", g_pass, g_fail);
    if (g_fail == 0) printf("ALL PASS\n");
    return g_fail;
}
