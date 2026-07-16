//
// test_livebulk.cpp — deterministic unit tests for LiveBulk (Sprint E-α: wire format §2.1-2.3
// + multi-block FEC serialization E8.2). No network, no MFC, no CryptoPP.
//
// Build standalone (from srchybrid/):
//   cl /EHsc /O2 /Fe:test_livebulk.exe tests\test_livebulk.cpp LiveBulk.cpp LiveFec.cpp
//   test_livebulk.exe        (exit 0 = all pass)
//
#include "../LiveBulk.h"
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <vector>

using namespace eSELive::Bulk;

static int g_fail = 0, g_pass = 0;
#define CHECK(cond, msg) do { if (cond) { ++g_pass; } else { ++g_fail; \
    printf("  FAIL: %s  (%s:%d)\n", msg, __FILE__, __LINE__); } } while (0)

struct Rng {
    uint32_t s;
    explicit Rng(uint32_t seed) : s(seed ? seed : 0xC0FFEEu) {}
    uint32_t next() { s ^= s << 13; s ^= s >> 17; s ^= s << 5; return s; }
    int range(int n) { return (int)(next() % (uint32_t)n); }
    uint8_t byte() { return (uint8_t)(next() >> 24); }
};

// ---- [1] wire round-trips -------------------------------------------------------------
static void testWire() {
    printf("[1] wire round-trips (BULK_CELL / BULK_DATA / BULK_ACK)\n");
    Rng rng(0x1234);

    // BULK_CELL: header + opaque (encrypted) payload
    {
        BulkCellHeader h;
        h.circ_id = 0xDEADBEEF; h.bcmd = BULK_DATA; h.nonce_seq = 0x0123456789ABCDEFull;
        std::vector<uint8_t> pl(1000);
        for (auto& b : pl) b = rng.byte();
        std::vector<uint8_t> wire;
        BulkCellPack(h, pl.data(), pl.size(), wire);
        CHECK(wire.size() == BULK_CELL_HEADER_BYTES + pl.size(), "cell wire size");

        BulkCellHeader h2; const uint8_t* p2 = nullptr;
        CHECK(BulkCellParse(wire.data(), wire.size(), h2, p2), "cell parse ok");
        CHECK(h2.circ_id == h.circ_id && h2.bcmd == h.bcmd &&
              h2.nonce_seq == h.nonce_seq && h2.length == pl.size(), "cell fields");
        CHECK(p2 && memcmp(p2, pl.data(), pl.size()) == 0, "cell payload bytes");

        // truncated / inconsistent length must be rejected
        BulkCellHeader h3; const uint8_t* p3 = nullptr;
        CHECK(!BulkCellParse(wire.data(), BULK_CELL_HEADER_BYTES - 1, h3, p3), "cell reject short");
        std::vector<uint8_t> bad = wire; bad.resize(BULK_CELL_HEADER_BYTES + 10); // claims 1000, has 10
        CHECK(!BulkCellParse(bad.data(), bad.size(), h3, p3), "cell reject len overrun");
    }

    // BULK_DATA: header + one 16KB symbol
    {
        BulkDataHeader h;
        for (int i = 0; i < 16; ++i) h.stream_key[i] = (uint8_t)(i * 7 + 1);
        h.seq = 42; h.block_idx = 2; h.n_blocks = 3; h.symbol_idx = 17;
        h.k = 62; h.r = 3; h.flags = 0; h.msg_len = 3000003;
        std::vector<uint8_t> sym(BULK_SYMBOL_BYTES);
        for (auto& b : sym) b = rng.byte();
        std::vector<uint8_t> wire;
        BulkDataPack(h, sym.data(), wire);
        CHECK(wire.size() == BULK_DATA_HEADER_BYTES + BULK_SYMBOL_BYTES, "data wire size");

        BulkDataHeader h2; const uint8_t* s2 = nullptr;
        CHECK(BulkDataParse(wire.data(), wire.size(), h2, s2), "data parse ok");
        CHECK(memcmp(h2.stream_key, h.stream_key, 16) == 0 && h2.seq == h.seq &&
              h2.block_idx == h.block_idx && h2.n_blocks == h.n_blocks &&
              h2.symbol_idx == h.symbol_idx && h2.k == h.k && h2.r == h.r &&
              h2.msg_len == h.msg_len, "data fields");
        CHECK(s2 && memcmp(s2, sym.data(), BULK_SYMBOL_BYTES) == 0, "data symbol bytes");
        CHECK(!BulkDataParse(wire.data(), wire.size() - 1, h2, s2), "data reject short");
    }

    // BULK_ACK
    {
        BulkAck a;
        for (int i = 0; i < 16; ++i) a.stream_key[i] = (uint8_t)(0xA0 + i);
        a.credits = 96; a.highest_seq = 123456;
        std::vector<uint8_t> wire; BulkAckPack(a, wire);
        CHECK(wire.size() == BULK_ACK_BYTES, "ack wire size");
        BulkAck a2;
        CHECK(BulkAckParse(wire.data(), wire.size(), a2), "ack parse ok");
        CHECK(memcmp(a2.stream_key, a.stream_key, 16) == 0 &&
              a2.credits == a.credits && a2.highest_seq == a.highest_seq, "ack fields");
    }
}

// ---- [2] layout ----------------------------------------------------------------------
static void testLayout() {
    printf("[2] multi-block layout (segment -> blocks)\n");
    const int SYM = BULK_SYMBOL_BYTES;

    auto expectBlocks = [&](uint32_t msg_len, int wantTotal, int wantBlocks) {
        BulkLayout L;
        CHECK(BulkComputeLayout(msg_len, L), "layout ok");
        CHECK(L.totalSymbols == wantTotal, "layout totalSymbols");
        CHECK(L.n_blocks == wantBlocks, "layout n_blocks");
        int acc = 0;
        for (int b = 0; b < L.n_blocks; ++b) { CHECK(L.k[b] >= 1 && L.k[b] <= BULK_MAX_K, "layout k in range"); acc += L.k[b]; }
        CHECK(acc == L.totalSymbols, "layout blocks sum to total");
        CHECK(L.start[0] == 0, "layout first start 0");
    };

    expectBlocks(1, 1, 1);                       // tiny
    expectBlocks((uint32_t)SYM, 1, 1);           // exactly one symbol
    expectBlocks((uint32_t)SYM * 64, 64, 1);     // exactly one full block
    expectBlocks((uint32_t)SYM * 64 + 1, 65, 2); // one over -> 2 blocks
    expectBlocks(3000003u, 184, 3);              // the 12000 kbps / 3 MB operating point

    // oversize: > 12 MB (BULK_MAX_K*BULK_MAX_GENS = 768 symbols) must be rejected
    BulkLayout L;
    CHECK(!BulkComputeLayout((uint32_t)SYM * (BULK_MAX_K * BULK_MAX_GENS) + 1, L), "layout reject oversize");
    CHECK(!BulkComputeLayout(0, L), "layout reject empty");
}

// ---- [3] multi-block segment round-trip with loss ------------------------------------
// Encode a record, drop up to r symbols PER block at random survivable positions, decode,
// assert byte-identical.
static bool segmentRoundTrip(int recordLen, int r, Rng& rng, bool dropMax) {
    std::vector<uint8_t> record(recordLen);
    for (auto& b : record) b = rng.byte();

    std::vector<BulkSymbol> syms;
    if (!BulkEncodeSegment(record.data(), record.size(), r, syms)) return false;

    // group by block to drop within survivable bounds
    BulkLayout L;
    if (!BulkComputeLayout((uint32_t)recordLen, L)) return false;

    // mark drops: for each block drop d (<=r) random symbols of its k+r
    std::vector<bool> dropped(syms.size(), false);
    // index symbols by (block -> list of positions in syms)
    std::vector<std::vector<int> > idxByBlock(L.n_blocks);
    for (int i = 0; i < (int)syms.size(); ++i) idxByBlock[syms[i].block_idx].push_back(i);
    for (int b = 0; b < L.n_blocks; ++b) {
        int d = dropMax ? r : rng.range(r + 1);
        // choose d distinct positions within this block
        std::vector<int>& pos = idxByBlock[b];
        std::vector<bool> chosen(pos.size(), false);
        int got = 0, guard = 0;
        while (got < d && guard++ < 1000) {
            int p = rng.range((int)pos.size());
            if (!chosen[p]) { chosen[p] = true; dropped[pos[p]] = true; ++got; }
        }
    }

    std::vector<BulkSymbol> recv;
    for (int i = 0; i < (int)syms.size(); ++i) if (!dropped[i]) recv.push_back(syms[i]);

    std::vector<uint8_t> out;
    if (!BulkDecodeSegment(recv, (uint32_t)recordLen, r, out)) return false;
    return out.size() == record.size() && memcmp(out.data(), record.data(), record.size()) == 0;
}

static void testSegment() {
    printf("[3] multi-block segment round-trip (random + worst-case drops)\n");
    Rng rng(0xBEEF);
    const int SYM = BULK_SYMBOL_BYTES;
    struct Case { int len; int r; };
    Case cases[] = {
        { 1, 0 }, { 1, 3 }, { 100, 3 },
        { SYM, 0 }, { SYM, 3 },
        { SYM * 64, 3 },          // exactly one block
        { SYM * 64 + 5, 3 },      // 2 blocks
        { 500003, 3 },            // ~0.5 MB
        { 3000003, 3 },           // 3 MB / 12000 kbps — 3 blocks
        { SYM * 184, 4 },         // 3 blocks, max r per block
    };
    for (Case c : cases) {
        char m[96];
        sprintf_s(m, sizeof(m), "segment len=%d r=%d random drops", c.len, c.r);
        CHECK(segmentRoundTrip(c.len, c.r, rng, /*dropMax*/false), m);
        if (c.r > 0) {
            sprintf_s(m, sizeof(m), "segment len=%d r=%d WORST drops (exactly r/block)", c.len, c.r);
            CHECK(segmentRoundTrip(c.len, c.r, rng, /*dropMax*/true), m);
        }
    }
}

// ---- [4] over-loss must fail gracefully (not crash) ----------------------------------
static void testOverLoss() {
    printf("[4] over-loss decode fails gracefully\n");
    Rng rng(0x77);
    const int recordLen = 3000003, r = 3;
    std::vector<uint8_t> record(recordLen);
    for (auto& b : record) b = rng.byte();
    std::vector<BulkSymbol> syms;
    CHECK(BulkEncodeSegment(record.data(), record.size(), r, syms), "encode for over-loss");

    // drop r+1 symbols from block 0 -> that block is unrecoverable
    int dropped = 0;
    std::vector<BulkSymbol> recv;
    for (const BulkSymbol& s : syms) {
        if (s.block_idx == 0 && dropped < r + 1) { ++dropped; continue; }
        recv.push_back(s);
    }
    std::vector<uint8_t> out;
    CHECK(!BulkDecodeSegment(recv, (uint32_t)recordLen, r, out), "decode rejects unrecoverable block");
}

// ---- [5] anti-replay window (B2) -----------------------------------------------------
static void testReplay() {
    printf("[5] anti-replay sliding window (B2)\n");
    {
        BulkReplayWindow w;
        // in-order accept
        for (uint64_t s = 0; s < 100; ++s) CHECK(w.Check(s), "in-order accept");
        // replay of any seen seq rejected
        CHECK(!w.Check(50), "replay rejected");
        CHECK(!w.Check(99), "replay rejected (highest)");
        // out-of-order within window accepted once, then rejected
        CHECK(w.Check(100), "advance");
        CHECK(w.Check(95) == false, "95 already seen -> reject"); // 95 was accepted in the loop
    }
    {
        BulkReplayWindow w;
        // accept a high seq, then a reordered-but-fresh lower seq inside window
        CHECK(w.Check(500), "first high");
        CHECK(w.Check(499), "reordered fresh inside window");
        CHECK(w.Check(450), "older fresh inside window");
        CHECK(!w.Check(499), "replay of reordered rejected");
        // jump far ahead -> old ones now out of window
        CHECK(w.Check(5000), "big jump");
        CHECK(!w.Check(500), "now too old -> reject");
        CHECK(w.Check(4999), "fresh near new highest");
    }
    {
        // gap larger than the window clears everything cleanly (no false replay)
        BulkReplayWindow w;
        CHECK(w.Check(10), "seed");
        CHECK(w.Check(10 + BulkReplayWindow::WINDOW_BITS + 5), "jump past window");
        CHECK(w.Check(10 + BulkReplayWindow::WINDOW_BITS + 4), "fresh below new highest accepted");
    }
}

int main() {
    printf("=== LiveBulk unit tests (wire + E8.2 multi-block) ===\n");
    testWire();
    testLayout();
    testSegment();
    testOverLoss();
    testReplay();
    printf("\n%d checks passed, %d failed.\n", g_pass, g_fail);
    if (g_fail == 0) printf("ALL PASS\n");
    return g_fail;
}
