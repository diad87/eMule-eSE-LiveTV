// SPDX-License-Identifier: MIT
//
// test_reach_facade.cpp — exercises the libreach C ABI (reach.h) the way an
// FFI consumer would: a mock host implements the callback vtable, and the test
// asserts the lifecycle / IoC / anti-dangling guarantees of L2.
//
// Standalone build (no MFC, no eMule), from libreach/:
//   cl /EHsc /O2 /W4 /std:c++17 /Iinclude /Febuild\test_reach_facade.exe ^
//      tests\test_reach_facade.cpp src\reach_context.cpp src\reach_codec.cpp
//   build\test_reach_facade.exe
#include "reach/reach.h"

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <vector>

static int g_fail = 0;
static int g_pass = 0;
#define CHECK(cond, msg) do { if (cond) { ++g_pass; } else { ++g_fail; \
    std::printf("  FAIL: %s  (%s:%d)\n", msg, __FILE__, __LINE__); } } while (0)

// ── Mock host ─────────────────────────────────────────────────────────────
struct MockHost {
    // The sentinel we expect to see echoed back as the `host` cookie in EVERY
    // callback. A different value here would prove the cookie plumbing is wrong.
    uint32_t        magic = 0xC0FFEE01u;

    uint64_t        clockMs = 1000;
    uint32_t        clockCalls = 0;
    uint32_t        csprngCounter = 0;

    uint32_t        sendUdpCount = 0;
    uint32_t        openTransportCount = 0;
    uint32_t        signalCount = 0;

    // Last on_result.
    int             resultCalls = 0;
    reach_peer_id   lastPeer = REACH_PEER_NONE;
    reach_result    lastResult = REACH_RESULT_PENDING;
    reach_layer     lastLayer = REACH_LAYER_NONE;
    void*           lastCookie = nullptr;

    // Re-entrancy probe: when set, on_result closes the very peer it is told
    // about — the deferred-free / no-UAF stress case.
    bool            closeOnResult = false;
    reach_context*  ctx = nullptr;
};

static MockHost* H(void* host) { return static_cast<MockHost*>(host); }

static int cb_send_udp(void* host, reach_peer_id, const reach_endpoint*,
                       const uint8_t*, size_t) {
    ++H(host)->sendUdpCount;
    return 0;
}
static int cb_open_transport(void* host, reach_peer_id, reach_layer,
                             const reach_endpoint*) {
    ++H(host)->openTransportCount;
    return 0;
}
static int cb_signal(void* host, reach_peer_id, const reach_endpoint*,
                     const uint8_t*, size_t) {
    ++H(host)->signalCount;
    return 0;
}
static int cb_csprng(void* host, uint8_t* out, size_t n) {
    MockHost* m = H(host);
    for (size_t i = 0; i < n; ++i) out[i] = static_cast<uint8_t>(m->csprngCounter++);
    return 0;
}
static uint64_t cb_clock(void* host) {
    MockHost* m = H(host);
    ++m->clockCalls;
    return m->clockMs;
}
static void cb_on_result(void* host, reach_peer_id peer,
                         reach_result result, reach_layer via) {
    MockHost* m = H(host);
    ++m->resultCalls;
    m->lastPeer = peer;
    m->lastResult = result;
    m->lastLayer = via;
    m->lastCookie = host;
    if (m->closeOnResult && m->ctx != nullptr)
        reach_peer_close(m->ctx, peer); // re-entrant close from inside a callback
}

static reach_host_callbacks makeCb() {
    reach_host_callbacks cb;
    std::memset(&cb, 0, sizeof(cb));
    cb.abi_version = REACH_ABI_VERSION;
    cb.send_udp = cb_send_udp;
    cb.open_transport = cb_open_transport;
    cb.signal_via_rdv = cb_signal;
    cb.csprng = cb_csprng;
    cb.clock_ms = cb_clock;
    cb.on_result = cb_on_result;
    cb.log = nullptr;
    return cb;
}

static void fillId(uint8_t id[REACH_KADID_SIZE], uint8_t seed) {
    for (int i = 0; i < REACH_KADID_SIZE; ++i)
        id[i] = static_cast<uint8_t>(seed + i);
}

// ── 1. create validation ──────────────────────────────────────────────────
static void test_create() {
    MockHost m;
    reach_host_callbacks cb = makeCb();
    reach_context* ctx = reach_context_create(&cb, nullptr, &m);
    CHECK(ctx != nullptr, "create ok with null cfg");
    reach_context_destroy(ctx);

    // Bad ABI rejected.
    reach_host_callbacks bad = cb;
    bad.abi_version = 999;
    CHECK(reach_context_create(&bad, nullptr, &m) == nullptr, "bad abi rejected");

    // Missing clock rejected (engine needs a monotonic clock).
    reach_host_callbacks noclk = cb;
    noclk.clock_ms = nullptr;
    CHECK(reach_context_create(&noclk, nullptr, &m) == nullptr, "null clock rejected");

    // Null callbacks rejected.
    CHECK(reach_context_create(nullptr, nullptr, &m) == nullptr, "null cb rejected");

    CHECK(reach_abi_version() == REACH_ABI_VERSION, "abi version accessor");
    // destroy(null) is a harmless no-op.
    reach_context_destroy(nullptr);
}

// ── 2. connect: handle minting + idempotency ───────────────────────────────
static void test_connect_idempotent() {
    MockHost m;
    reach_host_callbacks cb = makeCb();
    reach_context* ctx = reach_context_create(&cb, nullptr, &m);

    uint8_t a[REACH_KADID_SIZE]; fillId(a, 0x10);
    reach_peer_id p1 = REACH_PEER_NONE, p1b = REACH_PEER_NONE;
    CHECK(reach_connect(ctx, a, nullptr, 0, &p1) == REACH_OK, "connect A ok");
    CHECK(p1 != REACH_PEER_NONE, "handle non-zero");
    // Same NodeID → same handle, no new connect counted.
    CHECK(reach_connect(ctx, a, nullptr, 0, &p1b) == REACH_OK, "reconnect A ok");
    CHECK(p1 == p1b, "idempotent same handle");

    uint8_t b[REACH_KADID_SIZE]; fillId(b, 0x90);
    reach_peer_id p2 = REACH_PEER_NONE;
    CHECK(reach_connect(ctx, b, nullptr, 0, &p2) == REACH_OK, "connect B ok");
    CHECK(p2 != p1, "distinct peers distinct handles");

    reach_stats st;
    CHECK(reach_get_stats(ctx, &st) == REACH_OK, "stats ok");
    CHECK(st.connects_total == 2, "two unique connects");
    CHECK(st.peers_pending == 2, "two pending");
    CHECK(st.peers_active == 2, "two active");

    reach_context_destroy(ctx);
}

// ── 3. tick resolves to CLASSIC (degenerate cascade) + cookie integrity ─────
static void test_classic_fallback() {
    MockHost m;
    reach_host_callbacks cb = makeCb();
    reach_context* ctx = reach_context_create(&cb, nullptr, &m);

    uint8_t a[REACH_KADID_SIZE]; fillId(a, 0x22);
    reach_peer_id p = REACH_PEER_NONE;
    reach_connect(ctx, a, nullptr, 0, &p);

    const int pending = reach_tick(ctx);
    CHECK(pending == 0, "no peers pending after tick");
    CHECK(m.resultCalls == 1, "on_result fired once");
    CHECK(m.lastPeer == p, "on_result for our peer");
    CHECK(m.lastResult == REACH_RESULT_CLASSIC, "resolves CLASSIC (no layers in L2)");
    CHECK(m.lastLayer == REACH_LAYER_CLASSIC, "via CLASSIC layer");
    // The context cookie must arrive intact — never a per-peer host pointer.
    CHECK(m.lastCookie == static_cast<void*>(&m), "cookie is the context cookie");
    // L2 has no active layers: it must not have touched transport/signaling.
    CHECK(m.sendUdpCount == 0 && m.openTransportCount == 0 && m.signalCount == 0,
          "no transport/signaling in L2");
    CHECK(m.clockCalls > 0, "clock was injected/used");

    reach_stats st; reach_get_stats(ctx, &st);
    CHECK(st.resolved_classic == 1, "stats classic == 1");

    reach_context_destroy(ctx);
}

// ── 4. generation handles defeat ABA (stale handle never reused) ────────────
static void test_aba_generation() {
    MockHost m;
    reach_host_callbacks cb = makeCb();
    reach_context* ctx = reach_context_create(&cb, nullptr, &m);

    uint8_t a[REACH_KADID_SIZE]; fillId(a, 0x33);
    reach_peer_id h1 = REACH_PEER_NONE;
    reach_connect(ctx, a, nullptr, 0, &h1);
    // Standalone close (not inside a callback) reclaims the slot immediately.
    CHECK(reach_peer_close(ctx, h1) == REACH_OK, "close A ok");
    // Closing again is harmless and reports stale, never crashes.
    CHECK(reach_peer_close(ctx, h1) == REACH_ERR_STALE_PEER, "double close stale");

    uint8_t b[REACH_KADID_SIZE]; fillId(b, 0x44);
    reach_peer_id h2 = REACH_PEER_NONE;
    reach_connect(ctx, b, nullptr, 0, &h2);
    CHECK(h2 != h1, "reused slot yields a different handle (generation bumped)");
    CHECK((h1 >> 32) == (h2 >> 32), "same slot index reused");
    CHECK((h1 & 0xFFFFFFFFu) != (h2 & 0xFFFFFFFFu), "generation differs");
    // The stale handle must not address the new occupant.
    CHECK(reach_peer_close(ctx, h1) == REACH_ERR_STALE_PEER, "stale h1 rejected");

    reach_context_destroy(ctx);
}

// ── 5. deferred free: closing a peer from inside on_result is UAF-free ───────
static void test_deferred_free_no_uaf() {
    MockHost m;
    m.closeOnResult = true;
    reach_host_callbacks cb = makeCb();
    reach_context* ctx = reach_context_create(&cb, nullptr, &m);
    m.ctx = ctx;

    uint8_t a[REACH_KADID_SIZE]; fillId(a, 0x55);
    reach_peer_id p = REACH_PEER_NONE;
    reach_connect(ctx, a, nullptr, 0, &p);

    // tick → resolvePeer → on_result → reach_peer_close(p). The slot must be
    // tombstoned during the tick and reclaimed only as tick unwinds — no
    // dangling index, no crash.
    const int pending = reach_tick(ctx);
    CHECK(pending == 0, "deferred: nothing pending after tick");
    CHECK(m.resultCalls == 1, "deferred: on_result fired");

    // After the sweep the handle is gone and the slot is free for reuse.
    CHECK(reach_peer_close(ctx, p) == REACH_ERR_STALE_PEER, "peer reclaimed post-tick");
    reach_stats st; reach_get_stats(ctx, &st);
    CHECK(st.peers_active == 0, "no active peers after deferred close");
    CHECK(st.resolved_classic == 1, "result still counted before close");

    // Slot is genuinely reusable.
    uint8_t b[REACH_KADID_SIZE]; fillId(b, 0x66);
    reach_peer_id p2 = REACH_PEER_NONE;
    CHECK(reach_connect(ctx, b, nullptr, 0, &p2) == REACH_OK, "reuse after deferred free");
    CHECK((p2 >> 32) == (p >> 32), "reclaimed slot index reused");

    reach_context_destroy(ctx);
}

// ── 6. stats snapshot is an immutable value copy ────────────────────────────
static void test_stats_snapshot() {
    MockHost m;
    reach_host_callbacks cb = makeCb();
    reach_context* ctx = reach_context_create(&cb, nullptr, &m);

    uint8_t a[REACH_KADID_SIZE]; fillId(a, 0x77);
    reach_peer_id p = REACH_PEER_NONE;
    reach_connect(ctx, a, nullptr, 0, &p);

    reach_stats snap1; reach_get_stats(ctx, &snap1);
    CHECK(snap1.connects_total == 1, "snapshot 1 connects");

    uint8_t b[REACH_KADID_SIZE]; fillId(b, 0x88);
    reach_peer_id p2 = REACH_PEER_NONE;
    reach_connect(ctx, b, nullptr, 0, &p2);

    // The earlier snapshot is a copy — engine mutation does not reach back.
    CHECK(snap1.connects_total == 1, "old snapshot unchanged");
    reach_stats snap2; reach_get_stats(ctx, &snap2);
    CHECK(snap2.connects_total == 2, "fresh snapshot reflects new connect");

    // on_transport_result on an unknown handle is harmless.
    CHECK(reach_on_transport_result(ctx, 0xDEADBEEF, 1) == REACH_ERR_STALE_PEER,
          "transport result on stale handle");

    reach_context_destroy(ctx);
}

// ── 7. connect carrying a TAG_REACH vector decodes (and malformed degrades) ──
static void test_connect_with_vector() {
    MockHost m;
    reach_host_callbacks cb = makeCb();
    reach_context* ctx = reach_context_create(&cb, nullptr, &m);

    // A minimal valid TAG_REACH payload: version 1, caps 0x0009, nRdv 0.
    const uint8_t good[] = {0x01, 0x09, 0x00, 0x00};
    uint8_t a[REACH_KADID_SIZE]; fillId(a, 0x99);
    reach_peer_id p = REACH_PEER_NONE;
    CHECK(reach_connect(ctx, a, good, sizeof(good), &p) == REACH_OK, "connect w/ vector");

    // Malformed vector must NOT fail the connect — it degrades to "no vector"
    // (project from classic). nRdv=4 is over the max.
    const uint8_t bad[] = {0x01, 0x00, 0x00, 0x04};
    uint8_t b[REACH_KADID_SIZE]; fillId(b, 0xA1);
    reach_peer_id p2 = REACH_PEER_NONE;
    CHECK(reach_connect(ctx, b, bad, sizeof(bad), &p2) == REACH_OK,
          "malformed vector degrades, connect still ok");

    reach_context_destroy(ctx);
}

int main() {
    std::printf("test_reach_facade — libreach L2 C-ABI / IoC / lifecycle\n");
    test_create();
    test_connect_idempotent();
    test_classic_fallback();
    test_aba_generation();
    test_deferred_free_no_uaf();
    test_stats_snapshot();
    test_connect_with_vector();
    std::printf("\nTOTAL: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
