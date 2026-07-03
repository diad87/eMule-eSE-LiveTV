// SPDX-License-Identifier: MIT
//
// test_reach_actuator.cpp — drives the L3 cascade ACTUATOR through the C ABI with
// a programmable mock host: reach_set_candidates (Option B) + advance() dispatch
// + NodeID route memory (nominated pair) + timer-free eviction (validate-on-use,
// TTL, budget timeout).
//
// Standalone build (no MFC), from libreach/:
//   cl /EHsc /O2 /W4 /std:c++17 /Iinclude /Febuild\test_reach_actuator.exe ^
//      tests\test_reach_actuator.cpp src\reach_context.cpp src\reach_codec.cpp ^
//      src\reach_cascade.cpp
//   build\test_reach_actuator.exe
#include "reach/reach.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

static int g_pass = 0, g_fail = 0;
#define CHECK(cond, msg) do { if (cond) { ++g_pass; } else { ++g_fail; \
    std::printf("  FAIL: %s  (%s:%d)\n", msg, __FILE__, __LINE__); } } while (0)

// ── Programmable mock host ──────────────────────────────────────────────────
struct Attempt { reach_layer layer; uint8_t family; uint8_t a0; uint16_t port; };

struct MockHost {
    uint64_t              clockMs = 1000;
    std::vector<Attempt>  attempts;          // every open_transport, in order
    int                   results = 0;
    reach_result          lastResult = REACH_RESULT_PENDING;
    reach_layer           lastVia = REACH_LAYER_NONE;
};
static MockHost* H(void* h) { return static_cast<MockHost*>(h); }

static int cb_open_transport(void* host, reach_peer_id, reach_layer layer,
                             const reach_endpoint* dst) {
    Attempt a;
    a.layer  = layer;
    a.family = dst ? dst->family : 0;
    a.a0     = dst ? dst->addr[0] : 0;
    a.port   = dst ? dst->port : 0;
    H(host)->attempts.push_back(a);
    return 0; // started; the test reports the outcome via reach_on_transport_result
}
static int      cb_send_udp(void*, reach_peer_id, const reach_endpoint*, const uint8_t*, size_t) { return 0; }
static int      cb_signal(void*, reach_peer_id, const reach_endpoint*, const uint8_t*, size_t) { return 0; }
static int      cb_csprng(void*, uint8_t* out, size_t n) { for (size_t i=0;i<n;i++) out[i]=0; return 0; }
static uint64_t cb_clock(void* host) { return H(host)->clockMs; }
static void     cb_on_result(void* host, reach_peer_id, reach_result r, reach_layer via) {
    MockHost* m = H(host); ++m->results; m->lastResult = r; m->lastVia = via;
}

static reach_host_callbacks makeCb() {
    reach_host_callbacks cb; std::memset(&cb, 0, sizeof(cb));
    cb.abi_version = REACH_ABI_VERSION;
    cb.send_udp = cb_send_udp; cb.open_transport = cb_open_transport;
    cb.signal_via_rdv = cb_signal; cb.csprng = cb_csprng; cb.clock_ms = cb_clock;
    cb.on_result = cb_on_result;
    return cb;
}
static reach_config cfg(uint16_t myCaps) {
    reach_config c; std::memset(&c, 0, sizeof(c));
    c.abi_version = REACH_ABI_VERSION; c.my_cap_flags = myCaps; return c;
}
static void fillId(uint8_t id[REACH_KADID_SIZE], uint8_t seed) {
    for (int i = 0; i < REACH_KADID_SIZE; ++i) id[i] = static_cast<uint8_t>(seed + i);
}
static reach_endpoint ep(uint8_t family, uint8_t a0, uint16_t port) {
    reach_endpoint e; std::memset(&e, 0, sizeof(e));
    e.family = family; e.addr[0] = a0; e.port = port; return e;
}
// KadCap bits (brand-neutral, mirror reach_types.h — kept local so the test only
// needs the C ABI header).
enum { CAP_V4_TCP = 1u<<0, CAP_V4_UDP = 1u<<1, CAP_V6 = 1u<<2,
       CAP_PUNCH2 = 1u<<3, CAP_PUNCH3 = 1u<<4, CAP_KEEPALIVE = 1u<<5, CAP_RELAY = 1u<<6 };

static std::vector<uint8_t> vec(uint16_t caps) {
    return { 0x01, (uint8_t)(caps & 0xFF), (uint8_t)(caps >> 8), 0x00 };
}
static std::vector<uint8_t> vecRdv(uint16_t caps, uint8_t rdvA0, uint16_t rdvPort) {
    std::vector<uint8_t> v = { 0x01, (uint8_t)(caps & 0xFF), (uint8_t)(caps >> 8), 0x01 };
    for (int i = 0; i < 16; ++i) v.push_back((uint8_t)(0xA0 + i));     // rdv nodeId
    v.push_back(rdvA0); v.push_back(0); v.push_back(0); v.push_back(0); // ipv4 = rdvA0.0.0.0
    v.push_back((uint8_t)(rdvPort & 0xFF)); v.push_back((uint8_t)(rdvPort >> 8)); // udpPort LE
    return v;
}

// ── 1. direct v4 connect succeeds, route gets remembered ────────────────────
static void test_direct_v4() {
    MockHost h; auto cb = makeCb(); auto c = cfg(0);
    reach_context* ctx = reach_context_create(&cb, &c, &h);
    uint8_t id[16]; fillId(id, 1);
    reach_peer_id p = REACH_PEER_NONE; auto v = vec(CAP_V4_TCP);
    reach_connect(ctx, id, v.data(), v.size(), &p);
    reach_endpoint e4 = ep(4, 10, 4662);
    CHECK(reach_set_candidates(ctx, p, &e4, nullptr) == REACH_OK, "set_candidates ok");

    reach_tick(ctx);
    CHECK(h.attempts.size() == 1, "one attempt emitted");
    CHECK(h.attempts[0].layer == REACH_LAYER_DIRECT_V4, "first rung is DIRECT_V4");
    CHECK(h.attempts[0].a0 == 10 && h.attempts[0].port == 4662, "dst is the v4 candidate");

    reach_on_transport_result(ctx, p, 1);
    CHECK(h.lastResult == REACH_RESULT_CONNECTED, "resolved CONNECTED");
    CHECK(h.lastVia == REACH_LAYER_DIRECT_V4, "via DIRECT_V4");
    reach_context_destroy(ctx);
}

// ── 2. DIRECT_V6 fails → falls back to DIRECT_V4 ────────────────────────────
static void test_fallback() {
    MockHost h; auto cb = makeCb(); auto c = cfg(CAP_V6);
    reach_context* ctx = reach_context_create(&cb, &c, &h);
    uint8_t id[16]; fillId(id, 2);
    reach_peer_id p = REACH_PEER_NONE; auto v = vec(CAP_V6 | CAP_V4_TCP);
    reach_connect(ctx, id, v.data(), v.size(), &p);
    reach_endpoint e4 = ep(4, 10, 4662), e6 = ep(6, 99, 4662);
    reach_set_candidates(ctx, p, &e4, &e6);

    reach_tick(ctx);
    CHECK(h.attempts.size() == 1 && h.attempts[0].layer == REACH_LAYER_DIRECT_V6, "v6 tried first");
    CHECK(h.attempts[0].family == 6 && h.attempts[0].a0 == 99, "v6 candidate dst");
    reach_on_transport_result(ctx, p, 0); // v6 fails
    CHECK(h.attempts.size() == 2 && h.attempts[1].layer == REACH_LAYER_DIRECT_V4, "falls back to v4");
    CHECK(h.attempts[1].family == 4 && h.attempts[1].a0 == 10, "v4 candidate dst");
    reach_on_transport_result(ctx, p, 1); // v4 connects
    CHECK(h.lastResult == REACH_RESULT_CONNECTED && h.lastVia == REACH_LAYER_DIRECT_V4, "connected via v4");
    reach_context_destroy(ctx);
}

// ── 3. applicable rung but NO endpoint → skipped → CLASSIC ──────────────────
static void test_skip_no_endpoint() {
    MockHost h; auto cb = makeCb(); auto c = cfg(0);
    reach_context* ctx = reach_context_create(&cb, &c, &h);
    uint8_t id[16]; fillId(id, 3);
    reach_peer_id p = REACH_PEER_NONE; auto v = vec(CAP_V4_TCP); // peer is HighID...
    reach_connect(ctx, id, v.data(), v.size(), &p);
    // ...but we never supply its endpoint → DIRECT_V4 cannot actuate.
    reach_tick(ctx);
    CHECK(h.attempts.empty(), "no attempt without an endpoint");
    CHECK(h.lastResult == REACH_RESULT_CLASSIC, "degrades to CLASSIC");
    reach_context_destroy(ctx);
}

// ── 4. remembered route tried first; a network jump evicts it & re-derives ───
static void test_remembered_and_eviction() {
    MockHost h; auto cb = makeCb(); auto c = cfg(0);
    reach_context* ctx = reach_context_create(&cb, &c, &h);
    uint8_t id[16]; fillId(id, 4);
    auto v = vec(CAP_V4_TCP);

    // First session: connect on 10.x via DIRECT_V4, succeeds → route remembered.
    reach_peer_id p1 = REACH_PEER_NONE;
    reach_connect(ctx, id, v.data(), v.size(), &p1);
    reach_endpoint old4 = ep(4, 10, 4662);
    reach_set_candidates(ctx, p1, &old4, nullptr);
    reach_tick(ctx);
    reach_on_transport_result(ctx, p1, 1);
    CHECK(h.lastVia == REACH_LAYER_DIRECT_V4, "session 1 connected via v4");
    reach_peer_close(ctx, p1);

    const size_t base = h.attempts.size(); // == 1

    // Second session, SAME NodeID, peer jumped Wi-Fi→mobile → new address 20.x.
    reach_peer_id p2 = REACH_PEER_NONE;
    reach_connect(ctx, id, v.data(), v.size(), &p2);
    reach_endpoint new4 = ep(4, 20, 4662);
    reach_set_candidates(ctx, p2, &new4, nullptr);

    reach_tick(ctx); // tries the REMEMBERED route first (old 10.x), optimistically
    CHECK(h.attempts.size() == base + 1, "remembered route attempted first");
    CHECK(h.attempts[base].layer == REACH_LAYER_DIRECT_V4 && h.attempts[base].a0 == 10,
          "remembered dst is the OLD endpoint");

    reach_on_transport_result(ctx, p2, 0); // stale route fails (peer moved)
    CHECK(h.attempts.size() == base + 2, "cascade restarts after stale route");
    CHECK(h.attempts[base + 1].a0 == 20, "re-derives DIRECT_V4 against the CURRENT endpoint");

    reach_on_transport_result(ctx, p2, 1);
    CHECK(h.lastResult == REACH_RESULT_CONNECTED, "session 2 connected on new network");
    reach_context_destroy(ctx);
}

// ── 5. set_candidates(NULL) clears a previously-set endpoint ─────────────────
static void test_null_clears() {
    MockHost h; auto cb = makeCb(); auto c = cfg(0);
    reach_context* ctx = reach_context_create(&cb, &c, &h);
    uint8_t id[16]; fillId(id, 5);
    reach_peer_id p = REACH_PEER_NONE; auto v = vec(CAP_V4_TCP);
    reach_connect(ctx, id, v.data(), v.size(), &p);
    reach_endpoint e4 = ep(4, 10, 4662);
    reach_set_candidates(ctx, p, &e4, nullptr);     // set...
    reach_set_candidates(ctx, p, nullptr, nullptr); // ...then clear (latest call wins)
    reach_tick(ctx);
    CHECK(h.attempts.empty(), "cleared candidate disables the direct rung");
    CHECK(h.lastResult == REACH_RESULT_CLASSIC, "no endpoint → CLASSIC");
    reach_context_destroy(ctx);
}

// ── 6. rdv-mediated rung (PUNCH_3W) sources dst from the vector anchor ───────
static void test_rdv_layer() {
    MockHost h; auto cb = makeCb(); auto c = cfg(CAP_PUNCH3);
    reach_context* ctx = reach_context_create(&cb, &c, &h);
    uint8_t id[16]; fillId(id, 6);
    reach_peer_id p = REACH_PEER_NONE; auto v = vecRdv(CAP_PUNCH3, /*rdv*/ 50, 9000);
    reach_connect(ctx, id, v.data(), v.size(), &p);
    // No primary candidate set — PUNCH_3W coordinates through the rdv anchor.
    reach_tick(ctx);
    CHECK(h.attempts.size() == 1 && h.attempts[0].layer == REACH_LAYER_PUNCH_3W, "PUNCH_3W selected");
    CHECK(h.attempts[0].family == 4 && h.attempts[0].a0 == 50 && h.attempts[0].port == 9000,
          "dst is the rdv anchor from the vector");
    reach_on_transport_result(ctx, p, 1);
    CHECK(h.lastVia == REACH_LAYER_PUNCH_3W, "connected via PUNCH_3W");
    reach_context_destroy(ctx);
}

// ── 7. per-layer budget timeout advances without a host result ───────────────
static void test_budget_timeout() {
    MockHost h; auto cb = makeCb(); auto c = cfg(CAP_V6);
    reach_context* ctx = reach_context_create(&cb, &c, &h);
    uint8_t id[16]; fillId(id, 7);
    reach_peer_id p = REACH_PEER_NONE; auto v = vec(CAP_V6 | CAP_V4_TCP);
    reach_connect(ctx, id, v.data(), v.size(), &p);
    reach_endpoint e4 = ep(4, 10, 4662), e6 = ep(6, 99, 4662);
    reach_set_candidates(ctx, p, &e4, &e6);

    reach_tick(ctx); // emits DIRECT_V6, then waits
    CHECK(h.attempts.size() == 1 && h.attempts[0].layer == REACH_LAYER_DIRECT_V6, "v6 attempt pending");
    // Host never reports. Advance the clock past the v6 budget (400ms default).
    h.clockMs += 500;
    reach_tick(ctx); // budget exceeded → treat as failure → next rung
    CHECK(h.attempts.size() == 2 && h.attempts[1].layer == REACH_LAYER_DIRECT_V4,
          "budget timeout fell through to DIRECT_V4 (no timer needed)");
    reach_context_destroy(ctx);
}

int main() {
    std::printf("test_reach_actuator — libreach L3 actuator / persistence / eviction\n");
    test_direct_v4();
    test_fallback();
    test_skip_no_endpoint();
    test_remembered_and_eviction();
    test_null_clears();
    test_rdv_layer();
    test_budget_timeout();
    std::printf("\nTOTAL: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
