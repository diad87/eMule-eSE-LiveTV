// SPDX-License-Identifier: MIT
//
// test_reach_cascade.cpp — golden vectors for the L3 cascade transition function
// (KEP-1 Appendix B / thesis §7.1). Pure-logic tests: no host, no sockets.
//
// Build (standalone, no MFC) — see libreach/README.md:
//   cl /EHsc /O2 /W4 /std:c++17 /Iinclude /Febuild\test_reach_cascade.exe ^
//      tests\test_reach_cascade.cpp src\reach_cascade.cpp
//   build\test_reach_cascade.exe
//   g++ -std=c++17 -O2 -Wall -Wextra -Iinclude -o trc \
//       tests/test_reach_cascade.cpp src/reach_cascade.cpp && ./trc
#include "reach/reach_cascade.h"

#include <cstdio>

using namespace reach;

static int g_checks = 0;
static int g_fails  = 0;

#define CHECK(cond)                                                          \
    do {                                                                     \
        ++g_checks;                                                          \
        if (!(cond)) {                                                       \
            ++g_fails;                                                       \
            std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond);      \
        }                                                                    \
    } while (0)

// Build a peer vector with the given caps and `nRdv` (empty) rendezvous anchors.
static ReachVector peer(std::uint16_t caps, std::size_t nRdv = 0) {
    ReachVector v;
    v.capFlags = caps;
    for (std::size_t i = 0; i < nRdv; ++i) {
        RdvEntry e;
        e.udpPort = static_cast<std::uint16_t>(9000 + i);
        e.token[0] = static_cast<Byte>(i + 1);
        e.expiresAt = 2000000000u;
        v.rdv.push_back(e);
    }
    return v;
}

// First applicable layer for (myCaps, peer): seed the walk with NONE.
static reach_layer first(std::uint16_t myCaps, const ReachVector& p) {
    return NextApplicableLayer(myCaps, p, REACH_LAYER_NONE);
}

int main() {
    const std::uint16_t kNone = 0;

    // ── Invariant 3: nothing applicable → CLASSIC ─────────────────────────
    CHECK(first(kNone, peer(0)) == REACH_LAYER_CLASSIC);
    CHECK(first(0xFFFF, peer(0)) == REACH_LAYER_CLASSIC);   // I'm capable, B is a blank

    // ── DIRECT_V6: local egress + peer inbound ────────────────────────────
    CHECK(first(KAD_CAP_V6_OUT, peer(KAD_CAP_V6_IN)) == REACH_LAYER_DIRECT_V6);
    CHECK(first(kNone,          peer(KAD_CAP_V6_IN)) != REACH_LAYER_DIRECT_V6); // I lack egress
    CHECK(first(KAD_CAP_V6_OUT, peer(0))             == REACH_LAYER_CLASSIC);   // B lacks inbound

    // ── DIRECT_V4: needs only B inbound-TCP (we connect out) ──────────────
    CHECK(first(kNone, peer(KAD_CAP_V4_TCP_IN)) == REACH_LAYER_DIRECT_V4);
    // v6 outranks v4 when both apply (attempt order).
    CHECK(first(KAD_CAP_V6_OUT, peer(KAD_CAP_V6_IN | KAD_CAP_V4_TCP_IN)) == REACH_LAYER_DIRECT_V6);
    CHECK(NextApplicableLayer(KAD_CAP_V6_OUT,
                              peer(KAD_CAP_V6_IN | KAD_CAP_V4_TCP_IN),
                              REACH_LAYER_DIRECT_V6) == REACH_LAYER_DIRECT_V4);

    // ── CALLBACK: A must accept inbound TCP AND B must be signalable ───────
    // A reachable (v4 tcp), B signalable via open UDP → CALLBACK.
    CHECK(first(KAD_CAP_V4_TCP_IN, peer(KAD_CAP_V4_UDP_IN)) == REACH_LAYER_CALLBACK);
    // A reachable, B signalable via rdv → CALLBACK.
    CHECK(first(KAD_CAP_V4_TCP_IN, peer(0, /*rdv*/1)) == REACH_LAYER_CALLBACK);
    // A NOT reachable for inbound TCP → no callback (asymmetry of §2.3).
    CHECK(first(kNone, peer(KAD_CAP_V4_UDP_IN, 1)) == REACH_LAYER_CLASSIC);
    // A reachable but B not signalable (no UDP, no rdv) → no callback.
    CHECK(first(KAD_CAP_V4_TCP_IN, peer(0)) == REACH_LAYER_CLASSIC);
    // A reachable only via v6, B v6-capable + signalable → CALLBACK.
    CHECK(first(KAD_CAP_V6_OUT | KAD_CAP_V6_IN,
                peer(KAD_CAP_V6_IN | KAD_CAP_V6_OUT | KAD_CAP_V4_UDP_IN)) == REACH_LAYER_DIRECT_V6);
    CHECK(NextApplicableLayer(KAD_CAP_V6_IN,
                              peer(KAD_CAP_V6_OUT | KAD_CAP_V4_UDP_IN),
                              REACH_LAYER_DIRECT_V6) == REACH_LAYER_CALLBACK);

    // ── PUNCH_2W: mutual cap (invariant 1) ────────────────────────────────
    CHECK(first(KAD_CAP_PUNCH_2W, peer(KAD_CAP_PUNCH_2W)) == REACH_LAYER_PUNCH_2W);
    CHECK(first(kNone,            peer(KAD_CAP_PUNCH_2W)) == REACH_LAYER_CLASSIC); // not mutual
    CHECK(first(KAD_CAP_PUNCH_2W, peer(0))                == REACH_LAYER_CLASSIC); // not mutual

    // ── PUNCH_3W: mutual cap AND B has an rdv ─────────────────────────────
    CHECK(first(KAD_CAP_PUNCH_3W, peer(KAD_CAP_PUNCH_3W, 1)) == REACH_LAYER_PUNCH_3W);
    CHECK(first(KAD_CAP_PUNCH_3W, peer(KAD_CAP_PUNCH_3W, 0)) == REACH_LAYER_CLASSIC); // no rdv
    CHECK(first(KAD_CAP_PUNCH_3W, peer(0, 1))                == REACH_LAYER_CLASSIC); // not mutual

    // ── RELAY: reserved rdv + mutual relay-client consent ─────────────────
    CHECK(first(KAD_CAP_RELAY_CLIENT, peer(KAD_CAP_RELAY_CLIENT, 1)) == REACH_LAYER_RELAY);
    CHECK(first(KAD_CAP_RELAY_CLIENT, peer(KAD_CAP_RELAY_CLIENT, 0)) == REACH_LAYER_CLASSIC);
    CHECK(first(kNone,                peer(KAD_CAP_RELAY_CLIENT, 1)) == REACH_LAYER_CLASSIC);
    CHECK(first(KAD_CAP_RELAY_OFFER,  peer(KAD_CAP_RELAY_OFFER, 1)) == REACH_LAYER_CLASSIC);

    // ── Full ladder walk: a maximally-capable pair visits every layer in order ──
    {
        const std::uint16_t allMine =
            KAD_CAP_V6_OUT | KAD_CAP_V6_IN | KAD_CAP_V4_TCP_IN | KAD_CAP_PUNCH_2W |
            KAD_CAP_PUNCH_3W | KAD_CAP_RELAY_CLIENT;
        const std::uint16_t allPeer =
            KAD_CAP_V6_IN | KAD_CAP_V6_OUT | KAD_CAP_V4_TCP_IN | KAD_CAP_V4_UDP_IN |
            KAD_CAP_PUNCH_2W | KAD_CAP_PUNCH_3W | KAD_CAP_RELAY_CLIENT;
        const ReachVector p = peer(allPeer, /*rdv*/1);
        reach_layer seq[REACH_LAYER_COUNT];
        int n = 0;
        reach_layer l = NextApplicableLayer(allMine, p, REACH_LAYER_NONE);
        while (l != REACH_LAYER_CLASSIC && n < REACH_LAYER_COUNT) {
            seq[n++] = l;
            l = NextApplicableLayer(allMine, p, l);
        }
        CHECK(n == 6);
        CHECK(seq[0] == REACH_LAYER_DIRECT_V6);
        CHECK(seq[1] == REACH_LAYER_DIRECT_V4);
        CHECK(seq[2] == REACH_LAYER_CALLBACK);
        CHECK(seq[3] == REACH_LAYER_PUNCH_2W);
        CHECK(seq[4] == REACH_LAYER_PUNCH_3W);
        CHECK(seq[5] == REACH_LAYER_RELAY);
        CHECK(l == REACH_LAYER_CLASSIC); // walk terminates at the fallback
    }

    // ── Monotonic walk: `after` always advances, terminates at CLASSIC ────
    {
        const ReachVector p = peer(KAD_CAP_V4_TCP_IN); // only one real layer applies
        reach_layer l = NextApplicableLayer(0, p, REACH_LAYER_NONE);
        CHECK(l == REACH_LAYER_DIRECT_V4);
        CHECK(NextApplicableLayer(0, p, l) == REACH_LAYER_CLASSIC);
    }

    std::printf("test_reach_cascade: %d checks, %d failures\n", g_checks, g_fails);
    return g_fails ? 1 : 0;
}
