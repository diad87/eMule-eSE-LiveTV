// SPDX-License-Identifier: MIT
//
// reach_engine.h — internal C++ engine behind the reach.h C ABI. NOT a public
// header: it is never installed and never crosses the FFI boundary. The public
// surface (reach.h) is pure C; this is the implementation detail.
//
// Single-threaded by contract (no mutex). Memory model: the engine owns every
// peer through a slot table of value types; it stores NO host object pointer
// (only the context-level `void* host` cookie). Per-peer identity that crosses
// the boundary is the generation-counted reach_peer_id handle.
#pragma once

#include "reach/reach.h"
#include "reach/reach_codec.h"

#include <cstdint>
#include <map>
#include <vector>

namespace reach {

// Lifecycle state of a peer's connection attempt.
enum class PeerState : std::uint8_t {
    Connecting, // cascade in progress
    Resolved,   // on_result delivered; awaiting host close
    Closing,    // tombstoned mid-call; slot reclaimed when the call unwinds
};

struct Peer {
    KadId         nodeId{};
    ReachVector   vector{};                 // decoded TAG_REACH (empty if none)
    bool          hasVector = false;
    reach_peer_id handle    = REACH_PEER_NONE;
    PeerState     state      = PeerState::Connecting;
    reach_layer   curLayer   = REACH_LAYER_NONE;
    std::uint64_t startMs    = 0;
    std::uint64_t deadlineMs = 0;

    // L3 actuator state. Candidate endpoints are the peer's OWN primary v4/v6
    // address (host-supplied via reach_set_candidates; NOT in the vector). The
    // rdv-mediated rungs source their dst from vector.rdv instead.
    reach_endpoint candV4{};   bool hasCandV4 = false;
    reach_endpoint candV6{};   bool hasCandV6 = false;
    reach_endpoint lastDst{};                       // endpoint of the in-flight attempt
    bool          awaitingResult  = false;          // an attempt is emitted; awaiting result/budget
    bool          usingRemembered = false;          // the in-flight attempt is the remembered route
    bool          routeTried      = false;          // remembered-route shortcut already consulted
    std::uint64_t layerStartMs    = 0;              // when the current layer attempt began (budget)
};

// A remembered "nominated pair" (thesis §7.1): the layer+endpoint that last
// connected for a NodeID, plus when it was verified. Outlives the peer slot
// (the whole point), so it lives in its own table, not in m_byNode. Eviction is
// timer-free: validate-on-use (a stale route fails its optimistic retry and is
// dropped), a TTL checked on access, and an LRU size cap.
struct RememberedRoute {
    reach_layer    layer          = REACH_LAYER_NONE;
    reach_endpoint dst{};
    std::uint64_t  lastVerifiedMs = 0;
};

// A handle-table slot. `generation` is bumped on every reclaim so that a stale
// reach_peer_id (old generation) can never address a reused slot (ABA defense).
struct Slot {
    std::uint32_t generation = 0;
    bool          occupied   = false;
    Peer          peer{};
};

class ReachEngine {
public:
    ReachEngine(const reach_host_callbacks& cb, const reach_config& cfg, void* host);

    // C-ABI operations (1:1 with reach.h).
    int          tick();
    reach_status connect(const std::uint8_t nodeid[REACH_KADID_SIZE],
                         const std::uint8_t* peerVector, std::size_t vectorLen,
                         reach_peer_id* outPeer);
    reach_status setCandidates(reach_peer_id peer, const reach_endpoint* v4,
                               const reach_endpoint* v6);
    reach_status close(reach_peer_id peer);
    reach_status onUdp(const reach_endpoint* from, std::uint8_t opcode,
                       const std::uint8_t* payload, std::size_t len);
    reach_status onTransportResult(reach_peer_id peer, bool connected);
    reach_status getStats(reach_stats* out) const;

private:
    // ── handle <-> slot mapping ──────────────────────────────────────────
    static reach_peer_id makeHandle(std::uint32_t index, std::uint32_t gen) {
        // index+1 in the high dword so handle 0 is never valid.
        return (static_cast<reach_peer_id>(index + 1) << 32) | gen;
    }
    static std::uint32_t handleIndex(reach_peer_id h) {
        return static_cast<std::uint32_t>(h >> 32) - 1u;
    }
    static std::uint32_t handleGen(reach_peer_id h) {
        return static_cast<std::uint32_t>(h & 0xFFFFFFFFu);
    }
    // Returns the live slot for `h`, or nullptr if stale/closing/unknown.
    Slot* resolve(reach_peer_id h);

    std::uint32_t allocSlot();          // index of a fresh occupied slot
    void          reclaim(std::uint32_t index); // bump gen, free for reuse

    // Re-entrancy guard so a close() inside a callback defers slot reclaim
    // until the outermost engine call unwinds (no iterator/index invalidation).
    void enterCall() { ++m_callDepth; }
    void leaveCall();

    // Cascade driver (Appendix B). L2: the layer set is empty, so this resolves
    // every peer to CLASSIC — the correct degenerate cascade (invariant 3:
    // all-layers-fail degrades to classic, never a new error). L3 inserts the
    // real layers ahead of the classic fallback here.
    void advance(std::uint32_t index, std::uint64_t nowMs);
    void resolvePeer(std::uint32_t index, reach_result result, reach_layer via);

    // L3 actuator helpers. endpointForLayer fills `out` with the dst a layer must
    // be attempted against (peer primary for direct/2w-punch, vector rdv anchor
    // for 3w-punch/relay); false ⇒ no endpoint ⇒ skip the rung. emitAttempt fires
    // open_transport and arms awaitingResult; it holds no Slot& across the
    // callback (which may re-enter connect()/close()).
    bool endpointForLayer(const Peer& p, reach_layer layer, reach_endpoint& out) const;
    bool emitAttempt(std::uint32_t index, reach_layer layer,
                     const reach_endpoint& dst, std::uint64_t now);
    bool tryLayer(std::uint32_t index, reach_layer layer, std::uint64_t now);
    std::uint64_t layerBudgetMs(reach_layer layer) const;

    // NodeID-keyed route memory (nominated pair). Timer-free eviction.
    void             rememberRoute(const KadId& id, reach_layer layer,
                                   const reach_endpoint& dst, std::uint64_t now);
    RememberedRoute* freshRoute(const KadId& id, std::uint64_t now); // nullptr if absent/stale
    void             forgetRoute(const KadId& id);

    std::uint64_t nowMs() { return m_cb.clock_ms ? m_cb.clock_ms(m_host) : 0; }
    void          logLine(int level, const char* msg);

    reach_host_callbacks m_cb;
    reach_config         m_cfg;
    void*                m_host;

    std::vector<Slot>          m_slots;
    std::vector<std::uint32_t> m_freeIdx;
    std::map<KadId, std::uint32_t> m_byNode;  // idempotent connect per NodeID
    std::map<KadId, RememberedRoute> m_routes; // remembered nominated pair per NodeID

    int                        m_callDepth = 0;
    std::vector<std::uint32_t> m_pendingFree; // tombstoned indices to reclaim

    reach_stats m_stats{};
};

} // namespace reach
