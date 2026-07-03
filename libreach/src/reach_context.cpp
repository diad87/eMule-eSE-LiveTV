// SPDX-License-Identifier: MIT
//
// reach_context.cpp — the reach.h C ABI shim plus the ReachEngine implementation.
// New code (not derived from eMule); MIT.
//
// Threading: single-threaded by contract. Memory: the engine owns peers by
// value in a slot table; the ONLY raw owning pointer is the reach_context the
// C ABI hands out (new at create, delete at destroy) — unavoidable at a C
// boundary, encapsulated here.
#include "reach_engine.h"
#include "reach/reach_cascade.h"   // NextApplicableLayer (L3 transition function)

#include <cstring>

namespace reach {

ReachEngine::ReachEngine(const reach_host_callbacks& cb,
                         const reach_config& cfg, void* host)
    : m_cb(cb), m_cfg(cfg), m_host(host) {
    const std::uint32_t reserve =
        m_cfg.max_peers != 0 ? m_cfg.max_peers : 64u;
    m_slots.reserve(reserve);
}

void ReachEngine::logLine(int level, const char* msg) {
    if (m_cb.log != nullptr)
        m_cb.log(m_host, level, msg);
}

void ReachEngine::leaveCall() {
    if (m_callDepth > 0)
        --m_callDepth;
    if (m_callDepth == 0 && !m_pendingFree.empty()) {
        // Outermost engine call is unwinding: now it is safe to reclaim the
        // slots that were tombstoned by a re-entrant close().
        for (std::uint32_t index : m_pendingFree) {
            if (index < m_slots.size() &&
                m_slots[index].occupied &&
                m_slots[index].peer.state == PeerState::Closing) {
                reclaim(index);
            }
        }
        m_pendingFree.clear();
    }
}

Slot* ReachEngine::resolve(reach_peer_id h) {
    if (h == REACH_PEER_NONE)
        return nullptr;
    const std::uint32_t index = handleIndex(h);
    if (index >= m_slots.size())
        return nullptr;
    Slot& s = m_slots[index];
    if (!s.occupied || s.generation != handleGen(h))
        return nullptr;
    if (s.peer.state == PeerState::Closing)
        return nullptr; // tombstoned: addressable no more
    return &s;
}

std::uint32_t ReachEngine::allocSlot() {
    if (!m_freeIdx.empty()) {
        const std::uint32_t index = m_freeIdx.back();
        m_freeIdx.pop_back();
        m_slots[index].occupied = true;
        m_slots[index].peer = Peer{};
        return index;
    }
    Slot s;
    s.occupied = true;
    m_slots.push_back(s);
    return static_cast<std::uint32_t>(m_slots.size() - 1);
}

void ReachEngine::reclaim(std::uint32_t index) {
    Slot& s = m_slots[index];
    s.occupied = false;
    s.peer = Peer{};
    ++s.generation; // invalidate every outstanding handle to this slot (ABA)
    m_freeIdx.push_back(index);
}

reach_status ReachEngine::connect(const std::uint8_t nodeid[REACH_KADID_SIZE],
                                  const std::uint8_t* peerVector,
                                  std::size_t vectorLen,
                                  reach_peer_id* outPeer) {
    if (nodeid == nullptr || outPeer == nullptr)
        return REACH_ERR_NULL_ARG;
    *outPeer = REACH_PEER_NONE;

    KadId id{};
    std::memcpy(id.data(), nodeid, kKadIdSize);

    // Idempotent per NodeID: an active attempt for this id returns its handle.
    auto it = m_byNode.find(id);
    if (it != m_byNode.end()) {
        const std::uint32_t index = it->second;
        if (index < m_slots.size() && m_slots[index].occupied &&
            m_slots[index].peer.state != PeerState::Closing) {
            *outPeer = m_slots[index].peer.handle;
            return REACH_OK;
        }
        m_byNode.erase(it); // stale mapping; fall through to a fresh attempt
    }

    const std::uint32_t index = allocSlot();
    Slot& s = m_slots[index];
    s.peer.nodeId = id;
    s.peer.handle = makeHandle(index, s.generation);
    s.peer.state = PeerState::Connecting;
    s.peer.startMs = nowMs();
    const std::uint32_t deadline =
        m_cfg.connect_deadline_ms != 0 ? m_cfg.connect_deadline_ms : 5000u;
    s.peer.deadlineMs = s.peer.startMs + deadline;

    if (peerVector != nullptr && vectorLen > 0) {
        const ReachStatus st =
            DecodeReachVector(peerVector, vectorLen, s.peer.vector);
        if (st == ReachStatus::Ok) {
            s.peer.hasVector = true;
        } else {
            s.peer.hasVector = false;
            logLine(1, "connect: malformed TAG_REACH, projecting from classic");
        }
    }

    m_byNode[id] = index;
    ++m_stats.connects_total;
    *outPeer = s.peer.handle;
    return REACH_OK;
}

reach_status ReachEngine::setCandidates(reach_peer_id peer,
                                        const reach_endpoint* v4,
                                        const reach_endpoint* v6) {
    Slot* s = resolve(peer);
    if (s == nullptr)
        return REACH_ERR_STALE_PEER;
    Peer& p = s->peer;
    // Latest call wins; an absent / family-mismatched endpoint disables its rung.
    if (v4 != nullptr && v4->family == 4) { p.candV4 = *v4; p.hasCandV4 = true; }
    else                                  { p.hasCandV4 = false; }
    if (v6 != nullptr && v6->family == 6) { p.candV6 = *v6; p.hasCandV6 = true; }
    else                                  { p.hasCandV6 = false; }
    return REACH_OK;
}

void ReachEngine::resolvePeer(std::uint32_t index, reach_result result,
                              reach_layer via) {
    // Mutate slot state BEFORE invoking the callback: on_result may re-enter
    // connect()/close(), which can reallocate m_slots — so we hold no Slot&
    // across the callback and never touch the slot afterwards.
    reach_peer_id handle;
    {
        Slot& s = m_slots[index];
        s.peer.state = PeerState::Resolved;
        s.peer.curLayer = via;
        handle = s.peer.handle;
    }
    if (result == REACH_RESULT_CONNECTED)
        ++m_stats.resolved_connected;
    else if (result == REACH_RESULT_CLASSIC)
        ++m_stats.resolved_classic;

    if (m_cb.on_result != nullptr)
        m_cb.on_result(m_host, handle, result, via);
}

// ── L3 cascade actuator ─────────────────────────────────────────────────────
namespace {
constexpr std::uint64_t kRouteTtlMs = 10ull * 60ull * 1000ull; // route freshness (10 min)
constexpr std::size_t   kMaxRoutes  = 1024;                     // LRU cap on remembered routes
} // namespace

std::uint64_t ReachEngine::layerBudgetMs(reach_layer layer) const {
    if (layer >= 0 && layer < REACH_LAYER_COUNT && m_cfg.layer_budget_ms[layer] != 0)
        return m_cfg.layer_budget_ms[layer];
    switch (layer) {                 // defaults: §7.1 (hundreds of ms for 1–3; seconds for 4–5)
        case REACH_LAYER_DIRECT_V6:
        case REACH_LAYER_DIRECT_V4:
        case REACH_LAYER_CALLBACK:  return 400;
        case REACH_LAYER_PUNCH_2W:
        case REACH_LAYER_PUNCH_3W:  return 3000;
        case REACH_LAYER_RELAY:     return 5000;
        default:                    return 1000;
    }
}

bool ReachEngine::endpointForLayer(const Peer& p, reach_layer layer,
                                   reach_endpoint& out) const {
    switch (layer) {
        case REACH_LAYER_DIRECT_V6:
            if (!p.hasCandV6) return false;
            out = p.candV6; return true;
        case REACH_LAYER_DIRECT_V4:
        case REACH_LAYER_CALLBACK:
        case REACH_LAYER_PUNCH_2W:
            if (!p.hasCandV4) return false;
            out = p.candV4; return true;
        case REACH_LAYER_PUNCH_3W:
        case REACH_LAYER_RELAY: {
            if (p.vector.rdv.empty()) return false;
            const RdvEntry& r = p.vector.rdv.front();   // first rdv anchor coordinates it
            std::memset(&out, 0, sizeof(out));
            out.family = 4;                             // rdv anchors are v4 in wire v1
            std::memcpy(out.addr, r.ipv4.data(), kIPv4Size);
            out.port = r.udpPort;
            return true;
        }
        default:
            return false;
    }
}

bool ReachEngine::emitAttempt(std::uint32_t index, reach_layer layer,
                              const reach_endpoint& dst, std::uint64_t now) {
    // Arm state BEFORE the callback (open_transport may re-enter connect()/close()
    // and reallocate m_slots), then hold no Slot& across it.
    reach_peer_id handle;
    {
        Peer& p = m_slots[index].peer;
        p.curLayer       = layer;
        p.lastDst        = dst;
        p.layerStartMs   = now;
        p.awaitingResult = true;
        handle           = p.handle;
    }
    const int rc = m_cb.open_transport
                       ? m_cb.open_transport(m_host, handle, layer, &dst)
                       : 1;
    if (rc != 0) {
        // Host could not even start it: re-resolve (the callback may have moved
        // the slot) and disarm so the caller advances to the next rung.
        if (index < m_slots.size() && m_slots[index].occupied &&
            m_slots[index].peer.handle == handle &&
            m_slots[index].peer.state == PeerState::Connecting)
            m_slots[index].peer.awaitingResult = false;
        return false;
    }
    return true;
}

bool ReachEngine::tryLayer(std::uint32_t index, reach_layer layer,
                           std::uint64_t now) {
    reach_endpoint dst{};
    if (!endpointForLayer(m_slots[index].peer, layer, dst))
        return false;                       // no endpoint for this rung → skip it
    return emitAttempt(index, layer, dst, now);
}

void ReachEngine::rememberRoute(const KadId& id, reach_layer layer,
                                const reach_endpoint& dst, std::uint64_t now) {
    if (layer == REACH_LAYER_NONE || layer == REACH_LAYER_CLASSIC)
        return;                             // only a real eSE rung is worth pinning
    if (m_routes.find(id) == m_routes.end() && m_routes.size() >= kMaxRoutes) {
        // LRU evict the oldest-verified entry. O(N) only on overflow; timer-free.
        auto oldest = m_routes.begin();
        for (auto it = m_routes.begin(); it != m_routes.end(); ++it)
            if (it->second.lastVerifiedMs < oldest->second.lastVerifiedMs)
                oldest = it;
        m_routes.erase(oldest);
    }
    RememberedRoute& r = m_routes[id];
    r.layer = layer; r.dst = dst; r.lastVerifiedMs = now;
}

RememberedRoute* ReachEngine::freshRoute(const KadId& id, std::uint64_t now) {
    auto it = m_routes.find(id);
    if (it == m_routes.end())
        return nullptr;
    if (now - it->second.lastVerifiedMs > kRouteTtlMs) {
        m_routes.erase(it);                 // TTL-on-access eviction (no timer)
        return nullptr;
    }
    return &it->second;
}

void ReachEngine::forgetRoute(const KadId& id) {
    m_routes.erase(id);
}

void ReachEngine::advance(std::uint32_t index, std::uint64_t now) {
    if (m_slots[index].peer.state != PeerState::Connecting)
        return;
    if (m_slots[index].peer.awaitingResult)
        return;                             // an attempt is in flight; tick() polices its budget

    // First entry for this peer: try the remembered nominated pair optimistically.
    // If it is stale (peer changed network) its attempt will fail and we restart
    // the full cascade — that failure IS the route's eviction trigger (validate-
    // on-use). The endpoint comes from the route itself, not endpointForLayer.
    if (m_slots[index].peer.curLayer == REACH_LAYER_NONE &&
        !m_slots[index].peer.routeTried) {
        m_slots[index].peer.routeTried = true;
        RememberedRoute* r = freshRoute(m_slots[index].peer.nodeId, now);
        if (r != nullptr) {
            const reach_layer    rl  = r->layer;
            const reach_endpoint rds = r->dst;
            m_slots[index].peer.usingRemembered = true;
            if (emitAttempt(index, rl, rds, now))
                return;
            m_slots[index].peer.usingRemembered = false; // could not start → cascade
        }
    }

    // Walk the Appendix-B ladder from curLayer, skipping rungs we cannot actuate
    // (no endpoint), until an attempt starts or the eSE layers are exhausted and
    // we fall to CLASSIC (invariant 3).
    reach_layer l = m_slots[index].peer.curLayer;
    for (;;) {
        l = NextApplicableLayer(m_cfg.my_cap_flags, m_slots[index].peer.vector, l);
        if (l == REACH_LAYER_CLASSIC) {
            resolvePeer(index, REACH_RESULT_CLASSIC, REACH_LAYER_CLASSIC);
            return;
        }
        m_slots[index].peer.usingRemembered = false;
        if (tryLayer(index, l, now))
            return;                         // attempt started; await its result
        m_slots[index].peer.curLayer = l;   // could not actuate → step past it
    }
}

int ReachEngine::tick() {
    enterCall();
    const std::uint64_t now = nowMs();
    // Snapshot the count so peers created by a re-entrant connect() (from an
    // on_result callback) are processed next tick, not this one. Index-based
    // iteration tolerates m_slots reallocation during callbacks.
    const std::size_t n = m_slots.size();
    for (std::size_t i = 0; i < n; ++i) {
        if (!m_slots[i].occupied ||
            m_slots[i].peer.state != PeerState::Connecting)
            continue;
        const std::uint32_t idx = static_cast<std::uint32_t>(i);
        if (m_slots[i].peer.awaitingResult) {
            // Per-layer budget: an attempt that does not resolve in time is a
            // failure (host never reported, or the path is dead). Treat it like
            // onTransportResult(false) and move on — the budget IS the timeout.
            if (now - m_slots[i].peer.layerStartMs >=
                    layerBudgetMs(m_slots[i].peer.curLayer)) {
                if (m_slots[i].peer.usingRemembered) {
                    forgetRoute(m_slots[i].peer.nodeId);
                    m_slots[i].peer.usingRemembered = false;
                    m_slots[i].peer.curLayer = REACH_LAYER_NONE;
                }
                m_slots[i].peer.awaitingResult = false;
                advance(idx, now);
            }
            continue;
        }
        // Overall deadline backstop: give up the cascade, degrade to classic.
        if (now >= m_slots[i].peer.deadlineMs) {
            resolvePeer(idx, REACH_RESULT_CLASSIC, REACH_LAYER_CLASSIC);
            continue;
        }
        advance(idx, now);
    }
    int pending = 0;
    for (const Slot& s : m_slots) {
        if (s.occupied && s.peer.state == PeerState::Connecting)
            ++pending;
    }
    leaveCall();
    return pending;
}

reach_status ReachEngine::close(reach_peer_id peer) {
    Slot* s = resolve(peer);
    if (s == nullptr)
        return REACH_ERR_STALE_PEER; // unknown / already closed / tombstoned
    const std::uint32_t index = handleIndex(peer);

    auto it = m_byNode.find(s->peer.nodeId);
    if (it != m_byNode.end() && it->second == index)
        m_byNode.erase(it);

    // Defer only when nested inside another engine call (a re-entrant close
    // from within a callback). m_callDepth counts callback-bearing entries
    // (tick/onUdp/onTransportResult); a standalone close sees depth 0 and
    // reclaims at once.
    if (m_callDepth > 0) {
        s->peer.state = PeerState::Closing;
        m_pendingFree.push_back(index);
    } else {
        reclaim(index);
    }
    return REACH_OK;
}

reach_status ReachEngine::onUdp(const reach_endpoint* from, std::uint8_t opcode,
                                const std::uint8_t* payload, std::size_t len) {
    if (from == nullptr)
        return REACH_ERR_NULL_ARG;
    (void)opcode;
    (void)payload;
    (void)len;
    enterCall();
    ++m_stats.udp_recv;
    // L2 owns no wire opcodes (punch REQ/ACK handlers land in L4). An unknown
    // opcode is correctly a no-op here: the host keeps handling its own wire.
    leaveCall();
    return REACH_OK;
}

reach_status ReachEngine::onTransportResult(reach_peer_id peer, bool connected) {
    enterCall();
    reach_status rc = REACH_OK;
    Slot* s = resolve(peer);
    if (s == nullptr) {
        rc = REACH_ERR_STALE_PEER;
    } else if (s->peer.state == PeerState::Connecting) {
        const std::uint32_t index = handleIndex(peer);
        const std::uint64_t now = nowMs();
        s->peer.awaitingResult = false;
        if (connected) {
            // Pin the winning nominated pair (NodeID-keyed) before resolving —
            // resolvePeer's callback may re-enter, so read the fields first.
            const reach_layer    via = s->peer.curLayer;
            const reach_endpoint dst = s->peer.lastDst;
            rememberRoute(s->peer.nodeId, via, dst, now);
            resolvePeer(index, REACH_RESULT_CONNECTED, via);
        } else {
            // Attempt failed. If it was the optimistic remembered route, the route
            // is stale (e.g. the peer jumped Wi-Fi→mobile): evict it and restart
            // the full cascade from the top against the current candidates.
            if (s->peer.usingRemembered) {
                forgetRoute(s->peer.nodeId);
                s->peer.usingRemembered = false;
                s->peer.curLayer = REACH_LAYER_NONE;
            }
            advance(index, now); // try the next applicable layer
        }
    }
    leaveCall();
    return rc;
}

reach_status ReachEngine::getStats(reach_stats* out) const {
    if (out == nullptr)
        return REACH_ERR_NULL_ARG;
    *out = m_stats;
    std::uint32_t active = 0, pending = 0;
    for (const Slot& s : m_slots) {
        if (s.occupied && s.peer.state != PeerState::Closing) {
            ++active;
            if (s.peer.state == PeerState::Connecting)
                ++pending;
        }
    }
    out->peers_active = active;
    out->peers_pending = pending;
    return REACH_OK;
}

} // namespace reach

// ─────────────────────────── C ABI shim ───────────────────────────────────
using reach::ReachEngine;

static ReachEngine* eng(reach_context* c) {
    return reinterpret_cast<ReachEngine*>(c);
}

extern "C" {

reach_context* reach_context_create(const reach_host_callbacks* cb,
                                    const reach_config* cfg, void* host) {
    if (cb == nullptr || cb->abi_version != REACH_ABI_VERSION)
        return nullptr;
    if (cb->clock_ms == nullptr) // the engine needs a monotonic clock
        return nullptr;
    if (cfg != nullptr && cfg->abi_version != REACH_ABI_VERSION)
        return nullptr;

    reach_config localCfg;
    if (cfg != nullptr) {
        localCfg = *cfg;
    } else {
        std::memset(&localCfg, 0, sizeof(localCfg));
        localCfg.abi_version = REACH_ABI_VERSION;
    }
    ReachEngine* e = new (std::nothrow) ReachEngine(*cb, localCfg, host);
    return reinterpret_cast<reach_context*>(e);
}

void reach_context_destroy(reach_context* ctx) {
    delete eng(ctx); // safe on null
}

int reach_tick(reach_context* ctx) {
    if (ctx == nullptr)
        return -REACH_ERR_NULL_ARG;
    return eng(ctx)->tick();
}

reach_status reach_connect(reach_context* ctx,
                           const uint8_t nodeid[REACH_KADID_SIZE],
                           const uint8_t* peer_vector, size_t vector_len,
                           reach_peer_id* out_peer) {
    if (ctx == nullptr)
        return REACH_ERR_NULL_ARG;
    return eng(ctx)->connect(nodeid, peer_vector, vector_len, out_peer);
}

reach_status reach_set_candidates(reach_context* ctx, reach_peer_id peer,
                                  const reach_endpoint* v4,
                                  const reach_endpoint* v6) {
    if (ctx == nullptr)
        return REACH_ERR_NULL_ARG;
    return eng(ctx)->setCandidates(peer, v4, v6);
}

reach_status reach_peer_close(reach_context* ctx, reach_peer_id peer) {
    if (ctx == nullptr)
        return REACH_ERR_NULL_ARG;
    return eng(ctx)->close(peer);
}

reach_status reach_on_udp(reach_context* ctx, const reach_endpoint* from,
                          uint8_t opcode, const uint8_t* payload, size_t len) {
    if (ctx == nullptr)
        return REACH_ERR_NULL_ARG;
    return eng(ctx)->onUdp(from, opcode, payload, len);
}

reach_status reach_on_transport_result(reach_context* ctx, reach_peer_id peer,
                                       int connected) {
    if (ctx == nullptr)
        return REACH_ERR_NULL_ARG;
    return eng(ctx)->onTransportResult(peer, connected != 0);
}

reach_status reach_get_stats(const reach_context* ctx, reach_stats* out) {
    if (ctx == nullptr)
        return REACH_ERR_NULL_ARG;
    // getStats is const; cast away only the opaque alias, not constness of data.
    return reinterpret_cast<const ReachEngine*>(ctx)->getStats(out);
}

const char* reach_status_str(reach_status s) {
    switch (s) {
        case REACH_OK:               return "REACH_OK";
        case REACH_ERR_NULL_ARG:     return "REACH_ERR_NULL_ARG";
        case REACH_ERR_BAD_ABI:      return "REACH_ERR_BAD_ABI";
        case REACH_ERR_NO_MEM:       return "REACH_ERR_NO_MEM";
        case REACH_ERR_STALE_PEER:   return "REACH_ERR_STALE_PEER";
        case REACH_ERR_UNKNOWN_PEER: return "REACH_ERR_UNKNOWN_PEER";
        case REACH_ERR_BAD_ARG:      return "REACH_ERR_BAD_ARG";
    }
    return "REACH_ERR_?";
}

uint32_t reach_abi_version(void) {
    return REACH_ABI_VERSION;
}

} // extern "C"
