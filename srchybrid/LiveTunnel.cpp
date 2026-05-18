// this file is part of eMule eSE — 2-hop onion tunnel manager impl (F4)
#include "stdafx.h"
#include "LiveTunnel.h"
#include "LiveCoverTraffic.h"
#include "LiveOnionCrypto.h"

namespace eSELive {

CLiveTunnel::CLiveTunnel()
    : m_rrNextIdx(0)
    , m_lastTickMs(0)
{}

CLiveTunnel& CLiveTunnel::Get()
{
    static CLiveTunnel s_instance;
    return s_instance;
}

uint32_t CLiveTunnel::NewCircuitId()
{
    // Local circuit IDs are 32-bit random — collisions astronomically rare;
    // we re-roll if Push collides (caller checks).
    uint8_t r[4];
    SecureRandomBytes(r, 4);
    uint32_t id = (uint32_t)r[0] | ((uint32_t)r[1] << 8)
                | ((uint32_t)r[2] << 16) | ((uint32_t)r[3] << 24);
    if (id == 0) id = 1;
    return id;
}

size_t CLiveTunnel::BuildPool(const uint8_t origin_pubkey[32],
                              const std::vector<CUpDownClient*>& relayCandidates,
                              size_t count)
{
    // F4 skeleton: builds the circuit OBJECTS and queues CREATE cells.
    // The actual TCP send to relay 1 happens in F5 when LiveMeshManager
    // gains the tunnel-aware send path. Here we register the circuit so
    // OnCellReceived can complete the handshake when CREATED arrives.
    if (count < TUNNEL_POOL_MIN) count = TUNNEL_POOL_MIN;
    if (count > TUNNEL_POOL_MAX) count = TUNNEL_POOL_MAX;
    if (relayCandidates.size() < 2) return 0;   // need >= 2 distinct hops

    CSingleLock lock(&m_lock, TRUE);
    size_t built = 0;
    for (size_t i = 0; i < count; ++i) {
        uint32_t id = 0;
        for (int t = 0; t < 4; ++t) {                  // up to 4 attempts
            id = NewCircuitId();
            bool collision = false;
            for (auto& c : m_circuits) if (c->Id() == id) { collision = true; break; }
            if (!collision) break;
            id = 0;
        }
        if (id == 0) continue;
        auto c = std::make_shared<CLiveCircuit>(id);
        c->SetState(CircuitState::Pending);
        // Hop selection — F5 wires the real picker (anti-Sybil /24, /16,
        // upload capacity, latency). For F4 we don't add hops yet; they
        // appear via OnCellReceived(CELL_CREATED) and ExtendHop().
        m_circuits.push_back(c);
        ++built;
    }
    (void)origin_pubkey;
    return built;
}

void CLiveTunnel::Stop()
{
    CSingleLock lock(&m_lock, TRUE);
    m_circuits.clear();
    m_rrNextIdx = 0;
}

bool CLiveTunnel::SendThrough(const uint8_t* payload, size_t payloadLen)
{
    if (!payload || payloadLen == 0) return false;
    CSingleLock lock(&m_lock, TRUE);
    if (m_circuits.empty()) return false;

    // Round-robin (multipath split, Decision 5.1).
    size_t tries = m_circuits.size();
    while (tries-- > 0) {
        const size_t idx = m_rrNextIdx % m_circuits.size();
        m_rrNextIdx = (m_rrNextIdx + 1) % m_circuits.size();
        auto& c = m_circuits[idx];
        if (c->State() != CircuitState::Active) continue;
        if (c->HopCount() == 0) continue;

        uint8_t cellPayload[CELL_PAYLOAD_MAX];
        size_t cellLen = 0;
        if (!c->OnionEncrypt(payload, payloadLen, cellPayload, cellLen))
            continue;
        uint8_t cell[CELL_TOTAL_BYTES];
        if (!CellPack(c->Id(), CELL_RELAY, cellPayload, cellLen, cell))
            continue;
        return c->m_sendQ.Push(cell);
    }
    return false;
}

bool CLiveTunnel::OnCellReceived(uint32_t circ_id, uint8_t cmd,
                                 const uint8_t* payload, uint16_t payloadLen,
                                 CUpDownClient* /*fromPeer*/)
{
    CSingleLock lock(&m_lock, TRUE);
    std::shared_ptr<CLiveCircuit> circ;
    for (auto& c : m_circuits)
        if (c->Id() == circ_id) { circ = c; break; }
    if (!circ) return false;

    switch (cmd) {
        case CELL_CREATED:
            // F5: derive K_send_A/K_recv_A from the ntor handshake reply,
            // register CircuitHop, set state HalfBuilt.
            (void)payload; (void)payloadLen;
            circ->SetState(CircuitState::HalfBuilt);
            return true;
        case CELL_EXTENDED:
            circ->SetState(CircuitState::Built);
            return true;
        case CELL_RELAY:
            // Peel one layer, forward / deliver. F5 wires the delivery
            // to LiveMeshManager.
            return true;
        case CELL_DESTROY:
            circ->SetState(CircuitState::Destroyed);
            return true;
        case CELL_PADDING:
            // Drop silently; statistics counted separately.
            return true;
        default:
            return false;
    }
}

void CLiveTunnel::Tick()
{
    CSingleLock lock(&m_lock, TRUE);
    // 1. Reap Destroyed circuits.
    auto isDead = [](const std::shared_ptr<CLiveCircuit>& c) {
        return c->State() == CircuitState::Destroyed;
    };
    m_circuits.erase(std::remove_if(m_circuits.begin(), m_circuits.end(), isDead),
                     m_circuits.end());
    // 2. Rotation: any circuit older than ROTATION_BASE_MS (+jitter) is
    // marked Destroyed; replacement build is initiated in F5 when we
    // have a swarm-peer list.
    for (auto& c : m_circuits) {
        if (c->State() == CircuitState::Active && c->AgeMs() > TUNNEL_ROTATION_BASE_MS)
            c->SetState(CircuitState::Destroyed);
    }
    m_lastTickMs = GetTickCount();
}

size_t CLiveTunnel::ActiveCircuitCount() const
{
    CSingleLock lock(&m_lock, TRUE);
    size_t n = 0;
    for (auto& c : m_circuits)
        if (c->State() == CircuitState::Active) ++n;
    return n;
}

}  // namespace eSELive
