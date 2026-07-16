// this file is part of eMule eSE — Persistent Search Tunnel pool impl (F4b)
#include "stdafx.h"
#include "KadV2TunnelPool.h"
#include "LiveCircuit.h"
#include "LiveTunnel.h"

namespace Kademlia {

namespace {

// D4 (v8.1): keep a small WARM pool. Target 2 = 1 in-use + 1 pre-built spare, so a
// circuit rotation never leaves the consumer with zero circuits (make-before-break).
// The old fixed 30s/25s pool TTL predated the 300s circuit rotation (TUNNEL_ROTATION_
// BASE_MS) and would have evicted still-Active circuits; retire is now driven by the
// circuit's OWN state (Destroyed) instead — see Tick().
const size_t PRIVATE_POOL_TARGET = 3;

}  // namespace

CKadV2TunnelPool& CKadV2TunnelPool::Get()
{
    static CKadV2TunnelPool s_instance;
    return s_instance;
}

std::shared_ptr<eSELive::CLiveCircuit> CKadV2TunnelPool::Acquire(const CUInt128& destinationKey)
{
    // v8.1 D5 (Cap 6 §6.5.2) - return the Active circuit whose EXIT is XOR-closest to
    // destinationKey. Best-effort: only circuits whose exit Kad node-ID was resolved at build
    // time (m_haveExitKadKey) join the XOR ranking; if none resolved one, fall back to the
    // first Active circuit (preserves the basic PST reuse benefit). XOR-by-exit-ID is a SOFT
    // proximity heuristic (the exit being near the target in DHT space => likely fewer hops at
    // its own Kad query), NOT a guarantee the exit holds the keyword.
    CSingleLock lock(&m_lock, TRUE);
    std::shared_ptr<eSELive::CLiveCircuit> bestXor;
    CUInt128 bestDist;   // meaningful only once bestXor is set
    std::shared_ptr<eSELive::CLiveCircuit> firstActive;
    for (auto& e : m_entries) {
        if (!e.tunnel || e.tunnel->State() != eSELive::CircuitState::Active ||
            e.tunnel->m_k6QuotaIssuerCircuit) continue;
        if (!firstActive) firstActive = e.tunnel;
        if (!e.tunnel->m_haveExitKadKey) continue;
        CUInt128 dist = destinationKey;
        dist.Xor(e.tunnel->m_exitKadKey);
        if (!bestXor || dist < bestDist) { bestXor = e.tunnel; bestDist = dist; }
    }
    return bestXor ? bestXor : firstActive;   // firstActive is nullptr if no Active circuit
}

void CKadV2TunnelPool::RegisterTunnel(std::shared_ptr<eSELive::CLiveCircuit> tunnel)
{
    if (!tunnel) return;
    CSingleLock lock(&m_lock, TRUE);
    for (const PoolEntry& existing : m_entries)
        if (existing.tunnel && existing.tunnel->Id() == tunnel->Id())
            return;
    PoolEntry pe;
    pe.tunnel = tunnel;
    m_entries.push_back(pe);
}

void CKadV2TunnelPool::Clear()
{
    CSingleLock lock(&m_lock, TRUE);
    m_entries.clear();   // drop our shared_ptr aliases (called from CLiveTunnel::Stop)
}

void CKadV2TunnelPool::Tick()
{
    size_t privateActive = 0;
    size_t quotaIssuerActive = 0;
    {
        CSingleLock lock(&m_lock, TRUE);

        // Step 1: retire entries whose underlying circuit is gone. Driven by the
        // circuit's OWN state (CLiveTunnel rotates Active circuits to Destroyed at
        // TUNNEL_ROTATION_BASE_MS, 300s), NOT a fixed pool TTL — the old 30s TTL would
        // have evicted still-Active circuits and churned the pool.
        auto isDead = [](const PoolEntry& e) {
            return !e.tunnel || e.tunnel->State() == eSELive::CircuitState::Destroyed;
        };
        m_entries.erase(std::remove_if(m_entries.begin(), m_entries.end(), isDead),
                        m_entries.end());

        // Count Active pool entries (originator circuits that reached Active and
        // registered) — the make-before-break target bound + the "seeded" guard below.
        for (auto& e : m_entries)
            if (e.tunnel && e.tunnel->State() == eSELive::CircuitState::Active) {
                if (e.tunnel->m_k6QuotaIssuerCircuit) ++quotaIssuerActive;
                else ++privateActive;
            }
    }   // release m_lock BEFORE calling CLiveTunnel — RegisterTunnel runs UNDER the
        // tunnel lock (tunnel->pool), so we must never nest pool->tunnel here.

    // Step 2: D4 make-before-break (outside the pool lock). Build ONE warm spare only if
    // the pool is already SEEDED (poolActive >= 1 — a circuit was built deliberately via
    // test_circuit or a prior successor) AND below target. The seeded guard means we NEVER
    // build from an empty pool, so a node that never opted into tunneling (no manual
    // circuit; default Adaptive->Direct) builds nothing here and the C5 control plane is
    // never auto-engaged on a working stream. The PendingCircuitCount()==0 IN-FLIGHT guard
    // stops Tick from re-firing every second while a successor is still mid-handshake (it
    // is Pending, not yet pool-Active) — otherwise it would burst a pile of Pending
    // circuits. BuildSuccessorCircuit is itself a no-op when no fork peer is connected.
    if (privateActive >= 1) {
        eSELive::CLiveTunnel& tun = eSELive::CLiveTunnel::Get();
        if (tun.PendingCircuitCount() == 0) {
            if (quotaIssuerActive == 0 && tun.BuildQuotaGuardCircuit())
                return;
            if (privateActive < PRIVATE_POOL_TARGET)
                tun.BuildSuccessorCircuit();
        }
    }
}

size_t CKadV2TunnelPool::Size() const
{
    CSingleLock lock(&m_lock, TRUE);
    return m_entries.size();
}

}  // namespace Kademlia
