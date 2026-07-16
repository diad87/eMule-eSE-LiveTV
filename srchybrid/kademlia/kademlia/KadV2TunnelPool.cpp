// this file is part of eMule eSE — Persistent Search Tunnel pool impl (F4b)
#include "stdafx.h"
#include "KadV2TunnelPool.h"
#include "KadV2ModeSelector.h"
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

// Empty-pool discovery is deliberately patient. A fresh node may spend a long
// time connected only to vanilla peers; retrying every CKademlia::Process tick
// would add needless scans and handshake churn. An Active registration resets
// the interval immediately.
const DWORD AUTO_SEED_RETRY_MIN_MS = 5u * 1000u;
const DWORD AUTO_SEED_RETRY_MAX_MS = 5u * 60u * 1000u;

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
    m_lastAutoSeedAttempt = GetTickCount();
    m_autoSeedRetryMs = AUTO_SEED_RETRY_MIN_MS;
}

void CKadV2TunnelPool::Clear()
{
    CSingleLock lock(&m_lock, TRUE);
    m_entries.clear();   // drop our shared_ptr aliases (called from CLiveTunnel::Stop)
    m_lastAutoSeedAttempt = 0;
    m_autoSeedRetryMs = AUTO_SEED_RETRY_MIN_MS;
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
        // registered) for adoption bootstrap and the warm-pool target below.
        for (auto& e : m_entries)
            if (e.tunnel && e.tunnel->State() == eSELive::CircuitState::Active) {
                if (e.tunnel->m_k6QuotaIssuerCircuit) ++quotaIssuerActive;
                else ++privateActive;
            }
    }   // release m_lock BEFORE calling CLiveTunnel — RegisterTunnel runs UNDER the
        // tunnel lock (tunnel->pool), so we must never nest pool->tunnel here.

    // Step 2: adoption bootstrap (outside the pool lock). Adaptive/Tunneled nodes
    // use Kad2 as the compatibility root-link and seed Kad6 as soon as one capable,
    // authenticated peer is connected. Direct mode never auto-engages this plane.
    eSELive::CLiveTunnel& tun = eSELive::CLiveTunnel::Get();
    if (privateActive == 0) {
        if (CKadV2ModeSelector::Get().GetDefaultMode() == CKadV2Mode::Direct ||
            tun.PendingCircuitCount() != 0)
            return;

        const DWORD now = GetTickCount();
        DWORD lastAttempt = 0;
        DWORD retryMs = AUTO_SEED_RETRY_MIN_MS;
        {
            CSingleLock lock(&m_lock, TRUE);
            lastAttempt = m_lastAutoSeedAttempt;
            retryMs = m_autoSeedRetryMs;
        }
        if (lastAttempt != 0 && now - lastAttempt < retryMs)
            return;

        // This is tunnelOnly-STRICT: without a compatible peer the attempt is
        // a local no-op. Back off until RegisterTunnel proves a circuit Active.
        tun.BuildSuccessorCircuit();
        {
            CSingleLock lock(&m_lock, TRUE);
            m_lastAutoSeedAttempt = now;
            if (m_autoSeedRetryMs < AUTO_SEED_RETRY_MAX_MS) {
                const DWORD doubled = m_autoSeedRetryMs * 2u;
                m_autoSeedRetryMs = doubled > AUTO_SEED_RETRY_MAX_MS
                    ? AUTO_SEED_RETRY_MAX_MS : doubled;
            }
        }
        return;
    }

    // Step 3: once seeded, keep the quota path and private warm spares ready.
    // The in-flight guard prevents bursts during CREATE/CREATED handshakes.
    if (tun.PendingCircuitCount() == 0) {
        if (quotaIssuerActive == 0 && tun.BuildQuotaGuardCircuit())
            return;
        if (privateActive < PRIVATE_POOL_TARGET)
            tun.BuildSuccessorCircuit();
    }
}

size_t CKadV2TunnelPool::Size() const
{
    CSingleLock lock(&m_lock, TRUE);
    return m_entries.size();
}

}  // namespace Kademlia
