// this file is part of eMule eSE — Persistent Search Tunnel pool impl (F4b)
#include "stdafx.h"
#include "KadV2TunnelPool.h"
#include "LiveCircuit.h"
#include "LiveTunnel.h"

namespace Kademlia {

namespace {

// Tunnel lifetime: 30 s nominal, successor pre-built at 25 s.
const DWORD TUNNEL_LIFETIME_MS         = 30u * 1000u;
const DWORD TUNNEL_SUCCESSOR_AT_MS     = 25u * 1000u;

}  // namespace

CKadV2TunnelPool& CKadV2TunnelPool::Get()
{
    static CKadV2TunnelPool s_instance;
    return s_instance;
}

std::shared_ptr<eSELive::CLiveCircuit> CKadV2TunnelPool::Acquire(const CUInt128& /*destinationKey*/)
{
    // F4b: simple LRU-style acquire. Real "destination match" (Cap 6
    // §6.5.2 ≤2-hop-XOR proximity) is added in F5 when we have the
    // last-hop routing-table info per circuit. For now we return any
    // Active circuit, which already gives the basic PST cost reduction
    // (most savings come from not rebuilding tunnels in the same session).
    CSingleLock lock(&m_lock, TRUE);
    for (auto& e : m_entries) {
        if (e.tunnel->State() == eSELive::CircuitState::Active)
            return e.tunnel;
    }
    return nullptr;
}

void CKadV2TunnelPool::RegisterTunnel(std::shared_ptr<eSELive::CLiveCircuit> tunnel)
{
    if (!tunnel) return;
    CSingleLock lock(&m_lock, TRUE);
    PoolEntry pe;
    pe.tunnel = tunnel;
    pe.createdTick = GetTickCount();
    pe.successorScheduled = false;
    m_entries.push_back(pe);
}

void CKadV2TunnelPool::Tick()
{
    const DWORD now = GetTickCount();
    CSingleLock lock(&m_lock, TRUE);

    // Step 1: schedule successor for entries reaching 25s.
    for (auto& e : m_entries) {
        const DWORD age = now - e.createdTick;
        if (!e.successorScheduled && age >= TUNNEL_SUCCESSOR_AT_MS &&
            e.tunnel->State() == eSELive::CircuitState::Active)
        {
            e.successorScheduled = true;
            // F5 wiring: ask CLiveTunnel::Get() to build a 1-circuit
            // successor pool. The successor inherits PST eligibility at
            // its next-Acquire.
        }
    }
    // Step 2: retire entries past lifetime.
    auto isExpired = [&](const PoolEntry& e) {
        return (now - e.createdTick) >= TUNNEL_LIFETIME_MS ||
               e.tunnel->State() == eSELive::CircuitState::Destroyed;
    };
    m_entries.erase(std::remove_if(m_entries.begin(), m_entries.end(), isExpired),
                    m_entries.end());
}

size_t CKadV2TunnelPool::Size() const
{
    CSingleLock lock(&m_lock, TRUE);
    return m_entries.size();
}

}  // namespace Kademlia
