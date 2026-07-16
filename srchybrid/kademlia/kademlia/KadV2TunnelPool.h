// this file is part of eMule eSE — Persistent Search Tunnel pool (F4b)
//
// Cap 6 §6.5 monograph. PST reuses an existing tunnel for multiple Kad
// RPCs in a session, reducing setup overhead (~600 ms per query) by ~80 %.
// v8.1 D4: make-before-break is now POOL_TARGET-driven — the pool keeps up to
// POOL_TARGET warm circuits and pre-builds a successor so a circuit rotation is
// invisible to the consumer. Adaptive/Tunneled mode also seeds the first circuit
// automatically when a compatible authenticated peer becomes available.
// Entries are retired when their underlying circuit reaches Destroyed (the circuit's
// OWN 300s rotation), not a fixed pool TTL.
#pragma once

#include "KadV2Defines.h"
#include <memory>
#include <vector>

namespace eSELive { class CLiveCircuit; }

namespace Kademlia {

class CKadV2TunnelPool {
public:
    static CKadV2TunnelPool& Get();

    // Look up an existing tunnel reusable for an RPC to `destinationKey`.
    // Returns NULL if no tunnel matches; caller falls back to building one.
    std::shared_ptr<eSELive::CLiveCircuit> Acquire(const CUInt128& destinationKey);

    // Register a freshly-built tunnel with the pool (called when a circuit reaches
    // Active). Stores a 2nd shared_ptr alias; retired when the circuit is Destroyed.
    void RegisterTunnel(std::shared_ptr<eSELive::CLiveCircuit> tunnel);

    // Drop all entries (called from CLiveTunnel::Stop so the pool's shared_ptr aliases
    // don't keep stopped circuits alive / counted).
    void Clear();

    // Periodic tick (called from CKademlia::Process every second):
    //   - Retire entries whose circuit is Destroyed.
    //   - In Adaptive/Tunneled mode, seed the first circuit with bounded backoff.
    //   - While below POOL_TARGET and nothing is mid-handshake, build ONE successor
    //     so a rotation never leaves the consumer with no circuit.
    void Tick();

    size_t Size() const;

    // Cap 6 §6.4.3 monograph: KAD_V2_TUNNEL_FANOUT for M3 sharded queries.
    // 8 tunnels in parallel, each multiplexing 8 RPCs → 64 shards total.
    static constexpr size_t TUNNEL_FANOUT = 8;

private:
    CKadV2TunnelPool()
        : m_lastAutoSeedAttempt(0)
        , m_autoSeedRetryMs(5u * 1000u)
    {}
    CKadV2TunnelPool(const CKadV2TunnelPool&) = delete;
    CKadV2TunnelPool& operator=(const CKadV2TunnelPool&) = delete;

    struct PoolEntry {
        std::shared_ptr<eSELive::CLiveCircuit> tunnel;
    };
    mutable CCriticalSection m_lock;
    std::vector<PoolEntry> m_entries;
    DWORD m_lastAutoSeedAttempt;
    DWORD m_autoSeedRetryMs;
};

}  // namespace Kademlia
