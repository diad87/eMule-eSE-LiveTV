// this file is part of eMule eSE — Persistent Search Tunnel pool (F4b)
//
// Cap 6 §6.5 monograph. PST reuses an existing tunnel for multiple Kad
// RPCs in a session, reducing setup overhead (~600 ms per query) by
// ~80 %. Make-before-break: at 25/30 s into a tunnel's lifetime, a
// successor is pre-built so rotation is invisible to the consumer.
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

    // Register a freshly-built tunnel with the pool. Lifetime starts now.
    void RegisterTunnel(std::shared_ptr<eSELive::CLiveCircuit> tunnel);

    // Periodic tick (called from CKademlia::Process every second):
    //   - At lifetime 25/30 s: schedule a successor tunnel build.
    //   - At lifetime 30 s: retire current tunnel (state Destroyed),
    //     replacement should already be ready.
    void Tick();

    size_t Size() const;

    // Cap 6 §6.4.3 monograph: KAD_V2_TUNNEL_FANOUT for M3 sharded queries.
    // 8 tunnels in parallel, each multiplexing 8 RPCs → 64 shards total.
    static constexpr size_t TUNNEL_FANOUT = 8;

private:
    CKadV2TunnelPool() {}
    CKadV2TunnelPool(const CKadV2TunnelPool&) = delete;
    CKadV2TunnelPool& operator=(const CKadV2TunnelPool&) = delete;

    struct PoolEntry {
        std::shared_ptr<eSELive::CLiveCircuit> tunnel;
        DWORD createdTick;
        bool  successorScheduled;
    };
    mutable CCriticalSection m_lock;
    std::vector<PoolEntry> m_entries;
};

}  // namespace Kademlia
