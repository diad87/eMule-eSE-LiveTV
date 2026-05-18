// this file is part of eMule eSE — Kad Search v2 M6 (k effective)
//
// Cap 4 §4.7 monograph. Adapts replication factor per keyword based on
// observed query rate at the custodian.
#pragma once

#include "KadV2Defines.h"

namespace Kademlia
{

class CKadV2KEffective
{
public:
    static CKadV2KEffective& Get();

    // === Custodian path ===

    // Called when a query for keyword `uTarget` is processed by this node.
    void OnQueryReceived(const CUInt128 &uTarget);

    // Called once per KADV2_K_UPDATE_INTERVAL_S to recompute k_effective.
    // Returns the list of (keyword, new_k) pairs that changed enough to
    // warrant gossiping a new TAG_K_EFFECTIVE to neighbours.
    struct KEffUpdate { CUInt128 uTarget; uint8 kNew; };
    void RecomputeAndGetChanges(CArray<KEffUpdate> &outChanges);

    // === Publisher path ===

    // Returns the k effective announced for `uTarget`. KADV2_K_BASE (10) if
    // not announced (compat v1: behave like fixed k=10).
    uint8 LookupKEffective(const CUInt128 &uTarget) const;

    // Cache an announce received in TAG_K_EFFECTIVE (Cap 5 monograph §5.4).
    void OnKEffectiveAnnounceReceived(const CUInt128 &uTarget, uint8 kNew);

private:
    CKadV2KEffective();
    CKadV2KEffective(const CKadV2KEffective&) = delete;
    CKadV2KEffective& operator=(const CKadV2KEffective&) = delete;

    struct CustodianBucket {
        uint32 queriesLastWindow;   // counter for current window
        uint8  kEffective;          // current k value
        uint32 windowStartUnixTs;
    };
    struct AnnouncedBucket {
        uint8  kEffective;
        uint32 lastSeenUnixTs;
    };

    mutable CCriticalSection m_lock;
    CMap<CStringA, LPCSTR, CustodianBucket,  CustodianBucket&>  m_custodian;
    CMap<CStringA, LPCSTR, AnnouncedBucket, AnnouncedBucket&>   m_announced;

    static CStringA KeyOf(const CUInt128 &u);

    // load_ratio = q_rate(kw) / mean(q_rate(*))
    // k_eff = clamp(K_BASE * max(1, log2(load_ratio)+1), K_MIN, K_MAX)
    static uint8 ComputeKEffective(uint32 queriesForKw, uint32 meanQueries);
};

}  // namespace Kademlia
