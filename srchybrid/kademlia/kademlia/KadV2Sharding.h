// this file is part of eMule eSE — Kad Search v2 sharding (M3)
//
// Cap 4 §4.4 monograph. Per-keyword adaptive shard degree.
// Custodian role: count entries per keyword, announce when hot.
// Publisher/searcher role: cache shard degrees announced by gossip,
// re-route to shard_key(kw, i) instead of MD4(kw).
#pragma once

#include "KadV2Defines.h"

namespace Kademlia
{

class CKadV2Sharding
{
public:
    static CKadV2Sharding& Get();

    // === Custodian path ===

    // Called from indexed.cpp when a new entry is added for keyword `uTarget`.
    // Returns the current shard degree s. If the entry count just crossed
    // T_hot, returns the newly promoted s and the caller should emit an
    // OP_KADEMLIA2_KEY_SHARD_ANNOUNCE gossip.
    uint8 OnEntryAdded(const CUInt128 &uKeywordHash, uint32 entryCount, bool &outShouldAnnounce);

    // Decay: called periodically (every minute) by Kademlia::Process. If
    // a keyword stayed cold for KADV2_SHARD_COOLDOWN_S, demote.
    void  ProcessDecay();

    // === Publisher/searcher path ===

    // Cache an announce received from a neighbour. Replaces previous entry
    // for the same uTarget. Expires at announceTime + KADV2_SHARD_ANNOUNCE_TTL_S.
    void  OnShardAnnounceReceived(const CUInt128 &uTarget, uint8 s, uint32 validUntilUnixTs);

    // Returns the current shard degree for `uTarget`. 0 means no sharding
    // active (publish/query to MD4(kw) directly).
    uint8 LookupShardDegree(const CUInt128 &uTarget) const;

    // Compute shard_key(kw, i) = MD4(kw_bytes || "\x1E" || uint8(i)).
    // Caller selects i via random_uint(0, 2^s - 1) for publish, or iterates
    // i ∈ [0, 2^s) for query.
    static CUInt128 DeriveShardKey(const CStringA &kwBytes, uint8 i);

    // === Wire format helpers (Cap 5 §5.3 monograph) ===

    // OP_KADEMLIA2_KEY_SHARD_ANNOUNCE payload: <kw_hash 16><s 1><valid_until 4>
    // Serialize into `out` (caller-allocated, ≥ 21 bytes); returns bytes written.
    static size_t SerializeAnnounce(const CUInt128 &uTarget, uint8 s, uint32 validUntilUnixTs, uint8 *out, size_t outLen);

    // Parse incoming announce. Returns false on malformed input.
    static bool   ParseAnnounce(const uint8 *in, size_t inLen, CUInt128 &outTarget, uint8 &outS, uint32 &outValidUntilUnixTs);

private:
    CKadV2Sharding();
    CKadV2Sharding(const CKadV2Sharding&) = delete;
    CKadV2Sharding& operator=(const CKadV2Sharding&) = delete;

    struct CustodianState {
        uint8  s;                // 0 = not sharded
        uint32 lastHotSince;     // GetTickCount() / 1000 (epoch s) when first promoted
        uint32 lastCheck;        // last decay check
    };
    struct AnnouncedState {
        uint8  s;
        uint32 validUntilUnixTs;
    };

    mutable CCriticalSection m_lock;
    // Keys are 32-char lowercase hex of the CUInt128 (CStringA). This matches
    // the eMule CMap pattern used elsewhere (e.g. m_streamPubkeyPin in
    // LiveStreamManager) and avoids needing a CUInt128-as-key specialisation.
    CMap<CStringA, LPCSTR, CustodianState, CustodianState&> m_custodian;
    CMap<CStringA, LPCSTR, AnnouncedState, AnnouncedState&> m_announced;

    static CStringA KeyOf(const CUInt128 &u);
    static uint8 ComputeShardDegree(uint32 entryCount);  // s = ceil(log2(n/T_hot)), clamped
};

}  // namespace Kademlia
