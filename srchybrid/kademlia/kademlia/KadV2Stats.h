// this file is part of eMule eSE — Kad Search v2 stats counters (F1)
//
// Per-mechanism counters exposed via /api/live/debug. Atomics (LONG +
// InterlockedIncrement) so multiple threads (UDP listener, search worker,
// timer, web server) can read/write without external locking.
#pragma once

namespace Kademlia
{

class CKadV2Stats
{
public:
    static CKadV2Stats& Get();   // singleton; lifetime = process

    // M3 — sharding
    void OnShardAnnounceRx()  { InterlockedIncrement(&m_shardAnnouncesRx); }
    void OnShardAnnounceTx()  { InterlockedIncrement(&m_shardAnnouncesTx); }
    void OnHotKeywordPromote() { InterlockedIncrement(&m_hotKeywordsPromoted); }
    void OnHotKeywordDemote()  { InterlockedIncrement(&m_hotKeywordsDemoted); }

    // M5 — bloom gossip
    void OnBloomRebuild()     { InterlockedIncrement(&m_bloomRebuilds); }
    void OnBloomRx()          { InterlockedIncrement(&m_bloomRx); }
    void OnBloomTx()          { InterlockedIncrement(&m_bloomTx); }
    void OnBloomHit()         { InterlockedIncrement(&m_bloomHits); }
    void OnBloomMiss()        { InterlockedIncrement(&m_bloomMisses); }
    void OnLocalQueryRx()     { InterlockedIncrement(&m_localQueriesRx); }
    void OnLocalQueryTx()     { InterlockedIncrement(&m_localQueriesTx); }
    void OnInboundQuotaDrop() { InterlockedIncrement(&m_inboundQuotaDrops); }

    // M6 — k effective
    void OnKEffectiveUpdate() { InterlockedIncrement(&m_kEffectiveUpdates); }

    // Snapshot (no lock; counters are atomic, read may be slightly skewed)
    struct Snapshot {
        LONG shardAnnouncesRx;
        LONG shardAnnouncesTx;
        LONG hotKeywordsPromoted;
        LONG hotKeywordsDemoted;
        LONG bloomRebuilds;
        LONG bloomRx;
        LONG bloomTx;
        LONG bloomHits;
        LONG bloomMisses;
        LONG localQueriesRx;
        LONG localQueriesTx;
        LONG inboundQuotaDrops;
        LONG kEffectiveUpdates;
    };
    Snapshot GetSnapshot() const;

private:
    CKadV2Stats();
    CKadV2Stats(const CKadV2Stats&) = delete;
    CKadV2Stats& operator=(const CKadV2Stats&) = delete;

    LONG m_shardAnnouncesRx;
    LONG m_shardAnnouncesTx;
    LONG m_hotKeywordsPromoted;
    LONG m_hotKeywordsDemoted;
    LONG m_bloomRebuilds;
    LONG m_bloomRx;
    LONG m_bloomTx;
    LONG m_bloomHits;
    LONG m_bloomMisses;
    LONG m_localQueriesRx;
    LONG m_localQueriesTx;
    LONG m_inboundQuotaDrops;
    LONG m_kEffectiveUpdates;
};

}  // namespace Kademlia
