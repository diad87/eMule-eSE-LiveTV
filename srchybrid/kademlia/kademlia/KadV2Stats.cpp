// this file is part of eMule eSE — Kad Search v2 stats counters impl (F1)
#include "stdafx.h"
#include "KadV2Stats.h"

namespace Kademlia
{

CKadV2Stats::CKadV2Stats()
    : m_shardAnnouncesRx(0)
    , m_shardAnnouncesTx(0)
    , m_hotKeywordsPromoted(0)
    , m_hotKeywordsDemoted(0)
    , m_bloomRebuilds(0)
    , m_bloomRx(0)
    , m_bloomTx(0)
    , m_bloomHits(0)
    , m_bloomMisses(0)
    , m_localQueriesRx(0)
    , m_localQueriesTx(0)
    , m_inboundQuotaDrops(0)
    , m_kEffectiveUpdates(0)
{}

CKadV2Stats& CKadV2Stats::Get()
{
    static CKadV2Stats s_instance;
    return s_instance;
}

CKadV2Stats::Snapshot CKadV2Stats::GetSnapshot() const
{
    Snapshot s;
    s.shardAnnouncesRx    = m_shardAnnouncesRx;
    s.shardAnnouncesTx    = m_shardAnnouncesTx;
    s.hotKeywordsPromoted = m_hotKeywordsPromoted;
    s.hotKeywordsDemoted  = m_hotKeywordsDemoted;
    s.bloomRebuilds       = m_bloomRebuilds;
    s.bloomRx             = m_bloomRx;
    s.bloomTx             = m_bloomTx;
    s.bloomHits           = m_bloomHits;
    s.bloomMisses         = m_bloomMisses;
    s.localQueriesRx      = m_localQueriesRx;
    s.localQueriesTx      = m_localQueriesTx;
    s.inboundQuotaDrops   = m_inboundQuotaDrops;
    s.kEffectiveUpdates   = m_kEffectiveUpdates;
    return s;
}

}  // namespace Kademlia
