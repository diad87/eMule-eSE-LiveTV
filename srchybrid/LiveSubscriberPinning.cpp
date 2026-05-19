// this file is part of eMule eSE — channel subscriber pinning impl (F3)
#include "stdafx.h"
#include "LiveSubscriberPinning.h"
#include "LiveSubscriptionStore.h"

namespace eSELive {

// Republish cadence: 6h base, ±60 min jitter (Cap 5 §5.3.4 thesis).
const uint32_t SUB_PIN_INTERVAL_SEC = 6u * 60u * 60u;
const uint32_t SUB_PIN_JITTER_SEC   = 60u * 60u;

uint64_t CLiveSubscriberPinning::IdOfPubkey(const uint8_t pubkey[32])
{
    // First 8 bytes is enough; collisions only matter for scheduler
    // identification (callback receives the real pubkey via store lookup
    // when needed).
    uint64_t id = 0;
    for (int i = 0; i < 8; ++i) id |= ((uint64_t)pubkey[i]) << (i * 8);
    return id;
}

CLiveSubscriberPinning& CLiveSubscriberPinning::Get()
{
    static CLiveSubscriberPinning s_instance;
    return s_instance;
}

void CLiveSubscriberPinning::Start()
{
    std::vector<SubscriptionEntry> subs;
    CLiveSubscriptionStore::Get().GetAll(subs);
    auto& sched = CSubscriberPinScheduler::Get();
    for (const auto& e : subs) {
        sched.AddOrUpdate(IdOfPubkey(e.channel_pubkey),
                          SUB_PIN_INTERVAL_SEC,
                          SUB_PIN_JITTER_SEC,
                          &DoRepublish);
    }
}

void CLiveSubscriberPinning::OnSubscriptionAdded(const uint8_t pubkey[32])
{
    CSubscriberPinScheduler::Get().AddOrUpdate(
        IdOfPubkey(pubkey),
        SUB_PIN_INTERVAL_SEC,
        SUB_PIN_JITTER_SEC,
        &DoRepublish);
}

void CLiveSubscriberPinning::OnSubscriptionRemoved(const uint8_t pubkey[32])
{
    CSubscriberPinScheduler::Get().Remove(IdOfPubkey(pubkey));
}

void CLiveSubscriberPinning::DoRepublish(uint64_t opaqueId)
{
    // F3: locate the subscription entry by id and (F5 onward) issue a
    // CLiveKadBridge::PublishChannel(channel_pubkey) via tunnel. For now
    // we just log; the wire-up happens when CLiveKadBridge gains the
    // PublishChannel method in F5.
    //
    // The cover-traffic mix (5-10 random non-subscribed records) is
    // also generated here once PublishChannel exists — pick from the
    // gossip cache via CLiveSubscriptionStore::PickCoverTrafficSet.
    (void)opaqueId;
}

}  // namespace eSELive
