// this file is part of eMule eSE — channel subscriber pinning (F3)
//
// Cap 5 §5.3.4 thesis. Every subscriber periodically republishes the
// ChannelRecord of channels they follow, so popular channels survive
// even if the owner is offline.
//
// Cover-traffic mixing: in the same burst, the client republishes
// 5-10 RANDOM records picked from "known but not subscribed", so an
// observer cannot infer which records are real subscriptions.
#pragma once

#include "SubscriberPinScheduler.h"

namespace eSELive {

class CLiveSubscriberPinning {
public:
    static CLiveSubscriberPinning& Get();

    // Called once at startup: registers a periodic job for every channel
    // in CLiveSubscriptionStore.
    void Start();

    // Subscription changes — keep scheduler in sync.
    void OnSubscriptionAdded(const uint8_t pubkey[32]);
    void OnSubscriptionRemoved(const uint8_t pubkey[32]);

private:
    CLiveSubscriberPinning() {}
    CLiveSubscriberPinning(const CLiveSubscriberPinning&) = delete;
    CLiveSubscriberPinning& operator=(const CLiveSubscriberPinning&) = delete;

    static void DoRepublish(uint64_t opaqueId);   // scheduler callback
    static uint64_t IdOfPubkey(const uint8_t pubkey[32]);
};

}  // namespace eSELive
