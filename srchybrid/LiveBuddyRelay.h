//this file is part of eMule
// v0.71 IPv6 Sprint 8 — LiveTV buddy relay (anti-firewall layer E for live).
//
// Scenario: a broadcaster on a network with no inbound reachability (both
// firewalled v6 AND CGNATed v4). All five upstream layers of the cascade
// failed. The broadcaster cannot accept viewers directly.
//
// Solution: pick a v6-reachable buddy with spare upload (typically another
// fork user with HighID). The broadcaster maintains a persistent outbound
// connection to the buddy. The buddy advertises itself as a relay for the
// stream. Viewers connect to the buddy; the buddy proxies chunks via the
// pre-existing connection back to the broadcaster.
//
// Wire opcodes:
//   OP_LIVE_RELAY_REQ (0xCE): viewer → buddy: "give me chunks for streamKey"
//   OP_LIVE_RELAY_FWD (0xCF): buddy ↔ broadcaster: chunks transit this link
//
// Sprint 8 ships the skeleton. Real buddy selection + bidirectional relay
// state machine + bandwidth accounting come incrementally.
#pragma once

#include "eMuleAI/Address.h"

class CUpDownClient;

class CLiveBuddyRelay {
public:
    static CLiveBuddyRelay& Instance();

    enum ERelayState {
        StateIdle           = 0,
        StateLookingForBuddy = 1,  // querying Kad for buddy candidates
        StateNegotiating    = 2,   // sending RELAY_REQ to a candidate
        StateActive         = 3,   // chunks flowing through buddy
        StateBuddyLost      = 4,   // buddy disconnected; falling back / retry
    };

    // Broadcaster side: I need a relay. Find a v6 HighID buddy.
    void StartAsBroadcaster();

    // Buddy side: a broadcaster asked me to relay. Accept if we have spare
    // upload + the broadcaster is in our trust list.
    bool AcceptRelayFromBroadcaster(CUpDownClient* broadcaster);

    // Viewer side: I see a stream advertised through a buddy. Connect to
    // the buddy with OP_LIVE_RELAY_REQ rather than the broadcaster directly.
    bool ConnectViaBuddy(const uchar streamKey[16], const CAddress& buddy, uint16 buddyPort);

    void Tick();
    ERelayState GetState() const;

private:
    CLiveBuddyRelay() = default;
    ~CLiveBuddyRelay() = default;
    CLiveBuddyRelay(const CLiveBuddyRelay&) = delete;
};
