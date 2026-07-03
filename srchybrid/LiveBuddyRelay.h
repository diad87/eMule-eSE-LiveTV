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

    // R.3 OP_LIVE_RELAY_FWD (0xCF) sub-ops. Public so CLiveStreamManager's per-segment
    // push (which owns the signing keys) can name RELAY_SUB_CHUNK. Values byte-identical
    // to the original file-private consts.
    enum ERelaySubOp {
        RELAY_SUB_SETUP      = 0x01,  // B -> Rel: please relay my streamKey
        RELAY_SUB_SETUP_OK   = 0x02,  // Rel -> B: accepted
        RELAY_SUB_SETUP_DENY = 0x03,  // Rel -> B: rejected
        RELAY_SUB_CHUNK      = 0x10,  // B -> Rel: a whole-chunk record
    };

    // Broadcaster side: I need a relay. Find a v6 HighID buddy.
    void StartAsBroadcaster();

    // Broadcaster side: a relay answered our SETUP (SETUP_OK/DENY), driving
    // Negotiating -> Active / BuddyLost. Routed here from the shared 0xCF dispatch.
    void OnRelayReply(CUpDownClient* fromBuddy, uint8 subop, const uchar streamKey[16]);
    // Broadcaster side: the active relay buddy (NULL until SETUP_OK), + setter used
    // by StartAsBroadcaster. CLiveStreamManager::FeedSegment pushes chunks to it.
    CUpDownClient* GetActiveBuddy() const;
    void SetCandidateBuddy(CUpDownClient* buddy);
    // Clear broadcaster-side egress state (candidate/active buddy) between broadcasts so a
    // stale buddy from a previous stream is never pushed the new stream. State-only, no I/O.
    void ResetBroadcasterEgress();

    // Relay side: inbound OP_LIVE_RELAY_REQ (0xCE) — a viewer subscribes to a stream
    // we relay. Registers it as a downstream consumer (bounded; anti-amplification).
    void OnRelayReq(CUpDownClient* viewer, const uchar streamKey[16]);

    // Clear all relay state tied to a client (broadcaster session / downstream viewer /
    // our buddy) when it disconnects. Called from ~CUpDownClient — covers every teardown.
    void OnPeerDisconnected(CUpDownClient* peer);

    // Buddy side: a broadcaster asked me to relay. Accept if we have spare
    // upload + the broadcaster is in our trust list.
    bool AcceptRelayFromBroadcaster(CUpDownClient* broadcaster);

    // Buddy side: inbound OP_LIVE_RELAY_FWD (0xCF) from a broadcaster. subop =
    // SETUP (policy+register) or CHUNK (feed the exit-proxy). payload/len = bytes
    // after subop(1)+streamKey(16). R.3 increment 2.
    void OnRelayFwd(CUpDownClient* from, uint8 subop, const uchar streamKey[16], const uint8* payload, uint32 len);

    // Viewer side: I see a stream advertised through a buddy. Connect to
    // the buddy with OP_LIVE_RELAY_REQ rather than the broadcaster directly.
    bool ConnectViaBuddy(const uchar streamKey[16], const CAddress& buddy, uint16 buddyPort);

    // Viewer side test/activation trigger: marshal a ConnectViaBuddy onto the main thread.
    // Safe to call from a webserver worker (only flips an atomic flag + copies the request);
    // the actual connect-out runs in Tick() on the main thread. ipNet is network-order.
    void RequestViewerConnect(const uchar streamKey[16], uint32 ipNet, uint16 port);

    void Tick();
    ERelayState GetState() const;

private:
    CLiveBuddyRelay() = default;
    ~CLiveBuddyRelay() = default;
    CLiveBuddyRelay(const CLiveBuddyRelay&) = delete;
};
