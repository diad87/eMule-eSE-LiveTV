//this file is part of eMule
// v0.71 IPv6 Sprint 8 — LiveTV buddy relay impl. See header for design.
#include "stdafx.h"
#include "LiveBuddyRelay.h"
#include "LiveDebugLog.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

// Per-instance state. A real implementation needs separate sessions for
// "I am a broadcaster looking for a buddy" vs "I am a buddy relaying for
// someone" vs "I am a viewer connecting via a buddy"; this Sprint 8 cut
// tracks the simplest single role at a time.
static CLiveBuddyRelay::ERelayState g_relayState = CLiveBuddyRelay::StateIdle;

CLiveBuddyRelay& CLiveBuddyRelay::Instance()
{
    static CLiveBuddyRelay inst;
    return inst;
}

void CLiveBuddyRelay::StartAsBroadcaster()
{
    // Sprint 8 stub: real work is to issue a Kad search for v6 HighID
    // peers that are willing relays (using a TAG_ESE_BUDDY_RELAY tag),
    // pick one with best uptime, send OP_LIVE_RELAY_REQ, manage the
    // persistent outbound connection. The state machine flips through
    // LookingForBuddy → Negotiating → Active.
    g_relayState = StateLookingForBuddy;
    LIVE_LOG("RELAY", "BuddyRelay: looking for v6 HighID buddy (Sprint 4 Kad-v6 pending)");
}

bool CLiveBuddyRelay::AcceptRelayFromBroadcaster(CUpDownClient* broadcaster)
{
    // Acceptance policy lives here. Sprint 8 stub: reject by default
    // until proper trust signalling exists (broadcaster pubkey in known
    // friends list, spare upload check, mesh diversity).
    (void)broadcaster;
    LIVE_LOG("RELAY", "BuddyRelay: rejecting buddy request (trust check pending)");
    return false;
}

bool CLiveBuddyRelay::ConnectViaBuddy(const uchar streamKey[16], const CAddress& buddy, uint16 buddyPort)
{
    (void)streamKey; (void)buddy; (void)buddyPort;
    // Sprint 8 stub: would open a connection to the buddy and send
    // OP_LIVE_RELAY_REQ. The buddy responds with chunks via OP_LIVE_RELAY_FWD
    // until the broadcaster's stream ends.
    g_relayState = StateNegotiating;
    LIVE_LOG("RELAY", "BuddyRelay: viewer-side connection via buddy (handler pending)");
    return false;
}

void CLiveBuddyRelay::Tick()
{
    // Per-second tick. Timeouts, retries, buddy health checks live here.
    // No-op in Sprint 8 stub.
}

CLiveBuddyRelay::ERelayState CLiveBuddyRelay::GetState() const
{
    return g_relayState;
}
