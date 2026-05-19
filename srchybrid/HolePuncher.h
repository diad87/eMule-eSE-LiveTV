//this file is part of eMule
// v0.71 IPv6 Sprint 5 — Coordinated UDP hole-punching (anti-firewall layer D).
//
// Per docs/IPV6_PLAN.md §8.5: when two peers (A and B) are both behind
// stateful firewalls that block unsolicited inbound, neither can initiate
// a connection. The classic STUN-like fix is to use a rendezvous node R
// that has reachable inbound (a Kad supernode in practice):
//
//   1. A → R: HOLEPUNCH_REQ targeting B
//   2. R → B: HOLEPUNCH_FWD with A's CAddress + port
//   3. A and B simultaneously send UDP packets to each other
//   4. Both firewalls believe each packet is a response to their outbound,
//      and create conntrack rules accepting the incoming packets
//   5. The first to land at the destination is ACKed: HOLEPUNCH_ACK
//
// Sprint 5 ships the state machine + opcode handling skeleton. Real
// integration with Kad supernodes (R candidates) lands in S5.5.
#pragma once

#include "eMuleAI/Address.h"

class CHolePuncher {
public:
    static CHolePuncher& Instance();

    enum EPunchState {
        StateIdle      = 0,
        StateReqSent   = 1,  // A: sent REQ to rendezvous, waiting for ACK
        StateFwdSent   = 2,  // R: forwarded to B, waiting for ACK from either
        StateConnected = 3,  // Both sides ACKed — hole is open
        StateTimeout   = 4,  // No ACK within window
    };

    // Initiator (A): start a punch attempt against a peer through a rendezvous.
    // Returns the session id (for status tracking) or 0 if the prerequisites
    // aren't met (e.g. no rendezvous in known Kad routing table).
    uint32 StartPunch(const CAddress& target, uint16 targetPort,
                      const CAddress& rendezvous, uint16 rendezvousPort);

    // Called by the Kad UDP listener when a HOLEPUNCH_REQ/FWD/ACK arrives.
    void OnRequest (uint32 sessionId, const CAddress& from, uint16 fromPort);
    void OnForward (uint32 sessionId, const CAddress& origin, uint16 originPort);
    void OnAck     (uint32 sessionId);

    EPunchState GetState(uint32 sessionId) const;

    // Tick from the main 1 s loop. Times sessions out, retries punches.
    void Tick();

private:
    CHolePuncher() = default;
    ~CHolePuncher() = default;
    CHolePuncher(const CHolePuncher&) = delete;

    // Sessions stored in a small map keyed by session id. Capped at 32 to
    // avoid OOM under adversarial REQ flooding (rate-limited per /64 anyway).
};
