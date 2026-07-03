//this file is part of eMule
// v0.71 IPv6 Sprint 5 — Kad keepalive (anti-firewall layer C).
//
// Per docs/IPV6_PLAN.md §8.5: stateful residential firewalls drop unsolicited
// inbound after the conntrack expires (typically 30-60 s). We rotate a small
// pool of supernodes (5-10) and send a tiny outbound KADEMLIA3_PING_REQ
// to each every 25 s. The supernode replies, the conntrack stays open, and
// any peer wishing to contact us via that supernode arrives during the
// remaining window.
//
// This is the cheapest of the three "make me reachable" layers — under
// 1 KB/s, no router involvement, works on every consumer network including
// CGNAT (as long as outbound v6 works at all).
//
// Sprint 5 ships the SKELETON. Real supernode selection (latency-based, with
// trust scoring) lands in S5.3. KADEMLIA3_PING_REQ/RES handlers live in
// the Kad UDP listener (Sprint 4).
#pragma once

#include "eMuleAI/Address.h"
#include <vector>

class CKadKeepalive {
public:
    static CKadKeepalive& Instance();

    // Wake the keepalive loop. Idempotent. The firewall prober calls this
    // when its cascade settles on LayerKeepalive.
    void Start();
    void Stop();
    bool IsRunning() const { return m_bRunning; }

    // Thread-safe activation control. The /api keepalive endpoint (or the firewall
    // prober) flips this from another thread; the real Start()/Stop() runs on the Kad
    // thread inside Tick(), so m_supernodes is never touched cross-thread.
    void RequestStart();
    void RequestStop();

    // Called every Process() tick from the main loop (~1 s).
    void Tick();

    // Register / blacklist supernodes. m_supernodes is rotated when a member
    // misses too many PINGs in a row.
    void AddSupernode(const CAddress& addr, uint16 port);
    void BlacklistSupernode(const CAddress& addr, uint16 port);

    // R.2: a supernode replied to our ping — refresh its health (called from the
    // KADEMLIA3_PING_RES handler in the Kad UDP listener). uIP is host-order.
    void OnPong(uint32 uIP, uint16 port);

    // Telemetry: how many keepalives went out / how many got a reply in the
    // last 5-minute window. Used by /api/live/debug.
    struct Stats {
        uint32 pingsSent;
        uint32 pongsReceived;
        uint32 supernodesActive;
        DWORD  lastTickMs;
    };
    Stats GetStats() const { return m_stats; }

private:
    CKadKeepalive() : m_bRunning(false), m_dwLastTick(0), m_ctrlRequest(0) { memset(&m_stats, 0, sizeof m_stats); }
    ~CKadKeepalive() = default;
    CKadKeepalive(const CKadKeepalive&) = delete;

    struct Supernode {
        CAddress addr;
        uint16   port;
        DWORD    lastPingTick;
        DWORD    lastPongTick;
        int      consecutiveMisses;
    };

    volatile bool        m_bRunning;      // read cross-thread by IsRunning() from webserver workers
    DWORD                m_dwLastTick;
    volatile LONG        m_ctrlRequest;   // 0=none, 1=start, 2=stop (cross-thread control)
    std::vector<Supernode> m_supernodes;
    Stats                m_stats;
};
