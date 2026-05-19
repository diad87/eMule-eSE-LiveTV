//this file is part of eMule
// v0.71 IPv6 Sprint 5 — Kad keepalive (anti-firewall layer C). See header.
#include "stdafx.h"
#include "KadKeepalive.h"
#include "LiveDebugLog.h"
#include "Preferences.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

// Send a KADEMLIA3_PING_REQ to each supernode every PING_INTERVAL_MS so that
// stateful firewall conntrack on the outbound flow stays open. If we miss
// PONG_TIMEOUT_MS pongs in a row from a supernode, we rotate it out of the
// active set. The supernode pool is rebuilt from Kad routing table entries
// once that lands in Sprint 4; until then AddSupernode() is called manually
// by the prober.
static const DWORD KEEPALIVE_PING_INTERVAL_MS = 25u * 1000u;   // 25 s
static const DWORD KEEPALIVE_PONG_TIMEOUT_MS  = 90u * 1000u;   // 3 missed pings
static const size_t KEEPALIVE_MAX_SUPERNODES   = 10;

CKadKeepalive& CKadKeepalive::Instance()
{
    static CKadKeepalive inst;
    return inst;
}

void CKadKeepalive::Start()
{
    if (m_bRunning) return;
    m_bRunning = true;
    m_dwLastTick = GetTickCount();
    LIVE_LOG("KAD3", "Keepalive started (interval=%us, pool size=%zu)",
        KEEPALIVE_PING_INTERVAL_MS / 1000, m_supernodes.size());
}

void CKadKeepalive::Stop()
{
    if (!m_bRunning) return;
    m_bRunning = false;
    LIVE_LOG("KAD3", "Keepalive stopped");
}

void CKadKeepalive::AddSupernode(const CAddress& addr, uint16 port)
{
    if (m_supernodes.size() >= KEEPALIVE_MAX_SUPERNODES) {
        // Pool full — silently ignore. Sprint 4 will replace the worst
        // candidate based on RTT/uptime once the routing table is wired.
        return;
    }
    // Dedup: same (addr, port) pair never added twice.
    for (auto& s : m_supernodes) {
        if (s.addr == addr && s.port == port) return;
    }
    Supernode s;
    s.addr = addr;
    s.port = port;
    s.lastPingTick = 0;
    s.lastPongTick = 0;
    s.consecutiveMisses = 0;
    m_supernodes.push_back(s);
    m_stats.supernodesActive = (uint32)m_supernodes.size();
}

void CKadKeepalive::BlacklistSupernode(const CAddress& addr, uint16 port)
{
    auto it = m_supernodes.begin();
    while (it != m_supernodes.end()) {
        if (it->addr == addr && it->port == port) {
            LIVE_LOG("KAD3", "Keepalive blacklisted supernode (misses=%d)",
                it->consecutiveMisses);
            it = m_supernodes.erase(it);
        } else {
            ++it;
        }
    }
    m_stats.supernodesActive = (uint32)m_supernodes.size();
}

void CKadKeepalive::Tick()
{
    if (!m_bRunning) return;
    DWORD now = GetTickCount();
    m_stats.lastTickMs = now;

    // Rate-limit: only emit at most one batch per PING_INTERVAL_MS to avoid
    // pinging every supernode every Process() tick (which is 1 s).
    if (now - m_dwLastTick < KEEPALIVE_PING_INTERVAL_MS) return;
    m_dwLastTick = now;

    // For each supernode: send a ping (or count it as missed if last pong
    // is too old). The actual send happens via the Kad UDP listener when
    // Sprint 4 implements KADEMLIA3_PING_REQ. Until then we just track
    // the schedule + maintain pool health; misses are simulated as 0
    // because no pings are emitted.
    auto it = m_supernodes.begin();
    while (it != m_supernodes.end()) {
        if (it->lastPongTick != 0 && (now - it->lastPongTick) > KEEPALIVE_PONG_TIMEOUT_MS) {
            it->consecutiveMisses++;
            if (it->consecutiveMisses >= 3) {
                LIVE_LOG("KAD3", "Keepalive: dropping unresponsive supernode (misses=%d)",
                    it->consecutiveMisses);
                it = m_supernodes.erase(it);
                continue;
            }
        }
        it->lastPingTick = now;
        // TODO Sprint 4: theApp.kadudpListener->SendKad3PingReq(it->addr, it->port);
        m_stats.pingsSent++;
        ++it;
    }
    m_stats.supernodesActive = (uint32)m_supernodes.size();
}
