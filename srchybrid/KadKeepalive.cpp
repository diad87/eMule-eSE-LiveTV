//this file is part of eMule
// v0.71 IPv6 Sprint 5 — Kad keepalive (anti-firewall layer C). See header.
#include "stdafx.h"
#include "KadKeepalive.h"
#include "LiveDebugLog.h"
#include "Preferences.h"
#include "kademlia/kademlia/Kademlia.h"        // R.2: CKademlia::GetUDPListener() / GetRoutingZone()
#include "kademlia/net/KademliaUDPListener.h"  // R.2: SendKad3PingReq
#include "kademlia/routing/RoutingZone.h"      // R.2: GetBootstrapContacts / ContactArray
#include "kademlia/routing/Contact.h"          // R.2: CContact (GetNetIP/GetUDPPort)

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

void CKadKeepalive::RequestStart() { InterlockedExchange(&m_ctrlRequest, 1); }
void CKadKeepalive::RequestStop()  { InterlockedExchange(&m_ctrlRequest, 2); }

void CKadKeepalive::AddSupernode(const CAddress& addr, uint16 port, const Kademlia::CUInt128& kadID)
{
	if (port == 0 || kadID == 0)
		return;
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
	s.kadID = kadID;
    s.lastPingTick = 0;
    // Seed the pong clock to "now" so a node that NEVER answers (e.g. a vanilla 0.70b
    // peer that drops our 0x66) still enters the miss-detector after PONG_TIMEOUT and is
    // rotated out, instead of being pinged forever. A real PONG resets it in OnPong().
    s.lastPongTick = GetTickCount();
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
    // Honor a cross-thread start/stop request here on the Kad thread, so Start()/Stop()
    // (which touch m_supernodes) never race the /api worker that flipped the flag.
    const LONG ctrl = InterlockedExchange(&m_ctrlRequest, 0);
    if (ctrl == 1) Start();
    else if (ctrl == 2) Stop();

    if (!m_bRunning) return;

    // R.2 pool population: stock the supernode set straight from the live Kad
    // routing table. GetBootstrapContacts returns the stable, long-lived contacts
    // (the same set used to seed nodes.dat), which is exactly what we want holding
    // our NAT conntrack open. Size-gated so it's a no-op once full. GetNetIP() is
    // network-order, so CAddress(...,false) stores it verbatim (Tick's ToUInt32(true)
    // converts back to host-order for the send).
    if (m_supernodes.size() < 5 && Kademlia::CKademlia::GetRoutingZone() != NULL) {
        Kademlia::ContactArray contacts;
        Kademlia::CKademlia::GetRoutingZone()->GetBootstrapContacts(contacts, 20);
        for (Kademlia::ContactArray::const_iterator it = contacts.begin();
             it != contacts.end() && m_supernodes.size() < KEEPALIVE_MAX_SUPERNODES; ++it) {
            Kademlia::CContact* c = *it;
            if (c == NULL || c->GetNetIP() == 0 || c->GetUDPPort() == 0) continue;
            AddSupernode(CAddress(c->GetNetIP(), false), c->GetUDPPort(), c->GetClientID());
        }
    }

    DWORD now = GetTickCount();
    m_stats.lastTickMs = now;

    // Rate-limit: only emit at most one batch per PING_INTERVAL_MS to avoid
    // pinging every supernode every Process() tick (which is 1 s).
    if (now - m_dwLastTick < KEEPALIVE_PING_INTERVAL_MS) return;
    m_dwLastTick = now;

    // For each supernode: drop it if it has gone (or always been) silent past the
    // timeout for 3 batches, otherwise emit a PING_REQ via the Kad UDP listener. The
    // far side answers 0x67 -> OnPong() refreshes lastPongTick. lastPongTick is seeded
    // at add time (AddSupernode) so never-responders also age out.
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
        if (Kademlia::CKademlia::GetUDPListener() != NULL) {
            it->lastPingTick = now;
            Kademlia::CKademlia::GetUDPListener()->SendKad3PingReq(it->addr.ToUInt32(true), it->port);
            m_stats.pingsSent++;   // only count pings we actually emitted
        }
        ++it;
    }
    m_stats.supernodesActive = (uint32)m_supernodes.size();
}

// R.2: a supernode answered our KADEMLIA3_PING_REQ with a PONG (0x67). Mark it
// healthy so the miss-detector in Tick() keeps it in the active set. The exact
// endpoint, Kad identity and a recent outstanding ping must all match. Called from
// CKademliaUDPListener::Process_KADEMLIA3_PING_RES on the Kad Process thread —
// same thread as Tick(), so m_supernodes needs no lock.
bool CKadKeepalive::OnPong(uint32 uIP, uint16 port, const Kademlia::CUInt128& kadID)
{
    if (uIP == 0 || port == 0 || kadID == 0) return false;
    const DWORD now = GetTickCount();
    for (auto& s : m_supernodes) {
        if (s.addr.ToUInt32(true) == uIP && s.port == port && s.kadID == kadID
            && s.lastPingTick != 0
            && now - s.lastPingTick <= KEEPALIVE_PONG_TIMEOUT_MS) {
            s.lastPongTick = now;
            s.lastPingTick = 0;
            s.consecutiveMisses = 0;
            m_stats.pongsReceived++;
            return true;
        }
    }
    return false;
}
