//this file is part of eMule
// v0.71 IPv6 Sprint 5 — Kad keepalive (anti-firewall layer C). See header.
#include "stdafx.h"
#include "KadKeepalive.h"
#include "emule.h"
#include "ClientList.h"
#include "UpdownClient.h"
#include "Opcodes.h"
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

// Send a KADEMLIA3_PING_REQ to each capability-confirmed fork peer every
// PING_INTERVAL_MS so that
// stateful firewall conntrack on the outbound flow stays open. If we miss
// PONG_TIMEOUT_MS pongs in a row from a target, we rotate it out of the
// active set. Tick() discovers targets from connected eD2K peers that have
// explicitly advertised ESE_CAP_KAD_KEEPALIVE; vanilla Kad contacts are not
// eligible.
static const DWORD KEEPALIVE_PING_INTERVAL_MS = 25u * 1000u;   // 25 s
static const DWORD KEEPALIVE_PONG_TIMEOUT_MS  = 90u * 1000u;   // 3 missed pings
static const size_t KEEPALIVE_MAX_SUPERNODES   = 10;

static void BroadcastKeepaliveCapability()
{
    if (theApp.clientlist == NULL) return;
    std::vector<CUpDownClient*> peers;
    theApp.clientlist->GetConnectedSnapshot(peers, 256, false);
    for (CUpDownClient* peer : peers)
        if (peer != NULL)
            peer->SendMuleInfoPacket(false);
}

CKadKeepalive& CKadKeepalive::Instance()
{
    static CKadKeepalive inst;
    return inst;
}

bool CKadKeepalive::IsRunning() const
{
    return ::InterlockedCompareExchange(
        const_cast<volatile LONG*>(&m_running), 0, 0) != 0;
}

CKadKeepalive::Stats CKadKeepalive::GetStats() const
{
    Stats snapshot = {};
    snapshot.pingsSent = static_cast<uint32>(::InterlockedCompareExchange(
        const_cast<volatile LONG*>(&m_statPingsSent), 0, 0));
    snapshot.pongsReceived = static_cast<uint32>(::InterlockedCompareExchange(
        const_cast<volatile LONG*>(&m_statPongsReceived), 0, 0));
    snapshot.supernodesActive = static_cast<uint32>(::InterlockedCompareExchange(
        const_cast<volatile LONG*>(&m_statSupernodesActive), 0, 0));
    snapshot.lastTickMs = static_cast<DWORD>(::InterlockedCompareExchange(
        const_cast<volatile LONG*>(&m_statLastTickMs), 0, 0));
    return snapshot;
}

void CKadKeepalive::Start()
{
    if (!thePrefs.IsEseNetLabActive()) {
        if (IsRunning())
            Stop();
        LIVE_LOG("KAD3", "Keepalive start rejected (NetLab consent inactive)");
        return;
    }
    const bool started = ::InterlockedExchange(&m_running, 1) == 0;
    volatile LONG* caps = reinterpret_cast<volatile LONG*>(&g_uEseCapsRuntime);
    const LONG previousCaps = ::InterlockedOr(
        caps, static_cast<LONG>(ESE_CAP_KAD_KEEPALIVE));
    if (started || (previousCaps & static_cast<LONG>(ESE_CAP_KAD_KEEPALIVE)) == 0)
        BroadcastKeepaliveCapability();
    if (!started) return;
    m_dwLastTick = GetTickCount();
    LIVE_LOG("KAD3", "Keepalive started (interval=%us, pool size=%zu)",
        KEEPALIVE_PING_INTERVAL_MS / 1000, m_supernodes.size());
}

void CKadKeepalive::Stop()
{
    const bool stopped = ::InterlockedExchange(&m_running, 0) != 0;
    volatile LONG* caps = reinterpret_cast<volatile LONG*>(&g_uEseCapsRuntime);
    const LONG previousCaps = ::InterlockedAnd(
        caps, ~static_cast<LONG>(ESE_CAP_KAD_KEEPALIVE));
    if (stopped || (previousCaps & static_cast<LONG>(ESE_CAP_KAD_KEEPALIVE)) != 0)
        BroadcastKeepaliveCapability();
    if (!stopped) return;
    LIVE_LOG("KAD3", "Keepalive stopped");
}

void CKadKeepalive::RequestStart() { InterlockedExchange(&m_ctrlRequest, 1); }
void CKadKeepalive::RequestStop()  { InterlockedExchange(&m_ctrlRequest, 2); }

void CKadKeepalive::AddSupernode(const CAddress& addr, uint16 port)
{
	if (port == 0 || addr.GetType() != CAddress::IPv4 || addr.IsNull())
		return;
    if (m_supernodes.size() >= KEEPALIVE_MAX_SUPERNODES) {
        // Pool full: keep the bounded active set. Ranking/replacement by
        // measured health can be added without admitting vanilla Kad nodes.
        return;
    }
    // Dedup: same (addr, port) pair never added twice.
    for (auto& s : m_supernodes) {
        if (s.addr == addr && s.port == port) return;
    }
    Supernode s;
    s.addr = addr;
    s.port = port;
    s.pendingNonce = Kademlia::CUInt128();
    s.lastPingTick = 0;
    // Seed the pong clock to "now" so a node that NEVER answers (e.g. a vanilla 0.70b
    // peer that drops our 0x66) still enters the miss-detector after PONG_TIMEOUT and is
    // rotated out, instead of being pinged forever. A real PONG resets it in OnPong().
    s.lastPongTick = GetTickCount();
    s.consecutiveMisses = 0;
    m_supernodes.push_back(s);
    ::InterlockedExchange(&m_statSupernodesActive,
        static_cast<LONG>(m_supernodes.size()));
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
    ::InterlockedExchange(&m_statSupernodesActive,
        static_cast<LONG>(m_supernodes.size()));
}

void CKadKeepalive::Tick()
{
    // Honor a cross-thread start/stop request here on the Kad thread, so Start()/Stop()
    // (which touch m_supernodes) never race the /api worker that flipped the flag.
    const LONG ctrl = InterlockedExchange(&m_ctrlRequest, 0);
    if (ctrl == 1) Start();
    else if (ctrl == 2) Stop();

    if (!thePrefs.IsEseNetLabActive()) {
        if (IsRunning())
            Stop();
        return;
    }
    if (!IsRunning()) return;

    // Only peers that explicitly advertised the R.2 capability understand the
    // Kad3 opcode.  The old routing-table population selected almost entirely
    // vanilla nodes, so pings rose forever while pongs could never move.
    if (m_supernodes.size() < 5 && theApp.clientlist != NULL) {
        std::vector<CUpDownClient*> peers;
        theApp.clientlist->GetConnectedSnapshot(peers, 32, false);
        for (CUpDownClient* peer : peers) {
            if (!peer || !peer->SupportsEseNetLabV1()
                || !peer->SupportsEseKadKeepalive()
                // KADEMLIA3_PING_REQ still carries a uint32 IPv4 endpoint.
                // A native-v6 client has only a synthetic compatibility value;
                // never turn that value into a real Kad target.
                || peer->IsIPv6OnlyEndpoint()
                || peer->GetConnectIP() == 0 || peer->GetKadPort() == 0)
                continue;
            AddSupernode(CAddress(peer->GetConnectIP(), false), peer->GetKadPort());
            if (m_supernodes.size() >= KEEPALIVE_MAX_SUPERNODES) break;
        }
    }

    DWORD now = GetTickCount();
    ::InterlockedExchange(&m_statLastTickMs, static_cast<LONG>(now));

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
            it->pendingNonce = Kademlia::CUInt128(true);
            Kademlia::CKademlia::GetUDPListener()->SendKad3PingReq(
                it->addr.ToUInt32(true), it->port, it->pendingNonce);
            ::InterlockedIncrement(&m_statPingsSent); // count only emitted pings
        }
        ++it;
    }
    ::InterlockedExchange(&m_statSupernodesActive,
        static_cast<LONG>(m_supernodes.size()));
}

// R.2: a capability-confirmed target answered our KADEMLIA3_PING_REQ with a
// PONG (0x67). Mark it
// healthy so the miss-detector in Tick() keeps it in the active set. The exact
// source IP, unpredictable outstanding nonce and freshness window must match;
// the source port may legitimately be NAT-translated and is learned. Called from
// CKademliaUDPListener::Process_KADEMLIA3_PING_RES on the Kad Process thread —
// same thread as Tick(), so m_supernodes needs no lock.
bool CKadKeepalive::OnPong(uint32 uIP, uint16 port, const Kademlia::CUInt128& nonce)
{
    if (!IsRunning() || uIP == 0 || port == 0 || nonce == 0) return false;
    const DWORD now = GetTickCount();
    for (auto& s : m_supernodes) {
        if (s.addr.ToUInt32(true) == uIP && s.pendingNonce == nonce
            && s.lastPingTick != 0
            && now - s.lastPingTick <= KEEPALIVE_PONG_TIMEOUT_MS) {
            // A symmetric NAT may answer from a translated source port. The
            // unpredictable nonce authenticates the outstanding probe, so learn
            // that observed endpoint for the next keepalive batch.
            s.port = port;
            s.lastPongTick = now;
            s.lastPingTick = 0;
            s.pendingNonce = Kademlia::CUInt128();
            s.consecutiveMisses = 0;
            ::InterlockedIncrement(&m_statPongsReceived);
            return true;
        }
    }
    return false;
}
