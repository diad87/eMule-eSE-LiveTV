//this file is part of eMule
// v0.71 IPv6 Sprint 8 — LiveTV buddy relay impl. See header for design.
// R.3 (2026-06-14): full relay floor for symmetric NAT / CGNAT.
//   RELAY role  (gated s_relayAcceptEnabled): 0xCF SETUP/CHUNK ingest + SETUP_OK/DENY
//               reply + 0xCE downstream re-emit (bounded, anti-amplification).
//   BROADCASTER role (gated CLiveStreamManager::s_relayEgressEnabled): pick a connected
//               HighID buddy, send SETUP; the per-segment chunk push lives in
//               CLiveStreamManager (the signing keys are private there).
//   VIEWER role: ConnectViaBuddy sends OP_LIVE_RELAY_REQ (0xCE) to the buddy.
// All dormant by default (both gates false + cap ESE_CAP_LIVE_RELAY not advertised) =
// zero wire/behavior change. Single-thread: every entry runs on the main thread
// (eD2K packet thread / Kad Process / ~CUpDownClient) — no lock needed; the only shared
// data-plane sink (ExitProxyOnWholeChunk) has its own internal lock.
#include "stdafx.h"
#include "LiveBuddyRelay.h"
#include "LiveDebugLog.h"
#include "emule.h"             // theApp (clientlist, liveStreamManager)
#include "clientlist.h"        // CClientList: GetConnectedSnapshot / FindClientByIP / AddClient
#include "UpDownClient.h"      // CUpDownClient
#include "LiveStreamManager.h" // theApp.liveStreamManager (IsBroadcasting/GetStreamKey/IsStreamSourcePeer)
#include "LiveTunnel.h"        // eSELive::CLiveTunnel::ExitProxyOnWholeChunk
#include "LivePackets.h"       // CreateRelayFwdPacket / CreateDenyPacket / AppendChunkSendPackets / ESE_FRAG_MAX_TOTAL
#include "Packets.h"           // Packet
#include "opcodes.h"           // OP_LIVE_RELAY_REQ / OP_LIVE_CHUNK_V2 / OP_EMULEPROT / ESE_CAP_LIVE_CHUNK_FRAG
#include "Preferences.h"       // thePrefs.GetUserHash
#include "SafeFile.h"          // CSafeMemFile
#include "Statistics.h"        // CStatistics relay counters
#include <map>
#include <set>
#include <vector>
#include <array>

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

static const size_t RELAY_MAX_STREAMS     = 3;       // concurrent relayed streams cap (anti-abuse)
static const DWORD  RELAY_SESSION_TTL_MS  = 120000;  // drop a session idle 120 s
static const size_t RELAY_MAX_DOWNSTREAM  = 8;       // 0xCE viewers per relayed stream (anti-amplification)

// Per-instance state. Single-role-at-a-time as in Sprint 8.
static CLiveBuddyRelay::ERelayState g_relayState = CLiveBuddyRelay::StateIdle;

// Rel (buddy) side: the streams we have agreed to relay. Keyed by streamKey.
struct SRelaySession {
    uint32 uBroadcasterIP;   // ONLY this IP may push chunks for the key (anti-injection)
    DWORD  dwLastActivity;
};
typedef std::array<uint8, 16> RelayKey;
static std::map<RelayKey, SRelaySession> g_relaySessions;
// Rel side: 0xCE viewers subscribed to each relayed stream (re-emit target).
static std::map<RelayKey, std::set<CUpDownClient*> > g_relayDownstream;
// Broadcaster side: the buddy we sent SETUP to / the one that accepted (SETUP_OK).
static CUpDownClient* g_candidateBuddy = NULL;
static CUpDownClient* g_activeBuddy    = NULL;

// Viewer-connect marshal (test/activation): a webserver worker stages a request via
// RequestViewerConnect; Tick() (main thread) drains it. InterlockedExchange is the barrier.
static volatile LONG g_pendingViewerConnect = 0;
static uchar  g_pvcStreamKey[16] = {0};
static uint32 g_pvcIpNet = 0;   // network order
static uint16 g_pvcPort  = 0;

// [eSE v9] hard relay byte-budget (abuse cap): rolling 1s window of the egress bytes we donate
// as a relay. Touched only on the main thread (like g_relaySessions), so no lock.
static DWORD  g_relayWindowStart = 0;
static uint32 g_relayWindowBytes = 0;

// R.3 relay-role gate: now driven by the runtime pref EseRelayAccept (default OFF), so the
// 0xCF/0xCE accept + downstream handling stay byte-for-byte dormant until an operator opts in.

static RelayKey MakeRelayKey(const uchar sk[16]) { RelayKey k; memcpy(k.data(), sk, 16); return k; }

CLiveBuddyRelay& CLiveBuddyRelay::Instance()
{
    static CLiveBuddyRelay inst;
    return inst;
}

// ── BROADCASTER role ──────────────────────────────────────────────────────────
void CLiveBuddyRelay::StartAsBroadcaster()
{
    if (theApp.liveStreamManager == NULL || !theApp.liveStreamManager->IsBroadcasting())
        return;
    // Discovery (decision: reuse already-connected HighID fork peers, like the tunnel
    // hop-picker — zero new Kad surface). Prefer privacy-tunneling-capable peers.
    std::vector<CUpDownClient*> cands;
    if (theApp.clientlist != NULL)
        theApp.clientlist->GetConnectedSnapshot(cands, 5, true);
    if (cands.empty() && theApp.clientlist != NULL)
        theApp.clientlist->GetConnectedSnapshot(cands, 5, false);
    CUpDownClient* buddy = NULL;
    for (size_t i = 0; i < cands.size(); ++i) {
        CUpDownClient* c = cands[i];
		if (c == NULL)                                           continue;
		// GetConnectedSnapshot already proves a live transport. The numeric
		// LowID/HighID label must not veto an established v6/punched relay.
        if (!c->SupportsLiveRelay())                          continue;  // [eSE v9] only ask peers that advertise relay duty (cap bit 21)
        if (theApp.liveStreamManager->IsStreamSourcePeer(c))  continue;  // not one of our sources
        buddy = c; break;
    }
    if (buddy == NULL) { g_relayState = StateLookingForBuddy; return; }
    g_candidateBuddy = buddy;
    g_relayState = StateNegotiating;
    const uchar* sk = theApp.liveStreamManager->GetStreamKey();
    Packet* setup = eSELive::CreateRelayFwdPacket(RELAY_SUB_SETUP, sk, NULL, 0);
    if (setup != NULL)
        buddy->SafeConnectAndSendPacket(setup);
    LIVE_LOG("RELAY", "broadcaster: SETUP sent to buddy, Negotiating");
}

void CLiveBuddyRelay::OnRelayReply(CUpDownClient* fromBuddy, uint8 subop, const uchar streamKey[16])
{
    (void)streamKey;
    if (fromBuddy == NULL || fromBuddy != g_candidateBuddy)   // ignore replies we didn't ask for
        return;
    if (subop == RELAY_SUB_SETUP_OK) {
        g_activeBuddy = fromBuddy;
        g_relayState = StateActive;
        LIVE_LOG("RELAY", "broadcaster: buddy ACCEPTED, egress active");
    } else {
        g_activeBuddy = NULL; g_candidateBuddy = NULL; g_relayState = StateBuddyLost;
        LIVE_LOG("RELAY", "broadcaster: buddy DENIED relay");
    }
}

CUpDownClient* CLiveBuddyRelay::GetActiveBuddy() const { return g_activeBuddy; }
void CLiveBuddyRelay::SetCandidateBuddy(CUpDownClient* b) { g_candidateBuddy = b; }

void CLiveBuddyRelay::ResetBroadcasterEgress()
{
    g_candidateBuddy = NULL;
    g_activeBuddy = NULL;
    if (g_relayState != StateIdle) g_relayState = StateIdle;
}

// ── VIEWER role ───────────────────────────────────────────────────────────────
bool CLiveBuddyRelay::ConnectViaBuddy(const uchar streamKey[16], const CAddress& buddy, uint16 buddyPort)
{
    // The relay request body is the legacy IPv4 eD2K format. Never collapse
    // a native IPv6 buddy into the synthetic uint32 compatibility value.
    if (theApp.clientlist == NULL || buddy.GetType() != CAddress::IPv4)
        return false;
    const uint32 ipNet = buddy.ToUInt32(false);   // network-order, matching the dial recipe
    if (ipNet == 0 || ipNet == 0xFFFFFFFF || buddyPort == 0)
        return false;
    CUpDownClient* c = theApp.clientlist->FindClientByIP(ipNet, buddyPort);
    if (c == NULL) {
        c = new CUpDownClient(NULL, buddyPort, ntohl(ipNet), 0, 0, false);
        c->SetIP(ipNet);
        theApp.clientlist->AddClient(c);
    }
    // OP_LIVE_RELAY_REQ payload mirrors SUBSCRIBE: <streamKey 16><viewerHash 16>.
    CSafeMemFile data(32);
    data.WriteHash16(streamKey);
    data.WriteHash16(thePrefs.GetUserHash());
    Packet* req = new Packet(data, OP_EMULEPROT);
    req->opcode = OP_LIVE_RELAY_REQ;
    c->SafeConnectAndSendPacket(req);
    g_relayState = StateNegotiating;
    LIVE_LOG("RELAY", "viewer: 0xCE RELAY_REQ sent to buddy");
    return true;
}

void CLiveBuddyRelay::RequestViewerConnect(const uchar streamKey[16], uint32 ipNet, uint16 port)
{
    memcpy(g_pvcStreamKey, streamKey, 16);
    g_pvcIpNet = ipNet;
    g_pvcPort = port;
    InterlockedExchange(&g_pendingViewerConnect, 1);   // drained in Tick() on the main thread
}

// ── RELAY (buddy) role ────────────────────────────────────────────────────────
bool CLiveBuddyRelay::AcceptRelayFromBroadcaster(CUpDownClient* broadcaster)
{
    // Relay quotas and session keys below are IPv4-only legacy fields. Native
    // IPv6 peers use the V2/tunnel paths and must not enter this table.
    if (broadcaster == NULL || broadcaster->IsIPv6OnlyEndpoint())
        return false;
    if (g_relaySessions.size() >= RELAY_MAX_STREAMS) {
        LIVE_LOG("RELAY", "BuddyRelay: at capacity (%u streams), rejecting", (unsigned)g_relaySessions.size());
        return false;
    }
    // finding #1 (open-relay drain): at most 1 relayed stream per source IP.
    const uint32 ip = broadcaster->GetIP();
    int perIp = 0;
    for (std::map<RelayKey, SRelaySession>::iterator it = g_relaySessions.begin(); it != g_relaySessions.end(); ++it)
        if (it->second.uBroadcasterIP == ip) perIp++;
    if (perIp >= 1) {
        LIVE_LOG("RELAY", "BuddyRelay: per-IP quota reached, rejecting");
        return false;
    }
    return true;
}

// Inbound OP_LIVE_RELAY_FWD (0xCF). Role is disambiguated purely by subop:
// SETUP/CHUNK = relay role (we are the buddy); SETUP_OK/DENY = broadcaster role.
void CLiveBuddyRelay::OnRelayFwd(CUpDownClient* from, uint8 subop, const uchar streamKey[16], const uint8* payload, uint32 len)
{
	if (from != NULL && from->IsIPv6OnlyEndpoint())
		return;
    // Broadcaster role: a relay replied to our SETUP. NOT behind s_relayAcceptEnabled
    // (a broadcaster must process replies) — but harmless when dormant: g_candidateBuddy
    // is NULL so OnRelayReply early-returns.
    if (subop == RELAY_SUB_SETUP_OK || subop == RELAY_SUB_SETUP_DENY) {
        OnRelayReply(from, subop, streamKey);
        return;
    }

    if (!thePrefs.GetEseRelayAccept() || from == NULL)   // relay-role gate (pref EseRelayAccept)
        return;
    const RelayKey key = MakeRelayKey(streamKey);

    if (subop == RELAY_SUB_SETUP) {
        InterlockedIncrement(&CStatistics::m_dwRelayReqRecv);
        if (!AcceptRelayFromBroadcaster(from)) {
            Packet* d = eSELive::CreateRelayFwdPacket(RELAY_SUB_SETUP_DENY, streamKey, NULL, 0);
            if (d != NULL) from->SendPacket(d, true);
            return;
        }
        SRelaySession s;
        s.uBroadcasterIP = from->GetIP();
        s.dwLastActivity = GetTickCount();
        g_relaySessions[key] = s;
        g_relayState = StateActive;
        InterlockedIncrement(&CStatistics::m_dwRelayAccepted);
        CStatistics::m_dwRelayActive = (DWORD)g_relaySessions.size();
        Packet* ok = eSELive::CreateRelayFwdPacket(RELAY_SUB_SETUP_OK, streamKey, NULL, 0);
        if (ok != NULL) from->SendPacket(ok, true);
        LIVE_LOG("RELAY", "BuddyRelay: ACCEPTED relay (active streams=%u)", (unsigned)g_relaySessions.size());
        return;
    }

    if (subop == RELAY_SUB_CHUNK) {
        std::map<RelayKey, SRelaySession>::iterator it = g_relaySessions.find(key);
        if (it == g_relaySessions.end())
            return;                                        // not relaying this stream
        if (it->second.uBroadcasterIP != from->GetIP())
            return;                                        // anti-injection: only the broadcaster
        it->second.dwLastActivity = GetTickCount();
        // [eSE v9] hard byte-budget: bound the egress bandwidth we donate so an abusive broadcaster
        // (or the downstream fan-out) can't turn us into a free CDN. Effective egress this chunk =
        // len*(1+downstream) (onion exit + each 0xCE viewer). Rolling 1s window; over budget we shed
        // load by dropping the chunk (fanout itself is separately capped by RELAY_MAX_DOWNSTREAM).
        {
            size_t dnCount = 0;
            std::map<RelayKey, std::set<CUpDownClient*> >::iterator dbit = g_relayDownstream.find(key);
            if (dbit != g_relayDownstream.end()) dnCount = dbit->second.size();
            const uint32 uEffBytes = len * (uint32)(1 + dnCount);
            const uint32 uMaxBytesPerSec = (uint32)thePrefs.GetEseRelayMaxKBps() * 1024u;
            const DWORD nowTick = GetTickCount();
            if (nowTick - g_relayWindowStart >= 1000) { g_relayWindowStart = nowTick; g_relayWindowBytes = 0; }
            if (g_relayWindowBytes + uEffBytes > uMaxBytesPerSec) {
                InterlockedIncrement(&CStatistics::m_dwRelayBudgetDrops);
                LIVE_LOG("RELAY", "budget exceeded (%u KB/s cap) — dropping chunk (eff=%u B)",
                    (unsigned)thePrefs.GetEseRelayMaxKBps(), (unsigned)uEffBytes);
                return;
            }
            g_relayWindowBytes += uEffBytes;
        }
        // (a) onion exit plane — unchanged (validates length, bounds the queue).
        eSELive::CLiveTunnel::Get().ExitProxyOnWholeChunk(streamKey, payload, len);
        // (b) re-emit to plain-eD2K 0xCE downstream subscribers as a normal V2 chunk.
        std::map<RelayKey, std::set<CUpDownClient*> >::iterator dit = g_relayDownstream.find(key);
        if (dit != g_relayDownstream.end() && len >= 20 && len <= eSELive::ESE_FRAG_MAX_TOTAL) {
            for (std::set<CUpDownClient*>::iterator vi = dit->second.begin(); vi != dit->second.end(); ++vi) {
                CUpDownClient* v = *vi;
                if (v == NULL) continue;
                // The payload IS an OP_LIVE_CHUNK_V2 body already (the broadcaster signed it);
                // wrap it verbatim and re-fragment for transport if the viewer supports frag.
                CSafeMemFile fm(len);
                fm.Write(payload, len);
                Packet* pk = new Packet(fm, OP_EMULEPROT);
                pk->opcode = OP_LIVE_CHUNK_V2;
                CArray<Packet*> batch;
                const bool frag = (v->GetEseCapabilities() & ESE_CAP_LIVE_CHUNK_FRAG) != 0;
                eSELive::AppendChunkSendPackets(pk, frag, batch);   // takes ownership of pk
                for (INT_PTR b = 0; b < batch.GetCount(); ++b)
                    v->SendPacket(batch[b], true);
            }
        }
        CStatistics::m_dwRelayBytesFwdKB += (len / 1024);
        return;
    }
}

// Inbound OP_LIVE_RELAY_REQ (0xCE): a viewer wants chunks for a stream we relay.
void CLiveBuddyRelay::OnRelayReq(CUpDownClient* viewer, const uchar streamKey[16])
{
    if (!thePrefs.GetEseRelayAccept() || viewer == NULL)
        return;
    const RelayKey key = MakeRelayKey(streamKey);
    if (g_relaySessions.find(key) == g_relaySessions.end()) {     // we don't relay this stream
        Packet* d = eSELive::CreateDenyPacket(streamKey, 0);
        if (d != NULL) viewer->SendPacket(d, true);
        return;
    }
    std::set<CUpDownClient*>& dn = g_relayDownstream[key];
    if (dn.size() >= RELAY_MAX_DOWNSTREAM) {                      // anti-amplification bound
        Packet* d = eSELive::CreateDenyPacket(streamKey, 0);
        if (d != NULL) viewer->SendPacket(d, true);
        return;
    }
    dn.insert(viewer);
    LIVE_LOG("RELAY", "relay: 0xCE downstream subscriber added (n=%u)", (unsigned)dn.size());
}

// Free every relay reference to a client on teardown (covers broadcaster session,
// downstream viewer, and our own buddy). Called from ~CUpDownClient.
void CLiveBuddyRelay::OnPeerDisconnected(CUpDownClient* peer)
{
    if (peer == NULL)
        return;
    const uint32 ip = peer->GetIP();
    for (std::map<RelayKey, SRelaySession>::iterator it = g_relaySessions.begin(); it != g_relaySessions.end(); ) {
        if (it->second.uBroadcasterIP == ip) it = g_relaySessions.erase(it);
        else ++it;
    }
    for (std::map<RelayKey, std::set<CUpDownClient*> >::iterator it = g_relayDownstream.begin(); it != g_relayDownstream.end(); ) {
        it->second.erase(peer);
        if (it->second.empty()) it = g_relayDownstream.erase(it);
        else ++it;
    }
    if (peer == g_activeBuddy || peer == g_candidateBuddy) {
        g_activeBuddy = NULL; g_candidateBuddy = NULL;
        if (g_relayState == StateActive) g_relayState = StateBuddyLost;
    }
    CStatistics::m_dwRelayActive = (DWORD)g_relaySessions.size();
}

void CLiveBuddyRelay::Tick()
{
    // Drain a staged viewer-connect request on the main thread (see RequestViewerConnect).
    // Done before the empty-sessions early-return because a viewer holds no relay sessions.
    if (InterlockedExchange(&g_pendingViewerConnect, 0) == 1)
        ConnectViaBuddy(g_pvcStreamKey, CAddress(g_pvcIpNet, false), g_pvcPort);

    // Expire idle relay sessions (broadcaster stopped pushing / disconnected).
    if (g_relaySessions.empty())
        return;
    const DWORD now = GetTickCount();
    for (std::map<RelayKey, SRelaySession>::iterator it = g_relaySessions.begin(); it != g_relaySessions.end(); ) {
        if (now - it->second.dwLastActivity > RELAY_SESSION_TTL_MS) {
            g_relayDownstream.erase(it->first);   // drop orphaned downstream for the dead stream
            it = g_relaySessions.erase(it);
        } else {
            ++it;
        }
    }
    CStatistics::m_dwRelayActive = (DWORD)g_relaySessions.size();
    if (g_relaySessions.empty() && g_relayState == StateActive)
        g_relayState = StateIdle;
}

CLiveBuddyRelay::ERelayState CLiveBuddyRelay::GetState() const
{
    return g_relayState;
}
