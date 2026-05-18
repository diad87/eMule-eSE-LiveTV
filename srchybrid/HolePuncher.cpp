//this file is part of eMule
// v0.71 IPv6 Sprint 5 — Coordinated UDP hole-punching. See header.
#include "stdafx.h"
#include "HolePuncher.h"
#include "LiveDebugLog.h"
#include <map>

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

static const DWORD PUNCH_TIMEOUT_MS = 8u * 1000u;     // total session budget
static const DWORD PUNCH_RETRY_MS   = 1u * 1000u;     // retry every 1 s
static const size_t MAX_SESSIONS    = 32;             // cap to avoid OOM

struct PunchSession {
    CHolePuncher::EPunchState state;
    CAddress targetAddr;
    uint16   targetPort;
    CAddress rendezvousAddr;
    uint16   rendezvousPort;
    DWORD    startTick;
    DWORD    lastSendTick;
    int      retries;
};

static std::map<uint32, PunchSession> g_sessions;
static uint32 g_nextSessionId = 1;

CHolePuncher& CHolePuncher::Instance()
{
    static CHolePuncher inst;
    return inst;
}

uint32 CHolePuncher::StartPunch(const CAddress& target, uint16 targetPort,
                                 const CAddress& rendezvous, uint16 rendezvousPort)
{
    if (g_sessions.size() >= MAX_SESSIONS) {
        // Capacity cap. Reject rather than evict — under flood, the
        // legitimate session might be evicted while the attacker keeps
        // refilling. Better to deny new attempts until existing time out.
        LIVE_LOG("KAD3", "HolePunch: session table full, refusing new");
        return 0;
    }
    uint32 sid = g_nextSessionId++;
    if (g_nextSessionId == 0) g_nextSessionId = 1;  // wrap

    PunchSession s;
    s.state            = StateReqSent;
    s.targetAddr       = target;
    s.targetPort       = targetPort;
    s.rendezvousAddr   = rendezvous;
    s.rendezvousPort   = rendezvousPort;
    s.startTick        = GetTickCount();
    s.lastSendTick     = s.startTick;
    s.retries          = 0;
    g_sessions[sid]    = s;

    // TODO Sprint 4: theApp.kadudpListener->SendKad3HolepunchReq(rendezvous, rendezvousPort, sid, target, targetPort);
    LIVE_LOG("KAD3", "HolePunch: sid=%u REQ → rendezvous", sid);
    return sid;
}

void CHolePuncher::OnRequest(uint32 sessionId, const CAddress& from, uint16 fromPort)
{
    // R receives REQ from A. Forward to B (the target).
    auto it = g_sessions.find(sessionId);
    if (it == g_sessions.end()) {
        // We're acting as R, but this session didn't come through us before.
        // Allocate a new "as rendezvous" session.
        if (g_sessions.size() >= MAX_SESSIONS) return;
        PunchSession s;
        s.state            = StateFwdSent;
        s.targetAddr       = from;
        s.targetPort       = fromPort;
        s.startTick        = GetTickCount();
        s.lastSendTick     = s.startTick;
        s.retries          = 0;
        g_sessions[sessionId] = s;
    }
    // TODO Sprint 4: theApp.kadudpListener->SendKad3HolepunchFwd(...);
    LIVE_LOG("KAD3", "HolePunch: sid=%u (as R) FWD → target", sessionId);
}

void CHolePuncher::OnForward(uint32 sessionId, const CAddress& origin, uint16 originPort)
{
    // B receives FWD from R. Now B punches outward to A simultaneously,
    // and waits for A's punch to land — same packet pair opens both
    // firewalls.
    auto it = g_sessions.find(sessionId);
    if (it == g_sessions.end()) {
        if (g_sessions.size() >= MAX_SESSIONS) return;
        PunchSession s;
        s.state            = StateReqSent;  // we'll send to origin
        s.targetAddr       = origin;
        s.targetPort       = originPort;
        s.startTick        = GetTickCount();
        s.lastSendTick     = s.startTick;
        s.retries          = 0;
        g_sessions[sessionId] = s;
    }
    // TODO Sprint 4: simultaneous send to origin.
    LIVE_LOG("KAD3", "HolePunch: sid=%u (as B) punch ← origin", sessionId);
}

void CHolePuncher::OnAck(uint32 sessionId)
{
    auto it = g_sessions.find(sessionId);
    if (it == g_sessions.end()) return;
    it->second.state = StateConnected;
    LIVE_LOG("KAD3", "HolePunch: sid=%u CONNECTED (took %u ms)",
        sessionId, GetTickCount() - it->second.startTick);
}

CHolePuncher::EPunchState CHolePuncher::GetState(uint32 sessionId) const
{
    auto it = g_sessions.find(sessionId);
    return (it == g_sessions.end()) ? StateIdle : it->second.state;
}

void CHolePuncher::Tick()
{
    DWORD now = GetTickCount();
    auto it = g_sessions.begin();
    while (it != g_sessions.end()) {
        PunchSession& s = it->second;
        if (s.state == StateConnected || s.state == StateTimeout) {
            // Settled — evict after a short cooldown so late-arriving ACKs
            // don't re-trigger anything.
            if (now - s.startTick > PUNCH_TIMEOUT_MS * 2) {
                it = g_sessions.erase(it);
                continue;
            }
        } else if (now - s.startTick > PUNCH_TIMEOUT_MS) {
            s.state = StateTimeout;
            LIVE_LOG("KAD3", "HolePunch: sid=%u TIMEOUT", it->first);
        } else if (now - s.lastSendTick > PUNCH_RETRY_MS) {
            // Retry the most recent send action.
            s.lastSendTick = now;
            s.retries++;
        }
        ++it;
    }
}
