// this file is part of eMule eSE - LT9 textual coordinator methods
uint32_t CLiveTunnel::BuildTestCircuit(CUpDownClient* clientHint)
{
    // Solo testing helper. A circuit is meaningful only through a peer that
    // advertised ESE_CAP_PRIVACY_TUNNELING in its HELLO. Do not
    // fall back to a legacy peer: that used to return ok=true and emit a
    // CREATE cell that could never complete.
    std::vector<CUpDownClient*> cands;
    if (clientHint) {
        if (clientHint->socket && clientHint->socket->IsConnected()
            && clientHint->SupportsEsePrivacyTunneling())
            cands.push_back(clientHint);
    } else if (theApp.clientlist) {
        theApp.clientlist->GetConnectedSnapshot(cands, 3, /*tunnelOnly=*/true);
    }
    if (cands.empty()) return 0;
    size_t before = 0;
    {
        CSingleLock lk(&m_lock, TRUE);
        before = m_circuitRegistry.Size();
    }
    size_t built = BuildPool(NULL, cands, 1);
    if (built == 0) return 0;
    // Return the id of the circuit we just added.
    CSingleLock lk(&m_lock, TRUE);
    if (m_circuitRegistry.Size() > before)
        return m_circuitRegistry.Back()->Id();
    return 0;
}
// Production successor build for the PST pool's make-before-break. A requested
// privacy profile never degrades to one hop: Strict tries exactly three relays,
// then Private tries exactly two authenticated distinct relays. Direct mode and
// one-hop diagnostics use separate explicit paths.
bool CLiveTunnel::BuildSuccessorCircuit()
{
    // K6-6: prefer a fully diverse, authenticated guard->middle->exit circuit.
    if (BuildSuccessor3Hop()) return true;
    return BuildSuccessor2Hop();
}
bool CLiveTunnel::BuildQuotaGuardCircuit()
{
    std::set<std::string> privatePathNodes;
    {
        CSingleLock lock(&m_lock, TRUE);
        for (const auto& circuit : m_circuitRegistry.GetSnapshot()) {
            if (circuit && circuit->m_k6QuotaIssuerCircuit &&
                circuit->State() != CircuitState::Destroyed)
                return false;
            if (!circuit || circuit->m_k6QuotaIssuerCircuit ||
                circuit->m_role != CircuitRole::Originator ||
                circuit->State() == CircuitState::Destroyed)
                continue;
            for (size_t hop = 0; hop < circuit->HopCount(); ++hop)
                privatePathNodes.insert(K6BinaryKey(
                    circuit->Hop(hop).pub_long, 32));
        }
    }
    std::vector<CUpDownClient*> peers;
    if (theApp.clientlist)
        theApp.clientlist->GetConnectedSnapshot(peers, 32, /*tunnelOnly=*/true);
    if (peers.empty()) return false;
    const bool havePinnedGuard = LoadK6Guard();
    std::array<uint8_t, 32> pinnedGuard{};
    if (havePinnedGuard && !m_scheduler.LT9CopyGuard(pinnedGuard))
        return false;
    CUpDownClient* selected = NULL;
    for (CUpDownClient* peer : peers) {
        if (!peer || !peer->socket || !peer->socket->IsConnected() ||
            !peer->HasValidHash() || !peer->HasEseNodePub() ||
            !peer->SupportsEseTunnelAuth() ||
            !peer->SupportsEseTunnelDataplane() ||
            !peer->SupportsEseTunnelStrict3() ||
            !peer->SupportsEseTunnelShaped() ||
            (peer->GetEseCapabilities() &
                (ESE_CAP_KAD6 | ESE_CAP_KAD6_ECONOMY)) !=
                (ESE_CAP_KAD6 | ESE_CAP_KAD6_ECONOMY) ||
            privatePathNodes.find(K6BinaryKey(peer->GetEseNodePub(), 32)) !=
                privatePathNodes.end() ||
            (theApp.liveStreamManager &&
             theApp.liveStreamManager->IsStreamSourcePeer(peer)))
            continue;
        if (!selected) selected = peer;
        if (havePinnedGuard && kad6::Kad6CtEqual(peer->GetEseNodePub(),
                pinnedGuard.data(), pinnedGuard.size())) {
            selected = peer;
            break;
        }
    }
    if (!selected) return false;
    size_t before = 0;
    {
        CSingleLock lock(&m_lock, TRUE);
        before = m_circuitRegistry.Size();
    }
    std::vector<CUpDownClient*> one{selected};
    if (BuildPool(NULL, one, 1) == 0) return false;
    CSingleLock lock(&m_lock, TRUE);
    for (size_t i = before; i < m_circuitRegistry.Size(); ++i) {
        const std::shared_ptr<CLiveCircuit> circuit = m_circuitRegistry.At(i);
        if (circuit && circuit->m_firstHopClient == selected &&
            circuit->State() == CircuitState::Pending) {
            circuit->m_k6QuotaIssuerCircuit = true;
            return true;
        }
    }
    return false;
}
// v8.1.1 F-2 — build a TRUE 2-hop circuit V -> hop1 -> exit with hop1 != exit.
// Mirrors BuildTestCircuit2Hop's pre-stage mechanism but REQUIRES two DISTINCT
// nodes (by user-hash), so a production circuit can never silently collapse into
// the loopback (hop2==hop1) degenerate case that looks like 2-hop but gives zero
// anonymity. No 1-hop fallback here (the caller decides that).
bool CLiveTunnel::BuildSuccessor2Hop()
{
    std::vector<CUpDownClient*> cands;
    if (theApp.clientlist)
        theApp.clientlist->GetConnectedSnapshot(cands, 5, /*tunnelOnly=*/true);
    std::vector<CUpDownClient*> eligible;
    for (CUpDownClient* p : cands) {
        if (!p || !p->socket || !p->socket->IsConnected() || !p->HasValidHash()
            || !p->HasEseNodePub() || !p->SupportsEseTunnelAuth()
            || !p->SupportsEseTunnelDataplane())
            continue;
        // v8.1.2 B6 (co-seeder filter) — never route a circuit through a peer that serves us
        // the channel we're viewing: it would learn (by being our hop) that this IP watches
        // that stream, defeating G1. Applies to hop1 AND the exit.
        if (theApp.liveStreamManager && theApp.liveStreamManager->IsStreamSourcePeer(p)) continue;
        eligible.push_back(p);
    }
    auto distinctNode = [](CUpDownClient* a, CUpDownClient* b) {
        if (!a || !b || a == b) return false;
        if (a->HasEseNodePub() && b->HasEseNodePub()
            && kad6::Kad6CtEqual(a->GetEseNodePub(), b->GetEseNodePub(), 32))
            return false;
        const uchar* ha = a->GetUserHash();
        const uchar* hb = b->GetUserHash();
        return !(ha && hb && memcmp(ha, hb, 16) == 0);
    };
    CUpDownClient* hop1 = NULL;
    CUpDownClient* hop2 = NULL;
    // Prefer a Kad6-capable EXIT; the guard may be any distinct authenticated
    // tunnel peer. This makes Kad6 win whenever it is present without removing
    // the legacy two-hop compatibility path during early adoption.
    for (CUpDownClient* exitCandidate : eligible) {
        if ((exitCandidate->GetEseCapabilities() & ESE_CAP_KAD6) == 0) continue;
        for (CUpDownClient* guardCandidate : eligible)
            if (distinctNode(guardCandidate, exitCandidate)) {
                hop1 = guardCandidate;
                hop2 = exitCandidate;
                break;
            }
        if (hop1) break;
    }
    if (!hop1) {
        for (CUpDownClient* p : eligible) {
            if (!hop1) { hop1 = p; continue; }
            if (!distinctNode(hop1, p)) continue;
            hop2 = p;
            break;
        }
    }
    if (!hop1 || !hop2) return false;   // < 2 distinct tunnel peers -> no real 2-hop
    size_t before = 0;
    { CSingleLock lk(&m_lock, TRUE); before = m_circuitRegistry.Size(); }
    std::vector<CUpDownClient*> hop1Vec = { hop1 };
    if (BuildPool(NULL, hop1Vec, 1) == 0) return false;   // BuildPool takes m_lock itself
    CSingleLock lk(&m_lock, TRUE);
    if (m_circuitRegistry.Size() <= before) return false;
    std::shared_ptr<CLiveCircuit> c = m_circuitRegistry.Back();
    // Pre-stage the exit: HandleCreated_Originator auto-extends to it after hop1's
    // CELL_CREATED, producing a real V -> hop1 -> exit circuit (hop1 forwards via F-1).
    c->m_private2 = true;
    c->m_pendingHopClients.push_back(hop2);
    return true;
}
void CLiveTunnel::Stop()
{
    m_scheduler.StopReleaseNotice();
    std::set<uint32_t> retiredCircuits;
    {
        CSingleLock lock(&m_lock, TRUE);
        (void)m_scheduler.CloseDeferredWork();
        m_pendingRequests.CancelAll();
        StopK6ShapeTimerLocked();
        m_scheduler.ClearShaping();
        const std::vector<uint32_t> retired = m_circuitRegistry.Clear();
        retiredCircuits.insert(retired.begin(), retired.end());
    }
    const uint64 now = static_cast<uint64_t>(time(NULL));
    SweepK6SourceLeases(std::set<uint32_t>(), retiredCircuits, now);
    SweepK6Gateway(now, std::set<uint32_t>());
    {
        CSingleLock pl(&m_pendingLock, TRUE);
        (void)m_exitServices.Clear();
        LT7_STATE(RelayReassemblyState).clear();
        m_scheduler.LT2ResetQuotaState();
        m_scheduler.ClearFair();
        m_exitServices.LT5ClearCredits();
    }
    // v8.1 D4 - the PST pool holds a 2nd shared_ptr alias per circuit. Clearing
    // the registry without clearing the pool would keep those circuits alive (and
    // counted as Active) indefinitely, and the pool would keep building successors
    // against a stopped subsystem. Clear it too (tunnel->pool order, same as RegisterTunnel).
    Kademlia::CKadV2TunnelPool::Get().Clear();
}
bool CLiveTunnel::SendThrough(const uint8_t* payload, size_t payloadLen)
{
    if (!payload || payloadLen == 0) return false;
    CSingleLock lock(&m_lock, TRUE);
    if (m_circuitRegistry.Empty()) return false;
    // Round-robin (multipath split, Decision 5.1).
    size_t tries = m_circuitRegistry.Size();
    while (tries-- > 0) {
        std::shared_ptr<CLiveCircuit> c = m_circuitRegistry.NextRoundRobin();
        if (c->State() != CircuitState::Active) continue;
        if (c->HopCount() == 0) continue;
        uint8_t cellPayload[CELL_PAYLOAD_MAX];
        size_t cellLen = 0;
        if (!c->OnionEncrypt(payload, payloadLen, cellPayload, cellLen))
            continue;
        uint8_t cell[CELL_TOTAL_BYTES];
        if (!CellPack(c->Id(), CELL_RELAY, cellPayload, (size_t)cellLen, cell))
            continue;
        // v0.71 P3.3 — instead of queueing, send directly to hop 1's socket.
        if (c->m_firstHopClient && SendCellToPeer(c->m_firstHopClient, cell))
            return true;
        // Fallback: queue (in case socket transiently busy).
        return c->m_sendQ.Push(cell);
    }
    return false;
}
// v8.1 D5 - best-effort: resolve the EXIT (last hop) peer's Kad node-ID from our routing
// table and stash it on the circuit, so CKadV2TunnelPool::Acquire can pick the circuit whose
// exit is XOR-closest to a Kad search target. Returns silently when the peer is not a Kad
// contact (mirrors the proven CUpDownClient::GetContact usage in BaseClient.cpp). The CUInt128
// is value-copied (a CContact* can be evicted from the routing bin). Main thread only.
// v0.71 P3.3 — originator-side: CELL_CREATED arrived for our circuit.
// Payload = relay's ephemeral X25519 pub (32B). We derive the shared
// secret with our stored ephemeral private, run HKDF, register hop 1,
// wipe ephemeral, advance state.
namespace {
CString EseK6GuardPath()
{
    return thePrefs.GetMuleDirectory(EMULE_CONFIGDIR) + _T("kad6_guard.dat");
}

bool EseK6PathRandom(void*, kad6::Byte* out, std::size_t length)
{
    if (!out && length != 0) return false;
    if (length) SecureRandomBytes(out, length);
    return true;
}

}

void CLiveTunnel::DestroyCircuitFailClosed(
    const std::shared_ptr<CLiveCircuit>& circ)
{
    if (!circ || circ->State() == CircuitState::Destroyed) return;
    uint8_t destroy[CELL_TOTAL_BYTES];
    if (circ->m_role == CircuitRole::Originator) {
        if (circ->m_firstHopClient
            && CellPack(circ->Id(), CELL_DESTROY, NULL, 0, destroy))
            SendCellToPeer(circ->m_firstHopClient, destroy);
    } else {
        if (circ->m_prevHopClient
            && CellPack(circ->Id(), CELL_DESTROY, NULL, 0, destroy))
            SendCellToPeer(circ->m_prevHopClient, destroy);
        if (circ->m_nextHopClient && circ->m_nextCircId != 0
            && CellPack(circ->m_nextCircId, CELL_DESTROY, NULL, 0, destroy))
            SendCellToPeer(circ->m_nextHopClient, destroy);
    }
    TransitionCircuitDestroyed(circ);
    circ->WipeKeys();
    circ->m_auth_ok = false;
    circ->m_exit_signed_caps = 0;
}

bool CLiveTunnel::LoadK6Guard()
{
    const uint64_t now = static_cast<uint64_t>(time(NULL));
    bool cachedValid = false;
    if (!m_scheduler.LT9BeginGuardLoad(now, cachedValid))
        return cachedValid;
    uint8_t bytes[80]{};
    try {
        CFile file;
        if (!file.Open(EseK6GuardPath(), CFile::modeRead | CFile::shareDenyWrite))
            return false;
        if (file.GetLength() != sizeof bytes) {
            file.Close();
            return false;
        }
        const bool read = file.Read(bytes, sizeof bytes) == sizeof bytes;
        file.Close();
        if (!read) return false;
    } catch (CFileException* error) {
        error->Delete();
        return false;
    }
    if (memcmp(bytes, "K6GRD1\0\0", 8) != 0)
        return false;
    uint8_t digest[32];
    const kad6::Kad6CryptoHooks crypto = MakeKad6HostCryptoHooks();
    if (!crypto.sha256 || !crypto.sha256(bytes, 48, digest)
        || !kad6::Kad6CtEqual(digest, bytes + 48, 32))
        return false;
    uint64_t expiry = 0;
    for (unsigned i = 0; i < 8; ++i)
        expiry |= static_cast<uint64_t>(bytes[40 + i]) << (i * 8);
    if (expiry <= now)
        return false;
    m_scheduler.LT9SetGuard(bytes + 8, expiry);
    return true;
}

bool CLiveTunnel::SaveK6Guard(const uint8_t nodePub[32], uint64_t expiresAt)
{
    if (!nodePub || expiresAt <= static_cast<uint64_t>(time(NULL)))
        return false;
    uint8_t bytes[80]{};
    memcpy(bytes, "K6GRD1\0\0", 8);
    memcpy(bytes + 8, nodePub, 32);
    for (unsigned i = 0; i < 8; ++i)
        bytes[40 + i] = static_cast<uint8_t>(expiresAt >> (i * 8));
    const kad6::Kad6CryptoHooks crypto = MakeKad6HostCryptoHooks();
    if (!crypto.sha256 || !crypto.sha256(bytes, 48, bytes + 48))
        return false;
    const CString path = EseK6GuardPath();
    const CString temporary = path + _T(".new");
    try {
        CFile file(temporary, CFile::modeCreate | CFile::modeWrite
                              | CFile::shareExclusive);
        file.Write(bytes, sizeof bytes);
        file.Flush();
        file.Close();
        if (!MoveFileEx(temporary, path,
                        MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
            DeleteFile(temporary);
            return false;
        }
    } catch (CFileException* error) {
        error->Delete();
        DeleteFile(temporary);
        return false;
    }
    m_scheduler.LT9SetGuard(nodePub, expiresAt);
    return true;
}

bool CLiveTunnel::BuildSuccessor3Hop(uint32_t* circuitId)
{
    if (circuitId) *circuitId = 0;
    std::set<std::string> quotaIssuerNodes;
    {
        CSingleLock lock(&m_lock, TRUE);
        for (const auto& circuit : m_circuitRegistry.GetSnapshot())
            if (circuit && circuit->m_k6QuotaIssuerCircuit &&
                circuit->State() != CircuitState::Destroyed &&
                circuit->m_firstHopClient &&
                circuit->m_firstHopClient->HasEseNodePub())
                quotaIssuerNodes.insert(K6BinaryKey(
                    circuit->m_firstHopClient->GetEseNodePub(), 32));
    }
    std::vector<CUpDownClient*> peers;
    if (theApp.clientlist)
        theApp.clientlist->GetConnectedSnapshot(peers, kad6::kK6PathMaxCandidates,
                                                /*tunnelOnly=*/true);
    if (peers.size() < kad6::kK6StrictHopCount)
        return false;
    Kademlia::CKad6RoutingTable* routes = Kademlia::CKademlia::GetKad6RoutingTable();
    if (!routes || !routes->HasAsnDatabase())
        return false;

    std::vector<kad6::K6PathCandidate> candidates;
    std::vector<CUpDownClient*> candidatePeers;
    candidates.reserve(peers.size()); candidatePeers.reserve(peers.size());
    for (CUpDownClient* peer : peers) {
        if (!peer || !peer->socket || !peer->socket->IsConnected()
            || !peer->HasValidHash() || !peer->HasEseNodePub()
            || quotaIssuerNodes.find(K6BinaryKey(peer->GetEseNodePub(), 32)) !=
                quotaIssuerNodes.end())
            continue;
        kad6::Kad6Address verifiedAddress;
        kad6::K6AsnInfo asn;
        if (!routes->LookupVerifiedIdentity(peer->GetEseNodePub(),
                                            verifiedAddress, asn))
            continue;
		bool endpointMatches = false;
		if (verifiedAddress.family == kad6::Kad6Address::Family::IPv6) {
			endpointMatches = peer->HasIPv6Address()
				&& memcmp(peer->GetIPv6Address().Data(),
					verifiedAddress.addr.data(), 16) == 0;
		} else if (verifiedAddress.family == kad6::Kad6Address::Family::IPv4
                   && !peer->IsIPv6OnlyEndpoint()) {
			const uint32 peerIPv4 = peer->GetIP();
			endpointMatches = peerIPv4 != 0
				&& memcmp(&peerIPv4, verifiedAddress.addr.data(), 4) == 0;
		}
		if (!endpointMatches)
			continue;
        kad6::K6PathCandidate candidate;
        memcpy(candidate.node_pub.data(), peer->GetEseNodePub(), 32);
        memcpy(candidate.user_hash.data(), peer->GetUserHash(), 16);
        candidate.address = verifiedAddress;
        candidate.asn = asn.asn;
        candidate.operator_group = asn.operator_group;
        const INT_PTR queued = peer->socket->GetControlQueueCount();
        candidate.weight = static_cast<uint32_t>(queued >= TUNNEL_EGRESS_MAX_QUEUED_CELLS
            ? 1 : TUNNEL_EGRESS_MAX_QUEUED_CELLS - queued);
        candidate.authenticated = peer->SupportsEseTunnelAuth();
        candidate.endpoint_verified = true;
        candidate.connected = true;
        candidate.supports_strict3 = peer->SupportsEseTunnelStrict3()
            && peer->SupportsEseTunnelDataplane();
        candidate.supports_shaping = peer->SupportsEseTunnelShaped()
            && peer->SupportsEseTunnelBulk();
        candidate.supports_exit =
            (peer->GetEseCapabilities() & ESE_CAP_KAD6) != 0;
        candidate.has_capacity = queued < TUNNEL_EGRESS_MAX_QUEUED_CELLS / 2;
        candidate.current_content_peer = theApp.liveStreamManager
            && theApp.liveStreamManager->IsStreamSourcePeer(peer);
		routes->ApplyPathEvidence(candidate.node_pub.data(),
			static_cast<std::uint64_t>(time(NULL)), candidate);
        candidates.push_back(candidate);
        candidatePeers.push_back(peer);
    }

    const bool havePinnedGuard = LoadK6Guard();
    std::array<uint8_t, 32> pinnedGuard{};
    if (havePinnedGuard && !m_scheduler.LT9CopyGuard(pinnedGuard))
        return false;
    kad6::K6StrictPath selected;
    kad6::K6NetworkPathPolicy networkPolicy;
    networkPolicy.require_multi_vantage = true;
    networkPolicy.fail_closed = true;
    const kad6::K6PathStatus status = kad6::SelectK6StrictPathV2(
        candidates, havePinnedGuard ? pinnedGuard.data() : NULL,
        networkPolicy, EseK6PathRandom, NULL, selected);
    if (status != kad6::K6PathStatus::Ok) {
        AddDebugLogLine(false, _T("Kad6 K6-6: STRICT path blocked (%hs) -- no diversity relaxation/fallback"),
                        kad6::K6PathStatusName(status));
        return false;
    }

    CUpDownClient* guard = candidatePeers[selected.index[0]];
    CUpDownClient* middle = candidatePeers[selected.index[1]];
    CUpDownClient* exit = candidatePeers[selected.index[2]];
    if (!havePinnedGuard) {
        const uint64_t expiry = static_cast<uint64_t>(time(NULL)) + 7ull * 24 * 60 * 60;
        if (!SaveK6Guard(guard->GetEseNodePub(), expiry))
            return false; // a STRICT guard must survive restart before use
    }

    size_t before = 0;
    { CSingleLock lk(&m_lock, TRUE); before = m_circuitRegistry.Size(); }
    std::vector<CUpDownClient*> first{guard};
    if (BuildPool(NULL, first, 1) == 0)
        return false;
    CSingleLock lk(&m_lock, TRUE);
    std::shared_ptr<CLiveCircuit> circuit;
    for (size_t i = before; i < m_circuitRegistry.Size(); ++i) {
        const std::shared_ptr<CLiveCircuit> candidate = m_circuitRegistry.At(i);
        if (candidate && candidate->m_role == CircuitRole::Originator
            && candidate->m_firstHopClient == guard
            && candidate->State() == CircuitState::Pending) {
            circuit = candidate;
            break;
        }
    }
    if (!circuit) return false;
    circuit->m_strict3 = true;
    circuit->m_path_diverse = true;
    circuit->m_pendingHopClients.push_back(middle);
    circuit->m_pendingHopClients.push_back(exit);
    if (circuitId) *circuitId = circuit->Id();
    return true;
}


// v0.71 P3.3 — relay-side: CELL_CREATE arrived from a peer wanting to
// establish a hop with us. Generate ephemeral, derive symmetric keys
// from shared, reply with CELL_CREATED. Register the circuit as a relay
// circuit so future RELAY cells from this peer can be peeled.

// === DoS hardening — CREATE handshake admission gate =======================
// A CELL_CREATE costs us an X25519 keypair + DH + HKDF on the MAIN thread and
// requires NO prior state from the sender — the classic Tor CREATE-flood. The
// gate runs before any crypto. All caps are deliberately GENEROUS: clipping a
// legitimate peer is worse than letting a mild flood through (the per-cell
// cost is sub-millisecond; only sustained floods matter).
namespace {
const DWORD CREATE_GATE_WINDOW_MS = 5000;
// Per source IP: a legit neighbour sends ~1-2 CREATEs per pool build (the
// pool's 3-5 circuits are spread over DISTINCT relays) plus one per rotation
// (every ~5 min, TUNNEL_ROTATION_BASE_MS), plus hop1->hop2 forwarded CREATEs
// when the neighbour relays for several viewers at once. 15 per 5 s window
// (3/s sustained) is ~2 orders of magnitude above that worst legit case.
const uint32_t CREATE_GATE_MAX_PER_IP = 15;
// Global, all sources: bounds total handshake crypto at 20/s no matter how
// distributed the flood is (~well under 2% of the main thread). Legit global
// load is viewers rotating 5-min pools through us: 20/s sustained covers
// thousands of simultaneous tunnels — far beyond this network's scale.
const uint32_t CREATE_GATE_MAX_GLOBAL = 100;
// Concurrent relay-side circuits ("concurrent handshakes": the handshake
// itself completes synchronously inside HandleCreate_Relay, so the durable
// per-CREATE cost is the circuit registered in the registry — memory plus the
// linear scan every incoming cell pays). Tick() reaps every circuit after
// the 5-min rotation, so this also bounds a slow drip-flood. 512 concurrent
// relay circuits = hundreds of simultaneous viewers tunneling through us.
const size_t CREATE_GATE_MAX_RELAY_CIRCS = 512;

struct CreateRateSlot {
    CAddress srcAddress;   // full source endpoint (IPv4 or native IPv6)
    uint32_t count;
    DWORD    windowStart;  // 0 = slot free
};
static CreateRateSlot s_createRates[32] = {};
static uint32_t s_createGlobalCount  = 0;
static DWORD    s_createGlobalWindow = 0;

// Counts this CREATE against the per-IP and global windows; returns true if
// it may proceed to the X25519 handshake. Main thread only (called from
// OnCellReceived). Sliding-window open-addressed cache, same pattern as the
// /24 OP_LIVE_REQUEST limiter in LiveStreamManager.cpp.
bool CreateGateAdmit(const CAddress& source)
{
    const DWORD now = ::GetTickCount();
    if (now - s_createGlobalWindow > CREATE_GATE_WINDOW_MS) {
        s_createGlobalWindow = now;
        s_createGlobalCount  = 0;
    }
    if (++s_createGlobalCount > CREATE_GATE_MAX_GLOBAL)
        return false;
    int slot = -1, freeSlot = -1;
    const uint32_t h = (source.HashKey() * 0x9E3779B1u) % _countof(s_createRates);
    for (uint32_t i = 0; i < _countof(s_createRates); ++i) {
        uint32_t idx = (h + i) % _countof(s_createRates);
        if (s_createRates[idx].srcAddress == source
            && s_createRates[idx].windowStart != 0) {
            slot = (int)idx; break;
        }
        if (s_createRates[idx].windowStart == 0 && freeSlot == -1) freeSlot = (int)idx;
        // Reuse expired slots
        if (s_createRates[idx].windowStart != 0 && now - s_createRates[idx].windowStart > CREATE_GATE_WINDOW_MS * 4) {
            if (freeSlot == -1) freeSlot = (int)idx;
        }
    }
    if (slot >= 0) {
        if (now - s_createRates[slot].windowStart > CREATE_GATE_WINDOW_MS) {
            s_createRates[slot].windowStart = now;
            s_createRates[slot].count = 1;
        } else if (++s_createRates[slot].count > CREATE_GATE_MAX_PER_IP) {
            return false;
        }
    } else if (freeSlot >= 0) {
        s_createRates[freeSlot].srcAddress = source;
        s_createRates[freeSlot].windowStart = now;
        s_createRates[freeSlot].count = 1;
    }
    return true;
}
}  // namespace

static CAddress CreatePeerAddress(const CUpDownClient* peer)
{
    if (peer == NULL)
        return CAddress();
    if (peer->socket != NULL) {
        const CAddress socketAddress = peer->socket->GetPeerCAddress();
        if (socketAddress.GetType() != CAddress::None && !socketAddress.IsNull())
            return socketAddress;
    }
    if (peer->IsIPv6OnlyEndpoint())
        return peer->GetIPv6Address();
    if (peer->GetIP() != 0 && peer->GetIP() != INADDR_NONE)
        return CAddress::FromIPv4NetworkOrder(peer->GetIP());
    if (peer->HasIPv6Address())
        return peer->GetIPv6Address();
    return CAddress();
}

bool CLiveTunnel::OnCellReceived(uint32_t circ_id, uint8_t cmd,
                                 const uint8_t* payload, uint16_t payloadLen,
                                 CUpDownClient* fromPeer)
{
    CSingleLock lock(&m_lock, TRUE);
    m_metrics.RecordCellReceived(CELL_TOTAL_BYTES);

    // CELL_CREATE: someone is asking us to be a relay for them. Handle
    // even if we don't know circ_id yet (this is by design — circ_id is
    // chosen by the originator and we learn it from the cell).
    if (cmd == CELL_CREATE) {
        if (!fromPeer) return false;   // HandleCreate_Relay would reject anyway
        // DoS hardening: admission gate BEFORE the X25519 work (see the
        // constants above). Drops are silent on the wire — V's circuit just
        // times out, exactly as if we were a vanilla 0.70b peer ignoring the
        // opcode — and the debug log is throttled so a flood can't flood it.
        const CAddress sourceAddress = CreatePeerAddress(fromPeer);
        bool admit = CreateGateAdmit(sourceAddress);
        if (admit) {
            size_t relayCircs = 0;
            for (const auto& c : m_circuitRegistry.GetSnapshot())
                if (c->m_role == CircuitRole::Relay) ++relayCircs;
            if (relayCircs >= CREATE_GATE_MAX_RELAY_CIRCS) admit = false;
        }
        if (!admit) {
            static DWORD s_lastGateLog = 0;
            if (::GetTickCount() - s_lastGateLog > 30000) {
                s_lastGateLog = ::GetTickCount();
                const std::string sourceText = sourceAddress.GetType() != CAddress::None
                    ? sourceAddress.ToString() : std::string("unknown");
                AddDebugLogLine(false,
                    _T("LiveTunnel: CREATE admission gate dropping handshake(s), last from %hs (DoS protection)"),
                    sourceText.c_str());
            }
            return true;   // consumed: silently dropped
        }
        return HandleCreate_Relay(circ_id, payload, payloadLen, fromPeer);
    }

    // v0.71 B — CELL_CREATED may be a relay-side "reply from hop2".
    // Look up by OUTBOUND id (relay-side m_nextCircId) BEFORE falling
    // through to the originator-side lookup. If found, this is hop1
    // receiving CREATED from hop2 and we must wrap it as EXTENDED back
    // to V on V's circ_id.
    if (cmd == CELL_CREATED) {
        auto relayCirc = m_circuitRegistry.FindRelayByOutgoingId(circ_id);
        if (relayCirc) {
            if (fromPeer != relayCirc->m_nextHopClient) return false;
            return ForwardCreatedAsExtended_Relay(circ_id, payload, payloadLen);
        }
    }

    if (cmd == CELL_EXTENDED) {
        auto relayCirc = m_circuitRegistry.FindRelayByOutgoingId(circ_id);
        if (relayCirc) {
            if (fromPeer != relayCirc->m_nextHopClient) return false;
            return ForwardExtendedCell_Reverse(relayCirc, payload, payloadLen);
        }
    }

    // DESTROY is directional even though it has no encrypted payload. An
    // outbound id identifies a close travelling back from the next hop;
    // forward it only to the bound previous transport peer and retire this
    // mapping. A failed STRICT3 prefix must not survive at guard or middle.
    if (cmd == CELL_DESTROY) {
        auto relayCirc = m_circuitRegistry.FindRelayByOutgoingId(circ_id);
        if (relayCirc) {
            if (fromPeer != relayCirc->m_nextHopClient) return false;
            uint8_t destroy[CELL_TOTAL_BYTES];
            if (relayCirc->m_prevHopClient
                && CellPack(relayCirc->Id(), CELL_DESTROY, NULL, 0, destroy))
                SendCellToPeer(relayCirc->m_prevHopClient, destroy);
            TransitionCircuitDestroyed(relayCirc);
            relayCirc->WipeKeys();
            return true;
        }
    }

    // v8.1.1 F-1 — reverse 2-hop DATA forwarding. A CELL_RELAY arriving on a
    // relay's OUTBOUND id (m_nextCircId) is a data cell coming back from hop2/exit;
    // re-add our hop1->V layer and relay it to V. Looked up BEFORE the by-Id lookup
    // (the outbound id is not a circuit Id on this node), mirroring CELL_CREATED above.
    if (cmd == CELL_RELAY) {
        auto relayCirc = m_circuitRegistry.FindRelayByOutgoingId(circ_id);
        if (relayCirc) {
            if (fromPeer != relayCirc->m_nextHopClient) return false;
            return ForwardRelayCell_Reverse(relayCirc, payload, payloadLen);
        }
    }

    // All other cells require an existing circuit entry by circ_id
    // (originator's V-side id, or relay-side from-V id).
    std::shared_ptr<CLiveCircuit> circ = m_circuitRegistry.FindById(circ_id);
    if (!circ) return false;
    if (circ->m_role == CircuitRole::Originator) {
        if (fromPeer != circ->m_firstHopClient) return false;
    } else if (fromPeer != circ->m_prevHopClient) {
        return false;
    }

    switch (cmd) {
        case CELL_CREATED:
            // Originator-side CREATED for hop1.
            if (circ->m_role != CircuitRole::Originator) return false;
            return HandleCreated_Originator(circ, payload, payloadLen);

        case CELL_EXTEND:
            // v0.71 B — relay receives EXTEND from V, forwards to hop2.
            if (circ->m_role != CircuitRole::Relay) return false;
            if (circ->m_nextHopClient)
                return ForwardExtendCell_Forward(circ, payload, payloadLen);
            return HandleExtend_Relay(circ, payload, payloadLen);

        case CELL_EXTENDED:
            // v0.71 B — originator receives EXTENDED back, derives hop2 keys.
            if (circ->m_role != CircuitRole::Originator) return false;
            return HandleExtended_Originator(circ, payload, payloadLen);

        case CELL_RELAY:
            // v8.1.1 F-1 — if we are an INTERMEDIATE relay (hop1) of a TRUE 2-hop
            // circuit (m_nextHopClient set, non-loopback), forward toward hop2/exit by
            // peeling exactly ONE layer — never terminate. This is what makes the exit
            // NOT see V's IP (G1). A 1-hop exit or loopback exit has m_nextHopClient
            // NULL and still terminates via HandleRelay_Exit below.
            if (circ->m_role == CircuitRole::Relay && circ->m_nextHopClient) {
                return ForwardRelayCell_Forward(circ, payload, payloadLen);
            }
            // v0.71 C — data plane delivery (terminating end).
            // Originator: peel ALL hops, parse TunnelOp, deliver.
            // Exit (1-hop, or loopback holding V↔hop2 keys): peel all hops,
            //   dispatch the inner payload, wrap reply, send back to V.
            if (circ->m_role == CircuitRole::Originator) {
                return HandleRelay_Originator(circ, payload, payloadLen);
            } else {
                return HandleRelay_Exit(circ, payload, payloadLen);
            }

        case CELL_DESTROY:
            // Arrived from the previous peer on our inbound id. Drain the
            // remaining forward prefix before deleting this local mapping.
            if (circ->m_role == CircuitRole::Relay && circ->m_nextHopClient
                && circ->m_nextCircId != 0) {
                uint8_t destroy[CELL_TOTAL_BYTES];
                if (CellPack(circ->m_nextCircId, CELL_DESTROY, NULL, 0, destroy))
                    SendCellToPeer(circ->m_nextHopClient, destroy);
            }
            TransitionCircuitDestroyed(circ);
            circ->WipeKeys();
            return true;

        case CELL_PADDING: {
            // Cover traffic. The originator OnionEncrypt'd this cell, which
            // advanced its per-hop nonce_send counter. We MUST peel it here
            // so our nonce_recv stays in lockstep: the ChaCha20-Poly1305
            // nonce is an implicit counter (not on the wire), so a dropped
            // cell desyncs it and the next real CELL_RELAY fails AEAD auth.
            // The decrypted plaintext is random padding and is discarded.
            if (circ->m_role == CircuitRole::Relay) {
                // A three-hop origin wrapped one layer for every relay. An
                // intermediate must consume exactly its own layer and carry
                // the same PADDING command onward; terminating it at the guard
                // would leave the middle/exit implicit nonce counters stale.
                if (circ->m_nextHopClient)
                    return ForwardPaddingCell_Forward(circ, payload, payloadLen);
                uint8_t scratch[CELL_PAYLOAD_MAX];
                size_t  scratchLen = 0;
                circ->OnionDecryptAll(payload, payloadLen, scratch, sizeof scratch, scratchLen);
            }
            return true;
        }

        default:
            return false;
    }
}

// === v0.71 B — 2-hop extension =============================================
// V (originator) → hop1 → hop2 → destination.
// After hop1's CREATED arrives, V triggers BuildExtend:
//   1. Generate a fresh X25519 ephemeral (separate from the one used for hop1)
//   2. Build EXTEND payload: hop2_ip(4) + hop2_port(2) + ev_pub2(32) = 38B
//   3. OnionEncrypt with V↔hop1 keys → ciphertext (38 + 16 tag = 54B)
//   4. Pack as CELL_EXTEND on V's circ_id, send to hop1
// hop1's HandleExtend_Relay:
//   1. AEAD-decrypt with K_recv_v_to_hop1 → plaintext 38B
//   2. Read hop2_endpoint, ev_pub2
//   3. Pick fresh outbound circ_id, send CELL_CREATE(ev_pub2) to hop2
//   4. Stash forwarding: m_nextHopClient + m_nextCircId on relay circuit
// hop2 sees a normal CELL_CREATE → HandleCreate_Relay (existing code) →
//   replies CELL_CREATED(er_pub2) to hop1 on the outbound circuit
// hop1's ForwardCreatedAsExtended_Relay:
//   1. Find relay circuit by outbound id
//   2. Wrap er_pub2 with K_send_r_to_v (AEAD-encrypt)
//   3. Send CELL_EXTENDED on V-side circ_id back to V
// V's HandleExtended_Originator:
//   1. AEAD-decrypt with K_recv_r_to_v_hop1 → er_pub2 plaintext
//   2. shared = X25519(er_pub2, V_extend_ephemeral_priv)
//   3. HKDF → K_v_to_hop2 + K_hop2_to_v
//   4. AddHop, wipe ephemeral, mark Active with hopCount=2

bool CLiveTunnel::ForwardPaddingCell_Forward(std::shared_ptr<CLiveCircuit>& circ,
                                             const uint8_t* payload, uint16_t payloadLen)
{
    if (!circ || circ->m_role != CircuitRole::Relay
        || !circ->m_nextHopClient || circ->m_nextCircId == 0
        || circ->HopCount() != 1 || payloadLen < 16)
        return false;
    uint8_t inner[CELL_PAYLOAD_MAX];
    size_t innerLen = 0;
    if (!circ->OnionPeelOne(0, payload, payloadLen, inner, innerLen))
        return false;
    uint8_t cell[CELL_TOTAL_BYTES];
    if (!CellPack(circ->m_nextCircId, CELL_PADDING, inner, innerLen, cell))
        return false;
    return SendCellToPeer(circ->m_nextHopClient, cell);
}

uint32_t CLiveTunnel::BuildTestCircuit2Hop()
{
    // A LAB two-hop request models the production Private profile: it requires
    // two distinct fork identities and every hop must authenticate. Never
    // silently collapse it into the old self-loop or Mixed-mode test.
    std::vector<CUpDownClient*> forkCands;
    if (theApp.clientlist)
        theApp.clientlist->GetConnectedSnapshot(forkCands, 5, /*tunnelOnly=*/true);
    if (forkCands.size() < 2) return 0;

    std::vector<CUpDownClient*> eligible;
    for (CUpDownClient* peer : forkCands) {
        if (!peer || !peer->socket || !peer->socket->IsConnected() ||
            !peer->HasValidHash() || !peer->HasEseNodePub() ||
            !peer->SupportsEseTunnelAuth() ||
            !peer->SupportsEseTunnelDataplane())
            continue;
        eligible.push_back(peer);
    }
    if (eligible.size() < 2) return 0;

    CUpDownClient* hop1 = eligible[0];
    CUpDownClient* hop2 = NULL;
    for (size_t i = 1; i < eligible.size(); ++i) {
        CUpDownClient* candidate = eligible[i];
        if (!candidate || candidate == hop1) continue;
        if (kad6::Kad6CtEqual(
                hop1->GetEseNodePub(), candidate->GetEseNodePub(), 32))
            continue;
        const uchar* firstHash = hop1->GetUserHash();
        const uchar* candidateHash = candidate->GetUserHash();
        if (firstHash && candidateHash && memcmp(firstHash, candidateHash, 16) == 0)
            continue;
        hop2 = candidate;
        break;
    }
    if (!hop2) return 0;

    std::vector<CUpDownClient*> hop1Vec = { hop1 };
    size_t built = BuildPool(NULL, hop1Vec, 1);
    if (built == 0) return 0;

    // The freshly-built circuit is at the back of the registry. We can't
    // call BuildExtend yet — the circuit is still Pending until CREATED
    // arrives. We mark a flag so HandleCreated_Originator triggers
    // BuildExtend automatically. For simplicity (and because there's no
    // good place to stash hop2 right now), we register a one-shot
    // post-CREATED action via a static map.
    CSingleLock lk(&m_lock, TRUE);
    if (m_circuitRegistry.Empty()) return 0;
    const std::shared_ptr<CLiveCircuit> c = m_circuitRegistry.Back();
    // Re-use m_nextHopClient on the ORIGINATOR side to mean "after
    // CREATED, extend to this peer". HandleCreated_Originator will check.
    c->m_private2 = true;
    c->m_pendingHopClients.push_back(hop2);
    return c->Id();
}

bool CLiveTunnel::TunnelPing(const std::string& text, std::string& replyText,
                             uint32_t timeoutMs)
{
    // v8.1 A4 - register the waiter BEFORE sending (generates a unique req_id;
    // a fast reply cannot race the registration), stash the message for retry,
    // then marshal a pinned send and wait through the pending domain.
    uint32_t req_id;
    PendingHandle pr = RegisterPending(req_id);
    m_pendingRequests.Configure(
        pr, TUN_OP_PING, 0, TUN_SEND_RETRIES,
        reinterpret_cast<const uint8_t*>(text.data()), text.size());
    EnqueueSendMsg(req_id, TUN_OP_PING,
                   (const uint8_t*)text.data(), text.size());

    std::vector<uint8_t> reply;
    if (!WaitPending(req_id, std::move(pr), timeoutMs, reply, NULL))
        return false;
    replyText.assign((const char*)reply.data(), reply.size());
    return true;
}

// v8.1 A1.7 - multi-cell echo round-trip. Marshals the message for a pinned
// send (A4: SendMessagePinned fragments it onto one circuit) and waits for the
// reassembled TUN_OP_ECHO_LARGE_REPLY. Worker-thread safe.
bool CLiveTunnel::TunnelEchoLarge(const std::vector<uint8_t>& payload,
                                  std::vector<uint8_t>& replyOut,
                                  uint32_t timeoutMs)
{
    // Reject oversize up front so the caller gets a clean false (the real
    // fragmentation now happens in SendMessagePinned, sized to the actual
    // circuit's hop count).
    if (payload.size() > TUN_MSG_MAX_BYTES)
        return false;

    // v8.1 A4 - register the waiter (generates a unique req_id), stash the
    // message for retry, then marshal a pinned send: all fragments ride ONE
    // circuit so they reassemble at one exit. Wait through the pending domain.
    uint32_t req_id;
    PendingHandle pr = RegisterPending(req_id);
    m_pendingRequests.Configure(
        pr, TUN_OP_ECHO_LARGE, 0, TUN_SEND_RETRIES,
        payload.empty() ? NULL : payload.data(), payload.size());
    EnqueueSendMsg(req_id, TUN_OP_ECHO_LARGE,
                   payload.empty() ? NULL : payload.data(), payload.size());

    return WaitPending(req_id, std::move(pr), timeoutMs, replyOut, NULL);
}

void CLiveTunnel::Tick()
{
    CSingleLock lock(&m_lock, TRUE);
    std::set<uint32_t> retiredCircuits;
    // Emit one terminal build sample per strict origin circuit before dead
    // entries are reaped. Success means the complete authenticated 3-hop path
    // reached Active; every fail-closed teardown is a failed build unless a
    // success was already recorded earlier in the circuit lifetime.
    const uint64_t buildMetricNow = static_cast<uint64_t>(time(NULL));
    for (const auto& circuit : m_circuitRegistry.GetSnapshot()) {
        if (circuit && circuit->State() == CircuitState::Destroyed)
            retiredCircuits.insert(circuit->Id());
        if (!circuit || !circuit->m_strict3 ||
            circuit->m_role != CircuitRole::Originator ||
            circuit->m_k6BuildMetricEmitted ||
            (circuit->State() != CircuitState::Active &&
             circuit->State() != CircuitState::Destroyed))
            continue;
        const bool ok = circuit->State() == CircuitState::Active;
        m_metrics.Observe(kad6::K6MetricFamily::CircuitBuildMs,
            ok ? 0 : 1, 0, 0, static_cast<double>(circuit->AgeMs()), buildMetricNow);
        m_metrics.Add(kad6::K6MetricFamily::BuildTotal,
            ok ? 0 : 1, ok ? 0 : 6, 0, 1, buildMetricNow);
        circuit->m_k6BuildMetricEmitted = true;
    }
    // 1. Reap Destroyed circuits.
    m_circuitRegistry.RemoveDestroyed(&retiredCircuits);

    // 2. Rotation: any ACTIVE circuit older than ROTATION_BASE_MS is
    // marked Destroyed. Pending circuits get a longer timeout because
    // they're waiting for handshake reply.
    const DWORD now = GetTickCount();
    for (const auto& c : m_circuitRegistry.GetSnapshot()) {
        if (c->State() == CircuitState::Active && c->AgeMs() > TUNNEL_ROTATION_BASE_MS) {
            if (c->m_strict3) DestroyCircuitFailClosed(c);
            else TransitionCircuitDestroyed(c); // normal legacy rotation
        } else if (c->State() == CircuitState::Pending && c->AgeMs() > TUNNEL_HANDSHAKE_TIMEOUT_MS * 8) {
            // 8x handshake timeout = ~6.4 s. After this, give up — peer
            // probably isn't running the fork. Distinct from a crypto reject:
            // this is a TIMED reap from Tick (with age), not a synchronous AUTH-ABORT.
            AddDebugLogLine(false, _T("LiveTunnel: circ=0x%08x REAP reason=HANDSHAKE_TIMEOUT (CREATED never arrived, age=%u ms) — NOT a crypto reject"), c->Id(), c->AgeMs());
            c->m_abort_reason = CircuitAbortReason::HandshakeTimeout;
            if (c->m_private2 || c->m_strict3) DestroyCircuitFailClosed(c);
            else TransitionCircuitDestroyed(c);
        } else if (c->State() == CircuitState::HalfBuilt
                   && c->m_extendStartedTick != 0
                   && LiveTunnelScheduler::HasStrictlyElapsed32(now, c->m_extendStartedTick,
                       TUNNEL_HANDSHAKE_TIMEOUT_MS * 16)) {
            // v8.1 fix: a circuit stuck mid-EXTEND (hop1 done, EXTENDED
            // never arrived) used to fall through both arms above and
            // leak forever. Time it out, with a longer budget since it
            // is waiting on a second handshake leg.
            AddDebugLogLine(false, _T("LiveTunnel: circ=0x%08x REAP reason=EXTEND_TIMEOUT (EXTENDED never arrived, age=%u ms) — NOT a crypto reject"), c->Id(), c->AgeMs());
            c->m_abort_reason = CircuitAbortReason::ExtendTimeout;
            if (c->m_private2 || c->m_strict3) DestroyCircuitFailClosed(c);
            else TransitionCircuitDestroyed(c);
        }
    }

    // 3. Economy operations require an unlinkable one-hop quota issuer whose
    // node is absent from the private path. Build that guard lazily once an
    // authenticated two-hop economy path exists, retrying at a bounded cadence.
    bool haveK6EconomyPath = false;
    bool haveK6QuotaGuard = false;
    for (const auto& circuit : m_circuitRegistry.GetSnapshot()) {
        if (!circuit || circuit->State() == CircuitState::Destroyed) continue;
        if (circuit->m_k6QuotaIssuerCircuit) {
            haveK6QuotaGuard = true;
            continue;
        }
        if (circuit->m_role == CircuitRole::Originator &&
            circuit->State() == CircuitState::Active &&
            circuit->HopCount() >= 2 && circuit->m_auth_ok &&
            (circuit->m_exit_signed_caps &
                (ESE_CAP_KAD6 | ESE_CAP_KAD6_ECONOMY)) ==
                (ESE_CAP_KAD6 | ESE_CAP_KAD6_ECONOMY))
            haveK6EconomyPath = true;
    }
    if ((IsK6PublicReleaseEnabled() ||
            thePrefs.IsEseNetLabContributionActive()) &&
        haveK6EconomyPath && !haveK6QuotaGuard &&
        m_scheduler.LT9ShouldAttemptQuotaGuard(now, 5000u))
        BuildQuotaGuardCircuit();

    // 4. Cover traffic emission. For each Active originator circuit, if it's
    // past m_nextPaddingTick, emit a CELL_PADDING with
    // random length and reschedule via Poisson distribution.
    // This makes TAG_ESE_CAPS bit 11 (cover_traffic) truthful: the bit
    // claims we generate cover traffic, and now we actually do.
    // K6-3: SourceLeases are circuit-bound. Rotation, DESTROY or timeout
    // drains their publishes; wall-clock expiry closes them independently of
    // GetTickCount wraparound.
    for (const auto& circuit : m_circuitRegistry.GetSnapshot())
        if (circuit && circuit->State() == CircuitState::Destroyed)
            retiredCircuits.insert(circuit->Id());

    {
        double circuitCounts[5][4] = {};
        for (const auto& circuit : m_circuitRegistry.GetSnapshot()) {
            if (!circuit) continue;
            const uint8 state = (std::min<uint8>)(static_cast<uint8>(circuit->State()), 4);
            const uint8 hops = (std::min<uint8>)(static_cast<uint8>(circuit->HopCount()), 3);
            circuitCounts[state][hops] += 1.0;
        }
        const uint64 metricNow = static_cast<uint64>(time(NULL));
        for (uint8 state = 0; state < 5; ++state)
            for (uint8 hops = 0; hops < 4; ++hops)
                m_metrics.Observe(kad6::K6MetricFamily::Circuits,
                    state, hops, 0, circuitCounts[state][hops], metricNow);
    }
    {
        std::set<uint32_t> active;
        for (const auto& c : m_circuitRegistry.GetSnapshot())
            if (c->State() == CircuitState::Active) active.insert(c->Id());
        const uint64 k6Now = static_cast<uint64_t>(time(NULL));
        SweepK6SourceLeases(active, retiredCircuits, k6Now);
        SweepK6Gateway(k6Now, active);
        StartK6VisibilityProbes(k6Now);
        QueueK6ShadowRefreshes(k6Now);
        StartDueK6ShadowPublishes(k6Now);
        RefreshK6NativePublishes(k6Now);
    }

    auto& covCfg = CLiveCoverTraffic::Get();
    for (const auto& c : m_circuitRegistry.GetSnapshot()) {
        if (c->State() != CircuitState::Active) continue;
        if (c->m_role != CircuitRole::Originator) continue;   // only originator drives cover
        if (c->HopCount() < 1) continue;
        if (c->m_lastPaddingTick == 0) {
            c->m_lastPaddingTick = now;
            c->m_nextPaddingDelayMs =
                covCfg.NextPaddingDelayMs((uint32_t)covCfg.GetProfile());
            continue;
        }
        if (!LiveTunnelScheduler::HasElapsed32(
                now, c->m_lastPaddingTick, c->m_nextPaddingDelayMs))
            continue;

        // Build a CELL_PADDING: payload = random bytes of random length.
        uint16_t fakeLen = covCfg.SampleFakeLength();
        // v8.1 fix: cap the fake length so the onion-wrapped padding cell
        // fits (each hop adds a 16-byte AEAD tag). SampleFakeLength()
        // returns 0..505, so without this ~6% of cover cells on a 2-hop
        // circuit overflowed OnionEncrypt and were dropped.
        const size_t covMaxFake = (c->HopCount() * 16 < CELL_PAYLOAD_MAX)
                                ? (CELL_PAYLOAD_MAX - c->HopCount() * 16) : 0;
        if (fakeLen > covMaxFake) fakeLen = (uint16_t)covMaxFake;
        std::vector<uint8_t> fakePlain(fakeLen);
        if (fakeLen > 0) SecureRandomBytes(fakePlain.data(), fakeLen);
        // Onion-wrap through the same hops as a real RELAY would.
        uint8_t cellPayload[CELL_PAYLOAD_MAX];
        size_t cellPayloadLen = 0;
        if (!c->OnionEncrypt(fakePlain.data(), fakePlain.size(),
                             cellPayload, cellPayloadLen))
            continue;
        uint8_t cell[CELL_TOTAL_BYTES];
        if (!CellPack(c->Id(), CELL_PADDING, cellPayload, cellPayloadLen, cell))
            continue;
        if (!c->m_firstHopClient) continue;
        if (SendCellToPeer(c->m_firstHopClient, cell)) {
            c->m_lastPaddingTick = now;
            c->m_nextPaddingDelayMs =
                covCfg.NextPaddingDelayMs((uint32_t)covCfg.GetProfile());
        }
    }

    // 3b. v8.1 D8 - periodic tunnel RTT probe. Every RTT_PING_INTERVAL_MS, send ONE
    // fire-and-forget TUN_OP_PING (reusing the existing ping op — no new wire opcode)
    // pinned by SendMessagePinned to an Active circuit, and record its req_id + send
    // tick. The PING_REPLY arm in HandleRelay_Originator differences the tick into
    // the metrics-owned RTT EWMA. SendMessagePinned returns 0 when there is no Active circuit,
    // so this is a pure no-op on a single-PC node (it never builds anything).
    {
        const DWORD RTT_PING_INTERVAL_MS = 5000u;
        if (m_scheduler.DueRttProbe(now, RTT_PING_INTERVAL_MS)) {
            // req_id is a fresh random NewCircuitId(), not deduped against the
            // pending domain. A ~2^-32 collision with an in-flight manual
            // TunnelPing would cost one washed-out EWMA sample; accepted given the odds
            // and that TunnelPing is a dev-only diagnostic path.
            const uint32_t rttReqId = NewCircuitId();
            const uint8_t pingBody[1] = { 0 };          // 1-byte body (exit echoes it)
            if (SendMessagePinned(rttReqId, TUN_OP_PING, pingBody, sizeof pingBody) != 0) {
                m_scheduler.LT9RecordRtt(rttReqId, now);
            } else {
                // No Active circuit -> no probe in flight. Drop any stale stamp so a
                // very-delayed reply to an old probe can't yield an inflated RTT sample.
                m_scheduler.LT9ClearRtt();
            }
        }
    }

    // 4. v8.1 A5 - sweep abandoned reassembly buffers. A multi-cell message
    // whose remaining fragments never arrive would otherwise leave its
    // ReassemblyEntry in LT7_STATE(RelayReassemblyState) forever (memory leak + DoS vector).
    {
        CSingleLock pl(&m_pendingLock, TRUE);
        for (auto it = LT7_STATE(RelayReassemblyState).begin(); it != LT7_STATE(RelayReassemblyState).end(); ) {
            if (LiveTunnelScheduler::HasStrictlyElapsed32(
                    now, it->second.first_seen_tick, TUN_REASSEMBLY_TTL_MS))
                it = LT7_STATE(RelayReassemblyState).erase(it);
            else
                ++it;
        }
        m_relayDispatcher.LT8SweepReplies(now,TUN_REQUEST_HARD_TTL_MS);
    }

    // 4b. v8.1.2 E3.4 - sweep abandoned bulk segment reassembly + dead-circuit replay
    // windows (under m_lock, already held). Same rationale as A5.
    SweepBulkReasm();

    // 4c. v8.1.2 E3.1/E3.3 - exit-side: drain headless-ingested records, FEC-encode and
    // push their symbols to the subscribed bulk circuits (under m_lock, already held).
    ProcessProxyIngest();

    // 4d. v8.1.2 E3.2 (viewer trigger) - while viewing a stream WITH Active bulk-capable
    // circuits, (re)subscribe to the bulk data plane every ~10 s. The throttle is well under
    // BULK_SUB_TTL_MS so the exit's subs stay fresh AND circuits that turned Active after the
    // join get covered. No-op at any node the exit isn't proxying this stream for (the exit
    // only registers/pushes if it proxies the streamKey). BulkSubscribe re-takes m_lock
    uchar viewerKey[16];
    if (theApp.liveStreamManager
        && theApp.liveStreamManager->CopyViewerStreamKey(viewerKey)
        && m_scheduler.DueBulkSubscription(now, 10000u)) {
        bool haveBulk = false;
        for (const auto& c : m_circuitRegistry.GetSnapshot())
            if (c->m_role == CircuitRole::Originator && c->State() == CircuitState::Active
                && c->HopCount() >= 1 && c->m_bulk_ok) { haveBulk = true; break; }
        if (haveBulk) {
            m_scheduler.MarkBulkSubscription(now);
            BulkSubscribe(viewerKey);
        }
    }

    // 5. v8.1 A4 - retry/fail messages pinned to a circuit that died mid-flight.
    // Rotation (step 2 above) or a CELL_DESTROY can kill a circuit while one of
    // its multi-cell messages was still in flight. Re-send the whole message on
    // another circuit (up to retries_left); when retries run out, wake the
    // waiter with a failure so it returns a clean error instead of timing out.
    {
        // Tick already owns the registry lock. Pass a value snapshot into the
        // pending domain; it must never call back into the registry while its
        // own mutex is held.
        std::set<uint32_t> activeCircuitIds;
        for (const auto& circuit : m_circuitRegistry.GetSnapshot()) {
            if (circuit && circuit->State() == CircuitState::Active)
                activeCircuitIds.insert(circuit->Id());
        }
        std::vector<MainThreadReq> retries;
        const std::vector<eSELive::LiveTunnelPending::RetryAction> actions =
            m_pendingRequests.CollectRetries(activeCircuitIds);
        retries.reserve(actions.size());
        for (const auto& action : actions) {
            MainThreadReq request;
            request.op = MT_SEND_MSG;
            request.reqId = action.request_id;
            request.subCmd = action.sub_cmd;
            request.requiredExitCaps = action.required_exit_caps;
            request.payload = action.message;
            retries.push_back(std::move(request));
        }
        // CollectRetries has released the pending-domain mutex before queue
        // publication, preserving registry -> pending -> queue lock order.
        const std::vector<LiveDeferredWork> cancelled = m_scheduler.EnqueueBatch(std::move(retries));
        for (const LiveDeferredWork& work : cancelled) {
            if (work.reqId != 0)
                SignalReply(work.reqId, NULL, 0, 0);
        }
    }

    // 6. v8.1 A6 - sweep deferred exit operations that never completed, or
    // whose circuit has gone (weak_ptr expired). TTL reuses the hard request
    // bound; without this a never-finishing exit op would leak forever.
    {
        CSingleLock pl(&m_pendingLock, TRUE);
        (void)m_exitServices.Sweep(now, TUN_REQUEST_HARD_TTL_MS);
    }

    // 7. v8.1 Sprint B - reply to tunneled Kad searches whose accumulation
    // window has elapsed (real results have been landing in the directory).
    FinishDueSearchJobs();

    m_scheduler.RecordTick(now);
}

size_t CLiveTunnel::ActiveCircuitCount() const
{
    CSingleLock lock(&m_lock, TRUE);
    size_t n = 0;
    for (const auto& c : m_circuitRegistry.GetSnapshot())
        if (c->State() == CircuitState::Active) ++n;
    return n;
}
bool CLiveTunnel::HasActiveCircuitWithExitCaps(uint32_t requiredCaps) const
{
    if (requiredCaps == 0) return ActiveCircuitCount() != 0;
    const size_t minimumHops = (requiredCaps & ESE_CAP_KAD6) != 0 ? 2 : 1;
    CSingleLock lock(&m_lock, TRUE);
    for (const auto& c : m_circuitRegistry.GetSnapshot()) {
        if (!c->m_k6QuotaIssuerCircuit &&
            c->m_role == CircuitRole::Originator &&
            c->State() == CircuitState::Active && c->HopCount() >= minimumHops &&
            c->m_firstHopClient && c->m_multicell_ok && c->m_auth_ok &&
            (c->m_exit_signed_caps & requiredCaps) == requiredCaps &&
            ((requiredCaps & ESE_CAP_TUNNEL_STRICT3) == 0
             || (c->m_strict3 && c->m_path_diverse && c->m_shaped_ok
                 && c->HopCount() == 3)))
            return true;
    }
    return false;
}

// v0.71 P3.8 — count circuits in flight (CREATE sent, CREATED not yet
// received). Important to expose because a test_circuit against a non-fork
// peer creates a Pending circuit that NEVER reaches Active (peer drops
// the unknown opcode), and ActiveCircuitCount alone would show 0
// throughout the entire 6s pending window, falsely suggesting nothing
// happened.
size_t CLiveTunnel::PendingCircuitCount() const
{
    CSingleLock lock(&m_lock, TRUE);
    size_t n = 0;
    for (const auto& c : m_circuitRegistry.GetSnapshot())
        if (c->State() == CircuitState::Pending) ++n;
    return n;
}
