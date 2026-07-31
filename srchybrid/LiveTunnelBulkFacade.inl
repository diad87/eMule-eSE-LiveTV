// this file is part of eMule eSE - LT7 bulk/proxy facade implementation
// Included once by LiveTunnel.cpp inside namespace eSELive.
// It partitions coordinator implementation without creating a reverse module dependency.
void CLiveTunnel::ExitHandle_LiveSubscribe(const TunnelRequestCtx& ctx)
{
    // Legacy v1 carries the endpoint (28 bytes). Kad6-native v2 keeps it at
    // the exit: [result_id 16][source_request_id u32][version=2][reserved 3].
    uint8_t status = 1;            // 1 = bad request (default)
    uint8_t streamKey[16] = {0};
    uint32_t bIP = 0, bAltIP = 0;
    uint16_t bPort = 0, bUDP = 0;
    bool resolved = false;
    if (ctx.body && ctx.bodyLen == 24 && ctx.body[20] == 2 &&
        ctx.body[21] == 0 && ctx.body[22] == 0 && ctx.body[23] == 0 && ctx.circ) {
        memcpy(streamKey, ctx.body, 16);
        kad6::Hash16 resultId{};
        memcpy(resultId.data(), streamKey, resultId.size());
        const uint32 sourceRequestId = eseRdU32LE(ctx.body + 16);
        LiveTunnelAuthorizedTarget target;
        (void)m_exitServices.LT4FindAuthorizedTarget(
            K6AuthorizedTargetKey(ctx.circ->Id(), sourceRequestId, resultId),
            static_cast<uint64>(time(NULL)), target);
        if (target.expires_at != 0 && target.result_id == resultId &&
            target.endpoint.addr.family == kad6::Kad6Address::Family::IPv4 &&
            target.endpoint.tcp_port != 0) {
            memcpy(&bIP, target.endpoint.addr.addr.data(), 4);
            bPort = target.endpoint.tcp_port;
            bUDP = target.endpoint.udp_port;
            resolved = bIP != 0;
        }
    } else if (ctx.body && ctx.bodyLen == 28) {
        memcpy(streamKey, ctx.body, 16);
        bIP    = eseRdU32LE(ctx.body + 16);
        bPort  = eseRdU16LE(ctx.body + 20);
        bUDP   = eseRdU16LE(ctx.body + 22);
        bAltIP = eseRdU32LE(ctx.body + 24);
        resolved = bIP != 0 && bPort != 0;
    }
    if (resolved) {
        // C7 — exit as multicast proxy: if we ALREADY hold a proxy subscription
        // for this stream (another tunneled viewer arrived first), do NOT dial /
        // re-subscribe to the broadcaster. One subscription per channel is enough
        // — the broadcaster sends the stream once to us and C3's ExitRelayLive
        // Control fans the control updates out to every subscribed circuit. This
        // avoids opening N sockets and tripping the broadcaster's per-IP SUBSCRIBE
        // rate limit when many viewers share one exit.
        const std::string hex = LiveStreamKeyHex(streamKey);
        bool alreadyProxied = false;
        {
            CSingleLock pl(&m_pendingLock, TRUE);
            auto it = LT7_STATE(ExitLiveSubscriptions).find(hex);
            alreadyProxied = (it != LT7_STATE(ExitLiveSubscriptions).end() &&
                !it->second.circuits.empty() && it->second.bIP == bIP &&
                it->second.bPort == bPort && bAltIP == 0);
        }
        bool sent = alreadyProxied;
        if (!alreadyProxied) {
            try {
                if (theApp.liveStreamManager)
                    sent = theApp.liveStreamManager->ExitProxySubscribe(
                        streamKey, bIP, bPort, bUDP, bAltIP);
            } catch (...) {}
        }
        status = sent ? 0 : 2;     // 0 = forwarded OK, 2 = dial/forward failed
        if (sent && ctx.circ) {
            // C3: remember this circuit so the broadcaster's heartbeats/announces
            // (which arrive on OUR socket, since we are the proxy subscriber) get
            // relayed back to this viewer. Record the broadcaster endpoint so the
            // sweep can UNSUBSCRIBE when the last viewer leaves (C4 zombie fix).
            CSingleLock pl(&m_pendingLock, TRUE);
            ExitStreamProxy& sp = LT7_STATE(ExitLiveSubscriptions)[hex];
            if (sp.bIP == 0) { sp.bIP = bIP; sp.bPort = bPort; memcpy(sp.streamKey, streamKey, 16); }
            sp.circuits[ctx.circ->Id()].lastSeen = GetTickCount();
            if (alreadyProxied)
                CLiveDebugLog::Get().Append("TUN", "C7 multicast: +1 tunneled viewer on existing proxy sub (%d total)",
                    (int)sp.circuits.size());
        }
    }
    // reply SUB_ACK = [status u8][streamKey 16] = 17 bytes (single-cell).
    uint8_t ack[17];
    ack[0] = status;
    memcpy(ack + 1, streamKey, 16);
    SendReply(ctx, TUN_OP_LIVE_SUB_ACK, ack, sizeof ack);
}
std::string CLiveTunnel::LiveStreamKeyHex(const uint8_t streamKey[16])
{
    static const char* hexd = "0123456789abcdef";
    std::string s(32, '0');
    for (int i = 0; i < 16; ++i) {
        s[i * 2]     = hexd[(streamKey[i] >> 4) & 0xF];
        s[i * 2 + 1] = hexd[streamKey[i] & 0xF];
    }
    return s;
}
void CLiveTunnel::ExitRelayLiveControl(const uint8_t streamKey[16],
                                       bool hasBitmap, uint16_t bitmap, uint32_t oldestSeq,
                                       const uint8_t* pubkeyOrNull)
{
    const std::string hex = LiveStreamKeyHex(streamKey);
    // Snapshot the target circuit ids under the pending lock, and RESTAMP
    // lastSeen on each: the broadcaster's heartbeats flow continuously while it
    // is live, so an actively-relayed circuit stays fresh. Without this restamp
    // the TTL sweep reaps a still-watching viewer at 10 min (lastSeen was frozen
    // at subscribe time), stopping the relay and stalling the stream.
    std::vector<uint32_t> targets;
    {
        CSingleLock pl(&m_pendingLock, TRUE);
        auto it = LT7_STATE(ExitLiveSubscriptions).find(hex);
        if (it == LT7_STATE(ExitLiveSubscriptions).end() || it->second.circuits.empty()) return;
        const DWORD nowT = GetTickCount();
        for (auto& kv : it->second.circuits) {
            kv.second.lastSeen = nowT;
            targets.push_back(kv.first);
        }
    }
    // Build the relay body once.
    uint8_t body[16 + 1 + 2 + 4 + 32];
    memcpy(body, streamKey, 16);
    uint8_t flags = 0;
    if (hasBitmap)      flags |= 0x01;
    if (pubkeyOrNull)   flags |= 0x02;
    body[16] = flags;
    eseWrU16LE(body + 17, hasBitmap ? bitmap : 0);
    eseWrU32LE(body + 19, hasBitmap ? oldestSeq : 0);
    if (pubkeyOrNull) memcpy(body + 23, pubkeyOrNull, 32);
    else              memset(body + 23, 0, 32);
    const size_t bodyLen = sizeof body;
    CSingleLock lock(&m_lock, TRUE);
    for (size_t i = 0; i < targets.size(); ++i) {
        std::shared_ptr<CLiveCircuit> circ;
        for (const auto& c : m_circuitRegistry.GetSnapshot()) {
            if (c->Id() == targets[i] && c->State() == CircuitState::Active &&
                c->m_role == CircuitRole::Relay) { circ = c; break; }
        }
        if (!circ) continue;
        TunnelRequestCtx ctx;
        ctx.circ   = circ;
        ctx.req_id = 0;   // unsolicited push
        SendReply(ctx, TUN_OP_LIVE_HEARTBEAT, body, bodyLen);
    }
}
void CLiveTunnel::ExitRelayPeerList(const uint8_t streamKey[16],
                                    uint32_t upstreamIP, uint16_t upstreamPort,
                                    const uint32_t* ips, const uint16_t* ports,
                                    uint8_t count)
{
    if (upstreamIP == 0 || upstreamPort == 0 ||
        count == 0 || ips == NULL || ports == NULL) return;
    if (count > 16) count = 16;   // ESE_LIVE_MAX_PEER_LIST; also bounds the single cell
    const std::string hex = LiveStreamKeyHex(streamKey);
    std::vector<uint32_t> targets;
    {
        CSingleLock pl(&m_pendingLock, TRUE);
        auto it = LT7_STATE(ExitLiveSubscriptions).find(hex);
        if (it == LT7_STATE(ExitLiveSubscriptions).end() || it->second.circuits.empty() ||
            it->second.bIP != upstreamIP ||
            it->second.bPort != upstreamPort) return;
        const DWORD nowT = GetTickCount();
        for (auto& kv : it->second.circuits) {
            kv.second.lastSeen = nowT;   // active relay keeps the circuit fresh vs the TTL sweep
            targets.push_back(kv.first);
        }
    }
    // Build the relay body once. Max = 16 + 1 + 16*6 = 113 bytes (well under the
    // single-cell payload budget), so no multi-cell fragmentation is needed.
    uint8_t body[16 + 1 + 16 * 6];
    memcpy(body, streamKey, 16);
    body[16] = count;
    for (uint8_t i = 0; i < count; ++i) {
        eseWrU32LE(body + 17 + (size_t)i * 6,     ips[i]);
        eseWrU16LE(body + 17 + (size_t)i * 6 + 4, ports[i]);
    }
    const size_t bodyLen = 16 + 1 + (size_t)count * 6;
    CSingleLock lock(&m_lock, TRUE);
    for (size_t i = 0; i < targets.size(); ++i) {
        std::shared_ptr<CLiveCircuit> circ;
        for (const auto& c : m_circuitRegistry.GetSnapshot()) {
            if (c->Id() == targets[i] && c->State() == CircuitState::Active &&
                c->m_role == CircuitRole::Relay) { circ = c; break; }
        }
        if (!circ) continue;
        TunnelRequestCtx ctx;
        ctx.circ   = circ;
        ctx.req_id = 0;   // unsolicited push
        SendReply(ctx, TUN_OP_LIVE_PEER_LIST, body, bodyLen);
    }
}
bool CLiveTunnel::SendBulkCellToPeer(CUpDownClient* peer, const uint8_t* bytes, size_t size)
{
    if (!bytes || size < Bulk::BULK_CELL_HEADER_BYTES
        || size > kad6::kK6ShapedTotal || !EseCanQueueBulkCells(peer, 1))
        return false;
    Packet* pkt = new Packet(OP_LIVE_BULK_CELL, (uint32)size, OP_EMULEPROT);
    memcpy(pkt->pBuffer, bytes, size);
    // Bulk lives on CEMSocket's standard queue. Its scheduler always drains
    // the control queue first, so CREATE/EXTEND, K6 RPCs, NACKs and teardown
    // cannot be trapped behind class-5 payload. The queue is independently
    // bounded above to preserve backpressure.
    peer->socket->SendPacket(pkt, false, static_cast<uint32>(size), false);
    m_metrics.RecordCellSent(size);
    return true;
}
bool CLiveTunnel::OnBulkCellReceived(const uint8_t* pkt, uint32_t size, CUpDownClient* fromPeer)
{
    CSingleLock lock(&m_lock, TRUE);
    m_metrics.RecordCellReceived(size);
    if (size == kad6::kK6ShapedTotal)
        return HandleK6ShapedCellLocked(pkt, size, fromPeer);

    Bulk::BulkCellHeader h;
    const uint8_t* payload = NULL;
    if (!Bulk::BulkCellParse(pkt, size, h, payload))
        return true;   // malformed -> consume + drop

    // Reverse forwarding: a bulk cell on a relay's OUTBOUND id is coming back from
    // hop2/exit -> re-add our hop1->V layer and relay to V (mirror of CELL_RELAY F-1).
    {
        auto relayCirc = m_circuitRegistry.FindRelayByOutgoingId(h.circ_id);
        if (relayCirc) {
            if (fromPeer != relayCirc->m_nextHopClient) return true;
            ForwardBulkCell_Reverse(relayCirc, h.bcmd, h.nonce_seq, payload, h.length);
            return true;
        }
    }

    // Terminating end (viewer/originator): decode + reassemble.
    std::shared_ptr<CLiveCircuit> circ;
    for (const auto& c : m_circuitRegistry.GetSnapshot())
        if (c->Id() == h.circ_id) { circ = c; break; }
    if (!circ) return true;
    if (circ->m_role == CircuitRole::Originator
        && fromPeer == circ->m_firstHopClient)
        DeliverBulkData(circ, h.nonce_seq, payload, h.length);
    return true;
}

bool CLiveTunnel::ForwardBulkCell_Reverse(std::shared_ptr<CLiveCircuit>& circ, uint8_t bcmd,
                                          uint64_t nonce_seq, const uint8_t* payload, size_t payloadLen)
{
    if (!circ || circ->m_role != CircuitRole::Relay || !circ->m_prevHopClient) return false;
    if (circ->HopCount() < 1) return false;

    std::vector<uint8_t> wrapped(payloadLen + 16);
    size_t wrappedLen = 0;
    if (!circ->EncryptOneLayerExplicit(0, nonce_seq, payload, payloadLen, wrapped.data(), wrappedLen))
        return false;

    Bulk::BulkCellHeader h;
    h.circ_id   = circ->Id();
    h.bcmd      = bcmd;
    h.nonce_seq = nonce_seq;
    std::vector<uint8_t> cell;
    Bulk::BulkCellPack(h, wrapped.data(), wrappedLen, cell);
    return SendBulkCellToPeer(circ->m_prevHopClient, cell.data(), cell.size());
}

bool CLiveTunnel::SendBulkCellReverse(std::shared_ptr<CLiveCircuit>& circ, uint8_t bcmd,
                                      const uint8_t* plain, size_t plainLen)
{
    if (!circ || circ->m_role != CircuitRole::Relay || !circ->m_prevHopClient) return false;
    if (circ->HopCount() < 1) return false;

    // Idle class-5 links retire after a randomized tail. A new terminal
    // record reactivates the already signed bucket reservation; it must never
    // fall through to legacy variable-length bulk.
    if (circ->m_shape_bucket_kib != 0 && circ->m_remoteHopIndex == 2
        && !EnsureK6ShaperLocked(circ, 1, circ->m_shape_bucket_kib))
        return false;

    // A shaped subscription turns arrival-triggered writes into bounded
    // reservoir inserts. The 10 ms class-5 heartbeat alone decides when a
    // data or padding record leaves this mapping.
    if (m_scheduler.HasShapedLink(circ->Id())) {
        if (bcmd != Bulk::BULK_DATA || !plain
            || plainLen > kad6::kK6ShapedInnerMax)
            return false;
        kad6::K6ShapedBulkPlainV1 shaped;
        shaped.kind = static_cast<uint8_t>(kad6::K6BulkKind::Data);
        if (plainLen >= 16) {
            shaped.stream_id = eseRdU64LE(plain) ^ eseRdU64LE(plain + 8);
            if (shaped.stream_id == 0) shaped.stream_id = 1;
        } else {
            shaped.stream_id = circ->Id();
        }
        if (plainLen >= 20) shaped.logical_sequence = eseRdU32LE(plain + 16);
        shaped.inner.assign(plain, plain + plainLen);
        LiveShapedQueuedRecord record;
        record.terminal = true;
        if (kad6::EncodeK6ShapedPlain(shaped, MakeKad6HostCryptoHooks(), record.bytes)
            != kad6::Kad6Status::Ok)
            return false;
        return QueueK6ShapedRecordLocked(circ, shaped.stream_id, std::move(record));
    }

    if (circ->m_bulk_nonce_send == 0) {
        uint8_t random[8];
        SecureRandomBytes(random, sizeof random);
        circ->m_bulk_nonce_send = eseRdU64LE(random);
        if (circ->m_bulk_nonce_send == 0) circ->m_bulk_nonce_send = 1;
    }
    const uint64_t nonce_seq = circ->m_bulk_nonce_send++;   // strictly increasing per (circ, dir)
    std::vector<uint8_t> wrapped(plainLen + 16);
    size_t wrappedLen = 0;
    if (!circ->EncryptOneLayerExplicit(0, nonce_seq, plain, plainLen, wrapped.data(), wrappedLen))
        return false;

    Bulk::BulkCellHeader h;
    h.circ_id   = circ->Id();
    h.bcmd      = bcmd;
    h.nonce_seq = nonce_seq;
    std::vector<uint8_t> cell;
    Bulk::BulkCellPack(h, wrapped.data(), wrappedLen, cell);
    return SendBulkCellToPeer(circ->m_prevHopClient, cell.data(), cell.size());
}

void CLiveTunnel::DeliverBulkData(std::shared_ptr<CLiveCircuit>& circ, uint64_t nonce_seq,
                                  const uint8_t* payload, size_t payloadLen)
{
    if (!circ) return;
    // Replay guard (per terminating circuit, recv direction) — out-of-order accepted.
    if (!m_exitServices.LT7AcceptReplay(circ->Id(), nonce_seq)) return;
    std::vector<uint8_t> plain(payloadLen ? payloadLen : 1);
    size_t plainLen = 0;
    if (!circ->OnionDecryptAllExplicit(nonce_seq, payload, payloadLen,
                                       plain.data(), plain.size(), plainLen))
        return;   // AEAD auth fail / bad cell -> drop

    DeliverBulkPlain(plain.data(), plainLen);
}

void CLiveTunnel::DeliverBulkPlain(const uint8_t* plain, size_t plainLen)
{
    if (!plain) return;
    Bulk::BulkDataHeader bh;
    const uint8_t* symbol = NULL;
    if (!Bulk::BulkDataParse(plain, plainLen, bh, symbol)) return;
    if (bh.msg_len == 0 || bh.n_blocks == 0) return;

    const std::string key = BulkReasmKey(bh.stream_key, bh.seq);
    BulkReasmEntry& e = LT7_STATE(BulkReassemblyState)[key];
    if (e.done) return;   // segment already rebuilt

    if (!e.haveLayout) {
        if (!Bulk::BulkComputeLayout(bh.msg_len, e.layout)) { LT7_STATE(BulkReassemblyState).erase(key); return; }
        memcpy(e.streamKey, bh.stream_key, 16);   // E3.5 NACK addressing
        e.seq = bh.seq;
        e.msg_len = bh.msg_len;
        e.n_blocks = bh.n_blocks;
        e.r = bh.r;
        e.first_seen_tick = GetTickCount();
        e.blockRecv.assign(e.layout.n_blocks, 0);
        e.haveLayout = true;
    }
    if (bh.block_idx >= e.layout.n_blocks) return;   // foreign block index

    // dedup by (block_idx, symbol_idx)
    for (const auto& s : e.symbols)
        if (s.block_idx == bh.block_idx && s.symbol_idx == bh.symbol_idx) return;

    Bulk::BulkSymbol bs;
    bs.block_idx  = bh.block_idx;
    bs.symbol_idx = bh.symbol_idx;
    bs.k          = bh.k;
    bs.data.assign(symbol, symbol + Bulk::BULK_SYMBOL_BYTES);
    e.symbols.push_back(std::move(bs));
    e.blockRecv[bh.block_idx]++;

    // Decode only once EVERY block has >= k_b symbols (bounds the 3 MB decode buffer).
    for (int b = 0; b < e.layout.n_blocks; ++b)
        if (e.blockRecv[b] < e.layout.k[b]) return;

    std::vector<uint8_t> record;
    if (Bulk::BulkDecodeSegment(e.symbols, e.msg_len, e.r, record)) {
        e.done = true;
        e.symbols.clear();              // free ~3 MB; keep the entry as a 'done' marker
        e.blockRecv.clear();
        AddDebugLogLine(false,
            _T("LiveTunnel: bulk segment rebuilt seq=%u (%u bytes, %u blocks) via FEC — injecting"),
            bh.seq, (unsigned)record.size(), (unsigned)e.n_blocks);
        // E3.4-final — hand the byte-identical signed CHUNK_V2 record to the EXISTING viewer
        // verify+inject path. IngestChunkPayload runs the SAME sha256 + Ed25519 verify the
        // direct path uses (against the pinned pubkey, LiveStreamManager.cpp:1609+) and, on
        // the viewer (m_bViewing), buffers + writes HLS so VLC plays it. NULL peer = no
        // per-peer credit (bulk arrives STRIPED across multi-hop circuits, not from one
        // CUpDownClient); PeerId(NULL)/GetOrCreateTrust(NULL) are null-safe (the one peer->
        // deref past the gate is already guarded). Backward-compat: only viewers that
        // negotiated bulk circuits ever reach here.
        if (theApp.liveStreamManager && theApp.liveStreamManager->IsViewingLive())
            theApp.liveStreamManager->IngestChunkPayload(NULL, OP_LIVE_CHUNK_V2,
                                                         record.data(), (uint32)record.size());
    }
}

std::string CLiveTunnel::BulkReasmKey(const uint8_t streamKey[16], uint32_t seq)
{
    std::string s = LiveStreamKeyHex(streamKey);
    char tail[16];
    _snprintf_s(tail, sizeof tail, _TRUNCATE, ":%u", seq);
    return s + tail;
}

void CLiveTunnel::SweepBulkReasm()
{
    // A5 pattern: drop partial/done segments past the ring window, and replay windows
    // for circuits that no longer exist. Caller holds m_lock (called from Tick()).
    const DWORD now = GetTickCount();
    const DWORD BULK_REASM_TTL_MS = 40000;   // > 16 segments x 2 s ring (32 s) + slack
    for (auto it = LT7_STATE(BulkReassemblyState).begin(); it != LT7_STATE(BulkReassemblyState).end(); ) {
        BulkReasmEntry& e = it->second;
        if (now - e.first_seen_tick > BULK_REASM_TTL_MS) { it = LT7_STATE(BulkReassemblyState).erase(it); continue; }
        // E3.5 (viewer) — still incomplete past the NACK deadline -> request a re-push of the
        // blocks short of k_b (throttled per entry). The exit re-encodes from its retained record.
        if (!e.done && e.haveLayout &&
            ese::live::LiveStreamRecovery::ShouldSendNack(
                now, e.first_seen_tick, e.lastNackTick)) {
            std::vector<std::pair<uint32_t, uint8_t>> missing;
            const std::vector<std::uint8_t> missingBlocks =
                ese::live::LiveStreamRecovery::MissingFecBlocks(
                    e.layout.k, e.layout.n_blocks, e.blockRecv);
            for (const std::uint8_t block : missingBlocks)
                missing.push_back(std::make_pair(e.seq, block));
            if (!missing.empty() && SendBulkNack(e.streamKey, missing))
                e.lastNackTick = now;
        }
        ++it;
    }
    // E3.5 — sweep retained exit records past the ring window (oldest at the front).
    while (!LT7_STATE(ProxyRecentRecords).empty() && now - LT7_STATE(ProxyRecentRecords).front().tick > BULK_REASM_TTL_MS)
        LT7_STATE(ProxyRecentRecords).pop_front();
    for (auto it = LT7_STATE(BulkReplayState).begin(); it != LT7_STATE(BulkReplayState).end(); ) {
        bool alive = false;
        if (m_circuitRegistry.FindById(it->first)) alive = true;
        if (!alive) it = LT7_STATE(BulkReplayState).erase(it); else ++it;
    }
    std::vector<uint32_t> liveShapeCircuits;
    for (const auto& circuit : m_circuitRegistry.GetSnapshot())
        if (circuit->State() != CircuitState::Destroyed)
            liveShapeCircuits.push_back(circuit->Id());
    m_scheduler.SweepShapedReplay(liveShapeCircuits);

    // v8.1.2 E3.2 — sweep explicit bulk subs: drop those whose circuit died or that went
    // silent past the TTL (the viewer re-subscribes on each refresh; the exit dedups by circ_id).
    {
        CSingleLock pl(&m_pendingLock, TRUE);
        for (auto it = LT7_STATE(BulkSubscriptions).begin(); it != LT7_STATE(BulkSubscriptions).end(); ) {
            std::vector<BulkSub>& subs = it->second;
            for (auto i = subs.begin(); i != subs.end(); ) {
                bool alive = false;
                if (m_circuitRegistry.FindById(i->circ_id)) alive = true;
                if (!alive || (DWORD)(now - i->lastSeen) > Bulk::BULK_SUB_TTL_MS) i = subs.erase(i);
                else ++i;
            }
            if (subs.empty()) it = LT7_STATE(BulkSubscriptions).erase(it); else ++it;
        }
    }
}

bool CLiveTunnel::IsExitProxying(const uint8_t streamKey[16]) const
{
    const std::string hex = LiveStreamKeyHex(streamKey);
    std::lock_guard<std::mutex> lk(LT7_STATE(ProxyIngestMutex));   // leaf
    return LT7_STATE(ProxyKeySet).find(hex) != LT7_STATE(ProxyKeySet).end();
}

void CLiveTunnel::ExitProxyOnWholeChunk(const uint8_t streamKey[16],
                                        const uint8_t* record, uint32_t recordLen)
{
    (void)streamKey;
    if (!record || recordLen < 20 || recordLen > ESE_FRAG_MAX_TOTAL) return;
    std::lock_guard<std::mutex> lk(LT7_STATE(ProxyIngestMutex));   // leaf
    LT7_STATE(ProxyReadyQueue).emplace_back(record, record + recordLen);
    while (LT7_STATE(ProxyReadyQueue).size() > 64) LT7_STATE(ProxyReadyQueue).pop_front();   // bound (DoS)
}

void CLiveTunnel::ExitProxyOnFragment(const uint8_t streamKey[16], uint32_t seqNum,
                                      uint16_t fragIndex, uint16_t fragCount, uint32_t totalLen,
                                      const uint8_t* fragData, uint32_t fragLen)
{
    // Validate (mirror of the viewer's checks — this runs BEFORE them).
    if (fragCount < 1 || fragCount > ESE_FRAG_MAX_COUNT) return;
    if (fragIndex >= fragCount) return;
    if (totalLen == 0 || totalLen > ESE_FRAG_MAX_TOTAL) return;
    if (!fragData) return;
    const uint32_t off = (uint32_t)fragIndex * ESE_FRAG_PAYLOAD;
    if (fragLen > ESE_FRAG_PAYLOAD || off > totalLen || off + fragLen > totalLen) return;

    char tail[16];
    _snprintf_s(tail, sizeof tail, _TRUNCATE, ":%u", seqNum);
    const std::string key = LiveStreamKeyHex(streamKey) + tail;

    (void)m_exitServices.LT7AcceptFragment(key,fragIndex,fragCount,totalLen,fragData,fragLen,off,GetTickCount());
}

void CLiveTunnel::RefreshProxyKeys()
{
    // Rebuild the leaf-locked mirror of which streams we exit-proxy. Called from Tick()
    // (m_lock held); m_pendingLock guards LT7_STATE(ExitLiveSubscriptions). Order: m_lock -> m_pendingLock
    // -> LT7_STATE(ProxyIngestMutex) (leaf), consistent with the rest of the tunnel.
    std::set<std::string> keys;
    {
        CSingleLock pl(&m_pendingLock, TRUE);
        for (const auto& kv : LT7_STATE(ExitLiveSubscriptions))
            if (!kv.second.circuits.empty()) keys.insert(kv.first);
        for (const auto& kv : LT7_STATE(BulkSubscriptions))       // E3.2 — also proxy streams with explicit bulk subs
            if (!kv.second.empty()) keys.insert(kv.first);
    }
    std::lock_guard<std::mutex> lk(LT7_STATE(ProxyIngestMutex));
    LT7_STATE(ProxyKeySet).swap(keys);
}

void CLiveTunnel::ProcessProxyIngest()
{
    // MAIN THREAD, from Tick() under m_lock. Refresh the proxy-key mirror, drain ready
    // records, FEC-encode each and push its symbols across the stream's subscribed circuits.
    RefreshProxyKeys();

    std::deque<std::vector<uint8_t>> ready;
    {
        std::lock_guard<std::mutex> lk(LT7_STATE(ProxyIngestMutex));   // leaf
        if (LT7_STATE(ProxyReadyQueue).empty()) return;
        ready.swap(LT7_STATE(ProxyReadyQueue));
    }

    for (std::vector<uint8_t>& record : ready) {
        if (record.size() < 20) continue;
        uint8_t streamKey[16];
        memcpy(streamKey, record.data(), 16);
        const uint32_t seq = eseRdU32LE(record.data() + 16);
        const std::string hex = LiveStreamKeyHex(streamKey);
        const int r = ProxyAdaptiveR(hex);   // E4' — parity adapts to the measured NACK rate

        std::vector<Bulk::BulkSymbol> symbols;
        if (!Bulk::BulkEncodeSegment(record.data(), record.size(), r, symbols))
            continue;
        Bulk::BulkLayout layout;
        if (!Bulk::BulkComputeLayout((uint32_t)record.size(), layout)) continue;

        // Build the push "sessions" — each is one viewer's circuit list. Prefer EXPLICIT bulk
        // subs (E3.2, grouped by session_id -> we can stripe across a viewer's circuits); fall
        // back to the C7 control subs (1 circuit each -> full k+r). Snapshot under m_pendingLock.
        std::vector<std::vector<uint32_t>> sessions;
        {
            CSingleLock pl(&m_pendingLock, TRUE);
            auto bit = LT7_STATE(BulkSubscriptions).find(hex);
            if (bit != LT7_STATE(BulkSubscriptions).end() && !bit->second.empty()) {
                std::map<uint32_t, std::vector<uint32_t>> bySession;
                for (const BulkSub& s : bit->second) bySession[s.session_id].push_back(s.circ_id);
                for (auto& kv : bySession) sessions.push_back(std::move(kv.second));
            } else {
                auto eit = LT7_STATE(ExitLiveSubscriptions).find(hex);
                if (eit != LT7_STATE(ExitLiveSubscriptions).end())
                    for (const auto& c : eit->second.circuits)
                        sessions.push_back(std::vector<uint32_t>(1, c.first));
            }
        }
        if (sessions.empty()) continue;

        // For each viewer (session), STRIPE the segment's symbols INTERLEAVED across its
        // circuits (B5): symbol with (block_idx b, symbol_idx s) -> circuit[(s + b) mod C], so
        // no circuit holds a whole block and a circuit death loses <= ceil((k+r)/C)/block. With
        // C==1 (fallback / single-circuit viewer) the whole k+r goes down the one circuit.
        // m_lock is held by Tick -> the circuit registry is safe to read.
        size_t pushed = 0;
        for (const std::vector<uint32_t>& sess : sessions) {
            const size_t C = sess.size();
            if (C == 0) continue;
            std::vector<std::shared_ptr<CLiveCircuit>> sc(C);
            for (size_t i = 0; i < C; ++i)
                sc[i] = m_circuitRegistry.FindById(sess[i]);
            for (const Bulk::BulkSymbol& s : symbols) {
                std::shared_ptr<CLiveCircuit>& cc = sc[((size_t)s.symbol_idx + s.block_idx) % C];
                if (!cc || cc->m_role != CircuitRole::Relay) continue;
                // v8.1.2 E7.2 (backpressure) — don't pile cells onto a hop socket that is
                // already backed up (slow viewer/circuit). Skipping bounds the exit's send-
                // queue RAM; the viewer recovers the skipped symbol via FEC parity or a NACK
                // (E3.5). For a multi-circuit viewer the other circuits still carry their stripe.
                if (cc->m_prevHopClient && cc->m_prevHopClient->socket
                    && cc->m_prevHopClient->socket->IsBusyQuickCheck()) continue;
                Bulk::BulkDataHeader bh;
                memcpy(bh.stream_key, streamKey, 16);
                bh.seq = seq; bh.block_idx = s.block_idx; bh.n_blocks = (uint8_t)layout.n_blocks;
                bh.symbol_idx = s.symbol_idx; bh.k = s.k; bh.r = (uint8_t)r;
                bh.flags = 0; bh.msg_len = (uint32_t)record.size();
                std::vector<uint8_t> payload;
                Bulk::BulkDataPack(bh, s.data.data(), payload);
                SendBulkCellReverse(cc, Bulk::BULK_DATA, payload.data(), payload.size());
                ++pushed;
            }
        }
        if (pushed)
            AddDebugLogLine(false,
                _T("LiveTunnel: exit pushed bulk seq=%u — %u symbols across %u viewer-session(s), %u blocks (r=%d)"),
                seq, (unsigned)symbols.size(), (unsigned)sessions.size(), (unsigned)layout.n_blocks, r);

        // E3.5 — retain the whole record so a viewer that fails to reassemble can NACK a
        // re-push (PushBlockToCircuit re-encodes on demand). Bounded ring (~16 segs x streams).
        ProxyRecentRec rec;
        memcpy(rec.streamKey, streamKey, 16);
        rec.seq = seq; rec.tick = GetTickCount(); rec.record = std::move(record);
        LT7_STATE(ProxyRecentRecords).push_back(std::move(rec));
        while (LT7_STATE(ProxyRecentRecords).size() > 48) LT7_STATE(ProxyRecentRecords).pop_front();
    }
}

void CLiveTunnel::ExitHandle_BulkSubscribe(const TunnelRequestCtx& ctx)
{
    // body v1: stream_key 16 + flags 1 + r_pref 1 + session_id 4
    // body v2: v1 + class5_bucket_kib u16. Unknown/invalid shaped requests
    // fail closed; they are never silently registered as unshaped bulk.
    if (!ctx.circ || !ctx.body || ctx.bodyLen < 22) return;
    uint8_t streamKey[16];
    memcpy(streamKey, ctx.body, 16);
    const uint8_t  r_pref    = ctx.body[17];
    const uint32_t sessionId = eseRdU32LE(ctx.body + 18);
    const bool shaped = (ctx.body[16] & K6_BULK_SUB_FLAG_SHAPED) != 0;
    const uint16_t shapeBucket = (shaped && ctx.bodyLen >= 24)
        ? eseRdU16LE(ctx.body + 22) : 0;
    if (shaped && (ctx.bodyLen < 24
        || !EnsureK6ShaperLocked(ctx.circ, 1, shapeBucket))) {
        AddDebugLogLine(false,
            _T("Kad6 K6-6: rejected malformed/unavailable class-5 subscription circ=0x%08x"),
            ctx.circ->Id());
        return;
    }
    const std::string hex = LiveStreamKeyHex(streamKey);
    const uint32_t cid = ctx.circ->Id();
    const DWORD now = GetTickCount();

    CSingleLock pl(&m_pendingLock, TRUE);
    std::vector<BulkSub>& subs = LT7_STATE(BulkSubscriptions)[hex];
    bool found = false;
    for (BulkSub& s : subs)
        if (s.circ_id == cid) {
            s.session_id = sessionId; s.r_pref = r_pref; s.shaped = shaped;
            s.shape_bucket_kib = shapeBucket; s.lastSeen = now;
            found = true; break;
        }
    if (!found) {
        if (subs.size() < 32) {                  // per-stream sub cap (DoS)
            BulkSub s; s.circ_id = cid; s.session_id = sessionId;
            s.r_pref = r_pref; s.shaped = shaped;
            s.shape_bucket_kib = shapeBucket; s.lastSeen = now;
            subs.push_back(s);
        }
    }
    AddDebugLogLine(false, _T("LiveTunnel: [E3.2] bulk SUBSCRIBE circ=0x%08x session=0x%08x r=%u (%u sub(s))"),
        cid, sessionId, (unsigned)r_pref, (unsigned)subs.size());
}

void CLiveTunnel::ExitHandle_BulkUnsub(const TunnelRequestCtx& ctx)
{
    if (!ctx.circ || !ctx.body || ctx.bodyLen < 16) return;
    uint8_t streamKey[16];
    memcpy(streamKey, ctx.body, 16);
    const std::string hex = LiveStreamKeyHex(streamKey);
    const uint32_t cid = ctx.circ->Id();
    CSingleLock pl(&m_pendingLock, TRUE);
    auto it = LT7_STATE(BulkSubscriptions).find(hex);
    if (it == LT7_STATE(BulkSubscriptions).end()) return;
    std::vector<BulkSub>& subs = it->second;
    for (auto i = subs.begin(); i != subs.end(); )
        if (i->circ_id == cid) i = subs.erase(i); else ++i;
    if (subs.empty()) LT7_STATE(BulkSubscriptions).erase(it);
}

size_t CLiveTunnel::BulkSubscribe(const uint8_t streamKey[16])
{
    CSingleLock lock(&m_lock, TRUE);
    // One fresh session_id groups ALL of this viewer's bulk circuits so the exit stripes
    // a segment's symbols across them (E3.2). Strict three-hop circuits add
    // the class-5 flag + bucket and refuse any unshaped downgrade.
    const uint32_t sessionId = NewCircuitId();

    size_t sent = 0;
    for (const auto& c : m_circuitRegistry.GetSnapshot()) {
        if (c->m_role != CircuitRole::Originator) continue;
        if (c->State() != CircuitState::Active) continue;
        if (c->HopCount() < 1 || !c->m_bulk_ok) continue;   // only bulk-capable Active circuits
        const bool shaped = c->m_strict3 && c->m_path_diverse
            && c->m_shaped_ok && K6ShapeValidBucket(c->m_shape_bucket_kib)
            && c->HopCount() == 3;
        if (c->m_strict3 && !shaped) continue;
        uint8_t body[24]{};
        memcpy(body, streamKey, 16);
        body[16] = shaped ? K6_BULK_SUB_FLAG_SHAPED : 0;
        body[17] = (uint8_t)Bulk::BULK_DEFAULT_R;
        eseWrU32LE(body + 18, sessionId);
        if (shaped) eseWrU16LE(body + 22, c->m_shape_bucket_kib);
        const size_t bodyLen = shaped ? sizeof body : 22;
        const size_t onion = c->HopCount() * 16;
        if (onion + SUB_HEADER_BYTES + FRAG_HEADER_BYTES >= CELL_PAYLOAD_MAX) continue;
        const size_t fragDataMax = CELL_PAYLOAD_MAX - onion - SUB_HEADER_BYTES - FRAG_HEADER_BYTES;
        std::vector<std::vector<uint8_t>> cells;
        if (!SplitIntoCells(TUN_OP_BULK_SUBSCRIBE, NewCircuitId(), body, bodyLen, fragDataMax, cells))
            continue;
        bool ok = true;
        for (auto& plain : cells) {
            uint8_t cellPayload[CELL_PAYLOAD_MAX];
            size_t cellLen = 0;
            if (!c->OnionEncrypt(plain.data(), plain.size(), cellPayload, cellLen)) { ok = false; break; }
            uint8_t cell[CELL_TOTAL_BYTES];
            if (!CellPack(c->Id(), CELL_RELAY, cellPayload, cellLen, cell)) { ok = false; break; }
            if (!c->m_firstHopClient || !SendCellToPeer(c->m_firstHopClient, cell)) { ok = false; break; }
        }
        if (ok) ++sent;
    }
    if (sent)
        AddDebugLogLine(false, _T("LiveTunnel: [E3.2] viewer bulk-subscribed on %u circuit(s), session=0x%08x"),
            (unsigned)sent, sessionId);
    return sent;
}

int CLiveTunnel::ProxyAdaptiveR(const std::string& hex)
{
    // E4' — adapt PARITY (not bitrate) to the measured NACK rate per stream (~10 s window):
    // no NACKs -> ease r down toward 2; light loss -> >=3; heavy -> up to BULK_MAX_R. Caller
    // holds m_lock.
    const DWORD now = GetTickCount();
    ProxyStreamCtl& c = LT7_STATE(ProxyControlState)[hex];
    std::uint32_t windowStart = c.windowStart;
    ese::live::LiveStreamRecovery::UpdateParityWindow(
        c.r, c.nackCount, windowStart, now);
    c.windowStart = windowStart;
    return c.r;
}

void CLiveTunnel::PushBlockToCircuit(std::shared_ptr<CLiveCircuit>& circ, const uint8_t streamKey[16],
                                     uint32_t seq, const std::vector<uint8_t>& record, int r, uint8_t blockIdx)
{
    if (!circ || record.size() < 20) return;
    Bulk::BulkLayout layout;
    if (!Bulk::BulkComputeLayout((uint32_t)record.size(), layout)) return;
    if (blockIdx >= layout.n_blocks) return;
    std::vector<Bulk::BulkSymbol> symbols;
    if (!Bulk::BulkEncodeSegment(record.data(), record.size(), r, symbols)) return;
    for (const Bulk::BulkSymbol& s : symbols) {
        if (s.block_idx != blockIdx) continue;
        Bulk::BulkDataHeader bh;
        memcpy(bh.stream_key, streamKey, 16);
        bh.seq = seq; bh.block_idx = s.block_idx; bh.n_blocks = (uint8_t)layout.n_blocks;
        bh.symbol_idx = s.symbol_idx; bh.k = s.k; bh.r = (uint8_t)r;
        bh.flags = 0; bh.msg_len = (uint32_t)record.size();
        std::vector<uint8_t> payload;
        Bulk::BulkDataPack(bh, s.data.data(), payload);
        SendBulkCellReverse(circ, Bulk::BULK_DATA, payload.data(), payload.size());
    }
}

void CLiveTunnel::ExitHandle_BulkNack(const TunnelRequestCtx& ctx)
{
    // body: stream_key 16 + count 1 + (seq 4 + block_idx 1)*count
    if (!ctx.circ || !ctx.body || ctx.bodyLen < 17) return;
    uint8_t streamKey[16];
    memcpy(streamKey, ctx.body, 16);
    const uint8_t count = ctx.body[16];
    if (count == 0 || (size_t)ctx.bodyLen < 17 + (size_t)count * 5) return;
    const std::string hex = LiveStreamKeyHex(streamKey);
    LT7_STATE(ProxyControlState)[hex].nackCount++;                  // E4' telemetry
    const int r = ProxyAdaptiveR(hex);
    std::shared_ptr<CLiveCircuit> circ = ctx.circ;
    for (uint8_t i = 0; i < count; ++i) {
        const uint8_t* ePtr = ctx.body + 17 + (size_t)i * 5;
        const uint32_t seq = eseRdU32LE(ePtr);
        const uint8_t  blk = ePtr[4];
        for (auto& rec : LT7_STATE(ProxyRecentRecords))
            if (rec.seq == seq && memcmp(rec.streamKey, streamKey, 16) == 0) {
                PushBlockToCircuit(circ, streamKey, seq, rec.record, r, blk);
                break;
            }
    }
    AddDebugLogLine(false, _T("LiveTunnel: [E3.5] bulk NACK %u block(s) re-pushed (r=%d)"),
        (unsigned)count, r);
}

bool CLiveTunnel::SendBulkNack(const uint8_t streamKey[16],
                               const std::vector<std::pair<uint32_t, uint8_t>>& missing)
{
    if (missing.empty() || missing.size() > 40) return false;   // caller holds m_lock
    std::vector<uint8_t> body;
    body.insert(body.end(), streamKey, streamKey + 16);
    body.push_back((uint8_t)missing.size());
    for (const auto& m : missing) {
        uint8_t tmp[4]; eseWrU32LE(tmp, m.first);
        body.insert(body.end(), tmp, tmp + 4);
        body.push_back(m.second);
    }
    for (const auto& c : m_circuitRegistry.GetSnapshot()) {
        if (c->m_role != CircuitRole::Originator || c->State() != CircuitState::Active) continue;
        if (c->HopCount() < 1 || !c->m_bulk_ok) continue;
        const size_t onion = c->HopCount() * 16;
        if (onion + SUB_HEADER_BYTES + FRAG_HEADER_BYTES >= CELL_PAYLOAD_MAX) continue;
        const size_t fragDataMax = CELL_PAYLOAD_MAX - onion - SUB_HEADER_BYTES - FRAG_HEADER_BYTES;
        std::vector<std::vector<uint8_t>> cells;
        if (!SplitIntoCells(TUN_OP_BULK_NACK, NewCircuitId(), body.data(), body.size(), fragDataMax, cells))
            continue;
        bool ok = true;
        for (auto& plain : cells) {
            uint8_t cp[CELL_PAYLOAD_MAX]; size_t cl = 0;
            if (!c->OnionEncrypt(plain.data(), plain.size(), cp, cl)) { ok = false; break; }
            uint8_t cell[CELL_TOTAL_BYTES];
            if (!CellPack(c->Id(), CELL_RELAY, cp, cl, cell)) { ok = false; break; }
            if (!c->m_firstHopClient || !SendCellToPeer(c->m_firstHopClient, cell)) { ok = false; break; }
        }
        if (ok) return true;
    }
    return false;
}

void CLiveTunnel::ProcessClass5Tick()
{
    struct Prepared {
        std::shared_ptr<CLiveCircuit> circuit;
        LiveShapedEmission emission;
    };
    const bool fairActive = ProcessK6FairTick();
    LiveShapedTickResult tick;
    std::vector<Prepared> prepared;
    {
        CSingleLock lock(&m_lock, TRUE);
        const std::vector<std::shared_ptr<CLiveCircuit>> circuits =
            m_circuitRegistry.GetSnapshot();
        std::vector<uint32_t> liveRelays;
        for (const auto& circ : circuits)
            if (circ->State() != CircuitState::Destroyed
                && circ->m_role == CircuitRole::Relay)
                liveRelays.push_back(circ->Id());
        tick = m_scheduler.PollShapedLinks(K6ShapeNowUs(), liveRelays, 8);
        auto findCircuit = [&](uint32_t circId) {
            for (const auto& circ : circuits)
                if (circ->Id() == circId)
                    return circ;
            return std::shared_ptr<CLiveCircuit>();
        };
        for (uint32_t circId : tick.exposed) {
            const auto circ = findCircuit(circId);
            if (circ) circ->m_traffic_shaping_exposed = true;
        }
        for (const LiveShapedTickWork& work : tick.work) {
            Prepared item;
            item.circuit = findCircuit(work.circ_id);
            if (!item.circuit || !PrepareK6ShapedEmissionLocked(
                    item.circuit, work.slot, item.emission)) {
                m_scheduler.MarkShapedExposed(work.circ_id);
                if (item.circuit)
                    item.circuit->m_traffic_shaping_exposed = true;
            } else {
                prepared.push_back(std::move(item));
            }
        }
        if (m_scheduler.ShouldStopClass5Timer(tick.has_links, fairActive))
            StopK6ShapeTimerLocked();
    }
    for (const LiveShapedRetirement& retired : tick.retired)
        AddDebugLogLine(false,
            _T("Kad6 K6-6: class-5 idle tail complete circ=0x%08x (%u epoch(s))"),
            retired.circ_id, static_cast<unsigned>(retired.idle_tail_epochs));
    for (const Prepared& item : prepared) {
        if (!EmitK6ShapedEmission(item.circuit, item.emission)) {
            CSingleLock lock(&m_lock, TRUE);
            m_scheduler.MarkShapedExposed(item.circuit->Id());
            item.circuit->m_traffic_shaping_exposed = true;
        }
    }
}
