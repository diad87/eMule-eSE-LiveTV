// this file is part of eMule eSE - LT8 search facade implementation
// Included once by LiveTunnel.cpp inside namespace eSELive.

bool EseBuildK6SearchStartFrame(const std::string& keyword, uint32_t reqId,
                                std::vector<uint8_t>& wire)
{
    wire.clear();
    if (keyword.empty() || keyword.size() > kad6::kK6SearchMaxQueryBytes ||
        !kad6::Kad6IsValidUtf8NoNul(
            reinterpret_cast<const kad6::Byte*>(keyword.data()), keyword.size()))
        return false;

    kad6::K6SearchStart start;
    start.search_kind = kad6::kK6SearchKindLive;
    start.network_mask = kad6::kK6NetMaskKad2;
    start.max_results = (uint16_t)TUN_SEARCH_MAX_RESULTS;
    start.deadline_ms = TUN_SEARCH_WINDOW_MS;
    start.query.assign(keyword.begin(), keyword.end());
    Kademlia::CUInt128 target;
    const CStringA keywordA(keyword.data(), (int)keyword.size());
    EseLiveGetKeywordHash(keywordA, &target);
    target.ToByteArray(start.target_hash.data());

    std::vector<uint8_t> body;
    if (kad6::EncodeK6SearchStart(start, body) != kad6::Kad6Status::Ok)
        return false;
    kad6::K6Frame frame;
    frame.msg_type = kad6::kK6MsgSearchStart;
    frame.flags = kad6::kK6FlagCancelable | kad6::kK6FlagLegacyKad2;
    frame.request_id = reqId;
    frame.body = std::move(body);
    return kad6::EncodeK6Frame(frame, wire) == kad6::Kad6Status::Ok;
}

bool CLiveTunnel::HandleK6SearchReply(const std::shared_ptr<CLiveCircuit>& circ,
                                      uint32_t req_id,
                                      const std::vector<uint8_t>& wire)
{
    kad6::K6Frame plan;
    return m_kadBridge.LT3PlanSearchReply(req_id, wire, plan) &&
        CKad6OriginSocket::LT3ExecuteSearchReply(*this, circ, plan, wire);
}

void CLiveTunnel::ExitHandle_KadSearch(const TunnelRequestCtx& ctx)
{
    std::string keyword((const char*)ctx.body, ctx.bodyLen);
    for (auto& ch : keyword) {
        if (ch >= 'A' && ch <= 'Z') ch = (char)(ch - 'A' + 'a');
    }

    CStringA resultStr;
    size_t matchCount = 0;
    const size_t MAX_HITS = 16;
    // Single-cell result: budget = payload room minus this circuit's onion
    // tags. Sprint B makes KAD results multi-cell (TUN_OP_KAD_RESULT_V2).
    const size_t hopOverhead = ctx.circ ? ctx.circ->HopCount() * 16 : 32;
    const size_t MAX_RESULT_BYTES =
        (CELL_PAYLOAD_MAX > SUB_HEADER_BYTES + hopOverhead)
            ? (CELL_PAYLOAD_MAX - SUB_HEADER_BYTES - hopOverhead) : 0;
    try {
        if (theApp.liveStreamManager) {
            CArray<LiveStreamEntry> entries;
            theApp.liveStreamManager->GetKadBridge().GetKnownStreams(entries);
            for (INT_PTR i = 0; i < entries.GetCount() && matchCount < MAX_HITS; ++i) {
                const auto& e = entries[i];
                CStringA titleA(e.title);
                CStringA titleLow = titleA;
                titleLow.MakeLower();
                if (titleLow.Find((LPCSTR)keyword.c_str()) < 0 && !keyword.empty())
                    continue;
                CStringA hit;
                hit.Format("%s|%u|%u;",
                    (LPCSTR)titleA, (unsigned)e.bitrate, (unsigned)e.viewerCount);
                if ((size_t)(resultStr.GetLength() + hit.GetLength()) > MAX_RESULT_BYTES)
                    break;
                resultStr += hit;
                ++matchCount;
            }
        }
    } catch (...) {}

    SendReply(ctx, TUN_OP_KAD_RESULT,
              (const uint8_t*)(LPCSTR)resultStr, (size_t)resultStr.GetLength());
}

void CLiveTunnel::ExitHandle_KadSearchV2(const TunnelRequestCtx& ctx)
{
    if (!ctx.circ) return;
    // body = [flags u8][kw_len u16 LE][keyword UTF-8] (breakdown 2.2); also
    // accept a bare keyword (no header) for forward-compat.
    std::string keyword;
    if (ctx.bodyLen >= 3) {
        uint16_t kwLen = (uint16_t)ctx.body[1] | ((uint16_t)ctx.body[2] << 8);
        size_t avail = ctx.bodyLen - 3;
        if (kwLen > avail) kwLen = (uint16_t)avail;
        keyword.assign((const char*)ctx.body + 3, kwLen);
    } else {
        keyword.assign((const char*)ctx.body, ctx.bodyLen);
    }
    for (auto& ch : keyword)
        if (ch >= 'A' && ch <= 'Z') ch = (char)(ch - 'A' + 'a');

    if (!BeginExitOperation(ctx, TUN_OP_KAD_RESULT_V2))
        return;

    TunnelSearchJob job;
    job.circ_id  = ctx.circ->Id();
    job.req_id   = ctx.req_id;
    job.keyword  = keyword;
    job.started  = GetTickCount();
    job.deadline = job.started + TUN_SEARCH_WINDOW_MS;

    // Fire the real dual-namespace search (main thread). The rate-limit /
    // cooldown inside SearchStreams protects the exit from being used as a Kad
    // amplifier; if it declines, kadSearchIds stays empty and we just serve
    // whatever the directory already holds when the window elapses.
    try {
        CString kw = EseUtf8CString(keyword);
        // v8.1 D1 - forceDirect=true: the exit MUST query Kad from its OWN IP,
        // never re-enter the tunnel branch (would cascade out our circuit).
        m_kadBridge.SearchStreams(kw, &job.kadSearchIds, /*forceDirect*/true);
    } catch (...) {}

    CSingleLock pl(&m_pendingLock, TRUE);
    m_relayDispatcher.LT8AddJob(LiveRequestKey(job.circ_id,job.req_id),job);
}

void CLiveTunnel::ExitHandle_KadCancel(const TunnelRequestCtx& ctx)
{
    if (!ctx.circ) return;
    const uint64_t key = LiveRequestKey(ctx.circ->Id(), ctx.req_id);
    TunnelSearchJob job;
    bool found = false;
    {
        CSingleLock pl(&m_pendingLock, TRUE);
        found=m_relayDispatcher.LT8TakeJob(key,job);
    }
    if (found) StopSearchJobKad(job);
    AbortExitOperation(ctx.circ->Id(), ctx.req_id);
}

void CLiveTunnel::ExitHandle_Kad6Gateway(const TunnelRequestCtx& ctx)
{
    if (!thePrefs.GetEseV9Experimental() || (g_uEseCapsRuntime & ESE_CAP_KAD6) == 0 || !ctx.circ || !ctx.body || ctx.bodyLen == 0) return;
    kad6::K6Frame plan;
    if (!m_kadBridge.LT3PlanExitGateway(ctx.req_id, ctx.body, ctx.bodyLen, plan)) {
        m_metrics.Add(kad6::K6MetricFamily::AuthFailTotal, 2, 0, 0, 1, static_cast<uint64>(time(NULL)));
        return;
    }
    CKad6OriginSocket::LT3ExecuteExitGateway(*this, ctx, plan);
}

bool CLiveTunnel::OnKad6GatewaySourceResult(uint32_t circuitId, uint32_t requestId,
                                            const uint8_t userHash[16], uint8_t sourceType,
                                            uint32_t ip, uint16_t tcpPort, uint16_t udpPort,
                                            uint8_t cryptOptions, uint16_t reachCaps,
                                            const uint8_t* ipv6OrNull)
{
    if (circuitId == 0 || requestId == 0 || userHash == NULL || tcpPort == 0 ||
        (sourceType != 1 && sourceType != 4))
        return false; // LowID/callback authority is intentionally not virtualized.

    TunnelSearchJob::SourceCandidate candidate;
    memcpy(candidate.userHash.data(), userHash, candidate.userHash.size());
    candidate.sourceType = sourceType;
    candidate.cryptOptions = cryptOptions;
    candidate.reachCaps = reachCaps;
    candidate.networkOrigin = kad6::kK6NetOriginKad2;
    candidate.provenance = kad6::K6Provenance::KadResult;
    candidate.score = 100 + (ipv6OrNull != NULL ? 10 : 0) +
        ((reachCaps & 0x0001u) != 0 ? 5 : 0);
    candidate.endpoint.tcp_port = tcpPort;
    candidate.endpoint.udp_port = udpPort;
    candidate.endpoint.transport_flags = kad6::kK6EpTcpEd2k;
    candidate.endpoint.valid_until = static_cast<uint64>(time(NULL)) +
        kad6::kK6TicketMaxTtlSeconds;
    if (ipv6OrNull != NULL) {
        candidate.endpoint.addr.family = kad6::Kad6Address::Family::IPv6;
        memcpy(candidate.endpoint.addr.addr.data(), ipv6OrNull, 16);
    } else if (ip != 0) {
        candidate.endpoint.addr.family = kad6::Kad6Address::Family::IPv4;
        candidate.endpoint.addr.addr = {static_cast<uint8_t>(ip),
            static_cast<uint8_t>(ip >> 8), static_cast<uint8_t>(ip >> 16),
            static_cast<uint8_t>(ip >> 24)};
    } else {
        return false;
    }
    if (!K6AllowTicketTarget(this,
            static_cast<kad6::Byte>(kad6::K6TicketService::Ed2kTcp), candidate.endpoint)) {
        m_metrics.Add(kad6::K6MetricFamily::SourceCandidateTotal,
            0, 1, 0, 1, static_cast<uint64>(time(NULL)));
        return false;
    }

    CSingleLock pl(&m_pendingLock, TRUE);
    const uint64_t key=LiveRequestKey(circuitId,requestId);TunnelSearchJob job;
    if (!m_relayDispatcher.LT8FindJob(key,job) ||
        job.searchKind != kad6::kK6SearchKindSourceHash ||
        job.sourceCandidates.size() >= job.maxResults)
        return false;
    for (const auto& old : job.sourceCandidates) {
        if (old.userHash == candidate.userHash && old.endpoint.addr == candidate.endpoint.addr &&
            old.endpoint.tcp_port == candidate.endpoint.tcp_port) {
            m_metrics.Add(kad6::K6MetricFamily::SourceCandidateTotal,
                0, 1, 0, 1, static_cast<uint64>(time(NULL)));
            return false;
        }
    }
    candidate.score = m_peerState.ApplySourceScore(candidate.score,
        BuildLiveSourceEndpointKey(candidate.endpoint, candidate.networkOrigin));
    job.sourceCandidates.push_back(std::move(candidate));
    const size_t count = job.sourceCandidates.size();
    const double elapsed = static_cast<double>(GetTickCount() - job.started);
    if (!job.firstSourceMetric) {
        job.firstSourceMetric = true;
        m_metrics.Observe(kad6::K6MetricFamily::SearchLatencyMs,
            0, 0, 0, elapsed, static_cast<uint64>(time(NULL)));
    }
    if (count >= 5 && !job.fiveSourceMetric) {
        job.fiveSourceMetric = true;
        m_metrics.Observe(kad6::K6MetricFamily::SearchLatencyMs,
            1, 0, 0, elapsed, static_cast<uint64>(time(NULL)));
    }
    m_metrics.Add(kad6::K6MetricFamily::SourceCandidateTotal,
        0, 0, 0, 1, static_cast<uint64>(time(NULL)));
    return m_relayDispatcher.LT8UpdateJob(key,job);
}

bool CLiveTunnel::OnKad6NativeSourceRecord(uint32_t circuitId,
                                            uint32_t requestId,
                                            const kad6::K6SourceRecord& record)
{
    if (circuitId == 0 || requestId == 0 || record.exits.empty()) return false;
    const uint64 now = static_cast<uint64>(time(NULL));
    const kad6::Kad6CryptoHooks crypto = MakeKad6HostCryptoHooks();
    if (kad6::VerifyK6SourceRecord(crypto, record) != kad6::Kad6Status::Ok) {
        m_metrics.Add(kad6::K6MetricFamily::SourceCandidateTotal,
            1, 1, 0, 1, now);
        return false;
    }
    if (kad6::K6SourceRecordCheckFresh(record, now) != kad6::Kad6Status::Ok) {
        m_metrics.Add(kad6::K6MetricFamily::SourceStaleTotal,
            1, 0, 0, 1, now);
        return false;
    }
    std::vector<uint8_t> canonical;
    kad6::Hash32 digest{};
    if (kad6::EncodeK6SourceRecord(record, canonical) != kad6::Kad6Status::Ok ||
        !crypto.sha256 || !crypto.sha256(canonical.data(), canonical.size(), digest.data()))
        return false;

    bool inserted = false,changed=false;
    CSingleLock pl(&m_pendingLock, TRUE);
    const uint64_t key=LiveRequestKey(circuitId,requestId);TunnelSearchJob job;
    if (!m_relayDispatcher.LT8FindJob(key,job) ||
        job.searchKind != kad6::kK6SearchKindSourceHash ||
        job.targetHash != record.object_hash)
        return false;

    for (const kad6::K6ExitDescriptor& exit : record.exits) {
        if (exit.exit_expires_at <= now || exit.endpoint.valid_until <= now ||
            exit.endpoint.tcp_port == 0 ||
            !K6AllowTicketTarget(this,
                static_cast<kad6::Byte>(kad6::K6TicketService::Ed2kTcp),
                exit.endpoint))
            continue;
        TunnelSearchJob::SourceCandidate candidate;
        candidate.userHash = record.source_pseudonym;
        candidate.endpoint = exit.endpoint;
        candidate.sourceType = exit.endpoint.addr.family ==
            kad6::Kad6Address::Family::IPv6 ? 4 : 1;
        candidate.reachCaps = static_cast<uint16_t>(exit.caps & 0xffffu);
        candidate.networkOrigin = kad6::kK6NetOriginKad6;
        candidate.provenance = kad6::K6Provenance::Routing;
        candidate.provenanceDigest = digest;
        const uint64 remaining = (std::min<uint64>)(
            record.expires_at - now, 24ull * 60 * 60);
        candidate.score = 200u + static_cast<uint32_t>(remaining / 3600u) +
            (exit.endpoint.addr.family == kad6::Kad6Address::Family::IPv6 ? 10u : 0u);
        candidate.score = m_peerState.ApplySourceScore(candidate.score,
            BuildLiveSourceEndpointKey(candidate.endpoint, candidate.networkOrigin));

        bool duplicate = false;
        for (auto& old : job.sourceCandidates) {
            if (old.userHash == candidate.userHash &&
                old.endpoint.addr == candidate.endpoint.addr &&
                old.endpoint.tcp_port == candidate.endpoint.tcp_port) {
                if (candidate.score > old.score) {old=candidate;changed=true;}
                duplicate = true;
                break;
            }
        }
        if (duplicate) {
            m_metrics.Add(kad6::K6MetricFamily::SourceCandidateTotal,
                1, 1, 0, 1, now);
        }
        if (!duplicate && job.sourceCandidates.size() <
                (std::min<size_t>)(200, (std::max<size_t>)(
                    job.maxResults * 2u, job.maxResults + 8u))) {
            job.sourceCandidates.push_back(std::move(candidate));
            inserted = true;changed=true;
            const size_t count = job.sourceCandidates.size();
            const double elapsed = static_cast<double>(GetTickCount() - job.started);
            if (!job.firstSourceMetric) {
                job.firstSourceMetric = true;
                m_metrics.Observe(kad6::K6MetricFamily::SearchLatencyMs,
                    0, 1, 0, elapsed, now);
            }
            if (count >= 5 && !job.fiveSourceMetric) {
                job.fiveSourceMetric = true;
                m_metrics.Observe(kad6::K6MetricFamily::SearchLatencyMs,
                    1, 1, 0, elapsed, now);
            }
            m_metrics.Add(kad6::K6MetricFamily::SourceCandidateTotal,
                1, 0, 0, 1, now);
        }
    }
    if(changed&&!m_relayDispatcher.LT8UpdateJob(key,job))return false;
    return inserted;
}

void CLiveTunnel::OnKad6SourceLookupRpc(uint8_t alpha, uint8_t result)
{
    const uint8_t alphaBucket = alpha <= 3 ? 0 : (alpha <= 5 ? 1 : 2);
    if (result > 3) result = 2;
    m_metrics.Add(kad6::K6MetricFamily::SearchRpcTotal,
        1, alphaBucket, result, 1, static_cast<uint64>(time(NULL)));
}

void CLiveTunnel::FinishDueSearchJobs()
{
    const DWORD now = GetTickCount();
    std::vector<TunnelSearchJob> due;
    {
        CSingleLock pl(&m_pendingLock, TRUE);
        due=m_relayDispatcher.LT8TakeDue(now);
    }
    for (size_t i = 0; i < due.size(); ++i) {
        if (due[i].canonicalK6) {
            const uint16_t sent = SendK6SearchResults(due[i]);
            if (due[i].searchKind == kad6::kK6SearchKindSourceHash) {
                bool foundByNetwork[2] = {false, false};
                for (const auto& source : due[i].sourceCandidates)
                    foundByNetwork[LiveTunnelKadBridge::NetworkIndex(
                        source.networkOrigin, kad6::kK6NetOriginKad6)] = true;
                const bool startedByNetwork[2] = {
                    due[i].kad2LookupStarted, due[i].kad6LookupStarted};
                const uint8_t masks[2] = {kad6::kK6NetMaskKad2, kad6::kK6NetMaskKad6};
                const uint64_t metricNow = static_cast<uint64_t>(time(NULL));
                for (uint8_t network = 0; network < 2; ++network)
                    if ((due[i].networkMask & masks[network]) != 0)
                        m_metrics.Add(kad6::K6MetricFamily::SearchTotal,
                            network, foundByNetwork[network] ? 0 :
                                (startedByNetwork[network] ? 1 : 2),
                            0, 1, metricNow);
            }
            kad6::K6SearchEnd end;
            end.status = due[i].lookupStarted
                ? kad6::K6SearchEndStatus::Ok
                : (!due[i].kadReachable
                    ? kad6::K6SearchEndStatus::NoRoute
                    : (sent > 0 ? kad6::K6SearchEndStatus::Partial
                                : kad6::K6SearchEndStatus::Overloaded));
            end.result_count = sent;
            end.elapsed_ms = GetTickCount() - due[i].started;
            std::vector<uint8_t> endBody, endWire;
            if (kad6::EncodeK6SearchEnd(end, endBody) == kad6::Kad6Status::Ok) {
                kad6::K6Frame frame;
                frame.msg_type = kad6::kK6MsgSearchEnd;
                frame.flags = kad6::kK6FlagResponse | kad6::kK6FlagFinal |
                              kad6::kK6FlagLegacyKad2;
                frame.request_id = due[i].req_id;
                frame.body = std::move(endBody);
                if (kad6::EncodeK6Frame(frame, endWire) == kad6::Kad6Status::Ok)
                    CompleteExitOperation(due[i].circ_id, due[i].req_id,
                                          endWire.data(), endWire.size());
                else
                    AbortExitOperation(due[i].circ_id, due[i].req_id);
            } else {
                AbortExitOperation(due[i].circ_id, due[i].req_id);
            }
        } else {
            std::vector<uint8_t> payload;
            SerializeSearchResults(due[i].keyword, payload);
            // CompleteExitOperation no-ops if the circuit rotated/died meanwhile.
            CompleteExitOperation(due[i].circ_id, due[i].req_id,
                                  payload.data(), payload.size());
        }
        StopSearchJobKad(due[i]);   // free the CSearch either way
    }
}

uint16_t CLiveTunnel::SendK6SearchResults(const TunnelSearchJob& job)
{
    uint16_t sent = 0;
    try {
        if (job.searchKind == kad6::kK6SearchKindSourceHash) {
            const std::vector<size_t> ranked =
                LiveTunnelPeerState::RankSources(job.sourceCandidates.size(),
                    [&job](size_t index) { return job.sourceCandidates[index].score; });
            const uint16_t limit = (uint16_t)(std::min<size_t>)(
                ranked.size(), (size_t)job.maxResults);
            for (uint16_t i = 0; i < limit; ++i) {
                const TunnelSearchJob::SourceCandidate& source =
                    job.sourceCandidates[ranked[i]];
                kad6::K6SearchResult result;
                result.result_id = source.userHash;
                result.result_kind = kad6::kK6SearchKindSourceHash;
                result.network_origin = source.networkOrigin;

                LiveTunnelAuthorizedTarget authorized;
                authorized.circ_id = job.circ_id;
                authorized.source_request_id = job.req_id;
                authorized.result_id = result.result_id;
                authorized.object_hash = job.targetHash;
                authorized.endpoint = source.endpoint;
                authorized.network_origin = source.networkOrigin;
                authorized.expires_at = authorized.endpoint.valid_until;

                std::vector<uint8_t> unsignedBody;
                if (kad6::EncodeK6SearchResult(result, unsignedBody) != kad6::Kad6Status::Ok)
                    continue;
                const kad6::Kad6CryptoHooks crypto = MakeKad6HostCryptoHooks();
                if (source.provenance == kad6::K6Provenance::Routing)
                    authorized.digest = source.provenanceDigest;
                else if (!crypto.sha256 || !crypto.sha256(unsignedBody.data(),
                        unsignedBody.size(), authorized.digest.data()))
                    continue;

                std::vector<uint8_t> ticketWire;
                if (!IssueK6RuntimeTicket(authorized, 4ull * 1024ull * 1024ull * 1024ull,
                        source.provenance, job.circ_id, job.req_id, i,
                        ticketWire))
                    continue;
                kad6::K6TargetTicket ticket;
                size_t ticketUsed = 0;
                if (kad6::DecodeK6TargetTicket(ticketWire.data(), ticketWire.size(), ticket,
                        &ticketUsed) != kad6::Kad6Status::Ok || ticketUsed != ticketWire.size())
                    continue;
                result.tickets.push_back(std::move(ticket));

                std::vector<uint8_t> resultBody, resultWire;
                if (kad6::EncodeK6SearchResult(result, resultBody) != kad6::Kad6Status::Ok)
                    continue;
                m_exitServices.LT4AuthorizeTarget(
                    K6AuthorizedTargetKey(
                        job.circ_id, job.req_id, authorized.result_id),
                    authorized);
                kad6::K6Frame frame;
                frame.msg_type = kad6::kK6MsgSearchResult;
                frame.flags = kad6::kK6FlagResponse | kad6::kK6FlagMore;
                if (source.networkOrigin == kad6::kK6NetOriginKad2)
                    frame.flags |= kad6::kK6FlagLegacyKad2;
                frame.request_id = job.req_id;
                frame.body = std::move(resultBody);
                if (kad6::EncodeK6Frame(frame, resultWire) != kad6::Kad6Status::Ok ||
                    !SendExitOperationPart(job.circ_id, job.req_id,
                        resultWire.data(), resultWire.size()))
                    break;
                ++sent;
            }
            return sent;
        }

        if (!theApp.liveStreamManager) return 0;
        CArray<LiveStreamEntry> entries;
        theApp.liveStreamManager->GetKadBridge().GetKnownStreams(entries);
        const uint16_t limit = (uint16_t)(std::min<size_t>)(
            TUN_SEARCH_MAX_RESULTS, (size_t)job.maxResults);
        for (INT_PTR i = 0; i < entries.GetCount() && sent < limit; ++i) {
            const LiveStreamEntry& e = entries[i];
            CString titleLow = e.title;
            titleLow.MakeLower();
            const std::vector<uint8_t> titleUtf8 = EseCStringUtf8(titleLow);
            const std::string titleKey(titleUtf8.begin(), titleUtf8.end());
            if (!job.keyword.empty() && job.keyword != "eselive" &&
                titleKey.find(job.keyword) == std::string::npos)
                continue;

            uint32_t ip = e.broadcasterIP;
            if (ip == 0 && e.isOwnStream) ip = theApp.GetPublicIP();
            kad6::K6LiveSearchMetadata live;
            std::copy(e.streamKey, e.streamKey + 16, live.result_id.begin());
            live.ipv4 = {{static_cast<uint8_t>(ip), static_cast<uint8_t>(ip >> 8),
                          static_cast<uint8_t>(ip >> 16), static_cast<uint8_t>(ip >> 24)}};
            live.tcp_port = e.broadcasterPort;
            live.udp_port = e.broadcasterUDPPort;
            live.bitrate_kbps = e.bitrate;
            live.viewer_count = e.viewerCount;
            live.started_at = e.startedAt;
            live.discovery_namespace = e.discoveryNamespace <= ESE_NS_LEGACY
                ? e.discoveryNamespace : ESE_NS_UNKNOWN;
            live.title_utf8 = EseCStringUtf8(e.title);
            live.category_utf8 = EseCStringUtf8(e.category);
            live.language_utf8 = EseCStringUtf8(e.language);

            kad6::K6SearchResult result;
            std::vector<uint8_t> resultBody, resultWire;
            if (kad6::BuildK6LiveSearchResult(live, result) != kad6::Kad6Status::Ok ||
                kad6::EncodeK6SearchResult(result, resultBody) != kad6::Kad6Status::Ok)
                continue;
            LiveTunnelAuthorizedTarget authorized;
            authorized.circ_id = job.circ_id;
            authorized.source_request_id = job.req_id;
            authorized.result_id = result.result_id;
            authorized.object_hash = result.result_id;
            authorized.endpoint.addr.family = kad6::Kad6Address::Family::IPv4;
            authorized.endpoint.addr.addr = {live.ipv4[0],live.ipv4[1],live.ipv4[2],live.ipv4[3]};
            authorized.endpoint.tcp_port = live.tcp_port;
            authorized.endpoint.udp_port = live.udp_port;
            authorized.endpoint.transport_flags = kad6::kK6EpTcpEd2k;
            // Match the origin's opaque Live route lifetime; the endpoint never
            // leaves exit-local authorized state.
            authorized.endpoint.valid_until = static_cast<uint64>(time(NULL)) + 120;
            authorized.expires_at = authorized.endpoint.valid_until;
            const kad6::Kad6CryptoHooks crypto = MakeKad6HostCryptoHooks();
            if (!crypto.sha256 ||
                !crypto.sha256(resultBody.data(), resultBody.size(), authorized.digest.data()) ||
                !K6AllowTicketTarget(this,
                    static_cast<kad6::Byte>(kad6::K6TicketService::Ed2kTcp),
                    authorized.endpoint))
                continue;
            // Live endpoints stay exit-local. Unlike file-source results, no
            // target ticket is embedded: its endpoint would be plaintext to A.
            // The later v2 LIVE_SUBSCRIBE resolves this authorized result_id on
            // this exact circuit and never returns the broadcaster address.
            m_exitServices.LT4AuthorizeTarget(
                K6AuthorizedTargetKey(
                    job.circ_id, job.req_id, authorized.result_id),
                authorized);
            kad6::K6Frame frame;
            frame.msg_type = kad6::kK6MsgSearchResult;
            frame.flags = kad6::kK6FlagResponse | kad6::kK6FlagMore |
                          kad6::kK6FlagLegacyKad2;
            frame.request_id = job.req_id;
            frame.body = std::move(resultBody);
            if (kad6::EncodeK6Frame(frame, resultWire) != kad6::Kad6Status::Ok)
                continue;
            if (!SendExitOperationPart(job.circ_id, job.req_id,
                                       resultWire.data(), resultWire.size()))
                break;
            ++sent;
        }
    } catch (...) {}
    return sent;
}

void CLiveTunnel::SerializeSearchResults(const std::string& keyword,
                                         std::vector<uint8_t>& out) const
{
    out.assign(4, 0);   // header: result_count(2) + flags(1) + reserved(1)
    uint16_t count = 0;

    auto putU16 = [&](uint16_t v){ out.push_back((uint8_t)(v & 0xFF));
                                   out.push_back((uint8_t)((v >> 8) & 0xFF)); };
    auto putU32 = [&](uint32_t v){ for (int i = 0; i < 4; ++i)
                                       out.push_back((uint8_t)((v >> (i*8)) & 0xFF)); };
    auto putStr8 = [&](const CStringA& s){
        int n = s.GetLength(); if (n > 255) n = 255;
        out.push_back((uint8_t)n);
        const char* p = (LPCSTR)s;
        out.insert(out.end(), (const uint8_t*)p, (const uint8_t*)p + n);
    };

    try {
        if (theApp.liveStreamManager) {
            CArray<LiveStreamEntry> entries;
            theApp.liveStreamManager->GetKadBridge().GetKnownStreams(entries);
            for (INT_PTR i = 0;
                 i < entries.GetCount() && count < TUN_SEARCH_MAX_RESULTS; ++i) {
                const LiveStreamEntry& e = entries[i];
                CStringA titleA(e.title);
                CStringA titleLow = titleA; titleLow.MakeLower();
                // "eselive" is the global keyword every stream publishes under,
                // so treat it (and an empty keyword) as match-all; any other
                // keyword still filters by title substring.
                if (!keyword.empty() && keyword != "eselive"
                    && titleLow.Find((LPCSTR)keyword.c_str()) < 0)
                    continue;
                if (out.size() > TUN_MSG_MAX_BYTES - 512) break;   // keep under the cap

                CStringA catA(e.category), langA(e.language);
                const size_t recLenPos = out.size();
                putU16(0);                                   // rec_len placeholder
                const size_t bodyStart = out.size();
                out.insert(out.end(), e.streamKey, e.streamKey + 16);
                // IP=0 fix (v8.1): our OWN stream's directory entry may still
                // carry broadcasterIP=0 if it was published before our public
                // IP was known. Substitute it here — the IP is reliably known
                // by the time we serve a tunneled search — so the originator
                // doesn't reject the result as "invalid endpoint (IP=0)".
                uint32 outBroadcasterIP = e.broadcasterIP;
                if (outBroadcasterIP == 0 && e.isOwnStream)
                    outBroadcasterIP = theApp.GetPublicIP();
                putU32(outBroadcasterIP);
                putU16(e.broadcasterPort);
                putU16(e.broadcasterUDPPort);
                putU16(e.bitrate);
                putU32(e.viewerCount);
                putU32(e.startedAt);
                out.push_back(e.discoveryNamespace);
                putStr8(titleA);
                putStr8(catA);
                putStr8(langA);
                const uint16_t recLen = (uint16_t)(out.size() - bodyStart);
                out[recLenPos]     = (uint8_t)(recLen & 0xFF);
                out[recLenPos + 1] = (uint8_t)((recLen >> 8) & 0xFF);
                ++count;
            }
        }
    } catch (...) {}

    out[0] = (uint8_t)(count & 0xFF);
    out[1] = (uint8_t)((count >> 8) & 0xFF);
    out[2] = 0x02;   // flags bit1 = final (MVP: single final reply)
    out[3] = 0;
}

void CLiveTunnel::StopSearchJobKad(const TunnelSearchJob& job)
{
    m_kadBridge.StopSearches(job.kadSearchIds);
}

bool CLiveTunnel::TunneledKadSearch(const std::string& keywordLower,
                                    std::string& resultsJsonOut,
                                    uint32_t timeoutMs)
{
    // K6-1 migration: prefer K6Frame only when a matching Active circuit's
    // exit signed ESE_CAP_KAD6. Otherwise retain the deployed 0x42/0x43 wire.
    uint32_t req_id;
    PendingHandle pr = RegisterPending(req_id);
    std::vector<uint8_t> body;
    const bool canonical = HasActiveCircuitWithExitCaps(ESE_CAP_KAD6);
    uint8_t op = TUN_OP_KAD_SEARCH_V2;
    uint32_t requiredCaps = 0;
    uint32_t pinnedCircuit = 0;
    if (canonical) {
        if (!EseBuildK6SearchStartFrame(keywordLower, req_id, body)) {
            std::vector<uint8_t> ignored;
            WaitPending(req_id, std::move(pr), 0, ignored, NULL);
            return false;
        }
        op = TUN_OP_KAD6_GATEWAY;
        requiredCaps = ESE_CAP_KAD6;
        pinnedCircuit = K6SelectOriginCircuit(requiredCaps, 0, 2);
        kad6::K6Frame quotaOperation;
        size_t quotaUsed = 0;
        if (pinnedCircuit == 0 ||
            kad6::DecodeK6Frame(body.data(), body.size(), quotaOperation, &quotaUsed) !=
                kad6::Kad6Status::Ok || quotaUsed != body.size()) {
            std::vector<uint8_t> ignored;
            WaitPending(req_id, std::move(pr), 0, ignored, NULL);
            return false;
        }
        if (K6CircuitHasExitCaps(pinnedCircuit, ESE_CAP_KAD6_ECONOMY, 2) &&
            !K6AcquireAnonymousQuota(pinnedCircuit, kad6::K6QuotaService::Control,
                quotaOperation.msg_type, quotaOperation.body,
                (std::max<uint32>)(3, timeoutMs / 2)) && IsK6PublicReleaseEnabled()) {
            std::vector<uint8_t> ignored;
            WaitPending(req_id, std::move(pr), 0, ignored, NULL);
            return false;
        }
    } else {
        const uint16_t kwLen = (uint16_t)(
            keywordLower.size() > 0xFFFF ? 0xFFFF : keywordLower.size());
        body.push_back(0x01);
        body.push_back((uint8_t)(kwLen & 0xFF));
        body.push_back((uint8_t)(kwLen >> 8));
        body.insert(body.end(), keywordLower.begin(), keywordLower.begin() + kwLen);
    }

    m_pendingRequests.Configure(
        pr, op, requiredCaps, canonical ? 0 : TUN_SEND_RETRIES,
        body.data(), body.size());
    EnqueueSendMsg(req_id, op, body.data(), body.size(), requiredCaps,
        pinnedCircuit);

    std::vector<uint8_t> reply;
    if (!WaitPending(req_id, std::move(pr), timeoutMs, reply, NULL))
        return false;
    resultsJsonOut = SB_ParseSearchResultsToJson(reply);
    return true;
}

void CLiveTunnel::SendKadSearchV2NoWait(const std::string& keywordLower)
{
    const uint32_t req_id=NewCircuitId();
    std::vector<uint8_t> body;
    if(HasActiveCircuitWithExitCaps(ESE_CAP_KAD6)){
        if(!EseBuildK6SearchStartFrame(keywordLower,req_id,body))return;
        EnqueueSendMsg(req_id,TUN_OP_KAD6_GATEWAY,body.data(),body.size(),ESE_CAP_KAD6);return;}
    const uint16_t kwLen=(uint16_t)(keywordLower.size()>0xFFFF?0xFFFF:keywordLower.size());
    body.push_back(0x01);body.push_back((uint8_t)(kwLen&0xFF));body.push_back((uint8_t)(kwLen>>8));
    body.insert(body.end(),keywordLower.begin(),keywordLower.begin()+kwLen);
    EnqueueSendMsg(req_id,TUN_OP_KAD_SEARCH_V2,body.data(),body.size());
}

