// this file is part of eMule eSE — 2-hop onion tunnel manager (F4)
//
// Pool of 3-5 circuits per active stream (Cap 5 §5.5). Handles:
//   - circuit construction (CREATE/CREATED/EXTEND/EXTENDED)
//   - rotation every 30s ±10s
//   - multipath: cells from a payload split across circuits
//   - cover traffic via LiveCoverTraffic
//
// Network I/O (actual TCP send/recv) is delegated to CClientReqSocket
// in F5; LiveTunnel owns cell construction + onion crypto only.
#pragma once
#include "LiveCircuit.h"
#include "LiveOnionCrypto.h"
#include "LiveCellQueue.h"   // v8.1 A2 - ReassemblyEntry, fragment helpers
#include "LiveBulk.h"        // v8.1.2 E1.2/E3.4 - bulk cell wire + multi-block FEC + replay window
#include "LiveTunnelPending.h"
#include "LiveCircuitRegistry.h"
#include "LiveCircuitHandshake.h"
#include "LiveRelayDispatcher.h"
#include "LiveExitServices.h"
#include "LiveTunnelScheduler.h"
#include "LiveTunnelPeerState.h"
#include "LiveTunnelKadBridge.h"
#include "LiveTunnelMetrics.h"
#include "kad6/kad6_lease.h"
#include "kad6/kad6_publish.h"
#include "kad6/kad6_frame.h"
#include "kad6/kad6_search.h"
#include "kad6/kad6_store.h"
#include "kad6/kad6_gateway.h"
#include "kad6/kad6_hints.h"
#include "kad6/kad6_vep.h"
#include "kad6/kad6_frontdoor.h"
#include "kad6/kad6_shaped_bulk.h"
#include "kad6/kad6_shaper.h"
#include "kad6/kad6_hardening.h"
#include "kad6/kad6_economy.h"
#include "kad6/kad6_quota.h"
#include "kad6/kad6_exit_notice.h"
#include "kad6/kad6_release.h"
#include "Kad6ExitNoticeServer.h"
#include <memory>
#include <vector>
#include <string>   // v0.71 C — TunnelPing text I/O
#include <map>      // v0.71 C — pending request table
#include <deque>    // v0.72 — main-thread work queue
#include <utility>  // v0.72 — std::move
#include <functional> // v8.1 A2 - std::function handler registry
#include <set>     // v8.1.2 E3.1 — exit-proxy stream-key set
#include <array>
class CUpDownClient;
namespace eSELive {
using K6AuthorizedTarget = LiveTunnelAuthorizedTarget;
using TunnelSearchJob = LiveTunnelSearchJob;
class CKad6ExitSocket;
class CKad6OriginSocket;
// Pool size limits from §5.5.5 thesis
const size_t TUNNEL_POOL_MIN = 3;
const size_t TUNNEL_POOL_MAX = 5;
const DWORD  TUNNEL_ROTATION_BASE_MS  = 300u * 1000u;   // v8.1: 5 min (was 30 s, too short: micro-cut streams + blocked testing)
const DWORD  TUNNEL_ROTATION_JITTER_MS = 10u * 1000u;
const DWORD  TUNNEL_HANDSHAKE_TIMEOUT_MS = 800u;
// v8.x Phase 2 — tunnel auth policy. Mixed (default): emit v2 to auth-capable
// peers, v1 otherwise, accept either. Strict: require a verified v2 handshake and
// abort any v1/unsigned cell. Toggle is a runtime flag for now (wire to a pref/UI
// later); the handshake crypto is final regardless of the toggle source.
bool TunnelAuthStrict();
void SetTunnelAuthStrict(bool strict);
// v8.1 Sprint B — tunneled Kad search.
const DWORD  TUN_SEARCH_WINDOW_MS   = 7000u;   // accumulate Kad results this long, then reply
const size_t TUN_SEARCH_MAX_RESULTS = 100;     // cap records per reply (anti-DoS + size)
class CLiveTunnel : private LiveCircuitHandshakeHost,
                    private ILiveRelayDispatcherPort {
public:
    static CLiveTunnel& Get();
    // MOD-0.2: headless characterization seam. It only invokes production
    // framing/reassembly and the empty-dispatch rejection; normal runtime
    // paths never call it.
    bool RunCharacterizationSelfTest(CString& outFailure);
    // Start building `count` circuits to reach the given origin pubkey
    // through the given pool of relay candidates. Returns number of
    // CREATE cells issued. Callbacks via OnCellReceived complete the
    // build asynchronously.
    size_t BuildPool(const uint8_t origin_pubkey[32],
                     const std::vector<CUpDownClient*>& relayCandidates,
                     size_t count);
    // Tear down all circuits and clear state.
    void Stop();
    // Send a payload through any one of the active circuits, using the
    // multipath split policy (round-robin by default — chunks consecutive
    // by seq get distinct circuits, Decision 5.1).
    bool SendThrough(const uint8_t* payload, size_t payloadLen);
    // Incoming cell from a hop (called by ListenSocket OP_LIVE_TUNNEL_CELL
    // handler in F5). Returns true if the cell was consumed.
    bool OnCellReceived(uint32_t circ_id, uint8_t cmd,
                        const uint8_t* payload, uint16_t payloadLen,
                        CUpDownClient* fromPeer);
    // v8.1.2 Sprint E (E1.2) — incoming OP_LIVE_BULK_CELL (0xD9) from a hop. Called by
    // the ListenSocket dispatch with the RAW packet bytes (after the opcode). Parses the
    // variable-length bulk cell (LiveBulk §2.1), then either FORWARDS it (intermediate
    // relay, reverse direction exit->hop1->V) or TERMINATES it (originator/viewer:
    // explicit-nonce onion-decrypt -> replay check -> BULK_DATA -> reassembly E3.4).
    // Returns true if the cell was consumed (incl. silently dropped).
    bool OnBulkCellReceived(const uint8_t* pkt, uint32_t size, CUpDownClient* fromPeer);
    // === v8.1.2 E3.1 — exit headless ingest hooks ==========================
    // Called from CLiveStreamManager's chunk path (IngestChunkPayload / OnChunkFragment
    // Received), which holds the MANAGER lock, BEFORE its m_bViewing gate. To preserve the
    // documented tunnel->manager lock order, these touch ONLY a LEAF-locked tunnel queue
    // (never the tunnel m_lock / m_pendingLock); the heavy work (FEC encode + stripe push)
    // runs later in Tick(). IsExitProxying is a cheap predicate (false for any non-exit
    // node and any stream we don't proxy -> the direct viewer path is byte-for-byte unchanged).
    bool IsExitProxying(const uint8_t streamKey[16]) const;
    // A whole CHUNK_V2/V1 record arrived for a proxied stream (small/low-bitrate path).
    void ExitProxyOnWholeChunk(const uint8_t streamKey[16], const uint8_t* record, uint32_t recordLen);
    // A fragment arrived for a proxied stream (native-bitrate path: 0xE0 > 1.8MB). The exit
    // reassembles it itself (the viewer's m_fragReasm is m_bViewing-gated + single-stream).
    void ExitProxyOnFragment(const uint8_t streamKey[16], uint32_t seqNum,
                             uint16_t fragIndex, uint16_t fragCount, uint32_t totalLen,
                             const uint8_t* fragData, uint32_t fragLen);
    // v8.1.2 E3.2 (viewer) — start the bulk data plane for `streamKey`: send
    // TUN_OP_BULK_SUBSCRIBE on every Active bulk-capable circuit, all tagged with one fresh
    // session_id (so the exit stripes across them). No-op if no bulk circuit exists (caller
    // stays on the direct/fallback path). Returns the number of circuits subscribed.
    size_t BulkSubscribe(const uint8_t streamKey[16]);
    // Periodic tick (rotation, cover traffic, dead circuit cleanup).
    void Tick();
    // K6-6 class-5 has a dedicated 10 ms UI-thread heartbeat. The ordinary
    // Kad Tick is ~1 Hz and cannot preserve fixed record slots.
    void ProcessClass5Tick();
    size_t ActiveCircuitCount() const;
    size_t PendingCircuitCount() const;      // v0.71 P3.8 — circuits in CREATE/CREATED handshake
    size_t RelayCircuitCount() const;        // v0.71 P3.3 — circuits we relay (intermediate)
    size_t TotalCircuitCount() const;        // v0.71 P3.3 — for UI / metrics
    // True only when an Active originator circuit terminates at an
    // authenticated exit whose signed CREATED-v2 capability snapshot contains
    // every requested bit.  Used by K6-1 to choose K6Frame vs legacy wire.
    bool HasActiveCircuitWithExitCaps(uint32_t requiredCaps) const;
    // v0.71 P3.6 — self-loop test: build a single-hop circuit to a peer
    // identified by clientHint. If clientHint == NULL, picks the first
    // connected CUpDownClient with a working socket (works for solo
    // testing against any eD2K peer; the peer will see an unknown
    // OP_LIVE_TUNNEL_CELL opcode and drop, so the originator circuit
    // stays Pending — but the SEND path is exercised end-to-end). If
    // clientHint points to a peer running this fork the handshake
    // completes and the circuit reaches Active. Returns the circuit_id
    // assigned, or 0 on failure.
    uint32_t BuildTestCircuit(CUpDownClient* clientHint);
    // PST pool make-before-break successor. Production privacy is fail-closed:
    // it builds either an exact 3-hop Strict path or an exact 2-hop Private path.
    // One-hop paths are reserved for explicit diagnostics and quota issuance.
    bool BuildSuccessorCircuit();
    // Build the dedicated direct issuer circuit used by anonymous quota
    // acquisition.  It is kept outside the private circuit pool and is never
    // eligible for ordinary origin traffic.
    bool BuildQuotaGuardCircuit();
    // K6-6: build one fail-closed STRICT circuit with exactly three remote
    // identities (guard, middle, exit).  No one/two-hop fallback occurs here.
    bool BuildSuccessor3Hop(uint32_t* circuitId = NULL);
    // v0.71 B (2-hop) — extended test: builds a 1-hop circuit AND, once
    // CREATED arrives, requests a 2nd hop. Returns the V-side circ_id.
    // If only 1 fork peer is available, hop2 loops back to the same peer
    // (semantically weird but valid for state-machine testing). Real
    // multi-node deployments pick 2 distinct peers.
    uint32_t BuildTestCircuit2Hop();
    // === v8.1 A2 - generic exit-side dispatcher ============================
    // Replaces the hardcoded sub_cmd switch in HandleRelay_Exit. One handler
    // is registered per sub_cmd; once a request is fully received (a legacy
    // single-cell op, or a reassembled multi-cell op) the dispatcher builds a
    // TunnelRequestCtx and invokes the handler. New ops (Sprint B/C) just
    // register a handler instead of editing HandleRelay_Exit.
    using TunnelRequestCtx = LiveTunnelRequestCtx;
    using TunnelOpHandler = LiveTunnelOpHandler;
    // v0.71 P1.B — does the user's mode + this operation route through
    // a tunnel? Returns true if a circuit should be used. Centralised
    // here so the same logic gates Kad search, Live subscribe, future
    // ops without code duplication. The decision combines the mode
    // selector (Direct/Tunneled/Adaptive) and current circuit
    // availability. If decision is "tunnel" but no Active circuit
    // exists, callers should fall back to the direct path (no
    // privacy but functional) rather than fail entirely.
    // v8.1 D7 - opClass is Kademlia::CKadV2ModeSelector::QueryContext::OperationClass
    // (0=KAD_SEARCH, 1=KAD_PUBLISH, 2=LIVE_CONTROL); passed as uint8_t to avoid pulling the
    // selector header into this widely-included header. Defaults to LIVE_CONTROL so the
    // existing subscribe call sites are unchanged.
    bool ShouldRouteThroughTunnel(const wchar_t* keywordOrNull, uint8_t opClass = 2) const;
    // v0.71 P1.A — issue a Kad keyword search through the tunnel.
    // Sends TUN_OP_KAD_SEARCH, waits for TUN_OP_KAD_RESULT. timeoutMs
    // bound on the whole operation. Returns true if any results came
    // back; resultsJsonOut receives a JSON array of {streamKey, name,
    // viewers, bitrate, ip, port} for the caller to interpret.
    bool TunneledKadSearch(const std::string& keywordLower,
                           std::string& resultsJsonOut,
                           uint32_t timeoutMs);
    // K6-3 source gateway. Blocking calls are worker-thread APIs, mirroring
    // TunneledKadSearch; unbind/unpublish are idempotent fire-and-forget.
    bool K6BindSource(const kad6::K6SourceBind& bind,
                      kad6::K6SourceBound& boundOut, uint32_t timeoutMs);
    bool K6PublishRecord(const kad6::K6Publish& publish,
                         kad6::K6PublishAck& ackOut, uint32_t timeoutMs);
    void K6SourceUnbindNoWait(const kad6::K6SourceUnbind& unbind);
    void K6UnpublishNoWait(const kad6::K6Unpublish& unpublish);
    // K6-4 outbound legacy gateway. Blocking methods are worker-thread APIs;
    // attach/send use the normal main-thread client engine and never open a
    // destination that is not covered by an exit-issued target ticket.
    bool K6RequestTargetTicket(const kad6::K6TargetTicketRequest& request,
                               std::vector<uint8_t>& ticketOut, uint32_t timeoutMs);
    bool K6DialEd2k(const std::vector<uint8_t>& ticket,
                    const std::vector<uint8_t>& initialData,
                    kad6::K6DialResult& resultOut, uint32_t timeoutMs);
    bool K6AttachOriginClient(uint64 streamId, CUpDownClient* client);
    bool K6SendEd2kFrameNoWait(uint64 streamId, const uint8_t* frame, size_t length);
    bool K6TakeSourceHints(uint64 streamId, kad6::K6SourceHints& hintsOut);
    bool K6GetVirtualIdentity(uint64 streamId,
                              kad6::K6VirtualIdentityEndpoint& vepOut) const;
    // K6-4 production activation. Source-hash lookup is fire-and-forget on
    // the main thread; matching results materialize ordinary download clients
    // carrying an opaque exit ticket. BeginK6Download consumes that ticket and
    // starts an asynchronous DIAL pinned to its issuing circuit.
    bool StartK6SourceLookup(const uint8_t fileHash[16], uint32_t& requestIdOut);
    bool BeginK6Download(CUpDownClient* client);
    void QueueK6SourceAdvertise(const uint8_t fileHash[16], uint64 fileSize,
                                kad6::K6CommitmentKind commitmentKind,
                                const uint8_t commitment[32]);
    // K6-5 inbound cohort front-door. The listener enables bounded pre-auth
    // only while at least one published source lease can accept sessions.
    bool HasK6ServingLeases() const;
    bool OnKad6GatewaySourceResult(uint32_t circuitId, uint32_t requestId,
                                   const uint8_t userHash[16], uint8_t sourceType,
                                   uint32_t ip, uint16_t tcpPort, uint16_t udpPort,
                                   uint8_t cryptOptions, uint16_t reachCaps,
                                   const uint8_t* ipv6OrNull);
    bool OnKad6NativeSourceRecord(uint32_t circuitId, uint32_t requestId,
                                  const kad6::K6SourceRecord& record);
    // MAIN THREAD. Native lookup transport reports only fixed alpha/result
    // buckets; no peer or target identity reaches the public metric registry.
    void OnKad6SourceLookupRpc(uint8_t alpha, uint8_t result);
    // Main-thread callbacks from the real Kad2 CSearch::STOREFILE path.
    bool AllowKad6ShadowPublishContact(uint64 publishLeaseId,
                                       const uint8_t custodianId[16]);
    void OnKad6ShadowPublishSent(uint64 publishLeaseId);
    void OnKad6ShadowPublishAck(uint64 publishLeaseId, uint8_t load,
                                bool hasLoadResponse);
    void OnKad6ShadowVerified(uint64 publishLeaseId);
    void OnKad6NativePublishAck(uint64 publishLeaseId,
                                kad6::K6StoreStatus status, uint8_t load,
                                uint64 acceptedEpoch);
    // v0.71 C — synchronous tunnel ping. Sends a PING through any
    // active circuit, blocks up to timeoutMs waiting for the reply.
    // Returns true if reply arrived in time, with replyText populated.
    // Used by the /api/live/privacy/tunnel_ping REST endpoint.
    bool TunnelPing(const std::string& text, std::string& replyText,
                    uint32_t timeoutMs);
    // v8.1 Sprint C (C1/C2) — tunneled LiveTV subscribe. Sends
    // TUN_OP_LIVE_SUBSCRIBE through a circuit; the exit forwards a real
    // OP_LIVE_SUBSCRIBE to the broadcaster ON V's BEHALF (the broadcaster sees
    // the exit, never V) and replies TUN_OP_LIVE_SUB_ACK. Returns true iff the
    // exit confirmed it forwarded the subscribe. The broadcaster's live-edge
    // bitmap + pubkey flow back via tunneled heartbeats (C3). ip/port/udp/altIP
    // are the same endpoint the viewer would dial directly (learned from Kad).
    // SUPERSEDED by SendLiveSubscribeNoWait (below) and has NO current caller: the
    // wired design is fire-and-forget — the one-way subscribe establishes the
    // tunneled session and the live edge returns via the C3 heartbeat relay, so no
    // caller blocks on the SUB_ACK (both dial sites run on the main thread, where a
    // blocking wait would be wrong). Kept as the symmetric off-thread blocking twin.
    // BLOCKING up to timeoutMs — call OFF the main thread (like TunneledKadSearch).
    bool TunneledLiveSubscribe(const uint8_t streamKey[16],
                               uint32_t bIP, uint16_t bPort, uint16_t bUDP,
                               uint32_t bAltIP, uint32_t timeoutMs);
    // v8.1 Sprint C (C5) — fire-and-forget tunneled subscribe. Unlike
    // TunneledLiveSubscribe this does NOT block for the SUB_ACK, so it is safe
    // to call from the main thread (the Live dial path). It enqueues a
    // TUN_OP_LIVE_SUBSCRIBE on a throwaway req_id; if no Active circuit exists
    // the enqueued send is a no-op (caller should have already checked
    // ActiveCircuitCount and fallen back to a direct subscribe). The SUB_ACK,
    // if any, is dropped (no waiter). The broadcaster's live edge then reaches
    // the viewer via the C3 tunneled-heartbeat relay.
    void SendLiveSubscribeNoWait(const uint8_t streamKey[16],
                                 uint32_t bIP, uint16_t bPort, uint16_t bUDP,
                                 uint32_t bAltIP);
    // Kad6-native Live result: the endpoint stays at the exit. Resolve the
    // result_id on the exact circuit that returned it and subscribe opaquely.
    bool SendK6LiveSubscribeNoWait(const uint8_t streamKey[16]);
    // v8.1 D1 - fire-and-forget tunneled Kad keyword search (keyword UTF-8, lowercased).
    // Like SendLiveSubscribeNoWait: throwaway req_id, no waiter; the TUN_OP_KAD_RESULT_V2
    // reply is parsed straight into the Live directory by HandleRelay_Originator. Safe from
    // the MAIN thread (the blocking TunneledKadSearch is not). No-op without an Active circuit.
    void SendKadSearchV2NoWait(const std::string& keywordLower);
    // v8.1 A1.7 - multi-cell echo test op. Splits `payload` into fragments,
    // sends them as TUN_OP_ECHO_LARGE, awaits the reassembled
    // TUN_OP_ECHO_LARGE_REPLY. Exercises the whole multi-cell path
    // end-to-end. Returns false on timeout or oversize message.
    bool TunnelEchoLarge(const std::vector<uint8_t>& payload,
                         std::vector<uint8_t>& replyOut, uint32_t timeoutMs);
    // v0.71 B — accessor for the panel/REST endpoint to enumerate all
    // active circuits with their per-hop endpoints. The caller receives
    // copies (no live refs) and may iterate without holding our lock.
    using CircuitSnapshot = LiveCircuitSnapshot;
    void GetCircuitsSnapshot(std::vector<CircuitSnapshot>& out) const;
    // K6-7 local beta controls. Mutations are marshaled to the main thread so
    // a Web UI worker never touches sockets or lease state. The snapshot and
    // sealed metrics contain only aggregate, fixed-cardinality values.
    using K6HardeningRuntimeSnapshot = LiveK6HardeningRuntimeSnapshot;
    bool RequestK6ServiceSwitch(kad6::K6Service service, bool enabled,
                                uint32 drainSeconds, uint32 timeoutMs);
    void GetK6HardeningSnapshot(K6HardeningRuntimeSnapshot& out);
    using K6ReleaseRuntimeSnapshot = LiveK6ReleaseRuntimeSnapshot;
    bool RequestK6PublicRelease(bool enable,
                                const kad6::K6ReleaseEvidence* evidence,
                                uint32 drainSeconds, uint32 timeoutMs);
    void GetK6ReleaseSnapshot(K6ReleaseRuntimeSnapshot& out);
    bool GetK6ReleaseOperatorChallenge(std::string& challenge);
    bool ConsumeK6ReleaseOperatorChallenge(const std::string& challenge);
    std::string GetK6PrometheusMetrics();
    bool StartK6ExitNotice(uint16 port, kad6::K6ExitNotice notice);
    void StopK6ExitNotice() noexcept;
    K6ExitNoticeServerSnapshot GetK6ExitNoticeSnapshot() const noexcept;
    // MAIN THREAD ONLY. A circuit is bound to the concrete eD2K client
    // connection used for each adjacent hop. Tear it down as soon as that
    // client disconnects so the API/pool cannot keep reporting or selecting
    // an Active circuit whose transport has already disappeared.
    void OnPeerDisconnected(CUpDownClient* peer);
    // === v0.72 — main-thread marshaling ====================================
    // The embedded webserver answers each HTTP request on its own worker
    // thread. CLiveTunnel, CUpDownClient and the eMule sockets are
    // single-threaded (main thread only), so the /api/live/privacy/*
    // endpoints must NOT call SendThrough / BuildTestCircuit* directly —
    // those touch peer sockets and the ClientList. Instead the endpoints
    // enqueue the work here and the main thread drains it from
    // ProcessMainThreadWork() (called once per Kad tick). Read-only endpoints
    // are served from caches the main thread keeps refreshed.
    // Worker-thread safe. Builds a test circuit ON THE MAIN THREAD and waits
    // up to timeoutMs for the resulting circuit id. hops is 1, 2 or strict 3.
    // Three-hop construction never loops back or degrades. Returns
    // the circuit id, or 0 on failure / timeout.
    uint32_t RequestTestCircuit(int hops, uint32_t timeoutMs);
    // Value-typed peer info — safe to hand to a worker thread (unlike raw
    // CUpDownClient pointers, which only the main thread may dereference).
    // Printable endpoints are immutable values. IPv6 is never exposed as the
    // synthetic legacy uint32 identity stored in `ip`.
    using PeerSnapshot = LivePeerSnapshot;
    // Worker-thread safe. Copies the peer snapshot the main thread refreshes
    // in ProcessMainThreadWork(). outTunnelingCount = connected peers that
    // advertised privacy-tunneling capability.
    void GetPeersSnapshot(std::vector<PeerSnapshot>& outAll,
                          size_t& outTunnelingCount) const;
    // MAIN THREAD ONLY. Drains the marshaled-work queue and refreshes the
    // peer cache. Call once per Kad process tick.
    void ProcessMainThreadWork();
    // v0.71 P3.3 — total counts of cells sent / received for metrics.
    uint64_t CellsSentTotal() const { return m_metrics.Totals().cells_sent; }
    uint64_t CellsRecvTotal() const { return m_metrics.Totals().cells_received; }
    // v8.1 D8 — total tunnel wire bytes (cells * CELL_TOTAL_BYTES; excludes the small
    // fixed OP_EMULEPROT/opcode header). Honest tunnel-carried byte figure.
    uint64_t BytesSentTotal() const { return m_metrics.Totals().bytes_sent; }
    uint64_t BytesRecvTotal() const { return m_metrics.Totals().bytes_received; }
    // v8.1 D8 — EWMA mean end-to-end tunnel RTT in ms (0 = unknown / no sample yet).
    // Measured by a periodic fire-and-forget TUN_OP_PING probe (see Tick).
    uint32_t MeanRttMs() const { return m_metrics.Totals().mean_rtt_ms; }
private:
    friend class CKad6ExitSocket;
    friend class CKad6OriginSocket;
    CLiveTunnel();
    CLiveTunnel(const CLiveTunnel&) = delete;
    CLiveTunnel& operator=(const CLiveTunnel&) = delete;
    static uint32_t NewCircuitId();
    bool SendCellToPeer(CUpDownClient* peer, const uint8_t cell[CELL_TOTAL_BYTES]);
    void DestroyCircuitFailClosed(const std::shared_ptr<CLiveCircuit>& circ);
    void TransitionCircuitDestroyed(const std::shared_ptr<CLiveCircuit>& circ);
    LiveCircuitRegistry& HandshakeCircuitRegistry() override { return m_circuitRegistry; }
    bool SendHandshakeCell(LiveHandshakePeerHandle peer, const uint8_t* cell) override {
        return SendCellToPeer(static_cast<CUpDownClient*>(peer), cell);
    }
    bool ReadHandshakePeer(LiveHandshakePeerHandle peer,
                           LiveHandshakePeerView& view) const override;
    void DestroyHandshakeCircuit(const std::shared_ptr<CLiveCircuit>& circuit) override { DestroyCircuitFailClosed(circuit); }
    uint32_t NewHandshakeCircuitId() override { return NewCircuitId(); }
    void ResolveHandshakeExitKey(LiveHandshakePeerHandle exit, CLiveCircuit& circuit) override;
    void RegisterActiveHandshakeCircuit(const std::shared_ptr<CLiveCircuit>& circuit) override;
    const uint8_t* LocalHandshakeUserHash() const override;
    const uint8_t* LocalHandshakeNodePublicKey() const override;
    bool SignHandshakeTranscript(const uint8_t* bytes, size_t length, uint8_t signature[64]) const override;
    bool HashHandshakeCircuitPrefix(const CLiveCircuit& circuit,
                                    uint8_t out[32]) const override;
    uint32_t HandshakeRuntimeCapabilities() const override;
    LiveHandshakePeerHandle FindConnectedHandshakePeerByHash(const uint8_t hash[16]) const override;
    LiveHandshakePeerHandle FindConnectedHandshakePeer(uint32_t ipv4, uint16_t port) const override;
    uint32_t LocalHandshakePublicIp() const override;
    bool IsRelayMultiCell(uint8_t subCommand) const override;
    bool ParseRelaySubHeader(const uint8_t* plain, size_t plainLength,
                             uint8_t& subCommand, uint32_t& requestId,
                             uint16_t& bodyLength,
                             const uint8_t*& body) const override;
    bool ParseRelayFragmentHeader(const uint8_t* body, size_t bodyLength,
                                  uint16_t& fragmentIndex,
                                  uint16_t& fragmentCount,
                                  uint32_t& messageLength,
                                  const uint8_t*& fragmentData,
                                  size_t& fragmentDataLength) const override;
    LiveRelayFragmentResult IngestRelayFragment(
        uint32_t circuitId, uint32_t requestId,
        uint16_t fragmentIndex, uint16_t fragmentCount,
        uint32_t messageLength, const uint8_t* fragmentData,
        size_t fragmentDataLength,
        std::vector<uint8_t>& completedMessage) override;
    bool DispatchRelayExit(const LiveTunnelRequestCtx& context) override;
    bool HandleCreated_Originator(std::shared_ptr<CLiveCircuit>& circ,
                                  const uint8_t* payload, uint16_t payloadLen);
    bool HandleCreate_Relay(uint32_t circId,
                            const uint8_t* payload, uint16_t payloadLen,
                            CUpDownClient* fromPeer);
    bool BuildExtend(std::shared_ptr<CLiveCircuit>& circ,
                     CUpDownClient* hop2);
    bool BuildSuccessor2Hop();
    bool ContinueOriginatorBuild(std::shared_ptr<CLiveCircuit>& circ);
    bool HandleExtend_Relay(std::shared_ptr<CLiveCircuit>& circ,
                            const uint8_t* payload, uint16_t payloadLen);
    bool ForwardCreatedAsExtended_Relay(uint32_t outboundCircId,
                                        const uint8_t* payload, uint16_t payloadLen);
    bool ForwardExtendCell_Forward(std::shared_ptr<CLiveCircuit>& circ,
                                   const uint8_t* payload, uint16_t payloadLen);
    bool ForwardPaddingCell_Forward(std::shared_ptr<CLiveCircuit>& circ,
                                    const uint8_t* payload, uint16_t payloadLen);
    bool ForwardExtendedCell_Reverse(std::shared_ptr<CLiveCircuit>& circ,
                                     const uint8_t* payload, uint16_t payloadLen);
    bool HandleExtended_Originator(std::shared_ptr<CLiveCircuit>& circ,
                                   const uint8_t* payload, uint16_t payloadLen);
    bool HandleRelay_Originator(std::shared_ptr<CLiveCircuit>& circ,
                                const uint8_t* payload, uint16_t payloadLen);
    bool HandleRelay_Exit(std::shared_ptr<CLiveCircuit>& circ,
                          const uint8_t* payload, uint16_t payloadLen);
    bool SendRelayReply(std::shared_ptr<CLiveCircuit>& circ,
                        const uint8_t* plain, size_t plainLen);
    bool ForwardRelayCell_Forward(std::shared_ptr<CLiveCircuit>& circ,
                                  const uint8_t* payload, uint16_t payloadLen);
    bool ForwardRelayCell_Reverse(std::shared_ptr<CLiveCircuit>& circ,
                                  const uint8_t* payload, uint16_t payloadLen);
    bool SendBulkCellToPeer(CUpDownClient* peer, const uint8_t* bytes, size_t size);
    bool ForwardBulkCell_Reverse(std::shared_ptr<CLiveCircuit>& circ, uint8_t bcmd,
                                 uint64_t nonce_seq, const uint8_t* payload, size_t payloadLen);
    bool SendBulkCellReverse(std::shared_ptr<CLiveCircuit>& circ, uint8_t bcmd,
                             const uint8_t* plain, size_t plainLen);
    void DeliverBulkData(std::shared_ptr<CLiveCircuit>& circ, uint64_t nonce_seq,
                         const uint8_t* payload, size_t payloadLen);
    void DeliverBulkPlain(const uint8_t* plain, size_t plainLen);
    bool EnsureK6ShaperLocked(const std::shared_ptr<CLiveCircuit>& circ,
                              int outputLayers, uint32_t bucketKiB);
    bool QueueK6ShapedRecordLocked(const std::shared_ptr<CLiveCircuit>& circ,
                                   uint64_t streamId, LiveShapedQueuedRecord&& record);
    bool HandleK6ShapedCellLocked(const uint8_t* pkt, size_t size,
                                  CUpDownClient* fromPeer);
    bool PrepareK6ShapedEmissionLocked(
        const std::shared_ptr<CLiveCircuit>& circ,
        const kad6::K6ShapeSlot& slot, LiveShapedEmission& emission);
    bool EmitK6ShapedEmission(
        const std::shared_ptr<CLiveCircuit>& circ,
        const LiveShapedEmission& emission);
    void DeliverK6ShapedOriginLocked(const std::shared_ptr<CLiveCircuit>& circ,
                                     const uint8_t* pkt, size_t size);
    bool EnsureK6ShapeTimerLocked();
    void StopK6ShapeTimerLocked();
    bool SendBulkNack(const uint8_t streamKey[16],
                      const std::vector<std::pair<uint32_t, uint8_t>>& missing);
    static std::string BulkReasmKey(const uint8_t streamKey[16], uint32_t seq);
    void SweepBulkReasm();
    void ProcessProxyIngest();
    void RefreshProxyKeys();   // rebuild the LT7 proxy-key mirror under pending + leaf locks
    void ExitHandle_BulkSubscribe(const TunnelRequestCtx& ctx);   // register/refresh a bulk sub
    void ExitHandle_BulkUnsub(const TunnelRequestCtx& ctx);       // drop a bulk sub
    void ExitHandle_BulkNack(const TunnelRequestCtx& ctx);  // re-push missing (seq, block) + bump NACK rate
    int  ProxyAdaptiveR(const std::string& hex);            // E4' — current r for a stream (adapts on NACK rate)
    void PushBlockToCircuit(std::shared_ptr<CLiveCircuit>& circ, const uint8_t streamKey[16],
                            uint32_t seq, const std::vector<uint8_t>& record, int r, uint8_t blockIdx);
    bool SendReply(const TunnelRequestCtx& ctx, uint8_t reply_op,
                   const uint8_t* payload, size_t payloadLen);
    void ExitHandle_Ping(const TunnelRequestCtx& ctx);
    void ExitHandle_KadSearch(const TunnelRequestCtx& ctx);
    void ExitHandle_EchoLarge(const TunnelRequestCtx& ctx);   // A1.7 test op
    bool BeginExitOperation(const TunnelRequestCtx& ctx, uint8_t reply_op);
    bool CompleteExitOperation(uint32_t circ_id, uint32_t req_id,
                               const uint8_t* payload, size_t payloadLen);
    bool SendExitOperationPart(uint32_t circ_id, uint32_t req_id,
                               const uint8_t* payload, size_t payloadLen);
    void AbortExitOperation(uint32_t circ_id, uint32_t req_id);
    void ExitHandle_KadSearchV2(const TunnelRequestCtx& ctx);   // B1
    void ExitHandle_KadCancel(const TunnelRequestCtx& ctx);     // B7
    void ExitHandle_Kad6Gateway(const TunnelRequestCtx& ctx);
    void ExitHandle_Kad6SourceBind(const TunnelRequestCtx& ctx,
                                   const kad6::K6Frame& frame);
    void ExitHandle_Kad6SourceUnbind(const TunnelRequestCtx& ctx,
                                     const kad6::K6Frame& frame);
    void ExitHandle_Kad6Publish(const TunnelRequestCtx& ctx,
                                const kad6::K6Frame& frame);
    void ExitHandle_Kad6Unpublish(const TunnelRequestCtx& ctx,
                                  const kad6::K6Frame& frame);
    void ExitHandle_Kad6TargetTicketReq(const TunnelRequestCtx& ctx,
                                        const kad6::K6Frame& frame);
    void ExitHandle_Kad6Dial(const TunnelRequestCtx& ctx,
                             const kad6::K6Frame& frame);
    void ExitHandle_Kad6StreamData(const TunnelRequestCtx& ctx,
                                   const kad6::K6Frame& frame);
    void ExitHandle_Kad6StreamHalfClose(const TunnelRequestCtx& ctx,
                                        const kad6::K6Frame& frame);
    void ExitHandle_Kad6StreamClose(const TunnelRequestCtx& ctx,
                                     const kad6::K6Frame& frame);
    void ExitHandle_Kad6MaxStreamData(const TunnelRequestCtx& ctx,
                                      const kad6::K6Frame& frame);
    void ExitHandle_Kad6MaxData(const TunnelRequestCtx& ctx,
                                const kad6::K6Frame& frame);
    void ExitHandle_Kad6QuotaKey(const TunnelRequestCtx& ctx,
                                 const kad6::K6Frame& frame);
    void ExitHandle_Kad6QuotaIssue(const TunnelRequestCtx& ctx,
                                   const kad6::K6Frame& frame);
    void ExitHandle_Kad6QuotaPresent(const TunnelRequestCtx& ctx,
                                     const kad6::K6Frame& frame);
    bool SendK6GatewayResponse(const TunnelRequestCtx& ctx, uint8_t msgType,
                               const std::vector<uint8_t>& body);
    bool SendK6GatewayPush(const std::weak_ptr<CLiveCircuit>& circuit,
                           uint32 circId, uint32 requestId, uint8 msgType,
                           uint16 flags, const std::vector<uint8_t>& body);
    void OnK6ExitSocketConnect(uint64 streamId, CKad6ExitSocket* socket, int error);
    void OnK6ExitSocketClosed(uint64 streamId, CKad6ExitSocket* socket, int error);
    void OnK6OriginSocketClosed(uint64 streamId, CKad6OriginSocket* socket);
    bool OnK6ExitPacket(uint64 streamId, const uint8_t* frame, size_t length);
    bool ActivateK6Inbound(CKad6ExitSocket* socket, const kad6::Hash16& fileHash,
                           const std::vector<std::vector<uint8_t>>& initialFrames);
    bool MarkK6SourceServingLocked(uint64 sourceLeaseId,
                                   kad6::K6CohortBackend& backend);
    bool SendK6FlowCredit(uint32 circId,
                          const std::weak_ptr<CLiveCircuit>& circuit,
                          bool fromExit,
                          const kad6::K6MaxStreamData& streamCredit,
                          const kad6::K6MaxData& circuitCredit);
    bool SendK6InitialCredit(uint32 circId, uint64 streamId, uint8 direction,
                             const std::weak_ptr<CLiveCircuit>& circuit,
                             bool fromExit);
    bool ConsumeK6ReceiveCredit(uint32 circId, uint64 streamId, uint8 direction,
                                size_t bytes,
                                const std::weak_ptr<CLiveCircuit>& circuit,
                                bool fromExit);
    void FlushK6OriginCredit(uint32 circId);
    void FlushK6ExitCredit(uint32 circId);
    LiveTunnelPeerState m_peerState;
    LiveTunnelMetrics m_metrics;
    bool K6EconomyAdmit(kad6::K6Service service);
    void RefreshK6EconomyMeasurements(uint64 nowSeconds,
        const std::array<uint64, static_cast<size_t>(kad6::K6Service::Count)>& active);
    bool IsK6PublicReleaseEnabled() const;
    bool EnsureK6QuotaAuthority(uint64 nowSeconds);
    bool K6QuotaPrincipal(const TunnelRequestCtx& ctx, kad6::Hash32& principal,
                          std::array<uint8_t, 6>& prefix48,
                          uint32& asn) const;
    bool K6QuotaIssuerTrusted(const uint8_t nodePub[32]) const;
    uint32 K6SelectOriginCircuit(uint32 requiredCaps,
                                 uint32 pinnedCircId = 0,
                                 size_t minimumHops = 1) const;
    bool K6CircuitHasExitCaps(uint32 circId, uint32 requiredCaps,
                              size_t minimumHops = 1) const;
    bool K6QuotaRoundTrip(uint32 circId, uint8 msgType,
                          const std::vector<uint8_t>& body,
                          uint8 expectedMsgType, uint32 timeoutMs,
                          kad6::K6Frame& response);
    bool K6AcquireAnonymousQuota(uint32 targetCircId,
                                 kad6::K6QuotaService service,
                                 uint8 operationMsgType,
                                 const std::vector<uint8_t>& operationBody,
                                 uint32 timeoutMs);
    bool ConsumeK6QuotaGrant(const TunnelRequestCtx& ctx,
                             kad6::K6QuotaService service,
                             const kad6::K6Frame& frame,
                             uint64* allocationId = nullptr);
    bool QueueK6FairPayloadLocked(uint64 streamId, uint8 direction,
                                  std::vector<uint8_t>&& bytes,
                                  size_t creditBytes = 0);
    void ReleaseK6FairStreamLocked(uint64 streamId);
    bool ProcessK6FairTick();
    bool ApplyK6ServiceSwitch(kad6::K6Service service, bool enabled,
                              uint32 drainSeconds);
    bool ApplyK6PublicRelease(bool enable,
                              const kad6::K6ReleaseEvidence* evidence,
                              uint32 drainSeconds);
    void RefreshK6PublicRelease(uint64 nowSeconds, uint32 drainSeconds = 300);
    static std::string K6AuthorizedTargetKey(uint32 circId, uint32 requestId,
                                             const kad6::Hash16& resultId);
    static bool K6AllowTicketTarget(void* context, kad6::Byte service,
                                    const kad6::K6Endpoint& endpoint);
    static bool K6ConsumeTicket(void* context, const kad6::K6TargetTicket& ticket);
    kad6::K6TargetPolicy K6TicketPolicy();
    bool IssueK6RuntimeTicket(const K6AuthorizedTarget& target, uint64 maxBytes,
                              kad6::K6Provenance provenance, uint64 session,
                              uint64 stream, uint64 sequence,
                              std::vector<uint8_t>& wire);
    void SweepK6Gateway(uint64 nowSeconds,
                        const std::set<uint32_t>& activeCircuits);
    static std::string K6BinaryKey(const uint8_t* bytes, size_t length);
    static std::string K6ShadowKey(const kad6::K6SourceLease& lease);
    bool EnsureK6SourceEpochsLoaded();
    void SweepK6SourceLeases(const std::set<uint32_t>& activeCircuits,
                             const std::set<uint32_t>& teardownQueue,
                             uint64 nowSeconds);
    void QueueK6ShadowRefreshes(uint64 nowSeconds);
    void StartDueK6ShadowPublishes(uint64 nowSeconds);
    void StartK6VisibilityProbes(uint64 nowSeconds);
    void RefreshK6NativePublishes(uint64 nowSeconds);
    void ExitHandle_LiveSubscribe(const TunnelRequestCtx& ctx);
    static std::string LiveStreamKeyHex(const uint8_t streamKey[16]);
public:
    void ExitRelayLiveControl(const uint8_t streamKey[16],
                              bool hasBitmap, uint16_t bitmap, uint32_t oldestSeq,
                              const uint8_t* pubkeyOrNull);
    void ExitRelayPeerList(const uint8_t streamKey[16],
                           uint32_t upstreamIP, uint16_t upstreamPort,
                           const uint32_t* ips, const uint16_t* ports, uint8_t count);
private:
    void FinishDueSearchJobs();
    void SerializeSearchResults(const std::string& keyword,
                                std::vector<uint8_t>& out) const;
    uint16_t SendK6SearchResults(const TunnelSearchJob& job);
    void StopSearchJobKad(const TunnelSearchJob& job);
    mutable CCriticalSection m_pendingLock;
    using PendingHandle = eSELive::LiveTunnelPending::Handle;
    eSELive::LiveTunnelPending m_pendingRequests;
    LiveRelayDispatcher m_relayDispatcher;
    LiveExitServices m_exitServices;
    PendingHandle RegisterPending(uint32_t& req_id);
    bool WaitPending(uint32_t req_id, PendingHandle pending, uint32_t timeoutMs,
                     std::vector<uint8_t>& outReply, uint32_t* outResult,
                     uint32_t* outCircuitId = NULL);
    void SignalReply(uint32_t req_id, const uint8_t* reply, size_t replyLen,
                     uint32_t result);
    uint32_t SendMessagePinned(uint32_t req_id, uint8_t sub_cmd,
                               const uint8_t* msg, size_t msgLen,
                               uint32_t requiredExitCaps = 0,
                               uint32_t pinnedCircId = 0);
    using MtOp = LiveDeferredOp;
    using MainThreadReq = LiveDeferredWork;
    static constexpr MtOp MT_SEND = MtOp::Send;
    static constexpr MtOp MT_BUILD_1HOP = MtOp::Build1Hop;
    static constexpr MtOp MT_BUILD_2HOP = MtOp::Build2Hop;
    static constexpr MtOp MT_SEND_MSG = MtOp::SendMessage;
    static constexpr MtOp MT_BUILD_3HOP = MtOp::Build3Hop;
    static constexpr MtOp MT_K6_SERVICE_SWITCH = MtOp::K6ServiceSwitch;
    static constexpr MtOp MT_K6_RELEASE_SWITCH = MtOp::K6ReleaseSwitch;
    LiveTunnelScheduler m_scheduler;
    void EnqueueSend(const uint8_t* payload, size_t payloadLen);
    void EnqueueSendMsg(uint32_t req_id, uint8_t sub_cmd,
                        const uint8_t* msg, size_t msgLen,
                        uint32_t requiredExitCaps = 0,
                        uint32_t pinnedCircId = 0);
    bool HandleK6SearchReply(const std::shared_ptr<CLiveCircuit>& circ,
                             uint32_t req_id, const std::vector<uint8_t>& wire);
    void RebuildPeersCache();
    mutable CCriticalSection m_lock;
    eSELive::LiveCircuitRegistry m_circuitRegistry; // caller-serialized by m_lock
    eSELive::LiveCircuitHandshake m_handshake;
    LiveTunnelKadBridge m_kadBridge;
    bool LoadK6Guard();
    bool SaveK6Guard(const uint8_t nodePub[32], uint64_t expiresAt);
};
}  // namespace eSELive
