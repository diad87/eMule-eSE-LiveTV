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

#include <memory>
#include <vector>
#include <string>   // v0.71 C — TunnelPing text I/O
#include <map>      // v0.71 C — pending request table
#include <deque>    // v0.72 — main-thread work queue
#include <utility>  // v0.72 — std::move
#include <functional> // v8.1 A2 - std::function handler registry
#include <set>     // v8.1.2 E3.1 — exit-proxy stream-key set

class CUpDownClient;

namespace eSELive {

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

// Endpoint opaque handle exposed to LiveMeshManager (Cap 5 §5.6.3 thesis).
// The mesh layer manipulates TunnelEndpoint references, not raw client pointers.
// RESERVED for the Sprint E data plane (C6/E3), where CLiveMeshManager re-indexes
// peers by endpoint. It is intentionally NOT used by the exit's ExitStreamProxy,
// which keys proxied viewers by bare circ_id: at an exit the originating viewer's
// pubkey is structurally unknowable (onion routing hides the originator — a relay
// circuit knows only its neighbour hops), and circ_id is the stable session handle
// that survives a CUpDownClient swap. remote_pubkey is populated only on the
// ORIGINATOR side, from the channel pubkey the viewer already holds.
struct TunnelEndpoint {
    uint32_t circ_id;
    uint8_t  remote_pubkey[32];      // origin's Ed25519 pub (channel pubkey for streams)
};

class CLiveTunnel {
public:
    static CLiveTunnel& Get();

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

    size_t ActiveCircuitCount() const;
    size_t PendingCircuitCount() const;      // v0.71 P3.8 — circuits in CREATE/CREATED handshake
    size_t RelayCircuitCount() const;        // v0.71 P3.3 — circuits we relay (intermediate)
    size_t TotalCircuitCount() const;        // v0.71 P3.3 — for UI / metrics

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

    // v8.1 D4 — PST pool make-before-break successor. tunnelOnly-STRICT (no
    // any-peer fallback), so it builds NOTHING when no fork peer is connected
    // (single-PC no-op). At most one 1-hop circuit. Called from CKadV2TunnelPool::Tick.
    bool BuildSuccessorCircuit();

    // v0.71 B (2-hop) — extended test: builds a 1-hop circuit AND, once
    // CREATED arrives, requests a 2nd hop. Returns the V-side circ_id.
    // If only 1 fork peer is available, hop2 loops back to the same peer
    // (semantically weird but valid for state-machine testing). Real
    // multi-node deployments pick 2 distinct peers.
    uint32_t BuildTestCircuit2Hop();

    // v0.71 C — sub-protocol for application payloads carried inside
    // CELL_RELAY. The plaintext after onion peel has this layout:
    //   [0]     sub_cmd (TunnelOpCmd)
    //   [1..4]  req_id (uint32 LE) — correlates request to reply
    //   [5..6]  text_len (uint16 LE)
    //   [7..N]  text bytes
    // Future sub_cmds (Kad search, Live subscribe, etc.) will extend
    // this. Keep the first 7 bytes structure stable.
    enum TunnelOpCmd : uint8_t {
        TUN_OP_PING        = 0x01,
        TUN_OP_PING_REPLY  = 0x02,
        // v0.71 P1.A — real operations through tunnel
        TUN_OP_KAD_SEARCH       = 0x10,   // V → exit: do Kad keyword search on my behalf
        TUN_OP_KAD_RESULT       = 0x11,   // exit → V: serialized search hits
        TUN_OP_LIVE_SUBSCRIBE   = 0x20,   // V → exit: forward subscribe to broadcaster
        TUN_OP_LIVE_SUB_ACK     = 0x21,   // exit → V: ack / broadcaster contact info
        TUN_OP_LIVE_HEARTBEAT   = 0x22,   // exit → V: relay broadcaster heartbeat/announce (C3)
        TUN_OP_LIVE_PEER_LIST   = 0x23,   // exit → V: relay broadcaster's OP_LIVE_PEER_LIST alt sources (C2/C3)
        // v8.1 Sprint A — multi-cell ops. sub_cmd >= TUN_MULTICELL_OP_MIN (0x40)
        // ALWAYS carries an 8-byte fragment header in its body (see
        // LiveCellQueue.h). 0x42-0x7F are reserved for Sprint B/C.
        TUN_OP_ECHO_LARGE       = 0x40,   // A1.7 test: V -> exit, arbitrary-size echo
        TUN_OP_ECHO_LARGE_REPLY = 0x41,   // A1.7 test: exit -> V, echoed payload
        // v8.1 Sprint B — real Kad search through the tunnel (multi-cell).
        TUN_OP_KAD_SEARCH_V2    = 0x42,   // V -> exit: run a real Kad CSearch on my behalf
        TUN_OP_KAD_RESULT_V2    = 0x43,   // exit -> V: rich result records (multi-cell)
        TUN_OP_KAD_CANCEL       = 0x44,   // V -> exit: abort an in-flight search by req_id
        // v8.1.2 Sprint E (E3.2) — bulk data plane control (0x50-0x5F reserved for E).
        // SUBSCRIBE body: stream_key 16 + flags 1 + r_pref 1 + session_id 4. session_id
        // groups a viewer's multiple bulk circuits so the exit can STRIPE symbols across
        // them (one viewer = one session_id on all its circuits).
        TUN_OP_BULK_SUBSCRIBE   = 0x50,   // V -> exit: start the bulk push for a stream on this circuit
        // NACK body: stream_key 16 + count 1 + (seq 4 + block_idx 1)*count. Requests a re-push
        // of specific (seq, block) the viewer could not reassemble (E3.5 gap-fill).
        TUN_OP_BULK_NACK        = 0x52,   // V -> exit: re-push missing (seq, block)
        TUN_OP_BULK_UNSUB       = 0x54    // V -> exit: stop the bulk push on this circuit
    };

    // === v8.1 A2 - generic exit-side dispatcher ============================
    // Replaces the hardcoded sub_cmd switch in HandleRelay_Exit. One handler
    // is registered per sub_cmd; once a request is fully received (a legacy
    // single-cell op, or a reassembled multi-cell op) the dispatcher builds a
    // TunnelRequestCtx and invokes the handler. New ops (Sprint B/C) just
    // register a handler instead of editing HandleRelay_Exit.
    struct TunnelRequestCtx {
        std::shared_ptr<CLiveCircuit> circ;     // circuit the request arrived on
        uint8_t        sub_cmd = 0;
        uint32_t       req_id  = 0;
        const uint8_t* body    = nullptr;       // request body (frag header stripped)
        size_t         bodyLen = 0;
    };
    using TunnelOpHandler = std::function<void(const TunnelRequestCtx&)>;

    // Register an exit-side handler for a sub_cmd. Last registration wins.
    void RegisterExitHandler(uint8_t sub_cmd, TunnelOpHandler handler);

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
    struct CircuitSnapshot {
        uint32_t circ_id;
        uint8_t  role;          // 0 = Originator, 1 = Relay
        uint8_t  state;         // CircuitState as uint
        uint32_t age_ms;
        uint32_t hop_count;
        uint8_t  next_hop_set;  // relay-side: 1 if forwarding to hop2
        uint32_t next_circ_id;
        uint8_t  auth_ok;       // v8.x Phase 2: 1 if ALL hops completed the authenticated v2 handshake
    };
    void GetCircuitsSnapshot(std::vector<CircuitSnapshot>& out) const;

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
    // up to timeoutMs for the resulting circuit id. hops is 1 or 2. Returns
    // the circuit id, or 0 on failure / timeout.
    uint32_t RequestTestCircuit(int hops, uint32_t timeoutMs);

    // Value-typed peer info — safe to hand to a worker thread (unlike raw
    // CUpDownClient pointers, which only the main thread may dereference).
    struct PeerSnapshot {
        uint32_t ip;
        uint16_t port;
        uint32_t fork_caps;
        uint32_t ese_caps;
    };
    // Worker-thread safe. Copies the peer snapshot the main thread refreshes
    // in ProcessMainThreadWork(). outTunnelingCount = connected peers that
    // advertised privacy-tunneling capability.
    void GetPeersSnapshot(std::vector<PeerSnapshot>& outAll,
                          size_t& outTunnelingCount) const;

    // MAIN THREAD ONLY. Drains the marshaled-work queue and refreshes the
    // peer cache. Call once per Kad process tick.
    void ProcessMainThreadWork();

    // v0.71 P3.3 — total counts of cells sent / received for metrics.
    uint64_t CellsSentTotal() const { return m_cellsSentTotal; }
    uint64_t CellsRecvTotal() const { return m_cellsRecvTotal; }
    // v8.1 D8 — total tunnel wire bytes (cells * CELL_TOTAL_BYTES; excludes the small
    // fixed OP_EMULEPROT/opcode header). Honest tunnel-carried byte figure.
    uint64_t BytesSentTotal() const { return m_bytesSentTotal; }
    uint64_t BytesRecvTotal() const { return m_bytesRecvTotal; }
    // v8.1 D8 — EWMA mean end-to-end tunnel RTT in ms (0 = unknown / no sample yet).
    // Measured by a periodic fire-and-forget TUN_OP_PING probe (see Tick).
    uint32_t MeanRttMs() const { return m_meanRttMs; }

private:
    CLiveTunnel();
    CLiveTunnel(const CLiveTunnel&) = delete;
    CLiveTunnel& operator=(const CLiveTunnel&) = delete;

    static uint32_t NewCircuitId();

    // v0.71 P3.3 — send a packed cell (CELL_TOTAL_BYTES) to a peer over
    // its existing CClientReqSocket, wrapped as OP_LIVE_TUNNEL_CELL.
    // Returns true if the packet was queued for send. Increments stats.
    bool SendCellToPeer(CUpDownClient* peer, const uint8_t cell[CELL_TOTAL_BYTES]);

    // Originator-side CREATED handler: complete handshake on hop 1.
    bool HandleCreated_Originator(std::shared_ptr<CLiveCircuit>& circ,
                                  const uint8_t* payload, uint16_t payloadLen);

    // Relay-side CREATE handler: generate ephemeral, derive keys, reply
    // with CREATED, register as relay circuit so future RELAY cells are
    // peeled correctly.
    bool HandleCreate_Relay(uint32_t circId,
                            const uint8_t* payload, uint16_t payloadLen,
                            CUpDownClient* fromPeer);

    // v0.71 B — originator side: send CELL_EXTEND through the now-active
    // hop1 circuit. Generates a fresh X25519 ephemeral for V↔hop2 and
    // encrypts a 38-byte payload (hop2 IP + port + new ev_pub) with
    // hop1's K_send. The receiver-side handlers below complete the
    // round-trip. Returns true on success.
    bool BuildExtend(std::shared_ptr<CLiveCircuit>& circ,
                     CUpDownClient* hop2);

    // v8.1.1 F-2 — build a TRUE 2-hop circuit V -> hop1 -> exit with hop1 != exit
    // (DISTINCT nodes by user-hash), so the exit never has a direct socket to V and
    // never sees V's IP (real anonymity / G1). Picks two distinct tunnel-capable
    // peers; pre-stages hop2 on the originator so HandleCreated_Originator auto-
    // extends after hop1's CREATED. NO loopback / 1-hop fallback here — returns
    // false if fewer than 2 distinct tunnel peers are connected (the caller decides
    // whether a degraded 1-hop circuit is acceptable). The loopback degenerate case
    // stays confined to BuildTestCircuit2Hop (manual 2-PC dev test only).
    bool BuildSuccessor2Hop();

    // v0.71 B — relay side: a CELL_EXTEND cell arrived on a relay-side
    // circuit. Peel V→hop1 layer, parse hop2 endpoint + new ephemeral,
    // pick new outbound circ_id, send CELL_CREATE to hop2. Store
    // forwarding state on the relay circuit.
    bool HandleExtend_Relay(std::shared_ptr<CLiveCircuit>& circ,
                            const uint8_t* payload, uint16_t payloadLen);

    // v0.71 B — relay side: CELL_CREATED arrived from hop2 on our
    // outbound forwarding circ. Look up which V-side circuit asked for
    // it, wrap CREATED payload with K_send_r_to_v, send as
    // CELL_EXTENDED back to V on V's circ_id.
    bool ForwardCreatedAsExtended_Relay(uint32_t outboundCircId,
                                        const uint8_t* payload, uint16_t payloadLen);

    // v0.71 B — originator side: a CELL_EXTENDED cell arrived on a
    // V-side originator circuit. Peel V→hop1 layer to reveal hop2's
    // er_pub. Derive V↔hop2 keys, add hop2 to m_hops, mark fully Active
    // with 2 hops. Wipe ephemeral.
    bool HandleExtended_Originator(std::shared_ptr<CLiveCircuit>& circ,
                                   const uint8_t* payload, uint16_t payloadLen);

    // v0.71 B — looks up a relay-side circuit by its OUTBOUND id (the
    // one we chose for talking to hop2). Returns nullptr if not found.
    std::shared_ptr<CLiveCircuit> FindRelayByOutgoingId(uint32_t outboundCircId);

    // v0.71 C — CELL_RELAY handlers.
    // Originator: peel ALL hops, parse TunnelOp, deliver to pending
    // request table or drop if no waiter.
    bool HandleRelay_Originator(std::shared_ptr<CLiveCircuit>& circ,
                                const uint8_t* payload, uint16_t payloadLen);
    // Exit/relay-with-2-hops: peel ALL hops (we keep both layers'
    // recv keys in m_hops when we're the exit). Parse TunnelOp.
    // For PING, build PING_REPLY and wrap back through both hops.
    bool HandleRelay_Exit(std::shared_ptr<CLiveCircuit>& circ,
                          const uint8_t* payload, uint16_t payloadLen);

    // v0.71 C — wrap a plaintext payload through a relay-side circuit's
    // hops in REVERSE order (mirror of originator's OnionEncrypt) and
    // send back to V via m_prevHopClient. Used when the exit produces
    // a reply (PING_REPLY, KadSearch result, etc.).
    bool SendRelayReply(std::shared_ptr<CLiveCircuit>& circ,
                        const uint8_t* plain, size_t plainLen);

    // === v8.1.1 F-1 — TRUE 2-hop relay forwarding of DATA cells (CELL_RELAY) ===
    // Until now the code only TERMINATED relay cells (HandleRelay_Exit peels ALL
    // layers + dispatches), so the only working configs were 1-hop (exit==hop1,
    // directly connected to V) or loopback — in both the exit sees V's IP, defeating
    // G1. These forward an OPAQUE cell through an intermediate hop1 WITHOUT decrypting
    // the application payload: hop1 peels/re-adds exactly ONE layer and relays. The
    // construction side (non-loopback HandleExtend_Relay) already stashes the
    // forwarding state (m_nextHopClient/m_nextCircId on hop1, m_prevHopClient on the
    // exit); these two methods are the missing DATA path. Counter-based crypto is fine
    // here (control rides TCP, no expected loss); the bulk data plane uses the
    // explicit-nonce twins (LiveCircuit::*Explicit) because FEC/NACK lose cells.
    //   Forward (V -> hop1 -> exit): peel our 1 layer, relay inner ct on m_nextCircId.
    bool ForwardRelayCell_Forward(std::shared_ptr<CLiveCircuit>& circ,
                                  const uint8_t* payload, uint16_t payloadLen);
    //   Reverse (exit -> hop1 -> V): re-add our 1 layer, relay to V on circ->Id().
    bool ForwardRelayCell_Reverse(std::shared_ptr<CLiveCircuit>& circ,
                                  const uint8_t* payload, uint16_t payloadLen);

    // === v8.1.2 Sprint E — bulk data plane carrier (OP_LIVE_BULK_CELL 0xD9) =====
    // Same 2-hop topology as F-1 but for variable-length bulk cells with an EXPLICIT
    // on-wire nonce (B2), so FEC/NACK loss never tears the circuit. Data flows
    // exit -> hop1 -> V only (push); the viewer's NACK/feedback ride the 512 B control
    // cells (TUN_OP_BULK_*).
    //   Send a variable-length bulk cell to a peer wrapped as OP_LIVE_BULK_CELL.
    bool SendBulkCellToPeer(CUpDownClient* peer, const uint8_t* bytes, size_t size);
    //   hop1 relays a bulk cell back to V: re-add our hop1->V layer (explicit nonce),
    //   preserving bcmd; re-pack on V's circ id and send to m_prevHopClient.
    bool ForwardBulkCell_Reverse(std::shared_ptr<CLiveCircuit>& circ, uint8_t bcmd,
                                 uint64_t nonce_seq, const uint8_t* payload, size_t payloadLen);
    //   EXIT pushes ONE bulk cell toward V (E3.3 scheduler uses this): wrap with our
    //   1 layer (explicit nonce from m_bulk_nonce_send++) and send to m_prevHopClient.
    bool SendBulkCellReverse(std::shared_ptr<CLiveCircuit>& circ, uint8_t bcmd,
                             const uint8_t* plain, size_t plainLen);
    //   Viewer terminating decode: explicit-nonce onion-decrypt-all -> replay check ->
    //   BULK_DATA -> accumulate into reassembly; on a complete segment, RS-decode the
    //   whole CHUNK_V2 record (E3.4) and deliver it to the chunk pipeline.
    void DeliverBulkData(std::shared_ptr<CLiveCircuit>& circ, uint64_t nonce_seq,
                         const uint8_t* payload, size_t payloadLen);

    // E3.4 reassembly: symbols of a (streamKey, seq) segment arrive STRIPED across the
    // viewer's bulk circuits, so this is keyed globally by (streamKey, seq), not per
    // circuit. The decode is attempted only once every block has >= k_b symbols (bounds
    // the 3 MB-buffer cost); Bulk::BulkDecodeSegment then rebuilds the signed CHUNK_V2
    // record byte-identical -> existing verify/inject (unchanged).
    struct BulkReasmEntry {
        uint8_t           streamKey[16] = {0};   // for E3.5 NACK addressing
        uint32_t          seq      = 0;
        uint32_t          msg_len  = 0;
        uint8_t           n_blocks = 0;
        uint8_t           r        = 0;
        DWORD             first_seen_tick = 0;
        bool              done     = false;
        Bulk::BulkLayout  layout;                // derived from msg_len on the first symbol
        bool              haveLayout = false;
        std::vector<int>  blockRecv;             // distinct symbols received per block
        std::vector<Bulk::BulkSymbol> symbols;   // deduped by (block_idx, symbol_idx)
        DWORD             lastNackTick = 0;       // E3.5 — throttle NACKs for this (streamKey,seq)
    };
    // E3.5 (viewer) — send a NACK requesting re-push of the listed (seq, block) pairs of a
    // stream, on an Active bulk circuit. Returns true if a NACK was sent.
    bool SendBulkNack(const uint8_t streamKey[16],
                      const std::vector<std::pair<uint32_t, uint8_t>>& missing);
    std::map<std::string, BulkReasmEntry> m_bulkReasm;          // key = streamKeyHex + ":" + seq
    std::map<uint32_t, Bulk::BulkReplayWindow> m_bulkReplay;    // per terminating circ_id (recv dir)
    static std::string BulkReasmKey(const uint8_t streamKey[16], uint32_t seq);
    // Sweep stale partial segments (pattern A5); called from Tick().
    void SweepBulkReasm();

    // === v8.1.2 E3.1/E3.3 — exit proxy ingest -> FEC encode -> stripe push ==
    // LEAF lock: held ONLY to touch the m_proxy* state, NEVER while acquiring m_lock /
    // m_pendingLock / the manager lock -> the documented tunnel->manager order is never
    // inverted, so the chunk hooks (which run under the manager lock) are deadlock-safe.
    mutable CCriticalSection m_proxyIngestLock;
    std::set<std::string> m_proxyKeys;                 // streamKeyHex this node exit-proxies (mirror of m_exitLiveSubs)
    struct ProxyFrag {
        uint32_t totalLen = 0; uint16_t fragCount = 0; uint16_t haveCount = 0; DWORD firstTick = 0;
        std::vector<uint8_t> buf; std::vector<bool> got;
    };
    std::map<std::string, ProxyFrag> m_proxyFragReasm; // key = streamKeyHex + ":" + seq (exit-side 0xE0 reassembly)
    std::deque<std::vector<uint8_t>> m_proxyReady;     // whole CHUNK_V2 records ready to FEC-encode + push
    // MAIN THREAD (Tick, under m_lock): refresh m_proxyKeys, drain m_proxyReady, FEC-encode each
    // record and push its symbols across the stream's subscribed bulk circuits.
    void ProcessProxyIngest();
    void RefreshProxyKeys();   // rebuild m_proxyKeys from m_exitLiveSubs + m_bulkSubs (under m_pendingLock + leaf)

    // v8.1.2 E3.2 — explicit bulk subscriptions. The viewer sends TUN_OP_BULK_SUBSCRIBE on
    // EACH of its bulk circuits, all carrying the SAME session_id, so the exit can group a
    // viewer's circuits and STRIPE a segment's symbols across them. When a stream has explicit
    // bulk subs, ProcessProxyIngest pushes to THESE (grouped + striped); otherwise it falls
    // back to the C7 control subs (full k+r per circuit). Under m_pendingLock.
    struct BulkSub { uint32_t circ_id = 0; uint32_t session_id = 0; uint8_t r_pref = 0; DWORD lastSeen = 0; };
    std::map<std::string, std::vector<BulkSub>> m_bulkSubs;   // streamKeyHex -> subs
    void ExitHandle_BulkSubscribe(const TunnelRequestCtx& ctx);   // register/refresh a bulk sub
    void ExitHandle_BulkUnsub(const TunnelRequestCtx& ctx);       // drop a bulk sub

    // v8.1.2 E3.5 (NACK gap-fill) + E4' (adaptive r). The exit retains the last few whole
    // records per stream so it can RE-PUSH blocks a viewer could not reassemble (TUN_OP_BULK_
    // NACK), and tracks the NACK rate to ADAPT the parity r up/down. All under m_lock.
    struct ProxyRecentRec { uint8_t streamKey[16] = {0}; uint32_t seq = 0; std::vector<uint8_t> record; DWORD tick = 0; };
    std::deque<ProxyRecentRec> m_proxyRecent;          // ring of recent records for re-push
    struct ProxyStreamCtl { int r = Bulk::BULK_DEFAULT_R; uint32_t nackCount = 0; DWORD windowStart = 0; };
    std::map<std::string, ProxyStreamCtl> m_proxyCtl;  // per streamKeyHex — adaptive r + NACK telemetry
    void ExitHandle_BulkNack(const TunnelRequestCtx& ctx);  // re-push missing (seq, block) + bump NACK rate
    int  ProxyAdaptiveR(const std::string& hex);            // E4' — current r for a stream (adapts on NACK rate)
    // Re-encode `record` and push ONLY block `blockIdx` to `circ` (used by ExitHandle_BulkNack).
    void PushBlockToCircuit(std::shared_ptr<CLiveCircuit>& circ, const uint8_t streamKey[16],
                            uint32_t seq, const std::vector<uint8_t>& record, int r, uint8_t blockIdx);

    // === v8.1 A2 - generic exit dispatcher (internals) =====================
    // Look up and invoke the registered handler for a fully-received request.
    void DispatchExitRequest(const TunnelRequestCtx& ctx);
    // Fragment + send a reply back to V. reply_op >= 0x40 is split into
    // multi-cell fragments (sub-header + frag-header per cell); a legacy
    // reply op (< 0x40) goes as one single cell. Each cell is onion-wrapped
    // and sent via SendRelayReply.
    bool SendReply(const TunnelRequestCtx& ctx, uint8_t reply_op,
                   const uint8_t* payload, size_t payloadLen);
    // Built-in exit handlers (registered in the constructor).
    void ExitHandle_Ping(const TunnelRequestCtx& ctx);
    void ExitHandle_KadSearch(const TunnelRequestCtx& ctx);
    void ExitHandle_EchoLarge(const TunnelRequestCtx& ctx);   // A1.7 test op
    // A2.2 - sub_cmd -> handler registry.
    std::map<uint8_t, TunnelOpHandler> m_exitHandlers;
    // A1.5 - partial multi-cell message under reassembly, keyed by
    // ExitOpKey(circ_id, req_id) so messages on different circuits that happen
    // to share a req_id never collide (the exit reassembles for many circuits
    // at once). Accessed under m_pendingLock. Swept by Tick() (A5).
    std::map<uint64_t, ReassemblyEntry> m_reassembly;

    // === v8.1 A6 - deferred exit-side operations ==========================
    // An exit handler that cannot answer immediately (e.g. a real Kad CSearch
    // in Sprint B that completes via callbacks up to 45 s later) registers an
    // ExitOperation in the handler and calls CompleteExitOperation when its
    // work finishes. The op remembers which circuit + req_id to reply on and
    // the reply opcode; it holds a weak_ptr so a slow operation does not keep a
    // rotated-out circuit alive. Swept on TTL / aborted when its circuit dies.
    struct ExitOperation {
        std::weak_ptr<CLiveCircuit> circ;       // circuit to reply on
        uint32_t circ_id  = 0;
        uint32_t req_id   = 0;
        uint8_t  reply_op = 0;
        DWORD    started  = 0;
    };
    static uint64_t ExitOpKey(uint32_t circ_id, uint32_t req_id) {
        return ((uint64_t)circ_id << 32) | req_id;
    }
    std::map<uint64_t, ExitOperation> m_exitOps;   // under m_pendingLock
    // Register a deferred reply; the handler returns without answering.
    bool BeginExitOperation(const TunnelRequestCtx& ctx, uint8_t reply_op);
    // Send the deferred reply (fragmented via SendReply) and discard the op.
    // Returns false if the op is unknown or its circuit has gone.
    bool CompleteExitOperation(uint32_t circ_id, uint32_t req_id,
                               const uint8_t* payload, size_t payloadLen);
    // Discard a deferred op without replying (e.g. cancelled / circuit dead).
    void AbortExitOperation(uint32_t circ_id, uint32_t req_id);

    // === v8.1 Sprint B - real Kad search via tunnel =======================
    // TUN_OP_KAD_SEARCH_V2 starts a real Kad CSearch on the exit and defers the
    // reply (A6). Results accumulate in CLiveKadBridge's directory (filled async
    // on the Kad UDP thread, thread-safe there); after TUN_SEARCH_WINDOW_MS,
    // Tick() reads the matching streams, serializes them as TUN_OP_KAD_RESULT_V2
    // and completes the deferred op. All of THIS runs on the main thread.
    struct TunnelSearchJob {
        uint32_t              circ_id  = 0;
        uint32_t              req_id   = 0;
        std::string           keyword;          // normalized (lowercase)
        DWORD                 deadline = 0;      // GetTickCount() when to reply
        std::vector<uint32_t> kadSearchIds;     // CSearch ids to StopSearch on finish
    };
    std::map<uint64_t, TunnelSearchJob> m_searchJobs;   // key = ExitOpKey, under m_pendingLock
    void ExitHandle_KadSearchV2(const TunnelRequestCtx& ctx);   // B1
    void ExitHandle_KadCancel(const TunnelRequestCtx& ctx);     // B7
    // v8.1 Sprint C (C2) — exit forwards a tunneled subscribe to the broadcaster
    // on the viewer's behalf, then acks. Runs on the main thread (OnCellReceived).
    void ExitHandle_LiveSubscribe(const TunnelRequestCtx& ctx);

    // v8.1 Sprint C (C3) — active exit-proxy subscriptions: streamKey (hex) ->
    // the set of V-side circuit ids that subscribed to that stream through us.
    // Populated by ExitHandle_LiveSubscribe; consumed by ExitRelayLiveControl to
    // tunnel the broadcaster's heartbeat/announce back to each subscribed V.
    // Swept (dead circuits / TTL) in Tick. Under m_pendingLock.
    struct ExitLiveSub { DWORD lastSeen = 0; };
    // Per-stream proxy: the broadcaster endpoint we subscribed to (so the sweep
    // can UNSUBSCRIBE when the last viewer leaves — otherwise the exit stays a
    // zombie viewer holding an upload slot) + the set of V circuits to relay to.
    struct ExitStreamProxy {
        uint8_t  streamKey[16] = {0};
        uint32_t bIP   = 0;
        uint16_t bPort = 0;
        std::map<uint32_t, ExitLiveSub> circuits;
    };
    std::map<std::string, ExitStreamProxy> m_exitLiveSubs;
    static std::string LiveStreamKeyHex(const uint8_t streamKey[16]);

public:
    // v8.1 Sprint C (C3) — called from the Live HEARTBEAT/ANNOUNCE handlers
    // (main thread). If THIS node is an exit proxying `streamKey` for one or
    // more tunneled viewers, relay the control update (bitmap+oldestSeq from a
    // heartbeat, and/or the broadcaster pubkey from an announce) to each
    // subscribed circuit as TUN_OP_LIVE_HEARTBEAT. No-op if we proxy no one for
    // this stream, so it is cheap to call unconditionally.
    void ExitRelayLiveControl(const uint8_t streamKey[16],
                              bool hasBitmap, uint16_t bitmap, uint32_t oldestSeq,
                              const uint8_t* pubkeyOrNull);
    // v8.1 Sprint C (C2/C3 finish) — called from CLiveStreamManager::OnPeerListReceived
    // (main thread, BEFORE its m_lock). If THIS node is an exit proxying `streamKey`
    // for tunneled viewers, relay the broadcaster's alternative-source list to each
    // subscribed circuit as TUN_OP_LIVE_PEER_LIST. No-op if we proxy no one for this
    // stream, so it is cheap to call unconditionally. ips are net-order DWORDs,
    // value-preserving through the LE body (no byte-swap).
    void ExitRelayPeerList(const uint8_t streamKey[16],
                           const uint32_t* ips, const uint16_t* ports, uint8_t count);
private:
    // B2/B3 - main thread: reply to jobs whose window elapsed, then drop them.
    void FinishDueSearchJobs();
    // Serialize matching known streams into the TUN_OP_KAD_RESULT_V2 wire body.
    void SerializeSearchResults(const std::string& keyword,
                                std::vector<uint8_t>& out) const;
    // StopSearch on the job's CSearch ids (main thread only).
    void StopSearchJobKad(const TunnelSearchJob& job);

    // v0.71 C — pending tunnel_ping requests. Key = req_id, value = the
    // reply text once it arrives. The TunnelPing() blocking call polls
    // this map under m_pendingLock with a wait/timeout. Cleared on reply
    // or on timeout.
    mutable CCriticalSection m_pendingLock;
    // v8.1 A3 - async request/reply. One PendingRequest per in-flight
    // request, keyed by req_id; the waiter (a webserver worker thread)
    // blocks on `evt`, the cell handler / main thread fills the reply and
    // SetEvent()s. Replaces the v0.71/v0.72 Sleep(50)-poll maps.
    struct PendingRequest {
        HANDLE   evt    = NULL;        // auto-reset; signaled when reply lands
        bool     done   = false;
        bool     failed = false;       // A4: woken by a send failure, not a reply
        uint32_t result = 0;          // RequestTestCircuit: built circuit id
        std::vector<uint8_t> reply;   // tunnel reply payload
        // v8.1 A4 - message pinning + retry. The whole logical message is sent
        // on ONE circuit; if that circuit dies mid-message Tick() retries it on
        // another (up to retries_left) by re-enqueuing from request_msg.
        uint32_t circ_id      = 0;     // circuit this request was pinned to (0 = not sent yet)
        uint8_t  sub_cmd      = 0;     // op to resend with
        int      retries_left = 0;     // remaining retries on circuit death
        std::vector<uint8_t> request_msg;  // original logical message body (for resend)
    };
    std::map<uint32_t, PendingRequest*> m_pending;     // under m_pendingLock
    // A3 helpers. RegisterPending must run BEFORE the send so a fast reply
    // cannot race the registration; the waiter owns the PendingRequest.
    // It generates a collision-free req_id (out param) under m_pendingLock so
    // two concurrent requests can never share a slot.
    PendingRequest* RegisterPending(uint32_t& req_id);
    bool WaitPending(uint32_t req_id, PendingRequest* pr, uint32_t timeoutMs,
                     std::vector<uint8_t>& outReply, uint32_t* outResult);
    void SignalReply(uint32_t req_id, const uint8_t* reply, size_t replyLen,
                     uint32_t result);

    // v8.1 A4 - send a whole logical message pinned to ONE circuit (round-robin
    // BY MESSAGE, not by cell). sub_cmd >= 0x40 is fragmented via SplitIntoCells;
    // < 0x40 is a single legacy cell. Returns the circuit id used, or 0 if no
    // Active circuit was available. MAIN THREAD ONLY (touches sockets).
    uint32_t SendMessagePinned(uint32_t req_id, uint8_t sub_cmd,
                               const uint8_t* msg, size_t msgLen);

    // v0.72 — marshaled-work queue: webserver worker threads push, the main
    // thread drains it in ProcessMainThreadWork().
    // A4 adds MT_SEND_MSG: marshal a whole logical message (req_id + sub_cmd +
    // body) so the main thread picks one circuit and pins all its cells to it.
    enum MtOp : uint8_t { MT_SEND = 1, MT_BUILD_1HOP = 2, MT_BUILD_2HOP = 3,
                          MT_SEND_MSG = 4 };
    struct MainThreadReq {
        MtOp                 op     = MT_SEND;
        uint32_t             reqId  = 0;   // MT_BUILD_*/MT_SEND_MSG key
        uint8_t              subCmd = 0;   // MT_SEND_MSG op
        std::vector<uint8_t> payload;      // MT_SEND payload / MT_SEND_MSG body
    };
    mutable CCriticalSection  m_mtLock;
    std::deque<MainThreadReq> m_mtQueue;

    // v0.72 — peer snapshot cache, rebuilt by the main thread every tick so
    // worker threads never dereference CUpDownClient pointers.
    mutable CCriticalSection  m_peersCacheLock;
    std::vector<PeerSnapshot> m_peersCacheAll;
    size_t                    m_peersCacheTunnelingCount = 0;

    // v0.72 — enqueue a SendThrough payload for the main thread. Used by
    // TunnelPing / TunneledKadSearch (they run on webserver worker threads).
    void EnqueueSend(const uint8_t* payload, size_t payloadLen);
    // v8.1 A4 — enqueue a whole logical message for pinned send on the main
    // thread (see SendMessagePinned). Replaces the per-cell EnqueueSend path
    // for tunnel ops so all cells of one message ride one circuit.
    void EnqueueSendMsg(uint32_t req_id, uint8_t sub_cmd,
                        const uint8_t* msg, size_t msgLen);
    // v0.72 — MAIN THREAD: refresh m_peersCache* from the live ClientList.
    void RebuildPeersCache();

    mutable CCriticalSection m_lock;
    std::vector<std::shared_ptr<CLiveCircuit>> m_circuits;
    size_t m_rrNextIdx;
    DWORD m_lastTickMs;
    uint64_t m_cellsSentTotal = 0;
    uint64_t m_cellsRecvTotal = 0;
    uint64_t m_bytesSentTotal = 0;   // v8.1 D8 - tunnel wire-byte telemetry
    uint64_t m_bytesRecvTotal = 0;
    // v8.1 D8 - periodic RTT probe state (all touched only under m_lock).
    DWORD    m_lastRttPingTick = 0;  // when we last SENT an RTT probe (interval gate)
    DWORD    m_rttPingSentTick = 0;  // send tick of the in-flight probe
    uint32_t m_rttPingReqId    = 0;  // req_id of the in-flight probe (0 = none outstanding)
    uint32_t m_meanRttMs       = 0;  // EWMA mean tunnel RTT (0 = unknown)
    // v8.1.2 E3.2 - last tick we (re)sent the viewer bulk-subscribe (throttle, < BULK_SUB_TTL_MS).
    DWORD    m_lastBulkSubTick  = 0;
};

}  // namespace eSELive
