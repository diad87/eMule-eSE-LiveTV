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

#include <memory>
#include <vector>
#include <string>   // v0.71 C — TunnelPing text I/O
#include <map>      // v0.71 C — pending request table
#include <deque>    // v0.72 — main-thread work queue
#include <utility>  // v0.72 — std::move
#include <functional> // v8.1 A2 - std::function handler registry

class CUpDownClient;

namespace eSELive {

// Pool size limits from §5.5.5 thesis
const size_t TUNNEL_POOL_MIN = 3;
const size_t TUNNEL_POOL_MAX = 5;
const DWORD  TUNNEL_ROTATION_BASE_MS  = 300u * 1000u;   // v8.1: 5 min (was 30 s, too short: micro-cut streams + blocked testing)
const DWORD  TUNNEL_ROTATION_JITTER_MS = 10u * 1000u;
const DWORD  TUNNEL_HANDSHAKE_TIMEOUT_MS = 800u;

// Endpoint opaque handle exposed to LiveMeshManager (Cap 5 §5.6.3 thesis).
// The mesh layer manipulates TunnelEndpoint references, not raw client pointers.
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
        // v8.1 Sprint A — multi-cell ops. sub_cmd >= TUN_MULTICELL_OP_MIN (0x40)
        // ALWAYS carries an 8-byte fragment header in its body (see
        // LiveCellQueue.h). 0x42-0x7F are reserved for Sprint B/C.
        TUN_OP_ECHO_LARGE       = 0x40,   // A1.7 test: V -> exit, arbitrary-size echo
        TUN_OP_ECHO_LARGE_REPLY = 0x41    // A1.7 test: exit -> V, echoed payload
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
    bool ShouldRouteThroughTunnel(const wchar_t* keywordOrNull) const;

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
    // A1.5 - req_id -> partial multi-cell message under reassembly. Accessed
    // under m_pendingLock. Swept by Tick() (A5).
    std::map<uint32_t, ReassemblyEntry> m_reassembly;

    // v0.71 C — pending tunnel_ping requests. Key = req_id, value = the
    // reply text once it arrives. The TunnelPing() blocking call polls
    // this map under m_pendingLock with a wait/timeout. Cleared on reply
    // or on timeout.
    mutable CCriticalSection m_pendingLock;
    std::map<uint32_t, std::string> m_pendingPingReplies;
    // v0.71 P1.A — pending KAD_RESULT replies keyed by req_id.
    std::map<uint32_t, std::string> m_pendingKadResults;
    // v8.1 A1.7 — reassembled TUN_OP_ECHO_LARGE_REPLY payloads keyed by
    // req_id; TunnelEchoLarge polls this under m_pendingLock.
    std::map<uint32_t, std::vector<uint8_t> > m_pendingEchoReplies;
    // v0.72 — test-circuit build results keyed by req_id (value 0 = failed).
    // RequestTestCircuit polls this; ProcessMainThreadWork fills it.
    std::map<uint32_t, uint32_t> m_pendingBuildResults;

    // v0.72 — marshaled-work queue: webserver worker threads push, the main
    // thread drains it in ProcessMainThreadWork().
    enum MtOp : uint8_t { MT_SEND = 1, MT_BUILD_1HOP = 2, MT_BUILD_2HOP = 3 };
    struct MainThreadReq {
        MtOp                 op    = MT_SEND;
        uint32_t             reqId = 0;   // MT_BUILD_* key into m_pendingBuildResults
        std::vector<uint8_t> payload;     // MT_SEND payload bytes
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
    // v0.72 — MAIN THREAD: refresh m_peersCache* from the live ClientList.
    void RebuildPeersCache();

    mutable CCriticalSection m_lock;
    std::vector<std::shared_ptr<CLiveCircuit>> m_circuits;
    size_t m_rrNextIdx;
    DWORD m_lastTickMs;
    uint64_t m_cellsSentTotal = 0;
    uint64_t m_cellsRecvTotal = 0;
};

}  // namespace eSELive
