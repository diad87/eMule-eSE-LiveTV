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

#include <memory>
#include <vector>
#include <string>   // v0.71 C — TunnelPing text I/O
#include <map>      // v0.71 C — pending request table

class CUpDownClient;

namespace eSELive {

// Pool size limits from §5.5.5 thesis
const size_t TUNNEL_POOL_MIN = 3;
const size_t TUNNEL_POOL_MAX = 5;
const DWORD  TUNNEL_ROTATION_BASE_MS  = 30u * 1000u;
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
        TUN_OP_PING       = 0x01,
        TUN_OP_PING_REPLY = 0x02
    };

    // v0.71 C — synchronous tunnel ping. Sends a PING through any
    // active circuit, blocks up to timeoutMs waiting for the reply.
    // Returns true if reply arrived in time, with replyText populated.
    // Used by the /api/live/privacy/tunnel_ping REST endpoint.
    bool TunnelPing(const std::string& text, std::string& replyText,
                    uint32_t timeoutMs);

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

    // v0.71 C — pending tunnel_ping requests. Key = req_id, value = the
    // reply text once it arrives. The TunnelPing() blocking call polls
    // this map under m_pendingLock with a wait/timeout. Cleared on reply
    // or on timeout.
    mutable CCriticalSection m_pendingLock;
    std::map<uint32_t, std::string> m_pendingPingReplies;

    mutable CCriticalSection m_lock;
    std::vector<std::shared_ptr<CLiveCircuit>> m_circuits;
    size_t m_rrNextIdx;
    DWORD m_lastTickMs;
    uint64_t m_cellsSentTotal = 0;
    uint64_t m_cellsRecvTotal = 0;
};

}  // namespace eSELive
