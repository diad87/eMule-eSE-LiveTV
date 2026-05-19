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

    mutable CCriticalSection m_lock;
    std::vector<std::shared_ptr<CLiveCircuit>> m_circuits;
    size_t m_rrNextIdx;
    DWORD m_lastTickMs;
    uint64_t m_cellsSentTotal = 0;
    uint64_t m_cellsRecvTotal = 0;
};

}  // namespace eSELive
