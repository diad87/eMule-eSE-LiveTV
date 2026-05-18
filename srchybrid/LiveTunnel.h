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

private:
    CLiveTunnel();
    CLiveTunnel(const CLiveTunnel&) = delete;
    CLiveTunnel& operator=(const CLiveTunnel&) = delete;

    static uint32_t NewCircuitId();

    mutable CCriticalSection m_lock;
    std::vector<std::shared_ptr<CLiveCircuit>> m_circuits;
    size_t m_rrNextIdx;
    DWORD m_lastTickMs;
};

}  // namespace eSELive
