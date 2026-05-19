// this file is part of eMule eSE — Tunnel circuit state (F4)
//
// Per-circuit state machine + onion key material. A circuit traverses
// 2 hops (3 for high-risk channels). The viewer is the originator; the
// last hop reaches the origin (broadcaster or seeder).
//
// Cap 5 §5.5.3 thesis: state machine (PENDING/HALF/BUILT/ACTIVE/DESTROYED).
#pragma once

#include <vector>
#include "LiveCellQueue.h"

class CUpDownClient;   // v0.71 P3.3 — for first hop client pointer

namespace eSELive {

enum class CircuitState : uint8_t {
    Pending    = 0,   // requested, no hops yet
    HalfBuilt  = 1,   // first hop established
    Built      = 2,   // all hops established
    Active     = 3,   // in use
    Destroyed  = 4    // being torn down
};

// v0.71 P3.3 — circuit role. The same node can be:
//   Originator: it built the circuit (knows full path)
//   Relay:      it's an intermediate hop (knows only neighbours)
// The state machine differs per role; same struct serves both via this flag.
enum class CircuitRole : uint8_t {
    Originator = 0,
    Relay      = 1
};

struct CircuitHop {
    uint32_t hop_id;             // assigned by remote hop in CELL_CREATED
    uint8_t  pub_long[32];       // remote hop's long-term Ed25519 pub (for auth)
    uint8_t  k_send[32];         // ChaCha20-Poly1305 key for V→hop
    uint8_t  k_recv[32];         // ChaCha20-Poly1305 key for hop→V
    uint64_t nonce_send;
    uint64_t nonce_recv;
};

class CLiveCircuit {
public:
    explicit CLiveCircuit(uint32_t circ_id);
    ~CLiveCircuit();

    uint32_t Id() const { return m_circ_id; }
    CircuitState State() const { return m_state; }
    void SetState(CircuitState s) { m_state = s; }

    bool AddHop(const CircuitHop& hop);
    size_t HopCount() const { return m_hops.size(); }
    const CircuitHop& Hop(size_t i) const { return m_hops[i]; }

    // Pack a payload through the onion (V→hops). `out` must hold
    // CELL_PAYLOAD_MAX bytes. After this returns true, `out` contains
    // the deepest-layer ciphertext destined for the LAST hop in the
    // circuit; the V-side socket sends it inside an OP_LIVE_TUNNEL_CELL
    // addressed to the FIRST hop.
    bool OnionEncrypt(const uint8_t* plaintext, size_t plaintextLen,
                      uint8_t outCellPayload[CELL_PAYLOAD_MAX],
                      size_t& outPayloadLen);

    // Peel one layer (used in INTERMEDIATE hops). Returns the plaintext
    // for THIS hop in `out`. Caller forwards `out` to the next hop.
    bool OnionPeelOne(uint8_t hopIdx,
                      const uint8_t* in, size_t inLen,
                      uint8_t* out, size_t& outLen);

    // Birth / age
    DWORD BornAtTick() const { return m_born_tick; }
    DWORD AgeMs() const { return GetTickCount() - m_born_tick; }

    // Pool for outgoing cells (sender→hop1)
    CCellQueue m_sendQ;

    // === v0.71 P3.3 — handshake & routing state =========================
    // Role (originator vs relay). Originators know the full path; relays
    // only know their neighbours.
    CircuitRole m_role = CircuitRole::Originator;

    // First-hop CUpDownClient* (originator side): where we send cells.
    // Owned by ClientList; we hold a raw pointer and rely on
    // CClientList notifications to clear circuits when a peer is destroyed.
    CUpDownClient* m_firstHopClient = NULL;

    // Relay side: pointer to the peer we received CREATE from. We send
    // CREATED back through it and forward any RELAY cells from the
    // forward direction back here.
    CUpDownClient* m_prevHopClient = NULL;

    // Ephemeral X25519 private key used during the CREATE/CREATED
    // handshake. Wiped after the shared secret is derived.
    uint8_t  m_ephemeral_priv[32] = {0};
    bool     m_have_ephemeral = false;

    // Wipe all session key material. Called from destructor.
    void WipeKeys();

private:
    uint32_t m_circ_id;
    CircuitState m_state;
    std::vector<CircuitHop> m_hops;
    DWORD m_born_tick;
};

}  // namespace eSELive
