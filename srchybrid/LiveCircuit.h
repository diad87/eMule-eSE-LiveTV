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
#include "kademlia/utils/UInt128.h"   // v8.1 D5 - exit Kad node-ID for XOR-closest Acquire

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

    // v0.71 C — V-side peel of ALL hops in forward order (hop0 outer,
    // hopN inner). Mirror of OnionEncrypt which iterates m_hops in
    // REVERSE wrapping with k_send; here we iterate FORWARD unwrapping
    // with k_recv. Returns true on success and writes the deepest-layer
    // plaintext into `out`. Used by the originator-side CELL_RELAY
    // handler to recover the application payload from incoming cells.
    bool OnionDecryptAll(const uint8_t* in, size_t inLen,
                        uint8_t* out, size_t outBufLen, size_t& outLen);

    // v0.71 C — AEAD-encrypt `in` with a SINGLE hop's k_send (no onion
    // wrapping). Used in two cases:
    //   1. Hop1 wrapping CELL_EXTENDED before V has hop2 registered
    //      (V only expects 1 layer of K_hop1_to_v).
    //   2. Diagnostics / debugging primitives that need a single layer.
    // Increments the hop's nonce_send counter atomically.
    bool EncryptOneLayer(uint8_t hopIdx,
                         const uint8_t* in, size_t inLen,
                         uint8_t* out, size_t& outLen);

    // === v8.1.1 Sprint E (E1.4 / B2) — explicit-nonce bulk crypto =========
    // The control plane derives the AEAD nonce from an IMPLICIT per-hop counter
    // (nonce_send/nonce_recv). A single lost/reordered/retransmitted cell desyncs
    // that counter and every later cell on the circuit then fails AEAD auth — which
    // would TEAR DOWN a bulk circuit on the first dropped symbol (LiveTunnel.cpp
    // documents exactly this). The bulk data plane therefore carries an EXPLICIT
    // nonce on the wire (BulkCellHeader.nonce_seq, LiveBulk.h §2.1) and derives the
    // AEAD nonce from it — never from a counter. These mirror their counter-based
    // twins above (same keys/direction) but take an explicit nonce and use
    // caller-provided buffers (no CELL_PAYLOAD_MAX cap), so 16 KB symbols fit.
    // The sender MUST make nonce_seq strictly increase per (circuit, direction) so a
    // (key, nonce) pair is never reused; the receiver enforces this with a replay
    // window (LiveBulk BulkReplayWindow). Same nonce across hops is safe: each hop
    // has a distinct key.

    // Add ONE layer with k_send[hopIdx], nonce = nonce_seq. out needs inLen + 16.
    bool EncryptOneLayerExplicit(uint8_t hopIdx, uint64_t nonce_seq,
                                 const uint8_t* in, size_t inLen,
                                 uint8_t* out, size_t& outLen);

    // Peel ONE layer with k_recv[hopIdx], nonce = nonce_seq. out needs inLen - 16.
    bool OnionPeelOneExplicit(uint8_t hopIdx, uint64_t nonce_seq,
                              const uint8_t* in, size_t inLen,
                              uint8_t* out, size_t& outLen);

    // Originator peel of ALL layers (k_recv, forward order), nonce = nonce_seq.
    bool OnionDecryptAllExplicit(uint64_t nonce_seq,
                                 const uint8_t* in, size_t inLen,
                                 uint8_t* out, size_t outBufLen, size_t& outLen);

    // Birth / age
    DWORD BornAtTick() const { return m_born_tick; }
    DWORD AgeMs() const { return GetTickCount() - m_born_tick; }

    // v0.71 P0.A — cover traffic state. Each circuit emits CELL_PADDING
    // independently with Poisson timing. m_nextPaddingTick is the tick
    // at which the next padding cell should be emitted. Set lazily on
    // first Active state; updated after each emit.
    DWORD m_lastPaddingTick = 0;
    DWORD m_nextPaddingDelayMs = 0;

    // Pool for outgoing cells (sender→hop1)
    CCellQueue m_sendQ;

    // === v0.71 P3.3 — handshake & routing state =========================
    // Role (originator vs relay). Originators know the full path; relays
    // only know their neighbours.
    CircuitRole m_role = CircuitRole::Originator;

    // v8.1 Sprint A7 — true while EVERY hop of this circuit advertised
    // ESE_CAP_TUNNEL_DATAPLANE. If a v8.0.0 peer is a hop this goes false and
    // the circuit is restricted to single-cell messages (no fragmentation).
    bool m_multicell_ok = true;

    // v8.1.2 Sprint E (E1.5) — true while EVERY hop advertised ESE_CAP_TUNNEL_BULK.
    // Only then may the bulk data plane (OP_LIVE_BULK_CELL 0xD9) ride this circuit;
    // otherwise the per-symbol multi-cell fallback (E1.6) is used. Seeded from hop1
    // in BuildPool, AND-ed with hop2 in BuildExtend (any non-bulk hop -> false).
    bool m_bulk_ok = false;

    // v8.1.2 (B2) — explicit per-cell AEAD nonce for the bulk data plane. The sender
    // increments this per bulk cell it originates on this circuit (send direction);
    // the value travels on the wire (BulkCellHeader.nonce_seq) so a dropped/reordered
    // bulk cell never desyncs the AEAD (unlike the control plane's implicit counter).
    uint64_t m_bulk_nonce_send = 0;

    // First-hop CUpDownClient* (originator side): where we send cells.
    // Owned by ClientList; we hold a raw pointer and rely on
    // CClientList notifications to clear circuits when a peer is destroyed.
    CUpDownClient* m_firstHopClient = NULL;

    // Relay side: pointer to the peer we received CREATE from. We send
    // CREATED back through it and forward any RELAY cells from the
    // forward direction back here.
    CUpDownClient* m_prevHopClient = NULL;

    // v0.71 B — relay-side forwarding state for 2-hop. When V sends
    // CELL_EXTEND through this relay (us = hop1), we pick a new outbound
    // circuit id, create a CELL_CREATE for hop2 with V's new ephemeral,
    // and stash hop2's CUpDownClient + the outbound id here. When hop2
    // replies CELL_CREATED on the outbound circuit, we look up this entry,
    // wrap with our K_send_r_to_v key, and send as CELL_EXTENDED to V.
    CUpDownClient* m_nextHopClient = NULL;
    uint32_t       m_nextCircId    = 0;

    // Ephemeral X25519 private key used during the CREATE/CREATED
    // handshake. Wiped after the shared secret is derived. For the
    // originator, this slot is reused for the EXTEND step (a new
    // ephemeral is generated for V↔hop2 handshake AFTER hop1's CREATED
    // wipe), so the same field naturally serves both phases.
    uint8_t  m_ephemeral_priv[32] = {0};
    bool     m_have_ephemeral = false;

    // v8.x Phase 2 — authenticated handshake (CREATE/CREATED v2) state.
    //   m_ephemeral_pub   : V's OWN ephemeral public, kept so the originator can
    //                       rebuild the signed transcript when CREATED returns
    //                       (reused for the EXTEND leg, like m_ephemeral_priv).
    //   m_create_nonce    : 128-bit CSPRNG anti-replay anchor V put in CREATE v2.
    //   m_expectedNodePub : the hop's Ed25519 identity V learned from its OWN HELLO
    //                       with that hop (no relay in between) — pinned to defeat
    //                       key-substitution by an intermediate.
    //   m_auth_ok         : true once a v2 CREATED signature verified against the pin.
    uint8_t  m_ephemeral_pub[32]   = {0};
    uint8_t  m_create_nonce[16]    = {0};
    uint8_t  m_expectedNodePub[32] = {0};
    bool     m_expectedNodePubSet  = false;
    uint8_t  m_expectedHash[16]    = {0};
    bool     m_auth_ok             = false;

    // v8.x Phase 2 — SECOND-hop (exit) authenticated-handshake state, kept STRICTLY
    // separate from the hop1 block above (no overwrite footgun on the EXTEND leg).
    // Harvested from V's OWN direct HELLO with hop2, so an intermediate hop1 cannot
    // substitute the exit's identity or ephemeral without breaking the transcript.
    uint8_t  m_ephemeral_pub2[32]   = {0};   // V's X25519 ephemeral for the V↔hop2 leg
    uint8_t  m_create_nonce2[16]    = {0};   // CSPRNG anti-replay anchor for hop2's transcript
    uint8_t  m_expectedNodePub2[32] = {0};   // pinned Ed25519 identity of hop2 (the exit)
    bool     m_expectedNodePub2Set  = false;
    uint8_t  m_expectedHash2[16]    = {0};   // hop2 MD4 user-hash (target binding)

    // v8.1 D5 - best-effort Kad node-ID of the EXIT (last hop), resolved from our routing
    // table at build time (originator side). Lets CKadV2TunnelPool::Acquire pick the circuit
    // whose exit is XOR-closest to a Kad search target. m_haveExitKadKey is the validity flag
    // (a real all-zero ID must not masquerade as "unknown"). Best-effort: stays false when the
    // exit peer is not a Kad contact, and Acquire then falls back to any-Active.
    Kademlia::CUInt128 m_exitKadKey;
    bool               m_haveExitKadKey = false;

    // Wipe all session key material. Called from destructor.
    void WipeKeys();

private:
    uint32_t m_circ_id;
    CircuitState m_state;
    std::vector<CircuitHop> m_hops;
    DWORD m_born_tick;
};

}  // namespace eSELive
