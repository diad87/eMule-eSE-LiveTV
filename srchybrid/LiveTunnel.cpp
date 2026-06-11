// this file is part of eMule eSE — 2-hop onion tunnel manager impl (F4 + P3)
//
// v0.71 P3 — graduates the F4 skeleton into a working 1-hop handshake.
// The originator generates an ephemeral X25519 keypair, sends CELL_CREATE
// to a relay candidate over OP_LIVE_TUNNEL_CELL, the relay derives shared
// secret via X25519, derives K_send/K_recv via HKDF, replies CELL_CREATED.
// The originator completes the same derivation and the circuit reaches
// Active. 2-hop extension (CELL_EXTEND/CELL_EXTENDED) is documented as
// the next step but not implemented here — single-hop is enough to make
// Onion tunnels: N > 0 in the UI and prove the path is wired.
//
// IMPORTANT: cells go through TCP via CClientReqSocket::SendPacket using
// the eMule extension protocol (OP_LIVE_TUNNEL_CELL = 0xD5). Any peer
// running this fork that calls ListenSocket::ProcessExtPacket and dispatches
// to CLiveTunnel::Get().OnCellReceived will complete the handshake. Peers
// without the fork drop the unknown opcode silently (no wire breakage).
#include "stdafx.h"
#include "LiveTunnel.h"
#include "LiveCoverTraffic.h"
#include "LiveOnionCrypto.h"

// v0.71 P3.3 — TCP send path.
#include "UpDownClient.h"
#include "ClientList.h"
#include "ListenSocket.h"     // CClientReqSocket::SendPacket
#include "Packets.h"
#include "Opcodes.h"          // OP_EMULEPROT, OP_LIVE_TUNNEL_CELL
#include "emule.h"            // theApp
#include "Preferences.h"      // v0.71 P0.B — thePrefs.GetUserHash()
#include "Log.h"              // v0.71 P0.B — AddDebugLogLine
// v0.71 P1 — Kad search through tunnel: lookup against local directory
#include "LiveStreamManager.h"
#include "LiveKadBridge.h"
#include "kademlia/kademlia/KadV2ModeSelector.h"
#include "kademlia/kademlia/SearchManager.h"   // v8.1 B - StopSearch on tunneled search
#include "kademlia/kademlia/KadV2TunnelPool.h"  // v8.1 D4 - register Active circuits in the PST pool

namespace eSELive {

CLiveTunnel::CLiveTunnel()
    : m_rrNextIdx(0)
    , m_lastTickMs(0)
{
    // v8.1 A2 - register the built-in exit-side handlers. Sprint B/C ops
    // register theirs the same way instead of editing HandleRelay_Exit.
    RegisterExitHandler(TUN_OP_PING,
        [this](const TunnelRequestCtx& c){ ExitHandle_Ping(c); });
    RegisterExitHandler(TUN_OP_KAD_SEARCH,
        [this](const TunnelRequestCtx& c){ ExitHandle_KadSearch(c); });
    RegisterExitHandler(TUN_OP_ECHO_LARGE,
        [this](const TunnelRequestCtx& c){ ExitHandle_EchoLarge(c); });
    // v8.1 Sprint B - real Kad search through the tunnel.
    RegisterExitHandler(TUN_OP_KAD_SEARCH_V2,
        [this](const TunnelRequestCtx& c){ ExitHandle_KadSearchV2(c); });
    RegisterExitHandler(TUN_OP_KAD_CANCEL,
        [this](const TunnelRequestCtx& c){ ExitHandle_KadCancel(c); });
    // v8.1 Sprint C - tunneled LiveTV subscribe (single-cell control op).
    RegisterExitHandler(TUN_OP_LIVE_SUBSCRIBE,
        [this](const TunnelRequestCtx& c){ ExitHandle_LiveSubscribe(c); });
}

// v8.1 Sprint C — little-endian field helpers for the Live tunnel op bodies.
namespace {
inline void eseWrU16LE(uint8_t* p, uint16_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
inline void eseWrU32LE(uint8_t* p, uint32_t v) {
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}
inline uint16_t eseRdU16LE(const uint8_t* p) { return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8)); }
inline uint32_t eseRdU32LE(const uint8_t* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
}  // namespace

CLiveTunnel& CLiveTunnel::Get()
{
    static CLiveTunnel s_instance;
    return s_instance;
}

uint32_t CLiveTunnel::NewCircuitId()
{
    // Local circuit IDs are 32-bit random — collisions astronomically rare;
    // we re-roll if Push collides (caller checks).
    uint8_t r[4];
    SecureRandomBytes(r, 4);
    uint32_t id = (uint32_t)r[0] | ((uint32_t)r[1] << 8)
                | ((uint32_t)r[2] << 16) | ((uint32_t)r[3] << 24);
    if (id == 0) id = 1;
    return id;
}

// v0.71 P3.3 — send a 512B cell to a peer wrapped as OP_LIVE_TUNNEL_CELL.
// Uses the existing extension-protocol packet path. Caller holds m_lock.
bool CLiveTunnel::SendCellToPeer(CUpDownClient* peer, const uint8_t cell[CELL_TOTAL_BYTES])
{
    if (!peer || !peer->socket || !peer->socket->IsConnected())
        return false;

    Packet* pkt = new Packet(OP_LIVE_TUNNEL_CELL, CELL_TOTAL_BYTES, OP_EMULEPROT);
    memcpy(pkt->pBuffer, cell, CELL_TOTAL_BYTES);
    peer->socket->SendPacket(pkt, true, true, 0);
    ++m_cellsSentTotal;
    m_bytesSentTotal += CELL_TOTAL_BYTES;   // v8.1 D8 - tunnel wire-byte telemetry
    return true;
}

size_t CLiveTunnel::BuildPool(const uint8_t origin_pubkey[32],
                              const std::vector<CUpDownClient*>& relayCandidates,
                              size_t count)
{
    // v0.71 P3.3 — real BuildPool. Picks the first connected candidate as
    // hop 1, generates an X25519 ephemeral, sends CELL_CREATE, registers
    // the circuit in Pending state. The handshake completes asynchronously
    // when CELL_CREATED arrives via OnCellReceived.
    //
    // 2-hop extension is the NEXT step: after CELL_CREATED, the originator
    // would send CELL_EXTEND (encrypted with K_send_hop1) carrying hop 2
    // endpoint + new ephemeral; hop 1 forwards as CELL_CREATE to hop 2.
    // That logic plugs into HandleCreated_Originator below — search for
    // "TODO P3.next" comment.
    if (count < TUNNEL_POOL_MIN) count = TUNNEL_POOL_MIN;
    if (count > TUNNEL_POOL_MAX) count = TUNNEL_POOL_MAX;
    if (relayCandidates.empty()) return 0;

    CSingleLock lock(&m_lock, TRUE);
    size_t built = 0;
    for (size_t i = 0; i < count && i < relayCandidates.size(); ++i) {
        CUpDownClient* hop1 = relayCandidates[i];
        if (!hop1 || !hop1->socket || !hop1->socket->IsConnected())
            continue;

        // Allocate a fresh circuit id.
        uint32_t id = 0;
        for (int t = 0; t < 4; ++t) {
            id = NewCircuitId();
            bool collision = false;
            for (auto& c : m_circuits) if (c->Id() == id) { collision = true; break; }
            if (!collision) break;
            id = 0;
        }
        if (id == 0) continue;

        // Generate ephemeral X25519 keypair for the handshake. The private
        // key stays in the circuit until CELL_CREATED arrives; then we
        // derive the shared secret and wipe.
        auto c = std::make_shared<CLiveCircuit>(id);
        c->m_role = CircuitRole::Originator;
        c->m_firstHopClient = hop1;
        // v8.1 A7.4 -- a circuit carries multi-cell messages only if EVERY hop
        // advertised ESE_CAP_TUNNEL_DATAPLANE. Seed from hop1; BuildExtend
        // AND-s in hop2. A v8.0.0 hop -> false -> single-cell fallback.
        c->m_multicell_ok = hop1->SupportsEseTunnelDataplane();
        uint8_t evPub[32];
        if (!X25519GenerateKeypair(evPub, c->m_ephemeral_priv)) {
            continue;
        }
        c->m_have_ephemeral = true;
        c->SetState(CircuitState::Pending);

        // v0.71 P0.B — CELL_CREATE payload = ev_pub (32B) + target_user_hash
        // (16B). target_user_hash binds the CREATE to a specific recipient:
        // the hop receiving it verifies the hash matches their own
        // eMule user_hash; if not (redirection attack), reply with
        // CELL_DESTROY. Old fork binaries that don't know about this
        // suffix parse the first 32B as ev_pub and ignore the rest —
        // backward compat preserved. Real ntor (with Ed25519 long-term
        // identity) would replace this with a signed binding; for now
        // user_hash is the available persistent identifier per node.
        uint8_t payload[32 + 16];
        memcpy(payload, evPub, 32);
        const uchar* hop1Hash = hop1->GetUserHash();
        if (hop1Hash) {
            memcpy(payload + 32, hop1Hash, 16);
        } else {
            // No hash known yet → fall back to ev_pub only (32B). The
            // hop1 with new binary won't reject; will accept (legacy compat).
            // Defensive — should be rare since HELLO completed.
            memset(payload + 32, 0, 16);
        }
        uint8_t cell[CELL_TOTAL_BYTES];
        if (!CellPack(id, CELL_CREATE, payload, sizeof payload, cell)) {
            // wipe ephemeral, skip
            c->WipeKeys();
            continue;
        }
        if (!SendCellToPeer(hop1, cell)) {
            c->WipeKeys();
            continue;
        }
        m_circuits.push_back(c);
        ++built;
    }
    (void)origin_pubkey;  // unused until ntor-with-pubkey binding lands
    return built;
}

uint32_t CLiveTunnel::BuildTestCircuit(CUpDownClient* clientHint)
{
    // v0.71 P3.6 — solo testing helper. Picks a peer (provided or first
    // available from ClientList) and starts a single-hop circuit build.
    // If the peer doesn't speak this fork, the CELL_CREATE drops silently
    // on their side and the circuit times out after rotation — but the
    // user has visible proof in the panel that the SEND path is wired.
    std::vector<CUpDownClient*> cands;
    if (clientHint) {
        cands.push_back(clientHint);
    } else if (theApp.clientlist) {
        // v0.71 P3.5 — PREFER peers that advertised ESE_CAP_PRIVACY_TUNNELING.
        // If we find any, use only those (handshake will actually succeed).
        // Fallback: any connected peer (test path still works — circuit
        // goes Pending until ~6 s timeout, demonstrates the send pipeline).
        theApp.clientlist->GetConnectedSnapshot(cands, 3, /*tunnelOnly=*/true);
        if (cands.empty()) {
            theApp.clientlist->GetConnectedSnapshot(cands, 3, /*tunnelOnly=*/false);
        }
    }
    if (cands.empty()) return 0;

    size_t before = 0;
    {
        CSingleLock lk(&m_lock, TRUE);
        before = m_circuits.size();
    }
    size_t built = BuildPool(NULL, cands, 1);
    if (built == 0) return 0;
    // Return the id of the circuit we just added.
    CSingleLock lk(&m_lock, TRUE);
    if (m_circuits.size() > before)
        return m_circuits.back()->Id();
    return 0;
}

// v8.1 D4 - tunnelOnly-STRICT successor build for the PST pool's make-before-break.
// Unlike BuildTestCircuit (which falls back to ANY connected peer for the manual test
// path), this builds ONLY through a peer that advertised privacy-tunneling, so on a
// single-PC node with no fork peer it is a pure no-op (GetConnectedSnapshot returns
// empty -> BuildPool builds nothing -> returns false). Builds EXACTLY ONE 1-hop circuit:
// BuildPool floors `count` up to TUNNEL_POOL_MIN(3), so we instead cap the CANDIDATE
// snapshot to 1 — BuildPool's build loop is bounded by relayCandidates.size(), so a
// 1-candidate snapshot yields exactly 1 circuit regardless of the floor.
// Called from CKadV2TunnelPool::Tick (main thread, with the pool lock NOT held).
bool CLiveTunnel::BuildSuccessorCircuit()
{
    std::vector<CUpDownClient*> cands;
    if (theApp.clientlist)
        theApp.clientlist->GetConnectedSnapshot(cands, 1, /*tunnelOnly=*/true);
    if (cands.empty()) return false;
    return BuildPool(NULL, cands, 1) > 0;
}

void CLiveTunnel::Stop()
{
    CSingleLock lock(&m_lock, TRUE);
    m_circuits.clear();
    m_rrNextIdx = 0;
    // v8.1 D4 - the PST pool holds a 2nd shared_ptr alias per circuit. Clearing
    // m_circuits without clearing the pool would keep those circuits alive (and
    // counted as Active) indefinitely, and the pool would keep building successors
    // against a stopped subsystem. Clear it too (tunnel->pool order, same as RegisterTunnel).
    Kademlia::CKadV2TunnelPool::Get().Clear();
}

bool CLiveTunnel::SendThrough(const uint8_t* payload, size_t payloadLen)
{
    if (!payload || payloadLen == 0) return false;
    CSingleLock lock(&m_lock, TRUE);
    if (m_circuits.empty()) return false;

    // Round-robin (multipath split, Decision 5.1).
    size_t tries = m_circuits.size();
    while (tries-- > 0) {
        const size_t idx = m_rrNextIdx % m_circuits.size();
        m_rrNextIdx = (m_rrNextIdx + 1) % m_circuits.size();
        auto& c = m_circuits[idx];
        if (c->State() != CircuitState::Active) continue;
        if (c->HopCount() == 0) continue;

        uint8_t cellPayload[CELL_PAYLOAD_MAX];
        size_t cellLen = 0;
        if (!c->OnionEncrypt(payload, payloadLen, cellPayload, cellLen))
            continue;
        uint8_t cell[CELL_TOTAL_BYTES];
        if (!CellPack(c->Id(), CELL_RELAY, cellPayload, (size_t)cellLen, cell))
            continue;
        // v0.71 P3.3 — instead of queueing, send directly to hop 1's socket.
        if (c->m_firstHopClient && SendCellToPeer(c->m_firstHopClient, cell))
            return true;
        // Fallback: queue (in case socket transiently busy).
        return c->m_sendQ.Push(cell);
    }
    return false;
}

// v0.71 P3.3 — originator-side: CELL_CREATED arrived for our circuit.
// Payload = relay's ephemeral X25519 pub (32B). We derive the shared
// secret with our stored ephemeral private, run HKDF, register hop 1,
// wipe ephemeral, advance state.
bool CLiveTunnel::HandleCreated_Originator(std::shared_ptr<CLiveCircuit>& circ,
                                           const uint8_t* payload, uint16_t payloadLen)
{
    if (!circ->m_have_ephemeral) return false;
    if (payloadLen < 32) return false;
    const uint8_t* relayPub = payload;

    uint8_t shared[32];
    if (!X25519SharedSecret(relayPub, circ->m_ephemeral_priv, shared))
        return false;

    // HKDF: derive 64 bytes (k_send 32 + k_recv 32) from the shared.
    // Salt is empty, info distinguishes direction so V→R and R→V keys
    // can be derived from the SAME shared without confusion attacks.
    uint8_t okm[64];
    const uint8_t info_send[] = "ese-tunnel-V-to-R-v1";
    const uint8_t info_recv[] = "ese-tunnel-R-to-V-v1";
    if (!Hkdf(shared, sizeof shared, NULL, 0, info_send, sizeof info_send - 1, okm, 32))
        return false;
    if (!Hkdf(shared, sizeof shared, NULL, 0, info_recv, sizeof info_recv - 1, okm + 32, 32))
        return false;

    CircuitHop hop = {};
    hop.hop_id = circ->Id();   // hop_id placeholder; ntor uses dedicated tag
    memcpy(hop.k_send, okm,      32);
    memcpy(hop.k_recv, okm + 32, 32);
    hop.nonce_send = 0;
    hop.nonce_recv = 0;
    if (!circ->AddHop(hop))
        return false;

    // Wipe ephemeral private key + shared.
    SecureWipe(circ->m_ephemeral_priv, sizeof circ->m_ephemeral_priv);
    circ->m_have_ephemeral = false;
    SecureWipe(shared, sizeof shared);
    SecureWipe(okm, sizeof okm);

    // 1-hop done. If BuildTestCircuit2Hop pre-staged a hop2 candidate
    // in m_nextHopClient, automatically extend now. Otherwise stay at
    // 1-hop Active (current default behavior, preserves P3 compat).
    circ->SetState(CircuitState::Active);
    if (circ->m_nextHopClient) {
        CUpDownClient* hop2 = circ->m_nextHopClient;
        circ->m_nextHopClient = NULL;   // clear staging slot
        // BuildExtend transitions back to HalfBuilt; CELL_EXTENDED will
        // promote to Active once derived. Failure leaves circuit at
        // 1-hop Active (graceful degrade).
        if (!BuildExtend(circ, hop2)) {
            // v8.1 D4 - extend failed -> circuit stays 1-hop Active and would otherwise
            // never be pooled (HandleExtended_Originator won't run). Register it now.
            Kademlia::CKadV2TunnelPool::Get().RegisterTunnel(circ);
        }
    } else {
        // v8.1 D4 - 1-hop-final circuit reached Active: register it in the PST pool.
        // (The 2-hop case registers in HandleExtended_Originator once EXTENDED lands;
        // registering here too would add an entry about to leave Active via BuildExtend.)
        Kademlia::CKadV2TunnelPool::Get().RegisterTunnel(circ);
    }
    return true;
}

// v0.71 P3.3 — relay-side: CELL_CREATE arrived from a peer wanting to
// establish a hop with us. Generate ephemeral, derive symmetric keys
// from shared, reply with CELL_CREATED. Register the circuit as a relay
// circuit so future RELAY cells from this peer can be peeled.
bool CLiveTunnel::HandleCreate_Relay(uint32_t circId,
                                     const uint8_t* payload, uint16_t payloadLen,
                                     CUpDownClient* fromPeer)
{
    if (!fromPeer || payloadLen < 32) return false;
    const uint8_t* viewerPub = payload;

    // v0.71 P0.B — verify target_user_hash binding (anti-MITM lite).
    // Payload format: ev_pub (32B) + target_user_hash (16B) = 48B from
    // new fork. Old fork sends just 32B (no target_hash). We accept
    // both for backward compat, but if the 16B suffix is present, it
    // MUST match our own user_hash — else this CREATE was targeted at
    // someone else (redirection attack) and we drop it.
    if (payloadLen >= 48) {
        const uint8_t* targetHash = payload + 32;
        const uchar* ourHash = thePrefs.GetUserHash();
        // Treat all-zero as "no binding info, fall back to legacy
        // acceptance" — defensive against new fork peers that couldn't
        // determine our hash before sending.
        bool allZero = true;
        for (int i = 0; i < 16; ++i) if (targetHash[i] != 0) { allZero = false; break; }
        if (!allZero && ourHash) {
            if (memcmp(targetHash, ourHash, 16) != 0) {
                // Not for us. Decline. (Could reply CELL_DESTROY but
                // silent drop also works — V's circuit will time out
                // and retry. Silent drop is harder to fingerprint
                // since attacker doesn't get explicit "rejected" signal.)
                AddDebugLogLine(false,
                    _T("LiveTunnel: CELL_CREATE target_hash mismatch — dropping (redirection attempt?)"));
                return false;
            }
        }
    }

    uint8_t erPub[32], erPriv[32];
    if (!X25519GenerateKeypair(erPub, erPriv)) return false;

    uint8_t shared[32];
    if (!X25519SharedSecret(viewerPub, erPriv, shared)) {
        SecureWipe(erPriv, sizeof erPriv);
        return false;
    }
    SecureWipe(erPriv, sizeof erPriv);

    // Same HKDF as the originator, but the labels are inverted from
    // *our* perspective: what V calls V→R is the relay's RECV, etc.
    uint8_t okm[64];
    const uint8_t info_v_to_r[] = "ese-tunnel-V-to-R-v1";
    const uint8_t info_r_to_v[] = "ese-tunnel-R-to-V-v1";
    if (!Hkdf(shared, sizeof shared, NULL, 0, info_v_to_r, sizeof info_v_to_r - 1, okm, 32) ||
        !Hkdf(shared, sizeof shared, NULL, 0, info_r_to_v, sizeof info_r_to_v - 1, okm + 32, 32))
    {
        SecureWipe(shared, sizeof shared);
        return false;
    }

    // Register the relay-side circuit. Originator-side AddHop fills
    // m_hops[0] with the keys; relay-side we also populate m_hops[0]
    // (single hop = ourselves), just with the inverted send/recv.
    auto c = std::make_shared<CLiveCircuit>(circId);
    c->m_role = CircuitRole::Relay;
    c->m_prevHopClient = fromPeer;
    CircuitHop hop = {};
    hop.hop_id = circId;
    memcpy(hop.k_send, okm + 32, 32);   // relay→V uses R-to-V key for send
    memcpy(hop.k_recv, okm,      32);   // V→relay uses V-to-R key for recv
    hop.nonce_send = 0;
    hop.nonce_recv = 0;
    c->AddHop(hop);
    c->SetState(CircuitState::Active);
    m_circuits.push_back(c);

    SecureWipe(shared, sizeof shared);
    SecureWipe(okm, sizeof okm);

    // Reply with CELL_CREATED carrying our ephemeral pub.
    uint8_t cell[CELL_TOTAL_BYTES];
    if (!CellPack(circId, CELL_CREATED, erPub, sizeof erPub, cell))
        return false;
    SendCellToPeer(fromPeer, cell);
    return true;
}

bool CLiveTunnel::OnCellReceived(uint32_t circ_id, uint8_t cmd,
                                 const uint8_t* payload, uint16_t payloadLen,
                                 CUpDownClient* fromPeer)
{
    CSingleLock lock(&m_lock, TRUE);
    ++m_cellsRecvTotal;
    m_bytesRecvTotal += CELL_TOTAL_BYTES;   // v8.1 D8 - tunnel wire-byte telemetry

    // CELL_CREATE: someone is asking us to be a relay for them. Handle
    // even if we don't know circ_id yet (this is by design — circ_id is
    // chosen by the originator and we learn it from the cell).
    if (cmd == CELL_CREATE) {
        return HandleCreate_Relay(circ_id, payload, payloadLen, fromPeer);
    }

    // v0.71 B — CELL_CREATED may be a relay-side "reply from hop2".
    // Look up by OUTBOUND id (relay-side m_nextCircId) BEFORE falling
    // through to the originator-side lookup. If found, this is hop1
    // receiving CREATED from hop2 and we must wrap it as EXTENDED back
    // to V on V's circ_id.
    if (cmd == CELL_CREATED) {
        auto relayCirc = FindRelayByOutgoingId(circ_id);
        if (relayCirc) {
            return ForwardCreatedAsExtended_Relay(circ_id, payload, payloadLen);
        }
    }

    // All other cells require an existing circuit entry by circ_id
    // (originator's V-side id, or relay-side from-V id).
    std::shared_ptr<CLiveCircuit> circ;
    for (auto& c : m_circuits)
        if (c->Id() == circ_id) { circ = c; break; }
    if (!circ) return false;

    switch (cmd) {
        case CELL_CREATED:
            // Originator-side CREATED for hop1.
            if (circ->m_role != CircuitRole::Originator) return false;
            return HandleCreated_Originator(circ, payload, payloadLen);

        case CELL_EXTEND:
            // v0.71 B — relay receives EXTEND from V, forwards to hop2.
            if (circ->m_role != CircuitRole::Relay) return false;
            return HandleExtend_Relay(circ, payload, payloadLen);

        case CELL_EXTENDED:
            // v0.71 B — originator receives EXTENDED back, derives hop2 keys.
            if (circ->m_role != CircuitRole::Originator) return false;
            return HandleExtended_Originator(circ, payload, payloadLen);

        case CELL_RELAY:
            // v0.71 C — data plane delivery.
            // Originator: peel ALL hops, parse TunnelOp, deliver.
            // Relay/exit (we hold V↔hop2 keys via self-loopback): peel
            //   all hops, dispatch the inner payload, wrap reply,
            //   send back to V.
            if (circ->m_role == CircuitRole::Originator) {
                return HandleRelay_Originator(circ, payload, payloadLen);
            } else {
                return HandleRelay_Exit(circ, payload, payloadLen);
            }

        case CELL_DESTROY:
            circ->SetState(CircuitState::Destroyed);
            return true;

        case CELL_PADDING: {
            // Cover traffic. The originator OnionEncrypt'd this cell, which
            // advanced its per-hop nonce_send counter. We MUST peel it here
            // so our nonce_recv stays in lockstep: the ChaCha20-Poly1305
            // nonce is an implicit counter (not on the wire), so a dropped
            // cell desyncs it and the next real CELL_RELAY fails AEAD auth.
            // The decrypted plaintext is random padding and is discarded.
            if (circ->m_role == CircuitRole::Relay) {
                uint8_t scratch[CELL_PAYLOAD_MAX];
                size_t  scratchLen = 0;
                circ->OnionDecryptAll(payload, payloadLen, scratch, sizeof scratch, scratchLen);
            }
            return true;
        }

        default:
            return false;
    }
}

// === v0.71 B — 2-hop extension =============================================
// V (originator) → hop1 → hop2 → destination.
// After hop1's CREATED arrives, V triggers BuildExtend:
//   1. Generate a fresh X25519 ephemeral (separate from the one used for hop1)
//   2. Build EXTEND payload: hop2_ip(4) + hop2_port(2) + ev_pub2(32) = 38B
//   3. OnionEncrypt with V↔hop1 keys → ciphertext (38 + 16 tag = 54B)
//   4. Pack as CELL_EXTEND on V's circ_id, send to hop1
// hop1's HandleExtend_Relay:
//   1. AEAD-decrypt with K_recv_v_to_hop1 → plaintext 38B
//   2. Read hop2_endpoint, ev_pub2
//   3. Pick fresh outbound circ_id, send CELL_CREATE(ev_pub2) to hop2
//   4. Stash forwarding: m_nextHopClient + m_nextCircId on relay circuit
// hop2 sees a normal CELL_CREATE → HandleCreate_Relay (existing code) →
//   replies CELL_CREATED(er_pub2) to hop1 on the outbound circuit
// hop1's ForwardCreatedAsExtended_Relay:
//   1. Find relay circuit by outbound id
//   2. Wrap er_pub2 with K_send_r_to_v (AEAD-encrypt)
//   3. Send CELL_EXTENDED on V-side circ_id back to V
// V's HandleExtended_Originator:
//   1. AEAD-decrypt with K_recv_r_to_v_hop1 → er_pub2 plaintext
//   2. shared = X25519(er_pub2, V_extend_ephemeral_priv)
//   3. HKDF → K_v_to_hop2 + K_hop2_to_v
//   4. AddHop, wipe ephemeral, mark Active with hopCount=2

bool CLiveTunnel::BuildExtend(std::shared_ptr<CLiveCircuit>& circ,
                              CUpDownClient* hop2)
{
    // Caller holds m_lock.
    if (!circ || !hop2) return false;
    if (circ->m_role != CircuitRole::Originator) return false;
    if (circ->HopCount() != 1) return false;   // must have hop1 already

    // v8.1 A7.4 -- AND hop2's multi-cell capability into the circuit flag.
    // If hop2 is a v8.0.0 peer, the whole circuit drops to single-cell.
    if (!hop2->SupportsEseTunnelDataplane())
        circ->m_multicell_ok = false;

    // Generate a fresh ephemeral for V↔hop2. The slot was wiped after
    // hop1's CREATED so it's safe to reuse.
    uint8_t evPub2[32];
    if (!X25519GenerateKeypair(evPub2, circ->m_ephemeral_priv))
        return false;
    circ->m_have_ephemeral = true;

    // v0.71 P0.B — EXTEND payload now 54B: 4B IP + 2B port + 32B ev_pub2
    // + 16B target_user_hash of hop2. hop2's HandleCreate_Relay will
    // verify the hash matches its own user_hash before responding,
    // making redirection by hop1 detectable.
    uint8_t extendPlain[54];
    const uint32 hop2_ip = hop2->GetIP();           // network byte order
    const uint16 hop2_port = hop2->GetUserPort();
    // Write IP as 4 bytes little-endian (consistent with our cell convention).
    extendPlain[0] = (uint8_t)(hop2_ip & 0xFF);
    extendPlain[1] = (uint8_t)((hop2_ip >>  8) & 0xFF);
    extendPlain[2] = (uint8_t)((hop2_ip >> 16) & 0xFF);
    extendPlain[3] = (uint8_t)((hop2_ip >> 24) & 0xFF);
    extendPlain[4] = (uint8_t)(hop2_port & 0xFF);
    extendPlain[5] = (uint8_t)((hop2_port >> 8) & 0xFF);
    memcpy(extendPlain + 6, evPub2, 32);
    const uchar* hop2Hash = hop2->GetUserHash();
    if (hop2Hash) {
        memcpy(extendPlain + 38, hop2Hash, 16);
    } else {
        memset(extendPlain + 38, 0, 16);
    }

    // OnionEncrypt with the single registered hop (hop1). Since there's
    // only 1 hop, this just AEAD-encrypts with K_v_to_hop1.
    uint8_t cellPayload[CELL_PAYLOAD_MAX];
    size_t cellLen = 0;
    if (!circ->OnionEncrypt(extendPlain, sizeof extendPlain, cellPayload, cellLen)) {
        SecureWipe(circ->m_ephemeral_priv, sizeof circ->m_ephemeral_priv);
        circ->m_have_ephemeral = false;
        return false;
    }

    // Pack as CELL_EXTEND and send through hop1.
    uint8_t cell[CELL_TOTAL_BYTES];
    if (!CellPack(circ->Id(), CELL_EXTEND, cellPayload, cellLen, cell)) {
        SecureWipe(circ->m_ephemeral_priv, sizeof circ->m_ephemeral_priv);
        circ->m_have_ephemeral = false;
        return false;
    }
    if (!circ->m_firstHopClient || !SendCellToPeer(circ->m_firstHopClient, cell)) {
        SecureWipe(circ->m_ephemeral_priv, sizeof circ->m_ephemeral_priv);
        circ->m_have_ephemeral = false;
        return false;
    }

    // Move state from Active (1-hop) back to "extending" — we represent
    // that as HalfBuilt to signal "more than just hop1 in flight". When
    // EXTENDED arrives we promote to Active again.
    circ->SetState(CircuitState::HalfBuilt);
    return true;
}

bool CLiveTunnel::HandleExtend_Relay(std::shared_ptr<CLiveCircuit>& circ,
                                     const uint8_t* payload, uint16_t payloadLen)
{
    // Caller holds m_lock. circ is the relay-side circuit (m_role == Relay).
    if (!circ || circ->m_role != CircuitRole::Relay) return false;
    if (circ->HopCount() != 1) return false;
    // v0.71 P0.B — payload now 54B plaintext (was 38B): 6B endpoint +
    // 32B ev_pub2 + 16B target_hash of hop2. Ciphertext = 54+16 tag = 70B.
    // Backward compat: if peer sent old 38B plaintext (54B ciphertext),
    // we still parse but skip the target_hash forward.
    if (payloadLen < 54) return false;
    uint8_t extendPlain[70];
    size_t extendPlainLen = 0;
    if (!circ->OnionPeelOne(0, payload, payloadLen, extendPlain, extendPlainLen))
        return false;
    if (extendPlainLen < 38) return false;

    // Parse hop2 endpoint + ev_pub2 + (optional) target_hash.
    uint32 hop2_ip = (uint32)extendPlain[0]
                   | ((uint32)extendPlain[1] << 8)
                   | ((uint32)extendPlain[2] << 16)
                   | ((uint32)extendPlain[3] << 24);
    uint16 hop2_port = (uint16)extendPlain[4] | ((uint16)extendPlain[5] << 8);
    const uint8_t* evPub2 = extendPlain + 6;
    const bool haveHop2Hash = (extendPlainLen >= 54);
    const uint8_t* hop2HashIn = haveHop2Hash ? (extendPlain + 38) : NULL;

    // v0.71 B - self-loopback detection. With only 2 fork PCs (testing), V
    // picks the same peer for hop1 and hop2, so this EXTEND's hop2 is US.
    // We detect that and synthesize the hop2 reply locally: generate
    // er_pub2/er_priv2, derive the shared, wrap er_pub2 as CELL_EXTENDED
    // with the current circuit's K_send_r_to_v, send back to V on V's
    // circ_id. From V's perspective the protocol completes perfectly;
    // reality is hop1 and hop2 are the same node (zero anonymity, explicit
    // test mode, NOT for production).
    //
    // v8.1 fix: detect the loopback by USER HASH, not IP. The old check
    // 'hop2_ip == theApp.GetPublicIP()' only matched when V reached us on
    // our public IP; over Tailscale/LAN/VPN hop2_ip is that address
    // instead, the compare failed, and the circuit stalled forever at
    // HalfBuilt. The user hash is our stable identity on any transport.
    bool isLoopback = false;
    if (haveHop2Hash) {
        bool hashAllZero = true;
        for (int i = 0; i < 16; ++i)
            if (hop2HashIn[i] != 0) { hashAllZero = false; break; }
        const uchar* ourHash = thePrefs.GetUserHash();
        if (!hashAllZero && ourHash && memcmp(hop2HashIn, ourHash, 16) == 0)
            isLoopback = true;
    }
    // Legacy fallback: public-IP match (pre-hash peers / same-WAN setups).
    if (!isLoopback && theApp.GetPublicIP() != 0 && hop2_ip == theApp.GetPublicIP())
        isLoopback = true;
    if (isLoopback) {
        uint8_t erPub2[32], erPriv2[32];
        if (!X25519GenerateKeypair(erPub2, erPriv2)) {
            SecureWipe(extendPlain, sizeof extendPlain);
            return false;
        }
        // v0.71 C — derive AND KEEP V↔hop2 keys on our side so we can
        // act as the exit hop for incoming CELL_RELAY. Before C we
        // wiped them (B only needed CREATED reply); now data plane
        // requires hop2's perspective on the same node.
        uint8_t shared[32];
        if (!X25519SharedSecret(evPub2, erPriv2, shared)) {
            SecureWipe(erPriv2, sizeof erPriv2);
            SecureWipe(extendPlain, sizeof extendPlain);
            return false;
        }
        SecureWipe(erPriv2, sizeof erPriv2);

        // HKDF the V↔hop2 keys with the SAME info-labels V uses.
        // From hop2's perspective: V→R is our RECV, R→V is our SEND.
        uint8_t okm[64];
        const uint8_t info_v_to_r[] = "ese-tunnel-V-to-R-v1";
        const uint8_t info_r_to_v[] = "ese-tunnel-R-to-V-v1";
        if (!Hkdf(shared, sizeof shared, NULL, 0, info_v_to_r, sizeof info_v_to_r - 1, okm, 32) ||
            !Hkdf(shared, sizeof shared, NULL, 0, info_r_to_v, sizeof info_r_to_v - 1, okm + 32, 32))
        {
            SecureWipe(shared, sizeof shared);
            SecureWipe(extendPlain, sizeof extendPlain);
            return false;
        }
        SecureWipe(shared, sizeof shared);

        // Add a SECOND hop entry to the relay-side circuit, representing
        // ourselves as hop2. Now m_hops has [V↔hop1, V↔hop2]. When a
        // CELL_RELAY arrives we peel both layers (the outer with
        // hop[0].k_recv = K_v_to_hop1, the inner with hop[1].k_recv
        // = K_v_to_hop2) to recover the application payload.
        CircuitHop hop2 = {};
        hop2.hop_id = circ->Id();
        memcpy(hop2.k_send, okm + 32, 32);   // R-to-V from hop2's view
        memcpy(hop2.k_recv, okm,      32);   // V-to-R from hop2's view
        hop2.nonce_send = 0;
        hop2.nonce_recv = 0;
        circ->AddHop(hop2);
        SecureWipe(okm, sizeof okm);

        // Wrap er_pub2 with our K_send_r_to_v of THE FIRST hop entry
        // (V↔hop1, which is m_hops[0].k_send) and send as CELL_EXTENDED.
        // OnionEncrypt iterates m_hops in REVERSE, so with 2 hops it'd
        // wrap with hop[1].k_send (V↔hop2) first, then hop[0].k_send.
        // But V expects the EXTENDED payload to be wrapped ONCE with
        // V↔hop1 key only (since V hasn't added hop2 yet at the moment
        // of receiving EXTENDED). So we manually AEAD-encrypt with just
        // m_hops[0].k_send instead of using OnionEncrypt.
        uint8_t wrapped[CELL_PAYLOAD_MAX];
        size_t wrappedLen = 0;
        // Use EncryptOneLayer with hop 0 only — V hasn't registered hop2
        // on her side yet, so the EXTENDED reply must be wrapped with
        // ONLY V↔hop1 key (not both). OnionEncrypt with 2 hops would
        // wrap with both, which V couldn't decrypt at this point.
        if (!circ->EncryptOneLayer(0, erPub2, 32, wrapped, wrappedLen)) {
            SecureWipe(extendPlain, sizeof extendPlain);
            return false;
        }
        uint8_t cell[CELL_TOTAL_BYTES];
        if (!CellPack(circ->Id(), CELL_EXTENDED, wrapped, wrappedLen, cell)) {
            SecureWipe(extendPlain, sizeof extendPlain);
            return false;
        }
        if (!circ->m_prevHopClient || !SendCellToPeer(circ->m_prevHopClient, cell)) {
            SecureWipe(extendPlain, sizeof extendPlain);
            return false;
        }
        SecureWipe(extendPlain, sizeof extendPlain);
        return true;
    }

    // Normal (non-loopback) path: resolve hop2 in our ClientList.
    // Two-hop only works if we (hop1) already have an open socket to hop2.
    CUpDownClient* hop2 = NULL;
    if (theApp.clientlist)
        hop2 = theApp.clientlist->FindClientByIP(hop2_ip, hop2_port);
    if (!hop2 || !hop2->socket || !hop2->socket->IsConnected()) {
        SecureWipe(extendPlain, sizeof extendPlain);
        return false;
    }

    // Pick a fresh outbound circ_id for the V↔hop2 leg as seen from us.
    uint32_t outId = 0;
    for (int t = 0; t < 4; ++t) {
        outId = NewCircuitId();
        bool collision = false;
        for (auto& c : m_circuits)
            if (c->Id() == outId || c->m_nextCircId == outId) { collision = true; break; }
        if (!collision) break;
        outId = 0;
    }
    if (outId == 0) {
        SecureWipe(extendPlain, sizeof extendPlain);
        return false;
    }

    // Stash forwarding state on the relay circuit.
    circ->m_nextHopClient = hop2;
    circ->m_nextCircId    = outId;

    // v0.71 P0.B — forward V's target_hash for hop2 in the CELL_CREATE.
    // Without this, an adversarial hop1 could send CREATE to a peer
    // OTHER than hop2 (different identity), and that peer would accept
    // since hop2_hash isn't validated. With the hash forwarded, the
    // wrong peer rejects (its own hash doesn't match) → V detects
    // hop1's redirection via timeout.
    uint8_t fwdPayload[48];
    memcpy(fwdPayload, evPub2, 32);
    if (haveHop2Hash) {
        memcpy(fwdPayload + 32, hop2HashIn, 16);
    } else {
        // Legacy V (no hash forwarded). Send zero so receiver does
        // legacy compat acceptance.
        memset(fwdPayload + 32, 0, 16);
    }
    uint8_t cell[CELL_TOTAL_BYTES];
    if (!CellPack(outId, CELL_CREATE, fwdPayload, sizeof fwdPayload, cell)) {
        SecureWipe(extendPlain, sizeof extendPlain);
        return false;
    }
    SendCellToPeer(hop2, cell);
    SecureWipe(extendPlain, sizeof extendPlain);
    return true;
}

std::shared_ptr<CLiveCircuit> CLiveTunnel::FindRelayByOutgoingId(uint32_t outboundCircId)
{
    // Caller holds m_lock.
    for (auto& c : m_circuits) {
        if (c->m_role == CircuitRole::Relay && c->m_nextCircId == outboundCircId)
            return c;
    }
    return nullptr;
}

bool CLiveTunnel::ForwardCreatedAsExtended_Relay(uint32_t outboundCircId,
                                                 const uint8_t* payload, uint16_t payloadLen)
{
    // Caller holds m_lock.
    auto circ = FindRelayByOutgoingId(outboundCircId);
    if (!circ || circ->HopCount() != 1 || payloadLen < 32) return false;

    // The cell's payload is hop2's er_pub2 (32B unencrypted). We wrap it
    // with K_send_r_to_v (hop[0].k_send on relay side, see HandleCreate_Relay
    // where we put R-to-V key into hop.k_send).
    uint8_t wrapped[CELL_PAYLOAD_MAX];
    size_t wrappedLen = 0;
    if (!circ->OnionEncrypt(payload, 32, wrapped, wrappedLen))
        return false;

    // Pack as CELL_EXTENDED on V's circ_id (which is circ->Id()).
    uint8_t cell[CELL_TOTAL_BYTES];
    if (!CellPack(circ->Id(), CELL_EXTENDED, wrapped, wrappedLen, cell))
        return false;
    if (!circ->m_prevHopClient || !SendCellToPeer(circ->m_prevHopClient, cell))
        return false;
    return true;
}

bool CLiveTunnel::HandleExtended_Originator(std::shared_ptr<CLiveCircuit>& circ,
                                            const uint8_t* payload, uint16_t payloadLen)
{
    // Caller holds m_lock. circ is the V-side circuit. The cell payload
    // is the wrapped er_pub2 (32+16 tag = 48B).
    if (!circ || circ->m_role != CircuitRole::Originator) return false;
    if (circ->HopCount() != 1) return false;
    if (!circ->m_have_ephemeral) return false;
    if (payloadLen < 48) return false;

    uint8_t plain[48];
    size_t plainLen = 0;
    if (!circ->OnionPeelOne(0, payload, payloadLen, plain, plainLen))
        return false;
    if (plainLen < 32) return false;
    const uint8_t* erPub2 = plain;

    // Derive V↔hop2 keys.
    uint8_t shared[32];
    if (!X25519SharedSecret(erPub2, circ->m_ephemeral_priv, shared))
        return false;

    uint8_t okm[64];
    const uint8_t info_send[] = "ese-tunnel-V-to-R-v1";
    const uint8_t info_recv[] = "ese-tunnel-R-to-V-v1";
    if (!Hkdf(shared, sizeof shared, NULL, 0, info_send, sizeof info_send - 1, okm, 32) ||
        !Hkdf(shared, sizeof shared, NULL, 0, info_recv, sizeof info_recv - 1, okm + 32, 32))
    {
        SecureWipe(shared, sizeof shared);
        return false;
    }

    CircuitHop hop2 = {};
    hop2.hop_id = circ->Id();
    memcpy(hop2.k_send, okm,      32);
    memcpy(hop2.k_recv, okm + 32, 32);
    hop2.nonce_send = 0;
    hop2.nonce_recv = 0;
    if (!circ->AddHop(hop2)) {
        SecureWipe(shared, sizeof shared);
        SecureWipe(okm, sizeof okm);
        return false;
    }

    SecureWipe(circ->m_ephemeral_priv, sizeof circ->m_ephemeral_priv);
    circ->m_have_ephemeral = false;
    SecureWipe(shared, sizeof shared);
    SecureWipe(okm, sizeof okm);
    SecureWipe(plain, sizeof plain);

    circ->SetState(CircuitState::Active);
    // v8.1 D4 - 2-hop circuit reached final Active: register it in the PST pool.
    Kademlia::CKadV2TunnelPool::Get().RegisterTunnel(circ);
    return true;
}

uint32_t CLiveTunnel::BuildTestCircuit2Hop()
{
    // Pick up to 2 distinct fork peers for the circuit. If only 1 fork
    // peer is available we loop hop2 back to the same peer — semantically
    // weird (a real circuit wants distinct hops for anonymity) but valid
    // for protocol/state-machine testing on a 2-PC dev setup. With 3+
    // fork nodes in the wild, the picker chooses 2 distinct ones.
    std::vector<CUpDownClient*> forkCands;
    if (theApp.clientlist)
        theApp.clientlist->GetConnectedSnapshot(forkCands, 5, /*tunnelOnly=*/true);
    if (forkCands.empty()) return 0;

    CUpDownClient* hop1 = forkCands[0];
    CUpDownClient* hop2 = (forkCands.size() >= 2) ? forkCands[1] : forkCands[0];

    std::vector<CUpDownClient*> hop1Vec = { hop1 };
    size_t built = BuildPool(NULL, hop1Vec, 1);
    if (built == 0) return 0;

    // The freshly-built circuit is at the back of m_circuits. We can't
    // call BuildExtend yet — the circuit is still Pending until CREATED
    // arrives. We mark a flag so HandleCreated_Originator triggers
    // BuildExtend automatically. For simplicity (and because there's no
    // good place to stash hop2 right now), we register a one-shot
    // post-CREATED action via a static map.
    CSingleLock lk(&m_lock, TRUE);
    if (m_circuits.empty()) return 0;
    auto& c = m_circuits.back();
    // Re-use m_nextHopClient on the ORIGINATOR side to mean "after
    // CREATED, extend to this peer". HandleCreated_Originator will check.
    c->m_nextHopClient = hop2;
    return c->Id();
}

void CLiveTunnel::GetCircuitsSnapshot(std::vector<CircuitSnapshot>& out) const
{
    CSingleLock lock(&m_lock, TRUE);
    out.clear();
    out.reserve(m_circuits.size());
    DWORD now = GetTickCount();
    for (auto& c : m_circuits) {
        CircuitSnapshot s = {};
        s.circ_id      = c->Id();
        s.role         = (uint8_t)c->m_role;
        s.state        = (uint8_t)c->State();
        s.age_ms       = now - c->BornAtTick();
        s.hop_count    = (uint32_t)c->HopCount();
        s.next_hop_set = c->m_nextHopClient ? 1 : 0;
        s.next_circ_id = c->m_nextCircId;
        out.push_back(s);
    }
}

// === v0.72 — main-thread marshaling impl ====================================
// SendThrough()/BuildTestCircuit*() touch peer sockets and the ClientList,
// which are main-thread only. The webserver privacy endpoints run on worker
// threads, so they enqueue the work here; the main thread runs it from
// ProcessMainThreadWork() (CKademlia::Process, ~1 Hz).

void CLiveTunnel::EnqueueSend(const uint8_t* payload, size_t payloadLen)
{
    if (!payload || payloadLen == 0) return;
    CSingleLock lk(&m_mtLock, TRUE);
    MainThreadReq req;
    req.op = MT_SEND;
    req.payload.assign(payload, payload + payloadLen);
    m_mtQueue.push_back(std::move(req));
}

// v8.1 A4 - marshal a whole logical message for pinned send on the main thread.
void CLiveTunnel::EnqueueSendMsg(uint32_t req_id, uint8_t sub_cmd,
                                 const uint8_t* msg, size_t msgLen)
{
    CSingleLock lk(&m_mtLock, TRUE);
    MainThreadReq req;
    req.op     = MT_SEND_MSG;
    req.reqId  = req_id;
    req.subCmd = sub_cmd;
    if (msg && msgLen) req.payload.assign(msg, msg + msgLen);
    m_mtQueue.push_back(std::move(req));
}

// v8.1 A4 - pin a whole logical message to ONE circuit. Round-robin BY MESSAGE
// (not by cell, as SendThrough does): all cells of one fragmented message must
// ride the same circuit so they reach the same exit in order and reassemble
// trivially. Returns the circuit id used (for retry tracking), or 0 if no
// Active circuit was available / the send could not start. MAIN THREAD ONLY.
uint32_t CLiveTunnel::SendMessagePinned(uint32_t req_id, uint8_t sub_cmd,
                                        const uint8_t* msg, size_t msgLen)
{
    CSingleLock lock(&m_lock, TRUE);
    if (m_circuits.empty()) return 0;

    // Pick one Active circuit, advancing the round-robin cursor once per
    // message. (SendThrough advances it once per cell -> wrong for multi-cell.)
    std::shared_ptr<CLiveCircuit> chosen;
    size_t tries = m_circuits.size();
    while (tries-- > 0) {
        const size_t idx = m_rrNextIdx % m_circuits.size();
        m_rrNextIdx = (m_rrNextIdx + 1) % m_circuits.size();
        auto& c = m_circuits[idx];
        if (c->State() == CircuitState::Active && c->HopCount() >= 1
            && c->m_firstHopClient
            // v8.1 D8 - only ORIGINATOR circuits can be pinned: we hold the full onion
            // key stack to reach the exit. Today m_firstHopClient is set only on the
            // originator path, so this is the same set; the explicit role check makes the
            // invariant self-documenting and future-proof (a relay circuit must never be
            // selected — we'd lack the keys to reach the exit).
            && c->m_role == CircuitRole::Originator
            // A7.4 - a multi-cell op (>= 0x40) needs every hop dataplane-capable;
            // a circuit with a v8.0.0 hop (m_multicell_ok == false) is only
            // eligible for single-cell legacy ops.
            && (sub_cmd < TUN_MULTICELL_OP_MIN || c->m_multicell_ok)) {
            chosen = c;
            break;
        }
    }
    if (!chosen) return 0;

    const size_t hopOverhead = chosen->HopCount() * 16;   // AEAD tag per hop

    // Build the cell plaintext(s) for this circuit's hop count.
    std::vector<std::vector<uint8_t> > cells;
    if (sub_cmd >= TUN_MULTICELL_OP_MIN) {
        if (SUB_HEADER_BYTES + FRAG_HEADER_BYTES + hopOverhead >= CELL_PAYLOAD_MAX)
            return 0;
        const size_t fragDataMax =
            CELL_PAYLOAD_MAX - SUB_HEADER_BYTES - FRAG_HEADER_BYTES - hopOverhead;
        if (!SplitIntoCells(sub_cmd, req_id, msg, msgLen, fragDataMax, cells))
            return 0;
    } else {
        // Single-cell legacy op (ping/search): sub-header + raw body, no frag hdr.
        if (SUB_HEADER_BYTES + msgLen + hopOverhead > CELL_PAYLOAD_MAX)
            return 0;
        std::vector<uint8_t> cell(SUB_HEADER_BYTES + msgLen);
        PackSubHeader(sub_cmd, req_id, (uint16_t)msgLen, cell.data());
        if (msgLen) memcpy(cell.data() + SUB_HEADER_BYTES, msg, msgLen);
        cells.push_back(std::move(cell));
    }

    // Onion-wrap each plaintext and send ALL on the SAME (chosen) circuit.
    for (size_t i = 0; i < cells.size(); ++i) {
        uint8_t cellPayload[CELL_PAYLOAD_MAX];
        size_t  cellLen = 0;
        uint8_t cell[CELL_TOTAL_BYTES];
        if (!chosen->OnionEncrypt(cells[i].data(), cells[i].size(),
                                  cellPayload, cellLen)
            || !CellPack(chosen->Id(), CELL_RELAY, cellPayload, cellLen, cell)) {
            // A4 fix - a mid-message failure can leave this circuit's per-hop
            // nonce out of step (OnionEncrypt advances it before it can fail).
            // Destroy the circuit so it is never reused with a desynced nonce;
            // returning its id lets Tick's retry (A4.3) re-send the whole
            // message on another circuit.
            chosen->SetState(CircuitState::Destroyed);
            return chosen->Id();
        }
        if (!SendCellToPeer(chosen->m_firstHopClient, cell))
            chosen->m_sendQ.Push(cell);   // transient socket busy -> queue
    }
    return chosen->Id();
}

// v8.1 A3 - async request/reply primitives. RegisterPending creates a
// per-request slot with an auto-reset event; WaitPending blocks on it (in a
// webserver worker thread - never the main thread); SignalReply fills the
// reply and wakes the waiter. The PendingRequest is freed by the waiter
// only, after it has erased the slot, so the signaler cannot use-after-free.
CLiveTunnel::PendingRequest* CLiveTunnel::RegisterPending(uint32_t& req_id)
{
    PendingRequest* pr = new PendingRequest();
    pr->evt = CreateEvent(NULL, FALSE, FALSE, NULL);   // auto-reset, unsignaled
    CSingleLock pl(&m_pendingLock, TRUE);
    // Pick a req_id not already in flight. A 32-bit random collision is ~2^-32,
    // but a duplicate would silently hijack the other request's slot, so we
    // re-roll (the same guard NewCircuitId() uses for circuit ids).
    uint32_t id;
    for (;;) {
        uint8_t r[4];
        SecureRandomBytes(r, 4);
        id = (uint32_t)r[0] | ((uint32_t)r[1] << 8)
           | ((uint32_t)r[2] << 16) | ((uint32_t)r[3] << 24);
        if (id != 0 && m_pending.find(id) == m_pending.end()) break;
    }
    req_id = id;
    m_pending[id] = pr;
    return pr;
}

bool CLiveTunnel::WaitPending(uint32_t req_id, PendingRequest* pr,
                              uint32_t timeoutMs,
                              std::vector<uint8_t>& outReply,
                              uint32_t* outResult)
{
    WaitForSingleObject(pr->evt, timeoutMs);
    bool ok = false;
    {
        CSingleLock pl(&m_pendingLock, TRUE);
        m_pending.erase(req_id);          // unregister: SignalReply can't find it now
        // A4: a request woken by send failure (pr->failed) returns false so the
        // caller reports an honest error, not an empty-but-"successful" reply.
        if (pr->done && !pr->failed) {
            outReply = std::move(pr->reply);
            if (outResult) *outResult = pr->result;
            ok = true;
        }
    }
    CloseHandle(pr->evt);
    delete pr;
    return ok;
}

void CLiveTunnel::SignalReply(uint32_t req_id, const uint8_t* reply,
                              size_t replyLen, uint32_t result)
{
    CSingleLock pl(&m_pendingLock, TRUE);
    auto it = m_pending.find(req_id);
    if (it == m_pending.end()) return;     // no waiter (timed out / unknown)
    PendingRequest* pr = it->second;
    if (reply && replyLen > 0)
        pr->reply.assign(reply, reply + replyLen);
    pr->result = result;
    pr->done   = true;
    SetEvent(pr->evt);
}

uint32_t CLiveTunnel::RequestTestCircuit(int hops, uint32_t timeoutMs)
{
    uint32_t reqId;
    PendingRequest* pr = RegisterPending(reqId);   // generates a unique req_id
    {
        CSingleLock lk(&m_mtLock, TRUE);
        MainThreadReq req;
        req.op    = (hops == 2) ? MT_BUILD_2HOP : MT_BUILD_1HOP;
        req.reqId = reqId;
        m_mtQueue.push_back(std::move(req));
    }
    std::vector<uint8_t> dummy;
    uint32_t circId = 0;
    WaitPending(reqId, pr, timeoutMs, dummy, &circId);
    return circId;   // 0 on timeout / build failure
}

void CLiveTunnel::ProcessMainThreadWork()
{
    // MAIN THREAD. Drain the marshaled-work queue. Bounded per call so a
    // burst of requests cannot stretch a single Kad tick.
    for (int budget = 0; budget < 256; ++budget) {
        MainThreadReq req;
        {
            CSingleLock lk(&m_mtLock, TRUE);
            if (m_mtQueue.empty()) break;
            req = std::move(m_mtQueue.front());
            m_mtQueue.pop_front();
        }
        try {
            switch (req.op) {
            case MT_SEND:
                if (!req.payload.empty())
                    SendThrough(req.payload.data(), req.payload.size());
                break;
            case MT_SEND_MSG: {
                // A4 - pin the whole message to one circuit; record which one
                // in the PendingRequest so Tick() can retry it on circuit death.
                const uint32_t cid = SendMessagePinned(
                    req.reqId, req.subCmd,
                    req.payload.empty() ? NULL : req.payload.data(),
                    req.payload.size());
                CSingleLock pl(&m_pendingLock, TRUE);
                auto it = m_pending.find(req.reqId);
                if (it != m_pending.end() && it->second)
                    it->second->circ_id = cid;   // 0 = no circuit -> caller times out
                break;
            }
            case MT_BUILD_1HOP:
            case MT_BUILD_2HOP: {
                const uint32_t circId = (req.op == MT_BUILD_2HOP)
                                      ? BuildTestCircuit2Hop()
                                      : BuildTestCircuit(NULL);
                SignalReply(req.reqId, NULL, 0, circId);   // wake RequestTestCircuit
                break;
            }
            }
        } catch (...) {
            // A single failed action must not stall the rest of the queue.
        }
    }
    RebuildPeersCache();
}

void CLiveTunnel::RebuildPeersCache()
{
    // MAIN THREAD. Snapshot the ClientList into value-typed records so the
    // /api/live/privacy/peers worker handler never touches CUpDownClient.
    std::vector<PeerSnapshot> all;
    size_t tunnelingCount = 0;
    if (theApp.clientlist) {
        std::vector<CUpDownClient*> snapAll, snapTun;
        theApp.clientlist->GetConnectedSnapshot(snapAll, 50, /*tunnelOnly=*/false);
        theApp.clientlist->GetConnectedSnapshot(snapTun, 50, /*tunnelOnly=*/true);
        tunnelingCount = snapTun.size();
        all.reserve(snapAll.size());
        for (CUpDownClient* c : snapAll) {
            if (!c) continue;
            PeerSnapshot p;
            p.ip        = c->GetIP();
            p.port      = c->GetUserPort();
            p.fork_caps = c->GetForkCaps();
            p.ese_caps  = c->GetEseCapabilities();
            all.push_back(p);
        }
    }
    CSingleLock lk(&m_peersCacheLock, TRUE);
    m_peersCacheAll.swap(all);
    m_peersCacheTunnelingCount = tunnelingCount;
}

void CLiveTunnel::GetPeersSnapshot(std::vector<PeerSnapshot>& outAll,
                                   size_t& outTunnelingCount) const
{
    CSingleLock lk(&m_peersCacheLock, TRUE);
    outAll            = m_peersCacheAll;
    outTunnelingCount = m_peersCacheTunnelingCount;
}

// === v0.71 C — Data plane: CELL_RELAY delivery + tunnel ping =================
// Sub-protocol carried inside the AEAD-decrypted CELL_RELAY payload:
//   [0]      sub_cmd (TunnelOpCmd: PING=0x01, PING_REPLY=0x02)
//   [1..4]   req_id (uint32 LE) — correlates request to reply
//   [5..6]   text_len (uint16 LE)
//   [7..N]   text bytes (UTF-8)
// V correlates a reply to its blocked caller by req_id via SignalReply ->
// the PendingRequest in m_pending (A3, under m_pendingLock). Exit-side
// dispatches PING by echoing back "echo:<text>" wrapped with the circuit keys.

bool CLiveTunnel::HandleRelay_Originator(std::shared_ptr<CLiveCircuit>& circ,
                                         const uint8_t* payload, uint16_t payloadLen)
{
    if (!circ || circ->m_role != CircuitRole::Originator) return false;
    if (circ->HopCount() < 1) return false;

    // Peel all V-side hops to get the plaintext sub-protocol payload.
    uint8_t plain[CELL_PAYLOAD_MAX];
    size_t plainLen = 0;
    if (!circ->OnionDecryptAll(payload, payloadLen, plain, sizeof plain, plainLen))
        return false;
    // A1.2 — parse + validate the 7-byte sub-header via the shared helper.
    uint8_t sub_cmd = 0; uint32_t req_id = 0; uint16_t text_len = 0;
    const uint8_t* body = NULL;
    if (!ParseSubHeader(plain, plainLen, sub_cmd, req_id, text_len, body))
        return false;   // malformed sub-header

    // v8.1 A1.7 - multi-cell reply (sub_cmd >= 0x40): the body carries an
    // 8-byte fragment header. Accumulate fragments; when the logical reply
    // is complete, hand it to the waiting TunnelEchoLarge() caller.
    if (sub_cmd >= TUN_MULTICELL_OP_MIN) {
        uint16_t fragIndex = 0, fragCount = 0;
        uint32_t msgTotal = 0;
        const uint8_t* fragData = NULL;
        size_t fragDataLen = 0;
        if (!ParseFragHeader(body, text_len, fragIndex, fragCount, msgTotal,
                             fragData, fragDataLen))
            return false;
        std::vector<uint8_t> msg;
        {
            CSingleLock pl(&m_pendingLock, TRUE);
            // A1 fix - key by (circ_id, req_id), consistent with the exit side.
            const uint64_t rkey = ExitOpKey(circ->Id(), req_id);
            ReassemblyEntry& e = m_reassembly[rkey];
            // v8.1 A5 - stamp the entry on its first fragment so Tick() can
            // sweep it if the rest of the message never arrives.
            if (!e.started) e.first_seen_tick = GetTickCount();
            ReassemblyResult r = ReassemblyIngest(e, fragIndex, fragCount,
                                                  msgTotal, fragData, fragDataLen);
            if (r == ReassemblyResult::Incomplete) return true;
            if (r == ReassemblyResult::Error) {
                m_reassembly.erase(rkey);
                return true;
            }
            msg = std::move(e.message);
            m_reassembly.erase(rkey);
        }   // release m_pendingLock before the heavier work below
        // v8.1 D1 - a tunneled DISCOVERY search reply (KAD_RESULT_V2) has no PendingRequest
        // waiter when issued by the fire-and-forget SendKadSearchV2NoWait, so SignalReply
        // would just drop it. Parse it straight into the SAME Live directory the direct
        // search uses, so a Tunneled-mode viewer's stream grid populates without leaking V's
        // IP/keyword onto the DHT. (Also runs for the blocking webserver TunneledKadSearch —
        // harmless: the directory dedupes by streamKey and that caller still gets its JSON
        // via SignalReply below.) Done AFTER releasing m_pendingLock; main thread.
        if (sub_cmd == TUN_OP_KAD_RESULT_V2 && theApp.liveStreamManager) {
            theApp.liveStreamManager->GetKadBridge().FeedTunneledSearchResults(msg);
        }
        // v8.1 A3 - wake the blocked TunnelEchoLarge()/TunneledKadSearch() call. SignalReply
        // re-takes m_pendingLock (CCriticalSection is recursive).
        SignalReply(req_id, msg.data(), msg.size(), 0);
        return true;
    }

    std::string text((const char*)body, text_len);

    if (sub_cmd == TUN_OP_PING_REPLY) {
        // v8.1 D8 - if this is our periodic RTT probe's reply, record the round trip.
        // (Runs under m_lock via OnCellReceived, same as the Tick send, so the RTT
        // fields are consistently synchronized.)
        if (req_id != 0 && req_id == m_rttPingReqId && m_rttPingSentTick != 0) {
            DWORD rtt = GetTickCount() - m_rttPingSentTick;
            if (rtt > 60000u) rtt = 60000u;   // clamp absurd/stale samples; also no overflow
            // EWMA (1/4 weight); first sample seeds the mean.
            m_meanRttMs = (m_meanRttMs == 0) ? (uint32_t)rtt
                                             : (uint32_t)((m_meanRttMs * 3 + rtt) / 4);
            m_rttPingReqId = 0;   // consume so a duplicate reply can't re-match
        }
        // v8.1 A3 - wake the blocked TunnelPing() call (no-op for the RTT probe, which
        // has no registered waiter).
        SignalReply(req_id, (const uint8_t*)text.data(), text.size(), 0);
        return true;
    }
    if (sub_cmd == TUN_OP_KAD_RESULT) {
        // v8.1 A3 - wake the blocked TunneledKadSearch() call.
        SignalReply(req_id, (const uint8_t*)text.data(), text.size(), 0);
        return true;
    }
    if (sub_cmd == TUN_OP_LIVE_SUB_ACK) {
        // v8.1 Sprint C - wake the blocked TunneledLiveSubscribe() call.
        // Body is binary ([status u8][streamKey 16]); std::string carries it fine.
        SignalReply(req_id, (const uint8_t*)text.data(), text.size(), 0);
        return true;
    }
    if (sub_cmd == TUN_OP_LIVE_HEARTBEAT) {
        // v8.1 Sprint C (C3) - exit relayed the broadcaster's control update.
        // Body: [streamKey 16][flags u8][bitmap u16 LE][oldestSeq u32 LE][pubkey 32].
        const uint8_t* b = (const uint8_t*)text.data();
        if (text.size() >= 16 + 1 + 2 + 4 + 32 && theApp.liveStreamManager) {
            uchar streamKey[16]; memcpy(streamKey, b, 16);
            uint8_t flags    = b[16];
            uint16_t bitmap  = eseRdU16LE(b + 17);
            uint32_t oldest  = eseRdU32LE(b + 19);
            const bool hasBitmap = (flags & 0x01) != 0;
            const bool hasPubkey = (flags & 0x02) != 0;
            theApp.liveStreamManager->OnTunneledLiveControl(
                streamKey, hasBitmap, bitmap, oldest,
                hasPubkey ? (b + 23) : NULL);
        }
        return true;
    }
    if (sub_cmd == TUN_OP_LIVE_PEER_LIST) {
        // v8.1 Sprint C (C2/C3) - exit relayed the broadcaster's peer-list of
        // alternative sources. Body: [streamKey 16][count u8][count*(ip u32 LE +
        // port u16 LE)]. Feed it into the normal (direct, in Tunelizado) dial path.
        const uint8_t* b = (const uint8_t*)text.data();
        if (text.size() >= 16 + 1 && theApp.liveStreamManager) {
            uchar streamKey[16]; memcpy(streamKey, b, 16);
            uint8_t count = b[16];
            if (count > 16) count = 16;
            const size_t need = 16u + 1u + (size_t)count * 6u;
            if (text.size() >= need) {
                uint32_t ips[16]; uint16_t ports[16];
                for (uint8_t i = 0; i < count; ++i) {
                    ips[i]   = eseRdU32LE(b + 17 + (size_t)i * 6);
                    ports[i] = eseRdU16LE(b + 17 + (size_t)i * 6 + 4);
                }
                theApp.liveStreamManager->OnTunneledPeerList(streamKey, ips, ports, count);
            }
        }
        return true;
    }
    // Unknown sub_cmd: drop silently (future ops land here).
    return true;
}

bool CLiveTunnel::HandleRelay_Exit(std::shared_ptr<CLiveCircuit>& circ,
                                   const uint8_t* payload, uint16_t payloadLen)
{
    if (!circ || circ->m_role != CircuitRole::Relay) return false;
    // Exit needs at least 1 hop's recv keys to peel. In the loopback
    // 2-hop case we hold both V↔hop1 and V↔hop2 keys (HopCount==2);
    // in 1-hop case we hold just V↔hop1 (HopCount==1). Both are valid
    // exit configurations from THIS node's perspective.
    if (circ->HopCount() < 1) return false;

    uint8_t plain[CELL_PAYLOAD_MAX];
    size_t plainLen = 0;
    if (!circ->OnionDecryptAll(payload, payloadLen, plain, sizeof plain, plainLen))
        return false;
    // A1.2 — parse + validate the 7-byte sub-header via the shared helper.
    uint8_t sub_cmd = 0; uint32_t req_id = 0; uint16_t body_len = 0;
    const uint8_t* body = NULL;
    if (!ParseSubHeader(plain, plainLen, sub_cmd, req_id, body_len, body))
        return false;   // malformed sub-header

    // v8.1 A2 - generic dispatch. sub_cmd < 0x40 is a legacy single-cell op
    // (body is the request as-is). sub_cmd >= 0x40 is a multi-cell op: the
    // body starts with an 8-byte fragment header; accumulate fragments
    // until the logical message is complete, then dispatch it.
    if (sub_cmd >= TUN_MULTICELL_OP_MIN) {
        uint16_t fragIndex = 0, fragCount = 0;
        uint32_t msgTotal = 0;
        const uint8_t* fragData = NULL;
        size_t fragDataLen = 0;
        if (!ParseFragHeader(body, body_len, fragIndex, fragCount, msgTotal,
                             fragData, fragDataLen))
            return false;   // malformed fragment header

        std::vector<uint8_t> message;
        {
            CSingleLock pl(&m_pendingLock, TRUE);
            // A1 fix - key by (circ_id, req_id): the exit reassembles for many
            // circuits at once, so two messages sharing a req_id on different
            // circuits must not collide in one ReassemblyEntry.
            const uint64_t rkey = ExitOpKey(circ->Id(), req_id);
            ReassemblyEntry& e = m_reassembly[rkey];
            // v8.1 A5 - stamp the entry on its first fragment so Tick()
            // can sweep it if the rest of the message never arrives.
            if (!e.started) e.first_seen_tick = GetTickCount();
            ReassemblyResult r = ReassemblyIngest(e, fragIndex, fragCount,
                                                  msgTotal, fragData, fragDataLen);
            if (r == ReassemblyResult::Incomplete)
                return true;                    // wait for more fragments
            if (r == ReassemblyResult::Error) {
                m_reassembly.erase(rkey);       // malformed -> drop the entry
                return true;
            }
            message = std::move(e.message);     // Complete: take the bytes
            m_reassembly.erase(rkey);
        }
        TunnelRequestCtx ctx;
        ctx.circ    = circ;
        ctx.sub_cmd = sub_cmd;
        ctx.req_id  = req_id;
        ctx.body    = message.data();
        ctx.bodyLen = message.size();
        DispatchExitRequest(ctx);
        return true;
    }

    // Legacy single-cell op: dispatch the raw body straight away.
    TunnelRequestCtx ctx;
    ctx.circ    = circ;
    ctx.sub_cmd = sub_cmd;
    ctx.req_id  = req_id;
    ctx.body    = body;
    ctx.bodyLen = body_len;
    DispatchExitRequest(ctx);
    return true;
}

// v8.1 A2.2 - register an exit-side handler for a sub_cmd (last wins).
void CLiveTunnel::RegisterExitHandler(uint8_t sub_cmd, TunnelOpHandler handler)
{
    m_exitHandlers[sub_cmd] = std::move(handler);
}

// v8.1 A2 - look up and invoke the handler for a fully-received request.
// m_exitHandlers is populated once in the constructor and only read after,
// so no lock is needed. Unknown sub_cmd -> drop silently.
void CLiveTunnel::DispatchExitRequest(const TunnelRequestCtx& ctx)
{
    auto it = m_exitHandlers.find(ctx.sub_cmd);
    if (it != m_exitHandlers.end() && it->second)
        it->second(ctx);
}

// === v8.1 A6 - deferred exit operations ==================================
// BeginExitOperation registers a pending reply; CompleteExitOperation sends it
// when the handler's work finishes (immediately, or later from a callback in
// Sprint B). Both run on the main thread (OnCellReceived / Kad callbacks).

bool CLiveTunnel::BeginExitOperation(const TunnelRequestCtx& ctx, uint8_t reply_op)
{
    if (!ctx.circ) return false;
    ExitOperation op;
    op.circ     = ctx.circ;
    op.circ_id  = ctx.circ->Id();
    op.req_id   = ctx.req_id;
    op.reply_op = reply_op;
    op.started  = GetTickCount();
    CSingleLock pl(&m_pendingLock, TRUE);
    m_exitOps[ExitOpKey(op.circ_id, op.req_id)] = op;
    return true;
}

bool CLiveTunnel::CompleteExitOperation(uint32_t circ_id, uint32_t req_id,
                                        const uint8_t* payload, size_t payloadLen)
{
    std::shared_ptr<CLiveCircuit> circ;
    uint8_t reply_op = 0;
    {
        CSingleLock pl(&m_pendingLock, TRUE);
        auto it = m_exitOps.find(ExitOpKey(circ_id, req_id));
        if (it == m_exitOps.end()) return false;
        circ     = it->second.circ.lock();
        reply_op = it->second.reply_op;
        m_exitOps.erase(it);
    }
    if (!circ) return false;            // circuit rotated/destroyed -> drop
    // Rebuild a minimal ctx and reuse SendReply (A2.4) for the fragmented reply.
    TunnelRequestCtx ctx;
    ctx.circ   = circ;
    ctx.req_id = req_id;
    return SendReply(ctx, reply_op, payload, payloadLen);
}

void CLiveTunnel::AbortExitOperation(uint32_t circ_id, uint32_t req_id)
{
    CSingleLock pl(&m_pendingLock, TRUE);
    m_exitOps.erase(ExitOpKey(circ_id, req_id));
}

// v8.1 A2.4 - fragment + send a reply back to V. A legacy reply op
// (reply_op < 0x40) goes as one single cell; a v8.1 op (>= 0x40) is split
// into multi-cell fragments. Each cell is onion-wrapped via SendRelayReply.
bool CLiveTunnel::SendReply(const TunnelRequestCtx& ctx, uint8_t reply_op,
                            const uint8_t* payload, size_t payloadLen)
{
    if (!ctx.circ) return false;
    std::shared_ptr<CLiveCircuit> circ = ctx.circ;   // SendRelayReply wants a non-const ref

    if (reply_op < TUN_MULTICELL_OP_MIN) {
        // Legacy single-cell reply: 7-byte sub-header + raw body.
        if (payloadLen > CELL_PAYLOAD_MAX - SUB_HEADER_BYTES) return false;
        std::vector<uint8_t> cell(SUB_HEADER_BYTES + payloadLen);
        PackSubHeader(reply_op, ctx.req_id, (uint16_t)payloadLen, cell.data());
        if (payloadLen > 0)
            memcpy(cell.data() + SUB_HEADER_BYTES, payload, payloadLen);
        return SendRelayReply(circ, cell.data(), cell.size());
    }

    // Multi-cell reply: leave room in each cell for this circuit's onion
    // tags (16 B per hop) plus the sub-header + fragment header.
    const size_t hopOverhead = circ->HopCount() * 16;
    if (SUB_HEADER_BYTES + FRAG_HEADER_BYTES + hopOverhead >= CELL_PAYLOAD_MAX)
        return false;
    const size_t fragDataMax =
        CELL_PAYLOAD_MAX - SUB_HEADER_BYTES - FRAG_HEADER_BYTES - hopOverhead;
    std::vector<std::vector<uint8_t> > cells;
    if (!SplitIntoCells(reply_op, ctx.req_id, payload, payloadLen,
                        fragDataMax, cells))
        return false;
    bool ok = true;
    for (size_t i = 0; i < cells.size(); ++i)
        ok = SendRelayReply(circ, cells[i].data(), cells[i].size()) && ok;
    return ok;
}

// v8.1 A2 - exit handler for TUN_OP_PING: echo the body back with an
// "echo:" prefix as TUN_OP_PING_REPLY. (Was inline in HandleRelay_Exit.)
void CLiveTunnel::ExitHandle_Ping(const TunnelRequestCtx& ctx)
{
    std::string echoText = "echo:" + std::string((const char*)ctx.body, ctx.bodyLen);
    if (echoText.size() > CELL_PAYLOAD_MAX - SUB_HEADER_BYTES)
        echoText.resize(CELL_PAYLOAD_MAX - SUB_HEADER_BYTES);
    SendReply(ctx, TUN_OP_PING_REPLY,
              (const uint8_t*)echoText.data(), echoText.size());
}

// v8.1 A2 - exit handler for TUN_OP_KAD_SEARCH. v0.71 P1.C behaviour:
// serve matches from our LOCAL stream directory cache (built by
// CLiveKadBridge) rather than issuing a fresh Kad query - that keeps V's
// privacy (only WE know what V searched for). Sprint B replaces this with
// a real CSearch. (Was inline in HandleRelay_Exit.)
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

// === v8.1 Sprint B - real Kad search via tunnel ==========================

// B1 - exit handler for TUN_OP_KAD_SEARCH_V2: launch a REAL dual-namespace Kad
// CSearch on V's behalf and DEFER the reply (A6). Results land asynchronously
// in the Kad bridge's stream directory (thread-safe there); FinishDueSearchJobs()
// (main thread, from Tick) reads them after TUN_SEARCH_WINDOW_MS and sends
// TUN_OP_KAD_RESULT_V2. The keyword reaches the exit in clear - accepted by
// design (thesis Decision 12.3); the exit queries Kad from ITS OWN ip, so V's
// identity never touches the DHT. Runs on the main thread (OnCellReceived).
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

    BeginExitOperation(ctx, TUN_OP_KAD_RESULT_V2);

    TunnelSearchJob job;
    job.circ_id  = ctx.circ->Id();
    job.req_id   = ctx.req_id;
    job.keyword  = keyword;
    job.deadline = GetTickCount() + TUN_SEARCH_WINDOW_MS;

    // Fire the real dual-namespace search (main thread). The rate-limit /
    // cooldown inside SearchStreams protects the exit from being used as a Kad
    // amplifier; if it declines, kadSearchIds stays empty and we just serve
    // whatever the directory already holds when the window elapses.
    try {
        if (theApp.liveStreamManager) {
            CString kw(keyword.c_str());
            // v8.1 D1 - bForceDirect=true: the exit MUST query Kad from its OWN IP, never
            // re-enter the tunnel branch (would cascade a tunneled search out our circuit).
            theApp.liveStreamManager->GetKadBridge().SearchStreams(kw, &job.kadSearchIds,
                                                                   /*bForceDirect*/true);
        }
    } catch (...) {}

    CSingleLock pl(&m_pendingLock, TRUE);
    m_searchJobs[ExitOpKey(job.circ_id, job.req_id)] = std::move(job);
}

// B7 - exit handler for TUN_OP_KAD_CANCEL: V aborts an in-flight search by
// req_id. Stop the CSearch(es), drop the deferred op, erase the job. No reply.
void CLiveTunnel::ExitHandle_KadCancel(const TunnelRequestCtx& ctx)
{
    if (!ctx.circ) return;
    const uint64_t key = ExitOpKey(ctx.circ->Id(), ctx.req_id);
    TunnelSearchJob job;
    bool found = false;
    {
        CSingleLock pl(&m_pendingLock, TRUE);
        auto it = m_searchJobs.find(key);
        if (it != m_searchJobs.end()) {
            job = std::move(it->second);
            m_searchJobs.erase(it);
            found = true;
        }
    }
    if (found) StopSearchJobKad(job);
    AbortExitOperation(ctx.circ->Id(), ctx.req_id);
}

// === v8.1 Sprint C - tunneled LiveTV subscribe ===========================
// C2 - exit handler for TUN_OP_LIVE_SUBSCRIBE. The viewer (V) found the stream
// via Kad and knows the broadcaster endpoint, but does not want the broadcaster
// (or a passive observer) to learn V's IP. So V tunnels the subscribe to us
// (the exit); WE dial the broadcaster and send OP_LIVE_SUBSCRIBE with OUR
// identity — the broadcaster sees the exit, never V. We ack immediately with
// TUN_OP_LIVE_SUB_ACK; the broadcaster's live-edge bitmap + pubkey reach V via
// tunneled heartbeats (C3). Runs on the main thread (OnCellReceived), so the
// dial + packet send are safe to do here. The broadcaster endpoint reaches the
// exit in clear — accepted in the 2-hop model (cf. Decision 12.3, keyword leak);
// what matters is V's identity never touches the broadcaster or the DHT.
void CLiveTunnel::ExitHandle_LiveSubscribe(const TunnelRequestCtx& ctx)
{
    // body = [streamKey 16][bIP u32 LE][bPort u16 LE][bUDP u16 LE][bAltIP u32 LE] = 28
    uint8_t status = 1;            // 1 = bad request (default)
    uint8_t streamKey[16] = {0};
    if (ctx.body && ctx.bodyLen >= 28) {
        memcpy(streamKey, ctx.body, 16);
        uint32_t bIP    = eseRdU32LE(ctx.body + 16);
        uint16_t bPort  = eseRdU16LE(ctx.body + 20);
        uint16_t bUDP   = eseRdU16LE(ctx.body + 22);
        uint32_t bAltIP = eseRdU32LE(ctx.body + 24);
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
            auto it = m_exitLiveSubs.find(hex);
            alreadyProxied = (it != m_exitLiveSubs.end() && !it->second.circuits.empty());
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
            ExitStreamProxy& sp = m_exitLiveSubs[hex];
            if (sp.bIP == 0) { sp.bIP = bIP; sp.bPort = bPort; memcpy(sp.streamKey, streamKey, 16); }
            sp.circuits[ctx.circ->Id()].lastSeen = GetTickCount();
            if (alreadyProxied)
                LIVE_LOG("TUN", "C7 multicast: +1 tunneled viewer on existing proxy sub (%d total)",
                    (int)sp.circuits.size());
        }
    }
    // reply SUB_ACK = [status u8][streamKey 16] = 17 bytes (single-cell).
    uint8_t ack[17];
    ack[0] = status;
    memcpy(ack + 1, streamKey, 16);
    SendReply(ctx, TUN_OP_LIVE_SUB_ACK, ack, sizeof ack);
}

// C3 - 32-char lowercase hex of a 16-byte streamKey (map key for m_exitLiveSubs).
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

// C3 - relay a broadcaster control update to every circuit that proxy-subscribed
// to `streamKey` through us. Called from the Live HEARTBEAT/ANNOUNCE handlers on
// the main thread. Builds TUN_OP_LIVE_HEARTBEAT and pushes it down each circuit
// (req_id = 0: this is an unsolicited push, not a reply to a pending request).
// Body: [streamKey 16][flags u8][bitmap u16 LE][oldestSeq u32 LE][pubkey 32].
// flags bit0 = bitmap/oldestSeq valid, bit1 = pubkey valid.
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
        auto it = m_exitLiveSubs.find(hex);
        if (it == m_exitLiveSubs.end() || it->second.circuits.empty()) return;
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
        for (auto& c : m_circuits) {
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

// C2/C3 (Sprint C finish) - relay the broadcaster's OP_LIVE_PEER_LIST (alternative
// sources) down every circuit that proxy-subscribed to `streamKey` through us, so a
// tunneled viewer learns the alt sources WITHOUT the broadcaster ever seeing the
// viewer. Same snapshot-under-pending-lock then walk-under-m_lock pattern as
// ExitRelayLiveControl (preserves the tunnel->manager-only lock order). Push
// (req_id = 0). Body: [streamKey 16][count u8][count*(ip u32 LE + port u16 LE)].
// ip is a net-order DWORD written byte-preserving via eseWrU32LE; the viewer reads
// it back with eseRdU32LE and feeds the identical value into OnPeerListReceived.
void CLiveTunnel::ExitRelayPeerList(const uint8_t streamKey[16],
                                    const uint32_t* ips, const uint16_t* ports,
                                    uint8_t count)
{
    if (count == 0 || ips == NULL || ports == NULL) return;
    if (count > 16) count = 16;   // ESE_LIVE_MAX_PEER_LIST; also bounds the single cell
    const std::string hex = LiveStreamKeyHex(streamKey);

    std::vector<uint32_t> targets;
    {
        CSingleLock pl(&m_pendingLock, TRUE);
        auto it = m_exitLiveSubs.find(hex);
        if (it == m_exitLiveSubs.end() || it->second.circuits.empty()) return;
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
        for (auto& c : m_circuits) {
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

// B2/B3 - MAIN THREAD (from Tick): reply to every search job whose accumulation
// window has elapsed, then drop it. The directory has been filling async with
// real Kad results since ExitHandle_KadSearchV2 fired the search.
void CLiveTunnel::FinishDueSearchJobs()
{
    const DWORD now = GetTickCount();
    std::vector<TunnelSearchJob> due;
    {
        CSingleLock pl(&m_pendingLock, TRUE);
        for (auto it = m_searchJobs.begin(); it != m_searchJobs.end(); ) {
            if ((int)(now - it->second.deadline) >= 0) {   // window elapsed (wrap-safe)
                due.push_back(std::move(it->second));
                it = m_searchJobs.erase(it);
            } else {
                ++it;
            }
        }
    }
    for (size_t i = 0; i < due.size(); ++i) {
        std::vector<uint8_t> payload;
        SerializeSearchResults(due[i].keyword, payload);
        // CompleteExitOperation no-ops if the circuit rotated/died meanwhile.
        CompleteExitOperation(due[i].circ_id, due[i].req_id,
                              payload.data(), payload.size());
        StopSearchJobKad(due[i]);   // free the CSearch either way
    }
}

// B3 - serialize known streams matching `keyword` into the TUN_OP_KAD_RESULT_V2
// wire body (breakdown 2.3). Reuses the exit's directory + GetKnownStreams()
// (which already filters tombstones and is thread-safe).
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
                putU32(e.broadcasterIP);
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

// Stop the CSearch(es) a job launched (main thread). Delayed-delete lets late
// UDP packets drain; the search is gone within ~15 s regardless.
void CLiveTunnel::StopSearchJobKad(const TunnelSearchJob& job)
{
    for (size_t i = 0; i < job.kadSearchIds.size(); ++i) {
        try { Kademlia::CSearchManager::StopSearch(job.kadSearchIds[i], true); }
        catch (...) {}
    }
}

// v8.1 A1.7 - exit handler for the multi-cell echo test op. The dispatcher
// has already reassembled the full request; echo it back as
// TUN_OP_ECHO_LARGE_REPLY. v8.1 A6 - routed through the deferred-operation
// framework: register the op, then complete it (here immediately; Sprint B1
// will instead complete from a Kad search callback that fires much later).
// The body is copied because a deferred completer cannot rely on ctx.body
// still being alive when it runs.
void CLiveTunnel::ExitHandle_EchoLarge(const TunnelRequestCtx& ctx)
{
    if (!ctx.circ) return;
    std::vector<uint8_t> echo(ctx.body, ctx.body + ctx.bodyLen);
    BeginExitOperation(ctx, TUN_OP_ECHO_LARGE_REPLY);
    CompleteExitOperation(ctx.circ->Id(), ctx.req_id, echo.data(), echo.size());
}

bool CLiveTunnel::ShouldRouteThroughTunnel(const wchar_t* keywordOrNull, uint8_t opClass) const
{
    using namespace Kademlia;
    CKadV2ModeSelector& sel = CKadV2ModeSelector::Get();
    CKadV2ModeSelector::QueryContext q = {};
    q.includesPrivateChannelHash = false;
    if (keywordOrNull) q.keywordLowercase = keywordOrNull;
    q.operationClass = (CKadV2ModeSelector::QueryContext::OperationClass)opClass;   // v8.1 D7
    CKadV2Mode decided = sel.Decide(q);
    return decided == CKadV2Mode::Tunneled;
}

// v8.1 Sprint B - parse the TUN_OP_KAD_RESULT_V2 wire body (breakdown 2.3) into
// a JSON array. Defensive: every field is bounds-checked against the buffer and
// the per-record length, since this is network-sourced data.
static std::string SB_JsonEscape(const char* p, size_t n)
{
    static const char* HEX = "0123456789abcdef";
    std::string s;
    for (size_t i = 0; i < n; ++i) {
        char c = p[i];
        if (c == '"' || c == '\\') { s += '\\'; s += c; }
        else if ((unsigned char)c < 0x20) {
            s += "\\u00"; s += HEX[((unsigned char)c >> 4) & 0xF]; s += HEX[c & 0xF];
        } else s += c;
    }
    return s;
}

static std::string SB_ParseSearchResultsToJson(const std::vector<uint8_t>& in)
{
    static const char* HEX = "0123456789abcdef";
    const size_t n = in.size();
    if (n < 4) return "[]";
    auto rd16 = [&](size_t o)->uint16_t { return (uint16_t)in[o] | ((uint16_t)in[o+1] << 8); };
    auto rd32 = [&](size_t o)->uint32_t {
        return (uint32_t)in[o] | ((uint32_t)in[o+1] << 8)
             | ((uint32_t)in[o+2] << 16) | ((uint32_t)in[o+3] << 24); };

    const uint16_t count = rd16(0);
    std::string json = "[";
    size_t p = 4;
    bool first = true;
    for (uint16_t r = 0; r < count && p + 2 <= n; ++r) {
        const uint16_t recLen = rd16(p); p += 2;
        const size_t recEnd = p + recLen;
        if (recEnd > n) break;
        if (recLen < 35) { p = recEnd; continue; }   // fixed part = 35 B
        const size_t rec = p;
        char keyhex[33];
        for (int i = 0; i < 16; ++i) {
            keyhex[i*2]   = HEX[(in[rec + i] >> 4) & 0xF];
            keyhex[i*2+1] = HEX[in[rec + i] & 0xF];
        }
        keyhex[32] = 0;
        size_t q = rec + 16;
        const uint32_t ip    = rd32(q); q += 4;
        const uint16_t port  = rd16(q); q += 2;
        const uint16_t uport = rd16(q); q += 2;
        const uint16_t brate = rd16(q); q += 2;
        const uint32_t views = rd32(q); q += 4;
        const uint32_t start = rd32(q); q += 4;
        const uint8_t  ns    = in[q];   q += 1;
        std::string title, cat, lang;
        auto rdstr = [&](std::string& o)->bool {
            if (q + 1 > recEnd) return false;
            uint8_t len = in[q]; q += 1;
            if (q + len > recEnd) return false;
            o.assign((const char*)&in[q], len); q += len; return true;
        };
        if (!rdstr(title) || !rdstr(cat) || !rdstr(lang)) { p = recEnd; continue; }

        std::string ipstr = std::to_string(ip & 0xFF) + "." + std::to_string((ip >> 8) & 0xFF)
                          + "." + std::to_string((ip >> 16) & 0xFF) + "." + std::to_string((ip >> 24) & 0xFF);
        if (!first) json += ",";
        first = false;
        json += "{\"stream_key\":\""; json += keyhex;
        json += "\",\"title\":\"";    json += SB_JsonEscape(title.data(), title.size());
        json += "\",\"category\":\""; json += SB_JsonEscape(cat.data(), cat.size());
        json += "\",\"language\":\""; json += SB_JsonEscape(lang.data(), lang.size());
        json += "\",\"bitrate\":";    json += std::to_string(brate);
        json += ",\"viewers\":";      json += std::to_string(views);
        json += ",\"ip\":\"";         json += ipstr;
        json += "\",\"port\":";       json += std::to_string(port);
        json += ",\"uport\":";        json += std::to_string(uport);
        json += ",\"started_at\":";   json += std::to_string(start);
        json += ",\"ns\":";           json += std::to_string((unsigned)ns);
        json += "}";
        p = recEnd;
    }
    json += "]";
    return json;
}

bool CLiveTunnel::TunneledKadSearch(const std::string& keywordLower,
                                    std::string& resultsJsonOut,
                                    uint32_t timeoutMs)
{
    // v8.1 Sprint B - send TUN_OP_KAD_SEARCH_V2: the exit runs a REAL Kad
    // CSearch on our behalf, accumulates DHT results for ~TUN_SEARCH_WINDOW_MS,
    // and replies with rich multi-cell TUN_OP_KAD_RESULT_V2. timeoutMs MUST
    // exceed the exit's window. resultsJsonOut receives a JSON array.
    uint32_t req_id;
    PendingRequest* pr = RegisterPending(req_id);

    // request body = [flags u8][kw_len u16 LE][keyword] (breakdown 2.2).
    std::vector<uint8_t> body;
    const uint16_t kwLen =
        (uint16_t)(keywordLower.size() > 0xFFFF ? 0xFFFF : keywordLower.size());
    body.push_back(0x01);                       // flags bit0 = include local cache
    body.push_back((uint8_t)(kwLen & 0xFF));
    body.push_back((uint8_t)(kwLen >> 8));
    body.insert(body.end(), keywordLower.begin(), keywordLower.begin() + kwLen);

    {
        CSingleLock pl(&m_pendingLock, TRUE);
        pr->sub_cmd      = TUN_OP_KAD_SEARCH_V2;
        pr->request_msg  = body;
        pr->retries_left = TUN_SEND_RETRIES;
    }
    EnqueueSendMsg(req_id, TUN_OP_KAD_SEARCH_V2, body.data(), body.size());

    std::vector<uint8_t> reply;
    if (!WaitPending(req_id, pr, timeoutMs, reply, NULL))
        return false;
    resultsJsonOut = SB_ParseSearchResultsToJson(reply);
    return true;
}

// v8.1 Sprint C (C1) — send TUN_OP_LIVE_SUBSCRIBE and block for the SUB_ACK.
// Mirror of TunneledKadSearch: register the waiter first, pin the message to
// one circuit (A4), wait for the exit's reply. Returns true iff status == 0
// (the exit forwarded our subscribe to the broadcaster). BLOCKING — call off
// the main thread.
bool CLiveTunnel::TunneledLiveSubscribe(const uint8_t streamKey[16],
                                        uint32_t bIP, uint16_t bPort, uint16_t bUDP,
                                        uint32_t bAltIP, uint32_t timeoutMs)
{
    uint32_t req_id;
    PendingRequest* pr = RegisterPending(req_id);

    std::vector<uint8_t> body(28);
    memcpy(body.data(), streamKey, 16);
    eseWrU32LE(body.data() + 16, bIP);
    eseWrU16LE(body.data() + 20, bPort);
    eseWrU16LE(body.data() + 22, bUDP);
    eseWrU32LE(body.data() + 24, bAltIP);

    {
        CSingleLock pl(&m_pendingLock, TRUE);
        pr->sub_cmd      = TUN_OP_LIVE_SUBSCRIBE;
        pr->request_msg  = body;
        pr->retries_left = TUN_SEND_RETRIES;
    }
    EnqueueSendMsg(req_id, TUN_OP_LIVE_SUBSCRIBE, body.data(), body.size());

    std::vector<uint8_t> reply;
    if (!WaitPending(req_id, pr, timeoutMs, reply, NULL))
        return false;
    // reply = [status u8][streamKey 16]; status 0 == forwarded.
    return reply.size() >= 1 && reply[0] == 0;
}

// v8.1 Sprint C (C5) — non-blocking tunneled subscribe (see header). Uses a
// throwaway req_id with NO PendingRequest: ProcessMainThreadWork's MT_SEND_MSG
// tolerates a missing slot (it just skips retry tracking), and the SUB_ACK
// reply finds no waiter in SignalReply (no-op). No leak, no block.
void CLiveTunnel::SendLiveSubscribeNoWait(const uint8_t streamKey[16],
                                          uint32_t bIP, uint16_t bPort, uint16_t bUDP,
                                          uint32_t bAltIP)
{
    const uint32_t req_id = NewCircuitId();   // random, collision-irrelevant here
    std::vector<uint8_t> body(28);
    memcpy(body.data(), streamKey, 16);
    eseWrU32LE(body.data() + 16, bIP);
    eseWrU16LE(body.data() + 20, bPort);
    eseWrU16LE(body.data() + 22, bUDP);
    eseWrU32LE(body.data() + 24, bAltIP);
    EnqueueSendMsg(req_id, TUN_OP_LIVE_SUBSCRIBE, body.data(), body.size());
}

// v8.1 D1 - non-blocking tunneled Kad keyword search. Like SendLiveSubscribeNoWait, uses a
// throwaway req_id with NO PendingRequest: the exit runs the real Kad search on our behalf
// and replies TUN_OP_KAD_RESULT_V2, which HandleRelay_Originator parses straight into the
// Live directory (no waiter to wake). This lets CLiveKadBridge::SearchStreams route
// discovery through the tunnel from the MAIN thread without blocking (the existing
// TunneledKadSearch is blocking and only safe off the main thread). Body =
// [flags u8][kw_len u16 LE][keyword bytes] (Sprint B breakdown 2.2), keyword UTF-8.
void CLiveTunnel::SendKadSearchV2NoWait(const std::string& keywordLower)
{
    const uint32_t req_id = NewCircuitId();
    std::vector<uint8_t> body;
    const uint16_t kwLen =
        (uint16_t)(keywordLower.size() > 0xFFFF ? 0xFFFF : keywordLower.size());
    body.push_back(0x01);                       // flags bit0 = include local cache
    body.push_back((uint8_t)(kwLen & 0xFF));
    body.push_back((uint8_t)(kwLen >> 8));
    body.insert(body.end(), keywordLower.begin(), keywordLower.begin() + kwLen);
    EnqueueSendMsg(req_id, TUN_OP_KAD_SEARCH_V2, body.data(), body.size());
}

bool CLiveTunnel::SendRelayReply(std::shared_ptr<CLiveCircuit>& circ,
                                 const uint8_t* plain, size_t plainLen)
{
    if (!circ || circ->HopCount() < 1 || !circ->m_prevHopClient) return false;
    // Wrap through ALL registered hops in REVERSE order, mirroring
    // V's OnionEncrypt. With m_hops = [V↔hop1, V↔hop2] this produces
    // outer-layer K_hop1_to_v wrapping inner-layer K_hop2_to_v — exactly
    // what V expects to peel (hop[0] outer first, hop[1] inner).
    uint8_t wrapped[CELL_PAYLOAD_MAX];
    size_t wrappedLen = 0;
    if (!circ->OnionEncrypt(plain, plainLen, wrapped, wrappedLen))
        return false;
    uint8_t cell[CELL_TOTAL_BYTES];
    if (!CellPack(circ->Id(), CELL_RELAY, wrapped, wrappedLen, cell))
        return false;
    return SendCellToPeer(circ->m_prevHopClient, cell);
}

bool CLiveTunnel::TunnelPing(const std::string& text, std::string& replyText,
                             uint32_t timeoutMs)
{
    // v8.1 A4 - register the waiter BEFORE sending (generates a unique req_id;
    // a fast reply cannot race the registration), stash the message for retry,
    // then marshal a pinned send and block on the event (A3, no poll).
    uint32_t req_id;
    PendingRequest* pr = RegisterPending(req_id);
    {
        CSingleLock pl(&m_pendingLock, TRUE);
        pr->sub_cmd      = TUN_OP_PING;
        pr->request_msg.assign(text.begin(), text.end());
        pr->retries_left = TUN_SEND_RETRIES;
    }
    EnqueueSendMsg(req_id, TUN_OP_PING,
                   (const uint8_t*)text.data(), text.size());

    std::vector<uint8_t> reply;
    if (!WaitPending(req_id, pr, timeoutMs, reply, NULL))
        return false;
    replyText.assign((const char*)reply.data(), reply.size());
    return true;
}

// v8.1 A1.7 - multi-cell echo round-trip. Marshals the message for a pinned
// send (A4: SendMessagePinned fragments it onto one circuit) and blocks on the
// event (A3) for the reassembled TUN_OP_ECHO_LARGE_REPLY. Worker-thread safe.
bool CLiveTunnel::TunnelEchoLarge(const std::vector<uint8_t>& payload,
                                  std::vector<uint8_t>& replyOut,
                                  uint32_t timeoutMs)
{
    // Reject oversize up front so the caller gets a clean false (the real
    // fragmentation now happens in SendMessagePinned, sized to the actual
    // circuit's hop count).
    if (payload.size() > TUN_MSG_MAX_BYTES)
        return false;

    // v8.1 A4 - register the waiter (generates a unique req_id), stash the
    // message for retry, then marshal a pinned send: all fragments ride ONE
    // circuit so they reassemble at one exit. Block on the event (A3, no poll).
    uint32_t req_id;
    PendingRequest* pr = RegisterPending(req_id);
    {
        CSingleLock pl(&m_pendingLock, TRUE);
        pr->sub_cmd      = TUN_OP_ECHO_LARGE;
        pr->request_msg  = payload;
        pr->retries_left = TUN_SEND_RETRIES;
    }
    EnqueueSendMsg(req_id, TUN_OP_ECHO_LARGE,
                   payload.empty() ? NULL : payload.data(), payload.size());

    return WaitPending(req_id, pr, timeoutMs, replyOut, NULL);
}

void CLiveTunnel::Tick()
{
    CSingleLock lock(&m_lock, TRUE);
    // 1. Reap Destroyed circuits.
    auto isDead = [](const std::shared_ptr<CLiveCircuit>& c) {
        return c->State() == CircuitState::Destroyed;
    };
    m_circuits.erase(std::remove_if(m_circuits.begin(), m_circuits.end(), isDead),
                     m_circuits.end());

    // 2. Rotation: any ACTIVE circuit older than ROTATION_BASE_MS is
    // marked Destroyed. Pending circuits get a longer timeout because
    // they're waiting for handshake reply.
    const DWORD now = GetTickCount();
    for (auto& c : m_circuits) {
        if (c->State() == CircuitState::Active && c->AgeMs() > TUNNEL_ROTATION_BASE_MS)
            c->SetState(CircuitState::Destroyed);
        else if (c->State() == CircuitState::Pending && c->AgeMs() > TUNNEL_HANDSHAKE_TIMEOUT_MS * 8)
            // 8x handshake timeout = ~6.4 s. After this, give up — peer
            // probably isn't running the fork.
            c->SetState(CircuitState::Destroyed);
        else if (c->State() == CircuitState::HalfBuilt && c->AgeMs() > TUNNEL_HANDSHAKE_TIMEOUT_MS * 16)
            // v8.1 fix: a circuit stuck mid-EXTEND (hop1 done, EXTENDED
            // never arrived) used to fall through both arms above and
            // leak forever. Time it out, with a longer budget since it
            // is waiting on a second handshake leg.
            c->SetState(CircuitState::Destroyed);
    }

    // 3. v0.71 P0.A — cover traffic emission. For each Active originator
    // circuit, if it's past m_nextPaddingTick, emit a CELL_PADDING with
    // random length and reschedule via Poisson distribution.
    // This makes TAG_ESE_CAPS bit 11 (cover_traffic) truthful: the bit
    // claims we generate cover traffic, and now we actually do.
    auto& covCfg = CLiveCoverTraffic::Get();
    for (auto& c : m_circuits) {
        if (c->State() != CircuitState::Active) continue;
        if (c->m_role != CircuitRole::Originator) continue;   // only originator drives cover
        if (c->HopCount() < 1) continue;
        if (c->m_lastPaddingTick == 0) {
            c->m_lastPaddingTick = now;
            c->m_nextPaddingDelayMs =
                covCfg.NextPaddingDelayMs((uint32_t)covCfg.GetProfile());
            continue;
        }
        if (now - c->m_lastPaddingTick < c->m_nextPaddingDelayMs) continue;

        // Build a CELL_PADDING: payload = random bytes of random length.
        uint16_t fakeLen = covCfg.SampleFakeLength();
        // v8.1 fix: cap the fake length so the onion-wrapped padding cell
        // fits (each hop adds a 16-byte AEAD tag). SampleFakeLength()
        // returns 0..505, so without this ~6% of cover cells on a 2-hop
        // circuit overflowed OnionEncrypt and were dropped.
        const size_t covMaxFake = (c->HopCount() * 16 < CELL_PAYLOAD_MAX)
                                ? (CELL_PAYLOAD_MAX - c->HopCount() * 16) : 0;
        if (fakeLen > covMaxFake) fakeLen = (uint16_t)covMaxFake;
        std::vector<uint8_t> fakePlain(fakeLen);
        if (fakeLen > 0) SecureRandomBytes(fakePlain.data(), fakeLen);
        // Onion-wrap through the same hops as a real RELAY would.
        uint8_t cellPayload[CELL_PAYLOAD_MAX];
        size_t cellPayloadLen = 0;
        if (!c->OnionEncrypt(fakePlain.data(), fakePlain.size(),
                             cellPayload, cellPayloadLen))
            continue;
        uint8_t cell[CELL_TOTAL_BYTES];
        if (!CellPack(c->Id(), CELL_PADDING, cellPayload, cellPayloadLen, cell))
            continue;
        if (!c->m_firstHopClient) continue;
        if (SendCellToPeer(c->m_firstHopClient, cell)) {
            c->m_lastPaddingTick = now;
            c->m_nextPaddingDelayMs =
                covCfg.NextPaddingDelayMs((uint32_t)covCfg.GetProfile());
        }
    }

    // 3b. v8.1 D8 - periodic tunnel RTT probe. Every RTT_PING_INTERVAL_MS, send ONE
    // fire-and-forget TUN_OP_PING (reusing the existing ping op — no new wire opcode)
    // pinned by SendMessagePinned to an Active circuit, and record its req_id + send
    // tick. The PING_REPLY arm in HandleRelay_Originator differences the tick into
    // m_meanRttMs (EWMA). SendMessagePinned returns 0 when there is no Active circuit,
    // so this is a pure no-op on a single-PC node (it never builds anything).
    {
        const DWORD RTT_PING_INTERVAL_MS = 5000u;
        if ((DWORD)(now - m_lastRttPingTick) >= RTT_PING_INTERVAL_MS) {
            m_lastRttPingTick = now;
            // req_id is a fresh random NewCircuitId(), NOT deduped against m_pending
            // (can't take m_pendingLock here — Tick holds m_lock, and the order is
            // m_pendingLock->m_lock). A ~2^-32 collision with an in-flight manual
            // TunnelPing would cost one washed-out EWMA sample; accepted given the odds
            // and that TunnelPing is a dev-only diagnostic path.
            const uint32_t rttReqId = NewCircuitId();
            const uint8_t pingBody[1] = { 0 };          // 1-byte body (exit echoes it)
            if (SendMessagePinned(rttReqId, TUN_OP_PING, pingBody, sizeof pingBody) != 0) {
                m_rttPingReqId    = rttReqId;
                m_rttPingSentTick = now;
            } else {
                // No Active circuit -> no probe in flight. Drop any stale stamp so a
                // very-delayed reply to an old probe can't yield an inflated RTT sample.
                m_rttPingReqId = 0;
            }
        }
    }

    // 4. v8.1 A5 - sweep abandoned reassembly buffers. A multi-cell message
    // whose remaining fragments never arrive would otherwise leave its
    // ReassemblyEntry in m_reassembly forever (memory leak + DoS vector).
    {
        CSingleLock pl(&m_pendingLock, TRUE);
        for (auto it = m_reassembly.begin(); it != m_reassembly.end(); ) {
            if ((DWORD)(now - it->second.first_seen_tick) > TUN_REASSEMBLY_TTL_MS)
                it = m_reassembly.erase(it);
            else
                ++it;
        }
    }

    // 5. v8.1 A4 - retry/fail messages pinned to a circuit that died mid-flight.
    // Rotation (step 2 above) or a CELL_DESTROY can kill a circuit while one of
    // its multi-cell messages was still in flight. Re-send the whole message on
    // another circuit (up to retries_left); when retries run out, wake the
    // waiter with a failure so it returns a clean error instead of timing out.
    {
        auto circuitAlive = [&](uint32_t id) -> bool {
            for (auto& c : m_circuits)
                if (c->Id() == id && c->State() == CircuitState::Active) return true;
            return false;
        };
        std::vector<MainThreadReq> retries;
        {
            CSingleLock pl(&m_pendingLock, TRUE);
            for (auto& kv : m_pending) {
                PendingRequest* pr = kv.second;
                if (!pr || pr->done) continue;
                if (pr->circ_id == 0) continue;            // not sent yet / no circuit
                if (circuitAlive(pr->circ_id)) continue;   // still on a live circuit
                if (pr->retries_left > 0) {
                    pr->retries_left--;
                    pr->circ_id = 0;                       // reassigned on resend
                    MainThreadReq rq;
                    rq.op      = MT_SEND_MSG;
                    rq.reqId   = kv.first;
                    rq.subCmd  = pr->sub_cmd;
                    rq.payload = pr->request_msg;
                    retries.push_back(std::move(rq));
                } else {
                    pr->failed = true;                     // out of retries -> honest fail
                    pr->done   = true;
                    SetEvent(pr->evt);
                }
            }
        }
        if (!retries.empty()) {
            CSingleLock lk(&m_mtLock, TRUE);
            for (size_t i = 0; i < retries.size(); ++i)
                m_mtQueue.push_back(std::move(retries[i]));
        }
    }

    // 6. v8.1 A6 - sweep deferred exit operations that never completed, or
    // whose circuit has gone (weak_ptr expired). TTL reuses the hard request
    // bound; without this a never-finishing exit op would leak forever.
    {
        CSingleLock pl(&m_pendingLock, TRUE);
        for (auto it = m_exitOps.begin(); it != m_exitOps.end(); ) {
            const bool expired =
                (DWORD)(now - it->second.started) > TUN_REQUEST_HARD_TTL_MS;
            if (expired || it->second.circ.expired())
                it = m_exitOps.erase(it);
            else
                ++it;
        }
    }

    // 7. v8.1 Sprint B - reply to tunneled Kad searches whose accumulation
    // window has elapsed (real results have been landing in the directory).
    FinishDueSearchJobs();

    // 8. v8.1 Sprint C (C3) - sweep exit-proxy subscriptions whose circuit died
    // or that went silent past the TTL, so a departed viewer stops us relaying
    // (and re-subscribing to) the broadcaster on its behalf.
    {
        auto circuitAlive = [&](uint32_t id) -> bool {
            for (auto& c : m_circuits)
                if (c->Id() == id && c->State() == CircuitState::Active) return true;
            return false;
        };
        const DWORD EXIT_SUB_TTL_MS = 10u * 60u * 1000u;   // 10 min
        // Streams whose last viewer left: UNSUBSCRIBE the exit from the
        // broadcaster (C4 zombie fix). Collected under m_pendingLock, dispatched
        // AFTER releasing it (the manager call takes CLiveStreamManager::m_lock —
        // preserve the tunnel->manager ordering, never hold m_pendingLock across it).
        struct DeadProxy { uint8_t streamKey[16]; uint32_t bIP; uint16_t bPort; };
        std::vector<DeadProxy> dead;
        {
            CSingleLock pl(&m_pendingLock, TRUE);
            for (auto sit = m_exitLiveSubs.begin(); sit != m_exitLiveSubs.end(); ) {
                auto& circs = sit->second.circuits;
                for (auto cit = circs.begin(); cit != circs.end(); ) {
                    if (!circuitAlive(cit->first) ||
                        (DWORD)(now - cit->second.lastSeen) > EXIT_SUB_TTL_MS)
                        cit = circs.erase(cit);
                    else
                        ++cit;
                }
                if (circs.empty()) {
                    DeadProxy dp;
                    memcpy(dp.streamKey, sit->second.streamKey, 16);
                    dp.bIP = sit->second.bIP; dp.bPort = sit->second.bPort;
                    dead.push_back(dp);
                    sit = m_exitLiveSubs.erase(sit);
                } else {
                    ++sit;
                }
            }
        }
        for (size_t i = 0; i < dead.size(); ++i) {
            if (theApp.liveStreamManager && dead[i].bIP != 0)
                theApp.liveStreamManager->ExitProxyUnsubscribe(
                    dead[i].streamKey, dead[i].bIP, dead[i].bPort);
        }
    }

    m_lastTickMs = now;
}

size_t CLiveTunnel::ActiveCircuitCount() const
{
    CSingleLock lock(&m_lock, TRUE);
    size_t n = 0;
    for (auto& c : m_circuits)
        if (c->State() == CircuitState::Active) ++n;
    return n;
}

// v0.71 P3.8 — count circuits in flight (CREATE sent, CREATED not yet
// received). Important to expose because a test_circuit against a non-fork
// peer creates a Pending circuit that NEVER reaches Active (peer drops
// the unknown opcode), and ActiveCircuitCount alone would show 0
// throughout the entire 6s pending window, falsely suggesting nothing
// happened.
size_t CLiveTunnel::PendingCircuitCount() const
{
    CSingleLock lock(&m_lock, TRUE);
    size_t n = 0;
    for (auto& c : m_circuits)
        if (c->State() == CircuitState::Pending) ++n;
    return n;
}

size_t CLiveTunnel::RelayCircuitCount() const
{
    CSingleLock lock(&m_lock, TRUE);
    size_t n = 0;
    for (auto& c : m_circuits)
        if (c->m_role == CircuitRole::Relay && c->State() == CircuitState::Active) ++n;
    return n;
}

size_t CLiveTunnel::TotalCircuitCount() const
{
    CSingleLock lock(&m_lock, TRUE);
    return m_circuits.size();
}

}  // namespace eSELive
