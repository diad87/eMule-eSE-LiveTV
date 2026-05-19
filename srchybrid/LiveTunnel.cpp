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

namespace eSELive {

CLiveTunnel::CLiveTunnel()
    : m_rrNextIdx(0)
    , m_lastTickMs(0)
{}

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
        uint8_t evPub[32];
        if (!X25519GenerateKeypair(evPub, c->m_ephemeral_priv)) {
            continue;
        }
        c->m_have_ephemeral = true;
        c->SetState(CircuitState::Pending);

        // Build CELL_CREATE payload = evPub (32B) only for now. A future
        // version would append a tag binding to the relay's long-term
        // pubkey (ntor proper) — we don't have a peer-id registry yet so
        // we skip that step and trust TCP origin (BCP for prototype).
        uint8_t cell[CELL_TOTAL_BYTES];
        if (!CellPack(id, CELL_CREATE, evPub, sizeof evPub, cell)) {
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

void CLiveTunnel::Stop()
{
    CSingleLock lock(&m_lock, TRUE);
    m_circuits.clear();
    m_rrNextIdx = 0;
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

    // 1-hop done — for the V1 release we treat this as Active. To extend
    // to 2-hop: here we'd build a CELL_EXTEND containing hop 2's
    // endpoint + a fresh ephemeral, encrypt with k_send (which IS what
    // OnionEncrypt does over the single registered hop), and send.
    // TODO P3.next: 2-hop extension.
    circ->SetState(CircuitState::Active);
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

    // CELL_CREATE: someone is asking us to be a relay for them. Handle
    // even if we don't know circ_id yet (this is by design — circ_id is
    // chosen by the originator and we learn it from the cell).
    if (cmd == CELL_CREATE) {
        return HandleCreate_Relay(circ_id, payload, payloadLen, fromPeer);
    }

    // All other cells require an existing circuit entry.
    std::shared_ptr<CLiveCircuit> circ;
    for (auto& c : m_circuits)
        if (c->Id() == circ_id) { circ = c; break; }
    if (!circ) return false;

    switch (cmd) {
        case CELL_CREATED:
            // Only meaningful on originator side.
            if (circ->m_role != CircuitRole::Originator) return false;
            return HandleCreated_Originator(circ, payload, payloadLen);

        case CELL_EXTEND:
        case CELL_EXTENDED:
            // TODO P3.next: 2-hop. For now log and drop.
            return true;

        case CELL_RELAY:
            // Originator: peel ALL layers; the consumer is whoever
            // registered with the tunnel (LiveStreamManager in F5 P3+).
            // Relay: peel ONE layer and forward (originator-side stays
            // single-hop in P3, so the relay branch is unreachable until
            // 2-hop extension lands — but we keep the check for safety).
            if (circ->m_role == CircuitRole::Originator) {
                // For now, only count it; data plane delivery is the
                // next milestone.
                return true;
            } else {
                // Relay forwarding logic — not needed for 1-hop tests.
                return true;
            }

        case CELL_DESTROY:
            circ->SetState(CircuitState::Destroyed);
            return true;

        case CELL_PADDING:
            // Cover traffic — drop, statistics already counted.
            return true;

        default:
            return false;
    }
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
