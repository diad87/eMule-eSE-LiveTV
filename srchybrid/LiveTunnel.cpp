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
        BuildExtend(circ, hop2);
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

        case CELL_PADDING:
            // Cover traffic — drop, statistics already counted.
            return true;

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

    // Generate a fresh ephemeral for V↔hop2. The slot was wiped after
    // hop1's CREATED so it's safe to reuse.
    uint8_t evPub2[32];
    if (!X25519GenerateKeypair(evPub2, circ->m_ephemeral_priv))
        return false;
    circ->m_have_ephemeral = true;

    // Build EXTEND payload: 4B IP + 2B port + 32B ev_pub2 = 38B.
    uint8_t extendPlain[38];
    const uint32 hop2_ip = hop2->GetIP();           // network byte order
    const uint16 hop2_port = hop2->GetUserPort();
    // Write IP as 4 bytes little-endian (consistent with our cell convention).
    // Note: peer-side will need to use this when calling FindClientByIP.
    extendPlain[0] = (uint8_t)(hop2_ip & 0xFF);
    extendPlain[1] = (uint8_t)((hop2_ip >>  8) & 0xFF);
    extendPlain[2] = (uint8_t)((hop2_ip >> 16) & 0xFF);
    extendPlain[3] = (uint8_t)((hop2_ip >> 24) & 0xFF);
    extendPlain[4] = (uint8_t)(hop2_port & 0xFF);
    extendPlain[5] = (uint8_t)((hop2_port >> 8) & 0xFF);
    memcpy(extendPlain + 6, evPub2, 32);

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
    // The encrypted EXTEND payload arrives as the cell's payload. We
    // need to AEAD-decrypt using our K_recv_v_to_hop1 (== hop[0].k_recv).
    // Plaintext is 38B; ciphertext = 38+16 tag = 54B.
    if (payloadLen < 54) return false;
    uint8_t extendPlain[54];
    size_t extendPlainLen = 0;
    if (!circ->OnionPeelOne(0, payload, payloadLen, extendPlain, extendPlainLen))
        return false;
    if (extendPlainLen < 38) return false;

    // Parse hop2 endpoint + ev_pub2.
    uint32 hop2_ip = (uint32)extendPlain[0]
                   | ((uint32)extendPlain[1] << 8)
                   | ((uint32)extendPlain[2] << 16)
                   | ((uint32)extendPlain[3] << 24);
    uint16 hop2_port = (uint16)extendPlain[4] | ((uint16)extendPlain[5] << 8);
    const uint8_t* evPub2 = extendPlain + 6;

    // v0.71 B — self-loopback detection. With only 2 fork PCs in the
    // network (testing), V picks the same peer for hop1 and hop2; so we
    // (hop1) receive an EXTEND with hop2_ip == our own public IP. We're
    // not in our own ClientList, so FindClientByIP returns NULL. To make
    // the test reach hop_count==2 visibly, we synthesize the hop2 reply
    // locally: generate er_pub2/er_priv2, derive the shared (just to
    // wipe er_priv2 cleanly), wrap er_pub2 as CELL_EXTENDED with the
    // current circuit's K_send_r_to_v, send back to V on V's circ_id.
    // From V's perspective the protocol completes perfectly; reality is
    // that hop1 and hop2 are the same node (zero anonymity — explicit
    // test mode, NOT for production).
    if (theApp.GetPublicIP() != 0 && hop2_ip == theApp.GetPublicIP()) {
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

    // Build and send CELL_CREATE to hop2 with the ev_pub2 we got from V.
    uint8_t cell[CELL_TOTAL_BYTES];
    if (!CellPack(outId, CELL_CREATE, evPub2, 32, cell)) {
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

// === v0.71 C — Data plane: CELL_RELAY delivery + tunnel ping =================
// Sub-protocol carried inside the AEAD-decrypted CELL_RELAY payload:
//   [0]      sub_cmd (TunnelOpCmd: PING=0x01, PING_REPLY=0x02)
//   [1..4]   req_id (uint32 LE) — correlates request to reply
//   [5..6]   text_len (uint16 LE)
//   [7..N]   text bytes (UTF-8)
// V dispatches PING_REPLY by req_id to pending HTTP requests in
// m_pendingPingReplies (under m_pendingLock). Exit-side dispatches PING
// by echoing back "echo:<text>" wrapped with the same circuit's keys.

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
    if (plainLen < 7) return false;   // too short for header

    const uint8_t sub_cmd = plain[0];
    const uint32_t req_id = (uint32_t)plain[1]
                          | ((uint32_t)plain[2] << 8)
                          | ((uint32_t)plain[3] << 16)
                          | ((uint32_t)plain[4] << 24);
    const uint16_t text_len = (uint16_t)plain[5] | ((uint16_t)plain[6] << 8);
    if (7u + text_len > plainLen) return false;
    std::string text((const char*)plain + 7, text_len);

    if (sub_cmd == TUN_OP_PING_REPLY) {
        // Store reply for the waiting TunnelPing() call.
        CSingleLock pl(&m_pendingLock, TRUE);
        m_pendingPingReplies[req_id] = text;
        return true;
    }
    // Unknown sub_cmd: drop silently (future ops land here).
    return true;
}

bool CLiveTunnel::HandleRelay_Exit(std::shared_ptr<CLiveCircuit>& circ,
                                   const uint8_t* payload, uint16_t payloadLen)
{
    if (!circ || circ->m_role != CircuitRole::Relay) return false;
    // Exit requires ALL hops' recv keys to peel the full onion. In the
    // self-loopback path we stash both V↔hop1 and V↔hop2 keys in
    // m_hops. If only 1 hop is registered we're hop1-only (no exit
    // capability) and the cell should have been forwarded already.
    if (circ->HopCount() < 2) return false;

    uint8_t plain[CELL_PAYLOAD_MAX];
    size_t plainLen = 0;
    if (!circ->OnionDecryptAll(payload, payloadLen, plain, sizeof plain, plainLen))
        return false;
    if (plainLen < 7) return false;

    const uint8_t sub_cmd = plain[0];
    const uint32_t req_id = (uint32_t)plain[1]
                          | ((uint32_t)plain[2] << 8)
                          | ((uint32_t)plain[3] << 16)
                          | ((uint32_t)plain[4] << 24);
    const uint16_t text_len = (uint16_t)plain[5] | ((uint16_t)plain[6] << 8);
    if (7u + text_len > plainLen) return false;

    if (sub_cmd == TUN_OP_PING) {
        // Build PING_REPLY echoing the same text with "echo:" prefix.
        std::string echoText = "echo:" + std::string((const char*)plain + 7, text_len);
        if (echoText.size() > CELL_PAYLOAD_MAX - 7) echoText.resize(CELL_PAYLOAD_MAX - 7);
        std::vector<uint8_t> reply(7 + echoText.size());
        reply[0] = TUN_OP_PING_REPLY;
        reply[1] = (uint8_t)(req_id & 0xFF);
        reply[2] = (uint8_t)((req_id >>  8) & 0xFF);
        reply[3] = (uint8_t)((req_id >> 16) & 0xFF);
        reply[4] = (uint8_t)((req_id >> 24) & 0xFF);
        const uint16_t rl = (uint16_t)echoText.size();
        reply[5] = (uint8_t)(rl & 0xFF);
        reply[6] = (uint8_t)((rl >> 8) & 0xFF);
        memcpy(reply.data() + 7, echoText.data(), echoText.size());
        return SendRelayReply(circ, reply.data(), reply.size());
    }
    return true;
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
    // Generate a random req_id (32-bit). Probabilistic collision is
    // ~negligible for the few outstanding pings we'd ever have.
    uint8_t r[4];
    SecureRandomBytes(r, 4);
    const uint32_t req_id = (uint32_t)r[0]
                          | ((uint32_t)r[1] << 8)
                          | ((uint32_t)r[2] << 16)
                          | ((uint32_t)r[3] << 24);

    // Build sub-protocol payload.
    std::vector<uint8_t> payload(7 + text.size());
    payload[0] = TUN_OP_PING;
    payload[1] = (uint8_t)(req_id & 0xFF);
    payload[2] = (uint8_t)((req_id >>  8) & 0xFF);
    payload[3] = (uint8_t)((req_id >> 16) & 0xFF);
    payload[4] = (uint8_t)((req_id >> 24) & 0xFF);
    const uint16_t tl = (uint16_t)text.size();
    payload[5] = (uint8_t)(tl & 0xFF);
    payload[6] = (uint8_t)((tl >> 8) & 0xFF);
    memcpy(payload.data() + 7, text.data(), text.size());

    // Send through tunnel.
    if (!SendThrough(payload.data(), payload.size()))
        return false;

    // Poll the pending replies map until timeout. Cheap poll because
    // the map is tiny; we sleep 50ms between checks. The CELL_RELAY
    // handler runs on the socket thread and writes to the map under
    // m_pendingLock.
    DWORD start = GetTickCount();
    while (GetTickCount() - start < timeoutMs) {
        {
            CSingleLock pl(&m_pendingLock, TRUE);
            auto it = m_pendingPingReplies.find(req_id);
            if (it != m_pendingPingReplies.end()) {
                replyText = it->second;
                m_pendingPingReplies.erase(it);
                return true;
            }
        }
        Sleep(50);
    }
    // Timeout. Clean up the slot if anything appeared meanwhile.
    CSingleLock pl(&m_pendingLock, TRUE);
    m_pendingPingReplies.erase(req_id);
    return false;
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
