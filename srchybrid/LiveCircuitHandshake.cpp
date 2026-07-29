// Physical owner of the authenticated live-circuit handshake (MOD-1.4).
// this file is part of eMule eSE — 2-hop onion tunnel manager impl (F4 + P3)
//
// v0.71 P3 — graduates the F4 skeleton into a working 1-hop handshake.
// The originator generates an ephemeral X25519 keypair, sends CELL_CREATE
// to a relay candidate over OP_LIVE_TUNNEL_CELL, the relay derives shared
// secret via X25519, derives K_send/K_recv via HKDF, replies CELL_CREATED.
// The originator completes the same derivation and the circuit reaches
// Active. 2-hop extension (CELL_EXTEND/CELL_EXTENDED) is IMPLEMENTED below
// (BuildExtend / HandleExtend_Relay / ForwardCreatedAsExtended_Relay /
// HandleExtended_Originator), in both v1 and authenticated v2 forms.
//
// IMPORTANT: cells go through TCP via CClientReqSocket::SendPacket using
// the eMule extension protocol (OP_LIVE_TUNNEL_CELL = 0xD5). Any peer
// running this fork that calls ListenSocket::ProcessExtPacket and dispatches
// to CLiveTunnel::Get().OnCellReceived will complete the handshake. Peers
// without the fork drop the unknown opcode silently (no wire breakage).
#include "stdafx.h"
#include "LiveCircuitHandshake.h"
#include "LiveCircuit.h"
#include "LiveOnionCrypto.h"
#include "Kad6CryptoHost.h"
#include "UpDownClient.h"
#include "Log.h"
#include "LiveCrypto.h"

namespace eSELive {

namespace LiveCircuitHandshakeWire {

// ===== v8.x Phase 2 — authenticated CREATE/CREATED v2 (signed handshake) =====
// Byte-exact, little-endian, fixed widths. The transcript serializer MUST be
// identical on the signer (relay)
// and the verifier (originator) — a single byte of drift makes the HKDF keys
// diverge and the circuit dies on its first AEAD cell.
void PutU32LE(uint8_t* p, uint32_t v) {
    p[0] = (uint8_t)(v & 0xFF);
    p[1] = (uint8_t)((v >> 8) & 0xFF);
    p[2] = (uint8_t)((v >> 16) & 0xFF);
    p[3] = (uint8_t)((v >> 24) & 0xFF);
}

// "ese-tun-created-v2" = 18 bytes (no NUL in the transcript).
static const char   TUN_TRANSCRIPT_LABEL[] = "ese-tun-created-v2";
// Compile-time guards against single-byte drift: edit the label or the layout
// formula without updating its twin and the BUILD breaks here, instead of the
// circuit dying silently on its first AEAD cell (signer/verifier key divergence).
static_assert(sizeof(TUN_TRANSCRIPT_LABEL) - 1 == 18, "eSE Auth: transcript label must be exactly 18 bytes (NUL excluded).");
static_assert(TUN_TRANSCRIPT_LEN == 150, "eSE Auth: canonical transcript layout must be exactly 150 bytes.");

// Canonical CREATED-v2 transcript (§4). `out` must hold TUN_TRANSCRIPT_LEN bytes.
void BuildCreatedTranscript(uint32_t circ_id,
                                   const uint8_t ev_pub[32], const uint8_t er_pub[32],
                                   uint32_t signed_caps, const uint8_t create_nonce[16],
                                   const uint8_t target_user_hash[16], const uint8_t node_pub[32],
                                   uint8_t* out /* TUN_TRANSCRIPT_LEN */) {
    size_t o = 0;
    (void)circ_id;   // circ_id is PER-LEG (V's id on V<->hop1, hop1's outId on hop1<->hop2),
                     // so signer and verifier would disagree on the EXTEND. create_nonce is the
                     // real session anchor and IS leg-consistent (V mints it, it's forwarded intact).
    memcpy(out + o, TUN_TRANSCRIPT_LABEL, 18);  o += 18;
    memcpy(out + o, ev_pub, 32);                o += 32;
    memcpy(out + o, er_pub, 32);                o += 32;
    PutU32LE(out + o, signed_caps);             o += 4;
    memcpy(out + o, create_nonce, 16);          o += 16;
    memcpy(out + o, target_user_hash, 16);      o += 16;
    memcpy(out + o, node_pub, 32);              o += 32;
    (void)o;  // == TUN_TRANSCRIPT_LEN
}

// HKDF `info` for the v2 directional keys (§5): label ‖ circ_id ‖ ev_pub ‖ er_pub
// ‖ signed_caps ‖ node_pub. `label20` is a 20-char direction string (no NUL).
static_assert(TUN_HKDF_INFO_LEN == 120, "eSE Auth: HKDF info context buffer must be exactly 120 bytes.");
size_t BuildHkdfInfoV2(const char* label20, uint32_t circ_id,
                              const uint8_t ev_pub[32], const uint8_t er_pub[32],
                              uint32_t signed_caps, const uint8_t node_pub[32],
                              uint8_t* out /* TUN_HKDF_INFO_LEN */) {
    size_t o = 0;
    (void)circ_id;   // excluded (per-leg, see transcript); salt = create_nonce binds the session.
    memcpy(out + o, label20, 20);   o += 20;
    memcpy(out + o, ev_pub, 32);    o += 32;
    memcpy(out + o, er_pub, 32);    o += 32;
    PutU32LE(out + o, signed_caps); o += 4;
    memcpy(out + o, node_pub, 32);  o += 32;
    return o;  // == TUN_HKDF_INFO_LEN
}
void PutU16LE(uint8_t* p, uint16_t v) {
    p[0] = static_cast<uint8_t>(v);
    p[1] = static_cast<uint8_t>(v >> 8);
}

// K6-6 authenticated context. v2 remains byte-for-byte compatible; v3 binds
// the origin circuit id, expected hop position and hash of the established
// prefix, all of which remain stable across relay-local outbound circuit ids.
static const char TUN_TRANSCRIPT_V3_LABEL[] = "kad6-tun-created-v3";
static_assert(sizeof(TUN_TRANSCRIPT_V3_LABEL) - 1 == 19, "K6 v3 transcript label drift");
static_assert(TUN_TRANSCRIPT_V3_LEN == 190, "K6 v3 transcript layout drift");
static_assert(TUN_HKDF_INFO_V3_LEN == 159, "K6 v3 HKDF layout drift");

void BuildCreatedTranscriptV3(uint32_t originCircId, uint8_t hopIndex,
                                     const uint8_t prefixHash[32],
                                     const uint8_t evPub[32], const uint8_t erPub[32],
                                     uint32_t signedCaps, uint16_t shapeBucketKiB,
                                     const uint8_t createNonce[16],
                                     const uint8_t targetHash[16], const uint8_t nodePub[32],
                                     uint8_t out[TUN_TRANSCRIPT_V3_LEN])
{
    size_t o = 0;
    memcpy(out + o, TUN_TRANSCRIPT_V3_LABEL, 19); o += 19;
    PutU32LE(out + o, originCircId); o += 4;
    out[o++] = hopIndex;
    memcpy(out + o, prefixHash, 32); o += 32;
    memcpy(out + o, evPub, 32); o += 32;
    memcpy(out + o, erPub, 32); o += 32;
    PutU32LE(out + o, signedCaps); o += 4;
    PutU16LE(out + o, shapeBucketKiB); o += 2;
    memcpy(out + o, createNonce, 16); o += 16;
    memcpy(out + o, targetHash, 16); o += 16;
    memcpy(out + o, nodePub, 32); o += 32;
    (void)o;
}

size_t BuildHkdfInfoV3(const char* label20, uint32_t originCircId,
                              uint8_t hopIndex, const uint8_t prefixHash[32],
                              const uint8_t evPub[32], const uint8_t erPub[32],
                              uint32_t signedCaps, uint16_t shapeBucketKiB,
                              const uint8_t nodePub[32],
                              uint8_t out[TUN_HKDF_INFO_V3_LEN])
{
    size_t o = 0;
    memcpy(out + o, label20, 20); o += 20;
    PutU32LE(out + o, originCircId); o += 4;
    out[o++] = hopIndex;
    memcpy(out + o, prefixHash, 32); o += 32;
    memcpy(out + o, evPub, 32); o += 32;
    memcpy(out + o, erPub, 32); o += 32;
    PutU32LE(out + o, signedCaps); o += 4;
    PutU16LE(out + o, shapeBucketKiB); o += 2;
    memcpy(out + o, nodePub, 32); o += 32;
    return o;
}

bool BuildCircuitPrefixHash(const CLiveCircuit& circ, uint8_t out[32])
{
    static const char label[] = "kad6-circuit-prefix-v1";
    std::vector<uint8_t> input;
    input.reserve(sizeof(label) - 1 + 5 + circ.HopCount() * 32);
    input.insert(input.end(), label, label + sizeof(label) - 1);
    uint8_t context[5];
    PutU32LE(context, circ.Id());
    context[4] = static_cast<uint8_t>(circ.HopCount());
    input.insert(input.end(), context, context + sizeof context);
    for (size_t i = 0; i < circ.HopCount(); ++i)
        input.insert(input.end(), circ.Hop(i).pub_long, circ.Hop(i).pub_long + 32);
    const kad6::Kad6CryptoHooks crypto = MakeKad6HostCryptoHooks();
    return crypto.sha256 && crypto.sha256(input.data(), input.size(), out);
}

static_assert(TUN_CREATE_V3_LEN <= CELL_PAYLOAD_MAX, "CREATE v3 must fit one cell");
static_assert(TUN_EXTEND_V3_LEN + 3 * 16 <= CELL_PAYLOAD_MAX,
              "EXTEND v3 plus maximum onion must fit one cell");

} // namespace LiveCircuitHandshakeWire

using namespace LiveCircuitHandshakeWire;

// v8.x Phase 2 — tunnel auth policy (see LiveTunnel.h). Mixed (default) accepts
// v1 + v2; Strict aborts any v1/unsigned handshake. Runtime flag for now.
static bool s_tunnelAuthStrict = false;
bool TunnelAuthStrict()          { return s_tunnelAuthStrict; }
void SetTunnelAuthStrict(bool s) { s_tunnelAuthStrict = s; }

// v8.x Phase 2 — compile-time tripwires: any future edit that desyncs a wire size
// from the helpers/buffers fails the BUILD, not a 3-PC lab run.
static_assert(TUN_TRANSCRIPT_LEN == 150, "CREATED-v2 transcript size drift (must equal the field sum)");
static_assert(TUN_HKDF_INFO_LEN  == 120, "HKDF-v2 info size drift (must equal the field sum)");
static_assert(69u  <= CELL_PAYLOAD_MAX,  "CREATE v2 (69B) must fit one cell payload");
static_assert(133u <= CELL_PAYLOAD_MAX,  "CREATED v2 (133B) must fit one cell payload");
static_assert(149u <= CELL_PAYLOAD_MAX,  "wrapped EXTENDED v2 (133+16 tag) must fit one cell payload");

namespace {
inline void eseWrU16LE(uint8_t* p, uint16_t v)
{
    p[0] = static_cast<uint8_t>(v);
    p[1] = static_cast<uint8_t>(v >> 8);
}

inline uint16_t eseRdU16LE(const uint8_t* p)
{
    return static_cast<uint16_t>(p[0])
        | static_cast<uint16_t>(static_cast<uint16_t>(p[1]) << 8);
}

inline uint32_t eseRdU32LE(const uint8_t* p)
{
    return static_cast<uint32_t>(p[0])
        | (static_cast<uint32_t>(p[1]) << 8)
        | (static_cast<uint32_t>(p[2]) << 16)
        | (static_cast<uint32_t>(p[3]) << 24);
}

constexpr uint16_t K6_SHAPE_RUNTIME_MAX_BUCKET_KIB = 1024;
constexpr size_t K6_SHAPE_MAX_RESERVED_LINKS = 8;
constexpr uint32_t HANDSHAKE_CAP_AUTH = 0x00040000;
constexpr uint32_t HANDSHAKE_CAP_STRICT3 = 0x02000000;
constexpr uint32_t HANDSHAKE_CAP_SHAPED = 0x04000000;

bool K6ShapeValidBucket(uint32_t bucketKiB)
{
    return bucketKiB >= 64
        && bucketKiB <= K6_SHAPE_RUNTIME_MAX_BUCKET_KIB
        && (bucketKiB & (bucketKiB - 1)) == 0;
}

} // namespace

bool LiveCircuitHandshake::HandleCreatedOriginator(std::shared_ptr<CLiveCircuit>& circ,
                                           const uint8_t* payload, uint16_t payloadLen)
{
    if (!circ || circ->m_role != CircuitRole::Originator
        || circ->State() != CircuitState::Pending
        || m_host.HandshakeCircuitRegistry().FindById(circ->Id()) != circ) {
        return false;
    }
    if (!circ->m_have_ephemeral) return false;
    if (payloadLen < 32) return false;

    // v8.x Phase 2 — authenticated CREATED v2 (133B: ver|er_pub|node_pub|caps|sig).
    const bool v3 = (payloadLen >= 133 && payload[0] == 0x03);
    const bool v2 = (payloadLen >= 133 && payload[0] == 0x02);
    const bool authenticated = v3 || v2;
    if ((TunnelAuthStrict() || circ->m_private2 || circ->m_strict3) && !authenticated) {
        // Distinct, greppable abort reasons (the rogue-relay test reads these to prove
        // the rejection was CRYPTO, not a network timeout — cf. the Tick reap logs).
        AddDebugLogLine(false, _T("LiveTunnel: v2 AUTH-ABORT hop1 circ=0x%08x reason=STRICT_V1 (unsigned CREATED rejected in strict mode)"), circ->Id());
        circ->m_abort_reason = CircuitAbortReason::StrictV1;
        m_host.DestroyHandshakeCircuit(circ); // strict: refuse the unsigned v1 downgrade
        return false;
    }
    if (circ->m_strict3 && !v3) {
        AddDebugLogLine(false, _T("Kad6 K6-6: STRICT circ=0x%08x rejected CREATE downgrade below v3"), circ->Id());
        m_host.DestroyHandshakeCircuit(circ);
        return false;
    }
    if (v3 && !K6ShapeValidBucket(circ->m_shape_bucket_kib)) {
        m_host.DestroyHandshakeCircuit(circ);
        return false;
    }

    const uint8_t* relayPub  = authenticated ? (payload + 1) : payload;   // er_pub
    const uint8_t* node_pub  = NULL;
    uint32_t       signedCaps = 0;
    if (authenticated) {
        node_pub   = payload + 33;
        signedCaps = (uint32_t)payload[65] | ((uint32_t)payload[66] << 8)
                   | ((uint32_t)payload[67] << 16) | ((uint32_t)payload[68] << 24);
        const uint8_t* sig = payload + 69;
        // (1) Identity pin: node_pub MUST equal the key V learned from hop1's own
        // HELLO (set in BuildPool, independent of any relay). Mismatch = substitution.
        if (!circ->m_expectedNodePubSet || memcmp(node_pub, circ->m_expectedNodePub, 32) != 0) {
            AddDebugLogLine(false, _T("LiveTunnel: v2 AUTH-ABORT hop1 circ=0x%08x reason=PIN_MISMATCH (node_pub != pinned hop1 identity)"), circ->Id());
            circ->m_abort_reason = CircuitAbortReason::PinMismatch;
            m_host.DestroyHandshakeCircuit(circ);
            return false;
        }
        // (2) Strict caps floor.
        const uint32_t capsFloor = HANDSHAKE_CAP_AUTH
            | (circ->m_strict3
                ? (HANDSHAKE_CAP_STRICT3 | HANDSHAKE_CAP_SHAPED) : 0);
        if ((TunnelAuthStrict() || circ->m_private2 || circ->m_strict3)
            && (signedCaps & capsFloor) != capsFloor) {
            AddDebugLogLine(false, _T("LiveTunnel: v2 AUTH-ABORT hop1 circ=0x%08x reason=CAPS_FLOOR (signed_caps lacks TUNNEL_AUTH)"), circ->Id());
            circ->m_abort_reason = CircuitAbortReason::CapsFloor;
            m_host.DestroyHandshakeCircuit(circ);
            return false;
        }
        // (3) VERIFY-BEFORE-DERIVE: a bad signature aborts before any X25519/HKDF,
        // so a forged CREATED costs zero asymmetric work and contaminates no state.
        uint8_t transcript[TUN_TRANSCRIPT_V3_LEN];
        size_t transcriptLen = TUN_TRANSCRIPT_LEN;
        if (v3) {
            BuildCreatedTranscriptV3(circ->Id(), circ->m_createHopIndex,
                circ->m_createPrefixHash, circ->m_ephemeral_pub, relayPub,
                signedCaps, circ->m_shape_bucket_kib,
                circ->m_create_nonce, circ->m_expectedHash,
                node_pub, transcript);
            transcriptLen = TUN_TRANSCRIPT_V3_LEN;
        } else {
            BuildCreatedTranscript(circ->Id(), circ->m_ephemeral_pub, relayPub,
                signedCaps, circ->m_create_nonce, circ->m_expectedHash,
                node_pub, transcript);
        }
        if (!VerifySignature(node_pub, transcript, transcriptLen, sig)) {
            AddDebugLogLine(false, _T("LiveTunnel: v2 AUTH-ABORT hop1 circ=0x%08x reason=SIG_FAIL (Ed25519 verify-before-derive tripped — forged/rogue CREATED)"), circ->Id());
            circ->m_abort_reason = CircuitAbortReason::SigFail;
            m_host.DestroyHandshakeCircuit(circ);
            return false;
        }
    }

    uint8_t shared[32];
    if (!X25519SharedSecret(relayPub, circ->m_ephemeral_priv, shared))
        return false;

    // HKDF: v1 = bare directional labels; v2 = transcript-bound (salt =
    // create_nonce). Originator's k_send = V→R, k_recv = R→V.
    uint8_t okm[64];
    bool kdfOk;
    if (v3) {
        uint8_t infoSend[TUN_HKDF_INFO_V3_LEN], infoRecv[TUN_HKDF_INFO_V3_LEN];
        size_t infoLen = BuildHkdfInfoV3("ese-tunnel-V-to-R-v3", circ->Id(),
            circ->m_createHopIndex, circ->m_createPrefixHash,
            circ->m_ephemeral_pub, relayPub, signedCaps,
            circ->m_shape_bucket_kib, node_pub, infoSend);
        BuildHkdfInfoV3("ese-tunnel-R-to-V-v3", circ->Id(),
            circ->m_createHopIndex, circ->m_createPrefixHash,
            circ->m_ephemeral_pub, relayPub, signedCaps,
            circ->m_shape_bucket_kib, node_pub, infoRecv);
        kdfOk = Hkdf(shared, sizeof shared, circ->m_create_nonce, 16,
                     infoSend, infoLen, okm, 32)
             && Hkdf(shared, sizeof shared, circ->m_create_nonce, 16,
                     infoRecv, infoLen, okm + 32, 32);
    } else if (v2) {
        uint8_t infoSend[TUN_HKDF_INFO_LEN], infoRecv[TUN_HKDF_INFO_LEN];
        size_t infoLen = BuildHkdfInfoV2("ese-tunnel-V-to-R-v2", circ->Id(), circ->m_ephemeral_pub, relayPub, signedCaps, node_pub, infoSend);
        BuildHkdfInfoV2("ese-tunnel-R-to-V-v2", circ->Id(), circ->m_ephemeral_pub, relayPub, signedCaps, node_pub, infoRecv);
        kdfOk = Hkdf(shared, sizeof shared, circ->m_create_nonce, 16, infoSend, infoLen, okm, 32)
             && Hkdf(shared, sizeof shared, circ->m_create_nonce, 16, infoRecv, infoLen, okm + 32, 32);
    } else {
        const uint8_t info_send[] = "ese-tunnel-V-to-R-v1";
        const uint8_t info_recv[] = "ese-tunnel-R-to-V-v1";
        kdfOk = Hkdf(shared, sizeof shared, NULL, 0, info_send, sizeof info_send - 1, okm, 32)
             && Hkdf(shared, sizeof shared, NULL, 0, info_recv, sizeof info_recv - 1, okm + 32, 32);
    }
    if (!kdfOk) {
        SecureWipe(shared, sizeof shared);
        return false;
    }

    CircuitHop hop = {};
    hop.hop_id = circ->Id();   // hop_id placeholder; ntor uses dedicated tag
    memcpy(hop.k_send, okm,      32);
    memcpy(hop.k_recv, okm + 32, 32);
    if (authenticated) memcpy(hop.pub_long, node_pub, 32);   // verified hop identity
    hop.nonce_send = 0;
    hop.nonce_recv = 0;
    if (!circ->AddHop(hop)) {
        SecureWipe(shared, sizeof shared);
        SecureWipe(okm, sizeof okm);
        return false;
    }
    if (authenticated) circ->m_auth_ok = true;
    circ->m_shaped_ok = circ->m_shaped_ok && authenticated
        && (signedCaps & HANDSHAKE_CAP_SHAPED) != 0;
    // The only capability bits trusted for service selection are those inside
    // the verified CREATED transcript.  If a second hop is staged, hop1 is not
    // the exit and HandleExtended_Originator will install hop2's snapshot.
    circ->m_exit_signed_caps = (authenticated && circ->m_pendingHopClients.empty()
                                && !circ->m_nextHopClient) ? signedCaps : 0;

    // Wipe ephemeral private key + shared.
    SecureWipe(circ->m_ephemeral_priv, sizeof circ->m_ephemeral_priv);
    circ->m_have_ephemeral = false;
    SecureWipe(shared, sizeof shared);
    SecureWipe(okm, sizeof okm);

    return ContinueOriginatorBuild(circ);
}

bool LiveCircuitHandshake::ContinueOriginatorBuild(std::shared_ptr<CLiveCircuit>& circ)
{
    // Caller holds m_lock. Extension is deliberately serial: one ephemeral
    // and one expected identity are live at a time, which bounds state and
    // makes replay/context checks unambiguous.
    if (!circ || circ->m_role != CircuitRole::Originator)
        return false;
    if (!circ->m_pendingHopClients.empty()) {
        CUpDownClient* target = circ->m_pendingHopClients.front();
        circ->m_pendingHopClients.erase(circ->m_pendingHopClients.begin());
        if (circ->m_pendingHopClients.empty()) {
            circ->m_haveExitKadKey = false;
            m_host.ResolveHandshakeExitKey(target, *circ);
        }
        if (BuildExtend(circ, target))
            return true;

        if (circ->m_private2 || circ->m_strict3) {
            AddDebugLogLine(false, _T("Kad6: %s circ=0x%08x build aborted at hop %u -- prefix is never reusable"),
                            circ->m_strict3 ? _T("STRICT") : _T("PRIVATE"),
                            circ->Id(), static_cast<unsigned>(circ->HopCount() + 1));
            m_host.DestroyHandshakeCircuit(circ);
            return false;
        }
        // Explicit diagnostic/legacy construction may retain its authenticated
        // prefix. Production Private and Strict never reach this arm.
        if (!m_host.HandshakeCircuitRegistry().Transition(circ, CircuitState::Active))
            return false;
        circ->m_haveExitKadKey = false;
        m_host.ResolveHandshakeExitKey(circ->m_firstHopClient, *circ);
        m_host.RegisterActiveHandshakeCircuit(circ);
        return true;
    }

    if ((circ->m_private2 && (circ->HopCount() != 2 || !circ->m_auth_ok)) ||
        (circ->m_strict3
         && (circ->HopCount() != 3 || !circ->m_auth_ok || !circ->m_path_diverse
             || !circ->m_shaped_ok || !K6ShapeValidBucket(circ->m_shape_bucket_kib)))) {
        AddDebugLogLine(false, _T("Kad6: %s circ=0x%08x activation refused (hops=%u auth=%u diverse=%u)"),
                        circ->m_strict3 ? _T("STRICT") : _T("PRIVATE"),
                        circ->Id(), static_cast<unsigned>(circ->HopCount()),
                        circ->m_auth_ok ? 1 : 0, circ->m_path_diverse ? 1 : 0);
        m_host.DestroyHandshakeCircuit(circ);
        return false;
    }
    if (!m_host.HandshakeCircuitRegistry().Transition(circ, CircuitState::Active))
        return false;
    if (circ->m_auth_ok)
        AddDebugLogLine(false, _T("LiveTunnel: authenticated circuit ACTIVE circ=0x%08x hops=%u%s"),
                        circ->Id(), static_cast<unsigned>(circ->HopCount()),
                        circ->m_strict3 ? _T(" STRICT3") : _T(""));
    m_host.RegisterActiveHandshakeCircuit(circ);
    return true;
}

bool LiveCircuitHandshake::HandleCreateRelay(uint32_t circId,
                                     const uint8_t* payload, uint16_t payloadLen,
                                     CUpDownClient* fromPeer)
{
    if (!fromPeer || payloadLen < 32) return false;
    // Reject identity ambiguity before doing handshake crypto or emitting a
    // CREATED response. Incoming IDs share the same dispatch namespace as
    // existing incoming and relay-outgoing legs.
    if (circId == 0 || m_host.HandshakeCircuitRegistry().ContainsAnyLegId(circId))
        return false;
    const uint8_t* viewerPub = payload;

    // v0.71 P0.B — verify target_user_hash binding (anti-MITM lite).
    // Payload format: ev_pub (32B) + target_user_hash (16B) = 48B from
    // new fork. Old fork sends just 32B (no target_hash). We accept
    // both for backward compat, but if the 16B suffix is present, it
    // MUST match our own user_hash — else this CREATE was targeted at
    // someone else (redirection attack) and we drop it.
    if (payloadLen >= 48) {
        const uint8_t* targetHash = payload + 32;
        const uint8_t* ourHash = m_host.LocalHandshakeUserHash();
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

    // v8.x Phase 2 — authenticated CREATE v2 detection (magic "EAU2" + ver 0x02 +
    // 16B create_nonce). BuildPool emits CREATE v2 whenever hop1 advertises
    // ESE_CAP_TUNNEL_AUTH (its hop1Auth branch), so this signed path IS reached
    // once that cap is advertised. Gated dormant today only because EmuleDlg does
    // not yet advertise the cap — not because the emit side is missing.
    const bool v3req = (payloadLen >= TUN_CREATE_V3_LEN
                        && memcmp(payload + 48, "EAU3", 4) == 0
                        && payload[52] == 0x03);
    const bool v2req = (payloadLen >= 69
                        && memcmp(payload + 48, "EAU2", 4) == 0
                        && payload[52] == 0x02);
    const uint8_t* nodePub = (v3req || v2req)
        ? m_host.LocalHandshakeNodePublicKey() : NULL;
    const bool     v3          = v3req && (nodePub != NULL);
    const bool     v2          = !v3 && v2req && (nodePub != NULL);
    const uint8_t* createNonce = (v3 || v2) ? (payload + 53) : NULL;
    const uint32_t originCircId = v3 ? eseRdU32LE(payload + 69) : circId;
    const uint8_t  hopIndex = v3 ? payload[73] : 0;
    const uint8_t* prefixHash = v3 ? payload + 74 : NULL;
    const uint16_t shapeBucketKiB = v3 ? eseRdU16LE(payload + 138) : 0;
    if (v3) {
        size_t reservedLinks = 0;
        for (const auto& existing : m_host.HandshakeCircuitRegistry().GetSnapshot())
            if (existing->m_role == CircuitRole::Relay
                && existing->State() != CircuitState::Destroyed
                && existing->m_shape_bucket_kib != 0)
                ++reservedLinks;
        if (originCircId == 0 || hopIndex >= 3
            || memcmp(payload + 106, nodePub, 32) != 0
            || (hopIndex == 0 && originCircId != circId)
            || !K6ShapeValidBucket(shapeBucketKiB)
            || (m_host.HandshakeRuntimeCapabilities()
                & HANDSHAKE_CAP_SHAPED) == 0
            || reservedLinks >= K6_SHAPE_MAX_RESERVED_LINKS) {
            AddDebugLogLine(false, _T("LiveTunnel: CREATE v3 context/target mismatch -- dropping"));
            return false;
        }
    }
    const uint32_t signedCaps = m_host.HandshakeRuntimeCapabilities();

    uint8_t erPub[32], erPriv[32];
    if (!X25519GenerateKeypair(erPub, erPriv)) return false;

    uint8_t shared[32];
    if (!X25519SharedSecret(viewerPub, erPriv, shared)) {
        SecureWipe(erPriv, sizeof erPriv);
        return false;
    }
    SecureWipe(erPriv, sizeof erPriv);

    // HKDF: v1 = bare directional labels; v2 = transcript-bound (salt =
    // create_nonce; info carries circ_id + both ephemerals + signed_caps +
    // node_pub) so any tampered field makes V and R derive different keys (§5).
    // Labels are inverted from *our* perspective: what V calls V→R is our RECV.
    uint8_t okm[64];
    bool kdfOk;
    if (v3) {
        uint8_t infoVR[TUN_HKDF_INFO_V3_LEN], infoRV[TUN_HKDF_INFO_V3_LEN];
        size_t infoLen = BuildHkdfInfoV3("ese-tunnel-V-to-R-v3", originCircId,
            hopIndex, prefixHash, viewerPub, erPub, signedCaps,
            shapeBucketKiB, nodePub, infoVR);
        BuildHkdfInfoV3("ese-tunnel-R-to-V-v3", originCircId, hopIndex,
            prefixHash, viewerPub, erPub, signedCaps,
            shapeBucketKiB, nodePub, infoRV);
        kdfOk = Hkdf(shared, sizeof shared, createNonce, 16, infoVR, infoLen, okm, 32)
             && Hkdf(shared, sizeof shared, createNonce, 16, infoRV, infoLen, okm + 32, 32);
    } else if (v2) {
        uint8_t infoVR[TUN_HKDF_INFO_LEN], infoRV[TUN_HKDF_INFO_LEN];
        size_t infoLen = BuildHkdfInfoV2("ese-tunnel-V-to-R-v2", circId, viewerPub, erPub, signedCaps, nodePub, infoVR);
        BuildHkdfInfoV2("ese-tunnel-R-to-V-v2", circId, viewerPub, erPub, signedCaps, nodePub, infoRV);
        kdfOk = Hkdf(shared, sizeof shared, createNonce, 16, infoVR, infoLen, okm, 32)
             && Hkdf(shared, sizeof shared, createNonce, 16, infoRV, infoLen, okm + 32, 32);
    } else {
        const uint8_t info_v_to_r[] = "ese-tunnel-V-to-R-v1";
        const uint8_t info_r_to_v[] = "ese-tunnel-R-to-V-v1";
        kdfOk = Hkdf(shared, sizeof shared, NULL, 0, info_v_to_r, sizeof info_v_to_r - 1, okm, 32)
             && Hkdf(shared, sizeof shared, NULL, 0, info_r_to_v, sizeof info_r_to_v - 1, okm + 32, 32);
    }
    if (!kdfOk) {
        SecureWipe(shared, sizeof shared);
        return false;
    }

    // Register the relay-side circuit. Originator-side AddHop fills
    // m_hops[0] with the keys; relay-side we also populate m_hops[0]
    // (single hop = ourselves), just with the inverted send/recv.
    auto c = std::make_shared<CLiveCircuit>(circId);
    c->m_role = CircuitRole::Relay;
    c->m_prevHopClient = fromPeer;
    c->m_originCircContext = originCircId;
    c->m_remoteHopIndex = hopIndex;
    c->m_shape_bucket_kib = shapeBucketKiB;
    c->m_strict3 = v3;
    c->m_shaped_ok = v3 && (signedCaps & HANDSHAKE_CAP_SHAPED) != 0;
    CircuitHop hop = {};
    hop.hop_id = circId;
    memcpy(hop.k_send, okm + 32, 32);   // relay→V uses R-to-V key for send
    memcpy(hop.k_recv, okm,      32);   // V→relay uses V-to-R key for recv
    hop.nonce_send = 0;
    hop.nonce_recv = 0;
    c->AddHop(hop);

    SecureWipe(shared, sizeof shared);
    SecureWipe(okm, sizeof okm);

    // Reply with CELL_CREATED. v1 = bare er_pub (32B). v2 = signed bundle (133B):
    // ver|er_pub|node_pub|signed_caps|sig, sig = Ed25519(node_priv, transcript).
    // The originator pins node_pub and verifies BEFORE deriving keys (§3.2/§7.3).
    uint8_t cell[CELL_TOTAL_BYTES];
    if (v3 || v2) {
        uint8_t transcript[TUN_TRANSCRIPT_V3_LEN];
        size_t transcriptLen = TUN_TRANSCRIPT_LEN;
        if (v3) {
            BuildCreatedTranscriptV3(originCircId, hopIndex, prefixHash,
                viewerPub, erPub, signedCaps, shapeBucketKiB,
                createNonce, payload + 32,
                nodePub, transcript);
            transcriptLen = TUN_TRANSCRIPT_V3_LEN;
        } else {
            BuildCreatedTranscript(circId, viewerPub, erPub, signedCaps, createNonce,
                payload + 32, nodePub, transcript);
        }
        uint8_t sig[64];
        if (!m_host.SignHandshakeTranscript(
                transcript, transcriptLen, sig))
            return false;
        uint8_t created[133];
        created[0] = v3 ? 0x03 : 0x02;           // ver
        memcpy(created + 1,  erPub,   32);        // er_pub
        memcpy(created + 33, nodePub, 32);        // node_pub
        PutU32LE(created + 65, signedCaps);       // signed_caps
        memcpy(created + 69, sig, 64);            // sig
        if (!CellPack(circId, CELL_CREATED, created, sizeof created, cell))
            return false;
    } else {
        if (!CellPack(circId, CELL_CREATED, erPub, sizeof erPub, cell))
            return false;
    }
    if (!m_host.SendHandshakeCell(fromPeer, cell))
        return false;

    // This relay leg completed the signed CREATED-v2/v3 protocol. Publish
    // it only after the response was queued so snapshots cannot show an
    // ACTIVE ghost or strict3=true/auth_ok=false for an authenticated leg.
    c->m_auth_ok = v3 || v2;
    return m_host.HandshakeCircuitRegistry().Add(c, CircuitState::Active);
}

bool LiveCircuitHandshake::BuildExtend(std::shared_ptr<CLiveCircuit>& circ,
                              CUpDownClient* target)
{
    // Caller holds m_lock.
    if (!circ || !target || circ->m_role != CircuitRole::Originator
        || circ->HopCount() < 1 || circ->HopCount() >= 3
        || circ->m_have_ephemeral)
        return false;
    if (circ->State() != CircuitState::Pending
        && circ->State() != CircuitState::HalfBuilt) {
        return false;
    }
    // Commit the extending state before preparing or emitting CELL_EXTEND.
    // ContinueOriginatorBuild either promotes a failed legacy prefix back to
    // Active or destroys private/strict prefixes, so no partial state escapes.
    if (!m_host.HandshakeCircuitRegistry().Transition(circ, CircuitState::HalfBuilt))
        return false;
    const uint8_t hopIndex = static_cast<uint8_t>(circ->HopCount());
    const uchar* targetHash = target->GetUserHash();
    if (!targetHash || !target->HasValidHash()) return false;
    for (size_t i = 0; i < circ->HopCount(); ++i)
        if (target->HasEseNodePub()
            && kad6::Kad6CtEqual(circ->Hop(i).pub_long,
                                 target->GetEseNodePub(), 32))
            return false;

    // v8.1 A7.4 -- AND hop2's multi-cell capability into the circuit flag.
    // If hop2 is a v8.0.0 peer, the whole circuit drops to single-cell.
    if (!target->SupportsEseTunnelDataplane())
        circ->m_multicell_ok = false;
    // v8.1.2 E1.5 -- AND hop2's bulk capability. Any non-bulk hop -> no bulk data plane
    // on this circuit (the per-symbol multi-cell fallback E1.6 is used instead).
    if (!target->SupportsEseTunnelBulk())
        circ->m_bulk_ok = false;
    if (!target->SupportsEseTunnelShaped())
        circ->m_shaped_ok = false;

    // Generate a fresh ephemeral for V↔hop2. The slot was wiped after
    // hop1's CREATED so it's safe to reuse.
    uint8_t evPub[32];
    if (!X25519GenerateKeypair(evPub, circ->m_ephemeral_priv))
        return false;
    circ->m_have_ephemeral = true;

    // v8.x Phase 2 — EXTEND payload: v1 = 54B (6B endpoint + ev_pub2 + hop2_hash);
    // v2 = 71B (+ ver 1 + create_nonce2 16). The v2 suffix rides INSIDE the V↔hop1
    // layer; hop1 reads it to build hop2's CREATE v2 but cannot usefully tamper —
    // hop2 signs it and V verifies against its OWN stored ev_pub2/nonce2 + hop2 pin.
    const bool targetAuth = target->SupportsEseTunnelAuth()
        && target->HasEseNodePub()
        && m_host.LocalHandshakeNodePublicKey() != NULL;
    const bool targetV3 = targetAuth && target->SupportsEseTunnelStrict3();
    if ((TunnelAuthStrict() || circ->m_private2 || circ->m_strict3) && !targetAuth) {
        SecureWipe(circ->m_ephemeral_priv, sizeof circ->m_ephemeral_priv);
        circ->m_have_ephemeral = false;
        return false;
    }
    if (circ->m_strict3 && (!targetV3 || !target->SupportsEseTunnelShaped()
        || !K6ShapeValidBucket(circ->m_shape_bucket_kib))) {
        SecureWipe(circ->m_ephemeral_priv, sizeof circ->m_ephemeral_priv);
        circ->m_have_ephemeral = false;
        return false;
    }

    uint8_t extendPlain[TUN_EXTEND_V3_LEN]{};
    size_t extendPlainLen = 0;
    if (targetV3) {
        memcpy(extendPlain, "K6X3", 4);
        extendPlain[4] = hopIndex;
        if (target->HasIPv6Address()) {
            extendPlain[5] = 6;
            memcpy(extendPlain + 6, target->GetIPv6Address().Data(), 16);
        } else {
            extendPlain[5] = 4;
            PutU32LE(extendPlain + 6, target->GetIP());
        }
        eseWrU16LE(extendPlain + 22, target->GetUserPort());
        memcpy(extendPlain + 24, target->GetEseNodePub(), 32);
        memcpy(extendPlain + 56, targetHash, 16);
        memcpy(extendPlain + 72, evPub, 32);
        SecureRandomBytes(circ->m_extendNonce, 16);
        memcpy(extendPlain + 104, circ->m_extendNonce, 16);
        PutU32LE(extendPlain + 120, circ->Id());
        if (!BuildCircuitPrefixHash(*circ, circ->m_extendPrefixHash)) {
            SecureWipe(circ->m_ephemeral_priv, sizeof circ->m_ephemeral_priv);
            circ->m_have_ephemeral = false;
            return false;
        }
        memcpy(extendPlain + 124, circ->m_extendPrefixHash, 32);
        PutU16LE(extendPlain + 156, circ->m_shape_bucket_kib);
        extendPlainLen = TUN_EXTEND_V3_LEN;
        memcpy(circ->m_extendEphemeralPub, evPub, 32);
        memcpy(circ->m_extendExpectedNodePub, target->GetEseNodePub(), 32);
        memcpy(circ->m_extendExpectedHash, targetHash, 16);
        circ->m_extendExpectedNodePubSet = true;
        circ->m_extendHopIndex = hopIndex;
        if (hopIndex == 1) {
            memcpy(circ->m_ephemeral_pub2, evPub, 32);
            memcpy(circ->m_create_nonce2, circ->m_extendNonce, 16);
            memcpy(circ->m_expectedNodePub2, target->GetEseNodePub(), 32);
            memcpy(circ->m_expectedHash2, targetHash, 16);
            circ->m_expectedNodePub2Set = true;
        }
    } else {
        // Legacy one-to-two-hop EXTEND remains byte-for-byte unchanged.
        // Its endpoint field is uint32 IPv4; an IPv6-only target must use the
        // authenticated V3 address-bearing extension or be rejected.
        if (hopIndex != 1 || target->IsIPv6OnlyEndpoint()) {
            SecureWipe(circ->m_ephemeral_priv, sizeof circ->m_ephemeral_priv);
            circ->m_have_ephemeral = false;
            return false;
        }
        PutU32LE(extendPlain, target->GetIP());
        eseWrU16LE(extendPlain + 4, target->GetUserPort());
        memcpy(extendPlain + 6, evPub, 32);
        memcpy(extendPlain + 38, targetHash, 16);
        if (targetAuth) {
            extendPlain[54] = 0x02;
            SecureRandomBytes(circ->m_create_nonce2, 16);
            memcpy(extendPlain + 55, circ->m_create_nonce2, 16);
            extendPlainLen = 71;
            memcpy(circ->m_ephemeral_pub2, evPub, 32);
            memcpy(circ->m_expectedNodePub2, target->GetEseNodePub(), 32);
            circ->m_expectedNodePub2Set = true;
            memcpy(circ->m_expectedHash2, targetHash, 16);
        } else {
            extendPlainLen = 54;
        }
    }

    // OnionEncrypt with the single registered hop (hop1): 1-layer AEAD with K_v_to_hop1.
    uint8_t cellPayload[CELL_PAYLOAD_MAX];
    size_t cellLen = 0;
    if (!circ->OnionEncrypt(extendPlain, extendPlainLen, cellPayload, cellLen)) {
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
    if (!circ->m_firstHopClient || !m_host.SendHandshakeCell(circ->m_firstHopClient, cell)) {
        SecureWipe(circ->m_ephemeral_priv, sizeof circ->m_ephemeral_priv);
        circ->m_have_ephemeral = false;
        return false;
    }

    // HalfBuilt was committed before emission; the timeout starts only
    // after CELL_EXTEND has actually been queued.
    circ->m_extendStartedTick = GetTickCount();
    return true;
}

bool LiveCircuitHandshake::HandleExtendRelay(std::shared_ptr<CLiveCircuit>& circ,
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
    uint8_t extendPlain[CELL_PAYLOAD_MAX];   // v8.x: holds the 71B v2 plaintext; sized to
                                             // max also BOUNDS a hostile oversized EXTEND
                                             // (was [70] — OnionPeelOne has no capacity arg,
                                             //  so a 505B cell peeled 489B -> stack smash).
    size_t extendPlainLen = 0;
    if (!circ->OnionPeelOne(0, payload, payloadLen, extendPlain, extendPlainLen))
        return false;
    if (extendPlainLen < 38) return false;

    const bool v3ext = extendPlainLen == TUN_EXTEND_V3_LEN
        && memcmp(extendPlain, "K6X3", 4) == 0;
    if (v3ext) {
        const uint8_t targetHopIndex = extendPlain[4];
        const uint8_t family = extendPlain[5];
        const uint16_t targetPort = eseRdU16LE(extendPlain + 22);
        const uint8_t* targetNodePub = extendPlain + 24;
        const uint8_t* targetHash = extendPlain + 56;
        const uint8_t* targetEvPub = extendPlain + 72;
        const uint8_t* targetNonce = extendPlain + 104;
        const uint32_t originCircId = eseRdU32LE(extendPlain + 120);
        const uint8_t* prefixHash = extendPlain + 124;
        const uint16_t shapeBucketKiB = eseRdU16LE(extendPlain + 156);
        if (targetHopIndex == 0 || targetHopIndex >= 3
            || targetHopIndex != static_cast<uint8_t>(circ->m_remoteHopIndex + 1)
            || originCircId == 0 || originCircId != circ->m_originCircContext
            || (family != 4 && family != 6) || targetPort == 0
            || shapeBucketKiB != circ->m_shape_bucket_kib
            || !K6ShapeValidBucket(shapeBucketKiB)
            || circ->m_nextHopClient || circ->m_nextCircId != 0) {
            SecureWipe(extendPlain, sizeof extendPlain);
            return false;
        }
        const uint8_t* ourHash = m_host.LocalHandshakeUserHash();
        const uint8_t* ourNodePub =
            m_host.LocalHandshakeNodePublicKey();
        if ((ourHash && kad6::Kad6CtEqual(ourHash, targetHash, 16))
            || (ourNodePub && kad6::Kad6CtEqual(ourNodePub, targetNodePub, 32))) {
            SecureWipe(extendPlain, sizeof extendPlain); // no loopback in v3
            return false;
        }

        CUpDownClient* target =
            m_host.FindConnectedHandshakePeerByHash(targetHash);
        if (!target || target->GetUserPort() != targetPort
            || !target->HasEseNodePub()
            || !target->SupportsEseTunnelAuth()
            || !target->SupportsEseTunnelStrict3()
            || !target->SupportsEseTunnelShaped()
            || !kad6::Kad6CtEqual(target->GetEseNodePub(), targetNodePub, 32)) {
            SecureWipe(extendPlain, sizeof extendPlain);
            return false;
        }
        if (family == 6) {
            if (!target->HasIPv6Address()
                || memcmp(target->GetIPv6Address().Data(), extendPlain + 6, 16) != 0) {
                SecureWipe(extendPlain, sizeof extendPlain);
                return false;
            }
        } else if (target->IsIPv6OnlyEndpoint()
                   || target->GetIP() != eseRdU32LE(extendPlain + 6)) {
            SecureWipe(extendPlain, sizeof extendPlain);
            return false;
        }

        uint32_t outId = 0;
        for (int attempt = 0; attempt < 4; ++attempt) {
            outId = m_host.NewHandshakeCircuitId();
            if (!m_host.HandshakeCircuitRegistry().ContainsAnyLegId(outId)) break;
            outId = 0;
        }
        if (outId == 0) {
            SecureWipe(extendPlain, sizeof extendPlain);
            return false;
        }

        uint8_t create[TUN_CREATE_V3_LEN]{};
        memcpy(create, targetEvPub, 32);
        memcpy(create + 32, targetHash, 16);
        memcpy(create + 48, "EAU3", 4);
        create[52] = 0x03;
        memcpy(create + 53, targetNonce, 16);
        PutU32LE(create + 69, originCircId);
        create[73] = targetHopIndex;
        memcpy(create + 74, prefixHash, 32);
        memcpy(create + 106, targetNodePub, 32);
        PutU16LE(create + 138, shapeBucketKiB);
        uint8_t cell[CELL_TOTAL_BYTES];
        if (!CellPack(outId, CELL_CREATE, create, sizeof create, cell)
            || !m_host.SendHandshakeCell(target, cell)) {
            SecureWipe(extendPlain, sizeof extendPlain);
            return false;
        }
        circ->m_nextHopClient = target;
        circ->m_nextCircId = outId;
        SecureWipe(extendPlain, sizeof extendPlain);
        return true;
    }

    // Parse hop2 endpoint + ev_pub2 + (optional) target_hash.
    uint32 hop2_ip = (uint32)extendPlain[0]
                   | ((uint32)extendPlain[1] << 8)
                   | ((uint32)extendPlain[2] << 16)
                   | ((uint32)extendPlain[3] << 24);
    uint16 hop2_port = (uint16)extendPlain[4] | ((uint16)extendPlain[5] << 8);
    const uint8_t* evPub2 = extendPlain + 6;
    const bool haveHop2Hash = (extendPlainLen >= 54);
    const uint8_t* hop2HashIn = haveHop2Hash ? (extendPlain + 38) : NULL;
    // v8.x Phase 2 — v2 EXTEND carries ver(0x02)+create_nonce2 at offset 54; hop1
    // propagates them into hop2's CREATE v2. (The loopback test path below ignores
    // them and stays v1 — 2-PC dev only; validate authenticated 2-hop with 3 nodes.)
    const bool v2ext = (extendPlainLen >= 71 && extendPlain[54] == 0x02);
    const uint8_t* nonce2In = v2ext ? (extendPlain + 55) : NULL;

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
        const uint8_t* ourHash = m_host.LocalHandshakeUserHash();
        if (!hashAllZero && ourHash && memcmp(hop2HashIn, ourHash, 16) == 0)
            isLoopback = true;
    }
    // Legacy fallback: public-IP match (pre-hash peers / same-WAN setups).
    const uint32_t localPublicIp = m_host.LocalHandshakePublicIp();
    if (!isLoopback && localPublicIp != 0 && hop2_ip == localPublicIp)
        isLoopback = true;
    if (isLoopback) {
        // v8.1.1 F-2 — loopback collapses BOTH hops onto one node: ZERO anonymity
        // (exit == hop1, directly connected to V). This is TEST-ONLY (2-PC dev via
        // BuildTestCircuit2Hop). Production builds (BuildSuccessor2Hop) require two
        // DISTINCT nodes and never reach here. Log it so it is never mistaken for
        // a real 2-hop circuit.
        AddDebugLogLine(false, _T("LiveTunnel: 2-hop EXTEND is LOOPBACK (hop2==self) — TEST-ONLY, ZERO anonymity (the exit sees V's IP)"));
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
        if (!circ->m_prevHopClient || !m_host.SendHandshakeCell(circ->m_prevHopClient, cell)) {
            SecureWipe(extendPlain, sizeof extendPlain);
            return false;
        }
        SecureWipe(extendPlain, sizeof extendPlain);
        return true;
    }

    // Normal (non-loopback) path: resolve hop2 in our ClientList.
    // Two-hop only works if we (hop1) already have an open socket to hop2.
    CUpDownClient* hop2 =
        m_host.FindConnectedHandshakePeer(hop2_ip, hop2_port);
    if (!hop2) {
        SecureWipe(extendPlain, sizeof extendPlain);
        return false;
    }

    // Pick a fresh outbound circ_id for the V↔hop2 leg as seen from us.
    uint32_t outId = 0;
    for (int t = 0; t < 4; ++t) {
        outId = m_host.NewHandshakeCircuitId();
        if (!m_host.HandshakeCircuitRegistry().ContainsAnyLegId(outId)) break;
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
    uint8_t fwdPayload[69];
    size_t  fwdLen;
    memcpy(fwdPayload, evPub2, 32);
    if (haveHop2Hash) memcpy(fwdPayload + 32, hop2HashIn, 16);
    else              memset(fwdPayload + 32, 0, 16);   // legacy V: zero -> compat acceptance
    if (v2ext) {
        // Build hop2's CREATE v2 (magic "EAU2" + ver + create_nonce2); hop2's
        // HandleCreate_Relay detects it and signs the CREATED v2.
        memcpy(fwdPayload + 48, "EAU2", 4);
        fwdPayload[52] = 0x02;
        memcpy(fwdPayload + 53, nonce2In, 16);
        fwdLen = 69;
    } else {
        fwdLen = 48;
    }
    uint8_t cell[CELL_TOTAL_BYTES];
    if (!CellPack(outId, CELL_CREATE, fwdPayload, fwdLen, cell)) {
        SecureWipe(extendPlain, sizeof extendPlain);
        return false;
    }
    m_host.SendHandshakeCell(hop2, cell);
    SecureWipe(extendPlain, sizeof extendPlain);
    return true;
}

bool LiveCircuitHandshake::ForwardCreatedAsExtendedRelay(uint32_t outboundCircId,
                                                 const uint8_t* payload, uint16_t payloadLen)
{
    // Caller holds m_lock.
    auto circ = m_host.HandshakeCircuitRegistry().FindRelayByOutgoingId(outboundCircId);
    if (!circ || circ->HopCount() != 1 || payloadLen < 32) return false;

    // hop2's CREATED rides back verbatim: v1 = 32B er_pub2, v2 = 133B signed bundle.
    // Wrap the WHOLE payload (length-preserving) with K_send_r_to_v (hop[0].k_send) —
    // hardcoding 32 would TRUNCATE a v2 CREATED and break hop2's signature for V.
    uint8_t wrapped[CELL_PAYLOAD_MAX];
    size_t wrappedLen = 0;
    if (!circ->OnionEncrypt(payload, payloadLen, wrapped, wrappedLen))
        return false;

    // Pack as CELL_EXTENDED on V's circ_id (which is circ->Id()).
    uint8_t cell[CELL_TOTAL_BYTES];
    if (!CellPack(circ->Id(), CELL_EXTENDED, wrapped, wrappedLen, cell))
        return false;
    if (!circ->m_prevHopClient || !m_host.SendHandshakeCell(circ->m_prevHopClient, cell))
        return false;
    return true;
}

bool LiveCircuitHandshake::ForwardExtendCellForward(std::shared_ptr<CLiveCircuit>& circ,
                                            const uint8_t* payload, uint16_t payloadLen)
{
    if (!circ || circ->m_role != CircuitRole::Relay
        || !circ->m_nextHopClient || circ->m_nextCircId == 0
        || circ->HopCount() != 1 || payloadLen < 16)
        return false;
    uint8_t inner[CELL_PAYLOAD_MAX];
    size_t innerLen = 0;
    if (!circ->OnionPeelOne(0, payload, payloadLen, inner, innerLen))
        return false;
    uint8_t cell[CELL_TOTAL_BYTES];
    if (!CellPack(circ->m_nextCircId, CELL_EXTEND, inner, innerLen, cell))
        return false;
    return m_host.SendHandshakeCell(circ->m_nextHopClient, cell);
}

bool LiveCircuitHandshake::ForwardExtendedCellReverse(std::shared_ptr<CLiveCircuit>& circ,
                                              const uint8_t* payload, uint16_t payloadLen)
{
    if (!circ || circ->m_role != CircuitRole::Relay || !circ->m_prevHopClient
        || circ->HopCount() != 1
        || payloadLen + 16 > CELL_PAYLOAD_MAX)
        return false;
    uint8_t wrapped[CELL_PAYLOAD_MAX];
    size_t wrappedLen = 0;
    if (!circ->EncryptOneLayer(0, payload, payloadLen, wrapped, wrappedLen))
        return false;
    uint8_t cell[CELL_TOTAL_BYTES];
    if (!CellPack(circ->Id(), CELL_EXTENDED, wrapped, wrappedLen, cell))
        return false;
    return m_host.SendHandshakeCell(circ->m_prevHopClient, cell);
}

bool LiveCircuitHandshake::HandleExtendedOriginator(std::shared_ptr<CLiveCircuit>& circ,
                                            const uint8_t* payload, uint16_t payloadLen)
{
    // Caller holds m_lock. circ is the V-side circuit. The cell payload
    // is the wrapped er_pub2 (32+16 tag = 48B).
    if (!circ || circ->m_role != CircuitRole::Originator
        || circ->State() != CircuitState::HalfBuilt
        || m_host.HandshakeCircuitRegistry().FindById(circ->Id()) != circ) {
        return false;
    }
    if (circ->HopCount() < 1 || circ->HopCount() >= 3) return false;
    const uint8_t expectedHopIndex = static_cast<uint8_t>(circ->HopCount());
    if (!circ->m_have_ephemeral) return false;
    if (payloadLen < 48) return false;

    uint8_t plain[CELL_PAYLOAD_MAX];   // was [48] — fits the 133B v2 payload AND bounds the peel
    size_t plainLen = 0;
    if (!circ->OnionDecryptAll(payload, payloadLen, plain, sizeof plain, plainLen))
        return false;
    if (plainLen < 32) return false;

    // v8.x Phase 2 — authenticated EXTENDED v2 (peeled = 133B: ver|er_pub2|node_pub2|caps|sig).
    const bool v3 = (plainLen >= 133 && plain[0] == 0x03);
    const bool v2 = (plainLen >= 133 && plain[0] == 0x02);
    const bool authenticated = v3 || v2;
    if ((TunnelAuthStrict() || circ->m_private2 || circ->m_strict3) && !authenticated) {
        AddDebugLogLine(false, _T("LiveTunnel: v2 AUTH-ABORT hop2 circ=0x%08x reason=STRICT_V1 (unsigned EXTENDED rejected in strict mode)"), circ->Id());
        circ->m_abort_reason = CircuitAbortReason::StrictV1;
        m_host.DestroyHandshakeCircuit(circ); // strict: refuse an unsigned hop2
        SecureWipe(plain, sizeof plain);
        return false;
    }
    if (circ->m_strict3 && !v3) {
        AddDebugLogLine(false, _T("Kad6 K6-6: STRICT circ=0x%08x rejected EXTENDED downgrade below v3"), circ->Id());
        m_host.DestroyHandshakeCircuit(circ);
        SecureWipe(plain, sizeof plain);
        return false;
    }
    if (v3 && !K6ShapeValidBucket(circ->m_shape_bucket_kib)) {
        m_host.DestroyHandshakeCircuit(circ);
        SecureWipe(plain, sizeof plain);
        return false;
    }

    const uint8_t* erPub2     = authenticated ? (plain + 1) : plain;
    const uint8_t* node_pub2  = NULL;
    uint32_t       signedCaps2 = 0;
    if (authenticated) {
        node_pub2   = plain + 33;
        signedCaps2 = (uint32_t)plain[65] | ((uint32_t)plain[66] << 8)
                    | ((uint32_t)plain[67] << 16) | ((uint32_t)plain[68] << 24);
        const uint8_t* sig2 = plain + 69;
        const bool expectedSet = v3 ? circ->m_extendExpectedNodePubSet
                                    : circ->m_expectedNodePub2Set;
        const uint8_t* expectedPub = v3 ? circ->m_extendExpectedNodePub
                                        : circ->m_expectedNodePub2;
        uint8_t actualPrefixHash[32]{};
        const bool prefixMatches = !v3
            || (BuildCircuitPrefixHash(*circ, actualPrefixHash)
                && kad6::Kad6CtEqual(actualPrefixHash,
                                     circ->m_extendPrefixHash, 32));
        // (1) Pin hop2's identity against the key V learned from its OWN HELLO with
        // hop2 (set in BuildExtend). If hop1 swapped in its own key -> mismatch -> abort.
        if (!expectedSet || memcmp(node_pub2, expectedPub, 32) != 0
            || (v3 && (circ->m_extendHopIndex != expectedHopIndex
                       || !prefixMatches))) {
            AddDebugLogLine(false, _T("LiveTunnel: v2 AUTH-ABORT hop2 circ=0x%08x reason=PIN_MISMATCH (exit node_pub != pinned hop2 identity — hop1 impersonation?)"), circ->Id());
            circ->m_abort_reason = CircuitAbortReason::PinMismatch;
            m_host.DestroyHandshakeCircuit(circ);
            SecureWipe(plain, sizeof plain);
            return false;
        }
        // (2) Strict caps floor.
        const uint32_t capsFloor = HANDSHAKE_CAP_AUTH
            | (circ->m_strict3
                ? (HANDSHAKE_CAP_STRICT3 | HANDSHAKE_CAP_SHAPED) : 0);
        if ((TunnelAuthStrict() || circ->m_private2 || circ->m_strict3)
            && (signedCaps2 & capsFloor) != capsFloor) {
            AddDebugLogLine(false, _T("LiveTunnel: v2 AUTH-ABORT hop2 circ=0x%08x reason=CAPS_FLOOR (exit signed_caps lacks TUNNEL_AUTH)"), circ->Id());
            circ->m_abort_reason = CircuitAbortReason::CapsFloor;
            m_host.DestroyHandshakeCircuit(circ);
            SecureWipe(plain, sizeof plain);
            return false;
        }
        // (3) VERIFY-BEFORE-DERIVE against V's OWN stored ev_pub2/nonce2 — so a
        // tampered ev_pub2 (hop1 MITM) fails here, before the second X25519/HKDF.
        uint8_t transcript[TUN_TRANSCRIPT_V3_LEN];
        size_t transcriptLen = TUN_TRANSCRIPT_LEN;
        if (v3) {
            BuildCreatedTranscriptV3(circ->Id(), circ->m_extendHopIndex,
                circ->m_extendPrefixHash, circ->m_extendEphemeralPub, erPub2,
                signedCaps2, circ->m_shape_bucket_kib,
                circ->m_extendNonce, circ->m_extendExpectedHash,
                node_pub2, transcript);
            transcriptLen = TUN_TRANSCRIPT_V3_LEN;
        } else {
            BuildCreatedTranscript(circ->Id(), circ->m_ephemeral_pub2, erPub2,
                signedCaps2, circ->m_create_nonce2, circ->m_expectedHash2,
                node_pub2, transcript);
        }
        if (!VerifySignature(node_pub2, transcript, transcriptLen, sig2)) {
            AddDebugLogLine(false, _T("LiveTunnel: v2 AUTH-ABORT hop2 circ=0x%08x reason=SIG_FAIL (exit Ed25519 verify-before-derive tripped — hop1 tampered ev_pub2 or forged CREATED)"), circ->Id());
            circ->m_abort_reason = CircuitAbortReason::SigFail;
            m_host.DestroyHandshakeCircuit(circ);
            SecureWipe(plain, sizeof plain);
            return false;
        }
    }

    // Derive V↔hop2 keys.
    uint8_t shared[32];
    if (!X25519SharedSecret(erPub2, circ->m_ephemeral_priv, shared))
        return false;

    uint8_t okm[64];
    bool kdfOk;
    if (v3) {
        uint8_t infoSend[TUN_HKDF_INFO_V3_LEN], infoRecv[TUN_HKDF_INFO_V3_LEN];
        size_t infoLen = BuildHkdfInfoV3("ese-tunnel-V-to-R-v3", circ->Id(),
            circ->m_extendHopIndex, circ->m_extendPrefixHash,
            circ->m_extendEphemeralPub, erPub2, signedCaps2,
            circ->m_shape_bucket_kib, node_pub2, infoSend);
        BuildHkdfInfoV3("ese-tunnel-R-to-V-v3", circ->Id(),
            circ->m_extendHopIndex, circ->m_extendPrefixHash,
            circ->m_extendEphemeralPub, erPub2, signedCaps2,
            circ->m_shape_bucket_kib, node_pub2, infoRecv);
        kdfOk = Hkdf(shared, sizeof shared, circ->m_extendNonce, 16,
                     infoSend, infoLen, okm, 32)
             && Hkdf(shared, sizeof shared, circ->m_extendNonce, 16,
                     infoRecv, infoLen, okm + 32, 32);
    } else if (v2) {
        uint8_t infoSend[TUN_HKDF_INFO_LEN], infoRecv[TUN_HKDF_INFO_LEN];
        size_t infoLen = BuildHkdfInfoV2("ese-tunnel-V-to-R-v2", circ->Id(), circ->m_ephemeral_pub2, erPub2, signedCaps2, node_pub2, infoSend);
        BuildHkdfInfoV2("ese-tunnel-R-to-V-v2", circ->Id(), circ->m_ephemeral_pub2, erPub2, signedCaps2, node_pub2, infoRecv);
        kdfOk = Hkdf(shared, sizeof shared, circ->m_create_nonce2, 16, infoSend, infoLen, okm, 32)
             && Hkdf(shared, sizeof shared, circ->m_create_nonce2, 16, infoRecv, infoLen, okm + 32, 32);
    } else {
        const uint8_t info_send[] = "ese-tunnel-V-to-R-v1";
        const uint8_t info_recv[] = "ese-tunnel-R-to-V-v1";
        kdfOk = Hkdf(shared, sizeof shared, NULL, 0, info_send, sizeof info_send - 1, okm, 32)
             && Hkdf(shared, sizeof shared, NULL, 0, info_recv, sizeof info_recv - 1, okm + 32, 32);
    }
    if (!kdfOk) {
        SecureWipe(shared, sizeof shared);
        SecureWipe(plain, sizeof plain);
        return false;
    }

    CircuitHop hop2 = {};
    hop2.hop_id = circ->Id();
    memcpy(hop2.k_send, okm,      32);
    memcpy(hop2.k_recv, okm + 32, 32);
    if (authenticated) memcpy(hop2.pub_long, node_pub2, 32);
    hop2.nonce_send = 0;
    hop2.nonce_recv = 0;
    if (!circ->AddHop(hop2)) {
        SecureWipe(shared, sizeof shared);
        SecureWipe(okm, sizeof okm);
        SecureWipe(plain, sizeof plain);
        return false;
    }
    circ->m_auth_ok = circ->m_auth_ok && authenticated;
    circ->m_shaped_ok = circ->m_shaped_ok && authenticated
        && (signedCaps2 & HANDSHAKE_CAP_SHAPED) != 0;
    circ->m_exit_signed_caps = (circ->m_auth_ok && authenticated
        && circ->m_pendingHopClients.empty()) ? signedCaps2 : 0;

    SecureWipe(circ->m_ephemeral_priv, sizeof circ->m_ephemeral_priv);
    circ->m_have_ephemeral = false;
    SecureWipe(shared, sizeof shared);
    SecureWipe(okm, sizeof okm);
    SecureWipe(plain, sizeof plain);

    circ->m_extendExpectedNodePubSet = false;
    circ->m_extendStartedTick = 0;
    return ContinueOriginatorBuild(circ);
}

} // namespace eSELive
