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
#include "LiveTunnel.h"
#include "LiveCoverTraffic.h"
#include "LiveOnionCrypto.h"
#include "Kad6CryptoHost.h"
#include "Kad6GatewaySocket.h"
#include "kademlia/kademlia/Prefs.h"
#include "kad6/kad6_records.h"

// v0.71 P3.3 — TCP send path.
#include "UpDownClient.h"
#include "ClientList.h"
#include "ListenSocket.h"     // CClientReqSocket::SendPacket
#include "Packets.h"
#include "Opcodes.h"          // OP_EMULEPROT, OP_LIVE_TUNNEL_CELL
#include "emule.h"            // theApp
#include "Preferences.h"      // v0.71 P0.B — thePrefs.GetUserHash()
#include "DownloadQueue.h"
#include "PartFile.h"
#include "Log.h"              // v0.71 P0.B — AddDebugLogLine
#include "NodeIdentity.h"     // v8.x Phase 2 — NodeIdentityPub/Sign for CREATED v2
#include "LiveCrypto.h"       // v8.x Phase 2 — VerifySignature (originator verify side)
// v0.71 P1 — Kad search through tunnel: lookup against local directory
#include "LiveStreamManager.h"
#include "LivePackets.h"        // v8.1.2 E3.1 - ESE_FRAG_* (exit-side 0xE0 reassembly)
#include "LiveKadBridge.h"
#include "kademlia/kademlia/KadV2ModeSelector.h"
#include "kademlia/kademlia/SearchManager.h"   // v8.1 B - StopSearch on tunneled search
#include "kademlia/kademlia/KadV2TunnelPool.h"  // v8.1 D4 - register Active circuits in the PST pool
#include "kademlia/kademlia/Kademlia.h"          // v8.1 D5 - routing-table lookup for the exit Kad ID
#include "kademlia/net/KademliaUDPListener.h"     // K6-3 native signed source STORE
#include "kademlia/routing/RoutingZone.h"        // v8.1 D5
#include "kademlia/routing/Contact.h"            // v8.1 D5
#include "kademlia/routing/Kad6RoutingTable.h"   // K6-6 path diversity metadata
#include "kademlia/kademlia/Search.h"            // K6-1 target_hash (Live namespace MD4)
#include "kad6/kad6_frame.h"                     // K6-2.1: validated gateway envelope
#include "kad6/kad6_live_search.h"               // K6-1 canonical Live tag mapping
#include "kad6/kad6_ed2k_policy.h"
#include "kad6/kad6_path.h"
#include "IPFilter.h"
#include "OtherFunctions.h"
#include "FirewallProberV6.h"
#include "eMuleAI/Address.h"

#include <limits>

namespace eSELive {

// ===== v8.x Phase 2 — authenticated CREATE/CREATED v2 (signed handshake) =====
// docs/AUTHENTICATED_TUNNEL_HANDSHAKE_PLAN.md §4/§5. Byte-exact, little-endian,
// fixed widths. The transcript serializer MUST be identical on the signer (relay)
// and the verifier (originator) — a single byte of drift makes the HKDF keys
// diverge and the circuit dies on its first AEAD cell.
static inline void PutU32LE(uint8_t* p, uint32_t v) {
    p[0] = (uint8_t)(v & 0xFF);
    p[1] = (uint8_t)((v >> 8) & 0xFF);
    p[2] = (uint8_t)((v >> 16) & 0xFF);
    p[3] = (uint8_t)((v >> 24) & 0xFF);
}

// "ese-tun-created-v2" = 18 bytes (no NUL in the transcript).
static const char   TUN_TRANSCRIPT_LABEL[] = "ese-tun-created-v2";
static const size_t TUN_TRANSCRIPT_LEN     = 18 + 32 + 32 + 4 + 16 + 16 + 32;       // 150 (circ_id dropped: per-leg on EXTEND, breaks cross-node match)
// Compile-time guards against single-byte drift: edit the label or the layout
// formula without updating its twin and the BUILD breaks here, instead of the
// circuit dying silently on its first AEAD cell (signer/verifier key divergence).
static_assert(sizeof(TUN_TRANSCRIPT_LABEL) - 1 == 18, "eSE Auth: transcript label must be exactly 18 bytes (NUL excluded).");
static_assert(TUN_TRANSCRIPT_LEN == 150, "eSE Auth: canonical transcript layout must be exactly 150 bytes.");

// Canonical CREATED-v2 transcript (§4). `out` must hold TUN_TRANSCRIPT_LEN bytes.
static void BuildCreatedTranscript(uint32_t circ_id,
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
static const size_t TUN_HKDF_INFO_LEN = 20 + 32 + 32 + 4 + 32;       // 120 (circ_id dropped, see transcript)
static_assert(TUN_HKDF_INFO_LEN == 120, "eSE Auth: HKDF info context buffer must be exactly 120 bytes.");
static size_t BuildHkdfInfoV2(const char* label20, uint32_t circ_id,
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
static inline void PutU16LE(uint8_t* p, uint16_t v) {
    p[0] = static_cast<uint8_t>(v);
    p[1] = static_cast<uint8_t>(v >> 8);
}

// K6-6 authenticated context. v2 remains byte-for-byte compatible; v3 binds
// the origin circuit id, expected hop position and hash of the established
// prefix, all of which remain stable across relay-local outbound circuit ids.
static const char TUN_TRANSCRIPT_V3_LABEL[] = "kad6-tun-created-v3";
static const size_t TUN_TRANSCRIPT_V3_LEN = 19 + 4 + 1 + 32 + 32 + 32 + 4 + 2 + 16 + 16 + 32;
static const size_t TUN_HKDF_INFO_V3_LEN = 20 + 4 + 1 + 32 + 32 + 32 + 4 + 2 + 32;
static_assert(sizeof(TUN_TRANSCRIPT_V3_LABEL) - 1 == 19, "K6 v3 transcript label drift");
static_assert(TUN_TRANSCRIPT_V3_LEN == 190, "K6 v3 transcript layout drift");
static_assert(TUN_HKDF_INFO_V3_LEN == 159, "K6 v3 HKDF layout drift");

static void BuildCreatedTranscriptV3(uint32_t originCircId, uint8_t hopIndex,
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

static size_t BuildHkdfInfoV3(const char* label20, uint32_t originCircId,
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

static bool BuildCircuitPrefixHash(const CLiveCircuit& circ, uint8_t out[32])
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

static const size_t TUN_CREATE_V3_LEN = 140;
static const size_t TUN_EXTEND_V3_LEN = 158;
static_assert(TUN_CREATE_V3_LEN <= CELL_PAYLOAD_MAX, "CREATE v3 must fit one cell");
static_assert(TUN_EXTEND_V3_LEN + 3 * 16 <= CELL_PAYLOAD_MAX,
              "EXTEND v3 plus maximum onion must fit one cell");

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
    // v8.1.2 Sprint E (E3.2) - explicit bulk data-plane subscribe/unsub.
    RegisterExitHandler(TUN_OP_BULK_SUBSCRIBE,
        [this](const TunnelRequestCtx& c){ ExitHandle_BulkSubscribe(c); });
    RegisterExitHandler(TUN_OP_BULK_UNSUB,
        [this](const TunnelRequestCtx& c){ ExitHandle_BulkUnsub(c); });
    RegisterExitHandler(TUN_OP_BULK_NACK,
        [this](const TunnelRequestCtx& c){ ExitHandle_BulkNack(c); });
    // K6-1A canonical Live search gateway.  Originators select it only from
    // the authenticated exit-capability snapshot; old peers retain 0x42/0x43.
    RegisterExitHandler(TUN_OP_KAD6_GATEWAY,
        [this](const TunnelRequestCtx& c){ ExitHandle_Kad6Gateway(c); });

    const kad6::Kad6CryptoHooks crypto = MakeKad6HostCryptoHooks();
    m_k6TicketSecretReady = crypto.random_bytes &&
        crypto.random_bytes(m_k6TicketSecret.data(), m_k6TicketSecret.size());

    // A fresh installation is never a public exit merely because the binary
    // contains the handlers. Operator consent plus signed release evidence is
    // required before any public Kad6 service admits work.
    const uint64 now = static_cast<uint64>(time(NULL));
    for (size_t i = 0; i < static_cast<size_t>(kad6::K6Service::Count); ++i)
        m_k6Hardening.SetEnabled(static_cast<kad6::K6Service>(i), false,
            now ? now : 1, 0, 0);
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
inline void eseWrU64LE(uint8_t* p, uint64_t v) {
    for (unsigned i = 0; i < 8; ++i) p[i] = (uint8_t)(v >> (i * 8));
}
inline uint64_t eseRdU64LE(const uint8_t* p) {
    uint64_t v = 0;
    for (unsigned i = 0; i < 8; ++i) v |= (uint64_t)p[i] << (i * 8);
    return v;
}

// USER32 timers have a practical 10 ms floor.  1024 KiB/s yields a 16.2 ms
// class-5 slot (15.4 ms at -5% jitter), so one callback never needs to batch
// multiple records. Higher protocol buckets remain representable but this
// host refuses them instead of claiming shaping it cannot schedule faithfully.
const uint16_t K6_SHAPE_RUNTIME_MAX_BUCKET_KIB = 1024;
const uint16_t K6_SHAPE_DEFAULT_BUCKET_KIB = K6_SHAPE_RUNTIME_MAX_BUCKET_KIB;
const uint8_t  K6_BULK_SUB_FLAG_SHAPED = 0x01;
const uint64_t K6_SHAPE_PADDING_NONCE = kad6::kK6ShapedPaddingSentinel;
const size_t   K6_SHAPE_MAX_RESERVED_LINKS = 8;

bool K6ShapeValidBucket(uint32_t bucketKiB)
{
    return bucketKiB >= kad6::kK6ShapeMinBucketKiB
        && bucketKiB <= K6_SHAPE_RUNTIME_MAX_BUCKET_KIB
        && (bucketKiB & (bucketKiB - 1)) == 0;
}

uint64_t K6ShapeReplayKey(uint32_t circId, uint8_t lane)
{
    return (static_cast<uint64_t>(circId) << 8) | lane;
}

uint64_t K6ShapeNowUs()
{
    LARGE_INTEGER counter{}, frequency{};
    if (::QueryPerformanceCounter(&counter) && ::QueryPerformanceFrequency(&frequency)
        && frequency.QuadPart > 0) {
        const uint64_t whole = static_cast<uint64_t>(counter.QuadPart / frequency.QuadPart);
        const uint64_t remainder = static_cast<uint64_t>(counter.QuadPart % frequency.QuadPart);
        return whole * 1000000ull
            + (remainder * 1000000ull) / static_cast<uint64_t>(frequency.QuadPart);
    }
    return static_cast<uint64_t>(::GetTickCount()) * 1000ull;
}

void CALLBACK K6Class5TimerProc(HWND, UINT, UINT_PTR timerId, DWORD) noexcept
{
    try {
        if (theApp.IsClosing()) {
            ::KillTimer(NULL, timerId);
            return;
        }
        CLiveTunnel::Get().ProcessClass5Tick();
    } catch (...) {
        // Timer callbacks must never unwind through USER32, and a dead
        // shaping timer must never leave a circuit advertised as STRICT.
        // Tear the tunnel pool down fail-closed; the normal successor loop
        // may rebuild fresh circuits afterwards.
        try { CLiveTunnel::Get().Stop(); } catch (...) {}
        ::KillTimer(NULL, timerId);
    }
}

std::vector<uint8_t> EseCStringUtf8(const CString& value)
{
    std::vector<uint8_t> out;
    if (value.IsEmpty()) return out;
    const int bytes = WideCharToMultiByte(CP_UTF8, 0, value, value.GetLength(),
                                           NULL, 0, NULL, NULL);
    if (bytes <= 0) return out;
    out.resize((size_t)bytes);
    WideCharToMultiByte(CP_UTF8, 0, value, value.GetLength(),
                        reinterpret_cast<char*>(out.data()), bytes, NULL, NULL);
    return out;
}

CString EseUtf8CString(const std::string& value)
{
    if (value.empty()) return CString();
    const int chars = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                                           value.data(), (int)value.size(),
                                           NULL, 0);
    if (chars <= 0) return CString();
    CStringW wide;
    wchar_t* dst = wide.GetBufferSetLength(chars);
    const int converted = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                                               value.data(), (int)value.size(),
                                               dst, chars);
    wide.ReleaseBuffer(converted == chars ? chars : 0);
    return converted == chars ? CString((LPCWSTR)wide) : CString();
}

// Append one K6 Live result to the legacy rich-result aggregate used by the
// existing directory/JSON consumers. This is a host compatibility adapter;
// the actual K6 wire remains K6Frame + canonical tags.
bool EseAppendLegacyK6Result(const kad6::K6LiveSearchMetadata& live,
                             std::vector<uint8_t>& aggregate)
{
    if (aggregate.empty()) aggregate.assign(4, 0);
    if (aggregate.size() < 4 || aggregate.size() > TUN_MSG_MAX_BYTES - 512)
        return false;

    std::vector<uint8_t> rec;
    rec.insert(rec.end(), live.result_id.begin(), live.result_id.end());
    const uint32_t ip = (uint32_t)live.ipv4[0] | ((uint32_t)live.ipv4[1] << 8) |
                        ((uint32_t)live.ipv4[2] << 16) | ((uint32_t)live.ipv4[3] << 24);
    const size_t fixed = rec.size();
    rec.resize(fixed + 4 + 2 + 2 + 2 + 4 + 4 + 1);
    eseWrU32LE(rec.data() + fixed, ip);
    eseWrU16LE(rec.data() + fixed + 4, live.tcp_port);
    eseWrU16LE(rec.data() + fixed + 6, live.udp_port);
    eseWrU16LE(rec.data() + fixed + 8, live.bitrate_kbps);
    eseWrU32LE(rec.data() + fixed + 10, live.viewer_count);
    eseWrU32LE(rec.data() + fixed + 14, live.started_at);
    rec[fixed + 18] = live.discovery_namespace;
    auto putStr8 = [&](const std::vector<uint8_t>& s) {
        const size_t n = (std::min<size_t>)(255, s.size());
        rec.push_back((uint8_t)n);
        rec.insert(rec.end(), s.begin(), s.begin() + n);
    };
    putStr8(live.title_utf8);
    putStr8(live.category_utf8);
    putStr8(live.language_utf8);
    if (rec.size() > 0xFFFF || aggregate.size() + 2 + rec.size() > TUN_MSG_MAX_BYTES)
        return false;
    const size_t at = aggregate.size();
    aggregate.resize(at + 2);
    eseWrU16LE(aggregate.data() + at, (uint16_t)rec.size());
    aggregate.insert(aggregate.end(), rec.begin(), rec.end());
    return true;
}

bool EseBuildK6SearchStartFrame(const std::string& keyword, uint32_t reqId,
                                std::vector<uint8_t>& wire)
{
    wire.clear();
    if (keyword.empty() || keyword.size() > kad6::kK6SearchMaxQueryBytes ||
        !kad6::Kad6IsValidUtf8NoNul(
            reinterpret_cast<const kad6::Byte*>(keyword.data()), keyword.size()))
        return false;

    kad6::K6SearchStart start;
    start.search_kind = kad6::kK6SearchKindLive;
    start.network_mask = kad6::kK6NetMaskKad2;
    start.max_results = (uint16_t)TUN_SEARCH_MAX_RESULTS;
    start.deadline_ms = TUN_SEARCH_WINDOW_MS;
    start.query.assign(keyword.begin(), keyword.end());
    Kademlia::CUInt128 target;
    const CStringA keywordA(keyword.data(), (int)keyword.size());
    EseLiveGetKeywordHash(keywordA, &target);
    target.ToByteArray(start.target_hash.data());

    std::vector<uint8_t> body;
    if (kad6::EncodeK6SearchStart(start, body) != kad6::Kad6Status::Ok)
        return false;
    kad6::K6Frame frame;
    frame.msg_type = kad6::kK6MsgSearchStart;
    frame.flags = kad6::kK6FlagCancelable | kad6::kK6FlagLegacyKad2;
    frame.request_id = reqId;
    frame.body = std::move(body);
    return kad6::EncodeK6Frame(frame, wire) == kad6::Kad6Status::Ok;
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

// Keep tunnel control queues bounded. At 512 bytes/cell this permits roughly
// one MiB of queued wire per neighbour while still accommodating several
// complete eD2K framed messages. A full queue is backpressure, not permission
// to allocate indefinitely.
static const INT_PTR TUNNEL_EGRESS_MAX_QUEUED_CELLS = 2048;
static const INT_PTR TUNNEL_BULK_MAX_QUEUED_CELLS = 256;

static bool EseCanQueueTunnelCells(CUpDownClient* peer, size_t count)
{
    return peer && peer->socket && peer->socket->IsConnected() &&
        count <= static_cast<size_t>(TUNNEL_EGRESS_MAX_QUEUED_CELLS) &&
        peer->socket->GetControlQueueCount() <=
            TUNNEL_EGRESS_MAX_QUEUED_CELLS - static_cast<INT_PTR>(count);
}

static bool EseCanQueueBulkCells(CUpDownClient* peer, size_t count)
{
    return peer && peer->socket && peer->socket->IsConnected() &&
        count <= static_cast<size_t>(TUNNEL_BULK_MAX_QUEUED_CELLS) &&
        peer->socket->DbgGetStdQueueCount() <=
            TUNNEL_BULK_MAX_QUEUED_CELLS - static_cast<INT_PTR>(count);
}

// v0.71 P3.3 — send a 512B cell to a peer wrapped as OP_LIVE_TUNNEL_CELL.
// Uses the existing extension-protocol packet path. Caller holds m_lock.
bool CLiveTunnel::SendCellToPeer(CUpDownClient* peer, const uint8_t cell[CELL_TOTAL_BYTES])
{
    if (!EseCanQueueTunnelCells(peer, 1))
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
    // 2-hop extension is IMPLEMENTED: after CELL_CREATED, HandleCreated_Originator
    // auto-calls BuildExtend (when a hop2 candidate was pre-staged), which sends
    // CELL_EXTEND (encrypted with K_send_hop1) carrying hop 2 endpoint + new
    // ephemeral; hop 1 forwards as CELL_CREATE to hop 2. Both v1 and authenticated
    // v2 paths exist.
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
        // v8.1.2 E1.5 — bulk data plane rides this circuit only if EVERY hop advertises
        // ESE_CAP_TUNNEL_BULK. Seed from hop1; BuildExtend AND-s in hop2.
        c->m_bulk_ok = hop1->SupportsEseTunnelBulk();
        c->m_shaped_ok = hop1->SupportsEseTunnelShaped();
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
        // v8.x Phase 2 — emit CREATE v2 (signed handshake) when hop1 can do it;
        // else v1. The v2 suffix (magic "EAU2" + ver + create_nonce) is ignored
        // by v1 peers (TLV-additive). Strict mode refuses non-auth hops outright.
        const uchar* hop1Hash = hop1->GetUserHash();
        const bool   hop1Auth = hop1->SupportsEseTunnelAuth() && hop1->HasEseNodePub()
                                && hop1->HasValidHash() && (NodeIdentityPub() != NULL);
        if (TunnelAuthStrict() && !hop1Auth) {
            c->WipeKeys();   // strict: no authenticated hop -> don't build this circuit
            continue;
        }
        const bool hop1v3 = hop1Auth && hop1->SupportsEseTunnelStrict3();
        uint8_t payload[TUN_CREATE_V3_LEN];
        size_t  payloadLen;
        memcpy(payload, evPub, 32);
        if (hop1Hash) memcpy(payload + 32, hop1Hash, 16);
        else          memset(payload + 32, 0, 16);
        if (hop1v3) {
            c->m_shape_bucket_kib = K6_SHAPE_DEFAULT_BUCKET_KIB;
            memcpy(payload + 48, "EAU3", 4);
            payload[52] = 0x03;
            SecureRandomBytes(c->m_create_nonce, 16);
            memcpy(payload + 53, c->m_create_nonce, 16);
            PutU32LE(payload + 69, id);
            payload[73] = 0; // guard
            if (!BuildCircuitPrefixHash(*c, c->m_createPrefixHash)) {
                c->WipeKeys();
                continue;
            }
            memcpy(payload + 74, c->m_createPrefixHash, 32);
            memcpy(payload + 106, hop1->GetEseNodePub(), 32);
            PutU16LE(payload + 138, c->m_shape_bucket_kib);
            c->m_createHopIndex = 0;
            payloadLen = TUN_CREATE_V3_LEN;
            memcpy(c->m_ephemeral_pub, evPub, 32);
            memcpy(c->m_expectedNodePub, hop1->GetEseNodePub(), 32);
            c->m_expectedNodePubSet = true;
            memcpy(c->m_expectedHash, hop1Hash, 16);
        } else if (hop1Auth) {
            memcpy(payload + 48, "EAU2", 4);
            payload[52] = 0x02;
            SecureRandomBytes(c->m_create_nonce, 16);
            memcpy(payload + 53, c->m_create_nonce, 16);
            payloadLen = 69;
            // Pin hop1's identity (from its OWN HELLO) + stash our ephemeral pub and
            // the target hash so HandleCreated_Originator can rebuild the transcript.
            memcpy(c->m_ephemeral_pub,   evPub, 32);
            memcpy(c->m_expectedNodePub, hop1->GetEseNodePub(), 32);
            c->m_expectedNodePubSet = true;
            memcpy(c->m_expectedHash, hop1Hash, 16);
        } else {
            payloadLen = 48;   // v1: ev_pub + target_user_hash
        }
        uint8_t cell[CELL_TOTAL_BYTES];
        if (!CellPack(id, CELL_CREATE, payload, payloadLen, cell)) {
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

// Production successor build for the PST pool's make-before-break. A requested
// privacy profile never degrades to one hop: Strict tries exactly three relays,
// then Private tries exactly two authenticated distinct relays. Direct mode and
// one-hop diagnostics use separate explicit paths.
bool CLiveTunnel::BuildSuccessorCircuit()
{
    // K6-6: prefer a fully diverse, authenticated guard->middle->exit circuit.
    if (BuildSuccessor3Hop()) return true;
    return BuildSuccessor2Hop();
}

bool CLiveTunnel::BuildQuotaGuardCircuit()
{
    std::set<std::string> privatePathNodes;
    {
        CSingleLock lock(&m_lock, TRUE);
        for (const auto& circuit : m_circuits) {
            if (circuit && circuit->m_k6QuotaIssuerCircuit &&
                circuit->State() != CircuitState::Destroyed)
                return false;
            if (!circuit || circuit->m_k6QuotaIssuerCircuit ||
                circuit->m_role != CircuitRole::Originator ||
                circuit->State() == CircuitState::Destroyed)
                continue;
            for (size_t hop = 0; hop < circuit->HopCount(); ++hop)
                privatePathNodes.insert(K6BinaryKey(
                    circuit->Hop(hop).pub_long, 32));
        }
    }

    std::vector<CUpDownClient*> peers;
    if (theApp.clientlist)
        theApp.clientlist->GetConnectedSnapshot(peers, 32, /*tunnelOnly=*/true);
    if (peers.empty()) return false;

    const bool havePinnedGuard = LoadK6Guard();
    CUpDownClient* selected = NULL;
    for (CUpDownClient* peer : peers) {
        if (!peer || !peer->socket || !peer->socket->IsConnected() ||
            !peer->HasValidHash() || !peer->HasEseNodePub() ||
            !peer->SupportsEseTunnelAuth() ||
            !peer->SupportsEseTunnelDataplane() ||
            !peer->SupportsEseTunnelStrict3() ||
            !peer->SupportsEseTunnelShaped() ||
            (peer->GetEseCapabilities() &
                (ESE_CAP_KAD6 | ESE_CAP_KAD6_ECONOMY)) !=
                (ESE_CAP_KAD6 | ESE_CAP_KAD6_ECONOMY) ||
            privatePathNodes.find(K6BinaryKey(peer->GetEseNodePub(), 32)) !=
                privatePathNodes.end() ||
            (theApp.liveStreamManager &&
             theApp.liveStreamManager->IsStreamSourcePeer(peer)))
            continue;
        if (!selected) selected = peer;
        if (havePinnedGuard && kad6::Kad6CtEqual(peer->GetEseNodePub(),
                m_k6GuardNodePub.data(), m_k6GuardNodePub.size())) {
            selected = peer;
            break;
        }
    }
    if (!selected) return false;

    size_t before = 0;
    {
        CSingleLock lock(&m_lock, TRUE);
        before = m_circuits.size();
    }
    std::vector<CUpDownClient*> one{selected};
    if (BuildPool(NULL, one, 1) == 0) return false;
    CSingleLock lock(&m_lock, TRUE);
    for (size_t i = before; i < m_circuits.size(); ++i) {
        const std::shared_ptr<CLiveCircuit>& circuit = m_circuits[i];
        if (circuit && circuit->m_firstHopClient == selected &&
            circuit->State() == CircuitState::Pending) {
            circuit->m_k6QuotaIssuerCircuit = true;
            return true;
        }
    }
    return false;
}

// v8.1.1 F-2 — build a TRUE 2-hop circuit V -> hop1 -> exit with hop1 != exit.
// Mirrors BuildTestCircuit2Hop's pre-stage mechanism but REQUIRES two DISTINCT
// nodes (by user-hash), so a production circuit can never silently collapse into
// the loopback (hop2==hop1) degenerate case that looks like 2-hop but gives zero
// anonymity. No 1-hop fallback here (the caller decides that).
bool CLiveTunnel::BuildSuccessor2Hop()
{
    std::vector<CUpDownClient*> cands;
    if (theApp.clientlist)
        theApp.clientlist->GetConnectedSnapshot(cands, 5, /*tunnelOnly=*/true);

    std::vector<CUpDownClient*> eligible;
    for (CUpDownClient* p : cands) {
        if (!p || !p->socket || !p->socket->IsConnected() || !p->HasValidHash()
            || !p->HasEseNodePub() || !p->SupportsEseTunnelAuth()
            || !p->SupportsEseTunnelDataplane())
            continue;
        // v8.1.2 B6 (co-seeder filter) — never route a circuit through a peer that serves us
        // the channel we're viewing: it would learn (by being our hop) that this IP watches
        // that stream, defeating G1. Applies to hop1 AND the exit.
        if (theApp.liveStreamManager && theApp.liveStreamManager->IsStreamSourcePeer(p)) continue;
        eligible.push_back(p);
    }
    auto distinctNode = [](CUpDownClient* a, CUpDownClient* b) {
        if (!a || !b || a == b) return false;
        const uchar* ha = a->GetUserHash();
        const uchar* hb = b->GetUserHash();
        return !(ha && hb && memcmp(ha, hb, 16) == 0);
    };

    CUpDownClient* hop1 = NULL;
    CUpDownClient* hop2 = NULL;
    // Prefer a Kad6-capable EXIT; the guard may be any distinct authenticated
    // tunnel peer. This makes Kad6 win whenever it is present without removing
    // the legacy two-hop compatibility path during early adoption.
    for (CUpDownClient* exitCandidate : eligible) {
        if ((exitCandidate->GetEseCapabilities() & ESE_CAP_KAD6) == 0) continue;
        for (CUpDownClient* guardCandidate : eligible)
            if (distinctNode(guardCandidate, exitCandidate)) {
                hop1 = guardCandidate;
                hop2 = exitCandidate;
                break;
            }
        if (hop1) break;
    }
    if (!hop1) {
        for (CUpDownClient* p : eligible) {
            if (!hop1) { hop1 = p; continue; }
            if (!distinctNode(hop1, p)) continue;
            hop2 = p;
            break;
        }
    }
    if (!hop1 || !hop2) return false;   // < 2 distinct tunnel peers -> no real 2-hop

    size_t before = 0;
    { CSingleLock lk(&m_lock, TRUE); before = m_circuits.size(); }

    std::vector<CUpDownClient*> hop1Vec = { hop1 };
    if (BuildPool(NULL, hop1Vec, 1) == 0) return false;   // BuildPool takes m_lock itself

    CSingleLock lk(&m_lock, TRUE);
    if (m_circuits.size() <= before) return false;
    auto& c = m_circuits.back();
    // Pre-stage the exit: HandleCreated_Originator auto-extends to it after hop1's
    // CELL_CREATED, producing a real V -> hop1 -> exit circuit (hop1 forwards via F-1).
    c->m_private2 = true;
    c->m_pendingHopClients.push_back(hop2);
    return true;
}

void CLiveTunnel::Stop()
{
    m_k6ExitNoticeServer.Stop();
    std::set<uint32_t> retiredCircuits;
    {
        CSingleLock lock(&m_lock, TRUE);
        StopK6ShapeTimerLocked();
        m_k6ShapeReverse.clear();
        m_k6ShapeReplay.clear();
        for (const auto& circuit : m_circuits)
            if (circuit) retiredCircuits.insert(circuit->Id());
        m_circuits.clear();
        m_rrNextIdx = 0;
    }
    const uint64 now = static_cast<uint64_t>(time(NULL));
    SweepK6SourceLeases(std::set<uint32_t>(), retiredCircuits, now);
    SweepK6Gateway(now, std::set<uint32_t>());
    {
        CSingleLock pl(&m_pendingLock, TRUE);
        m_k6QuotaGrants.clear();
        m_k6FairPayloads.clear();
        m_k6FairCredits.clear();
        m_k6FairAllocationByStream.clear();
        m_k6FairPayloadBytes = 0;
        m_k6FairScheduler.Reset();
        m_k6QuotaIssuerLimiter = kad6::K6QuotaIssuerLimiter();
        m_k6QuotaHierarchy = kad6::K6QuotaHierarchy();
        m_k6QuotaSpent = kad6::K6QuotaSpentSet();
        m_k6SendCredits.clear();
        m_k6ReceiveCredits.clear();
        m_k6FlowStreamsByCircuit.clear();
    }
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

// v8.1 D5 - best-effort: resolve the EXIT (last hop) peer's Kad node-ID from our routing
// table and stash it on the circuit, so CKadV2TunnelPool::Acquire can pick the circuit whose
// exit is XOR-closest to a Kad search target. Returns silently when the peer is not a Kad
// contact (mirrors the proven CUpDownClient::GetContact usage in BaseClient.cpp). The CUInt128
// is value-copied (a CContact* can be evicted from the routing bin). Main thread only.
static void EseTryResolveExitKadKey(CUpDownClient* exit, CLiveCircuit& c)
{
    if (!exit || c.m_haveExitKadKey) return;
    if (exit->GetConnectIP() == 0) return;   // D5 - avoid GetContact(0,...) matching a 0-IP contact
    if (!Kademlia::CKademlia::IsRunning()) return;
    Kademlia::CRoutingZone* rz = Kademlia::CKademlia::GetRoutingZone();
    if (!rz) return;
    Kademlia::CContact* pc = rz->GetContact(ntohl(exit->GetConnectIP()), 0, false);
    if (!pc) return;
    c.m_exitKadKey     = pc->GetClientID();   // value copy
    c.m_haveExitKadKey = true;
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

    // v8.x Phase 2 — authenticated CREATED v2 (133B: ver|er_pub|node_pub|caps|sig).
    const bool v3 = (payloadLen >= 133 && payload[0] == 0x03);
    const bool v2 = (payloadLen >= 133 && payload[0] == 0x02);
    const bool authenticated = v3 || v2;
    if ((TunnelAuthStrict() || circ->m_private2 || circ->m_strict3) && !authenticated) {
        // Distinct, greppable abort reasons (the rogue-relay test reads these to prove
        // the rejection was CRYPTO, not a network timeout — cf. the Tick reap logs).
        AddDebugLogLine(false, _T("LiveTunnel: v2 AUTH-ABORT hop1 circ=0x%08x reason=STRICT_V1 (unsigned CREATED rejected in strict mode)"), circ->Id());
        DestroyCircuitFailClosed(circ); // strict: refuse the unsigned v1 downgrade
        return false;
    }
    if (circ->m_strict3 && !v3) {
        AddDebugLogLine(false, _T("Kad6 K6-6: STRICT circ=0x%08x rejected CREATE downgrade below v3"), circ->Id());
        DestroyCircuitFailClosed(circ);
        return false;
    }
    if (v3 && !K6ShapeValidBucket(circ->m_shape_bucket_kib)) {
        DestroyCircuitFailClosed(circ);
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
            DestroyCircuitFailClosed(circ);
            return false;
        }
        // (2) Strict caps floor.
        const uint32_t capsFloor = ESE_CAP_TUNNEL_AUTH
            | (circ->m_strict3 ? (ESE_CAP_TUNNEL_STRICT3 | ESE_CAP_TUNNEL_SHAPED) : 0);
        if ((TunnelAuthStrict() || circ->m_private2 || circ->m_strict3)
            && (signedCaps & capsFloor) != capsFloor) {
            AddDebugLogLine(false, _T("LiveTunnel: v2 AUTH-ABORT hop1 circ=0x%08x reason=CAPS_FLOOR (signed_caps lacks TUNNEL_AUTH)"), circ->Id());
            DestroyCircuitFailClosed(circ);
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
            DestroyCircuitFailClosed(circ);
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
        && (signedCaps & ESE_CAP_TUNNEL_SHAPED) != 0;
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

    circ->SetState(CircuitState::Active);
    return ContinueOriginatorBuild(circ);
}

namespace {
CString EseK6GuardPath()
{
    return thePrefs.GetMuleDirectory(EMULE_CONFIGDIR) + _T("kad6_guard.dat");
}

bool EseK6PathRandom(void*, kad6::Byte* out, std::size_t length)
{
    if (!out && length != 0) return false;
    if (length) SecureRandomBytes(out, length);
    return true;
}

}

void CLiveTunnel::DestroyCircuitFailClosed(std::shared_ptr<CLiveCircuit>& circ)
{
    if (!circ || circ->State() == CircuitState::Destroyed) return;
    uint8_t destroy[CELL_TOTAL_BYTES];
    if (circ->m_role == CircuitRole::Originator) {
        if (circ->m_firstHopClient
            && CellPack(circ->Id(), CELL_DESTROY, NULL, 0, destroy))
            SendCellToPeer(circ->m_firstHopClient, destroy);
    } else {
        if (circ->m_prevHopClient
            && CellPack(circ->Id(), CELL_DESTROY, NULL, 0, destroy))
            SendCellToPeer(circ->m_prevHopClient, destroy);
        if (circ->m_nextHopClient && circ->m_nextCircId != 0
            && CellPack(circ->m_nextCircId, CELL_DESTROY, NULL, 0, destroy))
            SendCellToPeer(circ->m_nextHopClient, destroy);
    }
    circ->SetState(CircuitState::Destroyed);
    circ->WipeKeys();
}

bool CLiveTunnel::LoadK6Guard()
{
    if (m_k6GuardLoaded)
        return m_k6GuardExpiresAt > static_cast<uint64_t>(time(NULL));
    m_k6GuardLoaded = true;
    m_k6GuardNodePub.fill(0);
    m_k6GuardExpiresAt = 0;
    uint8_t bytes[80]{};
    try {
        CFile file;
        if (!file.Open(EseK6GuardPath(), CFile::modeRead | CFile::shareDenyWrite))
            return false;
        if (file.GetLength() != sizeof bytes) {
            file.Close();
            return false;
        }
        const bool read = file.Read(bytes, sizeof bytes) == sizeof bytes;
        file.Close();
        if (!read) return false;
    } catch (CFileException* error) {
        error->Delete();
        return false;
    }
    if (memcmp(bytes, "K6GRD1\0\0", 8) != 0)
        return false;
    uint8_t digest[32];
    const kad6::Kad6CryptoHooks crypto = MakeKad6HostCryptoHooks();
    if (!crypto.sha256 || !crypto.sha256(bytes, 48, digest)
        || !kad6::Kad6CtEqual(digest, bytes + 48, 32))
        return false;
    uint64_t expiry = 0;
    for (unsigned i = 0; i < 8; ++i)
        expiry |= static_cast<uint64_t>(bytes[40 + i]) << (i * 8);
    if (expiry <= static_cast<uint64_t>(time(NULL)))
        return false;
    memcpy(m_k6GuardNodePub.data(), bytes + 8, 32);
    m_k6GuardExpiresAt = expiry;
    return true;
}

bool CLiveTunnel::SaveK6Guard(const uint8_t nodePub[32], uint64_t expiresAt)
{
    if (!nodePub || expiresAt <= static_cast<uint64_t>(time(NULL)))
        return false;
    uint8_t bytes[80]{};
    memcpy(bytes, "K6GRD1\0\0", 8);
    memcpy(bytes + 8, nodePub, 32);
    for (unsigned i = 0; i < 8; ++i)
        bytes[40 + i] = static_cast<uint8_t>(expiresAt >> (i * 8));
    const kad6::Kad6CryptoHooks crypto = MakeKad6HostCryptoHooks();
    if (!crypto.sha256 || !crypto.sha256(bytes, 48, bytes + 48))
        return false;
    const CString path = EseK6GuardPath();
    const CString temporary = path + _T(".new");
    try {
        CFile file(temporary, CFile::modeCreate | CFile::modeWrite
                              | CFile::shareExclusive);
        file.Write(bytes, sizeof bytes);
        file.Flush();
        file.Close();
        if (!MoveFileEx(temporary, path,
                        MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
            DeleteFile(temporary);
            return false;
        }
    } catch (CFileException* error) {
        error->Delete();
        DeleteFile(temporary);
        return false;
    }
    memcpy(m_k6GuardNodePub.data(), nodePub, 32);
    m_k6GuardExpiresAt = expiresAt;
    m_k6GuardLoaded = true;
    return true;
}

bool CLiveTunnel::BuildSuccessor3Hop(uint32_t* circuitId)
{
    if (circuitId) *circuitId = 0;
    std::set<std::string> quotaIssuerNodes;
    {
        CSingleLock lock(&m_lock, TRUE);
        for (const auto& circuit : m_circuits)
            if (circuit && circuit->m_k6QuotaIssuerCircuit &&
                circuit->State() != CircuitState::Destroyed &&
                circuit->m_firstHopClient &&
                circuit->m_firstHopClient->HasEseNodePub())
                quotaIssuerNodes.insert(K6BinaryKey(
                    circuit->m_firstHopClient->GetEseNodePub(), 32));
    }
    std::vector<CUpDownClient*> peers;
    if (theApp.clientlist)
        theApp.clientlist->GetConnectedSnapshot(peers, kad6::kK6PathMaxCandidates,
                                                /*tunnelOnly=*/true);
    if (peers.size() < kad6::kK6StrictHopCount)
        return false;
    Kademlia::CKad6RoutingTable* routes = Kademlia::CKademlia::GetKad6RoutingTable();
    if (!routes || !routes->HasAsnDatabase())
        return false;

    std::vector<kad6::K6PathCandidate> candidates;
    std::vector<CUpDownClient*> candidatePeers;
    candidates.reserve(peers.size()); candidatePeers.reserve(peers.size());
    for (CUpDownClient* peer : peers) {
        if (!peer || !peer->socket || !peer->socket->IsConnected()
            || !peer->HasValidHash() || !peer->HasEseNodePub()
            || quotaIssuerNodes.find(K6BinaryKey(peer->GetEseNodePub(), 32)) !=
                quotaIssuerNodes.end())
            continue;
        kad6::Kad6Address verifiedAddress;
        kad6::K6AsnInfo asn;
        if (!routes->LookupVerifiedIdentity(peer->GetEseNodePub(),
                                            verifiedAddress, asn))
            continue;
		bool endpointMatches = false;
		if (verifiedAddress.family == kad6::Kad6Address::Family::IPv6) {
			endpointMatches = peer->HasIPv6Address()
				&& memcmp(peer->GetIPv6Address().Data(),
					verifiedAddress.addr.data(), 16) == 0;
		} else if (verifiedAddress.family == kad6::Kad6Address::Family::IPv4) {
			const uint32 peerIp = peer->GetIP();
			endpointMatches = peerIp != 0
				&& memcmp(&peerIp, verifiedAddress.addr.data(), 4) == 0;
		}
		if (!endpointMatches)
			continue;
        kad6::K6PathCandidate candidate;
        memcpy(candidate.node_pub.data(), peer->GetEseNodePub(), 32);
        memcpy(candidate.user_hash.data(), peer->GetUserHash(), 16);
        candidate.address = verifiedAddress;
        candidate.asn = asn.asn;
        candidate.operator_group = asn.operator_group;
        const INT_PTR queued = peer->socket->GetControlQueueCount();
        candidate.weight = static_cast<uint32_t>(queued >= TUNNEL_EGRESS_MAX_QUEUED_CELLS
            ? 1 : TUNNEL_EGRESS_MAX_QUEUED_CELLS - queued);
        candidate.authenticated = peer->SupportsEseTunnelAuth();
        candidate.endpoint_verified = true;
        candidate.connected = true;
        candidate.supports_strict3 = peer->SupportsEseTunnelStrict3()
            && peer->SupportsEseTunnelDataplane();
        candidate.supports_shaping = peer->SupportsEseTunnelShaped()
            && peer->SupportsEseTunnelBulk();
        candidate.supports_exit =
            (peer->GetEseCapabilities() & ESE_CAP_KAD6) != 0;
        candidate.has_capacity = queued < TUNNEL_EGRESS_MAX_QUEUED_CELLS / 2;
        candidate.current_content_peer = theApp.liveStreamManager
            && theApp.liveStreamManager->IsStreamSourcePeer(peer);
		routes->ApplyPathEvidence(candidate.node_pub.data(),
			static_cast<std::uint64_t>(time(NULL)), candidate);
        candidates.push_back(candidate);
        candidatePeers.push_back(peer);
    }

    const bool havePinnedGuard = LoadK6Guard();
    kad6::K6StrictPath selected;
    kad6::K6NetworkPathPolicy networkPolicy;
    networkPolicy.require_multi_vantage = true;
    networkPolicy.fail_closed = true;
    const kad6::K6PathStatus status = kad6::SelectK6StrictPathV2(
        candidates, havePinnedGuard ? m_k6GuardNodePub.data() : NULL,
        networkPolicy, EseK6PathRandom, NULL, selected);
    if (status != kad6::K6PathStatus::Ok) {
        AddDebugLogLine(false, _T("Kad6 K6-6: STRICT path blocked (%hs) -- no diversity relaxation/fallback"),
                        kad6::K6PathStatusName(status));
        return false;
    }

    CUpDownClient* guard = candidatePeers[selected.index[0]];
    CUpDownClient* middle = candidatePeers[selected.index[1]];
    CUpDownClient* exit = candidatePeers[selected.index[2]];
    if (!havePinnedGuard) {
        const uint64_t expiry = static_cast<uint64_t>(time(NULL)) + 7ull * 24 * 60 * 60;
        if (!SaveK6Guard(guard->GetEseNodePub(), expiry))
            return false; // a STRICT guard must survive restart before use
    }

    size_t before = 0;
    { CSingleLock lk(&m_lock, TRUE); before = m_circuits.size(); }
    std::vector<CUpDownClient*> first{guard};
    if (BuildPool(NULL, first, 1) == 0)
        return false;
    CSingleLock lk(&m_lock, TRUE);
    std::shared_ptr<CLiveCircuit> circuit;
    for (size_t i = before; i < m_circuits.size(); ++i) {
        const std::shared_ptr<CLiveCircuit>& candidate = m_circuits[i];
        if (candidate && candidate->m_role == CircuitRole::Originator
            && candidate->m_firstHopClient == guard
            && candidate->State() == CircuitState::Pending) {
            circuit = candidate;
            break;
        }
    }
    if (!circuit) return false;
    circuit->m_strict3 = true;
    circuit->m_path_diverse = true;
    circuit->m_pendingHopClients.push_back(middle);
    circuit->m_pendingHopClients.push_back(exit);
    if (circuitId) *circuitId = circuit->Id();
    return true;
}

bool CLiveTunnel::ContinueOriginatorBuild(std::shared_ptr<CLiveCircuit>& circ)
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
            EseTryResolveExitKadKey(target, *circ);
        }
        if (BuildExtend(circ, target))
            return true;

        if (circ->m_private2 || circ->m_strict3) {
            AddDebugLogLine(false, _T("Kad6: %s circ=0x%08x build aborted at hop %u -- prefix is never reusable"),
                            circ->m_strict3 ? _T("STRICT") : _T("PRIVATE"),
                            circ->Id(), static_cast<unsigned>(circ->HopCount() + 1));
            DestroyCircuitFailClosed(circ);
            return false;
        }
        // Explicit diagnostic/legacy construction may retain its authenticated
        // prefix. Production Private and Strict never reach this arm.
        circ->SetState(CircuitState::Active);
        circ->m_haveExitKadKey = false;
        EseTryResolveExitKadKey(circ->m_firstHopClient, *circ);
        Kademlia::CKadV2TunnelPool::Get().RegisterTunnel(circ);
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
        DestroyCircuitFailClosed(circ);
        return false;
    }
    circ->SetState(CircuitState::Active);
    if (circ->m_auth_ok)
        AddDebugLogLine(false, _T("LiveTunnel: authenticated circuit ACTIVE circ=0x%08x hops=%u%s"),
                        circ->Id(), static_cast<unsigned>(circ->HopCount()),
                        circ->m_strict3 ? _T(" STRICT3") : _T(""));
    Kademlia::CKadV2TunnelPool::Get().RegisterTunnel(circ);
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
    const uint8_t* nodePub     = (v3req || v2req) ? NodeIdentityPub() : NULL;
    const bool     v3          = v3req && (nodePub != NULL);
    const bool     v2          = !v3 && v2req && (nodePub != NULL);
    const uint8_t* createNonce = (v3 || v2) ? (payload + 53) : NULL;
    const uint32_t originCircId = v3 ? eseRdU32LE(payload + 69) : circId;
    const uint8_t  hopIndex = v3 ? payload[73] : 0;
    const uint8_t* prefixHash = v3 ? payload + 74 : NULL;
    const uint16_t shapeBucketKiB = v3 ? eseRdU16LE(payload + 138) : 0;
    if (v3) {
        size_t reservedLinks = 0;
        for (const auto& existing : m_circuits)
            if (existing->m_role == CircuitRole::Relay
                && existing->State() != CircuitState::Destroyed
                && existing->m_shape_bucket_kib != 0)
                ++reservedLinks;
        if (originCircId == 0 || hopIndex >= 3
            || memcmp(payload + 106, nodePub, 32) != 0
            || (hopIndex == 0 && originCircId != circId)
            || !K6ShapeValidBucket(shapeBucketKiB)
            || (g_uEseCapsRuntime & ESE_CAP_TUNNEL_SHAPED) == 0
            || reservedLinks >= K6_SHAPE_MAX_RESERVED_LINKS) {
            AddDebugLogLine(false, _T("LiveTunnel: CREATE v3 context/target mismatch -- dropping"));
            return false;
        }
    }
    const uint32_t signedCaps  = g_uEseCapsRuntime;

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
    c->m_shaped_ok = v3 && (signedCaps & ESE_CAP_TUNNEL_SHAPED) != 0;
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
        if (!NodeIdentitySign(transcript, transcriptLen, sig))
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
    if (!SendCellToPeer(fromPeer, cell))
        return false;

    // This relay leg completed the signed CREATED-v2/v3 protocol. Publish
    // it only after the response was queued so snapshots cannot show an
    // ACTIVE ghost or strict3=true/auth_ok=false for an authenticated leg.
    c->m_auth_ok = v3 || v2;
    c->SetState(CircuitState::Active);
    m_circuits.push_back(c);
    return true;
}

// === DoS hardening — CREATE handshake admission gate =======================
// A CELL_CREATE costs us an X25519 keypair + DH + HKDF on the MAIN thread and
// requires NO prior state from the sender — the classic Tor CREATE-flood. The
// gate runs before any crypto. All caps are deliberately GENEROUS: clipping a
// legitimate peer is worse than letting a mild flood through (the per-cell
// cost is sub-millisecond; only sustained floods matter).
namespace {
const DWORD CREATE_GATE_WINDOW_MS = 5000;
// Per source IP: a legit neighbour sends ~1-2 CREATEs per pool build (the
// pool's 3-5 circuits are spread over DISTINCT relays) plus one per rotation
// (every ~5 min, TUNNEL_ROTATION_BASE_MS), plus hop1->hop2 forwarded CREATEs
// when the neighbour relays for several viewers at once. 15 per 5 s window
// (3/s sustained) is ~2 orders of magnitude above that worst legit case.
const uint32_t CREATE_GATE_MAX_PER_IP = 15;
// Global, all sources: bounds total handshake crypto at 20/s no matter how
// distributed the flood is (~well under 2% of the main thread). Legit global
// load is viewers rotating 5-min pools through us: 20/s sustained covers
// thousands of simultaneous tunnels — far beyond this network's scale.
const uint32_t CREATE_GATE_MAX_GLOBAL = 100;
// Concurrent relay-side circuits ("concurrent handshakes": the handshake
// itself completes synchronously inside HandleCreate_Relay, so the durable
// per-CREATE cost is the circuit registered in m_circuits — memory plus the
// linear scan every incoming cell pays). Tick() reaps every circuit after
// the 5-min rotation, so this also bounds a slow drip-flood. 512 concurrent
// relay circuits = hundreds of simultaneous viewers tunneling through us.
const size_t CREATE_GATE_MAX_RELAY_CIRCS = 512;

struct CreateRateSlot {
    uint32_t srcIp;        // full source IP (network order)
    uint32_t count;
    DWORD    windowStart;  // 0 = slot free
};
static CreateRateSlot s_createRates[32] = {};
static uint32_t s_createGlobalCount  = 0;
static DWORD    s_createGlobalWindow = 0;

// Counts this CREATE against the per-IP and global windows; returns true if
// it may proceed to the X25519 handshake. Main thread only (called from
// OnCellReceived). Sliding-window open-addressed cache, same pattern as the
// /24 OP_LIVE_REQUEST limiter in LiveStreamManager.cpp.
bool CreateGateAdmit(uint32_t ipNet)
{
    const DWORD now = ::GetTickCount();
    if (now - s_createGlobalWindow > CREATE_GATE_WINDOW_MS) {
        s_createGlobalWindow = now;
        s_createGlobalCount  = 0;
    }
    if (++s_createGlobalCount > CREATE_GATE_MAX_GLOBAL)
        return false;
    int slot = -1, freeSlot = -1;
    uint32_t h = (ipNet * 0x9E3779B1u) % _countof(s_createRates);
    for (uint32_t i = 0; i < _countof(s_createRates); ++i) {
        uint32_t idx = (h + i) % _countof(s_createRates);
        if (s_createRates[idx].srcIp == ipNet && s_createRates[idx].windowStart != 0) {
            slot = (int)idx; break;
        }
        if (s_createRates[idx].windowStart == 0 && freeSlot == -1) freeSlot = (int)idx;
        // Reuse expired slots
        if (s_createRates[idx].windowStart != 0 && now - s_createRates[idx].windowStart > CREATE_GATE_WINDOW_MS * 4) {
            if (freeSlot == -1) freeSlot = (int)idx;
        }
    }
    if (slot >= 0) {
        if (now - s_createRates[slot].windowStart > CREATE_GATE_WINDOW_MS) {
            s_createRates[slot].windowStart = now;
            s_createRates[slot].count = 1;
        } else if (++s_createRates[slot].count > CREATE_GATE_MAX_PER_IP) {
            return false;
        }
    } else if (freeSlot >= 0) {
        s_createRates[freeSlot].srcIp = ipNet;
        s_createRates[freeSlot].windowStart = now;
        s_createRates[freeSlot].count = 1;
    }
    return true;
}
}  // namespace

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
        if (!fromPeer) return false;   // HandleCreate_Relay would reject anyway
        // DoS hardening: admission gate BEFORE the X25519 work (see the
        // constants above). Drops are silent on the wire — V's circuit just
        // times out, exactly as if we were a vanilla 0.70b peer ignoring the
        // opcode — and the debug log is throttled so a flood can't flood it.
        bool admit = CreateGateAdmit(fromPeer->GetIP());
        if (admit) {
            size_t relayCircs = 0;
            for (const auto& c : m_circuits)
                if (c->m_role == CircuitRole::Relay) ++relayCircs;
            if (relayCircs >= CREATE_GATE_MAX_RELAY_CIRCS) admit = false;
        }
        if (!admit) {
            static DWORD s_lastGateLog = 0;
            if (::GetTickCount() - s_lastGateLog > 30000) {
                s_lastGateLog = ::GetTickCount();
                const uint32_t ip = fromPeer->GetIP();
                AddDebugLogLine(false,
                    _T("LiveTunnel: CREATE admission gate dropping handshake(s), last from %u.%u.%u.%u (DoS protection)"),
                    ip & 0xFF, (ip >> 8) & 0xFF, (ip >> 16) & 0xFF, (ip >> 24) & 0xFF);
            }
            return true;   // consumed: silently dropped
        }
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
            if (fromPeer != relayCirc->m_nextHopClient) return false;
            return ForwardCreatedAsExtended_Relay(circ_id, payload, payloadLen);
        }
    }

    if (cmd == CELL_EXTENDED) {
        auto relayCirc = FindRelayByOutgoingId(circ_id);
        if (relayCirc) {
            if (fromPeer != relayCirc->m_nextHopClient) return false;
            return ForwardExtendedCell_Reverse(relayCirc, payload, payloadLen);
        }
    }

    // DESTROY is directional even though it has no encrypted payload. An
    // outbound id identifies a close travelling back from the next hop;
    // forward it only to the bound previous transport peer and retire this
    // mapping. A failed STRICT3 prefix must not survive at guard or middle.
    if (cmd == CELL_DESTROY) {
        auto relayCirc = FindRelayByOutgoingId(circ_id);
        if (relayCirc) {
            if (fromPeer != relayCirc->m_nextHopClient) return false;
            uint8_t destroy[CELL_TOTAL_BYTES];
            if (relayCirc->m_prevHopClient
                && CellPack(relayCirc->Id(), CELL_DESTROY, NULL, 0, destroy))
                SendCellToPeer(relayCirc->m_prevHopClient, destroy);
            relayCirc->SetState(CircuitState::Destroyed);
            relayCirc->WipeKeys();
            return true;
        }
    }

    // v8.1.1 F-1 — reverse 2-hop DATA forwarding. A CELL_RELAY arriving on a
    // relay's OUTBOUND id (m_nextCircId) is a data cell coming back from hop2/exit;
    // re-add our hop1->V layer and relay it to V. Looked up BEFORE the by-Id lookup
    // (the outbound id is not a circuit Id on this node), mirroring CELL_CREATED above.
    if (cmd == CELL_RELAY) {
        auto relayCirc = FindRelayByOutgoingId(circ_id);
        if (relayCirc) {
            if (fromPeer != relayCirc->m_nextHopClient) return false;
            return ForwardRelayCell_Reverse(relayCirc, payload, payloadLen);
        }
    }

    // All other cells require an existing circuit entry by circ_id
    // (originator's V-side id, or relay-side from-V id).
    std::shared_ptr<CLiveCircuit> circ;
    for (auto& c : m_circuits)
        if (c->Id() == circ_id) { circ = c; break; }
    if (!circ) return false;
    if (circ->m_role == CircuitRole::Originator) {
        if (fromPeer != circ->m_firstHopClient) return false;
    } else if (fromPeer != circ->m_prevHopClient) {
        return false;
    }

    switch (cmd) {
        case CELL_CREATED:
            // Originator-side CREATED for hop1.
            if (circ->m_role != CircuitRole::Originator) return false;
            return HandleCreated_Originator(circ, payload, payloadLen);

        case CELL_EXTEND:
            // v0.71 B — relay receives EXTEND from V, forwards to hop2.
            if (circ->m_role != CircuitRole::Relay) return false;
            if (circ->m_nextHopClient)
                return ForwardExtendCell_Forward(circ, payload, payloadLen);
            return HandleExtend_Relay(circ, payload, payloadLen);

        case CELL_EXTENDED:
            // v0.71 B — originator receives EXTENDED back, derives hop2 keys.
            if (circ->m_role != CircuitRole::Originator) return false;
            return HandleExtended_Originator(circ, payload, payloadLen);

        case CELL_RELAY:
            // v8.1.1 F-1 — if we are an INTERMEDIATE relay (hop1) of a TRUE 2-hop
            // circuit (m_nextHopClient set, non-loopback), forward toward hop2/exit by
            // peeling exactly ONE layer — never terminate. This is what makes the exit
            // NOT see V's IP (G1). A 1-hop exit or loopback exit has m_nextHopClient
            // NULL and still terminates via HandleRelay_Exit below.
            if (circ->m_role == CircuitRole::Relay && circ->m_nextHopClient) {
                return ForwardRelayCell_Forward(circ, payload, payloadLen);
            }
            // v0.71 C — data plane delivery (terminating end).
            // Originator: peel ALL hops, parse TunnelOp, deliver.
            // Exit (1-hop, or loopback holding V↔hop2 keys): peel all hops,
            //   dispatch the inner payload, wrap reply, send back to V.
            if (circ->m_role == CircuitRole::Originator) {
                return HandleRelay_Originator(circ, payload, payloadLen);
            } else {
                return HandleRelay_Exit(circ, payload, payloadLen);
            }

        case CELL_DESTROY:
            // Arrived from the previous peer on our inbound id. Drain the
            // remaining forward prefix before deleting this local mapping.
            if (circ->m_role == CircuitRole::Relay && circ->m_nextHopClient
                && circ->m_nextCircId != 0) {
                uint8_t destroy[CELL_TOTAL_BYTES];
                if (CellPack(circ->m_nextCircId, CELL_DESTROY, NULL, 0, destroy))
                    SendCellToPeer(circ->m_nextHopClient, destroy);
            }
            circ->SetState(CircuitState::Destroyed);
            circ->WipeKeys();
            return true;

        case CELL_PADDING: {
            // Cover traffic. The originator OnionEncrypt'd this cell, which
            // advanced its per-hop nonce_send counter. We MUST peel it here
            // so our nonce_recv stays in lockstep: the ChaCha20-Poly1305
            // nonce is an implicit counter (not on the wire), so a dropped
            // cell desyncs it and the next real CELL_RELAY fails AEAD auth.
            // The decrypted plaintext is random padding and is discarded.
            if (circ->m_role == CircuitRole::Relay) {
                // A three-hop origin wrapped one layer for every relay. An
                // intermediate must consume exactly its own layer and carry
                // the same PADDING command onward; terminating it at the guard
                // would leave the middle/exit implicit nonce counters stale.
                if (circ->m_nextHopClient)
                    return ForwardPaddingCell_Forward(circ, payload, payloadLen);
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
                              CUpDownClient* target)
{
    // Caller holds m_lock.
    if (!circ || !target || circ->m_role != CircuitRole::Originator
        || circ->HopCount() < 1 || circ->HopCount() >= 3
        || circ->m_have_ephemeral)
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
        && target->HasEseNodePub() && NodeIdentityPub() != NULL;
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
        if (hopIndex != 1) {
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
    if (!circ->m_firstHopClient || !SendCellToPeer(circ->m_firstHopClient, cell)) {
        SecureWipe(circ->m_ephemeral_priv, sizeof circ->m_ephemeral_priv);
        circ->m_have_ephemeral = false;
        return false;
    }

    // Move state from Active (1-hop) back to "extending" — we represent
    // that as HalfBuilt to signal "more than just hop1 in flight". When
    // EXTENDED arrives we promote to Active again.
    circ->m_extendStartedTick = GetTickCount();
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
        const uchar* ourHash = thePrefs.GetUserHash();
        const uint8_t* ourNodePub = NodeIdentityPub();
        if ((ourHash && kad6::Kad6CtEqual(ourHash, targetHash, 16))
            || (ourNodePub && kad6::Kad6CtEqual(ourNodePub, targetNodePub, 32))) {
            SecureWipe(extendPlain, sizeof extendPlain); // no loopback in v3
            return false;
        }

        CUpDownClient* target = theApp.clientlist
            ? theApp.clientlist->FindClientByUserHash(targetHash) : NULL;
        if (!target || !target->socket || !target->socket->IsConnected()
            || target->GetUserPort() != targetPort || !target->HasEseNodePub()
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
        } else if (target->GetIP() != eseRdU32LE(extendPlain + 6)) {
            SecureWipe(extendPlain, sizeof extendPlain);
            return false;
        }

        uint32_t outId = 0;
        for (int attempt = 0; attempt < 4; ++attempt) {
            outId = NewCircuitId();
            bool collision = false;
            for (const auto& candidate : m_circuits)
                if (candidate->Id() == outId || candidate->m_nextCircId == outId) {
                    collision = true; break;
                }
            if (!collision) break;
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
            || !SendCellToPeer(target, cell)) {
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
        const uchar* ourHash = thePrefs.GetUserHash();
        if (!hashAllZero && ourHash && memcmp(hop2HashIn, ourHash, 16) == 0)
            isLoopback = true;
    }
    // Legacy fallback: public-IP match (pre-hash peers / same-WAN setups).
    if (!isLoopback && theApp.GetPublicIP() != 0 && hop2_ip == theApp.GetPublicIP())
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
    if (!circ->m_prevHopClient || !SendCellToPeer(circ->m_prevHopClient, cell))
        return false;
    return true;
}

bool CLiveTunnel::ForwardExtendCell_Forward(std::shared_ptr<CLiveCircuit>& circ,
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
    return SendCellToPeer(circ->m_nextHopClient, cell);
}

bool CLiveTunnel::ForwardPaddingCell_Forward(std::shared_ptr<CLiveCircuit>& circ,
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
    if (!CellPack(circ->m_nextCircId, CELL_PADDING, inner, innerLen, cell))
        return false;
    return SendCellToPeer(circ->m_nextHopClient, cell);
}

bool CLiveTunnel::ForwardExtendedCell_Reverse(std::shared_ptr<CLiveCircuit>& circ,
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
    return SendCellToPeer(circ->m_prevHopClient, cell);
}

bool CLiveTunnel::HandleExtended_Originator(std::shared_ptr<CLiveCircuit>& circ,
                                            const uint8_t* payload, uint16_t payloadLen)
{
    // Caller holds m_lock. circ is the V-side circuit. The cell payload
    // is the wrapped er_pub2 (32+16 tag = 48B).
    if (!circ || circ->m_role != CircuitRole::Originator) return false;
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
        DestroyCircuitFailClosed(circ); // strict: refuse an unsigned hop2
        SecureWipe(plain, sizeof plain);
        return false;
    }
    if (circ->m_strict3 && !v3) {
        AddDebugLogLine(false, _T("Kad6 K6-6: STRICT circ=0x%08x rejected EXTENDED downgrade below v3"), circ->Id());
        DestroyCircuitFailClosed(circ);
        SecureWipe(plain, sizeof plain);
        return false;
    }
    if (v3 && !K6ShapeValidBucket(circ->m_shape_bucket_kib)) {
        DestroyCircuitFailClosed(circ);
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
            DestroyCircuitFailClosed(circ);
            SecureWipe(plain, sizeof plain);
            return false;
        }
        // (2) Strict caps floor.
        const uint32_t capsFloor = ESE_CAP_TUNNEL_AUTH
            | (circ->m_strict3 ? (ESE_CAP_TUNNEL_STRICT3 | ESE_CAP_TUNNEL_SHAPED) : 0);
        if ((TunnelAuthStrict() || circ->m_private2 || circ->m_strict3)
            && (signedCaps2 & capsFloor) != capsFloor) {
            AddDebugLogLine(false, _T("LiveTunnel: v2 AUTH-ABORT hop2 circ=0x%08x reason=CAPS_FLOOR (exit signed_caps lacks TUNNEL_AUTH)"), circ->Id());
            DestroyCircuitFailClosed(circ);
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
            DestroyCircuitFailClosed(circ);
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
        && (signedCaps2 & ESE_CAP_TUNNEL_SHAPED) != 0;
    circ->m_exit_signed_caps = (circ->m_auth_ok && authenticated
        && circ->m_pendingHopClients.empty()) ? signedCaps2 : 0;

    SecureWipe(circ->m_ephemeral_priv, sizeof circ->m_ephemeral_priv);
    circ->m_have_ephemeral = false;
    SecureWipe(shared, sizeof shared);
    SecureWipe(okm, sizeof okm);
    SecureWipe(plain, sizeof plain);

    circ->m_extendExpectedNodePubSet = false;
    circ->m_extendStartedTick = 0;
    circ->SetState(CircuitState::Active);
    return ContinueOriginatorBuild(circ);
}

uint32_t CLiveTunnel::BuildTestCircuit2Hop()
{
    // A two-hop request is fail-closed: it requires two distinct fork
    // identities. Never silently collapse it into the old self-loop test.
    std::vector<CUpDownClient*> forkCands;
    if (theApp.clientlist)
        theApp.clientlist->GetConnectedSnapshot(forkCands, 5, /*tunnelOnly=*/true);
    if (forkCands.size() < 2) return 0;

    CUpDownClient* hop1 = forkCands[0];
    CUpDownClient* hop2 = NULL;
    for (size_t i = 1; i < forkCands.size(); ++i) {
        CUpDownClient* candidate = forkCands[i];
        if (!candidate || candidate == hop1) continue;
        const uchar* firstHash = hop1->GetUserHash();
        const uchar* candidateHash = candidate->GetUserHash();
        if (firstHash && candidateHash && memcmp(firstHash, candidateHash, 16) == 0)
            continue;
        hop2 = candidate;
        break;
    }
    if (!hop2) return 0;

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
    c->m_pendingHopClients.push_back(hop2);
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
        s.auth_ok      = c->m_auth_ok ? 1 : 0;   // v8.x Phase 2 — drives the panel "Auth" column
        s.strict3      = c->m_strict3 ? 1 : 0;
        s.shaped       = (c->m_shaped_ok || c->m_shape_bucket_kib != 0) ? 1 : 0;
        s.shaping_exposed = c->m_traffic_shaping_exposed ? 1 : 0;
        out.push_back(s);
    }
}

void CLiveTunnel::GetK6HardeningSnapshot(K6HardeningRuntimeSnapshot& out)
{
    out = K6HardeningRuntimeSnapshot{};
    out.control = m_k6Hardening.Snapshot();
    out.metrics = m_k6Metrics.WindowInfo(static_cast<uint64>(time(NULL)));
    {
        CSingleLock pl(&m_pendingLock, TRUE);
        for (const auto& pair : m_k6SourceLeases.Entries())
            if (pair.second.state != kad6::K6SourceLeaseState::Closed)
                ++out.active_leases;
        out.active_publishes = static_cast<uint64>(m_k6Publishes.size());
        for (const auto& pair : m_k6ExitStreams) {
            if (pair.second.inbound) ++out.full_streams;
            else ++out.dial_streams;
        }
        out.source_epoch_store_failed = m_k6SourceEpochsLoadFailed;
        out.economy_measurement_ready = m_k6EconomyReady;
        for (size_t i = 0; i < out.economy.size(); ++i) {
            out.rho[i] = m_k6EconomyReady ? kad6::K6Rho(m_k6EconomyInputs[i]) :
                std::numeric_limits<double>::infinity();
            out.economy[i] = m_k6EconomyTelemetry.Latest(static_cast<kad6::Byte>(i));
        }
        // A local process can never self-certify the 30-day supply, top-five
        // loss and external quota-audit gates. Those explicit evidence bits
        // remain false here, so the default cannot silently flip itself.
        kad6::K6StrictReleaseEvidence evidence;
        kad6::K6SupplyInputs supply;
        out.strict_recommended = kad6::K6MayRecommendStrictObserved(
            0, supply, out.economy[static_cast<size_t>(kad6::K6Service::ExitEd2kFull)],
            evidence);
    }
    {
        CSingleLock lock(&m_lock, TRUE);
        for (const auto& circuit : m_circuits)
            if (circuit && circuit->m_traffic_shaping_exposed)
                ++out.shaping_exposed_circuits;
    }
}

namespace {
CString K6ReleaseEvidencePath()
{
    return thePrefs.GetMuleDirectory(EMULE_CONFIGDIR) + _T("kad6_release_gate.dat");
}
}

bool CLiveTunnel::LoadK6ReleaseEvidence()
{
    CSingleLock release(&m_k6ReleaseLock, TRUE);
    m_k6ReleaseEvidenceLoaded = true;
    m_k6ReleaseEvidencePresent = false;
    m_k6ReleaseEvidence = kad6::K6ReleaseEvidence{};
    try {
        CFile file;
        if (!file.Open(K6ReleaseEvidencePath(), CFile::modeRead | CFile::shareDenyWrite))
            return false;
        const ULONGLONG length = file.GetLength();
        if (length != kad6::kK6ReleaseEvidenceWireSize) {
            file.Close();
            m_k6ReleaseStatus = kad6::K6ReleaseGateStatus::BadEncoding;
            return false;
        }
        std::vector<uint8_t> wire(static_cast<size_t>(length));
        const bool read = file.Read(wire.data(), static_cast<UINT>(wire.size())) ==
            wire.size();
        file.Close();
        if (!read || kad6::DecodeK6ReleaseEvidence(wire.data(), wire.size(),
                m_k6ReleaseEvidence) != kad6::Kad6Status::Ok) {
            m_k6ReleaseStatus = kad6::K6ReleaseGateStatus::BadEncoding;
            return false;
        }
        m_k6ReleaseEvidencePresent = true;
        return true;
    } catch (CFileException* error) {
        error->Delete();
        m_k6ReleaseStatus = kad6::K6ReleaseGateStatus::BadEncoding;
        return false;
    }
}

bool CLiveTunnel::SaveK6ReleaseEvidence(const std::vector<uint8_t>& wire) const
{
    if (wire.size() != kad6::kK6ReleaseEvidenceWireSize) return false;
    const CString path = K6ReleaseEvidencePath();
    const CString temporary = path + _T(".new");
    try {
        CFile file(temporary, CFile::modeCreate | CFile::modeWrite |
                              CFile::shareExclusive);
        file.Write(wire.data(), static_cast<UINT>(wire.size()));
        file.Flush();
        file.Close();
        if (!MoveFileEx(temporary, path,
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
            DeleteFile(temporary);
            return false;
        }
        return true;
    } catch (CFileException* error) {
        error->Delete();
        DeleteFile(temporary);
        return false;
    }
}

void CLiveTunnel::RefreshK6PublicRelease(uint64 nowSeconds, uint32 drainSeconds)
{
    if (nowSeconds == 0) return;
    bool evidenceLoaded = false;
    {
        CSingleLock release(&m_k6ReleaseLock, TRUE);
        evidenceLoaded = m_k6ReleaseEvidenceLoaded;
    }
    if (!evidenceLoaded) LoadK6ReleaseEvidence();

    const bool optIn = thePrefs.GetKad6PublicExitOptIn();
    bool evidencePresent = false;
    kad6::K6ReleaseEvidence evidence;
    {
        CSingleLock release(&m_k6ReleaseLock, TRUE);
        evidencePresent = m_k6ReleaseEvidencePresent;
        evidence = m_k6ReleaseEvidence;
    }
    kad6::K6ReleaseGateStatus evidenceStatus = kad6::K6ReleaseGateStatus::Missing;
    if (evidencePresent && NodeIdentityPub() != NULL)
        evidenceStatus = kad6::EvaluateK6ReleaseEvidence(
            MakeKad6HostCryptoHooks(), evidence,
            NodeIdentityPub(), nowSeconds);

    bool shapingExposed = false;
    {
        CSingleLock lock(&m_lock, TRUE);
        for (const auto& circuit : m_circuits)
            if (circuit && circuit->m_traffic_shaping_exposed) {
                shapingExposed = true;
                break;
            }
    }
    bool runtimeHealthy = NodeIdentityIsPersistent() && m_k6TicketSecretReady &&
        m_k6EconomyReady && !m_k6SourceEpochsLoadFailed && !shapingExposed;
    if (runtimeHealthy) {
        CSingleLock pl(&m_pendingLock, TRUE);
        for (const kad6::K6SaturationInputs& input : m_k6EconomyInputs)
            if (!std::isfinite(kad6::K6Rho(input)) ||
                kad6::K6Rho(input) >= kad6::kK6RhoTarget) {
                runtimeHealthy = false;
                break;
            }
    }

    const kad6::K6ReleaseGateStatus status =
        !optIn ? kad6::K6ReleaseGateStatus::OperatorOptOut
        : evidenceStatus != kad6::K6ReleaseGateStatus::Ok ? evidenceStatus
        : !runtimeHealthy ? kad6::K6ReleaseGateStatus::RuntimeUnhealthy
        : kad6::K6ReleaseGateStatus::Ok;
    const bool shouldEnable = status == kad6::K6ReleaseGateStatus::Ok;
    bool previouslyEnabled = false;
    {
        CSingleLock release(&m_k6ReleaseLock, TRUE);
        m_k6ReleaseRuntimeHealthy = runtimeHealthy;
        m_k6ReleaseStatus = status;
        previouslyEnabled = m_k6PublicStableEnabled;
    }
    if (shouldEnable == previouslyEnabled) return;

    if (shouldEnable) {
        {
            CSingleLock release(&m_k6ReleaseLock, TRUE);
            m_k6PublicStableEnabled = true; // permits the controlled enable calls below
        }
        bool enabled = true;
        for (size_t i = 0; i < static_cast<size_t>(kad6::K6Service::Count); ++i)
            enabled = ApplyK6ServiceSwitch(static_cast<kad6::K6Service>(i), true, 0) && enabled;
        if (!enabled) {
            {
                CSingleLock release(&m_k6ReleaseLock, TRUE);
                m_k6PublicStableEnabled = false;
                m_k6ReleaseStatus = kad6::K6ReleaseGateStatus::RuntimeUnhealthy;
            }
            for (size_t i = 0; i < static_cast<size_t>(kad6::K6Service::Count); ++i)
                ApplyK6ServiceSwitch(static_cast<kad6::K6Service>(i), false, 0);
        }
    } else {
        {
            CSingleLock release(&m_k6ReleaseLock, TRUE);
            m_k6PublicStableEnabled = false;
        }
        for (size_t i = 0; i < static_cast<size_t>(kad6::K6Service::Count); ++i)
            ApplyK6ServiceSwitch(static_cast<kad6::K6Service>(i), false,
                                 drainSeconds);
    }
}

bool CLiveTunnel::ApplyK6PublicRelease(bool enable,
                                       const kad6::K6ReleaseEvidence* evidence,
                                       uint32 drainSeconds)
{
    const uint64 now = static_cast<uint64>(time(NULL));
    if (!enable) {
        thePrefs.SetKad6PublicExitOptIn(false);
        RefreshK6PublicRelease(now, drainSeconds);
        return !IsK6PublicReleaseEnabled();
    }
    if (!NodeIdentityIsPersistent() || NodeIdentityPub() == NULL) return false;
    if (evidence != NULL) {
        kad6::K6ReleaseEvidence candidate = *evidence;
        candidate.version = kad6::kK6ReleaseEvidenceVersion;
        memcpy(candidate.node_pub.data(), NodeIdentityPub(), candidate.node_pub.size());
        if (candidate.issued_at == 0) candidate.issued_at = now;
        if (candidate.valid_until == 0)
            candidate.valid_until = candidate.issued_at + 30ull * 24 * 60 * 60;
        std::vector<uint8_t> wire;
        if (kad6::SignK6ReleaseEvidence(MakeKad6HostCryptoHooks(), candidate, wire) !=
                kad6::Kad6Status::Ok ||
            kad6::EvaluateK6ReleaseEvidence(MakeKad6HostCryptoHooks(), candidate,
                NodeIdentityPub(), now) != kad6::K6ReleaseGateStatus::Ok ||
            !SaveK6ReleaseEvidence(wire))
            return false;
        {
            CSingleLock release(&m_k6ReleaseLock, TRUE);
            m_k6ReleaseEvidence = candidate;
            m_k6ReleaseEvidenceLoaded = true;
            m_k6ReleaseEvidencePresent = true;
        }
    }
    thePrefs.SetKad6PublicExitOptIn(true);
    RefreshK6PublicRelease(now, drainSeconds);
    return IsK6PublicReleaseEnabled();
}

void CLiveTunnel::GetK6ReleaseSnapshot(K6ReleaseRuntimeSnapshot& out)
{
    out = K6ReleaseRuntimeSnapshot{};
    out.operator_opt_in = thePrefs.GetKad6PublicExitOptIn();
    {
        CSingleLock release(&m_k6ReleaseLock, TRUE);
        out.evidence_present = m_k6ReleaseEvidencePresent;
        out.runtime_healthy = m_k6ReleaseRuntimeHealthy;
        out.public_exit_enabled = m_k6PublicStableEnabled;
        out.status = m_k6ReleaseStatus;
        out.evidence = m_k6ReleaseEvidence;
    }
    out.evidence_valid = out.evidence_present && NodeIdentityPub() != NULL &&
        kad6::EvaluateK6ReleaseEvidence(MakeKad6HostCryptoHooks(),
            out.evidence, NodeIdentityPub(), static_cast<uint64>(time(NULL))) ==
            kad6::K6ReleaseGateStatus::Ok;
}

bool CLiveTunnel::IsK6PublicReleaseEnabled() const
{
    CSingleLock release(&m_k6ReleaseLock, TRUE);
    return m_k6PublicStableEnabled;
}

bool CLiveTunnel::GetK6ReleaseOperatorChallenge(std::string& challenge)
{
    challenge.clear();
    const uint64 now = static_cast<uint64>(time(NULL));
    CSingleLock release(&m_k6ReleaseLock, TRUE);
    if (!m_k6ReleaseChallengeReady || m_k6ReleaseChallengeExpires <= now) {
        const kad6::Kad6CryptoHooks crypto = MakeKad6HostCryptoHooks();
        if (!crypto.random_bytes || !crypto.random_bytes(
                m_k6ReleaseChallenge.data(), m_k6ReleaseChallenge.size())) {
            m_k6ReleaseChallenge.fill(0);
            m_k6ReleaseChallengeExpires = 0;
            m_k6ReleaseChallengeReady = false;
            return false;
        }
        m_k6ReleaseChallengeExpires = now + 60;
        m_k6ReleaseChallengeReady = true;
    }
    static const char hex[] = "0123456789abcdef";
    challenge.resize(m_k6ReleaseChallenge.size() * 2);
    for (size_t i = 0; i < m_k6ReleaseChallenge.size(); ++i) {
        challenge[i * 2] = hex[m_k6ReleaseChallenge[i] >> 4];
        challenge[i * 2 + 1] = hex[m_k6ReleaseChallenge[i] & 0x0f];
    }
    return true;
}

bool CLiveTunnel::ConsumeK6ReleaseOperatorChallenge(const std::string& challenge)
{
    if (challenge.size() != m_k6ReleaseChallenge.size() * 2) return false;
    std::array<uint8_t, 32> decoded{};
    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (size_t i = 0; i < decoded.size(); ++i) {
        const int hi = nibble(challenge[i * 2]);
        const int lo = nibble(challenge[i * 2 + 1]);
        if (hi < 0 || lo < 0) return false;
        decoded[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    const uint64 now = static_cast<uint64>(time(NULL));
    CSingleLock release(&m_k6ReleaseLock, TRUE);
    const bool valid = m_k6ReleaseChallengeReady &&
        m_k6ReleaseChallengeExpires > now &&
        kad6::Kad6CtEqual(decoded.data(), m_k6ReleaseChallenge.data(), decoded.size());
    if (valid) {
        m_k6ReleaseChallenge.fill(0);
        m_k6ReleaseChallengeExpires = 0;
        m_k6ReleaseChallengeReady = false;
    }
    return valid;
}

namespace {
uint64 K6FileTimeValue(const FILETIME& value)
{
    return (static_cast<uint64>(value.dwHighDateTime) << 32) |
        static_cast<uint64>(value.dwLowDateTime);
}
}

void CLiveTunnel::RefreshK6EconomyMeasurements(uint64 nowSeconds,
    const std::array<uint64, static_cast<size_t>(kad6::K6Service::Count)>& active)
{
    if (nowSeconds == 0) return;
    const uint64 elapsed = m_k6EconomyLastSampleAt && nowSeconds > m_k6EconomyLastSampleAt
        ? nowSeconds - m_k6EconomyLastSampleAt : 1;
    const uint64 byteDelta = m_k6EconomyUsefulBytes >= m_k6EconomyLastUsefulBytes
        ? m_k6EconomyUsefulBytes - m_k6EconomyLastUsefulBytes : 0;
    const uint64 publishDelta = m_k6EconomyPublishAttempts >= m_k6EconomyLastPublishAttempts
        ? m_k6EconomyPublishAttempts - m_k6EconomyLastPublishAttempts : 0;

    // Configured/estimated upload is KiB/s. Divide by two because an exit moves
    // every useful byte once on the onion side and once on the exterior side.
    const double usefulCapacity = static_cast<double>(
        thePrefs.GetMaxGraphUploadRate(true)) * 1024.0 * 8.0 / 2.0;
    const double demandedBps = static_cast<double>(byteDelta) * 8.0 /
        static_cast<double>(elapsed);
    const double publishQps = static_cast<double>(publishDelta) /
        static_cast<double>(elapsed);

    double processCpu = 0.0;
    FILETIME created{}, exited{}, processKernel{}, processUser{};
    FILETIME idle{}, systemKernel{}, systemUser{};
    if (GetProcessTimes(GetCurrentProcess(), &created, &exited,
            &processKernel, &processUser) &&
        GetSystemTimes(&idle, &systemKernel, &systemUser)) {
        const uint64 processNow = K6FileTimeValue(processKernel) + K6FileTimeValue(processUser);
        const uint64 systemNow = K6FileTimeValue(systemKernel) + K6FileTimeValue(systemUser);
        if (m_k6EconomyLastProcessCpu && systemNow > m_k6EconomyLastSystemCpu &&
            processNow >= m_k6EconomyLastProcessCpu)
            processCpu = (std::min)(1.0, static_cast<double>(
                processNow - m_k6EconomyLastProcessCpu) /
                static_cast<double>(systemNow - m_k6EconomyLastSystemCpu));
        m_k6EconomyLastProcessCpu = processNow;
        m_k6EconomyLastSystemCpu = systemNow;
    }

    uint64 occupiedPreauth = 0;
    if (theApp.listensocket != NULL)
        occupiedPreauth = static_cast<uint64>(
            theApp.listensocket->GetK6PreAuthStats().active);

    CSingleLock pl(&m_pendingLock, TRUE);
    for (size_t i = 0; i < m_k6EconomyInputs.size(); ++i) {
        kad6::K6SaturationInputs input;
        input.demanded_useful_bps = (i == static_cast<size_t>(kad6::K6Service::ExitEd2kDial) ||
            i == static_cast<size_t>(kad6::K6Service::ExitEd2kFull)) ? demandedBps : 0.0;
        input.available_useful_bps = usefulCapacity;
        input.overhead_factor = 1.15;
        input.active_streams = active[i];
        input.available_stream_slots = i == static_cast<size_t>(kad6::K6Service::ExitKad)
            ? 4096u : 512u;
        input.occupied_preauth_slots = i == static_cast<size_t>(kad6::K6Service::ExitEd2kFull)
            ? occupiedPreauth : 0;
        input.available_preauth_slots = kad6::kK6PreAuthMaxSlots;
        input.demanded_publish_qps = i == static_cast<size_t>(kad6::K6Service::ExitKad)
            ? publishQps : 0.0;
        input.available_publish_qps = 2.0; // K6PublishBudget default: 120 / 60 s.
        input.measured_exit_cpu = processCpu;
        input.exit_cpu_budget = 0.85;
        m_k6EconomyInputs[i] = input;
        m_k6EconomyTelemetry.Observe(static_cast<kad6::Byte>(i), nowSeconds,
            kad6::K6Rho(input), false, false);
    }
    m_k6EconomyTelemetry.SealThrough(nowSeconds);
    m_k6EconomyLastUsefulBytes = m_k6EconomyUsefulBytes;
    m_k6EconomyLastPublishAttempts = m_k6EconomyPublishAttempts;
    m_k6EconomyLastSampleAt = nowSeconds;
    m_k6EconomyReady = usefulCapacity > 0.0;
}

bool CLiveTunnel::K6EconomyAdmit(kad6::K6Service service)
{
    const size_t index = static_cast<size_t>(service);
    if (index >= m_k6EconomyInputs.size()) return false;
    CSingleLock pl(&m_pendingLock, TRUE);
    const double rho = m_k6EconomyReady
        ? kad6::K6Rho(m_k6EconomyInputs[index])
        : std::numeric_limits<double>::infinity();
    const bool admitted = m_k6EconomyReady &&
        kad6::K6AdmitLease(m_k6EconomyInputs[index]);
    m_k6EconomyTelemetry.Observe(static_cast<kad6::Byte>(index),
        static_cast<uint64>(time(NULL)), rho, true, admitted);
    return admitted;
}

std::string CLiveTunnel::GetK6PrometheusMetrics()
{
    return m_k6Metrics.ExportPrometheus(static_cast<uint64>(time(NULL)));
}

bool CLiveTunnel::StartK6ExitNotice(uint16 port, kad6::K6ExitNotice notice)
{
    if (port == 0 || !NodeIdentityIsPersistent() || NodeIdentityPub() == NULL)
        return false;
    memcpy(notice.node_pub.data(), NodeIdentityPub(), notice.node_pub.size());
    std::string signedJson;
    if (kad6::SignK6ExitNotice(MakeKad6HostCryptoHooks(), notice, signedJson) !=
            kad6::Kad6Status::Ok)
        return false;
    m_k6ExitNoticeServer.Stop();
    return m_k6ExitNoticeServer.Start(port, signedJson);
}

void CLiveTunnel::StopK6ExitNotice() noexcept
{
    m_k6ExitNoticeServer.Stop();
}

K6ExitNoticeServerSnapshot CLiveTunnel::GetK6ExitNoticeSnapshot() const noexcept
{
    return m_k6ExitNoticeServer.Snapshot();
}

namespace {
std::string K6WideToUtf8(const wchar_t* value)
{
    if (!value || !*value) return std::string();
    const int length = WideCharToMultiByte(CP_UTF8, 0, value, -1,
        NULL, 0, NULL, NULL);
    if (length <= 1) return std::string();
    std::string result(static_cast<size_t>(length - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, value, -1, &result[0], length - 1,
        NULL, NULL);
    return result;
}
}

bool CLiveTunnel::EnsureK6QuotaAuthority(uint64 nowSeconds)
{
    if (!thePrefs.GetEseV9Experimental() ||
        (g_uEseCapsRuntime & ESE_CAP_KAD6) == 0 ||
        nowSeconds == 0 || !NodeIdentityIsPersistent() || NodeIdentityPub() == NULL)
        return false;
    if (!m_k6QuotaCrypto.Ready()) {
        if (m_k6QuotaInitAttempted) return false;
        m_k6QuotaInitAttempted = true;
        CString path = thePrefs.GetMuleDirectory(EMULE_CONFIGDIR);
        if (path.IsEmpty()) return false;
        const TCHAR last = path[path.GetLength() - 1];
        if (last != _T('\\') && last != _T('/')) path += _T('\\');
        path += _T("kad6_quota_rsa.dat");
        if (!m_k6QuotaCrypto.Initialize(K6WideToUtf8(path), 4096) ||
            !m_k6QuotaCrypto.Persistent())
            return false;
    }
    const uint64 epoch = kad6::K6QuotaEpoch(nowSeconds);
    if (m_k6QuotaCertificateEpoch != epoch || m_k6QuotaCertificateWire.empty()) {
        kad6::K6QuotaIssuerCertificate certificate;
        certificate.key = m_k6QuotaCrypto.PublicKey();
        memcpy(certificate.issuer_node_pub.data(), NodeIdentityPub(),
            certificate.issuer_node_pub.size());
        certificate.policy_id = 1;
        certificate.service_mask = 0x0F;
        certificate.valid_from_epoch = epoch;
        certificate.valid_until_epoch = epoch + 1;
        std::vector<uint8_t> encoded;
        if (kad6::SignK6QuotaIssuerCertificate(MakeKad6HostCryptoHooks(),
                certificate, encoded) != kad6::Kad6Status::Ok)
            return false;
        m_k6QuotaCertificate = std::move(certificate);
        m_k6QuotaCertificateWire = std::move(encoded);
        m_k6QuotaCertificateEpoch = epoch;
    }
    m_k6QuotaIssuerLimiter.Prune(epoch);
    m_k6QuotaSpent.Prune(epoch);
    volatile LONG* caps = reinterpret_cast<volatile LONG*>(&g_uEseCapsRuntime);
    ::InterlockedOr(caps, static_cast<LONG>(ESE_CAP_KAD6_ECONOMY));
    return true;
}

bool CLiveTunnel::K6QuotaPrincipal(const TunnelRequestCtx& ctx,
                                   kad6::Hash32& principal,
                                   std::array<uint8_t, 6>& prefix48,
                                   uint32& asn) const
{
    principal.fill(0);
    prefix48.fill(0);
    // Unknown ASNs share one deliberately conservative local bucket. This is
    // not an asserted ASN and never appears on wire or in public telemetry.
    asn = (std::numeric_limits<uint32>::max)();
    // Only v3 proves this terminal is hop 0. A terminal v2 circuit could be the
    // last hop of a longer path, in which case its direct neighbour is not A.
    if (!ctx.circ || ctx.circ->m_originCircContext == 0 ||
        ctx.circ->m_remoteHopIndex != 0 || ctx.circ->m_nextHopClient != NULL ||
        ctx.circ->m_prevHopClient == NULL || !m_k6TicketSecretReady)
        return false;
    CUpDownClient* peer = ctx.circ->m_prevHopClient;
    CAddress address;
    if (peer->socket != NULL) address = peer->socket->GetPeerCAddress();
    if (address.GetType() == CAddress::None && peer->HasIPv6Address())
        address = peer->GetIPv6Address();
    if (address.GetType() == CAddress::None && peer->GetConnectIP() != 0)
        address = CAddress(peer->GetConnectIP(), false);
    if (address.GetType() != CAddress::IPv4 && address.GetType() != CAddress::IPv6)
        return false;

    static const char domain[] = "eSE-Kad6-QuotaPrincipal-v1";
    std::vector<uint8_t> message(domain, domain + sizeof domain - 1);
    if (address.GetType() == CAddress::IPv4) {
        message.push_back(4);
        message.push_back(32);
        message.insert(message.end(), address.Data(), address.Data() + 4);
        prefix48[0] = 4;
        prefix48[1] = 32;
        memcpy(prefix48.data() + 2, address.Data(), 4);
    } else {
        // Aggregate at /48 so rotating /64s cannot multiply issuance. The raw
        // address and this local hash never leave the guard.
        message.push_back(6);
        message.push_back(48);
        message.insert(message.end(), address.Data(), address.Data() + 6);
        memcpy(prefix48.data(), address.Data(), prefix48.size());
        kad6::Kad6Address kadAddress;
        kadAddress.family = kad6::Kad6Address::Family::IPv6;
        memcpy(kadAddress.addr.data(), address.Data(), kadAddress.addr.size());
        Kademlia::CKad6RoutingTable* table = Kademlia::CKademlia::GetKad6RoutingTable();
        kad6::K6AsnInfo info;
        if (table && table->LookupAddressAsn(kadAddress, info)) asn = info.asn;
    }
    const kad6::Kad6CryptoHooks crypto = MakeKad6HostCryptoHooks();
    return crypto.hmac_sha256 && crypto.hmac_sha256(m_k6TicketSecret.data(),
        m_k6TicketSecret.size(), message.data(), message.size(), principal.data());
}

bool CLiveTunnel::K6QuotaIssuerTrusted(const uint8_t nodePub[32]) const
{
    if (!nodePub) return false;
    const uint8_t* own = NodeIdentityPub();
    if (own && kad6::Kad6CtEqual(own, nodePub, 32)) return true;
    Kademlia::CKad6RoutingTable* table = Kademlia::CKademlia::GetKad6RoutingTable();
    if (!table) return false;
    kad6::Kad6Address address;
    kad6::K6AsnInfo asn;
    return table->LookupVerifiedIdentity(nodePub, address, asn);
}

uint32 CLiveTunnel::K6SelectOriginCircuit(uint32 requiredCaps,
                                          uint32 pinnedCircId,
                                          size_t minimumHops) const
{
    CSingleLock lock(&m_lock, TRUE);
    for (const auto& circuit : m_circuits) {
        if (!circuit || (pinnedCircId != 0 && circuit->Id() != pinnedCircId) ||
            circuit->m_role != CircuitRole::Originator ||
            circuit->m_k6QuotaIssuerCircuit ||
            circuit->State() != CircuitState::Active ||
            circuit->HopCount() < minimumHops ||
            circuit->m_firstHopClient == NULL || !circuit->m_multicell_ok ||
            !circuit->m_auth_ok ||
            (circuit->m_exit_signed_caps & requiredCaps) != requiredCaps ||
            ((requiredCaps & ESE_CAP_TUNNEL_STRICT3) != 0 &&
             (!circuit->m_strict3 || !circuit->m_path_diverse ||
              !circuit->m_shaped_ok || circuit->HopCount() != 3)))
            continue;
        return circuit->Id();
    }
    return 0;
}

bool CLiveTunnel::K6CircuitHasExitCaps(uint32 circId,
                                       uint32 requiredCaps,
                                       size_t minimumHops) const
{
    return circId != 0 &&
        K6SelectOriginCircuit(requiredCaps, circId, minimumHops) == circId;
}

bool CLiveTunnel::K6QuotaRoundTrip(uint32 circId, uint8 msgType,
                                   const std::vector<uint8_t>& body,
                                   uint8 expectedMsgType, uint32 timeoutMs,
                                   kad6::K6Frame& response)
{
    response = kad6::K6Frame{};
    if (circId == 0 || timeoutMs == 0) return false;
    uint32 reqId = 0;
    PendingRequest* pending = RegisterPending(reqId);
    kad6::K6Frame request;
    request.msg_type = msgType;
    request.request_id = reqId;
    request.body = body;
    std::vector<uint8_t> wire;
    if (kad6::EncodeK6Frame(request, wire) != kad6::Kad6Status::Ok) {
        std::vector<uint8_t> ignored;
        WaitPending(reqId, pending, 0, ignored, NULL);
        return false;
    }
    const uint32 caps = ESE_CAP_KAD6 | ESE_CAP_KAD6_ECONOMY;
    {
        CSingleLock pl(&m_pendingLock, TRUE);
        pending->sub_cmd = TUN_OP_KAD6_GATEWAY;
        pending->required_exit_caps = caps;
        pending->request_msg = wire;
        pending->retries_left = 0;
    }
    EnqueueSendMsg(reqId, TUN_OP_KAD6_GATEWAY, wire.data(), wire.size(), caps,
        circId);
    std::vector<uint8_t> reply;
    if (!WaitPending(reqId, pending, timeoutMs, reply, NULL)) return false;
    size_t consumed = 0;
    return kad6::DecodeK6Frame(reply.data(), reply.size(), response, &consumed) ==
            kad6::Kad6Status::Ok && consumed == reply.size() &&
        response.request_id == reqId && response.session_id == 0 &&
        response.msg_type == expectedMsgType &&
        (response.flags & (kad6::kK6FlagResponse | kad6::kK6FlagFinal)) ==
            (kad6::kK6FlagResponse | kad6::kK6FlagFinal);
}

bool CLiveTunnel::K6AcquireAnonymousQuota(
    uint32 targetCircId, kad6::K6QuotaService service, uint8 operationMsgType,
    const std::vector<uint8_t>& operationBody, uint32 timeoutMs)
{
    if (targetCircId == 0 || timeoutMs < 3 ||
        !K6CircuitHasExitCaps(targetCircId,
            ESE_CAP_KAD6 | ESE_CAP_KAD6_ECONOMY, 2))
        return false;

    uint32 guardCircId = 0;
    {
        CSingleLock lock(&m_lock, TRUE);
        const CLiveCircuit* target = NULL;
        for (const auto& circuit : m_circuits)
            if (circuit && circuit->Id() == targetCircId && circuit->HopCount() != 0) {
                target = circuit.get();
                break;
            }
        if (!target) return false;
        const uint8_t* targetPub = target->Hop(target->HopCount() - 1).pub_long;
        for (const auto& circuit : m_circuits) {
            if (!circuit || circuit->Id() == targetCircId ||
                !circuit->m_k6QuotaIssuerCircuit ||
                circuit->m_role != CircuitRole::Originator ||
                circuit->State() != CircuitState::Active || circuit->HopCount() != 1 ||
                circuit->m_firstHopClient == NULL || !circuit->m_multicell_ok ||
                !circuit->m_auth_ok || circuit->m_shape_bucket_kib == 0 ||
                (circuit->m_exit_signed_caps &
                    (ESE_CAP_KAD6 | ESE_CAP_KAD6_ECONOMY |
                     ESE_CAP_TUNNEL_STRICT3)) !=
                    (ESE_CAP_KAD6 | ESE_CAP_KAD6_ECONOMY |
                     ESE_CAP_TUNNEL_STRICT3) ||
                kad6::Kad6CtEqual(circuit->Hop(0).pub_long, targetPub, 32))
                continue;
            guardCircId = circuit->Id();
            break;
        }
    }
    if (guardCircId == 0) return false;

    const uint32 stageTimeout = (std::max<uint32>)(1, timeoutMs / 3);
    kad6::K6Frame keyFrame;
    if (!K6QuotaRoundTrip(guardCircId, kad6::kK6MsgQuotaKeyReq,
            std::vector<uint8_t>(), kad6::kK6MsgQuotaKey, stageTimeout, keyFrame))
        return false;
    kad6::K6QuotaIssuerCertificate certificate;
    size_t consumed = 0;
    if (kad6::DecodeK6QuotaIssuerCertificate(keyFrame.body.data(), keyFrame.body.size(),
            certificate, &consumed) != kad6::Kad6Status::Ok ||
        consumed != keyFrame.body.size() ||
        (certificate.service_mask & (1u << static_cast<unsigned>(service))) == 0)
        return false;

    kad6::K6QuotaToken token;
    token.service = service;
    token.policy_id = certificate.policy_id;
    const uint64 now = static_cast<uint64>(time(NULL));
    token.valid_epoch = kad6::K6QuotaEpoch(now);
    token.subepoch_slot = kad6::K6QuotaSubepoch(now);
    token.issuer_key_id = certificate.key_id;
    const kad6::Kad6CryptoHooks identity = MakeKad6HostCryptoHooks();
    if (!identity.random_bytes ||
        !identity.random_bytes(token.admission_unit.data(), token.admission_unit.size()) ||
        kad6::K6QuotaContextHash(identity, operationMsgType, operationBody.data(),
            operationBody.size(), token.presentation_context_hash) !=
            kad6::Kad6Status::Ok)
        return false;
    kad6::K6QuotaBlindState blind;
    if (kad6::BlindK6QuotaToken(m_k6QuotaCrypto.Hooks(), certificate.key,
            token, blind) != kad6::Kad6Status::Ok)
        return false;

    kad6::K6QuotaBlindRequest issue;
    issue.issuer_key_id = certificate.key_id;
    issue.service = service;
    issue.subepoch_slot = token.subepoch_slot;
    issue.blinded_messages.push_back(blind.blinded_message);
    std::vector<uint8_t> issueBody;
    if (kad6::EncodeK6QuotaBlindRequest(issue, issueBody) != kad6::Kad6Status::Ok)
        return false;
    kad6::K6Frame issuedFrame;
    if (!K6QuotaRoundTrip(guardCircId, kad6::kK6MsgQuotaIssue, issueBody,
            kad6::kK6MsgQuotaIssued, stageTimeout, issuedFrame))
        return false;
    kad6::K6QuotaBlindResponse issued;
    consumed = 0;
    if (kad6::DecodeK6QuotaBlindResponse(issuedFrame.body.data(),
            issuedFrame.body.size(), issued, &consumed) != kad6::Kad6Status::Ok ||
        consumed != issuedFrame.body.size() || issued.status != kad6::K6QuotaStatus::Ok ||
        issued.blind_signatures.size() != 1 ||
        issued.issuer_certificate != keyFrame.body)
        return false;

    kad6::K6QuotaPresentation presentation;
    if (kad6::FinalizeK6QuotaToken(m_k6QuotaCrypto.Hooks(), certificate, blind,
            issued.blind_signatures[0], presentation) != kad6::Kad6Status::Ok)
        return false;
    std::vector<uint8_t> presentationBody;
    if (kad6::EncodeK6QuotaPresentation(presentation, presentationBody) !=
            kad6::Kad6Status::Ok)
        return false;
    kad6::K6Frame statusFrame;
    if (!K6QuotaRoundTrip(targetCircId, kad6::kK6MsgQuotaPresent,
            presentationBody, kad6::kK6MsgQuotaStatus, stageTimeout, statusFrame))
        return false;
    kad6::K6QuotaPresentationResult status;
    consumed = 0;
    kad6::Hash32 expectedUnitHash{};
    return kad6::DecodeK6QuotaPresentationResult(statusFrame.body.data(),
               statusFrame.body.size(), status, &consumed) == kad6::Kad6Status::Ok &&
        consumed == statusFrame.body.size() && status.status == kad6::K6QuotaStatus::Ok &&
        status.valid_epoch == token.valid_epoch && identity.sha256 &&
        identity.sha256(token.admission_unit.data(), token.admission_unit.size(),
            expectedUnitHash.data()) &&
        kad6::Kad6CtEqual(status.admission_unit_hash.data(), expectedUnitHash.data(),
            expectedUnitHash.size());
}

std::string CLiveTunnel::K6QuotaGrantKey(uint32 circId,
                                         const kad6::Hash32& context)
{
    std::string key(sizeof circId + context.size(), '\0');
    memcpy(&key[0], &circId, sizeof circId);
    memcpy(&key[sizeof circId], context.data(), context.size());
    return key;
}

bool CLiveTunnel::ConsumeK6QuotaGrant(const TunnelRequestCtx& ctx,
                                      kad6::K6QuotaService service,
                                      const kad6::K6Frame& frame,
                                      uint64* allocationId)
{
    if (allocationId) *allocationId = 0;
    kad6::Hash32 context;
    if (!ctx.circ || kad6::K6QuotaContextHash(MakeKad6HostCryptoHooks(),
            frame.msg_type, frame.body.data(), frame.body.size(), context) !=
            kad6::Kad6Status::Ok)
        return false;
    CSingleLock pl(&m_pendingLock, TRUE);
    const std::string key = K6QuotaGrantKey(ctx.circ->Id(), context);
    auto grant = m_k6QuotaGrants.find(key);
    if (grant == m_k6QuotaGrants.end()) return !IsK6PublicReleaseEnabled();
    if (grant->second.expires_at <= static_cast<uint64>(time(NULL)) ||
        grant->second.service != service) {
        m_k6FairScheduler.ReleaseAllocation(grant->second.allocation_id);
        m_k6QuotaGrants.erase(grant);
        return false;
    }
    if (allocationId) *allocationId = grant->second.allocation_id;
    else m_k6FairScheduler.ReleaseAllocation(grant->second.allocation_id);
    m_k6QuotaGrants.erase(grant);
    return true;
}

bool CLiveTunnel::QueueK6FairPayloadLocked(uint64 streamId, uint8 direction,
                                           std::vector<uint8_t>&& bytes,
                                           size_t creditBytes)
{
    if (streamId == 0 || direction > 1 || bytes.empty() ||
        m_k6FairAllocationByStream.find(streamId) == m_k6FairAllocationByStream.end())
        return false;
    std::deque<K6FairPayload>& queue = m_k6FairPayloads[streamId];
    uint64 streamBytes = 0;
    for (const K6FairPayload& payload : queue) streamBytes += payload.bytes.size();
    if (queue.size() >= 64 || streamBytes + bytes.size() > 2u * 1024u * 1024u ||
        m_k6FairPayloadBytes + bytes.size() > kad6::kK6FairMaxQueuedBytes)
        return false;
    {
        // Global lock order is pending -> tunnel. The timer is shared with
        // class-5, but the fair queue has independent state and payload caps.
        CSingleLock lock(&m_lock, TRUE);
        if (m_k6ShapeTimer == 0) {
            m_k6ShapeTimer = ::SetTimer(NULL, 0, 10, K6Class5TimerProc);
            if (m_k6ShapeTimer == 0) return false;
        }
    }
    if (!m_k6FairScheduler.Enqueue(streamId, bytes.size())) return false;
    K6FairPayload payload;
    payload.direction = direction;
    payload.credit_bytes = creditBytes;
    payload.bytes = std::move(bytes);
    m_k6FairPayloadBytes += payload.bytes.size();
    queue.push_back(std::move(payload));
    return true;
}

void CLiveTunnel::ReleaseK6FairStreamLocked(uint64 streamId)
{
    auto payloads = m_k6FairPayloads.find(streamId);
    if (payloads != m_k6FairPayloads.end()) {
        for (const K6FairPayload& payload : payloads->second)
            m_k6FairPayloadBytes -= (std::min<uint64>)(
                m_k6FairPayloadBytes, payload.bytes.size());
        m_k6FairPayloads.erase(payloads);
    }
    m_k6FairCredits.erase(streamId);
    m_k6FairScheduler.ReleaseStream(streamId);
    auto allocation = m_k6FairAllocationByStream.find(streamId);
    if (allocation != m_k6FairAllocationByStream.end()) {
        m_k6FairScheduler.ReleaseAllocation(allocation->second);
        m_k6FairAllocationByStream.erase(allocation);
    }
}

bool CLiveTunnel::ProcessK6FairTick()
{
    struct Ready {
        uint64 stream_id = 0;
        uint8 direction = 0;
        size_t credit_bytes = 0;
        std::vector<uint8_t> bytes;
    };
    std::vector<Ready> ready;
    {
        CSingleLock pl(&m_pendingLock, TRUE);
        const uint64 maxBytes = (std::max<uint64>)(1,
            static_cast<uint64>(thePrefs.GetMaxGraphUploadRate(true)) * 1024ull / 200ull);
        std::vector<kad6::K6FairGrant> grants;
        m_k6FairScheduler.Poll(maxBytes, 128, grants);
        std::set<uint64> touched;
        for (const kad6::K6FairGrant& grant : grants) {
            m_k6FairCredits[grant.stream_id] += grant.bytes;
            touched.insert(grant.stream_id);
        }
        for (uint64 streamId : touched) {
            auto queue = m_k6FairPayloads.find(streamId);
            if (queue == m_k6FairPayloads.end()) continue;
            uint64& credit = m_k6FairCredits[streamId];
            while (!queue->second.empty() &&
                   credit >= queue->second.front().bytes.size()) {
                K6FairPayload payload = std::move(queue->second.front());
                queue->second.pop_front();
                credit -= payload.bytes.size();
                m_k6FairPayloadBytes -= (std::min<uint64>)(
                    m_k6FairPayloadBytes, payload.bytes.size());
                Ready item;
                item.stream_id = streamId;
                item.direction = payload.direction;
                item.credit_bytes = payload.credit_bytes;
                item.bytes = std::move(payload.bytes);
                ready.push_back(std::move(item));
            }
            if (queue->second.empty()) {
                m_k6FairPayloads.erase(queue);
                if (credit == 0) m_k6FairCredits.erase(streamId);
            }
        }
    }

    std::set<uint64> failed;
    for (const Ready& item : ready) {
        K6ExitStreamRuntime runtime;
        bool found = false;
        {
            CSingleLock pl(&m_pendingLock, TRUE);
            auto stream = m_k6ExitStreams.find(item.stream_id);
            if (stream != m_k6ExitStreams.end() && stream->second.connected) {
                runtime = stream->second;
                found = true;
            }
        }
        bool sent = false;
        if (found && item.direction == 0 && runtime.socket)
            sent = runtime.socket->SendRawFrame(item.bytes.data(), item.bytes.size());
        else if (found && item.direction == 1)
            sent = SendK6GatewayPush(runtime.circuit, runtime.circ_id, 0,
                kad6::kK6MsgStreamData, kad6::kK6FlagFinal, item.bytes);
        if (!sent) {
            failed.insert(item.stream_id);
            continue;
        }
        m_k6Metrics.Add(kad6::K6MetricFamily::ExitBytesTotal,
            item.direction == 0 ? 1 : 0, runtime.inbound ? 3 : 2, 0,
            static_cast<uint64>(item.bytes.size()), static_cast<uint64>(time(NULL)));
        m_k6Metrics.Add(kad6::K6MetricFamily::TransportBytesTotal,
            0, item.direction == 0 ? 1 : 0, 0,
            static_cast<uint64>(item.bytes.size()), static_cast<uint64>(time(NULL)));
        {
            CSingleLock pl(&m_pendingLock, TRUE);
            m_k6EconomyUsefulBytes += static_cast<uint64>(item.bytes.size());
        }
        if (item.credit_bytes != 0)
            ConsumeK6ReceiveCredit(runtime.circ_id, item.stream_id, 0,
                item.credit_bytes, runtime.circuit, true);
    }
    for (uint64 streamId : failed) {
        CKad6ExitSocket* socket = NULL;
        {
            CSingleLock pl(&m_pendingLock, TRUE);
            auto stream = m_k6ExitStreams.find(streamId);
            if (stream != m_k6ExitStreams.end()) socket = stream->second.socket;
            ReleaseK6FairStreamLocked(streamId);
        }
        if (socket) socket->Disconnect(_T("Kad6 fair queue send failed"));
    }
    CSingleLock pl(&m_pendingLock, TRUE);
    return m_k6FairPayloadBytes != 0 || m_k6FairScheduler.queued_bytes() != 0;
}

bool CLiveTunnel::RegisterK6FlowControlLocked(uint32 circId, uint64 streamId)
{
    if (circId == 0 || streamId == 0) return false;
    const auto existing = m_k6FlowStreamsByCircuit.find(circId);
    if (existing != m_k6FlowStreamsByCircuit.end() &&
        existing->second.find(streamId) != existing->second.end()) return false;
    std::set<uint64>& members = m_k6FlowStreamsByCircuit[circId];
    kad6::K6SendCreditLedger& sender = m_k6SendCredits[circId];
    kad6::K6ReceiveCreditWindow& receiver = m_k6ReceiveCredits[circId];
    if (sender.RegisterStream(streamId) != kad6::Kad6Status::Ok ||
        receiver.RegisterStream(streamId) != kad6::Kad6Status::Ok) {
        sender.RemoveStream(streamId);
        receiver.RemoveStream(streamId);
        if (members.empty()) {
            m_k6FlowStreamsByCircuit.erase(circId);
            m_k6SendCredits.erase(circId);
            m_k6ReceiveCredits.erase(circId);
        }
        return false;
    }
    members.insert(streamId);
    return true;
}

void CLiveTunnel::RemoveK6FlowControlLocked(uint32 circId, uint64 streamId)
{
    auto streams = m_k6FlowStreamsByCircuit.find(circId);
    if (streams == m_k6FlowStreamsByCircuit.end()) return;
    auto sender = m_k6SendCredits.find(circId);
    if (sender != m_k6SendCredits.end()) sender->second.RemoveStream(streamId);
    auto receiver = m_k6ReceiveCredits.find(circId);
    if (receiver != m_k6ReceiveCredits.end()) receiver->second.RemoveStream(streamId);
    streams->second.erase(streamId);
    if (streams->second.empty()) {
        m_k6FlowStreamsByCircuit.erase(streams);
        m_k6SendCredits.erase(circId);
        m_k6ReceiveCredits.erase(circId);
    }
}

bool CLiveTunnel::SendK6FlowCredit(
    uint32 circId, const std::weak_ptr<CLiveCircuit>& circuit, bool fromExit,
    const kad6::K6MaxStreamData& streamCredit,
    const kad6::K6MaxData& circuitCredit)
{
    auto sendOne = [&](uint8 msgType, const std::vector<uint8_t>& body) -> bool {
        if (fromExit)
            return SendK6GatewayPush(circuit, circId, 0, msgType,
                kad6::kK6FlagFinal, body);
        kad6::K6Frame frame;
        frame.msg_type = msgType;
        frame.request_id = NewCircuitId();
        frame.body = body;
        std::vector<uint8_t> wire;
        return kad6::EncodeK6Frame(frame, wire) == kad6::Kad6Status::Ok &&
            SendMessagePinned(frame.request_id, TUN_OP_KAD6_GATEWAY,
                wire.data(), wire.size(), ESE_CAP_KAD6, circId) == circId;
    };
    std::vector<uint8_t> streamBody, circuitBody;
    return kad6::EncodeK6MaxStreamData(streamCredit, streamBody) ==
               kad6::Kad6Status::Ok &&
        kad6::EncodeK6MaxData(circuitCredit, circuitBody) ==
               kad6::Kad6Status::Ok &&
        sendOne(kad6::kK6MsgMaxStreamData, streamBody) &&
        sendOne(kad6::kK6MsgMaxData, circuitBody);
}

bool CLiveTunnel::SendK6InitialCredit(
    uint32 circId, uint64 streamId, uint8 direction,
    const std::weak_ptr<CLiveCircuit>& circuit, bool fromExit)
{
    kad6::K6MaxStreamData streamCredit;
    kad6::K6MaxData circuitCredit;
    {
        CSingleLock pl(&m_pendingLock, TRUE);
        const auto receiver = m_k6ReceiveCredits.find(circId);
        if (receiver == m_k6ReceiveCredits.end() ||
            receiver->second.InitialCredit(streamId, direction, streamCredit,
                circuitCredit) != kad6::Kad6Status::Ok)
            return false;
    }
    return SendK6FlowCredit(circId, circuit, fromExit, streamCredit, circuitCredit);
}

bool CLiveTunnel::ConsumeK6ReceiveCredit(
    uint32 circId, uint64 streamId, uint8 direction, size_t bytes,
    const std::weak_ptr<CLiveCircuit>& circuit, bool fromExit)
{
    kad6::K6MaxStreamData streamCredit;
    kad6::K6MaxData circuitCredit;
    bool stillPaused = false;
    {
        CSingleLock pl(&m_pendingLock, TRUE);
        const auto receiver = m_k6ReceiveCredits.find(circId);
        if (receiver == m_k6ReceiveCredits.end() ||
            receiver->second.Consume(streamId, direction, bytes,
                K6ShapeNowUs() / 1000u, streamCredit, circuitCredit) !=
                    kad6::Kad6Status::Ok)
            return false;
        stillPaused = receiver->second.reads_paused();
    }
    // Hysteresis is operational, not cosmetic: while occupancy remains above
    // the 25% low watermark, do not reopen the sender's read side.
    if (stillPaused) return true;
    return SendK6FlowCredit(circId, circuit, fromExit, streamCredit, circuitCredit);
}

void CLiveTunnel::FlushK6OriginCredit(uint32 circId)
{
    std::vector<CKad6OriginSocket*> resumed;
    CSingleLock pl(&m_pendingLock, TRUE);
    auto ledger = m_k6SendCredits.find(circId);
    if (ledger == m_k6SendCredits.end()) return;
    CSingleLock ql(&m_mtLock, TRUE);
    for (auto& pair : m_k6OriginStreams) {
        K6OriginStreamRuntime& stream = pair.second;
        if (stream.circ_id != circId) continue;
        while (!stream.pending_credit_frames.empty()) {
            K6QueuedOriginFrame& queued = stream.pending_credit_frames.front();
            const uint64 sent = ledger->second.stream_sent(pair.first, 0);
            const uint64 received = stream.flow.total_bytes(1);
            const uint64 remaining = stream.dial.max_bytes == 0 ||
                    sent + received >= stream.dial.max_bytes
                ? (stream.dial.max_bytes == 0 ? (std::numeric_limits<uint64>::max)() : 0)
                : stream.dial.max_bytes - sent - received;
            if (ledger->second.CommitSend(pair.first, 0, queued.data_bytes,
                    remaining, (std::numeric_limits<uint64>::max)(),
                    2u * 1024u * 1024u) != kad6::Kad6Status::Ok)
                break;
            MainThreadReq request;
            request.op = MT_SEND_MSG;
            request.reqId = queued.request_id;
            request.subCmd = TUN_OP_KAD6_GATEWAY;
            request.requiredExitCaps = ESE_CAP_KAD6;
            request.pinnedCircId = circId;
            request.k6StreamId = pair.first;
            request.k6FlowBytes = queued.wire.size();
            request.k6Sequence = queued.sequence;
            request.k6DataBytes = queued.data_bytes;
            request.payload = std::move(queued.wire);
            stream.pending_credit_bytes -= (std::min)(stream.pending_credit_bytes,
                queued.data_bytes);
            stream.pending_credit_frames.pop_front();
            m_mtQueue.push_back(std::move(request));
        }
        if (stream.pending_credit_frames.empty()) {
            stream.credit_stall_since_ms = 0;
            if (stream.socket) resumed.push_back(stream.socket);
        }
    }
    ql.Unlock();
    pl.Unlock();
    for (CKad6OriginSocket* socket : resumed)
        if (socket) socket->SetKad6FlowBlocked(false);
}

void CLiveTunnel::FlushK6ExitCredit(uint32 circId)
{
    struct Push {
        std::weak_ptr<CLiveCircuit> circuit;
        uint32 circ_id = 0;
        uint64 stream_id = 0;
        std::vector<uint8_t> body;
    };
    std::vector<Push> pushes;
    std::vector<CKad6ExitSocket*> resumed;
    std::vector<CKad6ExitSocket*> failed;
    {
        CSingleLock pl(&m_pendingLock, TRUE);
        auto ledger = m_k6SendCredits.find(circId);
        if (ledger == m_k6SendCredits.end()) return;
        for (auto& pair : m_k6ExitStreams) {
            K6ExitStreamRuntime& stream = pair.second;
            if (stream.circ_id != circId || !stream.connected) continue;
            while (!stream.pending_credit_frames.empty()) {
                const std::vector<uint8_t>& raw = stream.pending_credit_frames.front();
                const uint64 sent = ledger->second.stream_sent(pair.first, 1);
                const uint64 received = stream.flow.total_bytes(0);
                const uint64 remaining = stream.stream_max_bytes == 0 ||
                        sent + received >= stream.stream_max_bytes
                    ? (stream.stream_max_bytes == 0
                        ? (std::numeric_limits<uint64>::max)() : 0)
                    : stream.stream_max_bytes - sent - received;
                if (ledger->second.Available(pair.first, 1, remaining,
                        (std::numeric_limits<uint64>::max)(),
                        2u * 1024u * 1024u) < raw.size())
                    break;
                kad6::K6StreamData data;
                data.stream_id = pair.first;
                data.sequence = stream.tx_sequence;
                data.direction = 1;
                data.flags = 0x02;
                data.data = raw;
                std::vector<uint8_t> body;
                if (kad6::EncodeK6StreamData(data, body) != kad6::Kad6Status::Ok ||
                    stream.flow.CanAccept(data) != kad6::Kad6Status::Ok)
                    break;
                bool queued = false;
                if (stream.quota_allocation_id != 0) {
                    queued = QueueK6FairPayloadLocked(pair.first, 1, std::move(body));
                    if (!queued) break;
                }
                if (ledger->second.CommitSend(pair.first, 1, raw.size(), remaining,
                        (std::numeric_limits<uint64>::max)(),
                        2u * 1024u * 1024u) != kad6::Kad6Status::Ok ||
                    stream.flow.Accept(data) != kad6::Kad6Status::Ok) {
                    if (queued) ReleaseK6FairStreamLocked(pair.first);
                    break;
                }
                ++stream.tx_sequence;
                if (stream.quota_allocation_id == 0) {
                    Push push;
                    push.circuit = stream.circuit;
                    push.circ_id = stream.circ_id;
                    push.stream_id = pair.first;
                    push.body = std::move(body);
                    pushes.push_back(std::move(push));
                    queued = true;
                }
                stream.pending_credit_bytes -= (std::min)(stream.pending_credit_bytes,
                    raw.size());
                stream.pending_credit_frames.pop_front();
            }
            if (stream.pending_credit_frames.empty()) {
                stream.credit_stall_since_ms = 0;
                if (stream.socket) resumed.push_back(stream.socket);
            }
        }
    }
    for (const Push& push : pushes)
        if (!SendK6GatewayPush(push.circuit, push.circ_id, 0,
                kad6::kK6MsgStreamData, kad6::kK6FlagFinal, push.body)) {
            CSingleLock pl(&m_pendingLock, TRUE);
            const auto stream = m_k6ExitStreams.find(push.stream_id);
            if (stream != m_k6ExitStreams.end() && stream->second.socket)
                failed.push_back(stream->second.socket);
        }
    for (CKad6ExitSocket* socket : failed)
        if (socket) socket->Disconnect(_T("Kad6 credit flush failed"));
    for (CKad6ExitSocket* socket : resumed)
        if (socket) socket->SetKad6ReadPaused(false);
}

bool CLiveTunnel::ApplyK6ServiceSwitch(kad6::K6Service service, bool enabled,
                                       uint32 drainSeconds)
{
    if (static_cast<size_t>(service) >= static_cast<size_t>(kad6::K6Service::Count))
        return false;
    // Individual hardening controls cannot bypass the release gate. They may
    // always stop/drain a service, but only a validated public-release state
    // can turn admission back on.
    if (enabled && !IsK6PublicReleaseEnabled())
        return false;
    const uint64 now = static_cast<uint64>(time(NULL));
    std::array<uint64, static_cast<size_t>(kad6::K6Service::Count)> active{};
    {
        CSingleLock pl(&m_pendingLock, TRUE);
        active[static_cast<size_t>(kad6::K6Service::Control)] =
            static_cast<uint64>(m_searchJobs.size());
        for (const auto& pair : m_k6SourceLeases.Entries())
            if (pair.second.state != kad6::K6SourceLeaseState::Closed)
                ++active[static_cast<size_t>(kad6::K6Service::ExitKad)];
        for (const auto& pair : m_k6ExitStreams)
            ++active[static_cast<size_t>(pair.second.inbound
                ? kad6::K6Service::ExitEd2kFull : kad6::K6Service::ExitEd2kDial)];
    }
    if (!m_k6Hardening.SetEnabled(service, enabled, now, drainSeconds,
            active[static_cast<size_t>(service)]))
        return false;

    std::vector<uint64> stoppedLeases;
    if (!enabled) {
        {
            CSingleLock pl(&m_pendingLock, TRUE);
            if (service == kad6::K6Service::ExitKad) {
            std::vector<uint64> leases;
            leases.reserve(m_k6SourceLeases.Entries().size());
            for (const auto& pair : m_k6SourceLeases.Entries())
                if (pair.second.state != kad6::K6SourceLeaseState::Closed)
                    leases.push_back(pair.first);
            for (uint64 lease : leases) {
                m_k6SourceLeases.BeginDrain(lease);
                stoppedLeases.push_back(lease);
                if (drainSeconds == 0) m_k6SourceLeases.Close(lease);
            }
            for (auto& pair : m_k6Publishes) {
                pair.second.refresh_enabled = false;
                m_k6PublishCoalescer.Remove(pair.first);
            }
            if (drainSeconds == 0) {
                m_k6Publishes.clear();
                m_k6ShadowPrimary.clear();
                m_k6SourceLeases.EraseClosed();
            }
            } else if (drainSeconds == 0 &&
                       (service == kad6::K6Service::ExitEd2kDial ||
                        service == kad6::K6Service::ExitEd2kFull)) {
                for (auto& pair : m_k6ExitStreams) {
                    const bool matches = pair.second.inbound
                        ? service == kad6::K6Service::ExitEd2kFull
                        : service == kad6::K6Service::ExitEd2kDial;
                    if (matches) {
                        pair.second.kill_switch_close = true;
                        pair.second.idle_deadline = now;
                    }
                }
            }
        }
        for (uint64 lease : stoppedLeases)
            m_k6CohortScheduler.SetServing(lease, false);
    }

    // ESE_CAP_KAD6 is only the coarse discovery bit. Stop advertising it when
    // every local class is disabled/draining; restore it only when the same
    // identity/privacy preconditions used by K6-1 are still true.
    const kad6::K6HardeningSnapshot snapshot = m_k6Hardening.Snapshot();
    volatile LONG* caps = reinterpret_cast<volatile LONG*>(&g_uEseCapsRuntime);
    if (snapshot.admission_mask == 0) {
        ::InterlockedAnd(caps, ~static_cast<LONG>(ESE_CAP_KAD6));
    } else if (thePrefs.GetEseV9Experimental() && NodeIdentityIsPersistent() &&
               Kademlia::CKadV2ModeSelector::Get().GetDefaultMode() !=
                   Kademlia::CKadV2Mode::Direct) {
        ::InterlockedOr(caps, static_cast<LONG>(ESE_CAP_KAD6));
    }
    AddDebugLogLine(false, _T("Kad6 K6-7: service=%hs state=%s drain=%us revision=%llu"),
        kad6::K6ServiceName(service), enabled ? _T("enabled") : _T("stopped"),
        drainSeconds, static_cast<unsigned long long>(snapshot.revision));
    return true;
}

void CLiveTunnel::OnPeerDisconnected(CUpDownClient* peer)
{
    if (!peer) return;

    // Download activations and established origin streams keep a non-owning
    // client pointer. Drop those references before the client can be deleted.
    // This is deliberately done before taking m_lock (the global lock order is
    // m_pendingLock -> m_lock).
    {
        CSingleLock pl(&m_pendingLock, TRUE);
        for (auto it = m_k6DownloadActivations.begin();
             it != m_k6DownloadActivations.end(); ) {
            if (it->second.client == peer)
                it = m_k6DownloadActivations.erase(it);
            else
                ++it;
        }
        for (auto& stream : m_k6OriginStreams)
            if (stream.second.client == peer)
                stream.second.client = NULL;
    }

    CSingleLock lock(&m_lock, TRUE);
    for (auto& c : m_circuits) {
        if (!c || c->State() == CircuitState::Destroyed) continue;

        const bool lostFirst = c->m_firstHopClient == peer;
        const bool lostPrev  = c->m_prevHopClient == peer;
        const bool lostNext  = c->m_nextHopClient == peer;
        const bool lostPending = std::find(c->m_pendingHopClients.begin(),
            c->m_pendingHopClients.end(), peer) != c->m_pendingHopClients.end();
        if (!lostFirst && !lostPrev && !lostNext && !lostPending) continue;

        // If an intermediate relay loses one side, notify the surviving side
        // before wiping the keys. This propagates exit death back to the
        // originator (or originator death toward the exit) instead of leaving
        // the remote half Active until rotation.
        uint8_t destroy[CELL_TOTAL_BYTES];
        if (c->m_role == CircuitRole::Relay) {
            if (lostPrev && c->m_nextHopClient && c->m_nextHopClient != peer &&
                c->m_nextCircId != 0 &&
                CellPack(c->m_nextCircId, CELL_DESTROY, NULL, 0, destroy)) {
                SendCellToPeer(c->m_nextHopClient, destroy);
            }
            if (lostNext && c->m_prevHopClient && c->m_prevHopClient != peer &&
                CellPack(c->Id(), CELL_DESTROY, NULL, 0, destroy)) {
                SendCellToPeer(c->m_prevHopClient, destroy);
            }
        }

        if (lostFirst) c->m_firstHopClient = NULL;
        if (lostPrev)  c->m_prevHopClient = NULL;
        if (lostNext)  c->m_nextHopClient = NULL;
        if (lostPending) c->m_pendingHopClients.clear();
        c->SetState(CircuitState::Destroyed);
        c->WipeKeys();
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
                                 const uint8_t* msg, size_t msgLen,
                                 uint32_t requiredExitCaps,
                                 uint32_t pinnedCircId)
{
    CSingleLock lk(&m_mtLock, TRUE);
    MainThreadReq req;
    req.op     = MT_SEND_MSG;
    req.reqId  = req_id;
    req.subCmd = sub_cmd;
    req.requiredExitCaps = requiredExitCaps;
    req.pinnedCircId = pinnedCircId;
    if (msg && msgLen) req.payload.assign(msg, msg + msgLen);
    m_mtQueue.push_back(std::move(req));
}

// v8.1 A4 - pin a whole logical message to ONE circuit. Round-robin BY MESSAGE
// (not by cell, as SendThrough does): all cells of one fragmented message must
// ride the same circuit so they reach the same exit in order and reassemble
// trivially. Returns the circuit id used (for retry tracking), or 0 if no
// Active circuit was available / the send could not start. MAIN THREAD ONLY.
uint32_t CLiveTunnel::SendMessagePinned(uint32_t req_id, uint8_t sub_cmd,
                                        const uint8_t* msg, size_t msgLen,
                                        uint32_t requiredExitCaps,
                                        uint32_t pinnedCircId)
{
    // The K6Frame STRICT bit is a transport invariant, not merely an exit
    // hint: it may only ride a completed diverse three-hop circuit.
    bool quotaMessage = false;
    size_t minimumHops = sub_cmd == TUN_OP_KAD6_GATEWAY ? 2 : 1;
    if (sub_cmd == TUN_OP_KAD6_GATEWAY && msg && msgLen) {
        kad6::K6Frame frame;
        size_t consumed = 0;
        if (kad6::DecodeK6Frame(msg, msgLen, frame, &consumed) == kad6::Kad6Status::Ok
            && consumed == msgLen) {
            if ((frame.flags & kad6::kK6FlagStrict) != 0)
                requiredExitCaps |= ESE_CAP_TUNNEL_STRICT3 | ESE_CAP_TUNNEL_SHAPED;
            quotaMessage = frame.msg_type == kad6::kK6MsgQuotaKeyReq ||
                frame.msg_type == kad6::kK6MsgQuotaIssue;
            if (quotaMessage)
                minimumHops = 1; // dedicated issuer circuit; never carries user work
            else if ((frame.flags & kad6::kK6FlagStrict) != 0)
                minimumHops = 3;
        }
    }
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
        if ((!pinnedCircId || c->Id() == pinnedCircId) &&
            (!c->m_k6QuotaIssuerCircuit || quotaMessage) &&
            c->State() == CircuitState::Active && c->HopCount() >= minimumHops
            && c->m_firstHopClient
            // v8.1 D8 - only ORIGINATOR circuits can be pinned: we hold the full onion
            // key stack to reach the exit. Today m_firstHopClient is set only on the
            // originator path, so this is the same set; the explicit role check makes the
            // invariant self-documenting and future-proof (a relay circuit must never be
            // selected — we'd lack the keys to reach the exit).
            && c->m_role == CircuitRole::Originator
            && (requiredExitCaps == 0 ||
                (c->m_auth_ok &&
                 (c->m_exit_signed_caps & requiredExitCaps) == requiredExitCaps))
            && ((requiredExitCaps & ESE_CAP_TUNNEL_STRICT3) == 0
                || (c->m_strict3 && c->m_path_diverse && c->m_shaped_ok
                    && c->HopCount() == 3))
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

    // Atomic preflight: never encrypt/send only a prefix of one logical
    // message merely because the neighbour's TCP control queue filled midway.
    if (!EseCanQueueTunnelCells(chosen->m_firstHopClient, cells.size()))
        return 0;

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
                              uint32_t* outResult,
                              uint32_t* outCircuitId)
{
    if (outCircuitId) *outCircuitId = 0;
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
            if (outCircuitId) *outCircuitId = pr->circ_id;
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
        req.op = hops == 3 ? MT_BUILD_3HOP
               : hops == 2 ? MT_BUILD_2HOP
                           : MT_BUILD_1HOP;
        req.reqId = reqId;
        m_mtQueue.push_back(std::move(req));
    }
    std::vector<uint8_t> dummy;
    uint32_t circId = 0;
    WaitPending(reqId, pr, timeoutMs, dummy, &circId);
    return circId;   // 0 on timeout / build failure
}

bool CLiveTunnel::RequestK6ServiceSwitch(kad6::K6Service service, bool enabled,
                                         uint32 drainSeconds, uint32 timeoutMs)
{
    if (static_cast<size_t>(service) >= static_cast<size_t>(kad6::K6Service::Count))
        return false;
    uint32_t reqId = 0;
    PendingRequest* pending = RegisterPending(reqId);
    {
        CSingleLock lk(&m_mtLock, TRUE);
        MainThreadReq request;
        request.op = MT_K6_SERVICE_SWITCH;
        request.reqId = reqId;
        request.k6Service = service;
        request.k6Enable = enabled;
        request.k6DrainSeconds = (std::min)(drainSeconds, kad6::kK6MaxDrainSeconds);
        m_mtQueue.push_back(std::move(request));
    }
    std::vector<uint8_t> ignored;
    uint32_t result = 0;
    return WaitPending(reqId, pending, timeoutMs, ignored, &result) && result == 1;
}

bool CLiveTunnel::RequestK6PublicRelease(
    bool enable, const kad6::K6ReleaseEvidence* evidence,
    uint32 drainSeconds, uint32 timeoutMs)
{
    uint32_t reqId = 0;
    PendingRequest* pending = RegisterPending(reqId);
    {
        CSingleLock lock(&m_mtLock, TRUE);
        MainThreadReq request;
        request.op = MT_K6_RELEASE_SWITCH;
        request.reqId = reqId;
        request.k6Enable = enable;
        request.k6DrainSeconds = (std::min)(drainSeconds,
            kad6::kK6MaxDrainSeconds);
        request.k6HasReleaseEvidence = evidence != NULL;
        if (evidence) request.k6ReleaseEvidence = *evidence;
        m_mtQueue.push_back(std::move(request));
    }
    std::vector<uint8_t> ignored;
    uint32_t result = 0;
    return WaitPending(reqId, pending, timeoutMs, ignored, &result) && result == 1;
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
                if (req.k6StreamId != 0) {
                    CSingleLock pl(&m_pendingLock, TRUE);
                    if (m_k6OriginStreams.find(req.k6StreamId) == m_k6OriginStreams.end())
                        break; // stream was closed while this bounded item waited.
                }
                const uint32_t cid = SendMessagePinned(
                    req.reqId, req.subCmd,
                    req.payload.empty() ? NULL : req.payload.data(),
                    req.payload.size(), req.requiredExitCaps, req.pinnedCircId);
                CKad6OriginSocket* failedK6Socket = NULL;
                {
                    CSingleLock pl(&m_pendingLock, TRUE);
                    auto it = m_pending.find(req.reqId);
                    if (it != m_pending.end() && it->second)
                        it->second->circ_id = cid;   // 0 = no circuit -> caller times out
                    if (req.k6StreamId != 0) {
                        auto stream = m_k6OriginStreams.find(req.k6StreamId);
                        if (stream != m_k6OriginStreams.end() && cid != 0 &&
                            stream->second.queued_tx_bytes >= req.k6DataBytes &&
                            stream->second.flow.AcceptFrame(0, req.k6Sequence,
                                req.k6DataBytes) == kad6::Kad6Status::Ok) {
                            stream->second.queued_tx_bytes -= req.k6DataBytes;
                            const uint64 now = static_cast<uint64>(time(NULL));
                            const uint64 idle =
                                (stream->second.dial.idle_timeout_ms + 999u) / 1000u;
                            stream->second.last_activity = now;
                            stream->second.idle_deadline = now + idle;
                        } else if (stream != m_k6OriginStreams.end()) {
                            failedK6Socket = stream->second.socket;
                        }
                    }
                }
                if (failedK6Socket)
                    failedK6Socket->Disconnect(_T("Kad6 tunnel backpressure"));
                break;
            }
            case MT_BUILD_1HOP:
            case MT_BUILD_2HOP:
            case MT_BUILD_3HOP: {
                uint32_t circId = 0;
                if (req.op == MT_BUILD_3HOP)
                    BuildSuccessor3Hop(&circId);
                else if (req.op == MT_BUILD_2HOP)
                    circId = BuildTestCircuit2Hop();
                else
                    circId = BuildTestCircuit(NULL);
                SignalReply(req.reqId, NULL, 0, circId);   // wake RequestTestCircuit
                break;
            }
            case MT_K6_SERVICE_SWITCH: {
                const bool ok = ApplyK6ServiceSwitch(req.k6Service, req.k6Enable,
                                                     req.k6DrainSeconds);
                SignalReply(req.reqId, NULL, 0, ok ? 1u : 0u);
                break;
            }
            case MT_K6_RELEASE_SWITCH: {
                const bool ok = ApplyK6PublicRelease(req.k6Enable,
                    req.k6HasReleaseEvidence ? &req.k6ReleaseEvidence : NULL,
                    req.k6DrainSeconds);
                SignalReply(req.reqId, NULL, 0, ok ? 1u : 0u);
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
        if (sub_cmd == TUN_OP_KAD6_GATEWAY)
            return HandleK6SearchReply(circ, req_id, msg);
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

bool CLiveTunnel::HandleK6SearchReply(const std::shared_ptr<CLiveCircuit>& circ,
                                      uint32_t req_id,
                                      const std::vector<uint8_t>& wire)
{
    if (!circ || wire.empty()) return false;
    kad6::K6Frame frame;
    size_t consumed = 0;
    if (kad6::DecodeK6Frame(wire.data(), wire.size(), frame, &consumed) !=
            kad6::Kad6Status::Ok || consumed != wire.size() ||
        frame.request_id != req_id || frame.session_id != 0 ||
        (frame.flags & kad6::kK6FlagResponse) == 0)
        return false;

    if (frame.msg_type == kad6::kK6MsgAccept) {
        if ((frame.flags & kad6::kK6FlagFinal) == 0) return false;
        kad6::K6DialResult accepted;
        consumed = 0;
        if (kad6::DecodeK6DialResult(frame.body.data(), frame.body.size(), accepted,
                &consumed) != kad6::Kad6Status::Ok || consumed != frame.body.size() ||
            accepted.status != kad6::K6DialStatus::Ok || accepted.stream_id == 0)
            return false;

        CKad6OriginSocket* socket = new CKad6OriginSocket();
        if (!socket->InitializeInbound(accepted.stream_id, accepted.remote_endpoint)) {
            socket->Safe_Delete();
            return false;
        }
        {
            CSingleLock pl(&m_pendingLock, TRUE);
            if (m_k6OriginStreams.size() >= 512 ||
                m_k6OriginStreams.find(accepted.stream_id) != m_k6OriginStreams.end() ||
                !RegisterK6FlowControlLocked(circ->Id(), accepted.stream_id)) {
                pl.Unlock(); socket->Safe_Delete(); return false;
            }
            K6OriginStreamRuntime runtime;
            runtime.circ_id = circ->Id();
            runtime.dial = accepted;
            runtime.socket = socket;
            runtime.flow = kad6::K6StreamFlowState(accepted.max_bytes);
            runtime.initial_data_sent = true;
            runtime.last_activity = static_cast<uint64>(time(NULL));
            runtime.idle_deadline = runtime.last_activity +
                ((accepted.idle_timeout_ms + 999u) / 1000u);
            m_k6OriginStreams[accepted.stream_id] = runtime;
        }
        if (!SendK6InitialCredit(circ->Id(), accepted.stream_id, 1, circ, false)) {
            CSingleLock pl(&m_pendingLock, TRUE);
            m_k6OriginStreams.erase(accepted.stream_id);
            RemoveK6FlowControlLocked(circ->Id(), accepted.stream_id);
            pl.Unlock();
            socket->Safe_Delete();
            return false;
        }
        LIVE_LOG("K6", "inbound ACCEPT stream=%llu circuit=%u",
            static_cast<unsigned long long>(accepted.stream_id), circ->Id());
        return true;
    }

    if (frame.msg_type == kad6::kK6MsgQuotaKey) {
        if ((frame.flags & kad6::kK6FlagFinal) == 0) return false;
        kad6::K6QuotaIssuerCertificate certificate;
        consumed = 0;
        if (kad6::DecodeK6QuotaIssuerCertificate(frame.body.data(), frame.body.size(),
                certificate, &consumed) != kad6::Kad6Status::Ok ||
            consumed != frame.body.size() ||
            kad6::VerifyK6QuotaIssuerCertificate(MakeKad6HostCryptoHooks(), certificate,
                kad6::K6QuotaEpoch(static_cast<uint64>(time(NULL)))) !=
                kad6::Kad6Status::Ok)
            return false;
        const uint8_t* expected = NULL;
        if (circ->HopCount() >= 2 && circ->m_expectedNodePub2Set)
            expected = circ->m_expectedNodePub2;
        else if (circ->m_expectedNodePubSet)
            expected = circ->m_expectedNodePub;
        if (!expected || !kad6::Kad6CtEqual(expected,
                certificate.issuer_node_pub.data(), 32)) return false;
        SignalReply(req_id, wire.data(), wire.size(), 0);
        return true;
    }

    if (frame.msg_type == kad6::kK6MsgQuotaIssued) {
        kad6::K6QuotaBlindResponse response;
        consumed = 0;
        if ((frame.flags & kad6::kK6FlagFinal) == 0 ||
            kad6::DecodeK6QuotaBlindResponse(frame.body.data(), frame.body.size(),
                response, &consumed) != kad6::Kad6Status::Ok ||
            consumed != frame.body.size()) return false;
        SignalReply(req_id, wire.data(), wire.size(), 0);
        return true;
    }

    if (frame.msg_type == kad6::kK6MsgQuotaStatus) {
        kad6::K6QuotaPresentationResult response;
        consumed = 0;
        if ((frame.flags & kad6::kK6FlagFinal) == 0 ||
            kad6::DecodeK6QuotaPresentationResult(frame.body.data(), frame.body.size(),
                response, &consumed) != kad6::Kad6Status::Ok ||
            consumed != frame.body.size()) return false;
        SignalReply(req_id, wire.data(), wire.size(), 0);
        return true;
    }

    if (frame.msg_type == kad6::kK6MsgVep) {
        kad6::K6VirtualIdentityEndpoint vep;
        consumed = 0;
        if (kad6::DecodeK6Vep(frame.body.data(), frame.body.size(), vep, &consumed) !=
                kad6::Kad6Status::Ok || consumed != frame.body.size() ||
            kad6::VerifyK6Vep(MakeKad6HostCryptoHooks(), vep,
                static_cast<uint64_t>(time(NULL))) != kad6::Kad6Status::Ok)
            return false;
        const uint8_t* expected = NULL;
        if (circ->HopCount() >= 2 && circ->m_expectedNodePub2Set)
            expected = circ->m_expectedNodePub2;
        else if (circ->m_expectedNodePubSet)
            expected = circ->m_expectedNodePub;
        if (!expected || memcmp(expected, vep.exit_node_pub.data(), 32) != 0)
            return false;
        CSingleLock pl(&m_pendingLock, TRUE);
        auto stream = m_k6OriginStreams.find(vep.source_lease_id);
        if (stream == m_k6OriginStreams.end()) return false;
        stream->second.vep = vep;
        stream->second.has_vep = true;
        if (stream->second.client &&
            vep.apparent_source_ip.family == kad6::Kad6Address::Family::IPv4) {
            uint32 ip = 0;
            memcpy(&ip, vep.apparent_source_ip.addr.data(), 4);
            stream->second.client->SetK6SecureIdentVepIPv4(ip);
        }
        return true;
    }

    if (frame.msg_type == kad6::kK6MsgSourceHints) {
        kad6::K6SourceHints hints;
        consumed = 0;
        if (kad6::DecodeK6SourceHints(frame.body.data(), frame.body.size(), hints,
                &consumed) != kad6::Kad6Status::Ok || consumed != frame.body.size())
            return false;
        CSingleLock pl(&m_pendingLock, TRUE);
        auto stream = m_k6OriginStreams.find(hints.source_stream_id);
        if (stream == m_k6OriginStreams.end() || stream->second.hints.size() >= 32)
            return false;
        stream->second.hints.push_back(std::move(hints));
        return true;
    }

    if (frame.msg_type == kad6::kK6MsgMaxStreamData) {
        kad6::K6MaxStreamData credit;
        consumed = 0;
        if (kad6::DecodeK6MaxStreamData(frame.body.data(), frame.body.size(), credit,
                &consumed) != kad6::Kad6Status::Ok || consumed != frame.body.size() ||
            credit.direction != 0)
            return false;
        {
            CSingleLock pl(&m_pendingLock, TRUE);
            const auto stream = m_k6OriginStreams.find(credit.stream_id);
            const auto ledger = m_k6SendCredits.find(circ->Id());
            if (stream == m_k6OriginStreams.end() || stream->second.circ_id != circ->Id() ||
                ledger == m_k6SendCredits.end() ||
                ledger->second.Grant(credit) != kad6::Kad6Status::Ok)
                return false;
        }
        FlushK6OriginCredit(circ->Id());
        return true;
    }

    if (frame.msg_type == kad6::kK6MsgMaxData) {
        kad6::K6MaxData credit;
        consumed = 0;
        if (kad6::DecodeK6MaxData(frame.body.data(), frame.body.size(), credit,
                &consumed) != kad6::Kad6Status::Ok || consumed != frame.body.size() ||
            credit.direction != 0)
            return false;
        {
            CSingleLock pl(&m_pendingLock, TRUE);
            const auto ledger = m_k6SendCredits.find(circ->Id());
            if (ledger == m_k6SendCredits.end() ||
                ledger->second.Grant(credit) != kad6::Kad6Status::Ok)
                return false;
        }
        FlushK6OriginCredit(circ->Id());
        return true;
    }

    if (frame.msg_type == kad6::kK6MsgStreamData) {
        kad6::K6StreamData data;
        consumed = 0;
        if (kad6::DecodeK6StreamData(frame.body.data(), frame.body.size(), data,
                &consumed) != kad6::Kad6Status::Ok || consumed != frame.body.size() ||
            data.direction != 1 || (data.flags & 0x02) == 0)
            return false;
        kad6::K6Ed2kFrameView inboundView;
        if (kad6::DecodeK6Ed2kFrame(data.data.data(), data.data.size(), inboundView) !=
                kad6::Kad6Status::Ok) return false;
        const bool suppressHandshakeReply =
            kad6::ClassifyK6Ed2kFrame(inboundView.protocol, inboundView.opcode) ==
                kad6::K6Ed2kFrameClass::Hello;
        CKad6OriginSocket* socket = NULL;
        {
            CSingleLock pl(&m_pendingLock, TRUE);
            auto stream = m_k6OriginStreams.find(data.stream_id);
            if (stream == m_k6OriginStreams.end()) return false;
            const uint64 maxBytes = stream->second.dial.max_bytes;
            const uint64 txBytes = stream->second.flow.total_bytes(0);
            const uint64 rxBytes = stream->second.flow.total_bytes(1);
            auto receiver = m_k6ReceiveCredits.find(circ->Id());
            const bool bufferForAttach = stream->second.socket == NULL;
            if ((maxBytes && (txBytes > maxBytes || rxBytes > maxBytes - txBytes ||
                    stream->second.queued_tx_bytes > maxBytes - txBytes - rxBytes ||
                    data.data.size() > maxBytes - txBytes - rxBytes -
                        stream->second.queued_tx_bytes)) ||
                receiver == m_k6ReceiveCredits.end() ||
                (bufferForAttach && (stream->second.pending_frames.size() >= 64 ||
                    stream->second.pending_frame_bytes + data.data.size() >
                        256u * 1024u)) ||
                receiver->second.CanAccept(data.stream_id, 1, data.data.size()) !=
                    kad6::Kad6Status::Ok ||
                stream->second.flow.CanAccept(data) != kad6::Kad6Status::Ok)
                return false;
            // Both preflights are side-effect free. Under m_pendingLock no
            // peer can invalidate either decision between the two commits.
            if (receiver->second.Accept(data.stream_id, 1, data.data.size(),
                    K6ShapeNowUs() / 1000u) != kad6::Kad6Status::Ok ||
                stream->second.flow.Accept(data) != kad6::Kad6Status::Ok)
                return false;
            const uint64 now = static_cast<uint64>(time(NULL));
            const uint64 idle = (stream->second.dial.idle_timeout_ms + 999u) / 1000u;
            stream->second.last_activity = now;
            stream->second.idle_deadline = now + idle;
            socket = stream->second.socket;
            if (!socket) {
                stream->second.pending_frame_bytes += data.data.size();
                stream->second.pending_frames.push_back(std::move(data.data));
                return true;
            }
        }
        const bool injected = socket->InjectRawFrame(data.data.data(), data.data.size(),
            suppressHandshakeReply);
        if (!injected) {
            socket->Disconnect(_T("Kad6 downstream application rejected frame"));
            return false;
        }
        if (injected) {
            CSingleLock pl(&m_pendingLock, TRUE);
            auto stream = m_k6OriginStreams.find(data.stream_id);
            if (stream != m_k6OriginStreams.end() && stream->second.socket == socket)
                stream->second.client = socket->client;
        }
        return ConsumeK6ReceiveCredit(circ->Id(), data.stream_id, 1,
            data.data.size(), circ, false);
    }

    if (frame.msg_type == kad6::kK6MsgStreamHalfClose) {
        kad6::K6StreamHalfClose close;
        consumed = 0;
        if (kad6::DecodeK6StreamHalfClose(frame.body.data(), frame.body.size(), close,
                &consumed) != kad6::Kad6Status::Ok || consumed != frame.body.size() ||
            close.direction != 1) return false;
        CSingleLock pl(&m_pendingLock, TRUE);
        auto stream = m_k6OriginStreams.find(close.stream_id);
        return stream != m_k6OriginStreams.end() &&
               stream->second.flow.HalfClose(close) == kad6::Kad6Status::Ok;
    }

    if (frame.msg_type == kad6::kK6MsgStreamClose) {
        kad6::K6StreamClose close;
        consumed = 0;
        if (kad6::DecodeK6StreamClose(frame.body.data(), frame.body.size(), close,
                &consumed) != kad6::Kad6Status::Ok || consumed != frame.body.size())
            return false;
        CKad6OriginSocket* socket = NULL;
        CUpDownClient* client = NULL;
        {
            CSingleLock pl(&m_pendingLock, TRUE);
            auto stream = m_k6OriginStreams.find(close.stream_id);
            if (stream == m_k6OriginStreams.end() ||
                stream->second.flow.Close(close) != kad6::Kad6Status::Ok) return false;
            socket = stream->second.socket;
            client = stream->second.client;
            RemoveK6FlowControlLocked(stream->second.circ_id, close.stream_id);
            m_k6OriginStreams.erase(stream);
        }
        if (client) client->ClearK6SecureIdentVep();
        if (socket) socket->Disconnect(_T("Kad6 remote stream closed"));
        return true;
    }

    if (frame.msg_type == kad6::kK6MsgDialOk) {
        if ((frame.flags & kad6::kK6FlagFinal) == 0) return false;
        kad6::K6DialResult result;
        consumed = 0;
        if (kad6::DecodeK6DialResult(frame.body.data(), frame.body.size(), result,
                &consumed) != kad6::Kad6Status::Ok || consumed != frame.body.size())
            return false;
        CUpDownClient* activationClient = NULL;
        bool hasActivation = false;
        {
            CSingleLock pl(&m_pendingLock, TRUE);
            auto activation = m_k6DownloadActivations.find(req_id);
            if (activation != m_k6DownloadActivations.end()) {
                if (activation->second.circ_id != circ->Id()) return false;
                activationClient = activation->second.client;
                hasActivation = true;
                m_k6DownloadActivations.erase(activation);
            }
        }
        bool streamRegistered = result.status != kad6::K6DialStatus::Ok;
        if (result.status == kad6::K6DialStatus::Ok) {
            CSingleLock pl(&m_pendingLock, TRUE);
            if (m_k6OriginStreams.size() < 512 && result.stream_id != 0 &&
                m_k6OriginStreams.find(result.stream_id) == m_k6OriginStreams.end() &&
                RegisterK6FlowControlLocked(circ->Id(), result.stream_id)) {
                K6OriginStreamRuntime runtime;
                runtime.circ_id = circ->Id();
                runtime.dial = result;
                runtime.flow = kad6::K6StreamFlowState(result.max_bytes);
                runtime.last_activity = static_cast<uint64>(time(NULL));
                runtime.idle_deadline = runtime.last_activity +
                    ((result.idle_timeout_ms + 999u) / 1000u);
                m_k6OriginStreams[result.stream_id] = runtime;
                streamRegistered = true;
            }
        }
        if (result.status == kad6::K6DialStatus::Ok && streamRegistered &&
            !SendK6InitialCredit(circ->Id(), result.stream_id, 1, circ, false)) {
            CSingleLock pl(&m_pendingLock, TRUE);
            m_k6OriginStreams.erase(result.stream_id);
            RemoveK6FlowControlLocked(circ->Id(), result.stream_id);
            streamRegistered = false;
        }
        if (hasActivation) {
            if (activationClient != NULL && result.status == kad6::K6DialStatus::Ok &&
                streamRegistered &&
                K6AttachOriginClient(result.stream_id, activationClient)) {
                LIVE_LOG("K6", "download stream attached req=%u stream=%llu",
                    req_id, static_cast<unsigned long long>(result.stream_id));
                return true;
            }
            // A successful exit DIAL whose local attach failed must not leave an
            // unowned stream consuming both ends until the idle timeout.
            if (streamRegistered && result.status == kad6::K6DialStatus::Ok) {
                K6OriginStreamRuntime orphan;
                bool found = false;
                {
                    CSingleLock pl(&m_pendingLock, TRUE);
                    auto stream = m_k6OriginStreams.find(result.stream_id);
                    if (stream != m_k6OriginStreams.end() &&
                        stream->second.socket == NULL) {
                        orphan = stream->second;
                        RemoveK6FlowControlLocked(stream->second.circ_id,
                            result.stream_id);
                        m_k6OriginStreams.erase(stream);
                        found = true;
                    }
                }
                if (found) {
                    kad6::K6StreamClose close;
                    close.stream_id = result.stream_id;
                    close.reason_code = 1;
                    std::vector<uint8_t> closeBody, closeWire;
                    kad6::K6Frame closeFrame;
                    closeFrame.msg_type = kad6::kK6MsgStreamClose;
                    closeFrame.flags = kad6::kK6FlagLegacyEd2k | kad6::kK6FlagFinal;
                    closeFrame.request_id = NewCircuitId();
                    if (kad6::EncodeK6StreamClose(close, closeBody) ==
                            kad6::Kad6Status::Ok) {
                        closeFrame.body = std::move(closeBody);
                        if (kad6::EncodeK6Frame(closeFrame, closeWire) ==
                                kad6::Kad6Status::Ok)
                            SendMessagePinned(closeFrame.request_id, TUN_OP_KAD6_GATEWAY,
                                closeWire.data(), closeWire.size(), ESE_CAP_KAD6,
                                orphan.circ_id);
                    }
                }
            }
            if (activationClient != NULL) {
                const bool deleteClient = activationClient->Disconnected(
                    _T("Kad6 gateway DIAL failed"));
                if (deleteClient) delete activationClient;
            }
            return true;
        }
        if (!streamRegistered) return false;
        SignalReply(req_id, wire.data(), wire.size(), 0);
        return true;
    }

    if (frame.msg_type == kad6::kK6MsgTargetTicket) {
        kad6::K6TargetTicketResponse response;
        consumed = 0;
        if ((frame.flags & kad6::kK6FlagFinal) == 0 ||
            kad6::DecodeK6TargetTicketResponse(frame.body.data(), frame.body.size(),
                response, &consumed) != kad6::Kad6Status::Ok ||
            consumed != frame.body.size()) return false;
        SignalReply(req_id, wire.data(), wire.size(), 0);
        return true;
    }

    // K6-3 control replies are single final frames. Validate their body here
    // before waking a worker-thread waiter; malformed exit data never escapes
    // as a successful SOURCE_BOUND/PUBLISH_ACK.
    if (frame.msg_type == kad6::kK6MsgSourceBound ||
        frame.msg_type == kad6::kK6MsgPublishAck) {
        if ((frame.flags & kad6::kK6FlagFinal) == 0 ||
            (frame.flags & kad6::kK6FlagMore) != 0)
            return false;
        if (frame.msg_type == kad6::kK6MsgSourceBound) {
            kad6::K6SourceBound value;
            consumed = 0;
            if (kad6::DecodeK6SourceBound(frame.body.data(), frame.body.size(),
                    value, &consumed) != kad6::Kad6Status::Ok ||
                consumed != frame.body.size()) return false;
        } else {
            kad6::K6PublishAck value;
            consumed = 0;
            if (kad6::DecodeK6PublishAck(frame.body.data(), frame.body.size(),
                    value, &consumed) != kad6::Kad6Status::Ok ||
                consumed != frame.body.size()) return false;
        }
        SignalReply(req_id, wire.data(), wire.size(), 0);
        return true;
    }

    const uint64_t key = ExitOpKey(circ->Id(), req_id);
    if (frame.msg_type == kad6::kK6MsgSearchResult) {
        if ((frame.flags & kad6::kK6FlagMore) == 0 ||
            (frame.flags & kad6::kK6FlagFinal) != 0)
            return false;
        kad6::K6SearchResult result;
        consumed = 0;
        if (kad6::DecodeK6SearchResult(frame.body.data(), frame.body.size(), result,
                                       &consumed) != kad6::Kad6Status::Ok ||
            consumed != frame.body.size())
            return false;

        if (result.result_kind == kad6::kK6SearchKindSourceHash) {
            K6OriginSourceLookup lookup;
            {
                CSingleLock pl(&m_pendingLock, TRUE);
                auto pendingLookup = m_k6OriginSourceLookups.find(req_id);
                if (pendingLookup == m_k6OriginSourceLookups.end() ||
                    (pendingLookup->second.circ_id != 0 &&
                     pendingLookup->second.circ_id != circ->Id()))
                    return false;
                pendingLookup->second.circ_id = circ->Id();
                lookup = pendingLookup->second;
            }

            bool materialized = false;
            for (const kad6::K6TargetTicket& ticket : result.tickets) {
                if (ticket.service != static_cast<kad6::Byte>(kad6::K6TicketService::Ed2kTcp) ||
                    (ticket.provenance_kind != static_cast<kad6::Byte>(kad6::K6Provenance::KadResult) &&
                     ticket.provenance_kind != static_cast<kad6::Byte>(kad6::K6Provenance::Routing)) ||
                    ticket.provenance_session != circ->Id() ||
                    ticket.provenance_stream != req_id ||
                    ticket.object_hash != lookup.file_hash ||
                    ticket.max_connections != 1 || ticket.max_bytes == 0 ||
                    ticket.expires_at <= static_cast<uint64>(time(NULL)) ||
                    ticket.target_endpoint.tcp_port == 0)
                    continue;

                std::vector<uint8_t> ticketWire;
                if (kad6::EncodeK6TargetTicket(ticket, ticketWire) != kad6::Kad6Status::Ok)
                    continue;
                Kademlia::CUInt128 contact(result.result_id.data());
                Kademlia::CUInt128 buddy;
                uint32 ip = 0;
                CAddress sourceV6;
                const CAddress* sourceV6Ptr = NULL;
                if (ticket.target_endpoint.addr.family == kad6::Kad6Address::Family::IPv4) {
                    memcpy(&ip, ticket.target_endpoint.addr.addr.data(), 4);
                } else if (ticket.target_endpoint.addr.family == kad6::Kad6Address::Family::IPv6) {
                    sourceV6 = CAddress(ticket.target_endpoint.addr.addr.data());
                    if (sourceV6.GetType() != CAddress::IPv6 || !sourceV6.IsPublicIP())
                        continue;
                    sourceV6Ptr = &sourceV6;
                    ip = 0x01000001u; // HighID-shaped placeholder; no direct dial is allowed.
                } else {
                    continue;
                }
                if (theApp.downloadqueue == NULL) return false;
                theApp.downloadqueue->KademliaSearchFile(req_id, &contact, &buddy, 1,
                    ip, ticket.target_endpoint.tcp_port, ticket.target_endpoint.udp_port,
                    0, 0, 0, 0, sourceV6Ptr, &ticketWire);
                materialized = true;
                break;
            }
            if (materialized) {
                CSingleLock pl(&m_pendingLock, TRUE);
                auto pendingLookup = m_k6OriginSourceLookups.find(req_id);
                if (pendingLookup != m_k6OriginSourceLookups.end() &&
                    pendingLookup->second.received != 0xffff)
                    ++pendingLookup->second.received;
            }
            return materialized;
        }

        kad6::K6LiveSearchMetadata live;
        if (kad6::ParseK6LiveSearchResult(result, live) != kad6::Kad6Status::Ok ||
            !result.tickets.empty())
            return false;

        std::vector<uint8_t> one;
        if (!EseAppendLegacyK6Result(live, one)) return false;
        one[0] = 1;
        one[1] = 0;
        one[2] = 0x02;
        one[3] = 0;
        {
            CSingleLock pl(&m_pendingLock, TRUE);
            K6SearchReplyAggregate& agg = m_k6SearchReplies[key];
            if (agg.legacy.empty()) {
                agg.legacy.assign(4, 0);
                agg.started = GetTickCount();
            }
            if (agg.count >= kad6::kK6SearchMaxResults ||
                agg.legacy.size() + one.size() - 4 > TUN_MSG_MAX_BYTES)
                return false;
            agg.legacy.insert(agg.legacy.end(), one.begin() + 4, one.end());
            ++agg.count;
            K6OriginTargetRoute route; route.circ_id = circ->Id();
            route.source_request_id = req_id;
            // Native Live results are opaque route handles, not reusable target
            // tickets. Keep their exit/origin correlation window deliberately short.
            route.expires_at = static_cast<uint64>(time(NULL)) + 120;
            m_k6OriginTargetRoutes[K6AuthorizedTargetKey(0, req_id, result.result_id)] = route;
            m_k6OriginLiveRoutes[K6BinaryKey(result.result_id.data(), result.result_id.size())] = route;
        }
        if (theApp.liveStreamManager)
            theApp.liveStreamManager->GetKadBridge().FeedTunneledSearchResults(one);
        return true;
    }

    if (frame.msg_type == kad6::kK6MsgSearchEnd) {
        if ((frame.flags & kad6::kK6FlagFinal) == 0 ||
            (frame.flags & kad6::kK6FlagMore) != 0)
            return false;
        kad6::K6SearchEnd end;
        consumed = 0;
        if (kad6::DecodeK6SearchEnd(frame.body.data(), frame.body.size(), end,
                                    &consumed) != kad6::Kad6Status::Ok ||
            consumed != frame.body.size())
            return false;

        uint16 sourceReceived = 0;
        bool sourceLookup = false;
        {
            CSingleLock pl(&m_pendingLock, TRUE);
            auto lookup = m_k6OriginSourceLookups.find(req_id);
            if (lookup != m_k6OriginSourceLookups.end()) {
                if (lookup->second.circ_id != 0 && lookup->second.circ_id != circ->Id())
                    return false;
                sourceReceived = lookup->second.received;
                m_k6OriginSourceLookups.erase(lookup);
                sourceLookup = true;
            }
        }
        if (sourceLookup) {
            if (theApp.downloadqueue != NULL) {
                CPartFile* file = theApp.downloadqueue->GetFileByKadFileSearchID(req_id);
                if (file != NULL) file->SetKadFileSearchID(0);
            }
            return sourceReceived == end.result_count;
        }

        std::vector<uint8_t> legacy(4, 0);
        uint16_t count = 0;
        {
            CSingleLock pl(&m_pendingLock, TRUE);
            auto it = m_k6SearchReplies.find(key);
            if (it != m_k6SearchReplies.end()) {
                legacy = std::move(it->second.legacy);
                count = it->second.count;
                m_k6SearchReplies.erase(it);
            }
        }
        if (count != end.result_count) return false;
        legacy[0] = (uint8_t)count;
        legacy[1] = (uint8_t)(count >> 8);
        legacy[2] = 0x02;
        legacy[3] = 0;
        SignalReply(req_id, legacy.data(), legacy.size(), 0);
        return true;
    }
    return false;
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

bool CLiveTunnel::SendExitOperationPart(uint32_t circ_id, uint32_t req_id,
                                        const uint8_t* payload, size_t payloadLen)
{
    std::shared_ptr<CLiveCircuit> circ;
    uint8_t reply_op = 0;
    {
        CSingleLock pl(&m_pendingLock, TRUE);
        auto it = m_exitOps.find(ExitOpKey(circ_id, req_id));
        if (it == m_exitOps.end()) return false;
        circ = it->second.circ.lock();
        reply_op = it->second.reply_op;
    }
    if (!circ) return false;
    TunnelRequestCtx ctx;
    ctx.circ = circ;
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
        if (!EseCanQueueTunnelCells(circ->m_prevHopClient, 1)) return false;
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
    if (!EseCanQueueTunnelCells(circ->m_prevHopClient, cells.size()))
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
    job.started  = GetTickCount();
    job.deadline = job.started + TUN_SEARCH_WINDOW_MS;

    // Fire the real dual-namespace search (main thread). The rate-limit /
    // cooldown inside SearchStreams protects the exit from being used as a Kad
    // amplifier; if it declines, kadSearchIds stays empty and we just serve
    // whatever the directory already holds when the window elapses.
    try {
        if (theApp.liveStreamManager) {
            CString kw = EseUtf8CString(keyword);
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

// K6-1 canonical search gateway. The old 0x42 handler remains byte-identical;
// this path is reached only when the originator selected an exit whose
// authenticated CREATED-v2 snapshot advertised ESE_CAP_KAD6.
void CLiveTunnel::ExitHandle_Kad6Gateway(const TunnelRequestCtx& ctx)
{
    if (!thePrefs.GetEseV9Experimental() ||
        (g_uEseCapsRuntime & ESE_CAP_KAD6) == 0 ||
        !ctx.circ || !ctx.body || ctx.bodyLen == 0)
        return;

    kad6::K6Frame frame;
    size_t consumed = 0;
    if (kad6::DecodeK6Frame(ctx.body, ctx.bodyLen, frame, &consumed) !=
            kad6::Kad6Status::Ok ||
        consumed != ctx.bodyLen || frame.request_id != ctx.req_id ||
        frame.session_id != 0 || (frame.flags & kad6::kK6FlagResponse) != 0 ||
        (frame.flags & kad6::kK6FlagReservedMask) != 0)
    {
        m_k6Metrics.Add(kad6::K6MetricFamily::AuthFailTotal, 2, 0, 0, 1,
                        static_cast<uint64>(time(NULL)));
        return;
    }
    if ((frame.flags & (kad6::kK6FlagMore | kad6::kK6FlagFinal)) != 0)
        return;

    switch (frame.msg_type) {
    case kad6::kK6MsgQuotaKeyReq:
        ExitHandle_Kad6QuotaKey(ctx, frame);
        return;
    case kad6::kK6MsgQuotaIssue:
        ExitHandle_Kad6QuotaIssue(ctx, frame);
        return;
    case kad6::kK6MsgQuotaPresent:
        ExitHandle_Kad6QuotaPresent(ctx, frame);
        return;
    case kad6::kK6MsgSourceBind:
        ExitHandle_Kad6SourceBind(ctx, frame);
        return;
    case kad6::kK6MsgSourceUnbind:
        ExitHandle_Kad6SourceUnbind(ctx, frame);
        return;
    case kad6::kK6MsgPublish:
        ExitHandle_Kad6Publish(ctx, frame);
        return;
    case kad6::kK6MsgUnpublish:
        ExitHandle_Kad6Unpublish(ctx, frame);
        return;
    case kad6::kK6MsgTargetTicketReq:
        ExitHandle_Kad6TargetTicketReq(ctx, frame);
        return;
    case kad6::kK6MsgDial:
        ExitHandle_Kad6Dial(ctx, frame);
        return;
    case kad6::kK6MsgStreamData:
        ExitHandle_Kad6StreamData(ctx, frame);
        return;
    case kad6::kK6MsgStreamHalfClose:
        ExitHandle_Kad6StreamHalfClose(ctx, frame);
        return;
    case kad6::kK6MsgStreamClose:
        ExitHandle_Kad6StreamClose(ctx, frame);
        return;
    case kad6::kK6MsgMaxStreamData:
        ExitHandle_Kad6MaxStreamData(ctx, frame);
        return;
    case kad6::kK6MsgMaxData:
        ExitHandle_Kad6MaxData(ctx, frame);
        return;
    case kad6::kK6MsgSearchStart:
        break;
    default:
        return;
    }

    kad6::K6SearchStart start;
    consumed = 0;
    if (kad6::DecodeK6SearchStart(frame.body.data(), frame.body.size(), start,
                                  &consumed) != kad6::Kad6Status::Ok ||
        consumed != frame.body.size())
        return;

    if (!BeginExitOperation(ctx, TUN_OP_KAD6_GATEWAY)) return;
    auto finishNow = [&](kad6::K6SearchEndStatus status) {
        kad6::K6SearchEnd end;
        end.status = status;
        std::vector<uint8_t> endBody, endWire;
        if (kad6::EncodeK6SearchEnd(end, endBody) != kad6::Kad6Status::Ok) {
            AbortExitOperation(ctx.circ->Id(), ctx.req_id);
            return;
        }
        kad6::K6Frame response;
        response.msg_type = kad6::kK6MsgSearchEnd;
        response.flags = kad6::kK6FlagResponse | kad6::kK6FlagFinal |
                         kad6::kK6FlagLegacyKad2;
        response.request_id = ctx.req_id;
        response.body = std::move(endBody);
        if (kad6::EncodeK6Frame(response, endWire) != kad6::Kad6Status::Ok) {
            AbortExitOperation(ctx.circ->Id(), ctx.req_id);
            return;
        }
        CompleteExitOperation(ctx.circ->Id(), ctx.req_id,
                              endWire.data(), endWire.size());
    };

    if (!ConsumeK6QuotaGrant(ctx, kad6::K6QuotaService::Control, frame)) {
        finishNow(kad6::K6SearchEndStatus::PolicyDenied);
        return;
    }

    if (!m_k6Hardening.CanAdmit(kad6::K6Service::Control)) {
        const uint64 now = static_cast<uint64>(time(NULL));
        m_k6Metrics.Add(kad6::K6MetricFamily::ExitRejectTotal, 8, 0, 0, 1, now);
        m_k6Metrics.Add(kad6::K6MetricFamily::SearchTotal, 0, 1, 0, 1, now);
        finishNow(kad6::K6SearchEndStatus::PolicyDenied);
        return;
    }

    // K6-1 Live discovery and K6-4 source-hash lookup both execute at X. No
    // other search kind is accepted here and Kad6-native source lookup remains
    // a separate K6-2 path.
    if ((start.search_kind != kad6::kK6SearchKindLive &&
         start.search_kind != kad6::kK6SearchKindSourceHash) ||
        (start.search_kind == kad6::kK6SearchKindLive &&
         start.network_mask != kad6::kK6NetMaskKad2) ||
        !start.options.empty()) {
        finishNow(kad6::K6SearchEndStatus::PolicyDenied);
        return;
    }

    if (start.search_kind == kad6::kK6SearchKindSourceHash) {
        if (!start.query.empty()) {
            finishNow(kad6::K6SearchEndStatus::PolicyDenied);
            return;
        }
        TunnelSearchJob job;
        job.circ_id = ctx.circ->Id();
        job.req_id = ctx.req_id;
        job.canonicalK6 = true;
        job.searchKind = kad6::kK6SearchKindSourceHash;
        job.targetHash = start.target_hash;
        job.maxResults = start.max_results;
        job.networkMask = start.network_mask;
        job.started = GetTickCount();
        job.deadline = job.started + (std::min<DWORD>)(TUN_SEARCH_WINDOW_MS,
                                                       (DWORD)start.deadline_ms);
        const bool wantKad2 = (start.network_mask & kad6::kK6NetMaskKad2) != 0;
        const bool wantKad6 = (start.network_mask & kad6::kK6NetMaskKad6) != 0;
        const bool kad2Reachable = wantKad2 && Kademlia::CKademlia::IsConnected();
        job.kadReachable = kad2Reachable;

        Kademlia::CUInt128 target(start.target_hash.data());
        Kademlia::CSearch* search = kad2Reachable
            ? Kademlia::CSearchManager::PrepareLookup(Kademlia::CSearch::FILE, false, target)
            : NULL;
        const uint64_t jobKey = ExitOpKey(job.circ_id, job.req_id);
        {
            // Register before CSearch::Go can deliver an immediate/local result.
            CSingleLock pl(&m_pendingLock, TRUE);
            m_searchJobs[jobKey] = job;
        }
        if (search != NULL) {
            search->SetK6GatewaySourceLookup(job.circ_id, job.req_id);
            const uint32 searchId = search->GetSearchID();
            const bool started = Kademlia::CSearchManager::StartSearch(search);
            CSingleLock pl(&m_pendingLock, TRUE);
            auto registered = m_searchJobs.find(jobKey);
            if (registered != m_searchJobs.end()) {
                registered->second.lookupStarted = started;
                registered->second.kad2LookupStarted = started;
                if (started) registered->second.kadSearchIds.push_back(searchId);
            }
        }
        bool nativeStarted = false;
        if (wantKad6 && Kademlia::CKademlia::GetUDPListener() != NULL)
            nativeStarted = Kademlia::CKademlia::GetUDPListener()->StartKad6SourceLookup(
                start.target_hash, job.circ_id, job.req_id, job.maxResults);
        if (nativeStarted) {
            CSingleLock pl(&m_pendingLock, TRUE);
            auto registered = m_searchJobs.find(jobKey);
            if (registered != m_searchJobs.end()) {
                registered->second.lookupStarted = true;
                registered->second.kad6LookupStarted = true;
                registered->second.kadReachable = true;
            }
        }
        return;
    }
    if (start.query.empty() ||
        !kad6::Kad6IsValidUtf8NoNul(start.query.data(), start.query.size())) {
        finishNow(kad6::K6SearchEndStatus::PolicyDenied);
        return;
    }

    // Require the same Unicode lowercase+trim normalization the origin-side
    // SearchStreams path applies before it emits UTF-8. This keeps the routed
    // target, exit lookup and displayed keyword byte-for-byte coherent.
    const std::string queryUtf8(start.query.begin(), start.query.end());
    CString searchWord = EseUtf8CString(queryUtf8);
    searchWord.MakeLower();
    searchWord.Trim();
    const std::vector<uint8_t> normalized = EseCStringUtf8(searchWord);
    if (normalized.empty() || normalized.size() != start.query.size() ||
        memcmp(normalized.data(), start.query.data(), normalized.size()) != 0) {
        finishNow(kad6::K6SearchEndStatus::PolicyDenied);
        return;
    }
    const std::string keyword(normalized.begin(), normalized.end());

    // Bind routing target to the exact query. This rejects a request that asks
    // for one keyword while steering accounting/routing toward another hash.
    Kademlia::CUInt128 expectedTarget;
    const CStringA keywordA(keyword.data(), (int)keyword.size());
    EseLiveGetKeywordHash(keywordA, &expectedTarget);
    uint8_t expectedBytes[16];
    expectedTarget.ToByteArray(expectedBytes);
    if (memcmp(expectedBytes, start.target_hash.data(), sizeof expectedBytes) != 0) {
        finishNow(kad6::K6SearchEndStatus::PolicyDenied);
        return;
    }

    TunnelSearchJob job;
    job.circ_id = ctx.circ->Id();
    job.req_id = ctx.req_id;
    job.keyword = keyword;
    job.canonicalK6 = true;
    job.searchKind = kad6::kK6SearchKindLive;
    job.targetHash = start.target_hash;
    job.maxResults = start.max_results;
    job.started = GetTickCount();
    job.deadline = job.started + (std::min<DWORD>)(TUN_SEARCH_WINDOW_MS,
                                                   (DWORD)start.deadline_ms);
    job.kadReachable = Kademlia::CKademlia::IsConnected();
    try {
        if (theApp.liveStreamManager)
            job.lookupStarted = theApp.liveStreamManager->GetKadBridge().SearchStreams(
                searchWord, &job.kadSearchIds, /*bForceDirect*/true);
    } catch (...) {}

    CSingleLock pl(&m_pendingLock, TRUE);
    m_searchJobs[ExitOpKey(job.circ_id, job.req_id)] = std::move(job);
}

bool CLiveTunnel::OnKad6GatewaySourceResult(uint32_t circuitId, uint32_t requestId,
                                            const uint8_t userHash[16], uint8_t sourceType,
                                            uint32_t ip, uint16_t tcpPort, uint16_t udpPort,
                                            uint8_t cryptOptions, uint16_t reachCaps,
                                            const uint8_t* ipv6OrNull)
{
    if (circuitId == 0 || requestId == 0 || userHash == NULL || tcpPort == 0 ||
        (sourceType != 1 && sourceType != 4))
        return false; // LowID/callback authority is intentionally not virtualized.

    TunnelSearchJob::SourceCandidate candidate;
    memcpy(candidate.userHash.data(), userHash, candidate.userHash.size());
    candidate.sourceType = sourceType;
    candidate.cryptOptions = cryptOptions;
    candidate.reachCaps = reachCaps;
    candidate.networkOrigin = kad6::kK6NetOriginKad2;
    candidate.provenance = kad6::K6Provenance::KadResult;
    candidate.score = 100 + (ipv6OrNull != NULL ? 10 : 0) +
        ((reachCaps & 0x0001u) != 0 ? 5 : 0);
    candidate.endpoint.tcp_port = tcpPort;
    candidate.endpoint.udp_port = udpPort;
    candidate.endpoint.transport_flags = kad6::kK6EpTcpEd2k;
    candidate.endpoint.valid_until = static_cast<uint64>(time(NULL)) +
        kad6::kK6TicketMaxTtlSeconds;
    if (ipv6OrNull != NULL) {
        candidate.endpoint.addr.family = kad6::Kad6Address::Family::IPv6;
        memcpy(candidate.endpoint.addr.addr.data(), ipv6OrNull, 16);
    } else if (ip != 0) {
        candidate.endpoint.addr.family = kad6::Kad6Address::Family::IPv4;
        candidate.endpoint.addr.addr = {static_cast<uint8_t>(ip),
            static_cast<uint8_t>(ip >> 8), static_cast<uint8_t>(ip >> 16),
            static_cast<uint8_t>(ip >> 24)};
    } else {
        return false;
    }
    if (!K6AllowTicketTarget(this,
            static_cast<kad6::Byte>(kad6::K6TicketService::Ed2kTcp), candidate.endpoint)) {
        m_k6Metrics.Add(kad6::K6MetricFamily::SourceCandidateTotal,
            0, 1, 0, 1, static_cast<uint64>(time(NULL)));
        return false;
    }

    CSingleLock pl(&m_pendingLock, TRUE);
    auto job = m_searchJobs.find(ExitOpKey(circuitId, requestId));
    if (job == m_searchJobs.end() ||
        job->second.searchKind != kad6::kK6SearchKindSourceHash ||
        job->second.sourceCandidates.size() >= job->second.maxResults)
        return false;
    for (const auto& old : job->second.sourceCandidates) {
        if (old.userHash == candidate.userHash && old.endpoint.addr == candidate.endpoint.addr &&
            old.endpoint.tcp_port == candidate.endpoint.tcp_port) {
            m_k6Metrics.Add(kad6::K6MetricFamily::SourceCandidateTotal,
                0, 1, 0, 1, static_cast<uint64>(time(NULL)));
            return false;
        }
    }
    const auto history = m_k6SourceScores.find(K6SourceScoreKey(
        candidate.endpoint, candidate.networkOrigin));
    if (history != m_k6SourceScores.end()) {
        const uint32 bonus = (std::min<uint32>)(100, history->second.successes * 20u);
        const uint32 penalty = (std::min<uint32>)(80, history->second.failures * 10u);
        candidate.score += bonus;
        candidate.score = candidate.score > penalty ? candidate.score - penalty : 0;
    }
    job->second.sourceCandidates.push_back(std::move(candidate));
    const size_t count = job->second.sourceCandidates.size();
    const double elapsed = static_cast<double>(GetTickCount() - job->second.started);
    if (!job->second.firstSourceMetric) {
        job->second.firstSourceMetric = true;
        m_k6Metrics.Observe(kad6::K6MetricFamily::SearchLatencyMs,
            0, 0, 0, elapsed, static_cast<uint64>(time(NULL)));
    }
    if (count >= 5 && !job->second.fiveSourceMetric) {
        job->second.fiveSourceMetric = true;
        m_k6Metrics.Observe(kad6::K6MetricFamily::SearchLatencyMs,
            1, 0, 0, elapsed, static_cast<uint64>(time(NULL)));
    }
    m_k6Metrics.Add(kad6::K6MetricFamily::SourceCandidateTotal,
        0, 0, 0, 1, static_cast<uint64>(time(NULL)));
    return true;
}

bool CLiveTunnel::OnKad6NativeSourceRecord(uint32_t circuitId,
                                            uint32_t requestId,
                                            const kad6::K6SourceRecord& record)
{
    if (circuitId == 0 || requestId == 0 || record.exits.empty()) return false;
    const uint64 now = static_cast<uint64>(time(NULL));
    const kad6::Kad6CryptoHooks crypto = MakeKad6HostCryptoHooks();
    if (kad6::VerifyK6SourceRecord(crypto, record) != kad6::Kad6Status::Ok) {
        m_k6Metrics.Add(kad6::K6MetricFamily::SourceCandidateTotal,
            1, 1, 0, 1, now);
        return false;
    }
    if (kad6::K6SourceRecordCheckFresh(record, now) != kad6::Kad6Status::Ok) {
        m_k6Metrics.Add(kad6::K6MetricFamily::SourceStaleTotal,
            1, 0, 0, 1, now);
        return false;
    }
    std::vector<uint8_t> canonical;
    kad6::Hash32 digest{};
    if (kad6::EncodeK6SourceRecord(record, canonical) != kad6::Kad6Status::Ok ||
        !crypto.sha256 || !crypto.sha256(canonical.data(), canonical.size(), digest.data()))
        return false;

    bool inserted = false;
    CSingleLock pl(&m_pendingLock, TRUE);
    auto job = m_searchJobs.find(ExitOpKey(circuitId, requestId));
    if (job == m_searchJobs.end() ||
        job->second.searchKind != kad6::kK6SearchKindSourceHash ||
        job->second.targetHash != record.object_hash)
        return false;

    for (const kad6::K6ExitDescriptor& exit : record.exits) {
        if (exit.exit_expires_at <= now || exit.endpoint.valid_until <= now ||
            exit.endpoint.tcp_port == 0 ||
            !K6AllowTicketTarget(this,
                static_cast<kad6::Byte>(kad6::K6TicketService::Ed2kTcp),
                exit.endpoint))
            continue;
        TunnelSearchJob::SourceCandidate candidate;
        candidate.userHash = record.source_pseudonym;
        candidate.endpoint = exit.endpoint;
        candidate.sourceType = exit.endpoint.addr.family ==
            kad6::Kad6Address::Family::IPv6 ? 4 : 1;
        candidate.reachCaps = static_cast<uint16_t>(exit.caps & 0xffffu);
        candidate.networkOrigin = kad6::kK6NetOriginKad6;
        candidate.provenance = kad6::K6Provenance::Routing;
        candidate.provenanceDigest = digest;
        const uint64 remaining = (std::min<uint64>)(
            record.expires_at - now, 24ull * 60 * 60);
        candidate.score = 200u + static_cast<uint32_t>(remaining / 3600u) +
            (exit.endpoint.addr.family == kad6::Kad6Address::Family::IPv6 ? 10u : 0u);
        const auto history = m_k6SourceScores.find(K6SourceScoreKey(
            candidate.endpoint, candidate.networkOrigin));
        if (history != m_k6SourceScores.end()) {
            const uint32 bonus = (std::min<uint32>)(100, history->second.successes * 20u);
            const uint32 penalty = (std::min<uint32>)(80, history->second.failures * 10u);
            candidate.score += bonus;
            candidate.score = candidate.score > penalty ? candidate.score - penalty : 0;
        }

        bool duplicate = false;
        for (auto& old : job->second.sourceCandidates) {
            if (old.userHash == candidate.userHash &&
                old.endpoint.addr == candidate.endpoint.addr &&
                old.endpoint.tcp_port == candidate.endpoint.tcp_port) {
                if (candidate.score > old.score) old = candidate;
                duplicate = true;
                break;
            }
        }
        if (duplicate) {
            m_k6Metrics.Add(kad6::K6MetricFamily::SourceCandidateTotal,
                1, 1, 0, 1, now);
        }
        if (!duplicate && job->second.sourceCandidates.size() <
                (std::min<size_t>)(200, (std::max<size_t>)(
                    job->second.maxResults * 2u, job->second.maxResults + 8u))) {
            job->second.sourceCandidates.push_back(std::move(candidate));
            inserted = true;
            const size_t count = job->second.sourceCandidates.size();
            const double elapsed = static_cast<double>(GetTickCount() - job->second.started);
            if (!job->second.firstSourceMetric) {
                job->second.firstSourceMetric = true;
                m_k6Metrics.Observe(kad6::K6MetricFamily::SearchLatencyMs,
                    0, 1, 0, elapsed, now);
            }
            if (count >= 5 && !job->second.fiveSourceMetric) {
                job->second.fiveSourceMetric = true;
                m_k6Metrics.Observe(kad6::K6MetricFamily::SearchLatencyMs,
                    1, 1, 0, elapsed, now);
            }
            m_k6Metrics.Add(kad6::K6MetricFamily::SourceCandidateTotal,
                1, 0, 0, 1, now);
        }
    }
    return inserted;
}

void CLiveTunnel::OnKad6SourceLookupRpc(uint8_t alpha, uint8_t result)
{
    const uint8_t alphaBucket = alpha <= 3 ? 0 : (alpha <= 5 ? 1 : 2);
    if (result > 3) result = 2;
    m_k6Metrics.Add(kad6::K6MetricFamily::SearchRpcTotal,
        1, alphaBucket, result, 1, static_cast<uint64>(time(NULL)));
}

std::string CLiveTunnel::K6BinaryKey(const uint8_t* bytes, size_t length)
{
    return bytes && length ? std::string(reinterpret_cast<const char*>(bytes), length)
                           : std::string();
}

std::string CLiveTunnel::K6SourceScoreKey(const kad6::K6Endpoint& endpoint,
                                          uint8 networkOrigin)
{
    std::string key;
    key.reserve(20);
    key.push_back(static_cast<char>(networkOrigin));
    key.push_back(static_cast<char>(endpoint.addr.family));
    key.append(reinterpret_cast<const char*>(endpoint.addr.addr.data()),
               endpoint.addr.addr.size());
    key.push_back(static_cast<char>(endpoint.tcp_port));
    key.push_back(static_cast<char>(endpoint.tcp_port >> 8));
    return key;
}

namespace {
CString K6SourceEpochPath()
{
    return thePrefs.GetMuleDirectory(EMULE_CONFIGDIR) + _T("kad6_source_epochs.dat");
}

uint32_t K6ReadU32(const uint8_t* p)
{
    return static_cast<uint32_t>(p[0]) |
        (static_cast<uint32_t>(p[1]) << 8) |
        (static_cast<uint32_t>(p[2]) << 16) |
        (static_cast<uint32_t>(p[3]) << 24);
}

uint64_t K6ReadU64(const uint8_t* p)
{
    uint64_t value = 0;
    for (size_t i = 0; i < 8; ++i)
        value |= static_cast<uint64_t>(p[i]) << (8 * i);
    return value;
}
}

bool CLiveTunnel::EnsureK6SourceEpochsLoaded()
{
    if (m_k6SourceEpochsLoaded)
        return !m_k6SourceEpochsLoadFailed;
    m_k6SourceEpochsLoaded = true;
    m_k6SourceEpochsLoadFailed = false;
    m_k6SourceEpochs.clear();

    const CString path = K6SourceEpochPath();
    if (GetFileAttributes(path) == INVALID_FILE_ATTRIBUTES)
        return true;
    try {
        CFile file;
        if (!file.Open(path, CFile::modeRead | CFile::shareDenyWrite)) {
            m_k6SourceEpochsLoadFailed = true;
            return false;
        }
        const ULONGLONG length = file.GetLength();
        const ULONGLONG maximum = 12ull + 8192ull * 40ull;
        if (length < 12 || length > maximum) {
            file.Close(); m_k6SourceEpochsLoadFailed = true; return false;
        }
        std::vector<uint8_t> wire(static_cast<size_t>(length));
        const bool read = file.Read(wire.data(), static_cast<UINT>(wire.size())) == wire.size();
        file.Close();
        if (!read || memcmp(wire.data(), "K6SE", 4) != 0 || wire[4] != 1 ||
            wire[5] != 0 || wire[6] != 0 || wire[7] != 0) {
            m_k6SourceEpochsLoadFailed = true; return false;
        }
        const uint32_t count = K6ReadU32(wire.data() + 8);
        if (count > 8192 || wire.size() != 12u + static_cast<size_t>(count) * 40u) {
            m_k6SourceEpochsLoadFailed = true; return false;
        }
        for (uint32_t i = 0; i < count; ++i) {
            const uint8_t* entry = wire.data() + 12u + static_cast<size_t>(i) * 40u;
            uint8_t nonzero = 0;
            for (size_t j = 0; j < 32; ++j) nonzero |= entry[j];
            const uint64 epoch = K6ReadU64(entry + 32);
            const std::string key = K6BinaryKey(entry, 32);
            if (nonzero == 0 || epoch == 0 || m_k6SourceEpochs.find(key) != m_k6SourceEpochs.end()) {
                m_k6SourceEpochs.clear(); m_k6SourceEpochsLoadFailed = true; return false;
            }
            m_k6SourceEpochs[key] = epoch;
        }
        return true;
    }
    catch (CFileException* error) {
        error->Delete();
        m_k6SourceEpochs.clear();
        m_k6SourceEpochsLoadFailed = true;
        return false;
    }
}

bool CLiveTunnel::SaveK6SourceEpochs() const
{
    if (m_k6SourceEpochs.size() > 8192)
        return false;
    std::vector<uint8_t> wire;
    wire.reserve(12u + m_k6SourceEpochs.size() * 40u);
    wire.insert(wire.end(), {'K', '6', 'S', 'E', 1, 0, 0, 0});
    const uint32_t count = static_cast<uint32_t>(m_k6SourceEpochs.size());
    for (size_t i = 0; i < 4; ++i)
        wire.push_back(static_cast<uint8_t>(count >> (8 * i)));
    for (const auto& pair : m_k6SourceEpochs) {
        wire.insert(wire.end(), pair.first.begin(), pair.first.end());
        for (size_t i = 0; i < 8; ++i)
            wire.push_back(static_cast<uint8_t>(pair.second >> (8 * i)));
    }
    const CString path = K6SourceEpochPath();
    const CString temporary = path + _T(".new");
    try {
        CFile file(temporary, CFile::modeCreate | CFile::modeWrite | CFile::shareExclusive);
        file.Write(wire.data(), static_cast<UINT>(wire.size()));
        file.Flush();
        file.Close();
        if (!MoveFileEx(temporary, path,
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
            DeleteFile(temporary);
            return false;
        }
        return true;
    }
    catch (CFileException* error) {
        error->Delete();
        DeleteFile(temporary);
        return false;
    }
}

std::string CLiveTunnel::K6ShadowKey(const kad6::K6SourceLease& lease)
{
    std::string key = K6BinaryKey(lease.bind.file_hash.data(), lease.bind.file_hash.size());
    key.append(K6BinaryKey(lease.bound.virtual_endpoint.addr.addr.data(),
        lease.bound.virtual_endpoint.addr.family == kad6::Kad6Address::Family::IPv6 ? 16 : 4));
    key.push_back(static_cast<char>(lease.bound.virtual_endpoint.tcp_port & 0xff));
    key.push_back(static_cast<char>(lease.bound.virtual_endpoint.tcp_port >> 8));
    key.push_back(static_cast<char>(lease.bound.virtual_endpoint.udp_port & 0xff));
    key.push_back(static_cast<char>(lease.bound.virtual_endpoint.udp_port >> 8));
    return key;
}

bool CLiveTunnel::SendK6GatewayResponse(const TunnelRequestCtx& ctx, uint8_t msgType,
                                        const std::vector<uint8_t>& body)
{
    kad6::K6Frame response;
    response.msg_type = msgType;
    response.flags = kad6::kK6FlagResponse | kad6::kK6FlagFinal;
    response.request_id = ctx.req_id;
    response.body = body;
    std::vector<uint8_t> wire;
    if (kad6::EncodeK6Frame(response, wire) != kad6::Kad6Status::Ok) {
        AbortExitOperation(ctx.circ ? ctx.circ->Id() : 0, ctx.req_id);
        return false;
    }
    return CompleteExitOperation(ctx.circ->Id(), ctx.req_id, wire.data(), wire.size());
}

void CLiveTunnel::ExitHandle_Kad6QuotaKey(const TunnelRequestCtx& ctx,
                                          const kad6::K6Frame& frame)
{
    if (!frame.body.empty() || !BeginExitOperation(ctx, TUN_OP_KAD6_GATEWAY))
        return;
    if (!EnsureK6QuotaAuthority(static_cast<uint64>(time(NULL)))) {
        AbortExitOperation(ctx.circ->Id(), ctx.req_id);
        return;
    }
    SendK6GatewayResponse(ctx, kad6::kK6MsgQuotaKey, m_k6QuotaCertificateWire);
}

void CLiveTunnel::ExitHandle_Kad6QuotaIssue(const TunnelRequestCtx& ctx,
                                            const kad6::K6Frame& frame)
{
    kad6::K6QuotaBlindRequest request;
    size_t consumed = 0;
    if (kad6::DecodeK6QuotaBlindRequest(frame.body.data(), frame.body.size(),
            request, &consumed) != kad6::Kad6Status::Ok ||
        consumed != frame.body.size() ||
        !BeginExitOperation(ctx, TUN_OP_KAD6_GATEWAY))
        return;
    kad6::K6QuotaBlindResponse response;
    response.status = kad6::K6QuotaStatus::PolicyDenied;
    const uint64 now = static_cast<uint64>(time(NULL));
    kad6::Hash32 principal;
    std::array<uint8_t, 6> prefix48{};
    uint32 asn = 0;
    if (!EnsureK6QuotaAuthority(now))
        response.status = kad6::K6QuotaStatus::CryptoFailure;
    else if (!kad6::Kad6CtEqual(request.issuer_key_id.data(),
             m_k6QuotaCertificate.key_id.data(), request.issuer_key_id.size()))
        response.status = kad6::K6QuotaStatus::UnknownIssuer;
    else if (!K6QuotaPrincipal(ctx, principal, prefix48, asn))
        response.status = kad6::K6QuotaStatus::PolicyDenied;
    else if (request.version == 2 &&
             request.subepoch_slot != kad6::K6QuotaSubepoch(now))
        response.status = kad6::K6QuotaStatus::WrongEpoch;
    else {
        const uint64 epoch = kad6::K6QuotaEpoch(now);
        if (request.version == 1) {
            response.status = m_k6QuotaIssuerLimiter.Reserve(principal, epoch,
                request.blinded_messages.size());
        } else {
            kad6::K6QuotaHierarchyRequest budget;
            budget.principal = principal;
            budget.prefix48 = prefix48;
            budget.issuer_key_id = request.issuer_key_id;
            budget.asn = asn;
            budget.service = request.service;
            budget.now_ms = (std::max<uint64>)(1, K6ShapeNowUs() / 1000u);
            budget.units = request.blinded_messages.size();
            response.status = m_k6QuotaHierarchy.Reserve(budget);
        }
        if (response.status == kad6::K6QuotaStatus::Ok) {
            const kad6::K6QuotaCryptoHooks hooks = m_k6QuotaCrypto.Hooks();
            response.blind_signatures.reserve(request.blinded_messages.size());
            for (const std::vector<uint8_t>& blinded : request.blinded_messages) {
                std::vector<uint8_t> signature;
                if (!hooks.blind_sign || !hooks.blind_sign(hooks.context,
                        request.issuer_key_id, blinded.data(), blinded.size(), signature)) {
                    response.status = kad6::K6QuotaStatus::CryptoFailure;
                    response.blind_signatures.clear();
                    break;
                }
                response.blind_signatures.push_back(std::move(signature));
            }
            if (response.status == kad6::K6QuotaStatus::Ok)
                response.issuer_certificate = m_k6QuotaCertificateWire;
        }
    }
    std::vector<uint8_t> body;
    if (kad6::EncodeK6QuotaBlindResponse(response, body) != kad6::Kad6Status::Ok)
        AbortExitOperation(ctx.circ->Id(), ctx.req_id);
    else
        SendK6GatewayResponse(ctx, kad6::kK6MsgQuotaIssued, body);
}

void CLiveTunnel::ExitHandle_Kad6QuotaPresent(const TunnelRequestCtx& ctx,
                                              const kad6::K6Frame& frame)
{
    kad6::K6QuotaPresentation presentation;
    size_t consumed = 0;
    if (kad6::DecodeK6QuotaPresentation(frame.body.data(), frame.body.size(),
            presentation, &consumed) != kad6::Kad6Status::Ok ||
        consumed != frame.body.size() ||
        !BeginExitOperation(ctx, TUN_OP_KAD6_GATEWAY))
        return;
    kad6::K6QuotaPresentationResult result;
    result.status = kad6::K6QuotaStatus::BadRequest;
    const uint64 now = static_cast<uint64>(time(NULL));
    kad6::K6QuotaToken token;
    kad6::K6QuotaIssuerCertificate certificate;
    if (!EnsureK6QuotaAuthority(now))
        result.status = kad6::K6QuotaStatus::CryptoFailure;
    else if (kad6::DecodeK6QuotaPreparedMessage(presentation.prepared_message.data(),
                 presentation.prepared_message.size(), token) != kad6::Kad6Status::Ok ||
             kad6::DecodeK6QuotaIssuerCertificate(presentation.issuer_certificate.data(),
                 presentation.issuer_certificate.size(), certificate, &consumed) !=
                 kad6::Kad6Status::Ok || consumed != presentation.issuer_certificate.size())
        result.status = kad6::K6QuotaStatus::InvalidProof;
    else {
        result.status = kad6::VerifyAndSpendK6Quota(MakeKad6HostCryptoHooks(),
            m_k6QuotaCrypto.Hooks(), m_k6QuotaSpent, presentation, token.service,
            token.policy_id, kad6::K6QuotaEpoch(now), kad6::K6QuotaSubepoch(now),
            token.presentation_context_hash,
            K6QuotaIssuerTrusted(certificate.issuer_node_pub.data()), &token, &certificate);
        if (result.status == kad6::K6QuotaStatus::Ok) {
            const kad6::Kad6CryptoHooks identity = MakeKad6HostCryptoHooks();
            if (!identity.sha256 || !identity.sha256(token.admission_unit.data(),
                    token.admission_unit.size(), result.admission_unit_hash.data()))
                result.status = kad6::K6QuotaStatus::CryptoFailure;
            else {
                uint64 allocation = 0;
                for (unsigned i = 0; i < 8; ++i)
                    allocation |= static_cast<uint64>(result.admission_unit_hash[i]) << (8 * i);
                if (allocation == 0) allocation = 1;
                CSingleLock pl(&m_pendingLock, TRUE);
                const std::string grantKey = K6QuotaGrantKey(
                    ctx.circ->Id(), token.presentation_context_hash);
                if (m_k6QuotaGrants.size() >= kad6::kK6QuotaDefaultSpentCapacity ||
                    m_k6QuotaGrants.find(grantKey) != m_k6QuotaGrants.end() ||
                    !m_k6FairScheduler.RegisterAllocation(allocation, certificate.key_id,
                        4ull * 1024ull * 1024ull * 1024ull,
                        16ull * 4ull * 1024ull * 1024ull * 1024ull)) {
                    result.status = kad6::K6QuotaStatus::Capacity;
                } else {
                    K6QuotaGrant grant;
                    grant.service = token.service;
                    grant.context = token.presentation_context_hash;
                    grant.issuer = certificate.key_id;
                    grant.allocation_id = allocation;
                    grant.expires_at = token.version == 2
                        ? token.valid_epoch * kad6::kK6QuotaEpochSeconds +
                          (static_cast<uint64>(token.subepoch_slot) + 1) *
                              kad6::kK6QuotaSubepochSeconds
                        : (token.valid_epoch + 1) * kad6::kK6QuotaEpochSeconds;
                    m_k6QuotaGrants[grantKey] = grant;
                    result.valid_epoch = token.valid_epoch;
                }
            }
        }
    }
    std::vector<uint8_t> body;
    if (kad6::EncodeK6QuotaPresentationResult(result, body) != kad6::Kad6Status::Ok)
        AbortExitOperation(ctx.circ->Id(), ctx.req_id);
    else
        SendK6GatewayResponse(ctx, kad6::kK6MsgQuotaStatus, body);
}

void CLiveTunnel::ExitHandle_Kad6SourceBind(const TunnelRequestCtx& ctx,
                                            const kad6::K6Frame& frame)
{
    kad6::K6SourceBind bind;
    size_t consumed = 0;
    if (kad6::DecodeK6SourceBind(frame.body.data(), frame.body.size(), bind,
            &consumed) != kad6::Kad6Status::Ok || consumed != frame.body.size())
        return;
    if (!BeginExitOperation(ctx, TUN_OP_KAD6_GATEWAY)) return;

    const kad6::Kad6CryptoHooks crypto = MakeKad6HostCryptoHooks();
    const uint8_t* exitPub = NodeIdentityPub();
    auto finish = [&](kad6::K6SourceBoundStatus status,
                      kad6::K6SourceBound* accepted) {
        kad6::K6SourceBound result;
        if (accepted) result = *accepted;
        else {
            result.status = status;
            result.bind_nonce = bind.bind_nonce;
            if (exitPub) memcpy(result.exit_node_pub.data(), exitPub, result.exit_node_pub.size());
        }
        std::vector<uint8_t> body;
        if (!exitPub || kad6::SignK6SourceBound(crypto, NULL, 0, bind, result, body) !=
                kad6::Kad6Status::Ok) {
            AbortExitOperation(ctx.circ->Id(), ctx.req_id);
            return;
        }
        SendK6GatewayResponse(ctx, kad6::kK6MsgSourceBound, body);
    };

    if (!ConsumeK6QuotaGrant(ctx, kad6::K6QuotaService::ExitKad, frame)) {
        finish(kad6::K6SourceBoundStatus::Overloaded, NULL);
        return;
    }

    if (!m_k6Hardening.CanAdmit(kad6::K6Service::ExitKad) ||
        !K6EconomyAdmit(kad6::K6Service::ExitKad)) {
        const uint64 now = static_cast<uint64>(time(NULL));
        m_k6Metrics.Add(kad6::K6MetricFamily::ExitRejectTotal, 8, 0, 0, 1, now);
        m_k6Metrics.Add(kad6::K6MetricFamily::ExitAdmissionTotal, 1, 1, 0, 1, now);
        finish(kad6::K6SourceBoundStatus::Overloaded, NULL);
        return;
    }

    if (!exitPub || kad6::VerifyK6CompatProofV1(crypto, bind) != kad6::Kad6Status::Ok) {
        finish(kad6::K6SourceBoundStatus::BadProof, NULL);
        return;
    }

    {
        CSingleLock pl(&m_pendingLock, TRUE);
        if (!EnsureK6SourceEpochsLoaded()) {
            pl.Unlock();
            finish(kad6::K6SourceBoundStatus::Overloaded, NULL);
            return;
        }
    }

    // Same epoch+nonce on the same circuit is an idempotent retry. Replaying
    // it through another circuit is not: active leases are circuit-bound.
    {
        CSingleLock pl(&m_pendingLock, TRUE);
        for (const auto& pair : m_k6SourceLeases.Entries()) {
            const kad6::K6SourceLease& old = pair.second;
            if (old.state != kad6::K6SourceLeaseState::Closed &&
                old.state != kad6::K6SourceLeaseState::Draining &&
                old.expires_at > static_cast<uint64_t>(time(NULL)) &&
                old.circuit_id == ctx.circ->Id() &&
                old.bind.source_epoch == bind.source_epoch &&
                kad6::Kad6CtEqual(old.bind.bind_nonce.data(), bind.bind_nonce.data(), 16) &&
                kad6::Kad6CtEqual(old.bind.file_hash.data(), bind.file_hash.data(), 16)) {
                kad6::K6SourceBound copy = old.bound;
                pl.Unlock();
                finish(kad6::K6SourceBoundStatus::Ok, &copy);
                return;
            }
        }
        const std::string identity = K6BinaryKey(bind.compat_pub_fingerprint.data(), 32);
        auto seen = m_k6SourceEpochs.find(identity);
        if (seen != m_k6SourceEpochs.end() && bind.source_epoch <= seen->second) {
            pl.Unlock();
            finish(kad6::K6SourceBoundStatus::StaleEpoch, NULL);
            return;
        }
    }

    // K6-3 can safely expose the existing exit-terminated cohort endpoint.
    // Dedicated VEP admission stays fail-closed until a distinct TCP+UDP
    // listener slot exists (K6-5); sharing the main port would violate
    // K6-SRC-011 and create ambiguous pre-HELLO demultiplexing.
    kad6::K6BindingMode effective = bind.requested_mode;
    if (effective == kad6::K6BindingMode::Auto)
        effective = bind.commitment_kind == kad6::K6CommitmentKind::None
            ? kad6::K6BindingMode::DedicatedVep : kad6::K6BindingMode::Cohort;
    if (effective != kad6::K6BindingMode::Cohort ||
        bind.commitment_kind == kad6::K6CommitmentKind::None ||
        (bind.transport_mask & kad6::kK6TransportTcp) == 0 ||
        (bind.flags & kad6::kK6SourceAllowInbound) == 0) {
        finish(kad6::K6SourceBoundStatus::Unsupported, NULL);
        return;
    }

    // One shared front-door may host many file hashes, but a given hash may
    // map to only one content-equivalent cohort. Otherwise K6-5 could not
    // choose a backend from the requested hash without ambiguous fanout.
    {
        CSingleLock pl(&m_pendingLock, TRUE);
        for (const auto& pair : m_k6SourceLeases.Entries()) {
            const kad6::K6SourceLease& existing = pair.second;
            if (existing.state == kad6::K6SourceLeaseState::Closed ||
                existing.state == kad6::K6SourceLeaseState::Draining ||
                !kad6::Kad6CtEqual(existing.bind.file_hash.data(), bind.file_hash.data(), 16))
                continue;
            if (existing.bind.file_size != bind.file_size ||
                existing.bind.commitment_kind != bind.commitment_kind ||
                !kad6::Kad6CtEqual(existing.bind.content_commitment.data(),
                    bind.content_commitment.data(), 32)) {
                pl.Unlock();
                finish(kad6::K6SourceBoundStatus::Unsupported, NULL);
                return;
            }
        }
    }

    const uint32_t publicIp = theApp.GetPublicIP();
    uint16_t udpPort = Kademlia::CKademlia::GetPrefs()->GetUseExternKadPort()
        ? Kademlia::CKademlia::GetPrefs()->GetExternalKadPort() : 0;
    if (udpPort == 0) udpPort = Kademlia::CKademlia::GetPrefs()->GetInternKadPort();
    if (publicIp == 0 || theApp.GetAdvertisedTcpPort() == 0 || udpPort == 0) {
        finish(kad6::K6SourceBoundStatus::Overloaded, NULL);
        return;
    }

    uint8_t randomLease[8];
    if (!crypto.random_bytes || !crypto.random_bytes(randomLease, sizeof randomLease)) {
        finish(kad6::K6SourceBoundStatus::Overloaded, NULL);
        return;
    }
    {
        CSingleLock pl(&m_pendingLock, TRUE);
        const uint32_t admission = m_k6PublishBudget.AdmissionPermille(
            static_cast<uint64_t>(time(NULL)));
        const uint32_t sample = (static_cast<uint32_t>(randomLease[0]) |
            (static_cast<uint32_t>(randomLease[1]) << 8)) % 1000u;
        if (m_k6SourceLeases.ActiveSize() >= 4096 || sample >= admission) {
            pl.Unlock();
            finish(kad6::K6SourceBoundStatus::Overloaded, NULL);
            return;
        }
    }
    uint64_t leaseId = 0;
    for (size_t i = 0; i < sizeof randomLease; ++i)
        leaseId |= static_cast<uint64_t>(randomLease[i]) << (8 * i);
    if (leaseId == 0) leaseId = 1;

    const uint64_t now = static_cast<uint64_t>(time(NULL));
    kad6::K6SourceBound bound;
    bound.status = kad6::K6SourceBoundStatus::Ok;
    bound.transport_mask = bind.transport_mask;
    bound.flags = bind.flags;
    bound.binding_mode = kad6::K6BindingMode::Cohort;
    bound.identity_mode = kad6::K6IdentityMode::ExitTerminated;
    bound.endpoint_slot = 1; // shared, explicit cohort front-door slot
    bound.source_lease_id = leaseId;
    bound.lifetime_s = (std::min)(bind.requested_lifetime_s, 2u * 60u * 60u);
    bound.refresh_after_s = (std::max)(1u, bound.lifetime_s / 2u);
    bound.commitment_kind = bind.commitment_kind;
    bound.content_commitment = bind.content_commitment;
    bound.virtual_endpoint.addr.family = kad6::Kad6Address::Family::IPv4;
    bound.virtual_endpoint.addr.addr = {
        static_cast<uint8_t>(publicIp), static_cast<uint8_t>(publicIp >> 8),
        static_cast<uint8_t>(publicIp >> 16), static_cast<uint8_t>(publicIp >> 24)};
    bound.virtual_endpoint.tcp_port = theApp.GetAdvertisedTcpPort();
    bound.virtual_endpoint.udp_port = udpPort;
    bound.virtual_endpoint.transport_flags = kad6::kK6EpTcpEd2k |
        kad6::kK6EpKad2Gateway | kad6::kK6EpEd2kGateway;
    bound.virtual_endpoint.valid_until = now + bound.lifetime_s;
    bound.exit_apparent_ip = bound.virtual_endpoint.addr;
    memcpy(bound.exit_node_pub.data(), exitPub, bound.exit_node_pub.size());
    bound.bind_nonce = bind.bind_nonce;

    std::vector<uint8_t> cohortMaterial;
    static const char cohortLabel[] = "Kad6-Cohort-v1";
    cohortMaterial.insert(cohortMaterial.end(), cohortLabel,
                          cohortLabel + sizeof cohortLabel - 1);
    cohortMaterial.insert(cohortMaterial.end(), exitPub, exitPub + 32);
    cohortMaterial.insert(cohortMaterial.end(), bind.file_hash.begin(), bind.file_hash.end());
    for (size_t i = 0; i < 8; ++i)
        cohortMaterial.push_back(static_cast<uint8_t>(bind.file_size >> (8 * i)));
    cohortMaterial.insert(cohortMaterial.end(), bind.content_commitment.begin(),
                          bind.content_commitment.end());
    uint8_t digest[32];
    if (!crypto.sha256(cohortMaterial.data(), cohortMaterial.size(), digest)) {
        finish(kad6::K6SourceBoundStatus::Overloaded, NULL);
        return;
    }
    memcpy(bound.cohort_id.data(), digest, bound.cohort_id.size());

    std::vector<uint8_t> pseudoMaterial(bind.compat_proof.begin(),
                                        bind.compat_proof.begin() + 32);
    pseudoMaterial.insert(pseudoMaterial.end(), bind.bind_nonce.begin(), bind.bind_nonce.end());
    if (!crypto.sha256(pseudoMaterial.data(), pseudoMaterial.size(), digest)) {
        finish(kad6::K6SourceBoundStatus::Overloaded, NULL);
        return;
    }
    kad6::Hash16 pseudonym{};
    memcpy(pseudonym.data(), digest, pseudonym.size());

    std::vector<uint8_t> encoded;
    if (kad6::SignK6SourceBound(crypto, NULL, 0, bind, bound, encoded) !=
            kad6::Kad6Status::Ok) {
        finish(kad6::K6SourceBoundStatus::Overloaded, NULL);
        return;
    }
    {
        CSingleLock pl(&m_pendingLock, TRUE);
        const std::string identity = K6BinaryKey(bind.compat_pub_fingerprint.data(), 32);
        auto previous = m_k6SourceEpochs.find(identity);
        const bool hadPrevious = previous != m_k6SourceEpochs.end();
        const uint64 previousEpoch = hadPrevious ? previous->second : 0;
        if (!hadPrevious && m_k6SourceEpochs.size() >= 8192) {
            pl.Unlock();
            finish(kad6::K6SourceBoundStatus::Overloaded, NULL);
            return;
        }
        m_k6SourceEpochs[identity] = bind.source_epoch;
        if (!SaveK6SourceEpochs()) {
            if (hadPrevious) m_k6SourceEpochs[identity] = previousEpoch;
            else m_k6SourceEpochs.erase(identity);
            pl.Unlock();
            finish(kad6::K6SourceBoundStatus::Overloaded, NULL);
            return;
        }
        if (m_k6SourceLeases.AddBound(ctx.circ->Id(), pseudonym, bind, bound, now) !=
                kad6::Kad6Status::Ok) {
            pl.Unlock();
            finish(kad6::K6SourceBoundStatus::Overloaded, NULL);
            return;
        }
    }
    m_k6Metrics.Add(kad6::K6MetricFamily::ExitAdmissionTotal, 1, 0, 0, 1, now);
    SendK6GatewayResponse(ctx, kad6::kK6MsgSourceBound, encoded);
}

void CLiveTunnel::ExitHandle_Kad6SourceUnbind(const TunnelRequestCtx& ctx,
                                              const kad6::K6Frame& frame)
{
    kad6::K6SourceUnbind unbind;
    size_t consumed = 0;
    if (kad6::DecodeK6SourceUnbind(frame.body.data(), frame.body.size(), unbind,
            &consumed) != kad6::Kad6Status::Ok || consumed != frame.body.size()) return;
    {
        CSingleLock pl(&m_pendingLock, TRUE);
        kad6::K6SourceLease* lease = m_k6SourceLeases.Find(unbind.source_lease_id);
        if (!lease || lease->circuit_id != ctx.circ->Id() ||
            unbind.source_epoch < lease->bind.source_epoch ||
            !kad6::Kad6CtEqual(unbind.bind_nonce.data(), lease->bind.bind_nonce.data(), 16))
            return;
        m_k6SourceLeases.BeginDrain(unbind.source_lease_id);
        for (auto& pair : m_k6Publishes)
            if (pair.second.source_lease_id == unbind.source_lease_id) {
                pair.second.refresh_enabled = false;
                m_k6PublishCoalescer.Remove(pair.first);
            }
    }
    m_k6CohortScheduler.SetServing(unbind.source_lease_id, false);
}

void CLiveTunnel::ExitHandle_Kad6Publish(const TunnelRequestCtx& ctx,
                                         const kad6::K6Frame& frame)
{
    kad6::K6Publish publish;
    size_t consumed = 0;
    if (kad6::DecodeK6Publish(frame.body.data(), frame.body.size(), publish,
            &consumed) != kad6::Kad6Status::Ok || consumed != frame.body.size()) return;
    if (!BeginExitOperation(ctx, TUN_OP_KAD6_GATEWAY)) return;
    auto reject = [&](const char* detail) {
        kad6::K6PublishAck ack;
        ack.status = kad6::K6PublishStatus::Rejected;
        ack.error_detail = detail;
        std::vector<uint8_t> body;
        if (kad6::EncodeK6PublishAck(ack, body) != kad6::Kad6Status::Ok)
            AbortExitOperation(ctx.circ->Id(), ctx.req_id);
        else SendK6GatewayResponse(ctx, kad6::kK6MsgPublishAck, body);
    };

    if (!ConsumeK6QuotaGrant(ctx, kad6::K6QuotaService::ExitKad, frame)) {
        reject("anonymous quota required or context mismatch");
        return;
    }

    if (!m_k6Hardening.CanAdmit(kad6::K6Service::ExitKad)) {
        const uint64 now = static_cast<uint64>(time(NULL));
        m_k6Metrics.Add(kad6::K6MetricFamily::ExitRejectTotal, 8, 0, 0, 1, now);
        m_k6Metrics.Add(kad6::K6MetricFamily::ExitAdmissionTotal, 1, 1, 0, 1, now);
        reject("EXIT_KAD disabled by local kill switch");
        return;
    }

    if (publish.record_kind != kad6::K6RecordKind::Source &&
        publish.record_kind != kad6::K6RecordKind::Kad6SourceDescriptor) {
        reject("K6-3 accepts source records only");
        return;
    }

    uint64_t sourceLeaseId = 0;
    kad6::K6SourceRecord nativeRecord;
    if (publish.record_kind == kad6::K6RecordKind::Source) {
        // Canonical shadow descriptor v1: version u8 | source_lease_id u64 LE |
        // file_size u64 LE. Identity/hash remain in the authenticated PUBLISH.
        if (publish.record.size() != 17 || publish.record[0] != 1) {
            reject("bad shadow source descriptor");
            return;
        }
        for (size_t i = 0; i < 8; ++i)
            sourceLeaseId |= static_cast<uint64_t>(publish.record[1 + i]) << (8 * i);
    } else {
        consumed = 0;
        const kad6::Kad6CryptoHooks crypto = MakeKad6HostCryptoHooks();
        if (kad6::DecodeK6SourceRecord(publish.record.data(), publish.record.size(),
                nativeRecord, &consumed) != kad6::Kad6Status::Ok ||
            consumed != publish.record.size() ||
            kad6::VerifyK6SourceRecord(crypto, nativeRecord) != kad6::Kad6Status::Ok ||
            kad6::K6SourceRecordCheckFresh(nativeRecord, static_cast<uint64_t>(time(NULL))) !=
                kad6::Kad6Status::Ok ||
            nativeRecord.source_epoch != publish.record_epoch ||
            !kad6::Kad6CtEqual(nativeRecord.object_hash.data(), publish.target_hash.data(), 16) ||
            !kad6::Kad6CtEqual(nativeRecord.source_pseudonym.data(), publish.source_id.data(), 16)) {
            reject("invalid signed Kad6 source record");
            return;
        }
        const uint8_t* exitPub = NodeIdentityPub();
        if (exitPub) for (const auto& descriptor : nativeRecord.exits)
            if (kad6::Kad6CtEqual(descriptor.exit_node_pub.data(), exitPub, 32)) {
                sourceLeaseId = descriptor.lease_hint;
                break;
            }
    }

    kad6::K6SourceLease leaseCopy;
    kad6::K6CohortBackend servingBackend;
    bool registerServing = false;
    {
        CSingleLock pl(&m_pendingLock, TRUE);
        const kad6::K6SourceLease* lease = m_k6SourceLeases.Find(sourceLeaseId);
        if (!lease || lease->circuit_id != ctx.circ->Id() ||
            !m_k6SourceLeases.CanPublish(sourceLeaseId) ||
            !kad6::Kad6CtEqual(lease->bind.file_hash.data(), publish.target_hash.data(), 16) ||
            publish.record_epoch < lease->bind.source_epoch) {
            pl.Unlock(); reject("no matching active SourceLease"); return;
        }
        if (publish.record_kind == kad6::K6RecordKind::Source) {
            uint64_t descriptorSize = 0;
            for (size_t i = 0; i < 8; ++i)
                descriptorSize |= static_cast<uint64_t>(publish.record[9 + i]) << (8 * i);
            if (descriptorSize != lease->bind.file_size ||
                !kad6::Kad6CtEqual(lease->bind.compat_user_hash.data(), publish.source_id.data(), 16)) {
                pl.Unlock(); reject("source descriptor does not match lease"); return;
            }
        } else {
            bool matchingExit = false;
            for (const auto& descriptor : nativeRecord.exits)
                if (descriptor.lease_hint == sourceLeaseId &&
                    kad6::Kad6CtEqual(descriptor.exit_node_pub.data(),
                        lease->bound.exit_node_pub.data(), 32) &&
                    descriptor.endpoint.addr == lease->bound.virtual_endpoint.addr &&
                    descriptor.endpoint.tcp_port == lease->bound.virtual_endpoint.tcp_port &&
                    descriptor.endpoint.udp_port == lease->bound.virtual_endpoint.udp_port &&
                    descriptor.exit_expires_at <= lease->expires_at) {
                    matchingExit = true;
                    break;
                }
            if (!matchingExit) {
                pl.Unlock(); reject("native exit descriptor does not match lease"); return;
            }
        }
        const uint8_t* publishKey = publish.record_kind == kad6::K6RecordKind::Source
            ? lease->bind.compat_proof.data() : nativeRecord.pub_key.data();
        if ((publish.flags & kad6::kK6PublishFlagSigned) == 0 ||
            kad6::VerifyK6Publish(MakeKad6HostCryptoHooks(), publishKey, publish) !=
                kad6::Kad6Status::Ok) {
            pl.Unlock(); reject("invalid publish signature"); return;
        }
        for (const auto& pair : m_k6Publishes) {
            const K6ExitPublishRuntime& old = pair.second;
            if (old.source_lease_id == sourceLeaseId &&
                old.request.record_epoch == publish.record_epoch &&
                old.request.network_mask == publish.network_mask &&
                old.request.record == publish.record && old.refresh_enabled) {
                kad6::K6PublishAck ack;
                ack.status = old.status; ack.published_networks = old.published_networks;
                ack.replica_count = old.replicas;
                ack.effective_ttl_s = static_cast<uint32_t>((std::min<uint64_t>)(
                    old.expires_at > static_cast<uint64_t>(time(NULL))
                        ? old.expires_at - static_cast<uint64_t>(time(NULL)) : 0,
                    kad6::kK6PublishMaxTtlSeconds));
                ack.publish_lease_id = old.publish_lease_id;
                ack.record_epoch = old.request.record_epoch;
                ack.refresh_after_s = (std::max)(1u, ack.effective_ttl_s / 2u);
                std::vector<uint8_t> body;
                const bool ok = kad6::EncodeK6PublishAck(ack, body) == kad6::Kad6Status::Ok;
                pl.Unlock();
                if (ok) SendK6GatewayResponse(ctx, kad6::kK6MsgPublishAck, body);
                else reject("expired publish lease");
                return;
            }
        }
        leaseCopy = *lease;
    }

    uint8_t randomLease[8];
    const kad6::Kad6CryptoHooks crypto = MakeKad6HostCryptoHooks();
    if (!crypto.random_bytes || !crypto.random_bytes(randomLease, sizeof randomLease)) {
        reject("CSPRNG unavailable"); return;
    }
    uint64_t publishLeaseId = 0;
    for (size_t i = 0; i < 8; ++i)
        publishLeaseId |= static_cast<uint64_t>(randomLease[i]) << (8 * i);
    if (publishLeaseId == 0) publishLeaseId = 1;
    const uint64_t now = static_cast<uint64_t>(time(NULL));
    uint32_t ttl = (std::min)(publish.requested_ttl_s,
        static_cast<uint32_t>((std::min<uint64_t>)(
            leaseCopy.expires_at > now ? leaseCopy.expires_at - now : 0,
            kad6::kK6PublishMaxTtlSeconds)));
    if (publish.record_kind == kad6::K6RecordKind::Kad6SourceDescriptor)
        ttl = (std::min)(ttl, static_cast<uint32_t>((std::min<uint64_t>)(
            nativeRecord.expires_at > now ? nativeRecord.expires_at - now : 0,
            kad6::kK6PublishMaxTtlSeconds)));
    if (ttl < kad6::kK6PublishMinTtlSeconds) { reject("SourceLease expires too soon"); return; }

    K6ExitPublishRuntime runtime;
    runtime.request = publish; runtime.publish_lease_id = publishLeaseId;
    runtime.source_lease_id = sourceLeaseId; runtime.expires_at = now + ttl;
    runtime.primary_publish_lease_id = publishLeaseId;
    runtime.auto_refresh = (publish.flags & kad6::kK6PublishFlagRefresh) != 0;

    {
        CSingleLock pl(&m_pendingLock, TRUE);
        if (m_k6Publishes.size() >= 8192 ||
            m_k6Publishes.find(publishLeaseId) != m_k6Publishes.end()) {
            pl.Unlock(); reject("publish lease capacity exhausted"); return;
        }
    }

    bool queuedKad2 = false;
    if ((publish.network_mask & kad6::kK6PublishNetKad2) != 0) {
        const std::string shadowKey = K6ShadowKey(leaseCopy);
        CSingleLock pl(&m_pendingLock, TRUE);
        auto primary = m_k6ShadowPrimary.find(shadowKey);
        bool needsExteriorPublish = false;
        if (primary != m_k6ShadowPrimary.end()) {
            runtime.primary_publish_lease_id = primary->second;
            queuedKad2 = true;
        } else {
            m_k6ShadowPrimary[shadowKey] = publishLeaseId;
            needsExteriorPublish = true;
            queuedKad2 = true;
        }
        kad6::K6PublishSchedule schedule;
        schedule.publish_lease_id = publishLeaseId;
        schedule.target_hash = publish.target_hash;
        schedule.endpoint[0] = static_cast<uint8_t>(leaseCopy.bound.endpoint_slot);
        memcpy(schedule.endpoint.data() + 1,
               leaseCopy.bound.virtual_endpoint.addr.addr.data(), 4);
        schedule.endpoint[5] = static_cast<uint8_t>(leaseCopy.bound.virtual_endpoint.tcp_port);
        schedule.endpoint[6] = static_cast<uint8_t>(leaseCopy.bound.virtual_endpoint.tcp_port >> 8);
        schedule.endpoint[7] = static_cast<uint8_t>(leaseCopy.bound.virtual_endpoint.udp_port);
        schedule.endpoint[8] = static_cast<uint8_t>(leaseCopy.bound.virtual_endpoint.udp_port >> 8);
        schedule.record_class = static_cast<uint8_t>(publish.record_kind);
        schedule.due_at = now; schedule.expires_at = now + ttl;
        if (needsExteriorPublish) {
            uint64_t effective = 0;
            runtime.kad2_queued = m_k6PublishCoalescer.Enqueue(schedule, 30, effective);
            if (effective != 0)
                runtime.primary_publish_lease_id = effective;
        }
        m_k6Publishes[publishLeaseId] = runtime;
        pl.Unlock();
    } else {
        CSingleLock pl(&m_pendingLock, TRUE);
        m_k6Publishes[publishLeaseId] = runtime;
    }

    bool queuedNative = false;
    if ((publish.network_mask & kad6::kK6PublishNetKad6) != 0 &&
        publish.record_kind == kad6::K6RecordKind::Kad6SourceDescriptor &&
        Kademlia::CKademlia::GetUDPListener() != NULL)
        queuedNative = Kademlia::CKademlia::GetUDPListener()->PublishKad6SourceRecord(
            publishLeaseId, nativeRecord);
    if (queuedNative) {
        CSingleLock pl(&m_pendingLock, TRUE);
        auto stored = m_k6Publishes.find(publishLeaseId);
        if (stored != m_k6Publishes.end()) {
            stored->second.status = kad6::K6PublishStatus::Sent;
            stored->second.published_networks |= kad6::kK6PublishNetKad6;
            if (stored->second.auto_refresh)
                stored->second.next_native_refresh_at = now + (std::max<uint64>)(
                    kad6::kK6PublishMinTtlSeconds, ttl / 2u);
            registerServing = MarkK6SourceServingLocked(sourceLeaseId,
                servingBackend);
        }
    }
    if (registerServing) m_k6CohortScheduler.Register(servingBackend);
    if (!queuedKad2 && !queuedNative) {
        CSingleLock pl(&m_pendingLock, TRUE);
        m_k6Publishes.erase(publishLeaseId);
        pl.Unlock(); reject("requested network unavailable"); return;
    }

    kad6::K6PublishAck ack;
    {
        CSingleLock pl(&m_pendingLock, TRUE);
        const auto stored = m_k6Publishes.find(publishLeaseId);
        if (stored != m_k6Publishes.end()) {
            ack.status = stored->second.status;
            ack.published_networks = stored->second.published_networks;
        } else ack.status = kad6::K6PublishStatus::Queued;
    }
    ack.effective_ttl_s = ttl;
    ack.publish_lease_id = publishLeaseId;
    ack.record_epoch = publish.record_epoch;
    ack.refresh_after_s = (std::max)(1u, ttl / 2u);
    std::vector<uint8_t> body;
    if (kad6::EncodeK6PublishAck(ack, body) != kad6::Kad6Status::Ok)
        AbortExitOperation(ctx.circ->Id(), ctx.req_id);
    else {
        m_k6Metrics.Add(kad6::K6MetricFamily::PublishTotal,
            (publish.network_mask & kad6::kK6PublishNetKad6) != 0 ? 1 : 0,
            0, 0, 1, now);
        SendK6GatewayResponse(ctx, kad6::kK6MsgPublishAck, body);
    }
}

void CLiveTunnel::ExitHandle_Kad6Unpublish(const TunnelRequestCtx& ctx,
                                           const kad6::K6Frame& frame)
{
    kad6::K6Unpublish value;
    size_t consumed = 0;
    if (kad6::DecodeK6Unpublish(frame.body.data(), frame.body.size(), value,
            &consumed) != kad6::Kad6Status::Ok || consumed != frame.body.size()) return;
    uint64 sourceLeaseId = 0;
    {
        CSingleLock pl(&m_pendingLock, TRUE);
        auto it = m_k6Publishes.find(value.publish_lease_id);
        const kad6::K6SourceLease* source = it == m_k6Publishes.end() ? NULL
            : m_k6SourceLeases.Find(it->second.source_lease_id);
        if (it == m_k6Publishes.end() || !source ||
            source->circuit_id != ctx.circ->Id() ||
            it->second.request.record_epoch > value.record_epoch ||
            !kad6::Kad6CtEqual(it->second.request.target_hash.data(), value.target_hash.data(), 16) ||
            !kad6::Kad6CtEqual(it->second.request.source_id.data(), value.source_id.data(), 16)) return;
        it->second.refresh_enabled = false;
        m_k6PublishCoalescer.Remove(value.publish_lease_id);
        sourceLeaseId = it->second.source_lease_id;
        m_k6SourceLeases.BeginDrain(sourceLeaseId);
    }
    m_k6CohortScheduler.SetServing(sourceLeaseId, false);
}

std::string CLiveTunnel::K6AuthorizedTargetKey(uint32 circId, uint32 requestId,
                                               const kad6::Hash16& resultId)
{
    std::string key;
    key.resize(8 + resultId.size());
    for (int i = 0; i < 4; ++i) {
        key[i] = static_cast<char>(circId >> (8 * i));
        key[4 + i] = static_cast<char>(requestId >> (8 * i));
    }
    memcpy(&key[8], resultId.data(), resultId.size());
    return key;
}

bool CLiveTunnel::K6AllowTicketTarget(void*, kad6::Byte service,
                                      const kad6::K6Endpoint& endpoint)
{
    if (service != static_cast<kad6::Byte>(kad6::K6TicketService::Ed2kTcp))
        return false; // K6-4 implements TCP eD2K only; UDP authority stays closed.
    const uint16 port = endpoint.tcp_port;
    static const uint16 denied[] = {22,23,25,53,80,110,135,139,143,389,443,445,
        1433,2375,3306,3389,5432,5900,5985,6379,8080,9200,11211};
    if (port == thePrefs.GetPort() || port == thePrefs.GetWSPort()) return false;
    for (size_t i = 0; i < _countof(denied); ++i) if (port == denied[i]) return false;
    if (endpoint.addr.family == kad6::Kad6Address::Family::IPv4) {
        uint32 ip = 0; memcpy(&ip, endpoint.addr.addr.data(), 4);
        return IsGoodIPPort(ip, port) && theApp.ipfilter != NULL &&
               !theApp.ipfilter->IsFiltered(ip) &&
               (theApp.clientlist == NULL || !theApp.clientlist->IsBannedClient(ip));
    }
    if (endpoint.addr.family == kad6::Kad6Address::Family::IPv6) {
        CAddress address(endpoint.addr.addr.data());
        return address.GetType() == CAddress::IPv6 && address.IsPublicIP();
    }
    return false;
}

bool CLiveTunnel::K6ConsumeTicket(void* context, const kad6::K6TargetTicket& ticket)
{
    CLiveTunnel* self = static_cast<CLiveTunnel*>(context);
    if (!self) return false;
    std::string key(reinterpret_cast<const char*>(ticket.nonce.data()), ticket.nonce.size());
    for (int i = 0; i < 8; ++i) key.push_back(static_cast<char>(ticket.lease_id >> (8 * i)));
    CSingleLock pl(&self->m_pendingLock, TRUE);
    K6UsedTicket& used = self->m_k6UsedTickets[key];
    if (used.used >= ticket.max_connections) return false;
    ++used.used; used.expires_at = ticket.expires_at;
    return true;
}

kad6::K6TargetPolicy CLiveTunnel::K6TicketPolicy()
{
    kad6::K6TargetPolicy policy;
    policy.context = this;
    policy.allow_target = &CLiveTunnel::K6AllowTicketTarget;
    policy.consume_use = &CLiveTunnel::K6ConsumeTicket;
    return policy;
}

bool CLiveTunnel::IssueK6RuntimeTicket(const K6AuthorizedTarget& target, uint64 maxBytes,
                                       kad6::K6Provenance provenance, uint64 session,
                                       uint64 stream, uint64 sequence,
                                       std::vector<uint8_t>& wire)
{
    wire.clear(); if (!m_k6TicketSecretReady || maxBytes == 0) return false;
    const uint64 now = static_cast<uint64>(time(NULL));
    kad6::K6TargetTicket ticket;
    ticket.service = static_cast<kad6::Byte>(kad6::K6TicketService::Ed2kTcp);
    ticket.provenance_kind = static_cast<kad6::Byte>(provenance);
    ticket.provenance_flags = target.network_origin == kad6::kK6NetOriginKad6
        ? kad6::kK6ProvenanceFlagNativeKad6 : 0;
    ticket.provenance_session = session;
    ticket.provenance_stream = stream;
    ticket.provenance_seq = sequence;
    ticket.provenance_digest = target.digest;
    ticket.target_endpoint = target.endpoint;
    ticket.target_endpoint.valid_until = now + kad6::kK6TicketMaxTtlSeconds;
    ticket.object_hash = target.object_hash;
    ticket.issued_at = now;
    ticket.expires_at = now + kad6::kK6TicketMaxTtlSeconds;
    ticket.max_bytes = (std::min<uint64>)(maxBytes, 16ull * 1024ull * 1024ull * 1024ull);
    ticket.max_connections = 1;
    const kad6::Kad6CryptoHooks crypto = MakeKad6HostCryptoHooks();
    uint8 random[24];
    if (!crypto.random_bytes || !crypto.random_bytes(random, sizeof random)) return false;
    ticket.lease_id = 0; for (int i = 0; i < 8; ++i) ticket.lease_id |= static_cast<uint64>(random[i]) << (8 * i);
    memcpy(ticket.nonce.data(), random + 8, 16);
    if (ticket.lease_id == 0) ticket.lease_id = 1;
    return kad6::IssueK6TargetTicket(crypto, K6TicketPolicy(),
        m_k6TicketSecret.data(), m_k6TicketSecret.size(), ticket, wire) == kad6::Kad6Status::Ok;
}

void CLiveTunnel::ExitHandle_Kad6TargetTicketReq(const TunnelRequestCtx& ctx,
                                                  const kad6::K6Frame& frame)
{
    kad6::K6TargetTicketRequest request; size_t consumed = 0;
    if (kad6::DecodeK6TargetTicketRequest(frame.body.data(), frame.body.size(), request,
            &consumed) != kad6::Kad6Status::Ok || consumed != frame.body.size()) return;
    if (!BeginExitOperation(ctx, TUN_OP_KAD6_GATEWAY)) return;
    kad6::K6TargetTicketResponse response;
    response.status = kad6::K6TargetTicketStatus::NotFound;
    K6AuthorizedTarget target; bool found = false;
    {
        CSingleLock pl(&m_pendingLock, TRUE);
        const auto it = m_k6AuthorizedTargets.find(K6AuthorizedTargetKey(
            ctx.circ->Id(), request.source_request_id, request.result_id));
        if (it != m_k6AuthorizedTargets.end() &&
            it->second.expires_at > static_cast<uint64>(time(NULL)) &&
            it->second.object_hash == request.object_hash) {
            target = it->second; found = true;
        }
    }
    if (found) {
        if (request.service != static_cast<kad6::Byte>(kad6::K6TicketService::Ed2kTcp))
            response.status = kad6::K6TargetTicketStatus::PolicyDenied;
        else if (IssueK6RuntimeTicket(target, request.requested_max_bytes,
                    kad6::K6Provenance::KadResult, ctx.circ->Id(),
                    request.source_request_id, 0, response.ticket))
            response.status = kad6::K6TargetTicketStatus::Ok;
        else
            response.status = kad6::K6TargetTicketStatus::PolicyDenied;
    }
    std::vector<uint8_t> body;
    if (kad6::EncodeK6TargetTicketResponse(response, body) != kad6::Kad6Status::Ok)
        AbortExitOperation(ctx.circ->Id(), ctx.req_id);
    else SendK6GatewayResponse(ctx, kad6::kK6MsgTargetTicket, body);
}

bool CLiveTunnel::SendK6GatewayPush(const std::weak_ptr<CLiveCircuit>& weak,
                                    uint32 circId, uint32 requestId, uint8 msgType,
                                    uint16 flags, const std::vector<uint8_t>& body)
{
    std::shared_ptr<CLiveCircuit> circ = weak.lock();
    if (!circ || circ->Id() != circId || circ->State() != CircuitState::Active) return false;
    kad6::K6Frame frame; frame.msg_type = msgType;
    frame.flags = kad6::kK6FlagResponse | flags;
    frame.request_id = requestId; frame.body = body;
    std::vector<uint8_t> wire;
    if (kad6::EncodeK6Frame(frame, wire) != kad6::Kad6Status::Ok) return false;
    TunnelRequestCtx ctx; ctx.circ = circ; ctx.req_id = requestId;
    return SendReply(ctx, TUN_OP_KAD6_GATEWAY, wire.data(), wire.size());
}

void CLiveTunnel::ExitHandle_Kad6Dial(const TunnelRequestCtx& ctx,
                                      const kad6::K6Frame& frame)
{
    kad6::K6Dial dial; size_t consumed = 0;
    if (kad6::DecodeK6Dial(frame.body.data(), frame.body.size(), dial, &consumed) !=
            kad6::Kad6Status::Ok || consumed != frame.body.size()) return;
    if (!BeginExitOperation(ctx, TUN_OP_KAD6_GATEWAY)) return;
    uint64 quotaAllocation = 0;
    auto reject = [&](kad6::K6DialStatus status) {
        if (quotaAllocation != 0) {
            m_k6FairScheduler.ReleaseAllocation(quotaAllocation);
            quotaAllocation = 0;
        }
        kad6::K6DialResult result; result.stream_id = NewCircuitId();
        result.status = status; result.transport = dial.protocol;
        result.apparent_local_endpoint.addr.family = kad6::Kad6Address::Family::None;
        result.remote_endpoint.addr.family = kad6::Kad6Address::Family::None;
        std::vector<uint8_t> body;
        if (kad6::EncodeK6DialResult(result, body) == kad6::Kad6Status::Ok)
            SendK6GatewayResponse(ctx, kad6::kK6MsgDialOk, body);
        else AbortExitOperation(ctx.circ->Id(), ctx.req_id);
    };
    if (!ConsumeK6QuotaGrant(ctx, kad6::K6QuotaService::ExitEd2kDial,
            frame, &quotaAllocation)) {
        reject(kad6::K6DialStatus::PolicyDenied);
        return;
    }
    if (!m_k6Hardening.CanAdmit(kad6::K6Service::ExitEd2kDial) ||
        !K6EconomyAdmit(kad6::K6Service::ExitEd2kDial)) {
        const uint64 now = static_cast<uint64>(time(NULL));
        m_k6Metrics.Add(kad6::K6MetricFamily::ExitRejectTotal, 8, 0, 0, 1, now);
        m_k6Metrics.Add(kad6::K6MetricFamily::ExitAdmissionTotal, 2, 1, 0, 1, now);
        reject(kad6::K6DialStatus::PolicyDenied);
        return;
    }
    if (dial.protocol != kad6::K6GatewayTransport::TcpEd2k) { reject(kad6::K6DialStatus::Unsupported); return; }
    {
        CSingleLock pl(&m_pendingLock, TRUE);
        if (m_k6ExitStreams.size() >= 512) { pl.Unlock(); reject(kad6::K6DialStatus::Overloaded); return; }
    }
    kad6::K6TargetTicket ticket;
    if (kad6::VerifyK6TargetTicket(MakeKad6HostCryptoHooks(), K6TicketPolicy(),
            m_k6TicketSecret.data(), m_k6TicketSecret.size(), dial.ticket.data(),
            dial.ticket.size(), static_cast<uint64>(time(NULL)), ticket) != kad6::Kad6Status::Ok ||
        ticket.service != static_cast<kad6::Byte>(kad6::K6TicketService::Ed2kTcp)) {
        reject(kad6::K6DialStatus::TicketRejected); return;
    }

    kad6::K6Endpoint apparent; apparent.tcp_port = theApp.GetAdvertisedTcpPort();
    apparent.udp_port = theApp.GetAdvertisedUdpPort(); apparent.transport_flags = kad6::kK6EpEd2kGateway;
    apparent.valid_until = static_cast<uint64>(time(NULL)) + kad6::kK6VepMaxTtlSeconds;
    if (ticket.target_endpoint.addr.family == kad6::Kad6Address::Family::IPv4) {
        const uint32 publicIp = theApp.GetPublicIP();
        if (publicIp == 0 || !IsGoodIP(publicIp)) {
            reject(kad6::K6DialStatus::PolicyDenied); return;
        }
        apparent.addr.family = kad6::Kad6Address::Family::IPv4;
        memcpy(apparent.addr.addr.data(), &publicIp, 4);
    } else if (ticket.target_endpoint.addr.family == kad6::Kad6Address::Family::IPv6) {
        const CAddress v6 = CFirewallProberV6::Instance().GetDetectedV6IP();
        if (v6.GetType() != CAddress::IPv6 || !v6.IsPublicIP()) {
            reject(kad6::K6DialStatus::PolicyDenied); return;
        }
        apparent.addr.family = kad6::Kad6Address::Family::IPv6;
        memcpy(apparent.addr.addr.data(), v6.Data(), 16);
    } else { reject(kad6::K6DialStatus::PolicyDenied); return; }

    std::vector<uint8_t> initial; size_t offset = 0; bool initialOk = true;
    while (offset < dial.initial_data.size()) {
        if (dial.initial_data.size() - offset < kad6::kK6Ed2kHeaderSize) { initialOk = false; break; }
        const uint8_t* p = dial.initial_data.data() + offset;
        const uint32 packetLength = static_cast<uint32>(p[1]) |
            (static_cast<uint32>(p[2]) << 8) | (static_cast<uint32>(p[3]) << 16) |
            (static_cast<uint32>(p[4]) << 24);
        const size_t frameLength = 5ull + packetLength;
        if (packetLength == 0 || frameLength > dial.initial_data.size() - offset) { initialOk = false; break; }
        kad6::K6Ed2kFrameView view;
        if (kad6::DecodeK6Ed2kFrame(p, frameLength, view) != kad6::Kad6Status::Ok) { initialOk = false; break; }
        const kad6::K6Ed2kDisposition disposition = kad6::K6Ed2kPolicy(
            kad6::K6Ed2kDirection::OriginToRemote,
            kad6::ClassifyK6Ed2kFrame(view.protocol, view.opcode));
        std::vector<uint8_t> rewritten;
        if (disposition == kad6::K6Ed2kDisposition::RewriteEndpoint) {
            if (view.opcode == OP_HELLO || view.opcode == OP_HELLOANSWER)
                initialOk = SanitizeK6HelloFrame(p, frameLength, apparent, rewritten);
            else
                initialOk = kad6::RewriteK6Ed2kPublicIpAnswer(view, apparent.addr, rewritten) == kad6::Kad6Status::Ok;
        } else if (disposition == kad6::K6Ed2kDisposition::Pass)
            rewritten.assign(p, p + frameLength);
        else if (disposition == kad6::K6Ed2kDisposition::Drop) {
            offset += frameLength; continue;
        } else initialOk = false;
        if (!initialOk) break;
        initial.insert(initial.end(), rewritten.begin(), rewritten.end()); offset += frameLength;
    }
    if (!initialOk) { reject(kad6::K6DialStatus::BadInitialData); return; }
    if (initial.size() > ticket.max_bytes) {
        reject(kad6::K6DialStatus::PolicyDenied); return;
    }
    const uint64 streamMaxBytes = (std::min<uint64>)(
        ticket.max_bytes - initial.size(), quotaAllocation != 0
            ? 4ull * 1024ull * 1024ull * 1024ull
            : ticket.max_bytes - initial.size());

    uint64 streamId = 0; const kad6::Kad6CryptoHooks crypto = MakeKad6HostCryptoHooks();
    uint8 randomId[8];
    do { if (!crypto.random_bytes || !crypto.random_bytes(randomId, 8)) { reject(kad6::K6DialStatus::Overloaded); return; }
        streamId = 0; for (int i=0;i<8;++i) streamId |= static_cast<uint64>(randomId[i]) << (8*i);
    } while (streamId == 0 || m_k6ExitStreams.find(streamId) != m_k6ExitStreams.end());

    if (quotaAllocation != 0) {
        kad6::Hash32 targetHash{};
        std::vector<uint8_t> target(ticket.target_endpoint.addr.addr.begin(),
                                    ticket.target_endpoint.addr.addr.end());
        target.push_back(static_cast<uint8_t>(ticket.target_endpoint.tcp_port));
        target.push_back(static_cast<uint8_t>(ticket.target_endpoint.tcp_port >> 8));
        if (!crypto.sha256 || !crypto.sha256(target.data(), target.size(), targetHash.data()) ||
            !m_k6FairScheduler.RegisterStream(quotaAllocation, streamId, targetHash,
                ticket.max_bytes, 16ull * 1024ull * 1024ull * 1024ull)) {
            reject(kad6::K6DialStatus::Overloaded);
            return;
        }
        CSingleLock pl(&m_pendingLock, TRUE);
        m_k6FairAllocationByStream[streamId] = quotaAllocation;
    }

    uint32 ip = 0; uint32 id = 0x01000001u;
    if (ticket.target_endpoint.addr.family == kad6::Kad6Address::Family::IPv4) {
        memcpy(&ip, ticket.target_endpoint.addr.addr.data(), 4); id = ntohl(ip);
    }
    CKad6ExitClient* client = new CKad6ExitClient(NULL, ticket.target_endpoint.tcp_port,
        id, 0, 0, false);
    if (ip) client->SetIP(ip);
    else {
        CAddress target(ticket.target_endpoint.addr.addr.data());
        client->SetIPv6Address(target); client->SetConnectIP(target.ToSyntheticUInt32());
        client->SetUserIDHybrid(0x01000001u);
    }
    theApp.clientlist->AddClient(client);
    K6ExitStreamRuntime runtime; runtime.circ_id = ctx.circ->Id(); runtime.dial_request_id = ctx.req_id;
    runtime.quota_allocation_id = quotaAllocation;
    runtime.circuit = ctx.circ; runtime.ticket = ticket; runtime.apparent = apparent;
    runtime.network_origin = (ticket.provenance_flags &
        kad6::kK6ProvenanceFlagNativeKad6) != 0
        ? kad6::kK6NetOriginKad6 : kad6::kK6NetOriginKad2;
    runtime.client = client; runtime.flow = kad6::K6StreamFlowState(streamMaxBytes);
    runtime.stream_max_bytes = streamMaxBytes;
    runtime.initial_data = std::move(initial); runtime.created_at = runtime.last_activity = static_cast<uint64>(time(NULL));
    runtime.idle_timeout_ms = dial.idle_timeout_ms;
    runtime.connect_deadline = runtime.created_at + ((dial.connect_timeout_ms + 999u) / 1000u);
    runtime.idle_deadline = runtime.created_at + ((dial.idle_timeout_ms + 999u) / 1000u);
    {
        CSingleLock pl(&m_pendingLock, TRUE);
        if (!RegisterK6FlowControlLocked(runtime.circ_id, streamId)) {
            pl.Unlock();
            ReleaseK6FairStreamLocked(streamId);
            reject(kad6::K6DialStatus::Overloaded);
            if (client->Disconnected(_T("Kad6 flow-control capacity"))) delete client;
            return;
        }
        m_k6ExitStreams[streamId] = runtime;
    }
    const bool connecting = client->TryToConnect(true, true, RUNTIME_CLASS(CKad6ExitSocket));
    CKad6ExitSocket* socket = connecting ? DYNAMIC_DOWNCAST(CKad6ExitSocket, client->socket) : NULL;
    if (!socket) {
        CSingleLock pl(&m_pendingLock, TRUE); m_k6ExitStreams.erase(streamId);
        RemoveK6FlowControlLocked(runtime.circ_id, streamId);
        K6SourceScore& score = m_k6SourceScores[K6SourceScoreKey(
            runtime.ticket.target_endpoint, runtime.network_origin)];
        if (score.failures != (std::numeric_limits<uint32>::max)()) ++score.failures;
        score.last_seen = static_cast<uint64>(time(NULL));
        ReleaseK6FairStreamLocked(streamId); pl.Unlock();
        m_k6Metrics.Add(kad6::K6MetricFamily::SourceDialTotal,
            runtime.network_origin == kad6::kK6NetOriginKad6 ? 1 : 0,
            2, 0, 1, static_cast<uint64>(time(NULL)));
        reject(kad6::K6DialStatus::ConnectFailed);
        if (connecting && client->Disconnected(_T("Kad6 outgoing connect failed")))
            delete client;
        return;
    }
    socket->Initialize(streamId);
    {
        CSingleLock pl(&m_pendingLock, TRUE);
        auto stream = m_k6ExitStreams.find(streamId);
        if (stream != m_k6ExitStreams.end()) stream->second.socket = socket;
    }
}

void CLiveTunnel::OnK6ExitSocketConnect(uint64 streamId, CKad6ExitSocket* socket, int error)
{
    K6ExitStreamRuntime runtime; bool found = false;
    {
        CSingleLock pl(&m_pendingLock, TRUE);
        auto it = m_k6ExitStreams.find(streamId);
        if (it != m_k6ExitStreams.end() && it->second.socket == socket) {
            runtime = it->second; found = true;
            if (error == 0) {
                const uint64 now = static_cast<uint64>(time(NULL));
                it->second.connected = true;
                it->second.last_activity = now;
                it->second.idle_deadline = now +
                    ((it->second.idle_timeout_ms + 999u) / 1000u);
            }
            else {
                ReleaseK6FairStreamLocked(streamId);
                RemoveK6FlowControlLocked(it->second.circ_id, streamId);
                m_k6ExitStreams.erase(it);
            }
        }
    }
    if (!found) return;
    kad6::K6DialResult result; result.stream_id = streamId;
    result.status = error == 0 ? kad6::K6DialStatus::Ok : kad6::K6DialStatus::ConnectFailed;
    result.transport = kad6::K6GatewayTransport::TcpEd2k; result.apparent_local_endpoint = runtime.apparent;
    result.remote_endpoint = runtime.ticket.target_endpoint; result.max_bytes = runtime.stream_max_bytes;
    result.idle_timeout_ms = runtime.idle_timeout_ms;
    std::vector<uint8_t> body;
    if (kad6::EncodeK6DialResult(result, body) != kad6::Kad6Status::Ok) {
        CSingleLock pl(&m_pendingLock, TRUE); m_k6ExitStreams.erase(streamId);
        RemoveK6FlowControlLocked(runtime.circ_id, streamId);
        ReleaseK6FairStreamLocked(streamId); pl.Unlock();
        AbortExitOperation(runtime.circ_id, runtime.dial_request_id);
        if (socket) socket->Disconnect(_T("Kad6 DIAL result encode failed"));
        return;
    }
    if (error == 0) {
        size_t offset = 0;
        while (offset < runtime.initial_data.size()) {
            const uint8_t* p = runtime.initial_data.data() + offset;
            const uint32 n = static_cast<uint32>(p[1]) | (static_cast<uint32>(p[2]) << 8) |
                (static_cast<uint32>(p[3]) << 16) | (static_cast<uint32>(p[4]) << 24);
            const size_t total = 5ull + n;
            if (!socket->SendRawFrame(p, total)) { result.status = kad6::K6DialStatus::ConnectFailed; break; }
            offset += total;
        }
        kad6::EncodeK6DialResult(result, body);
    }
    {
        CSingleLock pl(&m_pendingLock, TRUE);
        K6SourceScore& score = m_k6SourceScores[K6SourceScoreKey(
            runtime.ticket.target_endpoint, runtime.network_origin)];
        if (result.status == kad6::K6DialStatus::Ok) {
            if (score.successes != (std::numeric_limits<uint32>::max)()) ++score.successes;
        } else if (score.failures != (std::numeric_limits<uint32>::max)()) {
            ++score.failures;
        }
        score.last_seen = static_cast<uint64>(time(NULL));
    }
    m_k6Metrics.Add(kad6::K6MetricFamily::SourceDialTotal,
        runtime.network_origin == kad6::kK6NetOriginKad6 ? 1 : 0,
        result.status == kad6::K6DialStatus::Ok ? 0 : 2, 0, 1,
        static_cast<uint64>(time(NULL)));
    if (result.status != kad6::K6DialStatus::Ok) {
        CSingleLock pl(&m_pendingLock, TRUE); m_k6ExitStreams.erase(streamId);
        RemoveK6FlowControlLocked(runtime.circ_id, streamId);
        ReleaseK6FairStreamLocked(streamId);
    }
    kad6::K6Frame response; response.msg_type = kad6::kK6MsgDialOk;
    response.flags = kad6::kK6FlagResponse | kad6::kK6FlagFinal;
    response.request_id = runtime.dial_request_id; response.body = body;
    std::vector<uint8_t> wire;
    if (kad6::EncodeK6Frame(response, wire) != kad6::Kad6Status::Ok ||
        !CompleteExitOperation(runtime.circ_id, runtime.dial_request_id,
                               wire.data(), wire.size())) {
        CSingleLock pl(&m_pendingLock, TRUE); m_k6ExitStreams.erase(streamId);
        RemoveK6FlowControlLocked(runtime.circ_id, streamId);
        ReleaseK6FairStreamLocked(streamId); pl.Unlock();
        if (socket) socket->Disconnect(_T("Kad6 DIAL reply failed"));
        return;
    }

    if (result.status != kad6::K6DialStatus::Ok) {
        if (socket) socket->Disconnect(_T("Kad6 initial data failed"));
        return;
    }

    if (result.status == kad6::K6DialStatus::Ok) {
        if (!SendK6InitialCredit(runtime.circ_id, streamId, 0,
                runtime.circuit, true)) {
            if (socket) socket->Disconnect(_T("Kad6 initial credit failed"));
            return;
        }
        const uint64 metricNow = static_cast<uint64>(time(NULL));
        m_k6Metrics.Add(kad6::K6MetricFamily::ExitAdmissionTotal, 2, 0, 0, 1,
                        metricNow);
        const uint8_t* pub = NodeIdentityPub();
        if (!pub) return;
        kad6::K6VirtualIdentityEndpoint vep;
        vep.apparent_source_ip = runtime.apparent.addr;
        vep.apparent_tcp_port = runtime.apparent.tcp_port;
        vep.apparent_udp_port = runtime.apparent.udp_port;
        memcpy(vep.exit_node_pub.data(), pub, 32);
        vep.source_lease_id = streamId;
        vep.valid_until = static_cast<uint64>(time(NULL)) + kad6::kK6VepMaxTtlSeconds;
        std::vector<uint8_t> vepBody;
        if (kad6::SignK6Vep(MakeKad6HostCryptoHooks(), vep, vepBody) == kad6::Kad6Status::Ok)
            SendK6GatewayPush(runtime.circuit, runtime.circ_id, 0,
                kad6::kK6MsgVep, kad6::kK6FlagFinal, vepBody);
    }
}

void CLiveTunnel::OnK6ExitSocketClosed(uint64 streamId, CKad6ExitSocket* socket, int error)
{
    (void)error;
    K6ExitStreamRuntime runtime; bool found = false;
    {
        CSingleLock pl(&m_pendingLock, TRUE);
        auto stream = m_k6ExitStreams.find(streamId);
        if (stream != m_k6ExitStreams.end() && stream->second.socket == socket) {
            runtime = stream->second;
            m_k6CohortScheduler.ReleaseStream(streamId);
            ReleaseK6FairStreamLocked(streamId);
            RemoveK6FlowControlLocked(stream->second.circ_id, streamId);
            m_k6ExitStreams.erase(stream);
            found = true;
        }
    }
    if (!found || !runtime.connected) return;
    kad6::K6StreamClose close; close.stream_id = streamId; close.reason_code = 1;
    close.last_tx_sequence = runtime.flow.next_sequence(0)
        ? runtime.flow.next_sequence(0) - 1 : 0;
    close.last_rx_sequence = runtime.flow.next_sequence(1)
        ? runtime.flow.next_sequence(1) - 1 : 0;
    close.total_tx_bytes = runtime.flow.total_bytes(0);
    close.total_rx_bytes = runtime.flow.total_bytes(1);
    std::vector<uint8_t> body;
    if (kad6::EncodeK6StreamClose(close, body) == kad6::Kad6Status::Ok)
        SendK6GatewayPush(runtime.circuit, runtime.circ_id, 0,
            kad6::kK6MsgStreamClose, kad6::kK6FlagFinal, body);
}

void CLiveTunnel::OnK6OriginSocketClosed(uint64 streamId, CKad6OriginSocket* socket)
{
    K6OriginStreamRuntime runtime;
    bool found = false;
    {
        CSingleLock pl(&m_pendingLock, TRUE);
        auto stream = m_k6OriginStreams.find(streamId);
        if (stream != m_k6OriginStreams.end() && stream->second.socket == socket) {
            runtime = stream->second;
            RemoveK6FlowControlLocked(stream->second.circ_id, streamId);
            m_k6OriginStreams.erase(stream);
            found = true;
        }
    }
    if (!found) return;
    if (runtime.client) runtime.client->ClearK6SecureIdentVep();

    kad6::K6StreamClose close;
    close.stream_id = streamId;
    close.reason_code = 1;
    close.last_tx_sequence = runtime.flow.next_sequence(0)
        ? runtime.flow.next_sequence(0) - 1 : 0;
    close.last_rx_sequence = runtime.flow.next_sequence(1)
        ? runtime.flow.next_sequence(1) - 1 : 0;
    close.total_tx_bytes = runtime.flow.total_bytes(0);
    close.total_rx_bytes = runtime.flow.total_bytes(1);
    std::vector<uint8_t> body, wire;
    kad6::K6Frame frame;
    frame.msg_type = kad6::kK6MsgStreamClose;
    frame.flags = kad6::kK6FlagLegacyEd2k | kad6::kK6FlagFinal;
    frame.request_id = NewCircuitId();
    if (kad6::EncodeK6StreamClose(close, body) == kad6::Kad6Status::Ok) {
        frame.body = std::move(body);
        if (kad6::EncodeK6Frame(frame, wire) == kad6::Kad6Status::Ok)
            SendMessagePinned(frame.request_id, TUN_OP_KAD6_GATEWAY,
                wire.data(), wire.size(), ESE_CAP_KAD6, runtime.circ_id);
    }
}

bool CLiveTunnel::HasK6ServingLeases() const
{
    CSingleLock pl(&m_pendingLock, TRUE);
    for (const auto& pair : m_k6SourceLeases.Entries())
        if (m_k6SourceLeases.CanAccept(pair.first)) return true;
    return false;
}

bool CLiveTunnel::MarkK6SourceServingLocked(uint64 sourceLeaseId,
                                            kad6::K6CohortBackend& backend)
{
    // MarkPublished is intentionally attempted first. If a second network
    // confirms an already-serving lease it returns BadValue, while
    // MarkServing remains idempotent for the Serving state.
    m_k6SourceLeases.MarkPublished(sourceLeaseId);
    if (m_k6SourceLeases.MarkServing(sourceLeaseId) != kad6::Kad6Status::Ok ||
        !m_k6SourceLeases.CanAccept(sourceLeaseId))
        return false;
    const kad6::K6SourceLease* lease = m_k6SourceLeases.Find(sourceLeaseId);
    if (!lease) return false;
    backend.lease_id = lease->lease_id;
    backend.circuit_id = lease->circuit_id;
    backend.file_hash = lease->bind.file_hash;
    backend.cohort_id = lease->bound.cohort_id;
    backend.serving = true;
    return true;
}

bool CLiveTunnel::ActivateK6Inbound(CKad6ExitSocket* socket,
                                    const kad6::Hash16& fileHash,
                                    const std::vector<std::vector<uint8_t>>& initialFrames)
{
    if (!socket || initialFrames.empty()) return false;
    if (!m_k6Hardening.CanAdmit(kad6::K6Service::ExitEd2kFull) ||
        !K6EconomyAdmit(kad6::K6Service::ExitEd2kFull)) {
        const uint64 now = static_cast<uint64>(time(NULL));
        m_k6Metrics.Add(kad6::K6MetricFamily::ExitRejectTotal, 8, 0, 0, 1, now);
        m_k6Metrics.Add(kad6::K6MetricFamily::ExitAdmissionTotal, 3, 1, 0, 1, now);
        return false;
    }

    const std::vector<uint8_t>* hello = NULL;
    for (const std::vector<uint8_t>& raw : initialFrames) {
        kad6::K6Ed2kFrameView view;
        if (kad6::DecodeK6Ed2kFrame(raw.data(), raw.size(), view) != kad6::Kad6Status::Ok)
            return false;
        if (!hello && kad6::ClassifyK6Ed2kFrame(view.protocol, view.opcode) ==
                kad6::K6Ed2kFrameClass::Hello)
            hello = &raw;
    }
    const std::vector<uint8_t>& request = initialFrames.back();
    kad6::K6Ed2kFrameView requestView;
    if (!hello || kad6::DecodeK6Ed2kFrame(request.data(), request.size(), requestView) !=
            kad6::Kad6Status::Ok || requestView.protocol != OP_EDONKEYPROT ||
        (requestView.opcode != OP_REQUESTFILENAME && requestView.opcode != OP_SETREQFILEID) ||
        requestView.payload_size < fileHash.size() ||
        !kad6::Kad6CtEqual(requestView.payload, fileHash.data(), fileHash.size()))
        return false;

    uint8 randomId[8];
    uint64 streamId = 0;
    const kad6::Kad6CryptoHooks crypto = MakeKad6HostCryptoHooks();
    if (!crypto.random_bytes) return false;
    do {
        if (!crypto.random_bytes(randomId, sizeof randomId)) return false;
        streamId = 0;
        for (size_t i = 0; i < sizeof randomId; ++i)
            streamId |= static_cast<uint64>(randomId[i]) << (8 * i);
    } while (streamId == 0);

    kad6::K6CohortBackend selected;
    kad6::K6SourceLease lease;
    {
        CSingleLock pl(&m_pendingLock, TRUE);
        if (m_k6ExitStreams.size() >= 512 ||
            m_k6ExitStreams.find(streamId) != m_k6ExitStreams.end()) return false;
        kad6::Hash16 cohort{};
        bool cohortSet = false;
        for (const auto& pair : m_k6SourceLeases.Entries()) {
            const kad6::K6SourceLease& candidate = pair.second;
            if (!m_k6SourceLeases.CanAccept(pair.first) ||
                !kad6::Kad6CtEqual(candidate.bind.file_hash.data(), fileHash.data(),
                    fileHash.size()))
                continue;
            if (!cohortSet) {
                cohort = candidate.bound.cohort_id;
                cohortSet = true;
            } else if (!kad6::Kad6CtEqual(cohort.data(),
                           candidate.bound.cohort_id.data(), cohort.size())) {
                // One shared endpoint cannot disambiguate distinct identities
                // for the same eD2K hash. Dedicated VEPs must handle that case.
                return false;
            }
        }
        if (!cohortSet || !m_k6CohortScheduler.Select(fileHash, cohort, streamId, selected))
            return false;
        const kad6::K6SourceLease* selectedLease = m_k6SourceLeases.Find(selected.lease_id);
        if (!selectedLease || !m_k6SourceLeases.CanAccept(selected.lease_id)) {
            m_k6CohortScheduler.ReleaseStream(streamId);
            ReleaseK6FairStreamLocked(streamId);
            return false;
        }
        lease = *selectedLease;
    }

    std::shared_ptr<CLiveCircuit> circuit;
    {
        CSingleLock lock(&m_lock, TRUE);
        for (const auto& candidate : m_circuits)
            if (candidate && candidate->Id() == selected.circuit_id &&
                candidate->State() == CircuitState::Active) {
                circuit = candidate;
                break;
            }
    }
    if (!circuit) {
        CSingleLock pl(&m_pendingLock, TRUE);
        m_k6CohortScheduler.ReleaseStream(streamId);
        ReleaseK6FairStreamLocked(streamId);
        return false;
    }

    const uint64 idleMs = 120000;
    uint64 maxBytes = 4ull * 1024ull * 1024ull * 1024ull;
    if (lease.bind.max_upload_bps != 0)
        maxBytes = (std::min)(maxBytes,
            static_cast<uint64>(lease.bind.max_upload_bps) * (idleMs / 1000u));
    if (!socket->BindInboundStream(streamId)) {
        CSingleLock pl(&m_pendingLock, TRUE);
        m_k6CohortScheduler.ReleaseStream(streamId);
        ReleaseK6FairStreamLocked(streamId);
        return false;
    }

    K6ExitStreamRuntime runtime;
    runtime.circ_id = selected.circuit_id;
    runtime.circuit = circuit;
    runtime.apparent = lease.bound.virtual_endpoint;
    runtime.socket = socket;
    runtime.client = socket->client;
    runtime.flow = kad6::K6StreamFlowState(maxBytes);
    runtime.stream_max_bytes = maxBytes;
    runtime.ticket.max_bytes = maxBytes;
    runtime.created_at = runtime.last_activity = static_cast<uint64>(time(NULL));
    runtime.idle_timeout_ms = static_cast<uint32>(idleMs);
    runtime.idle_deadline = runtime.created_at + (idleMs / 1000u);
    runtime.connected = true;
    runtime.inbound = true;
    {
        CSingleLock pl(&m_pendingLock, TRUE);
        if (!RegisterK6FlowControlLocked(runtime.circ_id, streamId)) {
            pl.Unlock();
            socket->Disconnect(_T("Kad6 flow-control capacity"));
            return false;
        }
        m_k6ExitStreams[streamId] = runtime;
    }
    m_k6Metrics.Add(kad6::K6MetricFamily::ExitAdmissionTotal, 3, 0, 0, 1,
                    runtime.created_at);

    kad6::K6DialResult accept;
    accept.stream_id = streamId;
    accept.status = kad6::K6DialStatus::Ok;
    accept.transport = kad6::K6GatewayTransport::TcpEd2k;
    accept.flags = 0x0001; // inbound front-door stream
    accept.apparent_local_endpoint = lease.bound.virtual_endpoint;
    // A needs a nonzero peer address for unchanged credit/client bookkeeping,
    // but disclosing the vanilla peer's network endpoint is unnecessary. Use
    // a stream-scoped RFC1918 pseudonym which can never be published or dialed.
    accept.remote_endpoint.addr.family = kad6::Kad6Address::Family::IPv4;
    accept.remote_endpoint.addr.addr = {10,
        static_cast<uint8_t>(streamId >> 16),
        static_cast<uint8_t>(streamId >> 8),
        static_cast<uint8_t>(streamId)};
    accept.max_bytes = maxBytes;
    accept.idle_timeout_ms = static_cast<uint32>(idleMs);
    std::vector<uint8_t> body;
    if (kad6::EncodeK6DialResult(accept, body) != kad6::Kad6Status::Ok ||
        !SendK6GatewayPush(circuit, selected.circuit_id, 0,
            kad6::kK6MsgAccept, kad6::kK6FlagFinal, body) ||
        !SendK6InitialCredit(selected.circuit_id, streamId, 0, circuit, true) ||
        !OnK6ExitPacket(streamId, hello->data(), hello->size()) ||
        !OnK6ExitPacket(streamId, request.data(), request.size())) {
        CSingleLock pl(&m_pendingLock, TRUE);
        m_k6ExitStreams.erase(streamId);
        RemoveK6FlowControlLocked(selected.circuit_id, streamId);
        m_k6CohortScheduler.ReleaseStream(streamId);
        ReleaseK6FairStreamLocked(streamId);
        pl.Unlock();
        socket->Disconnect(_T("Kad6 inbound activation failed"));
        return false;
    }
    LIVE_LOG("K6", "front-door selected lease=%llu stream=%llu circuit=%u",
        static_cast<unsigned long long>(selected.lease_id),
        static_cast<unsigned long long>(streamId), selected.circuit_id);
    return true;
}

void CLiveTunnel::ExitHandle_Kad6StreamData(const TunnelRequestCtx& ctx,
                                             const kad6::K6Frame& frame)
{
    kad6::K6StreamData data; size_t consumed = 0;
    if (kad6::DecodeK6StreamData(frame.body.data(), frame.body.size(), data, &consumed) !=
            kad6::Kad6Status::Ok || consumed != frame.body.size() || data.direction != 0 ||
        (data.flags & 0x02) == 0) return;
    kad6::K6Ed2kFrameView view;
    if (kad6::DecodeK6Ed2kFrame(data.data.data(), data.data.size(), view) != kad6::Kad6Status::Ok)
        return;
    CKad6ExitSocket* socket = NULL; kad6::K6Endpoint apparent;
    {
        CSingleLock pl(&m_pendingLock, TRUE);
        auto stream = m_k6ExitStreams.find(data.stream_id);
        auto receiver = m_k6ReceiveCredits.find(ctx.circ->Id());
        if (stream == m_k6ExitStreams.end() || stream->second.circ_id != ctx.circ->Id() ||
            !stream->second.connected ||
            receiver == m_k6ReceiveCredits.end() ||
            receiver->second.CanAccept(data.stream_id, 0, data.data.size()) !=
                kad6::Kad6Status::Ok ||
            stream->second.flow.CanAccept(data) != kad6::Kad6Status::Ok) return;
        if (receiver->second.Accept(data.stream_id, 0, data.data.size(),
                K6ShapeNowUs() / 1000u) != kad6::Kad6Status::Ok ||
            stream->second.flow.Accept(data) != kad6::Kad6Status::Ok) return;
        socket = stream->second.socket; apparent = stream->second.apparent;
        const uint64 now = static_cast<uint64>(time(NULL));
        const uint64 idle = (stream->second.idle_timeout_ms + 999u) / 1000u;
        stream->second.last_activity = now;
        stream->second.idle_deadline = now + idle;
    }
    const kad6::K6Ed2kDisposition disposition = kad6::K6Ed2kPolicy(
        kad6::K6Ed2kDirection::OriginToRemote,
        kad6::ClassifyK6Ed2kFrame(view.protocol, view.opcode));
    std::vector<uint8_t> rewritten;
    if (disposition == kad6::K6Ed2kDisposition::Pass)
        rewritten = data.data;
    else if (disposition == kad6::K6Ed2kDisposition::RewriteEndpoint) {
        const bool ok = (view.opcode == OP_HELLO || view.opcode == OP_HELLOANSWER)
            ? SanitizeK6HelloFrame(data.data.data(), data.data.size(), apparent, rewritten)
            : kad6::RewriteK6Ed2kPublicIpAnswer(view, apparent.addr, rewritten) == kad6::Kad6Status::Ok;
        if (!ok) {
            ConsumeK6ReceiveCredit(ctx.circ->Id(), data.stream_id, 0,
                data.data.size(), ctx.circ, true);
            return;
        }
    } else if (disposition == kad6::K6Ed2kDisposition::Drop) {
        ConsumeK6ReceiveCredit(ctx.circ->Id(), data.stream_id, 0,
            data.data.size(), ctx.circ, true);
        return;
    } else {
        ConsumeK6ReceiveCredit(ctx.circ->Id(), data.stream_id, 0,
            data.data.size(), ctx.circ, true);
        return;
    }
    bool fairStream = false;
    bool fairQueued = false;
    {
        CSingleLock pl(&m_pendingLock, TRUE);
        fairStream = m_k6FairAllocationByStream.find(data.stream_id) !=
            m_k6FairAllocationByStream.end();
        if (fairStream)
            fairQueued = QueueK6FairPayloadLocked(data.stream_id, 0,
                std::move(rewritten), data.data.size());
        if (fairStream && !fairQueued) ReleaseK6FairStreamLocked(data.stream_id);
    }
    if (fairStream) {
        if (!fairQueued && socket)
            socket->Disconnect(_T("Kad6 fair queue capacity exhausted"));
        return;
    }
    if (socket && socket->SendRawFrame(rewritten.data(), rewritten.size())) {
        bool inbound = false;
        {
            CSingleLock pl(&m_pendingLock, TRUE);
            const auto stream = m_k6ExitStreams.find(data.stream_id);
            inbound = stream != m_k6ExitStreams.end() && stream->second.inbound;
        }
        m_k6Metrics.Add(kad6::K6MetricFamily::ExitBytesTotal, 1,
            inbound ? 3 : 2, 0, static_cast<uint64>(rewritten.size()),
            static_cast<uint64>(time(NULL)));
        m_k6Metrics.Add(kad6::K6MetricFamily::TransportBytesTotal, 0, 1, 0,
            static_cast<uint64>(rewritten.size()), static_cast<uint64>(time(NULL)));
        {
            CSingleLock pl(&m_pendingLock, TRUE);
            m_k6EconomyUsefulBytes += static_cast<uint64>(rewritten.size());
        }
        ConsumeK6ReceiveCredit(ctx.circ->Id(), data.stream_id, 0,
            data.data.size(), ctx.circ, true);
    } else if (socket) {
        socket->Disconnect(_T("Kad6 downstream socket rejected frame"));
    }
}

void CLiveTunnel::ExitHandle_Kad6StreamHalfClose(const TunnelRequestCtx& ctx,
                                                  const kad6::K6Frame& frame)
{
    kad6::K6StreamHalfClose close; size_t consumed = 0;
    if (kad6::DecodeK6StreamHalfClose(frame.body.data(), frame.body.size(), close,
            &consumed) != kad6::Kad6Status::Ok || consumed != frame.body.size() ||
        close.direction != 0) return;
    CSingleLock pl(&m_pendingLock, TRUE);
    auto stream = m_k6ExitStreams.find(close.stream_id);
    if (stream != m_k6ExitStreams.end() && stream->second.circ_id == ctx.circ->Id())
        stream->second.flow.HalfClose(close);
}

void CLiveTunnel::ExitHandle_Kad6StreamClose(const TunnelRequestCtx& ctx,
                                              const kad6::K6Frame& frame)
{
    kad6::K6StreamClose close; size_t consumed = 0; CKad6ExitSocket* socket = NULL;
    if (kad6::DecodeK6StreamClose(frame.body.data(), frame.body.size(), close,
            &consumed) != kad6::Kad6Status::Ok || consumed != frame.body.size()) return;
    {
        CSingleLock pl(&m_pendingLock, TRUE);
        auto stream = m_k6ExitStreams.find(close.stream_id);
        if (stream == m_k6ExitStreams.end() || stream->second.circ_id != ctx.circ->Id() ||
            stream->second.flow.Close(close) != kad6::Kad6Status::Ok) return;
        socket = stream->second.socket;
        RemoveK6FlowControlLocked(stream->second.circ_id, close.stream_id);
        m_k6ExitStreams.erase(stream);
        m_k6CohortScheduler.ReleaseStream(close.stream_id);
        ReleaseK6FairStreamLocked(close.stream_id);
    }
    if (socket) socket->Disconnect(_T("Kad6 stream closed"));
}

void CLiveTunnel::ExitHandle_Kad6MaxStreamData(const TunnelRequestCtx& ctx,
                                                const kad6::K6Frame& frame)
{
    kad6::K6MaxStreamData credit;
    size_t consumed = 0;
    if (kad6::DecodeK6MaxStreamData(frame.body.data(), frame.body.size(), credit,
            &consumed) != kad6::Kad6Status::Ok || consumed != frame.body.size() ||
        credit.direction != 1)
        return;
    {
        CSingleLock pl(&m_pendingLock, TRUE);
        const auto stream = m_k6ExitStreams.find(credit.stream_id);
        const auto ledger = m_k6SendCredits.find(ctx.circ->Id());
        if (stream == m_k6ExitStreams.end() ||
            stream->second.circ_id != ctx.circ->Id() ||
            ledger == m_k6SendCredits.end() ||
            ledger->second.Grant(credit) != kad6::Kad6Status::Ok)
            return;
    }
    FlushK6ExitCredit(ctx.circ->Id());
}

void CLiveTunnel::ExitHandle_Kad6MaxData(const TunnelRequestCtx& ctx,
                                          const kad6::K6Frame& frame)
{
    kad6::K6MaxData credit;
    size_t consumed = 0;
    if (kad6::DecodeK6MaxData(frame.body.data(), frame.body.size(), credit,
            &consumed) != kad6::Kad6Status::Ok || consumed != frame.body.size() ||
        credit.direction != 1)
        return;
    {
        CSingleLock pl(&m_pendingLock, TRUE);
        const auto ledger = m_k6SendCredits.find(ctx.circ->Id());
        if (ledger == m_k6SendCredits.end() ||
            ledger->second.Grant(credit) != kad6::Kad6Status::Ok)
            return;
    }
    FlushK6ExitCredit(ctx.circ->Id());
}

bool CLiveTunnel::OnK6ExitPacket(uint64 streamId, const uint8_t* raw, size_t length)
{
    kad6::K6Ed2kFrameView view;
    if (kad6::DecodeK6Ed2kFrame(raw, length, view) != kad6::Kad6Status::Ok) return false;
    K6ExitStreamRuntime runtime; uint64 sequence = 0;
    {
        CSingleLock pl(&m_pendingLock, TRUE);
        auto stream = m_k6ExitStreams.find(streamId);
        if (stream == m_k6ExitStreams.end() || !stream->second.connected) return false;
        runtime = stream->second; sequence = stream->second.tx_sequence;
        const uint64 now = static_cast<uint64>(time(NULL));
        const uint64 idle = (stream->second.idle_timeout_ms + 999u) / 1000u;
        stream->second.last_activity = now;
        stream->second.idle_deadline = now + idle;
    }
    const kad6::K6Ed2kFrameClass frameClass = kad6::ClassifyK6Ed2kFrame(view.protocol, view.opcode);
    const kad6::K6Ed2kDisposition disposition = kad6::K6Ed2kPolicy(
        kad6::K6Ed2kDirection::RemoteToOrigin, frameClass);
    if (disposition == kad6::K6Ed2kDisposition::ConvertToHints) {
        kad6::K6ParsedPex pex;
        if (kad6::DecodeEd2kSourceExchange(view.opcode, view.payload, view.payload_size, pex) !=
                kad6::Kad6Status::Ok) return false;
        kad6::Hash32 digest{}; const kad6::Kad6CryptoHooks crypto = MakeKad6HostCryptoHooks();
        if (!crypto.sha256 || !crypto.sha256(raw, length, digest.data())) return false;
        kad6::K6SourceHints hints; hints.source_session_id = runtime.circ_id;
        hints.source_stream_id = streamId; hints.pex_version = pex.version;
        hints.object_hash = pex.object_hash; hints.exterior_message_hash = digest;
        {
            CSingleLock pl(&m_pendingLock, TRUE);
            auto stream = m_k6ExitStreams.find(streamId);
            if (stream == m_k6ExitStreams.end()) return false;
            hints.source_message_seq = stream->second.pex_sequence++;
        }
        std::set<std::string> dedupe;
        for (size_t i = 0; i < pex.sources.size() && hints.sources.size() < kad6::kK6SourceHintsMaxSources; ++i) {
            const kad6::K6ParsedPexSource& source = pex.sources[i];
            if (source.low_id || source.endpoint.tcp_port == 0) continue;
            std::string key(reinterpret_cast<const char*>(source.endpoint.addr.addr.data()), 16);
            key.push_back(static_cast<char>(source.endpoint.tcp_port));
            key.push_back(static_cast<char>(source.endpoint.tcp_port >> 8));
            if (!dedupe.insert(key).second) continue;
            K6AuthorizedTarget target; target.circ_id = runtime.circ_id;
            target.object_hash = pex.object_hash; target.digest = digest;
            target.endpoint = source.endpoint;
            target.endpoint.valid_until = static_cast<uint64>(time(NULL)) + kad6::kK6TicketMaxTtlSeconds;
            if (!K6AllowTicketTarget(this, static_cast<kad6::Byte>(kad6::K6TicketService::Ed2kTcp), target.endpoint))
                continue;
            kad6::K6SourceHint hint; hint.endpoint = target.endpoint;
            hint.user_hash = source.user_hash; hint.crypt_options = source.crypt_options;
            if (!IssueK6RuntimeTicket(target, runtime.ticket.max_bytes,
                    kad6::K6Provenance::Pex, runtime.circ_id, streamId,
                    hints.source_message_seq, hint.ticket)) continue;
            hints.sources.push_back(std::move(hint));
        }
        std::vector<uint8_t> body;
        return kad6::EncodeK6SourceHints(hints, body) == kad6::Kad6Status::Ok &&
            SendK6GatewayPush(runtime.circuit, runtime.circ_id, 0,
                kad6::kK6MsgSourceHints, kad6::kK6FlagFinal, body);
    }
    if (disposition == kad6::K6Ed2kDisposition::Drop) return true;
    if (disposition != kad6::K6Ed2kDisposition::Pass) return false;
    CKad6ExitSocket* pauseSocket = NULL;
    {
        CSingleLock pl(&m_pendingLock, TRUE);
        auto stream = m_k6ExitStreams.find(streamId);
        auto ledger = stream == m_k6ExitStreams.end()
            ? m_k6SendCredits.end() : m_k6SendCredits.find(stream->second.circ_id);
        if (stream == m_k6ExitStreams.end() || ledger == m_k6SendCredits.end())
            return false;
        const uint64 sent = ledger->second.stream_sent(streamId, 1);
        const uint64 received = stream->second.flow.total_bytes(0);
        const uint64 remaining = stream->second.stream_max_bytes == 0 ||
                sent + received >= stream->second.stream_max_bytes
            ? (stream->second.stream_max_bytes == 0
                ? (std::numeric_limits<uint64>::max)() : 0)
            : stream->second.stream_max_bytes - sent - received;
        const bool waitForCredit = !stream->second.pending_credit_frames.empty() ||
            ledger->second.Available(streamId, 1, remaining,
                (std::numeric_limits<uint64>::max)(),
                2u * 1024u * 1024u - stream->second.pending_credit_bytes) < length;
        if (waitForCredit) {
            if (stream->second.pending_credit_frames.size() >= 64 ||
                length > 2u * 1024u * 1024u - stream->second.pending_credit_bytes)
                return false;
            stream->second.pending_credit_frames.emplace_back(raw, raw + length);
            stream->second.pending_credit_bytes += length;
            if (stream->second.credit_stall_since_ms == 0)
                stream->second.credit_stall_since_ms = K6ShapeNowUs() / 1000u;
            pauseSocket = stream->second.socket;
        }
    }
    if (pauseSocket) {
        pauseSocket->SetKad6ReadPaused(true);
        return true;
    }
    kad6::K6StreamData data; data.stream_id = streamId; data.sequence = sequence;
    data.direction = 1; data.flags = 0x02; data.data.assign(raw, raw + length);
    std::vector<uint8_t> body;
    if (kad6::EncodeK6StreamData(data, body) != kad6::Kad6Status::Ok) return false;
    if (runtime.quota_allocation_id != 0) {
        CSingleLock pl(&m_pendingLock, TRUE);
        auto stream = m_k6ExitStreams.find(streamId);
        auto ledger = stream == m_k6ExitStreams.end()
            ? m_k6SendCredits.end() : m_k6SendCredits.find(stream->second.circ_id);
        if (stream == m_k6ExitStreams.end() || ledger == m_k6SendCredits.end() ||
            stream->second.flow.CanAccept(data) != kad6::Kad6Status::Ok)
            return false;
        if (!QueueK6FairPayloadLocked(streamId, 1, std::move(body))) {
            ReleaseK6FairStreamLocked(streamId);
            return false;
        }
        const uint64 sent = ledger->second.stream_sent(streamId, 1);
        const uint64 received = stream->second.flow.total_bytes(0);
        const uint64 remaining = stream->second.stream_max_bytes == 0 ||
                sent + received >= stream->second.stream_max_bytes
            ? (stream->second.stream_max_bytes == 0
                ? (std::numeric_limits<uint64>::max)() : 0)
            : stream->second.stream_max_bytes - sent - received;
        if (ledger->second.CommitSend(streamId, 1, length, remaining,
                (std::numeric_limits<uint64>::max)(), 2u * 1024u * 1024u) !=
                    kad6::Kad6Status::Ok ||
            stream->second.flow.Accept(data) != kad6::Kad6Status::Ok) {
            ReleaseK6FairStreamLocked(streamId);
            return false;
        }
        ++stream->second.tx_sequence;
        return true;
    }
    {
        CSingleLock pl(&m_pendingLock, TRUE);
        auto stream = m_k6ExitStreams.find(streamId);
        auto ledger = stream == m_k6ExitStreams.end()
            ? m_k6SendCredits.end() : m_k6SendCredits.find(stream->second.circ_id);
        if (stream == m_k6ExitStreams.end() || ledger == m_k6SendCredits.end() ||
            stream->second.flow.CanAccept(data) != kad6::Kad6Status::Ok)
            return false;
        const uint64 sent = ledger->second.stream_sent(streamId, 1);
        const uint64 received = stream->second.flow.total_bytes(0);
        const uint64 remaining = stream->second.stream_max_bytes == 0 ||
                sent + received >= stream->second.stream_max_bytes
            ? (stream->second.stream_max_bytes == 0
                ? (std::numeric_limits<uint64>::max)() : 0)
            : stream->second.stream_max_bytes - sent - received;
        if (ledger->second.CommitSend(streamId, 1, length, remaining,
                (std::numeric_limits<uint64>::max)(), 2u * 1024u * 1024u) !=
                    kad6::Kad6Status::Ok ||
            stream->second.flow.Accept(data) != kad6::Kad6Status::Ok)
            return false;
        ++stream->second.tx_sequence;
    }
    if (!SendK6GatewayPush(runtime.circuit, runtime.circ_id, 0,
            kad6::kK6MsgStreamData, kad6::kK6FlagFinal, body)) {
        CKad6ExitSocket* socket = NULL;
        {
            CSingleLock pl(&m_pendingLock, TRUE);
            const auto stream = m_k6ExitStreams.find(streamId);
            if (stream != m_k6ExitStreams.end()) socket = stream->second.socket;
        }
        if (socket) socket->Disconnect(_T("Kad6 tunnel rejected accepted frame"));
        return false;
    }
    m_k6Metrics.Add(kad6::K6MetricFamily::ExitBytesTotal, 0,
        runtime.inbound ? 3 : 2, 0, static_cast<uint64>(length),
        static_cast<uint64>(time(NULL)));
    m_k6Metrics.Add(kad6::K6MetricFamily::TransportBytesTotal, 0, 0, 0,
        static_cast<uint64>(length), static_cast<uint64>(time(NULL)));
    {
        CSingleLock pl(&m_pendingLock, TRUE);
        m_k6EconomyUsefulBytes += static_cast<uint64>(length);
    }
    return true;
}

bool CLiveTunnel::AllowKad6ShadowPublishContact(uint64 publishLeaseId,
                                                const uint8_t custodianId[16])
{
    if (!custodianId) return false;
    CSingleLock pl(&m_pendingLock, TRUE);
    ++m_k6EconomyPublishAttempts;
    auto runtime = m_k6Publishes.find(publishLeaseId);
    if (runtime == m_k6Publishes.end() || !runtime->second.refresh_enabled ||
        runtime->second.expires_at <= static_cast<uint64_t>(time(NULL))) return false;
    const kad6::K6SourceLease* lease = m_k6SourceLeases.Find(runtime->second.source_lease_id);
    if (!lease || !m_k6SourceLeases.CanPublish(lease->lease_id)) return false;
    kad6::K6PublishBudgetKey key;
    key.target_hash = runtime->second.request.target_hash;
    memcpy(key.custodian.data(), custodianId, 16);
    key.record_class = static_cast<uint8_t>(runtime->second.request.record_kind);
    key.endpoint[0] = static_cast<uint8_t>(lease->bound.endpoint_slot);
    memcpy(key.endpoint.data() + 1, lease->bound.virtual_endpoint.addr.addr.data(), 4);
    key.endpoint[5] = static_cast<uint8_t>(lease->bound.virtual_endpoint.tcp_port);
    key.endpoint[6] = static_cast<uint8_t>(lease->bound.virtual_endpoint.tcp_port >> 8);
    key.endpoint[7] = static_cast<uint8_t>(lease->bound.virtual_endpoint.udp_port);
    key.endpoint[8] = static_cast<uint8_t>(lease->bound.virtual_endpoint.udp_port >> 8);
    return m_k6PublishBudget.Admit(key, static_cast<uint64_t>(time(NULL)));
}

void CLiveTunnel::OnKad6ShadowPublishSent(uint64 publishLeaseId)
{
    std::vector<kad6::K6CohortBackend> serving;
    {
        CSingleLock pl(&m_pendingLock, TRUE);
        auto primary = m_k6Publishes.find(publishLeaseId);
        if (primary == m_k6Publishes.end()) return;
        const uint64_t primaryId = primary->second.primary_publish_lease_id;
        for (auto& pair : m_k6Publishes)
            if (pair.second.primary_publish_lease_id == primaryId) {
                if (pair.second.status == kad6::K6PublishStatus::Queued)
                    pair.second.status = kad6::K6PublishStatus::Sent;
                pair.second.published_networks |= kad6::kK6PublishNetKad2;
                kad6::K6CohortBackend backend;
                if (MarkK6SourceServingLocked(pair.second.source_lease_id, backend))
                    serving.push_back(backend);
            }
    }
    for (const kad6::K6CohortBackend& backend : serving)
        m_k6CohortScheduler.Register(backend);
}

void CLiveTunnel::OnKad6ShadowPublishAck(uint64 publishLeaseId, uint8_t load,
                                         bool hasLoadResponse)
{
    CSingleLock pl(&m_pendingLock, TRUE);
    auto primary = m_k6Publishes.find(publishLeaseId);
    if (primary == m_k6Publishes.end()) return;
    const uint64_t primaryId = primary->second.primary_publish_lease_id;
    for (auto& pair : m_k6Publishes) if (pair.second.primary_publish_lease_id == primaryId) {
        if (pair.second.status != kad6::K6PublishStatus::VerifiedVisible)
            pair.second.status = kad6::K6PublishStatus::RemoteAck;
        pair.second.published_networks |= kad6::kK6PublishNetKad2;
        if (pair.second.replicas != 0xffff) ++pair.second.replicas;
        pair.second.max_load = (std::max)(pair.second.max_load, load);
        if (pair.second.visibility_probe_at == 0)
            pair.second.visibility_probe_at = static_cast<uint64_t>(time(NULL)) + 145;
    }
    if (hasLoadResponse && load >= 80)
        m_k6PublishBudget.NoteOverload(static_cast<uint64_t>(time(NULL)));
}

void CLiveTunnel::OnKad6ShadowVerified(uint64 publishLeaseId)
{
    CSingleLock pl(&m_pendingLock, TRUE);
    auto primary = m_k6Publishes.find(publishLeaseId);
    if (primary == m_k6Publishes.end()) return;
    const uint64 primaryId = primary->second.primary_publish_lease_id;
    for (auto& pair : m_k6Publishes)
        if (pair.second.primary_publish_lease_id == primaryId) {
            pair.second.status = kad6::K6PublishStatus::VerifiedVisible;
            pair.second.published_networks |= kad6::kK6PublishNetKad2;
            pair.second.visibility_probe_started = false;
            pair.second.visibility_probe_at = 0;
            pair.second.visibility_probe_deadline = 0;
        }
}

void CLiveTunnel::OnKad6NativePublishAck(uint64 publishLeaseId,
                                         kad6::K6StoreStatus status,
                                         uint8_t load, uint64 acceptedEpoch)
{
    CSingleLock pl(&m_pendingLock, TRUE);
    auto runtime = m_k6Publishes.find(publishLeaseId);
    if (runtime == m_k6Publishes.end()) return;
    if (status == kad6::K6StoreStatus::Stored &&
        acceptedEpoch >= runtime->second.request.record_epoch) {
        if (runtime->second.status != kad6::K6PublishStatus::VerifiedVisible)
            runtime->second.status = kad6::K6PublishStatus::RemoteAck;
        runtime->second.published_networks |= kad6::kK6PublishNetKad6;
        if (runtime->second.replicas != 0xffff) ++runtime->second.replicas;
        runtime->second.max_load = (std::max)(runtime->second.max_load, load);
    } else if (status == kad6::K6StoreStatus::Overloaded) {
        m_k6PublishBudget.NoteOverload(static_cast<uint64_t>(time(NULL)));
        if (runtime->second.auto_refresh) {
            const uint64 now = static_cast<uint64_t>(time(NULL));
            runtime->second.next_native_refresh_at = now + runtime->second.native_backoff_s;
            runtime->second.native_backoff_s = (std::min)(
                runtime->second.native_backoff_s * 2u, 15u * 60u);
        }
        if (runtime->second.published_networks != 0)
            runtime->second.status = kad6::K6PublishStatus::Partial;
    }
}

void CLiveTunnel::RefreshK6NativePublishes(uint64 nowSeconds)
{
    struct NativeRefresh {
        uint64 publishLeaseId;
        kad6::K6SourceRecord record;
    };
    std::vector<NativeRefresh> due;
    {
        CSingleLock pl(&m_pendingLock, TRUE);
        for (auto& pair : m_k6Publishes) {
            K6ExitPublishRuntime& runtime = pair.second;
            if (!runtime.refresh_enabled || !runtime.auto_refresh ||
                runtime.next_native_refresh_at == 0 ||
                runtime.next_native_refresh_at > nowSeconds ||
                runtime.expires_at <= nowSeconds + kad6::kK6PublishMinTtlSeconds ||
                runtime.request.record_kind != kad6::K6RecordKind::Kad6SourceDescriptor ||
                (runtime.request.network_mask & kad6::kK6PublishNetKad6) == 0)
                continue;
            kad6::K6SourceRecord record;
            size_t consumed = 0;
            if (kad6::DecodeK6SourceRecord(runtime.request.record.data(),
                    runtime.request.record.size(), record, &consumed) != kad6::Kad6Status::Ok ||
                consumed != runtime.request.record.size() ||
                kad6::K6SourceRecordCheckFresh(record, nowSeconds) != kad6::Kad6Status::Ok)
                continue;
            runtime.next_native_refresh_at = nowSeconds + runtime.native_backoff_s;
            due.push_back({runtime.publish_lease_id, std::move(record)});
        }
    }
    Kademlia::CKademliaUDPListener* listener = Kademlia::CKademlia::GetUDPListener();
    if (!listener) return;
    for (const NativeRefresh& refresh : due) {
        const bool sent = listener->PublishKad6SourceRecord(
            refresh.publishLeaseId, refresh.record);
        CSingleLock pl(&m_pendingLock, TRUE);
        auto runtime = m_k6Publishes.find(refresh.publishLeaseId);
        if (runtime == m_k6Publishes.end()) continue;
        if (sent) {
            const uint64 remaining = runtime->second.expires_at > nowSeconds
                ? runtime->second.expires_at - nowSeconds : 0;
            runtime->second.next_native_refresh_at = nowSeconds + (std::max<uint64>)(
                kad6::kK6PublishMinTtlSeconds, remaining / 2);
            runtime->second.native_backoff_s = 60;
            runtime->second.published_networks |= kad6::kK6PublishNetKad6;
            if (runtime->second.status == kad6::K6PublishStatus::Queued)
                runtime->second.status = kad6::K6PublishStatus::Sent;
        } else {
            runtime->second.next_native_refresh_at =
                nowSeconds + runtime->second.native_backoff_s;
            runtime->second.native_backoff_s = (std::min)(
                runtime->second.native_backoff_s * 2u, 15u * 60u);
        }
    }
}

void CLiveTunnel::QueueK6ShadowRefreshes(uint64 nowSeconds)
{
    CSingleLock pl(&m_pendingLock, TRUE);

    // Re-elect one stable exterior publisher per (endpoint, hash). This also
    // repairs a cohort when its previous primary expired or was unpublished.
    for (auto it = m_k6ShadowPrimary.begin(); it != m_k6ShadowPrimary.end(); ) {
        auto runtime = m_k6Publishes.find(it->second);
        const kad6::K6SourceLease* lease = runtime == m_k6Publishes.end() ? NULL
            : m_k6SourceLeases.Find(runtime->second.source_lease_id);
        if (runtime == m_k6Publishes.end() || !runtime->second.refresh_enabled ||
            runtime->second.expires_at <= nowSeconds || !lease ||
            !m_k6SourceLeases.CanPublish(runtime->second.source_lease_id) ||
            K6ShadowKey(*lease) != it->first)
            it = m_k6ShadowPrimary.erase(it);
        else
            ++it;
    }
    for (auto& pair : m_k6Publishes) {
        K6ExitPublishRuntime& runtime = pair.second;
        if (!runtime.refresh_enabled || runtime.expires_at <= nowSeconds ||
            (runtime.request.network_mask & kad6::kK6PublishNetKad2) == 0)
            continue;
        const kad6::K6SourceLease* lease = m_k6SourceLeases.Find(runtime.source_lease_id);
        if (!lease || !m_k6SourceLeases.CanPublish(runtime.source_lease_id))
            continue;
        const std::string key = K6ShadowKey(*lease);
        auto primary = m_k6ShadowPrimary.find(key);
        if (primary == m_k6ShadowPrimary.end()) {
            m_k6ShadowPrimary[key] = runtime.publish_lease_id;
            if (!runtime.kad2_queued && runtime.next_refresh_at == 0)
                runtime.next_refresh_at = nowSeconds;
        }
    }
    for (auto& pair : m_k6Publishes) {
        K6ExitPublishRuntime& runtime = pair.second;
        if (!runtime.refresh_enabled || runtime.expires_at <= nowSeconds ||
            (runtime.request.network_mask & kad6::kK6PublishNetKad2) == 0)
            continue;
        const kad6::K6SourceLease* lease = m_k6SourceLeases.Find(runtime.source_lease_id);
        if (!lease || !m_k6SourceLeases.CanPublish(runtime.source_lease_id))
            continue;
        const auto primary = m_k6ShadowPrimary.find(K6ShadowKey(*lease));
        if (primary != m_k6ShadowPrimary.end())
            runtime.primary_publish_lease_id = primary->second;
    }

    for (auto& pair : m_k6Publishes) {
        K6ExitPublishRuntime& runtime = pair.second;
        if (runtime.primary_publish_lease_id != runtime.publish_lease_id ||
            !runtime.refresh_enabled || !runtime.auto_refresh || runtime.kad2_queued ||
            runtime.next_refresh_at == 0 || runtime.next_refresh_at > nowSeconds ||
            runtime.expires_at <= nowSeconds + kad6::kK6PublishMinTtlSeconds)
            continue;
        const kad6::K6SourceLease* lease = m_k6SourceLeases.Find(runtime.source_lease_id);
        if (!lease || !m_k6SourceLeases.CanPublish(runtime.source_lease_id))
            continue;
        runtime.kad2_search_active = false;
        kad6::K6PublishSchedule schedule;
        schedule.publish_lease_id = runtime.publish_lease_id;
        schedule.target_hash = runtime.request.target_hash;
        schedule.endpoint[0] = static_cast<uint8_t>(lease->bound.endpoint_slot);
        memcpy(schedule.endpoint.data() + 1,
            lease->bound.virtual_endpoint.addr.addr.data(), 4);
        schedule.endpoint[5] = static_cast<uint8_t>(lease->bound.virtual_endpoint.tcp_port);
        schedule.endpoint[6] = static_cast<uint8_t>(lease->bound.virtual_endpoint.tcp_port >> 8);
        schedule.endpoint[7] = static_cast<uint8_t>(lease->bound.virtual_endpoint.udp_port);
        schedule.endpoint[8] = static_cast<uint8_t>(lease->bound.virtual_endpoint.udp_port >> 8);
        schedule.record_class = static_cast<uint8_t>(runtime.request.record_kind);
        schedule.due_at = nowSeconds;
        schedule.expires_at = runtime.expires_at;
        uint64 effective = 0;
        runtime.kad2_queued = m_k6PublishCoalescer.Enqueue(schedule, 30, effective);
        if (effective != 0)
            runtime.primary_publish_lease_id = effective;
    }
}

void CLiveTunnel::StartDueK6ShadowPublishes(uint64 nowSeconds)
{
    std::vector<kad6::K6PublishSchedule> due;
    {
        CSingleLock pl(&m_pendingLock, TRUE);
        due = m_k6PublishCoalescer.TakeDue(nowSeconds, 8);
    }

    for (const kad6::K6PublishSchedule& schedule : due) {
        K6ExitPublishRuntime runtime;
        kad6::K6SourceLease lease;
        bool ready = false;
        {
            CSingleLock pl(&m_pendingLock, TRUE);
            auto found = m_k6Publishes.find(schedule.publish_lease_id);
            if (found != m_k6Publishes.end()) {
                found->second.kad2_queued = false;
                const kad6::K6SourceLease* source =
                    m_k6SourceLeases.Find(found->second.source_lease_id);
                if (source && found->second.refresh_enabled &&
                    found->second.primary_publish_lease_id == schedule.publish_lease_id &&
                    found->second.expires_at > nowSeconds &&
                    m_k6SourceLeases.CanPublish(source->lease_id)) {
                    runtime = found->second;
                    lease = *source;
                    ready = true;
                }
            }
        }
        if (!ready)
            continue;

        Kademlia::CUInt128 target(runtime.request.target_hash.data());
        Kademlia::CSearch* search = Kademlia::CSearchManager::PrepareLookup(
            Kademlia::CSearch::STOREFILE, false, target);
        bool started = search != NULL;
        if (started) {
            search->SetK6ShadowSource(runtime.publish_lease_id, lease.bind.file_size,
                lease.bind.compat_user_hash.data(),
                lease.bound.virtual_endpoint.tcp_port,
                lease.bound.virtual_endpoint.udp_port);
            started = Kademlia::CSearchManager::StartSearch(search);
        }

        CSingleLock pl(&m_pendingLock, TRUE);
        auto primary = m_k6Publishes.find(runtime.publish_lease_id);
        if (primary == m_k6Publishes.end())
            continue;
        const uint64 primaryId = runtime.publish_lease_id;
        if (started) {
            const uint64 remaining = primary->second.expires_at > nowSeconds
                ? primary->second.expires_at - nowSeconds : 0;
            const uint64 refresh = (std::max<uint64>)(
                kad6::kK6PublishMinTtlSeconds, remaining / 2);
            for (auto& pair : m_k6Publishes)
                if (pair.second.primary_publish_lease_id == primaryId) {
                    pair.second.kad2_search_active = true;
                    pair.second.next_refresh_at = nowSeconds + refresh;
                    pair.second.refresh_backoff_s = 60;
                }
        } else {
            const uint32 backoff = (std::min)(primary->second.refresh_backoff_s, 15u * 60u);
            for (auto& pair : m_k6Publishes)
                if (pair.second.primary_publish_lease_id == primaryId) {
                    pair.second.kad2_search_active = false;
                    pair.second.next_refresh_at = nowSeconds + backoff;
                    pair.second.refresh_backoff_s = (std::min)(backoff * 2u, 15u * 60u);
                    if (pair.second.published_networks != 0)
                        pair.second.status = kad6::K6PublishStatus::Partial;
                }
        }
    }
}

void CLiveTunnel::StartK6VisibilityProbes(uint64 nowSeconds)
{
    struct Probe {
        uint64 publishLeaseId;
        kad6::Hash16 target;
        kad6::Hash16 compatUserHash;
        uint32 ip;
        uint16 tcpPort;
        uint16 udpPort;
    };
    std::vector<Probe> due;
    {
        CSingleLock pl(&m_pendingLock, TRUE);
        for (auto& pair : m_k6Publishes) {
            K6ExitPublishRuntime& runtime = pair.second;
            if (runtime.primary_publish_lease_id != runtime.publish_lease_id ||
                !runtime.refresh_enabled || runtime.expires_at <= nowSeconds ||
                (runtime.published_networks & kad6::kK6PublishNetKad2) == 0 ||
                runtime.status == kad6::K6PublishStatus::VerifiedVisible)
                continue;
            if (runtime.visibility_probe_started) {
                if (runtime.visibility_probe_deadline > nowSeconds)
                    continue;
                runtime.visibility_probe_started = false;
                runtime.visibility_probe_at = nowSeconds + 60;
                m_k6PublishBudget.NoteOverload(nowSeconds);
            }
            if (runtime.visibility_probe_at == 0 || runtime.visibility_probe_at > nowSeconds)
                continue;
            const kad6::K6SourceLease* lease = m_k6SourceLeases.Find(runtime.source_lease_id);
            if (!lease || !m_k6SourceLeases.CanPublish(runtime.source_lease_id))
                continue;
            uint32 ip = static_cast<uint32>(lease->bound.virtual_endpoint.addr.addr[0]) |
                (static_cast<uint32>(lease->bound.virtual_endpoint.addr.addr[1]) << 8) |
                (static_cast<uint32>(lease->bound.virtual_endpoint.addr.addr[2]) << 16) |
                (static_cast<uint32>(lease->bound.virtual_endpoint.addr.addr[3]) << 24);
            Probe probe;
            probe.publishLeaseId = runtime.publish_lease_id;
            probe.target = runtime.request.target_hash;
            probe.compatUserHash = lease->bind.compat_user_hash;
            probe.ip = ip;
            probe.tcpPort = lease->bound.virtual_endpoint.tcp_port;
            probe.udpPort = lease->bound.virtual_endpoint.udp_port;
            runtime.visibility_probe_started = true;
            runtime.visibility_probe_deadline = nowSeconds + 50;
            due.push_back(probe);
        }
    }
    for (const Probe& probe : due) {
        Kademlia::CUInt128 target(probe.target.data());
        Kademlia::CSearch* search = Kademlia::CSearchManager::PrepareLookup(
            Kademlia::CSearch::FILE, false, target);
        bool started = search != NULL;
        if (started) {
            search->SetK6VisibilityProbe(probe.publishLeaseId,
                probe.compatUserHash.data(), probe.ip, probe.tcpPort, probe.udpPort);
            started = Kademlia::CSearchManager::StartSearch(search);
        }
        if (!started) {
            CSingleLock pl(&m_pendingLock, TRUE);
            auto runtime = m_k6Publishes.find(probe.publishLeaseId);
            if (runtime != m_k6Publishes.end()) {
                runtime->second.visibility_probe_started = false;
                runtime->second.visibility_probe_at = nowSeconds + 15;
                runtime->second.visibility_probe_deadline = 0;
            }
        }
    }
}

void CLiveTunnel::SweepK6Gateway(uint64 nowSeconds,
                                 const std::set<uint32_t>& activeCircuits)
{
    struct ExpiredExit { uint64 stream_id = 0; K6ExitStreamRuntime runtime; uint16 reason = 0; };
    struct ExpiredOrigin { uint64 stream_id = 0; K6OriginStreamRuntime runtime; uint16 reason = 0; };
    struct ExpiredActivation { uint32 request_id = 0; CUpDownClient* client = NULL; };
    std::vector<ExpiredExit> exits;
    std::vector<ExpiredOrigin> origins;
    std::vector<uint32_t> sourceLookups;
    std::vector<ExpiredActivation> activations;
    std::vector<uint64> stoppedLeases;
    std::vector<uint64> releasedCohortStreams;
    const DWORD nowTick = GetTickCount();
    const uint64 nowFlowMs = K6ShapeNowUs() / 1000u;
    std::array<uint64, static_cast<size_t>(kad6::K6Service::Count)> serviceActive{};
    double streamProfiles[4][3] = {};
    std::set<uint32> strictCircuits;
    for (const auto& circuit : m_circuits)
        if (circuit && circuit->m_strict3 && circuit->m_shaped_ok &&
            circuit->State() == CircuitState::Active)
            strictCircuits.insert(circuit->Id());
    {
        CSingleLock pl(&m_pendingLock, TRUE);
        serviceActive[static_cast<size_t>(kad6::K6Service::Control)] =
            static_cast<uint64>(m_searchJobs.size());
        for (const auto& pair : m_k6SourceLeases.Entries())
            if (pair.second.state != kad6::K6SourceLeaseState::Closed)
                ++serviceActive[static_cast<size_t>(kad6::K6Service::ExitKad)];
        for (const auto& pair : m_k6ExitStreams) {
            const size_t service = static_cast<size_t>(pair.second.inbound
                ? kad6::K6Service::ExitEd2kFull : kad6::K6Service::ExitEd2kDial);
            ++serviceActive[service];
            const size_t profile = strictCircuits.find(pair.second.circ_id) !=
                strictCircuits.end() ? 2 : 1;
            streamProfiles[service][profile] += 1.0;
        }
    }
    const kad6::K6DrainResult drain = m_k6Hardening.Tick(nowSeconds, serviceActive);
    {
        CSingleLock pl(&m_pendingLock, TRUE);
        if ((drain.force_close_mask &
             kad6::K6ServiceBit(kad6::K6Service::ExitKad)) != 0) {
            std::vector<uint64> leases;
            leases.reserve(m_k6SourceLeases.Entries().size());
            for (const auto& pair : m_k6SourceLeases.Entries())
                if (pair.second.state != kad6::K6SourceLeaseState::Closed)
                    leases.push_back(pair.first);
            for (uint64 lease : leases) {
                m_k6SourceLeases.Close(lease);
                stoppedLeases.push_back(lease);
            }
            m_k6Publishes.clear();
            m_k6ShadowPrimary.clear();
            m_k6SourceLeases.EraseClosed();
        }
        for (auto it = m_k6AuthorizedTargets.begin(); it != m_k6AuthorizedTargets.end(); )
            if (it->second.expires_at <= nowSeconds) it = m_k6AuthorizedTargets.erase(it);
            else ++it;
        for (auto it = m_k6UsedTickets.begin(); it != m_k6UsedTickets.end(); )
            if (it->second.expires_at <= nowSeconds) it = m_k6UsedTickets.erase(it);
            else ++it;
        for (auto it = m_k6QuotaGrants.begin(); it != m_k6QuotaGrants.end(); ) {
            if (it->second.expires_at <= nowSeconds) {
                m_k6FairScheduler.ReleaseAllocation(it->second.allocation_id);
                it = m_k6QuotaGrants.erase(it);
            } else ++it;
        }
        for (auto it = m_k6OriginTargetRoutes.begin(); it != m_k6OriginTargetRoutes.end(); )
            if (it->second.expires_at <= nowSeconds ||
                activeCircuits.find(it->second.circ_id) == activeCircuits.end())
                it = m_k6OriginTargetRoutes.erase(it);
            else ++it;
        for (auto it = m_k6OriginLiveRoutes.begin(); it != m_k6OriginLiveRoutes.end(); )
            if (it->second.expires_at <= nowSeconds ||
                activeCircuits.find(it->second.circ_id) == activeCircuits.end())
                it = m_k6OriginLiveRoutes.erase(it);
            else ++it;

        std::set<uint64> lostSourceLeases;
        for (auto it = m_k6OriginSourceLeaseRoutes.begin();
             it != m_k6OriginSourceLeaseRoutes.end(); ) {
            if (activeCircuits.find(it->second) == activeCircuits.end()) {
                lostSourceLeases.insert(it->first);
                it = m_k6OriginSourceLeaseRoutes.erase(it);
            } else ++it;
        }
        for (auto it = m_k6OriginPublishLeaseRoutes.begin();
             it != m_k6OriginPublishLeaseRoutes.end(); )
            if (activeCircuits.find(it->second) == activeCircuits.end())
                it = m_k6OriginPublishLeaseRoutes.erase(it);
            else ++it;
        if (!lostSourceLeases.empty())
            for (auto& pair : m_k6OriginAdvertisements)
                if (lostSourceLeases.find(pair.second.source_lease_id) !=
                        lostSourceLeases.end()) {
                    pair.second.source_lease_id = 0;
                    pair.second.publish_lease_id = 0;
                    pair.second.next_attempt = 0;
                }

        for (auto it = m_k6OriginSourceLookups.begin();
             it != m_k6OriginSourceLookups.end(); ) {
            const bool timedOut = (int)(nowTick - it->second.deadline) >= 0;
            const bool circuitLost = it->second.circ_id != 0 &&
                activeCircuits.find(it->second.circ_id) == activeCircuits.end();
            if (!timedOut && !circuitLost) { ++it; continue; }
            sourceLookups.push_back(it->first);
            it = m_k6OriginSourceLookups.erase(it);
        }
        for (auto it = m_k6DownloadActivations.begin();
             it != m_k6DownloadActivations.end(); ) {
            const bool timedOut = (int)(nowTick - it->second.deadline) >= 0;
            const bool circuitLost = activeCircuits.find(it->second.circ_id) ==
                activeCircuits.end();
            if (!timedOut && !circuitLost) { ++it; continue; }
            ExpiredActivation expired;
            expired.request_id = it->first;
            expired.client = it->second.client;
            activations.push_back(expired);
            it = m_k6DownloadActivations.erase(it);
        }

        for (auto it = m_k6ExitStreams.begin(); it != m_k6ExitStreams.end(); ) {
            uint16 reason = 0;
            const kad6::K6Service streamService = it->second.inbound
                ? kad6::K6Service::ExitEd2kFull : kad6::K6Service::ExitEd2kDial;
            if (it->second.kill_switch_close ||
                (drain.force_close_mask & kad6::K6ServiceBit(streamService)) != 0) reason = 5;
            else if (activeCircuits.find(it->second.circ_id) == activeCircuits.end()) reason = 3;
            else if (!it->second.connected && it->second.connect_deadline &&
                     it->second.connect_deadline <= nowSeconds) reason = 4;
            else if (it->second.credit_stall_since_ms != 0 &&
                     nowFlowMs >= it->second.credit_stall_since_ms &&
                     nowFlowMs - it->second.credit_stall_since_ms >=
                         kad6::kK6CreditStallDeadlineMs) reason = 6;
            else if (it->second.idle_deadline && it->second.idle_deadline <= nowSeconds) reason = 2;
            if (!reason) { ++it; continue; }
            ExpiredExit expired; expired.stream_id = it->first;
            expired.runtime = it->second; expired.reason = reason;
            exits.push_back(std::move(expired));
            releasedCohortStreams.push_back(it->first);
            ReleaseK6FairStreamLocked(it->first);
            RemoveK6FlowControlLocked(it->second.circ_id, it->first);
            it = m_k6ExitStreams.erase(it);
        }
        for (auto it = m_k6OriginStreams.begin(); it != m_k6OriginStreams.end(); ) {
            const bool creditStalled = it->second.credit_stall_since_ms != 0 &&
                nowFlowMs >= it->second.credit_stall_since_ms &&
                nowFlowMs - it->second.credit_stall_since_ms >=
                    kad6::kK6CreditStallDeadlineMs;
            if (!creditStalled &&
                activeCircuits.find(it->second.circ_id) != activeCircuits.end() &&
                (!it->second.idle_deadline || it->second.idle_deadline > nowSeconds)) {
                ++it; continue;
            }
            ExpiredOrigin expired; expired.stream_id = it->first;
            expired.runtime = it->second;
            expired.reason = activeCircuits.find(it->second.circ_id) ==
                activeCircuits.end() ? 3 : creditStalled ? 6 : 2;
            origins.push_back(std::move(expired));
            RemoveK6FlowControlLocked(it->second.circ_id, it->first);
            it = m_k6OriginStreams.erase(it);
        }
        for (auto it = m_k6SourceScores.begin(); it != m_k6SourceScores.end(); )
            if (it->second.last_seen != 0 &&
                it->second.last_seen + 24ull * 60 * 60 <= nowSeconds)
                it = m_k6SourceScores.erase(it);
            else
                ++it;
        while (m_k6SourceScores.size() > 4096)
            m_k6SourceScores.erase(m_k6SourceScores.begin());
    }

    // Never hold m_pendingLock while notifying a circuit or disconnecting an
    // eD2K socket: both paths can synchronously re-enter tunnel/client code.
    for (uint64 lease : stoppedLeases)
        m_k6CohortScheduler.SetServing(lease, false);
    for (uint64 stream : releasedCohortStreams)
        m_k6CohortScheduler.ReleaseStream(stream);
    for (uint32_t requestId : sourceLookups) {
        if (theApp.downloadqueue == NULL) continue;
        CPartFile* file = theApp.downloadqueue->GetFileByKadFileSearchID(requestId);
        if (file != NULL) file->SetKadFileSearchID(0);
    }
    for (const ExpiredActivation& expired : activations) {
        if (expired.client == NULL) continue;
        const bool deleteClient = expired.client->Disconnected(
            _T("Kad6 gateway DIAL timeout or circuit closed"));
        if (deleteClient) delete expired.client;
    }
    for (const ExpiredExit& expired : exits) {
        const K6ExitStreamRuntime& runtime = expired.runtime;
        if (expired.reason == 4) {
            {
                CSingleLock pl(&m_pendingLock, TRUE);
                K6SourceScore& score = m_k6SourceScores[K6SourceScoreKey(
                    runtime.ticket.target_endpoint, runtime.network_origin)];
                if (score.failures != (std::numeric_limits<uint32>::max)())
                    ++score.failures;
                score.last_seen = nowSeconds;
            }
            m_k6Metrics.Add(kad6::K6MetricFamily::SourceDialTotal,
                runtime.network_origin == kad6::kK6NetOriginKad6 ? 1 : 0,
                3, 0, 1, nowSeconds);
        }
        if (!runtime.connected) {
            if (expired.reason == 4) {
                kad6::K6DialResult result; result.stream_id = expired.stream_id;
                result.status = kad6::K6DialStatus::Timeout;
                result.transport = kad6::K6GatewayTransport::TcpEd2k;
                result.apparent_local_endpoint = runtime.apparent;
                result.remote_endpoint = runtime.ticket.target_endpoint;
                result.max_bytes = runtime.stream_max_bytes;
                result.idle_timeout_ms = runtime.idle_timeout_ms;
                std::vector<uint8_t> body, wire;
                kad6::K6Frame frame; frame.msg_type = kad6::kK6MsgDialOk;
                frame.flags = kad6::kK6FlagResponse | kad6::kK6FlagFinal;
                frame.request_id = runtime.dial_request_id;
                if (kad6::EncodeK6DialResult(result, body) == kad6::Kad6Status::Ok) {
                    frame.body = std::move(body);
                    if (kad6::EncodeK6Frame(frame, wire) == kad6::Kad6Status::Ok)
                        CompleteExitOperation(runtime.circ_id, runtime.dial_request_id,
                            wire.data(), wire.size());
                }
            } else {
                AbortExitOperation(runtime.circ_id, runtime.dial_request_id);
            }
        } else {
            kad6::K6StreamClose close; close.stream_id = expired.stream_id;
            close.reason_code = expired.reason;
            close.last_tx_sequence = runtime.flow.next_sequence(0)
                ? runtime.flow.next_sequence(0) - 1 : 0;
            close.last_rx_sequence = runtime.flow.next_sequence(1)
                ? runtime.flow.next_sequence(1) - 1 : 0;
            close.total_tx_bytes = runtime.flow.total_bytes(0);
            close.total_rx_bytes = runtime.flow.total_bytes(1);
            std::vector<uint8_t> body;
            if (kad6::EncodeK6StreamClose(close, body) == kad6::Kad6Status::Ok)
                SendK6GatewayPush(runtime.circuit, runtime.circ_id, 0,
                    kad6::kK6MsgStreamClose, kad6::kK6FlagFinal, body);
        }
        if (runtime.socket) runtime.socket->Disconnect(
            expired.reason == 2 ? _T("Kad6 idle timeout") :
            expired.reason == 4 ? _T("Kad6 connect timeout") :
            expired.reason == 5 ? _T("Kad6 local kill switch") : _T("Kad6 circuit closed"));
    }
    for (const ExpiredOrigin& expired : origins) {
        const K6OriginStreamRuntime& runtime = expired.runtime;
        if (activeCircuits.find(runtime.circ_id) != activeCircuits.end()) {
            kad6::K6StreamClose close; close.stream_id = expired.stream_id;
            close.reason_code = expired.reason;
            close.last_tx_sequence = runtime.flow.next_sequence(0)
                ? runtime.flow.next_sequence(0) - 1 : 0;
            close.last_rx_sequence = runtime.flow.next_sequence(1)
                ? runtime.flow.next_sequence(1) - 1 : 0;
            close.total_tx_bytes = runtime.flow.total_bytes(0);
            close.total_rx_bytes = runtime.flow.total_bytes(1);
            std::vector<uint8_t> body, wire;
            kad6::K6Frame frame; frame.msg_type = kad6::kK6MsgStreamClose;
            frame.flags = kad6::kK6FlagLegacyEd2k | kad6::kK6FlagFinal;
            frame.request_id = NewCircuitId();
            if (kad6::EncodeK6StreamClose(close, body) == kad6::Kad6Status::Ok) {
                frame.body = std::move(body);
                if (kad6::EncodeK6Frame(frame, wire) == kad6::Kad6Status::Ok)
                    SendMessagePinned(frame.request_id, TUN_OP_KAD6_GATEWAY,
                        wire.data(), wire.size(), ESE_CAP_KAD6, runtime.circ_id);
            }
        }
        if (runtime.client) runtime.client->ClearK6SecureIdentVep();
        if (runtime.socket) runtime.socket->Disconnect(_T("Kad6 stream expired"));
    }

    // Sealed-window gauges: samples are taken once per engine tick, but only a
    // completed 15-minute aggregate can leave the process.
    const double leaseCapacity = static_cast<double>(serviceActive[
        static_cast<size_t>(kad6::K6Service::ExitKad)]) / 4096.0;
    const double dialCapacity = static_cast<double>(serviceActive[
        static_cast<size_t>(kad6::K6Service::ExitEd2kDial)]) / 512.0;
    const double fullCapacity = static_cast<double>(serviceActive[
        static_cast<size_t>(kad6::K6Service::ExitEd2kFull)]) / 512.0;
    m_k6Metrics.Observe(kad6::K6MetricFamily::ExitCapacityRatio, 1, 0, 0,
                        leaseCapacity, nowSeconds);
    m_k6Metrics.Observe(kad6::K6MetricFamily::ExitCapacityRatio, 2, 0, 0,
                        dialCapacity, nowSeconds);
    m_k6Metrics.Observe(kad6::K6MetricFamily::ExitCapacityRatio, 3, 0, 0,
                        fullCapacity, nowSeconds);
    for (uint8 service = 2; service <= 3; ++service)
        for (uint8 profile = 1; profile <= 2; ++profile)
            for (uint8 state = 0; state < 4; ++state)
                m_k6Metrics.Observe(kad6::K6MetricFamily::Sessions,
                    service, profile, state,
                    state == 1 ? streamProfiles[service][profile] : 0.0, nowSeconds);
    RefreshK6EconomyMeasurements(nowSeconds, serviceActive);
    EnsureK6QuotaAuthority(nowSeconds);
    RefreshK6PublicRelease(nowSeconds);
}

void CLiveTunnel::SweepK6SourceLeases(const std::set<uint32_t>& activeCircuits,
                                      const std::set<uint32_t>& teardownQueue,
                                      uint64 nowSeconds)
{
    // L1/Q27: process teardown/expiry incrementally.  The persistent table
    // queue is populated from circuit lifecycle events.
    const uint64 startedUs = K6ShapeNowUs();
    const size_t transitionCap = 256;
    size_t remaining = transitionCap;
    std::vector<uint64_t> stoppedLeases;
    {
        CSingleLock pl(&m_pendingLock, TRUE);
        for (uint32_t circuitId : teardownQueue)
            if (activeCircuits.find(circuitId) == activeCircuits.end())
                m_k6SourceLeases.QueueCircuitTeardown(circuitId);
        if (remaining != 0 && K6ShapeNowUs() - startedUs < 2000) {
            const size_t changed = m_k6SourceLeases.DrainQueuedCircuits(
                remaining, &stoppedLeases);
            remaining -= changed;
        }
        if (remaining != 0 && K6ShapeNowUs() - startedUs < 2000) {
            const size_t changed = m_k6SourceLeases.ExpireSome(
                nowSeconds, remaining, &stoppedLeases);
            remaining -= changed;
        }
        m_k6PublishCoalescer.Expire(nowSeconds);
        for (auto it = m_k6Publishes.begin(); it != m_k6Publishes.end(); ) {
            const kad6::K6SourceLease* source =
                m_k6SourceLeases.Find(it->second.source_lease_id);
            if (it->second.expires_at <= nowSeconds || !source ||
                source->state == kad6::K6SourceLeaseState::Draining ||
                source->state == kad6::K6SourceLeaseState::Closed) {
                it = m_k6Publishes.erase(it);
            } else ++it;
        }
        m_k6SourceLeases.EraseClosedSome(transitionCap);
    }
    // Scheduler notification is deliberately outside m_pendingLock: a future
    // scheduler/socket implementation may call back into host code.
    for (uint64_t leaseId : stoppedLeases)
        m_k6CohortScheduler.SetServing(leaseId, false);
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
    // Legacy v1 carries the endpoint (28 bytes). Kad6-native v2 keeps it at
    // the exit: [result_id 16][source_request_id u32][version=2][reserved 3].
    uint8_t status = 1;            // 1 = bad request (default)
    uint8_t streamKey[16] = {0};
    uint32_t bIP = 0, bAltIP = 0;
    uint16_t bPort = 0, bUDP = 0;
    bool resolved = false;
    if (ctx.body && ctx.bodyLen == 24 && ctx.body[20] == 2 &&
        ctx.body[21] == 0 && ctx.body[22] == 0 && ctx.body[23] == 0 && ctx.circ) {
        memcpy(streamKey, ctx.body, 16);
        kad6::Hash16 resultId{};
        memcpy(resultId.data(), streamKey, resultId.size());
        const uint32 sourceRequestId = eseRdU32LE(ctx.body + 16);
        K6AuthorizedTarget target;
        {
            CSingleLock pl(&m_pendingLock, TRUE);
            const auto found = m_k6AuthorizedTargets.find(K6AuthorizedTargetKey(
                ctx.circ->Id(), sourceRequestId, resultId));
            if (found != m_k6AuthorizedTargets.end() &&
                found->second.expires_at > static_cast<uint64>(time(NULL)))
                target = found->second;
        }
        if (target.expires_at != 0 && target.result_id == resultId &&
            target.endpoint.addr.family == kad6::Kad6Address::Family::IPv4 &&
            target.endpoint.tcp_port != 0) {
            memcpy(&bIP, target.endpoint.addr.addr.data(), 4);
            bPort = target.endpoint.tcp_port;
            bUDP = target.endpoint.udp_port;
            resolved = bIP != 0;
        }
    } else if (ctx.body && ctx.bodyLen == 28) {
        memcpy(streamKey, ctx.body, 16);
        bIP    = eseRdU32LE(ctx.body + 16);
        bPort  = eseRdU16LE(ctx.body + 20);
        bUDP   = eseRdU16LE(ctx.body + 22);
        bAltIP = eseRdU32LE(ctx.body + 24);
        resolved = bIP != 0 && bPort != 0;
    }
    if (resolved) {
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
            alreadyProxied = (it != m_exitLiveSubs.end() &&
                !it->second.circuits.empty() && it->second.bIP == bIP &&
                it->second.bPort == bPort && bAltIP == 0);
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
        if (due[i].canonicalK6) {
            const uint16_t sent = SendK6SearchResults(due[i]);
            if (due[i].searchKind == kad6::kK6SearchKindSourceHash) {
                bool foundByNetwork[2] = {false, false};
                for (const auto& source : due[i].sourceCandidates)
                    foundByNetwork[source.networkOrigin == kad6::kK6NetOriginKad6 ? 1 : 0] = true;
                const bool startedByNetwork[2] = {
                    due[i].kad2LookupStarted, due[i].kad6LookupStarted};
                const uint8_t masks[2] = {kad6::kK6NetMaskKad2, kad6::kK6NetMaskKad6};
                const uint64_t metricNow = static_cast<uint64_t>(time(NULL));
                for (uint8_t network = 0; network < 2; ++network)
                    if ((due[i].networkMask & masks[network]) != 0)
                        m_k6Metrics.Add(kad6::K6MetricFamily::SearchTotal,
                            network, foundByNetwork[network] ? 0 :
                                (startedByNetwork[network] ? 1 : 2),
                            0, 1, metricNow);
            }
            kad6::K6SearchEnd end;
            end.status = due[i].lookupStarted
                ? kad6::K6SearchEndStatus::Ok
                : (!due[i].kadReachable
                    ? kad6::K6SearchEndStatus::NoRoute
                    : (sent > 0 ? kad6::K6SearchEndStatus::Partial
                                : kad6::K6SearchEndStatus::Overloaded));
            end.result_count = sent;
            end.elapsed_ms = GetTickCount() - due[i].started;
            std::vector<uint8_t> endBody, endWire;
            if (kad6::EncodeK6SearchEnd(end, endBody) == kad6::Kad6Status::Ok) {
                kad6::K6Frame frame;
                frame.msg_type = kad6::kK6MsgSearchEnd;
                frame.flags = kad6::kK6FlagResponse | kad6::kK6FlagFinal |
                              kad6::kK6FlagLegacyKad2;
                frame.request_id = due[i].req_id;
                frame.body = std::move(endBody);
                if (kad6::EncodeK6Frame(frame, endWire) == kad6::Kad6Status::Ok)
                    CompleteExitOperation(due[i].circ_id, due[i].req_id,
                                          endWire.data(), endWire.size());
                else
                    AbortExitOperation(due[i].circ_id, due[i].req_id);
            } else {
                AbortExitOperation(due[i].circ_id, due[i].req_id);
            }
        } else {
            std::vector<uint8_t> payload;
            SerializeSearchResults(due[i].keyword, payload);
            // CompleteExitOperation no-ops if the circuit rotated/died meanwhile.
            CompleteExitOperation(due[i].circ_id, due[i].req_id,
                                  payload.data(), payload.size());
        }
        StopSearchJobKad(due[i]);   // free the CSearch either way
    }
}

uint16_t CLiveTunnel::SendK6SearchResults(const TunnelSearchJob& job)
{
    uint16_t sent = 0;
    try {
        if (job.searchKind == kad6::kK6SearchKindSourceHash) {
            std::vector<const TunnelSearchJob::SourceCandidate*> ranked;
            ranked.reserve(job.sourceCandidates.size());
            for (const auto& source : job.sourceCandidates) ranked.push_back(&source);
            std::stable_sort(ranked.begin(), ranked.end(),
                [](const TunnelSearchJob::SourceCandidate* a,
                   const TunnelSearchJob::SourceCandidate* b) {
                    return a->score > b->score;
                });
            const uint16_t limit = (uint16_t)(std::min<size_t>)(
                ranked.size(), (size_t)job.maxResults);
            for (uint16_t i = 0; i < limit; ++i) {
                const TunnelSearchJob::SourceCandidate& source = *ranked[i];
                kad6::K6SearchResult result;
                result.result_id = source.userHash;
                result.result_kind = kad6::kK6SearchKindSourceHash;
                result.network_origin = source.networkOrigin;

                K6AuthorizedTarget authorized;
                authorized.circ_id = job.circ_id;
                authorized.source_request_id = job.req_id;
                authorized.result_id = result.result_id;
                authorized.object_hash = job.targetHash;
                authorized.endpoint = source.endpoint;
                authorized.network_origin = source.networkOrigin;
                authorized.expires_at = authorized.endpoint.valid_until;

                std::vector<uint8_t> unsignedBody;
                if (kad6::EncodeK6SearchResult(result, unsignedBody) != kad6::Kad6Status::Ok)
                    continue;
                const kad6::Kad6CryptoHooks crypto = MakeKad6HostCryptoHooks();
                if (source.provenance == kad6::K6Provenance::Routing)
                    authorized.digest = source.provenanceDigest;
                else if (!crypto.sha256 || !crypto.sha256(unsignedBody.data(),
                        unsignedBody.size(), authorized.digest.data()))
                    continue;

                std::vector<uint8_t> ticketWire;
                if (!IssueK6RuntimeTicket(authorized, 4ull * 1024ull * 1024ull * 1024ull,
                        source.provenance, job.circ_id, job.req_id, i,
                        ticketWire))
                    continue;
                kad6::K6TargetTicket ticket;
                size_t ticketUsed = 0;
                if (kad6::DecodeK6TargetTicket(ticketWire.data(), ticketWire.size(), ticket,
                        &ticketUsed) != kad6::Kad6Status::Ok || ticketUsed != ticketWire.size())
                    continue;
                result.tickets.push_back(std::move(ticket));

                std::vector<uint8_t> resultBody, resultWire;
                if (kad6::EncodeK6SearchResult(result, resultBody) != kad6::Kad6Status::Ok)
                    continue;
                {
                    CSingleLock pl(&m_pendingLock, TRUE);
                    m_k6AuthorizedTargets[K6AuthorizedTargetKey(job.circ_id, job.req_id,
                        authorized.result_id)] = authorized;
                }
                kad6::K6Frame frame;
                frame.msg_type = kad6::kK6MsgSearchResult;
                frame.flags = kad6::kK6FlagResponse | kad6::kK6FlagMore;
                if (source.networkOrigin == kad6::kK6NetOriginKad2)
                    frame.flags |= kad6::kK6FlagLegacyKad2;
                frame.request_id = job.req_id;
                frame.body = std::move(resultBody);
                if (kad6::EncodeK6Frame(frame, resultWire) != kad6::Kad6Status::Ok ||
                    !SendExitOperationPart(job.circ_id, job.req_id,
                        resultWire.data(), resultWire.size()))
                    break;
                ++sent;
            }
            return sent;
        }

        if (!theApp.liveStreamManager) return 0;
        CArray<LiveStreamEntry> entries;
        theApp.liveStreamManager->GetKadBridge().GetKnownStreams(entries);
        const uint16_t limit = (uint16_t)(std::min<size_t>)(
            TUN_SEARCH_MAX_RESULTS, (size_t)job.maxResults);
        for (INT_PTR i = 0; i < entries.GetCount() && sent < limit; ++i) {
            const LiveStreamEntry& e = entries[i];
            CString titleLow = e.title;
            titleLow.MakeLower();
            const std::vector<uint8_t> titleUtf8 = EseCStringUtf8(titleLow);
            const std::string titleKey(titleUtf8.begin(), titleUtf8.end());
            if (!job.keyword.empty() && job.keyword != "eselive" &&
                titleKey.find(job.keyword) == std::string::npos)
                continue;

            uint32_t ip = e.broadcasterIP;
            if (ip == 0 && e.isOwnStream) ip = theApp.GetPublicIP();
            kad6::K6LiveSearchMetadata live;
            std::copy(e.streamKey, e.streamKey + 16, live.result_id.begin());
            live.ipv4 = {{static_cast<uint8_t>(ip), static_cast<uint8_t>(ip >> 8),
                          static_cast<uint8_t>(ip >> 16), static_cast<uint8_t>(ip >> 24)}};
            live.tcp_port = e.broadcasterPort;
            live.udp_port = e.broadcasterUDPPort;
            live.bitrate_kbps = e.bitrate;
            live.viewer_count = e.viewerCount;
            live.started_at = e.startedAt;
            live.discovery_namespace = e.discoveryNamespace <= ESE_NS_LEGACY
                ? e.discoveryNamespace : ESE_NS_UNKNOWN;
            live.title_utf8 = EseCStringUtf8(e.title);
            live.category_utf8 = EseCStringUtf8(e.category);
            live.language_utf8 = EseCStringUtf8(e.language);

            kad6::K6SearchResult result;
            std::vector<uint8_t> resultBody, resultWire;
            if (kad6::BuildK6LiveSearchResult(live, result) != kad6::Kad6Status::Ok ||
                kad6::EncodeK6SearchResult(result, resultBody) != kad6::Kad6Status::Ok)
                continue;
            K6AuthorizedTarget authorized;
            authorized.circ_id = job.circ_id;
            authorized.source_request_id = job.req_id;
            authorized.result_id = result.result_id;
            authorized.object_hash = result.result_id;
            authorized.endpoint.addr.family = kad6::Kad6Address::Family::IPv4;
            authorized.endpoint.addr.addr = {live.ipv4[0],live.ipv4[1],live.ipv4[2],live.ipv4[3]};
            authorized.endpoint.tcp_port = live.tcp_port;
            authorized.endpoint.udp_port = live.udp_port;
            authorized.endpoint.transport_flags = kad6::kK6EpTcpEd2k;
            // Match the origin's opaque Live route lifetime; the endpoint never
            // leaves exit-local authorized state.
            authorized.endpoint.valid_until = static_cast<uint64>(time(NULL)) + 120;
            authorized.expires_at = authorized.endpoint.valid_until;
            const kad6::Kad6CryptoHooks crypto = MakeKad6HostCryptoHooks();
            if (!crypto.sha256 ||
                !crypto.sha256(resultBody.data(), resultBody.size(), authorized.digest.data()) ||
                !K6AllowTicketTarget(this,
                    static_cast<kad6::Byte>(kad6::K6TicketService::Ed2kTcp),
                    authorized.endpoint))
                continue;
            // Live endpoints stay exit-local. Unlike file-source results, no
            // target ticket is embedded: its endpoint would be plaintext to A.
            // The later v2 LIVE_SUBSCRIBE resolves this authorized result_id on
            // this exact circuit and never returns the broadcaster address.
            {
                CSingleLock pl(&m_pendingLock, TRUE);
                m_k6AuthorizedTargets[K6AuthorizedTargetKey(job.circ_id, job.req_id,
                    authorized.result_id)] = authorized;
            }
            kad6::K6Frame frame;
            frame.msg_type = kad6::kK6MsgSearchResult;
            frame.flags = kad6::kK6FlagResponse | kad6::kK6FlagMore |
                          kad6::kK6FlagLegacyKad2;
            frame.request_id = job.req_id;
            frame.body = std::move(resultBody);
            if (kad6::EncodeK6Frame(frame, resultWire) != kad6::Kad6Status::Ok)
                continue;
            if (!SendExitOperationPart(job.circ_id, job.req_id,
                                       resultWire.data(), resultWire.size()))
                break;
            ++sent;
        }
    } catch (...) {}
    return sent;
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
                // IP=0 fix (v8.1): our OWN stream's directory entry may still
                // carry broadcasterIP=0 if it was published before our public
                // IP was known. Substitute it here — the IP is reliably known
                // by the time we serve a tunneled search — so the originator
                // doesn't reject the result as "invalid endpoint (IP=0)".
                uint32 outBroadcasterIP = e.broadcasterIP;
                if (outBroadcasterIP == 0 && e.isOwnStream)
                    outBroadcasterIP = theApp.GetPublicIP();
                putU32(outBroadcasterIP);
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
    // K6-1 migration: prefer K6Frame only when a matching Active circuit's
    // exit signed ESE_CAP_KAD6. Otherwise retain the deployed 0x42/0x43 wire.
    uint32_t req_id;
    PendingRequest* pr = RegisterPending(req_id);
    std::vector<uint8_t> body;
    const bool canonical = HasActiveCircuitWithExitCaps(ESE_CAP_KAD6);
    uint8_t op = TUN_OP_KAD_SEARCH_V2;
    uint32_t requiredCaps = 0;
    uint32_t pinnedCircuit = 0;
    if (canonical) {
        if (!EseBuildK6SearchStartFrame(keywordLower, req_id, body)) {
            std::vector<uint8_t> ignored;
            WaitPending(req_id, pr, 0, ignored, NULL);
            return false;
        }
        op = TUN_OP_KAD6_GATEWAY;
        requiredCaps = ESE_CAP_KAD6;
        pinnedCircuit = K6SelectOriginCircuit(requiredCaps, 0, 2);
        kad6::K6Frame quotaOperation;
        size_t quotaUsed = 0;
        if (pinnedCircuit == 0 ||
            kad6::DecodeK6Frame(body.data(), body.size(), quotaOperation, &quotaUsed) !=
                kad6::Kad6Status::Ok || quotaUsed != body.size()) {
            std::vector<uint8_t> ignored;
            WaitPending(req_id, pr, 0, ignored, NULL);
            return false;
        }
        if (K6CircuitHasExitCaps(pinnedCircuit, ESE_CAP_KAD6_ECONOMY, 2) &&
            !K6AcquireAnonymousQuota(pinnedCircuit, kad6::K6QuotaService::Control,
                quotaOperation.msg_type, quotaOperation.body,
                (std::max<uint32>)(3, timeoutMs / 2)) && IsK6PublicReleaseEnabled()) {
            std::vector<uint8_t> ignored;
            WaitPending(req_id, pr, 0, ignored, NULL);
            return false;
        }
    } else {
        const uint16_t kwLen = (uint16_t)(
            keywordLower.size() > 0xFFFF ? 0xFFFF : keywordLower.size());
        body.push_back(0x01);
        body.push_back((uint8_t)(kwLen & 0xFF));
        body.push_back((uint8_t)(kwLen >> 8));
        body.insert(body.end(), keywordLower.begin(), keywordLower.begin() + kwLen);
    }

    {
        CSingleLock pl(&m_pendingLock, TRUE);
        pr->sub_cmd      = op;
        pr->required_exit_caps = requiredCaps;
        pr->request_msg  = body;
        pr->retries_left = canonical ? 0 : TUN_SEND_RETRIES;
    }
    EnqueueSendMsg(req_id, op, body.data(), body.size(), requiredCaps,
        pinnedCircuit);

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
bool CLiveTunnel::K6BindSource(const kad6::K6SourceBind& bind,
                               kad6::K6SourceBound& boundOut,
                               uint32_t timeoutMs)
{
    boundOut = kad6::K6SourceBound{};
    const uint32_t requiredCaps = ESE_CAP_KAD6
        | ((bind.flags & kad6::kK6SourceStrict)
            ? (ESE_CAP_TUNNEL_STRICT3 | ESE_CAP_TUNNEL_SHAPED) : 0);
    const uint32 targetCircuit = K6SelectOriginCircuit(requiredCaps, 0, 2);
    if (targetCircuit == 0) return false;
    std::vector<uint8_t> body, wire;
    if (kad6::EncodeK6SourceBind(bind, body) != kad6::Kad6Status::Ok) return false;
    if (K6CircuitHasExitCaps(targetCircuit, ESE_CAP_KAD6_ECONOMY, 2) &&
        !K6AcquireAnonymousQuota(targetCircuit, kad6::K6QuotaService::ExitKad,
            kad6::kK6MsgSourceBind, body,
            (std::max<uint32>)(3, timeoutMs / 2)) && IsK6PublicReleaseEnabled())
        return false;
    uint32_t reqId;
    PendingRequest* pending = RegisterPending(reqId);
    kad6::K6Frame frame;
    frame.msg_type = kad6::kK6MsgSourceBind;
    frame.flags = kad6::kK6FlagLegacyEd2k |
        ((bind.flags & kad6::kK6SourceStrict) ? kad6::kK6FlagStrict : 0);
    frame.request_id = reqId;
    frame.body = std::move(body);
    if (kad6::EncodeK6Frame(frame, wire) != kad6::Kad6Status::Ok) {
        std::vector<uint8_t> ignored;
        WaitPending(reqId, pending, 0, ignored, NULL);
        return false;
    }
    {
        CSingleLock pl(&m_pendingLock, TRUE);
        pending->sub_cmd = TUN_OP_KAD6_GATEWAY;
        pending->required_exit_caps = requiredCaps;
        pending->request_msg = wire;
        pending->retries_left = 0;
    }
    EnqueueSendMsg(reqId, TUN_OP_KAD6_GATEWAY, wire.data(), wire.size(), requiredCaps,
        targetCircuit);
    std::vector<uint8_t> reply;
    uint32 pinnedCircuit = 0;
    if (!WaitPending(reqId, pending, timeoutMs, reply, NULL, &pinnedCircuit)) return false;
    kad6::K6Frame response;
    size_t consumed = 0;
    if (kad6::DecodeK6Frame(reply.data(), reply.size(), response, &consumed) !=
            kad6::Kad6Status::Ok || consumed != reply.size() ||
        response.msg_type != kad6::kK6MsgSourceBound || response.request_id != reqId ||
        kad6::DecodeK6SourceBound(response.body.data(), response.body.size(), boundOut,
            &consumed) != kad6::Kad6Status::Ok || consumed != response.body.size())
        return false;
    if (boundOut.status != kad6::K6SourceBoundStatus::Ok || pinnedCircuit == 0)
        return false;
    std::array<uint8_t, kad6::kEd25519PubSize> expectedExit{};
    bool exitPinned = false;
    {
        CSingleLock lock(&m_lock, TRUE);
        for (const auto& circuit : m_circuits) {
            if (!circuit || circuit->Id() != pinnedCircuit ||
                circuit->m_role != CircuitRole::Originator ||
                circuit->State() != CircuitState::Active || !circuit->m_auth_ok ||
                circuit->HopCount() == 0)
                continue;
            memcpy(expectedExit.data(),
                   circuit->Hop(circuit->HopCount() - 1).pub_long,
                   expectedExit.size());
            exitPinned = true;
            break;
        }
    }
    // The signature alone authenticates only the key embedded by the sender.
    // Bind it to the last authenticated hop of the exact response circuit.
    if (!exitPinned ||
        kad6::VerifyK6SourceBound(MakeKad6HostCryptoHooks(), bind, boundOut,
            expectedExit.data()) != kad6::Kad6Status::Ok)
        return false;
    {
        CSingleLock pl(&m_pendingLock, TRUE);
        m_k6OriginSourceLeaseRoutes[boundOut.source_lease_id] = pinnedCircuit;
    }
    return true;
}

bool CLiveTunnel::K6PublishRecord(const kad6::K6Publish& publish,
                                  kad6::K6PublishAck& ackOut,
                                  uint32_t timeoutMs)
{
    ackOut = kad6::K6PublishAck{};
    if (!HasActiveCircuitWithExitCaps(ESE_CAP_KAD6)) return false;
    std::vector<uint8_t> body, wire;
    if (kad6::EncodeK6Publish(publish, body) != kad6::Kad6Status::Ok) return false;
    uint64 sourceLeaseId = 0;
    if (publish.record_kind == kad6::K6RecordKind::Source &&
        publish.record.size() == 17 && publish.record[0] == 1) {
        for (size_t i = 0; i < 8; ++i)
            sourceLeaseId |= static_cast<uint64>(publish.record[1 + i]) << (8 * i);
    } else if (publish.record_kind == kad6::K6RecordKind::Kad6SourceDescriptor) {
        kad6::K6SourceRecord record;
        size_t used = 0;
        if (kad6::DecodeK6SourceRecord(publish.record.data(), publish.record.size(),
                record, &used) == kad6::Kad6Status::Ok && used == publish.record.size()) {
            CSingleLock pl(&m_pendingLock, TRUE);
            for (const auto& descriptor : record.exits)
                if (m_k6OriginSourceLeaseRoutes.find(descriptor.lease_hint) !=
                        m_k6OriginSourceLeaseRoutes.end()) {
                    sourceLeaseId = descriptor.lease_hint;
                    break;
                }
        }
    }
    uint32 pinnedCircuit = 0;
    {
        CSingleLock pl(&m_pendingLock, TRUE);
        auto route = m_k6OriginSourceLeaseRoutes.find(sourceLeaseId);
        if (route != m_k6OriginSourceLeaseRoutes.end()) pinnedCircuit = route->second;
    }
    if (sourceLeaseId == 0 || pinnedCircuit == 0) return false;

    if (K6CircuitHasExitCaps(pinnedCircuit, ESE_CAP_KAD6_ECONOMY, 2) &&
        !K6AcquireAnonymousQuota(pinnedCircuit, kad6::K6QuotaService::ExitKad,
            kad6::kK6MsgPublish, body,
            (std::max<uint32>)(3, timeoutMs / 2)) && IsK6PublicReleaseEnabled())
        return false;

    uint32_t reqId;
    PendingRequest* pending = RegisterPending(reqId);
    kad6::K6Frame frame;
    frame.msg_type = kad6::kK6MsgPublish;
    frame.flags = ((publish.network_mask & kad6::kK6PublishNetKad2)
        ? kad6::kK6FlagLegacyKad2 : 0) |
        ((publish.network_mask & kad6::kK6PublishNetKad6)
        ? kad6::kK6FlagNativeKad6 : 0);
    frame.request_id = reqId;
    frame.body = std::move(body);
    if (kad6::EncodeK6Frame(frame, wire) != kad6::Kad6Status::Ok) {
        std::vector<uint8_t> ignored;
        WaitPending(reqId, pending, 0, ignored, NULL);
        return false;
    }
    {
        CSingleLock pl(&m_pendingLock, TRUE);
        pending->sub_cmd = TUN_OP_KAD6_GATEWAY;
        pending->required_exit_caps = ESE_CAP_KAD6;
        pending->request_msg = wire;
        // A SourceLease is circuit-bound. Retrying this publish on another
        // circuit is guaranteed to fail and could create misleading state.
        pending->retries_left = 0;
    }
    EnqueueSendMsg(reqId, TUN_OP_KAD6_GATEWAY, wire.data(), wire.size(),
        ESE_CAP_KAD6, pinnedCircuit);
    std::vector<uint8_t> reply;
    if (!WaitPending(reqId, pending, timeoutMs, reply, NULL)) return false;
    kad6::K6Frame response;
    size_t consumed = 0;
    if (kad6::DecodeK6Frame(reply.data(), reply.size(), response, &consumed) !=
            kad6::Kad6Status::Ok || consumed != reply.size() ||
        response.msg_type != kad6::kK6MsgPublishAck || response.request_id != reqId ||
        kad6::DecodeK6PublishAck(response.body.data(), response.body.size(), ackOut,
            &consumed) != kad6::Kad6Status::Ok || consumed != response.body.size())
        return false;
    if (ackOut.status == kad6::K6PublishStatus::Rejected) return false;
    {
        CSingleLock pl(&m_pendingLock, TRUE);
        m_k6OriginPublishLeaseRoutes[ackOut.publish_lease_id] = pinnedCircuit;
    }
    return true;
}

void CLiveTunnel::K6SourceUnbindNoWait(const kad6::K6SourceUnbind& unbind)
{
    if (!HasActiveCircuitWithExitCaps(ESE_CAP_KAD6)) return;
    std::vector<uint8_t> body, wire;
    if (kad6::EncodeK6SourceUnbind(unbind, body) != kad6::Kad6Status::Ok) return;
    const uint32_t reqId = NewCircuitId();
    kad6::K6Frame frame; frame.msg_type = kad6::kK6MsgSourceUnbind;
    frame.request_id = reqId; frame.body = std::move(body);
    uint32 pinnedCircuit = 0;
    {
        CSingleLock pl(&m_pendingLock, TRUE);
        auto route = m_k6OriginSourceLeaseRoutes.find(unbind.source_lease_id);
        if (route != m_k6OriginSourceLeaseRoutes.end()) {
            pinnedCircuit = route->second;
            m_k6OriginSourceLeaseRoutes.erase(route);
        }
    }
    if (pinnedCircuit != 0 &&
        kad6::EncodeK6Frame(frame, wire) == kad6::Kad6Status::Ok)
        EnqueueSendMsg(reqId, TUN_OP_KAD6_GATEWAY, wire.data(), wire.size(),
            ESE_CAP_KAD6, pinnedCircuit);
}

void CLiveTunnel::K6UnpublishNoWait(const kad6::K6Unpublish& unpublish)
{
    if (!HasActiveCircuitWithExitCaps(ESE_CAP_KAD6)) return;
    std::vector<uint8_t> body, wire;
    if (kad6::EncodeK6Unpublish(unpublish, body) != kad6::Kad6Status::Ok) return;
    const uint32_t reqId = NewCircuitId();
    kad6::K6Frame frame; frame.msg_type = kad6::kK6MsgUnpublish;
    frame.request_id = reqId; frame.body = std::move(body);
    uint32 pinnedCircuit = 0;
    {
        CSingleLock pl(&m_pendingLock, TRUE);
        auto route = m_k6OriginPublishLeaseRoutes.find(unpublish.publish_lease_id);
        if (route != m_k6OriginPublishLeaseRoutes.end()) {
            pinnedCircuit = route->second;
            m_k6OriginPublishLeaseRoutes.erase(route);
        }
    }
    if (pinnedCircuit != 0 &&
        kad6::EncodeK6Frame(frame, wire) == kad6::Kad6Status::Ok)
        EnqueueSendMsg(reqId, TUN_OP_KAD6_GATEWAY, wire.data(), wire.size(),
            ESE_CAP_KAD6, pinnedCircuit);
}

void CLiveTunnel::QueueK6SourceAdvertise(const uint8_t fileHash[16], uint64 fileSize,
                                         kad6::K6CommitmentKind commitmentKind,
                                         const uint8_t commitment[32])
{
    if (!fileHash || !commitment || fileSize == 0 || theApp.IsClosing() ||
        commitmentKind == kad6::K6CommitmentKind::None ||
        !NodeIdentityIsPersistent() || !HasActiveCircuitWithExitCaps(ESE_CAP_KAD6))
        return;
    uint8 anyHash = 0, anyCommitment = 0;
    for (size_t i = 0; i < 16; ++i) anyHash |= fileHash[i];
    for (size_t i = 0; i < 32; ++i) anyCommitment |= commitment[i];
    if (!anyHash || !anyCommitment) return;

    const uint64 now = static_cast<uint64>(time(NULL));
    const std::string key = K6BinaryKey(fileHash, 16);
    uint64 epoch = 0;
    {
        CSingleLock pl(&m_pendingLock, TRUE);
        K6OriginAdvertiseState& state = m_k6OriginAdvertisements[key];
        if (state.in_flight || state.next_attempt > now) return;
        size_t workers = 0;
        for (const auto& pair : m_k6OriginAdvertisements)
            if (pair.second.in_flight) ++workers;
        if (workers >= 2) return;
        const uint64 timeBase = now <= ((std::numeric_limits<uint64>::max)() >> 20)
            ? now << 20 : now;
        if (m_k6OriginSourceEpoch < timeBase) m_k6OriginSourceEpoch = timeBase;
        if (m_k6OriginSourceEpoch == (std::numeric_limits<uint64>::max)()) return;
        epoch = ++m_k6OriginSourceEpoch;
        state.in_flight = true;
        state.next_attempt = now + 30;
    }

    const uint8_t* publicKey = NodeIdentityPub();
    const kad6::Kad6CryptoHooks crypto = MakeKad6HostCryptoHooks();
    K6OriginAdvertiseWork* work = new K6OriginAdvertiseWork();
    work->owner = this;
    work->key = key;
    memcpy(work->bind.file_hash.data(), fileHash, work->bind.file_hash.size());
    work->bind.file_size = fileSize;
    memcpy(work->bind.compat_user_hash.data(), thePrefs.GetUserHash(),
        work->bind.compat_user_hash.size());
    work->bind.desired_family = 4;
    work->bind.transport_mask = kad6::kK6TransportTcp;
    work->bind.flags = kad6::kK6SourceAllowInbound | kad6::kK6SourceStrict |
        kad6::kK6SourceFile;
    work->bind.requested_lifetime_s = 2u * 60u * 60u;
    const uint64 maxUpload = static_cast<uint64>(thePrefs.GetMaxUpload()) * 1024ull;
    work->bind.max_upload_bps = static_cast<uint32>((std::min<uint64>)(
        maxUpload, kad6::kK6SourceMaxUploadBps));
    work->bind.source_epoch = epoch;
    work->bind.requested_mode = kad6::K6BindingMode::Cohort;
    work->bind.commitment_kind = commitmentKind;
    memcpy(work->bind.content_commitment.data(), commitment,
        work->bind.content_commitment.size());
    bool prepared = publicKey && crypto.random_bytes &&
        crypto.random_bytes(work->bind.bind_nonce.data(), work->bind.bind_nonce.size()) &&
        kad6::MakeK6CompatProofV1(crypto, NULL, 0, publicKey, work->bind) ==
            kad6::Kad6Status::Ok;
    CWinThread* thread = prepared ? AfxBeginThread(&CLiveTunnel::K6OriginAdvertiseWorker,
        work, THREAD_PRIORITY_BELOW_NORMAL) : NULL;
    if (!thread) {
        delete work;
        CSingleLock pl(&m_pendingLock, TRUE);
        K6OriginAdvertiseState& state = m_k6OriginAdvertisements[key];
        state.in_flight = false;
        state.next_attempt = now + 60;
    }
}

UINT AFX_CDECL CLiveTunnel::K6OriginAdvertiseWorker(LPVOID context)
{
    std::unique_ptr<K6OriginAdvertiseWork> work(
        static_cast<K6OriginAdvertiseWork*>(context));
    if (!work || !work->owner) return 1;
    kad6::K6SourceBound bound;
    kad6::K6PublishAck ack;
    bool success = work->owner->K6BindSource(work->bind, bound, 15000);
    if (success) {
        kad6::K6Publish publish;
        publish.record_kind = kad6::K6RecordKind::Source;
        publish.network_mask = kad6::kK6PublishNetKad2;
        publish.flags = kad6::kK6PublishFlagSigned | kad6::kK6PublishFlagRefresh;
        publish.requested_ttl_s = bound.lifetime_s;
        publish.record_epoch = work->bind.source_epoch;
        publish.target_hash = work->bind.file_hash;
        publish.source_id = work->bind.compat_user_hash;
        publish.record.resize(17);
        publish.record[0] = 1;
        for (size_t i = 0; i < 8; ++i) {
            publish.record[1 + i] = static_cast<uint8_t>(bound.source_lease_id >> (8 * i));
            publish.record[9 + i] = static_cast<uint8_t>(work->bind.file_size >> (8 * i));
        }
        std::vector<uint8_t> canonical;
        success = kad6::SignK6Publish(MakeKad6HostCryptoHooks(), NULL, 0,
            publish, canonical) == kad6::Kad6Status::Ok &&
            work->owner->K6PublishRecord(publish, ack, 15000);
    }
    if (!success && bound.source_lease_id != 0) {
        kad6::K6SourceUnbind unbind;
        unbind.source_lease_id = bound.source_lease_id;
        unbind.source_epoch = work->bind.source_epoch;
        unbind.reason = kad6::K6SourceUnbindReason::Policy;
        unbind.bind_nonce = work->bind.bind_nonce;
        work->owner->K6SourceUnbindNoWait(unbind);
    }
    const uint32 refresh = success && bound.lifetime_s > 120
        ? bound.lifetime_s - 60 : 60;
    work->owner->FinishK6OriginAdvertise(work->key, success,
        success ? bound.source_lease_id : 0,
        success ? ack.publish_lease_id : 0, refresh);
    return success ? 0 : 1;
}

void CLiveTunnel::FinishK6OriginAdvertise(const std::string& key, bool success,
                                          uint64 sourceLeaseId,
                                          uint64 publishLeaseId,
                                          uint32 refreshAfter)
{
    const uint64 now = static_cast<uint64>(time(NULL));
    CSingleLock pl(&m_pendingLock, TRUE);
    K6OriginAdvertiseState& state = m_k6OriginAdvertisements[key];
    state.in_flight = false;
    state.next_attempt = now + (std::max)(30u, refreshAfter);
    if (success) {
        state.source_lease_id = sourceLeaseId;
        state.publish_lease_id = publishLeaseId;
        LIVE_LOG("K6", "source advertised lease=%llu publish=%llu refresh=%u",
            static_cast<unsigned long long>(sourceLeaseId),
            static_cast<unsigned long long>(publishLeaseId), refreshAfter);
    } else {
        LIVE_LOG("K6", "source advertise failed; retry in %u s", refreshAfter);
    }
}

bool CLiveTunnel::StartK6SourceLookup(const uint8_t fileHash[16],
                                      uint32_t& requestIdOut)
{
    requestIdOut = 0;
    if (fileHash == NULL || !HasActiveCircuitWithExitCaps(ESE_CAP_KAD6)) return false;
    uint8_t any = 0;
    for (size_t i = 0; i < 16; ++i) any |= fileHash[i];
    if (any == 0) return false;

    uint32_t reqId = 0;
    for (;;) {
        reqId = NewCircuitId();
        CSingleLock pl(&m_pendingLock, TRUE);
        if (reqId != 0 && m_k6OriginSourceLookups.find(reqId) ==
                m_k6OriginSourceLookups.end())
            break;
    }

    kad6::K6SearchStart start;
    start.search_kind = kad6::kK6SearchKindSourceHash;
    start.network_mask = kad6::kK6NetMaskKad2 | kad6::kK6NetMaskKad6;
    start.max_results = 100;
    start.deadline_ms = TUN_SEARCH_WINDOW_MS;
    memcpy(start.target_hash.data(), fileHash, start.target_hash.size());
    std::vector<uint8_t> body, wire;
    if (kad6::EncodeK6SearchStart(start, body) != kad6::Kad6Status::Ok) return false;
    kad6::K6Frame frame;
    frame.msg_type = kad6::kK6MsgSearchStart;
    frame.flags = kad6::kK6FlagCancelable | kad6::kK6FlagLegacyKad2;
    frame.request_id = reqId;
    frame.body = std::move(body);
    if (kad6::EncodeK6Frame(frame, wire) != kad6::Kad6Status::Ok) return false;

    K6OriginSourceLookup lookup;
    memcpy(lookup.file_hash.data(), fileHash, lookup.file_hash.size());
    lookup.deadline = GetTickCount() + TUN_SEARCH_WINDOW_MS + 15000u;
    {
        CSingleLock pl(&m_pendingLock, TRUE);
        m_k6OriginSourceLookups[reqId] = lookup;
    }
    EnqueueSendMsg(reqId, TUN_OP_KAD6_GATEWAY, wire.data(), wire.size(), ESE_CAP_KAD6);
    requestIdOut = reqId;
    LIVE_LOG("K6", "source-hash lookup queued req=%u", reqId);
    return true;
}

bool CLiveTunnel::BeginK6Download(CUpDownClient* client)
{
    if (client == NULL || client->GetRequestFile() == NULL ||
        !HasActiveCircuitWithExitCaps(ESE_CAP_KAD6))
        return false;

    std::vector<uint8_t> ticketWire;
    if (!client->TakeK6TargetTicket(ticketWire)) return false;
    kad6::K6TargetTicket ticket;
    size_t used = 0;
    if (kad6::DecodeK6TargetTicket(ticketWire.data(), ticketWire.size(), ticket, &used) !=
            kad6::Kad6Status::Ok || used != ticketWire.size() ||
        ticket.service != static_cast<kad6::Byte>(kad6::K6TicketService::Ed2kTcp) ||
        (ticket.provenance_kind != static_cast<kad6::Byte>(kad6::K6Provenance::KadResult) &&
         ticket.provenance_kind != static_cast<kad6::Byte>(kad6::K6Provenance::Routing)) ||
        ticket.provenance_session == 0 || ticket.provenance_session > 0xffffffffULL ||
        ticket.max_connections != 1 || ticket.max_bytes == 0 ||
        ticket.expires_at <= static_cast<uint64>(time(NULL)) ||
        kad6::K6TicketTargetForbidden(ticket) ||
        memcmp(ticket.object_hash.data(), client->GetRequestFile()->GetFileHash(), 16) != 0)
        return false;

    kad6::K6Dial dial;
    dial.ticket = std::move(ticketWire);
    dial.protocol = kad6::K6GatewayTransport::TcpEd2k;
    dial.connect_timeout_ms = 10000;
    dial.idle_timeout_ms = 120000;
    std::vector<uint8_t> body, wire;
    if (kad6::EncodeK6Dial(dial, body) != kad6::Kad6Status::Ok) return false;

    uint32_t reqId = 0;
    for (;;) {
        reqId = NewCircuitId();
        CSingleLock pl(&m_pendingLock, TRUE);
        if (reqId != 0 && m_k6DownloadActivations.find(reqId) ==
                m_k6DownloadActivations.end())
            break;
    }
    {
        CSingleLock pl(&m_pendingLock, TRUE);
        K6DownloadActivation activation;
        activation.client = client;
        activation.circ_id = static_cast<uint32>(ticket.provenance_session);
        activation.deadline = GetTickCount() + kad6::kK6DialMaxConnectTimeoutMs + 5000u;
        m_k6DownloadActivations[reqId] = activation;
    }

    kad6::K6Frame frame;
    frame.msg_type = kad6::kK6MsgDial;
    frame.flags = kad6::kK6FlagLegacyEd2k;
    frame.request_id = reqId;
    frame.body = std::move(body);
    if (kad6::EncodeK6Frame(frame, wire) != kad6::Kad6Status::Ok) {
        CSingleLock pl(&m_pendingLock, TRUE);
        m_k6DownloadActivations.erase(reqId);
        return false;
    }
    EnqueueSendMsg(reqId, TUN_OP_KAD6_GATEWAY, wire.data(), wire.size(),
        ESE_CAP_KAD6, static_cast<uint32>(ticket.provenance_session));
    LIVE_LOG("K6", "download DIAL queued req=%u", reqId);
    return true;
}

bool CLiveTunnel::K6RequestTargetTicket(const kad6::K6TargetTicketRequest& request,
                                        std::vector<uint8_t>& ticketOut,
                                        uint32_t timeoutMs)
{
    ticketOut.clear(); if (!HasActiveCircuitWithExitCaps(ESE_CAP_KAD6)) return false;
    uint32 pinnedCircId = 0;
    {
        CSingleLock pl(&m_pendingLock, TRUE);
        const auto route = m_k6OriginTargetRoutes.find(
            K6AuthorizedTargetKey(0, request.source_request_id, request.result_id));
        if (route == m_k6OriginTargetRoutes.end() ||
            route->second.expires_at <= static_cast<uint64>(time(NULL))) return false;
        pinnedCircId = route->second.circ_id;
    }
    std::vector<uint8_t> body, wire;
    if (kad6::EncodeK6TargetTicketRequest(request, body) != kad6::Kad6Status::Ok) return false;
    uint32 reqId; PendingRequest* pending = RegisterPending(reqId);
    kad6::K6Frame frame; frame.msg_type = kad6::kK6MsgTargetTicketReq;
    frame.flags = kad6::kK6FlagLegacyEd2k; frame.request_id = reqId; frame.body = std::move(body);
    if (kad6::EncodeK6Frame(frame, wire) != kad6::Kad6Status::Ok) {
        std::vector<uint8_t> ignored; WaitPending(reqId, pending, 0, ignored, NULL); return false;
    }
    {
        CSingleLock pl(&m_pendingLock, TRUE); pending->sub_cmd = TUN_OP_KAD6_GATEWAY;
        pending->required_exit_caps = ESE_CAP_KAD6; pending->request_msg = wire;
        pending->retries_left = 0; // result authorization is bound to this exact exit/circuit.
    }
    EnqueueSendMsg(reqId, TUN_OP_KAD6_GATEWAY, wire.data(), wire.size(),
        ESE_CAP_KAD6, pinnedCircId);
    std::vector<uint8_t> reply;
    if (!WaitPending(reqId, pending, timeoutMs, reply, NULL)) return false;
    kad6::K6Frame response; size_t used = 0; kad6::K6TargetTicketResponse ticket;
    if (kad6::DecodeK6Frame(reply.data(), reply.size(), response, &used) != kad6::Kad6Status::Ok ||
        used != reply.size() || response.msg_type != kad6::kK6MsgTargetTicket ||
        response.request_id != reqId ||
        kad6::DecodeK6TargetTicketResponse(response.body.data(), response.body.size(), ticket,
            &used) != kad6::Kad6Status::Ok || used != response.body.size() ||
        ticket.status != kad6::K6TargetTicketStatus::Ok) return false;
    ticketOut = std::move(ticket.ticket); return true;
}

bool CLiveTunnel::K6DialEd2k(const std::vector<uint8_t>& ticket,
                             const std::vector<uint8_t>& initialData,
                             kad6::K6DialResult& resultOut, uint32_t timeoutMs)
{
    resultOut = kad6::K6DialResult{};
    if (!HasActiveCircuitWithExitCaps(ESE_CAP_KAD6)) return false;
    kad6::K6TargetTicket ticketMeta; size_t ticketUsed = 0;
    if (kad6::DecodeK6TargetTicket(ticket.data(), ticket.size(), ticketMeta,
            &ticketUsed) != kad6::Kad6Status::Ok || ticketUsed != ticket.size() ||
        ticketMeta.provenance_session == 0 ||
        ticketMeta.provenance_session > 0xffffffffULL) return false;
    const uint32 pinnedCircId = static_cast<uint32>(ticketMeta.provenance_session);
    bool initialHasHello = false; size_t initialOffset = 0;
    while (initialOffset < initialData.size()) {
        kad6::K6Ed2kFrameView initialFrame;
        if (initialData.size() - initialOffset < kad6::kK6Ed2kHeaderSize) return false;
        const uint8_t* p = initialData.data() + initialOffset;
        const uint32 packetLength = static_cast<uint32>(p[1]) |
            (static_cast<uint32>(p[2]) << 8) | (static_cast<uint32>(p[3]) << 16) |
            (static_cast<uint32>(p[4]) << 24);
        const size_t frameLength = 5ull + packetLength;
        if (packetLength == 0 || frameLength > initialData.size() - initialOffset ||
            kad6::DecodeK6Ed2kFrame(p, frameLength, initialFrame) != kad6::Kad6Status::Ok)
            return false;
        initialHasHello = initialHasHello ||
            kad6::ClassifyK6Ed2kFrame(initialFrame.protocol, initialFrame.opcode) ==
                kad6::K6Ed2kFrameClass::Hello;
        initialOffset += frameLength;
    }
    kad6::K6Dial dial; dial.ticket = ticket; dial.protocol = kad6::K6GatewayTransport::TcpEd2k;
    dial.connect_timeout_ms = (std::max<uint32>)(kad6::kK6DialMinConnectTimeoutMs,
        (std::min<uint32>)(timeoutMs, kad6::kK6DialMaxConnectTimeoutMs));
    dial.idle_timeout_ms = 120000; dial.initial_data = initialData;
    std::vector<uint8_t> body, wire;
    if (kad6::EncodeK6Dial(dial, body) != kad6::Kad6Status::Ok) return false;
    if (K6CircuitHasExitCaps(pinnedCircId, ESE_CAP_KAD6_ECONOMY, 2) &&
        !K6AcquireAnonymousQuota(pinnedCircId,
            kad6::K6QuotaService::ExitEd2kDial, kad6::kK6MsgDial, body,
            (std::max<uint32>)(3, timeoutMs / 2)) && IsK6PublicReleaseEnabled())
        return false;
    uint32 reqId; PendingRequest* pending = RegisterPending(reqId);
    kad6::K6Frame frame; frame.msg_type = kad6::kK6MsgDial;
    frame.flags = kad6::kK6FlagLegacyEd2k; frame.request_id = reqId; frame.body = std::move(body);
    if (kad6::EncodeK6Frame(frame, wire) != kad6::Kad6Status::Ok) {
        std::vector<uint8_t> ignored; WaitPending(reqId, pending, 0, ignored, NULL); return false;
    }
    {
        CSingleLock pl(&m_pendingLock, TRUE); pending->sub_cmd = TUN_OP_KAD6_GATEWAY;
        pending->required_exit_caps = ESE_CAP_KAD6; pending->request_msg = wire;
        pending->retries_left = 0; // a single-use DIAL must never be replayed automatically.
    }
    EnqueueSendMsg(reqId, TUN_OP_KAD6_GATEWAY, wire.data(), wire.size(),
        ESE_CAP_KAD6, pinnedCircId);
    std::vector<uint8_t> reply;
    if (!WaitPending(reqId, pending, timeoutMs, reply, NULL)) return false;
    kad6::K6Frame response; size_t used = 0;
    if (kad6::DecodeK6Frame(reply.data(), reply.size(), response, &used) != kad6::Kad6Status::Ok ||
        used != reply.size() || response.msg_type != kad6::kK6MsgDialOk ||
        response.request_id != reqId ||
        kad6::DecodeK6DialResult(response.body.data(), response.body.size(), resultOut,
            &used) != kad6::Kad6Status::Ok || used != response.body.size()) return false;
    if (resultOut.status == kad6::K6DialStatus::Ok) {
        CSingleLock pl(&m_pendingLock, TRUE);
        auto stream = m_k6OriginStreams.find(resultOut.stream_id);
        if (stream == m_k6OriginStreams.end()) return false;
        stream->second.initial_data_sent = initialHasHello;
    }
    return resultOut.status == kad6::K6DialStatus::Ok;
}

bool CLiveTunnel::K6AttachOriginClient(uint64 streamId, CUpDownClient* client)
{
    if (!streamId || !client || client->socket != NULL) return false;
    CKad6OriginSocket* socket = new CKad6OriginSocket();
    if (!socket->Initialize(streamId, client)) { socket->Safe_Delete(); return false; }
    std::deque<std::vector<uint8_t>> pendingFrames;
    bool sendHello = true;
    uint32 flowCircId = 0;
    {
        CSingleLock pl(&m_pendingLock, TRUE);
        auto stream = m_k6OriginStreams.find(streamId);
        if (stream == m_k6OriginStreams.end() || stream->second.socket != NULL) {
            pl.Unlock(); socket->Safe_Delete(); return false;
        }
        stream->second.socket = socket; stream->second.client = client;
        flowCircId = stream->second.circ_id;
        sendHello = !stream->second.initial_data_sent;
        pendingFrames.swap(stream->second.pending_frames);
        stream->second.pending_frame_bytes = 0;
        if (stream->second.has_vep &&
            stream->second.vep.apparent_source_ip.family == kad6::Kad6Address::Family::IPv4) {
            uint32 ip = 0; memcpy(&ip, stream->second.vep.apparent_source_ip.addr.data(), 4);
            client->SetK6SecureIdentVepIPv4(ip);
        }
    }
    if (sendHello) client->SendHelloPacket();
    for (const std::vector<uint8_t>& frame : pendingFrames)
        if (!socket->InjectRawFrame(frame.data(), frame.size()) ||
            !ConsumeK6ReceiveCredit(flowCircId, streamId, 1, frame.size(),
                std::weak_ptr<CLiveCircuit>(), false)) {
            socket->Disconnect(_T("Kad6 buffered frame rejected"));
            return false;
        }
    return true;
}

bool CLiveTunnel::K6SendEd2kFrameNoWait(uint64 streamId, const uint8_t* raw, size_t length)
{
    kad6::K6Ed2kFrameView view;
    if (!raw || kad6::DecodeK6Ed2kFrame(raw, length, view) != kad6::Kad6Status::Ok) return false;
    kad6::K6StreamData data; data.stream_id = streamId; data.direction = 0;
    data.flags = 0x02; data.data.assign(raw, raw + length);
    CSingleLock pl(&m_pendingLock, TRUE);
    auto stream = m_k6OriginStreams.find(streamId);
    if (stream == m_k6OriginStreams.end()) return false;
    data.sequence = stream->second.next_tx_sequence;

    std::vector<uint8_t> body, wire;
    if (kad6::EncodeK6StreamData(data, body) != kad6::Kad6Status::Ok) return false;
    const uint32 reqId = NewCircuitId(); kad6::K6Frame frame;
    frame.msg_type = kad6::kK6MsgStreamData; frame.flags = kad6::kK6FlagLegacyEd2k;
    frame.request_id = reqId; frame.body = std::move(body);
    if (kad6::EncodeK6Frame(frame, wire) != kad6::Kad6Status::Ok) return false;

    // Bound work waiting to reach the main-thread circuit sender. The queue is
    // released as requests are popped; no socket thread blocks for credit.
    CSingleLock ql(&m_mtLock, TRUE);
    size_t streamMessages = 0, streamBytes = 0, globalBytes = 0;
    for (const MainThreadReq& queued : m_mtQueue) {
        if (queued.k6StreamId == 0) continue;
        globalBytes += queued.k6FlowBytes;
        if (queued.k6StreamId == streamId) {
            ++streamMessages;
            streamBytes += queued.k6FlowBytes;
        }
    }
    for (const auto& origin : m_k6OriginStreams) {
        for (const K6QueuedOriginFrame& queued : origin.second.pending_credit_frames) {
            globalBytes += queued.wire.size();
            if (origin.first == streamId) {
                ++streamMessages;
                streamBytes += queued.wire.size();
            }
        }
    }
    const size_t perStreamLimit = 2u * 1024u * 1024u;
    const size_t globalLimit = 32u * 1024u * 1024u;
    if (wire.size() > perStreamLimit || wire.size() > globalLimit ||
        streamMessages >= 64 || streamBytes > perStreamLimit - wire.size() ||
        globalBytes > globalLimit - wire.size()) return false;
    const uint64 maxBytes = stream->second.dial.max_bytes;
    const uint64 txBytes = stream->second.flow.total_bytes(0);
    const uint64 rxBytes = stream->second.flow.total_bytes(1);
    if (stream->second.next_tx_sequence == (std::numeric_limits<uint64>::max)() ||
        (maxBytes && (txBytes > maxBytes || rxBytes > maxBytes - txBytes ||
            stream->second.queued_tx_bytes > maxBytes - txBytes - rxBytes ||
            data.data.size() > maxBytes - txBytes - rxBytes -
                stream->second.queued_tx_bytes))) return false;
    ++stream->second.next_tx_sequence;
    stream->second.queued_tx_bytes += data.data.size();

    auto ledger = m_k6SendCredits.find(stream->second.circ_id);
    if (ledger == m_k6SendCredits.end()) {
        --stream->second.next_tx_sequence;
        stream->second.queued_tx_bytes -= data.data.size();
        return false;
    }
    const uint64 sent = ledger->second.stream_sent(streamId, 0);
    const uint64 remaining = maxBytes == 0 || sent + rxBytes >= maxBytes
        ? (maxBytes == 0 ? (std::numeric_limits<uint64>::max)() : 0)
        : maxBytes - sent - rxBytes;
    const bool waitForCredit = !stream->second.pending_credit_frames.empty() ||
        ledger->second.CommitSend(streamId, 0, data.data.size(), remaining,
            (std::numeric_limits<uint64>::max)(),
            perStreamLimit - streamBytes) != kad6::Kad6Status::Ok;
    if (waitForCredit) {
        K6QueuedOriginFrame queued;
        queued.request_id = reqId;
        queued.sequence = data.sequence;
        queued.data_bytes = data.data.size();
        queued.wire = std::move(wire);
        stream->second.pending_credit_bytes += queued.data_bytes;
        stream->second.pending_credit_frames.push_back(std::move(queued));
        if (stream->second.credit_stall_since_ms == 0)
            stream->second.credit_stall_since_ms = K6ShapeNowUs() / 1000u;
        if (stream->second.socket) stream->second.socket->SetKad6FlowBlocked(true);
        return true;
    }

    MainThreadReq request;
    request.op = MT_SEND_MSG;
    request.reqId = reqId;
    request.subCmd = TUN_OP_KAD6_GATEWAY;
    request.requiredExitCaps = ESE_CAP_KAD6;
    request.pinnedCircId = stream->second.circ_id;
    request.k6StreamId = streamId;
    request.k6FlowBytes = wire.size();
    request.k6Sequence = data.sequence;
    request.k6DataBytes = data.data.size();
    request.payload = std::move(wire);
    m_mtQueue.push_back(std::move(request));
    return true;
}

bool CLiveTunnel::K6TakeSourceHints(uint64 streamId, kad6::K6SourceHints& hintsOut)
{
    hintsOut = kad6::K6SourceHints{}; CSingleLock pl(&m_pendingLock, TRUE);
    auto stream = m_k6OriginStreams.find(streamId);
    if (stream == m_k6OriginStreams.end() || stream->second.hints.empty()) return false;
    hintsOut = std::move(stream->second.hints.front()); stream->second.hints.pop_front(); return true;
}

bool CLiveTunnel::K6GetVirtualIdentity(uint64 streamId,
                                       kad6::K6VirtualIdentityEndpoint& vepOut) const
{
    vepOut = kad6::K6VirtualIdentityEndpoint{}; CSingleLock pl(&m_pendingLock, TRUE);
    const auto stream = m_k6OriginStreams.find(streamId);
    if (stream == m_k6OriginStreams.end() || !stream->second.has_vep) return false;
    vepOut = stream->second.vep; return true;
}

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

bool CLiveTunnel::SendK6LiveSubscribeNoWait(const uint8_t streamKey[16])
{
    if (!streamKey) return false;
    K6OriginTargetRoute route;
    {
        CSingleLock pl(&m_pendingLock, TRUE);
        const auto found = m_k6OriginLiveRoutes.find(K6BinaryKey(streamKey, 16));
        if (found == m_k6OriginLiveRoutes.end() ||
            found->second.expires_at <= static_cast<uint64>(time(NULL)))
            return false;
        route = found->second;
    }
    if (route.circ_id == 0 || route.source_request_id == 0 ||
        K6SelectOriginCircuit(ESE_CAP_KAD6, route.circ_id, 2) != route.circ_id)
        return false;

    const uint32_t reqId = NewCircuitId();
    std::vector<uint8_t> body(24, 0);
    memcpy(body.data(), streamKey, 16);
    eseWrU32LE(body.data() + 16, route.source_request_id);
    body[20] = 2;
    EnqueueSendMsg(reqId, TUN_OP_LIVE_SUBSCRIBE, body.data(), body.size(),
                   ESE_CAP_KAD6, route.circ_id);
    return true;
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
    if (HasActiveCircuitWithExitCaps(ESE_CAP_KAD6)) {
        if (!EseBuildK6SearchStartFrame(keywordLower, req_id, body)) return;
        EnqueueSendMsg(req_id, TUN_OP_KAD6_GATEWAY, body.data(), body.size(),
                       ESE_CAP_KAD6);
        return;
    }
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

// === v8.1.1 F-1 — TRUE 2-hop relay forwarding of DATA cells ==================
// hop1 sits between V and the exit. It relays opaque onion cells in both
// directions, peeling/adding exactly ONE layer, so it learns V's IP but never
// the application payload, and the exit learns the payload but never V's IP (G1).
// CellPack always repads to CELL_TOTAL_BYTES, so the 512 B wire size is preserved
// after a layer is removed (the declared `length` shrinks by the 16 B AEAD tag).

// Forward (V -> hop1 -> exit): peel our V<->hop1 layer (advances nonce_recv) and
// relay the still-encrypted inner cell to hop2/exit on the outbound circ id.
bool CLiveTunnel::ForwardRelayCell_Forward(std::shared_ptr<CLiveCircuit>& circ,
                                           const uint8_t* payload, uint16_t payloadLen)
{
    if (!circ || circ->m_role != CircuitRole::Relay) return false;
    if (!circ->m_nextHopClient || circ->m_nextCircId == 0) return false;
    if (circ->HopCount() < 1) return false;

    uint8_t inner[CELL_PAYLOAD_MAX];
    size_t  innerLen = 0;
    // Peel exactly ONE layer (hop[0].k_recv = V->hop1). The inner bytes stay
    // encrypted for the exit; we never parse them. A bad/desynced cell -> drop.
    if (!circ->OnionPeelOne(0, payload, payloadLen, inner, innerLen))
        return false;

    uint8_t cell[CELL_TOTAL_BYTES];
    if (!CellPack(circ->m_nextCircId, CELL_RELAY, inner, innerLen, cell))
        return false;
    return SendCellToPeer(circ->m_nextHopClient, cell);
}

// Reverse (exit -> hop1 -> V): a data cell arrived from hop2/exit on our outbound
// id. Add our hop1->V layer back (hop[0].k_send) and relay to V on V's circ id.
bool CLiveTunnel::ForwardRelayCell_Reverse(std::shared_ptr<CLiveCircuit>& circ,
                                           const uint8_t* payload, uint16_t payloadLen)
{
    if (!circ || circ->m_role != CircuitRole::Relay || !circ->m_prevHopClient) return false;
    if (circ->HopCount() < 1) return false;

    uint8_t wrapped[CELL_PAYLOAD_MAX];
    size_t  wrappedLen = 0;
    // Add ONE layer (hop[0].k_send = hop1->V). V then peels hop1 (outer) then the
    // exit layer (inner) via OnionDecryptAll. payloadLen + 16 must fit a cell; the
    // forward path already bounds the plaintext so it does.
    if (!circ->EncryptOneLayer(0, payload, payloadLen, wrapped, wrappedLen))
        return false;
    if (wrappedLen > CELL_PAYLOAD_MAX) return false;

    uint8_t cell[CELL_TOTAL_BYTES];
    if (!CellPack(circ->Id(), CELL_RELAY, wrapped, wrappedLen, cell))
        return false;
    return SendCellToPeer(circ->m_prevHopClient, cell);
}

// === v8.1.2 Sprint E — bulk data plane carrier (OP_LIVE_BULK_CELL 0xD9) =======
// Same 2-hop topology as F-1 but for variable-length bulk cells with an EXPLICIT
// on-wire nonce (B2). Data flows exit -> hop1 -> V (push); NACK/feedback ride the
// 512 B control cells. Bulk buffers are up to ~17 KB so they live on the heap, not
// the 505 B stack cells.

static_assert(Bulk::BULK_DATA_HEADER_BYTES + Bulk::BULK_SYMBOL_BYTES
              == kad6::kK6ShapedInnerMax,
              "class-5 inner payload must fit one complete legacy bulk symbol");

bool CLiveTunnel::SendBulkCellToPeer(CUpDownClient* peer, const uint8_t* bytes, size_t size)
{
    if (!bytes || size < Bulk::BULK_CELL_HEADER_BYTES
        || size > kad6::kK6ShapedTotal || !EseCanQueueBulkCells(peer, 1))
        return false;
    Packet* pkt = new Packet(OP_LIVE_BULK_CELL, (uint32)size, OP_EMULEPROT);
    memcpy(pkt->pBuffer, bytes, size);
    // Bulk lives on CEMSocket's standard queue. Its scheduler always drains
    // the control queue first, so CREATE/EXTEND, K6 RPCs, NACKs and teardown
    // cannot be trapped behind class-5 payload. The queue is independently
    // bounded above to preserve backpressure.
    peer->socket->SendPacket(pkt, false, static_cast<uint32>(size), false);
    ++m_cellsSentTotal;
    m_bytesSentTotal += size;
    return true;
}

void CLiveTunnel::StopK6ShapeTimerLocked()
{
    if (m_k6ShapeTimer != 0) {
        ::KillTimer(NULL, m_k6ShapeTimer);
        m_k6ShapeTimer = 0;
    }
}

bool CLiveTunnel::EnsureK6ShaperLocked(const std::shared_ptr<CLiveCircuit>& circ,
                                       int outputLayers, uint32_t bucketKiB)
{
    if (!circ || circ->m_role != CircuitRole::Relay || circ->HopCount() != 1
        || outputLayers < 1 || outputLayers > 3
        || circ->m_remoteHopIndex > 2
        || bucketKiB != circ->m_shape_bucket_kib
        || !K6ShapeValidBucket(bucketKiB)
        || outputLayers != 3 - static_cast<int>(circ->m_remoteHopIndex))
        return false;

    auto existing = m_k6ShapeReverse.find(circ->Id());
    if (existing != m_k6ShapeReverse.end())
        return existing->second.output_layers == outputLayers
            && existing->second.bucket_kib == bucketKiB
            && existing->second.scheduler.configured();

    const kad6::Kad6CryptoHooks crypto = MakeKad6HostCryptoHooks();
    uint8_t random[19]{};
    if (!crypto.random_bytes || !crypto.random_bytes(random, sizeof random))
        return false;
    const uint32_t reservoirMs = kad6::kK6ShapeMinReservoirMs
        + eseRdU16LE(random) % (kad6::kK6ShapeMaxReservoirMs
                               - kad6::kK6ShapeMinReservoirMs + 1);
    uint64_t phase = eseRdU64LE(random + 2);
    uint64_t paddingSequence = eseRdU64LE(random + 10);

    static const char nonceRootLabel[] = "kad6-shape-nonce-root-v1";
    uint8_t nonceRootInfo[sizeof(nonceRootLabel) - 1 + 10]{};
    size_t nonceRootLen = 0;
    memcpy(nonceRootInfo + nonceRootLen, nonceRootLabel,
           sizeof(nonceRootLabel) - 1);
    nonceRootLen += sizeof(nonceRootLabel) - 1;
    PutU32LE(nonceRootInfo + nonceRootLen, circ->m_originCircContext);
    nonceRootLen += 4;
    PutU32LE(nonceRootInfo + nonceRootLen, circ->Id()); nonceRootLen += 4;
    nonceRootInfo[nonceRootLen++] = circ->m_remoteHopIndex;
    nonceRootInfo[nonceRootLen++] = 1; // reverse direction
    uint8_t nonceRoot[8]{};
    if (!Hkdf(circ->Hop(0).k_send, sizeof circ->Hop(0).k_send,
              NULL, 0, nonceRootInfo, nonceRootLen,
              nonceRoot, sizeof nonceRoot))
        return false;

    K6ShapedLinkState state;
    state.bucket_kib = bucketKiB;
    state.output_layers = outputLayers;
    state.nonce_epoch_high_base = eseRdU32LE(nonceRoot) & 0x7FFFFFFFu;
    if (state.nonce_epoch_high_base == 0) state.nonce_epoch_high_base = 1;
    state.padding_sequence = paddingSequence;
    state.idle_tail_epochs = static_cast<uint8_t>(1 + random[18] % 3);
    const uint64_t nowUs = K6ShapeNowUs();
    state.last_input_us = nowUs;
    if (state.scheduler.Configure(bucketKiB, reservoirMs, nowUs, phase)
        != kad6::Kad6Status::Ok)
        return false;
    m_k6ShapeReverse.emplace(circ->Id(), std::move(state));

    if (m_k6ShapeTimer == 0) {
        m_k6ShapeTimer = ::SetTimer(NULL, 0, 10, K6Class5TimerProc);
        if (m_k6ShapeTimer == 0) {
            m_k6ShapeReverse.erase(circ->Id());
            return false;
        }
    }
    AddDebugLogLine(false,
        _T("Kad6 K6-6: class-5 link active circ=0x%08x hop=%u bucket=%uKiB/s reservoir=%u records"),
        circ->Id(), static_cast<unsigned>(circ->m_remoteHopIndex), bucketKiB,
        static_cast<unsigned>(m_k6ShapeReverse[circ->Id()].scheduler.reservoir_capacity()));
    return true;
}

bool CLiveTunnel::QueueK6ShapedRecordLocked(const std::shared_ptr<CLiveCircuit>& circ,
                                            uint64_t streamId,
                                            K6ShapedQueuedRecord&& record)
{
    if (!circ || streamId == 0) return false;
    auto stateIt = m_k6ShapeReverse.find(circ->Id());
    if (stateIt == m_k6ShapeReverse.end()) return false;
    K6ShapedLinkState& state = stateIt->second;
    try {
        std::deque<K6ShapedQueuedRecord>& queue = state.records[streamId];
        queue.push_back(std::move(record));
        if (!state.scheduler.Enqueue(streamId)) {
            queue.pop_back();
            if (queue.empty()) state.records.erase(streamId);
            state.exposed = true;
            circ->m_traffic_shaping_exposed = true;
            return false;
        }
    } catch (...) {
        state.exposed = true;
        circ->m_traffic_shaping_exposed = true;
        return false;
    }
    state.last_input_us = K6ShapeNowUs();
    return true;
}

bool CLiveTunnel::EmitK6ShapedSlotLocked(const std::shared_ptr<CLiveCircuit>& circ,
                                         K6ShapedLinkState& state,
                                         const kad6::K6ShapeSlot& slot)
{
    if (!circ || !circ->m_prevHopClient || state.output_layers < 1
        || state.output_layers > 3)
        return false;
    const kad6::Kad6CryptoHooks crypto = MakeKad6HostCryptoHooks();
    K6ShapedQueuedRecord record;
    bool haveRecord = false;
    if (slot.kind == kad6::K6ShapeSlotKind::Data) {
        auto q = state.records.find(slot.stream_id);
        if (q == state.records.end() || q->second.empty()) {
            state.exposed = true;
            return false; // scheduler/record reservoir invariant broke
        }
        record = std::move(q->second.front());
        q->second.pop_front();
        if (q->second.empty()) state.records.erase(q);
        haveRecord = true;
    }

    std::vector<uint8_t> layerPlain;
    if (haveRecord) {
        if (record.terminal) {
            if (state.output_layers != 1
                || record.bytes.size() != kad6::kK6ShapedPlainSize)
                return false;
            layerPlain.resize(8 + record.bytes.size());
            eseWrU64LE(layerPlain.data(), 0); // terminal sentinel
            memcpy(layerPlain.data() + 8, record.bytes.data(), record.bytes.size());
        } else {
            const size_t expected = kad6::K6ShapedPrefixLen(state.output_layers - 1);
            if (state.output_layers <= 1 || record.incoming_nonce == 0
                || record.incoming_nonce == K6_SHAPE_PADDING_NONCE
                || record.bytes.size() != expected)
                return false;
            layerPlain.resize(8 + record.bytes.size());
            eseWrU64LE(layerPlain.data(), record.incoming_nonce);
            memcpy(layerPlain.data() + 8, record.bytes.data(), record.bytes.size());
        }
    } else if (state.output_layers == 1) {
        // Terminal padding uses the same authenticated plaintext codec as data.
        kad6::K6ShapedBulkPlainV1 padding;
        padding.kind = static_cast<uint8_t>(kad6::K6BulkKind::Padding);
        padding.stream_id = circ->Id();
        padding.logical_sequence = state.padding_sequence++;
        std::vector<uint8_t> encoded;
        if (kad6::EncodeK6ShapedPlain(padding, crypto, encoded)
            != kad6::Kad6Status::Ok)
            return false;
        layerPlain.resize(8 + encoded.size());
        eseWrU64LE(layerPlain.data(), 0);
        memcpy(layerPlain.data() + 8, encoded.data(), encoded.size());
    } else {
        // Hop-generated padding terminates at this authenticated layer. The
        // all-ones inner nonce is hidden by AEAD and can never be an outer
        // link nonce; the origin drops it without needing keys for fake hops.
        const size_t lower = kad6::K6ShapedPrefixLen(state.output_layers - 1);
        layerPlain.resize(8 + lower);
        eseWrU64LE(layerPlain.data(), K6_SHAPE_PADDING_NONCE);
        if (!crypto.random_bytes || !crypto.random_bytes(layerPlain.data() + 8, lower))
            return false;
    }

    if (!state.nonce_epoch_ready || state.nonce_epoch != slot.epoch) {
        static const char epochLabel[] = "kad6-shape-nonce-epoch-v1";
        uint8_t epochInfo[sizeof(epochLabel) - 1 + 18]{};
        size_t epochInfoLen = 0;
        memcpy(epochInfo + epochInfoLen, epochLabel, sizeof(epochLabel) - 1);
        epochInfoLen += sizeof(epochLabel) - 1;
        PutU32LE(epochInfo + epochInfoLen, circ->m_originCircContext);
        epochInfoLen += 4;
        PutU32LE(epochInfo + epochInfoLen, circ->Id()); epochInfoLen += 4;
        epochInfo[epochInfoLen++] = circ->m_remoteHopIndex;
        epochInfo[epochInfoLen++] = 1; // reverse direction
        eseWrU64LE(epochInfo + epochInfoLen, slot.epoch); epochInfoLen += 8;
        uint8_t epochMaterial[8]{};
        if (!Hkdf(circ->Hop(0).k_send, sizeof circ->Hop(0).k_send,
                  NULL, 0, epochInfo, epochInfoLen,
                  epochMaterial, sizeof epochMaterial))
            return false;
        const uint64_t epochHigh = static_cast<uint64_t>(state.nonce_epoch_high_base)
            + slot.epoch;
        if (epochHigh >= 0xFFFFFFFFull) return false;
        state.nonce_epoch = slot.epoch;
        state.nonce_epoch_low_base = eseRdU32LE(epochMaterial) & 0x00FFFFFFu;
        state.nonce_in_epoch = 0;
        state.nonce_epoch_ready = true;
    }
    if (state.nonce_in_epoch >= 0xFF000000u) return false;
    const uint64_t linkNonce =
        ((static_cast<uint64_t>(state.nonce_epoch_high_base) + state.nonce_epoch) << 32)
        | static_cast<uint64_t>(state.nonce_epoch_low_base + state.nonce_in_epoch++);
    if (linkNonce == 0 || linkNonce == K6_SHAPE_PADDING_NONCE)
        return false;

    std::vector<uint8_t> prefix(layerPlain.size() + 16);
    size_t prefixLen = 0;
    if (!circ->EncryptOneLayerExplicit(0, linkNonce, layerPlain.data(),
                                       layerPlain.size(), prefix.data(), prefixLen)
        || prefixLen != kad6::K6ShapedPrefixLen(state.output_layers))
        return false;
    prefix.resize(prefixLen);
    std::vector<uint8_t> carrier;
    if (kad6::BuildK6ShapedCarrier(prefix.data(), prefix.size(), state.output_layers,
                                   circ->Id(), linkNonce, crypto, carrier)
        != kad6::Kad6Status::Ok)
        return false;
    if (!SendBulkCellToPeer(circ->m_prevHopClient, carrier.data(), carrier.size())) {
        state.exposed = true; // sticky telemetry: a scheduled slot was missed
        circ->m_traffic_shaping_exposed = true;
        return false;
    }
    const uint64_t metricNow = static_cast<uint64_t>(time(NULL));
    const uint64_t useful = haveRecord
        ? static_cast<uint64_t>((std::min)(record.bytes.size(), carrier.size())) : 0;
    if (useful != 0)
        m_k6Metrics.Add(kad6::K6MetricFamily::TransportBytesTotal,
            0, 1, 0, useful, metricNow);
    m_k6Metrics.Add(kad6::K6MetricFamily::TransportBytesTotal,
        1, 1, 0, static_cast<uint64_t>(carrier.size()) - useful, metricNow);
    return true;
}

void CLiveTunnel::DeliverK6ShapedOriginLocked(
    const std::shared_ptr<CLiveCircuit>& circ, const uint8_t* pkt, size_t size)
{
    if (!circ || circ->m_role != CircuitRole::Originator || !circ->m_strict3
        || !circ->m_path_diverse || !circ->m_shaped_ok || circ->HopCount() != 3)
        return;
    kad6::K6ShapedHeader header;
    std::vector<uint8_t> current;
    if (kad6::ExtractK6ShapedPrefix(pkt, size, 3, current, &header)
        != kad6::Kad6Status::Ok
        || header.circ_id != circ->Id()
        || header.link_nonce_seq == K6_SHAPE_PADDING_NONCE)
        return;

    uint64_t linkNonce = header.link_nonce_seq;
    for (uint8_t hop = 0; hop < 3; ++hop) {
        // Each origin<->hop layer owns an independent nonce space. Checking
        // all three prevents a malicious upstream relay from replaying an
        // authenticated downstream prefix under a fresh outer nonce.
        if (linkNonce == 0 || linkNonce == K6_SHAPE_PADDING_NONCE
            || !m_k6ShapeReplay[K6ShapeReplayKey(circ->Id(), hop)].Check(linkNonce))
            return;
        if (current.size() < 16) return;
        std::vector<uint8_t> opened(current.size() - 16);
        size_t openedLen = 0;
        if (!circ->OnionPeelOneExplicit(hop, linkNonce, current.data(),
                                        current.size(), opened.data(), openedLen)
            || openedLen != opened.size() || openedLen < 8)
            return;
        const uint64_t nextNonce = eseRdU64LE(opened.data());
        if (nextNonce == K6_SHAPE_PADDING_NONCE)
            return; // authenticated padding generated by this hop
        if (hop < 2) {
            const size_t expected = kad6::K6ShapedPrefixLen(2 - hop);
            if (nextNonce == 0 || openedLen != 8 + expected)
                return;
            current.assign(opened.begin() + 8, opened.end());
            linkNonce = nextNonce;
            continue;
        }
        if (nextNonce != 0 || openedLen != 8 + kad6::kK6ShapedPlainSize)
            return;
        kad6::K6ShapedBulkPlainV1 plain;
        if (kad6::DecodeK6ShapedPlain(opened.data() + 8,
                                      kad6::kK6ShapedPlainSize, plain)
            != kad6::Kad6Status::Ok)
            return;
        if (plain.kind == static_cast<uint8_t>(kad6::K6BulkKind::Padding))
            return;
        if (plain.kind != static_cast<uint8_t>(kad6::K6BulkKind::Data)
            || plain.inner.size() != Bulk::BULK_DATA_HEADER_BYTES
                                      + Bulk::BULK_SYMBOL_BYTES)
            return;
        DeliverBulkPlain(plain.inner.data(), plain.inner.size());
        return;
    }
}

bool CLiveTunnel::HandleK6ShapedCellLocked(const uint8_t* pkt, size_t size,
                                           CUpDownClient* fromPeer)
{
    kad6::K6ShapedHeader header;
    if (kad6::PeekK6ShapedHeader(pkt, size, header) != kad6::Kad6Status::Ok
        || header.link_nonce_seq == K6_SHAPE_PADDING_NONCE)
        return true;

    std::shared_ptr<CLiveCircuit> relay = FindRelayByOutgoingId(header.circ_id);
    if (relay) {
        if (fromPeer != relay->m_nextHopClient || relay->m_remoteHopIndex >= 2
            || relay->m_originCircContext == 0 || relay->HopCount() != 1)
            return true;
        const int incomingLayers = 2 - static_cast<int>(relay->m_remoteHopIndex);
        std::vector<uint8_t> prefix;
        if (kad6::ExtractK6ShapedPrefix(pkt, size, incomingLayers, prefix)
            != kad6::Kad6Status::Ok
            || !m_k6ShapeReplay[K6ShapeReplayKey(
                    relay->Id(), static_cast<uint8_t>(0x80u + relay->m_remoteHopIndex))]
                    .Check(header.link_nonce_seq)
            || !EnsureK6ShaperLocked(relay, incomingLayers + 1,
                                     relay->m_shape_bucket_kib))
            return true;
        K6ShapedQueuedRecord record;
        record.incoming_nonce = header.link_nonce_seq;
        record.bytes = std::move(prefix);
        if (!QueueK6ShapedRecordLocked(relay, relay->Id(), std::move(record))) {
            AddDebugLogLine(false,
                _T("Kad6 K6-6: class-5 reservoir overflow circ=0x%08x -- fail closed"),
                relay->Id());
            DestroyCircuitFailClosed(relay);
        }
        return true;
    }

    for (auto& candidate : m_circuits) {
        if (candidate->Id() == header.circ_id
            && candidate->m_role == CircuitRole::Originator) {
            if (fromPeer == candidate->m_firstHopClient)
                DeliverK6ShapedOriginLocked(candidate, pkt, size);
            return true;
        }
    }
    return true;
}

void CLiveTunnel::ProcessClass5Tick()
{
    const bool fairActive = ProcessK6FairTick();
    CSingleLock lock(&m_lock, TRUE);
    if (m_k6ShapeReverse.empty()) {
        if (!fairActive) StopK6ShapeTimerLocked();
        return;
    }
    const uint64_t nowUs = K6ShapeNowUs();
    for (auto it = m_k6ShapeReverse.begin(); it != m_k6ShapeReverse.end(); ) {
        std::shared_ptr<CLiveCircuit> circ;
        for (auto& candidate : m_circuits)
            if (candidate->Id() == it->first) { circ = candidate; break; }
        if (!circ || circ->State() == CircuitState::Destroyed
            || circ->m_role != CircuitRole::Relay) {
            const uint32_t deadId = it->first;
            for (auto replay = m_k6ShapeReplay.begin(); replay != m_k6ShapeReplay.end(); )
                if (static_cast<uint32_t>(replay->first >> 8) == deadId)
                    replay = m_k6ShapeReplay.erase(replay);
                else
                    ++replay;
            it = m_k6ShapeReverse.erase(it);
            continue;
        }
        const uint64_t idleTailUs = static_cast<uint64_t>(it->second.idle_tail_epochs)
            * kad6::kK6ShapeEpochUs;
        if (it->second.scheduler.queued_records() == 0
            && nowUs - it->second.last_input_us >= idleTailUs) {
            AddDebugLogLine(false,
                _T("Kad6 K6-6: class-5 idle tail complete circ=0x%08x (%u epoch(s))"),
                circ->Id(), static_cast<unsigned>(it->second.idle_tail_epochs));
            it = m_k6ShapeReverse.erase(it);
            continue;
        }
        std::vector<kad6::K6ShapeSlot> slots;
        it->second.scheduler.Poll(nowUs, 8, slots);
        if (it->second.scheduler.exposed())
            it->second.exposed = circ->m_traffic_shaping_exposed = true;
        for (const kad6::K6ShapeSlot& slot : slots)
            if (!EmitK6ShapedSlotLocked(circ, it->second, slot))
                it->second.exposed = circ->m_traffic_shaping_exposed = true;
        ++it;
    }
    if (m_k6ShapeReverse.empty() && !fairActive) StopK6ShapeTimerLocked();
}

bool CLiveTunnel::OnBulkCellReceived(const uint8_t* pkt, uint32_t size, CUpDownClient* fromPeer)
{
    CSingleLock lock(&m_lock, TRUE);
    ++m_cellsRecvTotal;
    m_bytesRecvTotal += size;

    if (size == kad6::kK6ShapedTotal)
        return HandleK6ShapedCellLocked(pkt, size, fromPeer);

    Bulk::BulkCellHeader h;
    const uint8_t* payload = NULL;
    if (!Bulk::BulkCellParse(pkt, size, h, payload))
        return true;   // malformed -> consume + drop

    // Reverse forwarding: a bulk cell on a relay's OUTBOUND id is coming back from
    // hop2/exit -> re-add our hop1->V layer and relay to V (mirror of CELL_RELAY F-1).
    {
        auto relayCirc = FindRelayByOutgoingId(h.circ_id);
        if (relayCirc) {
            if (fromPeer != relayCirc->m_nextHopClient) return true;
            ForwardBulkCell_Reverse(relayCirc, h.bcmd, h.nonce_seq, payload, h.length);
            return true;
        }
    }

    // Terminating end (viewer/originator): decode + reassemble.
    std::shared_ptr<CLiveCircuit> circ;
    for (auto& c : m_circuits)
        if (c->Id() == h.circ_id) { circ = c; break; }
    if (!circ) return true;
    if (circ->m_role == CircuitRole::Originator
        && fromPeer == circ->m_firstHopClient)
        DeliverBulkData(circ, h.nonce_seq, payload, h.length);
    return true;
}

bool CLiveTunnel::ForwardBulkCell_Reverse(std::shared_ptr<CLiveCircuit>& circ, uint8_t bcmd,
                                          uint64_t nonce_seq, const uint8_t* payload, size_t payloadLen)
{
    if (!circ || circ->m_role != CircuitRole::Relay || !circ->m_prevHopClient) return false;
    if (circ->HopCount() < 1) return false;

    std::vector<uint8_t> wrapped(payloadLen + 16);
    size_t wrappedLen = 0;
    if (!circ->EncryptOneLayerExplicit(0, nonce_seq, payload, payloadLen, wrapped.data(), wrappedLen))
        return false;

    Bulk::BulkCellHeader h;
    h.circ_id   = circ->Id();
    h.bcmd      = bcmd;
    h.nonce_seq = nonce_seq;
    std::vector<uint8_t> cell;
    Bulk::BulkCellPack(h, wrapped.data(), wrappedLen, cell);
    return SendBulkCellToPeer(circ->m_prevHopClient, cell.data(), cell.size());
}

bool CLiveTunnel::SendBulkCellReverse(std::shared_ptr<CLiveCircuit>& circ, uint8_t bcmd,
                                      const uint8_t* plain, size_t plainLen)
{
    if (!circ || circ->m_role != CircuitRole::Relay || !circ->m_prevHopClient) return false;
    if (circ->HopCount() < 1) return false;

    // Idle class-5 links retire after a randomized tail. A new terminal
    // record reactivates the already signed bucket reservation; it must never
    // fall through to legacy variable-length bulk.
    if (circ->m_shape_bucket_kib != 0 && circ->m_remoteHopIndex == 2
        && !EnsureK6ShaperLocked(circ, 1, circ->m_shape_bucket_kib))
        return false;

    // A shaped subscription turns arrival-triggered writes into bounded
    // reservoir inserts. The 10 ms class-5 heartbeat alone decides when a
    // data or padding record leaves this mapping.
    if (m_k6ShapeReverse.find(circ->Id()) != m_k6ShapeReverse.end()) {
        if (bcmd != Bulk::BULK_DATA || !plain
            || plainLen > kad6::kK6ShapedInnerMax)
            return false;
        kad6::K6ShapedBulkPlainV1 shaped;
        shaped.kind = static_cast<uint8_t>(kad6::K6BulkKind::Data);
        if (plainLen >= 16) {
            shaped.stream_id = eseRdU64LE(plain) ^ eseRdU64LE(plain + 8);
            if (shaped.stream_id == 0) shaped.stream_id = 1;
        } else {
            shaped.stream_id = circ->Id();
        }
        if (plainLen >= 20) shaped.logical_sequence = eseRdU32LE(plain + 16);
        shaped.inner.assign(plain, plain + plainLen);
        K6ShapedQueuedRecord record;
        record.terminal = true;
        if (kad6::EncodeK6ShapedPlain(shaped, MakeKad6HostCryptoHooks(), record.bytes)
            != kad6::Kad6Status::Ok)
            return false;
        return QueueK6ShapedRecordLocked(circ, shaped.stream_id, std::move(record));
    }

    if (circ->m_bulk_nonce_send == 0) {
        uint8_t random[8];
        SecureRandomBytes(random, sizeof random);
        circ->m_bulk_nonce_send = eseRdU64LE(random);
        if (circ->m_bulk_nonce_send == 0) circ->m_bulk_nonce_send = 1;
    }
    const uint64_t nonce_seq = circ->m_bulk_nonce_send++;   // strictly increasing per (circ, dir)
    std::vector<uint8_t> wrapped(plainLen + 16);
    size_t wrappedLen = 0;
    if (!circ->EncryptOneLayerExplicit(0, nonce_seq, plain, plainLen, wrapped.data(), wrappedLen))
        return false;

    Bulk::BulkCellHeader h;
    h.circ_id   = circ->Id();
    h.bcmd      = bcmd;
    h.nonce_seq = nonce_seq;
    std::vector<uint8_t> cell;
    Bulk::BulkCellPack(h, wrapped.data(), wrappedLen, cell);
    return SendBulkCellToPeer(circ->m_prevHopClient, cell.data(), cell.size());
}

void CLiveTunnel::DeliverBulkData(std::shared_ptr<CLiveCircuit>& circ, uint64_t nonce_seq,
                                  const uint8_t* payload, size_t payloadLen)
{
    if (!circ) return;
    // Replay guard (per terminating circuit, recv direction) — out-of-order accepted.
    if (!m_bulkReplay[circ->Id()].Check(nonce_seq)) return;

    std::vector<uint8_t> plain(payloadLen ? payloadLen : 1);
    size_t plainLen = 0;
    if (!circ->OnionDecryptAllExplicit(nonce_seq, payload, payloadLen,
                                       plain.data(), plain.size(), plainLen))
        return;   // AEAD auth fail / bad cell -> drop

    DeliverBulkPlain(plain.data(), plainLen);
}

void CLiveTunnel::DeliverBulkPlain(const uint8_t* plain, size_t plainLen)
{
    if (!plain) return;
    Bulk::BulkDataHeader bh;
    const uint8_t* symbol = NULL;
    if (!Bulk::BulkDataParse(plain, plainLen, bh, symbol)) return;
    if (bh.msg_len == 0 || bh.n_blocks == 0) return;

    const std::string key = BulkReasmKey(bh.stream_key, bh.seq);
    BulkReasmEntry& e = m_bulkReasm[key];
    if (e.done) return;   // segment already rebuilt

    if (!e.haveLayout) {
        if (!Bulk::BulkComputeLayout(bh.msg_len, e.layout)) { m_bulkReasm.erase(key); return; }
        memcpy(e.streamKey, bh.stream_key, 16);   // E3.5 NACK addressing
        e.seq = bh.seq;
        e.msg_len = bh.msg_len;
        e.n_blocks = bh.n_blocks;
        e.r = bh.r;
        e.first_seen_tick = GetTickCount();
        e.blockRecv.assign(e.layout.n_blocks, 0);
        e.haveLayout = true;
    }
    if (bh.block_idx >= e.layout.n_blocks) return;   // foreign block index

    // dedup by (block_idx, symbol_idx)
    for (const auto& s : e.symbols)
        if (s.block_idx == bh.block_idx && s.symbol_idx == bh.symbol_idx) return;

    Bulk::BulkSymbol bs;
    bs.block_idx  = bh.block_idx;
    bs.symbol_idx = bh.symbol_idx;
    bs.k          = bh.k;
    bs.data.assign(symbol, symbol + Bulk::BULK_SYMBOL_BYTES);
    e.symbols.push_back(std::move(bs));
    e.blockRecv[bh.block_idx]++;

    // Decode only once EVERY block has >= k_b symbols (bounds the 3 MB decode buffer).
    for (int b = 0; b < e.layout.n_blocks; ++b)
        if (e.blockRecv[b] < e.layout.k[b]) return;

    std::vector<uint8_t> record;
    if (Bulk::BulkDecodeSegment(e.symbols, e.msg_len, e.r, record)) {
        e.done = true;
        e.symbols.clear();              // free ~3 MB; keep the entry as a 'done' marker
        e.blockRecv.clear();
        AddDebugLogLine(false,
            _T("LiveTunnel: bulk segment rebuilt seq=%u (%u bytes, %u blocks) via FEC — injecting"),
            bh.seq, (unsigned)record.size(), (unsigned)e.n_blocks);
        // E3.4-final — hand the byte-identical signed CHUNK_V2 record to the EXISTING viewer
        // verify+inject path. IngestChunkPayload runs the SAME sha256 + Ed25519 verify the
        // direct path uses (against the pinned pubkey, LiveStreamManager.cpp:1609+) and, on
        // the viewer (m_bViewing), buffers + writes HLS so VLC plays it. NULL peer = no
        // per-peer credit (bulk arrives STRIPED across multi-hop circuits, not from one
        // CUpDownClient); PeerId(NULL)/GetOrCreateTrust(NULL) are null-safe (the one peer->
        // deref past the gate is already guarded). Backward-compat: only viewers that
        // negotiated bulk circuits ever reach here.
        if (theApp.liveStreamManager && theApp.liveStreamManager->IsViewingLive())
            theApp.liveStreamManager->IngestChunkPayload(NULL, OP_LIVE_CHUNK_V2,
                                                         record.data(), (uint32)record.size());
    }
}

std::string CLiveTunnel::BulkReasmKey(const uint8_t streamKey[16], uint32_t seq)
{
    std::string s = LiveStreamKeyHex(streamKey);
    char tail[16];
    _snprintf_s(tail, sizeof tail, _TRUNCATE, ":%u", seq);
    return s + tail;
}

void CLiveTunnel::SweepBulkReasm()
{
    // A5 pattern: drop partial/done segments past the ring window, and replay windows
    // for circuits that no longer exist. Caller holds m_lock (called from Tick()).
    const DWORD now = GetTickCount();
    const DWORD BULK_REASM_TTL_MS = 40000;   // > 16 segments x 2 s ring (32 s) + slack
    for (auto it = m_bulkReasm.begin(); it != m_bulkReasm.end(); ) {
        BulkReasmEntry& e = it->second;
        if (now - e.first_seen_tick > BULK_REASM_TTL_MS) { it = m_bulkReasm.erase(it); continue; }
        // E3.5 (viewer) — still incomplete past the NACK deadline -> request a re-push of the
        // blocks short of k_b (throttled per entry). The exit re-encodes from its retained record.
        if (!e.done && e.haveLayout
            && (DWORD)(now - e.first_seen_tick) > 3000
            && (DWORD)(now - e.lastNackTick) > 2000) {
            std::vector<std::pair<uint32_t, uint8_t>> missing;
            for (int b = 0; b < e.layout.n_blocks && missing.size() < 16; ++b)
                if (b < (int)e.blockRecv.size() && e.blockRecv[b] < e.layout.k[b])
                    missing.push_back(std::make_pair(e.seq, (uint8_t)b));
            if (!missing.empty() && SendBulkNack(e.streamKey, missing))
                e.lastNackTick = now;
        }
        ++it;
    }
    // E3.5 — sweep retained exit records past the ring window (oldest at the front).
    while (!m_proxyRecent.empty() && now - m_proxyRecent.front().tick > BULK_REASM_TTL_MS)
        m_proxyRecent.pop_front();
    for (auto it = m_bulkReplay.begin(); it != m_bulkReplay.end(); ) {
        bool alive = false;
        for (auto& c : m_circuits) if (c->Id() == it->first) { alive = true; break; }
        if (!alive) it = m_bulkReplay.erase(it); else ++it;
    }
    for (auto it = m_k6ShapeReplay.begin(); it != m_k6ShapeReplay.end(); ) {
        bool alive = false;
        for (auto& c : m_circuits)
            if (c->Id() == static_cast<uint32_t>(it->first >> 8)
                && c->State() != CircuitState::Destroyed) {
                alive = true; break;
            }
        if (!alive) it = m_k6ShapeReplay.erase(it); else ++it;
    }

    // v8.1.2 E3.2 — sweep explicit bulk subs: drop those whose circuit died or that went
    // silent past the TTL (the viewer re-subscribes on each refresh; the exit dedups by circ_id).
    {
        CSingleLock pl(&m_pendingLock, TRUE);
        for (auto it = m_bulkSubs.begin(); it != m_bulkSubs.end(); ) {
            std::vector<BulkSub>& subs = it->second;
            for (auto i = subs.begin(); i != subs.end(); ) {
                bool alive = false;
                for (auto& c : m_circuits) if (c->Id() == i->circ_id) { alive = true; break; }
                if (!alive || (DWORD)(now - i->lastSeen) > Bulk::BULK_SUB_TTL_MS) i = subs.erase(i);
                else ++i;
            }
            if (subs.empty()) it = m_bulkSubs.erase(it); else ++it;
        }
    }
}

// === v8.1.2 E3.1/E3.3 — exit headless ingest -> FEC encode -> stripe push =====
// The chunk hooks below run UNDER the manager lock and only touch the leaf-locked
// m_proxy* state (never m_lock/m_pendingLock), so the tunnel->manager lock order is
// never inverted. The heavy work runs in ProcessProxyIngest() from Tick() under m_lock.

bool CLiveTunnel::IsExitProxying(const uint8_t streamKey[16]) const
{
    const std::string hex = LiveStreamKeyHex(streamKey);
    CSingleLock lk(&m_proxyIngestLock, TRUE);   // leaf
    return m_proxyKeys.find(hex) != m_proxyKeys.end();
}

void CLiveTunnel::ExitProxyOnWholeChunk(const uint8_t streamKey[16],
                                        const uint8_t* record, uint32_t recordLen)
{
    (void)streamKey;
    if (!record || recordLen < 20 || recordLen > ESE_FRAG_MAX_TOTAL) return;
    CSingleLock lk(&m_proxyIngestLock, TRUE);   // leaf
    m_proxyReady.emplace_back(record, record + recordLen);
    while (m_proxyReady.size() > 64) m_proxyReady.pop_front();   // bound (DoS)
}

void CLiveTunnel::ExitProxyOnFragment(const uint8_t streamKey[16], uint32_t seqNum,
                                      uint16_t fragIndex, uint16_t fragCount, uint32_t totalLen,
                                      const uint8_t* fragData, uint32_t fragLen)
{
    // Validate (mirror of the viewer's checks — this runs BEFORE them).
    if (fragCount < 1 || fragCount > ESE_FRAG_MAX_COUNT) return;
    if (fragIndex >= fragCount) return;
    if (totalLen == 0 || totalLen > ESE_FRAG_MAX_TOTAL) return;
    if (!fragData) return;
    const uint32_t off = (uint32_t)fragIndex * ESE_FRAG_PAYLOAD;
    if (fragLen > ESE_FRAG_PAYLOAD || off > totalLen || off + fragLen > totalLen) return;

    char tail[16];
    _snprintf_s(tail, sizeof tail, _TRUNCATE, ":%u", seqNum);
    const std::string key = LiveStreamKeyHex(streamKey) + tail;

    CSingleLock lk(&m_proxyIngestLock, TRUE);   // leaf
    auto it = m_proxyFragReasm.find(key);
    if (it == m_proxyFragReasm.end()) {
        if ((int)m_proxyFragReasm.size() >= ESE_FRAG_MAX_CONCURRENT) {   // evict oldest
            auto oldest = m_proxyFragReasm.begin();
            for (auto i = m_proxyFragReasm.begin(); i != m_proxyFragReasm.end(); ++i)
                if ((LONG)(i->second.firstTick - oldest->second.firstTick) < 0) oldest = i;
            m_proxyFragReasm.erase(oldest);
        }
        ProxyFrag nf;
        nf.totalLen = totalLen; nf.fragCount = fragCount; nf.haveCount = 0;
        nf.firstTick = GetTickCount();
        nf.buf.resize(totalLen);
        nf.got.assign(fragCount, false);
        it = m_proxyFragReasm.emplace(key, std::move(nf)).first;
    } else if (it->second.totalLen != totalLen || it->second.fragCount != fragCount) {
        ProxyFrag& f2 = it->second;                                     // VBR restart -> reset
        f2.totalLen = totalLen; f2.fragCount = fragCount; f2.haveCount = 0;
        f2.firstTick = GetTickCount();
        f2.buf.assign(totalLen, 0);
        f2.got.assign(fragCount, false);
    }
    ProxyFrag& fr = it->second;
    if (fragIndex < fr.got.size() && fr.got[fragIndex]) return;          // dup fragment
    memcpy(fr.buf.data() + off, fragData, fragLen);
    if (fragIndex < fr.got.size()) fr.got[fragIndex] = true;
    fr.haveCount++;
    if (fr.haveCount == fr.fragCount) {                                  // complete record
        m_proxyReady.push_back(std::move(fr.buf));
        m_proxyFragReasm.erase(it);
        while (m_proxyReady.size() > 64) m_proxyReady.pop_front();
    }
}

void CLiveTunnel::RefreshProxyKeys()
{
    // Rebuild the leaf-locked mirror of which streams we exit-proxy. Called from Tick()
    // (m_lock held); m_pendingLock guards m_exitLiveSubs. Order: m_lock -> m_pendingLock
    // -> m_proxyIngestLock (leaf), consistent with the rest of the tunnel.
    std::set<std::string> keys;
    {
        CSingleLock pl(&m_pendingLock, TRUE);
        for (const auto& kv : m_exitLiveSubs)
            if (!kv.second.circuits.empty()) keys.insert(kv.first);
        for (const auto& kv : m_bulkSubs)       // E3.2 — also proxy streams with explicit bulk subs
            if (!kv.second.empty()) keys.insert(kv.first);
    }
    CSingleLock lk(&m_proxyIngestLock, TRUE);
    m_proxyKeys.swap(keys);
}

void CLiveTunnel::ProcessProxyIngest()
{
    // MAIN THREAD, from Tick() under m_lock. Refresh the proxy-key mirror, drain ready
    // records, FEC-encode each and push its symbols across the stream's subscribed circuits.
    RefreshProxyKeys();

    std::deque<std::vector<uint8_t>> ready;
    {
        CSingleLock lk(&m_proxyIngestLock, TRUE);   // leaf
        if (m_proxyReady.empty()) return;
        ready.swap(m_proxyReady);
    }

    for (std::vector<uint8_t>& record : ready) {
        if (record.size() < 20) continue;
        uint8_t streamKey[16];
        memcpy(streamKey, record.data(), 16);
        const uint32_t seq = eseRdU32LE(record.data() + 16);
        const std::string hex = LiveStreamKeyHex(streamKey);
        const int r = ProxyAdaptiveR(hex);   // E4' — parity adapts to the measured NACK rate

        std::vector<Bulk::BulkSymbol> symbols;
        if (!Bulk::BulkEncodeSegment(record.data(), record.size(), r, symbols))
            continue;
        Bulk::BulkLayout layout;
        if (!Bulk::BulkComputeLayout((uint32_t)record.size(), layout)) continue;

        // Build the push "sessions" — each is one viewer's circuit list. Prefer EXPLICIT bulk
        // subs (E3.2, grouped by session_id -> we can stripe across a viewer's circuits); fall
        // back to the C7 control subs (1 circuit each -> full k+r). Snapshot under m_pendingLock.
        std::vector<std::vector<uint32_t>> sessions;
        {
            CSingleLock pl(&m_pendingLock, TRUE);
            auto bit = m_bulkSubs.find(hex);
            if (bit != m_bulkSubs.end() && !bit->second.empty()) {
                std::map<uint32_t, std::vector<uint32_t>> bySession;
                for (const BulkSub& s : bit->second) bySession[s.session_id].push_back(s.circ_id);
                for (auto& kv : bySession) sessions.push_back(std::move(kv.second));
            } else {
                auto eit = m_exitLiveSubs.find(hex);
                if (eit != m_exitLiveSubs.end())
                    for (const auto& c : eit->second.circuits)
                        sessions.push_back(std::vector<uint32_t>(1, c.first));
            }
        }
        if (sessions.empty()) continue;

        // For each viewer (session), STRIPE the segment's symbols INTERLEAVED across its
        // circuits (B5): symbol with (block_idx b, symbol_idx s) -> circuit[(s + b) mod C], so
        // no circuit holds a whole block and a circuit death loses <= ceil((k+r)/C)/block. With
        // C==1 (fallback / single-circuit viewer) the whole k+r goes down the one circuit.
        // m_lock is held by Tick -> m_circuits is safe to read.
        size_t pushed = 0;
        for (const std::vector<uint32_t>& sess : sessions) {
            const size_t C = sess.size();
            if (C == 0) continue;
            std::vector<std::shared_ptr<CLiveCircuit>> sc(C);
            for (size_t i = 0; i < C; ++i)
                for (auto& c : m_circuits) if (c->Id() == sess[i]) { sc[i] = c; break; }
            for (const Bulk::BulkSymbol& s : symbols) {
                std::shared_ptr<CLiveCircuit>& cc = sc[((size_t)s.symbol_idx + s.block_idx) % C];
                if (!cc || cc->m_role != CircuitRole::Relay) continue;
                // v8.1.2 E7.2 (backpressure) — don't pile cells onto a hop socket that is
                // already backed up (slow viewer/circuit). Skipping bounds the exit's send-
                // queue RAM; the viewer recovers the skipped symbol via FEC parity or a NACK
                // (E3.5). For a multi-circuit viewer the other circuits still carry their stripe.
                if (cc->m_prevHopClient && cc->m_prevHopClient->socket
                    && cc->m_prevHopClient->socket->IsBusyQuickCheck()) continue;
                Bulk::BulkDataHeader bh;
                memcpy(bh.stream_key, streamKey, 16);
                bh.seq = seq; bh.block_idx = s.block_idx; bh.n_blocks = (uint8_t)layout.n_blocks;
                bh.symbol_idx = s.symbol_idx; bh.k = s.k; bh.r = (uint8_t)r;
                bh.flags = 0; bh.msg_len = (uint32_t)record.size();
                std::vector<uint8_t> payload;
                Bulk::BulkDataPack(bh, s.data.data(), payload);
                SendBulkCellReverse(cc, Bulk::BULK_DATA, payload.data(), payload.size());
                ++pushed;
            }
        }
        if (pushed)
            AddDebugLogLine(false,
                _T("LiveTunnel: exit pushed bulk seq=%u — %u symbols across %u viewer-session(s), %u blocks (r=%d)"),
                seq, (unsigned)symbols.size(), (unsigned)sessions.size(), (unsigned)layout.n_blocks, r);

        // E3.5 — retain the whole record so a viewer that fails to reassemble can NACK a
        // re-push (PushBlockToCircuit re-encodes on demand). Bounded ring (~16 segs x streams).
        ProxyRecentRec rec;
        memcpy(rec.streamKey, streamKey, 16);
        rec.seq = seq; rec.tick = GetTickCount(); rec.record = std::move(record);
        m_proxyRecent.push_back(std::move(rec));
        while (m_proxyRecent.size() > 48) m_proxyRecent.pop_front();
    }
}

// === v8.1.2 E3.2 — explicit bulk subscribe (exit handlers + viewer sender) =====

void CLiveTunnel::ExitHandle_BulkSubscribe(const TunnelRequestCtx& ctx)
{
    // body v1: stream_key 16 + flags 1 + r_pref 1 + session_id 4
    // body v2: v1 + class5_bucket_kib u16. Unknown/invalid shaped requests
    // fail closed; they are never silently registered as unshaped bulk.
    if (!ctx.circ || !ctx.body || ctx.bodyLen < 22) return;
    uint8_t streamKey[16];
    memcpy(streamKey, ctx.body, 16);
    const uint8_t  r_pref    = ctx.body[17];
    const uint32_t sessionId = eseRdU32LE(ctx.body + 18);
    const bool shaped = (ctx.body[16] & K6_BULK_SUB_FLAG_SHAPED) != 0;
    const uint16_t shapeBucket = (shaped && ctx.bodyLen >= 24)
        ? eseRdU16LE(ctx.body + 22) : 0;
    if (shaped && (ctx.bodyLen < 24
        || !EnsureK6ShaperLocked(ctx.circ, 1, shapeBucket))) {
        AddDebugLogLine(false,
            _T("Kad6 K6-6: rejected malformed/unavailable class-5 subscription circ=0x%08x"),
            ctx.circ->Id());
        return;
    }
    const std::string hex = LiveStreamKeyHex(streamKey);
    const uint32_t cid = ctx.circ->Id();
    const DWORD now = GetTickCount();

    CSingleLock pl(&m_pendingLock, TRUE);
    std::vector<BulkSub>& subs = m_bulkSubs[hex];
    bool found = false;
    for (BulkSub& s : subs)
        if (s.circ_id == cid) {
            s.session_id = sessionId; s.r_pref = r_pref; s.shaped = shaped;
            s.shape_bucket_kib = shapeBucket; s.lastSeen = now;
            found = true; break;
        }
    if (!found) {
        if (subs.size() < 32) {                  // per-stream sub cap (DoS)
            BulkSub s; s.circ_id = cid; s.session_id = sessionId;
            s.r_pref = r_pref; s.shaped = shaped;
            s.shape_bucket_kib = shapeBucket; s.lastSeen = now;
            subs.push_back(s);
        }
    }
    AddDebugLogLine(false, _T("LiveTunnel: [E3.2] bulk SUBSCRIBE circ=0x%08x session=0x%08x r=%u (%u sub(s))"),
        cid, sessionId, (unsigned)r_pref, (unsigned)subs.size());
}

void CLiveTunnel::ExitHandle_BulkUnsub(const TunnelRequestCtx& ctx)
{
    if (!ctx.circ || !ctx.body || ctx.bodyLen < 16) return;
    uint8_t streamKey[16];
    memcpy(streamKey, ctx.body, 16);
    const std::string hex = LiveStreamKeyHex(streamKey);
    const uint32_t cid = ctx.circ->Id();
    CSingleLock pl(&m_pendingLock, TRUE);
    auto it = m_bulkSubs.find(hex);
    if (it == m_bulkSubs.end()) return;
    std::vector<BulkSub>& subs = it->second;
    for (auto i = subs.begin(); i != subs.end(); )
        if (i->circ_id == cid) i = subs.erase(i); else ++i;
    if (subs.empty()) m_bulkSubs.erase(it);
}

size_t CLiveTunnel::BulkSubscribe(const uint8_t streamKey[16])
{
    CSingleLock lock(&m_lock, TRUE);
    // One fresh session_id groups ALL of this viewer's bulk circuits so the exit stripes
    // a segment's symbols across them (E3.2). Strict three-hop circuits add
    // the class-5 flag + bucket and refuse any unshaped downgrade.
    const uint32_t sessionId = NewCircuitId();

    size_t sent = 0;
    for (auto& c : m_circuits) {
        if (c->m_role != CircuitRole::Originator) continue;
        if (c->State() != CircuitState::Active) continue;
        if (c->HopCount() < 1 || !c->m_bulk_ok) continue;   // only bulk-capable Active circuits
        const bool shaped = c->m_strict3 && c->m_path_diverse
            && c->m_shaped_ok && K6ShapeValidBucket(c->m_shape_bucket_kib)
            && c->HopCount() == 3;
        if (c->m_strict3 && !shaped) continue;
        uint8_t body[24]{};
        memcpy(body, streamKey, 16);
        body[16] = shaped ? K6_BULK_SUB_FLAG_SHAPED : 0;
        body[17] = (uint8_t)Bulk::BULK_DEFAULT_R;
        eseWrU32LE(body + 18, sessionId);
        if (shaped) eseWrU16LE(body + 22, c->m_shape_bucket_kib);
        const size_t bodyLen = shaped ? sizeof body : 22;
        const size_t onion = c->HopCount() * 16;
        if (onion + SUB_HEADER_BYTES + FRAG_HEADER_BYTES >= CELL_PAYLOAD_MAX) continue;
        const size_t fragDataMax = CELL_PAYLOAD_MAX - onion - SUB_HEADER_BYTES - FRAG_HEADER_BYTES;
        std::vector<std::vector<uint8_t>> cells;
        if (!SplitIntoCells(TUN_OP_BULK_SUBSCRIBE, NewCircuitId(), body, bodyLen, fragDataMax, cells))
            continue;
        bool ok = true;
        for (auto& plain : cells) {
            uint8_t cellPayload[CELL_PAYLOAD_MAX];
            size_t cellLen = 0;
            if (!c->OnionEncrypt(plain.data(), plain.size(), cellPayload, cellLen)) { ok = false; break; }
            uint8_t cell[CELL_TOTAL_BYTES];
            if (!CellPack(c->Id(), CELL_RELAY, cellPayload, cellLen, cell)) { ok = false; break; }
            if (!c->m_firstHopClient || !SendCellToPeer(c->m_firstHopClient, cell)) { ok = false; break; }
        }
        if (ok) ++sent;
    }
    if (sent)
        AddDebugLogLine(false, _T("LiveTunnel: [E3.2] viewer bulk-subscribed on %u circuit(s), session=0x%08x"),
            (unsigned)sent, sessionId);
    return sent;
}

// === v8.1.2 E3.5 (NACK gap-fill) + E4' (adaptive r) ===========================

int CLiveTunnel::ProxyAdaptiveR(const std::string& hex)
{
    // E4' — adapt PARITY (not bitrate) to the measured NACK rate per stream (~10 s window):
    // no NACKs -> ease r down toward 2; light loss -> >=3; heavy -> up to BULK_MAX_R. Caller
    // holds m_lock.
    const DWORD now = GetTickCount();
    ProxyStreamCtl& c = m_proxyCtl[hex];
    if (c.windowStart == 0) { c.windowStart = now; c.r = Bulk::BULK_DEFAULT_R; }
    if ((DWORD)(now - c.windowStart) >= 10000) {
        if      (c.nackCount == 0) c.r = (c.r > 2 ? c.r - 1 : 2);
        else if (c.nackCount <= 3) c.r = (c.r < 3 ? 3 : c.r);
        else                       c.r = (c.r < Bulk::BULK_MAX_R ? c.r + 1 : Bulk::BULK_MAX_R);
        c.nackCount = 0;
        c.windowStart = now;
    }
    if (c.r < 2) c.r = 2;
    if (c.r > Bulk::BULK_MAX_R) c.r = Bulk::BULK_MAX_R;
    return c.r;
}

void CLiveTunnel::PushBlockToCircuit(std::shared_ptr<CLiveCircuit>& circ, const uint8_t streamKey[16],
                                     uint32_t seq, const std::vector<uint8_t>& record, int r, uint8_t blockIdx)
{
    if (!circ || record.size() < 20) return;
    Bulk::BulkLayout layout;
    if (!Bulk::BulkComputeLayout((uint32_t)record.size(), layout)) return;
    if (blockIdx >= layout.n_blocks) return;
    std::vector<Bulk::BulkSymbol> symbols;
    if (!Bulk::BulkEncodeSegment(record.data(), record.size(), r, symbols)) return;
    for (const Bulk::BulkSymbol& s : symbols) {
        if (s.block_idx != blockIdx) continue;
        Bulk::BulkDataHeader bh;
        memcpy(bh.stream_key, streamKey, 16);
        bh.seq = seq; bh.block_idx = s.block_idx; bh.n_blocks = (uint8_t)layout.n_blocks;
        bh.symbol_idx = s.symbol_idx; bh.k = s.k; bh.r = (uint8_t)r;
        bh.flags = 0; bh.msg_len = (uint32_t)record.size();
        std::vector<uint8_t> payload;
        Bulk::BulkDataPack(bh, s.data.data(), payload);
        SendBulkCellReverse(circ, Bulk::BULK_DATA, payload.data(), payload.size());
    }
}

void CLiveTunnel::ExitHandle_BulkNack(const TunnelRequestCtx& ctx)
{
    // body: stream_key 16 + count 1 + (seq 4 + block_idx 1)*count
    if (!ctx.circ || !ctx.body || ctx.bodyLen < 17) return;
    uint8_t streamKey[16];
    memcpy(streamKey, ctx.body, 16);
    const uint8_t count = ctx.body[16];
    if (count == 0 || (size_t)ctx.bodyLen < 17 + (size_t)count * 5) return;
    const std::string hex = LiveStreamKeyHex(streamKey);
    m_proxyCtl[hex].nackCount++;                  // E4' telemetry
    const int r = ProxyAdaptiveR(hex);
    std::shared_ptr<CLiveCircuit> circ = ctx.circ;
    for (uint8_t i = 0; i < count; ++i) {
        const uint8_t* ePtr = ctx.body + 17 + (size_t)i * 5;
        const uint32_t seq = eseRdU32LE(ePtr);
        const uint8_t  blk = ePtr[4];
        for (auto& rec : m_proxyRecent)
            if (rec.seq == seq && memcmp(rec.streamKey, streamKey, 16) == 0) {
                PushBlockToCircuit(circ, streamKey, seq, rec.record, r, blk);
                break;
            }
    }
    AddDebugLogLine(false, _T("LiveTunnel: [E3.5] bulk NACK %u block(s) re-pushed (r=%d)"),
        (unsigned)count, r);
}

bool CLiveTunnel::SendBulkNack(const uint8_t streamKey[16],
                               const std::vector<std::pair<uint32_t, uint8_t>>& missing)
{
    if (missing.empty() || missing.size() > 40) return false;   // caller holds m_lock
    std::vector<uint8_t> body;
    body.insert(body.end(), streamKey, streamKey + 16);
    body.push_back((uint8_t)missing.size());
    for (const auto& m : missing) {
        uint8_t tmp[4]; eseWrU32LE(tmp, m.first);
        body.insert(body.end(), tmp, tmp + 4);
        body.push_back(m.second);
    }
    for (auto& c : m_circuits) {
        if (c->m_role != CircuitRole::Originator || c->State() != CircuitState::Active) continue;
        if (c->HopCount() < 1 || !c->m_bulk_ok) continue;
        const size_t onion = c->HopCount() * 16;
        if (onion + SUB_HEADER_BYTES + FRAG_HEADER_BYTES >= CELL_PAYLOAD_MAX) continue;
        const size_t fragDataMax = CELL_PAYLOAD_MAX - onion - SUB_HEADER_BYTES - FRAG_HEADER_BYTES;
        std::vector<std::vector<uint8_t>> cells;
        if (!SplitIntoCells(TUN_OP_BULK_NACK, NewCircuitId(), body.data(), body.size(), fragDataMax, cells))
            continue;
        bool ok = true;
        for (auto& plain : cells) {
            uint8_t cp[CELL_PAYLOAD_MAX]; size_t cl = 0;
            if (!c->OnionEncrypt(plain.data(), plain.size(), cp, cl)) { ok = false; break; }
            uint8_t cell[CELL_TOTAL_BYTES];
            if (!CellPack(c->Id(), CELL_RELAY, cp, cl, cell)) { ok = false; break; }
            if (!c->m_firstHopClient || !SendCellToPeer(c->m_firstHopClient, cell)) { ok = false; break; }
        }
        if (ok) return true;
    }
    return false;
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
    std::set<uint32_t> retiredCircuits;
    // Emit one terminal build sample per strict origin circuit before dead
    // entries are reaped. Success means the complete authenticated 3-hop path
    // reached Active; every fail-closed teardown is a failed build unless a
    // success was already recorded earlier in the circuit lifetime.
    const uint64_t buildMetricNow = static_cast<uint64_t>(time(NULL));
    for (const auto& circuit : m_circuits) {
        if (circuit && circuit->State() == CircuitState::Destroyed)
            retiredCircuits.insert(circuit->Id());
        if (!circuit || !circuit->m_strict3 ||
            circuit->m_role != CircuitRole::Originator ||
            circuit->m_k6BuildMetricEmitted ||
            (circuit->State() != CircuitState::Active &&
             circuit->State() != CircuitState::Destroyed))
            continue;
        const bool ok = circuit->State() == CircuitState::Active;
        m_k6Metrics.Observe(kad6::K6MetricFamily::CircuitBuildMs,
            ok ? 0 : 1, 0, 0, static_cast<double>(circuit->AgeMs()), buildMetricNow);
        m_k6Metrics.Add(kad6::K6MetricFamily::BuildTotal,
            ok ? 0 : 1, ok ? 0 : 6, 0, 1, buildMetricNow);
        circuit->m_k6BuildMetricEmitted = true;
    }
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
        if (c->State() == CircuitState::Active && c->AgeMs() > TUNNEL_ROTATION_BASE_MS) {
            if (c->m_strict3) DestroyCircuitFailClosed(c);
            else c->SetState(CircuitState::Destroyed); // normal legacy rotation
        } else if (c->State() == CircuitState::Pending && c->AgeMs() > TUNNEL_HANDSHAKE_TIMEOUT_MS * 8) {
            // 8x handshake timeout = ~6.4 s. After this, give up — peer
            // probably isn't running the fork. Distinct from a crypto reject:
            // this is a TIMED reap from Tick (with age), not a synchronous AUTH-ABORT.
            AddDebugLogLine(false, _T("LiveTunnel: circ=0x%08x REAP reason=HANDSHAKE_TIMEOUT (CREATED never arrived, age=%u ms) — NOT a crypto reject"), c->Id(), c->AgeMs());
            if (c->m_strict3) DestroyCircuitFailClosed(c);
            else c->SetState(CircuitState::Destroyed);
        } else if (c->State() == CircuitState::HalfBuilt
                   && c->m_extendStartedTick != 0
                   && (DWORD)(now - c->m_extendStartedTick) > TUNNEL_HANDSHAKE_TIMEOUT_MS * 16) {
            // v8.1 fix: a circuit stuck mid-EXTEND (hop1 done, EXTENDED
            // never arrived) used to fall through both arms above and
            // leak forever. Time it out, with a longer budget since it
            // is waiting on a second handshake leg.
            AddDebugLogLine(false, _T("LiveTunnel: circ=0x%08x REAP reason=EXTEND_TIMEOUT (EXTENDED never arrived, age=%u ms) — NOT a crypto reject"), c->Id(), c->AgeMs());
            if (c->m_strict3) DestroyCircuitFailClosed(c);
            else c->SetState(CircuitState::Destroyed);
        }
    }

    // 3. v0.71 P0.A — cover traffic emission. For each Active originator
    // circuit, if it's past m_nextPaddingTick, emit a CELL_PADDING with
    // random length and reschedule via Poisson distribution.
    // This makes TAG_ESE_CAPS bit 11 (cover_traffic) truthful: the bit
    // claims we generate cover traffic, and now we actually do.
    // K6-3: SourceLeases are circuit-bound. Rotation, DESTROY or timeout
    // drains their publishes; wall-clock expiry closes them independently of
    // GetTickCount wraparound.
    for (const auto& circuit : m_circuits)
        if (circuit && circuit->State() == CircuitState::Destroyed)
            retiredCircuits.insert(circuit->Id());

    {
        double circuitCounts[5][4] = {};
        for (const auto& circuit : m_circuits) {
            if (!circuit) continue;
            const uint8 state = (std::min<uint8>)(static_cast<uint8>(circuit->State()), 4);
            const uint8 hops = (std::min<uint8>)(static_cast<uint8>(circuit->HopCount()), 3);
            circuitCounts[state][hops] += 1.0;
        }
        const uint64 metricNow = static_cast<uint64>(time(NULL));
        for (uint8 state = 0; state < 5; ++state)
            for (uint8 hops = 0; hops < 4; ++hops)
                m_k6Metrics.Observe(kad6::K6MetricFamily::Circuits,
                    state, hops, 0, circuitCounts[state][hops], metricNow);
    }
    {
        std::set<uint32_t> active;
        for (const auto& c : m_circuits)
            if (c->State() == CircuitState::Active) active.insert(c->Id());
        const uint64 k6Now = static_cast<uint64_t>(time(NULL));
        SweepK6SourceLeases(active, retiredCircuits, k6Now);
        SweepK6Gateway(k6Now, active);
        StartK6VisibilityProbes(k6Now);
        QueueK6ShadowRefreshes(k6Now);
        StartDueK6ShadowPublishes(k6Now);
        RefreshK6NativePublishes(k6Now);
    }

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
        for (auto it = m_k6SearchReplies.begin(); it != m_k6SearchReplies.end(); ) {
            if ((DWORD)(now - it->second.started) > TUN_REQUEST_HARD_TTL_MS)
                it = m_k6SearchReplies.erase(it);
            else
                ++it;
        }
    }

    // 4b. v8.1.2 E3.4 - sweep abandoned bulk segment reassembly + dead-circuit replay
    // windows (under m_lock, already held). Same rationale as A5.
    SweepBulkReasm();

    // 4c. v8.1.2 E3.1/E3.3 - exit-side: drain headless-ingested records, FEC-encode and
    // push their symbols to the subscribed bulk circuits (under m_lock, already held).
    ProcessProxyIngest();

    // 4d. v8.1.2 E3.2 (viewer trigger) - while viewing a stream WITH Active bulk-capable
    // circuits, (re)subscribe to the bulk data plane every ~10 s. The throttle is well under
    // BULK_SUB_TTL_MS so the exit's subs stay fresh AND circuits that turned Active after the
    // join get covered. No-op at any node the exit isn't proxying this stream for (the exit
    // only registers/pushes if it proxies the streamKey). BulkSubscribe re-takes m_lock
    // (recursive CCriticalSection) — fine. liveStreamManager->IsViewingLive()/GetStreamKey()
    // are unlocked inline reads (same pattern as elsewhere), so no manager lock is taken here.
    if (theApp.liveStreamManager && theApp.liveStreamManager->IsViewingLive()
        && (DWORD)(now - m_lastBulkSubTick) > 10000u) {
        bool haveBulk = false;
        for (auto& c : m_circuits)
            if (c->m_role == CircuitRole::Originator && c->State() == CircuitState::Active
                && c->HopCount() >= 1 && c->m_bulk_ok) { haveBulk = true; break; }
        if (haveBulk) {
            m_lastBulkSubTick = now;
            BulkSubscribe(theApp.liveStreamManager->GetStreamKey());
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
                    rq.requiredExitCaps = pr->required_exit_caps;
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

bool CLiveTunnel::HasActiveCircuitWithExitCaps(uint32_t requiredCaps) const
{
    if (requiredCaps == 0) return ActiveCircuitCount() != 0;
    const size_t minimumHops = (requiredCaps & ESE_CAP_KAD6) != 0 ? 2 : 1;
    CSingleLock lock(&m_lock, TRUE);
    for (const auto& c : m_circuits) {
        if (!c->m_k6QuotaIssuerCircuit &&
            c->m_role == CircuitRole::Originator &&
            c->State() == CircuitState::Active && c->HopCount() >= minimumHops &&
            c->m_firstHopClient && c->m_multicell_ok && c->m_auth_ok &&
            (c->m_exit_signed_caps & requiredCaps) == requiredCaps &&
            ((requiredCaps & ESE_CAP_TUNNEL_STRICT3) == 0
             || (c->m_strict3 && c->m_path_diverse && c->m_shaped_ok
                 && c->HopCount() == 3)))
            return true;
    }
    return false;
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
