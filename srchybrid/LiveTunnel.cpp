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
#include "LiveStreamRecovery.h"
#include "LiveCircuitHandshake.h"
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
#include "DirectReachabilityManager.h"
#include "eMuleAI/Address.h"

#include <limits>

namespace eSELive {

using namespace LiveCircuitHandshakeWire;

namespace {
bool K6ReleaseRandom(void*, std::uint8_t*, std::size_t);

LiveSourceEndpointKey BuildLiveSourceEndpointKey(const kad6::K6Endpoint& endpoint, uint8 origin)
{
    return {origin, static_cast<uint8>(endpoint.addr.family), endpoint.addr.addr, endpoint.tcp_port};
}

LiveTunnelKadPorts BuildLiveTunnelKadPorts()
{
    LiveTunnelKadPorts ports;
    ports.should_route = [](const wchar_t* keyword, std::uint8_t operationClass) {
        using namespace Kademlia;
        CKadV2ModeSelector::QueryContext query = {};
        query.includesPrivateChannelHash = false; if (keyword) query.keywordLowercase = keyword;
        query.operationClass = static_cast<
            CKadV2ModeSelector::QueryContext::OperationClass>(operationClass);
        return CKadV2ModeSelector::Get().Decide(query) == CKadV2Mode::Tunneled;
    };
    ports.search_streams = [](const wchar_t* keyword,
        std::vector<std::uint32_t>* searchIds, bool forceDirect) {
        return theApp.liveStreamManager && keyword &&
            theApp.liveStreamManager->GetKadBridge().SearchStreams(
                CString(keyword), searchIds, forceDirect);
    };
    ports.stop_search = [](std::uint32_t id) {
        Kademlia::CSearchManager::StopSearch(id, true); };
    ports.selected_networks = [] {
        const uint8 selected = thePrefs.GetEffectiveKadNetworkMask();
        uint8 bridgeMask = 0;
        if (KadNetworkPolicy::HasKad2(selected)) bridgeMask |= LiveTunnelKadBridge::kSelectedKad2;
        if (KadNetworkPolicy::HasKad6(selected)) bridgeMask |= LiveTunnelKadBridge::kSelectedKad6;
        return bridgeMask;
    };
    return ports;
}
} // namespace

CLiveTunnel::CLiveTunnel()
    : m_handshake(*this),
      m_kadBridge(BuildLiveTunnelKadPorts())
{
    m_scheduler.ReopenDeferredWork();
    const CString releasePath=thePrefs.GetMuleDirectory(EMULE_CONFIGDIR)+_T("kad6_release_gate.dat");
    m_scheduler.ConfigureReleaseGate(
        std::wstring(releasePath.GetString()), K6ReleaseRandom, this,
        [](void* raw, bool enable, std::uint32_t drain) {
        CLiveTunnel& self = *static_cast<CLiveTunnel*>(raw);
        bool accepted = true;
        for (size_t i = 0; i < static_cast<size_t>(kad6::K6Service::Count); ++i)
            accepted = self.ApplyK6ServiceSwitch(static_cast<kad6::K6Service>(i),
                enable, drain) && accepted;
        return accepted;
    });

    // v8.1 A2 - register the built-in exit-side handlers. Sprint B/C ops
    // register theirs the same way instead of editing HandleRelay_Exit.
    m_exitServices.RegisterHandler(TUN_OP_PING,
        [this](const TunnelRequestCtx& c){ ExitHandle_Ping(c); });
    m_exitServices.RegisterHandler(TUN_OP_KAD_SEARCH,
        [this](const TunnelRequestCtx& c){ ExitHandle_KadSearch(c); });
    m_exitServices.RegisterHandler(TUN_OP_ECHO_LARGE,
        [this](const TunnelRequestCtx& c){ ExitHandle_EchoLarge(c); });
    // v8.1 Sprint B - real Kad search through the tunnel.
    m_exitServices.RegisterHandler(TUN_OP_KAD_SEARCH_V2,
        [this](const TunnelRequestCtx& c){ ExitHandle_KadSearchV2(c); });
    m_exitServices.RegisterHandler(TUN_OP_KAD_CANCEL,
        [this](const TunnelRequestCtx& c){ ExitHandle_KadCancel(c); });
    // v8.1 Sprint C - tunneled LiveTV subscribe (single-cell control op).
    m_exitServices.RegisterHandler(TUN_OP_LIVE_SUBSCRIBE,
        [this](const TunnelRequestCtx& c){ ExitHandle_LiveSubscribe(c); });
    // v8.1.2 Sprint E (E3.2) - explicit bulk data-plane subscribe/unsub.
    m_exitServices.RegisterHandler(TUN_OP_BULK_SUBSCRIBE,
        [this](const TunnelRequestCtx& c){ ExitHandle_BulkSubscribe(c); });
    m_exitServices.RegisterHandler(TUN_OP_BULK_UNSUB,
        [this](const TunnelRequestCtx& c){ ExitHandle_BulkUnsub(c); });
    m_exitServices.RegisterHandler(TUN_OP_BULK_NACK,
        [this](const TunnelRequestCtx& c){ ExitHandle_BulkNack(c); });
    // K6-1A canonical Live search gateway.  Originators select it only from
    // the authenticated exit-capability snapshot; old peers retain 0x42/0x43.
    m_exitServices.RegisterHandler(TUN_OP_KAD6_GATEWAY,
        [this](const TunnelRequestCtx& c){ ExitHandle_Kad6Gateway(c); });

    const kad6::Kad6CryptoHooks crypto = MakeKad6HostCryptoHooks(); std::array<uint8_t, 32> ticketSecret{};
    if (crypto.random_bytes && crypto.random_bytes(ticketSecret.data(), ticketSecret.size()))
        m_exitServices.LT4InitializeTicketSecret(ticketSecret);

    // A fresh installation is never a public exit merely because the binary
    // contains the handlers. Operator consent plus signed release evidence is
    // required before any public Kad6 service admits work.
    const uint64 now = static_cast<uint64>(time(NULL));
    for (size_t i = 0; i < static_cast<size_t>(kad6::K6Service::Count); ++i)
        m_scheduler.LT2HardeningSetEnabled(static_cast<kad6::K6Service>(i), false,
            now ? now : 1, 0, 0);
}

// v8.1 Sprint C — little-endian field helpers for the Live tunnel op bodies.
bool CLiveTunnel::HandleCreated_Originator(
    std::shared_ptr<CLiveCircuit>& circ,
    const uint8_t* payload, uint16_t payloadLen)
{
    return m_handshake.HandleCreatedOriginator(circ, payload, payloadLen);
}

bool CLiveTunnel::ContinueOriginatorBuild(
    std::shared_ptr<CLiveCircuit>& circ)
{
    return m_handshake.ContinueOriginatorBuild(circ);
}

bool CLiveTunnel::HandleCreate_Relay(
    uint32_t circId, const uint8_t* payload, uint16_t payloadLen,
    CUpDownClient* fromPeer)
{
    return m_handshake.HandleCreateRelay(
        circId, payload, payloadLen, fromPeer);
}

bool CLiveTunnel::BuildExtend(
    std::shared_ptr<CLiveCircuit>& circ, CUpDownClient* target)
{
    return m_handshake.BuildExtend(circ, target);
}

bool CLiveTunnel::HandleExtend_Relay(
    std::shared_ptr<CLiveCircuit>& circ,
    const uint8_t* payload, uint16_t payloadLen)
{
    return m_handshake.HandleExtendRelay(circ, payload, payloadLen);
}

bool CLiveTunnel::ForwardCreatedAsExtended_Relay(
    uint32_t outboundCircId, const uint8_t* payload, uint16_t payloadLen)
{
    return m_handshake.ForwardCreatedAsExtendedRelay(
        outboundCircId, payload, payloadLen);
}

bool CLiveTunnel::ForwardExtendCell_Forward(
    std::shared_ptr<CLiveCircuit>& circ,
    const uint8_t* payload, uint16_t payloadLen)
{
    return m_handshake.ForwardExtendCellForward(circ, payload, payloadLen);
}

bool CLiveTunnel::ForwardExtendedCell_Reverse(
    std::shared_ptr<CLiveCircuit>& circ,
    const uint8_t* payload, uint16_t payloadLen)
{
    return m_handshake.ForwardExtendedCellReverse(circ, payload, payloadLen);
}

bool CLiveTunnel::HandleExtended_Originator(
    std::shared_ptr<CLiveCircuit>& circ,
    const uint8_t* payload, uint16_t payloadLen)
{
    return m_handshake.HandleExtendedOriginator(circ, payload, payloadLen);
}

void CLiveTunnel::ResolveHandshakeExitKey(
    LiveHandshakePeerHandle exitHandle, CLiveCircuit& circuit)
{
    CUpDownClient* exit = static_cast<CUpDownClient*>(exitHandle);
    if (!exit || circuit.m_haveExitKadKey || exit->IsIPv6OnlyEndpoint())
        return;
    if (exit->GetConnectIP() == 0
        || !Kademlia::CKademlia::IsKad2Running())
        return;
    Kademlia::CRoutingZone* zone =
        Kademlia::CKademlia::GetRoutingZone();
    if (!zone) return;
    Kademlia::CContact* contact =
        zone->GetContact(ntohl(exit->GetConnectIP()), 0, false);
    if (!contact) return;
    circuit.m_exitKadKey = contact->GetClientID();
    circuit.m_haveExitKadKey = true;
}

bool CLiveTunnel::ReadHandshakePeer(
    LiveHandshakePeerHandle peerHandle,
    LiveHandshakePeerView& view) const
{
    CUpDownClient* peer = static_cast<CUpDownClient*>(peerHandle);
    if (!peer)
        return false;
    view = LiveHandshakePeerView{};
    view.validHash = peer->HasValidHash();
    const uchar* hash = peer->GetUserHash();
    if (hash)
        memcpy(view.userHash, hash, sizeof view.userHash);
    view.hasNodePublicKey = peer->HasEseNodePub();
    if (view.hasNodePublicKey)
        memcpy(view.nodePublicKey, peer->GetEseNodePub(), sizeof view.nodePublicKey);
    view.supportsDataplane = peer->SupportsEseTunnelDataplane();
    view.supportsBulk = peer->SupportsEseTunnelBulk();
    view.supportsAuth = peer->SupportsEseTunnelAuth();
    view.supportsStrict3 = peer->SupportsEseTunnelStrict3();
    view.supportsShaped = peer->SupportsEseTunnelShaped();
    view.hasIpv6 = peer->HasIPv6Address();
    if (view.hasIpv6)
        memcpy(view.ipv6, peer->GetIPv6Address().Data(), sizeof view.ipv6);
    view.ipv6Only = peer->IsIPv6OnlyEndpoint();
    view.ipv4 = peer->GetIP();
    view.port = peer->GetUserPort();
    return true;
}

void CLiveTunnel::RegisterActiveHandshakeCircuit(
    const std::shared_ptr<CLiveCircuit>& circuit)
{
    Kademlia::CKadV2TunnelPool::Get().RegisterTunnel(circuit);
}

const uint8_t* CLiveTunnel::LocalHandshakeUserHash() const
{
    return thePrefs.GetUserHash();
}

const uint8_t* CLiveTunnel::LocalHandshakeNodePublicKey() const
{
    return NodeIdentityPub();
}

bool CLiveTunnel::SignHandshakeTranscript(
    const uint8_t* bytes, size_t length, uint8_t signature[64]) const
{
    return NodeIdentitySign(bytes, length, signature);
}

bool CLiveTunnel::HashHandshakeCircuitPrefix(
    const CLiveCircuit& circuit, uint8_t out[32]) const
{
    static const char label[] = "kad6-circuit-prefix-v1";
    std::vector<uint8_t> input;
    input.reserve(sizeof(label) - 1 + 5 + circuit.HopCount() * 32);
    input.insert(input.end(), label, label + sizeof(label) - 1);
    uint8_t context[5];
    PutU32LE(context, circuit.Id());
    context[4] = static_cast<uint8_t>(circuit.HopCount());
    input.insert(input.end(), context, context + sizeof context);
    for (size_t i = 0; i < circuit.HopCount(); ++i)
        input.insert(
            input.end(),
            circuit.Hop(i).pub_long,
            circuit.Hop(i).pub_long + 32);
    const kad6::Kad6CryptoHooks crypto = MakeKad6HostCryptoHooks();
    return crypto.sha256 && crypto.sha256(input.data(), input.size(), out);
}

uint32_t CLiveTunnel::HandshakeRuntimeCapabilities() const
{
    return g_uEseCapsRuntime;
}

LiveHandshakePeerHandle CLiveTunnel::FindConnectedHandshakePeerByHash(
    const uint8_t hash[16]) const
{
    CUpDownClient* peer = theApp.clientlist
        ? theApp.clientlist->FindClientByUserHash(hash) : NULL;
    return peer && peer->socket && peer->socket->IsConnected() ? peer : NULL;
}

LiveHandshakePeerHandle CLiveTunnel::FindConnectedHandshakePeer(
    uint32_t ipv4, uint16_t port) const
{
    CUpDownClient* peer = theApp.clientlist
        ? theApp.clientlist->FindClientByIP(ipv4, port) : NULL;
    return peer && peer->socket && peer->socket->IsConnected() ? peer : NULL;
}

uint32_t CLiveTunnel::LocalHandshakePublicIp() const
{
    return theApp.GetPublicIP();
}

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

const uint16_t K6_SHAPE_DEFAULT_BUCKET_KIB = K6_SHAPE_RUNTIME_MAX_BUCKET_KIB;
const uint8_t  K6_BULK_SUB_FLAG_SHAPED = 0x01;
const uint64_t K6_SHAPE_PADDING_NONCE = kad6::kK6ShapedPaddingSentinel;

bool K6ShapeValidBucket(uint32_t bucketKiB)
{
    return bucketKiB >= kad6::kK6ShapeMinBucketKiB
        && bucketKiB <= K6_SHAPE_RUNTIME_MAX_BUCKET_KIB
        && (bucketKiB & (bucketKiB - 1)) == 0;
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

uint64_t M2A_LT3_K6ShapeNowUs() { return K6ShapeNowUs(); } std::vector<uint8_t> M2A_LT3_EseCStringUtf8(const CString& v) { return EseCStringUtf8(v); }
CString M2A_LT3_EseUtf8CString(const std::string& v) { return EseUtf8CString(v); }
bool M2A_LT3_AppendLegacyK6Result(const kad6::K6LiveSearchMetadata& v, std::vector<uint8_t>& out) { return EseAppendLegacyK6Result(v, out); }
CLiveTunnel& CLiveTunnel::Get()
{
    static CLiveTunnel s_instance;
    return s_instance;
}

bool CLiveTunnel::RunCharacterizationSelfTest(CString& outFailure)
{
    outFailure.Empty();
    const eSELive::FramingSelfTestResult framing = eSELive::RunFramingCharacterizationSelfTest();
    if (framing == eSELive::FramingSelfTestResult::SplitFailed) {
        outFailure = _T("tunnel framing split failed");
        return false;
    }
    if (framing == eSELive::FramingSelfTestResult::ParseOrReassemblyFailed) {
        outFailure = _T("tunnel framing parse or reassembly failed");
        return false;
    }
    if (framing == eSELive::FramingSelfTestResult::PayloadMismatch) {
        outFailure = _T("tunnel framing payload mismatch");
        return false;
    }
    const eSELive::CircuitRegistrySelfTestResult registry =
        eSELive::RunCircuitRegistryCharacterizationSelfTest();
    if (registry != eSELive::CircuitRegistrySelfTestResult::Pass) {
        outFailure.Format(
            _T("tunnel circuit registry characterization failed (%u)"),
            static_cast<unsigned>(registry));
        return false;
    }
    if (!eSELive::RunLiveExitServicesCharacterizationSelfTest()) {
        outFailure = _T("tunnel exit services characterization failed");
        return false;
    }
    if (!eSELive::RunLiveRelayDispatcherCharacterizationSelfTest()) {
        outFailure = _T("tunnel relay dispatcher characterization failed");
        return false;
    }
    if (!eSELive::RunLiveTunnelSchedulerCharacterizationSelfTest()) {
        outFailure = _T("tunnel scheduler characterization failed");
        return false;
    }
    if (!eSELive::RunLiveTunnelPeerStateCharacterizationSelfTest()) {
        outFailure = _T("tunnel peer-state characterization failed");
        return false;
    }
    uint32 lateRequest=0; PendingHandle latePending=RegisterPending(lateRequest); std::vector<uint8_t> lateIgnored; WaitPending(lateRequest,std::move(latePending),0,lateIgnored,NULL); kad6::K6SearchEnd lateEnd{}; std::vector<uint8_t> lateBody, lateWire; kad6::K6Frame lateFrame{}; lateFrame.msg_type=kad6::kK6MsgSearchEnd; lateFrame.flags=kad6::kK6FlagResponse|kad6::kK6FlagFinal; lateFrame.request_id=lateRequest; if (!eSELive::RunLiveTunnelKadBridgeCharacterizationSelfTest() || kad6::EncodeK6SearchEnd(lateEnd,lateBody)!=kad6::Kad6Status::Ok || (lateFrame.body=std::move(lateBody),kad6::EncodeK6Frame(lateFrame,lateWire))!=kad6::Kad6Status::Ok || HandleK6SearchReply(std::make_shared<CLiveCircuit>(7),lateFrame.request_id,lateWire)) {
        outFailure = _T("tunnel Kad-bridge characterization failed");
        return false;
    }
    if (!eSELive::RunLiveTunnelMetricsCharacterizationSelfTest()) {
        outFailure = _T("tunnel metrics characterization failed");
        return false;
    }
    if (SendThrough(NULL, 0)) {
        outFailure = _T("tunnel empty dispatch was accepted");
        return false;
    }
    return true;
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
    m_metrics.RecordCellSent(CELL_TOTAL_BYTES);
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
    if (relayCandidates.empty() || theApp.IsClosing()) return 0;

    CSingleLock lock(&m_lock, TRUE);
    m_scheduler.ReopenDeferredWork();
    size_t built = 0;
    for (size_t i = 0; i < count && i < relayCandidates.size(); ++i) {
        CUpDownClient* hop1 = relayCandidates[i];
        if (!hop1 || !hop1->socket || !hop1->socket->IsConnected())
            continue;

        // Allocate a fresh circuit id.
        uint32_t id = 0;
        for (int t = 0; t < 4; ++t) {
            id = NewCircuitId();
            if (!m_circuitRegistry.ContainsIncomingId(id)) break;
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
            if (!HashHandshakeCircuitPrefix(*c, c->m_createPrefixHash)) {
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
        if (m_circuitRegistry.Add(c, CircuitState::Pending))
            ++built;
    }
    (void)origin_pubkey;  // unused until ntor-with-pubkey binding lands
    return built;
}

uint32_t CLiveTunnel::BuildTestCircuit(CUpDownClient* clientHint)
{
    // Solo testing helper. A circuit is meaningful only through a peer that
    // advertised ESE_CAP_PRIVACY_TUNNELING in its HELLO. Do not
    // fall back to a legacy peer: that used to return ok=true and emit a
    // CREATE cell that could never complete.
    std::vector<CUpDownClient*> cands;
    if (clientHint) {
        if (clientHint->socket && clientHint->socket->IsConnected()
            && clientHint->SupportsEsePrivacyTunneling())
            cands.push_back(clientHint);
    } else if (theApp.clientlist) {
        theApp.clientlist->GetConnectedSnapshot(cands, 3, /*tunnelOnly=*/true);
    }
    if (cands.empty()) return 0;

    size_t before = 0;
    {
        CSingleLock lk(&m_lock, TRUE);
        before = m_circuitRegistry.Size();
    }
    size_t built = BuildPool(NULL, cands, 1);
    if (built == 0) return 0;
    // Return the id of the circuit we just added.
    CSingleLock lk(&m_lock, TRUE);
    if (m_circuitRegistry.Size() > before)
        return m_circuitRegistry.Back()->Id();
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
        for (const auto& circuit : m_circuitRegistry.GetSnapshot()) {
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
        before = m_circuitRegistry.Size();
    }
    std::vector<CUpDownClient*> one{selected};
    if (BuildPool(NULL, one, 1) == 0) return false;
    CSingleLock lock(&m_lock, TRUE);
    for (size_t i = before; i < m_circuitRegistry.Size(); ++i) {
        const std::shared_ptr<CLiveCircuit> circuit = m_circuitRegistry.At(i);
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
        if (a->HasEseNodePub() && b->HasEseNodePub()
            && kad6::Kad6CtEqual(a->GetEseNodePub(), b->GetEseNodePub(), 32))
            return false;
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
    { CSingleLock lk(&m_lock, TRUE); before = m_circuitRegistry.Size(); }

    std::vector<CUpDownClient*> hop1Vec = { hop1 };
    if (BuildPool(NULL, hop1Vec, 1) == 0) return false;   // BuildPool takes m_lock itself

    CSingleLock lk(&m_lock, TRUE);
    if (m_circuitRegistry.Size() <= before) return false;
    std::shared_ptr<CLiveCircuit> c = m_circuitRegistry.Back();
    // Pre-stage the exit: HandleCreated_Originator auto-extends to it after hop1's
    // CELL_CREATED, producing a real V -> hop1 -> exit circuit (hop1 forwards via F-1).
    c->m_private2 = true;
    c->m_pendingHopClients.push_back(hop2);
    return true;
}

void CLiveTunnel::Stop()
{
    m_scheduler.StopReleaseNotice();
    std::set<uint32_t> retiredCircuits;
    {
        CSingleLock lock(&m_lock, TRUE);
        (void)m_scheduler.CloseDeferredWork();
        m_pendingRequests.CancelAll();
        StopK6ShapeTimerLocked();
        m_scheduler.ClearShaping();
        const std::vector<uint32_t> retired = m_circuitRegistry.Clear();
        retiredCircuits.insert(retired.begin(), retired.end());
    }
    const uint64 now = static_cast<uint64_t>(time(NULL));
    SweepK6SourceLeases(std::set<uint32_t>(), retiredCircuits, now);
    SweepK6Gateway(now, std::set<uint32_t>());
    {
        CSingleLock pl(&m_pendingLock, TRUE);
        (void)m_exitServices.Clear();
        m_reassembly.clear();
        m_scheduler.LT2ResetQuotaState();
        m_scheduler.ClearFair();
        m_exitServices.LT5ClearCredits();
    }
    // v8.1 D4 - the PST pool holds a 2nd shared_ptr alias per circuit. Clearing
    // the registry without clearing the pool would keep those circuits alive (and
    // counted as Active) indefinitely, and the pool would keep building successors
    // against a stopped subsystem. Clear it too (tunnel->pool order, same as RegisterTunnel).
    Kademlia::CKadV2TunnelPool::Get().Clear();
}

bool CLiveTunnel::SendThrough(const uint8_t* payload, size_t payloadLen)
{
    if (!payload || payloadLen == 0) return false;
    CSingleLock lock(&m_lock, TRUE);
    if (m_circuitRegistry.Empty()) return false;

    // Round-robin (multipath split, Decision 5.1).
    size_t tries = m_circuitRegistry.Size();
    while (tries-- > 0) {
        std::shared_ptr<CLiveCircuit> c = m_circuitRegistry.NextRoundRobin();
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

// v0.71 P3.3 — originator-side: CELL_CREATED arrived for our circuit.
// Payload = relay's ephemeral X25519 pub (32B). We derive the shared
// secret with our stored ephemeral private, run HKDF, register hop 1,
// wipe ephemeral, advance state.

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

void CLiveTunnel::DestroyCircuitFailClosed(
    const std::shared_ptr<CLiveCircuit>& circ)
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
    TransitionCircuitDestroyed(circ);
    circ->WipeKeys();
    circ->m_auth_ok = false;
    circ->m_exit_signed_caps = 0;
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
        for (const auto& circuit : m_circuitRegistry.GetSnapshot())
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
		} else if (verifiedAddress.family == kad6::Kad6Address::Family::IPv4
                   && !peer->IsIPv6OnlyEndpoint()) {
			const uint32 peerIPv4 = peer->GetIP();
			endpointMatches = peerIPv4 != 0
				&& memcmp(&peerIPv4, verifiedAddress.addr.data(), 4) == 0;
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
    { CSingleLock lk(&m_lock, TRUE); before = m_circuitRegistry.Size(); }
    std::vector<CUpDownClient*> first{guard};
    if (BuildPool(NULL, first, 1) == 0)
        return false;
    CSingleLock lk(&m_lock, TRUE);
    std::shared_ptr<CLiveCircuit> circuit;
    for (size_t i = before; i < m_circuitRegistry.Size(); ++i) {
        const std::shared_ptr<CLiveCircuit> candidate = m_circuitRegistry.At(i);
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


// v0.71 P3.3 — relay-side: CELL_CREATE arrived from a peer wanting to
// establish a hop with us. Generate ephemeral, derive symmetric keys
// from shared, reply with CELL_CREATED. Register the circuit as a relay
// circuit so future RELAY cells from this peer can be peeled.

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
// per-CREATE cost is the circuit registered in the registry — memory plus the
// linear scan every incoming cell pays). Tick() reaps every circuit after
// the 5-min rotation, so this also bounds a slow drip-flood. 512 concurrent
// relay circuits = hundreds of simultaneous viewers tunneling through us.
const size_t CREATE_GATE_MAX_RELAY_CIRCS = 512;

struct CreateRateSlot {
    CAddress srcAddress;   // full source endpoint (IPv4 or native IPv6)
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
bool CreateGateAdmit(const CAddress& source)
{
    const DWORD now = ::GetTickCount();
    if (now - s_createGlobalWindow > CREATE_GATE_WINDOW_MS) {
        s_createGlobalWindow = now;
        s_createGlobalCount  = 0;
    }
    if (++s_createGlobalCount > CREATE_GATE_MAX_GLOBAL)
        return false;
    int slot = -1, freeSlot = -1;
    const uint32_t h = (source.HashKey() * 0x9E3779B1u) % _countof(s_createRates);
    for (uint32_t i = 0; i < _countof(s_createRates); ++i) {
        uint32_t idx = (h + i) % _countof(s_createRates);
        if (s_createRates[idx].srcAddress == source
            && s_createRates[idx].windowStart != 0) {
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
        s_createRates[freeSlot].srcAddress = source;
        s_createRates[freeSlot].windowStart = now;
        s_createRates[freeSlot].count = 1;
    }
    return true;
}
}  // namespace

static CAddress CreatePeerAddress(const CUpDownClient* peer)
{
    if (peer == NULL)
        return CAddress();
    if (peer->socket != NULL) {
        const CAddress socketAddress = peer->socket->GetPeerCAddress();
        if (socketAddress.GetType() != CAddress::None && !socketAddress.IsNull())
            return socketAddress;
    }
    if (peer->IsIPv6OnlyEndpoint())
        return peer->GetIPv6Address();
    if (peer->GetIP() != 0 && peer->GetIP() != INADDR_NONE)
        return CAddress::FromIPv4NetworkOrder(peer->GetIP());
    if (peer->HasIPv6Address())
        return peer->GetIPv6Address();
    return CAddress();
}

bool CLiveTunnel::OnCellReceived(uint32_t circ_id, uint8_t cmd,
                                 const uint8_t* payload, uint16_t payloadLen,
                                 CUpDownClient* fromPeer)
{
    CSingleLock lock(&m_lock, TRUE);
    m_metrics.RecordCellReceived(CELL_TOTAL_BYTES);

    // CELL_CREATE: someone is asking us to be a relay for them. Handle
    // even if we don't know circ_id yet (this is by design — circ_id is
    // chosen by the originator and we learn it from the cell).
    if (cmd == CELL_CREATE) {
        if (!fromPeer) return false;   // HandleCreate_Relay would reject anyway
        // DoS hardening: admission gate BEFORE the X25519 work (see the
        // constants above). Drops are silent on the wire — V's circuit just
        // times out, exactly as if we were a vanilla 0.70b peer ignoring the
        // opcode — and the debug log is throttled so a flood can't flood it.
        const CAddress sourceAddress = CreatePeerAddress(fromPeer);
        bool admit = CreateGateAdmit(sourceAddress);
        if (admit) {
            size_t relayCircs = 0;
            for (const auto& c : m_circuitRegistry.GetSnapshot())
                if (c->m_role == CircuitRole::Relay) ++relayCircs;
            if (relayCircs >= CREATE_GATE_MAX_RELAY_CIRCS) admit = false;
        }
        if (!admit) {
            static DWORD s_lastGateLog = 0;
            if (::GetTickCount() - s_lastGateLog > 30000) {
                s_lastGateLog = ::GetTickCount();
                const std::string sourceText = sourceAddress.GetType() != CAddress::None
                    ? sourceAddress.ToString() : std::string("unknown");
                AddDebugLogLine(false,
                    _T("LiveTunnel: CREATE admission gate dropping handshake(s), last from %hs (DoS protection)"),
                    sourceText.c_str());
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
        auto relayCirc = m_circuitRegistry.FindRelayByOutgoingId(circ_id);
        if (relayCirc) {
            if (fromPeer != relayCirc->m_nextHopClient) return false;
            return ForwardCreatedAsExtended_Relay(circ_id, payload, payloadLen);
        }
    }

    if (cmd == CELL_EXTENDED) {
        auto relayCirc = m_circuitRegistry.FindRelayByOutgoingId(circ_id);
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
        auto relayCirc = m_circuitRegistry.FindRelayByOutgoingId(circ_id);
        if (relayCirc) {
            if (fromPeer != relayCirc->m_nextHopClient) return false;
            uint8_t destroy[CELL_TOTAL_BYTES];
            if (relayCirc->m_prevHopClient
                && CellPack(relayCirc->Id(), CELL_DESTROY, NULL, 0, destroy))
                SendCellToPeer(relayCirc->m_prevHopClient, destroy);
            TransitionCircuitDestroyed(relayCirc);
            relayCirc->WipeKeys();
            return true;
        }
    }

    // v8.1.1 F-1 — reverse 2-hop DATA forwarding. A CELL_RELAY arriving on a
    // relay's OUTBOUND id (m_nextCircId) is a data cell coming back from hop2/exit;
    // re-add our hop1->V layer and relay it to V. Looked up BEFORE the by-Id lookup
    // (the outbound id is not a circuit Id on this node), mirroring CELL_CREATED above.
    if (cmd == CELL_RELAY) {
        auto relayCirc = m_circuitRegistry.FindRelayByOutgoingId(circ_id);
        if (relayCirc) {
            if (fromPeer != relayCirc->m_nextHopClient) return false;
            return ForwardRelayCell_Reverse(relayCirc, payload, payloadLen);
        }
    }

    // All other cells require an existing circuit entry by circ_id
    // (originator's V-side id, or relay-side from-V id).
    std::shared_ptr<CLiveCircuit> circ = m_circuitRegistry.FindById(circ_id);
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
            TransitionCircuitDestroyed(circ);
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

uint32_t CLiveTunnel::BuildTestCircuit2Hop()
{
    // A LAB two-hop request models the production Private profile: it requires
    // two distinct fork identities and every hop must authenticate. Never
    // silently collapse it into the old self-loop or Mixed-mode test.
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

    // The freshly-built circuit is at the back of the registry. We can't
    // call BuildExtend yet — the circuit is still Pending until CREATED
    // arrives. We mark a flag so HandleCreated_Originator triggers
    // BuildExtend automatically. For simplicity (and because there's no
    // good place to stash hop2 right now), we register a one-shot
    // post-CREATED action via a static map.
    CSingleLock lk(&m_lock, TRUE);
    if (m_circuitRegistry.Empty()) return 0;
    const std::shared_ptr<CLiveCircuit> c = m_circuitRegistry.Back();
    // Re-use m_nextHopClient on the ORIGINATOR side to mean "after
    // CREATED, extend to this peer". HandleCreated_Originator will check.
    c->m_private2 = true;
    c->m_pendingHopClients.push_back(hop2);
    return c->Id();
}

void CLiveTunnel::GetCircuitsSnapshot(std::vector<CircuitSnapshot>& out) const
{
    CSingleLock lock(&m_lock, TRUE);
    out.clear();
    out.reserve(m_circuitRegistry.Size());
    DWORD now = GetTickCount();
    for (const auto& c : m_circuitRegistry.GetSnapshot()) {
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
        s.abort_reason = static_cast<uint8_t>(c->m_abort_reason);
        out.push_back(s);
    }
}

void CLiveTunnel::GetK6HardeningSnapshot(K6HardeningRuntimeSnapshot& out)
{
    CKad6OriginSocket::LT3GetHardeningSnapshot(*this, out);
}

namespace {
bool K6ReleaseRandom(
    void*, std::uint8_t* bytes, std::size_t size)
{
    const kad6::Kad6CryptoHooks crypto = MakeKad6HostCryptoHooks();
    return crypto.random_bytes && crypto.random_bytes(bytes, size);
}

} // namespace

void CLiveTunnel::RefreshK6PublicRelease(uint64 nowSeconds, uint32 drainSeconds)
{
    if (nowSeconds == 0) return;
    const bool optIn = thePrefs.GetKad6PublicExitOptIn();
    const bool betaOptIn = thePrefs.IsEseNetLabContributionActive() &&
        thePrefs.GetKad6BetaExitOptIn();
    K6ReleaseRuntimeSnapshot release;
    const kad6::K6ReleaseGateStatus evidenceStatus = m_scheduler.GetReleaseSnapshot(
        release, optIn, betaOptIn, NodeIdentityPub(),
        MakeKad6HostCryptoHooks(), nowSeconds);

    bool shapingExposed = false;
    {
        CSingleLock lock(&m_lock, TRUE);
        for (const auto& circuit : m_circuitRegistry.GetSnapshot())
            if (circuit && circuit->m_traffic_shaping_exposed)
                { shapingExposed = true; break; }
    }
    bool runtimeHealthy = NodeIdentityIsPersistent() && m_exitServices.LT4TicketSecretReady() &&
        m_scheduler.LT2EconomyHealthy() && !m_kadBridge.LT3SourceEpochStoreFailed() && !shapingExposed;

    m_scheduler.ApplyReleaseEvaluation(
        optIn, betaOptIn, runtimeHealthy, evidenceStatus, drainSeconds);
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
    if (evidence && !m_scheduler.SaveReleaseEvidence(*evidence,
            MakeKad6HostCryptoHooks(), NodeIdentityPub(), now)) return false;
    thePrefs.SetKad6PublicExitOptIn(true);
    RefreshK6PublicRelease(now, drainSeconds);
    return IsK6PublicReleaseEnabled();
}

void CLiveTunnel::GetK6ReleaseSnapshot(K6ReleaseRuntimeSnapshot& out)
{
    m_scheduler.GetReleaseSnapshot(out, thePrefs.GetKad6PublicExitOptIn(),
        thePrefs.GetKad6BetaExitOptIn() && thePrefs.IsEseNetLabContributionActive(),
        NodeIdentityPub(), MakeKad6HostCryptoHooks(),
        static_cast<uint64>(time(NULL)));
}

bool CLiveTunnel::IsK6PublicReleaseEnabled() const
{ return m_scheduler.IsReleaseEnabled(); }

bool CLiveTunnel::GetK6ReleaseOperatorChallenge(std::string& challenge)
{ return m_scheduler.GetReleaseChallenge(
    challenge, static_cast<std::uint64_t>(time(NULL))); }

bool CLiveTunnel::ConsumeK6ReleaseOperatorChallenge(const std::string& challenge)
{ return m_scheduler.ConsumeReleaseChallenge(
    challenge, static_cast<std::uint64_t>(time(NULL))); }

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
    // Configured/estimated upload is KiB/s. Divide by two because an exit moves
    // every useful byte once on the onion side and once on the exterior side.
    const double usefulCapacity = static_cast<double>(
        thePrefs.GetMaxGraphUploadRate(true)) * 1024.0 * 8.0 / 2.0;
    uint64 processNow = 0;
    uint64 systemNow = 0;
    FILETIME created{}, exited{}, processKernel{}, processUser{};
    FILETIME idle{}, systemKernel{}, systemUser{};
    if (GetProcessTimes(GetCurrentProcess(), &created, &exited,
            &processKernel, &processUser) &&
        GetSystemTimes(&idle, &systemKernel, &systemUser)) {
        processNow =
            K6FileTimeValue(processKernel) + K6FileTimeValue(processUser);
        systemNow =
            K6FileTimeValue(systemKernel) + K6FileTimeValue(systemUser);
    }
    uint64 occupiedPreauth = 0;
    if (theApp.listensocket != NULL)
        occupiedPreauth = static_cast<uint64>(
            theApp.listensocket->GetK6PreAuthStats().active);
    m_scheduler.LT2RefreshEconomy(nowSeconds, active, usefulCapacity,
        processNow, systemNow, occupiedPreauth);
}

bool CLiveTunnel::K6EconomyAdmit(kad6::K6Service service)
{
    return m_scheduler.LT2EconomyAdmit(service, static_cast<uint64>(time(NULL)));
}

std::string CLiveTunnel::GetK6PrometheusMetrics()
{
    return m_metrics.ExportPrometheus(static_cast<uint64>(time(NULL)));
}

bool CLiveTunnel::StartK6ExitNotice(uint16 port, kad6::K6ExitNotice notice)
{
    return NodeIdentityIsPersistent() && m_scheduler.StartReleaseNotice(
        port, notice, MakeKad6HostCryptoHooks(), NodeIdentityPub());
}

void CLiveTunnel::StopK6ExitNotice() noexcept
{ m_scheduler.StopReleaseNotice(); }

K6ExitNoticeServerSnapshot CLiveTunnel::GetK6ExitNoticeSnapshot() const noexcept
{ return m_scheduler.GetReleaseNoticeSnapshot(); }

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
    CString path = thePrefs.GetMuleDirectory(EMULE_CONFIGDIR);
    if (path.IsEmpty()) return false;
    const TCHAR last = path[path.GetLength() - 1];
    if (last != _T('\\') && last != _T('/')) path += _T('\\');
    path += _T("kad6_quota_rsa.dat");
    if (!m_scheduler.LT2EnsureQuotaAuthority(
            nowSeconds, K6WideToUtf8(path), NodeIdentityPub(),
            MakeKad6HostCryptoHooks()))
        return false;
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
        ctx.circ->m_prevHopClient == NULL || !m_exitServices.LT4TicketSecretReady())
        return false;
    CUpDownClient* peer = ctx.circ->m_prevHopClient;
    CAddress address;
    if (peer->socket != NULL) address = peer->socket->GetPeerCAddress();
    if (address.GetType() == CAddress::None && peer->HasIPv6Address())
        address = peer->GetIPv6Address();
    if (address.GetType() == CAddress::None && !peer->IsIPv6OnlyEndpoint()
        && peer->GetConnectIP() != 0)
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
    const kad6::Kad6CryptoHooks crypto = MakeKad6HostCryptoHooks(); return crypto.hmac_sha256 && crypto.hmac_sha256(m_exitServices.LT4TicketSecret().data(),
        32, message.data(),
        message.size(), principal.data());
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
    std::vector<LiveOriginCircuitCandidate> candidates;
    candidates.reserve(m_circuitRegistry.Size());
    for (const auto& circuit : m_circuitRegistry.GetSnapshot()) {
        if (!circuit)
            continue;
        LiveOriginCircuitCandidate candidate;
        candidate.circuit_id = circuit->Id(); candidate.hop_count = circuit->HopCount();
        candidate.originator = circuit->m_role == CircuitRole::Originator; candidate.quota_issuer = circuit->m_k6QuotaIssuerCircuit;
        candidate.active = circuit->State() == CircuitState::Active; candidate.has_first_hop = circuit->m_firstHopClient != NULL;
        candidate.multicell = circuit->m_multicell_ok; candidate.authenticated = circuit->m_auth_ok;
        candidate.exit_signed_caps = circuit->m_exit_signed_caps; candidate.shaped = circuit->m_shaped_ok;
        candidate.strict3 = circuit->m_strict3; candidate.path_diverse = circuit->m_path_diverse;
        candidates.push_back(candidate);
    }
    return LiveTunnelPeerState::SelectOriginCircuit(
        candidates, requiredCaps, pinnedCircId, minimumHops,
        ESE_CAP_TUNNEL_STRICT3);
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
    uint32 reqId=0;PendingHandle pending=RegisterPending(reqId);
    kad6::K6Frame request;request.msg_type=msgType;request.request_id=reqId;request.body=body;
    uint32 caps=ESE_CAP_KAD6;size_t used=0;if(msgType==kad6::kK6MsgSourceBind){kad6::K6SourceBind bind;
        if(kad6::DecodeK6SourceBind(body.data(),body.size(),bind,&used)!=kad6::Kad6Status::Ok||used!=body.size())return false;
        request.flags=kad6::kK6FlagLegacyEd2k;if(bind.flags&kad6::kK6SourceStrict){request.flags|=kad6::kK6FlagStrict;caps|=ESE_CAP_TUNNEL_STRICT3|ESE_CAP_TUNNEL_SHAPED;}}
    else if(msgType==kad6::kK6MsgPublish){kad6::K6Publish publish;if(kad6::DecodeK6Publish(body.data(),body.size(),publish,&used)!=kad6::Kad6Status::Ok||used!=body.size())return false;
        request.flags=((publish.network_mask&kad6::kK6PublishNetKad2)?kad6::kK6FlagLegacyKad2:0)|((publish.network_mask&kad6::kK6PublishNetKad6)?kad6::kK6FlagNativeKad6:0);}
    else if(msgType==kad6::kK6MsgTargetTicketReq||msgType==kad6::kK6MsgDial)request.flags=kad6::kK6FlagLegacyEd2k;
    else caps|=ESE_CAP_KAD6_ECONOMY;
    std::vector<uint8_t> wire;
    if (kad6::EncodeK6Frame(request, wire) != kad6::Kad6Status::Ok) {
        std::vector<uint8_t> ignored;
        WaitPending(reqId, std::move(pending), 0, ignored, NULL);
        return false;
    }
    m_pendingRequests.Configure(pending,TUN_OP_KAD6_GATEWAY,caps,0,wire.data(),wire.size());
    EnqueueSendMsg(reqId,TUN_OP_KAD6_GATEWAY,wire.data(),wire.size(),caps,circId);
    std::vector<uint8_t> reply;
    if (!WaitPending(reqId, std::move(pending), timeoutMs, reply, NULL)) return false;
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
        for (const auto& circuit : m_circuitRegistry.GetSnapshot())
            if (circuit && circuit->Id() == targetCircId && circuit->HopCount() != 0) {
                target = circuit.get();
                break;
            }
        if (!target) return false;
        const uint8_t* targetPub = target->Hop(target->HopCount() - 1).pub_long;
        for (const auto& circuit : m_circuitRegistry.GetSnapshot()) {
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
    if (!m_scheduler.LT2BlindQuotaToken(certificate, token, blind))
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
    if (!m_scheduler.LT2FinalizeQuotaToken(
            certificate, blind, issued.blind_signatures[0], presentation))
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
    return m_scheduler.LT2ConsumeQuotaGrant(
        ctx.circ->Id(), context, static_cast<uint8_t>(service),
        static_cast<uint64>(time(NULL)), !IsK6PublicReleaseEnabled(),
        allocationId);
}

bool CLiveTunnel::QueueK6FairPayloadLocked(uint64 streamId, uint8 direction,
                                           std::vector<uint8_t>&& bytes,
                                           size_t creditBytes)
{
    return m_scheduler.QueueFairPayload(
        streamId, direction, std::move(bytes), creditBytes);
}

void CLiveTunnel::ReleaseK6FairStreamLocked(uint64 streamId)
{
    m_scheduler.ReleaseFairStream(streamId);
}

bool CLiveTunnel::ProcessK6FairTick()
{
    std::vector<LiveFairReady> ready;
    {
        CSingleLock pl(&m_pendingLock, TRUE);
        const uint64 maxBytes = (std::max<uint64>)(1,
            static_cast<uint64>(thePrefs.GetMaxGraphUploadRate(true)) * 1024ull / 200ull);
        ready = m_scheduler.PollFair(maxBytes, 128);
    }

    std::set<uint64> failed;
    for (const LiveFairReady& item : ready) {
        K6ExitStreamRuntime runtime;
        bool found = false;
        {
            CSingleLock pl(&m_pendingLock, TRUE);
            found=m_exitServices.LT5FindExit(item.stream_id,runtime)&&runtime.connected;
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
        m_metrics.Add(kad6::K6MetricFamily::ExitBytesTotal,
            item.direction == 0 ? 1 : 0, runtime.inbound ? 3 : 2, 0,
            static_cast<uint64>(item.bytes.size()), static_cast<uint64>(time(NULL)));
        m_metrics.Add(kad6::K6MetricFamily::TransportBytesTotal,
            0, item.direction == 0 ? 1 : 0, 0,
            static_cast<uint64>(item.bytes.size()), static_cast<uint64>(time(NULL)));
        {
            CSingleLock pl(&m_pendingLock, TRUE);
            m_scheduler.LT2RecordUsefulBytes(static_cast<uint64>(item.bytes.size()));
        }
        if (item.credit_bytes != 0)
            ConsumeK6ReceiveCredit(runtime.circ_id, item.stream_id, 0,
                item.credit_bytes, runtime.circuit, true);
    }
    for (uint64 streamId : failed) {
        CKad6ExitSocket* socket = NULL;
        {
            CSingleLock pl(&m_pendingLock, TRUE);
            K6ExitStreamRuntime stream;if(m_exitServices.LT5FindExit(streamId,stream))socket=stream.socket;
            ReleaseK6FairStreamLocked(streamId);
        }
        if (socket) socket->Disconnect(_T("Kad6 fair queue send failed"));
    }
    CSingleLock pl(&m_pendingLock, TRUE);
    return m_scheduler.HasFairWork();
}

bool CLiveTunnel::ApplyK6ServiceSwitch(kad6::K6Service service, bool enabled,
                                       uint32 drainSeconds)
{
    return CKad6OriginSocket::LT3ApplyServiceSwitch(*this, service, enabled, drainSeconds);
}

void CLiveTunnel::OnPeerDisconnected(CUpDownClient* peer)
{
    if(!peer)return;
    // Drop non-owning origin references before acquiring the circuit lock.
    {
        m_kadBridge.LT6RemoveDownloadActivationsByClient(reinterpret_cast<std::uintptr_t>(peer));
        CSingleLock pl(&m_pendingLock, TRUE);
        for(auto stream:m_exitServices.LT5OriginSnapshot())if(stream.second.client==peer){
            CKad6OriginSocket* socket=stream.second.socket;stream.second.client=NULL;
            m_exitServices.LT5UpdateOrigin(stream.first,socket,stream.second.generation,stream.second);}
    }
    CSingleLock lock(&m_lock, TRUE);
    for(const auto& c:m_circuitRegistry.GetSnapshot()){
        if(!c||c->State()==CircuitState::Destroyed)continue;
        const bool lostFirst=c->m_firstHopClient==peer,lostPrev=c->m_prevHopClient==peer,lostNext=c->m_nextHopClient==peer;
        const bool lostPending=std::find(c->m_pendingHopClients.begin(),c->m_pendingHopClients.end(),peer)!=c->m_pendingHopClients.end();
        LivePeerDisconnectView view;
        view.relay=c->m_role==CircuitRole::Relay;view.lost_first=lostFirst;view.lost_previous=lostPrev;
        view.lost_next=lostNext;view.lost_pending=lostPending;
        view.has_previous_survivor=c->m_prevHopClient&&c->m_prevHopClient!=peer;
        view.has_next_survivor=c->m_nextHopClient&&c->m_nextHopClient!=peer;
        view.has_next_circuit=c->m_nextCircId!=0;
        const auto plan=LiveTunnelPeerState::PlanDisconnect(view);if(!plan.affected)continue;
        // Notify a surviving relay half before keys are wiped.
        uint8_t destroy[CELL_TOTAL_BYTES];
        if(view.relay){
            if(plan.notify_next&&CellPack(c->m_nextCircId,CELL_DESTROY,NULL,0,destroy))SendCellToPeer(c->m_nextHopClient,destroy);
            if(plan.notify_previous&&CellPack(c->Id(),CELL_DESTROY,NULL,0,destroy))SendCellToPeer(c->m_prevHopClient,destroy);
        }
        if(plan.clear_first)c->m_firstHopClient=NULL;if(plan.clear_previous)c->m_prevHopClient=NULL;
        if(plan.clear_next)c->m_nextHopClient=NULL;if(plan.clear_pending)c->m_pendingHopClients.clear();
        if(plan.destroy){TransitionCircuitDestroyed(c);c->WipeKeys();}
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
    MainThreadReq req;
    req.op = MT_SEND;
    req.payload.assign(payload, payload + payloadLen);
    (void)m_scheduler.Enqueue(std::move(req));
}

// v8.1 A4 - marshal a whole logical message for pinned send on the main thread.
void CLiveTunnel::EnqueueSendMsg(uint32_t req_id, uint8_t sub_cmd,
                                 const uint8_t* msg, size_t msgLen,
                                 uint32_t requiredExitCaps,
                                 uint32_t pinnedCircId)
{
    MainThreadReq req;
    req.op     = MT_SEND_MSG;
    req.reqId  = req_id;
    req.subCmd = sub_cmd;
    req.requiredExitCaps = requiredExitCaps;
    req.pinnedCircId = pinnedCircId;
    if (msg && msgLen) req.payload.assign(msg, msg + msgLen);
    if (!m_scheduler.Enqueue(std::move(req)) && req_id != 0) SignalReply(req_id, NULL, 0, 0);
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
            if ((frame.flags & kad6::kK6FlagStrict) != 0)
                minimumHops = 3;
            else if (quotaMessage)
                minimumHops = 1; // dedicated issuer circuit; never carries user work
        }
    }
    CSingleLock lock(&m_lock, TRUE);
    if (m_circuitRegistry.Empty()) return 0;

    // Pick one Active circuit, advancing the round-robin cursor once per
    // message. (SendThrough advances it once per cell -> wrong for multi-cell.)
    std::shared_ptr<CLiveCircuit> chosen;
    size_t tries = m_circuitRegistry.Size();
    while (tries-- > 0) {
        const std::shared_ptr<CLiveCircuit> c =
            m_circuitRegistry.NextRoundRobin();
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
            TransitionCircuitDestroyed(chosen);
            return chosen->Id();
        }
        if (!SendCellToPeer(chosen->m_firstHopClient, cell))
            chosen->m_sendQ.Push(cell);   // transient socket busy -> queue
    }
    return chosen->Id();
}

// v9.2 MOD-1.2 - coordinator adapters for the extracted pending domain.
// Entropy remains a coordinator concern; collision rejection, request
// lifetime, waits, and exactly-once completion are module-owned.
CLiveTunnel::PendingHandle CLiveTunnel::RegisterPending(uint32_t& req_id)
{
    PendingHandle pending = m_pendingRequests.Register([&]() -> uint32_t {
        uint8_t r[4];
        SecureRandomBytes(r, 4);
        return (uint32_t)r[0] | ((uint32_t)r[1] << 8)
             | ((uint32_t)r[2] << 16) | ((uint32_t)r[3] << 24);
    });
    req_id = pending.request_id();
    return pending;
}

bool CLiveTunnel::WaitPending(uint32_t req_id, PendingHandle pending,
                              uint32_t timeoutMs,
                              std::vector<uint8_t>& outReply,
                              uint32_t* outResult,
                              uint32_t* outCircuitId)
{
    UNREFERENCED_PARAMETER(req_id);
    if (outCircuitId) *outCircuitId = 0;
    eSELive::LiveTunnelPending::Outcome outcome;
    if (!m_pendingRequests.Wait(std::move(pending), timeoutMs, outcome))
        return false;

    outReply = std::move(outcome.reply);
    if (outResult) *outResult = outcome.result;
    if (outCircuitId) *outCircuitId = outcome.circuit_id;
    return true;
}

void CLiveTunnel::SignalReply(uint32_t req_id, const uint8_t* reply,
                              size_t replyLen, uint32_t result)
{
    m_pendingRequests.Complete(req_id, reply, replyLen, result);
}

uint32_t CLiveTunnel::RequestTestCircuit(int hops, uint32_t timeoutMs)
{
    uint32_t reqId;
    PendingHandle pr = RegisterPending(reqId);   // generates a unique req_id
    MainThreadReq req;
    req.op = hops == 3 ? MT_BUILD_3HOP
           : hops == 2 ? MT_BUILD_2HOP
                       : MT_BUILD_1HOP;
    req.reqId = reqId;
    if (!m_scheduler.Enqueue(std::move(req))) SignalReply(reqId, NULL, 0, 0);
    std::vector<uint8_t> dummy;
    uint32_t circId = 0;
    WaitPending(reqId, std::move(pr), timeoutMs, dummy, &circId);
    return circId;   // 0 on timeout / build failure
}

bool CLiveTunnel::RequestK6ServiceSwitch(kad6::K6Service service, bool enabled,
                                         uint32 drainSeconds, uint32 timeoutMs)
{
    if (static_cast<size_t>(service) >= static_cast<size_t>(kad6::K6Service::Count))
        return false;
    uint32_t reqId = 0;
    PendingHandle pending = RegisterPending(reqId);
    MainThreadReq request;
    request.op = MT_K6_SERVICE_SWITCH;
    request.reqId = reqId;
    request.k6Service = service;
    request.k6Enable = enabled;
    request.k6DrainSeconds = (std::min)(drainSeconds, kad6::kK6MaxDrainSeconds);
    if (!m_scheduler.Enqueue(std::move(request))) SignalReply(reqId, NULL, 0, 0);
    std::vector<uint8_t> ignored;
    uint32_t result = 0;
    return WaitPending(reqId, std::move(pending), timeoutMs, ignored, &result) && result == 1;
}

bool CLiveTunnel::RequestK6PublicRelease(
    bool enable, const kad6::K6ReleaseEvidence* evidence,
    uint32 drainSeconds, uint32 timeoutMs)
{
    uint32_t reqId = 0;
    PendingHandle pending = RegisterPending(reqId);
    MainThreadReq request;
    request.op = MT_K6_RELEASE_SWITCH;
    request.reqId = reqId;
    request.k6Enable = enable;
    request.k6DrainSeconds = (std::min)(drainSeconds,
        kad6::kK6MaxDrainSeconds);
    request.k6HasReleaseEvidence = evidence != NULL;
    if (evidence) request.k6ReleaseEvidence = *evidence;
    if (!m_scheduler.Enqueue(std::move(request))) SignalReply(reqId, NULL, 0, 0);
    std::vector<uint8_t> ignored;
    uint32_t result = 0;
    return WaitPending(reqId, std::move(pending), timeoutMs, ignored, &result) && result == 1;
}

void CLiveTunnel::ProcessMainThreadWork()
{
    // MAIN THREAD. Drain the marshaled-work queue. Bounded per call so a
    // burst of requests cannot stretch a single Kad tick.
    for (size_t budget = 0;
         budget < LiveTunnelScheduler::kDefaultDrainBudget; ++budget) {
        MainThreadReq req;
        if (!m_scheduler.TryTake(req)) break;
        try {
            switch (req.op) {
            case MT_SEND:
                if (!req.payload.empty())
                    SendThrough(req.payload.data(), req.payload.size());
                break;
            case MT_SEND_MSG: {
                // A4 - pin the whole message to one circuit; record which one
                // in the pending domain so Tick() can retry it on circuit death.
                if (req.k6StreamId != 0) {
                    CSingleLock pl(&m_pendingLock, TRUE);
                    K6OriginStreamRuntime stream;if(!m_exitServices.LT5FindOrigin(req.k6StreamId,stream)||stream.generation!=req.k6Generation)
                        break; // stream was closed while this bounded item waited.
                }
                const uint32_t cid = SendMessagePinned(
                    req.reqId, req.subCmd,
                    req.payload.empty() ? NULL : req.payload.data(),
                    req.payload.size(), req.requiredExitCaps, req.pinnedCircId);
                m_pendingRequests.SetCircuit(req.reqId, cid);
                CKad6OriginSocket* failedK6Socket = NULL;
                {
                    CSingleLock pl(&m_pendingLock, TRUE);
                    if (req.k6StreamId != 0) {
                        K6OriginStreamRuntime stream;
                        if(m_exitServices.LT5FindOrigin(req.k6StreamId,stream)&&stream.generation==req.k6Generation&&cid!=0&&
                            stream.queued_tx_bytes>=req.k6DataBytes&&
                            stream.flow.AcceptFrame(0, req.k6Sequence,
                                req.k6DataBytes) == kad6::Kad6Status::Ok) {
                            stream.queued_tx_bytes-=req.k6DataBytes;
                            const uint64 now = static_cast<uint64>(time(NULL));
                            const uint64 idle=(stream.dial.idle_timeout_ms+999u)/1000u;
                            stream.last_activity=now;stream.idle_deadline=now+idle;
                            if(!m_exitServices.LT5UpdateOrigin(req.k6StreamId,stream.socket,stream.generation,stream))failedK6Socket=stream.socket;
                        } else if(stream.generation==req.k6Generation){
                            failedK6Socket=stream.socket;
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
            p.has_ipv4  = !c->IsIPv6OnlyEndpoint()
                       && c->GetIP() != 0
                       && c->GetIP() != 0xFFFFFFFFu;
            if (c->HasIPv6Address()) {
                p.address = c->GetIPv6Address().ToString();
            } else {
                p.address = CAddress::FromIPv4NetworkOrder(c->GetIP()).ToString();
            }
            all.push_back(p);
        }
    }
    m_metrics.ReplacePeers(std::move(all), tunnelingCount);
}

void CLiveTunnel::GetPeersSnapshot(std::vector<PeerSnapshot>& outAll,
                                   size_t& outTunnelingCount) const
{
    m_metrics.GetPeers(outAll, outTunnelingCount);
}

// === v0.71 C — Data plane: CELL_RELAY delivery + tunnel ping =================
// Sub-protocol carried inside the AEAD-decrypted CELL_RELAY payload:
//   [0]      sub_cmd (TunnelOpCmd: PING=0x01, PING_REPLY=0x02)
//   [1..4]   req_id (uint32 LE) — correlates request to reply
//   [5..6]   text_len (uint16 LE)
//   [7..N]   text bytes (UTF-8)
// V correlates a reply to its blocked caller by req_id via SignalReply and
// LiveTunnelPending. Exit-side
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
            const uint64_t rkey = LiveRequestKey(circ->Id(), req_id);
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
        // v8.1 D1 - a tunneled DISCOVERY search reply (KAD_RESULT_V2) has no pending waiter
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
            m_metrics.ObserveMeanRtt(static_cast<uint32_t>(rtt));
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
    kad6::K6Frame plan;
    return m_kadBridge.LT3PlanSearchReply(req_id, wire, plan) &&
        CKad6OriginSocket::LT3ExecuteSearchReply(*this, circ, plan, wire);
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
    return m_relayDispatcher.DispatchExitPlain(circ, plain, plainLen, *this);
}

void CLiveTunnel::TransitionCircuitDestroyed(
    const std::shared_ptr<CLiveCircuit>& circ)
{
    if (!circ)
        return;

    const uint32_t circuitId = circ->Id();
    {
        CSingleLock pending(&m_pendingLock, TRUE);
        (void)m_exitServices.AbortCircuit(circuitId);
        for (auto entry = m_reassembly.begin();
             entry != m_reassembly.end();) {
            if (static_cast<uint32_t>(entry->first >> 32) == circuitId)
                entry = m_reassembly.erase(entry);
            else
                ++entry;
        }
    }
    m_circuitRegistry.Transition(circ, CircuitState::Destroyed);
}

bool CLiveTunnel::IsRelayMultiCell(uint8_t subCommand) const
{
    return subCommand >= TUN_MULTICELL_OP_MIN;
}

bool CLiveTunnel::ParseRelaySubHeader(
    const uint8_t* plain, size_t plainLength,
    uint8_t& subCommand, uint32_t& requestId,
    uint16_t& bodyLength, const uint8_t*& body) const
{
    return ParseSubHeader(
        plain, plainLength, subCommand, requestId, bodyLength, body);
}

bool CLiveTunnel::ParseRelayFragmentHeader(
    const uint8_t* body, size_t bodyLength,
    uint16_t& fragmentIndex, uint16_t& fragmentCount,
    uint32_t& messageLength, const uint8_t*& fragmentData,
    size_t& fragmentDataLength) const
{
    return ParseFragHeader(
        body, bodyLength, fragmentIndex, fragmentCount, messageLength,
        fragmentData, fragmentDataLength);
}

LiveRelayFragmentResult CLiveTunnel::IngestRelayFragment(
    uint32_t circuitId, uint32_t requestId,
    uint16_t fragmentIndex, uint16_t fragmentCount,
    uint32_t messageLength, const uint8_t* fragmentData,
    size_t fragmentDataLength, std::vector<uint8_t>& completedMessage)
{
    CSingleLock pending(&m_pendingLock, TRUE);
    const uint64_t key = LiveRequestKey(circuitId, requestId);
    ReassemblyEntry& entry = m_reassembly[key];
    if (!entry.started)
        entry.first_seen_tick = GetTickCount();

    const ReassemblyResult result = ReassemblyIngest(
        entry, fragmentIndex, fragmentCount, messageLength,
        fragmentData, fragmentDataLength);
    if (result == ReassemblyResult::Incomplete)
        return LiveRelayFragmentResult::Incomplete;
    if (result == ReassemblyResult::Error) {
        m_reassembly.erase(key);
        return LiveRelayFragmentResult::Rejected;
    }

    completedMessage = std::move(entry.message);
    m_reassembly.erase(key);
    return LiveRelayFragmentResult::Complete;
}

bool CLiveTunnel::DispatchRelayExit(const LiveTunnelRequestCtx& context)
{
    return m_exitServices.Dispatch(context.sub_cmd, context);
}

// === v8.1 A6 - deferred exit operations ==================================
// BeginExitOperation registers a pending reply; CompleteExitOperation sends it
// when the handler's work finishes (immediately, or later from a callback in
// Sprint B). Both run on the main thread (OnCellReceived / Kad callbacks).

bool CLiveTunnel::BeginExitOperation(const TunnelRequestCtx& ctx, uint8_t reply_op)
{
    if (!ctx.circ)
        return false;
    CSingleLock pl(&m_pendingLock, TRUE);
    return m_exitServices.Begin(
        ctx.circ, ctx.req_id, reply_op, GetTickCount());
}

bool CLiveTunnel::CompleteExitOperation(uint32_t circ_id, uint32_t req_id,
                                        const uint8_t* payload, size_t payloadLen)
{
    LiveExitServices::Completion completion;
    {
        CSingleLock pl(&m_pendingLock, TRUE);
        if (!m_exitServices.TakeCompletion(
                circ_id, req_id, completion))
            return false;
    }
    // Rebuild a minimal ctx and reuse SendReply (A2.4) for the fragmented reply.
    TunnelRequestCtx ctx;
    ctx.circ   = completion.circuit;
    ctx.req_id = req_id;
    return SendReply(ctx, completion.reply_op, payload, payloadLen);
}

bool CLiveTunnel::SendExitOperationPart(uint32_t circ_id, uint32_t req_id,
                                        const uint8_t* payload, size_t payloadLen)
{
    LiveExitServices::Completion completion;
    {
        CSingleLock pl(&m_pendingLock, TRUE);
        if (!m_exitServices.FindPart(
                circ_id, req_id, completion))
            return false;
    }
    TunnelRequestCtx ctx;
    ctx.circ = completion.circuit;
    ctx.req_id = req_id;
    return SendReply(ctx, completion.reply_op, payload, payloadLen);
}

void CLiveTunnel::AbortExitOperation(uint32_t circ_id, uint32_t req_id)
{
    CSingleLock pl(&m_pendingLock, TRUE);
    (void)m_exitServices.Abort(circ_id, req_id);
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

    if (!BeginExitOperation(ctx, TUN_OP_KAD_RESULT_V2))
        return;

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
        CString kw = EseUtf8CString(keyword);
        // v8.1 D1 - forceDirect=true: the exit MUST query Kad from its OWN IP,
        // never re-enter the tunnel branch (would cascade out our circuit).
        m_kadBridge.SearchStreams(kw, &job.kadSearchIds, /*forceDirect*/true);
    } catch (...) {}

    CSingleLock pl(&m_pendingLock, TRUE);
    m_searchJobs[LiveRequestKey(job.circ_id, job.req_id)] = std::move(job);
}

// B7 - exit handler for TUN_OP_KAD_CANCEL: V aborts an in-flight search by
// req_id. Stop the CSearch(es), drop the deferred op, erase the job. No reply.
void CLiveTunnel::ExitHandle_KadCancel(const TunnelRequestCtx& ctx)
{
    if (!ctx.circ) return;
    const uint64_t key = LiveRequestKey(ctx.circ->Id(), ctx.req_id);
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
    if (!thePrefs.GetEseV9Experimental() || (g_uEseCapsRuntime & ESE_CAP_KAD6) == 0 || !ctx.circ || !ctx.body || ctx.bodyLen == 0) return;
    kad6::K6Frame plan;
    if (!m_kadBridge.LT3PlanExitGateway(ctx.req_id, ctx.body, ctx.bodyLen, plan)) {
        m_metrics.Add(kad6::K6MetricFamily::AuthFailTotal, 2, 0, 0, 1, static_cast<uint64>(time(NULL)));
        return;
    }
    CKad6OriginSocket::LT3ExecuteExitGateway(*this, ctx, plan);
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
        m_metrics.Add(kad6::K6MetricFamily::SourceCandidateTotal,
            0, 1, 0, 1, static_cast<uint64>(time(NULL)));
        return false;
    }

    CSingleLock pl(&m_pendingLock, TRUE);
    auto job = m_searchJobs.find(LiveRequestKey(circuitId, requestId));
    if (job == m_searchJobs.end() ||
        job->second.searchKind != kad6::kK6SearchKindSourceHash ||
        job->second.sourceCandidates.size() >= job->second.maxResults)
        return false;
    for (const auto& old : job->second.sourceCandidates) {
        if (old.userHash == candidate.userHash && old.endpoint.addr == candidate.endpoint.addr &&
            old.endpoint.tcp_port == candidate.endpoint.tcp_port) {
            m_metrics.Add(kad6::K6MetricFamily::SourceCandidateTotal,
                0, 1, 0, 1, static_cast<uint64>(time(NULL)));
            return false;
        }
    }
    candidate.score = m_peerState.ApplySourceScore(candidate.score,
        BuildLiveSourceEndpointKey(candidate.endpoint, candidate.networkOrigin));
    job->second.sourceCandidates.push_back(std::move(candidate));
    const size_t count = job->second.sourceCandidates.size();
    const double elapsed = static_cast<double>(GetTickCount() - job->second.started);
    if (!job->second.firstSourceMetric) {
        job->second.firstSourceMetric = true;
        m_metrics.Observe(kad6::K6MetricFamily::SearchLatencyMs,
            0, 0, 0, elapsed, static_cast<uint64>(time(NULL)));
    }
    if (count >= 5 && !job->second.fiveSourceMetric) {
        job->second.fiveSourceMetric = true;
        m_metrics.Observe(kad6::K6MetricFamily::SearchLatencyMs,
            1, 0, 0, elapsed, static_cast<uint64>(time(NULL)));
    }
    m_metrics.Add(kad6::K6MetricFamily::SourceCandidateTotal,
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
        m_metrics.Add(kad6::K6MetricFamily::SourceCandidateTotal,
            1, 1, 0, 1, now);
        return false;
    }
    if (kad6::K6SourceRecordCheckFresh(record, now) != kad6::Kad6Status::Ok) {
        m_metrics.Add(kad6::K6MetricFamily::SourceStaleTotal,
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
    auto job = m_searchJobs.find(LiveRequestKey(circuitId, requestId));
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
        candidate.score = m_peerState.ApplySourceScore(candidate.score,
            BuildLiveSourceEndpointKey(candidate.endpoint, candidate.networkOrigin));

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
            m_metrics.Add(kad6::K6MetricFamily::SourceCandidateTotal,
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
                m_metrics.Observe(kad6::K6MetricFamily::SearchLatencyMs,
                    0, 1, 0, elapsed, now);
            }
            if (count >= 5 && !job->second.fiveSourceMetric) {
                job->second.fiveSourceMetric = true;
                m_metrics.Observe(kad6::K6MetricFamily::SearchLatencyMs,
                    1, 1, 0, elapsed, now);
            }
            m_metrics.Add(kad6::K6MetricFamily::SourceCandidateTotal,
                1, 0, 0, 1, now);
        }
    }
    return inserted;
}

void CLiveTunnel::OnKad6SourceLookupRpc(uint8_t alpha, uint8_t result)
{
    const uint8_t alphaBucket = alpha <= 3 ? 0 : (alpha <= 5 ? 1 : 2);
    if (result > 3) result = 2;
    m_metrics.Add(kad6::K6MetricFamily::SearchRpcTotal,
        1, alphaBucket, result, 1, static_cast<uint64>(time(NULL)));
}

std::string CLiveTunnel::K6BinaryKey(const uint8_t* b,size_t n){return CKad6OriginSocket::LT4BinaryKey(b,n);}
bool CLiveTunnel::EnsureK6SourceEpochsLoaded()
{
    return CKad6OriginSocket::LT3EnsureEpochsLoaded(*this);
}

std::string CLiveTunnel::K6ShadowKey(const kad6::K6SourceLease& l){return CKad6OriginSocket::LT4ShadowKey(&l);}

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
    SendK6GatewayResponse(ctx, kad6::kK6MsgQuotaKey, m_scheduler.LT2QuotaCertificateWire());
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
    else if (!K6QuotaPrincipal(ctx, principal, prefix48, asn))
        response.status = kad6::K6QuotaStatus::PolicyDenied;
    else
        m_scheduler.LT2IssueQuota(
            request, principal, prefix48, asn, now,
            (std::max<uint64>)(1, K6ShapeNowUs() / 1000u), response);
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
    kad6::K6QuotaIssuerCertificate certificate;
    if (!EnsureK6QuotaAuthority(now))
        result.status = kad6::K6QuotaStatus::CryptoFailure;
    else if (kad6::DecodeK6QuotaIssuerCertificate(
                 presentation.issuer_certificate.data(),
                 presentation.issuer_certificate.size(), certificate, &consumed) !=
                 kad6::Kad6Status::Ok || consumed != presentation.issuer_certificate.size())
        result.status = kad6::K6QuotaStatus::InvalidProof;
    else
        m_scheduler.LT2PresentQuota(
            presentation,
            K6QuotaIssuerTrusted(certificate.issuer_node_pub.data()),
            ctx.circ->Id(), now, MakeKad6HostCryptoHooks(), result);
    std::vector<uint8_t> body;
    if (kad6::EncodeK6QuotaPresentationResult(result, body) != kad6::Kad6Status::Ok)
        AbortExitOperation(ctx.circ->Id(), ctx.req_id);
    else
        SendK6GatewayResponse(ctx, kad6::kK6MsgQuotaStatus, body);
}
void CLiveTunnel::ExitHandle_Kad6SourceBind(const TunnelRequestCtx& c,const kad6::K6Frame& f){CKad6OriginSocket::LT4SourceBind(*this,c,f);}

void CLiveTunnel::ExitHandle_Kad6SourceUnbind(const TunnelRequestCtx& ctx,
                                              const kad6::K6Frame& frame)
{
    CKad6OriginSocket::LT3SourceUnbind(*this, ctx, frame);
}
void CLiveTunnel::ExitHandle_Kad6Publish(const TunnelRequestCtx& c,const kad6::K6Frame& f){CKad6OriginSocket::LT4Publish(*this,c,f);}

void CLiveTunnel::ExitHandle_Kad6Unpublish(const TunnelRequestCtx& ctx,
                                           const kad6::K6Frame& frame)
{
    CKad6OriginSocket::LT3Unpublish(*this, ctx, frame);
}

std::string CLiveTunnel::K6AuthorizedTargetKey(uint32 c,uint32 r,const kad6::Hash16& id){return CKad6OriginSocket::LT4AuthorizedKey(c,r,&id);}

bool CLiveTunnel::K6AllowTicketTarget(void*,kad6::Byte s,const kad6::K6Endpoint& e){return CKad6OriginSocket::LT4AllowTarget(s,e);}
bool CLiveTunnel::K6ConsumeTicket(void* c,const kad6::K6TargetTicket& t){return CKad6OriginSocket::LT4ConsumeTicket(c,t);}

kad6::K6TargetPolicy CLiveTunnel::K6TicketPolicy(){return CKad6OriginSocket::LT4TicketPolicy(*this);}

bool CLiveTunnel::IssueK6RuntimeTicket(const K6AuthorizedTarget& t,uint64 b,kad6::K6Provenance p,uint64 s,uint64 st,uint64 q,std::vector<uint8_t>& w){return CKad6OriginSocket::LT4IssueTicket(*this,&t,b,p,s,st,q,w);}
void CLiveTunnel::ExitHandle_Kad6TargetTicketReq(const TunnelRequestCtx& c,const kad6::K6Frame& f){CKad6OriginSocket::LT4TargetTicketReq(*this,c,f);}

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

bool CLiveTunnel::HasK6ServingLeases() const
{
    return CKad6OriginSocket::LT3HasServingLeases(*this);
}

bool CLiveTunnel::MarkK6SourceServingLocked(uint64 sourceLeaseId,
                                            kad6::K6CohortBackend& backend)
{
    return CKad6OriginSocket::LT3MarkServing(*this, sourceLeaseId, backend);
}

bool CLiveTunnel::AllowKad6ShadowPublishContact(uint64 id,const uint8_t* c){return CKad6OriginSocket::LT4AllowShadow(*this,id,c);}
void CLiveTunnel::OnKad6ShadowPublishSent(uint64 id){CKad6OriginSocket::LT4ShadowSent(*this,id);}
void CLiveTunnel::OnKad6ShadowPublishAck(uint64 id,uint8_t load,bool response){CKad6OriginSocket::LT4ShadowAck(*this,id,load,response);}
void CLiveTunnel::OnKad6ShadowVerified(uint64 id){CKad6OriginSocket::LT4ShadowVerified(*this,id);}
void CLiveTunnel::OnKad6NativePublishAck(uint64 id,kad6::K6StoreStatus s,uint8_t load,uint64 epoch){CKad6OriginSocket::LT4NativeAck(*this,id,s,load,epoch);}
void CLiveTunnel::RefreshK6NativePublishes(uint64 now){CKad6OriginSocket::LT4RefreshNative(*this,now);}

void CLiveTunnel::QueueK6ShadowRefreshes(uint64 nowSeconds)
{
    CKad6OriginSocket::LT3QueueRefreshes(*this, nowSeconds);
}
void CLiveTunnel::StartDueK6ShadowPublishes(uint64 now){CKad6OriginSocket::LT4StartShadow(*this,now);}
void CLiveTunnel::StartK6VisibilityProbes(uint64 now){CKad6OriginSocket::LT4StartProbes(*this,now);}

void CLiveTunnel::SweepK6SourceLeases(const std::set<uint32_t>& activeCircuits,
                                      const std::set<uint32_t>& teardownQueue,
                                      uint64 nowSeconds)
{
    CKad6OriginSocket::LT3SweepLeases(*this, activeCircuits, teardownQueue, nowSeconds);
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
        LiveTunnelAuthorizedTarget target;
        (void)m_exitServices.LT4FindAuthorizedTarget(
            K6AuthorizedTargetKey(ctx.circ->Id(), sourceRequestId, resultId),
            static_cast<uint64>(time(NULL)), target);
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
        for (const auto& c : m_circuitRegistry.GetSnapshot()) {
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
                                    uint32_t upstreamIP, uint16_t upstreamPort,
                                    const uint32_t* ips, const uint16_t* ports,
                                    uint8_t count)
{
    if (upstreamIP == 0 || upstreamPort == 0 ||
        count == 0 || ips == NULL || ports == NULL) return;
    if (count > 16) count = 16;   // ESE_LIVE_MAX_PEER_LIST; also bounds the single cell
    const std::string hex = LiveStreamKeyHex(streamKey);

    std::vector<uint32_t> targets;
    {
        CSingleLock pl(&m_pendingLock, TRUE);
        auto it = m_exitLiveSubs.find(hex);
        if (it == m_exitLiveSubs.end() || it->second.circuits.empty() ||
            it->second.bIP != upstreamIP ||
            it->second.bPort != upstreamPort) return;
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
        for (const auto& c : m_circuitRegistry.GetSnapshot()) {
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
            if (LiveTunnelScheduler::DeadlineReached32(now, it->second.deadline)) {
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
                    foundByNetwork[LiveTunnelKadBridge::NetworkIndex(
                        source.networkOrigin, kad6::kK6NetOriginKad6)] = true;
                const bool startedByNetwork[2] = {
                    due[i].kad2LookupStarted, due[i].kad6LookupStarted};
                const uint8_t masks[2] = {kad6::kK6NetMaskKad2, kad6::kK6NetMaskKad6};
                const uint64_t metricNow = static_cast<uint64_t>(time(NULL));
                for (uint8_t network = 0; network < 2; ++network)
                    if ((due[i].networkMask & masks[network]) != 0)
                        m_metrics.Add(kad6::K6MetricFamily::SearchTotal,
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
            const std::vector<size_t> ranked =
                LiveTunnelPeerState::RankSources(job.sourceCandidates.size(),
                    [&job](size_t index) { return job.sourceCandidates[index].score; });
            const uint16_t limit = (uint16_t)(std::min<size_t>)(
                ranked.size(), (size_t)job.maxResults);
            for (uint16_t i = 0; i < limit; ++i) {
                const TunnelSearchJob::SourceCandidate& source =
                    job.sourceCandidates[ranked[i]];
                kad6::K6SearchResult result;
                result.result_id = source.userHash;
                result.result_kind = kad6::kK6SearchKindSourceHash;
                result.network_origin = source.networkOrigin;

                LiveTunnelAuthorizedTarget authorized;
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
                m_exitServices.LT4AuthorizeTarget(
                    K6AuthorizedTargetKey(
                        job.circ_id, job.req_id, authorized.result_id),
                    authorized);
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
            LiveTunnelAuthorizedTarget authorized;
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
            m_exitServices.LT4AuthorizeTarget(
                K6AuthorizedTargetKey(
                    job.circ_id, job.req_id, authorized.result_id),
                authorized);
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
    m_kadBridge.StopSearches(job.kadSearchIds);
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
    if (!BeginExitOperation(ctx, TUN_OP_ECHO_LARGE_REPLY))
        return;
    CompleteExitOperation(ctx.circ->Id(), ctx.req_id, echo.data(), echo.size());
}

bool CLiveTunnel::ShouldRouteThroughTunnel(const wchar_t* keywordOrNull, uint8_t opClass) const
{
    return m_kadBridge.ShouldRouteThroughTunnel(keywordOrNull, opClass);
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
    PendingHandle pr = RegisterPending(req_id);
    std::vector<uint8_t> body;
    const bool canonical = HasActiveCircuitWithExitCaps(ESE_CAP_KAD6);
    uint8_t op = TUN_OP_KAD_SEARCH_V2;
    uint32_t requiredCaps = 0;
    uint32_t pinnedCircuit = 0;
    if (canonical) {
        if (!EseBuildK6SearchStartFrame(keywordLower, req_id, body)) {
            std::vector<uint8_t> ignored;
            WaitPending(req_id, std::move(pr), 0, ignored, NULL);
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
            WaitPending(req_id, std::move(pr), 0, ignored, NULL);
            return false;
        }
        if (K6CircuitHasExitCaps(pinnedCircuit, ESE_CAP_KAD6_ECONOMY, 2) &&
            !K6AcquireAnonymousQuota(pinnedCircuit, kad6::K6QuotaService::Control,
                quotaOperation.msg_type, quotaOperation.body,
                (std::max<uint32>)(3, timeoutMs / 2)) && IsK6PublicReleaseEnabled()) {
            std::vector<uint8_t> ignored;
            WaitPending(req_id, std::move(pr), 0, ignored, NULL);
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

    m_pendingRequests.Configure(
        pr, op, requiredCaps, canonical ? 0 : TUN_SEND_RETRIES,
        body.data(), body.size());
    EnqueueSendMsg(req_id, op, body.data(), body.size(), requiredCaps,
        pinnedCircuit);

    std::vector<uint8_t> reply;
    if (!WaitPending(req_id, std::move(pr), timeoutMs, reply, NULL))
        return false;
    resultsJsonOut = SB_ParseSearchResultsToJson(reply);
    return true;
}

// v8.1 Sprint C (C1) — send TUN_OP_LIVE_SUBSCRIBE and block for the SUB_ACK.
// Mirror of TunneledKadSearch: register the waiter first, pin the message to
// one circuit (A4), wait for the exit's reply. Returns true iff status == 0
// (the exit forwarded our subscribe to the broadcaster). BLOCKING — call off
// the main thread.















// Fire-and-forget legacy subscribe; an unmatched ACK is intentionally ignored.


// Non-blocking search; replies feed the directory without a pending waiter.

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
    m_metrics.RecordCellSent(size);
    return true;
}

bool CLiveTunnel::EnsureK6ShapeTimerLocked()
{
    if (m_scheduler.HasClass5Timer())
        return true;
    const UINT_PTR token = ::SetTimer(NULL, 0, 10, K6Class5TimerProc);
    if (token == 0)
        return false;
    if (!m_scheduler.PublishClass5Timer(
            static_cast<std::uintptr_t>(token))) {
        ::KillTimer(NULL, token);
        return false;
    }
    return true;
}

void CLiveTunnel::StopK6ShapeTimerLocked()
{
    const std::uintptr_t token = m_scheduler.ReleaseClass5Timer();
    if (token != 0)
        ::KillTimer(NULL, static_cast<UINT_PTR>(token));
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

    if (m_scheduler.HasShapedLink(circ->Id()))
        return m_scheduler.ShapedLinkMatches(
            circ->Id(), outputLayers, bucketKiB);

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

    LiveShapedLinkConfig config;
    config.circ_id = circ->Id();
    config.bucket_kib = bucketKiB;
    config.output_layers = outputLayers;
    config.reservoir_ms = reservoirMs;
    config.phase = phase;
    config.nonce_epoch_high_base = eseRdU32LE(nonceRoot) & 0x7FFFFFFFu;
    if (config.nonce_epoch_high_base == 0) config.nonce_epoch_high_base = 1;
    config.padding_sequence = paddingSequence;
    config.idle_tail_epochs = static_cast<uint8_t>(1 + random[18] % 3);
    const uint64_t nowUs = K6ShapeNowUs();
    config.now_us = nowUs;
    if (!m_scheduler.ConfigureShapedLink(config))
        return false;

    if (!EnsureK6ShapeTimerLocked()) {
        m_scheduler.RemoveShapedLink(circ->Id());
        return false;
    }
    AddDebugLogLine(false,
        _T("Kad6 K6-6: class-5 link active circ=0x%08x hop=%u bucket=%uKiB/s reservoir=%u records"),
        circ->Id(), static_cast<unsigned>(circ->m_remoteHopIndex), bucketKiB,
        static_cast<unsigned>(m_scheduler.ShapedReservoirCapacity(circ->Id())));
    return true;
}

bool CLiveTunnel::QueueK6ShapedRecordLocked(const std::shared_ptr<CLiveCircuit>& circ,
                                            uint64_t streamId,
                                            LiveShapedQueuedRecord&& record)
{
    if (!circ || streamId == 0) return false;
    if (!m_scheduler.QueueShapedRecord(
            circ->Id(), streamId, std::move(record), K6ShapeNowUs())) {
        circ->m_traffic_shaping_exposed = true;
        return false;
    }
    return true;
}

bool CLiveTunnel::PrepareK6ShapedEmissionLocked(
    const std::shared_ptr<CLiveCircuit>& circ,
    const kad6::K6ShapeSlot& slot, LiveShapedEmission& emission)
{
    if (!circ) return false;
    const kad6::Kad6CryptoHooks crypto = MakeKad6HostCryptoHooks();
    uint32_t epochLowBase = 0;
    if (m_scheduler.NeedsShapedEpoch(circ->Id(), slot.epoch)) {
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
        epochLowBase = eseRdU32LE(epochMaterial);
    }

    return m_scheduler.PrepareShapedEmission(
        circ->Id(), slot, crypto, epochLowBase, emission);
}

bool CLiveTunnel::EmitK6ShapedEmission(
    const std::shared_ptr<CLiveCircuit>& circ,
    const LiveShapedEmission& emission)
{
    if (!circ || !circ->m_prevHopClient) return false;
    const kad6::Kad6CryptoHooks crypto = MakeKad6HostCryptoHooks();
    std::vector<uint8_t> prefix(emission.layer_plain.size() + 16);
    size_t prefixLen = 0;
    if (!circ->EncryptOneLayerExplicit(
            0, emission.link_nonce, emission.layer_plain.data(),
            emission.layer_plain.size(), prefix.data(), prefixLen)
        || prefixLen != kad6::K6ShapedPrefixLen(emission.output_layers))
        return false;
    prefix.resize(prefixLen);
    std::vector<uint8_t> carrier;
    if (kad6::BuildK6ShapedCarrier(
            prefix.data(), prefix.size(), emission.output_layers,
            circ->Id(), emission.link_nonce, crypto, carrier)
        != kad6::Kad6Status::Ok)
        return false;
    if (!SendBulkCellToPeer(circ->m_prevHopClient, carrier.data(), carrier.size()))
        return false;
    const uint64_t metricNow = static_cast<uint64_t>(time(NULL));
    const uint64_t useful = static_cast<uint64_t>(
        (std::min)(emission.record_bytes, carrier.size()));
    if (useful != 0)
        m_metrics.Add(kad6::K6MetricFamily::TransportBytesTotal,
            0, 1, 0, useful, metricNow);
    m_metrics.Add(kad6::K6MetricFamily::TransportBytesTotal,
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
            || !m_scheduler.AcceptShapedReplay(circ->Id(), hop, linkNonce))
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

    std::shared_ptr<CLiveCircuit> relay =
        m_circuitRegistry.FindRelayByOutgoingId(header.circ_id);
    if (relay) {
        if (fromPeer != relay->m_nextHopClient || relay->m_remoteHopIndex >= 2
            || relay->m_originCircContext == 0 || relay->HopCount() != 1)
            return true;
        const int incomingLayers = 2 - static_cast<int>(relay->m_remoteHopIndex);
        std::vector<uint8_t> prefix;
        if (kad6::ExtractK6ShapedPrefix(pkt, size, incomingLayers, prefix)
            != kad6::Kad6Status::Ok
            || !m_scheduler.AcceptShapedReplay(
                    relay->Id(),
                    static_cast<uint8_t>(0x80u + relay->m_remoteHopIndex),
                    header.link_nonce_seq)
            || !EnsureK6ShaperLocked(relay, incomingLayers + 1,
                                     relay->m_shape_bucket_kib))
            return true;
        LiveShapedQueuedRecord record;
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

    for (const auto& candidate : m_circuitRegistry.GetSnapshot()) {
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
    struct Prepared {
        std::shared_ptr<CLiveCircuit> circuit;
        LiveShapedEmission emission;
    };
    const bool fairActive = ProcessK6FairTick();
    LiveShapedTickResult tick;
    std::vector<Prepared> prepared;
    {
        CSingleLock lock(&m_lock, TRUE);
        const std::vector<std::shared_ptr<CLiveCircuit>> circuits =
            m_circuitRegistry.GetSnapshot();
        std::vector<uint32_t> liveRelays;
        for (const auto& circ : circuits)
            if (circ->State() != CircuitState::Destroyed
                && circ->m_role == CircuitRole::Relay)
                liveRelays.push_back(circ->Id());
        tick = m_scheduler.PollShapedLinks(K6ShapeNowUs(), liveRelays, 8);
        auto findCircuit = [&](uint32_t circId) {
            for (const auto& circ : circuits)
                if (circ->Id() == circId)
                    return circ;
            return std::shared_ptr<CLiveCircuit>();
        };
        for (uint32_t circId : tick.exposed) {
            const auto circ = findCircuit(circId);
            if (circ) circ->m_traffic_shaping_exposed = true;
        }
        for (const LiveShapedTickWork& work : tick.work) {
            Prepared item;
            item.circuit = findCircuit(work.circ_id);
            if (!item.circuit || !PrepareK6ShapedEmissionLocked(
                    item.circuit, work.slot, item.emission)) {
                m_scheduler.MarkShapedExposed(work.circ_id);
                if (item.circuit)
                    item.circuit->m_traffic_shaping_exposed = true;
            } else {
                prepared.push_back(std::move(item));
            }
        }
        if (m_scheduler.ShouldStopClass5Timer(tick.has_links, fairActive))
            StopK6ShapeTimerLocked();
    }
    for (const LiveShapedRetirement& retired : tick.retired)
        AddDebugLogLine(false,
            _T("Kad6 K6-6: class-5 idle tail complete circ=0x%08x (%u epoch(s))"),
            retired.circ_id, static_cast<unsigned>(retired.idle_tail_epochs));
    for (const Prepared& item : prepared) {
        if (!EmitK6ShapedEmission(item.circuit, item.emission)) {
            CSingleLock lock(&m_lock, TRUE);
            m_scheduler.MarkShapedExposed(item.circuit->Id());
            item.circuit->m_traffic_shaping_exposed = true;
        }
    }
}

bool CLiveTunnel::OnBulkCellReceived(const uint8_t* pkt, uint32_t size, CUpDownClient* fromPeer)
{
    CSingleLock lock(&m_lock, TRUE);
    m_metrics.RecordCellReceived(size);

    if (size == kad6::kK6ShapedTotal)
        return HandleK6ShapedCellLocked(pkt, size, fromPeer);

    Bulk::BulkCellHeader h;
    const uint8_t* payload = NULL;
    if (!Bulk::BulkCellParse(pkt, size, h, payload))
        return true;   // malformed -> consume + drop

    // Reverse forwarding: a bulk cell on a relay's OUTBOUND id is coming back from
    // hop2/exit -> re-add our hop1->V layer and relay to V (mirror of CELL_RELAY F-1).
    {
        auto relayCirc = m_circuitRegistry.FindRelayByOutgoingId(h.circ_id);
        if (relayCirc) {
            if (fromPeer != relayCirc->m_nextHopClient) return true;
            ForwardBulkCell_Reverse(relayCirc, h.bcmd, h.nonce_seq, payload, h.length);
            return true;
        }
    }

    // Terminating end (viewer/originator): decode + reassemble.
    std::shared_ptr<CLiveCircuit> circ;
    for (const auto& c : m_circuitRegistry.GetSnapshot())
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
    if (m_scheduler.HasShapedLink(circ->Id())) {
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
        LiveShapedQueuedRecord record;
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
        if (!e.done && e.haveLayout &&
            ese::live::LiveStreamRecovery::ShouldSendNack(
                now, e.first_seen_tick, e.lastNackTick)) {
            std::vector<std::pair<uint32_t, uint8_t>> missing;
            const std::vector<std::uint8_t> missingBlocks =
                ese::live::LiveStreamRecovery::MissingFecBlocks(
                    e.layout.k, e.layout.n_blocks, e.blockRecv);
            for (const std::uint8_t block : missingBlocks)
                missing.push_back(std::make_pair(e.seq, block));
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
        if (m_circuitRegistry.FindById(it->first)) alive = true;
        if (!alive) it = m_bulkReplay.erase(it); else ++it;
    }
    std::vector<uint32_t> liveShapeCircuits;
    for (const auto& circuit : m_circuitRegistry.GetSnapshot())
        if (circuit->State() != CircuitState::Destroyed)
            liveShapeCircuits.push_back(circuit->Id());
    m_scheduler.SweepShapedReplay(liveShapeCircuits);

    // v8.1.2 E3.2 — sweep explicit bulk subs: drop those whose circuit died or that went
    // silent past the TTL (the viewer re-subscribes on each refresh; the exit dedups by circ_id).
    {
        CSingleLock pl(&m_pendingLock, TRUE);
        for (auto it = m_bulkSubs.begin(); it != m_bulkSubs.end(); ) {
            std::vector<BulkSub>& subs = it->second;
            for (auto i = subs.begin(); i != subs.end(); ) {
                bool alive = false;
                if (m_circuitRegistry.FindById(i->circ_id)) alive = true;
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
        // m_lock is held by Tick -> the circuit registry is safe to read.
        size_t pushed = 0;
        for (const std::vector<uint32_t>& sess : sessions) {
            const size_t C = sess.size();
            if (C == 0) continue;
            std::vector<std::shared_ptr<CLiveCircuit>> sc(C);
            for (size_t i = 0; i < C; ++i)
                sc[i] = m_circuitRegistry.FindById(sess[i]);
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
    for (const auto& c : m_circuitRegistry.GetSnapshot()) {
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
    std::uint32_t windowStart = c.windowStart;
    ese::live::LiveStreamRecovery::UpdateParityWindow(
        c.r, c.nackCount, windowStart, now);
    c.windowStart = windowStart;
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
    for (const auto& c : m_circuitRegistry.GetSnapshot()) {
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
    // then marshal a pinned send and wait through the pending domain.
    uint32_t req_id;
    PendingHandle pr = RegisterPending(req_id);
    m_pendingRequests.Configure(
        pr, TUN_OP_PING, 0, TUN_SEND_RETRIES,
        reinterpret_cast<const uint8_t*>(text.data()), text.size());
    EnqueueSendMsg(req_id, TUN_OP_PING,
                   (const uint8_t*)text.data(), text.size());

    std::vector<uint8_t> reply;
    if (!WaitPending(req_id, std::move(pr), timeoutMs, reply, NULL))
        return false;
    replyText.assign((const char*)reply.data(), reply.size());
    return true;
}

// v8.1 A1.7 - multi-cell echo round-trip. Marshals the message for a pinned
// send (A4: SendMessagePinned fragments it onto one circuit) and waits for the
// reassembled TUN_OP_ECHO_LARGE_REPLY. Worker-thread safe.
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
    // circuit so they reassemble at one exit. Wait through the pending domain.
    uint32_t req_id;
    PendingHandle pr = RegisterPending(req_id);
    m_pendingRequests.Configure(
        pr, TUN_OP_ECHO_LARGE, 0, TUN_SEND_RETRIES,
        payload.empty() ? NULL : payload.data(), payload.size());
    EnqueueSendMsg(req_id, TUN_OP_ECHO_LARGE,
                   payload.empty() ? NULL : payload.data(), payload.size());

    return WaitPending(req_id, std::move(pr), timeoutMs, replyOut, NULL);
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
    for (const auto& circuit : m_circuitRegistry.GetSnapshot()) {
        if (circuit && circuit->State() == CircuitState::Destroyed)
            retiredCircuits.insert(circuit->Id());
        if (!circuit || !circuit->m_strict3 ||
            circuit->m_role != CircuitRole::Originator ||
            circuit->m_k6BuildMetricEmitted ||
            (circuit->State() != CircuitState::Active &&
             circuit->State() != CircuitState::Destroyed))
            continue;
        const bool ok = circuit->State() == CircuitState::Active;
        m_metrics.Observe(kad6::K6MetricFamily::CircuitBuildMs,
            ok ? 0 : 1, 0, 0, static_cast<double>(circuit->AgeMs()), buildMetricNow);
        m_metrics.Add(kad6::K6MetricFamily::BuildTotal,
            ok ? 0 : 1, ok ? 0 : 6, 0, 1, buildMetricNow);
        circuit->m_k6BuildMetricEmitted = true;
    }
    // 1. Reap Destroyed circuits.
    m_circuitRegistry.RemoveDestroyed(&retiredCircuits);

    // 2. Rotation: any ACTIVE circuit older than ROTATION_BASE_MS is
    // marked Destroyed. Pending circuits get a longer timeout because
    // they're waiting for handshake reply.
    const DWORD now = GetTickCount();
    for (const auto& c : m_circuitRegistry.GetSnapshot()) {
        if (c->State() == CircuitState::Active && c->AgeMs() > TUNNEL_ROTATION_BASE_MS) {
            if (c->m_strict3) DestroyCircuitFailClosed(c);
            else TransitionCircuitDestroyed(c); // normal legacy rotation
        } else if (c->State() == CircuitState::Pending && c->AgeMs() > TUNNEL_HANDSHAKE_TIMEOUT_MS * 8) {
            // 8x handshake timeout = ~6.4 s. After this, give up — peer
            // probably isn't running the fork. Distinct from a crypto reject:
            // this is a TIMED reap from Tick (with age), not a synchronous AUTH-ABORT.
            AddDebugLogLine(false, _T("LiveTunnel: circ=0x%08x REAP reason=HANDSHAKE_TIMEOUT (CREATED never arrived, age=%u ms) — NOT a crypto reject"), c->Id(), c->AgeMs());
            c->m_abort_reason = CircuitAbortReason::HandshakeTimeout;
            if (c->m_private2 || c->m_strict3) DestroyCircuitFailClosed(c);
            else TransitionCircuitDestroyed(c);
        } else if (c->State() == CircuitState::HalfBuilt
                   && c->m_extendStartedTick != 0
                   && LiveTunnelScheduler::HasStrictlyElapsed32(now, c->m_extendStartedTick,
                       TUNNEL_HANDSHAKE_TIMEOUT_MS * 16)) {
            // v8.1 fix: a circuit stuck mid-EXTEND (hop1 done, EXTENDED
            // never arrived) used to fall through both arms above and
            // leak forever. Time it out, with a longer budget since it
            // is waiting on a second handshake leg.
            AddDebugLogLine(false, _T("LiveTunnel: circ=0x%08x REAP reason=EXTEND_TIMEOUT (EXTENDED never arrived, age=%u ms) — NOT a crypto reject"), c->Id(), c->AgeMs());
            c->m_abort_reason = CircuitAbortReason::ExtendTimeout;
            if (c->m_private2 || c->m_strict3) DestroyCircuitFailClosed(c);
            else TransitionCircuitDestroyed(c);
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
    for (const auto& circuit : m_circuitRegistry.GetSnapshot())
        if (circuit && circuit->State() == CircuitState::Destroyed)
            retiredCircuits.insert(circuit->Id());

    {
        double circuitCounts[5][4] = {};
        for (const auto& circuit : m_circuitRegistry.GetSnapshot()) {
            if (!circuit) continue;
            const uint8 state = (std::min<uint8>)(static_cast<uint8>(circuit->State()), 4);
            const uint8 hops = (std::min<uint8>)(static_cast<uint8>(circuit->HopCount()), 3);
            circuitCounts[state][hops] += 1.0;
        }
        const uint64 metricNow = static_cast<uint64>(time(NULL));
        for (uint8 state = 0; state < 5; ++state)
            for (uint8 hops = 0; hops < 4; ++hops)
                m_metrics.Observe(kad6::K6MetricFamily::Circuits,
                    state, hops, 0, circuitCounts[state][hops], metricNow);
    }
    {
        std::set<uint32_t> active;
        for (const auto& c : m_circuitRegistry.GetSnapshot())
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
    for (const auto& c : m_circuitRegistry.GetSnapshot()) {
        if (c->State() != CircuitState::Active) continue;
        if (c->m_role != CircuitRole::Originator) continue;   // only originator drives cover
        if (c->HopCount() < 1) continue;
        if (c->m_lastPaddingTick == 0) {
            c->m_lastPaddingTick = now;
            c->m_nextPaddingDelayMs =
                covCfg.NextPaddingDelayMs((uint32_t)covCfg.GetProfile());
            continue;
        }
        if (!LiveTunnelScheduler::HasElapsed32(
                now, c->m_lastPaddingTick, c->m_nextPaddingDelayMs))
            continue;

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
    // the metrics-owned RTT EWMA. SendMessagePinned returns 0 when there is no Active circuit,
    // so this is a pure no-op on a single-PC node (it never builds anything).
    {
        const DWORD RTT_PING_INTERVAL_MS = 5000u;
        if (m_scheduler.DueRttProbe(now, RTT_PING_INTERVAL_MS)) {
            // req_id is a fresh random NewCircuitId(), not deduped against the
            // pending domain. A ~2^-32 collision with an in-flight manual
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
            if (LiveTunnelScheduler::HasStrictlyElapsed32(
                    now, it->second.first_seen_tick, TUN_REASSEMBLY_TTL_MS))
                it = m_reassembly.erase(it);
            else
                ++it;
        }
        for (auto it = m_k6SearchReplies.begin(); it != m_k6SearchReplies.end(); ) {
            if (LiveTunnelScheduler::HasStrictlyElapsed32(
                    now, it->second.started, TUN_REQUEST_HARD_TTL_MS))
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
    uchar viewerKey[16];
    if (theApp.liveStreamManager
        && theApp.liveStreamManager->CopyViewerStreamKey(viewerKey)
        && m_scheduler.DueBulkSubscription(now, 10000u)) {
        bool haveBulk = false;
        for (const auto& c : m_circuitRegistry.GetSnapshot())
            if (c->m_role == CircuitRole::Originator && c->State() == CircuitState::Active
                && c->HopCount() >= 1 && c->m_bulk_ok) { haveBulk = true; break; }
        if (haveBulk) {
            m_scheduler.MarkBulkSubscription(now);
            BulkSubscribe(viewerKey);
        }
    }

    // 5. v8.1 A4 - retry/fail messages pinned to a circuit that died mid-flight.
    // Rotation (step 2 above) or a CELL_DESTROY can kill a circuit while one of
    // its multi-cell messages was still in flight. Re-send the whole message on
    // another circuit (up to retries_left); when retries run out, wake the
    // waiter with a failure so it returns a clean error instead of timing out.
    {
        // Tick already owns the registry lock. Pass a value snapshot into the
        // pending domain; it must never call back into the registry while its
        // own mutex is held.
        std::set<uint32_t> activeCircuitIds;
        for (const auto& circuit : m_circuitRegistry.GetSnapshot()) {
            if (circuit && circuit->State() == CircuitState::Active)
                activeCircuitIds.insert(circuit->Id());
        }
        std::vector<MainThreadReq> retries;
        const std::vector<eSELive::LiveTunnelPending::RetryAction> actions =
            m_pendingRequests.CollectRetries(activeCircuitIds);
        retries.reserve(actions.size());
        for (const auto& action : actions) {
            MainThreadReq request;
            request.op = MT_SEND_MSG;
            request.reqId = action.request_id;
            request.subCmd = action.sub_cmd;
            request.requiredExitCaps = action.required_exit_caps;
            request.payload = action.message;
            retries.push_back(std::move(request));
        }
        // CollectRetries has released the pending-domain mutex before queue
        // publication, preserving registry -> pending -> queue lock order.
        const std::vector<LiveDeferredWork> cancelled = m_scheduler.EnqueueBatch(std::move(retries));
        for (const LiveDeferredWork& work : cancelled) {
            if (work.reqId != 0)
                SignalReply(work.reqId, NULL, 0, 0);
        }
    }

    // 6. v8.1 A6 - sweep deferred exit operations that never completed, or
    // whose circuit has gone (weak_ptr expired). TTL reuses the hard request
    // bound; without this a never-finishing exit op would leak forever.
    {
        CSingleLock pl(&m_pendingLock, TRUE);
        (void)m_exitServices.Sweep(now, TUN_REQUEST_HARD_TTL_MS);
    }

    // 7. v8.1 Sprint B - reply to tunneled Kad searches whose accumulation
    // window has elapsed (real results have been landing in the directory).
    FinishDueSearchJobs();

    // 8. v8.1 Sprint C (C3) - sweep exit-proxy subscriptions whose circuit died
    // or that went silent past the TTL, so a departed viewer stops us relaying
    // (and re-subscribing to) the broadcaster on its behalf.
    {
        auto circuitAlive = [&](uint32_t id) -> bool {
            const std::shared_ptr<CLiveCircuit> circuit =
                m_circuitRegistry.FindById(id);
            return circuit && circuit->State() == CircuitState::Active;
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
                        LiveTunnelScheduler::HasStrictlyElapsed32(
                            now, cit->second.lastSeen, EXIT_SUB_TTL_MS))
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

    m_scheduler.RecordTick(now);
}

size_t CLiveTunnel::ActiveCircuitCount() const
{
    CSingleLock lock(&m_lock, TRUE);
    size_t n = 0;
    for (const auto& c : m_circuitRegistry.GetSnapshot())
        if (c->State() == CircuitState::Active) ++n;
    return n;
}

bool CLiveTunnel::HasActiveCircuitWithExitCaps(uint32_t requiredCaps) const
{
    if (requiredCaps == 0) return ActiveCircuitCount() != 0;
    const size_t minimumHops = (requiredCaps & ESE_CAP_KAD6) != 0 ? 2 : 1;
    CSingleLock lock(&m_lock, TRUE);
    for (const auto& c : m_circuitRegistry.GetSnapshot()) {
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
    for (const auto& c : m_circuitRegistry.GetSnapshot())
        if (c->State() == CircuitState::Pending) ++n;
    return n;
}

size_t CLiveTunnel::RelayCircuitCount() const
{
    CSingleLock lock(&m_lock, TRUE);
    size_t n = 0;
    for (const auto& c : m_circuitRegistry.GetSnapshot())
        if (c->m_role == CircuitRole::Relay && c->State() == CircuitState::Active) ++n;
    return n;
}

size_t CLiveTunnel::TotalCircuitCount() const
{
    CSingleLock lock(&m_lock, TRUE);
    return m_circuitRegistry.Size();
}

bool CLiveTunnel::TunneledLiveSubscribe(const uint8_t streamKey[16],
                                        uint32_t bIP, uint16_t bPort, uint16_t bUDP,
                                        uint32_t bAltIP, uint32_t timeoutMs)
{
    uint32_t req_id;PendingHandle pending=RegisterPending(req_id);std::vector<uint8_t> body(28),reply;
    memcpy(body.data(),streamKey,16);eseWrU32LE(body.data()+16,bIP);eseWrU16LE(body.data()+20,bPort);
    eseWrU16LE(body.data()+22,bUDP);eseWrU32LE(body.data()+24,bAltIP);
    m_pendingRequests.Configure(pending,TUN_OP_LIVE_SUBSCRIBE,0,TUN_SEND_RETRIES,body.data(),body.size());
    EnqueueSendMsg(req_id,TUN_OP_LIVE_SUBSCRIBE,body.data(),body.size());
    return WaitPending(req_id,std::move(pending),timeoutMs,reply,NULL)&&!reply.empty()&&reply[0]==0;
}

void CLiveTunnel::SendLiveSubscribeNoWait(const uint8_t streamKey[16],
                                           uint32_t bIP, uint16_t bPort, uint16_t bUDP,
                                           uint32_t bAltIP)
{
    const uint32_t req_id=NewCircuitId();
    std::vector<uint8_t> body(28);
    memcpy(body.data(),streamKey,16);eseWrU32LE(body.data()+16,bIP);eseWrU16LE(body.data()+20,bPort);
    eseWrU16LE(body.data()+22,bUDP);eseWrU32LE(body.data()+24,bAltIP);
    EnqueueSendMsg(req_id,TUN_OP_LIVE_SUBSCRIBE,body.data(),body.size());
}

void CLiveTunnel::SendKadSearchV2NoWait(const std::string& keywordLower)
{
    const uint32_t req_id=NewCircuitId();
    std::vector<uint8_t> body;
    if(HasActiveCircuitWithExitCaps(ESE_CAP_KAD6)){
        if(!EseBuildK6SearchStartFrame(keywordLower,req_id,body))return;
        EnqueueSendMsg(req_id,TUN_OP_KAD6_GATEWAY,body.data(),body.size(),ESE_CAP_KAD6);return;}
    const uint16_t kwLen=(uint16_t)(keywordLower.size()>0xFFFF?0xFFFF:keywordLower.size());
    body.push_back(0x01);body.push_back((uint8_t)(kwLen&0xFF));body.push_back((uint8_t)(kwLen>>8));
    body.insert(body.end(),keywordLower.begin(),keywordLower.begin()+kwLen);
    EnqueueSendMsg(req_id,TUN_OP_KAD_SEARCH_V2,body.data(),body.size());
}

}  // namespace eSELive
