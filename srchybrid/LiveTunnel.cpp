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
#define LT7_STATE(member) (*m_exitServices.LT7State().member)
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
    if (!eSELive::RunLiveExitServicesCharacterizationSelfTest() || !eSELive::RunLiveTunnelBulkStateCharacterizationSelfTest()) {
        outFailure = _T("tunnel exit-services or bulk-proxy characterization failed");
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
            ReassemblyEntry& e = LT7_STATE(RelayReassemblyState)[rkey];
            // v8.1 A5 - stamp the entry on its first fragment so Tick() can
            // sweep it if the rest of the message never arrives.
            if (!e.started) e.first_seen_tick = GetTickCount();
            ReassemblyResult r = ReassemblyIngest(e, fragIndex, fragCount,
                                                  msgTotal, fragData, fragDataLen);
            if (r == ReassemblyResult::Incomplete) return true;
            if (r == ReassemblyResult::Error) {
                LT7_STATE(RelayReassemblyState).erase(rkey);
                return true;
            }
            msg = std::move(e.message);
            LT7_STATE(RelayReassemblyState).erase(rkey);
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
        uint32_t rtt = 0;
        if (m_scheduler.LT9ConsumeRtt(req_id, GetTickCount(), rtt)) {
            if (rtt > 60000u) rtt = 60000u;   // clamp absurd/stale samples; also no overflow
            // EWMA (1/4 weight); first sample seeds the mean.
            m_metrics.ObserveMeanRtt(static_cast<uint32_t>(rtt));
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
        for (auto entry = LT7_STATE(RelayReassemblyState).begin();
             entry != LT7_STATE(RelayReassemblyState).end();) {
            if (static_cast<uint32_t>(entry->first >> 32) == circuitId)
                entry = LT7_STATE(RelayReassemblyState).erase(entry);
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
    ReassemblyEntry& entry = LT7_STATE(RelayReassemblyState)[key];
    if (!entry.started)
        entry.first_seen_tick = GetTickCount();
    const ReassemblyResult result = ReassemblyIngest(
        entry, fragmentIndex, fragmentCount, messageLength,
        fragmentData, fragmentDataLength);
    if (result == ReassemblyResult::Incomplete)
        return LiveRelayFragmentResult::Incomplete;
    if (result == ReassemblyResult::Error) {
        LT7_STATE(RelayReassemblyState).erase(key);
        return LiveRelayFragmentResult::Rejected;
    }
    completedMessage = std::move(entry.message);
    LT7_STATE(RelayReassemblyState).erase(key);
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
bool M2A_LT5CommitOriginSendCompat(LiveExitServices& exitServices,CKad6OriginSocket* source,uint64 streamId,uint64 generation,uint64 bytes,uint64 remaining,uint64 quota,uint64 headroom){return exitServices.LT5CommitOriginSend(source,streamId,generation,0,bytes,remaining,quota,headroom);}
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
#include "LiveTunnelBulkFacade.inl"
// C3 - 32-char lowercase hex of a 16-byte streamKey (map key for LT7_STATE(ExitLiveSubscriptions)).
// C3 - relay a broadcaster control update to every circuit that proxy-subscribed
// to `streamKey` through us. Called from the Live HEARTBEAT/ANNOUNCE handlers on
// the main thread. Builds TUN_OP_LIVE_HEARTBEAT and pushes it down each circuit
// (req_id = 0: this is an unsolicited push, not a reply to a pending request).
// Body: [streamKey 16][flags u8][bitmap u16 LE][oldestSeq u32 LE][pubkey 32].
// flags bit0 = bitmap/oldestSeq valid, bit1 = pubkey valid.
// C2/C3 (Sprint C finish) - relay the broadcaster's OP_LIVE_PEER_LIST (alternative
// sources) down every circuit that proxy-subscribed to `streamKey` through us, so a
// tunneled viewer learns the alt sources WITHOUT the broadcaster ever seeing the
// viewer. Same snapshot-under-pending-lock then walk-under-m_lock pattern as
// ExitRelayLiveControl (preserves the tunnel->manager-only lock order). Push
// (req_id = 0). Body: [streamKey 16][count u8][count*(ip u32 LE + port u16 LE)].
// ip is a net-order DWORD written byte-preserving via eseWrU32LE; the viewer reads
// it back with eseRdU32LE and feeds the identical value into OnPeerListReceived.
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
// v8.1 Sprint C (C1) — send TUN_OP_LIVE_SUBSCRIBE and block for the SUB_ACK.
// (the exit forwarded our subscribe to the broadcaster). BLOCKING — call off
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
// === v8.1.2 E3.1/E3.3 — exit headless ingest -> FEC encode -> stripe push =====
// The chunk hooks below run UNDER the manager lock and only touch the leaf-locked
// m_proxy* state (never m_lock/m_pendingLock), so the tunnel->manager lock order is
// never inverted. The heavy work runs in ProcessProxyIngest() from Tick() under m_lock.
// === v8.1.2 E3.2 — explicit bulk subscribe (exit handlers + viewer sender) =====
// === v8.1.2 E3.5 (NACK gap-fill) + E4' (adaptive r) ===========================
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
// Keep the previously characterized LT3 boundary compile-time-bound after
// the LT8 search method bodies move into the textual facade below.
namespace {
using LT3PlanSearchReplyContract = decltype(&LiveTunnelKadBridge::LT3PlanSearchReply);
using LT3ExecuteSearchReplyContract = decltype(&CKad6OriginSocket::LT3ExecuteSearchReply);
using LT3PlanExitGatewayContract = decltype(&LiveTunnelKadBridge::LT3PlanExitGateway);
using LT3ExecuteExitGatewayContract = decltype(&CKad6OriginSocket::LT3ExecuteExitGateway);
}
#include "LiveTunnelCoordinatorMethods.inl"
#include "LiveTunnelSearchFacade.inl"
}  // namespace eSELive
