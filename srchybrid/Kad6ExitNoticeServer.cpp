// K6-NOTICE-001: isolated, read-only, bounded HTTP surface.
#include "Kad6ExitNoticeServer.h"
#include "LiveTunnelMetrics.h"
#include "LiveTunnelReleaseGate.h"
#include "LiveTunnelScheduler.h"
#include "kad6/kad6_exit_notice.h"
#include "kad6/kad6_release.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstring>
#include <fstream>
#include <mutex>
#include <thread>

namespace {

constexpr std::size_t kMaxNoticeBytes = 8192;
constexpr std::size_t kMaxHeaderBytes = 2048;
constexpr unsigned kRateBurst = 20;
constexpr unsigned kRatePerSecond = 5;

bool ValidDocument(const std::string& value) noexcept {
    return value.size() >= 2 && value.size() <= kMaxNoticeBytes &&
        value.front() == '{' && value.back() == '}' &&
        value.find('\0') == std::string::npos;
}

bool SendAll(SOCKET socket, const char* data, std::size_t size,
             std::uint64_t& sent) noexcept {
    while (size != 0) {
        const int chunk = send(socket, data,
            static_cast<int>((std::min)(size, static_cast<std::size_t>(16384))), 0);
        if (chunk <= 0) return false;
        data += chunk;
        size -= static_cast<std::size_t>(chunk);
        sent += static_cast<std::uint64_t>(chunk);
    }
    return true;
}

} // namespace

struct CKad6ExitNoticeServer::Impl {
    mutable std::mutex document_lock;
    std::string document;
    std::thread worker;
    std::atomic<bool> running{false};
    std::atomic<SOCKET> listen_socket{INVALID_SOCKET};
    std::atomic<std::uint64_t> requests{0};
    std::atomic<std::uint64_t> rejected{0};
    std::atomic<std::uint64_t> bytes_sent{0};
    std::atomic<std::uint16_t> port{0};
    bool winsock_started = false;
    std::mutex evidence_lock;
    std::wstring evidence_path;

    bool RateAllowed() noexcept {
        using Clock = std::chrono::steady_clock;
        static_assert(kRateBurst >= kRatePerSecond, "invalid notice rate policy");
        const auto now = Clock::now();
        if (rate_updated.time_since_epoch().count() == 0) rate_updated = now;
        const double elapsed = std::chrono::duration<double>(now - rate_updated).count();
        rate_tokens = (std::min)(static_cast<double>(kRateBurst),
            rate_tokens + elapsed * static_cast<double>(kRatePerSecond));
        rate_updated = now;
        if (rate_tokens < 1.0) return false;
        rate_tokens -= 1.0;
        return true;
    }

    void Reply(SOCKET client) noexcept {
        DWORD timeout = 2000;
        setsockopt(client, SOL_SOCKET, SO_RCVTIMEO,
            reinterpret_cast<const char*>(&timeout), sizeof timeout);
        setsockopt(client, SOL_SOCKET, SO_SNDTIMEO,
            reinterpret_cast<const char*>(&timeout), sizeof timeout);

        char request[kMaxHeaderBytes + 1]{};
        std::size_t used = 0;
        bool complete = false;
        while (used < kMaxHeaderBytes) {
            const int got = recv(client, request + used,
                static_cast<int>(kMaxHeaderBytes - used), 0);
            if (got <= 0) break;
            used += static_cast<std::size_t>(got);
            request[used] = 0;
            if (std::string(request, used).find("\r\n\r\n") != std::string::npos) {
                complete = true;
                break;
            }
        }

        requests.fetch_add(1, std::memory_order_relaxed);
        const char get10[] = "GET /.well-known/kad6-exit HTTP/1.0\r\n";
        const char get11[] = "GET /.well-known/kad6-exit HTTP/1.1\r\n";
        const bool exact_get = complete &&
            ((used >= sizeof get10 - 1 &&
              std::equal(get10, get10 + sizeof get10 - 1, request)) ||
             (used >= sizeof get11 - 1 &&
              std::equal(get11, get11 + sizeof get11 - 1, request)));

        std::uint64_t sent = 0;
        if (!exact_get || !RateAllowed()) {
            rejected.fetch_add(1, std::memory_order_relaxed);
            const char denied[] =
                "HTTP/1.1 404 Not Found\r\nConnection: close\r\n"
                "Content-Length: 0\r\nCache-Control: no-store\r\n\r\n";
            SendAll(client, denied, sizeof denied - 1, sent);
        } else {
            std::string body;
            {
                std::lock_guard<std::mutex> guard(document_lock);
                body = document;
            }
            const std::string header =
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: application/kad6-exit+json\r\n"
                "X-Content-Type-Options: nosniff\r\n"
                "Cache-Control: public, max-age=300\r\n"
                "Connection: close\r\nContent-Length: " +
                std::to_string(body.size()) + "\r\n\r\n";
            if (SendAll(client, header.data(), header.size(), sent))
                SendAll(client, body.data(), body.size(), sent);
        }
        bytes_sent.fetch_add(sent, std::memory_order_relaxed);
        shutdown(client, SD_BOTH);
        closesocket(client);
    }

    void Run() noexcept {
        while (running.load(std::memory_order_acquire)) {
            const SOCKET listener = listen_socket.load(std::memory_order_acquire);
            if (listener == INVALID_SOCKET) break;
            fd_set read_set;
            FD_ZERO(&read_set);
            FD_SET(listener, &read_set);
            timeval wait{0, 250000};
            const int selected = select(0, &read_set, nullptr, nullptr, &wait);
            if (selected <= 0 || !running.load(std::memory_order_acquire)) continue;
            sockaddr_storage peer{};
            int peer_size = sizeof peer;
            const SOCKET client = accept(listener,
                reinterpret_cast<sockaddr*>(&peer), &peer_size);
            if (client != INVALID_SOCKET) Reply(client);
        }
    }

    double rate_tokens = static_cast<double>(kRateBurst);
    std::chrono::steady_clock::time_point rate_updated{};
};

CKad6ExitNoticeServer::CKad6ExitNoticeServer() : impl_(new Impl) {}
CKad6ExitNoticeServer::~CKad6ExitNoticeServer() { Stop(); }

bool CKad6ExitNoticeServer::Start(std::uint16_t port,
                                  const std::string& signed_notice_json) {
    if (!impl_ || impl_->running.load(std::memory_order_acquire) || port == 0 ||
        !ValidDocument(signed_notice_json)) return false;

    WSADATA data{};
    if (WSAStartup(MAKEWORD(2, 2), &data) != 0) return false;
    impl_->winsock_started = true;
    const SOCKET listener = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (listener == INVALID_SOCKET) {
        Stop();
        return false;
    }
    int reuse = 1;
    int v6only = 0;
    setsockopt(listener, SOL_SOCKET, SO_REUSEADDR,
        reinterpret_cast<const char*>(&reuse), sizeof reuse);
    if (setsockopt(listener, IPPROTO_IPV6, IPV6_V6ONLY,
            reinterpret_cast<const char*>(&v6only), sizeof v6only) != 0) {
        closesocket(listener);
        Stop();
        return false;
    }
    sockaddr_in6 endpoint{};
    endpoint.sin6_family = AF_INET6;
    endpoint.sin6_addr = in6addr_any;
    endpoint.sin6_port = htons(port);
    if (bind(listener, reinterpret_cast<const sockaddr*>(&endpoint),
             sizeof endpoint) != 0 || listen(listener, 16) != 0) {
        closesocket(listener);
        Stop();
        return false;
    }
    {
        std::lock_guard<std::mutex> guard(impl_->document_lock);
        impl_->document = signed_notice_json;
    }
    impl_->port.store(port, std::memory_order_release);
    impl_->listen_socket.store(listener, std::memory_order_release);
    impl_->running.store(true, std::memory_order_release);
    try {
        impl_->worker = std::thread([this] { impl_->Run(); });
    } catch (...) {
        Stop();
        return false;
    }
    return true;
}

bool CKad6ExitNoticeServer::Update(const std::string& signed_notice_json) {
    if (!impl_ || !impl_->running.load(std::memory_order_acquire) ||
        !ValidDocument(signed_notice_json)) return false;
    std::lock_guard<std::mutex> guard(impl_->document_lock);
    impl_->document = signed_notice_json;
    return true;
}

void CKad6ExitNoticeServer::Stop() noexcept {
    if (!impl_) return;
    impl_->running.store(false, std::memory_order_release);
    const SOCKET listener = impl_->listen_socket.exchange(
        INVALID_SOCKET, std::memory_order_acq_rel);
    if (listener != INVALID_SOCKET) {
        shutdown(listener, SD_BOTH);
        closesocket(listener);
    }
    if (impl_->worker.joinable()) impl_->worker.join();
    impl_->port.store(0, std::memory_order_release);
    if (impl_->winsock_started) {
        WSACleanup();
        impl_->winsock_started = false;
    }
}

K6ExitNoticeServerSnapshot CKad6ExitNoticeServer::Snapshot() const noexcept {
    K6ExitNoticeServerSnapshot value;
    if (!impl_) return value;
    value.running = impl_->running.load(std::memory_order_acquire);
    value.port = impl_->port.load(std::memory_order_acquire);
    value.requests = impl_->requests.load(std::memory_order_relaxed);
    value.rejected = impl_->rejected.load(std::memory_order_relaxed);
    value.bytes_sent = impl_->bytes_sent.load(std::memory_order_relaxed);
    return value;
}

void CKad6ExitNoticeServer::ConfigureEvidencePath(std::wstring path) {
    std::lock_guard<std::mutex> guard(impl_->evidence_lock);
    impl_->evidence_path = std::move(path);
}
bool CKad6ExitNoticeServer::LoadEvidence(
    std::vector<std::uint8_t>& wire, std::uint32_t& status) {
    std::lock_guard<std::mutex> guard(impl_->evidence_lock);
    std::ifstream file(impl_->evidence_path, std::ios::binary | std::ios::ate);
    status = static_cast<std::uint32_t>(kad6::K6ReleaseGateStatus::Missing);
    if (!file) return false;
    const auto invalid = [&] {
        wire.clear(); status = static_cast<std::uint32_t>(
            kad6::K6ReleaseGateStatus::BadEncoding); return false;
    };
    const std::streamoff size = file.tellg();
    if (size < 0 || static_cast<std::size_t>(size) !=
            kad6::kK6ReleaseEvidenceWireSize) return invalid();
    wire.resize(static_cast<std::size_t>(size));
    file.seekg(0);
    kad6::K6ReleaseEvidence decoded;
    const bool valid = file.read(reinterpret_cast<char*>(wire.data()),
        static_cast<std::streamsize>(wire.size())) &&
        kad6::DecodeK6ReleaseEvidence(wire.data(), wire.size(), decoded) ==
            kad6::Kad6Status::Ok;
    return valid ? true : invalid();
}
bool CKad6ExitNoticeServer::SaveEvidence(
    const std::vector<std::uint8_t>& wire) {
    std::lock_guard<std::mutex> guard(impl_->evidence_lock);
    const std::wstring temporary = impl_->evidence_path + L".new";
    std::ofstream file(temporary, std::ios::binary | std::ios::trunc);
    if (!file || !file.write(reinterpret_cast<const char*>(wire.data()),
            static_cast<std::streamsize>(wire.size())) || !file.flush()) {
        file.close(); DeleteFileW(temporary.c_str()); return false;
    }
    file.close();
    if (MoveFileExW(temporary.c_str(), impl_->evidence_path.c_str(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) return true;
    DeleteFileW(temporary.c_str());
    return false;
}

namespace eSELive {
namespace {
bool LoadReleaseEvidenceAdapter(
    void* raw, std::vector<std::uint8_t>& wire, std::uint32_t& status)
{ return static_cast<CKad6ExitNoticeServer*>(raw)->LoadEvidence(wire, status); }
bool SaveReleaseEvidenceAdapter(
    void* raw, const std::vector<std::uint8_t>& wire)
{ return wire.size() == kad6::kK6ReleaseEvidenceWireSize &&
    static_cast<CKad6ExitNoticeServer*>(raw)->SaveEvidence(wire); }
bool StartReleaseNoticeAdapter(
    void* raw, std::uint16_t port, const std::string& notice)
{
    auto* adapter = static_cast<CKad6ExitNoticeServer*>(raw);
    adapter->Stop();
    return adapter->Start(port, notice);
}
void StopReleaseNoticeAdapter(void* raw) noexcept
{ static_cast<CKad6ExitNoticeServer*>(raw)->Stop(); }
LiveTunnelReleaseNoticeSnapshot ReleaseNoticeSnapshotAdapter(
    void* raw) noexcept
{
    const K6ExitNoticeServerSnapshot source =
        static_cast<CKad6ExitNoticeServer*>(raw)->Snapshot();
    return {source.running, source.port, source.requests,
        source.rejected, source.bytes_sent};
}
} // namespace

void M2A_LT1_ConfigureBridge(M2AModuleHandle& binding,
    CKad6ExitNoticeServer& adapter,
    const std::wstring& evidencePath,
    bool (*random)(void*, std::uint8_t*, std::size_t),
    void* serviceContext, bool (*services)(void*, bool, std::uint32_t))
{
    adapter.ConfigureEvidencePath(evidencePath);
    LiveTunnelReleaseStorePort port;
    port.context = &adapter;
    port.services_context = serviceContext;
    port.load = LoadReleaseEvidenceAdapter; port.save = SaveReleaseEvidenceAdapter;
    port.random = random;
    port.notice_start = StartReleaseNoticeAdapter;
    port.notice_stop = StopReleaseNoticeAdapter;
    port.notice_snapshot = ReleaseNoticeSnapshotAdapter;
    port.services = services;
    ResolveLiveTunnelReleaseGate(binding)->Configure(port);
}
bool M2A_LT1_SaveEvidenceBridge(M2AModuleHandle& binding, kad6::K6ReleaseEvidence evidence,
    const kad6::Kad6CryptoHooks& crypto, const std::uint8_t* pub, std::uint64_t now)
{
    evidence.version = kad6::kK6ReleaseEvidenceVersion;
    std::memcpy(evidence.node_pub.data(), pub, evidence.node_pub.size());
    if (!evidence.issued_at) evidence.issued_at = now;
    if (!evidence.valid_until) evidence.valid_until =
        evidence.issued_at + 30ull * 24 * 60 * 60;
    std::vector<std::uint8_t> wire;
    return kad6::SignK6ReleaseEvidence(crypto, evidence, wire) == kad6::Kad6Status::Ok
        && kad6::EvaluateK6ReleaseEvidence(crypto, evidence, pub, now) ==
            kad6::K6ReleaseGateStatus::Ok &&
        ResolveLiveTunnelReleaseGate(binding)->SaveEvidence(wire);
}
bool M2A_LT1_StartNoticeBridge(M2AModuleHandle& binding, std::uint16_t port,
    const kad6::K6ExitNotice& source, const kad6::Kad6CryptoHooks& crypto,
    const std::uint8_t* pub)
{
    if (!port || !pub) return false;
    kad6::K6ExitNotice notice = source;
    std::memcpy(notice.node_pub.data(), pub, notice.node_pub.size());
    std::string json;
    if (kad6::SignK6ExitNotice(crypto, notice, json) != kad6::Kad6Status::Ok) return false;
    auto* gate = ResolveLiveTunnelReleaseGate(binding);
    gate->StopNotice(); return gate->StartNotice(port, json);
}
void M2A_LT1_StopNoticeBridge(M2AModuleHandle& binding) noexcept
{ ResolveLiveTunnelReleaseGate(binding)->StopNotice(); }
K6ExitNoticeServerSnapshot M2A_LT1_NoticeSnapshotBridge(const M2AModuleHandle& binding) noexcept
{
    const auto source =
        ResolveLiveTunnelReleaseGate(binding)->NoticeSnapshot();
    return {source.running, source.port, source.requests,
        source.rejected, source.bytes_sent};
}
kad6::K6ReleaseGateStatus M2A_LT1_GetSnapshotBridge(M2AModuleHandle& binding,
    LiveK6ReleaseRuntimeSnapshot& out,
    bool optIn, bool betaOptIn, const std::uint8_t* pub,
    const kad6::Kad6CryptoHooks& crypto, std::uint64_t now)
{
    out = {}; out.operator_opt_in = optIn; out.beta_exit_opt_in = betaOptIn;
    auto* gate = ResolveLiveTunnelReleaseGate(binding);
    (void)gate->LoadEvidence();
    const auto state = gate->Snapshot();
    out.runtime_healthy = state.runtime_healthy;
    out.public_exit_enabled = state.public_enabled; out.beta_exit_enabled = state.beta_enabled;
    out.status = static_cast<kad6::K6ReleaseGateStatus>(state.status);
    out.evidence_present = state.evidence_present && kad6::DecodeK6ReleaseEvidence(
        state.evidence_wire.data(), state.evidence_wire.size(), out.evidence) ==
        kad6::Kad6Status::Ok;
    const kad6::K6ReleaseGateStatus evidenceStatus =
        out.evidence_present && pub ? kad6::EvaluateK6ReleaseEvidence(
            crypto, out.evidence, pub, now) : kad6::K6ReleaseGateStatus::Missing;
    out.evidence_valid = evidenceStatus == kad6::K6ReleaseGateStatus::Ok;
    return evidenceStatus;
}
void M2A_LT1_ApplyEvaluationBridge(M2AModuleHandle& binding,
    bool optIn, bool betaOptIn, bool healthy,
    kad6::K6ReleaseGateStatus evidence, std::uint32_t drain)
{
    ResolveLiveTunnelReleaseGate(binding)->ApplyEvaluation(
        optIn, betaOptIn, healthy, static_cast<std::uint32_t>(evidence),
        static_cast<std::uint32_t>(kad6::K6ReleaseGateStatus::Ok),
        static_cast<std::uint32_t>(kad6::K6ReleaseGateStatus::OperatorOptOut),
        static_cast<std::uint32_t>(kad6::K6ReleaseGateStatus::RuntimeUnhealthy),
        drain);
}
bool M2A_LT1_IsEnabledBridge(const M2AModuleHandle& binding) noexcept
{ return ResolveLiveTunnelReleaseGate(binding)->IsEnabled(); }
bool M2A_LT1_GetChallengeBridge(
    M2AModuleHandle& binding, std::string& challenge, std::uint64_t now)
{ return ResolveLiveTunnelReleaseGate(binding)->GetChallenge(challenge, now); }
bool M2A_LT1_ConsumeChallengeBridge(M2AModuleHandle& binding,
    const std::string& challenge, std::uint64_t now) noexcept
{ return ResolveLiveTunnelReleaseGate(binding)->ConsumeChallenge(challenge, now); }
} // namespace eSELive
