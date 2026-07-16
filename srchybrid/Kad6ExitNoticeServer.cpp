// K6-NOTICE-001: isolated, read-only, bounded HTTP surface.
#include "Kad6ExitNoticeServer.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>

#include <algorithm>
#include <atomic>
#include <chrono>
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
