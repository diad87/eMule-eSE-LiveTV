// Dedicated read-only listener for the signed Kad6 public-exit notice.
// Deliberately has no dependency on WebServer, sessions or administrative UI.
#pragma once

#include <cstdint>
#include <memory>
#include <string>

struct K6ExitNoticeServerSnapshot {
    bool running = false;
    std::uint16_t port = 0;
    std::uint64_t requests = 0;
    std::uint64_t rejected = 0;
    std::uint64_t bytes_sent = 0;
};

class CKad6ExitNoticeServer {
public:
    CKad6ExitNoticeServer();
    ~CKad6ExitNoticeServer();

    CKad6ExitNoticeServer(const CKad6ExitNoticeServer&) = delete;
    CKad6ExitNoticeServer& operator=(const CKad6ExitNoticeServer&) = delete;

    // Opt-in only. Binds a separate dual-stack socket ([::], IPV6_V6ONLY=0).
    // The document must already be signed canonical JSON.
    bool Start(std::uint16_t port, const std::string& signed_notice_json);
    bool Update(const std::string& signed_notice_json);
    void Stop() noexcept;
    K6ExitNoticeServerSnapshot Snapshot() const noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
