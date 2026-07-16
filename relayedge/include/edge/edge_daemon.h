// SPDX-License-Identifier: MIT
#pragma once

#include "edge/edge_allocator.h"
#include "edge/tls_tcp_carrier.h"

namespace relayedge {

// Single-host coordinator. Network activation is possible only for an
// explicitly enabled and fully validated lab or P4 public configuration.
class EdgeDaemon {
public:
    relay::RelayStatus Start(const EdgeConfig& config,
                             std::uint64_t now_ms) noexcept;
    relay::RelayStatus BeginDrain(std::uint64_t now_ms,
                                  std::uint64_t deadline_ms) noexcept;
    relay::RelayStatus AcceptTls(TlsTcpCarrier& carrier) noexcept;
    relay::RelayStatus Tick(std::uint64_t now_ms) noexcept;
    relay::RelayStatus Kill(std::uint64_t now_ms) noexcept;

    EdgeHealth health() const noexcept { return runtime_.health(); }
    bool CanAcceptSessions() const noexcept { return runtime_.CanAcceptSessions(); }
    std::uint16_t bound_port() const noexcept { return listener_.bound_port(); }
    const EdgeRuntime& runtime() const noexcept { return runtime_; }
    EdgeRuntime& runtime() noexcept { return runtime_; }
    EdgeSessionTable& sessions() noexcept { return sessions_; }
    EdgeTcpAllocator& allocator() noexcept { return allocator_; }

private:
    void CloseResources(std::uint64_t now_ms) noexcept;

    EdgeRuntime runtime_{};
    EdgeSessionTable sessions_{};
    EdgeTcpAllocator allocator_{};
    LabTlsListener listener_{};
    bool started_ = false;
};

} // namespace relayedge
