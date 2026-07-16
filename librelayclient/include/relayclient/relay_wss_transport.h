// SPDX-License-Identifier: MIT
#pragma once

#include "relayclient/relay_client.h"
#include "relay/epr_lease.h"
#include "relay/krp_auth.h"

#include <condition_variable>
#include <array>
#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <thread>

namespace relayedge {
class TlsTcpCarrier;
class WssH1Carrier;
}

namespace relayclient {

// TLS/WSS connector shared by the standalone P3 gate and the eMule adapter.
// It posts value events only. KRP authentication/lease messages are consumed by
// the session layer and are intentionally not reimplemented here.
class RelayWssTransport final : public IRelayTransportController {
public:
    explicit RelayWssTransport(IRelayEventNotifier* notifier = nullptr,
                               relay::INodeIdentitySigner* signer = nullptr) noexcept;
    ~RelayWssTransport() override;

    relay::RelayStatus Start(std::uint64_t generation,
                             const RelayClientConfig& config,
                             const std::shared_ptr<RelayEventQueue>& events) noexcept override;
    void Stop(std::uint64_t generation) noexcept override;
    void Join() noexcept override;

    // Main-thread call made immediately before CServerSocket connects. Only a
    // numeric public server address is accepted; DNS resolution remains in the
    // eMule/server-list layer and the edge revalidates the final IP.
    bool PrepareEd2kServerRoute(const char* numeric_address,
                                std::uint16_t server_port,
                                std::uint16_t& loopback_proxy_port) noexcept;
    bool DataPlaneReady() const noexcept {
        return data_plane_ready_.load(std::memory_order_acquire);
    }
    std::uint16_t PublicTcpPort() const noexcept {
        return public_tcp_port_.load(std::memory_order_acquire);
    }

private:
    void Worker(std::uint64_t generation, RelayClientConfig config,
                std::shared_ptr<RelayEventQueue> events) noexcept;
    void Publish(const std::shared_ptr<RelayEventQueue>& events,
                 RelayClientEventType type, std::uint64_t generation,
                 RelayReason reason = RelayReason::None) noexcept;
    bool StopRequested(std::uint64_t generation) noexcept;
    relay::RelayStatus RunTcpDataPlane(
        relayedge::TlsTcpCarrier& tls,
        relayedge::WssH1Carrier& wss,
        std::uint64_t generation,
        const RelayClientConfig& config,
        const std::shared_ptr<RelayEventQueue>& events) noexcept;

    IRelayEventNotifier* notifier_ = nullptr;
    relay::INodeIdentitySigner* signer_ = nullptr;
    std::mutex mutex_;
    std::condition_variable stopped_cv_;
    std::thread worker_;
    std::uint64_t generation_ = 0;
    bool stop_requested_ = false;
    struct PendingServerRoute {
        relay::EprAddressFamily family = relay::EprAddressFamily::None;
        relay::EprAddressBytes address{};
        std::uint16_t port = 0;
        std::uint64_t serial = 0;
    };
    std::mutex route_mutex_;
    PendingServerRoute pending_server_route_{};
    std::atomic<bool> data_plane_ready_{false};
    std::atomic<std::uint16_t> public_tcp_port_{0};
    std::atomic<std::uint16_t> loopback_proxy_port_{0};
};

} // namespace relayclient
