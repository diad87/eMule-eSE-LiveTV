// SPDX-License-Identifier: MIT
#include "relayclient/relay_client.h"
#include "relayclient/relay_wss_transport.h"

#include "edge/tls_tcp_carrier.h"
#include "edge/wss_carrier.h"
#include "edge/wss_h1.h"

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <thread>
#include <vector>

namespace {

std::uint64_t g_checks = 0;

void Check(bool condition, const char* expression, int line) {
    ++g_checks;
    if (!condition) {
        std::cerr << "CHECK failed at line " << line << ": " << expression << '\n';
        std::exit(1);
    }
}

#define CHECK(value) Check((value), #value, __LINE__)

relay::RelayStatus ReceiveHttp(relayedge::IRelayCarrier& carrier,
                               std::vector<relay::Byte>& bytes) {
    bytes.clear();
    while (bytes.size() < relayedge::kMaxWssHandshakeBytes) {
        std::array<relay::Byte, 2048> chunk{};
        std::size_t received = 0;
        const relay::RelayStatus status = carrier.Receive(chunk.data(), chunk.size(), received);
        if (status != relay::RelayStatus::Ok)
            return status;
        bytes.insert(bytes.end(), chunk.begin(), chunk.begin() + received);
        if (bytes.size() >= 4) {
            for (std::size_t i = 3; i < bytes.size(); ++i) {
                if (bytes[i - 3] == '\r' && bytes[i - 2] == '\n' &&
                    bytes[i - 1] == '\r' && bytes[i] == '\n')
                    return relay::RelayStatus::Ok;
            }
        }
    }
    return relay::RelayStatus::TooLarge;
}

class CountingNotifier final : public relayclient::IRelayEventNotifier {
public:
    void Notify(std::uint64_t generation) noexcept override {
        ++calls;
        last_generation = generation;
        worker_thread = std::this_thread::get_id();
    }
    std::atomic<std::uint64_t> calls{0};
    std::atomic<std::uint64_t> last_generation{0};
    std::thread::id worker_thread{};
};

relayclient::RelayClientConfig Config(std::uint16_t port, const char* ca) {
    relayclient::RelayClientConfig config;
    config.enabled = true;
    config.endpoint_host = "127.0.0.1";
    config.endpoint_port = port;
    config.expected_server_name = "localhost";
    config.ca_bundle_path = ca;
    config.reconnect_min_ms = 100;
    config.reconnect_max_ms = 1000;
    config.lease_grace_ms = 100;
    return config;
}

void TestClientH1Helpers() {
    std::vector<relay::Byte> request;
    std::string key;
    CHECK(relayedge::BuildWssClientUpgradeRequest("relay.example", "/krp/v1",
                                                   request, key) == relay::RelayStatus::Ok);
    CHECK(key.size() == 24);
    relayedge::WssUpgradeRequest parsed;
    CHECK(relayedge::ParseWssUpgradeRequest(request.data(), request.size(), parsed) ==
          relay::RelayStatus::Ok);
    std::vector<relay::Byte> response;
    CHECK(relayedge::BuildWssUpgradeResponse(parsed, response) == relay::RelayStatus::Ok);
    std::size_t consumed = 0;
    CHECK(relayedge::ParseWssUpgradeResponse(response.data(), response.size(), key, consumed) ==
          relay::RelayStatus::Ok);
    CHECK(consumed == response.size());
    response[9] = '4';
    CHECK(relayedge::ParseWssUpgradeResponse(response.data(), response.size(), key, consumed) !=
          relay::RelayStatus::Ok);
    CHECK(relayedge::BuildWssClientUpgradeRequest("bad\r\nhost", "/krp/v1",
                                                   request, key) ==
          relay::RelayStatus::InvalidArgument);
    CHECK(relayedge::BuildWssClientUpgradeRequest("relay.example", "/other",
                                                   request, key) ==
          relay::RelayStatus::InvalidArgument);
}

void TestRealTransport(const char* certificate, const char* private_key,
                       const char* ca) {
    relayedge::LabTlsListener listener;
    CHECK(listener.Open("127.0.0.1", 0) == relay::RelayStatus::Ok);
    relayedge::TlsTcpCarrier server;
    relay::RelayStatus server_status = relay::RelayStatus::InvalidState;
    std::thread server_thread([&]() {
        server_status = listener.Accept(certificate, private_key, server);
        if (server_status != relay::RelayStatus::Ok)
            return;
        std::vector<relay::Byte> http;
        server_status = ReceiveHttp(server, http);
        if (server_status != relay::RelayStatus::Ok)
            return;
        relayedge::WssUpgradeRequest upgrade;
        server_status = relayedge::ParseWssUpgradeRequest(http.data(), http.size(), upgrade);
        if (server_status != relay::RelayStatus::Ok)
            return;
        std::vector<relay::Byte> response;
        server_status = relayedge::BuildWssUpgradeResponse(upgrade, response);
        if (server_status != relay::RelayStatus::Ok)
            return;
        server_status = server.Send(response.data(), response.size());
        if (server_status != relay::RelayStatus::Ok)
            return;
        relayedge::WssH1Carrier wss(server, false);
        std::array<relay::Byte, 128> ignored{};
        std::size_t received = 0;
        std::size_t wait_slices = 0;
        do {
            server_status = wss.Receive(ignored.data(), ignored.size(), received);
        } while (server_status == relay::RelayStatus::Truncated && ++wait_slices < 20);
    });

    const std::thread::id main_thread = std::this_thread::get_id();
    CountingNotifier notifier;
    relayclient::RelayWssTransport transport(&notifier);
    relayclient::RelayClientManager manager(transport);
    CHECK(manager.Configure(Config(listener.bound_port(), ca)) == relay::RelayStatus::Ok);
    CHECK(manager.Start(0) == relay::RelayStatus::Ok);
    bool wss_ready = false;
    bool ticks_ok = true;
    for (std::uint64_t now = 1; now <= 5000; ++now) {
        if (manager.Tick(now) != relay::RelayStatus::Ok) {
            ticks_ok = false;
            break;
        }
        if (manager.Snapshot().carrier == relayclient::RelayCarrierState::WssReady) {
            wss_ready = true;
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    CHECK(ticks_ok);
    CHECK(wss_ready);
    CHECK(manager.Snapshot().session == relayclient::RelaySessionState::None);
    CHECK(manager.Snapshot().ed2k == relayclient::RelayEd2kState::LowId);
    CHECK(manager.Snapshot().route == relayclient::RelayRouteState::RelayConnecting);
    CHECK(notifier.calls >= 2);
    CHECK(notifier.last_generation == manager.Snapshot().generation);
    CHECK(notifier.worker_thread != main_thread);
    CHECK(manager.Disable() == relay::RelayStatus::Ok);
    server_thread.join();
    CHECK(server_status == relay::RelayStatus::Expired ||
          server_status == relay::RelayStatus::AuthFailed);
    CHECK(manager.Snapshot().carrier == relayclient::RelayCarrierState::Disabled);
    CHECK(manager.Snapshot().route == relayclient::RelayRouteState::Classic);
    server.Close();
    listener.Close();
}

void TestRemoteCloseSchedulesReconnect(const char* certificate,
                                       const char* private_key,
                                       const char* ca) {
    relayedge::LabTlsListener listener;
    CHECK(listener.Open("127.0.0.1", 0) == relay::RelayStatus::Ok);
    relayedge::TlsTcpCarrier server;
    relay::RelayStatus server_status = relay::RelayStatus::InvalidState;
    std::thread server_thread([&]() {
        server_status = listener.Accept(certificate, private_key, server);
        if (server_status != relay::RelayStatus::Ok)
            return;
        std::vector<relay::Byte> http;
        server_status = ReceiveHttp(server, http);
        relayedge::WssUpgradeRequest upgrade;
        if (server_status == relay::RelayStatus::Ok)
            server_status = relayedge::ParseWssUpgradeRequest(http.data(), http.size(), upgrade);
        std::vector<relay::Byte> response;
        if (server_status == relay::RelayStatus::Ok)
            server_status = relayedge::BuildWssUpgradeResponse(upgrade, response);
        if (server_status == relay::RelayStatus::Ok)
            server_status = server.Send(response.data(), response.size());
        if (server_status == relay::RelayStatus::Ok) {
            relayedge::WssH1Carrier wss(server, false);
            wss.Close();
        }
    });

    relayclient::RelayWssTransport transport;
    relayclient::RelayClientManager manager(transport);
    CHECK(manager.Configure(Config(listener.bound_port(), ca)) == relay::RelayStatus::Ok);
    CHECK(manager.Start(1000) == relay::RelayStatus::Ok);
    bool backoff = false;
    bool ticks_ok = true;
    for (std::uint64_t now = 1001; now <= 6000; ++now) {
        if (manager.Tick(now) != relay::RelayStatus::Ok) {
            ticks_ok = false;
            break;
        }
        if (manager.Snapshot().carrier == relayclient::RelayCarrierState::Backoff) {
            backoff = true;
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    CHECK(ticks_ok);
    CHECK(backoff);
    CHECK(manager.Snapshot().reason == relayclient::RelayReason::RemoteClosed);
    CHECK(manager.Snapshot().route == relayclient::RelayRouteState::FallbackClassic);
    CHECK(manager.Snapshot().ed2k == relayclient::RelayEd2kState::LowId);
    CHECK(manager.Metrics().reconnects_scheduled == 1);
    CHECK(manager.Disable() == relay::RelayStatus::Ok);
    server_thread.join();
    CHECK(server_status == relay::RelayStatus::Ok);
    server.Close();
    listener.Close();
}

} // namespace

int main(int argc, char** argv) {
    if (argc != 4) {
        std::cerr << "usage: test_relay_wss_transport CERT KEY CA\n";
        return 2;
    }
    TestClientH1Helpers();
    TestRealTransport(argv[1], argv[2], argv[3]);
    TestRemoteCloseSchedulesReconnect(argv[1], argv[2], argv[3]);
    std::cout << "librelayclient P3 TLS/WSS transport passed: " << g_checks
              << " checks, worker-to-main queue only\n";
    return 0;
}
