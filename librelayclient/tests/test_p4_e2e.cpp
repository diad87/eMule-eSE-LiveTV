// SPDX-License-Identifier: MIT
// P4 loopback E2E: classic bytes cross client->WSS->edge->server and a real
// inbound TCP connection crosses edge->WSS->the local eMule listener.
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>

#include "relayclient/relay_client.h"
#include "relayclient/relay_wss_transport.h"
#include "edge/edge_daemon.h"
#include "edge/krp_tcp_session.h"
#include "edge/wss_h1.h"
#include "../../cryptopp/xed25519.h"
#include "../../cryptopp/osrng.h"

#include <array>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <string>
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

struct SocketOwner {
    SOCKET value = INVALID_SOCKET;
    SocketOwner() = default;
    explicit SocketOwner(SOCKET socket) : value(socket) {}
    ~SocketOwner() { if (value != INVALID_SOCKET) closesocket(value); }
    SocketOwner(const SocketOwner&) = delete;
    SocketOwner& operator=(const SocketOwner&) = delete;
    SocketOwner(SocketOwner&& other) noexcept : value(other.value) { other.value = INVALID_SOCKET; }
};

SocketOwner Listen(std::uint16_t& port) {
    SocketOwner socket(::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));
    CHECK(socket.value != INVALID_SOCKET);
    BOOL exclusive = TRUE;
    CHECK(setsockopt(socket.value, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
        reinterpret_cast<const char*>(&exclusive), sizeof(exclusive)) == 0);
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.S_un.S_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = 0;
    CHECK(bind(socket.value, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) == 0);
    CHECK(listen(socket.value, SOMAXCONN) == 0);
    int size = sizeof(address);
    CHECK(getsockname(socket.value, reinterpret_cast<sockaddr*>(&address), &size) == 0);
    port = ntohs(address.sin_port);
    CHECK(port != 0);
    return socket;
}

std::uint16_t FindFreePort() {
    std::uint16_t port = 0;
    SocketOwner temporary = Listen(port);
    return port;
}

SocketOwner Connect(std::uint16_t port) {
    SocketOwner socket(::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));
    if (socket.value == INVALID_SOCKET) return socket;
    DWORD timeout = 10000;
    (void)setsockopt(socket.value, SOL_SOCKET, SO_RCVTIMEO,
        reinterpret_cast<const char*>(&timeout), sizeof(timeout));
    (void)setsockopt(socket.value, SOL_SOCKET, SO_SNDTIMEO,
        reinterpret_cast<const char*>(&timeout), sizeof(timeout));
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.S_un.S_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons(port);
    if (connect(socket.value, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) != 0) {
        closesocket(socket.value); socket.value = INVALID_SOCKET;
    }
    return socket;
}

bool SendAll(SOCKET socket, const std::vector<relay::Byte>& bytes) {
    std::size_t sent = 0;
    while (sent < bytes.size()) {
        const int result = send(socket,
            reinterpret_cast<const char*>(bytes.data() + sent),
            static_cast<int>(bytes.size() - sent), 0);
        if (result <= 0) return false;
        sent += static_cast<std::size_t>(result);
    }
    return true;
}

bool ReceiveExact(SOCKET socket, std::vector<relay::Byte>& bytes, std::size_t size) {
    bytes.resize(size);
    std::size_t received = 0;
    while (received < size) {
        const int result = recv(socket,
            reinterpret_cast<char*>(bytes.data() + received),
            static_cast<int>(size - received), 0);
        if (result <= 0) return false;
        received += static_cast<std::size_t>(result);
    }
    return true;
}

relay::RelayStatus ReceiveHttp(relayedge::TlsTcpCarrier& carrier,
                               std::vector<relay::Byte>& bytes) {
    bytes.clear();
    while (bytes.size() < relayedge::kMaxWssHandshakeBytes) {
        std::array<relay::Byte, 2048> chunk{};
        std::size_t received = 0;
        const relay::RelayStatus status = carrier.Receive(chunk.data(), chunk.size(), received);
        if (status != relay::RelayStatus::Ok) return status;
        bytes.insert(bytes.end(), chunk.begin(), chunk.begin() + received);
        const std::string text(bytes.begin(), bytes.end());
        if (text.find("\r\n\r\n") != std::string::npos) return relay::RelayStatus::Ok;
    }
    return relay::RelayStatus::TooLarge;
}

class TestIdentity final : public relay::INodeIdentitySigner {
public:
    TestIdentity() {
        CryptoPP::AutoSeededRandomPool random;
        key_.GenerateRandom(random, CryptoPP::g_nullNameValuePairs);
        std::copy(key_.GetPublicKeyBytePtr(), key_.GetPublicKeyBytePtr() + node_.size(), node_.begin());
    }
    bool IsPersistent() const noexcept override { return true; }
    const relay::NodeId& PublicNodeId() const noexcept override { return node_; }
    bool Sign(const relay::Byte* message, std::size_t size,
              relay::KrpAuthSignature& signature) noexcept override {
        try {
            CryptoPP::ed25519Signer signer(key_);
            CryptoPP::AutoSeededRandomPool random;
            return signer.SignMessage(random, message, size, signature.data()) == signature.size();
        } catch (...) { return false; }
    }
private:
    CryptoPP::ed25519PrivateKey key_;
    relay::NodeId node_{};
};

bool WaitFor(relayclient::RelayClientManager& manager,
             relayclient::RelayLeaseState lease,
             std::chrono::milliseconds timeout) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    std::uint64_t now = 1;
    while (std::chrono::steady_clock::now() < deadline) {
        if (manager.Tick(now++) != relay::RelayStatus::Ok) return false;
        if (manager.Snapshot().lease == lease) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
    return false;
}

} // namespace

int main(int argc, char** argv) {
    if (argc != 4) {
        std::cerr << "usage: test_p4_e2e CERT KEY CA\n";
        return 2;
    }
    WSADATA winsock{};
    CHECK(WSAStartup(MAKEWORD(2, 2), &winsock) == 0);
    const std::string token_path = "build\\p4-test-token.hex";
    {
        std::ofstream token(token_path, std::ios::binary);
        CHECK(static_cast<bool>(token));
        token << "00112233445566778899aabbccddeeff"
                 "102132435465768798a9bacbdcedfe0f\n";
    }

    std::uint16_t classic_server_port = 0;
    SocketOwner classic_server_listener = Listen(classic_server_port);
    std::uint16_t local_emule_port = 0;
    SocketOwner local_emule_listener = Listen(local_emule_port);
    const std::uint16_t lease_port = FindFreePort();

    relayedge::EdgeConfig edge_config;
    edge_config.mode = relayedge::EdgeMode::LabLoopback;
    edge_config.explicit_lab_enable = true;
    edge_config.bind_address = "127.0.0.1";
    edge_config.port = 0;
    edge_config.certificate_path = argv[1];
    edge_config.private_key_path = argv[2];
    edge_config.auth_token_path = token_path;
    edge_config.max_sessions = 4;
    edge_config.max_flows_per_session = 32;
    edge_config.lease_first_port = lease_port;
    edge_config.lease_last_port = lease_port;
    edge_config.reuse_delay_ms = 1000;
    relayedge::EdgeDaemon daemon;
    CHECK(daemon.Start(edge_config, 1) == relay::RelayStatus::Ok);

    relay::RelayStatus edge_status = relay::RelayStatus::InvalidState;
    relayedge::KrpTcpSessionStats edge_stats;
    std::thread edge([&]() {
        relayedge::TlsTcpCarrier tls;
        edge_status = daemon.AcceptTls(tls);
        std::vector<relay::Byte> http;
        if (edge_status == relay::RelayStatus::Ok) edge_status = ReceiveHttp(tls, http);
        relayedge::WssUpgradeRequest request;
        if (edge_status == relay::RelayStatus::Ok)
            edge_status = relayedge::ParseWssUpgradeRequest(http.data(), http.size(), request);
        std::vector<relay::Byte> response;
        if (edge_status == relay::RelayStatus::Ok)
            edge_status = relayedge::BuildWssUpgradeResponse(request, response);
        if (edge_status == relay::RelayStatus::Ok)
            edge_status = tls.Send(response.data(), response.size());
        if (edge_status == relay::RelayStatus::Ok) {
            relayedge::WssH1Carrier wss(tls, false);
            edge_status = relayedge::RunKrpTcpSession(daemon, tls, wss,
                edge_config, edge_stats);
        }
        tls.Close();
    });

    const std::vector<relay::Byte> callback_hello =
        {0xE3, 0x03, 0x00, 0x00, 0x00, 0x01, 0xCA, 0x11};
    const std::vector<relay::Byte> callback_answer =
        {0xC5, 0x03, 0x00, 0x00, 0x00, 0x4C, 0xAB, 0x22};
    const std::vector<relay::Byte> peer_hello =
        {0xE3, 0x03, 0x00, 0x00, 0x00, 0x01, 0xBB, 0x33};
    const std::vector<relay::Byte> peer_answer =
        {0xC5, 0x03, 0x00, 0x00, 0x00, 0x4C, 0xCC, 0x44};
    std::vector<relay::Byte> peer_bulk(256u * 1024u);
    for (std::size_t i = 0; i < peer_bulk.size(); ++i)
        peer_bulk[i] = static_cast<relay::Byte>((i * 131u + 17u) & 0xFFu);
    std::atomic<bool> callback_ok{false};
    std::atomic<bool> peer_ok{false};
    std::thread local_emule([&]() {
        for (int index = 0; index < 2; ++index) {
            SocketOwner inbound(accept(local_emule_listener.value, nullptr, nullptr));
            if (inbound.value == INVALID_SOCKET) return;
            std::vector<relay::Byte> received;
            const std::vector<relay::Byte>& expected = index == 0 ? callback_hello : peer_hello;
            const std::vector<relay::Byte>& answer = index == 0 ? callback_answer : peer_answer;
            bool ok = ReceiveExact(inbound.value, received, expected.size()) &&
                received == expected && SendAll(inbound.value, answer);
            if (ok && index == 1) {
                std::vector<relay::Byte> bulk;
                ok = ReceiveExact(inbound.value, bulk, peer_bulk.size()) &&
                    bulk == peer_bulk && SendAll(inbound.value, bulk);
            }
            if (index == 0) callback_ok.store(ok); else peer_ok.store(ok);
        }
    });

    std::atomic<bool> server_login_ok{false};
    std::atomic<bool> callback_return_ok{false};
    std::thread classic_server([&]() {
        SocketOwner server(accept(classic_server_listener.value, nullptr, nullptr));
        if (server.value == INVALID_SOCKET) return;
        std::vector<relay::Byte> login;
        if (!ReceiveExact(server.value, login, 8)) return;
        server_login_ok.store(login[0] == 0xE3 && login[5] == 0x01 &&
            login[6] == static_cast<relay::Byte>(lease_port & 0xFFu) &&
            login[7] == static_cast<relay::Byte>(lease_port >> 8));
        SocketOwner callback = Connect(lease_port);
        if (callback.value == INVALID_SOCKET || !SendAll(callback.value, callback_hello)) return;
        std::vector<relay::Byte> answer;
        callback_return_ok.store(ReceiveExact(callback.value, answer, callback_answer.size()) &&
            answer == callback_answer);
        const std::vector<relay::Byte> id_change =
            {0xE3, 0x05, 0x00, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, 0x7F};
        (void)SendAll(server.value, id_change);
    });

    TestIdentity identity;
    relayclient::RelayWssTransport transport(nullptr, &identity);
    relayclient::RelayClientManager manager(transport);
    relayclient::RelayClientConfig config;
    config.enabled = true;
    config.endpoint_host = "127.0.0.1";
    config.endpoint_port = daemon.bound_port();
    config.expected_server_name = "localhost";
    config.ca_bundle_path = argv[3];
    config.experimental_tcp_data_plane = true;
    config.auth_token_path = token_path;
    config.local_tcp_port = local_emule_port;
    config.reconnect_min_ms = 100;
    config.reconnect_max_ms = 1000;
    CHECK(manager.Configure(config) == relay::RelayStatus::Ok);
    CHECK(manager.Start(1) == relay::RelayStatus::Ok);
    CHECK(WaitFor(manager, relayclient::RelayLeaseState::Active,
        std::chrono::seconds(20)));
    CHECK(transport.DataPlaneReady());
    CHECK(transport.PublicTcpPort() == lease_port);

    std::uint16_t proxy_port = 0;
    CHECK(transport.PrepareEd2kServerRoute("127.0.0.1",
        classic_server_port, proxy_port));
    SocketOwner emule_server = Connect(proxy_port);
    CHECK(emule_server.value != INVALID_SOCKET);
    const std::vector<relay::Byte> login =
        {0xE3, 0x03, 0x00, 0x00, 0x00, 0x01,
         static_cast<relay::Byte>(lease_port & 0xFFu),
         static_cast<relay::Byte>(lease_port >> 8)};
    CHECK(SendAll(emule_server.value, login));
    std::vector<relay::Byte> id_change;
    CHECK(ReceiveExact(emule_server.value, id_change, 10));
    CHECK(id_change[0] == 0xE3 && id_change[5] == 0x40);

    const auto evidence_deadline = std::chrono::steady_clock::now() +
        std::chrono::seconds(10);
    std::uint64_t tick = 1000;
    while (std::chrono::steady_clock::now() < evidence_deadline &&
           manager.Snapshot().endpoint != relayclient::RelayEndpointState::Reachable) {
        CHECK(manager.Tick(tick++) == relay::RelayStatus::Ok);
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
    CHECK(manager.Snapshot().endpoint == relayclient::RelayEndpointState::Reachable);
    CHECK(manager.ApplyEd2kRelayEvidence(true, true, true) == relay::RelayStatus::Ok);
    CHECK(manager.Snapshot().ed2k == relayclient::RelayEd2kState::RelayHighId);

    SocketOwner peer = Connect(lease_port);
    CHECK(peer.value != INVALID_SOCKET);
    CHECK(SendAll(peer.value, peer_hello));
    std::vector<relay::Byte> peer_response;
    CHECK(ReceiveExact(peer.value, peer_response, peer_answer.size()));
    CHECK(peer_response == peer_answer);
    CHECK(SendAll(peer.value, peer_bulk));
    std::vector<relay::Byte> peer_bulk_echo;
    CHECK(ReceiveExact(peer.value, peer_bulk_echo, peer_bulk.size()));
    CHECK(peer_bulk_echo == peer_bulk);

    classic_server.join();
    local_emule.join();
    CHECK(server_login_ok.load());
    CHECK(callback_ok.load());
    CHECK(callback_return_ok.load());
    CHECK(peer_ok.load());
    CHECK(manager.Shutdown() == relay::RelayStatus::Ok);
    edge.join();
    CHECK(edge_status == relay::RelayStatus::Ok ||
          edge_status == relay::RelayStatus::Expired);
    CHECK(edge_stats.authenticated == 1);
    CHECK(edge_stats.leases == 1);
    CHECK(edge_stats.server_flows == 1);
    CHECK(edge_stats.inbound_flows >= 2);
    (void)daemon.Kill(2);
    std::remove(token_path.c_str());
    std::cout << "P4 E2E PASS: " << g_checks
              << " checks; real TLS/WSS auth, lease, server flow, callback, peer, "
                 "IDCHANGE and 256 KiB bidirectional data\n";
    WSACleanup();
    return 0;
}
