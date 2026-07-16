// SPDX-License-Identifier: MIT
// P4 relay edge: default OFF; public activation requires an explicit validated config.
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include "edge/edge_daemon.h"
#include "edge/krp_p4_crypto.h"
#include "edge/krp_tcp_session.h"
#include "edge/wss_carrier.h"
#include "edge/wss_h1.h"
#include "relay/krp_control.h"
#include "relay/relay_core.h"

#include <array>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

namespace {

std::uint64_t NowMs() noexcept {
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
}

int SelfTest() {
    const relay::RelayCoreBuildInfo& info = relay::GetRelayCoreBuildInfo();
    relayedge::EdgeConfig disabled;
    if (info.wire_enabled || info.public_mode_enabled || relay::RelayCoreCanOpenNetwork() ||
        relayedge::ValidateEdgeConfig(disabled) != relay::RelayStatus::Disabled) {
        std::fputs("relayedge self-test: FAIL (fail-closed invariant broken)\n", stderr);
        return 1;
    }
    std::printf("relayedge P4: PASS (KRP %u.%u, default OFF, explicit activation required)\n",
                static_cast<unsigned>(info.version_major),
                static_cast<unsigned>(info.version_minor));
    return 0;
}

int GenerateToken(const char* path) {
    if (path == nullptr || *path == '\0') return 3;
    std::ifstream existing(path, std::ios::binary);
    if (existing.good()) {
        std::fputs("relayedge: refusing to overwrite existing token file\n", stderr);
        return 3;
    }
    relayedge::KrpAuthToken token{};
    if (relayedge::SecureRandom(token.data(), token.size()) != relay::RelayStatus::Ok)
        return 4;
    static constexpr char hex[] = "0123456789abcdef";
    std::string encoded(token.size() * 2, '0');
    for (std::size_t i = 0; i < token.size(); ++i) {
        encoded[i * 2] = hex[token[i] >> 4];
        encoded[i * 2 + 1] = hex[token[i] & 0x0Fu];
    }
    SecureZeroMemory(token.data(), token.size());
    std::ofstream output(path, std::ios::binary | std::ios::out);
    if (!output) return 4;
    output << encoded << '\n';
    output.close();
    SecureZeroMemory(encoded.data(), encoded.size());
    if (!output) return 4;
    std::printf("relayedge: generated deployment token; restrict its ACL: %s\n", path);
    return 0;
}

int LoadConfig(const char* path, relayedge::EdgeConfig& config) {
    const relay::RelayStatus status = relayedge::LoadEdgeConfig(path, config);
    if (status != relay::RelayStatus::Ok) {
        std::fprintf(stderr, "relayedge: config rejected: %s\n",
                     relay::RelayStatusName(status));
        return 3;
    }
    return 0;
}

int CheckConfig(const char* path) {
    relayedge::EdgeConfig config;
    const int loaded = LoadConfig(path, config);
    if (loaded != 0)
        return loaded;
    if (relayedge::ValidateLabTlsCredentials(config.certificate_path.c_str(),
            config.private_key_path.c_str()) != relay::RelayStatus::Ok) {
        std::fputs("relayedge: config rejected: invalid certificate/key\n", stderr);
        return 3;
    }
    if (config.mode == relayedge::EdgeMode::ExperimentalPublic) {
        relayedge::KrpAuthToken token{};
        if (relayedge::LoadKrpAuthToken(config.auth_token_path.c_str(), token) !=
            relay::RelayStatus::Ok) {
            std::fputs("relayedge: config rejected: invalid auth token file\n", stderr);
            return 3;
        }
        SecureZeroMemory(token.data(), token.size());
    }
    std::printf("relayedge config: VALID (%s %s:%u, sessions=%zu)\n",
                config.mode == relayedge::EdgeMode::ExperimentalPublic
                    ? "experimental-public" : "lab-loopback",
                config.bind_address.c_str(), static_cast<unsigned>(config.port), config.max_sessions);
    return 0;
}

int StartupCheck(const char* path) {
    relayedge::EdgeConfig config;
    const int loaded = LoadConfig(path, config);
    if (loaded != 0)
        return loaded;
    relayedge::EdgeDaemon daemon;
    const std::uint64_t now = NowMs();
    relay::RelayStatus status = daemon.Start(config, now);
    if (status != relay::RelayStatus::Ok) {
        std::fprintf(stderr, "relayedge startup: FAIL (%s)\n",
                     relay::RelayStatusName(status));
        return 4;
    }
    std::printf("relayedge health: HEALTHY (loopback port %u)\n",
                static_cast<unsigned>(daemon.bound_port()));
    status = daemon.BeginDrain(now + 1, now + 2);
    if (status == relay::RelayStatus::Ok)
        status = daemon.Tick(now + 2);
    if (status != relay::RelayStatus::Expired || daemon.bound_port() != 0) {
        std::fputs("relayedge shutdown: FAIL\n", stderr);
        return 5;
    }
    std::fputs("relayedge shutdown: DRAINED (no listener orphan)\n", stdout);
    return 0;
}

relay::RelayStatus ReceiveHttp(relayedge::TlsTcpCarrier& carrier,
                               std::vector<relay::Byte>& bytes) {
    std::array<relay::Byte, 1024> chunk{};
    for (std::size_t attempt = 0; attempt < 16; ++attempt) {
        std::size_t received = 0;
        relay::RelayStatus status =
            carrier.Receive(chunk.data(), chunk.size(), received);
        if (status != relay::RelayStatus::Ok)
            return status;
        bytes.insert(bytes.end(), chunk.begin(), chunk.begin() + received);
        if (bytes.size() > relayedge::kMaxWssHandshakeBytes)
            return relay::RelayStatus::TooLarge;
        if (std::string(bytes.begin(), bytes.end()).find("\r\n\r\n") !=
            std::string::npos)
            return relay::RelayStatus::Ok;
    }
    return relay::RelayStatus::TooLarge;
}

relay::RelayStatus UpgradeWss(relayedge::TlsTcpCarrier& tls) {
    std::vector<relay::Byte> request_bytes;
    relay::RelayStatus status = ReceiveHttp(tls, request_bytes);
    relayedge::WssUpgradeRequest request;
    if (status == relay::RelayStatus::Ok)
        status = relayedge::ParseWssUpgradeRequest(
            request_bytes.data(), request_bytes.size(), request);
    std::vector<relay::Byte> response;
    if (status == relay::RelayStatus::Ok)
        status = relayedge::BuildWssUpgradeResponse(request, response);
    if (status == relay::RelayStatus::Ok)
        status = tls.Send(response.data(), response.size());
    return status;
}

int ServePingOnce(const char* path) {
    relayedge::EdgeConfig config;
    const int loaded = LoadConfig(path, config);
    if (loaded != 0)
        return loaded;
    relayedge::EdgeDaemon daemon;
    const std::uint64_t started_at = NowMs();
    relay::RelayStatus status = daemon.Start(config, started_at);
    if (status != relay::RelayStatus::Ok) {
        std::fprintf(stderr, "relayedge serve: startup failed (%s)\n",
                     relay::RelayStatusName(status));
        return 4;
    }
    std::printf("relayedge lab: listening on %s:%u for one WSS KRP PING\n",
                config.bind_address.c_str(), static_cast<unsigned>(daemon.bound_port()));
    relayedge::TlsTcpCarrier tls;
    status = daemon.AcceptTls(tls);
    if (status == relay::RelayStatus::Ok) {
        std::vector<relay::Byte> request_bytes;
        status = ReceiveHttp(tls, request_bytes);
        relayedge::WssUpgradeRequest request;
        if (status == relay::RelayStatus::Ok)
            status = relayedge::ParseWssUpgradeRequest(
                request_bytes.data(), request_bytes.size(), request);
        std::vector<relay::Byte> response;
        if (status == relay::RelayStatus::Ok)
            status = relayedge::BuildWssUpgradeResponse(request, response);
        if (status == relay::RelayStatus::Ok)
            status = tls.Send(response.data(), response.size());
        if (status == relay::RelayStatus::Ok) {
            relayedge::WssH1Carrier wss(tls, false);
            std::vector<relay::Byte> wire(relayedge::kMaxWssPayloadBytes);
            std::size_t received = 0;
            status = wss.Receive(wire.data(), wire.size(), received);
            wire.resize(received);
            relay::KrpControlFrame ping;
            std::size_t consumed = 0;
            if (status == relay::RelayStatus::Ok)
                status = relay::DecodeKrpControlFrame(
                    wire.data(), wire.size(), ping, consumed);
            if (status == relay::RelayStatus::Ok &&
                (consumed != wire.size() || ping.type != static_cast<std::uint64_t>(
                    relay::KrpMessageType::KRP_PING)))
                status = relay::RelayStatus::UnsupportedMessage;
            relay::KrpControlFrame pong;
            pong.type = static_cast<std::uint64_t>(relay::KrpMessageType::KRP_PONG);
            pong.flags = relay::kKrpFlagIdempotent;
            pong.payload = ping.payload;
            std::vector<relay::Byte> pong_wire;
            if (status == relay::RelayStatus::Ok)
                status = relay::EncodeKrpControlFrame(pong, pong_wire);
            if (status == relay::RelayStatus::Ok)
                status = wss.Send(pong_wire.data(), pong_wire.size());
        }
    }
    tls.Close();
    (void)daemon.Kill(NowMs());
    if (status != relay::RelayStatus::Ok) {
        std::fprintf(stderr, "relayedge lab: session failed (%s)\n",
                     relay::RelayStatusName(status));
        return 6;
    }
    std::fputs("relayedge lab: KRP PING/PONG served; daemon drained\n", stdout);
    return 0;
}

int ServeTcp(const char* path) {
    relayedge::EdgeConfig config;
    const int loaded = LoadConfig(path, config);
    if (loaded != 0) return loaded;
    relayedge::KrpAuthToken token{};
    if (relayedge::LoadKrpAuthToken(config.auth_token_path.c_str(), token) !=
        relay::RelayStatus::Ok) {
        std::fputs("relayedge P4: auth token file rejected\n", stderr);
        return 3;
    }
    SecureZeroMemory(token.data(), token.size());
    relayedge::EdgeDaemon daemon;
    relay::RelayStatus status = daemon.Start(config, NowMs());
    if (status != relay::RelayStatus::Ok) {
        std::fprintf(stderr, "relayedge P4: startup failed (%s)\n",
                     relay::RelayStatusName(status));
        return 4;
    }
    std::printf("relayedge P4: control WSS on %s:%u; lease range %u-%u; advertised IPv4 %s\n",
        config.bind_address.c_str(), static_cast<unsigned>(daemon.bound_port()),
        static_cast<unsigned>(config.lease_first_port),
        static_cast<unsigned>(config.lease_last_port),
        config.mode == relayedge::EdgeMode::LabLoopback ? "127.0.0.1" : config.public_ipv4.c_str());
    std::fputs("relayedge P4: waiting for authenticated clients (Ctrl+C to stop)\n", stdout);
    for (;;) {
        relayedge::TlsTcpCarrier tls;
        status = daemon.AcceptTls(tls);
        if (status == relay::RelayStatus::Ok) status = UpgradeWss(tls);
        relayedge::KrpTcpSessionStats stats;
        if (status == relay::RelayStatus::Ok) {
            relayedge::WssH1Carrier wss(tls, false);
            status = relayedge::RunKrpTcpSession(daemon, tls, wss, config, stats);
        }
        tls.Close();
        std::printf("relayedge P4: session %s; auth=%I64u lease=%I64u server=%I64u inbound=%I64u tx=%I64u rx=%I64u\n",
            relay::RelayStatusName(status), stats.authenticated, stats.leases,
            stats.server_flows, stats.inbound_flows,
            stats.bytes_to_client, stats.bytes_from_client);
        if (!daemon.CanAcceptSessions()) break;
    }
    (void)daemon.Kill(NowMs());
    return status == relay::RelayStatus::Ok ? 0 : 6;
}

} // namespace

int main(int argc, char** argv) {
    if (argc == 2 && std::strcmp(argv[1], "--self-test") == 0)
        return SelfTest();
    if (argc == 2 && std::strcmp(argv[1], "--version") == 0) {
        const relay::RelayCoreBuildInfo& info = relay::GetRelayCoreBuildInfo();
        std::printf("relayedge P4 KRP %u.%u (experimental TCP, default OFF)\n",
                    static_cast<unsigned>(info.version_major),
                    static_cast<unsigned>(info.version_minor));
        return 0;
    }
    if (argc == 3 && std::strcmp(argv[1], "--check-config") == 0)
        return CheckConfig(argv[2]);
    if (argc == 3 && std::strcmp(argv[1], "--generate-token") == 0)
        return GenerateToken(argv[2]);
    if (argc == 3 && std::strcmp(argv[1], "--lab-startup-check") == 0)
        return StartupCheck(argv[2]);
    if (argc == 3 && std::strcmp(argv[1], "--lab-serve-ping-once") == 0)
        return ServePingOnce(argv[2]);
    if (argc == 3 && (std::strcmp(argv[1], "--experimental-serve") == 0 ||
                      std::strcmp(argv[1], "--lab-serve-tcp") == 0))
        return ServeTcp(argv[2]);

    std::fputs(
        "relayedge: default OFF; use --generate-token, --check-config, --lab-startup-check, --lab-serve-tcp or --experimental-serve\n",
        stderr);
    return 2;
}
