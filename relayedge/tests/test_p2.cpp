// SPDX-License-Identifier: MIT
#include "edge/edge_allocator.h"
#include "edge/edge_auth.h"
#include "edge/edge_daemon.h"
#include "edge/edge_policy.h"
#include "edge/tls_tcp_carrier.h"
#include "edge/wss_carrier.h"
#include "edge/wss_h1.h"
#include "relay/krp_control.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#include <thread>
#include <vector>

namespace {

struct TestState {
    std::uint64_t checks = 0;
    bool failed = false;

    void Check(bool condition, const char* message) {
        ++checks;
        if (!condition) {
            std::fprintf(stderr, "FAIL: %s\n", message);
            failed = true;
        }
    }
};

relayedge::EdgeConfig LabConfig() {
    relayedge::EdgeConfig config;
    config.mode = relayedge::EdgeMode::LabLoopback;
    config.explicit_lab_enable = true;
    config.certificate_path = "test-cert";
    config.private_key_path = "test-key";
    config.max_sessions = 4;
    config.max_flows_per_session = 2;
    config.max_leases_per_session = 1;
    config.max_preauth_bytes = 64;
    config.preauth_timeout_ms = 1000;
    config.idle_timeout_ms = 2000;
    config.reuse_delay_ms = 1000;
    return config;
}

relay::KrpSessionBinding Binding(relay::Byte seed) {
    relay::KrpSessionBinding binding;
    binding.session_id.fill(seed);
    binding.node_id.fill(static_cast<relay::Byte>(seed + 1));
    binding.owner_edge_id.fill(static_cast<relay::Byte>(seed + 2));
    binding.fencing_token.fill(static_cast<relay::Byte>(seed + 3));
    binding.session_epoch = seed;
    binding.route_generation = seed;
    return binding;
}

class FakeIdentity final : public relay::INodeIdentitySigner,
                           public relay::IKrpIdentityVerifier {
public:
    explicit FakeIdentity(relay::Byte seed) { node_.fill(seed); }
    bool IsPersistent() const noexcept override { return true; }
    const relay::NodeId& PublicNodeId() const noexcept override { return node_; }
    bool Sign(const relay::Byte* message, std::size_t size,
              relay::KrpAuthSignature& signature) noexcept override {
        if (message == nullptr || size == 0)
            return false;
        for (std::size_t index = 0; index < signature.size(); ++index)
            signature[index] = message[index % size] ^ node_[index % node_.size()] ^
                static_cast<relay::Byte>(index);
        return true;
    }
    bool Verify(const relay::NodeId& node, const relay::Byte* message,
                std::size_t size,
                const relay::KrpAuthSignature& signature) noexcept override {
        if (node != node_ || message == nullptr || size == 0)
            return false;
        relay::KrpAuthSignature expected{};
        if (!Sign(message, size, expected))
            return false;
        return expected == signature;
    }

private:
    relay::NodeId node_{};
};

void TestRuntimeAndSessions(TestState& test, const char* certificate,
                            const char* private_key) {
    relayedge::EdgeConfig config = LabConfig();
    config.certificate_path = certificate;
    config.private_key_path = private_key;
    {
        const char* const oversized_path = "build/p2-oversized.conf";
        std::ofstream output(oversized_path, std::ios::binary);
        const std::string oversized(relayedge::kMaxConfigFileBytes + 1, 'x');
        output.write(oversized.data(), static_cast<std::streamsize>(oversized.size()));
        output.close();
        relayedge::EdgeConfig ignored;
        test.Check(relayedge::LoadEdgeConfig(oversized_path, ignored) ==
                       relay::RelayStatus::TooLarge,
                   "oversized config rejected before parsing");
        (void)std::remove(oversized_path);
    }
    {
        const char* const duplicate_path = "build/p2-duplicate.conf";
        std::ofstream output(duplicate_path, std::ios::binary);
        output << "mode=lab-loopback\nmode=lab-loopback\n";
        output.close();
        relayedge::EdgeConfig ignored;
        test.Check(relayedge::LoadEdgeConfig(duplicate_path, ignored) ==
                       relay::RelayStatus::Malformed,
                   "duplicate config key rejected");
        (void)std::remove(duplicate_path);
    }
    {
        const char* const nul_path = "build/p2-nul.conf";
        std::ofstream output(nul_path, std::ios::binary);
        const std::array<char, 5> bytes = {'m', 'o', '\0', 'd', 'e'};
        output.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
        output.close();
        relayedge::EdgeConfig ignored;
        test.Check(relayedge::LoadEdgeConfig(nul_path, ignored) ==
                       relay::RelayStatus::Malformed,
                   "NUL config rejected");
        (void)std::remove(nul_path);
    }
    test.Check(relayedge::ValidateEdgeConfig(config) == relay::RelayStatus::Ok,
               "valid explicit lab config");
    relayedge::EdgeConfig forbidden = config;
    forbidden.bind_address = "0.0.0.0";
    test.Check(relayedge::ValidateEdgeConfig(forbidden) == relay::RelayStatus::TargetForbidden,
               "wildcard bind denied");
    forbidden = config;
    forbidden.explicit_lab_enable = false;
    test.Check(relayedge::ValidateEdgeConfig(forbidden) == relay::RelayStatus::Disabled,
               "implicit lab mode denied");

    relayedge::EdgeRuntime runtime;
    test.Check(runtime.Start(config, 100) == relay::RelayStatus::Ok,
               "runtime starts");
    test.Check(runtime.health() == relayedge::EdgeHealth::Healthy,
               "runtime healthy");
    test.Check(runtime.BeginDrain(200, 500) == relay::RelayStatus::Ok,
               "runtime begins drain");
    test.Check(!runtime.CanAcceptSessions(), "drain rejects sessions");
    test.Check(runtime.Tick(500) == relay::RelayStatus::Expired,
               "drain deadline stops runtime");

    relayedge::EdgeRuntime killed;
    test.Check(killed.Start(config, 100) == relay::RelayStatus::Ok,
               "kill runtime starts");
    test.Check(killed.Kill(101) == relay::RelayStatus::Ok,
               "kill switch succeeds");
    test.Check(killed.metrics().Get(relayedge::EdgeMetric::KillSwitch) == 1,
               "kill switch metric");
    test.Check(killed.audit().size() == 2, "bounded structured audit records");

    relayedge::EdgeMetrics metrics;
    relayedge::EdgeSessionTable sessions;
    test.Check(sessions.Initialize(config, &metrics) == relay::RelayStatus::Ok,
               "session table initializes");
    relayedge::EdgeSessionHandle handle{};
    test.Check(sessions.Admit(100, handle) == relay::RelayStatus::Ok,
               "preauth admitted");
    test.Check(sessions.AddPreAuthBytes(handle, 64, 101) == relay::RelayStatus::Ok,
               "preauth exact limit");
    test.Check(sessions.Activate(handle, Binding(1), 102) == relay::RelayStatus::Ok,
               "session activates");
    test.Check(sessions.ReserveFlow(handle) == relay::RelayStatus::Ok,
               "first flow quota");
    test.Check(sessions.ReserveFlow(handle) == relay::RelayStatus::Ok,
               "second flow quota");
    test.Check(sessions.ReserveFlow(handle) == relay::RelayStatus::QuotaExceeded,
               "flow quota bounded");
    test.Check(sessions.ReserveLease(handle) == relay::RelayStatus::Ok,
               "first lease quota");
    test.Check(sessions.ReserveLease(handle) == relay::RelayStatus::QuotaExceeded,
               "lease quota bounded");
    test.Check(sessions.Tick(2102) == 1, "idle session expires");
    test.Check(sessions.Get(handle) == nullptr, "stale handle invalidated");

    relayedge::EdgeSessionHandle oversized{};
    test.Check(sessions.Admit(3000, oversized) == relay::RelayStatus::Ok,
               "new preauth admitted");
    test.Check(sessions.AddPreAuthBytes(oversized, 65, 3001) == relay::RelayStatus::TooLarge,
               "preauth byte cap closes session");
    test.Check(sessions.occupied_count() == 0, "oversized preauth slot released");

    relayedge::EdgeDaemon daemon;
    test.Check(daemon.Start(config, 5000) == relay::RelayStatus::Ok,
               "single-host daemon starts");
    test.Check(daemon.health() == relayedge::EdgeHealth::Healthy &&
                   daemon.bound_port() != 0,
               "daemon health and loopback listener active");
    relayedge::EdgeSessionHandle daemon_session{};
    test.Check(daemon.sessions().Admit(5001, daemon_session) == relay::RelayStatus::Ok &&
                   daemon.sessions().Activate(daemon_session, Binding(20), 5002) ==
                       relay::RelayStatus::Ok,
               "daemon owns active session");
    relayedge::EdgePortLease daemon_lease;
    test.Check(daemon.allocator().Allocate(daemon_session, daemon.sessions(), 20, 5003,
                   daemon_lease) == relay::RelayStatus::Ok,
               "daemon owns bounded lease");
    test.Check(daemon.BeginDrain(5004, 5100) == relay::RelayStatus::Ok &&
                   !daemon.CanAcceptSessions() && daemon.bound_port() == 0,
               "GOAWAY drain closes admission listener");
    test.Check(daemon.Tick(5100) == relay::RelayStatus::Expired &&
                   daemon.allocator().live_count() == 0 &&
                   daemon.sessions().occupied_count() == 0,
               "drain deadline leaves no session or exterior lease orphan");

    relayedge::EdgeConfig bad_credentials = config;
    bad_credentials.certificate_path = "missing-relayedge-certificate.pem";
    relayedge::EdgeDaemon rejected_daemon;
    test.Check(rejected_daemon.Start(bad_credentials, 6000) ==
                   relay::RelayStatus::AuthFailed && rejected_daemon.bound_port() == 0,
               "invalid TLS credentials fail health before listener activation");
}

void TestAuthAllocatorAndPolicy(TestState& test) {
    relayedge::EdgeConfig config = LabConfig();
    relayedge::EdgeMetrics metrics;
    relayedge::EdgeSessionTable sessions;
    test.Check(sessions.Initialize(config, &metrics) == relay::RelayStatus::Ok,
               "auth session table initializes");

    FakeIdentity identity(9);
    relay::KrpAuthTranscriptContext context;
    context.carrier_profile = relay::KrpCarrierProfile::WssH1;
    context.challenge_timestamp = 100;
    context.node_id = identity.PublicNodeId();
    context.client_nonce.fill(1);
    context.relay_id.fill(2);
    context.relay_nonce.fill(3);
    context.carrier_binding.fill(4);
    context.settings_hash.fill(5);
    relay::KrpAuthResponse response;
    test.Check(relay::SignKrpAuthTranscript(context, identity, response) ==
                   relay::RelayStatus::Ok,
               "auth transcript signed");
    relay::KrpSessionBinding binding = Binding(7);
    binding.node_id = identity.PublicNodeId();
    relayedge::EdgeSessionHandle authenticated{};
    test.Check(sessions.Admit(100, authenticated) == relay::RelayStatus::Ok,
               "auth slot admitted");
    test.Check(relayedge::AuthenticateEdgeSession(sessions, authenticated, context,
               response, identity, binding, 101) == relay::RelayStatus::Ok,
               "carrier-bound KRP auth activates session");

    relayedge::EdgeTcpAllocator allocator;
    test.Check(allocator.Initialize(40000, 40000, config.reuse_delay_ms, &metrics) ==
                   relay::RelayStatus::Ok,
               "allocator initializes");
    relayedge::EdgePortLease lease;
    test.Check(allocator.Allocate(authenticated, sessions, 1, 102, lease) ==
                   relay::RelayStatus::Ok,
               "authenticated owner gets allocation");
    relayedge::EdgePortLease quota_lease;
    test.Check(allocator.Allocate(authenticated, sessions, 2, 102, quota_lease) ==
                   relay::RelayStatus::QuotaExceeded,
               "allocator enforces per-session lease quota itself");
    test.Check(!allocator.CanAnnounce(lease.lease_id, lease.generation),
               "allocated endpoint not announced");
    test.Check(allocator.MarkBound(lease.lease_id, lease.generation) == relay::RelayStatus::Ok,
               "lease bound");
    test.Check(!allocator.CanAnnounce(lease.lease_id, lease.generation),
               "bound endpoint not announced");
    relay::EprProbeNonce nonce{};
    nonce.fill(6);
    test.Check(allocator.BeginProbe(lease.lease_id, lease.generation, nonce) ==
                   relay::RelayStatus::Ok,
               "probe begins");
    relay::EprProbeNonce wrong = nonce;
    wrong[0] ^= 1;
    test.Check(allocator.CompleteProbe(lease.lease_id, lease.generation, wrong, true, 103) ==
                   relay::RelayStatus::AuthFailed,
               "wrong probe nonce rejected");
    test.Check(!allocator.CanAnnounce(lease.lease_id, lease.generation),
               "failed probe cannot announce");
    test.Check(allocator.CompleteProbe(lease.lease_id, lease.generation, nonce, true, 104) ==
                   relay::RelayStatus::Ok,
               "probe activates endpoint");
    test.Check(allocator.CanAnnounce(lease.lease_id, lease.generation),
               "only active probed endpoint announces");
    test.Check(allocator.Release(lease.lease_id, lease.generation, 105) ==
                   relay::RelayStatus::Ok,
               "active lease released");
    relayedge::EdgePortLease early_reuse;
    test.Check(allocator.Allocate(authenticated, sessions, 2, 1104, early_reuse) ==
                   relay::RelayStatus::QuotaExceeded,
               "allocation still enforces reuse delay");
    relayedge::EdgePortLease reclaimed;
    test.Check(allocator.Allocate(authenticated, sessions, 2, 1105, reclaimed) ==
                   relay::RelayStatus::Ok,
               "allocation reclaims an expired reuse-delay port without an external tick");
    test.Check(allocator.Release(reclaimed.lease_id, reclaimed.generation, 1106) ==
                   relay::RelayStatus::Ok &&
                   allocator.Tick(2106) == 1,
               "reclaimed test lease is released");

    relayedge::EdgeSessionHandle failed{};
    test.Check(sessions.Admit(200, failed) == relay::RelayStatus::Ok,
               "failed auth slot admitted");
    relay::KrpAuthResponse bad = response;
    bad.signature[0] ^= 1;
    test.Check(relayedge::AuthenticateEdgeSession(sessions, failed, context, bad,
               identity, binding, 201) == relay::RelayStatus::AuthFailed,
               "bad auth rejected");
    relayedge::EdgePortLease forbidden_lease;
    test.Check(allocator.Allocate(failed, sessions, 2, 202, forbidden_lease) ==
                   relay::RelayStatus::AuthFailed,
               "failed auth consumes no lease");
    test.Check(allocator.live_count() == 0, "no live lease after failed auth");

    relayedge::EdgePolicyConfig policy_config;
    policy_config.relay_listener_port = 8443;
    policy_config.explicit_lab_loopback_port_test = true;
    relayedge::EdgePolicyEngine policy(policy_config, nullptr, &metrics);
    relayedge::EdgeTarget target;
    target.family = relay::EprAddressFamily::IPv4;
    target.address[0] = 8; target.address[1] = 8;
    target.address[2] = 8; target.address[3] = 8;
    target.port = 4661;
    test.Check(policy.Check(relay::KrpService::Ed2kServer, target) == relay::RelayStatus::Ok,
               "public authorized service target allowed");
    target.address[0] = 127; target.address[1] = 0;
    target.address[2] = 0; target.address[3] = 1;
    test.Check(policy.Check(relay::KrpService::Ed2kServer, target) ==
                   relay::RelayStatus::TargetForbidden,
               "loopback target denied");
    test.Check(policy.RevalidateBeforeConnect(relay::KrpService::LegacyTcpOutbound,
               target) == relay::RelayStatus::TargetForbidden,
               "loopback denied again at connect");
    test.Check(policy.Check(relay::KrpService::PortTest, target) == relay::RelayStatus::Ok,
               "explicit loopback port-test exception");
    target.address[0] = 169; target.address[1] = 254;
    target.port = 80;
    test.Check(policy.Check(relay::KrpService::LegacyTcpOutbound, target) ==
                   relay::RelayStatus::TargetForbidden,
               "metadata/link-local target denied");
    target.address[0] = 8; target.address[1] = 8;
    target.port = 53;
    test.Check(policy.Check(relay::KrpService::LegacyTcpOutbound, target) ==
                   relay::RelayStatus::TargetForbidden,
               "infrastructure port denied");
    target.port = 8443;
    test.Check(policy.Check(relay::KrpService::LegacyTcpOutbound, target) ==
                   relay::RelayStatus::TargetForbidden,
               "relay control port denied");
    target.port = 4662;
    test.Check(policy.Check(static_cast<relay::KrpService>(255), target) ==
                   relay::RelayStatus::TargetForbidden,
               "unknown service denied fail-closed");
}

void TestWss(TestState& test) {
    const std::string request_text =
        "GET /krp/v1 HTTP/1.1\r\nHost: 127.0.0.1\r\nUpgrade: websocket\r\n"
        "Connection: keep-alive, Upgrade\r\nSec-WebSocket-Version: 13\r\n"
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        "Sec-WebSocket-Protocol: other, krp.v1\r\n\r\n";
    relayedge::WssUpgradeRequest request;
    test.Check(relayedge::ParseWssUpgradeRequest(
        reinterpret_cast<const relay::Byte*>(request_text.data()), request_text.size(),
        request) == relay::RelayStatus::Ok, "valid bounded WSS upgrade");
    std::vector<relay::Byte> response;
    test.Check(relayedge::BuildWssUpgradeResponse(request, response) ==
                   relay::RelayStatus::Ok,
               "WSS response built");
    const std::string response_text(response.begin(), response.end());
    test.Check(response_text.find("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=") != std::string::npos,
               "RFC6455 accept hash");
    test.Check(response_text.find("Sec-WebSocket-Protocol: krp.v1") != std::string::npos,
               "KRP subprotocol selected");

    std::string bad = request_text;
    const std::size_t protocol = bad.find("krp.v1", bad.find("Sec-WebSocket-Protocol"));
    bad.replace(protocol, 6, "text.v");
    test.Check(relayedge::ParseWssUpgradeRequest(
        reinterpret_cast<const relay::Byte*>(bad.data()), bad.size(), request) ==
                   relay::RelayStatus::UnsupportedOption,
               "missing krp.v1 rejected");
    bad = request_text;
    bad.insert(bad.size() - 2, "Sec-WebSocket-Extensions: permessage-deflate\r\n");
    test.Check(relayedge::ParseWssUpgradeRequest(
        reinterpret_cast<const relay::Byte*>(bad.data()), bad.size(), request) ==
                   relay::RelayStatus::UnsupportedOption,
               "extensions rejected");
    std::vector<relay::Byte> oversized_handshake(
        relayedge::kMaxWssHandshakeBytes + 1, 'A');
    test.Check(relayedge::ParseWssUpgradeRequest(oversized_handshake.data(),
        oversized_handshake.size(), request) == relay::RelayStatus::TooLarge,
        "oversized WSS handshake rejected before parsing");

    std::uint32_t random = 0xC001D00Du;
    for (std::size_t iteration = 0; iteration < 10000; ++iteration) {
        std::array<relay::Byte, 512> bytes{};
        random = random * 1664525u + 1013904223u;
        const std::size_t size = random % bytes.size();
        for (std::size_t index = 0; index < size; ++index) {
            random = random * 1664525u + 1013904223u;
            bytes[index] = static_cast<relay::Byte>(random >> 24);
        }
        const relay::RelayStatus status = relayedge::ParseWssUpgradeRequest(
            bytes.data(), size, request);
        test.Check(status != relay::RelayStatus::Ok || request.consumed <= size,
                   "bounded H1 handshake fuzz input");
    }

    constexpr std::array<relay::Byte, 4> mask = {1, 2, 3, 4};
    const std::array<relay::Byte, 5> payload = {0, 1, 2, 3, 4};
    std::vector<relay::Byte> encoded;
    test.Check(relayedge::EncodeWssFrame(relayedge::WssOpcode::Binary,
        payload.data(), payload.size(), true, mask, encoded) == relay::RelayStatus::Ok,
        "masked binary frame encoded");
    relayedge::WssFrameParser parser(true);
    relayedge::WssFrame frame;
    for (relay::Byte byte : encoded) {
        test.Check(parser.AddBytes(&byte, 1) == relay::RelayStatus::Ok,
                   "slow reader byte remains bounded");
    }
    test.Check(parser.Pop(frame) == relay::RelayStatus::Ok,
               "slow reader frame completes");
    test.Check(frame.opcode == relayedge::WssOpcode::Binary &&
                   std::equal(frame.payload.begin(), frame.payload.end(), payload.begin()),
               "masked payload recovered");
    test.Check(parser.buffered_bytes() == 0, "frame buffer drained");

    relayedge::WssFrameParser server_parser(true);
    test.Check(relayedge::EncodeWssFrame(relayedge::WssOpcode::Binary,
        payload.data(), payload.size(), false, mask, encoded) == relay::RelayStatus::Ok,
        "unmasked frame encoded");
    test.Check(server_parser.AddBytes(encoded.data(), encoded.size()) == relay::RelayStatus::Ok,
               "unmasked input buffered");
    test.Check(server_parser.Pop(frame) == relay::RelayStatus::Malformed,
               "client masking mandatory");

    const std::array<relay::Byte, 2> reserved_close = {0x03, 0xED};
    test.Check(relayedge::EncodeWssFrame(relayedge::WssOpcode::Close,
        reserved_close.data(), reserved_close.size(), false, mask, encoded) ==
            relay::RelayStatus::InvalidArgument,
        "reserved close code rejected");
    const std::array<relay::Byte, 6> invalid_close_utf8 = {
        0x88, 0x04, 0x03, 0xE8, 0xC0, 0x80};
    relayedge::WssFrameParser close_parser(false);
    test.Check(close_parser.AddBytes(invalid_close_utf8.data(), invalid_close_utf8.size()) ==
                   relay::RelayStatus::Ok &&
                   close_parser.Pop(frame) == relay::RelayStatus::Malformed,
               "invalid close UTF-8 rejected");

    for (std::size_t iteration = 0; iteration < 20000; ++iteration) {
        std::array<relay::Byte, 64> bytes{};
        random = random * 1664525u + 1013904223u;
        const std::size_t size = random % bytes.size();
        for (std::size_t index = 0; index < size; ++index) {
            random = random * 1664525u + 1013904223u;
            bytes[index] = static_cast<relay::Byte>(random >> 24);
        }
        relayedge::WssFrameParser fuzz((iteration & 1u) == 0);
        test.Check(fuzz.AddBytes(bytes.data(), size) == relay::RelayStatus::Ok,
                   "bounded WSS fuzz input");
        (void)fuzz.Pop(frame);
    }
}

relay::RelayStatus ReceiveHttp(relayedge::TlsTcpCarrier& carrier,
                               std::vector<relay::Byte>& bytes) {
    std::array<relay::Byte, 1024> chunk{};
    for (std::size_t attempt = 0; attempt < 16; ++attempt) {
        std::size_t received = 0;
        const relay::RelayStatus status = carrier.Receive(chunk.data(), chunk.size(), received);
        if (status != relay::RelayStatus::Ok)
            return status;
        bytes.insert(bytes.end(), chunk.begin(), chunk.begin() + received);
        if (bytes.size() > relayedge::kMaxWssHandshakeBytes)
            return relay::RelayStatus::TooLarge;
        const std::string text(bytes.begin(), bytes.end());
        if (text.find("\r\n\r\n") != std::string::npos)
            return relay::RelayStatus::Ok;
    }
    return relay::RelayStatus::TooLarge;
}

void TestTlsWss(TestState& test, const char* certificate,
                const char* private_key, const char* ca_certificate) {
    relayedge::EdgeConfig config = LabConfig();
    config.certificate_path = certificate;
    config.private_key_path = private_key;
    relayedge::EdgeDaemon daemon;
    test.Check(daemon.Start(config, 7000) == relay::RelayStatus::Ok,
               "real TLS daemon binds only loopback");
    const std::uint16_t port = daemon.bound_port();
    test.Check(port != 0, "ephemeral TLS port assigned");

    relayedge::TlsTcpCarrier server;
    relay::RelayStatus server_status = relay::RelayStatus::InvalidState;
    relay::KrpCarrierBinding server_binding{};
    std::vector<relay::Byte> server_payload;
    relay::KrpControlFrame server_frame;
    std::thread server_thread([&]() {
        server_status = daemon.AcceptTls(server);
        if (server_status != relay::RelayStatus::Ok)
            return;
        std::vector<relay::Byte> http;
        server_status = ReceiveHttp(server, http);
        if (server_status != relay::RelayStatus::Ok)
            return;
        relayedge::WssUpgradeRequest request;
        server_status = relayedge::ParseWssUpgradeRequest(http.data(), http.size(), request);
        if (server_status != relay::RelayStatus::Ok)
            return;
        std::vector<relay::Byte> response;
        server_status = relayedge::BuildWssUpgradeResponse(request, response);
        if (server_status != relay::RelayStatus::Ok)
            return;
        server_status = server.Send(response.data(), response.size());
        if (server_status != relay::RelayStatus::Ok)
            return;
        relayedge::WssH1Carrier wss(server, false);
        server_payload.resize(1024);
        std::size_t received = 0;
        server_status = wss.Receive(server_payload.data(), server_payload.size(), received);
        server_payload.resize(received);
        std::size_t consumed = 0;
        if (server_status == relay::RelayStatus::Ok)
            server_status = relay::DecodeKrpControlFrame(server_payload.data(),
                server_payload.size(), server_frame, consumed);
        relay::KrpControlFrame pong;
        pong.type = static_cast<std::uint64_t>(relay::KrpMessageType::KRP_PONG);
        pong.flags = relay::kKrpFlagIdempotent;
        pong.payload = server_frame.payload;
        std::vector<relay::Byte> pong_wire;
        if (server_status == relay::RelayStatus::Ok && consumed == server_payload.size())
            server_status = relay::EncodeKrpControlFrame(pong, pong_wire);
        else if (server_status == relay::RelayStatus::Ok)
            server_status = relay::RelayStatus::Malformed;
        if (server_status == relay::RelayStatus::Ok)
            server_status = wss.Send(pong_wire.data(), pong_wire.size());
        if (server_status == relay::RelayStatus::Ok)
            server_status = wss.ExportBinding(server_binding);
    });

    relayedge::TlsTcpCarrier client;
    const relay::RelayStatus connect = client.ConnectLab(
        "127.0.0.1", port, ca_certificate, "localhost");
    if (connect != relay::RelayStatus::Ok)
        std::fprintf(stderr, "TLS client error: -0x%04X\n", -client.last_tls_error());
    test.Check(connect == relay::RelayStatus::Ok, "verified TLS client connects");
    if (connect == relay::RelayStatus::Ok) {
        const std::string request =
            "GET /krp/v1 HTTP/1.1\r\nHost: 127.0.0.1\r\nUpgrade: websocket\r\n"
            "Connection: Upgrade\r\nSec-WebSocket-Version: 13\r\n"
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
            "Sec-WebSocket-Protocol: krp.v1\r\n\r\n";
        test.Check(client.Send(reinterpret_cast<const relay::Byte*>(request.data()),
                               request.size()) == relay::RelayStatus::Ok,
                   "WSS upgrade sent inside TLS");
        std::vector<relay::Byte> response;
        test.Check(ReceiveHttp(client, response) == relay::RelayStatus::Ok,
                   "WSS 101 received inside TLS");
        const std::string response_text(response.begin(), response.end());
        test.Check(response_text.find("HTTP/1.1 101") == 0 &&
                       response_text.find("Sec-WebSocket-Protocol: krp.v1") != std::string::npos,
                   "real TLS carries krp.v1 WSS");
        relay::KrpControlFrame ping;
        ping.type = static_cast<std::uint64_t>(relay::KrpMessageType::KRP_PING);
        ping.flags = relay::kKrpFlagIdempotent;
        ping.payload = {'K','R','P',1,0,2,3,4};
        std::vector<relay::Byte> ping_wire;
        test.Check(relay::EncodeKrpControlFrame(ping, ping_wire) == relay::RelayStatus::Ok,
                   "canonical KRP PING encoded");
        relayedge::WssH1Carrier wss(client, true);
        test.Check(wss.Send(ping_wire.data(), ping_wire.size()) == relay::RelayStatus::Ok,
                   "binary KRP frame sent over WSS/TLS");
        std::array<relay::Byte, 1024> received_bytes{};
        std::size_t received = 0;
        test.Check(wss.Receive(received_bytes.data(), received_bytes.size(), received) ==
                       relay::RelayStatus::Ok,
                   "binary echo received over WSS/TLS");
        relay::KrpControlFrame pong;
        std::size_t consumed = 0;
        test.Check(relay::DecodeKrpControlFrame(received_bytes.data(), received, pong,
                       consumed) == relay::RelayStatus::Ok && consumed == received &&
                       pong.type == static_cast<std::uint64_t>(relay::KrpMessageType::KRP_PONG) &&
                       pong.payload == ping.payload,
                   "canonical KRP PING/PONG round trips");
    }
    server_thread.join();
    if (server_status != relay::RelayStatus::Ok)
        std::fprintf(stderr, "TLS server error: -0x%04X\n", -server.last_tls_error());
    test.Check(server_status == relay::RelayStatus::Ok,
               "TLS/WSS server path completes");
    test.Check(server_frame.type ==
                   static_cast<std::uint64_t>(relay::KrpMessageType::KRP_PING) &&
                   server_frame.payload == std::vector<relay::Byte>({'K','R','P',1,0,2,3,4}),
               "server decoded canonical KRP PING bytes");
    relay::KrpCarrierBinding client_binding{};
    test.Check(client.ExportBinding(client_binding) == relay::RelayStatus::Ok,
               "client TLS exporter available");
    test.Check(client_binding == server_binding &&
                   std::any_of(client_binding.begin(), client_binding.end(),
                               [](relay::Byte byte) { return byte != 0; }),
               "TLS exporter binds both KRP peers");
    const std::string tls_version = client.negotiated_tls_version();
    test.Check(tls_version == "TLSv1.2" || tls_version == "TLSv1.3",
               "TLS 1.2 or newer negotiated");
    client.Close();
    server.Close();
    test.Check(daemon.Kill(7001) == relay::RelayStatus::Ok && daemon.bound_port() == 0,
               "real TLS daemon kill leaves no listener");
}

void TestTlsRecoveryAndFailure(TestState& test, const char* certificate,
                               const char* private_key, const char* ca_certificate) {
    for (std::size_t iteration = 0; iteration < 8; ++iteration) {
        relayedge::LabTlsListener listener;
        test.Check(listener.Open("127.0.0.1", 0) == relay::RelayStatus::Ok,
                   "reconnect listener opens");
        relayedge::TlsTcpCarrier server;
        relay::RelayStatus accepted = relay::RelayStatus::InvalidState;
        relay::KrpCarrierBinding server_binding{};
        std::thread thread([&]() {
            accepted = listener.Accept(certificate, private_key, server);
            if (accepted == relay::RelayStatus::Ok)
                accepted = server.ExportBinding(server_binding);
        });
        relayedge::TlsTcpCarrier client;
        const relay::RelayStatus connected = client.ConnectLab(
            "127.0.0.1", listener.bound_port(), ca_certificate, "localhost");
        thread.join();
        relay::KrpCarrierBinding client_binding{};
        test.Check(connected == relay::RelayStatus::Ok &&
                       client.ExportBinding(client_binding) == relay::RelayStatus::Ok,
                   "reconnect TLS handshake and exporter succeed");
        test.Check(accepted == relay::RelayStatus::Ok &&
                       client_binding == server_binding,
                   "reconnect carrier binding agrees");
        server.Close();
        std::array<relay::Byte, 16> bytes{};
        std::size_t received = 0;
        const relay::RelayStatus cut = client.Receive(bytes.data(), bytes.size(), received);
        test.Check(cut == relay::RelayStatus::Expired || cut == relay::RelayStatus::AuthFailed,
                   "carrier cut detected within bounded I/O timeout");
        client.Close();
        listener.Close();
    }

    relayedge::LabTlsListener listener;
    test.Check(listener.Open("127.0.0.1", 0) == relay::RelayStatus::Ok,
               "failed TLS listener opens");
    relayedge::TlsTcpCarrier server;
    relay::RelayStatus accepted = relay::RelayStatus::Ok;
    std::thread thread([&]() {
        accepted = listener.Accept(certificate, private_key, server);
    });
    relayedge::TlsTcpCarrier client;
    const relay::RelayStatus rejected = client.ConnectLab(
        "127.0.0.1", listener.bound_port(), ca_certificate, "wrong.invalid");
    thread.join();
    test.Check(rejected == relay::RelayStatus::AuthFailed,
               "certificate hostname mismatch rejected");
    test.Check(client.state() == relayedge::CarrierState::Failed &&
                   server.state() == relayedge::CarrierState::Failed &&
                   accepted != relay::RelayStatus::Ok,
               "failed TLS leaves no open carrier");
    client.Close();
    server.Close();
    listener.Close();
}

} // namespace

int main(int argc, char** argv) {
    if (argc != 4) {
        std::fprintf(stderr, "usage: test_p2 CERT KEY CA\n");
        return 2;
    }
    TestState test;
    TestRuntimeAndSessions(test, argv[1], argv[2]);
    TestAuthAllocatorAndPolicy(test);
    TestWss(test);
    TestTlsWss(test, argv[1], argv[2], argv[3]);
    TestTlsRecoveryAndFailure(test, argv[1], argv[2], argv[3]);
    if (test.failed) {
        std::fprintf(stderr, "relayedge P2: FAIL (%llu checks)\n",
                     static_cast<unsigned long long>(test.checks));
        return 1;
    }
    std::printf("relayedge P2: PASS (%llu checks, real TLS/WSS loopback)\n",
                static_cast<unsigned long long>(test.checks));
    return 0;
}
