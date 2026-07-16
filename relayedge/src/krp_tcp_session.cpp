// SPDX-License-Identifier: MIT
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>

#include "edge/krp_tcp_session.h"

#include "edge/edge_auth.h"
#include "edge/edge_policy.h"
#include "edge/krp_p4_crypto.h"
#include "relay/krp_control.h"
#include "relay/krp_tcp_wire.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <limits>
#include <utility>
#include <vector>

namespace relayedge {
namespace {

constexpr std::size_t kMaxP4Flows = 256;
constexpr DWORD kRawSocketTimeoutMs = 5000;

std::uint64_t NowMs() noexcept {
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count());
}

std::uint64_t NowSeconds() noexcept {
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
}

struct SocketOwner {
    SOCKET value = INVALID_SOCKET;
    SocketOwner() = default;
    explicit SocketOwner(SOCKET socket) : value(socket) {}
    ~SocketOwner() { Close(); }
    SocketOwner(const SocketOwner&) = delete;
    SocketOwner& operator=(const SocketOwner&) = delete;
    SocketOwner(SocketOwner&& other) noexcept : value(other.value) { other.value = INVALID_SOCKET; }
    SocketOwner& operator=(SocketOwner&& other) noexcept {
        if (this != &other) { Close(); value = other.value; other.value = INVALID_SOCKET; }
        return *this;
    }
    void Close() noexcept {
        if (value != INVALID_SOCKET) { closesocket(value); value = INVALID_SOCKET; }
    }
};

struct Flow {
    std::uint64_t id = 0;
    SocketOwner socket;
    std::uint64_t send_sequence = 0;
    std::uint64_t receive_sequence = 0;
    bool awaiting_accept = false;
    bool server = false;
};

relay::RelayStatus SendControl(WssH1Carrier& wss, relay::KrpMessageType type,
                               std::uint64_t flags, const std::vector<relay::Byte>& payload) {
    relay::KrpControlFrame frame;
    frame.type = static_cast<std::uint64_t>(type);
    frame.flags = flags;
    frame.payload = payload;
    std::vector<relay::Byte> wire;
    relay::RelayStatus status = relay::EncodeKrpControlFrame(frame, wire);
    return status == relay::RelayStatus::Ok ? wss.Send(wire.data(), wire.size()) : status;
}

relay::RelayStatus ReceiveControl(WssH1Carrier& wss, relay::KrpControlFrame& frame) {
    std::vector<relay::Byte> wire(kMaxWssPayloadBytes);
    std::size_t received = 0;
    relay::RelayStatus status = wss.Receive(wire.data(), wire.size(), received);
    if (status != relay::RelayStatus::Ok) return status;
    std::size_t consumed = 0;
    status = relay::DecodeKrpControlFrame(wire.data(), received, frame, consumed);
    return status == relay::RelayStatus::Ok && consumed == received
        ? relay::RelayStatus::Ok
        : (status == relay::RelayStatus::Ok ? relay::RelayStatus::Malformed : status);
}

relay::RelayStatus SendServerStatus(WssH1Carrier& wss, std::uint64_t flow_id,
                                    relay::RelayStatus result) {
    relay::KrpServerStatusPayload value{flow_id, result};
    std::vector<relay::Byte> payload;
    relay::RelayStatus status = relay::EncodeKrpServerStatus(value, payload);
    return status == relay::RelayStatus::Ok
        ? SendControl(wss, relay::KrpMessageType::KRP_SERVER_STATUS,
            relay::kKrpFlagHasRouteGeneration, payload) : status;
}

relay::RelayStatus SendTerminal(WssH1Carrier& wss, std::uint64_t flow_id,
                                relay::RelayStatus reason) {
    relay::KrpFlowTerminalPayload value{flow_id, reason};
    std::vector<relay::Byte> payload;
    relay::RelayStatus status = relay::EncodeKrpFlowTerminal(value, payload);
    return status == relay::RelayStatus::Ok
        ? SendControl(wss, relay::KrpMessageType::KRP_FLOW_CLOSE, 0, payload) : status;
}

relay::RelayStatus PublicIpv4(const EdgeConfig& config,
                              std::array<relay::Byte, 4>& bytes) noexcept {
    const char* const text = config.mode == EdgeMode::LabLoopback
        ? "127.0.0.1" : config.public_ipv4.c_str();
    IN_ADDR address{};
    if (InetPtonA(AF_INET, text, &address) != 1)
        return relay::RelayStatus::InvalidArgument;
    const relay::Byte* raw = reinterpret_cast<const relay::Byte*>(&address.S_un.S_addr);
    std::copy(raw, raw + 4, bytes.begin());
    return relay::RelayStatus::Ok;
}

bool SockaddrFromTarget(const EdgeTarget& target, sockaddr_storage& storage,
                        int& length) noexcept {
    storage = {};
    length = 0;
    if (target.family == relay::EprAddressFamily::IPv4) {
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_port = htons(target.port);
        std::copy(target.address.begin(), target.address.begin() + 4,
                  reinterpret_cast<relay::Byte*>(&address.sin_addr.S_un.S_addr));
        std::memcpy(&storage, &address, sizeof(address));
        length = sizeof(address);
        return true;
    }
    if (target.family == relay::EprAddressFamily::IPv6) {
        sockaddr_in6 address{};
        address.sin6_family = AF_INET6;
        address.sin6_port = htons(target.port);
        std::copy(target.address.begin(), target.address.end(), address.sin6_addr.u.Byte);
        std::memcpy(&storage, &address, sizeof(address));
        length = sizeof(address);
        return true;
    }
    return false;
}

relay::RelayStatus SetSocketTimeouts(SOCKET socket) noexcept {
    const char* value = reinterpret_cast<const char*>(&kRawSocketTimeoutMs);
    return setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, value, sizeof(kRawSocketTimeoutMs)) == 0 &&
           setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, value, sizeof(kRawSocketTimeoutMs)) == 0
        ? relay::RelayStatus::Ok : relay::RelayStatus::InvalidState;
}

relay::RelayStatus BindSourceIfSpecific(SOCKET socket, int family,
                                        const EdgeConfig& config) noexcept {
    if (family != AF_INET || config.bind_address == "0.0.0.0" ||
        config.bind_address == "::" || config.bind_address.empty())
        return relay::RelayStatus::Ok;
    sockaddr_in source{};
    source.sin_family = AF_INET;
    source.sin_port = 0;
    if (InetPtonA(AF_INET, config.bind_address.c_str(), &source.sin_addr) != 1)
        return relay::RelayStatus::InvalidArgument;
    return bind(socket, reinterpret_cast<const sockaddr*>(&source), sizeof(source)) == 0
        ? relay::RelayStatus::Ok : relay::RelayStatus::InvalidState;
}

relay::RelayStatus ConnectTarget(const EdgeTarget& target, const EdgeConfig& config,
                                 SocketOwner& result) noexcept {
    sockaddr_storage address{};
    int length = 0;
    if (!SockaddrFromTarget(target, address, length))
        return relay::RelayStatus::InvalidArgument;
    SocketOwner socket(::socket(address.ss_family, SOCK_STREAM, IPPROTO_TCP));
    if (socket.value == INVALID_SOCKET ||
        SetSocketTimeouts(socket.value) != relay::RelayStatus::Ok)
        return relay::RelayStatus::InvalidState;
    const relay::RelayStatus bind_status =
        BindSourceIfSpecific(socket.value, address.ss_family, config);
    if (bind_status != relay::RelayStatus::Ok)
        return bind_status;
    u_long nonblocking = 1;
    if (ioctlsocket(socket.value, FIONBIO, &nonblocking) != 0)
        return relay::RelayStatus::InvalidState;
    int connected = ::connect(socket.value,
        reinterpret_cast<const sockaddr*>(&address), length);
    if (connected == SOCKET_ERROR && WSAGetLastError() != WSAEWOULDBLOCK)
        return relay::RelayStatus::TargetForbidden;
    if (connected == SOCKET_ERROR) {
        fd_set write_set;
        FD_ZERO(&write_set);
        FD_SET(socket.value, &write_set);
        timeval timeout{};
        timeout.tv_sec = 10;
        const int selected = select(0, nullptr, &write_set, nullptr, &timeout);
        int error = 0;
        int error_size = sizeof(error);
        if (selected <= 0 || getsockopt(socket.value, SOL_SOCKET, SO_ERROR,
            reinterpret_cast<char*>(&error), &error_size) != 0 || error != 0)
            return relay::RelayStatus::TargetForbidden;
    }
    nonblocking = 0;
    if (ioctlsocket(socket.value, FIONBIO, &nonblocking) != 0)
        return relay::RelayStatus::InvalidState;
    result = std::move(socket);
    return relay::RelayStatus::Ok;
}

relay::RelayStatus OpenLeaseListener(const EdgeConfig& config, std::uint16_t port,
                                     SocketOwner& listener) noexcept {
    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE | AI_NUMERICSERV;
    char port_text[6]{};
    std::snprintf(port_text, sizeof(port_text), "%u", static_cast<unsigned>(port));
    addrinfo* addresses = nullptr;
    const char* bind_text = config.bind_address == "0.0.0.0"
        ? nullptr : config.bind_address.c_str();
    if (getaddrinfo(bind_text, port_text, &hints, &addresses) != 0)
        return relay::RelayStatus::TargetForbidden;
    SocketOwner candidate(::socket(addresses->ai_family,
        addresses->ai_socktype, addresses->ai_protocol));
    BOOL exclusive = TRUE;
    const bool ok = candidate.value != INVALID_SOCKET &&
        setsockopt(candidate.value, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
            reinterpret_cast<const char*>(&exclusive), sizeof(exclusive)) == 0 &&
        bind(candidate.value, addresses->ai_addr,
            static_cast<int>(addresses->ai_addrlen)) == 0 &&
        listen(candidate.value, SOMAXCONN) == 0;
    freeaddrinfo(addresses);
    if (!ok) return relay::RelayStatus::TargetForbidden;
    listener = std::move(candidate);
    return relay::RelayStatus::Ok;
}

relay::RelayStatus SendRaw(SOCKET socket, const relay::Byte* data,
                           std::size_t size) noexcept {
    std::size_t sent = 0;
    while (sent < size) {
        const int chunk = static_cast<int>((std::min)(size - sent,
            static_cast<std::size_t>((std::numeric_limits<int>::max)())));
        const int result = send(socket,
            reinterpret_cast<const char*>(data + sent), chunk, 0);
        if (result <= 0) return relay::RelayStatus::Expired;
        sent += static_cast<std::size_t>(result);
    }
    return relay::RelayStatus::Ok;
}

Flow* FindFlow(std::vector<Flow>& flows, std::uint64_t id) noexcept {
    const auto found = std::find_if(flows.begin(), flows.end(),
        [id](const Flow& flow) { return flow.id == id; });
    return found == flows.end() ? nullptr : &*found;
}

void EraseFlow(std::vector<Flow>& flows, std::uint64_t id,
               EdgeSessionTable& sessions, EdgeSessionHandle handle) noexcept {
    const auto found = std::find_if(flows.begin(), flows.end(),
        [id](const Flow& flow) { return flow.id == id; });
    if (found != flows.end()) {
        (void)sessions.ReleaseFlow(handle);
        flows.erase(found);
    }
}

relay::RelayStatus Authenticate(EdgeDaemon& daemon, WssH1Carrier& wss,
                                const EdgeConfig& config, EdgeSessionHandle& handle,
                                relay::KrpSessionBinding& binding) {
    relay::RelayStatus status = daemon.sessions().Admit(NowMs(), handle);
    relay::KrpControlFrame frame;
    if (status == relay::RelayStatus::Ok) status = ReceiveControl(wss, frame);
    if (status != relay::RelayStatus::Ok ||
        frame.type != static_cast<std::uint64_t>(relay::KrpMessageType::KRP_HELLO))
        return status == relay::RelayStatus::Ok
            ? relay::RelayStatus::UnsupportedMessage : status;
    status = daemon.sessions().AddPreAuthBytes(handle, frame.payload.size(), NowMs());
    relay::KrpHelloPayload hello;
    if (status == relay::RelayStatus::Ok)
        status = relay::DecodeKrpHello(frame.payload.data(), frame.payload.size(), hello);
    if (status != relay::RelayStatus::Ok ||
        hello.version_major != relay::kKrpVersionMajor)
        return status == relay::RelayStatus::Ok
            ? relay::RelayStatus::UnsupportedVersion : status;

    relay::KrpAuthTranscriptContext context;
    context.version_major = hello.version_major;
    context.version_minor = hello.version_minor;
    context.carrier_profile = relay::KrpCarrierProfile::WssH1;
    context.challenge_timestamp = NowSeconds();
    context.node_id = hello.node_id;
    context.client_nonce = hello.client_nonce;
    if (SecureRandom(context.relay_id.data(), context.relay_id.size()) != relay::RelayStatus::Ok ||
        SecureRandom(context.relay_nonce.data(), context.relay_nonce.size()) != relay::RelayStatus::Ok ||
        SecureRandom(context.settings_hash.data(), context.settings_hash.size()) != relay::RelayStatus::Ok ||
        wss.ExportBinding(context.carrier_binding) != relay::RelayStatus::Ok)
        return relay::RelayStatus::InvalidState;
    relay::KrpAuthChallengePayload challenge{context.relay_id,
        context.relay_nonce, context.challenge_timestamp, context.settings_hash};
    std::vector<relay::Byte> payload;
    status = relay::EncodeKrpAuthChallenge(challenge, payload);
    if (status == relay::RelayStatus::Ok)
        status = SendControl(wss, relay::KrpMessageType::KRP_AUTH_CHALLENGE,
            relay::kKrpFlagRequiresOneRtt, payload);
    if (status == relay::RelayStatus::Ok) status = ReceiveControl(wss, frame);
    if (status != relay::RelayStatus::Ok ||
        frame.type != static_cast<std::uint64_t>(relay::KrpMessageType::KRP_AUTH_RESPONSE))
        return status == relay::RelayStatus::Ok
            ? relay::RelayStatus::UnsupportedMessage : status;
    status = daemon.sessions().AddPreAuthBytes(handle, frame.payload.size(), NowMs());
    relay::KrpAuthResponsePayload response;
    if (status == relay::RelayStatus::Ok)
        status = relay::DecodeKrpAuthResponsePayload(frame.payload.data(),
            frame.payload.size(), response);
    std::vector<relay::Byte> transcript;
    if (status == relay::RelayStatus::Ok)
        status = relay::BuildKrpAuthTranscript(context, transcript);
    KrpAuthToken token{};
    relay::KrpTokenProof expected{};
    if (status == relay::RelayStatus::Ok)
        status = LoadKrpAuthToken(config.auth_token_path.c_str(), token);
    if (status == relay::RelayStatus::Ok)
        status = ComputeKrpTokenProof(token, transcript,
            response.response.signature, expected);
    SecureZeroMemory(token.data(), token.size());
    if (status != relay::RelayStatus::Ok ||
        !ConstantTimeEqual(expected, response.token_proof)) {
        (void)daemon.sessions().FailAuthentication(handle, NowMs());
        return relay::RelayStatus::AuthFailed;
    }

    binding.node_id = hello.node_id;
    binding.session_epoch = 1;
    binding.route_generation = 1;
    if (SecureRandom(binding.session_id.data(), binding.session_id.size()) != relay::RelayStatus::Ok ||
        SecureRandom(binding.owner_edge_id.data(), binding.owner_edge_id.size()) != relay::RelayStatus::Ok ||
        SecureRandom(binding.fencing_token.data(), binding.fencing_token.size()) != relay::RelayStatus::Ok)
        return relay::RelayStatus::InvalidState;
    Ed25519IdentityVerifier verifier;
    status = AuthenticateEdgeSession(daemon.sessions(), handle, context,
        response.response, verifier, binding, NowMs());
    if (status != relay::RelayStatus::Ok) return status;
    relay::KrpAuthOkPayload ok{binding.session_id,
        binding.session_epoch, binding.route_generation};
    payload.clear();
    status = relay::EncodeKrpAuthOk(ok, payload);
    return status == relay::RelayStatus::Ok
        ? SendControl(wss, relay::KrpMessageType::KRP_AUTH_OK,
            relay::kKrpFlagHasSessionEpoch |
            relay::kKrpFlagHasRouteGeneration, payload) : status;
}

relay::RelayStatus HandleInboundAccept(SocketOwner& lease_listener,
                                       std::vector<Flow>& flows,
                                       std::uint64_t& next_flow_id,
                                       EdgeDaemon& daemon,
                                       EdgeSessionHandle handle,
                                       const relay::KrpSessionBinding& binding,
                                       const EdgePortLease& lease,
                                       WssH1Carrier& wss,
                                       KrpTcpSessionStats& stats) {
    sockaddr_storage remote{};
    int remote_size = sizeof(remote);
    SocketOwner accepted(accept(lease_listener.value,
        reinterpret_cast<sockaddr*>(&remote), &remote_size));
    if (accepted.value == INVALID_SOCKET)
        return relay::RelayStatus::Ok;
    relay::RelayStatus status = daemon.sessions().ReserveFlow(handle);
    if (status != relay::RelayStatus::Ok) return status;
    (void)SetSocketTimeouts(accepted.value);
    Flow incoming;
    incoming.id = next_flow_id;
    next_flow_id += 2;
    incoming.socket = std::move(accepted);
    incoming.awaiting_accept = true;
    relay::KrpFlowOpenPayload open;
    open.session_epoch = binding.session_epoch;
    open.route_generation = binding.route_generation;
    open.lease_id = lease.lease_id;
    open.lease_generation = lease.generation;
    open.flow_id = incoming.id;
    open.kind = relay::KrpClassicFlowKind::LegacyTcpInbound;
    if (remote.ss_family == AF_INET) {
        open.remote_family = relay::EprAddressFamily::IPv4;
        const auto* address = reinterpret_cast<const sockaddr_in*>(&remote);
        const relay::Byte* raw = reinterpret_cast<const relay::Byte*>(
            &address->sin_addr.S_un.S_addr);
        std::copy(raw, raw + 4, open.remote_address.begin());
        open.remote_port = ntohs(address->sin_port);
    } else if (remote.ss_family == AF_INET6) {
        open.remote_family = relay::EprAddressFamily::IPv6;
        const auto* address = reinterpret_cast<const sockaddr_in6*>(&remote);
        std::copy(address->sin6_addr.u.Byte, address->sin6_addr.u.Byte + 16,
            open.remote_address.begin());
        open.remote_port = ntohs(address->sin6_port);
    } else {
        (void)daemon.sessions().ReleaseFlow(handle);
        return relay::RelayStatus::TargetForbidden;
    }
    std::vector<relay::Byte> payload;
    status = relay::EncodeKrpFlowOpen(open, payload);
    if (status == relay::RelayStatus::Ok)
        status = SendControl(wss, relay::KrpMessageType::KRP_FLOW_OPEN,
            relay::kKrpFlagHasSessionEpoch |
            relay::kKrpFlagHasRouteGeneration |
            relay::kKrpFlagHasLeaseGeneration, payload);
    if (status != relay::RelayStatus::Ok) {
        (void)daemon.sessions().ReleaseFlow(handle);
        return status;
    }
    flows.push_back(std::move(incoming));
    ++stats.inbound_flows;
    return relay::RelayStatus::Ok;
}

} // namespace

relay::RelayStatus RunKrpTcpSession(EdgeDaemon& daemon, TlsTcpCarrier& tls,
                                    WssH1Carrier& wss,
                                    const EdgeConfig& config,
                                    KrpTcpSessionStats& stats) noexcept {
    stats = {};
    try {
        EdgeSessionHandle handle{};
        struct SessionCleanup {
            EdgeDaemon& daemon;
            EdgeSessionHandle& handle;
            ~SessionCleanup() {
                (void)daemon.allocator().ReleaseOwner(handle, NowMs());
                (void)daemon.sessions().Close(handle);
            }
        } cleanup{daemon, handle};
        relay::KrpSessionBinding binding{};
        relay::RelayStatus status = Authenticate(daemon, wss, config,
            handle, binding);
        if (status != relay::RelayStatus::Ok) return status;
        ++stats.authenticated;

        relay::KrpControlFrame frame;
        status = ReceiveControl(wss, frame);
        if (status != relay::RelayStatus::Ok ||
            frame.type != static_cast<std::uint64_t>(
                relay::KrpMessageType::KRP_LEASE_REQUEST))
            return status == relay::RelayStatus::Ok
                ? relay::RelayStatus::UnsupportedMessage : status;
        relay::KrpLeaseRequestPayload request;
        status = relay::DecodeKrpLeaseRequest(frame.payload.data(),
            frame.payload.size(), request);
        if (status != relay::RelayStatus::Ok ||
            request.session_epoch != binding.session_epoch)
            return status == relay::RelayStatus::Ok
                ? relay::RelayStatus::StaleEpoch : status;
        EdgePortLease lease;
        status = daemon.allocator().Allocate(handle, daemon.sessions(),
            request.requested_lease_id, NowMs(), lease);
        SocketOwner lease_listener;
        if (status == relay::RelayStatus::Ok)
            status = OpenLeaseListener(config, lease.port, lease_listener);
        relay::EprProbeNonce nonce{};
        if (status == relay::RelayStatus::Ok)
            status = daemon.allocator().MarkBound(lease.lease_id, lease.generation);
        if (status == relay::RelayStatus::Ok)
            status = SecureRandom(nonce.data(), nonce.size());
        if (status == relay::RelayStatus::Ok)
            status = daemon.allocator().BeginProbe(lease.lease_id,
                lease.generation, nonce);
        if (status == relay::RelayStatus::Ok)
            status = daemon.allocator().CompleteProbe(lease.lease_id,
                lease.generation, nonce, true, NowMs());
        std::array<relay::Byte, 4> public_ipv4{};
        if (status == relay::RelayStatus::Ok)
            status = PublicIpv4(config, public_ipv4);
        if (status != relay::RelayStatus::Ok) {
            (void)daemon.allocator().ReleaseOwner(handle, NowMs());
            return status;
        }
        relay::KrpLeaseGrantedPayload granted{binding.session_epoch,
            lease.lease_id, lease.generation, public_ipv4, lease.port};
        std::vector<relay::Byte> payload;
        status = relay::EncodeKrpLeaseGranted(granted, payload);
        if (status == relay::RelayStatus::Ok)
            status = SendControl(wss, relay::KrpMessageType::KRP_LEASE_GRANTED,
                relay::kKrpFlagHasSessionEpoch |
                relay::kKrpFlagHasLeaseGeneration, payload);
        if (status != relay::RelayStatus::Ok) return status;
        ++stats.leases;

        EdgePolicyConfig policy_config;
        policy_config.explicit_lab_loopback_ed2k =
            config.mode == EdgeMode::LabLoopback;
        policy_config.relay_listener_port = config.port;
        EdgePolicyEngine policy(policy_config, nullptr,
            &daemon.runtime().metrics());
        std::vector<Flow> flows;
        flows.reserve((std::min)(config.max_flows_per_session, kMaxP4Flows));
        std::uint64_t next_flow_id = 2;
        for (;;) {
            (void)daemon.sessions().Touch(handle, NowMs());
            fd_set read_set;
            FD_ZERO(&read_set);
            FD_SET(lease_listener.value, &read_set);
            for (const Flow& flow : flows) {
                if (!flow.awaiting_accept) FD_SET(flow.socket.value, &read_set);
            }
            timeval timeout{};
            timeout.tv_usec = 20000;
            const int selected = select(0, &read_set, nullptr, nullptr, &timeout);
            if (selected == SOCKET_ERROR) return relay::RelayStatus::InvalidState;
            if (FD_ISSET(lease_listener.value, &read_set) &&
                flows.size() < config.max_flows_per_session) {
                status = HandleInboundAccept(lease_listener, flows, next_flow_id,
                    daemon, handle, binding, lease, wss, stats);
                if (status != relay::RelayStatus::Ok) return status;
            }

            std::array<relay::Byte, 16384> raw{};
            std::vector<std::uint64_t> closed;
            for (Flow& flow : flows) {
                if (flow.awaiting_accept ||
                    !FD_ISSET(flow.socket.value, &read_set))
                    continue;
                const int received = recv(flow.socket.value,
                    reinterpret_cast<char*>(raw.data()),
                    static_cast<int>(raw.size()), 0);
                if (received <= 0) {
                    (void)SendTerminal(wss, flow.id, relay::RelayStatus::Ok);
                    closed.push_back(flow.id);
                    continue;
                }
                relay::KrpFlowDataPayload data;
                data.flow_id = flow.id;
                data.sequence = flow.send_sequence++;
                data.bytes.assign(raw.begin(), raw.begin() + received);
                payload.clear();
                status = relay::EncodeKrpFlowData(data, payload);
                if (status == relay::RelayStatus::Ok)
                    status = SendControl(wss,
                        relay::KrpMessageType::KRP_FLOW_DATA, 0, payload);
                if (status != relay::RelayStatus::Ok) return status;
                stats.bytes_to_client += static_cast<std::uint64_t>(received);
            }
            for (std::uint64_t id : closed)
                EraseFlow(flows, id, daemon.sessions(), handle);

            bool tls_readable = false;
            status = tls.WaitReadable(0, tls_readable);
            if (status != relay::RelayStatus::Ok) break;
            if (!tls_readable && !wss.HasBufferedInput()) continue;
            status = ReceiveControl(wss, frame);
            if (status == relay::RelayStatus::Truncated) continue;
            if (status != relay::RelayStatus::Ok) break;
            if (frame.type == static_cast<std::uint64_t>(
                    relay::KrpMessageType::KRP_SERVER_BIND)) {
                relay::KrpServerBindPayload bind_value;
                status = relay::DecodeKrpServerBind(frame.payload.data(),
                    frame.payload.size(), bind_value);
                if (status != relay::RelayStatus::Ok ||
                    bind_value.session_epoch != binding.session_epoch ||
                    bind_value.route_generation != binding.route_generation ||
                    bind_value.lease_id != lease.lease_id ||
                    bind_value.lease_generation != lease.generation ||
                    FindFlow(flows, bind_value.flow_id) != nullptr)
                    return status == relay::RelayStatus::Ok
                        ? relay::RelayStatus::StaleGeneration : status;
                EdgeTarget target{bind_value.target_family,
                    bind_value.target_address, bind_value.target_port};
                status = policy.Check(relay::KrpService::Ed2kServer, target);
                if (status == relay::RelayStatus::Ok)
                    status = policy.RevalidateBeforeConnect(
                        relay::KrpService::Ed2kServer, target);
                Flow server;
                server.id = bind_value.flow_id;
                server.server = true;
                bool flow_reserved = false;
                if (status == relay::RelayStatus::Ok) {
                    status = daemon.sessions().ReserveFlow(handle);
                    flow_reserved = status == relay::RelayStatus::Ok;
                }
                if (status == relay::RelayStatus::Ok)
                    status = ConnectTarget(target, config, server.socket);
                (void)SendServerStatus(wss, bind_value.flow_id, status);
                if (status == relay::RelayStatus::Ok) {
                    flows.push_back(std::move(server));
                    ++stats.server_flows;
                } else if (flow_reserved) {
                    (void)daemon.sessions().ReleaseFlow(handle);
                }
                continue;
            }
            if (frame.type == static_cast<std::uint64_t>(
                    relay::KrpMessageType::KRP_FLOW_ACCEPT)) {
                relay::KrpFlowTerminalPayload accepted;
                status = relay::DecodeKrpFlowTerminal(frame.payload.data(),
                    frame.payload.size(), accepted);
                Flow* const flow = FindFlow(flows, accepted.flow_id);
                if (status != relay::RelayStatus::Ok || flow == nullptr ||
                    !flow->awaiting_accept ||
                    accepted.reason != relay::RelayStatus::Ok)
                    return relay::RelayStatus::InvalidState;
                flow->awaiting_accept = false;
                continue;
            }
            if (frame.type == static_cast<std::uint64_t>(
                    relay::KrpMessageType::KRP_FLOW_DATA)) {
                relay::KrpFlowDataPayload data;
                status = relay::DecodeKrpFlowData(frame.payload.data(),
                    frame.payload.size(), data);
                Flow* const flow = FindFlow(flows, data.flow_id);
                if (status != relay::RelayStatus::Ok || flow == nullptr ||
                    flow->awaiting_accept ||
                    data.sequence != flow->receive_sequence++)
                    return status == relay::RelayStatus::Ok
                        ? relay::RelayStatus::SequenceError : status;
                status = SendRaw(flow->socket.value,
                    data.bytes.data(), data.bytes.size());
                if (status != relay::RelayStatus::Ok) {
                    const std::uint64_t id = flow->id;
                    (void)SendTerminal(wss, id, status);
                    EraseFlow(flows, id, daemon.sessions(), handle);
                } else {
                    stats.bytes_from_client += data.bytes.size();
                }
                continue;
            }
            if (frame.type == static_cast<std::uint64_t>(
                    relay::KrpMessageType::KRP_FLOW_CLOSE) ||
                frame.type == static_cast<std::uint64_t>(
                    relay::KrpMessageType::KRP_FLOW_RESET)) {
                relay::KrpFlowTerminalPayload terminal;
                status = relay::DecodeKrpFlowTerminal(frame.payload.data(),
                    frame.payload.size(), terminal);
                if (status != relay::RelayStatus::Ok ||
                    FindFlow(flows, terminal.flow_id) == nullptr)
                    return relay::RelayStatus::InvalidState;
                EraseFlow(flows, terminal.flow_id,
                    daemon.sessions(), handle);
                continue;
            }
            if (frame.type == static_cast<std::uint64_t>(
                    relay::KrpMessageType::KRP_PING)) {
                status = SendControl(wss, relay::KrpMessageType::KRP_PONG,
                    relay::kKrpFlagIdempotent, frame.payload);
                if (status != relay::RelayStatus::Ok) return status;
                continue;
            }
            return relay::RelayStatus::UnsupportedMessage;
        }
        return status == relay::RelayStatus::Expired
            ? relay::RelayStatus::Ok : status;
    } catch (...) {
        return relay::RelayStatus::InvalidState;
    }
}

} // namespace relayedge
