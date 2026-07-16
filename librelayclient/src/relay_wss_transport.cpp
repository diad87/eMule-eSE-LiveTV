// SPDX-License-Identifier: MIT
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>

#include "relayclient/relay_wss_transport.h"

#include "edge/tls_tcp_carrier.h"
#include "edge/wss_carrier.h"
#include "edge/wss_h1.h"
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

namespace relayclient {

namespace {

constexpr DWORD kLocalSocketTimeoutMs = 5000;

struct ClientSocket {
    SOCKET value = INVALID_SOCKET;
    ClientSocket() = default;
    explicit ClientSocket(SOCKET socket) : value(socket) {}
    ~ClientSocket() { Close(); }
    ClientSocket(const ClientSocket&) = delete;
    ClientSocket& operator=(const ClientSocket&) = delete;
    ClientSocket(ClientSocket&& other) noexcept : value(other.value) {
        other.value = INVALID_SOCKET;
    }
    ClientSocket& operator=(ClientSocket&& other) noexcept {
        if (this != &other) {
            Close(); value = other.value; other.value = INVALID_SOCKET;
        }
        return *this;
    }
    void Close() noexcept {
        if (value != INVALID_SOCKET) {
            closesocket(value);
            value = INVALID_SOCKET;
        }
    }
};

struct ClientFlow {
    std::uint64_t id = 0;
    ClientSocket socket;
    std::uint64_t send_sequence = 0;
    std::uint64_t receive_sequence = 0;
    bool server = false;
    bool awaiting_server_status = false;
};

relay::RelayStatus SetLocalTimeouts(SOCKET socket) noexcept {
    const char* value = reinterpret_cast<const char*>(&kLocalSocketTimeoutMs);
    return setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, value,
                      sizeof(kLocalSocketTimeoutMs)) == 0 &&
           setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, value,
                      sizeof(kLocalSocketTimeoutMs)) == 0
        ? relay::RelayStatus::Ok : relay::RelayStatus::InvalidState;
}

relay::RelayStatus OpenLoopbackListener(ClientSocket& listener,
                                        std::uint16_t& port) noexcept {
    port = 0;
    ClientSocket socket(::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));
    if (socket.value == INVALID_SOCKET) return relay::RelayStatus::InvalidState;
    BOOL exclusive = TRUE;
    if (setsockopt(socket.value, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
        reinterpret_cast<const char*>(&exclusive), sizeof(exclusive)) != 0)
        return relay::RelayStatus::InvalidState;
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.S_un.S_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = 0;
    if (bind(socket.value, reinterpret_cast<const sockaddr*>(&address),
             sizeof(address)) != 0 || listen(socket.value, 4) != 0)
        return relay::RelayStatus::TargetForbidden;
    int address_size = sizeof(address);
    if (getsockname(socket.value, reinterpret_cast<sockaddr*>(&address),
                    &address_size) != 0)
        return relay::RelayStatus::InvalidState;
    port = ntohs(address.sin_port);
    if (port == 0) return relay::RelayStatus::InvalidState;
    listener = std::move(socket);
    return relay::RelayStatus::Ok;
}

relay::RelayStatus ConnectLoopback(std::uint16_t port,
                                   ClientSocket& connected) noexcept {
    if (port == 0) return relay::RelayStatus::InvalidArgument;
    ClientSocket socket(::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));
    if (socket.value == INVALID_SOCKET ||
        SetLocalTimeouts(socket.value) != relay::RelayStatus::Ok)
        return relay::RelayStatus::InvalidState;
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.S_un.S_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons(port);
    if (connect(socket.value, reinterpret_cast<const sockaddr*>(&address),
                sizeof(address)) != 0)
        return relay::RelayStatus::TargetForbidden;
    connected = std::move(socket);
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

relay::RelayStatus SendControl(relayedge::WssH1Carrier& wss,
                               relay::KrpMessageType type,
                               std::uint64_t flags,
                               const std::vector<relay::Byte>& payload) {
    relay::KrpControlFrame frame;
    frame.type = static_cast<std::uint64_t>(type);
    frame.flags = flags;
    frame.payload = payload;
    std::vector<relay::Byte> wire;
    relay::RelayStatus status = relay::EncodeKrpControlFrame(frame, wire);
    return status == relay::RelayStatus::Ok
        ? wss.Send(wire.data(), wire.size()) : status;
}

relay::RelayStatus ReceiveControl(relayedge::WssH1Carrier& wss,
                                  relay::KrpControlFrame& frame) {
    std::vector<relay::Byte> wire(relayedge::kMaxWssPayloadBytes);
    std::size_t received = 0;
    relay::RelayStatus status = wss.Receive(wire.data(), wire.size(), received);
    if (status != relay::RelayStatus::Ok) return status;
    std::size_t consumed = 0;
    status = relay::DecodeKrpControlFrame(wire.data(), received, frame, consumed);
    return status == relay::RelayStatus::Ok && consumed == received
        ? relay::RelayStatus::Ok
        : (status == relay::RelayStatus::Ok ? relay::RelayStatus::Malformed : status);
}

ClientFlow* FindFlow(std::vector<ClientFlow>& flows, std::uint64_t id) noexcept {
    const auto found = std::find_if(flows.begin(), flows.end(),
        [id](const ClientFlow& flow) { return flow.id == id; });
    return found == flows.end() ? nullptr : &*found;
}

void EraseFlow(std::vector<ClientFlow>& flows, std::uint64_t id) noexcept {
    const auto found = std::find_if(flows.begin(), flows.end(),
        [id](const ClientFlow& flow) { return flow.id == id; });
    if (found != flows.end()) flows.erase(found);
}

relay::RelayStatus SendTerminal(relayedge::WssH1Carrier& wss,
                                relay::KrpMessageType type,
                                std::uint64_t flow_id,
                                relay::RelayStatus reason) {
    relay::KrpFlowTerminalPayload value{flow_id, reason};
    std::vector<relay::Byte> payload;
    relay::RelayStatus status = relay::EncodeKrpFlowTerminal(value, payload);
    return status == relay::RelayStatus::Ok
        ? SendControl(wss, type, 0, payload) : status;
}

} // namespace

RelayWssTransport::RelayWssTransport(IRelayEventNotifier* notifier,
                                     relay::INodeIdentitySigner* signer) noexcept
    : notifier_(notifier), signer_(signer) {}

RelayWssTransport::~RelayWssTransport() {
    Stop(generation_);
    Join();
}

relay::RelayStatus RelayWssTransport::Start(
    std::uint64_t generation,
    const RelayClientConfig& config,
    const std::shared_ptr<RelayEventQueue>& events) noexcept {
    if (!events || ValidateRelayClientConfig(config) != relay::RelayStatus::Ok)
        return relay::RelayStatus::InvalidArgument;
    std::lock_guard<std::mutex> lock(mutex_);
    if (worker_.joinable())
        return relay::RelayStatus::InvalidState;
    generation_ = generation;
    stop_requested_ = false;
    data_plane_ready_.store(false, std::memory_order_release);
    public_tcp_port_.store(0, std::memory_order_release);
    loopback_proxy_port_.store(0, std::memory_order_release);
    try {
        worker_ = std::thread(&RelayWssTransport::Worker, this, generation, config, events);
    } catch (...) {
        return relay::RelayStatus::InvalidState;
    }
    return relay::RelayStatus::Ok;
}

void RelayWssTransport::Stop(std::uint64_t generation) noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    if (generation == generation_)
        stop_requested_ = true;
    stopped_cv_.notify_all();
}

void RelayWssTransport::Join() noexcept {
    if (worker_.joinable() && worker_.get_id() != std::this_thread::get_id())
        worker_.join();
}

bool RelayWssTransport::PrepareEd2kServerRoute(
    const char* numeric_address, std::uint16_t server_port,
    std::uint16_t& loopback_proxy_port) noexcept {
    loopback_proxy_port = 0;
    if (!data_plane_ready_.load(std::memory_order_acquire) ||
        numeric_address == nullptr || *numeric_address == '\0' || server_port == 0)
        return false;
    PendingServerRoute route;
    IN_ADDR ipv4{};
    IN6_ADDR ipv6{};
    if (InetPtonA(AF_INET, numeric_address, &ipv4) == 1) {
        route.family = relay::EprAddressFamily::IPv4;
        const relay::Byte* raw = reinterpret_cast<const relay::Byte*>(&ipv4.S_un.S_addr);
        std::copy(raw, raw + 4, route.address.begin());
    } else if (InetPtonA(AF_INET6, numeric_address, &ipv6) == 1) {
        route.family = relay::EprAddressFamily::IPv6;
        std::copy(ipv6.u.Byte, ipv6.u.Byte + 16, route.address.begin());
    } else {
        return false;
    }
    route.port = server_port;
    {
        std::lock_guard<std::mutex> lock(route_mutex_);
        if (pending_server_route_.port != 0)
            return false;
        route.serial = pending_server_route_.serial + 1;
        if (route.serial == 0) route.serial = 1;
        pending_server_route_ = route;
    }
    loopback_proxy_port = loopback_proxy_port_.load(std::memory_order_acquire);
    return loopback_proxy_port != 0;
}

void RelayWssTransport::Publish(const std::shared_ptr<RelayEventQueue>& events,
                                RelayClientEventType type,
                                std::uint64_t generation,
                                RelayReason reason) noexcept {
    RelayClientEvent event;
    event.type = type;
    event.generation = generation;
    event.reason = reason;
    if (events->Push(event) && notifier_ != nullptr)
        notifier_->Notify(generation);
}

bool RelayWssTransport::StopRequested(std::uint64_t generation) noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    return stop_requested_ || generation_ != generation;
}

relay::RelayStatus RelayWssTransport::RunTcpDataPlane(
    relayedge::TlsTcpCarrier& tls,
    relayedge::WssH1Carrier& wss,
    std::uint64_t generation,
    const RelayClientConfig& config,
    const std::shared_ptr<RelayEventQueue>& events) noexcept {
    struct ResetPublicState {
        RelayWssTransport* owner;
        ~ResetPublicState() {
            owner->data_plane_ready_.store(false, std::memory_order_release);
            owner->public_tcp_port_.store(0, std::memory_order_release);
            owner->loopback_proxy_port_.store(0, std::memory_order_release);
            std::lock_guard<std::mutex> lock(owner->route_mutex_);
            const std::uint64_t serial = owner->pending_server_route_.serial;
            owner->pending_server_route_ = {};
            owner->pending_server_route_.serial = serial;
        }
    } reset{this};

    if (signer_ == nullptr || !signer_->IsPersistent())
        return relay::RelayStatus::AuthFailed;
    relayedge::KrpAuthToken token{};
    relay::RelayStatus status = relayedge::LoadKrpAuthToken(
        config.auth_token_path.c_str(), token);
    if (status != relay::RelayStatus::Ok)
        return relay::RelayStatus::AuthFailed;

    auto receive_bounded = [&](relay::KrpControlFrame& frame) {
        const auto deadline = std::chrono::steady_clock::now() +
            std::chrono::seconds(15);
        for (;;) {
            if (StopRequested(generation)) return relay::RelayStatus::Expired;
            relay::RelayStatus received = ReceiveControl(wss, frame);
            if (received != relay::RelayStatus::Truncated) return received;
            if (std::chrono::steady_clock::now() >= deadline)
                return relay::RelayStatus::Expired;
        }
    };

    Publish(events, RelayClientEventType::AuthStarted, generation);
    relay::KrpHelloPayload hello;
    hello.node_id = signer_->PublicNodeId();
    status = relayedge::SecureRandom(hello.client_nonce.data(),
                                     hello.client_nonce.size());
    std::vector<relay::Byte> payload;
    if (status == relay::RelayStatus::Ok)
        status = relay::EncodeKrpHello(hello, payload);
    if (status == relay::RelayStatus::Ok)
        status = SendControl(wss, relay::KrpMessageType::KRP_HELLO, 0, payload);
    relay::KrpControlFrame frame;
    if (status == relay::RelayStatus::Ok) status = receive_bounded(frame);
    if (status != relay::RelayStatus::Ok ||
        frame.type != static_cast<std::uint64_t>(
            relay::KrpMessageType::KRP_AUTH_CHALLENGE)) {
        SecureZeroMemory(token.data(), token.size());
        return relay::RelayStatus::AuthFailed;
    }
    relay::KrpAuthChallengePayload challenge;
    status = relay::DecodeKrpAuthChallenge(frame.payload.data(),
        frame.payload.size(), challenge);
    relay::KrpAuthTranscriptContext context;
    context.version_major = hello.version_major;
    context.version_minor = hello.version_minor;
    context.carrier_profile = relay::KrpCarrierProfile::WssH1;
    context.challenge_timestamp = challenge.timestamp;
    context.node_id = hello.node_id;
    context.client_nonce = hello.client_nonce;
    context.relay_id = challenge.relay_id;
    context.relay_nonce = challenge.relay_nonce;
    context.settings_hash = challenge.settings_hash;
    if (status == relay::RelayStatus::Ok)
        status = wss.ExportBinding(context.carrier_binding);
    relay::KrpAuthResponsePayload response;
    if (status == relay::RelayStatus::Ok)
        status = relay::SignKrpAuthTranscript(context, *signer_, response.response);
    std::vector<relay::Byte> transcript;
    if (status == relay::RelayStatus::Ok)
        status = relay::BuildKrpAuthTranscript(context, transcript);
    if (status == relay::RelayStatus::Ok)
        status = relayedge::ComputeKrpTokenProof(token, transcript,
            response.response.signature, response.token_proof);
    SecureZeroMemory(token.data(), token.size());
    payload.clear();
    if (status == relay::RelayStatus::Ok)
        status = relay::EncodeKrpAuthResponsePayload(response, payload);
    if (status == relay::RelayStatus::Ok)
        status = SendControl(wss, relay::KrpMessageType::KRP_AUTH_RESPONSE,
            relay::kKrpFlagRequiresOneRtt, payload);
    if (status == relay::RelayStatus::Ok) status = receive_bounded(frame);
    if (status != relay::RelayStatus::Ok ||
        frame.type != static_cast<std::uint64_t>(
            relay::KrpMessageType::KRP_AUTH_OK))
        return relay::RelayStatus::AuthFailed;
    relay::KrpAuthOkPayload authenticated;
    status = relay::DecodeKrpAuthOk(frame.payload.data(), frame.payload.size(),
                                    authenticated);
    if (status != relay::RelayStatus::Ok ||
        authenticated.session_epoch == 0 ||
        authenticated.route_generation == 0)
        return relay::RelayStatus::AuthFailed;
    Publish(events, RelayClientEventType::Authenticated, generation);

    Publish(events, RelayClientEventType::LeaseRequested, generation);
    relay::KrpLeaseRequestPayload lease_request;
    lease_request.session_epoch = authenticated.session_epoch;
    status = relayedge::SecureRandom(
        reinterpret_cast<relay::Byte*>(&lease_request.requested_lease_id),
        sizeof(lease_request.requested_lease_id));
    if (lease_request.requested_lease_id == 0)
        lease_request.requested_lease_id = 1;
    payload.clear();
    if (status == relay::RelayStatus::Ok)
        status = relay::EncodeKrpLeaseRequest(lease_request, payload);
    if (status == relay::RelayStatus::Ok)
        status = SendControl(wss, relay::KrpMessageType::KRP_LEASE_REQUEST,
            relay::kKrpFlagRequiresOneRtt |
            relay::kKrpFlagHasSessionEpoch, payload);
    if (status == relay::RelayStatus::Ok) status = receive_bounded(frame);
    if (status != relay::RelayStatus::Ok ||
        frame.type != static_cast<std::uint64_t>(
            relay::KrpMessageType::KRP_LEASE_GRANTED))
        return status == relay::RelayStatus::Ok
            ? relay::RelayStatus::UnsupportedMessage : status;
    relay::KrpLeaseGrantedPayload lease;
    status = relay::DecodeKrpLeaseGranted(frame.payload.data(),
        frame.payload.size(), lease);
    if (status != relay::RelayStatus::Ok ||
        lease.session_epoch != authenticated.session_epoch ||
        lease.lease_id != lease_request.requested_lease_id)
        return relay::RelayStatus::StaleEpoch;
    Publish(events, RelayClientEventType::LeaseAllocated, generation);
    Publish(events, RelayClientEventType::LeaseProbing, generation);

    ClientSocket proxy_listener;
    std::uint16_t proxy_port = 0;
    status = OpenLoopbackListener(proxy_listener, proxy_port);
    if (status != relay::RelayStatus::Ok) return status;
    public_tcp_port_.store(lease.tcp_port, std::memory_order_release);
    loopback_proxy_port_.store(proxy_port, std::memory_order_release);
    data_plane_ready_.store(true, std::memory_order_release);
    Publish(events, RelayClientEventType::LeaseActive, generation);

    std::vector<ClientFlow> flows;
    flows.reserve(256);
    std::uint64_t next_server_flow_id = 1;
    while (!StopRequested(generation)) {
        fd_set read_set;
        FD_ZERO(&read_set);
        FD_SET(proxy_listener.value, &read_set);
        for (const ClientFlow& flow : flows) {
            if (!flow.awaiting_server_status)
                FD_SET(flow.socket.value, &read_set);
        }
        timeval timeout{};
        timeout.tv_usec = 10000;
        const int selected = select(0, &read_set, nullptr, nullptr, &timeout);
        if (selected == SOCKET_ERROR) return relay::RelayStatus::InvalidState;

        if (FD_ISSET(proxy_listener.value, &read_set)) {
            ClientSocket local(accept(proxy_listener.value, nullptr, nullptr));
            PendingServerRoute route;
            {
                std::lock_guard<std::mutex> lock(route_mutex_);
                route = pending_server_route_;
                pending_server_route_.family = relay::EprAddressFamily::None;
                pending_server_route_.address.fill(0);
                pending_server_route_.port = 0;
            }
            if (local.value != INVALID_SOCKET && route.port != 0) {
                (void)SetLocalTimeouts(local.value);
                ClientFlow server;
                server.id = next_server_flow_id;
                next_server_flow_id += 2;
                server.socket = std::move(local);
                server.server = true;
                server.awaiting_server_status = true;
                relay::KrpServerBindPayload bind_value;
                bind_value.session_epoch = authenticated.session_epoch;
                bind_value.route_generation = authenticated.route_generation;
                bind_value.lease_id = lease.lease_id;
                bind_value.lease_generation = lease.lease_generation;
                bind_value.flow_id = server.id;
                bind_value.target_family = route.family;
                bind_value.target_address = route.address;
                bind_value.target_port = route.port;
                payload.clear();
                status = relay::EncodeKrpServerBind(bind_value, payload);
                if (status == relay::RelayStatus::Ok)
                    status = SendControl(wss,
                        relay::KrpMessageType::KRP_SERVER_BIND,
                        relay::kKrpFlagHasSessionEpoch |
                        relay::kKrpFlagHasRouteGeneration |
                        relay::kKrpFlagHasLeaseGeneration, payload);
                if (status != relay::RelayStatus::Ok) return status;
                flows.push_back(std::move(server));
            }
        }

        std::array<relay::Byte, 16384> raw{};
        std::vector<std::uint64_t> closed;
        for (ClientFlow& flow : flows) {
            if (flow.awaiting_server_status ||
                !FD_ISSET(flow.socket.value, &read_set))
                continue;
            const int received = recv(flow.socket.value,
                reinterpret_cast<char*>(raw.data()),
                static_cast<int>(raw.size()), 0);
            if (received <= 0) {
                (void)SendTerminal(wss,
                    relay::KrpMessageType::KRP_FLOW_CLOSE,
                    flow.id, relay::RelayStatus::Ok);
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
        }
        for (std::uint64_t id : closed) EraseFlow(flows, id);

        bool tls_readable = false;
        status = tls.WaitReadable(0, tls_readable);
        if (status != relay::RelayStatus::Ok) return status;
        if (!tls_readable && !wss.HasBufferedInput()) continue;
        status = ReceiveControl(wss, frame);
        if (status == relay::RelayStatus::Truncated) continue;
        if (status != relay::RelayStatus::Ok) return status;

        if (frame.type == static_cast<std::uint64_t>(
                relay::KrpMessageType::KRP_SERVER_STATUS)) {
            relay::KrpServerStatusPayload server_status;
            status = relay::DecodeKrpServerStatus(frame.payload.data(),
                frame.payload.size(), server_status);
            ClientFlow* const flow = FindFlow(flows, server_status.flow_id);
            if (status != relay::RelayStatus::Ok || flow == nullptr ||
                !flow->server || !flow->awaiting_server_status)
                return relay::RelayStatus::InvalidState;
            if (server_status.status != relay::RelayStatus::Ok) {
                EraseFlow(flows, server_status.flow_id);
            } else {
                flow->awaiting_server_status = false;
            }
            continue;
        }
        if (frame.type == static_cast<std::uint64_t>(
                relay::KrpMessageType::KRP_FLOW_OPEN)) {
            relay::KrpFlowOpenPayload open;
            status = relay::DecodeKrpFlowOpen(frame.payload.data(),
                frame.payload.size(), open);
            if (status != relay::RelayStatus::Ok ||
                open.session_epoch != authenticated.session_epoch ||
                open.route_generation != authenticated.route_generation ||
                open.lease_id != lease.lease_id ||
                open.lease_generation != lease.lease_generation ||
                FindFlow(flows, open.flow_id) != nullptr)
                return relay::RelayStatus::StaleGeneration;
            ClientFlow inbound;
            inbound.id = open.flow_id;
            status = ConnectLoopback(config.local_tcp_port, inbound.socket);
            if (status != relay::RelayStatus::Ok) {
                (void)SendTerminal(wss,
                    relay::KrpMessageType::KRP_FLOW_RESET,
                    open.flow_id, status);
                continue;
            }
            flows.push_back(std::move(inbound));
            status = SendTerminal(wss,
                relay::KrpMessageType::KRP_FLOW_ACCEPT,
                open.flow_id, relay::RelayStatus::Ok);
            if (status != relay::RelayStatus::Ok) return status;
            Publish(events, RelayClientEventType::EndpointReachable, generation);
            continue;
        }
        if (frame.type == static_cast<std::uint64_t>(
                relay::KrpMessageType::KRP_FLOW_DATA)) {
            relay::KrpFlowDataPayload data;
            status = relay::DecodeKrpFlowData(frame.payload.data(),
                frame.payload.size(), data);
            ClientFlow* const flow = FindFlow(flows, data.flow_id);
            if (status != relay::RelayStatus::Ok || flow == nullptr ||
                flow->awaiting_server_status ||
                data.sequence != flow->receive_sequence++)
                return status == relay::RelayStatus::Ok
                    ? relay::RelayStatus::SequenceError : status;
            status = SendRaw(flow->socket.value,
                data.bytes.data(), data.bytes.size());
            if (status != relay::RelayStatus::Ok) {
                const std::uint64_t id = flow->id;
                (void)SendTerminal(wss,
                    relay::KrpMessageType::KRP_FLOW_RESET, id, status);
                EraseFlow(flows, id);
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
            EraseFlow(flows, terminal.flow_id);
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
    return relay::RelayStatus::Ok;
}

void RelayWssTransport::Worker(std::uint64_t generation,
                               RelayClientConfig config,
                               std::shared_ptr<RelayEventQueue> events) noexcept {
    relayedge::TlsTcpCarrier tls;
    relay::RelayStatus status = tls.Connect(config.endpoint_host.c_str(),
        config.endpoint_port, config.ca_bundle_path.c_str(),
        config.expected_server_name.c_str());
    if (status != relay::RelayStatus::Ok) {
        Publish(events, RelayClientEventType::TlsFailed, generation, RelayReason::TlsFailed);
        return;
    }
    Publish(events, RelayClientEventType::TransportConnected, generation);

    std::vector<relay::Byte> request;
    std::string key;
    status = relayedge::BuildWssClientUpgradeRequest(config.endpoint_host.c_str(),
        config.endpoint_path.c_str(), request, key);
    if (status == relay::RelayStatus::Ok)
        status = tls.Send(request.data(), request.size());

    std::vector<relay::Byte> response;
    std::size_t consumed = 0;
    while (status == relay::RelayStatus::Ok) {
        status = relayedge::ParseWssUpgradeResponse(response.data(), response.size(),
                                                     key, consumed);
        if (status != relay::RelayStatus::Truncated)
            break;
        if (response.size() >= relayedge::kMaxWssHandshakeBytes) {
            status = relay::RelayStatus::TooLarge;
            break;
        }
        std::array<relay::Byte, 2048> chunk{};
        std::size_t received = 0;
        status = tls.Receive(chunk.data(), chunk.size(), received);
        if (status == relay::RelayStatus::Ok) {
            try {
                response.insert(response.end(), chunk.begin(), chunk.begin() + received);
            } catch (...) {
                status = relay::RelayStatus::TooLarge;
            }
        }
    }
    if (status != relay::RelayStatus::Ok || consumed != response.size()) {
        Publish(events, RelayClientEventType::WssFailed, generation, RelayReason::WssFailed);
        tls.Close();
        return;
    }

    relayedge::WssH1Carrier wss(tls, true);
    Publish(events, RelayClientEventType::WssReady, generation);

    if (config.experimental_tcp_data_plane) {
        status = RunTcpDataPlane(tls, wss, generation, config, events);
        if (!StopRequested(generation) && status != relay::RelayStatus::Ok) {
            if (status == relay::RelayStatus::AuthFailed)
                Publish(events, RelayClientEventType::AuthFailed, generation,
                        RelayReason::AuthFailed);
            else
                Publish(events, RelayClientEventType::Disconnected, generation,
                        status == relay::RelayStatus::TargetForbidden
                            ? RelayReason::PolicyDenied
                            : RelayReason::RemoteClosed);
        }
        wss.Close();
        return;
    }

    // Reads use 500 ms slices. This detects a post-upgrade remote close while
    // keeping Stop/Join bounded without cross-thread mbedTLS calls.
    while (!StopRequested(generation)) {
        bool readable = false;
        status = tls.WaitReadable(250, readable);
        if (status != relay::RelayStatus::Ok) {
            if (!StopRequested(generation))
                Publish(events, RelayClientEventType::Disconnected, generation,
                        RelayReason::RemoteClosed);
            break;
        }
        if (!readable)
            continue;
        std::array<relay::Byte, 1024> incoming{};
        std::size_t received = 0;
        status = wss.Receive(incoming.data(), incoming.size(), received);
        if (status == relay::RelayStatus::Truncated)
            continue;
        if (StopRequested(generation))
            break;
        if (status == relay::RelayStatus::Ok) {
            // The carrier never interprets or logs KRP payload. Until a KRP
            // session driver consumes it, fail closed instead of discarding it.
            Publish(events, RelayClientEventType::Fatal, generation,
                    RelayReason::ProtocolError);
        } else {
            Publish(events, RelayClientEventType::Disconnected, generation,
                    RelayReason::RemoteClosed);
        }
        break;
    }
    wss.Close();
}

} // namespace relayclient
