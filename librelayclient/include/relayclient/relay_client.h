// SPDX-License-Identifier: MIT
// Main-thread-owned KRP client state machine. Network workers may only publish
// bounded value events into RelayEventQueue; they never receive eMule objects.
#pragma once

#include "relay/relay_core.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

namespace relayclient {

constexpr std::size_t kRelayEventQueueCapacity = 256;
constexpr std::size_t kRelayEndpointHostMax = 253;
constexpr std::size_t kRelayEndpointPathMax = 128;
constexpr std::size_t kRelayCaPathMax = 1024;
constexpr std::size_t kRelayAuthTokenPathMax = 1024;

enum class RelayServerPolicy : std::uint8_t {
    SelectedServerOnly = 0,
    AnyConnectedServer = 1,
};

struct RelayClientConfig {
    bool enabled = false;
    bool kill_switch = false;
    std::string endpoint_host;
    std::uint16_t endpoint_port = 443;
    std::string endpoint_path = "/krp/v1";
    std::string expected_server_name;
    std::string ca_bundle_path;
    // P4 remains separately gated from the P3 carrier. When enabled it
    // requires a persistent NodeIdentity signer, a deployment token file and
    // the local eMule TCP listener port used for inbound peer delivery.
    bool experimental_tcp_data_plane = false;
    std::string auth_token_path;
    std::uint16_t local_tcp_port = 0;
    RelayServerPolicy server_policy = RelayServerPolicy::SelectedServerOnly;
    std::uint32_t reconnect_min_ms = 1000;
    std::uint32_t reconnect_max_ms = 60000;
    std::uint32_t reconnect_jitter_percent = 20;
    std::uint32_t lease_grace_ms = 30000;
};

relay::RelayStatus ValidateRelayClientConfig(const RelayClientConfig& config) noexcept;

enum class RelayCarrierState : std::uint8_t {
    Disabled = 0,
    Disconnected,
    Connecting,
    TlsReady,
    WssReady,
    Authenticating,
    Active,
    Backoff,
    Draining,
    Failed,
};

enum class RelaySessionState : std::uint8_t { None = 0, Authenticating, Active };
enum class RelayLeaseState : std::uint8_t { None = 0, Requesting, Allocated, Probing, Active, Grace, Revoked };
enum class RelayEd2kState : std::uint8_t { LowId = 0, RelayPending, RelayHighId, RelayDegraded };
enum class RelayEndpointState : std::uint8_t { Unknown = 0, Probing, Reachable, Degraded };
enum class RelayKadState : std::uint8_t { Classic = 0, RelayCandidate, RelayActive };
enum class RelayRouteState : std::uint8_t { Classic = 0, RelayConnecting, RelayReady, RelayActive, FallbackClassic };

enum class RelayReason : std::uint8_t {
    None = 0,
    Disabled,
    KillSwitch,
    InvalidConfig,
    TransportStartFailed,
    TlsFailed,
    WssFailed,
    AuthFailed,
    PolicyDenied,
    RemoteClosed,
    ProtocolError,
    LocalShutdown,
    QueueOverflow,
    StaleEvent,
};

enum class RelayClientEventType : std::uint8_t {
    TransportConnected = 0,
    WssReady,
    AuthStarted,
    Authenticated,
    LeaseRequested,
    LeaseAllocated,
    LeaseProbing,
    LeaseActive,
    EndpointReachable,
    EndpointDegraded,
    Disconnected,
    TlsFailed,
    WssFailed,
    AuthFailed,
    PolicyDenied,
    Fatal,
};

struct RelayClientEvent {
    RelayClientEventType type = RelayClientEventType::Disconnected;
    std::uint64_t generation = 0;
    RelayReason reason = RelayReason::None;
    std::uint64_t value = 0;
};

class RelayEventQueue final {
public:
    bool Push(const RelayClientEvent& event) noexcept;
    bool Pop(RelayClientEvent& event) noexcept;
    void Close() noexcept;
    void Reset() noexcept;
    std::uint64_t Dropped() const noexcept;
    std::size_t Size() const noexcept;

private:
    mutable std::mutex mutex_;
    std::array<RelayClientEvent, kRelayEventQueueCapacity> events_{};
    std::size_t head_ = 0;
    std::size_t size_ = 0;
    std::uint64_t dropped_ = 0;
    bool closed_ = false;
};

class IRelayTransportController {
public:
    virtual ~IRelayTransportController() = default;
    virtual relay::RelayStatus Start(std::uint64_t generation,
                                     const RelayClientConfig& config,
                                     const std::shared_ptr<RelayEventQueue>& events) noexcept = 0;
    virtual void Stop(std::uint64_t generation) noexcept = 0;
    virtual void Join() noexcept = 0;
};

class IRelayEventNotifier {
public:
    virtual ~IRelayEventNotifier() = default;
    virtual void Notify(std::uint64_t generation) noexcept = 0;
};

struct RelayClientSnapshot {
    bool configured_enabled = false;
    bool kill_switch = false;
    RelayCarrierState carrier = RelayCarrierState::Disabled;
    RelaySessionState session = RelaySessionState::None;
    RelayLeaseState lease = RelayLeaseState::None;
    RelayEd2kState ed2k = RelayEd2kState::LowId;
    RelayEndpointState endpoint = RelayEndpointState::Unknown;
    RelayKadState kad = RelayKadState::Classic;
    RelayRouteState route = RelayRouteState::Classic;
    RelayReason reason = RelayReason::Disabled;
    std::uint64_t generation = 0;
    std::uint64_t next_retry_ms = 0;
    std::uint64_t grace_deadline_ms = 0;
    std::uint32_t reconnect_attempt = 0;
};

struct RelayClientMetrics {
    std::uint64_t transport_starts = 0;
    std::uint64_t reconnects_scheduled = 0;
    std::uint64_t events_processed = 0;
    std::uint64_t stale_events = 0;
    std::uint64_t invalid_transitions = 0;
    std::uint64_t disconnects = 0;
    std::uint64_t shutdowns = 0;
    std::uint64_t queue_drops = 0;
};

class RelayClientManager final {
public:
    explicit RelayClientManager(IRelayTransportController& transport) noexcept;
    ~RelayClientManager();

    RelayClientManager(const RelayClientManager&) = delete;
    RelayClientManager& operator=(const RelayClientManager&) = delete;

    relay::RelayStatus Configure(const RelayClientConfig& config) noexcept;
    relay::RelayStatus Start(std::uint64_t now_ms) noexcept;
    relay::RelayStatus Tick(std::uint64_t now_ms) noexcept;
    relay::RelayStatus Disable() noexcept;
    relay::RelayStatus SetKillSwitch(bool active) noexcept;
    relay::RelayStatus Shutdown() noexcept;

    // Only protocol evidence already validated on the eMule main thread may
    // promote the displayed ED2K state. Worker events cannot claim High ID.
    relay::RelayStatus ApplyEd2kRelayEvidence(bool id_change_confirmed,
                                               bool endpoint_reachable,
                                               bool current_server_is_selected) noexcept;

    const RelayClientSnapshot& Snapshot() const noexcept { return snapshot_; }
    RelayClientMetrics Metrics() const noexcept;
    std::shared_ptr<RelayEventQueue> EventQueue() const noexcept { return events_; }
    bool IsMainThread() const noexcept;

private:
    relay::RelayStatus BeginAttempt(std::uint64_t now_ms) noexcept;
    void HandleEvent(const RelayClientEvent& event, std::uint64_t now_ms) noexcept;
    void HandleDisconnect(RelayReason reason, std::uint64_t now_ms, bool retry) noexcept;
    void ScheduleReconnect(std::uint64_t now_ms) noexcept;
    void ClearPublicState(bool disabled, RelayReason reason) noexcept;
    std::uint64_t BackoffDelayMs(std::uint32_t attempt) const noexcept;

    IRelayTransportController& transport_;
    const std::thread::id owner_thread_;
    std::shared_ptr<RelayEventQueue> events_;
    RelayClientConfig config_{};
    RelayClientSnapshot snapshot_{};
    RelayClientMetrics metrics_{};
    bool transport_started_ = false;
    bool shutdown_ = false;
};

const char* RelayCarrierStateName(RelayCarrierState value) noexcept;
const char* RelaySessionStateName(RelaySessionState value) noexcept;
const char* RelayLeaseStateName(RelayLeaseState value) noexcept;
const char* RelayEd2kStateName(RelayEd2kState value) noexcept;
const char* RelayEndpointStateName(RelayEndpointState value) noexcept;
const char* RelayKadStateName(RelayKadState value) noexcept;
const char* RelayRouteStateName(RelayRouteState value) noexcept;
const char* RelayReasonName(RelayReason value) noexcept;

} // namespace relayclient
