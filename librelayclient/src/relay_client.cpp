// SPDX-License-Identifier: MIT
#include "relayclient/relay_client.h"

#include <algorithm>
#include <limits>

namespace relayclient {
namespace {

std::uint64_t SaturatingAdd(std::uint64_t left, std::uint64_t right) noexcept {
    if (right > std::numeric_limits<std::uint64_t>::max() - left)
        return std::numeric_limits<std::uint64_t>::max();
    return left + right;
}

void SaturatingIncrement(std::uint64_t& value) noexcept {
    if (value != std::numeric_limits<std::uint64_t>::max())
        ++value;
}

} // namespace

relay::RelayStatus ValidateRelayClientConfig(const RelayClientConfig& config) noexcept {
    if (config.reconnect_min_ms == 0 || config.reconnect_max_ms < config.reconnect_min_ms ||
        config.reconnect_max_ms > 3600000 || config.reconnect_jitter_percent > 25 ||
        config.lease_grace_ms > 300000)
        return relay::RelayStatus::InvalidArgument;
    if (!config.enabled)
        return relay::RelayStatus::Ok;
    if (config.endpoint_host.empty() || config.endpoint_host.size() > kRelayEndpointHostMax ||
        config.endpoint_port == 0 || config.endpoint_path != "/krp/v1" ||
        config.expected_server_name.empty() ||
        config.expected_server_name.size() > kRelayEndpointHostMax ||
        config.ca_bundle_path.empty() || config.ca_bundle_path.size() > kRelayCaPathMax)
        return relay::RelayStatus::InvalidArgument;
    if (config.experimental_tcp_data_plane &&
        (config.auth_token_path.empty() ||
         config.auth_token_path.size() > kRelayAuthTokenPathMax ||
         config.local_tcp_port == 0))
        return relay::RelayStatus::InvalidArgument;
    return relay::RelayStatus::Ok;
}

bool RelayEventQueue::Push(const RelayClientEvent& event) noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    if (closed_ || size_ == events_.size()) {
        SaturatingIncrement(dropped_);
        return false;
    }
    events_[(head_ + size_) % events_.size()] = event;
    ++size_;
    return true;
}

bool RelayEventQueue::Pop(RelayClientEvent& event) noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    if (size_ == 0)
        return false;
    event = events_[head_];
    head_ = (head_ + 1) % events_.size();
    --size_;
    return true;
}

void RelayEventQueue::Close() noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    closed_ = true;
    head_ = 0;
    size_ = 0;
}

void RelayEventQueue::Reset() noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    closed_ = false;
    head_ = 0;
    size_ = 0;
}

std::uint64_t RelayEventQueue::Dropped() const noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    return dropped_;
}

std::size_t RelayEventQueue::Size() const noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    return size_;
}

RelayClientManager::RelayClientManager(IRelayTransportController& transport) noexcept
    : transport_(transport), owner_thread_(std::this_thread::get_id()),
      events_(std::make_shared<RelayEventQueue>()) {}

RelayClientManager::~RelayClientManager() {
    if (IsMainThread())
        Shutdown();
    else
        events_->Close();
}

bool RelayClientManager::IsMainThread() const noexcept {
    return std::this_thread::get_id() == owner_thread_;
}

relay::RelayStatus RelayClientManager::Configure(const RelayClientConfig& config) noexcept {
    if (!IsMainThread() || shutdown_ || transport_started_ ||
        snapshot_.carrier == RelayCarrierState::Backoff)
        return relay::RelayStatus::InvalidState;
    const relay::RelayStatus status = ValidateRelayClientConfig(config);
    if (status != relay::RelayStatus::Ok) {
        snapshot_.reason = RelayReason::InvalidConfig;
        return status;
    }
    config_ = config;
    snapshot_.configured_enabled = config.enabled;
    snapshot_.kill_switch = config.kill_switch;
    ClearPublicState(!config.enabled || config.kill_switch,
                     config.kill_switch ? RelayReason::KillSwitch :
                     (config.enabled ? RelayReason::None : RelayReason::Disabled));
    return relay::RelayStatus::Ok;
}

relay::RelayStatus RelayClientManager::Start(std::uint64_t now_ms) noexcept {
    if (!IsMainThread() || shutdown_)
        return relay::RelayStatus::InvalidState;
    if (!config_.enabled || config_.kill_switch)
        return relay::RelayStatus::Disabled;
    if (ValidateRelayClientConfig(config_) != relay::RelayStatus::Ok) {
        snapshot_.reason = RelayReason::InvalidConfig;
        return relay::RelayStatus::InvalidArgument;
    }
    if (transport_started_ || snapshot_.carrier == RelayCarrierState::Backoff)
        return relay::RelayStatus::InvalidState;
    return BeginAttempt(now_ms);
}

relay::RelayStatus RelayClientManager::BeginAttempt(std::uint64_t now_ms) noexcept {
    (void)now_ms;
    if (transport_started_) {
        transport_.Join();
        transport_started_ = false;
    }
    events_->Reset();
    ++snapshot_.generation;
    snapshot_.carrier = RelayCarrierState::Connecting;
    snapshot_.session = RelaySessionState::None;
    snapshot_.route = RelayRouteState::RelayConnecting;
    snapshot_.reason = RelayReason::None;
    snapshot_.next_retry_ms = 0;
    const relay::RelayStatus status = transport_.Start(snapshot_.generation, config_, events_);
    if (status != relay::RelayStatus::Ok) {
        HandleDisconnect(RelayReason::TransportStartFailed, now_ms, true);
        return status;
    }
    transport_started_ = true;
    SaturatingIncrement(metrics_.transport_starts);
    return relay::RelayStatus::Ok;
}

relay::RelayStatus RelayClientManager::Tick(std::uint64_t now_ms) noexcept {
    if (!IsMainThread() || shutdown_)
        return relay::RelayStatus::InvalidState;

    RelayClientEvent event;
    while (events_->Pop(event)) {
        SaturatingIncrement(metrics_.events_processed);
        HandleEvent(event, now_ms);
    }

    if (snapshot_.lease == RelayLeaseState::Grace &&
        now_ms >= snapshot_.grace_deadline_ms) {
        snapshot_.lease = RelayLeaseState::None;
        snapshot_.endpoint = RelayEndpointState::Unknown;
        snapshot_.ed2k = RelayEd2kState::LowId;
        snapshot_.grace_deadline_ms = 0;
    }

    if (snapshot_.carrier == RelayCarrierState::Backoff &&
        now_ms >= snapshot_.next_retry_ms) {
        if (transport_started_) {
            transport_.Join();
            transport_started_ = false;
        }
        return BeginAttempt(now_ms);
    }
    return relay::RelayStatus::Ok;
}

void RelayClientManager::HandleEvent(const RelayClientEvent& event,
                                     std::uint64_t now_ms) noexcept {
    if (event.generation != snapshot_.generation) {
        SaturatingIncrement(metrics_.stale_events);
        snapshot_.reason = RelayReason::StaleEvent;
        return;
    }
    switch (event.type) {
    case RelayClientEventType::TransportConnected:
        if (snapshot_.carrier != RelayCarrierState::Connecting) {
            SaturatingIncrement(metrics_.invalid_transitions);
            return;
        }
        snapshot_.carrier = RelayCarrierState::TlsReady;
        break;
    case RelayClientEventType::WssReady:
        if (snapshot_.carrier != RelayCarrierState::TlsReady) {
            SaturatingIncrement(metrics_.invalid_transitions);
            return;
        }
        snapshot_.carrier = RelayCarrierState::WssReady;
        break;
    case RelayClientEventType::AuthStarted:
        if (snapshot_.carrier != RelayCarrierState::WssReady) {
            SaturatingIncrement(metrics_.invalid_transitions);
            return;
        }
        snapshot_.carrier = RelayCarrierState::Authenticating;
        snapshot_.session = RelaySessionState::Authenticating;
        break;
    case RelayClientEventType::Authenticated:
        if (snapshot_.session != RelaySessionState::Authenticating) {
            SaturatingIncrement(metrics_.invalid_transitions);
            return;
        }
        snapshot_.carrier = RelayCarrierState::Active;
        snapshot_.session = RelaySessionState::Active;
        snapshot_.reconnect_attempt = 0;
        break;
    case RelayClientEventType::LeaseRequested:
        if (snapshot_.session != RelaySessionState::Active) {
            SaturatingIncrement(metrics_.invalid_transitions);
            return;
        }
        snapshot_.lease = RelayLeaseState::Requesting;
        snapshot_.ed2k = RelayEd2kState::RelayPending;
        break;
    case RelayClientEventType::LeaseAllocated:
        if (snapshot_.lease != RelayLeaseState::Requesting) {
            SaturatingIncrement(metrics_.invalid_transitions);
            return;
        }
        snapshot_.lease = RelayLeaseState::Allocated;
        break;
    case RelayClientEventType::LeaseProbing:
        if (snapshot_.lease != RelayLeaseState::Allocated) {
            SaturatingIncrement(metrics_.invalid_transitions);
            return;
        }
        snapshot_.lease = RelayLeaseState::Probing;
        snapshot_.endpoint = RelayEndpointState::Probing;
        break;
    case RelayClientEventType::LeaseActive:
        if (snapshot_.lease != RelayLeaseState::Probing) {
            SaturatingIncrement(metrics_.invalid_transitions);
            return;
        }
        snapshot_.lease = RelayLeaseState::Active;
        snapshot_.route = RelayRouteState::RelayReady;
        break;
    case RelayClientEventType::EndpointReachable:
        if (snapshot_.lease != RelayLeaseState::Active) {
            SaturatingIncrement(metrics_.invalid_transitions);
            return;
        }
        snapshot_.endpoint = RelayEndpointState::Reachable;
        break;
    case RelayClientEventType::EndpointDegraded:
        snapshot_.endpoint = RelayEndpointState::Degraded;
        if (snapshot_.ed2k == RelayEd2kState::RelayHighId)
            snapshot_.ed2k = RelayEd2kState::RelayDegraded;
        snapshot_.route = RelayRouteState::FallbackClassic;
        snapshot_.reason = event.reason;
        break;
    case RelayClientEventType::Disconnected:
        HandleDisconnect(event.reason == RelayReason::None ? RelayReason::RemoteClosed : event.reason,
                         now_ms, true);
        break;
    case RelayClientEventType::TlsFailed:
        HandleDisconnect(RelayReason::TlsFailed, now_ms, true);
        break;
    case RelayClientEventType::WssFailed:
        HandleDisconnect(RelayReason::WssFailed, now_ms, true);
        break;
    case RelayClientEventType::AuthFailed:
        HandleDisconnect(RelayReason::AuthFailed, now_ms, true);
        break;
    case RelayClientEventType::PolicyDenied:
        HandleDisconnect(RelayReason::PolicyDenied, now_ms, false);
        snapshot_.carrier = RelayCarrierState::Failed;
        break;
    case RelayClientEventType::Fatal:
        HandleDisconnect(event.reason == RelayReason::None ? RelayReason::ProtocolError : event.reason,
                         now_ms, false);
        snapshot_.carrier = RelayCarrierState::Failed;
        break;
    }
}

void RelayClientManager::HandleDisconnect(RelayReason reason, std::uint64_t now_ms,
                                          bool retry) noexcept {
    SaturatingIncrement(metrics_.disconnects);
    const bool had_public_state = snapshot_.lease == RelayLeaseState::Active ||
                                  snapshot_.ed2k == RelayEd2kState::RelayHighId;
    snapshot_.session = RelaySessionState::None;
    snapshot_.kad = RelayKadState::Classic;
    snapshot_.route = RelayRouteState::FallbackClassic;
    snapshot_.reason = reason;
    if (had_public_state && config_.lease_grace_ms != 0) {
        snapshot_.lease = RelayLeaseState::Grace;
        snapshot_.endpoint = RelayEndpointState::Degraded;
        snapshot_.ed2k = RelayEd2kState::RelayDegraded;
        snapshot_.grace_deadline_ms = SaturatingAdd(now_ms, config_.lease_grace_ms);
    } else {
        snapshot_.lease = RelayLeaseState::None;
        snapshot_.endpoint = RelayEndpointState::Unknown;
        snapshot_.ed2k = RelayEd2kState::LowId;
        snapshot_.grace_deadline_ms = 0;
    }
    if (retry && config_.enabled && !config_.kill_switch)
        ScheduleReconnect(now_ms);
    else {
        snapshot_.carrier = RelayCarrierState::Disconnected;
        snapshot_.next_retry_ms = 0;
    }
}

void RelayClientManager::ScheduleReconnect(std::uint64_t now_ms) noexcept {
    const std::uint64_t delay = BackoffDelayMs(snapshot_.reconnect_attempt);
    snapshot_.carrier = RelayCarrierState::Backoff;
    snapshot_.next_retry_ms = SaturatingAdd(now_ms, delay);
    if (snapshot_.reconnect_attempt != std::numeric_limits<std::uint32_t>::max())
        ++snapshot_.reconnect_attempt;
    SaturatingIncrement(metrics_.reconnects_scheduled);
}

std::uint64_t RelayClientManager::BackoffDelayMs(std::uint32_t attempt) const noexcept {
    std::uint64_t base = config_.reconnect_min_ms;
    const std::uint32_t shifts = std::min<std::uint32_t>(attempt, 31);
    for (std::uint32_t i = 0; i < shifts && base < config_.reconnect_max_ms; ++i)
        base = std::min<std::uint64_t>(base * 2, config_.reconnect_max_ms);
    const std::uint64_t spread = (base * config_.reconnect_jitter_percent) / 100;
    if (spread == 0)
        return base;
    std::uint64_t x = snapshot_.generation ^ (static_cast<std::uint64_t>(attempt) << 32) ^
                      0x9E3779B97F4A7C15ull;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    const std::uint64_t width = spread * 2 + 1;
    const std::int64_t offset = static_cast<std::int64_t>(x % width) -
                                static_cast<std::int64_t>(spread);
    return static_cast<std::uint64_t>(static_cast<std::int64_t>(base) + offset);
}

relay::RelayStatus RelayClientManager::Disable() noexcept {
    if (!IsMainThread() || shutdown_)
        return relay::RelayStatus::InvalidState;
    config_.enabled = false;
    snapshot_.configured_enabled = false;
    if (transport_started_)
        transport_.Stop(snapshot_.generation);
    transport_.Join();
    transport_started_ = false;
    ++snapshot_.generation;
    events_->Reset();
    ClearPublicState(true, RelayReason::Disabled);
    return relay::RelayStatus::Ok;
}

relay::RelayStatus RelayClientManager::SetKillSwitch(bool active) noexcept {
    if (!IsMainThread() || shutdown_)
        return relay::RelayStatus::InvalidState;
    config_.kill_switch = active;
    snapshot_.kill_switch = active;
    if (!active)
        return relay::RelayStatus::Ok;
    if (transport_started_)
        transport_.Stop(snapshot_.generation);
    transport_.Join();
    transport_started_ = false;
    ++snapshot_.generation;
    events_->Reset();
    ClearPublicState(true, RelayReason::KillSwitch);
    return relay::RelayStatus::Ok;
}

void RelayClientManager::ClearPublicState(bool disabled, RelayReason reason) noexcept {
    snapshot_.carrier = disabled ? RelayCarrierState::Disabled : RelayCarrierState::Disconnected;
    snapshot_.session = RelaySessionState::None;
    snapshot_.lease = RelayLeaseState::None;
    snapshot_.ed2k = RelayEd2kState::LowId;
    snapshot_.endpoint = RelayEndpointState::Unknown;
    snapshot_.kad = RelayKadState::Classic;
    snapshot_.route = RelayRouteState::Classic;
    snapshot_.reason = reason;
    snapshot_.next_retry_ms = 0;
    snapshot_.grace_deadline_ms = 0;
    snapshot_.reconnect_attempt = 0;
}

relay::RelayStatus RelayClientManager::ApplyEd2kRelayEvidence(
    bool id_change_confirmed, bool endpoint_reachable,
    bool current_server_is_selected) noexcept {
    if (!IsMainThread() || shutdown_)
        return relay::RelayStatus::InvalidState;
    if (!id_change_confirmed || !endpoint_reachable ||
        (config_.server_policy == RelayServerPolicy::SelectedServerOnly &&
         !current_server_is_selected) ||
        snapshot_.session != RelaySessionState::Active ||
        snapshot_.lease != RelayLeaseState::Active ||
        snapshot_.endpoint != RelayEndpointState::Reachable)
        return relay::RelayStatus::InvalidState;
    snapshot_.ed2k = RelayEd2kState::RelayHighId;
    snapshot_.route = RelayRouteState::RelayActive;
    return relay::RelayStatus::Ok;
}

relay::RelayStatus RelayClientManager::Shutdown() noexcept {
    if (!IsMainThread())
        return relay::RelayStatus::InvalidState;
    if (shutdown_)
        return relay::RelayStatus::Ok;
    if (transport_started_) {
        snapshot_.carrier = RelayCarrierState::Draining;
        transport_.Stop(snapshot_.generation);
    }
    transport_.Join();
    transport_started_ = false;
    ++snapshot_.generation;
    events_->Close();
    ClearPublicState(true, RelayReason::LocalShutdown);
    shutdown_ = true;
    SaturatingIncrement(metrics_.shutdowns);
    return relay::RelayStatus::Ok;
}

RelayClientMetrics RelayClientManager::Metrics() const noexcept {
    RelayClientMetrics copy = metrics_;
    copy.queue_drops = events_->Dropped();
    return copy;
}

#define RELAY_NAME_CASE(value) case value: return #value

const char* RelayCarrierStateName(RelayCarrierState value) noexcept {
    switch (value) {
    RELAY_NAME_CASE(RelayCarrierState::Disabled); RELAY_NAME_CASE(RelayCarrierState::Disconnected);
    RELAY_NAME_CASE(RelayCarrierState::Connecting); RELAY_NAME_CASE(RelayCarrierState::TlsReady);
    RELAY_NAME_CASE(RelayCarrierState::WssReady); RELAY_NAME_CASE(RelayCarrierState::Authenticating);
    RELAY_NAME_CASE(RelayCarrierState::Active); RELAY_NAME_CASE(RelayCarrierState::Backoff);
    RELAY_NAME_CASE(RelayCarrierState::Draining); RELAY_NAME_CASE(RelayCarrierState::Failed);
    }
    return "RelayCarrierState::Unknown";
}

const char* RelaySessionStateName(RelaySessionState value) noexcept {
    switch (value) {
    RELAY_NAME_CASE(RelaySessionState::None); RELAY_NAME_CASE(RelaySessionState::Authenticating);
    RELAY_NAME_CASE(RelaySessionState::Active);
    }
    return "RelaySessionState::Unknown";
}

const char* RelayLeaseStateName(RelayLeaseState value) noexcept {
    switch (value) {
    RELAY_NAME_CASE(RelayLeaseState::None); RELAY_NAME_CASE(RelayLeaseState::Requesting);
    RELAY_NAME_CASE(RelayLeaseState::Allocated); RELAY_NAME_CASE(RelayLeaseState::Probing);
    RELAY_NAME_CASE(RelayLeaseState::Active); RELAY_NAME_CASE(RelayLeaseState::Grace);
    RELAY_NAME_CASE(RelayLeaseState::Revoked);
    }
    return "RelayLeaseState::Unknown";
}

const char* RelayEd2kStateName(RelayEd2kState value) noexcept {
    switch (value) {
    RELAY_NAME_CASE(RelayEd2kState::LowId); RELAY_NAME_CASE(RelayEd2kState::RelayPending);
    RELAY_NAME_CASE(RelayEd2kState::RelayHighId); RELAY_NAME_CASE(RelayEd2kState::RelayDegraded);
    }
    return "RelayEd2kState::Unknown";
}

const char* RelayEndpointStateName(RelayEndpointState value) noexcept {
    switch (value) {
    RELAY_NAME_CASE(RelayEndpointState::Unknown); RELAY_NAME_CASE(RelayEndpointState::Probing);
    RELAY_NAME_CASE(RelayEndpointState::Reachable); RELAY_NAME_CASE(RelayEndpointState::Degraded);
    }
    return "RelayEndpointState::UnknownValue";
}

const char* RelayKadStateName(RelayKadState value) noexcept {
    switch (value) {
    RELAY_NAME_CASE(RelayKadState::Classic); RELAY_NAME_CASE(RelayKadState::RelayCandidate);
    RELAY_NAME_CASE(RelayKadState::RelayActive);
    }
    return "RelayKadState::Unknown";
}

const char* RelayRouteStateName(RelayRouteState value) noexcept {
    switch (value) {
    RELAY_NAME_CASE(RelayRouteState::Classic); RELAY_NAME_CASE(RelayRouteState::RelayConnecting);
    RELAY_NAME_CASE(RelayRouteState::RelayReady); RELAY_NAME_CASE(RelayRouteState::RelayActive);
    RELAY_NAME_CASE(RelayRouteState::FallbackClassic);
    }
    return "RelayRouteState::Unknown";
}

const char* RelayReasonName(RelayReason value) noexcept {
    switch (value) {
    RELAY_NAME_CASE(RelayReason::None); RELAY_NAME_CASE(RelayReason::Disabled);
    RELAY_NAME_CASE(RelayReason::KillSwitch); RELAY_NAME_CASE(RelayReason::InvalidConfig);
    RELAY_NAME_CASE(RelayReason::TransportStartFailed); RELAY_NAME_CASE(RelayReason::TlsFailed);
    RELAY_NAME_CASE(RelayReason::WssFailed); RELAY_NAME_CASE(RelayReason::AuthFailed);
    RELAY_NAME_CASE(RelayReason::PolicyDenied); RELAY_NAME_CASE(RelayReason::RemoteClosed);
    RELAY_NAME_CASE(RelayReason::ProtocolError); RELAY_NAME_CASE(RelayReason::LocalShutdown);
    RELAY_NAME_CASE(RelayReason::QueueOverflow); RELAY_NAME_CASE(RelayReason::StaleEvent);
    }
    return "RelayReason::Unknown";
}

#undef RELAY_NAME_CASE

} // namespace relayclient
