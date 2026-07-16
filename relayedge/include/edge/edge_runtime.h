// SPDX-License-Identifier: MIT
#pragma once

#include "relay/relay_core.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

namespace relayedge {

constexpr std::size_t kMaxConfigFileBytes = 16 * 1024;
constexpr std::size_t kMaxConfigLineBytes = 1024;
constexpr std::size_t kMaxConfigPathBytes = 512;
constexpr std::size_t kAuditRingSize = 1024;
constexpr std::uint64_t kMaxDrainMs = 300000;

enum class EdgeMode : std::uint8_t { Disabled = 0, LabLoopback, ExperimentalPublic };
enum class EdgeLifecycle : std::uint8_t {
    Stopped = 0,
    Starting,
    Running,
    Draining,
    Failed,
};
enum class EdgeHealth : std::uint8_t {
    Disabled = 0,
    Starting,
    Healthy,
    Draining,
    Failed,
};

struct EdgeConfig {
    EdgeMode mode = EdgeMode::Disabled;
    bool explicit_lab_enable = false;
    bool explicit_public_enable = false;
    std::string bind_address = "127.0.0.1";
    std::uint16_t port = 0;
    // Required in experimental-public mode. This is the IPv4 announced to
    // eD2K. On a 1:1 cloud NAT it may differ from bind_address.
    std::string public_ipv4;
    std::string auth_token_path;
    std::string certificate_path;
    std::string private_key_path;
    std::size_t max_sessions = 256;
    std::size_t max_flows_per_session = 256;
    std::size_t max_leases_per_session = 1;
    std::size_t max_preauth_bytes = 16 * 1024;
    std::uint64_t preauth_timeout_ms = 10000;
    std::uint64_t idle_timeout_ms = 90000;
    std::uint64_t reuse_delay_ms = 120000;
    std::uint16_t lease_first_port = 40000;
    std::uint16_t lease_last_port = 40031;
};

relay::RelayStatus LoadEdgeConfig(const char* path, EdgeConfig& config);
relay::RelayStatus ValidateEdgeConfig(const EdgeConfig& config) noexcept;

enum class EdgeMetric : std::uint8_t {
    StartOk = 0,
    StartRejected,
    PreAuthAccepted,
    AuthOk,
    AuthFailed,
    SessionTimeout,
    FlowAccepted,
    FlowRejected,
    LeaseAllocated,
    LeaseRejected,
    PolicyDenied,
    ReplayRejected,
    SlowReaderReset,
    GoAwaySent,
    KillSwitch,
    Count,
};

class EdgeMetrics {
public:
    void Increment(EdgeMetric metric, std::uint64_t amount = 1) noexcept;
    std::uint64_t Get(EdgeMetric metric) const noexcept;

private:
    std::array<std::uint64_t, static_cast<std::size_t>(EdgeMetric::Count)> values_{};
};

enum class AuditReason : std::uint8_t {
    Started = 0,
    ConfigRejected,
    AuthRejected,
    QuotaRejected,
    PolicyRejected,
    ReplayRejected,
    Draining,
    Killed,
    Failed,
    Stopped,
};

struct AuditEvent {
    std::uint64_t timestamp_ms = 0;
    AuditReason reason = AuditReason::Started;
    std::uint64_t session_handle = 0;
    std::uint64_t object_id = 0;
    relay::RelayStatus status = relay::RelayStatus::Ok;
};

class AuditRing {
public:
    void Push(const AuditEvent& event) noexcept;
    std::size_t size() const noexcept { return size_; }
    const AuditEvent* At(std::size_t oldest_index) const noexcept;

private:
    std::array<AuditEvent, kAuditRingSize> events_{};
    std::size_t next_ = 0;
    std::size_t size_ = 0;
};

class EdgeRuntime {
public:
    relay::RelayStatus Start(const EdgeConfig& config, std::uint64_t now_ms) noexcept;
    relay::RelayStatus BeginDrain(std::uint64_t now_ms,
                                  std::uint64_t deadline_ms) noexcept;
    relay::RelayStatus Tick(std::uint64_t now_ms) noexcept;
    relay::RelayStatus Kill(std::uint64_t now_ms) noexcept;
    relay::RelayStatus Fail(std::uint64_t now_ms,
                            relay::RelayStatus reason) noexcept;

    bool CanAcceptSessions() const noexcept {
        return state_ == EdgeLifecycle::Running && !kill_switch_;
    }
    EdgeLifecycle state() const noexcept { return state_; }
    EdgeHealth health() const noexcept;
    const EdgeConfig& config() const noexcept { return config_; }
    const EdgeMetrics& metrics() const noexcept { return metrics_; }
    EdgeMetrics& metrics() noexcept { return metrics_; }
    const AuditRing& audit() const noexcept { return audit_; }

private:
    EdgeConfig config_{};
    EdgeLifecycle state_ = EdgeLifecycle::Stopped;
    bool kill_switch_ = false;
    std::uint64_t drain_deadline_ms_ = 0;
    EdgeMetrics metrics_{};
    AuditRing audit_{};
};

const char* EdgeLifecycleName(EdgeLifecycle state) noexcept;

} // namespace relayedge
