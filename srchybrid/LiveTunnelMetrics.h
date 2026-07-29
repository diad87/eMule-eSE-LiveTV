// this file is part of eMule eSE - immutable tunnel observability owner
#pragma once

#include "kad6/kad6_economy.h"
#include "kad6/kad6_hardening.h"
#include "kad6/kad6_release.h"

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

namespace eSELive {

struct LiveCircuitSnapshot {
    std::uint32_t circ_id = 0;
    std::uint8_t role = 0;
    std::uint8_t state = 0;
    std::uint32_t age_ms = 0;
    std::uint32_t hop_count = 0;
    std::uint8_t next_hop_set = 0;
    std::uint32_t next_circ_id = 0;
    std::uint8_t auth_ok = 0;
    std::uint8_t strict3 = 0;
    std::uint8_t shaped = 0;
    std::uint8_t shaping_exposed = 0;
    std::uint8_t abort_reason = 0;
};

struct LiveK6HardeningRuntimeSnapshot {
    kad6::K6HardeningSnapshot control;
    kad6::K6MetricsWindowInfo metrics;
    std::uint64_t active_leases = 0;
    std::uint64_t active_publishes = 0;
    std::uint64_t dial_streams = 0;
    std::uint64_t full_streams = 0;
    std::uint32_t shaping_exposed_circuits = 0;
    bool source_epoch_store_failed = false;
    bool economy_measurement_ready = false;
    bool strict_recommended = false;
    std::array<double, static_cast<std::size_t>(kad6::K6Service::Count)> rho{};
    std::array<kad6::K6EconomyWindowSnapshot,
               static_cast<std::size_t>(kad6::K6Service::Count)> economy{};
};

struct LiveK6ReleaseRuntimeSnapshot {
    bool operator_opt_in = false;
    bool evidence_present = false;
    bool evidence_valid = false;
    bool runtime_healthy = false;
    bool public_exit_enabled = false;
    bool beta_exit_opt_in = false;
    bool beta_exit_enabled = false;
    kad6::K6ReleaseGateStatus status = kad6::K6ReleaseGateStatus::Missing;
    kad6::K6ReleaseEvidence evidence;
};

struct LivePeerSnapshot {
    std::uint32_t ip = 0;
    std::uint16_t port = 0;
    std::uint32_t fork_caps = 0;
    std::uint32_t ese_caps = 0;
    std::string address;
    bool has_ipv4 = false;
};

struct LiveTunnelTotalsSnapshot {
    std::uint64_t cells_sent = 0;
    std::uint64_t cells_received = 0;
    std::uint64_t bytes_sent = 0;
    std::uint64_t bytes_received = 0;
    std::uint32_t mean_rtt_ms = 0;
};

class LiveTunnelMetrics {
public:
    LiveTunnelMetrics() noexcept = default;
    LiveTunnelMetrics(const LiveTunnelMetrics&) = delete;
    LiveTunnelMetrics& operator=(const LiveTunnelMetrics&) = delete;

    void RecordCellSent(std::size_t wire_bytes) noexcept;
    void RecordCellReceived(std::size_t wire_bytes) noexcept;
    void ObserveMeanRtt(std::uint32_t rtt_ms) noexcept;
    LiveTunnelTotalsSnapshot Totals() const noexcept;

    bool Add(kad6::K6MetricFamily family, std::uint8_t label_a,
             std::uint8_t label_b, std::uint8_t label_c,
             std::uint64_t amount, std::uint64_t now_seconds) noexcept;
    bool Observe(kad6::K6MetricFamily family, std::uint8_t label_a,
                 std::uint8_t label_b, std::uint8_t label_c,
                 double value, std::uint64_t now_seconds) noexcept;
    kad6::K6MetricsWindowInfo WindowInfo(std::uint64_t now_seconds) noexcept;
    std::string ExportPrometheus(std::uint64_t now_seconds);

    void ReplacePeers(std::vector<LivePeerSnapshot> peers,
                      std::size_t tunneling_count);
    void GetPeers(std::vector<LivePeerSnapshot>& peers,
                  std::size_t& tunneling_count) const;

private:
    std::atomic<std::uint64_t> cells_sent_{0};
    std::atomic<std::uint64_t> cells_received_{0};
    std::atomic<std::uint64_t> bytes_sent_{0};
    std::atomic<std::uint64_t> bytes_received_{0};
    std::atomic<std::uint32_t> mean_rtt_ms_{0};
    kad6::K6Metrics k6_metrics_;
    mutable std::mutex peers_mutex_;
    std::vector<LivePeerSnapshot> peers_;
    std::size_t tunneling_count_ = 0;
};

bool RunLiveTunnelMetricsCharacterizationSelfTest();

} // namespace eSELive
