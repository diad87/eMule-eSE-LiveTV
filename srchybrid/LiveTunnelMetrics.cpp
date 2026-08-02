// this file is part of eMule eSE - immutable tunnel observability owner
#include "LiveTunnelMetrics.h"

#include <limits>
#include <utility>

namespace eSELive {

void LiveTunnelMetrics::RecordCellSent(std::size_t wire_bytes) noexcept
{
    cells_sent_.fetch_add(1, std::memory_order_relaxed);
    bytes_sent_.fetch_add(static_cast<std::uint64_t>(wire_bytes),
                          std::memory_order_relaxed);
}

void LiveTunnelMetrics::RecordCellReceived(std::size_t wire_bytes) noexcept
{
    cells_received_.fetch_add(1, std::memory_order_relaxed);
    bytes_received_.fetch_add(static_cast<std::uint64_t>(wire_bytes),
                              std::memory_order_relaxed);
}

void LiveTunnelMetrics::ObserveMeanRtt(std::uint32_t rtt_ms) noexcept
{
    std::uint32_t current = mean_rtt_ms_.load(std::memory_order_relaxed);
    for (;;) {
        const std::uint32_t desired = current == 0
            ? rtt_ms
            : static_cast<std::uint32_t>(
                (static_cast<std::uint64_t>(current) * 3u + rtt_ms) / 4u);
        if (mean_rtt_ms_.compare_exchange_weak(
                current, desired, std::memory_order_relaxed,
                std::memory_order_relaxed))
            return;
    }
}

LiveTunnelTotalsSnapshot LiveTunnelMetrics::Totals() const noexcept
{
    LiveTunnelTotalsSnapshot result;
    result.cells_sent = cells_sent_.load(std::memory_order_relaxed);
    result.cells_received = cells_received_.load(std::memory_order_relaxed);
    result.bytes_sent = bytes_sent_.load(std::memory_order_relaxed);
    result.bytes_received = bytes_received_.load(std::memory_order_relaxed);
    result.mean_rtt_ms = mean_rtt_ms_.load(std::memory_order_relaxed);
    return result;
}

void LiveTunnelMetrics::RecordOriginAdvertiseSuccess() noexcept
{
    origin_advertise_success_total_.fetch_add(1, std::memory_order_relaxed);
}

void LiveTunnelMetrics::RecordOriginSourceRecovered() noexcept
{
    origin_source_recovered_total_.fetch_add(1, std::memory_order_relaxed);
}

std::uint64_t LiveTunnelMetrics::OriginAdvertiseSuccessTotal() const noexcept
{
    return origin_advertise_success_total_.load(std::memory_order_relaxed);
}

std::uint64_t LiveTunnelMetrics::OriginSourceRecoveredTotal() const noexcept
{
    return origin_source_recovered_total_.load(std::memory_order_relaxed);
}

bool LiveTunnelMetrics::Add(
    kad6::K6MetricFamily family, std::uint8_t label_a,
    std::uint8_t label_b, std::uint8_t label_c,
    std::uint64_t amount, std::uint64_t now_seconds) noexcept
{
    return k6_metrics_.Add(
        family, label_a, label_b, label_c, amount, now_seconds);
}

bool LiveTunnelMetrics::Observe(
    kad6::K6MetricFamily family, std::uint8_t label_a,
    std::uint8_t label_b, std::uint8_t label_c,
    double value, std::uint64_t now_seconds) noexcept
{
    return k6_metrics_.Observe(
        family, label_a, label_b, label_c, value, now_seconds);
}

kad6::K6MetricsWindowInfo LiveTunnelMetrics::WindowInfo(
    std::uint64_t now_seconds) noexcept
{
    return k6_metrics_.WindowInfo(now_seconds);
}

std::string LiveTunnelMetrics::ExportPrometheus(std::uint64_t now_seconds)
{
    return k6_metrics_.ExportPrometheus(now_seconds);
}

void LiveTunnelMetrics::ReplacePeers(
    std::vector<LivePeerSnapshot> peers, std::size_t tunneling_count)
{
    std::lock_guard<std::mutex> lock(peers_mutex_);
    peers_.swap(peers);
    tunneling_count_ = tunneling_count;
}

void LiveTunnelMetrics::GetPeers(
    std::vector<LivePeerSnapshot>& peers, std::size_t& tunneling_count) const
{
    std::lock_guard<std::mutex> lock(peers_mutex_);
    peers = peers_;
    tunneling_count = tunneling_count_;
}

bool RunLiveTunnelMetricsCharacterizationSelfTest()
{
    LiveTunnelMetrics metrics;
    metrics.RecordCellSent(512);
    metrics.RecordCellSent(48);
    metrics.RecordCellReceived(256);
    metrics.ObserveMeanRtt(100);
    metrics.ObserveMeanRtt(200);
    metrics.RecordOriginAdvertiseSuccess();
    metrics.RecordOriginSourceRecovered();
    const LiveTunnelTotalsSnapshot totals = metrics.Totals();
    if (totals.cells_sent != 2 || totals.cells_received != 1 ||
        totals.bytes_sent != 560 || totals.bytes_received != 256 ||
        totals.mean_rtt_ms != 125 ||
        metrics.OriginAdvertiseSuccessTotal() != 1 ||
        metrics.OriginSourceRecoveredTotal() != 1)
        return false;

    LivePeerSnapshot peer;
    peer.ip = 0x01020304u;
    peer.port = 4662;
    peer.address = "1.2.3.4";
    peer.has_ipv4 = true;
    peer.hash_ready = true;
    peer.node_pub_ready = true;
    peer.auth_cap = true;
    peer.dataplane_cap = true;
    peer.auth_ready = true;
    std::vector<LivePeerSnapshot> peers(1, peer);
    metrics.ReplacePeers(std::move(peers), 1);
    std::vector<LivePeerSnapshot> copy;
    std::size_t tunneling_count = 0;
    metrics.GetPeers(copy, tunneling_count);
    return copy.size() == 1 && copy[0].ip == peer.ip &&
        copy[0].address == peer.address && tunneling_count == 1 &&
        copy[0].auth_ready && copy[0].hash_ready &&
        copy[0].node_pub_ready && copy[0].auth_cap &&
        copy[0].dataplane_cap;
}

} // namespace eSELive
