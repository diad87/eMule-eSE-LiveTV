#pragma once

#include "M2ABindingPort.h"

#include <cstdint>
#include <string>
#include <vector>

namespace ese { namespace web {

enum class W10DiagnosticsOperation { KrpStatus, Preflight, Metrics, Log, Debug, Ipv6Echo, ReachStatus };
struct W10DiagnosticsRequest {
	W10DiagnosticsOperation operation = W10DiagnosticsOperation::KrpStatus;
	int log_n = 100, tcp_port = 0, udp_port = 0, timeout_ms = 5000;
	std::string target, nonce;
};
struct W10Ipv6EchoResult {
	bool success = false;
	std::string error, target, nonce;
	int tcp_port = 0, udp_port = 0, tcp_error = 0, udp_error = 0;
	std::uint32_t tcp_bytes = 0, udp_bytes = 0;
};
struct W10PreflightSnapshot { bool kad_connected = false, high_id = false, kad_firewalled = false, ed2k_lowid = false, firewall_checking = false, ffmpeg_found = false; std::uint32_t max_upload_kbs = 0; std::uint16_t port = 0; std::string public_ip, public_ip_v6, ffmpeg_path; };
struct W10MetricsSnapshot { long chunks_received = 0, chunks_requested = 0, chunks_missing = 0, kad_publishes = 0, kad_searches = 0, peer_disconnects = 0, kad_searches_empty = 0, kad_searches_rate_limited = 0, pending_dials_dropped = 0, join_first_count = 0, join_first_sum = 0; int chunks_served = 0, view_peers = 0, broadcast_peers = 0, mesh_peers = 0, buffer_count = 0, pending_requests = 0; bool broadcasting = false, viewing = false; };
struct W10DebugPeer { std::string ip; std::uint16_t port = 0; std::int64_t level = 0, fail_count = 0, response_percent = 0; std::uint32_t rtt_ms = 0; };
struct W10DebugSnapshot { bool available = false, broadcasting = false, viewing = false, emergency_mode = false, kad_connected = false; std::uint32_t uptime_ms = 0, now_ms = 0, last_publish_time = 0, last_search_time = 0, last_result_time = 0, last_result_ip = 0, last_chunk_received_at = 0, hls_segments_written = 0, hls_playlist_refreshes = 0, kad_publishes = 0, kad_searches = 0, kad_results_accepted = 0, kad_results_rejected = 0, source_dial_attempts = 0, subscribe_sent = 0, subscribe_accepted = 0, chunks_requested = 0, chunks_received = 0, chunks_missing = 0, duplicate_chunks_received = 0, requests_suppressed_inflight = 0, peer_disconnects = 0, skipped_initial_pushes = 0, subscribes_rate_limited = 0, requests_rate_limited = 0, ends_rejected_no_auth = 0, tombstones_evicted = 0, oldest_sequence = 0, newest_sequence = 0; std::uint64_t total_redistributed = 0; std::uint16_t last_result_port = 0, chunk_bitmap = 0; std::int64_t known_streams = 0, known_streams_clean = 0, known_streams_legacy = 0, view_peers = 0, broadcast_peers = 0, mesh_peers = 0, pending_requests = 0, chunks_served = 0, super_seeders = 0, middle_peers = 0, leaf_peers = 0, chunk_count = 0, missing_chunks = 0, max_capacity = 15, segment_duration_seconds = 2; std::vector<W10DebugPeer> peer_detail; };
struct W10DiagnosticsResponse { std::string header, body; };
struct W10DiagnosticsPort {
	void* context = nullptr;
	bool (*read_krp_json)(void*, std::string&) = nullptr;
	bool (*read_preflight)(void*, W10PreflightSnapshot&) = nullptr;
	bool (*read_metrics)(void*, W10MetricsSnapshot&) = nullptr;
	void (*read_percentiles)(void*, std::uint32_t&, std::uint32_t&, std::uint32_t&) = nullptr;
	std::uint32_t (*read_latency_mean)(void*) = nullptr;
	int (*read_latency_samples)(void*) = nullptr;
	bool (*read_kad6_metrics)(void*, std::string&) = nullptr;
	bool (*read_log)(void*, int, std::vector<std::string>&) = nullptr;
	bool (*read_debug)(void*, W10DebugSnapshot&) = nullptr;
	bool (*run_ipv6_echo)(void*, const W10DiagnosticsRequest&, W10Ipv6EchoResult&) = nullptr;
	bool (*read_reach_json)(void*, std::string&) = nullptr;
};

bool RunW10LiveDiagnosticsApi(const W10DiagnosticsRequest&, const W10DiagnosticsPort&, W10DiagnosticsResponse&);
bool RunW10LiveDiagnosticsCharacterizationSelfTest(std::string& failure);

} } // namespace ese::web

namespace eSELive {
class WebLiveApiDiagnosticsController final { public: explicit WebLiveApiDiagnosticsController(const M2AParentPort& parent) noexcept; private: M2AParentPort m_parent; };
M2AModuleHandle M2A_BIND_W10_47570D3256(const M2AParentPort& parent);
void M2A_UNBIND_W10_47570D3256(const M2AParentPort& parent);
} // namespace eSELive
