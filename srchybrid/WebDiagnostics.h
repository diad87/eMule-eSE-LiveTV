#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace ese {
namespace web {

struct WebLocalConnectionDiagnostics {
	bool exposed = false;
	std::string user_hash;
	std::int64_t connecting_client_count = 0;
	std::int64_t connecting_client_adds = 0;
	std::int64_t connecting_client_high_water = 0;
	std::int64_t connecting_client_duplicate_adds = 0;
};

struct WebNetworkStatusDiagnostics {
	bool upnp_critical_error = false;
	bool utp_hole_punch_enabled = false;
	bool web_upnp_active = false;
	std::string upnp_ports_forwarded = "unknown";
	bool kad_connected = false;
	std::uint32_t kad_configured_mask = 0;
	std::uint32_t kad_running_mask = 0;
	bool kad2_running = false;
	bool kad2_connected = false;
	bool kad6_running = false;
	bool kad6_connected = false;
	std::uint32_t kad6_verified_contacts = 0;
	bool ed2k_connected = false;
	WebLocalConnectionDiagnostics local;
	std::uint32_t hole_punch_attempts = 0;
	std::uint32_t hole_punch_success = 0;
	std::uint32_t hole_punch_sym_nat_fail = 0;
	std::uint32_t hole_punch_encrypted = 0;
	std::uint32_t hole_punch_plaintext = 0;
	std::uint32_t hole_punch_req_recv = 0;
	std::uint32_t hole_punch_challenge_sent = 0;
	std::uint32_t kad3_rdv_req_sent = 0;
	std::uint32_t kad3_rdv_req_recv = 0;
	std::uint32_t kad3_rdv_challenge_sent = 0;
	std::uint32_t kad3_rdv_fwd = 0;
	std::uint32_t kad3_rdv_success = 0;
	bool keepalive_running = false;
	std::uint32_t keepalive_pings_sent = 0;
	std::uint32_t keepalive_pongs_recv = 0;
	std::uint32_t keepalive_supernodes = 0;
	std::string netlab_consent = "undecided";
	std::string netlab_advanced_consent = "undecided";
	std::string netlab_contribution_consent = "undecided";
	bool netlab_enabled = false;
};

struct WebLiveMeshDiagnostics {
	std::int64_t mesh_peers = 0;
	std::int64_t pending_requests = 0;
	std::int64_t chunks_served = 0;
	std::uint64_t total_redistributed = 0;
	std::int64_t super_seeders = 0;
	std::int64_t middle_peers = 0;
	std::int64_t leaf_peers = 0;
	std::uint32_t upload_floor = 0;
	bool emergency_mode = false;
};

struct WebLiveDebugPeerDiagnostics {
	std::string ip;
	std::uint16_t port = 0;
	std::int64_t level = 0;
	std::int64_t fail_count = 0;
	std::int64_t response_percent = 0;
	std::uint32_t rtt_ms = 0;
};

struct WebLiveDebugDiagnostics {
	bool available = false;
	bool broadcasting = false;
	bool viewing = false;
	bool emergency_mode = false;
	std::uint32_t uptime_ms = 0;
	std::uint64_t total_redistributed = 0;
	std::uint32_t now_ms = 0;

	bool kad_connected = false;
	std::int64_t known_streams = 0;
	std::int64_t known_streams_clean = 0;
	std::int64_t known_streams_legacy = 0;
	std::uint32_t last_publish_time = 0;
	std::uint32_t last_search_time = 0;
	std::uint32_t last_result_time = 0;
	std::uint32_t last_result_ip = 0;
	std::uint16_t last_result_port = 0;

	std::int64_t view_peers = 0;
	std::int64_t broadcast_peers = 0;
	std::int64_t mesh_peers = 0;
	std::int64_t pending_requests = 0;
	std::int64_t chunks_served = 0;
	std::int64_t super_seeders = 0;
	std::int64_t middle_peers = 0;
	std::int64_t leaf_peers = 0;

	std::int64_t chunk_count = 0;
	std::uint32_t oldest_sequence = 0;
	std::uint32_t newest_sequence = 0;
	std::uint16_t chunk_bitmap = 0;
	std::int64_t missing_chunks = 0;
	std::int64_t max_capacity = 15;

	std::uint32_t hls_segments_written = 0;
	std::uint32_t hls_playlist_refreshes = 0;
	std::uint32_t last_chunk_received_at = 0;
	std::int64_t segment_duration_seconds = 2;

	std::uint32_t kad_publishes = 0;
	std::uint32_t kad_searches = 0;
	std::uint32_t kad_results_accepted = 0;
	std::uint32_t kad_results_rejected = 0;
	std::uint32_t source_dial_attempts = 0;
	std::uint32_t subscribe_sent = 0;
	std::uint32_t subscribe_accepted = 0;
	std::uint32_t chunks_requested = 0;
	std::uint32_t chunks_received = 0;
	std::uint32_t chunks_missing = 0;
	std::uint32_t duplicate_chunks_received = 0;
	std::uint32_t requests_suppressed_inflight = 0;
	std::uint32_t peer_disconnects = 0;
	std::uint32_t skipped_initial_pushes = 0;
	std::uint32_t subscribes_rate_limited = 0;
	std::uint32_t requests_rate_limited = 0;
	std::uint32_t ends_rejected_no_auth = 0;
	std::uint32_t tombstones_evicted = 0;
	std::vector<WebLiveDebugPeerDiagnostics> peer_detail;
};

class WebDiagnostics final
{
public:
	static constexpr std::size_t MaxDebugPeers()
	{
		return 16u;
	}

	static std::string Serialize(const WebNetworkStatusDiagnostics& model);
	static std::string Serialize(const WebLiveMeshDiagnostics& model);
	static std::string Serialize(const WebLiveDebugDiagnostics& model);
};

bool RunWebDiagnosticsSelfTest(std::string& failure);

} // namespace web
} // namespace ese
