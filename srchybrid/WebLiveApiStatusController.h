#pragma once

#include "M2ABindingPort.h"
#include <array>
#include <cstdint>
#include <string>

namespace ese { namespace web {

// Portable W8 boundary: the web host supplies snapshots through these ports.
enum class W8LiveStatusOperation { Status, Channels, Mesh };

struct W8LiveStatusSnapshot {
	bool upnp_critical_error = false, utp_hole_punch_enabled = false, web_upnp_active = false;
	std::string upnp_ports_forwarded = "unknown";
	bool kad_connected = false, kad2_running = false, kad2_connected = false;
	bool kad6_running = false, kad6_connected = false, ed2k_connected = false;
	std::uint32_t kad_configured_mask = 0, kad_running_mask = 0, kad6_verified_contacts = 0;
	std::string user_hash;
	std::int64_t connecting_client_count = 0, connecting_client_adds = 0;
	std::int64_t connecting_client_high_water = 0, connecting_client_duplicate_adds = 0;
	std::uint32_t hole_punch_attempts = 0, hole_punch_success = 0, hole_punch_sym_nat_fail = 0;
	std::uint32_t hole_punch_encrypted = 0, hole_punch_plaintext = 0, hole_punch_req_recv = 0;
	std::uint32_t hole_punch_challenge_sent = 0, kad3_rdv_req_sent = 0, kad3_rdv_req_recv = 0;
	std::uint32_t kad3_rdv_challenge_sent = 0, kad3_rdv_fwd = 0, kad3_rdv_success = 0;
	bool keepalive_running = false;
	std::uint32_t keepalive_pings_sent = 0, keepalive_pongs_recv = 0, keepalive_supernodes = 0;
	std::string netlab_consent = "undecided", netlab_advanced_consent = "undecided";
	std::string netlab_contribution_consent = "undecided";
	bool netlab_enabled = false;
};

struct W8LiveChannelSnapshot {
	bool broadcasting = false;
	std::array<std::uint8_t, 16> stream_key{};
	std::string title, category, language;
	std::uint32_t started_at = 0, viewer_count = 0, bitrate = 0;
};

struct W8LiveMeshSnapshot {
	std::int64_t mesh_peers = 0, pending_requests = 0, chunks_served = 0;
	std::uint64_t total_redistributed = 0;
	std::int64_t super_seeders = 0, middle_peers = 0, leaf_peers = 0;
	std::uint32_t upload_floor = 0;
	bool emergency_mode = false;
};

struct W8LiveStatusPort {
	void* context = nullptr;
	bool (*read_status)(void*, W8LiveStatusSnapshot&) = nullptr;
	bool (*read_channel)(void*, W8LiveChannelSnapshot&) = nullptr;
	bool (*read_mesh)(void*, W8LiveMeshSnapshot&) = nullptr;
};

struct W8LiveStatusResponse { std::string header; std::string body; };

bool RunW8LiveStatusApi(W8LiveStatusOperation operation, bool loopback,
	const W8LiveStatusPort& port, W8LiveStatusResponse& response);
bool RunW8LiveStatusCharacterizationSelfTest(std::string& failure);

} } // namespace ese::web

namespace eSELive {

class WebLiveApiStatusController {
public:
	explicit WebLiveApiStatusController(const M2AParentPort& parent);
private:
	M2AParentPort m_parent;
};

M2AModuleHandle M2A_BIND_W8_E988965D5A(const M2AParentPort& parent);
void M2A_UNBIND_W8_E988965D5A(const M2AParentPort& parent);

} // namespace eSELive
