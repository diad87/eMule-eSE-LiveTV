#pragma once

#include <cstdint>
#include <string>

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

class WebDiagnostics final
{
public:
	static std::string Serialize(const WebNetworkStatusDiagnostics& model);
	static std::string Serialize(const WebLiveMeshDiagnostics& model);
};

bool RunWebDiagnosticsSelfTest(std::string& failure);

} // namespace web
} // namespace ese
