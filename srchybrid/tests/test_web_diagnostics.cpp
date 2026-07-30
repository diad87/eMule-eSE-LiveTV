#include "../WebDiagnostics.h"

#include <iostream>
#include <string>

namespace {

int failures = 0;

void Check(bool condition, const char* message)
{
	if (!condition) {
		std::cerr << "FAIL: " << message << '\n';
		++failures;
	}
}

} // namespace

int main()
{
	using ese::web::WebDiagnostics;
	using ese::web::WebLiveDebugDiagnostics;
	using ese::web::WebLiveDebugPeerDiagnostics;
	using ese::web::WebLiveMeshDiagnostics;
	using ese::web::WebNetworkStatusDiagnostics;

	WebNetworkStatusDiagnostics status;
	status.upnp_critical_error = true;
	status.upnp_ports_forwarded = "unknown";
	status.kad_configured_mask = 3;
	status.kad6_verified_contacts = 7;
	status.local.exposed = true;
	status.local.user_hash = "0011";
	status.local.connecting_client_count = 1;
	status.local.connecting_client_adds = 2;
	status.local.connecting_client_high_water = 3;
	status.local.connecting_client_duplicate_adds = 4;
	status.hole_punch_attempts = 5;
	status.keepalive_running = true;
	status.netlab_consent = "accepted";
	status.netlab_advanced_consent = "declined";
	status.netlab_contribution_consent = "undecided";
	status.netlab_enabled = true;
	const std::string statusJson = WebDiagnostics::Serialize(status);
	Check(
		statusJson.find(
			"\"user_hash\":\"0011\",\"connecting_client_count\":1,"
			"\"connecting_client_adds\":2,"
			"\"connecting_client_high_water\":3,"
			"\"connecting_client_duplicate_adds\":4") !=
			std::string::npos,
		"local status projection");
	Check(
		statusJson.find("\"hole_punch_attempts\":5") != std::string::npos &&
			statusJson.find("\"keepalive_running\":true") !=
				std::string::npos &&
			statusJson.find("\"netlab_enabled\":true}") != std::string::npos,
		"status counters and consent");

	status.local.exposed = false;
	status.local.user_hash = "secret";
	const std::string remoteStatus = WebDiagnostics::Serialize(status);
	Check(
		remoteStatus.find("secret") == std::string::npos &&
			remoteStatus.find(
				"\"user_hash\":null,\"connecting_client_count\":null,"
				"\"connecting_client_adds\":null,"
				"\"connecting_client_high_water\":null,"
				"\"connecting_client_duplicate_adds\":null") !=
				std::string::npos,
		"remote status privacy is fail-closed");

	WebLiveMeshDiagnostics mesh;
	mesh.mesh_peers = 1;
	mesh.pending_requests = 2;
	mesh.chunks_served = 3;
	mesh.total_redistributed = 4;
	mesh.super_seeders = 5;
	mesh.middle_peers = 6;
	mesh.leaf_peers = 7;
	mesh.upload_floor = 8;
	mesh.emergency_mode = true;
	Check(
		WebDiagnostics::Serialize(mesh) ==
			"{\"meshPeers\":1,\"pendingRequests\":2,\"chunksServed\":3,"
			"\"totalRedistributed\":4,"
			"\"trustLevels\":{\"superSeeders\":5,\"middle\":6,\"leaf\":7},"
			"\"uploadFloor\":8,\"emergencyMode\":true,"
			"\"source\":\"emule-core\"}",
		"mesh response remains exact");

	WebLiveDebugDiagnostics unavailable;
	const std::string unavailableJson =
		WebDiagnostics::Serialize(unavailable);
	Check(
		unavailableJson.rfind("{\"broadcasting\":false", 0) == 0 &&
			unavailableJson.find("\"maxCapacity\":15") !=
				std::string::npos &&
			unavailableJson.find("\"segmentDurationSec\":2") !=
				std::string::npos,
		"unavailable debug response remains compatible");

	WebLiveDebugDiagnostics debug;
	debug.available = true;
	debug.broadcasting = true;
	debug.viewing = true;
	debug.emergency_mode = true;
	debug.uptime_ms = 9;
	debug.total_redistributed = 10;
	debug.now_ms = 4;
	debug.last_publish_time = 0xfffffffdu;
	debug.last_search_time = 2;
	debug.last_result_time = 0;
	debug.last_result_port = 4662;
	debug.max_capacity = 15;
	debug.segment_duration_seconds = 2;
	debug.last_chunk_received_at = 3;
	debug.kad_publishes = 11;
	debug.tombstones_evicted = 12;
	debug.peer_detail.push_back(WebLiveDebugPeerDiagnostics{
		"2001:db8::1\"\n", 13, 1, 2, 99, 14});
	const std::string debugJson = WebDiagnostics::Serialize(debug);
	Check(
		debugJson.find(
			"\"lastPublishAgeMs\":7,\"lastSearchAgeMs\":2,"
			"\"lastResultAgeMs\":0") != std::string::npos,
		"debug ages preserve 32-bit tick wrap");
	Check(
		debugJson.find(
			"\"lastChunkAgeMs\":1,\"segmentDurationSec\":2") !=
			std::string::npos,
		"debug HLS age");
	Check(
		debugJson.find(
			"\"ip\":\"2001:db8::1\\\"\\n\",\"port\":13") !=
			std::string::npos,
		"debug peer text is escaped");
	Check(
		debugJson.find("\"tombstonesEvicted\":12}") !=
			std::string::npos &&
			debugJson.find("\"source\":\"emule-core-debug\"}") !=
				std::string::npos,
		"debug counters and source");

	debug.peer_detail.assign(
		WebDiagnostics::MaxDebugPeers() + 5u,
		WebLiveDebugPeerDiagnostics{});
	const std::string bounded = WebDiagnostics::Serialize(debug);
	std::size_t peerCount = 0;
	for (std::size_t offset = 0;
		(offset = bounded.find("\"ip\":", offset)) != std::string::npos;
		offset += 5) {
		++peerCount;
	}
	Check(
		peerCount == WebDiagnostics::MaxDebugPeers(),
		"debug peer detail is capped");

	std::string failure;
	Check(
		ese::web::RunWebDiagnosticsSelfTest(failure),
		failure.empty() ? "embedded diagnostics selftest" : failure.c_str());

	if (failures != 0)
		return 1;
	std::cout << "web diagnostics tests: PASS\n";
	return 0;
}
