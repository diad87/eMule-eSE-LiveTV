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
	const std::string expectedStatus =
		"{\"upnp_critical_error\":true,"
		"\"utp_hole_punch_enabled\":false,\"web_upnp_active\":false,"
		"\"upnp_ports_forwarded\":\"unknown\",\"kad_connected\":false,"
		"\"kad_configured_mask\":3,\"kad_running_mask\":0,"
		"\"kad2_running\":false,\"kad2_connected\":false,"
		"\"kad6_running\":false,\"kad6_connected\":false,"
		"\"kad6_verified_contacts\":7,\"ed2k_connected\":false,"
		"\"user_hash\":\"0011\",\"connecting_client_count\":1,"
		"\"connecting_client_adds\":2,"
		"\"connecting_client_high_water\":3,"
		"\"connecting_client_duplicate_adds\":4,"
		"\"hole_punch_attempts\":5,\"hole_punch_success\":0,"
		"\"hole_punch_sym_nat_fail\":0,\"hole_punch_encrypted\":0,"
		"\"hole_punch_plaintext\":0,\"hole_punch_req_recv\":0,"
		"\"hole_punch_challenge_sent\":0,\"kad3_rdv_req_sent\":0,"
		"\"kad3_rdv_req_recv\":0,\"kad3_rdv_challenge_sent\":0,"
		"\"kad3_rdv_fwd\":0,\"kad3_rdv_success\":0,"
		"\"keepalive_running\":true,\"keepalive_pings_sent\":0,"
		"\"keepalive_pongs_recv\":0,\"keepalive_supernodes\":0,"
		"\"netlab_consent\":\"accepted\","
		"\"netlab_advanced_consent\":\"declined\","
		"\"netlab_contribution_consent\":\"undecided\","
		"\"netlab_enabled\":true}";
	Check(
		statusJson == expectedStatus,
		"local status response remains byte-exact");

	status.local.exposed = false;
	status.local.user_hash = "secret";
	const std::string remoteStatus = WebDiagnostics::Serialize(status);
	std::string expectedRemoteStatus = expectedStatus;
	const std::string localFields =
		"\"user_hash\":\"0011\",\"connecting_client_count\":1,"
		"\"connecting_client_adds\":2,"
		"\"connecting_client_high_water\":3,"
		"\"connecting_client_duplicate_adds\":4";
	const std::string remoteFields =
		"\"user_hash\":null,\"connecting_client_count\":null,"
		"\"connecting_client_adds\":null,"
		"\"connecting_client_high_water\":null,"
		"\"connecting_client_duplicate_adds\":null";
	const std::size_t localOffset = expectedRemoteStatus.find(localFields);
	Check(localOffset != std::string::npos, "status fixture is valid");
	if (localOffset != std::string::npos)
		expectedRemoteStatus.replace(
			localOffset, localFields.size(), remoteFields);
	Check(
		remoteStatus == expectedRemoteStatus &&
			remoteStatus.find("secret") == std::string::npos,
		"remote status privacy and nullability remain byte-exact");

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
		unavailableJson ==
			"{\"broadcasting\":false,\"viewing\":false,"
			"\"emergencyMode\":false,\"uptimeMs\":0,"
			"\"totalRedistributed\":0,"
			"\"discovery\":{\"kadConnected\":false,\"knownStreams\":0,"
			"\"knownStreamsClean\":0,\"knownStreamsLegacy\":0,"
			"\"lastPublishAgeMs\":0,\"lastSearchAgeMs\":0,"
			"\"lastResultAgeMs\":0,\"lastResultIP\":0,"
			"\"lastResultPort\":0},"
			"\"peers\":{\"viewPeers\":0,\"broadcastPeers\":0,"
			"\"meshPeers\":0,\"pendingRequests\":0,\"chunksServed\":0,"
			"\"trustLevels\":{\"superSeeders\":0,\"middle\":0,"
			"\"leaf\":0}},"
			"\"chunks\":{\"count\":0,\"oldestSeq\":0,\"newestSeq\":0,"
			"\"bitmap\":0,\"missing\":0,\"maxCapacity\":15},"
			"\"hls\":{\"segmentsWritten\":0,\"playlistRefreshes\":0,"
			"\"lastChunkAgeMs\":0,\"segmentDurationSec\":2},"
			"\"counters\":{\"kadPublishes\":0,\"kadSearches\":0,"
			"\"kadResultsAccepted\":0,\"kadResultsRejected\":0,"
			"\"sourceDialAttempts\":0,\"subscribeSent\":0,"
			"\"subscribeAccepted\":0,\"chunksRequested\":0,"
			"\"chunksReceived\":0,\"chunksMissing\":0,"
			"\"peerDisconnects\":0},"
			"\"source\":\"emule-core-debug\"}",
		"unavailable debug response remains byte-exact");

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
		debugJson ==
			"{\"broadcasting\":true,\"viewing\":true,"
			"\"emergencyMode\":true,\"uptimeMs\":9,"
			"\"totalRedistributed\":10,"
			"\"discovery\":{\"kadConnected\":false,\"knownStreams\":0,"
			"\"knownStreamsClean\":0,\"knownStreamsLegacy\":0,"
			"\"lastPublishAgeMs\":7,\"lastSearchAgeMs\":2,"
			"\"lastResultAgeMs\":0,\"lastResultIP\":0,"
			"\"lastResultPort\":4662},"
			"\"peers\":{\"viewPeers\":0,\"broadcastPeers\":0,"
			"\"meshPeers\":0,\"pendingRequests\":0,\"chunksServed\":0,"
			"\"trustLevels\":{\"superSeeders\":0,\"middle\":0,"
			"\"leaf\":0}},"
			"\"chunks\":{\"count\":0,\"oldestSeq\":0,\"newestSeq\":0,"
			"\"bitmap\":0,\"missing\":0,\"maxCapacity\":15},"
			"\"hls\":{\"segmentsWritten\":0,\"playlistRefreshes\":0,"
			"\"lastChunkAgeMs\":1,\"segmentDurationSec\":2},"
			"\"counters\":{\"kadPublishes\":11,\"kadSearches\":0,"
			"\"kadResultsAccepted\":0,\"kadResultsRejected\":0,"
			"\"sourceDialAttempts\":0,\"subscribeSent\":0,"
			"\"subscribeAccepted\":0,\"chunksRequested\":0,"
			"\"chunksReceived\":0,\"chunksMissing\":0,"
			"\"duplicateChunksReceived\":0,"
			"\"requestsSuppressedInflight\":0,\"peerDisconnects\":0,"
			"\"skippedInitialPushes\":0,\"subscribesRateLimited\":0,"
			"\"requestsRateLimited\":0,\"endsRejectedNoAuth\":0,"
			"\"tombstonesEvicted\":12},"
			"\"peerDetail\":[{\"ip\":\"2001:db8::1\\\"\\n\","
			"\"port\":13,\"level\":1,\"failCount\":2,\"respPct\":99,"
			"\"rttMs\":14}],\"source\":\"emule-core-debug\"}",
		"available debug response remains byte-exact");

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
