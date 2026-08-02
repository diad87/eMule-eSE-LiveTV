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

	std::string failure;
	Check(
		ese::web::RunWebDiagnosticsSelfTest(failure),
		failure.empty() ? "embedded diagnostics selftest" : failure.c_str());

	if (failures != 0)
		return 1;
	std::cout << "web diagnostics tests: PASS\n";
	return 0;
}
