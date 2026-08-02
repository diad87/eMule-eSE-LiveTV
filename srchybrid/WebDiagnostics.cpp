#include "WebDiagnostics.h"

namespace ese {
namespace web {
namespace {

const char* JsonBool(bool value)
{
	return value ? "true" : "false";
}

void AppendQuoted(std::string& output, const std::string& value)
{
	static const char kHex[] = "0123456789abcdef";
	output += '"';
	for (const unsigned char byte : value) {
		switch (byte) {
		case '"': output += "\\\""; break;
		case '\\': output += "\\\\"; break;
		case '\b': output += "\\b"; break;
		case '\f': output += "\\f"; break;
		case '\n': output += "\\n"; break;
		case '\r': output += "\\r"; break;
		case '\t': output += "\\t"; break;
		default:
			if (byte < 0x20u) {
				output += "\\u00";
				output += kHex[(byte >> 4u) & 0x0fu];
				output += kHex[byte & 0x0fu];
			} else {
				output += static_cast<char>(byte);
			}
			break;
		}
	}
	output += '"';
}

template <typename Integer>
void AppendNumber(std::string& output, Integer value)
{
	output += std::to_string(value);
}

void AppendLocal(
	std::string& output,
	const WebLocalConnectionDiagnostics& local)
{
	output += "\"user_hash\":";
	if (local.exposed)
		AppendQuoted(output, local.user_hash);
	else
		output += "null";
	output += ",\"connecting_client_count\":";
	if (local.exposed)
		AppendNumber(output, local.connecting_client_count);
	else
		output += "null";
	output += ",\"connecting_client_adds\":";
	if (local.exposed)
		AppendNumber(output, local.connecting_client_adds);
	else
		output += "null";
	output += ",\"connecting_client_high_water\":";
	if (local.exposed)
		AppendNumber(output, local.connecting_client_high_water);
	else
		output += "null";
	output += ",\"connecting_client_duplicate_adds\":";
	if (local.exposed)
		AppendNumber(output, local.connecting_client_duplicate_adds);
	else
		output += "null";
	output += ',';
}

} // namespace

std::string WebDiagnostics::Serialize(
	const WebNetworkStatusDiagnostics& model)
{
	std::string output = "{\"upnp_critical_error\":";
	output += JsonBool(model.upnp_critical_error);
	output += ",\"utp_hole_punch_enabled\":";
	output += JsonBool(model.utp_hole_punch_enabled);
	output += ",\"web_upnp_active\":";
	output += JsonBool(model.web_upnp_active);
	output += ",\"upnp_ports_forwarded\":";
	AppendQuoted(output, model.upnp_ports_forwarded);
	output += ",\"kad_connected\":";
	output += JsonBool(model.kad_connected);
	output += ",\"kad_configured_mask\":";
	AppendNumber(output, model.kad_configured_mask);
	output += ",\"kad_running_mask\":";
	AppendNumber(output, model.kad_running_mask);
	output += ",\"kad2_running\":";
	output += JsonBool(model.kad2_running);
	output += ",\"kad2_connected\":";
	output += JsonBool(model.kad2_connected);
	output += ",\"kad6_running\":";
	output += JsonBool(model.kad6_running);
	output += ",\"kad6_connected\":";
	output += JsonBool(model.kad6_connected);
	output += ",\"kad6_verified_contacts\":";
	AppendNumber(output, model.kad6_verified_contacts);
	output += ",\"ed2k_connected\":";
	output += JsonBool(model.ed2k_connected);
	output += ',';
	AppendLocal(output, model.local);
	output += "\"hole_punch_attempts\":";
	AppendNumber(output, model.hole_punch_attempts);
	output += ",\"hole_punch_success\":";
	AppendNumber(output, model.hole_punch_success);
	output += ",\"hole_punch_sym_nat_fail\":";
	AppendNumber(output, model.hole_punch_sym_nat_fail);
	output += ",\"hole_punch_encrypted\":";
	AppendNumber(output, model.hole_punch_encrypted);
	output += ",\"hole_punch_plaintext\":";
	AppendNumber(output, model.hole_punch_plaintext);
	output += ",\"hole_punch_req_recv\":";
	AppendNumber(output, model.hole_punch_req_recv);
	output += ",\"hole_punch_challenge_sent\":";
	AppendNumber(output, model.hole_punch_challenge_sent);
	output += ",\"kad3_rdv_req_sent\":";
	AppendNumber(output, model.kad3_rdv_req_sent);
	output += ",\"kad3_rdv_req_recv\":";
	AppendNumber(output, model.kad3_rdv_req_recv);
	output += ",\"kad3_rdv_challenge_sent\":";
	AppendNumber(output, model.kad3_rdv_challenge_sent);
	output += ",\"kad3_rdv_fwd\":";
	AppendNumber(output, model.kad3_rdv_fwd);
	output += ",\"kad3_rdv_success\":";
	AppendNumber(output, model.kad3_rdv_success);
	output += ",\"keepalive_running\":";
	output += JsonBool(model.keepalive_running);
	output += ",\"keepalive_pings_sent\":";
	AppendNumber(output, model.keepalive_pings_sent);
	output += ",\"keepalive_pongs_recv\":";
	AppendNumber(output, model.keepalive_pongs_recv);
	output += ",\"keepalive_supernodes\":";
	AppendNumber(output, model.keepalive_supernodes);
	output += ",\"netlab_consent\":";
	AppendQuoted(output, model.netlab_consent);
	output += ",\"netlab_advanced_consent\":";
	AppendQuoted(output, model.netlab_advanced_consent);
	output += ",\"netlab_contribution_consent\":";
	AppendQuoted(output, model.netlab_contribution_consent);
	output += ",\"netlab_enabled\":";
	output += JsonBool(model.netlab_enabled);
	output += '}';
	return output;
}

std::string WebDiagnostics::Serialize(
	const WebLiveMeshDiagnostics& model)
{
	std::string output = "{\"meshPeers\":";
	AppendNumber(output, model.mesh_peers);
	output += ",\"pendingRequests\":";
	AppendNumber(output, model.pending_requests);
	output += ",\"chunksServed\":";
	AppendNumber(output, model.chunks_served);
	output += ",\"totalRedistributed\":";
	AppendNumber(output, model.total_redistributed);
	output += ",\"trustLevels\":{\"superSeeders\":";
	AppendNumber(output, model.super_seeders);
	output += ",\"middle\":";
	AppendNumber(output, model.middle_peers);
	output += ",\"leaf\":";
	AppendNumber(output, model.leaf_peers);
	output += "},\"uploadFloor\":";
	AppendNumber(output, model.upload_floor);
	output += ",\"emergencyMode\":";
	output += JsonBool(model.emergency_mode);
	output += ",\"source\":\"emule-core\"}";
	return output;
}

bool RunWebDiagnosticsSelfTest(std::string& failure)
{
	failure.clear();
	WebNetworkStatusDiagnostics status;
	status.local.exposed = false;
	status.local.user_hash = "must-not-leak";
	const std::string remote = WebDiagnostics::Serialize(status);
	if (remote.find("must-not-leak") != std::string::npos ||
		remote.find("\"user_hash\":null") == std::string::npos) {
		failure = "remote diagnostics disclosed local identity";
		return false;
	}

	status.local.exposed = true;
	status.local.user_hash = "bad\"\n";
	const std::string local = WebDiagnostics::Serialize(status);
	if (local.find("\"user_hash\":\"bad\\\"\\n\"") ==
		std::string::npos) {
		failure = "local diagnostics changed JSON escaping";
		return false;
	}

	return true;
}

} // namespace web
} // namespace ese
