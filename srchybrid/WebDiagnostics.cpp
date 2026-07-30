#include "WebDiagnostics.h"

#include <algorithm>

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

std::uint32_t Age(std::uint32_t now, std::uint32_t timestamp)
{
	return timestamp == 0u ? 0u : now - timestamp;
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

std::string WebDiagnostics::Serialize(
	const WebLiveDebugDiagnostics& model)
{
	if (!model.available) {
		return
			"{\"broadcasting\":false,\"viewing\":false,"
			"\"emergencyMode\":false,\"uptimeMs\":0,\"totalRedistributed\":0,"
			"\"discovery\":{\"kadConnected\":false,\"knownStreams\":0,"
			"\"knownStreamsClean\":0,\"knownStreamsLegacy\":0,"
			"\"lastPublishAgeMs\":0,\"lastSearchAgeMs\":0,\"lastResultAgeMs\":0,"
			"\"lastResultIP\":0,\"lastResultPort\":0},"
			"\"peers\":{\"viewPeers\":0,\"broadcastPeers\":0,\"meshPeers\":0,"
			"\"pendingRequests\":0,\"chunksServed\":0,"
			"\"trustLevels\":{\"superSeeders\":0,\"middle\":0,\"leaf\":0}},"
			"\"chunks\":{\"count\":0,\"oldestSeq\":0,\"newestSeq\":0,"
			"\"bitmap\":0,\"missing\":0,\"maxCapacity\":15},"
			"\"hls\":{\"segmentsWritten\":0,\"playlistRefreshes\":0,"
			"\"lastChunkAgeMs\":0,\"segmentDurationSec\":2},"
			"\"counters\":{\"kadPublishes\":0,\"kadSearches\":0,"
			"\"kadResultsAccepted\":0,\"kadResultsRejected\":0,"
			"\"sourceDialAttempts\":0,"
			"\"subscribeSent\":0,\"subscribeAccepted\":0,"
			"\"chunksRequested\":0,\"chunksReceived\":0,"
			"\"chunksMissing\":0,\"peerDisconnects\":0},"
			"\"source\":\"emule-core-debug\"}";
	}

	std::string output = "{\"broadcasting\":";
	output += JsonBool(model.broadcasting);
	output += ",\"viewing\":";
	output += JsonBool(model.viewing);
	output += ",\"emergencyMode\":";
	output += JsonBool(model.emergency_mode);
	output += ",\"uptimeMs\":";
	AppendNumber(output, model.uptime_ms);
	output += ",\"totalRedistributed\":";
	AppendNumber(output, model.total_redistributed);
	output += ",\"discovery\":{\"kadConnected\":";
	output += JsonBool(model.kad_connected);
	output += ",\"knownStreams\":";
	AppendNumber(output, model.known_streams);
	output += ",\"knownStreamsClean\":";
	AppendNumber(output, model.known_streams_clean);
	output += ",\"knownStreamsLegacy\":";
	AppendNumber(output, model.known_streams_legacy);
	output += ",\"lastPublishAgeMs\":";
	AppendNumber(output, Age(model.now_ms, model.last_publish_time));
	output += ",\"lastSearchAgeMs\":";
	AppendNumber(output, Age(model.now_ms, model.last_search_time));
	output += ",\"lastResultAgeMs\":";
	AppendNumber(output, Age(model.now_ms, model.last_result_time));
	output += ",\"lastResultIP\":";
	AppendNumber(output, model.last_result_ip);
	output += ",\"lastResultPort\":";
	AppendNumber(output, model.last_result_port);
	output += "},\"peers\":{\"viewPeers\":";
	AppendNumber(output, model.view_peers);
	output += ",\"broadcastPeers\":";
	AppendNumber(output, model.broadcast_peers);
	output += ",\"meshPeers\":";
	AppendNumber(output, model.mesh_peers);
	output += ",\"pendingRequests\":";
	AppendNumber(output, model.pending_requests);
	output += ",\"chunksServed\":";
	AppendNumber(output, model.chunks_served);
	output += ",\"trustLevels\":{\"superSeeders\":";
	AppendNumber(output, model.super_seeders);
	output += ",\"middle\":";
	AppendNumber(output, model.middle_peers);
	output += ",\"leaf\":";
	AppendNumber(output, model.leaf_peers);
	output += "}},\"chunks\":{\"count\":";
	AppendNumber(output, model.chunk_count);
	output += ",\"oldestSeq\":";
	AppendNumber(output, model.oldest_sequence);
	output += ",\"newestSeq\":";
	AppendNumber(output, model.newest_sequence);
	output += ",\"bitmap\":";
	AppendNumber(output, model.chunk_bitmap);
	output += ",\"missing\":";
	AppendNumber(output, model.missing_chunks);
	output += ",\"maxCapacity\":";
	AppendNumber(output, model.max_capacity);
	output += "},\"hls\":{\"segmentsWritten\":";
	AppendNumber(output, model.hls_segments_written);
	output += ",\"playlistRefreshes\":";
	AppendNumber(output, model.hls_playlist_refreshes);
	output += ",\"lastChunkAgeMs\":";
	AppendNumber(output, Age(model.now_ms, model.last_chunk_received_at));
	output += ",\"segmentDurationSec\":";
	AppendNumber(output, model.segment_duration_seconds);
	output += "},\"counters\":{\"kadPublishes\":";
	AppendNumber(output, model.kad_publishes);
	output += ",\"kadSearches\":";
	AppendNumber(output, model.kad_searches);
	output += ",\"kadResultsAccepted\":";
	AppendNumber(output, model.kad_results_accepted);
	output += ",\"kadResultsRejected\":";
	AppendNumber(output, model.kad_results_rejected);
	output += ",\"sourceDialAttempts\":";
	AppendNumber(output, model.source_dial_attempts);
	output += ",\"subscribeSent\":";
	AppendNumber(output, model.subscribe_sent);
	output += ",\"subscribeAccepted\":";
	AppendNumber(output, model.subscribe_accepted);
	output += ",\"chunksRequested\":";
	AppendNumber(output, model.chunks_requested);
	output += ",\"chunksReceived\":";
	AppendNumber(output, model.chunks_received);
	output += ",\"chunksMissing\":";
	AppendNumber(output, model.chunks_missing);
	output += ",\"duplicateChunksReceived\":";
	AppendNumber(output, model.duplicate_chunks_received);
	output += ",\"requestsSuppressedInflight\":";
	AppendNumber(output, model.requests_suppressed_inflight);
	output += ",\"peerDisconnects\":";
	AppendNumber(output, model.peer_disconnects);
	output += ",\"skippedInitialPushes\":";
	AppendNumber(output, model.skipped_initial_pushes);
	output += ",\"subscribesRateLimited\":";
	AppendNumber(output, model.subscribes_rate_limited);
	output += ",\"requestsRateLimited\":";
	AppendNumber(output, model.requests_rate_limited);
	output += ",\"endsRejectedNoAuth\":";
	AppendNumber(output, model.ends_rejected_no_auth);
	output += ",\"tombstonesEvicted\":";
	AppendNumber(output, model.tombstones_evicted);
	output += '}';

	const std::size_t peerCount =
		std::min(model.peer_detail.size(), MaxDebugPeers());
	if (peerCount != 0u) {
		output += ",\"peerDetail\":[";
		for (std::size_t index = 0; index < peerCount; ++index) {
			if (index != 0u)
				output += ',';
			const WebLiveDebugPeerDiagnostics& peer =
				model.peer_detail[index];
			output += "{\"ip\":";
			AppendQuoted(output, peer.ip);
			output += ",\"port\":";
			AppendNumber(output, peer.port);
			output += ",\"level\":";
			AppendNumber(output, peer.level);
			output += ",\"failCount\":";
			AppendNumber(output, peer.fail_count);
			output += ",\"respPct\":";
			AppendNumber(output, peer.response_percent);
			output += ",\"rttMs\":";
			AppendNumber(output, peer.rtt_ms);
			output += '}';
		}
		output += ']';
	}
	output += ",\"source\":\"emule-core-debug\"}";
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

	WebLiveDebugDiagnostics debug;
	debug.available = true;
	debug.now_ms = 5u;
	debug.last_publish_time = 0xfffffffdu;
	debug.peer_detail.resize(WebDiagnostics::MaxDebugPeers() + 1u);
	debug.peer_detail[0].ip = "bad\"\n";
	const std::string debugJson = WebDiagnostics::Serialize(debug);
	if (debugJson.find("\"lastPublishAgeMs\":8") == std::string::npos ||
		debugJson.find("\"ip\":\"bad\\\"\\n\"") == std::string::npos) {
		failure = "live diagnostics changed wrap-safe ages or escaping";
		return false;
	}
	std::size_t peers = 0u;
	for (std::size_t offset = 0u;
		(offset = debugJson.find("\"ip\":", offset)) != std::string::npos;
		offset += 5u) {
		++peers;
	}
	if (peers != WebDiagnostics::MaxDebugPeers()) {
		failure = "live diagnostics peer detail is not bounded";
		return false;
	}
	return true;
}

} // namespace web
} // namespace ese
