#pragma once

#include "M2ABindingPort.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace ese { namespace web {

// W11 deliberately transports values only. Authentication, sockets, GUI and
// concrete Kad types remain on the WebServer adapter side of this boundary.
enum class W11LegacyOperation { Hls, Dashboard, NetlabReport, TunnelEcho, TunnelPing, Circuits, Peers, TestCircuit, Kad6Release, Kad6Hardening, LiveIndex, LivePlayer };
struct W11LegacyRequest { W11LegacyOperation operation = W11LegacyOperation::Dashboard; bool loopback = false; std::string resource, range, bytes, text, hops, service, enabled, challenge, confirm, field_sha256, audit_sha256, observed_from, observed_to, admission_attempts, admission_ppm, headroom_bps, gate_mask, valid_until, drain_seconds; };
struct W11LegacyResponse { std::string header, body; std::string file_path, file_name, public_path, file_range, etag, last_modified, cors_origin; std::uint64_t maximum_bytes = 0; bool file_response = false, hls = false, cors_wildcard = false, concurrent = false, allow_empty = false; };
struct W11HlsSnapshot { std::string root_path, viewer_key; bool root_exists = false; };
struct W11StaticFileRequest { std::string web_root, url, public_path, range, etag, last_modified; std::uint64_t maximum_bytes = 0; };
struct W11NetlabReportSnapshot { std::string version, consent; bool enabled = false, has_ipv4 = false, has_ipv6 = false, firewalled = false, kad_connected = false, keepalive_running = false, utp_connected = false; std::uint32_t hole_attempts = 0, hole_success = 0, hole_sym_nat_fail = 0, hole_spray = 0, kad3_requests = 0, kad3_forwarded = 0, kad3_success = 0, keepalive_pings = 0, keepalive_pongs = 0, keepalive_peers = 0, utp_sockets = 0, relay_kb = 0; std::uint64_t session_received = 0, session_sent = 0; };
struct W11CircuitSnapshot { std::uint32_t circ_id = 0, age_ms = 0, next_circ_id = 0; std::uint16_t hop_count = 0; unsigned role = 0, state = 0, abort_reason = 0; bool next_hop_set = false, auth_ok = false, strict3 = false, shaped = false, shaping_exposed = false; };
struct W11PeerSnapshot { std::string ip, address; std::uint16_t port = 0; std::uint32_t fork_caps = 0, ese_caps = 0; bool auth_ready = false, hash_ready = false, node_pub_ready = false, auth_cap = false, dataplane_cap = false; };
struct W11ReleaseEvidence { std::string field_sha256, audit_sha256; std::uint64_t observed_from = 0, observed_to = 0, admission_attempts = 0, headroom_bps = 0, valid_until = 0; std::uint32_t admission_ppm = 0; std::uint16_t gate_mask = 0; };
struct W11ReleaseSnapshot { std::string status, challenge; bool operator_opt_in = false, evidence_present = false, evidence_valid = false, runtime_healthy = false; bool public_exit_enabled = false, beta_exit_opt_in = false, beta_exit_enabled = false; W11ReleaseEvidence evidence; };
struct W11HardeningServiceSnapshot { std::string service, state; std::uint64_t changed_at = 0, drain_deadline = 0; bool admitting = false; };
struct W11HardeningEconomySnapshot { std::string service; bool rho_present = false, sealed = false; double rho = 0.0, admission_ratio = 0.0, rho_p50 = 0.0, rho_p95 = 0.0; std::uint64_t starts_at = 0, ends_at = 0, samples = 0, admission_attempts = 0, admission_successes = 0; };
struct W11HardeningSnapshot { std::uint64_t revision = 0, active_leases = 0, active_publishes = 0, dial_streams = 0, full_streams = 0, shaping_exposed_circuits = 0, origin_advertise_success_total = 0, origin_source_recovered_total = 0; bool source_epoch_store_failed = false, metrics_ready = false, economy_measurement_ready = false, strict_recommended = false; std::uint64_t metrics_start = 0, metrics_end = 0; std::uint32_t metrics_fixed_series = 0, metrics_exported_series = 0; bool exit_notice_running = false; std::uint16_t exit_notice_port = 0; std::uint64_t exit_notice_requests = 0, exit_notice_rejected = 0, exit_notice_bytes_sent = 0; std::vector<W11HardeningServiceSnapshot> services; std::vector<W11HardeningEconomySnapshot> economy; };
struct W11LegacyPort { void* context = nullptr; bool (*resolve_hls)(void*, const W11LegacyRequest&, W11HlsSnapshot&) = nullptr; void (*note_player_fetch)(void*) = nullptr; bool (*read_netlab_report)(void*, W11NetlabReportSnapshot&) = nullptr; bool (*run_tunnel_echo)(void*, const std::vector<std::uint8_t>&, std::vector<std::uint8_t>&) = nullptr; bool (*run_tunnel_ping)(void*, const std::string&, std::string&) = nullptr; bool (*read_circuits)(void*, std::vector<W11CircuitSnapshot>&) = nullptr; bool (*read_peers)(void*, std::vector<W11PeerSnapshot>&, std::size_t&) = nullptr; bool (*request_test_circuit)(void*, unsigned, std::uint32_t&) = nullptr; bool (*consume_release_challenge)(void*, const std::string&) = nullptr; bool (*request_release)(void*, bool, const W11ReleaseEvidence*, std::uint32_t) = nullptr; bool (*read_release)(void*, bool, W11ReleaseSnapshot&) = nullptr; bool (*request_hardening)(void*, const std::string&, bool, std::uint32_t) = nullptr; bool (*read_hardening)(void*, W11HardeningSnapshot&) = nullptr; };

bool RunW11LiveLegacyApi(const W11LegacyRequest&, const W11LegacyPort&, W11LegacyResponse&);
bool BuildW11LegacyStaticFile(const W11StaticFileRequest&, W11LegacyResponse&);
bool RunW11LiveLegacyCharacterizationSelfTest(std::string& failure);

} } // namespace ese::web

namespace eSELive {
class WebLiveApiLegacyController final {
public:
	explicit WebLiveApiLegacyController(const M2AParentPort& parent) noexcept;
private:
	M2AParentPort m_parent;
};
M2AModuleHandle M2A_BIND_W11_55908BF94D(const M2AParentPort& parent);
void M2A_UNBIND_W11_55908BF94D(const M2AParentPort& parent);
} // namespace eSELive
