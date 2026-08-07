#include "stdafx.h"
#ifdef K
#undef K
#endif
#include <locale.h>
#include <algorithm>
#include <cmath>
#include <vector>
#include "emule.h"
#include "StringConversion.h"
#include "OtherFunctions.h"
#include "WebApiSerializer.h"
#include "WebDiagnostics.h"
#include "WebHlsCapabilityController.h"
#include "WebServerFacade.h"
#include "M2ABindingPort.h"
#include "WebRequestParser.h"
#include "WebRouteTable.h"
#include "WebSearchController.h"
#include "WebSharedController.h"
#include "WebStaticAssets.h"
#include "WebTransferController.h"
#include "WebServer.h"
#include "ClientCredits.h"
#include "ClientList.h"
#include "DownloadQueue.h"
#include "ED2KLink.h"
#include "emuledlg.h"
#include "FriendList.h"
#include "ini2.h"
#include "Kademlia/Kademlia/Kademlia.h"
#include "Kademlia/Kademlia/UDPFirewallTester.h"
#include "Kademlia/net/KademliaUDPListener.h"
#include "Kademlia/Kademlia/KadV2Defines.h"     // F5: privacy endpoint
#include "Kademlia/Kademlia/KadV2ModeSelector.h"
// v0.71 P1.1 — runtime visibility headers for /api/live/privacy. We expose
// what the privacy stack is ACTUALLY doing so the user (and any external
// monitoring) can verify the modules are alive vs. dormant.
#include "Kademlia/Kademlia/KadV2TunnelPool.h"
#include "LiveTunnel.h"
#include "LiveSubscriptionStore.h"
#include "FirewallProberV6.h"
#include "ClientUDPSocket.h"
#include "eMuleAI/UtpSocket.h"
#include "Opcodes.h"   // g_uEseCapsRuntime extern
#include "KademliaWnd.h"
#include "KadSearchListCtrl.h"
#include "kademlia/kademlia/Entry.h"
#include "KnownFileList.h"
#include "ListenSocket.h"
#include "LiveStreamManager.h"
#include "LiveDebugLog.h"
#include "RTMPIngest.h"
#include <deque>
#include "Log.h"
#include "MenuCmds.h"
#include "Preferences.h"
#include "Server.h"
#include "ServerList.h"
#include "ServerWnd.h"
#include "SearchList.h"
#include "SearchDlg.h"
#include "SearchParams.h"
#include "SharedFileList.h"
#include "ServerConnect.h"
#include "StatisticsDlg.h"
#include "Opcodes.h"
#include "Statistics.h"
#include "KadKeepalive.h"      // R.2: keepalive control + stats for /api/keepalive and /api/status
#include "LiveBuddyRelay.h"    // R.3: relay accept/egress/viewer-connect for /api/relay/*
#include "RelayClient.h"       // P3: read-only KRP state cache; no worker-thread eMule access
#include "DirectReachabilityManager.h"
#include "QArray.h"
#include "TransferDlg.h"
#include "UploadQueue.h"
#include "UpDownClient.h"
#include "UPnPImpl.h"
#include "UPnPImplWrapper.h"
#include "UserMsgs.h"

using namespace eSELive;

namespace {

bool EseI08WaitWritable(SOCKET socketValue, DWORD timeoutMs, int& errorCode)
{
	fd_set writable;
	fd_set exceptional;
	FD_ZERO(&writable);
	FD_ZERO(&exceptional);
	FD_SET(socketValue, &writable);
	FD_SET(socketValue, &exceptional);
	timeval timeout;
	timeout.tv_sec = timeoutMs / 1000;
	timeout.tv_usec = (timeoutMs % 1000) * 1000;
	const int selected = select(0, NULL, &writable, &exceptional, &timeout);
	if (selected <= 0 || FD_ISSET(socketValue, &exceptional)) {
		errorCode = selected == 0 ? WSAETIMEDOUT : WSAGetLastError();
		return false;
	}
	int pendingError = 0;
	int pendingLength = sizeof(pendingError);
	if (getsockopt(socketValue, SOL_SOCKET, SO_ERROR,
		reinterpret_cast<char*>(&pendingError), &pendingLength) != 0
		|| pendingError != 0) {
		errorCode = pendingError != 0 ? pendingError : WSAGetLastError();
		return false;
	}
	return true;
}

bool EseI08TcpEcho(const sockaddr* target, int targetLength,
	const std::vector<uint8_t>& payload, DWORD timeoutMs,
	unsigned& receivedBytes, int& errorCode)
{
	receivedBytes = 0;
	errorCode = 0;
	SOCKET socketValue = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	if (socketValue == INVALID_SOCKET) {
		errorCode = WSAGetLastError();
		return false;
	}

	u_long nonBlocking = 1;
	if (ioctlsocket(socketValue, FIONBIO, &nonBlocking) != 0) {
		errorCode = WSAGetLastError();
		closesocket(socketValue);
		return false;
	}
	if (connect(socketValue, target, targetLength) == SOCKET_ERROR) {
		const int connectError = WSAGetLastError();
		if (connectError != WSAEWOULDBLOCK
			&& connectError != WSAEINPROGRESS
			&& connectError != WSAEINVAL) {
			errorCode = connectError;
			closesocket(socketValue);
			return false;
		}
		if (!EseI08WaitWritable(socketValue, timeoutMs, errorCode)) {
			closesocket(socketValue);
			return false;
		}
	}
	nonBlocking = 0;
	if (ioctlsocket(socketValue, FIONBIO, &nonBlocking) != 0) {
		errorCode = WSAGetLastError();
		closesocket(socketValue);
		return false;
	}
	setsockopt(socketValue, SOL_SOCKET, SO_RCVTIMEO,
		reinterpret_cast<const char*>(&timeoutMs), sizeof(timeoutMs));
	setsockopt(socketValue, SOL_SOCKET, SO_SNDTIMEO,
		reinterpret_cast<const char*>(&timeoutMs), sizeof(timeoutMs));

	size_t sent = 0;
	while (sent < payload.size()) {
		const int part = send(socketValue,
			reinterpret_cast<const char*>(payload.data() + sent),
			static_cast<int>(payload.size() - sent), 0);
		if (part <= 0) {
			errorCode = WSAGetLastError();
			closesocket(socketValue);
			return false;
		}
		sent += static_cast<size_t>(part);
	}
	if (shutdown(socketValue, SD_SEND) != 0) {
		errorCode = WSAGetLastError();
		closesocket(socketValue);
		return false;
	}

	std::vector<uint8_t> reply(payload.size());
	while (receivedBytes < reply.size()) {
		const int part = recv(socketValue,
			reinterpret_cast<char*>(reply.data() + receivedBytes),
			static_cast<int>(reply.size() - receivedBytes), 0);
		if (part <= 0) {
			errorCode = part == 0 ? WSAECONNRESET : WSAGetLastError();
			closesocket(socketValue);
			return false;
		}
		receivedBytes += static_cast<unsigned>(part);
	}
	closesocket(socketValue);
	if (reply != payload) {
		errorCode = -1;
		return false;
	}
	return true;
}

bool EseI08UdpEcho(const sockaddr* target, int targetLength,
	const CAddress& expectedAddress, uint16 expectedPort,
	const std::vector<uint8_t>& payload, DWORD timeoutMs,
	unsigned& receivedBytes, int& errorCode)
{
	receivedBytes = 0;
	errorCode = 0;
	SOCKET socketValue = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	if (socketValue == INVALID_SOCKET) {
		errorCode = WSAGetLastError();
		return false;
	}
	setsockopt(socketValue, SOL_SOCKET, SO_RCVTIMEO,
		reinterpret_cast<const char*>(&timeoutMs), sizeof(timeoutMs));
	setsockopt(socketValue, SOL_SOCKET, SO_SNDTIMEO,
		reinterpret_cast<const char*>(&timeoutMs), sizeof(timeoutMs));
	const int sent = sendto(socketValue,
		reinterpret_cast<const char*>(payload.data()),
		static_cast<int>(payload.size()), 0, target, targetLength);
	if (sent != static_cast<int>(payload.size())) {
		errorCode = WSAGetLastError();
		closesocket(socketValue);
		return false;
	}

	std::vector<uint8_t> reply(payload.size() + 1);
	sockaddr_storage source;
	memset(&source, 0, sizeof(source));
	int sourceLength = sizeof(source);
	const int received = recvfrom(socketValue,
		reinterpret_cast<char*>(reply.data()),
		static_cast<int>(reply.size()), 0,
		reinterpret_cast<sockaddr*>(&source), &sourceLength);
	if (received <= 0) {
		errorCode = WSAGetLastError();
		closesocket(socketValue);
		return false;
	}
	closesocket(socketValue);
	receivedBytes = static_cast<unsigned>(received);

	CAddress sourceAddress;
	uint16 sourcePort = 0;
	if (!CAddress::TryFromSA(reinterpret_cast<sockaddr*>(&source),
		sourceLength, sourceAddress, &sourcePort)
		|| sourceAddress != expectedAddress || sourcePort != expectedPort) {
		errorCode = -2;
		return false;
	}
	if (reply.size() < payload.size()
		|| receivedBytes != payload.size()
		|| memcmp(reply.data(), payload.data(), payload.size()) != 0) {
		errorCode = -1;
		return false;
	}
	return true;
}

} // namespace

enum class W8LiveStreamOperation { Join, Leave, PlayerAlive, BroadcastStart, BroadcastStop, DirectJoin, StreamFile }; struct W8LiveStreamRequest { W8LiveStreamOperation operation = W8LiveStreamOperation::Join; std::string key, title, source, category, language, bitrate, file, direct; std::string link, ip, port, stream_hash, stream_resource; std::string ui_title, ui_source, ui_category, ui_language, ui_file, ui_link; std::string title_encoded_wire; }; struct W8LiveStreamAddress { enum class Family { None, IPv4, IPv6 } family = Family::None; std::string text; std::uint16_t port = 0; };
struct W8LiveStreamResponse { unsigned status = 200; std::string reason = "OK"; std::string content_type = "application/json"; std::string body; bool cors = true; bool nosniff = true; bool forward_stream_file = false; std::string stream_hash, stream_resource; }; struct W8LiveBroadcastRequest { std::string source, title, category, language, file; std::uint16_t bitrate = 0; }; class W8LiveStreamPort { public: virtual ~W8LiveStreamPort() = default; virtual bool IsAvailable() const = 0; virtual bool Join(const std::array<unsigned char, 16>& key, const std::string& title, const W8LiveStreamAddress& address, bool& joined, bool& dialed) = 0; virtual bool Leave(const std::array<unsigned char, 16>& key, bool has_key) = 0; virtual bool CopyViewerKey(std::array<unsigned char, 16>& key) const = 0; virtual void NotePlayerFetch() = 0; virtual bool StartBroadcast(const W8LiveBroadcastRequest& request) = 0; virtual void BroadcastLiveness(bool& alive, int& chunks) const = 0; virtual bool StopBroadcast() = 0; virtual bool CopyBroadcastKey(std::array<unsigned char, 16>& key) const = 0; virtual std::string PublicIPv4Text() const = 0; virtual std::uint16_t AdvertisedPort() const = 0; virtual std::uint32_t NowMs() const = 0; virtual void PauseMs(unsigned milliseconds) = 0; virtual bool IsUnsupportedIPv6Socks4() const = 0; virtual bool IsUsableAddress(const std::string& text, bool ipv6) const = 0; };
std::string W8EscapeJson(const std::string& input); std::string W8EncodeKey16(const std::array<unsigned char, 16>& key); bool W8DecodeKey16(const std::string& input, std::array<unsigned char, 16>& key); std::string W8BuildLiveStreamHeader(const W8LiveStreamResponse& response); bool RunW8LiveStreamApi(const W8LiveStreamRequest& request, W8LiveStreamPort& port, W8LiveStreamResponse& response); bool RunW8LiveStreamCharacterizationSelfTest(std::string& failure);
namespace ese { namespace web {
enum class W8LiveStatusOperation { Status, Channels, Mesh }; struct W8LiveStatusSnapshot { bool upnp_critical_error = false, utp_hole_punch_enabled = false, web_upnp_active = false; std::string upnp_ports_forwarded = "unknown"; bool kad_connected = false, kad2_running = false, kad2_connected = false; bool kad6_running = false, kad6_connected = false, ed2k_connected = false; std::uint32_t kad_configured_mask = 0, kad_running_mask = 0, kad6_verified_contacts = 0; std::string user_hash; std::int64_t connecting_client_count = 0, connecting_client_adds = 0; std::int64_t connecting_client_high_water = 0, connecting_client_duplicate_adds = 0; std::uint32_t hole_punch_attempts = 0, hole_punch_success = 0, hole_punch_sym_nat_fail = 0; std::uint32_t hole_punch_encrypted = 0, hole_punch_plaintext = 0, hole_punch_req_recv = 0; std::uint32_t hole_punch_challenge_sent = 0, kad3_rdv_req_sent = 0, kad3_rdv_req_recv = 0; std::uint32_t kad3_rdv_challenge_sent = 0, kad3_rdv_fwd = 0, kad3_rdv_success = 0; bool keepalive_running = false; std::uint32_t keepalive_pings_sent = 0, keepalive_pongs_recv = 0, keepalive_supernodes = 0; std::string netlab_consent = "undecided", netlab_advanced_consent = "undecided"; std::string netlab_contribution_consent = "undecided"; bool netlab_enabled = false; }; struct W8LiveChannelSnapshot { bool broadcasting = false; std::array<std::uint8_t, 16> stream_key{}; std::string title, category, language; std::uint32_t started_at = 0, viewer_count = 0, bitrate = 0; };
struct W8LiveMeshSnapshot { std::int64_t mesh_peers = 0, pending_requests = 0, chunks_served = 0; std::uint64_t total_redistributed = 0; std::int64_t super_seeders = 0, middle_peers = 0, leaf_peers = 0; std::uint32_t upload_floor = 0; bool emergency_mode = false; }; struct W8LiveStatusPort { void* context = nullptr; bool (*read_status)(void*, W8LiveStatusSnapshot&) = nullptr; bool (*read_channel)(void*, W8LiveChannelSnapshot&) = nullptr; bool (*read_mesh)(void*, W8LiveMeshSnapshot&) = nullptr; }; struct W8LiveStatusResponse { std::string header; std::string body; };
bool RunW8LiveStatusApi(W8LiveStatusOperation operation, bool loopback, const W8LiveStatusPort& port, W8LiveStatusResponse& response); bool RunW8LiveStatusCharacterizationSelfTest(std::string& failure);
} }
enum class W9LiveTransferOperation { NetworkConnect, Rendezvous, KeepaliveStart, KeepaliveStop, RelayAccept, RelayEgress, RelaySelector, RelayConnect, HolePunch };
enum class W9LiveTransferRate { NetworkConnect, ManualRendezvous, KeepaliveToggle, ManualHolePunch };
enum class W9LiveRelayToggle { Accept, Egress, Selector };
enum class W9LiveTransferGuard { Ok, InvalidIpPort, KadNotReady, HolePunchDisabled, RendezvousDisabled, NetlabConsentRequired, NetlabTargetRequired, UtpNotReady };
struct W9LiveTransferRequest { W9LiveTransferOperation operation = W9LiveTransferOperation::NetworkConnect; std::string ed2k, kad, target_ip, target_udp_port, rdv_ip, rdv_udp_port; std::string on, stream, buddy_ip, buddy_port, ip, udp_port, spread; };
struct W9LiveTransferRateDecision { bool allowed = false; std::uint64_t retry_after_ms = 0; };
struct W9LiveHolePunchResult { W9LiveTransferGuard guard = W9LiveTransferGuard::InvalidIpPort; std::uint32_t attempts_before = 0; std::uint16_t spread = 0; };
struct W9LiveTransferSnapshot { bool ed2k_connected = false, ed2k_connecting = false, kad_running = false, kad_connected = false; bool kad2_running = false, kad2_connected = false, kad6_running = false, kad6_connected = false; bool netlab_active = false, kad_udp_ready = false, utp_hole_punch_enabled = false; bool kad3_rendezvous_enabled = false, client_utp_ready = false, keepalive_running = false; bool relay_accept = false, relay_egress = false, relay_selector = false, port_predict = false; std::uint32_t kad_configured_mask = 0, kad_running_mask = 0, kad6_verified_contacts = 0; std::uint32_t kad3_rdv_req_sent = 0, kad3_rdv_req_recv = 0, kad3_rdv_challenge_sent = 0, kad3_rdv_fwd = 0, kad3_rdv_success = 0; std::uint32_t keepalive_pings_sent = 0, keepalive_pongs_recv = 0, keepalive_supernodes = 0; std::uint32_t relay_req_recv = 0, relay_accepted = 0, relay_active = 0, relay_bytes_fwd_kb = 0, relay_budget_drops = 0, relay_max_kbps = 0; std::uint32_t reach_direct = 0, reach_punch2 = 0, reach_punch3 = 0, reach_relay = 0; std::uint32_t hole_attempts = 0, hole_success = 0, hole_sym_nat_fail = 0, hole_encrypted = 0, hole_plaintext = 0, hole_spray_reqs = 0, hole_req_recv = 0, hole_challenge_sent = 0; std::uint16_t port_predict_spread = 0; };
struct W9LiveTransferResponse { unsigned status = 200; std::string reason = "OK", content_type = "application/json", body; bool cors = true, nosniff = true, cache_no_store = false; };
struct W9LiveTransferPort { void* context = nullptr; std::uint64_t (*now_ms)(void*) = nullptr; W9LiveTransferRateDecision (*check_rate)(void*, W9LiveTransferRate, std::uint64_t, std::uint64_t) = nullptr; bool (*parse_ipv4_legacy)(void*, const std::string&, std::uint32_t&) = nullptr; bool (*read_snapshot)(void*, W9LiveTransferSnapshot&) = nullptr; void (*request_network)(void*, bool, bool, bool&, bool&) = nullptr; W9LiveTransferGuard (*request_rendezvous)(void*, std::uint32_t, std::uint16_t, std::uint32_t, std::uint16_t) = nullptr; W9LiveTransferGuard (*request_keepalive)(void*, bool) = nullptr; void (*set_relay)(void*, W9LiveRelayToggle, bool) = nullptr; void (*request_relay_connect)(void*, const std::array<unsigned char, 16>&, std::uint32_t, std::uint16_t) = nullptr; W9LiveHolePunchResult (*request_hole_punch)(void*, std::uint32_t, std::uint16_t, bool, int) = nullptr; };
std::string W9BuildLiveTransferHeader(const W9LiveTransferResponse& response); bool RunW9LiveTransferApi(const W9LiveTransferRequest&, W9LiveTransferPort&, W9LiveTransferResponse&); bool RunW9LiveTransferCharacterizationSelfTest(std::string& failure);
namespace ese { namespace web {
enum class W9SearchOperation { SourceResolutions, PrivacySubscriptions, TunnelSearch, Diagnose, KadStreams };
struct W9SearchRequest { W9SearchOperation operation = W9SearchOperation::SourceResolutions; bool loopback = false, keyword_lowered = false; std::string after, add, remove, name, keyword, key; };
struct W9SourceCandidate { std::string family, endpoint_sha256, outcome, source_origin; };
struct W9SourceEvent { std::uint64_t sequence = 0; std::string hostname_sha256, file_ed2k_hash, resolver_result, resolved_endpoint_set_sha256, materialized_endpoint_set_sha256; std::uint32_t port = 0, resolved_ipv4 = 0, resolved_ipv6 = 0, materialized_ipv4 = 0, materialized_ipv6 = 0; bool simultaneously_retained = false; std::vector<W9SourceCandidate> candidates; };
struct W9Subscription { std::array<std::uint8_t, 32> pubkey{}; std::string name; std::uint64_t added = 0; };
struct W9DirectoryEntry { std::string title, broadcaster_ip; std::uint32_t broadcaster_port = 0, bitrate = 0, viewers = 0, last_seen_age_ms = 0; bool own = false; };
struct W9DiagnoseSnapshot { bool kad_connected = false, broadcasting = false, viewing = false, in_directory = false, public_ip_available = false; std::string public_ip; std::uint16_t tcp_port = 0; std::uint32_t directory_size = 0; W9DirectoryEntry entry; };
struct W9KadStream { std::array<std::uint8_t, 16> key{}; std::string title, category, language; std::uint32_t bitrate = 0, viewers = 0, broadcaster_ip = 0, broadcaster_port = 0, started_at = 0, last_seen = 0; bool own = false, kad6_tunnel = false; };
struct W9SearchPort { void* context = nullptr; std::uint32_t (*now_ms)(void*) = nullptr; bool (*read_source_events)(void*, std::uint64_t, std::uint64_t&, std::vector<W9SourceEvent>&) = nullptr; bool (*add_subscription)(void*, const std::array<std::uint8_t, 32>&, const std::string&, std::string&) = nullptr; bool (*remove_subscription)(void*, const std::array<std::uint8_t, 32>&, std::string&) = nullptr; bool (*list_subscriptions)(void*, std::vector<W9Subscription>&) = nullptr; bool (*tunnel_search)(void*, const std::string&, std::string&, unsigned) = nullptr; bool (*read_diagnose)(void*, const std::array<std::uint8_t, 16>*, W9DiagnoseSnapshot&) = nullptr; void (*request_kad_refresh)(void*) = nullptr; bool (*read_kad_streams)(void*, bool&, std::vector<W9KadStream>&) = nullptr; };
struct W9SearchResponse { std::string header, body; };
bool RunW9LiveSearchApi(const W9SearchRequest&, const W9SearchPort&, W9SearchResponse&); bool RunW9LiveSearchCharacterizationSelfTest(std::string& failure);
} }
enum class W10SettingsOperation { EseV9, Privacy, EdgeSabotage };
struct W10SettingsRequest { W10SettingsOperation operation = W10SettingsOperation::EseV9; bool loopback = false; std::string on, mode, fallback, add_sensitive, rm_sensitive, delay; };
struct W10NetlabSnapshot { std::string consent = "undecided", advanced_consent = "undecided", contribution_consent = "undecided"; bool enabled = false, capability_advertised = false, ipv6_auto = false, hole_punch = false; bool auto_keepalive = false, selector = false, port_predict = false, ed2k_punch3 = false; bool kad3_rendezvous = false, relay_accept = false, relay_egress = false, krp = false; bool kad6_beta_exit = false, kad6_stable_public_exit = false, keepalive_running = false; bool experimental = false, hole_punch_master = false; std::uint32_t reach_direct = 0, reach_punch2 = 0, reach_punch3 = 0, reach_relay = 0; };
struct W10PrivacySnapshot { std::string mode = "adaptive", fallback = "balanced", public_ipv6; std::vector<std::string> sensitive_keywords, caps_human; std::uint32_t caps_bits = 0, circuits_active = 0, circuits_pending = 0, tunnel_pool_size = 0; std::uint32_t subscriptions_loaded = 0, mean_rtt_ms = 0; std::uint64_t cells_sent = 0, cells_recv = 0, bytes_sent = 0, bytes_recv = 0; bool kad6_preferred = false, kad6_circuit_active = false; std::string route_state = "kad2_direct"; };
struct W10SettingsResponse { unsigned status = 200; std::string reason = "OK", header, body; };
struct W10SettingsPort { void* context = nullptr; bool (*read_netlab)(void*, W10NetlabSnapshot&) = nullptr; bool (*netlab_consent_accepted)(void*) = nullptr; void (*apply_netlab)(void*, bool) = nullptr; void (*refresh_preview_caps)(void*) = nullptr; void (*request_keepalive)(void*, bool) = nullptr; bool (*persist_disable_and_verify)(void*) = nullptr; bool (*save_preferences)(void*) = nullptr; void (*post_krp_event)(void*) = nullptr; bool (*read_privacy_policy)(void*, W10PrivacySnapshot&) = nullptr; void (*set_privacy_mode)(void*, const std::string&) = nullptr; void (*set_fallback)(void*, const std::string&) = nullptr; void (*add_sensitive)(void*, const std::string&) = nullptr; void (*remove_sensitive)(void*, const std::string&) = nullptr; void (*mirror_privacy_preferences)(void*) = nullptr; bool (*read_privacy_runtime)(void*, W10PrivacySnapshot&) = nullptr; bool test_hooks_enabled = false; void (*set_edge_sabotage)(void*, bool, int, std::uint32_t) = nullptr; };
bool RunW10LiveSettingsApi(const W10SettingsRequest&, const W10SettingsPort&, W10SettingsResponse&); bool RunW10LiveSettingsCharacterizationSelfTest(std::string& failure);
namespace ese { namespace web {
enum class W10DiagnosticsOperation { KrpStatus, Preflight, Metrics, Log, Debug, Ipv6Echo, ReachStatus };
struct W10DiagnosticsRequest { W10DiagnosticsOperation operation = W10DiagnosticsOperation::KrpStatus; int log_n = 100, tcp_port = 0, udp_port = 0, timeout_ms = 5000; std::string target, nonce; };
struct W10Ipv6EchoResult { bool success = false; std::string error, target, nonce; int tcp_port = 0, udp_port = 0, tcp_error = 0, udp_error = 0; std::uint32_t tcp_bytes = 0, udp_bytes = 0; };
struct W10PreflightSnapshot { bool kad_connected = false, high_id = false, kad_firewalled = false, ed2k_lowid = false, firewall_checking = false, ffmpeg_found = false; std::uint32_t max_upload_kbs = 0; std::uint16_t port = 0; std::string public_ip, public_ip_v6, ffmpeg_path; };
struct W10MetricsSnapshot { long chunks_received = 0, chunks_requested = 0, chunks_missing = 0, kad_publishes = 0, kad_searches = 0, peer_disconnects = 0, kad_searches_empty = 0, kad_searches_rate_limited = 0, pending_dials_dropped = 0, join_first_count = 0, join_first_sum = 0; int chunks_served = 0, view_peers = 0, broadcast_peers = 0, mesh_peers = 0, buffer_count = 0, pending_requests = 0; bool broadcasting = false, viewing = false; };
struct W10DebugPeer { std::string ip; std::uint16_t port = 0; std::int64_t level = 0, fail_count = 0, response_percent = 0; std::uint32_t rtt_ms = 0; };
struct W10DebugSnapshot { bool available = false, broadcasting = false, viewing = false, emergency_mode = false, kad_connected = false; std::uint32_t uptime_ms = 0, now_ms = 0, last_publish_time = 0, last_search_time = 0, last_result_time = 0, last_result_ip = 0, last_chunk_received_at = 0, hls_segments_written = 0, hls_playlist_refreshes = 0, kad_publishes = 0, kad_searches = 0, kad_results_accepted = 0, kad_results_rejected = 0, source_dial_attempts = 0, subscribe_sent = 0, subscribe_accepted = 0, chunks_requested = 0, chunks_received = 0, chunks_missing = 0, duplicate_chunks_received = 0, requests_suppressed_inflight = 0, peer_disconnects = 0, skipped_initial_pushes = 0, subscribes_rate_limited = 0, requests_rate_limited = 0, ends_rejected_no_auth = 0, tombstones_evicted = 0, oldest_sequence = 0, newest_sequence = 0; std::uint64_t total_redistributed = 0; std::uint16_t last_result_port = 0, chunk_bitmap = 0; std::int64_t known_streams = 0, known_streams_clean = 0, known_streams_legacy = 0, view_peers = 0, broadcast_peers = 0, mesh_peers = 0, pending_requests = 0, chunks_served = 0, super_seeders = 0, middle_peers = 0, leaf_peers = 0, chunk_count = 0, missing_chunks = 0, max_capacity = 15, segment_duration_seconds = 2; std::vector<W10DebugPeer> peer_detail; };
struct W10DiagnosticsResponse { std::string header, body; };
struct W10DiagnosticsPort { void* context = nullptr; bool (*read_krp_json)(void*, std::string&) = nullptr; bool (*read_preflight)(void*, W10PreflightSnapshot&) = nullptr; bool (*read_metrics)(void*, W10MetricsSnapshot&) = nullptr; void (*read_percentiles)(void*, std::uint32_t&, std::uint32_t&, std::uint32_t&) = nullptr; std::uint32_t (*read_latency_mean)(void*) = nullptr; int (*read_latency_samples)(void*) = nullptr; bool (*read_kad6_metrics)(void*, std::string&) = nullptr; bool (*read_log)(void*, int, std::vector<std::string>&) = nullptr; bool (*read_debug)(void*, W10DebugSnapshot&) = nullptr; bool (*run_ipv6_echo)(void*, const W10DiagnosticsRequest&, W10Ipv6EchoResult&) = nullptr; bool (*read_reach_json)(void*,std::string&) = nullptr; };
bool RunW10LiveDiagnosticsApi(const W10DiagnosticsRequest&, const W10DiagnosticsPort&, W10DiagnosticsResponse&); bool RunW10LiveDiagnosticsCharacterizationSelfTest(std::string& failure);
} }
namespace ese { namespace web {
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
bool RunW11LiveLegacyApi(const W11LegacyRequest&, const W11LegacyPort&, W11LegacyResponse&); bool BuildW11LegacyStaticFile(const W11StaticFileRequest&, W11LegacyResponse&); bool RunW11LiveLegacyCharacterizationSelfTest(std::string&);
} }
namespace eSELive {
M2AModuleHandle M2A_BIND_W8_4974C0F316(const M2AParentPort&); void M2A_UNBIND_W8_4974C0F316(const M2AParentPort&);
M2AModuleHandle M2A_BIND_W8_E988965D5A(const M2AParentPort&); void M2A_UNBIND_W8_E988965D5A(const M2AParentPort&);
M2AModuleHandle M2A_BIND_W9_52CC9DEBDD(const M2AParentPort&); void M2A_UNBIND_W9_52CC9DEBDD(const M2AParentPort&);
M2AModuleHandle M2A_BIND_W9_3B359EBB1A(const M2AParentPort&); void M2A_UNBIND_W9_3B359EBB1A(const M2AParentPort&);
M2AModuleHandle M2A_BIND_W10_E9722EA045(const M2AParentPort&); void M2A_UNBIND_W10_E9722EA045(const M2AParentPort&);
M2AModuleHandle M2A_BIND_W10_47570D3256(const M2AParentPort&); void M2A_UNBIND_W10_47570D3256(const M2AParentPort&);
M2AModuleHandle M2A_BIND_W11_55908BF94D(const M2AParentPort&); void M2A_UNBIND_W11_55908BF94D(const M2AParentPort&);
M2AModuleHandle M2A_BIND_W12_B26D83D73F(const M2AParentPort&); void M2A_UNBIND_W12_B26D83D73F(const M2AParentPort&);
}
namespace eSELive {
enum class WebClassicView : std::uint8_t { Unknown = 0, Login, RemoteLinkAdded, RemoteLinkFailed, CommentList, Header, Footer, Server, Shared, Transfer, Search, Graphs, Log, ServerInfo, DebugLog, MyInfo, Stats, Kad, Options };
enum class WebAdminAction : std::uint8_t { Close, Shutdown, Reboot };
struct WebClassicInput {
	const void* legacy = nullptr; CString url; CString ip_text; CStringA csrf_token; CStringA fetch_site; CStringA browser_session_token; CString admin_password_hash; CString guest_password_hash; CString access_denied_text;
	std::uint32_t ip = 0; int default_category = 0; bool loopback = false; bool app_running = false; bool use_gzip = false; bool guest_enabled = false; bool allow_high_level = false; bool secure_transport = false;
};
struct WebClassicPort {
	void* context = nullptr; CString (*parse_url)(const CString&, const CString&) = nullptr; bool (*validate_challenge)(const void*, const CString&, const CString&, bool&) = nullptr;
	bool (*login_blocked)(void*, std::uint32_t, std::uint64_t) = nullptr; bool (*add_session)(void*, std::uint32_t, bool, int, std::uint64_t, const CStringA&, const CStringA&) = nullptr; bool (*resolve_browser_session)(void*, const CStringA&, std::uint64_t, std::uint64_t, std::uint32_t&) = nullptr; bool (*validate_csrf)(void*, std::uint32_t, const CStringA&, const CStringA&) = nullptr;
	void (*record_login_failure)(void*, std::uint32_t, std::uint64_t) = nullptr; void (*record_login_success)(void*, std::uint32_t) = nullptr; bool (*remove_session)(const void*, long) = nullptr; bool (*is_logged_in)(const void*, long) = nullptr; bool (*is_admin)(const void*, const CString&) = nullptr;
	void (*send_content)(const void*, const CStringA&, const CString&) = nullptr; void (*send_binary)(const void*, const CStringA&, const void*, unsigned long) = nullptr; void (*send_reply)(const void*, const char*) = nullptr;
	void (*notify_login)(bool, const CString&) = nullptr; void (*notify_bad_login)(const CString&) = nullptr; void (*perform_admin_action)(WebAdminAction) = nullptr; bool (*send_requested_file)(const void*, const CString&) = nullptr; CString (*render)(WebClassicView, const void*, long) = nullptr;
	bool Complete() const noexcept;
};
M2AModuleHandle M2A_BIND_W1_EC6846B80E(const M2AParentPort&); void M2A_UNBIND_W1_EC6846B80E(const M2AParentPort&);
void RunWebClassicRequest(const M2AParentPort&, const WebClassicInput&, const WebClassicPort&); bool RunWebClassicRequestCharacterizationSelfTest(); std::uint64_t WebRequestAuthNowMs() noexcept; std::uint64_t WebRequestSessionTimeoutMs() noexcept; CStringA GenerateWebRequestHexToken(); CStringA DigestWebRequestToken(const CStringA&); std::uint32_t GenerateWebRequestWord32(); bool ValidateWebChallengeDigest(const CStringA&, const CStringA&, const CString&, bool, const CString&, bool&); int CompressWebGzip(unsigned char*, unsigned long*, const unsigned char*, unsigned long, int); enum class WebTemplateId : std::uint8_t { Header, HeaderStylesheet, Footer, ServerList, ServerLine, TransferImages, TransferList, TransferDownHeader, TransferDownFooter, TransferDownLine, TransferUpHeader, TransferUpFooter, TransferUpLine, TransferUpQueueShow, TransferUpQueueHide, TransferUpQueueLine, TransferUpQueueBannedShow, TransferUpQueueBannedHide, TransferUpQueueBannedLine, TransferUpQueueFriendShow, TransferUpQueueFriendHide, TransferUpQueueFriendLine, SharedList, SharedLine, Graphs, Log, ServerInfo, DebugLog, Stats, Preferences, Login, AddServerBox, Search, ProgressbarWidth, SearchHeader, SearchResultLine, ProgressbarImgs, ProgressbarImgsPercent, CatArrow, DownArrow, UpArrow, DownDoubleArrow, UpDoubleArrow, Kad, BootstrapLine, MyInfoLog, CommentList, CommentListLine, Count }; enum class WebTemplateLogView : std::uint8_t { Log, ServerInfo, DebugLog }; struct WebHeaderRuntime { CString version, serverName; std::uint32_t serverUsers = 0, serverMaxUsers = 0, serverFiles = 0; std::uint32_t allUsers = 0, allFiles = 0, openSockets = 0; double downloadRate = 0.0, uploadRate = 0.0; bool serverConnecting = false, serverConnected = false, highId = false; bool kad2Connected = false, kadFirewalled = false; bool kad6Connected = false, kadRunning = false; }; struct WebCommentRow { CString user, file, text, rating; }; struct WebCommentListInput { bool found = false; CString fileName; std::vector<WebCommentRow> rows; }; M2AModuleHandle M2A_BIND_W2_071B3D442B(const M2AParentPort&); void M2A_UNBIND_W2_071B3D442B(const M2AParentPort&); M2AModuleHandle M2A_BIND_W2_9330EBAD15(const M2AParentPort&); void M2A_UNBIND_W2_9330EBAD15(const M2AParentPort&); bool ReloadWebTemplates(const M2AParentPort&, const CString&, bool, bool, bool&); CString GetWebTemplate(const M2AParentPort&, WebTemplateId); CString GetWebTemplateLastModified(const M2AParentPort&); CString GetWebTemplateETag(const M2AParentPort&); M2AModuleHandle CaptureWebTemplateSnapshot(const M2AParentPort&); CString EscapeWebTemplateText(const CString&, bool); CString GetWebPlainResource(UINT, bool); bool RunWebTemplateCharacterizationSelfTest(); CString RenderWebHeader(const M2AParentPort&, const CString&, const CString&, const CString&, long, bool, std::uint32_t, const CString&, const CString&, const CString&, const WebHeaderRuntime&); CString RenderWebFooter(const M2AParentPort&, const CString&); CString RenderWebLogin(const M2AParentPort&, const CString&, const CStringA&, bool, const CString&); CString RenderWebLogView(WebTemplateLogView, const CString&, const CString&, const CString&); CString RenderWebMyInfo(const CString&, const CString&); CString RenderWebStats(const CString&, const CString&); CString RenderWebCommentList(const WebCommentListInput&, const CString&, const CString&); void InsertWebCategoryBox(CString&, int, LPCTSTR, bool, bool, const CString&, const CString&, int, bool); bool RunWebPageChromeCharacterizationSelfTest();
enum class WebServerAction : std::uint8_t { Connect, Disconnect, Remove, AddStatic, RemoveStatic, PriorityLow, PriorityNormal, PriorityHigh }; struct WebServerRow { CString description, fullIp, ip, name, priorityText, state, version; std::uint32_t files = 0, hardLimit = 0, maxUsers = 0, ping = 0; std::uint32_t softLimit = 0, users = 0; int failed = 0, port = 0; std::uint8_t priority = 0; bool isStatic = false; }; struct WebServerPageInput { CString url, pageTemplate, rowTemplate, addTemplate, upArrow, downArrow; bool admin = false; unsigned sort = 0; bool reverse = false; std::array<bool, 10> hidden{}; }; struct WebServerPageResult { CString html; unsigned sort = 0; bool reverse = false; std::array<bool, 10> hidden{}; }; struct WebServerGuiPort { void* context = nullptr; CString (*parse)(void*, const CString&, const CString&) = nullptr; CString (*plain)(void*, unsigned) = nullptr; void (*action)(void*, WebServerAction, const CString&, int) = nullptr; bool (*addServer)(void*, const CString&, int, const CString&, const CString&, bool, bool, CString&) = nullptr; void (*updateServerMet)(void*, const CString&, CString&) = nullptr; void (*saveHidden)(void*, const std::array<bool, 10>&) = nullptr; void (*snapshot)(void*, std::vector<WebServerRow>&) = nullptr; bool Complete() const noexcept; }; M2AModuleHandle M2A_BIND_W3_F05B56128F(const M2AParentPort&); void M2A_UNBIND_W3_F05B56128F(const M2AParentPort&); WebServerPageResult RunWebServerPage(const M2AParentPort&, const WebServerPageInput&, const WebServerGuiPort&); bool RunWebServerPageCharacterizationSelfTest();
enum class WebTransferTemplate : std::uint8_t { Images, List, DownHeader, DownFooter, DownLine, UpHeader, UpFooter, UpLine, QueueShow, QueueHide, QueueLine, QueueBannedShow, QueueBannedHide, QueueBannedLine, QueueFriendShow, QueueFriendHide, QueueFriendLine, ProgressbarWidth, CatArrow, DownArrow, UpArrow };
struct WebTransferProjectionInput { CString url, session, categorySuffix, selectedFile; int category = 0; bool admin = false; unsigned downloadSort = 0, uploadSort = 0, queueSort = 0; bool downloadReverse = false, uploadReverse = false, queueReverse = false; bool showQueue = false, showBanned = false, showFriend = false; unsigned maxWebUploadFileSizeMB = 0; std::array<bool, 8> downloadHidden{}; std::array<bool, 5> uploadHidden{}; std::array<bool, 4> queueHidden{}; };
struct WebTransferSnapshot { CArray<DownloadFiles> downloads; CArray<UploadUsers> uploads; CArray<QueueUsers> queue; int queueCount = 0, bannedCount = 0, friendCount = 0; int queueSecure = 0, bannedSecure = 0, friendSecure = 0; };
struct WebTransferProjectionPort { void* context = nullptr; CString (*templateText)(void*, WebTransferTemplate) = nullptr; CString (*plain)(void*, unsigned) = nullptr; CString (*special)(void*, const CString&, bool) = nullptr; void (*insertCategory)(void*, CString&, int, LPCTSTR, bool, bool, const CString&, const CString&, int) = nullptr; void (*snapshot)(void*, int, unsigned, bool, unsigned, bool, unsigned, bool, bool, bool, bool, WebTransferSnapshot&) = nullptr; bool Complete() const noexcept; };
M2AModuleHandle M2A_BIND_W4_AD763A5EE0(const M2AParentPort&); void M2A_UNBIND_W4_AD763A5EE0(const M2AParentPort&); CString RunWebTransferProjection(const M2AParentPort&, const WebTransferProjectionInput&, const WebTransferProjectionPort&); bool RunWebTransferProjectionCharacterizationSelfTest();
enum class WebTransferActionKind : std::uint8_t { None = 0, ClearCompletedAll, ClearCompletedFile, AddDownload, SaveDownloadColumn, SaveUploadColumn, SaveQueueColumn, CategoryPriorityLow, CategoryPriorityNormal, CategoryPriorityHigh, CategoryPriorityAuto, FriendAdd, FriendRemove, FileStop, FilePause, FileResume, FileCancel, FileGetLink, FileRename, FilePriorityLow, FilePriorityNormal, FilePriorityHigh, FilePriorityAuto, FileSetCategory, FileStreamSeek }; enum class WebTransferActionSortDomain : std::uint8_t { None = 0, Download, Upload, Queue }; struct WebTransferActionCommand { WebTransferActionKind kind = WebTransferActionKind::None; std::string value; long number = -1; unsigned index = 0; bool flag = false; }; struct WebTransferActionInput { bool admin = false; int category = 0; std::string clearCompleted; std::string addDownload; std::string columnCommand; std::string columnIndex; std::string columnValue; std::string categoryPriority; std::string operation; std::string fileHash; std::string userHash; std::string actionText; std::string numericValue; std::string sort; std::string sortReverse; std::string showQueue; std::string showBanned; std::string showFriend; unsigned downloadSort = 0; unsigned uploadSort = 0; unsigned queueSort = 0; bool downloadReverse = false; bool uploadReverse = false; bool queueReverse = false; bool queueVisible = false; bool bannedVisible = false; bool friendVisible = false; }; struct WebTransferActionResult { WebTransferActionSortDomain sortDomain = WebTransferActionSortDomain::None; unsigned downloadSort = 0; unsigned uploadSort = 0; unsigned queueSort = 0; bool downloadReverse = false; bool uploadReverse = false; bool queueReverse = false; bool queueVisible = false; bool bannedVisible = false; bool friendVisible = false; }; struct WebTransferActionsPort { void* context = nullptr; void (*emit)(void*, const WebTransferActionCommand&) = nullptr; bool Complete() const noexcept; };
M2AModuleHandle M2A_BIND_W5_095B87253F(const M2AParentPort&); void M2A_UNBIND_W5_095B87253F(const M2AParentPort&); WebTransferActionResult RunWebTransferActions(const M2AParentPort&, const WebTransferActionInput&, const WebTransferActionsPort&); bool RunWebTransferActionsCharacterizationSelfTest();
struct WebSearchProjectionRow { std::wstring fileName; std::wstring limitedName; std::wstring typeImage; std::wstring sizeText; std::uint64_t sizeBytes = 0; std::wstring hash; std::wstring sources; std::wstring sourceBucket; std::uint8_t red = 0; std::uint8_t green = 0; std::uint8_t blue = 0; }; struct WebSearchProjectionInput { std::wstring pageTemplate; std::wstring headerTemplate; std::wstring rowTemplate; std::wstring message; std::wstring categoryBox; std::wstring session; std::wstring upArrow; std::wstring downArrow; std::array<bool, 4> hidden{}; unsigned sortColumn = 0; bool ascending = true; std::vector<std::pair<std::wstring, std::wstring>> replacements; std::array<std::wstring, 4> columnNames; std::vector<WebSearchProjectionRow> rows; };
M2AModuleHandle M2A_BIND_W6_64C04005E2(const M2AParentPort&); void M2A_UNBIND_W6_64C04005E2(const M2AParentPort&); std::wstring RunWebSearchProjection(const M2AParentPort&, const WebSearchProjectionInput&); bool RunWebSearchProjectionCharacterizationSelfTest();
enum class WebSharedFilesSort : unsigned { State, Type, Name, Size, Transferred, AllTimeTransferred, Requests, AllTimeRequests, Accepts, AllTimeAccepts, Completes, Priority }; enum class WebSharedFilePriority : std::uint8_t { VeryLow, Low, Normal, High, Release };
struct WebSharedFilesRow { std::wstring hash; std::wstring fileName; std::wstring fileState; std::wstring fileType; std::wstring ed2kLink; std::wstring priorityLabel; std::wstring fileSizeText; std::wstring transferredText; std::wstring allTimeTransferredText; std::array<std::wstring, 3> textOrder{}; std::uint64_t fileSizeBytes = 0; std::uint64_t transferredBytes = 0; std::uint64_t allTimeTransferredBytes = 0; std::uint32_t requests = 0; std::uint32_t allTimeRequests = 0; std::uint32_t accepts = 0; std::uint32_t allTimeAccepts = 0; std::uint32_t completeSourcesLow = 0; std::uint32_t completeSourcesHigh = 0; std::uint32_t completeSourcesOrder = 0; std::uint32_t priorityOrder = 0; WebSharedFilePriority priority = WebSharedFilePriority::Normal; bool partFile = false; bool autoPriority = false; }; struct WebSharedFilesInput { std::wstring pageTemplate; std::wstring rowTemplate; std::wstring session; std::wstring selectedHash; std::wstring message; std::wstring upArrow; std::wstring downArrow; std::wstring upDoubleArrow; std::wstring downDoubleArrow; std::array<std::wstring, 7> columnNames{}; std::wstring actionsLabel; std::wstring reloadLabel; std::wstring sharedListLabel; std::array<bool, 7> hidden{}; WebSharedFilesSort sort = WebSharedFilesSort::Name; bool reverse = false; bool admin = false; std::uint64_t maximumDownloadMiB = 0; std::size_t shortNameLimit = 40; std::vector<std::pair<std::wstring, std::wstring>> replacements; std::vector<WebSharedFilesRow> rows; };
M2AModuleHandle M2A_BIND_W6_B161DA740E(const M2AParentPort&); void M2A_UNBIND_W6_B161DA740E(const M2AParentPort&); std::wstring RunWebSharedFilesController(const M2AParentPort&, const WebSharedFilesInput&); bool RunWebSharedFilesControllerCharacterizationSelfTest();
}
struct WebTemplateParentAdapter { M2AParentPort operator()(const void* parent) const; };
static const WebTemplateParentAdapter WebTemplateParent = {};
M2AParentPort WebTemplateParentAdapter::operator()(const void* parent) const { return M2AParentPort{const_cast<void*>(parent)}; }
static void SendWebForbidden(CWebSocket* socket, const char* hint)
{
	CStringA body;
	body.Format("{\"error\":\"forbidden\",\"hint\":\"%s\"}", hint);
	CStringA header;
	header.Format(
		"HTTP/1.1 403 Forbidden\r\n"
		"Content-Type: application/json\r\n"
		"Cache-Control: no-store\r\n"
		"Content-Length: %d\r\n\r\n",
		body.GetLength());
	const std::string hardened = ese::web::HardenLiveResponseHeaders(
		std::string(header.GetString(), header.GetLength()), true);
	socket->SendData(hardened.data(), static_cast<int>(hardened.size()));
	socket->SendData(body, body.GetLength());
}

namespace {
std::string W8Legacy(const CString& text) { const CStringA legacy(text); return std::string((LPCSTR)legacy, legacy.GetLength()); } std::string W8Utf8(const CString& text) { const CStringA value(StrToUtf8(text)); return std::string((LPCSTR)value, value.GetLength()); } CString W8Text(const std::string& text) { return OptUtf8ToStr(text.data(), static_cast<int>(text.size())); }
void W8Assign(const CString& text, std::string& wire, std::string& ui, std::string* encoded = nullptr) { wire=W8Legacy(text); ui=W8Utf8(text); if(encoded!=nullptr) { encoded->clear(); if(!text.IsEmpty()) *encoded=W8Legacy(EncodeURLQueryParam(text)); } }
class W8LiveAppPort final : public W8LiveStreamPort { public: bool IsAvailable() const override { return theApp.liveStreamManager != NULL; } bool Join(const std::array<unsigned char, 16>& key, const std::string& title, const W8LiveStreamAddress& address, bool& joined, bool& dialed) override { CString titleText=W8Text(title); const CStringA addressBytes(address.text.data(),static_cast<int>(address.text.size())); CString addressText(addressBytes); LiveWebJoinReq req; req.streamKey=key.data(); req.title=titleText; req.address=address.family==W8LiveStreamAddress::Family::None?CAddress():CAddress(addressText,false); req.port=address.port; req.joined=req.dialed=false; if(theApp.emuledlg!=NULL) theApp.emuledlg->SendMessage(UM_LIVE_WEB_JOIN,0,(LPARAM)&req); joined=req.joined; dialed=req.dialed; return joined; } bool Leave(const std::array<unsigned char, 16>& key, bool has) override { LiveWebLeaveReq req; memcpy(req.streamKey, key.data(), 16); req.hasStreamKey = has; req.wasViewing = false; if (theApp.emuledlg != NULL && IsAvailable()) theApp.emuledlg->SendMessage(UM_LIVE_WEB_LEAVE, 0, (LPARAM)&req); return req.wasViewing; } bool CopyViewerKey(std::array<unsigned char, 16>& key) const override { return IsAvailable() && theApp.liveStreamManager->CopyViewerStreamKey(key.data()); } void NotePlayerFetch() override { if (IsAvailable()) theApp.liveStreamManager->NotePlayerFetch(); } bool StartBroadcast(const W8LiveBroadcastRequest& in) override { if(!IsAvailable()||theApp.emuledlg==NULL)return false; CString source=W8Text(in.source),title=W8Text(in.title),category=W8Text(in.category),language=W8Text(in.language),file=W8Text(in.file); LiveWebBroadcastReq req; req.action=LIVE_WEB_BC_LAUNCH; req.sourceType=source; req.title=title; req.category=category; req.language=language; req.mediaFilePath=file; req.bitrate=in.bitrate; req.ok=false; theApp.emuledlg->SendMessage(UM_LIVE_WEB_BROADCAST,0,(LPARAM)&req); return req.ok; } void BroadcastLiveness(bool& alive, int& chunks) const override { alive = false; chunks = 0; if (IsAvailable()) theApp.liveStreamManager->GetBroadcastLivenessStatus(alive, chunks); } bool StopBroadcast() override { if (!IsAvailable() || theApp.emuledlg == NULL) return false; LiveWebBroadcastReq req; req.action = LIVE_WEB_BC_STOP; req.sourceType = req.title = req.category = req.language = req.mediaFilePath = _T(""); req.bitrate = 0; req.ok = false; theApp.emuledlg->SendMessage(UM_LIVE_WEB_BROADCAST, 0, (LPARAM)&req); return req.ok; } bool CopyBroadcastKey(std::array<unsigned char, 16>& key) const override { return IsAvailable() && theApp.liveStreamManager->CopyBroadcastStreamKey(key.data()); } std::string PublicIPv4Text() const override { const uint32 ip=theApp.GetPublicIP(); return ip==0?std::string():W8Legacy(ipstr(ip)); } std::uint16_t AdvertisedPort() const override { return theApp.GetAdvertisedTcpPort(); } std::uint32_t NowMs() const override { return GetTickCount(); } void PauseMs(unsigned value) override { Sleep(value); } bool IsUnsupportedIPv6Socks4() const override { const ProxySettings& proxy = thePrefs.GetProxySettings(); return proxy.bUseProxy && (proxy.type == PROXYTYPE_SOCKS4 || proxy.type == PROXYTYPE_SOCKS4A); } bool IsUsableAddress(const std::string& text, bool ipv6) const override { const CStringA bytes(text.data(),static_cast<int>(text.size())); CAddress address(CString(bytes), false); uint32 ipv4 = 0; return ipv6 ? address.GetType() == CAddress::IPv6 && address.IsUsableDirectIPv6() : address.GetType() == CAddress::IPv4 && address.TryToUInt32(ipv4) && ipv4 != 0 && ipv4 != INADDR_NONE; } };
struct W8StatusContext { bool loopback; static bool ReadStatus(void*, ese::web::W8LiveStatusSnapshot&); static bool ReadChannel(void*, ese::web::W8LiveChannelSnapshot&); static bool ReadMesh(void*, ese::web::W8LiveMeshSnapshot&); static void Send(CWebSocket*, const std::string&, const std::string&); };
bool W8StatusContext::ReadStatus(void* raw, ese::web::W8LiveStatusSnapshot& out) { const W8StatusContext& context = *static_cast<W8StatusContext*>(raw); const char* forwarded = "unknown"; if (theApp.m_pUPnPFinder && theApp.m_pUPnPFinder->GetImplementation()) { const TRISTATE state = theApp.m_pUPnPFinder->GetImplementation()->ArePortsForwarded(); forwarded = state == TRIS_TRUE ? "true" : state == TRIS_FALSE ? "false" : "unknown"; } out.upnp_critical_error = thePrefs.GetUPnPCriticalError(); out.utp_hole_punch_enabled = thePrefs.GetUtpHolePunchEnabled(); out.web_upnp_active = thePrefs.GetWSUseUPnP(); out.upnp_ports_forwarded = forwarded; out.kad_connected = Kademlia::CKademlia::IsAnyConnected(); out.kad_configured_mask = thePrefs.GetKadNetworkMask(); out.kad_running_mask = Kademlia::CKademlia::GetRunningNetworkMask(); out.kad2_running = Kademlia::CKademlia::IsKad2Running(); out.kad2_connected = Kademlia::CKademlia::IsKad2Connected(); out.kad6_running = Kademlia::CKademlia::IsKad6Running(); out.kad6_connected = Kademlia::CKademlia::IsKad6Connected(); out.kad6_verified_contacts = Kademlia::CKademlia::GetKad6VerifiedContacts(); out.ed2k_connected = theApp.serverconnect && theApp.serverconnect->IsConnected(); if (context.loopback) { out.user_hash = W8Legacy(md4str(thePrefs.GetUserHash())); out.connecting_client_count = theApp.clientlist ? theApp.clientlist->GetConnectingClientCount() : 0; out.connecting_client_adds = theApp.clientlist ? theApp.clientlist->GetConnectingClientAdds() : 0; out.connecting_client_high_water = theApp.clientlist ? theApp.clientlist->GetConnectingClientHighWater() : 0; out.connecting_client_duplicate_adds = theApp.clientlist ? theApp.clientlist->GetConnectingClientDuplicateAdds() : 0; } const CKadKeepalive::Stats keepalive = CKadKeepalive::Instance().GetStats(); out.hole_punch_attempts=CStatistics::m_dwHolePunchAttempts; out.hole_punch_success=CStatistics::m_dwHolePunchSuccess; out.hole_punch_sym_nat_fail=CStatistics::m_dwHolePunchSymNATFail; out.hole_punch_encrypted=CStatistics::m_dwHolePunchEncrypted; out.hole_punch_plaintext=CStatistics::m_dwHolePunchPlaintext; out.hole_punch_req_recv=CStatistics::m_dwHolePunchReqRecv; out.hole_punch_challenge_sent=CStatistics::m_dwHolePunchChallengeSent; out.kad3_rdv_req_sent=CStatistics::m_dwKad3RdvReqSent; out.kad3_rdv_req_recv=CStatistics::m_dwKad3RdvReqRecv; out.kad3_rdv_challenge_sent=CStatistics::m_dwKad3RdvChallengeSent; out.kad3_rdv_fwd=CStatistics::m_dwKad3RdvFwd; out.kad3_rdv_success=CStatistics::m_dwKad3RdvSuccess; out.keepalive_running=CKadKeepalive::Instance().IsRunning(); out.keepalive_pings_sent=keepalive.pingsSent; out.keepalive_pongs_recv=keepalive.pongsReceived; out.keepalive_supernodes=keepalive.supernodesActive; out.netlab_consent=thePrefs.GetEseNetLabConsent()==CPreferences::EseNetLabAccepted?"accepted":thePrefs.GetEseNetLabConsent()==CPreferences::EseNetLabDeclined?"declined":"undecided"; out.netlab_advanced_consent=thePrefs.GetEseNetLabAdvancedConsent()==CPreferences::EseNetLabAccepted?"accepted":thePrefs.GetEseNetLabAdvancedConsent()==CPreferences::EseNetLabDeclined?"declined":"undecided"; out.netlab_contribution_consent=thePrefs.GetEseNetLabContributionConsent()==CPreferences::EseNetLabAccepted?"accepted":thePrefs.GetEseNetLabContributionConsent()==CPreferences::EseNetLabDeclined?"declined":"undecided"; out.netlab_enabled=thePrefs.IsEseNetLabActive(); return true; }
bool W8StatusContext::ReadChannel(void*, ese::web::W8LiveChannelSnapshot& out) { if (theApp.liveStreamManager == NULL) return true; const LiveChannelSnapshot snapshot = theApp.liveStreamManager->GetChannelSnapshot(); out.broadcasting=snapshot.broadcasting; memcpy(out.stream_key.data(), snapshot.streamKey, 16); out.title=W8Legacy(snapshot.title); out.category=W8Legacy(snapshot.category); out.language=W8Legacy(snapshot.language); out.started_at=snapshot.startedAt; out.viewer_count=snapshot.viewerCount; out.bitrate=snapshot.bitrate; return true; }
bool W8StatusContext::ReadMesh(void*, ese::web::W8LiveMeshSnapshot& out) { if (theApp.liveStreamManager == NULL) return true; const LiveDebugSnapshot snapshot = theApp.liveStreamManager->BuildDebugSnapshot(); out.mesh_peers=snapshot.meshPeers; out.pending_requests=snapshot.pendingRequests; out.chunks_served=snapshot.chunksServed; out.total_redistributed=snapshot.totalRedistributed; out.super_seeders=snapshot.superSeeders; out.middle_peers=snapshot.middlePeers; out.leaf_peers=snapshot.leafPeers; out.upload_floor=snapshot.minUploadRequired; out.emergency_mode=snapshot.emergencyMode; return true; }
void W8StatusContext::Send(CWebSocket* socket, const std::string& header, const std::string& body) { const std::string hardened=ese::web::HardenLiveResponseHeaders(header,true); const CStringA h(hardened.data(),static_cast<int>(hardened.size())),b(body.data(),static_cast<int>(body.size())); socket->SendData(h,h.GetLength()); socket->SendData(b,b.GetLength()); }
struct W9TransferContext { ese::web::WebAuthPolicy* auth; CUpDownClient* target; static std::uint64_t Now(void*); static W9LiveTransferRateDecision Rate(void*,W9LiveTransferRate,std::uint64_t,std::uint64_t); static bool ParseIPv4(void*,const std::string&,std::uint32_t&); static bool Read(void*,W9LiveTransferSnapshot&); static void Network(void*,bool,bool,bool&,bool&); static W9LiveTransferGuard Rendezvous(void*,std::uint32_t,std::uint16_t,std::uint32_t,std::uint16_t); static W9LiveTransferGuard Keepalive(void*,bool); static void Relay(void*,W9LiveRelayToggle,bool); static void RelayConnect(void*,const std::array<unsigned char,16>&,std::uint32_t,std::uint16_t); static W9LiveHolePunchResult HolePunch(void*,std::uint32_t,std::uint16_t,bool,int); };
std::uint64_t W9TransferContext::Now(void*) { return eSELive::WebRequestAuthNowMs(); }
W9LiveTransferRateDecision W9TransferContext::Rate(void* raw,W9LiveTransferRate action,std::uint64_t now,std::uint64_t interval) { ese::web::WebAction native=ese::web::WebAction::NetworkConnect; switch(action){case W9LiveTransferRate::NetworkConnect:break;case W9LiveTransferRate::ManualRendezvous:native=ese::web::WebAction::ManualRendezvous;break;case W9LiveTransferRate::KeepaliveToggle:native=ese::web::WebAction::KeepaliveToggle;break;case W9LiveTransferRate::ManualHolePunch:native=ese::web::WebAction::ManualHolePunch;break;} const ese::web::WebRateDecision result=static_cast<W9TransferContext*>(raw)->auth->CheckRateLimit(native,now,interval); return {result.allowed,result.retry_after_ms}; }
bool W9TransferContext::ParseIPv4(void*,const std::string& text,std::uint32_t& out) { out=static_cast<std::uint32_t>(inet_addr(text.c_str())); return out!=INADDR_NONE&&out!=0; }
bool W9TransferContext::Read(void*,W9LiveTransferSnapshot& out) { out=W9LiveTransferSnapshot(); out.ed2k_connected=theApp.serverconnect&&theApp.serverconnect->IsConnected(); out.ed2k_connecting=theApp.serverconnect&&theApp.serverconnect->IsConnecting(); out.kad_running=Kademlia::CKademlia::IsRunning(); out.kad_connected=Kademlia::CKademlia::IsAnyConnected(); out.kad_configured_mask=thePrefs.GetKadNetworkMask(); out.kad_running_mask=Kademlia::CKademlia::GetRunningNetworkMask(); out.kad2_running=Kademlia::CKademlia::IsKad2Running(); out.kad2_connected=Kademlia::CKademlia::IsConnected(); out.kad6_running=Kademlia::CKademlia::IsKad6Running(); out.kad6_connected=Kademlia::CKademlia::IsKad6Connected(); out.kad6_verified_contacts=Kademlia::CKademlia::GetKad6VerifiedContacts(); out.netlab_active=thePrefs.IsEseNetLabActive(); out.kad_udp_ready=Kademlia::CKademlia::GetUDPListener()!=NULL; out.utp_hole_punch_enabled=thePrefs.GetUtpHolePunchEnabled(); out.kad3_rendezvous_enabled=thePrefs.GetEseKad3Rendezvous(); out.client_utp_ready=theApp.clientudp&&theApp.clientudp->IsUtpReady(); const CKadKeepalive::Stats keep=CKadKeepalive::Instance().GetStats(); out.keepalive_running=CKadKeepalive::Instance().IsRunning(); out.keepalive_pings_sent=keep.pingsSent; out.keepalive_pongs_recv=keep.pongsReceived; out.keepalive_supernodes=keep.supernodesActive; out.relay_accept=thePrefs.GetEseRelayAccept(); out.relay_egress=thePrefs.GetEseRelayEgress(); out.relay_selector=thePrefs.GetEseReachSelector(); out.relay_req_recv=CStatistics::m_dwRelayReqRecv; out.relay_accepted=CStatistics::m_dwRelayAccepted; out.relay_active=CStatistics::m_dwRelayActive; out.relay_bytes_fwd_kb=CStatistics::m_dwRelayBytesFwdKB; out.relay_budget_drops=CStatistics::m_dwRelayBudgetDrops; out.relay_max_kbps=thePrefs.GetEseRelayMaxKBps(); out.reach_direct=CStatistics::m_dwReachConnDirect; out.reach_punch2=CStatistics::m_dwReachConnPunch2; out.reach_punch3=CStatistics::m_dwReachConnPunch3; out.reach_relay=CStatistics::m_dwReachConnRelay; out.hole_attempts=CStatistics::m_dwHolePunchAttempts; out.hole_success=CStatistics::m_dwHolePunchSuccess; out.hole_sym_nat_fail=CStatistics::m_dwHolePunchSymNATFail; out.hole_encrypted=CStatistics::m_dwHolePunchEncrypted; out.hole_plaintext=CStatistics::m_dwHolePunchPlaintext; out.hole_spray_reqs=CStatistics::m_dwHolePunchSprayReqs; out.hole_req_recv=CStatistics::m_dwHolePunchReqRecv; out.hole_challenge_sent=CStatistics::m_dwHolePunchChallengeSent; out.kad3_rdv_req_sent=CStatistics::m_dwKad3RdvReqSent; out.kad3_rdv_req_recv=CStatistics::m_dwKad3RdvReqRecv; out.kad3_rdv_challenge_sent=CStatistics::m_dwKad3RdvChallengeSent; out.kad3_rdv_fwd=CStatistics::m_dwKad3RdvFwd; out.kad3_rdv_success=CStatistics::m_dwKad3RdvSuccess; out.port_predict=thePrefs.GetEseHolePunchPortPredict(); out.port_predict_spread=static_cast<std::uint16_t>(thePrefs.GetEseHolePunchPortSpread()); return true; }
void W9TransferContext::Network(void*,bool ed2k,bool kad,bool& ed2kSent,bool& kadSent) { ed2kSent=kadSent=false; if(ed2k&&theApp.serverconnect&&!theApp.serverconnect->IsConnected()&&!theApp.serverconnect->IsConnecting()){SendMessage(theApp.emuledlg->m_hWnd,WEB_GUI_INTERACTION,WEBGUIIA_CONNECTTOSERVER,0);ed2kSent=true;} if(kad&&!Kademlia::CKademlia::IsRunning()){SendMessage(theApp.emuledlg->m_hWnd,WEB_GUI_INTERACTION,WEBGUIIA_KAD_START,0);kadSent=true;} }
W9LiveTransferGuard W9TransferContext::Rendezvous(void*,std::uint32_t rdv,std::uint16_t rdvPort,std::uint32_t target,std::uint16_t targetPort) { if(!Kademlia::CKademlia::IsConnected()||Kademlia::CKademlia::GetUDPListener()==NULL)return W9LiveTransferGuard::KadNotReady;if(!thePrefs.GetUtpHolePunchEnabled())return W9LiveTransferGuard::HolePunchDisabled;if(!thePrefs.GetEseKad3Rendezvous())return W9LiveTransferGuard::RendezvousDisabled;Kademlia::CKademlia::GetUDPListener()->InitiateKad3Rendezvous(ntohl(rdv),rdvPort,ntohl(target),targetPort);return W9LiveTransferGuard::Ok; }
W9LiveTransferGuard W9TransferContext::Keepalive(void*,bool start) { if(start&&!thePrefs.IsEseNetLabActive())return W9LiveTransferGuard::NetlabConsentRequired;if(start)CKadKeepalive::Instance().RequestStart();else CKadKeepalive::Instance().RequestStop();return W9LiveTransferGuard::Ok; }
void W9TransferContext::Relay(void*,W9LiveRelayToggle toggle,bool on) { if(toggle==W9LiveRelayToggle::Accept){thePrefs.SetEseRelayAccept(on);volatile LONG* caps=reinterpret_cast<volatile LONG*>(&g_uEseCapsRuntime);if(on)::InterlockedOr(caps,static_cast<LONG>(ESE_CAP_LIVE_RELAY));else ::InterlockedAnd(caps,~static_cast<LONG>(ESE_CAP_LIVE_RELAY));}else if(toggle==W9LiveRelayToggle::Egress)thePrefs.SetEseRelayEgress(on);else thePrefs.SetEseReachSelector(on); }
void W9TransferContext::RelayConnect(void*,const std::array<unsigned char,16>& key,std::uint32_t ip,std::uint16_t port) { CLiveBuddyRelay::Instance().RequestViewerConnect(key.data(),ip,port); }
W9LiveHolePunchResult W9TransferContext::HolePunch(void* raw,std::uint32_t ip,std::uint16_t port,bool validIp,int requestedSpread) { W9TransferContext& context=*static_cast<W9TransferContext*>(raw);W9LiveHolePunchResult result;result.attempts_before=CStatistics::m_dwHolePunchAttempts;context.target=theApp.clientlist?theApp.clientlist->FindClientByIP_KadPort(ip,port):NULL;if(context.target==NULL&&theApp.clientlist)context.target=theApp.clientlist->FindClientByIP(ip);if(!validIp||ip==INADDR_NONE||ip==0||port==0)result.guard=W9LiveTransferGuard::InvalidIpPort;else if(!thePrefs.IsEseNetLabActive())result.guard=W9LiveTransferGuard::NetlabConsentRequired;else if(context.target==NULL||!context.target->SupportsEseNetLabV1Target())result.guard=W9LiveTransferGuard::NetlabTargetRequired;else if(!Kademlia::CKademlia::IsConnected()||Kademlia::CKademlia::GetUDPListener()==NULL)result.guard=W9LiveTransferGuard::KadNotReady;else if(!thePrefs.GetUtpHolePunchEnabled())result.guard=W9LiveTransferGuard::HolePunchDisabled;else if(theApp.clientudp==NULL||!theApp.clientudp->IsUtpReady())result.guard=W9LiveTransferGuard::UtpNotReady;else{result.spread=requestedSpread>0?static_cast<std::uint16_t>(requestedSpread>8?8:requestedSpread):(thePrefs.GetEseHolePunchPortPredict()?static_cast<std::uint16_t>(thePrefs.GetEseHolePunchPortSpread()):0);Kademlia::CKademlia::GetUDPListener()->SendEseHolePunchReqSpray(ntohl(ip),port,result.spread,true,context.target);result.guard=W9LiveTransferGuard::Ok;}return result; }
static std::string W9Bytes(const CStringA& value) { return std::string(static_cast<LPCSTR>(value),value.GetLength()); }
struct W9SearchContext { static std::uint32_t Now(void*); static bool Sources(void*,std::uint64_t,std::uint64_t&,std::vector<ese::web::W9SourceEvent>&); static bool Add(void*,const std::array<std::uint8_t,32>&,const std::string&,std::string&); static bool Remove(void*,const std::array<std::uint8_t,32>&,std::string&); static bool List(void*,std::vector<ese::web::W9Subscription>&); static bool Tunnel(void*,const std::string&,std::string&,unsigned); static bool Diagnose(void*,const std::array<std::uint8_t,16>*,ese::web::W9DiagnoseSnapshot&); static void Refresh(void*); static bool Streams(void*,bool&,std::vector<ese::web::W9KadStream>&); };
std::uint32_t W9SearchContext::Now(void*) { return GetTickCount(); }
bool W9SearchContext::Sources(void*,std::uint64_t after,std::uint64_t& sequence,std::vector<ese::web::W9SourceEvent>& out) { sequence=0;out.clear();if(!theApp.downloadqueue)return true;std::vector<SSourceResolutionEvent> native;theApp.downloadqueue->GetSourceResolutionEvents(after,sequence,native);out.reserve(native.size());for(const SSourceResolutionEvent& item:native){ese::web::W9SourceEvent event;event.sequence=item.sequence;event.hostname_sha256=W9Bytes(item.hostnameSha256);event.file_ed2k_hash=W9Bytes(item.fileEd2kHash);event.port=item.port;event.resolver_result=W9Bytes(item.resolverResult);event.resolved_ipv4=item.resolvedIPv4Count;event.resolved_ipv6=item.resolvedIPv6Count;event.resolved_endpoint_set_sha256=W9Bytes(item.resolvedEndpointSetSha256);event.materialized_ipv4=item.materializedIPv4Count;event.materialized_ipv6=item.materializedIPv6Count;event.materialized_endpoint_set_sha256=W9Bytes(item.materializedEndpointSetSha256);event.simultaneously_retained=item.simultaneouslyRetained;event.candidates.reserve(item.candidates.size());for(const SSourceResolutionCandidateEvent& c:item.candidates)event.candidates.push_back({W9Bytes(c.family),W9Bytes(c.endpointSha256),W9Bytes(c.outcome),W9Bytes(c.sourceOrigin)});out.push_back(std::move(event));}return true; }
bool W9SearchContext::Add(void*,const std::array<std::uint8_t,32>& key,const std::string& name,std::string&) { eSELive::SubscriptionEntry entry={};memcpy(entry.channel_pubkey,key.data(),key.size());entry.name=CStringA(name.data(),static_cast<int>(name.size()));entry.added_unix_ts=static_cast<std::uint64_t>(time(NULL));entry.notifications=true;auto& store=eSELive::CLiveSubscriptionStore::Get();const bool added=store.Add(entry);if(added)store.Save();return added; }
bool W9SearchContext::Remove(void*,const std::array<std::uint8_t,32>& key,std::string&) { auto& store=eSELive::CLiveSubscriptionStore::Get();const bool removed=store.Remove(key.data());if(removed)store.Save();return removed; }
bool W9SearchContext::List(void*,std::vector<ese::web::W9Subscription>& out) { std::vector<eSELive::SubscriptionEntry> native;eSELive::CLiveSubscriptionStore::Get().GetAll(native);out.clear();out.reserve(native.size());for(const eSELive::SubscriptionEntry& item:native){ese::web::W9Subscription value;memcpy(value.pubkey.data(),item.channel_pubkey,value.pubkey.size());value.name=W9Bytes(item.name);value.added=item.added_unix_ts;out.push_back(std::move(value));}return true; }
bool W9SearchContext::Tunnel(void*,const std::string& keyword,std::string& reply,unsigned timeout) { return eSELive::CLiveTunnel::Get().TunneledKadSearch(keyword,reply,timeout); }
bool W9SearchContext::Diagnose(void*,const std::array<std::uint8_t,16>* key,ese::web::W9DiagnoseSnapshot& out) { out=ese::web::W9DiagnoseSnapshot();out.kad_connected=Kademlia::CKademlia::IsConnected();out.broadcasting=theApp.liveStreamManager&&theApp.liveStreamManager->IsBroadcasting();out.viewing=theApp.liveStreamManager&&theApp.liveStreamManager->IsViewingLive();const std::uint32_t publicIp=theApp.GetPublicIP();out.public_ip_available=publicIp!=0;out.public_ip=W8Legacy(ipstr(publicIp));out.tcp_port=theApp.GetAdvertisedTcpPort();if(key&&theApp.liveStreamManager){LiveStreamEntry entry;if(theApp.liveStreamManager->GetKadBridge().GetStreamInfo(key->data(),entry)){out.in_directory=true;out.entry.title=W8Legacy(entry.title);out.entry.broadcaster_ip=W8Legacy(ipstr(entry.broadcasterIP));out.entry.broadcaster_port=entry.broadcasterPort;out.entry.bitrate=entry.bitrate;out.entry.viewers=entry.viewerCount;out.entry.last_seen_age_ms=GetTickCount()-entry.lastSeen;out.entry.own=entry.isOwnStream;}}out.directory_size=theApp.liveStreamManager?static_cast<std::uint32_t>(theApp.liveStreamManager->GetKadBridge().GetDirectoryCount()):0;return true; }
void W9SearchContext::Refresh(void*) { if(theApp.liveStreamManager&&theApp.emuledlg)theApp.emuledlg->PostMessage(UM_LIVE_KAD_REFRESH); }
bool W9SearchContext::Streams(void*,bool& kad,std::vector<ese::web::W9KadStream>& out) { CArray<LiveStreamEntry> native;if(theApp.liveStreamManager)theApp.liveStreamManager->GetKadBridge().GetKnownStreams(native);kad=Kademlia::CKademlia::IsConnected();out.clear();out.reserve(static_cast<std::size_t>(native.GetCount()));for(INT_PTR i=0;i<native.GetCount();++i){const LiveStreamEntry& item=native[i];ese::web::W9KadStream value;memcpy(value.key.data(),item.streamKey,value.key.size());value.title=W8Legacy(item.title);value.category=W8Legacy(item.category);value.language=W8Legacy(item.language);value.bitrate=item.bitrate;value.viewers=item.viewerCount;value.broadcaster_ip=item.broadcasterIP;value.broadcaster_port=item.broadcasterPort;value.started_at=item.startedAt;value.last_seen=item.lastSeen;value.own=item.isOwnStream;value.kad6_tunnel=item.privacyOrigin==ESE_PRIV_ORIGIN_KAD6_TUNNEL;out.push_back(std::move(value));}return true; }
using Kademlia::CKadV2Mode; using Kademlia::CKadV2ModeSelector;
static CString W10Text(const std::string& value) { return W8Text(value); }
struct W10SettingsContext { static bool ReadNetlab(void*,W10NetlabSnapshot&); static bool Consent(void*); static void Apply(void*,bool); static void Refresh(void*); static void Keepalive(void*,bool); static bool PersistDisable(void*); static bool Save(void*); static void Post(void*); static bool ReadPrivacy(void*,W10PrivacySnapshot&); static void SetMode(void*,const std::string&); static void SetFallback(void*,const std::string&); static void Add(void*,const std::string&); static void Remove(void*,const std::string&); static void Mirror(void*); static bool ReadRuntime(void*,W10PrivacySnapshot&); static void Edge(void*,bool,int,std::uint32_t); static W10SettingsPort Port(); };
bool W10SettingsContext::ReadNetlab(void*,W10NetlabSnapshot& o) { o=W10NetlabSnapshot();o.consent=thePrefs.GetEseNetLabConsent()==CPreferences::EseNetLabAccepted?"accepted":thePrefs.GetEseNetLabConsent()==CPreferences::EseNetLabDeclined?"declined":"undecided";o.advanced_consent=thePrefs.GetEseNetLabAdvancedConsent()==CPreferences::EseNetLabAccepted?"accepted":thePrefs.GetEseNetLabAdvancedConsent()==CPreferences::EseNetLabDeclined?"declined":"undecided";o.contribution_consent=thePrefs.GetEseNetLabContributionConsent()==CPreferences::EseNetLabAccepted?"accepted":thePrefs.GetEseNetLabContributionConsent()==CPreferences::EseNetLabDeclined?"declined":"undecided";o.enabled=thePrefs.IsEseNetLabActive();o.capability_advertised=(g_uEseCapsRuntime&ESE_CAP_NETLAB_V1)!=0;o.ipv6_auto=thePrefs.IsIPv6Enabled();o.hole_punch=thePrefs.GetUtpHolePunchEnabled();o.auto_keepalive=thePrefs.GetEseAutoKeepalive();o.selector=thePrefs.GetEseReachSelector();o.port_predict=thePrefs.GetEseHolePunchPortPredict();o.ed2k_punch3=thePrefs.GetEseEd2kPunch3();o.kad3_rendezvous=thePrefs.GetEseKad3Rendezvous();o.relay_accept=thePrefs.GetEseRelayAccept();o.relay_egress=thePrefs.GetEseRelayEgress();o.krp=thePrefs.GetKrpRelayEnabled();o.kad6_beta_exit=thePrefs.GetKad6BetaExitOptIn();o.kad6_stable_public_exit=thePrefs.GetKad6PublicExitOptIn();o.keepalive_running=CKadKeepalive::Instance().IsRunning();o.experimental=thePrefs.GetEseV9Experimental();o.hole_punch_master=thePrefs.GetUtpHolePunchEnabled();o.reach_direct=CStatistics::m_dwReachConnDirect;o.reach_punch2=CStatistics::m_dwReachConnPunch2;o.reach_punch3=CStatistics::m_dwReachConnPunch3;o.reach_relay=CStatistics::m_dwReachConnRelay;return true; }
bool W10SettingsContext::Consent(void*) { return thePrefs.GetEseNetLabConsent()==CPreferences::EseNetLabAccepted; }
void W10SettingsContext::Apply(void*,bool on) { thePrefs.ApplyEseNetLabPreferenceState(on); }
void W10SettingsContext::Refresh(void*) { RefreshEseV9PreviewCaps(); }
void W10SettingsContext::Keepalive(void*,bool on) { if(on)CKadKeepalive::Instance().RequestStart();else CKadKeepalive::Instance().RequestStop(); }
bool W10SettingsContext::PersistDisable(void*) { CIni ini(CPreferences::GetConfigFile(),_T("eMule"));ini.WriteBool(_T("EseNetLabEnabled"),false,_T("eSE"));return !ini.GetBool(_T("EseNetLabEnabled"),true,_T("eSE")); }
bool W10SettingsContext::Save(void*) { return CPreferences::Save()!=0; }
void W10SettingsContext::Post(void*) { if(theApp.emuledlg!=NULL&&::IsWindow(theApp.emuledlg->GetSafeHwnd()))::PostMessage(theApp.emuledlg->GetSafeHwnd(),UM_KRP_CLIENT_EVENT,0,0); }
bool W10SettingsContext::ReadPrivacy(void*,W10PrivacySnapshot& o) { CKadV2ModeSelector& s=CKadV2ModeSelector::Get();o=W10PrivacySnapshot();o.mode=s.GetDefaultMode()==CKadV2Mode::Direct?"direct":s.GetDefaultMode()==CKadV2Mode::Tunneled?"tunneled":"adaptive";o.fallback=s.GetFallbackPolicy()==CKadV2ModeSelector::STRICT_PRIVACY?"strict":s.GetFallbackPolicy()==CKadV2ModeSelector::BEST_EFFORT?"best_effort":"balanced";std::vector<CStringW> keys;s.GetSensitiveKeywords(keys);o.sensitive_keywords.reserve(keys.size());for(const CStringW& key:keys)o.sensitive_keywords.push_back(W8Legacy(CString(key)));o.caps_bits=g_uEseCapsRuntime;struct Cap{std::uint32_t bit;const char* name;};const Cap caps[]={{ESE_CAP_M1_SUBSCRIBER_PIN,"M1_subscriber_pin"},{ESE_CAP_M2_COMPOSITE_KEYS,"M2_composite_keys"},{ESE_CAP_M3_SHARDING,"M3_sharding"},{ESE_CAP_M4_TRIGRAMS,"M4_trigrams"},{ESE_CAP_M5_BLOOM_GOSSIP,"M5_bloom_gossip"},{ESE_CAP_M6_K_EFFECTIVE,"M6_k_effective"},{ESE_CAP_PRIVACY_TUNNELING,"privacy_tunneling"},{ESE_CAP_SEALED_RECORDS,"sealed_records"},{ESE_CAP_GOSSIP_PROTOCOL,"gossip_protocol"},{ESE_CAP_COVER_TRAFFIC,"cover_traffic"},{ESE_CAP_TUNNEL_AUTH,"tunnel_auth"},{ESE_CAP_KAD6,"kad6"},{ESE_CAP_TUNNEL_STRICT3,"tunnel_strict3"},{ESE_CAP_TUNNEL_SHAPED,"tunnel_shaped"},{ESE_CAP_NETLAB_V1,"netlab_v1"}};for(const Cap& cap:caps)if(o.caps_bits&cap.bit)o.caps_human.push_back(cap.name);o.kad6_preferred=s.GetDefaultMode()!=CKadV2Mode::Direct;return true; }
void W10SettingsContext::SetMode(void*,const std::string& value) { CKadV2ModeSelector::Get().SetDefaultMode(value=="direct"?CKadV2Mode::Direct:value=="tunneled"?CKadV2Mode::Tunneled:CKadV2Mode::Adaptive); }
void W10SettingsContext::SetFallback(void*,const std::string& value) { CKadV2ModeSelector::Get().SetFallbackPolicy(value=="strict"?CKadV2ModeSelector::STRICT_PRIVACY:value=="best_effort"?CKadV2ModeSelector::BEST_EFFORT:CKadV2ModeSelector::BALANCED); }
void W10SettingsContext::Add(void*,const std::string& value) { CKadV2ModeSelector::Get().AddSensitiveKeyword(W10Text(value)); }
void W10SettingsContext::Remove(void*,const std::string& value) { CKadV2ModeSelector::Get().RemoveSensitiveKeyword(W10Text(value)); }
void W10SettingsContext::Mirror(void*) { CKadV2ModeSelector& s=CKadV2ModeSelector::Get();thePrefs.SetKadV2PrivacyMode(static_cast<int>(s.GetDefaultMode()));thePrefs.SetKadV2FallbackPolicy(static_cast<int>(s.GetFallbackPolicy()));std::vector<CStringW> keys;s.GetSensitiveKeywords(keys);CString joined;for(const CStringW& item:keys){CString key(item);key.Replace(_T("|"),_T(" "));if(!joined.IsEmpty())joined+=_T("|");joined+=key;}thePrefs.SetKadV2SensitiveKeywords(joined); }
bool W10SettingsContext::ReadRuntime(void*,W10PrivacySnapshot& o) { try{eSELive::CLiveTunnel& t=eSELive::CLiveTunnel::Get();o.circuits_active=static_cast<std::uint32_t>(t.ActiveCircuitCount());o.circuits_pending=static_cast<std::uint32_t>(t.PendingCircuitCount());o.tunnel_pool_size=static_cast<std::uint32_t>(Kademlia::CKadV2TunnelPool::Get().Size());o.subscriptions_loaded=static_cast<std::uint32_t>(eSELive::CLiveSubscriptionStore::Get().Count());CAddress v6=CFirewallProberV6::Instance().GetDetectedV6IP();if(!v6.IsNull())o.public_ipv6=W9Bytes(CStringA(v6.ToStringC()));o.kad6_circuit_active=t.HasActiveCircuitWithExitCaps(ESE_CAP_KAD6);o.cells_sent=t.CellsSentTotal();o.cells_recv=t.CellsRecvTotal();o.bytes_sent=t.BytesSentTotal();o.bytes_recv=t.BytesRecvTotal();o.mean_rtt_ms=t.MeanRttMs();}catch(...){ }o.route_state=!o.kad6_preferred?"kad2_direct":o.kad6_circuit_active?"kad6":o.circuits_active!=0?"tunnel_kad2_compat":o.fallback=="strict"?"blocked_waiting_kad6":"kad2_fallback";return true; }
#ifdef ESE_TEST_HOOKS
void W10SettingsContext::Edge(void*,bool on,int mode,std::uint32_t delay) { extern bool g_eseTestSabotageOn;extern int g_eseTestSabotageMode;extern DWORD g_eseTestSabotageDelayMs;g_eseTestSabotageOn=on;g_eseTestSabotageMode=mode;g_eseTestSabotageDelayMs=delay; }
#else
void W10SettingsContext::Edge(void*,bool,int,std::uint32_t) {}
#endif
W10SettingsPort W10SettingsContext::Port() { W10SettingsPort p={nullptr,W10SettingsContext::ReadNetlab,W10SettingsContext::Consent,W10SettingsContext::Apply,W10SettingsContext::Refresh,W10SettingsContext::Keepalive,W10SettingsContext::PersistDisable,W10SettingsContext::Save,W10SettingsContext::Post,W10SettingsContext::ReadPrivacy,W10SettingsContext::SetMode,W10SettingsContext::SetFallback,W10SettingsContext::Add,W10SettingsContext::Remove,W10SettingsContext::Mirror,W10SettingsContext::ReadRuntime,false,nullptr};
#ifdef ESE_TEST_HOOKS
p.test_hooks_enabled=true;p.set_edge_sabotage=W10SettingsContext::Edge;
#endif
return p; }
struct W10DiagnosticsContext { bool metrics_available=false; static bool Krp(void*,std::string&); static bool Reach(void*,std::string&); static bool Preflight(void*,ese::web::W10PreflightSnapshot&); static bool Metrics(void*,ese::web::W10MetricsSnapshot&); static void Percentiles(void*,std::uint32_t&,std::uint32_t&,std::uint32_t&); static std::uint32_t Mean(void*); static int Samples(void*); static bool Kad6(void*,std::string&); static bool Log(void*,int,std::vector<std::string>&); static bool Debug(void*,ese::web::W10DebugSnapshot&); static bool Ipv6Echo(void*,const ese::web::W10DiagnosticsRequest&,ese::web::W10Ipv6EchoResult&); };
bool W10DiagnosticsContext::Krp(void*,std::string& o) { if(theApp.relayclient==NULL)return false;CStringA json;theApp.relayclient->GetStatusJson(json);o=W9Bytes(json);return true; }
bool W10DiagnosticsContext::Reach(void*,std::string& o) { if(theApp.directreachability==NULL)return false;CStringA json;theApp.directreachability->GetStatusJson(json);if(json.IsEmpty())return false;o=W9Bytes(json);return true; }
bool W10DiagnosticsContext::Preflight(void*,ese::web::W10PreflightSnapshot& o) { o=ese::web::W10PreflightSnapshot();o.kad_connected=Kademlia::CKademlia::IsConnected();const bool verified=Kademlia::CUDPFirewallTester::IsVerified();o.kad_firewalled=theApp.IsFirewalled();o.ed2k_lowid=!theApp.HasVerifiedEd2kHighId();o.high_id=!o.ed2k_lowid;o.firewall_checking=!verified&&o.kad_connected&&o.ed2k_lowid;o.max_upload_kbs=thePrefs.GetMaxUpload();o.port=theApp.GetAdvertisedTcpPort();const std::uint32_t ip=theApp.GetPublicIP();if(ip!=0)o.public_ip=W8Legacy(ipstr(ip));const CString ffmpeg=CRTMPIngest::FindFFmpeg();o.ffmpeg_found=GetFileAttributes(ffmpeg)!=INVALID_FILE_ATTRIBUTES;o.ffmpeg_path=W8Legacy(ffmpeg);try{const CAddress v6=CFirewallProberV6::Instance().GetDetectedV6IP();if(!v6.IsNull())o.public_ip_v6=W9Bytes(CStringA(v6.ToStringC()));}catch(...){ }return true; }
bool W10DiagnosticsContext::Metrics(void* raw,ese::web::W10MetricsSnapshot& o) { W10DiagnosticsContext& c=*static_cast<W10DiagnosticsContext*>(raw);o=ese::web::W10MetricsSnapshot();c.metrics_available=theApp.liveStreamManager!=NULL;if(!c.metrics_available)return true;const LiveDebugSnapshot s=theApp.liveStreamManager->BuildDebugSnapshot();o.chunks_received=s.counters.chunksReceived;o.chunks_requested=s.counters.chunksRequested;o.chunks_missing=s.counters.chunksMissing;o.chunks_served=s.chunksServed;o.kad_publishes=s.counters.kadPublishes;o.kad_searches=s.counters.kadSearches;o.peer_disconnects=s.counters.peerDisconnects;o.view_peers=s.viewPeers;o.broadcast_peers=s.broadcastPeers;o.mesh_peers=s.meshPeers;o.buffer_count=s.bufCount;o.pending_requests=s.pendingRequests;o.broadcasting=s.broadcasting;o.viewing=s.viewing;o.kad_searches_empty=s.counters.kadSearchesEmpty;o.kad_searches_rate_limited=s.counters.kadSearchesRateLimited;o.pending_dials_dropped=s.counters.pendingDialsDropped;o.join_first_count=s.counters.joinToFirstChunkSamples;o.join_first_sum=s.counters.joinToFirstChunkSumMs;return true; }
void W10DiagnosticsContext::Percentiles(void* raw,std::uint32_t& p50,std::uint32_t& p95,std::uint32_t& p99) { if(static_cast<W10DiagnosticsContext*>(raw)->metrics_available){DWORD a=0,b=0,c=0;theApp.liveStreamManager->ChunkArrivalLatency().Percentiles(a,b,c);p50=a;p95=b;p99=c;} }
std::uint32_t W10DiagnosticsContext::Mean(void* raw) { return static_cast<W10DiagnosticsContext*>(raw)->metrics_available?theApp.liveStreamManager->ChunkArrivalLatency().Mean():0; }
int W10DiagnosticsContext::Samples(void* raw) { return static_cast<W10DiagnosticsContext*>(raw)->metrics_available?theApp.liveStreamManager->ChunkArrivalLatency().SampleCount():0; }
bool W10DiagnosticsContext::Kad6(void*,std::string& o) { o=eSELive::CLiveTunnel::Get().GetK6PrometheusMetrics();return true; }
bool W10DiagnosticsContext::Log(void*,int n,std::vector<std::string>& o) { std::deque<CStringA> native;CLiveDebugLog::Get().GetRecent(n,native);o.clear();o.reserve(native.size());for(const CStringA& item:native)o.push_back(W9Bytes(item));return true; }
bool W10DiagnosticsContext::Debug(void*,ese::web::W10DebugSnapshot& o) { o=ese::web::W10DebugSnapshot();if(theApp.liveStreamManager==NULL)return true;const LiveDebugSnapshot s=theApp.liveStreamManager->BuildDebugSnapshot();o.available=true;o.broadcasting=s.broadcasting;o.viewing=s.viewing;o.emergency_mode=s.emergencyMode;o.uptime_ms=s.uptimeMs;o.total_redistributed=s.totalRedistributed;o.now_ms=GetTickCount();o.kad_connected=s.kad.kadConnected;o.known_streams=s.kad.knownStreams;o.known_streams_clean=s.kad.knownStreamsClean;o.known_streams_legacy=s.kad.knownStreamsLegacy;o.last_publish_time=s.kad.lastPublishTime;o.last_search_time=s.kad.lastSearchTime;o.last_result_time=s.kad.lastResultTime;o.last_result_ip=s.kad.lastResultIP;o.last_result_port=s.kad.lastResultPort;o.view_peers=s.viewPeers;o.broadcast_peers=s.broadcastPeers;o.mesh_peers=s.meshPeers;o.pending_requests=s.pendingRequests;o.chunks_served=s.chunksServed;o.super_seeders=s.superSeeders;o.middle_peers=s.middlePeers;o.leaf_peers=s.leafPeers;o.chunk_count=s.bufCount;o.oldest_sequence=s.oldestSeq;o.newest_sequence=s.newestSeq;o.chunk_bitmap=s.bitmap;o.missing_chunks=s.missingChunks;o.max_capacity=ESE_LIVE_MAX_SEGMENTS;o.hls_segments_written=s.counters.hlsSegmentsWritten;o.hls_playlist_refreshes=s.counters.hlsPlaylistRefresh;o.last_chunk_received_at=static_cast<std::uint32_t>(s.counters.lastChunkReceivedAt);o.segment_duration_seconds=ESE_LIVE_SEGMENT_DURATION;o.kad_publishes=s.counters.kadPublishes;o.kad_searches=s.counters.kadSearches;o.kad_results_accepted=s.counters.kadResultsAccepted;o.kad_results_rejected=s.counters.kadResultsRejected;o.source_dial_attempts=s.counters.sourceDialAttempts;o.subscribe_sent=s.counters.subscribeSent;o.subscribe_accepted=s.counters.subscribeAccepted;o.chunks_requested=s.counters.chunksRequested;o.chunks_received=s.counters.chunksReceived;o.chunks_missing=s.counters.chunksMissing;o.duplicate_chunks_received=s.counters.duplicateChunksReceived;o.requests_suppressed_inflight=s.counters.requestsSuppressedInflight;o.peer_disconnects=s.counters.peerDisconnects;o.skipped_initial_pushes=s.counters.skippedInitialPushes;o.subscribes_rate_limited=s.counters.subscribesRateLimited;o.requests_rate_limited=s.counters.requestsRateLimited;o.ends_rejected_no_auth=s.counters.endsRejectedNoAuth;o.tombstones_evicted=s.counters.tombstonesEvicted;const int count=(std::max)(0,(std::min)(s.peerDetailCount,LiveDebugSnapshot::MAX_PEER_DBG));o.peer_detail.reserve(static_cast<std::size_t>(count));for(int i=0;i<count;++i)o.peer_detail.push_back({s.peerDetail[i].ip,s.peerDetail[i].port,s.peerDetail[i].level,s.peerDetail[i].failCount,s.peerDetail[i].respPct,s.peerDetail[i].rttMs});return true; }
bool W10DiagnosticsContext::Ipv6Echo(void*,const ese::web::W10DiagnosticsRequest& q,ese::web::W10Ipv6EchoResult& o) {
	o=ese::web::W10Ipv6EchoResult();o.tcp_port=q.tcp_port;o.udp_port=q.udp_port;
	bool nonceValid=q.nonce.size()==32;for(char c:q.nonce)nonceValid=nonceValid&&((c>='0'&&c<='9')||(c>='a'&&c<='f')||(c>='A'&&c<='F'));if(nonceValid)o.nonce=q.nonce;
	const CString targetText=W8Text(q.target);CAddress targetAddress;const bool addressParsed=targetAddress.FromString(targetText,false);const bool targetAllowed=addressParsed&&targetAddress.GetType()==CAddress::IPv6&&!targetAddress.IsMappedIPv4()&&(targetAddress.IsPublicIP()||(thePrefs.IsEseNetLabContributionActive()&&targetAddress.IsUniqueLocalIPv6()));
	if(!thePrefs.IsEseNetLabContributionActive())o.error="netlab_contribution_required";else if(!targetAllowed)o.error="native_ipv6_literal_required";else if(q.tcp_port<1024||q.tcp_port>65535||q.udp_port<1024||q.udp_port>65535)o.error="invalid_port";else if(!nonceValid)o.error="nonce_must_be_32_hex";else if(q.timeout_ms<1000||q.timeout_ms>8000)o.error="invalid_timeout";else{
		static volatile LONG lastProbe=0;const DWORD now=GetTickCount();bool admitted=false;for(;;){const LONG previous=InterlockedCompareExchange(&lastProbe,0,0);if(previous!=0&&(DWORD)(now-static_cast<DWORD>(previous))<2000u)break;if(InterlockedCompareExchange(&lastProbe,static_cast<LONG>(now),previous)==previous){admitted=true;break;}}if(!admitted){o.error="rate_limited";return true;}
		o.target=W9Bytes(CStringA(targetAddress.ToStringC()));std::string payloadText="ese-v91-i08-v1:"+q.nonce+"|target="+o.target;const std::vector<std::uint8_t> payload(payloadText.begin(),payloadText.end());sockaddr_storage tcpTarget,udpTarget;memset(&tcpTarget,0,sizeof(tcpTarget));memset(&udpTarget,0,sizeof(udpTarget));int tcpLength=sizeof(tcpTarget),udpLength=sizeof(udpTarget);if(!targetAddress.TryToSA(reinterpret_cast<sockaddr*>(&tcpTarget),&tcpLength,static_cast<std::uint16_t>(q.tcp_port))||!targetAddress.TryToSA(reinterpret_cast<sockaddr*>(&udpTarget),&udpLength,static_cast<std::uint16_t>(q.udp_port)))o.error="sockaddr_conversion_failed";else{unsigned tcpBytes=0,udpBytes=0;const bool tcpOk=EseI08TcpEcho(reinterpret_cast<sockaddr*>(&tcpTarget),tcpLength,payload,static_cast<DWORD>(q.timeout_ms),tcpBytes,o.tcp_error);const bool udpOk=EseI08UdpEcho(reinterpret_cast<sockaddr*>(&udpTarget),udpLength,targetAddress,static_cast<std::uint16_t>(q.udp_port),payload,static_cast<DWORD>(q.timeout_ms),udpBytes,o.udp_error);o.tcp_bytes=tcpBytes;o.udp_bytes=udpBytes;o.success=tcpOk&&udpOk;if(!o.success)o.error="echo_failed";}
	}return true;
}
}

struct W11LegacyContext {
	static bool Hls(void*,const ese::web::W11LegacyRequest& q,ese::web::W11HlsSnapshot& o){TCHAR tmp[MAX_PATH];GetTempPath(MAX_PATH,tmp);o.root_path=W8Utf8(CString(tmp))+"eMule_RTMP";CString p=OptUtf8ToStr(o.root_path.c_str(),static_cast<int>(o.root_path.size()))+_T("\\")+OptUtf8ToStr(q.resource.c_str(),static_cast<int>(q.resource.size()));o.root_exists=PathFileExists(p)!=FALSE;if(!o.root_exists&&theApp.liveStreamManager){std::array<unsigned char,16> key;if(theApp.liveStreamManager->CopyViewerStreamKey(key.data()))o.viewer_key=W8EncodeKey16(key);}return true;}
	static void Note(void*){if(theApp.liveStreamManager)theApp.liveStreamManager->NotePlayerFetch();}
	static bool Netlab(void*,ese::web::W11NetlabReportSnapshot& o){o=ese::web::W11NetlabReportSnapshot();const CAddress v6=CFirewallProberV6::Instance().GetDetectedV6IP();o.version=W9Bytes(CStringA(CT2A(theApp.m_strCurVersionLong)));o.consent=thePrefs.GetEseNetLabConsent()==CPreferences::EseNetLabAccepted?"accepted":thePrefs.GetEseNetLabConsent()==CPreferences::EseNetLabDeclined?"declined":"undecided";o.enabled=thePrefs.IsEseNetLabActive();o.has_ipv4=theApp.GetPublicIP()!=0;o.has_ipv6=v6.GetType()==CAddress::IPv6&&v6.IsPublicIP();o.firewalled=theApp.IsFirewalled();o.kad_connected=Kademlia::CKademlia::IsConnected();const CKadKeepalive::Stats ka=CKadKeepalive::Instance().GetStats();o.keepalive_running=CKadKeepalive::Instance().IsRunning();o.keepalive_pings=ka.pingsSent;o.keepalive_pongs=ka.pongsReceived;o.keepalive_peers=ka.supernodesActive;o.utp_sockets=static_cast<std::uint32_t>(CUtpSocket::GetConnectedSocketCount());o.utp_connected=o.utp_sockets!=0;o.hole_attempts=CStatistics::m_dwHolePunchAttempts;o.hole_success=CStatistics::m_dwHolePunchSuccess;o.hole_sym_nat_fail=CStatistics::m_dwHolePunchSymNATFail;o.hole_spray=CStatistics::m_dwHolePunchSprayReqs;o.kad3_requests=CStatistics::m_dwKad3RdvReqSent;o.kad3_forwarded=CStatistics::m_dwKad3RdvFwd;o.kad3_success=CStatistics::m_dwKad3RdvSuccess;o.session_received=theStats.sessionReceivedBytes;o.session_sent=theStats.sessionSentBytes;o.relay_kb=CStatistics::m_dwRelayBytesFwdKB;return true;}
	static bool Echo(void*,const std::vector<std::uint8_t>& in,std::vector<std::uint8_t>& out){try{return eSELive::CLiveTunnel::Get().TunnelEchoLarge(in,out,15000);}catch(...){return false;}}
	static bool Ping(void*,const std::string& in,std::string& out){try{return eSELive::CLiveTunnel::Get().TunnelPing(in,out,5000);}catch(...){return false;}}
	static bool Circuits(void*,std::vector<ese::web::W11CircuitSnapshot>& out){out.clear();try{std::vector<eSELive::CLiveTunnel::CircuitSnapshot> all;eSELive::CLiveTunnel::Get().GetCircuitsSnapshot(all);out.reserve(all.size());for(const auto&s:all)out.push_back({s.circ_id,s.age_ms,s.next_circ_id,static_cast<std::uint16_t>(s.hop_count),static_cast<unsigned>(s.role),static_cast<unsigned>(s.state),static_cast<unsigned>(s.abort_reason),s.next_hop_set!=0,s.auth_ok!=0,s.strict3!=0,s.shaped!=0,s.shaping_exposed!=0});}catch(...){}return true;}
	static bool Peers(void*,std::vector<ese::web::W11PeerSnapshot>& out,std::size_t& count){out.clear();count=0;try{std::vector<eSELive::CLiveTunnel::PeerSnapshot> all;eSELive::CLiveTunnel::Get().GetPeersSnapshot(all,count);out.reserve(all.size());for(const auto&p:all)out.push_back({p.has_ipv4?W8Legacy(CString(CAddress::FromIPv4NetworkOrder(p.ip).ToString().c_str())):std::string(),p.address,p.port,p.fork_caps,p.ese_caps,p.auth_ready,p.hash_ready,p.node_pub_ready,p.auth_cap,p.dataplane_cap});}catch(...){}return true;}
	static bool Test(void*,unsigned hops,std::uint32_t& id){id=0;try{id=eSELive::CLiveTunnel::Get().RequestTestCircuit(hops,2500);}catch(...){}return id!=0;}
	static bool Consume(void*,const std::string& text){return eSELive::CLiveTunnel::Get().ConsumeK6ReleaseOperatorChallenge(text);}
	static bool Digest(const std::string& text,kad6::Hash32& out){if(text.size()!=64)return false;for(size_t i=0;i<32;++i){const char a=text[i*2],b=text[i*2+1];const int hi=a>='0'&&a<='9'?a-'0':a>='a'&&a<='f'?a-'a'+10:a>='A'&&a<='F'?a-'A'+10:-1,lo=b>='0'&&b<='9'?b-'0':b>='a'&&b<='f'?b-'a'+10:b>='A'&&b<='F'?b-'A'+10:-1;if(hi<0||lo<0)return false;out[i]=static_cast<uint8_t>((hi<<4)|lo);}return true;}
	static bool Release(void*,bool enabled,const ese::web::W11ReleaseEvidence* in,std::uint32_t drain){kad6::K6ReleaseEvidence native;const kad6::K6ReleaseEvidence* p=NULL;if(in){if(!Digest(in->field_sha256,native.field_digest)||!Digest(in->audit_sha256,native.external_audit_digest))return false;native.observed_from=in->observed_from;native.observed_to=in->observed_to;native.admission_attempts=in->admission_attempts;native.admission_success_ppm=in->admission_ppm;native.useful_headroom_bps=in->headroom_bps;native.gate_mask=in->gate_mask;native.valid_until=in->valid_until;p=&native;}try{return eSELive::CLiveTunnel::Get().RequestK6PublicRelease(enabled,p,drain,5000);}catch(...){return false;}}
	static bool ReadRelease(void*,bool local,ese::web::W11ReleaseSnapshot& o){o=ese::web::W11ReleaseSnapshot();eSELive::CLiveTunnel::K6ReleaseRuntimeSnapshot s;try{eSELive::CLiveTunnel::Get().GetK6ReleaseSnapshot(s);}catch(...){}o.status=kad6::K6ReleaseGateStatusName(s.status);o.operator_opt_in=s.operator_opt_in;o.evidence_present=s.evidence_present;o.evidence_valid=s.evidence_valid;o.runtime_healthy=s.runtime_healthy;o.public_exit_enabled=s.public_exit_enabled;o.beta_exit_opt_in=s.beta_exit_opt_in;o.beta_exit_enabled=s.beta_exit_enabled;o.evidence.gate_mask=s.evidence.gate_mask;o.evidence.observed_from=s.evidence.observed_from;o.evidence.observed_to=s.evidence.observed_to;o.evidence.valid_until=s.evidence.valid_until;o.evidence.admission_attempts=s.evidence.admission_attempts;o.evidence.admission_ppm=s.evidence.admission_success_ppm;o.evidence.headroom_bps=s.evidence.useful_headroom_bps;if(local)try{eSELive::CLiveTunnel::Get().GetK6ReleaseOperatorChallenge(o.challenge);}catch(...){o.challenge.clear();}return true;}
	static bool Hardening(void*,const std::string& service,bool enabled,std::uint32_t drain){kad6::K6Service s=service=="control"?kad6::K6Service::Control:service=="exit_kad"?kad6::K6Service::ExitKad:service=="exit_ed2k_dial"?kad6::K6Service::ExitEd2kDial:kad6::K6Service::ExitEd2kFull;try{return eSELive::CLiveTunnel::Get().RequestK6ServiceSwitch(s,enabled,drain,3500);}catch(...){return false;}}
	static bool ReadHardening(void*,ese::web::W11HardeningSnapshot& o){o=ese::web::W11HardeningSnapshot();eSELive::CLiveTunnel::K6HardeningRuntimeSnapshot s;try{eSELive::CLiveTunnel::Get().GetK6HardeningSnapshot(s);}catch(...){}o.revision=s.control.revision;o.active_leases=s.active_leases;o.active_publishes=s.active_publishes;o.dial_streams=s.dial_streams;o.full_streams=s.full_streams;o.shaping_exposed_circuits=s.shaping_exposed_circuits;o.origin_advertise_success_total=s.origin_advertise_success_total;o.origin_source_recovered_total=s.origin_source_recovered_total;o.source_epoch_store_failed=s.source_epoch_store_failed;o.metrics_ready=s.metrics.ready;o.metrics_start=s.metrics.start;o.metrics_end=s.metrics.end;o.metrics_fixed_series=s.metrics.fixed_series;o.metrics_exported_series=s.metrics.exported_series;o.economy_measurement_ready=s.economy_measurement_ready;o.strict_recommended=s.strict_recommended;for(size_t i=0;i<s.control.services.size();++i){const kad6::K6ServiceSnapshot& x=s.control.services[i];o.services.push_back({kad6::K6ServiceName(x.service),kad6::K6ServiceStateName(x.state),x.changed_at,x.drain_deadline,(s.control.admission_mask&kad6::K6ServiceBit(x.service))!=0});}for(size_t i=0;i<s.economy.size();++i){const kad6::K6EconomyWindowSnapshot& x=s.economy[i];o.economy.push_back({kad6::K6ServiceName(static_cast<kad6::K6Service>(i)),s.economy_measurement_ready&&std::isfinite(s.rho[i]),x.sealed,s.rho[i],x.admission_ratio,x.rho_p50,x.rho_p95,x.starts_at,x.ends_at,x.samples,x.admission_attempts,x.admission_successes});}K6ExitNoticeServerSnapshot n;try{n=eSELive::CLiveTunnel::Get().GetK6ExitNoticeSnapshot();}catch(...){}o.exit_notice_running=n.running;o.exit_notice_port=n.port;o.exit_notice_requests=n.requests;o.exit_notice_rejected=n.rejected;o.exit_notice_bytes_sent=n.bytes_sent;return true;}
	static ese::web::W11LegacyPort Port(){return {NULL,Hls,Note,Netlab,Echo,Ping,Circuits,Peers,Test,Consume,Release,ReadRelease,Hardening,ReadHardening};}
};
static void SendW11Response(const ThreadData& d,const ese::web::W11LegacyResponse& r){if(r.file_response){ese::web::WebFileResponseOptions o;o.lastModified=r.last_modified;o.etag=r.etag;o.corsOrigin=r.cors_origin;d.pSocket->SendFileResponse(OptUtf8ToStr(r.file_path.c_str(),static_cast<int>(r.file_path.size())),CStringA(r.public_path.c_str()),CStringA(r.file_range.c_str()),o,r.maximum_bytes,r.concurrent,r.allow_empty);return;}const std::string h=ese::web::HardenLiveResponseHeaders(r.header,true);d.pSocket->SendData(h.data(),static_cast<int>(h.size()));d.pSocket->SendData(r.body.data(),static_cast<int>(r.body.size()));}
static bool RunW11LiveLegacyStaticFile(const ThreadData& d){const CWebServer* pThis=reinterpret_cast<CWebServer*>(d.pThis);if(pThis==NULL)return false;M2AModuleHandle snapshot=CaptureWebTemplateSnapshot(WebTemplateParent(pThis));(void)snapshot;const CStringA lastModified(GetWebTemplateLastModified(WebTemplateParent(pThis))),etag(GetWebTemplateETag(WebTemplateParent(pThis)));ese::web::W11StaticFileRequest q;q.web_root=W8Utf8(thePrefs.GetMuleDirectory(EMULE_WEBSERVERDIR));q.url=W8Utf8(d.sURL);q.public_path=W8Legacy(d.sURL);q.range=W9Bytes(d.sRange);q.last_modified=W9Bytes(lastModified);q.etag=W9Bytes(etag);q.maximum_bytes=static_cast<std::uint64_t>(thePrefs.GetMaxWebUploadFileSizeMB())*1024ull*1024ull;ese::web::W11LegacyResponse r;if(!ese::web::BuildW11LegacyStaticFile(q,r))return false;SendW11Response(d,r);return true;}

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

#ifdef UNICODE
#define _tcreate_locale  _wcreate_locale
#else
#define _tcreate_locale  _create_locale
#endif // !UNICODE

// eSE: Cabeceras HTTP de seguridad reforzadas (Fase 1 - CORS/CSRF)
#define HTTPInit \
	"Server: eMule\r\n" \
	"Connection: close\r\n" \
	"Content-Type: text/html\r\n" \
	"X-Content-Type-Options: nosniff\r\n" \
	"X-Frame-Options: SAMEORIGIN\r\n" \
	"Cache-Control: no-store\r\n" \
	"Access-Control-Allow-Origin: http://localhost:3000\r\n" \
	"Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n" \
	"Access-Control-Allow-Headers: Authorization, X-CSRF-Token, Content-Type\r\n" \
	"Access-Control-Expose-Headers: X-CSRF-Token\r\n"
#define HTTPInitGZ HTTPInit "Content-Encoding: gzip\r\n"
#define HTTPENCODING _T("utf-8")

//SyruS CQArray-Sorting operators
bool operator > (QueueUsers &first, QueueUsers &second)
{
	return (first.sIndex.CompareNoCase(second.sIndex) > 0);
}
bool operator < (QueueUsers &first, QueueUsers &second)
{
	return (first.sIndex.CompareNoCase(second.sIndex) < 0);
}

bool operator > (SearchFileStruct &first, SearchFileStruct &second)
{
	return (first.m_strIndex.CompareNoCase(second.m_strIndex) > 0);
}
bool operator < (SearchFileStruct &first, SearchFileStruct &second)
{
	return (first.m_strIndex.CompareNoCase(second.m_strIndex) < 0);
}

static BOOL	WSdownloadColumnHidden[8];
static BOOL	WSuploadColumnHidden[5];
static BOOL	WSqueueColumnHidden[4];
static BOOL	WSsharedColumnHidden[7];
static BOOL	WSserverColumnHidden[10];
static BOOL	WSsearchColumnHidden[4];

CWebServer::CWebServer()
	: m_uCurIP()
	, m_iSearchSortby(3)
	, m_nIntruderDetect()
	, m_bServerWorking()
	, m_bSearchAsc()
	, m_bIsTempDisabled()
{
	M2AModuleHandle streamBinding = M2A_BIND_W8_4974C0F316(M2AParentPort{this}); if (!streamBinding) return; M2AModuleHandle liveTransferBinding = M2A_BIND_W9_52CC9DEBDD(M2AParentPort{this}); if (!liveTransferBinding) return; M2AModuleHandle liveSearchBinding = M2A_BIND_W9_3B359EBB1A(M2AParentPort{this}); if (!liveSearchBinding) return; M2AModuleHandle w10SettingsBinding = M2A_BIND_W10_E9722EA045(M2AParentPort{this}); if (!w10SettingsBinding) return; M2AModuleHandle w10DiagnosticsBinding = M2A_BIND_W10_47570D3256(M2AParentPort{this}); if (!w10DiagnosticsBinding) return; M2AModuleHandle w11LegacyBinding = M2A_BIND_W11_55908BF94D(M2AParentPort{this}); if (!w11LegacyBinding) return; M2AModuleHandle serverListBinding = M2A_BIND_W3_F05B56128F(M2AParentPort{this}); if (!serverListBinding) return; CIni ini(thePrefs.GetConfigFile(), _T("WebServer"));
	ini.SerGet(true, WSdownloadColumnHidden, _countof(WSdownloadColumnHidden), _T("downloadColumnHidden"));
	ini.SerGet(true, WSuploadColumnHidden, _countof(WSuploadColumnHidden), _T("uploadColumnHidden"));
	ini.SerGet(true, WSqueueColumnHidden, _countof(WSqueueColumnHidden), _T("queueColumnHidden"));
	ini.SerGet(true, WSsearchColumnHidden, _countof(WSsearchColumnHidden), _T("searchColumnHidden"));
	ini.SerGet(true, WSsharedColumnHidden, _countof(WSsharedColumnHidden), _T("sharedColumnHidden"));
	ini.SerGet(true, WSserverColumnHidden, _countof(WSserverColumnHidden), _T("serverColumnHidden"));
	m_Params.bShowUploadQueue = ini.GetBool(_T("ShowUploadQueue"), false);
	m_Params.bShowUploadQueueBanned = ini.GetBool(_T("ShowUploadQueueBanned"), false);
	m_Params.bShowUploadQueueFriend = ini.GetBool(_T("ShowUploadQueueFriend"), false);
	m_Params.bDownloadSortReverse = ini.GetBool(_T("DownloadSortReverse"), true);
	m_Params.bUploadSortReverse = ini.GetBool(_T("UploadSortReverse"), true);
	m_Params.bQueueSortReverse = ini.GetBool(_T("QueueSortReverse"), true);
	m_Params.bServerSortReverse = ini.GetBool(_T("ServerSortReverse"), true);
	m_Params.bSharedSortReverse = ini.GetBool(_T("SharedSortReverse"), true);
	m_Params.DownloadSort = (DownloadSort)ini.GetInt(_T("DownloadSort"), DOWN_SORT_NAME);
	m_Params.UploadSort = (UploadSort)ini.GetInt(_T("UploadSort"), UP_SORT_FILENAME);
	m_Params.QueueSort = (QueueSort)ini.GetInt(_T("QueueSort"), QU_SORT_FILENAME);
	m_Params.ServerSort = (ServerSort)ini.GetInt(_T("ServerSort"), SERVER_SORT_NAME);
	m_Params.SharedSort = (SharedSort)ini.GetInt(_T("SharedSort"), SHARED_SORT_NAME);
}

CWebServer::~CWebServer()
{
	// save layout settings
	CIni ini(thePrefs.GetConfigFile(), _T("WebServer"));
	ini.WriteBool(_T("ShowUploadQueue"), m_Params.bShowUploadQueue);
	ini.WriteBool(_T("ShowUploadQueueBanned"), m_Params.bShowUploadQueueBanned);
	ini.WriteBool(_T("ShowUploadQueueFriend"), m_Params.bShowUploadQueueFriend);
	ini.WriteBool(_T("DownloadSortReverse"), m_Params.bDownloadSortReverse);
	ini.WriteBool(_T("UploadSortReverse"), m_Params.bUploadSortReverse);
	ini.WriteBool(_T("QueueSortReverse"), m_Params.bQueueSortReverse);
	ini.WriteBool(_T("ServerSortReverse"), m_Params.bServerSortReverse);
	ini.WriteBool(_T("SharedSortReverse"), m_Params.bSharedSortReverse);
	ini.WriteInt(_T("DownloadSort"), m_Params.DownloadSort);
	ini.WriteInt(_T("UploadSort"), m_Params.UploadSort);
	ini.WriteInt(_T("QueueSort"), m_Params.QueueSort);
	ini.WriteInt(_T("ServerSort"), m_Params.ServerSort);
	ini.WriteInt(_T("SharedSort"), m_Params.SharedSort);
	m_authPolicy.RevokeAllHlsCapabilities();
	if (m_bServerWorking)
		StopSockets();
	M2A_UNBIND_W12_B26D83D73F(M2AParentPort{this}); M2A_UNBIND_W11_55908BF94D(M2AParentPort{this}); M2A_UNBIND_W10_E9722EA045(M2AParentPort{this}); M2A_UNBIND_W10_47570D3256(M2AParentPort{this}); M2A_UNBIND_W9_52CC9DEBDD(M2AParentPort{this}); M2A_UNBIND_W9_3B359EBB1A(M2AParentPort{this}); M2A_UNBIND_W8_4974C0F316(M2AParentPort{this}); M2A_UNBIND_W8_E988965D5A(M2AParentPort{this}); M2A_UNBIND_W1_EC6846B80E(M2AParentPort{this}); M2A_UNBIND_W2_9330EBAD15(M2AParentPort{this}); M2A_UNBIND_W2_071B3D442B(M2AParentPort{this}); M2A_UNBIND_W3_F05B56128F(M2AParentPort{this}); M2A_UNBIND_W4_AD763A5EE0(M2AParentPort{this}); M2A_UNBIND_W5_095B87253F(M2AParentPort{this}); M2A_UNBIND_W6_64C04005E2(M2AParentPort{this}); M2A_UNBIND_W6_B161DA740E(M2AParentPort{this});
}

void CWebServer::_SaveWIConfigArray(BOOL *array, int size, LPCTSTR key)
{
	CIni ini(thePrefs.GetConfigFile(), _T("WebServer"));
	ini.SerGet(false, array, size, key);
}

bool CWebServer::ReloadTemplates()
{
	M2AModuleHandle binding = M2A_BIND_W2_071B3D442B(M2AParentPort{this}); if (!binding) return false; bool stopServer = false; const bool loaded = ReloadWebTemplates(M2AParentPort{this}, thePrefs.GetTemplate(), thePrefs.GetWSIsEnabled(), m_bServerWorking, stopServer); if (stopServer) StopServer(); return loaded;
}
//Cax2 - restarts the server with the new port settings
void CWebServer::RestartSockets()
{
	M2AModuleHandle headerBinding = M2A_BIND_W2_9330EBAD15(M2AParentPort{this}); if (!headerBinding) return;
	m_authPolicy.RevokeAllHlsCapabilities();
	StopSockets();
	if (m_bServerWorking)
		StartSockets(this);
}

void CWebServer::StartServer()
{
	M2AModuleHandle facadeBinding = M2A_BIND_W12_B26D83D73F(M2AParentPort{this}); if (!facadeBinding) return; M2AModuleHandle requestDispatchBinding = M2A_BIND_W1_EC6846B80E(M2AParentPort{this}); if (!requestDispatchBinding) return; M2AModuleHandle templateBinding = M2A_BIND_W2_071B3D442B(M2AParentPort{this}); M2AModuleHandle headerBinding = M2A_BIND_W2_9330EBAD15(M2AParentPort{this}); if (!templateBinding || !headerBinding) return;
	bool wsPrefEnabled = thePrefs.GetWSIsEnabled();
	LIVE_LOG("WS", "StartServer entry: pref.Enabled=%d  pref.Port=%u  serverWorking=%d  template=\"%S\"",
		(int)wsPrefEnabled, (unsigned)thePrefs.GetWSPort(),
		(int)m_bServerWorking, (LPCWSTR)thePrefs.GetTemplate());
	if (m_bServerWorking == wsPrefEnabled) {
		LIVE_LOG("WS", "StartServer SKIP: already in target state (%d)", (int)wsPrefEnabled);
		return;
	}
	m_authPolicy.RevokeAllHlsCapabilities();
	m_bServerWorking = wsPrefEnabled;
	if (m_bServerWorking) {
		LIVE_LOG("WS", "StartServer: calling ReloadTemplates()");
		ReloadTemplates();
		LIVE_LOG("WS", "StartServer: ReloadTemplates returned, serverWorking=%d", (int)m_bServerWorking);
		if (m_bServerWorking) {
			LIVE_LOG("WS", "StartServer: calling StartSockets()");
			StartSockets(this);
			m_nIntruderDetect = 0;
			m_bIsTempDisabled = false;
			LIVE_LOG("WS", "StartServer: StartSockets returned (no bind feedback yet — see WSL events)");
		} else {
			LIVE_LOG("WS", "StartServer ABORT: ReloadTemplates disabled the server");
		}
	} else {
		LIVE_LOG("WS", "StartServer: stopping (pref disabled)");
		StopSockets();
	}
	UINT uid = (thePrefs.GetWSIsEnabled() && m_bServerWorking) ? IDS_ENABLED : IDS_DISABLED;
	AddLogLine(false, _T("%s: %s%s")
		, (LPCTSTR)_GetPlainResString(IDS_PW_WS)
		, (LPCTSTR)_GetPlainResString(uid).MakeLower()
		, (uid == IDS_ENABLED && thePrefs.GetWebUseHttps()) ? _T(" (HTTPS)") : _T(""));
	LIVE_LOG("WS", "StartServer EXIT: bServerWorking=%d  pref.Enabled=%d",
		(int)m_bServerWorking, (int)thePrefs.GetWSIsEnabled());
}

void CWebServer::StopServer()
{
	m_authPolicy.RevokeAllHlsCapabilities();
	M2AModuleHandle statusBinding = M2A_BIND_W8_E988965D5A(M2AParentPort{this}); if (!statusBinding) return; if (m_bServerWorking) {
		StopSockets();
		m_bServerWorking = false;
	}
	thePrefs.SetWSIsEnabled(false);
	M2A_UNBIND_W12_B26D83D73F(M2AParentPort{this});
}

void CWebServer::AddStatsLine(const UpDown &line)
{
	M2AModuleHandle transferActionsBinding = M2A_BIND_W5_095B87253F(M2AParentPort{this}); if (!transferActionsBinding) return; m_Params.PointsForWeb.Add(line);
	if (m_Params.PointsForWeb.GetCount() > WEB_GRAPH_WIDTH)
		m_Params.PointsForWeb.RemoveAt(0);
}

CString CWebServer::_SpecialChars(const CString &cstr, bool noquote /*=false*/)
{
	return EscapeWebTemplateText(cstr, noquote);
}

bool CWebServer::RunCharacterizationSelfTest(CString& outFailure)
{
	outFailure.Empty();
	if (_ParseURL(_T("/?a=one&b=two"), _T("b")) != _T("two")) {
		outFailure = _T("web parser failed deterministic query");
		return false;
	}
	std::string parserFailure; if (!ese::web::RunCharacterizationSelfTest(parserFailure)) {
		outFailure = OptUtf8ToStr(
			parserFailure.data(), static_cast<int>(parserFailure.size()));
		return false;
	}
	std::string authFailure;
	if (!ese::web::RunWebAuthPolicySelfTest(authFailure)) {
		outFailure = OptUtf8ToStr(
			authFailure.data(), static_cast<int>(authFailure.size()));
		return false;
	}
	std::string hlsCapabilityFailure;
	if (!ese::web::RunWebHlsCapabilityControllerSelfTest(
			hlsCapabilityFailure)) {
		outFailure = OptUtf8ToStr(
			hlsCapabilityFailure.data(),
			static_cast<int>(hlsCapabilityFailure.size()));
		return false;
	}
	std::string routeFailure;
	if (!ese::web::RunWebRouteTableSelfTest(routeFailure)) {
		outFailure = OptUtf8ToStr(routeFailure.data(), static_cast<int>(routeFailure.size()));
		return false;
	}
	if (!RunWebClassicRequestCharacterizationSelfTest()) { outFailure = _T("web request dispatch route table changed"); return false; } if (!RunWebTemplateCharacterizationSelfTest() || !RunWebPageChromeCharacterizationSelfTest()) { outFailure = _T("web template/header rendering changed"); return false; } if (!RunWebServerPageCharacterizationSelfTest()) { outFailure = _T("web server-list rendering changed"); return false; } if (!RunWebTransferProjectionCharacterizationSelfTest()) { outFailure = _T("web transfer projection changed"); return false; } if (!RunWebTransferActionsCharacterizationSelfTest()) { outFailure = _T("web transfer actions changed"); return false; } if (!RunWebSearchProjectionCharacterizationSelfTest()) { outFailure = _T("web search projection changed"); return false; } if (!RunWebSharedFilesControllerCharacterizationSelfTest()) { outFailure = _T("web shared-files projection changed"); return false; } const ese::web::WebSharedComparison sharedCompatibility{0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0}; const ese::web::WebSharedRowProjection sharedProjection = ese::web::WebSharedController::ProjectRow(false, ese::web::WebSharedPriority::Normal, false, 1024, 1, 1, 1); if (ese::web::WebSharedController::Compare(2, false, sharedCompatibility) != -1 || std::string(sharedProjection.priority_token) != "Normal" || !sharedProjection.downloadable || sharedProjection.complete_sources != "1") { outFailure = _T("web shared policy compatibility changed"); return false; }
	std::string serializerFailure;
	std::string w8Failure; const CString w8Unicode(_T("\x0416")); if (W8Text(W8Utf8(w8Unicode)) != w8Unicode || W10Text(W8Utf8(w8Unicode)) != w8Unicode) { outFailure = _T("web Live API UTF-8 boundary changed"); return false; } std::string w8Wire, w8Ui, w8Encoded; W8Assign(_T("A b!"),w8Wire,w8Ui,&w8Encoded); if(w8Wire!="A b!" || w8Ui!="A b!" || w8Encoded!="A+b%21") { outFailure = _T("web Live API legacy wire boundary changed"); return false; } if (!RunW8LiveStreamCharacterizationSelfTest(w8Failure) || !ese::web::RunW8LiveStatusCharacterizationSelfTest(w8Failure) || !RunW9LiveTransferCharacterizationSelfTest(w8Failure) || !ese::web::RunW9LiveSearchCharacterizationSelfTest(w8Failure) || !RunW10LiveSettingsCharacterizationSelfTest(w8Failure) || !ese::web::RunW10LiveDiagnosticsCharacterizationSelfTest(w8Failure) || !ese::web::RunW11LiveLegacyCharacterizationSelfTest(w8Failure) || !ese::web::RunWebServerFacadeCharacterizationSelfTest(w8Failure)) { outFailure = OptUtf8ToStr(w8Failure.data(), static_cast<int>(w8Failure.size())); return false; }
	if (!ese::web::RunWebApiSerializerSelfTest(serializerFailure)) {
		outFailure = OptUtf8ToStr(
			serializerFailure.data(),
			static_cast<int>(serializerFailure.size()));
		return false;
	}
	std::string diagnosticsFailure;
	if (!ese::web::RunWebDiagnosticsSelfTest(diagnosticsFailure)) {
		outFailure = OptUtf8ToStr(
			diagnosticsFailure.data(),
			static_cast<int>(diagnosticsFailure.size()));
		return false;
	}
	std::string staticFailure;
	if (!ese::web::RunWebStaticAssetsSelfTest(staticFailure)) {
		outFailure = OptUtf8ToStr(
			staticFailure.data(), static_cast<int>(staticFailure.size()));
		return false;
	}
	std::string responseFailure;
	if (!ese::web::RunWebSocketResponseSelfTest(responseFailure)) {
		outFailure = OptUtf8ToStr(
			responseFailure.data(),
			static_cast<int>(responseFailure.size()));
		return false;
	}
	if (_SpecialChars(_T("<&\"'\n"), true) != _T("&lt;&amp;&quot;&#8217;\\n")) {
		outFailure = _T("web serialization escaping changed");
		return false;
	}
	const Bytef input[] = "mod02";
	Bytef compressed[64] = {};
	uLongf compressedLength = sizeof(compressed);
	if (CompressWebGzip(compressed, &compressedLength, input, sizeof(input) - 1, Z_BEST_SPEED) != 0
		|| compressedLength < 18
		|| compressed[0] != 0x1f || compressed[1] != 0x8b) {
		outFailure = _T("web gzip serialization failed");
		return false;
	}
	const uLong expectedCrc = crc32(0, input, sizeof(input) - 1);
	const size_t trailer = static_cast<size_t>(compressedLength) - 8;
	const uint32 trailerCrc = static_cast<uint32>(compressed[trailer])
		| (static_cast<uint32>(compressed[trailer + 1]) << 8)
		| (static_cast<uint32>(compressed[trailer + 2]) << 16)
		| (static_cast<uint32>(compressed[trailer + 3]) << 24);
	const uint32 trailerSize = static_cast<uint32>(compressed[trailer + 4])
		| (static_cast<uint32>(compressed[trailer + 5]) << 8)
		| (static_cast<uint32>(compressed[trailer + 6]) << 16)
		| (static_cast<uint32>(compressed[trailer + 7]) << 24);
	if (trailerCrc != static_cast<uint32>(expectedCrc)
		|| trailerSize != sizeof(input) - 1) {
		outFailure = _T("web gzip trailer changed");
		return false;
	}
	Bytef inflated[sizeof(input) - 1] = {};
	z_stream inflater = {};
	inflater.next_in = compressed;
	inflater.avail_in = static_cast<uInt>(compressedLength);
	inflater.next_out = inflated;
	inflater.avail_out = sizeof(inflated);
	if (inflateInit2(&inflater, MAX_WBITS + 16) != Z_OK) {
		outFailure = _T("web gzip inflate init failed");
		return false;
	}
	const int inflateResult = inflate(&inflater, Z_FINISH);
	inflateEnd(&inflater);
	if (inflateResult != Z_STREAM_END || inflater.total_out != sizeof(inflated)
		|| memcmp(inflated, input, sizeof(inflated)) != 0) {
		outFailure = _T("web gzip round-trip changed");
		return false;
	}
	return true;
}

void CWebServer::_ProcessURL(const ThreadData &Data)
{
	CWebServer* owner = reinterpret_cast<CWebServer*>(Data.pThis); if (owner == NULL) return;
	WebClassicPort port; port.context = owner;
	port.parse_url = [](const CString& url, const CString& field) { return _ParseURL(url, field); };
	port.validate_challenge = [](const void* raw, const CString& nonce, const CString& response, bool& admin) { return _ValidateChallengeResponse(*static_cast<const ThreadData*>(raw), nonce, response, admin); };
	port.login_blocked = [](void* raw, std::uint32_t ip, std::uint64_t now) { return static_cast<CWebServer*>(raw)->m_authPolicy.IsLoginBlocked(ip, now); };
	port.add_session = [](void* raw, std::uint32_t id, bool admin, int category, std::uint64_t now, const CStringA& csrf, const CStringA& bearer) {
		const CStringA digest=DigestWebRequestToken(bearer);return static_cast<CWebServer*>(raw)->m_authPolicy.AddSession(id, admin ? ese::web::WebRole::Admin : ese::web::WebRole::Guest, category, now, std::string((LPCSTR)csrf, csrf.GetLength()), std::string((LPCSTR)digest, digest.GetLength())); };
	port.resolve_browser_session = [](void* raw, const CStringA& bearer, std::uint64_t now, std::uint64_t timeout, std::uint32_t& id) {
		const CStringA digest=DigestWebRequestToken(bearer);ese::web::WebSessionSnapshot session; if (!static_cast<CWebServer*>(raw)->m_authPolicy.ResolveBrowserSessionDigest(std::string((LPCSTR)digest, digest.GetLength()), now, timeout, &session)) return false; id = session.id; return true; };
	port.validate_csrf = [](void* raw, std::uint32_t id, const CStringA& token, const CStringA& fetchSite) {
		ese::web::WebSessionSnapshot session; CWebServer* server = static_cast<CWebServer*>(raw); if (!server->m_authPolicy.GetSession(id, session)) return true;
		return ese::web::WebAuthPolicy::ValidateCsrfRequest(session, std::string((LPCSTR)token, token.GetLength()), std::string((LPCSTR)fetchSite, fetchSite.GetLength())); };
	port.record_login_failure = [](void* raw, std::uint32_t ip, std::uint64_t now) { static_cast<CWebServer*>(raw)->m_authPolicy.RecordLoginFailure(ip, now); };
	port.record_login_success = [](void* raw, std::uint32_t ip) { static_cast<CWebServer*>(raw)->m_authPolicy.RecordLoginSuccess(ip); };
	port.remove_session = [](const void* raw, long session) { return _RemoveSession(*static_cast<const ThreadData*>(raw), session); };
	port.is_logged_in = [](const void* raw, long session) { return _IsLoggedIn(*static_cast<const ThreadData*>(raw), session); };
	port.is_admin = [](const void* raw, const CString& session) { return _IsSessionAdmin(*static_cast<const ThreadData*>(raw), session); };
	port.send_content = [](const void* raw, const CStringA& header, const CString& body) { static_cast<const ThreadData*>(raw)->pSocket->SendContent(header, body); };
	port.send_binary = [](const void* raw, const CStringA& header, const void* body, unsigned long size) { static_cast<const ThreadData*>(raw)->pSocket->SendContent(header, body, size); };
	port.send_reply = [](const void* raw, const char* reply) { static_cast<const ThreadData*>(raw)->pSocket->SendReply(reply); };
	port.notify_login = [](bool admin, const CString& ip) { SendMessage(theApp.emuledlg->m_hWnd, WEB_GUI_INTERACTION, WEBGUIIA_UPDATEMYINFO, 0); AddLogLine(true, GetResString(admin ? IDS_WEB_ADMINLOGIN : IDS_WEB_GUESTLOGIN) + _T(" (%s)"), (LPCTSTR)ip); };
	port.notify_bad_login = [](const CString& ip) { LogWarning(LOG_STATUSBAR, GetResString(IDS_WEB_BADLOGINATTEMPT) + _T(" (%s)"), (LPCTSTR)ip); };
	port.perform_admin_action = [](WebAdminAction action) { if (action == WebAdminAction::Close) { theApp.m_app_state = APP_STATE_SHUTTINGDOWN; SendMessage(theApp.emuledlg->m_hWnd, WM_CLOSE, 0, 0); } else SendMessage(theApp.emuledlg->m_hWnd, WEB_GUI_INTERACTION, WEBGUIIA_WINFUNC, action == WebAdminAction::Shutdown ? 1 : 2); };
	port.send_requested_file = [](const void* raw, const CString& fileHash) {
		const ThreadData& data = *static_cast<const ThreadData*>(raw); uchar hash[MDX_DIGEST_SIZE]; if (!strmd4(fileHash, hash)) return false;
		CKnownFile* file = theApp.sharedfiles->GetFileByID(hash); if (file == NULL) return false; const UINT maxMb = thePrefs.GetMaxWebUploadFileSizeMB();
		if (maxMb != 0 && file->GetFileSize() > static_cast<uint64>(maxMb) * 1024 * 1024) { data.pSocket->SendReply("HTTP/1.1 403 Forbidden\r\n"); return true; }
		const CStringA name(wc2utf8(file->GetFileName())); ese::web::WebFileResponseOptions options; options.cacheControl = "no-store";
		options.attachmentUtf8.assign((LPCSTR)name, name.GetLength()); data.pSocket->SendFileResponse(file->GetFilePath(), "download.bin", data.sRange, options, static_cast<ULONGLONG>(maxMb) * 1024ull * 1024ull, false, true); return true; };
	port.render = [](WebClassicView view, const void* raw, long session) {
		const ThreadData& data = *static_cast<const ThreadData*>(raw); switch (view) {
		case WebClassicView::Login: return _GetLoginScreen(data); case WebClassicView::RemoteLinkAdded: return _GetRemoteLinkAddedOk(data); case WebClassicView::RemoteLinkFailed: return _GetRemoteLinkAddedFailed(data); case WebClassicView::CommentList: return _GetCommentlist(data);
		case WebClassicView::Header: return _GetHeader(data, session); case WebClassicView::Footer: return _GetFooter(data); case WebClassicView::Server: return _GetServerList(data); case WebClassicView::Shared: return static_cast<CWebServer*>(data.pThis)->_GetSharedFilesList(data); case WebClassicView::Transfer: return _GetTransferList(data);
		case WebClassicView::Search: return _GetSearch(data); case WebClassicView::Graphs: return _GetGraphs(data); case WebClassicView::Log: return _GetLog(data);
		case WebClassicView::ServerInfo: return _GetServerInfo(data); case WebClassicView::DebugLog: return _GetDebugLog(data); case WebClassicView::MyInfo: return _GetMyInfo(data); case WebClassicView::Stats: return _GetStats(data); case WebClassicView::Kad: return _GetKadDlg(data); case WebClassicView::Options: return _GetPreferences(data);
		default: return CString();
		}
	};
	WebClassicInput input; input.legacy = &Data; input.url = Data.sURL; input.ip_text = ipstr(Data.inadr); input.csrf_token = Data.sCsrfToken; input.fetch_site = Data.sFetchSite; input.browser_session_token = Data.sBrowserSessionToken;
	input.admin_password_hash = thePrefs.GetWSPass(); input.guest_password_hash = thePrefs.GetWSLowPass(); input.access_denied_text = _GetPlainResString(IDS_ACCESSDENIED); input.ip = inet_addr(ipstrA(Data.inadr));
	input.default_category = -thePrefs.GetCatFilter(0); input.loopback = Data.inadr.S_un.S_addr == htonl(INADDR_LOOPBACK); input.app_running = theApp.IsRunning(); input.use_gzip = thePrefs.GetWebUseGzip(); input.guest_enabled = thePrefs.GetWSIsLowUserEnabled(); input.allow_high_level = thePrefs.GetWebAdminAllowedHiLevFunc(); input.secure_transport = Data.bSecureTransport;
	M2AModuleHandle templateSnapshot = CaptureWebTemplateSnapshot(WebTemplateParent(owner)); RunWebClassicRequest(M2AParentPort{owner}, input, port);
}

CString CWebServer::_ParseURLArray(CString URL, CString fieldname)
{
	const CStringA urlA(URL);
	const CStringA fieldA(fieldname);
	const std::string url(urlA.GetString(), urlA.GetLength());
	const std::string field(fieldA.GetString(), fieldA.GetLength());
	std::vector<std::string> values;
	if (ese::web::GetQueryValues(url, field, values) != ese::web::QueryStatus::Ok)
		return CString();
	CString res;
	for (const std::string &value : values) {
		const CString decoded(OptUtf8ToStr(
			value.data(), static_cast<int>(value.size())));
		if (decoded.IsEmpty())
			break;
		res.AppendFormat(_T("%s|"), (LPCTSTR)decoded);
	}
	return res;
}

CString CWebServer::_ParseURL(const CString &URL, const CString &fieldname)
{
	const CStringA urlA(URL);
	const CStringA fieldA(fieldname);
	const std::string url(urlA.GetString(), urlA.GetLength());
	const std::string field(fieldA.GetString(), fieldA.GetLength());
	std::string value;
	if (ese::web::GetQueryValue(url, field, value) != ese::web::QueryStatus::Ok)
		return CString();
	return OptUtf8ToStr(value.data(), static_cast<int>(value.size()));
}

CString CWebServer::_GetHeader(const ThreadData &Data, long lSession)
{
	CWebServer* owner = reinterpret_cast<CWebServer*>(Data.pThis); if (owner == NULL) return CString();
	WebHeaderRuntime runtime; runtime.version = theApp.m_strCurVersionLong; runtime.serverConnecting = theApp.serverconnect->IsConnecting(); runtime.serverConnected = theApp.serverconnect->IsConnected(); runtime.highId = theApp.HasVerifiedEd2kHighId(); if (runtime.serverConnected) { CServer* current = theApp.serverconnect->GetCurrentServer(); CServer* server = current == NULL ? NULL : theApp.serverlist->GetServerByAddress(current->GetAddress(), current->GetPort()); if (server != NULL) { runtime.serverName = server->GetListName(); runtime.serverUsers = server->GetUsers(); runtime.serverMaxUsers = server->GetMaxUsers(); runtime.serverFiles = server->GetFiles(); } } for (INT_PTR index = theApp.serverlist->GetServerCount(); --index >= 0;) { const CServer* server = theApp.serverlist->GetServerAt(index); runtime.allUsers += server->GetUsers(); runtime.allFiles += server->GetFiles(); } runtime.kad2Connected = Kademlia::CKademlia::IsKad2Connected(); runtime.kadFirewalled = Kademlia::CKademlia::IsFirewalled(); runtime.kad6Connected = Kademlia::CKademlia::IsKad6Connected(); runtime.kadRunning = Kademlia::CKademlia::IsRunning(); runtime.downloadRate = theApp.downloadqueue->GetDatarate(); runtime.uploadRate = theApp.uploadqueue->GetDatarate(); runtime.openSockets = theApp.listensocket->GetOpenSockets();
	return RenderWebHeader(WebTemplateParent(owner), _ParseURL(Data.sURL, _T("w")), _ParseURL(Data.sURL, _T("cat")), _ParseURL(Data.sURL, _T("c")), lSession, _IsSessionAdmin(Data, lSession), GenerateWebRequestWord32(), GetWebTemplate(WebTemplateParent(owner), WebTemplateId::Header), GetWebTemplate(WebTemplateParent(owner), WebTemplateId::HeaderStylesheet), GetWebTemplate(WebTemplateParent(owner), WebTemplateId::CatArrow), runtime);
}
const CString CWebServer::_GetFooter(const ThreadData &Data)
{
	const CWebServer* owner = reinterpret_cast<CWebServer*>(Data.pThis); return owner == NULL ? CString() : RenderWebFooter(WebTemplateParent(owner), GetWebTemplate(WebTemplateParent(owner), WebTemplateId::Footer));
}
CString CWebServer::_GetServerList(const ThreadData &Data)
{
	M2AModuleHandle binding = M2A_BIND_W3_F05B56128F(M2AParentPort{Data.pThis}); if (!binding) return CString();
	CWebServer* owner = static_cast<CWebServer*>(Data.pThis); if (owner == nullptr) return CString();
	WebServerPageInput input; input.url = Data.sURL; input.admin = _IsSessionAdmin(Data, _ParseURL(Data.sURL, _T("ses"))); input.sort = owner->m_Params.ServerSort; input.reverse = owner->m_Params.bServerSortReverse;
	input.pageTemplate = GetWebTemplate(WebTemplateParent(owner), WebTemplateId::ServerList); input.rowTemplate = GetWebTemplate(WebTemplateParent(owner), WebTemplateId::ServerLine); input.addTemplate = GetWebTemplate(WebTemplateParent(owner), WebTemplateId::AddServerBox); input.upArrow = GetWebTemplate(WebTemplateParent(owner), WebTemplateId::UpArrow); input.downArrow = GetWebTemplate(WebTemplateParent(owner), WebTemplateId::DownArrow);
	for (std::size_t index = 0; index < input.hidden.size(); ++index) input.hidden[index] = WSserverColumnHidden[index] != FALSE;
	WebServerGuiPort port; port.context = owner;
	port.parse = [](void*, const CString& url, const CString& field) { return _ParseURL(url, field); };
	port.plain = [](void*, unsigned id) { return _GetPlainResString(id); };
	port.action = [](void*, WebServerAction action, const CString& ip, int serverPort) { if (action == WebServerAction::Disconnect) { const bool connecting = theApp.serverconnect->IsConnecting(); SendMessage(theApp.emuledlg->m_hWnd, WEB_GUI_INTERACTION, connecting ? WEBGUIIA_STOPCONNECTING : WEBGUIIA_DISCONNECT, connecting ? 0 : 1); return; } if (action == WebServerAction::Connect && ip.IsEmpty()) { SendMessage(theApp.emuledlg->m_hWnd, WEB_GUI_INTERACTION, WEBGUIIA_CONNECTTOSERVER, 0); return; } CServer* server = theApp.serverlist->GetServerByAddress(ip, static_cast<uint16>(serverPort)); if (server == nullptr) return; switch (action) { case WebServerAction::Connect: SendMessage(theApp.emuledlg->m_hWnd, WEB_GUI_INTERACTION, WEBGUIIA_CONNECTTOSERVER, reinterpret_cast<LPARAM>(server)); break; case WebServerAction::Remove: SendMessage(theApp.emuledlg->m_hWnd, WEB_GUI_INTERACTION, WEBGUIIA_SERVER_REMOVE, reinterpret_cast<LPARAM>(server)); break; case WebServerAction::AddStatic: SendMessage(theApp.emuledlg->m_hWnd, WEB_GUI_INTERACTION, WEBGUIIA_ADD_TO_STATIC, reinterpret_cast<LPARAM>(server)); break; case WebServerAction::RemoveStatic: SendMessage(theApp.emuledlg->m_hWnd, WEB_GUI_INTERACTION, WEBGUIIA_REMOVE_FROM_STATIC, reinterpret_cast<LPARAM>(server)); break; case WebServerAction::PriorityLow: server->SetPreference(SRV_PR_LOW); SendMessage(theApp.emuledlg->m_hWnd, WEB_GUI_INTERACTION, WEBGUIIA_UPDATESERVER, reinterpret_cast<LPARAM>(server)); break; case WebServerAction::PriorityNormal: server->SetPreference(SRV_PR_NORMAL); SendMessage(theApp.emuledlg->m_hWnd, WEB_GUI_INTERACTION, WEBGUIIA_UPDATESERVER, reinterpret_cast<LPARAM>(server)); break; case WebServerAction::PriorityHigh: server->SetPreference(SRV_PR_HIGH); SendMessage(theApp.emuledlg->m_hWnd, WEB_GUI_INTERACTION, WEBGUIIA_UPDATESERVER, reinterpret_cast<LPARAM>(server)); break; default: break; } };
	port.addServer = [](void*, const CString& address, int serverPort, const CString& name, const CString& priority, bool makeStatic, bool connectNow, CString& message) { message = EscapeWebTemplateText(theApp.emuledlg->GetLastLogEntry(), true); CServer* server = new CServer(static_cast<uint16>(serverPort), address); server->SetListName(name); if (!theApp.emuledlg->serverwnd->serverlistctrl.AddServer(server, true)) { delete server; return false; } if (priority == _T("low")) server->SetPreference(PR_LOW); else if (priority == _T("normal")) server->SetPreference(PR_NORMAL); else if (priority == _T("high")) server->SetPreference(PR_HIGH); SendMessage(theApp.emuledlg->m_hWnd, WEB_GUI_INTERACTION, WEBGUIIA_UPDATESERVER, reinterpret_cast<LPARAM>(server)); if (makeStatic) { SendMessage(theApp.emuledlg->m_hWnd, WEB_GUI_INTERACTION, WEBGUIIA_ADD_TO_STATIC, reinterpret_cast<LPARAM>(server)); message.AppendFormat(_T("<br>%s"), (LPCTSTR)EscapeWebTemplateText(theApp.emuledlg->GetLastLogEntry(), true)); } if (connectNow) SendMessage(theApp.emuledlg->m_hWnd, WEB_GUI_INTERACTION, WEBGUIIA_CONNECTTOSERVER, reinterpret_cast<LPARAM>(server)); return true; };
	port.updateServerMet = [](void*, const CString& url, CString& message) { SendMessage(theApp.emuledlg->m_hWnd, WEB_GUI_INTERACTION, WEBGUIIA_UPDATESERVERMETFROMURL, reinterpret_cast<LPARAM>((LPCTSTR)url)); message = EscapeWebTemplateText(theApp.emuledlg->GetLastLogEntry(), true); };
	port.saveHidden = [](void*, const std::array<bool, 10>& hidden) { for (std::size_t index = 0; index < hidden.size(); ++index) WSserverColumnHidden[index] = hidden[index]; _SaveWIConfigArray(WSserverColumnHidden, _countof(WSserverColumnHidden), _T("serverColumnHidden")); };
	port.snapshot = [](void*, std::vector<WebServerRow>& rows) { rows.reserve(static_cast<std::size_t>(theApp.serverlist->GetServerCount())); for (INT_PTR index = theApp.serverlist->GetServerCount(); --index >= 0;) { const CServer& server = *theApp.serverlist->GetServerAt(index); WebServerRow row; row.name = EscapeWebTemplateText(server.GetListName(), true); row.ip = server.GetAddress(); row.port = server.GetPort(); row.description = EscapeWebTemplateText(server.GetDescription(), true); row.ping = server.GetPing(); row.users = server.GetUsers(); row.maxUsers = server.GetMaxUsers(); row.files = server.GetFiles(); row.isStatic = server.IsStaticMember(); unsigned priorityId = 0; switch (server.GetPreference()) { case SRV_PR_HIGH: priorityId = IDS_PRIOHIGH; row.priority = 2; break; case SRV_PR_NORMAL: priorityId = IDS_PRIONORMAL; row.priority = 1; break; case SRV_PR_LOW: priorityId = IDS_PRIOLOW; row.priority = 0; break; default: break; } if (priorityId != 0) row.priorityText = _GetPlainResString(priorityId); row.failed = server.GetFailedCount(); row.softLimit = server.GetSoftFiles(); row.hardLimit = server.GetHardFiles(); row.version = server.GetVersion(); if (inet_addr(CStringA(row.ip)) != INADDR_NONE) { for (int part = 0, position = 0; part < 4 && position >= 0; ++part) { const CString token(row.ip.Tokenize(_T("."), position)); row.fullIp.AppendFormat(&_T("000%s")[min(token.GetLength(), 3)], (LPCTSTR)token); } } else row.fullIp = row.ip; row.state = server.GetFailedCount() ? _T("failed") : _T("disconnected"); if (theApp.serverconnect->IsConnecting()) row.state = _T("connecting"); else if (theApp.serverconnect->IsConnected() && theApp.serverconnect->GetCurrentServer() != nullptr && theApp.serverconnect->GetCurrentServer()->GetFullIP() == server.GetFullIP()) row.state = theApp.HasVerifiedEd2kHighId() ? _T("high") : _T("low"); rows.push_back(row); } };
	if (!port.Complete()) return CString();
	const WebServerPageResult result(RunWebServerPage(WebTemplateParent(owner), input, port)); owner->m_Params.ServerSort = static_cast<ServerSort>(result.sort); owner->m_Params.bServerSortReverse = result.reverse;
	for (std::size_t index = 0; index < result.hidden.size(); ++index) WSserverColumnHidden[index] = result.hidden[index];
	return result.html;
}
void CWebServer::_MakeTransferList(CString &, CWebServer *pThis, const ThreadData &Data, void *, void *, bool bAdmin) {
	/* PlanFileAction compatibility marker. */ if (pThis == NULL) return; const CString session(_ParseURL(Data.sURL, _T("ses"))); const long sessionId = _tstol(session); const CString category(_ParseURL(Data.sURL, _T("cat"))); const int cat = category.IsEmpty() ? _GetLastUserCat(Data, sessionId) : _tstoi(category); const CString addDownload(_ParseURL(Data.sURL, _T("ed2k"))); const CString actionText(_ParseURL(Data.sURL, _T("name"))); WebTransferActionInput input; input.admin = bAdmin; input.category = cat; input.clearCompleted = std::string(CT2A(_ParseURL(Data.sURL, _T("clearcompleted")))); input.addDownload = std::string(CT2A(addDownload)); input.columnCommand = std::string(CT2A(_ParseURL(Data.sURL, _T("c")))); input.columnIndex = std::string(CT2A(_ParseURL(Data.sURL, _T("m")))); input.columnValue = std::string(CT2A(_ParseURL(Data.sURL, _T("v")))); input.categoryPriority = std::string(CT2A(_ParseURL(Data.sURL, _T("p")))); input.operation = std::string(CT2A(_ParseURL(Data.sURL, _T("op")))); input.fileHash = std::string(CT2A(_ParseURL(Data.sURL, _T("file")))); input.userHash = std::string(CT2A(_ParseURL(Data.sURL, _T("userhash")))); input.actionText = std::string(CT2A(actionText)); input.numericValue = std::string(CT2A(_ParseURL(Data.sURL, input.operation == "setcat" ? _T("filecat") : _T("part")))); input.sort = std::string(CT2A(_ParseURL(Data.sURL, _T("sort")))); input.sortReverse = std::string(CT2A(_ParseURL(Data.sURL, _T("sortreverse")))); input.showQueue = std::string(CT2A(_ParseURL(Data.sURL, _T("showuploadqueue")))); input.showBanned = std::string(CT2A(_ParseURL(Data.sURL, _T("showuploadqueuebanned")))); input.showFriend = std::string(CT2A(_ParseURL(Data.sURL, _T("showuploadqueuefriend")))); input.downloadSort = pThis->m_Params.DownloadSort; input.uploadSort = pThis->m_Params.UploadSort; input.queueSort = pThis->m_Params.QueueSort; input.downloadReverse = pThis->m_Params.bDownloadSortReverse; input.uploadReverse = pThis->m_Params.bUploadSortReverse; input.queueReverse = pThis->m_Params.bQueueSortReverse; input.queueVisible = pThis->m_Params.bShowUploadQueue; input.bannedVisible = pThis->m_Params.bShowUploadQueueBanned; input.friendVisible = pThis->m_Params.bShowUploadQueueFriend; struct TransferActionContext { CWebServer* owner; int category; CString fileHash; CString addDownload; CString actionText; } context{pThis, cat, _ParseURL(Data.sURL, _T("file")), addDownload, actionText}; WebTransferActionsPort port; port.context = &context;
	port.emit = [](void* raw, const WebTransferActionCommand& action) { TransferActionContext& c = *static_cast<TransferActionContext*>(raw); CString value(CA2CT(action.value.c_str())); switch (action.kind) { case WebTransferActionKind::ClearCompletedAll: theApp.emuledlg->SendMessage(WEB_CLEAR_COMPLETED, 0, c.category); break; case WebTransferActionKind::ClearCompletedFile: { uchar hash[MDX_DIGEST_SIZE]; if (strmd4(value, hash)) { uchar* copy = new uchar[MDX_DIGEST_SIZE]; md4cpy(copy, hash); theApp.emuledlg->SendMessage(WEB_CLEAR_COMPLETED, 1, reinterpret_cast<LPARAM>(copy)); } break; } case WebTransferActionKind::AddDownload: theApp.emuledlg->SendMessage(WEB_ADDDOWNLOADS, reinterpret_cast<WPARAM>((LPCTSTR)c.addDownload), c.category); break; case WebTransferActionKind::SaveDownloadColumn: case WebTransferActionKind::SaveUploadColumn: case WebTransferActionKind::SaveQueueColumn: { BOOL* columns = action.kind == WebTransferActionKind::SaveDownloadColumn ? WSdownloadColumnHidden : action.kind == WebTransferActionKind::SaveUploadColumn ? WSuploadColumnHidden : WSqueueColumnHidden; const int count = action.kind == WebTransferActionKind::SaveDownloadColumn ? 8 : action.kind == WebTransferActionKind::SaveUploadColumn ? 5 : 4; LPCTSTR key = action.kind == WebTransferActionKind::SaveDownloadColumn ? _T("downloadColumnHidden") : action.kind == WebTransferActionKind::SaveUploadColumn ? _T("uploadColumnHidden") : _T("queueColumnHidden"); columns[action.index] = action.flag; _SaveWIConfigArray(columns, count, key); break; } case WebTransferActionKind::CategoryPriorityLow: SendMessage(theApp.emuledlg->m_hWnd, WEB_CATPRIO, c.category, PR_LOW); break; case WebTransferActionKind::CategoryPriorityNormal: SendMessage(theApp.emuledlg->m_hWnd, WEB_CATPRIO, c.category, PR_NORMAL); break; case WebTransferActionKind::CategoryPriorityHigh: SendMessage(theApp.emuledlg->m_hWnd, WEB_CATPRIO, c.category, PR_HIGH); break; case WebTransferActionKind::CategoryPriorityAuto: SendMessage(theApp.emuledlg->m_hWnd, WEB_CATPRIO, c.category, PR_AUTO); break; case WebTransferActionKind::FriendAdd: case WebTransferActionKind::FriendRemove: { uchar hash[MDX_DIGEST_SIZE]; if (!strmd4(value, hash)) break; CUpDownClient* client = theApp.clientlist->FindClientByUserHash(hash); if (action.kind == WebTransferActionKind::FriendAdd && client) SendMessage(theApp.emuledlg->m_hWnd, WEB_ADDREMOVEFRIEND, reinterpret_cast<WPARAM>(client), 1); else if (action.kind == WebTransferActionKind::FriendRemove && client) { const CFriend* entry = theApp.friendlist->SearchFriend(hash, 0, 0); if (entry) SendMessage(theApp.emuledlg->m_hWnd, WEB_ADDREMOVEFRIEND, reinterpret_cast<WPARAM>(entry), 0); } break; } case WebTransferActionKind::FileStop: case WebTransferActionKind::FilePause: case WebTransferActionKind::FileResume: case WebTransferActionKind::FileCancel: case WebTransferActionKind::FileGetLink: case WebTransferActionKind::FileRename: case WebTransferActionKind::FilePriorityLow: case WebTransferActionKind::FilePriorityNormal: case WebTransferActionKind::FilePriorityHigh: case WebTransferActionKind::FilePriorityAuto: case WebTransferActionKind::FileSetCategory: case WebTransferActionKind::FileStreamSeek: { WebFileOperationRequest* request = new WebFileOperationRequest; CString hash = action.kind == WebTransferActionKind::FileRename ? c.fileHash : value; if (!strmd4(hash, request->fileHash)) { delete request; break; } switch (action.kind) { case WebTransferActionKind::FileStop: request->operation = WEBFILEOP_STOP; break; case WebTransferActionKind::FilePause: request->operation = WEBFILEOP_PAUSE; break; case WebTransferActionKind::FileResume: request->operation = WEBFILEOP_RESUME; break; case WebTransferActionKind::FileCancel: request->operation = WEBFILEOP_CANCEL; break; case WebTransferActionKind::FileGetLink: request->operation = WEBFILEOP_GETFLC; break; case WebTransferActionKind::FileRename: request->operation = WEBFILEOP_RENAME; request->text = c.actionText; break; case WebTransferActionKind::FilePriorityLow: request->operation = WEBFILEOP_PRIOLOW; break; case WebTransferActionKind::FilePriorityNormal: request->operation = WEBFILEOP_PRIONORMAL; break; case WebTransferActionKind::FilePriorityHigh: request->operation = WEBFILEOP_PRIOHIGH; break; case WebTransferActionKind::FilePriorityAuto: request->operation = WEBFILEOP_PRIOAUTO; break; case WebTransferActionKind::FileSetCategory: request->operation = WEBFILEOP_SETCAT; request->value = action.number; break; default: request->operation = WEBFILEOP_STREAMSEEK; request->value = action.number; break; } SendMessage(theApp.emuledlg->m_hWnd, WEB_GUI_INTERACTION, WEBGUIIA_FILE_OPERATION, reinterpret_cast<LPARAM>(request)); break; } default: break; } };
	if (!port.Complete()) return; M2AModuleHandle actionBinding = M2A_BIND_W5_095B87253F(M2AParentPort{pThis}); if (!actionBinding) return; const WebTransferActionResult result = RunWebTransferActions(M2AParentPort{pThis}, input, port); pThis->m_Params.DownloadSort = static_cast<DownloadSort>(result.downloadSort); pThis->m_Params.UploadSort = static_cast<UploadSort>(result.uploadSort); pThis->m_Params.QueueSort = static_cast<QueueSort>(result.queueSort); pThis->m_Params.bDownloadSortReverse = result.downloadReverse; pThis->m_Params.bUploadSortReverse = result.uploadReverse; pThis->m_Params.bQueueSortReverse = result.queueReverse; pThis->m_Params.bShowUploadQueue = result.queueVisible; pThis->m_Params.bShowUploadQueueBanned = result.bannedVisible; pThis->m_Params.bShowUploadQueueFriend = result.friendVisible;
}
CString CWebServer::_GetTransferList(const ThreadData &Data)
{
	CWebServer *pThis = reinterpret_cast<CWebServer*>(Data.pThis); if (pThis == NULL) return CString(); const CString sSession(_ParseURL(Data.sURL, _T("ses"))); const long lSession = _tstol(sSession); const bool bAdmin = _IsSessionAdmin(Data, lSession); int cat; const CString catp(_ParseURL(Data.sURL, _T("cat"))); if (catp.IsEmpty()) cat = _GetLastUserCat(Data, lSession); else { cat = _tstoi(catp); _SetLastUserCat(Data, lSession, cat); } CString sCat; if (cat != 0) sCat.Format(_T("&amp;cat=%i"), cat); CString ignored; _MakeTransferList(ignored, pThis, Data, nullptr, nullptr, bAdmin); const CString sFile(_ParseURL(Data.sURL, _T("file")));
	M2AModuleHandle projectionBinding = M2A_BIND_W4_AD763A5EE0(M2AParentPort{pThis}); if (!projectionBinding) return CString();
	WebTransferProjectionInput projection; projection.url = Data.sURL; projection.session = sSession; projection.categorySuffix = sCat; projection.selectedFile = sFile; projection.category = cat; projection.admin = bAdmin; projection.downloadSort = pThis->m_Params.DownloadSort; projection.uploadSort = pThis->m_Params.UploadSort; projection.queueSort = pThis->m_Params.QueueSort; projection.downloadReverse = pThis->m_Params.bDownloadSortReverse; projection.uploadReverse = pThis->m_Params.bUploadSortReverse; projection.queueReverse = pThis->m_Params.bQueueSortReverse; projection.showQueue = pThis->m_Params.bShowUploadQueue; projection.showBanned = pThis->m_Params.bShowUploadQueueBanned; projection.showFriend = pThis->m_Params.bShowUploadQueueFriend; projection.maxWebUploadFileSizeMB = thePrefs.GetMaxWebUploadFileSizeMB();
	for (unsigned i = 0; i < projection.downloadHidden.size(); ++i) projection.downloadHidden[i] = WSdownloadColumnHidden[i] != FALSE; for (unsigned i = 0; i < projection.uploadHidden.size(); ++i) projection.uploadHidden[i] = WSuploadColumnHidden[i] != FALSE; for (unsigned i = 0; i < projection.queueHidden.size(); ++i) projection.queueHidden[i] = WSqueueColumnHidden[i] != FALSE;
	struct ProjectionContext { CWebServer* owner; const ThreadData* data; } context{pThis, &Data}; WebTransferProjectionPort port; port.context = &context;
	port.templateText = [](void* raw, WebTransferTemplate id) { static const WebTemplateId ids[] = { WebTemplateId::TransferImages, WebTemplateId::TransferList, WebTemplateId::TransferDownHeader, WebTemplateId::TransferDownFooter, WebTemplateId::TransferDownLine, WebTemplateId::TransferUpHeader, WebTemplateId::TransferUpFooter, WebTemplateId::TransferUpLine, WebTemplateId::TransferUpQueueShow, WebTemplateId::TransferUpQueueHide, WebTemplateId::TransferUpQueueLine, WebTemplateId::TransferUpQueueBannedShow, WebTemplateId::TransferUpQueueBannedHide, WebTemplateId::TransferUpQueueBannedLine, WebTemplateId::TransferUpQueueFriendShow, WebTemplateId::TransferUpQueueFriendHide, WebTemplateId::TransferUpQueueFriendLine, WebTemplateId::ProgressbarWidth, WebTemplateId::CatArrow, WebTemplateId::DownArrow, WebTemplateId::UpArrow }; ProjectionContext* c = static_cast<ProjectionContext*>(raw); return GetWebTemplate(WebTemplateParent(c->owner), ids[static_cast<unsigned>(id)]); };
	port.plain = [](void*, unsigned id) { return _GetPlainResString(id); }; port.special = [](void*, const CString& text, bool noquote) { return _SpecialChars(text, noquote); }; port.insertCategory = [](void*, CString& out, int selected, LPCTSTR label, bool jump, bool extra, const CString& session, const CString& hash, int fileCategory) { InsertWebCategoryBox(out, selected, label, jump, extra, session, hash, fileCategory, false); };
	port.snapshot = [](void* rawContext, int selectedCategory, unsigned, bool, unsigned, bool, unsigned queueSort, bool queueReverse, bool showQueue, bool showBanned, bool showFriend, WebTransferSnapshot& snapshot) {
		struct Capture { int category; unsigned queueSort; bool queueReverse, showQueue, showBanned, showFriend; const ThreadData* data; WebTransferSnapshot* output; } capture{selectedCategory, queueSort, queueReverse, showQueue, showBanned, showFriend, static_cast<ProjectionContext*>(rawContext)->data, &snapshot}; WebTransferSnapshotRequest request; request.context = &capture; request.capture = [](void* raw) { Capture& parameters = *static_cast<Capture*>(raw); const int selectedCategory = parameters.category; const unsigned queueSort = parameters.queueSort; const bool queueReverse = parameters.queueReverse, showQueue = parameters.showQueue, showBanned = parameters.showBanned, showFriend = parameters.showFriend; WebTransferSnapshot& snapshot = *parameters.output;
		CArray<CPartFile*, CPartFile*> parts; theApp.emuledlg->transferwnd->GetDownloadList()->GetDisplayedFiles(&parts);
		for (INT_PTR i = 0; i < parts.GetCount(); ++i) { CPartFile* part = parts[i]; if (!part) continue; bool include = true; if (selectedCategory < 0) { switch (selectedCategory) { case -1: include = part->GetCategory() == 0; break; case -2: include = part->IsPartFile(); break; case -3: include = !part->IsPartFile(); break; case -4: include = (part->GetStatus() == PS_READY || part->GetStatus() == PS_EMPTY) && part->GetTransferringSrcCount() == 0; break; case -5: include = (part->GetStatus() == PS_READY || part->GetStatus() == PS_EMPTY) && part->GetTransferringSrcCount() > 0; break; case -6: include = part->GetStatus() == PS_ERROR; break; case -7: include = part->GetStatus() == PS_PAUSED || part->IsStopped(); break; case -8: include = part->lastseencomplete != 0; break; case -9: include = part->IsMovie(); break; case -10: include = ED2KFT_AUDIO == GetED2KFileTypeID(part->GetFileName()); break; case -11: include = part->IsArchive(); break; case -12: include = ED2KFT_CDIMAGE == GetED2KFileTypeID(part->GetFileName()); break; case -13: include = ED2KFT_DOCUMENT == GetED2KFileTypeID(part->GetFileName()); break; case -14: include = ED2KFT_IMAGE == GetED2KFileTypeID(part->GetFileName()); break; case -15: include = ED2KFT_PROGRAM == GetED2KFileTypeID(part->GetFileName()); break; case -16: include = ED2KFT_EMULECOLLECTION == GetED2KFileTypeID(part->GetFileName()); break; } } else if (selectedCategory > 0) include = part->GetCategory() == static_cast<UINT>(selectedCategory); if (!include) continue;
			DownloadFiles item{}; item.sFileName = _SpecialChars(part->GetFileName()); item.sFileType = _GetWebImageNameForFileType(item.sFileName); item.sFileNameJS = _SpecialChars(part->GetFileName()); item.m_qwFileSize = part->GetFileSize(); item.m_qwFileTransferred = part->GetCompletedSize(); item.m_dblCompleted = part->GetPercentCompleted(); item.lFileSpeed = part->GetDatarate(); item.iComment = part->HasComment() || part->HasRating() ? (part->HasBadRating() ? 2 : 1) : 0; item.iFileState = part->getPartfileStatusRank();
			switch (part->GetStatus()) { case PS_HASHING: item.sFileState = _T("hashing"); break; case PS_WAITINGFORHASH: item.sFileState = _T("waitinghash"); break; case PS_ERROR: item.sFileState = _T("error"); break; case PS_COMPLETING: item.sFileState = _T("completing"); break; case PS_COMPLETE: item.sFileState = _T("complete"); break; case PS_PAUSED: item.sFileState = part->IsStopped() ? _T("stopped") : _T("paused"); break; default: item.sFileState = part->GetDatarate() > 0 ? _T("downloading") : _T("waiting"); }
			item.bFileAutoPrio = part->IsAutoDownPriority(); item.nFilePrio = part->GetDownPriority(); item.nCategory = part->GetCategory(); item.sCategory = thePrefs.GetCategory(item.nCategory)->strTitle; item.sCategory.Replace(_T("'"), _T("\\'")); item.sFileHash = md4str(part->GetFileHash()); item.sDownloadGraph = _GetDownloadGraph(*parameters.data, item.sFileHash); item.lSourceCount = part->GetSourceCount(); item.lNotCurrentSourceCount = part->GetNotCurrentSourcesCount(); item.lTransferringSourceCount = part->GetTransferringSrcCount(); item.bIsComplete = !part->IsPartFile(); item.bIsPreview = part->IsReadyForPreview(); item.bIsGetFLC = part->GetPreviewPrio(); item.sED2kLink = theApp.GetPublicIP() != 0 && !theApp.IsFirewalled() ? part->GetED2kLink(false, false, false, true, theApp.GetPublicIP()) : part->GetED2kLink(); item.sFileInfo = _SpecialChars(part->GetInfoSummary(true), false); snapshot.downloads.Add(item); }
		for (POSITION pos = theApp.uploadqueue->GetFirstFromUploadList(); pos != NULL;) { const CUpDownClient& client(*theApp.uploadqueue->GetNextFromUploadList(pos)); UploadUsers item{}; item.sUserHash = md4str(client.GetUserHash()); item.sActive = client.GetUploadDatarate() > 0 ? _T("downloading") : _T("waiting"); item.sClientState = client.GetUploadDatarate() > 0 ? _T("uploading") : _T("connecting"); item.sFileInfo = _SpecialChars(_GetClientSummary(client), false); item.sFileInfo.Replace(_T("\\"), _T("\\\\")); item.sFileInfo.Replace(_T("\n"), _T("<br>")); item.sFileInfo.Replace(_T("'"), _T("&#8217;")); _GetClientversionImage(client, item.sClientSoft); item.sClientExtra = client.IsBanned() ? _T("banned") : (client.IsFriend() ? _T("friend") : (client.Credits()->GetScoreRatio(client.GetIP()) > 1 ? _T("credit") : _T("none"))); CString name(client.GetUserName()); if (name.GetLength() > SHORT_LENGTH_MIN) { name.Truncate(SHORT_LENGTH_MIN - 3); name += _T("..."); } item.sUserName = _SpecialChars(name); CKnownFile* known = theApp.sharedfiles->GetFileByID(client.GetUploadFileID()); item.sFileName = known ? _SpecialChars(known->GetFileName()) : _GetPlainResString(IDS_REQ_UNKNOWNFILE); item.nTransferredDown = client.GetTransferredDown(); item.nTransferredUp = client.GetTransferredUp(); const UINT rate = client.GetUploadDatarate(); item.nDataRate = rate == UNLIMITED ? 0 : rate; item.sClientNameVersion = client.GetClientSoftVer(); snapshot.uploads.Add(item); }
		CQArray<QueueUsers, QueueUsers> queue; for (POSITION pos = theApp.uploadqueue->waitinglist.GetHeadPosition(); pos != NULL;) { const CUpDownClient& client(*theApp.uploadqueue->waitinglist.GetNext(pos)); QueueUsers item{}; const int secure = client.Credits()->GetCurrentIdentState(client.GetIP()) == IS_IDENTIFIED; if (client.IsBanned()) { item.sClientExtra = _T("banned"); ++snapshot.bannedCount; snapshot.bannedSecure += secure; } else if (client.IsFriend()) { item.sClientExtra = _T("friend"); ++snapshot.friendCount; snapshot.friendSecure += secure; } else { item.sClientExtra = _T("none"); ++snapshot.queueCount; snapshot.queueSecure += secure; } CString name(client.GetUserName()); if (name.GetLength() > SHORT_LENGTH_MIN) { name.Truncate(SHORT_LENGTH_MIN - 3); name += _T("..."); } item.sUserName = _SpecialChars(name); item.sClientNameVersion = client.GetClientSoftVer(); CKnownFile* known = theApp.sharedfiles->GetFileByID(client.GetUploadFileID()); item.sFileName = known ? _SpecialChars(known->GetFileName()) : _GetPlainResString(IDS_REQ_UNKNOWNFILE); item.sClientState = item.sClientExtra; item.sClientStateSpecial = _T("connecting"); item.nScore = client.GetScore(false); _GetClientversionImage(client, item.sClientSoft); item.sUserHash = md4str(client.GetUserHash()); switch (queueSort) { case QU_SORT_CLIENT: item.sIndex = item.sClientSoft; break; case QU_SORT_USER: item.sIndex = item.sUserName; break; case QU_SORT_VERSION: item.sIndex = item.sClientNameVersion; break; case QU_SORT_FILENAME: item.sIndex = item.sFileName; break; case QU_SORT_SCORE: item.sIndex.Format(_T("%09u"), item.nScore); } queue.Add(item); }
		INT_PTR next = 0; uint32 score = 0; for (INT_PTR i = queue.GetCount(); --i >= 0;) if (queue[i].nScore > score) { next = i; score = queue[i].nScore; } if (queue.GetCount() != 0) { queue[next].sClientState = _T("next"); queue[next].sClientStateSpecial = queue[next].sClientState; } if ((snapshot.queueCount > 0 && showQueue) || (snapshot.bannedCount > 0 && showBanned) || (snapshot.friendCount > 0 && showFriend)) queue.QuickSort(queueReverse); for (INT_PTR i = 0; i < queue.GetCount(); ++i) snapshot.queue.Add(queue[i]);
		}; SendMessage(theApp.emuledlg->m_hWnd, WEB_GUI_INTERACTION, WEBGUIIA_TRANSFER_SNAPSHOT, reinterpret_cast<LPARAM>(&request));
	};
	if (!port.Complete()) return CString(); return RunWebTransferProjection(M2AParentPort{pThis}, projection, port);
}
CString CWebServer::_GetSharedFilesList(const ThreadData &Data)
{
	M2AModuleHandle sharedFilesBinding = M2A_BIND_W6_B161DA740E(M2AParentPort{Data.pThis}); if (!sharedFilesBinding) return CString(); CWebServer* const pThis = static_cast<CWebServer*>(Data.pThis); if (pThis == NULL) return CString();
	const auto wide = [](const CString& value) { return std::wstring(static_cast<LPCWSTR>(value), static_cast<std::size_t>(value.GetLength())); };
	const auto lower = [&wide](const CString& value) { CString folded(value); folded.MakeLower(); return wide(folded); };
	const CString sSession(_ParseURL(Data.sURL, _T("ses"))); const bool admin = _IsSessionAdmin(Data, sSession);
	const CString sort(_ParseURL(Data.sURL, _T("sort"))); const CString sortReverse(_ParseURL(Data.sURL, _T("sortreverse")));
	const ese::web::WebSharedSortDecision sortDecision = ese::web::WebSharedController::PlanSort(admin, std::string(CT2A(sort)), std::string(CT2A(sortReverse)));
	if (sortDecision.allowed) { if (sortDecision.update_sort) pThis->m_Params.SharedSort = static_cast<SharedSort>(sortDecision.target_index); if (sortDecision.update_reverse) pThis->m_Params.bSharedSortReverse = sortDecision.reverse; }
	const CString selectedHash(_ParseURL(Data.sURL, _T("hash"))); const CString priorityText(_ParseURL(Data.sURL, _T("prio")));
	const ese::web::WebSharedPriorityDecision priorityDecision = ese::web::WebSharedController::PlanPriority(admin, std::string(CT2A(selectedHash)), std::string(CT2A(priorityText)));
	uchar priorityFileId[MDX_DIGEST_SIZE]; if (priorityDecision.allowed && DecodeBase16(selectedHash, selectedHash.GetLength(), priorityFileId, _countof(priorityFileId))) {
		CKnownFile* file = theApp.sharedfiles->GetFileByID(priorityFileId); if (file != NULL) { if (priorityDecision.priority == ese::web::WebSharedPriority::Auto) { file->SetAutoUpPriority(true); file->UpdateAutoUpPriority(); } else { const uint8 value = priorityDecision.priority == ese::web::WebSharedPriority::VeryLow ? PR_VERYLOW : (priorityDecision.priority == ese::web::WebSharedPriority::Low ? PR_LOW : (priorityDecision.priority == ese::web::WebSharedPriority::Normal ? PR_NORMAL : (priorityDecision.priority == ese::web::WebSharedPriority::High ? PR_HIGH : PR_VERYHIGH))); file->SetAutoUpPriority(false); file->SetUpPriority(value); } SendMessage(theApp.emuledlg->m_hWnd, WEB_GUI_INTERACTION, WEBGUIIA_UPD_SFUPDATE, reinterpret_cast<LPARAM>(file)); }
	}
	if (_ParseURL(Data.sURL, _T("c")) == _T("menu")) { const CString index(_ParseURL(Data.sURL, _T("m"))); const CString hidden(_ParseURL(Data.sURL, _T("v"))); const ese::web::WebSharedColumnChange change = ese::web::WebSharedController::PlanColumnChange(admin, std::string(CT2A(index)), std::string(CT2A(hidden))); if (change.allowed) { WSsharedColumnHidden[change.index] = change.hidden; _SaveWIConfigArray(WSsharedColumnHidden, _countof(WSsharedColumnHidden), _T("sharedColumnHidden")); } }
	const CString reload(_ParseURL(Data.sURL, _T("reload"))); if (ese::web::WebSharedController::PlanReload(admin, std::string(CT2A(reload)))) SendMessage(theApp.emuledlg->m_hWnd, WEB_GUI_INTERACTION, WEBGUIIA_SHARED_FILES_RELOAD, 0);
	CString message; if (reload == _T("true")) { message = _SpecialChars(theApp.emuledlg->GetLastLogEntry().TrimRight(_T('\n'))); const int newline = message.ReverseFind(_T('\n')); if (newline > 0) message.Delete(0, newline); }
	WebSharedFilesInput input; input.pageTemplate = wide(GetWebTemplate(WebTemplateParent(pThis), WebTemplateId::SharedList)); input.rowTemplate = wide(GetWebTemplate(WebTemplateParent(pThis), WebTemplateId::SharedLine)); input.session = wide(sSession); input.selectedHash = wide(selectedHash); input.message = wide(message);
	input.upArrow = wide(GetWebTemplate(WebTemplateParent(pThis), WebTemplateId::UpArrow)); input.downArrow = wide(GetWebTemplate(WebTemplateParent(pThis), WebTemplateId::DownArrow)); input.upDoubleArrow = wide(GetWebTemplate(WebTemplateParent(pThis), WebTemplateId::UpDoubleArrow)); input.downDoubleArrow = wide(GetWebTemplate(WebTemplateParent(pThis), WebTemplateId::DownDoubleArrow));
	input.columnNames = { wide(_GetPlainResString(IDS_DL_FILENAME)), wide(_GetPlainResString(IDS_SF_TRANSFERRED)), wide(_GetPlainResString(IDS_SF_REQUESTS)), wide(_GetPlainResString(IDS_SF_ACCEPTS)), wide(_GetPlainResString(IDS_DL_SIZE)), wide(_GetPlainResString(IDS_COMPLSOURCES)), wide(_GetPlainResString(IDS_PRIORITY)) };
	input.actionsLabel = wide(_GetPlainResString(IDS_WEB_ACTIONS)); input.reloadLabel = wide(_GetPlainResString(IDS_SF_RELOAD)); input.sharedListLabel = wide(_GetPlainResString(IDS_SHAREDFILES));
	input.hidden = {{ !!WSsharedColumnHidden[0], !!WSsharedColumnHidden[1], !!WSsharedColumnHidden[2], !!WSsharedColumnHidden[3], !!WSsharedColumnHidden[4], !!WSsharedColumnHidden[5], !!WSsharedColumnHidden[6] }}; input.sort = static_cast<WebSharedFilesSort>(pThis->m_Params.SharedSort); input.reverse = pThis->m_Params.bSharedSortReverse; input.admin = admin; input.maximumDownloadMiB = thePrefs.GetMaxWebUploadFileSizeMB(); input.shortNameLimit = SHORT_LENGTH;
	for (POSITION pos = BEFORE_START_POSITION; pos != NULL;) {
		CKnownFile* file = theApp.sharedfiles->GetFileNext(pos); if (file == NULL) continue; WebSharedFilesRow row; const CString fileName(file->GetFileName()); const CString fileState(file->IsPartFile() ? _T("filedown") : _T("file")); const CString fileType(_GetWebImageNameForFileType(fileName));
		row.hash = wide(md4str(file->GetFileHash())); row.fileName = wide(fileName); row.fileState = wide(fileState); row.fileType = wide(fileType); row.ed2kLink = wide(theApp.GetPublicIP() && !theApp.IsFirewalled() ? file->GetED2kLink(false, false, false, true, theApp.GetPublicIP()) : file->GetED2kLink()); row.textOrder = { lower(fileState), lower(fileType), lower(fileName) };
		row.fileSizeBytes = file->GetFileSize(); row.transferredBytes = file->statistic.GetTransferred(); row.allTimeTransferredBytes = file->statistic.GetAllTimeTransferred(); row.requests = file->statistic.GetRequests(); row.allTimeRequests = file->statistic.GetAllTimeRequests(); row.accepts = file->statistic.GetAccepts(); row.allTimeAccepts = file->statistic.GetAllTimeAccepts();
		row.fileSizeText = wide(CString(CastItoXBytes(row.fileSizeBytes))); row.transferredText = wide(CString(CastItoXBytes(row.transferredBytes))); row.allTimeTransferredText = wide(CString(CastItoXBytes(row.allTimeTransferredBytes))); row.completeSourcesLow = file->m_nCompleteSourcesCountLo; row.completeSourcesHigh = file->m_nCompleteSourcesCountHi; row.completeSourcesOrder = file->m_nCompleteSourcesCount;
		const uint8 rawPriority = file->GetUpPriority(); row.priorityOrder = CSharedFileList::GetRealPrio(rawPriority); row.autoPriority = file->IsAutoUpPriority(); row.partFile = file->IsPartFile(); UINT priorityResource = IDS_PRIONORMAL;
		if (rawPriority == PR_VERYLOW) { row.priority = WebSharedFilePriority::VeryLow; priorityResource = row.autoPriority ? IDS_PRIOAUTONORMAL : IDS_PRIOVERYLOW; } else if (rawPriority == PR_LOW) { row.priority = WebSharedFilePriority::Low; priorityResource = row.autoPriority ? IDS_PRIOAUTOLOW : IDS_PRIOLOW; } else if (rawPriority == PR_HIGH) { row.priority = WebSharedFilePriority::High; priorityResource = row.autoPriority ? IDS_PRIOAUTOHIGH : IDS_PRIOHIGH; } else if (rawPriority == PR_VERYHIGH) { row.priority = WebSharedFilePriority::Release; priorityResource = row.autoPriority ? IDS_PRIOAUTORELEASE : IDS_PRIORELEASE; } else { row.priority = WebSharedFilePriority::Normal; priorityResource = row.autoPriority ? IDS_PRIOAUTONORMAL : IDS_PRIONORMAL; }
		row.priorityLabel = wide(GetResString(priorityResource)); input.rows.push_back(std::move(row));
	}
	const std::wstring rendered = RunWebSharedFilesController(M2AParentPort{pThis}, input); return CString(rendered.c_str());
}

CString CWebServer::_GetGraphs(const ThreadData &Data)
{
	const CWebServer *pThis = reinterpret_cast<CWebServer*>(Data.pThis);
	if (pThis == NULL)
		return CString();

	CString Out(GetWebTemplate(WebTemplateParent(pThis), WebTemplateId::Graphs));

	CString strGraphDownload, strGraphUpload, strGraphCons;
	LPCTSTR pszFmt = _T("%u");
	INT_PTR cnt = min(WEB_GRAPH_WIDTH, pThis->m_Params.PointsForWeb.GetCount());
	for (INT_PTR i = 0; i < cnt; ++i) {
		const UpDown &pt = pThis->m_Params.PointsForWeb[i];
		// download
		strGraphDownload.AppendFormat(pszFmt, (uint32)(pt.download * 1024));
		// upload
		strGraphUpload.AppendFormat(pszFmt, (uint32)(pt.upload * 1024));
		// connections
		strGraphCons.AppendFormat(pszFmt, (uint32)(pt.connections));
		pszFmt = _T(",%u");
	}

	Out.Replace(_T("[GraphDownload]"), strGraphDownload);
	Out.Replace(_T("[GraphUpload]"), strGraphUpload);
	Out.Replace(_T("[GraphConnections]"), strGraphCons);

	Out.Replace(_T("[TxtDownload]"), _GetPlainResString(IDS_TW_DOWNLOADS));
	Out.Replace(_T("[TxtUpload]"), _GetPlainResString(IDS_TW_UPLOADS));
	Out.Replace(_T("[TxtTime]"), _GetPlainResString(IDS_TIME));
	Out.Replace(_T("[KByteSec]"), _GetPlainResString(IDS_KBYTESPERSEC));
	Out.Replace(_T("[TxtConnections]"), _GetPlainResString(IDS_SP_ACTCON));

	Out.Replace(_T("[ScaleTime]"), (LPCTSTR)CastSecondsToHM(((time_t)thePrefs.GetTrafficOMeterInterval()) * WEB_GRAPH_WIDTH));

	CString s1;
	s1.Format(_T("%u"), thePrefs.GetMaxGraphDownloadRate() + 4);
	Out.Replace(_T("[MaxDownload]"), s1);
	s1.Format(_T("%u"), thePrefs.GetMaxGraphUploadRate(true) + 4);
	Out.Replace(_T("[MaxUpload]"), s1);
	s1.Format(_T("%u"), thePrefs.GetMaxConnections() + 20);
	Out.Replace(_T("[MaxConnections]"), s1);

	return Out;
}
CString CWebServer::_GetLog(const ThreadData &Data)
{
	const CWebServer* owner = reinterpret_cast<CWebServer*>(Data.pThis); if (owner == NULL) return CString(); const CString session(_ParseURL(Data.sURL, _T("ses"))); if (_ParseURL(Data.sURL, _T("clear")) == _T("yes") && _IsSessionAdmin(Data, session)) theApp.emuledlg->ResetLog(); return RenderWebLogView(WebTemplateLogView::Log, GetWebTemplate(WebTemplateParent(owner), WebTemplateId::Log), session, theApp.emuledlg->GetAllLogEntries());
}
CString CWebServer::_GetServerInfo(const ThreadData &Data)
{
	const CWebServer* owner = reinterpret_cast<CWebServer*>(Data.pThis); if (owner == NULL) return CString(); const CString session(_ParseURL(Data.sURL, _T("ses"))); if (_ParseURL(Data.sURL, _T("clear")) == _T("yes") && _IsSessionAdmin(Data, session)) theApp.emuledlg->ResetServerInfo(); return RenderWebLogView(WebTemplateLogView::ServerInfo, GetWebTemplate(WebTemplateParent(owner), WebTemplateId::ServerInfo), session, theApp.emuledlg->GetServerInfoText());
}
CString CWebServer::_GetDebugLog(const ThreadData &Data)
{
	const CWebServer* owner = reinterpret_cast<CWebServer*>(Data.pThis); if (owner == NULL) return CString(); const CString session(_ParseURL(Data.sURL, _T("ses"))); if (_ParseURL(Data.sURL, _T("clear")) == _T("yes") && _IsSessionAdmin(Data, session)) theApp.emuledlg->ResetDebugLog(); return RenderWebLogView(WebTemplateLogView::DebugLog, GetWebTemplate(WebTemplateParent(owner), WebTemplateId::DebugLog), session, theApp.emuledlg->GetAllDebugLogEntries());
}
CString CWebServer::_GetMyInfo(const ThreadData &Data)
{
	const CWebServer* owner = reinterpret_cast<CWebServer*>(Data.pThis); return owner == NULL ? CString() : RenderWebMyInfo(GetWebTemplate(WebTemplateParent(owner), WebTemplateId::MyInfoLog), theApp.emuledlg->serverwnd->GetMyInfoString());
}
CString CWebServer::_GetKadDlg(const ThreadData &Data)
{
	const CWebServer *pThis = reinterpret_cast<CWebServer*>(Data.pThis);
	if (pThis == NULL)
		return CString();

	/*if (!thePrefs.GetNetworkKademlia()) {
		CString buffer;
		buffer.Format(_T("<br><center>[KADDEACTIVATED]</center>")  );
		return buffer;
	}*/

	const CString &sSession(_ParseURL(Data.sURL, _T("ses")));
	CString Out(GetWebTemplate(WebTemplateParent(pThis), WebTemplateId::Kad));

	if (_IsSessionAdmin(Data, sSession)) {
		if (!_ParseURL(Data.sURL, _T("bootstrap")).IsEmpty()) {
			CString dest(_ParseURL(Data.sURL, _T("ip")));
			// Keep an IPv6 literal as a single host when the GUI message
			// transports the host:port pair.
			if (dest.Find(_T(':')) >= 0 &&
				(dest.IsEmpty() || dest[0] != _T('[')))
				dest = _T("[") + dest + _T("]");
			dest.AppendFormat(_T(":%s"), (LPCTSTR)_ParseURL(Data.sURL, _T("port")));
			SendMessage(theApp.emuledlg->m_hWnd, WEB_GUI_INTERACTION, WEBGUIIA_KAD_BOOTSTRAP, (LPARAM)(LPCTSTR)dest);
		}

		const CString &sAction(_ParseURL(Data.sURL, _T("c")));
		if (sAction == _T("connect"))
			SendMessage(theApp.emuledlg->m_hWnd, WEB_GUI_INTERACTION, WEBGUIIA_KAD_START, 0);
		else if (sAction == _T("disconnect"))
			SendMessage(theApp.emuledlg->m_hWnd, WEB_GUI_INTERACTION, WEBGUIIA_KAD_STOP, 0);
		else if (sAction == _T("rcfirewall"))
			SendMessage(theApp.emuledlg->m_hWnd, WEB_GUI_INTERACTION, WEBGUIIA_KAD_RCFW, 0);
	}
	// check the condition if bootstrap is possible
	Out.Replace(_T("[BOOTSTRAPLINE]"),
		(!thePrefs.IsKad2Enabled() || Kademlia::CKademlia::IsKad2Connected())
			? _T("") : (LPCTSTR)GetWebTemplate(WebTemplateParent(pThis), WebTemplateId::BootstrapLine));

	// Infos
	CString buffer;
	CString kad2State = GetResString(Kademlia::CKademlia::IsKad2Connected()
		? (Kademlia::CKademlia::IsFirewalled() ? IDS_FIREWALLED : IDS_CONNECTED)
		: (Kademlia::CKademlia::IsKad2Running() ? IDS_CONNECTING : IDS_DISCONNECTED));
	CString kad6State = GetResString(Kademlia::CKademlia::IsKad6Connected()
		? IDS_CONNECTED
		: (Kademlia::CKademlia::IsKad6Running() ? IDS_CONNECTING : IDS_DISCONNECTED));
	CString kadState;
	kadState.Format(_T("Kad2: %s | Kad6: %s"), (LPCTSTR)kad2State,
		(LPCTSTR)kad6State);
	Out.Replace(_T("[KADSTATUS]"), kadState);
	if (Kademlia::CKademlia::IsRunning()) {
		if (Kademlia::CKademlia::IsKad2Connected()
			&& Kademlia::CKademlia::IsFirewalled())
			buffer.Format(_T("<a href=\"?ses=%s&amp;w=kad&amp;c=rcfirewall\">%s</a><br>"),
				(LPCTSTR)sSession, (LPCTSTR)GetResString(IDS_KAD_RECHECKFW));
		else
			buffer.Empty();
		buffer.AppendFormat(_T("<a href=\"?ses=%s&amp;w=kad&amp;c=disconnect\">%s</a>"),
			(LPCTSTR)sSession, (LPCTSTR)GetResString(IDS_IRC_DISCONNECT));
	} else {
		buffer.Format(_T("<a href=\"?ses=%s&amp;w=kad&amp;c=connect\">%s</a>"),
			(LPCTSTR)sSession, (LPCTSTR)GetResString(IDS_IRC_CONNECT));
	}

		Out.Replace(_T("[KADACTION]"), buffer);

		// kadstats
		// labels
		buffer.Format(_T("Kad2 %s<br>Kad6 %s<br>%s"),
			(LPCTSTR)GetResString(IDS_KADCONTACTLAB),
			(LPCTSTR)GetResString(IDS_KADCONTACTLAB),
			(LPCTSTR)GetResString(IDS_KADSEARCHLAB));
		Out.Replace(_T("[KADSTATSLABELS]"), buffer);

		// numbers
		buffer.Format(_T("%u<br>%u<br>%i"),
			theApp.emuledlg->kademliawnd->GetContactCount(),
			Kademlia::CKademlia::GetKad6VerifiedContacts(),
			theApp.emuledlg->kademliawnd->searchList->GetItemCount());
		Out.Replace(_T("[KADSTATSDATA]"), buffer);

		Out.Replace(_T("[BS_IP]"), GetResString(IDS_IP));
		Out.Replace(_T("[BS_PORT]"), GetResString(IDS_PORT));
		Out.Replace(_T("[BOOTSTRAP]"), GetResString(IDS_BOOTSTRAP));
		Out.Replace(_T("[KADSTAT]"), GetResString(IDS_STATSSETUPINFO));
		Out.Replace(_T("[STATUS]"), GetResString(IDS_STATUS));
		Out.Replace(_T("[KAD]"), GetResString(IDS_KADEMLIA));
		Out.Replace(_T("[Session]"), sSession);

		return Out;
}

CString CWebServer::_GetStats(const ThreadData &Data)
{
	const CWebServer* owner = reinterpret_cast<CWebServer*>(Data.pThis); if (owner == NULL) return CString(); SendMessage(theApp.emuledlg->m_hWnd, WEB_GUI_INTERACTION, WEBGUIIA_SHOWSTATISTICS, 1); return RenderWebStats(GetWebTemplate(WebTemplateParent(owner), WebTemplateId::Stats), theApp.emuledlg->statisticswnd->m_stattree.GetHTMLForExport());
}
CString CWebServer::_GetPreferences(const ThreadData &Data)
{
	const CWebServer *pThis = reinterpret_cast<CWebServer*>(Data.pThis);
	if (pThis == NULL)
		return CString();

	const CString &sSession(_ParseURL(Data.sURL, _T("ses")));

	CString Out(GetWebTemplate(WebTemplateParent(pThis), WebTemplateId::Preferences));
	Out.Replace(_T("[Session]"), sSession);

	if ((_ParseURL(Data.sURL, _T("saveprefs")) == _T("true")) && _IsSessionAdmin(Data, sSession)) {
		CString strTmp(_ParseURL(Data.sURL, _T("gzip")));
		if (strTmp == _T("true") || strTmp == _T("on"))
			thePrefs.SetWebUseGzip(true);
		else if (strTmp == _T("false") || strTmp.IsEmpty())
			thePrefs.SetWebUseGzip(false);

		if (!_ParseURL(Data.sURL, _T("refresh")).IsEmpty())
			thePrefs.SetWebPageRefresh(_tstoi(_ParseURL(Data.sURL, _T("refresh"))));

		strTmp = _ParseURL(Data.sURL, _T("maxcapdown"));
		if (!strTmp.IsEmpty())
			thePrefs.SetMaxGraphDownloadRate(_tstoi(strTmp));
		strTmp = _ParseURL(Data.sURL, _T("maxcapup"));
		if (!strTmp.IsEmpty())
			thePrefs.SetMaxGraphUploadRate(_tstoi(strTmp));

		strTmp = _ParseURL(Data.sURL, _T("maxdown"));
		if (!strTmp.IsEmpty()) {
			uint32 dwSpeed = _tstoi(strTmp);
			thePrefs.SetMaxDownload(dwSpeed > 0 ? dwSpeed : UNLIMITED);
		}
		strTmp = _ParseURL(Data.sURL, _T("maxup"));
		if (!strTmp.IsEmpty()) {
			uint32 dwSpeed = _tstoi(strTmp);
			thePrefs.SetMaxUpload(dwSpeed > 0 ? dwSpeed : UNLIMITED);
		}

		if (!_ParseURL(Data.sURL, _T("maxsources")).IsEmpty())
			thePrefs.SetMaxSourcesPerFile(_tstoi(_ParseURL(Data.sURL, _T("maxsources"))));
		if (!_ParseURL(Data.sURL, _T("maxconnections")).IsEmpty())
			thePrefs.SetMaxConnections(_tstoi(_ParseURL(Data.sURL, _T("maxconnections"))));
		if (!_ParseURL(Data.sURL, _T("maxconnectionsperfive")).IsEmpty())
			thePrefs.SetMaxConsPerFive(_tstoi(_ParseURL(Data.sURL, _T("maxconnectionsperfive"))));
	}

	// Fill form
	Out.Replace(_T("[UseGzipVal]"), thePrefs.GetWebUseGzip() ? _T("checked") : _T(""));

	CString sRefresh;
	sRefresh.Format(_T("%d"), thePrefs.GetWebPageRefresh());
	Out.Replace(_T("[RefreshVal]"), sRefresh);

	sRefresh.Format(_T("%u"), thePrefs.GetMaxSourcePerFileDefault());
	Out.Replace(_T("[MaxSourcesVal]"), sRefresh);

	sRefresh.Format(_T("%u"), thePrefs.GetMaxConnections());
	Out.Replace(_T("[MaxConnectionsVal]"), sRefresh);

	sRefresh.Format(_T("%u"), thePrefs.GetMaxConperFive());
	Out.Replace(_T("[MaxConnectionsPer5Val]"), sRefresh);

	Out.Replace(_T("[KBS]"), _GetPlainResString(IDS_KBYTESPERSEC) + _T(':'));
	Out.Replace(_T("[LimitForm]"), _GetPlainResString(IDS_WEB_CONLIMITS) + _T(':'));
	Out.Replace(_T("[MaxSources]"), _GetPlainResString(IDS_PW_MAXSOURCES) + _T(':'));
	Out.Replace(_T("[MaxConnections]"), _GetPlainResString(IDS_PW_MAXC) + _T(':'));
	Out.Replace(_T("[MaxConnectionsPer5]"), _GetPlainResString(IDS_MAXCON5SECLABEL) + _T(':'));
	Out.Replace(_T("[UseGzipForm]"), _GetPlainResString(IDS_WEB_GZIP_COMPRESSION));
	Out.Replace(_T("[UseGzipComment]"), _GetPlainResString(IDS_WEB_GZIP_COMMENT));

	Out.Replace(_T("[RefreshTimeForm]"), _GetPlainResString(IDS_WEB_REFRESH_TIME));
	Out.Replace(_T("[RefreshTimeComment]"), _GetPlainResString(IDS_WEB_REFRESH_COMMENT));
	Out.Replace(_T("[SpeedForm]"), _GetPlainResString(IDS_SPEED_LIMITS));
	Out.Replace(_T("[SpeedCapForm]"), _GetPlainResString(IDS_CAPACITY_LIMITS));

	Out.Replace(_T("[MaxCapDown]"), _GetPlainResString(IDS_PW_CON_DOWNLBL));
	Out.Replace(_T("[MaxCapUp]"), _GetPlainResString(IDS_PW_CON_UPLBL));
	Out.Replace(_T("[MaxDown]"), _GetPlainResString(IDS_PW_CON_DOWNLBL));
	Out.Replace(_T("[MaxUp]"), _GetPlainResString(IDS_PW_CON_UPLBL));
	Out.Replace(_T("[WebControl]"), _GetPlainResString(IDS_WEB_CONTROL));
	Out.Replace(_T("[eMuleAppName]"), _T("eMule"));
	Out.Replace(_T("[Apply]"), _GetPlainResString(IDS_PW_APPLY));

	CString m_sTestURL;
	m_sTestURL.Format(PORTTESTURL, theApp.GetAdvertisedTcpPort(),
		theApp.GetAdvertisedUdpPort(), thePrefs.GetLanguageID());

	// the portcheck will need to do an obfuscated callback too if obfuscation is requested, so we have to provide our userhash so it can create the key
	if (thePrefs.IsCryptLayerPreferred())
		m_sTestURL.AppendFormat(_T("&obfuscated_test=%s"), (LPCTSTR)md4str(thePrefs.GetUserHash()));

	Out.Replace(_T("[CONNECTIONTESTLINK]"), _SpecialChars(m_sTestURL));
	Out.Replace(_T("[CONNECTIONTESTLABEL]"), GetResString(IDS_CONNECTIONTEST));


	CString sT;
	sT.Format(_T("%u"), thePrefs.GetMaxDownload() == UNLIMITED ? 0u : thePrefs.GetMaxDownload());
	Out.Replace(_T("[MaxDownVal]"), sT);

	sT.Format(_T("%u"), thePrefs.GetMaxUpload() == UNLIMITED ? 0u : thePrefs.GetMaxUpload());
	Out.Replace(_T("[MaxUpVal]"), sT);

	sT.Format(_T("%u"), thePrefs.GetMaxGraphDownloadRate());
	Out.Replace(_T("[MaxCapDownVal]"), sT);

	sT.Format(_T("%u"), thePrefs.GetMaxGraphUploadRate(true));
	Out.Replace(_T("[MaxCapUpVal]"), sT);

	return Out;
}

CString CWebServer::_GetLoginScreen(const ThreadData &Data)
{
	CWebServer* owner = reinterpret_cast<CWebServer*>(Data.pThis); return owner == NULL ? CString() : RenderWebLogin(WebTemplateParent(owner), GetWebTemplate(WebTemplateParent(owner), WebTemplateId::Login), _GenerateNonce(Data), owner->m_nIntruderDetect >= 1, theApp.m_strCurVersionLong);
}
// eSE 8.14: Generate a CSPRNG nonce for challenge-response login
CStringA CWebServer::_GenerateNonce(const ThreadData &Data)
{
	CWebServer *pThis = reinterpret_cast<CWebServer*>(Data.pThis);
	if (pThis == NULL)
		return CStringA();

	const CStringA nonce = GenerateWebRequestHexToken();
	const std::uint32_t clientIp = inet_addr(ipstrA(Data.inadr));
	const std::string value((LPCSTR)nonce, nonce.GetLength());
	if (!pThis->m_authPolicy.AddChallenge(value, clientIp, eSELive::WebRequestAuthNowMs()))
		return CStringA();
	return nonce;
}

// eSE 8.14: Validate SHA256(nonce + storedHash) == clientResponse
bool CWebServer::_ValidateChallengeResponse(const ThreadData &Data,
	const CString &sNonce, const CString &sResponse, bool &outIsAdmin)
{
	CWebServer* owner = reinterpret_cast<CWebServer*>(Data.pThis);
	if (owner == NULL)
		return false;
	CStringA nonce = CT2A(sNonce), response = CT2A(sResponse);
	nonce.MakeLower(); response.MakeLower();
	const std::uint32_t clientIp = inet_addr(ipstrA(Data.inadr));
	if (!owner->m_authPolicy.ConsumeChallenge(
		std::string((LPCSTR)nonce, nonce.GetLength()),
		clientIp, eSELive::WebRequestAuthNowMs()))
		return false;
	return ValidateWebChallengeDigest(
		nonce, response, thePrefs.GetWSPass(),
		thePrefs.GetWSIsLowUserEnabled(), thePrefs.GetWSLowPass(), outIsAdmin);
}


bool CWebServer::_IsLoggedIn(const ThreadData &Data, long lSession)
{
	CWebServer *pThis = reinterpret_cast<CWebServer*>(Data.pThis);
	if (pThis == NULL)
		return false;
	return lSession > 0 && pThis->m_authPolicy.TouchSession(
		static_cast<std::uint32_t>(lSession),
		eSELive::WebRequestAuthNowMs(),
		eSELive::WebRequestSessionTimeoutMs());
}

void CWebServer::_RemoveTimeOuts(const ThreadData &Data)
{
	// remove expired sessions
	CWebServer *pThis = reinterpret_cast<CWebServer*>(Data.pThis);
	if (pThis != NULL)
		pThis->UpdateSessionCount();
}

bool CWebServer::_RemoveSession(const ThreadData &Data, long lSession)
{
	CWebServer *pThis = reinterpret_cast<CWebServer*>(Data.pThis);
	if (pThis == NULL || lSession == 0)
		return false;

	if (!pThis->m_authPolicy.RemoveSession(static_cast<std::uint32_t>(lSession)))
		return false;
	AddLogLine(true, (LPCTSTR)GetResString(IDS_WEB_SESSIONEND), (LPCTSTR)ipstr(pThis->m_uCurIP));
	SendMessage(theApp.emuledlg->m_hWnd, WEB_GUI_INTERACTION, WEBGUIIA_UPDATEMYINFO, 0);
	return true;
}

bool CWebServer::_IsSessionAdmin(const ThreadData &Data, long sessionID)
{
	CWebServer *pThis = reinterpret_cast<CWebServer*>(Data.pThis);
	if (pThis == NULL || sessionID <= 0)
		return false;
	ese::web::WebSessionSnapshot session;
	return pThis->m_authPolicy.GetSession(
		static_cast<std::uint32_t>(sessionID), session) &&
		ese::web::WebAuthPolicy::HasPermission(
			session.role, ese::web::WebRole::Admin);
}

bool CWebServer::_IsSessionAdmin(const ThreadData &Data, const CString &strSsessionID)
{
	return _IsSessionAdmin(Data, _tstol(strSsessionID));
}

CString CWebServer::_GetPlainResString(UINT nID, bool noquote)
{
	return GetWebPlainResource(nID, noquote);
}

void CWebServer::_GetPlainResString(CString &rstrOut, UINT nID, bool noquote)
{
	rstrOut = GetWebPlainResource(nID, noquote);
}
// Ornis: creating the progressbar. colored if resources are given/available
CString CWebServer::_GetDownloadGraph(const ThreadData &Data, const CString &filehash)
{
	const CWebServer *pThis = reinterpret_cast<CWebServer*>(Data.pThis);
	if (pThis == NULL)
		return CString();

	uchar fileid[MDX_DIGEST_SIZE];
	if (filehash.GetLength() != MDX_DIGEST_SIZE * 2 || !DecodeBase16(filehash, MDX_DIGEST_SIZE * 2, fileid, _countof(fileid)))
		return CString();

	//	Color style (paused files)
	static LPCTSTR const styles_paused[12] =
	{
		_T("p_green.gif"), _T("p_black.gif"), _T("p_yellow.gif"), _T("p_red.gif"),
		_T("p_blue1.gif"), _T("p_blue2.gif"), _T("p_blue3.gif"), _T("p_blue4.gif"),
		_T("p_blue5.gif"), _T("p_blue6.gif"), _T("p_greenpercent.gif"), _T("transparent.gif")
	};
	//	Color style (active files)
	static LPCTSTR const styles_active[12] =
	{
		_T("green.gif"), _T("black.gif"), _T("yellow.gif"), _T("red.gif"),
		_T("blue1.gif"), _T("blue2.gif"), _T("blue3.gif"), _T("blue4.gif"),
		_T("blue5.gif"), _T("blue6.gif"), _T("greenpercent.gif"), _T("transparent.gif")
	};

	// v7.4.0 — snapshot under DownloadQueue lock so the rendering loop below
	// never reads CPartFile state mid-mutation. Holding a CPartFile* across
	// the rendering loop is the use-after-free we keep almost hitting.
	struct PartFileRenderSnapshot {
		bool             found = false;
		bool             isPartFile = false;
		EPartFileStatus  status = PS_EMPTY;
		UINT             percentCompleted = 0;
		CStringA         chunkBar;
		uint16           barWidth = 0;
	};
	PartFileRenderSnapshot snap;
	snap.barWidth = (uint16)_tstoi(GetWebTemplate(WebTemplateParent(pThis), WebTemplateId::ProgressbarWidth));
	theApp.downloadqueue->WithFileByID(fileid, [&](CPartFile *f) {
		snap.found            = true;
		snap.isPartFile       = f->IsPartFile();
		snap.status           = f->GetStatus();
		snap.percentCompleted = f->GetPercentCompleted();
		snap.chunkBar         = f->GetProgressString(snap.barWidth);
	});
	const LPCTSTR *barcolours = (snap.found && snap.status == PS_PAUSED) ? styles_paused : styles_active;

	CString Out;
	if (!snap.found || !snap.isPartFile) {
		Out.Format(GetWebTemplate(WebTemplateParent(pThis), WebTemplateId::ProgressbarImgsPercent), barcolours[10], snap.barWidth);
		Out += _T("<br>");
		Out.AppendFormat(GetWebTemplate(WebTemplateParent(pThis), WebTemplateId::ProgressbarImgs), barcolours[0], snap.barWidth);
	} else {
		const CStringA &s_ChunkBar = snap.chunkBar;
		// and now make a graph out of the array - need to be in a progressive way

		int compl = static_cast<int>((snap.barWidth / 100.0) * snap.percentCompleted);
		Out.Format(GetWebTemplate(WebTemplateParent(pThis), WebTemplateId::ProgressbarImgsPercent), barcolours[compl > 0 ? 10 : 11], (compl > 0 ? compl : 5));
		Out += _T("<br>");

		BYTE lastcolor = 1;
		uint16 lastindex = 0;
		const uint16 uBarWidth = snap.barWidth;
		for (uint16 i = 0; i < uBarWidth; ++i) {
			BYTE c = (BYTE)(s_ChunkBar[i] - '0');
			if (c >= _countof(styles_active)) c = 0;          // defence-in-depth clamp
			if (lastcolor != c) {
				if (i > lastindex && lastcolor < _countof(styles_active))
					Out.AppendFormat(GetWebTemplate(WebTemplateParent(pThis), WebTemplateId::ProgressbarImgs), barcolours[lastcolor], i - lastindex);
				lastcolor = c;
				lastindex = i;
			}
		}
		if (lastcolor >= _countof(styles_active)) lastcolor = 0;   // hard clamp
		Out.AppendFormat(GetWebTemplate(WebTemplateParent(pThis), WebTemplateId::ProgressbarImgs), barcolours[lastcolor], uBarWidth - lastindex);
	}
	return Out;
}

CString CWebServer::_GetSearch(const ThreadData &Data)
{
	M2AModuleHandle projectionBinding = M2A_BIND_W6_64C04005E2(M2AParentPort{Data.pThis}); if (!projectionBinding) return CString();
	CWebServer *pThis = reinterpret_cast<CWebServer*>(Data.pThis); if (pThis == NULL) return CString();
	const auto wide = [](const CString& value) { return std::wstring(static_cast<LPCWSTR>(value), value.GetLength()); };
	CString sCat; const int cat = _tstoi(_ParseURL(Data.sURL, _T("cat"))); if (cat != 0) sCat.Format(_T("%i"), cat);
	const CString &sSession(_ParseURL(Data.sURL, _T("ses"))); const bool bSessionAdmin = _IsSessionAdmin(Data, sSession); CString Out(GetWebTemplate(WebTemplateParent(pThis), WebTemplateId::Search));
	if (!_ParseURL(Data.sURL, _T("downloads")).IsEmpty() && bSessionAdmin) {
		const CString &downloads(_ParseURLArray(Data.sURL, _T("downloads"))); const std::vector<std::string> hashes = ese::web::WebSearchController::PlanDownloads(bSessionAdmin, std::string(CT2A(downloads)));
		for (const std::string& hash : hashes) { const CString hashText(CA2T(hash.c_str())); SendMessage(theApp.emuledlg->m_hWnd, WEB_ADDDOWNLOADS, (LPARAM)(LPCTSTR)hashText, cat); }
	}
	if (_ParseURL(Data.sURL, _T("c")) == _T("menu")) {
		const CString index = _ParseURL(Data.sURL, _T("m")); const CString hidden = _ParseURL(Data.sURL, _T("v")); const ese::web::WebSearchColumnChange change = ese::web::WebSearchController::PlanColumnChange(bSessionAdmin, std::string(CT2A(index)), std::string(CT2A(hidden)));
		if (change.allowed) { WSsearchColumnHidden[change.index] = change.hidden; _SaveWIConfigArray(WSsearchColumnHidden, _countof(WSsearchColumnHidden), _T("searchColumnHidden")); }
	}
	if (!_ParseURL(Data.sURL, _T("tosearch")).IsEmpty() && bSessionAdmin) {
		const CString expression = _ParseURL(Data.sURL, _T("tosearch")); const CString fileType = _ParseURL(Data.sURL, _T("type")); const CString minimum = _ParseURL(Data.sURL, _T("min")); const CString maximum = _ParseURL(Data.sURL, _T("max")); const CString availability = _ParseURL(Data.sURL, _T("avail")); const CString extension = _ParseURL(Data.sURL, _T("ext")); const CString method = _ParseURL(Data.sURL, _T("method"));
		const ese::web::WebSearchRequest request = ese::web::WebSearchController::PlanSearch(bSessionAdmin, std::string(CT2A(expression)), std::string(CT2A(fileType)), std::string(CT2A(minimum)), std::string(CT2A(maximum)), std::string(CT2A(availability)), std::string(CT2A(extension)), std::string(CT2A(method))); CString strResponse = request.allowed ? _GetPlainResString(IDS_SW_SEARCHINGINFO) : _GetPlainResString(IDS_ERROR); SSearchParams* pParams = NULL;
		if (request.allowed) {
			SendMessage(theApp.emuledlg->m_hWnd, WEB_GUI_INTERACTION, WEBGUIIA_DELETEALLSEARCHES, 0); pParams = new SSearchParams; pParams->strExpression = expression; pParams->strFileType = fileType; pParams->ullMinSize = request.minimum_bytes; pParams->ullMaxSize = request.maximum_bytes; pParams->uAvailability = request.availability; pParams->strExtension = extension; pParams->eType = request.method == ese::web::WebSearchMethod::Kademlia ? SearchTypeKademlia : (request.method == ese::web::WebSearchMethod::Global ? SearchTypeEd2kGlobal : SearchTypeEd2kServer);
			try { if (pParams->eType != SearchTypeKademlia) { if (!theApp.emuledlg->searchwnd->DoNewEd2kSearch(pParams)) { delete pParams; pParams = NULL; strResponse = _GetPlainResString(IDS_ERR_NOTCONNECTED); } } else if (!theApp.emuledlg->searchwnd->DoNewKadSearch(pParams)) { delete pParams; pParams = NULL; strResponse = _GetPlainResString(IDS_ERR_NOTCONNECTEDKAD); } } catch (...) { AddDebugLogLine(DLP_VERYHIGH, false, _T("*** Exception in CWebServer::_GetSearch search dispatch")); strResponse = _GetPlainResString(IDS_ERROR); ASSERT(0); delete pParams; pParams = NULL; }
		}
		Out.Replace(_T("[Message]"), strResponse);
	} else if (!_ParseURL(Data.sURL, _T("tosearch")).IsEmpty() && !bSessionAdmin) Out.Replace(_T("[Message]"), _GetPlainResString(IDS_ACCESSDENIED)); else Out.Replace(_T("[Message]"), _GetPlainResString(IDS_SW_REFETCHRES));
	const CString sSort = _ParseURL(Data.sURL, _T("sort")); const CString sortAscending = _ParseURL(Data.sURL, _T("sortAsc")); const ese::web::WebSearchSortDecision searchSort = ese::web::WebSearchController::PlanSort(bSessionAdmin, std::string(CT2A(sSort)), std::string(CT2A(sortAscending)), static_cast<unsigned>(pThis->m_iSearchSortby), pThis->m_bSearchAsc);
	if (searchSort.allowed) { pThis->m_iSearchSortby = static_cast<int>(searchSort.column); pThis->m_bSearchAsc = searchSort.ascending; }
	CQArray<SearchFileStruct, SearchFileStruct> searchSnapshot; theApp.searchlist->GetWebList(&searchSnapshot, pThis->m_iSearchSortby); searchSnapshot.QuickSort(pThis->m_bSearchAsc);
	WebSearchProjectionInput input; input.pageTemplate = wide(Out); input.headerTemplate = wide(GetWebTemplate(WebTemplateParent(pThis), WebTemplateId::SearchHeader)); input.rowTemplate = wide(GetWebTemplate(WebTemplateParent(pThis), WebTemplateId::SearchResultLine)); input.session = wide(sSession); input.upArrow = wide(GetWebTemplate(WebTemplateParent(pThis), WebTemplateId::UpArrow)); input.downArrow = wide(GetWebTemplate(WebTemplateParent(pThis), WebTemplateId::DownArrow)); input.hidden = {{ !!WSsearchColumnHidden[0], !!WSsearchColumnHidden[1], !!WSsearchColumnHidden[2], !!WSsearchColumnHidden[3] }}; input.sortColumn = static_cast<unsigned>(pThis->m_iSearchSortby); input.ascending = pThis->m_bSearchAsc;
	input.columnNames = { wide(_GetPlainResString(IDS_DL_FILENAME)), wide(_GetPlainResString(IDS_DL_SIZE)), wide(_GetPlainResString(IDS_FILEHASH)), wide(_GetPlainResString(IDS_DL_SOURCES)) };
	input.replacements = { { L"[Result]", wide(GetResString(IDS_SW_RESULT)) }, { L"[Name]", wide(_GetPlainResString(IDS_SW_NAME)) }, { L"[Type]", wide(_GetPlainResString(IDS_TYPE)) }, { L"[Any]", wide(_GetPlainResString(IDS_SEARCH_ANY)) }, { L"[Audio]", wide(_GetPlainResString(IDS_SEARCH_AUDIO)) }, { L"[Image]", wide(_GetPlainResString(IDS_SEARCH_PICS)) }, { L"[Video]", wide(_GetPlainResString(IDS_SEARCH_VIDEO)) }, { L"[Document]", wide(_GetPlainResString(IDS_SEARCH_DOC)) }, { L"[CDImage]", wide(_GetPlainResString(IDS_SEARCH_CDIMG)) }, { L"[Program]", wide(_GetPlainResString(IDS_SEARCH_PRG)) }, { L"[Archive]", wide(_GetPlainResString(IDS_SEARCH_ARC)) }, { L"[Search]", wide(_GetPlainResString(IDS_EM_SEARCH)) }, { L"[Unicode]", wide(_GetPlainResString(IDS_SEARCH_UNICODE)) }, { L"[Size]", wide(_GetPlainResString(IDS_DL_SIZE)) }, { L"[Start]", wide(_GetPlainResString(IDS_SW_START)) }, { L"[USESSERVER]", wide(_GetPlainResString(IDS_SERVER)) }, { L"[USEKADEMLIA]", wide(_GetPlainResString(IDS_KADEMLIA)) }, { L"[METHOD]", wide(_GetPlainResString(IDS_METHOD)) }, { L"[SizeMin]", wide(_GetPlainResString(IDS_SEARCHMINSIZE)) }, { L"[SizeMax]", wide(_GetPlainResString(IDS_SEARCHMAXSIZE)) }, { L"[Availabl]", wide(_GetPlainResString(IDS_SEARCHAVAIL)) }, { L"[Extention]", wide(_GetPlainResString(IDS_SEARCHEXTENTION)) }, { L"[Global]", wide(_GetPlainResString(IDS_SW_GLOBAL)) }, { L"[MB]", wide(_GetPlainResString(IDS_MBYTES)) }, { L"[Apply]", wide(_GetPlainResString(IDS_PW_APPLY)) }, { L"[CatSel]", wide(sCat) }, { L"[Ed2klink]", wide(_GetPlainResString(IDS_SW_LINK)) }, { L"[Download]", wide(_GetPlainResString(IDS_DOWNLOAD)) } };
	for (uint16 i = 0; i < searchSnapshot.GetCount(); ++i) {
		const SearchFileStruct structFile = searchSnapshot.GetAt(i); uchar aFileHash[16]; DecodeBase16(structFile.m_strFileHash, 32, aFileHash, _countof(aFileHash)); const bool downloading = theApp.downloadqueue->HasFileByID(aFileHash) != NULL; CKnownFile* sameFile = downloading ? NULL : theApp.sharedfiles->GetFileByID(aFileHash); if (!downloading && sameFile == NULL) sameFile = theApp.knownfiles->FindKnownFileByID(aFileHash); const ese::web::WebSearchResultProjection projection = ese::web::WebSearchController::ProjectResult(downloading, sameFile != NULL, structFile.m_uSourceCount); CString sources; sources.Format(_T("%u(%u)"), structFile.m_uSourceCount, structFile.m_dwCompleteSourceCount);
		WebSearchProjectionRow row; row.fileName = wide(structFile.m_strFileName); row.limitedName = wide(StringLimit(structFile.m_strFileName, 70)); row.typeImage = wide(_GetWebImageNameForFileType(structFile.m_strFileName)); row.sizeText = wide(CastItoXBytes(structFile.m_uFileSize)); row.sizeBytes = structFile.m_uFileSize; row.hash = wide(structFile.m_strFileHash); row.sources = wide(sources); row.sourceBucket = wide(CString(projection.source_bucket)); row.red = static_cast<std::uint8_t>(projection.red); row.green = static_cast<std::uint8_t>(projection.green); row.blue = static_cast<std::uint8_t>(projection.blue); input.rows.push_back(row);
	}
	if (thePrefs.GetCatCount() > 1) _InsertCatBox(Out, 0, GetWebTemplate(WebTemplateParent(pThis), WebTemplateId::CatArrow), false, false, sSession, _T("")); else Out.Replace(_T("[CATBOX]"), _T("")); input.pageTemplate = wide(Out);
	const std::wstring rendered = RunWebSearchProjection(M2AParentPort{pThis}, input); return CString(rendered.c_str());
}

INT_PTR CWebServer::UpdateSessionCount()
{
	M2AModuleHandle transferProjectionBinding = M2A_BIND_W4_AD763A5EE0(M2AParentPort{this}); if (!transferProjectionBinding) return 0; const std::size_t removed = m_authPolicy.PurgeExpiredSessions(
		eSELive::WebRequestAuthNowMs(), eSELive::WebRequestSessionTimeoutMs());
	if (removed != 0)
		SendMessage(theApp.emuledlg->m_hWnd, WEB_GUI_INTERACTION, WEBGUIIA_UPDATEMYINFO, 0);

	return static_cast<INT_PTR>(m_authPolicy.SessionCount());
}

void CWebServer::_InsertCatBox(CString &Out, int preselect, LPCTSTR boxlabel, bool jump, bool extraCats, const CString &sSession, const CString &sFileHash, bool ed2kbox)
{
	int fileCategory = preselect; uchar hash[MDX_DIGEST_SIZE]; if (!sFileHash.IsEmpty() && strmd4(sFileHash, hash)) theApp.downloadqueue->WithFileByID(hash, [&](CPartFile* file) { fileCategory = file->GetCategory(); });
	InsertWebCategoryBox(Out, preselect, boxlabel, jump, extraCats, sSession, sFileHash, fileCategory, ed2kbox);
}
CString CWebServer::_GetRemoteLinkAddedOk(const ThreadData &Data)
{
	CWebServer *pThis = reinterpret_cast<CWebServer*>(Data.pThis);
	if (pThis == NULL)
		return CString();

	int cat = _tstoi(_ParseURL(Data.sURL, _T("cat")));
	CString HTTPTemp = _ParseURL(Data.sURL, _T("c"));

	const TCHAR *buf = HTTPTemp;
	theApp.emuledlg->SendMessage(WEB_ADDDOWNLOADS, (WPARAM)buf, cat);

	const CString description = GetResString(IDS_WEB_REMOTE_LINK_ADDED);
	const std::wstring body = ese::web::Serialize(
		ese::web::WebRemoteLinkXmlResponseModel{
			true,
			std::wstring(
				static_cast<LPCTSTR>(description),
				static_cast<std::size_t>(description.GetLength())),
			std::wstring(
				static_cast<LPCTSTR>(HTTPTemp),
				static_cast<std::size_t>(HTTPTemp.GetLength()))});
	return CString(body.data(), static_cast<int>(body.size()));
}

CString CWebServer::_GetRemoteLinkAddedFailed(const ThreadData &Data)
{
	CWebServer *pThis = reinterpret_cast<CWebServer*>(Data.pThis);
	if (pThis == NULL)
		return CString();

	const CString description = GetResString(IDS_WEB_REMOTE_LINK_NOT_ADDED);
	const std::wstring body = ese::web::Serialize(
		ese::web::WebRemoteLinkXmlResponseModel{
			false,
			std::wstring(
				static_cast<LPCTSTR>(description),
				static_cast<std::size_t>(description.GetLength())),
			std::wstring()});
	return CString(body.data(), static_cast<int>(body.size()));
}

void CWebServer::_SetLastUserCat(const ThreadData &Data, long lSession, int cat)
{
	CWebServer *pThis = reinterpret_cast<CWebServer*>(Data.pThis);
	if (pThis == NULL)
		return;

	if (lSession > 0)
		pThis->m_authPolicy.SetLastCategory(
			static_cast<std::uint32_t>(lSession),
			cat,
			eSELive::WebRequestAuthNowMs(),
			eSELive::WebRequestSessionTimeoutMs());
}

int CWebServer::_GetLastUserCat(const ThreadData &Data, long lSession)
{
	CWebServer *pThis = reinterpret_cast<CWebServer*>(Data.pThis);
	if (pThis == NULL)
		return 0;

	int category = 0;
	return lSession > 0 && pThis->m_authPolicy.GetLastCategory(
		static_cast<std::uint32_t>(lSession),
		category,
		eSELive::WebRequestAuthNowMs(),
		eSELive::WebRequestSessionTimeoutMs())
		? category
		: 0;
}



static CStringA W8JsonA(const CStringA& input) { const std::string escaped = W8EscapeJson(std::string((LPCSTR)input, input.GetLength())); return CStringA(escaped.data(), static_cast<int>(escaped.size())); }
static CStringA W8KeyA(const uchar* key) { std::array<unsigned char, 16> value; memcpy(value.data(), key, value.size()); const std::string encoded = W8EncodeKey16(value); return CStringA(encoded.data(), static_cast<int>(encoded.size())); }
static bool W12CopyHlsSource(
	const std::string& streamHash,
	LiveHlsSourceSnapshot& source)
{
	source = LiveHlsSourceSnapshot();
	std::array<unsigned char, 16> key{};
	return theApp.liveStreamManager != NULL &&
		W8DecodeKey16(streamHash, key) &&
		theApp.liveStreamManager->CopyHlsSourceSnapshot(key.data(), source);
}

static ese::web::WebHlsSourceRole W12PolicyHlsRole(
	const LiveHlsSourceSnapshot& source)
{
	return source.broadcast
		? ese::web::WebHlsSourceRole::Broadcast
		: ese::web::WebHlsSourceRole::Viewer;
}

static bool W12CopyWebHlsSource(
	void* raw,
	const std::string& streamHash,
	ese::web::WebHlsLiveSourceSnapshot& output)
{
	if (raw == nullptr || raw != theApp.liveStreamManager)
		return false;
	LiveHlsSourceSnapshot source;
	if (!W12CopyHlsSource(streamHash, source))
		return false;
	std::array<unsigned char, 16> key{};
	memcpy(key.data(), source.streamKey, key.size());
	output.stream_key = W8EncodeKey16(key);
	output.generation = source.generation;
	output.role = W12PolicyHlsRole(source);
	return true;
}

static bool W12BuildWebHlsFilePath(
	const ese::web::WebHlsLiveSourceSnapshot& source,
	const std::string& resourceBytes,
	CString& filePath)
{
	TCHAR temporaryRoot[MAX_PATH] = {};
	const DWORD temporaryLength =
		GetTempPath(_countof(temporaryRoot), temporaryRoot);
	if (temporaryLength == 0 || temporaryLength >= _countof(temporaryRoot))
		return false;
	const CString resource = OptUtf8ToStr(
		resourceBytes.data(), static_cast<int>(resourceBytes.size()));
	const CString streamHash = OptUtf8ToStr(
		source.stream_key.data(), static_cast<int>(source.stream_key.size()));
	if (source.role == ese::web::WebHlsSourceRole::Broadcast) {
		filePath.Format(
			_T("%seMule_RTMP\\%s"), temporaryRoot, (LPCTSTR)resource);
	} else {
		filePath.Format(
			_T("%seMule_RTMP\\%s\\%s"), temporaryRoot,
			(LPCTSTR)streamHash, (LPCTSTR)resource);
	}
	return true;
}

struct W12HlsLeaseContext {
	ese::web::WebAuthPolicy* policy = nullptr;
	CWebSocket* socket = nullptr;
	ese::web::WebHlsCapabilityReadRequest request;
	ese::web::WebHlsLiveSourceSnapshot source;
	ese::web::WebPreparedFileResponse prepared;
	bool commit_rejected = false;
};

static LiveHlsReadPreparation W12PrepareWebHlsRead(void* raw)
{
	W12HlsLeaseContext& context =
		*static_cast<W12HlsLeaseContext*>(raw);
	if (context.policy == nullptr || context.socket == nullptr)
		return LiveHlsReadPreparation::Failed;
	// The request may have waited for the manager lease.  Commit must use a
	// fresh clock so an expired owner/capability cannot pass with Inspect time.
	const std::uint64_t commitNowMs = eSELive::WebRequestAuthNowMs();
	if (!ese::web::CommitWebHlsCapabilityRead(
			*context.policy, context.request, context.source, commitNowMs)) {
		context.commit_rejected = true;
		return LiveHlsReadPreparation::Failed;
	}
	CString filePath;
	if (!W12BuildWebHlsFilePath(
			context.source, context.request.resource, filePath))
		return LiveHlsReadPreparation::Failed;
	ese::web::WebFileResponseOptions options;
	options.cacheControl = "no-store";
	options.noReferrer = true;
	if (!context.socket->PrepareBufferedFileResponse(
		filePath,
		CStringA(
			context.request.resource.data(),
			static_cast<int>(context.request.resource.size())),
		CStringA(
			context.request.range.data(),
			static_cast<int>(context.request.range.size())),
		options,
		ese::web::WebPreparedFileResponse::kMaximumBodyBytes,
		true,
		false,
		context.prepared))
		return LiveHlsReadPreparation::Failed;
	const bool successfulBody =
		context.prepared.plan.IsSuccess() &&
		context.prepared.plan.length != 0u &&
		context.prepared.plan.length == context.prepared.body.size();
	return successfulBody
		? LiveHlsReadPreparation::PreparedWithBody
		: LiveHlsReadPreparation::PreparedWithoutBody;
}

static bool W12MakeLiveHlsLeaseSnapshot(
	const ese::web::WebHlsLiveSourceSnapshot& source,
	LiveHlsSourceSnapshot& expected)
{
	std::array<unsigned char, 16> key{};
	if (!W8DecodeKey16(source.stream_key, key) || source.generation == 0)
		return false;
	memcpy(expected.streamKey, key.data(), key.size());
	expected.generation = source.generation;
	expected.broadcast =
		source.role == ese::web::WebHlsSourceRole::Broadcast;
	return true;
}

enum class W12HlsDispatchResult { NotCapability, Handled };

static W12HlsDispatchResult W12ProcessHlsCapability(
	ese::web::WebAuthPolicy& policy,
	const ThreadData& data,
	const CStringA& url)
{
	const std::string target((LPCSTR)url, url.GetLength());
	ese::web::WebHlsCapabilityPath path;
	if (!ese::web::ParseWebHlsCapabilityPath(target, path)) {
		if (target.compare(0, 3, "/h/") != 0)
			return W12HlsDispatchResult::NotCapability;
		data.pSocket->SendReply(
			"HTTP/1.1 404 Not Found\r\nCache-Control: no-store\r\n"
			"Referrer-Policy: no-referrer\r\nContent-Length: 0\r\n\r\n");
		return W12HlsDispatchResult::Handled;
	}
	const CStringA raw(path.token.c_str());
	const CStringA digest = eSELive::DigestWebRequestToken(raw);
	ese::web::WebHlsCapabilityReadRequest request;
	request.token_digest.assign((LPCSTR)digest, digest.GetLength());
	request.path_generation = path.generation;
	request.stream_key = path.stream_hash;
	request.resource = path.resource;
	request.range.assign((LPCSTR)data.sRange, data.sRange.GetLength());
	request.now_ms = eSELive::WebRequestAuthNowMs();
	request.session_timeout_ms = eSELive::WebRequestSessionTimeoutMs();
	const ese::web::WebHlsCapabilityReadPort port{
		theApp.liveStreamManager, W12CopyWebHlsSource};
	const ese::web::WebHlsCapabilityReadDecision decision =
		ese::web::RunWebHlsCapabilityRead(policy, request, port);
	if (decision.status == ese::web::WebHlsCapabilityReadStatus::Rejected) {
		SendWebForbidden(data.pSocket, "access denied");
		const std::string rejection = ese::web::BuildRejectedHlsCapabilityLog(
			data.inadr.S_un.S_addr);
		LIVE_LOG("SEC", "%s", rejection.c_str());
		return W12HlsDispatchResult::Handled;
	}
	LiveHlsSourceSnapshot expected;
	CLiveStreamManager* const manager = theApp.liveStreamManager;
	if (manager == NULL ||
		!W12MakeLiveHlsLeaseSnapshot(decision.source, expected)) {
		SendWebForbidden(data.pSocket, "access denied");
		return W12HlsDispatchResult::Handled;
	}
	W12HlsLeaseContext context;
	context.policy = &policy;
	context.socket = data.pSocket;
	context.request = request;
	context.source = decision.source;
	const LiveHlsReadExecution executed = manager->ExecuteHlsReadIfCurrent(
		expected, W12PrepareWebHlsRead, &context);
	if (executed == LiveHlsReadExecution::Stale) {
		policy.RevokeHlsCapabilityDigest(request.token_digest);
		SendWebForbidden(data.pSocket, "access denied");
		return W12HlsDispatchResult::Handled;
	}
	if (executed == LiveHlsReadExecution::Failed) {
		if (context.commit_rejected) {
			SendWebForbidden(
				data.pSocket, "access denied");
			return W12HlsDispatchResult::Handled;
		}
		data.pSocket->SendReply(
			"HTTP/1.1 500 Internal Server Error\r\n"
			"Cache-Control: no-store\r\nReferrer-Policy: no-referrer\r\n"
			"Content-Length: 0\r\n\r\n");
		return W12HlsDispatchResult::Handled;
	}
	// Socket queuing is deliberately outside CLiveStreamManager::m_lock.  The
	// response owns immutable captured bytes plus its aggregate reservation.
	if (!data.pSocket->SendPreparedFileResponse(std::move(context.prepared))) {
		data.pSocket->Disconnect();
	}
	return W12HlsDispatchResult::Handled;
}

struct W12LiveAuthorization {
	CStringA url;
	bool token_auth = false;
	bool token_admin = false;
	std::uint32_t session_id = 0;
	ese::web::WebSessionSnapshot session;
};

static bool W12AuthorizeLiveRequest(
	ese::web::WebAuthPolicy& policy,
	const ThreadData& data,
	const CStringA& inputUrl,
	W12LiveAuthorization& output)
{
	output = W12LiveAuthorization();
	output.url = inputUrl;
	const bool loopback =
		data.inadr.S_un.S_addr == htonl(INADDR_LOOPBACK);
	const std::uint64_t nowMs = eSELive::WebRequestAuthNowMs();
	const std::uint64_t timeoutMs = eSELive::WebRequestSessionTimeoutMs();
	auto resolve = [&policy, &data, nowMs, timeoutMs](
		std::uint32_t expected, ese::web::WebSessionSnapshot& session) {
		if (data.sBrowserSessionToken.IsEmpty())
			return false;
		const CStringA digest =
			eSELive::DigestWebRequestToken(data.sBrowserSessionToken);
		return policy.ResolveBrowserSessionDigest(
			std::string((LPCSTR)digest, digest.GetLength()),
			nowMs, timeoutMs, &session, expected);
	};
	if (output.url.GetLength() > 3 && strncmp(output.url, "/s/", 3) == 0) {
		const int slash = output.url.Find('/', 3);
		const long locator = slash > 3 ? atol((LPCSTR)output.url + 3) : 0;
		if (!loopback || locator <= 0 ||
			!resolve(static_cast<std::uint32_t>(locator), output.session)) {
			SendWebForbidden(data.pSocket, "invalid or expired token");
			const std::string rejection = ese::web::BuildRejectedLiveSessionLog(
				data.inadr.S_un.S_addr);
			LIVE_LOG("SEC", "%s", rejection.c_str());
			return false;
		}
		output.url.Delete(0, slash);
		output.token_auth = true;
	} else if (resolve(0, output.session)) {
		output.token_auth = true;
	}
	if (output.token_auth) {
		output.token_admin = output.session.role == ese::web::WebRole::Admin;
		output.session_id = output.session.id;
	}
	if (!loopback &&
		(data.webRoute == ese::web::WebRouteId::ApiLiveStream ||
		 data.webRoute == ese::web::WebRouteId::LegacyHls)) {
		SendWebForbidden(data.pSocket, "HLS capability required");
		return false;
	}
	const std::string path((LPCSTR)output.url, output.url.GetLength());
	const ese::web::WebSessionSnapshot* session =
		output.token_auth ? &output.session : nullptr;
	if (!ese::web::WebAuthPolicy::AuthorizeLiveRequest(
			path, loopback, session,
			std::string((LPCSTR)data.sCsrfToken, data.sCsrfToken.GetLength()),
			std::string((LPCSTR)data.sFetchSite, data.sFetchSite.GetLength()),
			std::string((LPCSTR)data.sHost, data.sHost.GetLength()),
			std::string((LPCSTR)data.sOrigin, data.sOrigin.GetLength()))) {
		SendWebForbidden(
			data.pSocket, "trusted origin or session CSRF required");
		return false;
	}
	const ese::web::WebRole role = output.token_admin
		? ese::web::WebRole::Admin : ese::web::WebRole::Guest;
	const ese::web::WebRole required =
		ese::web::WebAuthPolicy::RequiredRoleForLivePath(path);
	if (output.token_auth &&
		!ese::web::WebAuthPolicy::HasPermission(role, required)) {
		SendWebForbidden(data.pSocket, "admin session required");
		return false;
	}
	return true;
}

enum class W12PlayerCapabilityResult { Rewritten, NoLiveSource, Failed };

static W12PlayerCapabilityResult W12RewritePlayerCapability(
	ese::web::WebAuthPolicy& policy,
	std::uint32_t sessionId,
	const std::string& requestedStream,
	std::string& header,
	std::string& body)
{
	std::string streamHash = requestedStream;
	std::transform(
		streamHash.begin(), streamHash.end(), streamHash.begin(),
		[](unsigned char character) {
			return static_cast<char>(std::tolower(character));
		});
	LiveHlsSourceSnapshot source;
	if (!W12CopyHlsSource(streamHash, source))
		return W12PlayerCapabilityResult::NoLiveSource;
	ese::web::WebHlsCapabilitySnapshot capability;
	CStringA raw;
	bool issued = false;
	for (unsigned attempt = 0; attempt < 16 && !issued; ++attempt) {
		const CStringA candidate = eSELive::GenerateWebRequestHexToken();
		const CStringA digest = eSELive::DigestWebRequestToken(candidate);
		issued = policy.IssueHlsReadCapability(
			sessionId, streamHash, W12PolicyHlsRole(source), source.generation,
			std::string((LPCSTR)digest, digest.GetLength()),
			eSELive::WebRequestAuthNowMs(),
			eSELive::WebRequestSessionTimeoutMs(), capability);
		if (issued)
			raw = candidate;
	}
	const std::string playlist = issued
		? ese::web::BuildHlsCapabilityPlaylistPath(
			std::string((LPCSTR)raw, raw.GetLength()),
			capability.generation, streamHash)
		: std::string();
	if (!issued || playlist.empty() ||
		!ese::web::RewriteLivePlayerForHlsCapability(
			header, body, streamHash, playlist)) {
		if (issued)
			policy.RevokeHlsCapabilityDigest(capability.token_digest);
		return W12PlayerCapabilityResult::Failed;
	}
	return W12PlayerCapabilityResult::Rewritten;
}

// eSE Live Streaming & Network Status API
void CWebServer::_ProcessLiveAPI(const ThreadData &Data)
{
	CWebServer *pThis = reinterpret_cast<CWebServer*>(Data.pThis);
	if (pThis == NULL)
		return;
	CStringA sURL(CT2A(Data.sURL));

	// W12 owns authentication via WebAuthPolicy::AuthorizeLiveRequest, followed
	// by WebAuthPolicy::RequiredRoleForLivePath.  The controller then confirms
	// role/key/generation and commits before any fetch or filesystem touch.
	if (W12ProcessHlsCapability(pThis->m_authPolicy, Data, sURL) ==
			W12HlsDispatchResult::Handled)
		return;
	W12LiveAuthorization authorization;
	if (!W12AuthorizeLiveRequest(
			pThis->m_authPolicy, Data, sURL, authorization))
		return;
	sURL = authorization.url;
	const bool bTokenAuth = authorization.token_auth;
	const std::uint32_t authenticatedSessionId = authorization.session_id;
	// W8 dispatch stays below the common session/CSRF/role gate above.  The
	// app adapter owns GUI marshalling, time, sockets and the HLS filesystem.
	ese::web::W8LiveStatusOperation statusOperation; bool hasStatus=false; switch(Data.webRoute) { case ese::web::WebRouteId::ApiStatus: statusOperation=ese::web::W8LiveStatusOperation::Status; hasStatus=true; break; case ese::web::WebRouteId::ApiLiveChannels: statusOperation=ese::web::W8LiveStatusOperation::Channels; hasStatus=true; break; case ese::web::WebRouteId::ApiLiveMesh: statusOperation=ese::web::W8LiveStatusOperation::Mesh; hasStatus=true; break; default: break; }
	if(hasStatus) { W8StatusContext context{Data.inadr.S_un.S_addr == htonl(INADDR_LOOPBACK)}; ese::web::W8LiveStatusPort port{&context,W8StatusContext::ReadStatus,W8StatusContext::ReadChannel,W8StatusContext::ReadMesh}; ese::web::W8LiveStatusResponse response; if(ese::web::RunW8LiveStatusApi(statusOperation,context.loopback,port,response)) { W8StatusContext::Send(Data.pSocket,response.header,response.body); return; } }
	W8LiveStreamRequest request; bool hasStream=false; switch(Data.webRoute) { case ese::web::WebRouteId::ApiLiveJoin: request.operation=W8LiveStreamOperation::Join; request.key=W8Legacy(_ParseURL(Data.sURL,_T("key"))); W8Assign(_ParseURL(Data.sURL,_T("title")),request.title,request.ui_title); hasStream=true; break; case ese::web::WebRouteId::ApiLiveLeave: request.operation=W8LiveStreamOperation::Leave; request.key=W8Legacy(_ParseURL(Data.sURL,_T("key"))); hasStream=true; break; case ese::web::WebRouteId::ApiLivePlayerAlive: request.operation=W8LiveStreamOperation::PlayerAlive; request.key=W8Legacy(_ParseURL(Data.sURL,_T("key"))); hasStream=true; break; case ese::web::WebRouteId::ApiLiveBroadcastStart: request.operation=W8LiveStreamOperation::BroadcastStart; W8Assign(_ParseURL(Data.sURL,_T("source")),request.source,request.ui_source); W8Assign(_ParseURL(Data.sURL,_T("title")),request.title,request.ui_title,&request.title_encoded_wire); W8Assign(_ParseURL(Data.sURL,_T("category")),request.category,request.ui_category); W8Assign(_ParseURL(Data.sURL,_T("language")),request.language,request.ui_language); request.bitrate=W8Legacy(_ParseURL(Data.sURL,_T("bitrate"))); W8Assign(_ParseURL(Data.sURL,_T("file")),request.file,request.ui_file); request.direct=W8Legacy(_ParseURL(Data.sURL,_T("direct"))); hasStream=true; break; case ese::web::WebRouteId::ApiLiveBroadcastStop: request.operation=W8LiveStreamOperation::BroadcastStop; hasStream=true; break; case ese::web::WebRouteId::ApiLiveDirectJoin: request.operation=W8LiveStreamOperation::DirectJoin; W8Assign(_ParseURL(Data.sURL,_T("link")),request.link,request.ui_link); request.key=W8Legacy(_ParseURL(Data.sURL,_T("key"))); request.ip=W8Legacy(_ParseURL(Data.sURL,_T("ip"))); request.port=W8Legacy(_ParseURL(Data.sURL,_T("port"))); W8Assign(_ParseURL(Data.sURL,_T("title")),request.title,request.ui_title); hasStream=true; break; case ese::web::WebRouteId::ApiLiveStream: request.operation=W8LiveStreamOperation::StreamFile; request.stream_hash=std::string((LPCSTR)sURL.Mid(10,32),32); request.stream_resource=std::string((LPCSTR)sURL.Mid(43)); hasStream=true; break; default: break; }
	if (hasStream) {
		W8LiveAppPort port; W8LiveStreamResponse response; if (RunW8LiveStreamApi(request, port, response)) { if (response.forward_stream_file) { TCHAR temp[MAX_PATH]; GetTempPath(MAX_PATH,temp); const CString hash=OptUtf8ToStr(response.stream_hash.data(),static_cast<int>(response.stream_hash.size())), resourceText=OptUtf8ToStr(response.stream_resource.data(),static_cast<int>(response.stream_resource.size())); const CStringA resource(response.stream_resource.data(),static_cast<int>(response.stream_resource.size())); CString path; path.Format(_T("%seMule_RTMP\\%s\\%s"),temp,(LPCTSTR)hash,(LPCTSTR)resourceText); ese::web::WebFileResponseOptions options; options.corsOrigin="http://127.0.0.1"; Data.pSocket->SendFileResponse(path,resource,Data.sRange,options,20ull*1024ull*1024ull,true,false); return; } W8StatusContext::Send(Data.pSocket,W8BuildLiveStreamHeader(response),response.body); return; }
	}
	// W9 keeps authorization above and delegates only request/wire ownership.
	W9LiveTransferRequest transfer; bool hasTransfer=false; switch(Data.webRoute){case ese::web::WebRouteId::ApiNetworkConnect:transfer.operation=W9LiveTransferOperation::NetworkConnect;transfer.ed2k=W8Legacy(_ParseURL(Data.sURL,_T("ed2k")));transfer.kad=W8Legacy(_ParseURL(Data.sURL,_T("kad")));hasTransfer=true;break;case ese::web::WebRouteId::ApiHolePunchRendezvousTest:transfer.operation=W9LiveTransferOperation::Rendezvous;transfer.target_ip=W8Legacy(_ParseURL(Data.sURL,_T("target_ip")));transfer.target_udp_port=W8Legacy(_ParseURL(Data.sURL,_T("target_udp_port")));transfer.rdv_ip=W8Legacy(_ParseURL(Data.sURL,_T("rdv_ip")));transfer.rdv_udp_port=W8Legacy(_ParseURL(Data.sURL,_T("rdv_udp_port")));hasTransfer=true;break;case ese::web::WebRouteId::ApiKeepaliveStart:transfer.operation=W9LiveTransferOperation::KeepaliveStart;hasTransfer=true;break;case ese::web::WebRouteId::ApiKeepaliveStop:transfer.operation=W9LiveTransferOperation::KeepaliveStop;hasTransfer=true;break;case ese::web::WebRouteId::ApiRelayAccept:transfer.operation=W9LiveTransferOperation::RelayAccept;transfer.on=W8Legacy(_ParseURL(Data.sURL,_T("on")));hasTransfer=true;break;case ese::web::WebRouteId::ApiRelayEgress:transfer.operation=W9LiveTransferOperation::RelayEgress;transfer.on=W8Legacy(_ParseURL(Data.sURL,_T("on")));hasTransfer=true;break;case ese::web::WebRouteId::ApiRelaySelector:transfer.operation=W9LiveTransferOperation::RelaySelector;transfer.on=W8Legacy(_ParseURL(Data.sURL,_T("on")));hasTransfer=true;break;case ese::web::WebRouteId::ApiRelayConnect:transfer.operation=W9LiveTransferOperation::RelayConnect;transfer.on=W8Legacy(_ParseURL(Data.sURL,_T("on")));transfer.stream=W8Legacy(_ParseURL(Data.sURL,_T("stream")));transfer.buddy_ip=W8Legacy(_ParseURL(Data.sURL,_T("buddy_ip")));transfer.buddy_port=W8Legacy(_ParseURL(Data.sURL,_T("buddy_port")));hasTransfer=true;break;case ese::web::WebRouteId::ApiHolePunchTest:transfer.operation=W9LiveTransferOperation::HolePunch;transfer.ip=W8Legacy(_ParseURL(Data.sURL,_T("ip")));transfer.udp_port=W8Legacy(_ParseURL(Data.sURL,_T("udp_port")));transfer.spread=W8Legacy(_ParseURL(Data.sURL,_T("spread")));hasTransfer=true;break;default:break;}
	if(hasTransfer){W9TransferContext context{&pThis->m_authPolicy,NULL};W9LiveTransferPort port{&context,W9TransferContext::Now,W9TransferContext::Rate,W9TransferContext::ParseIPv4,W9TransferContext::Read,W9TransferContext::Network,W9TransferContext::Rendezvous,W9TransferContext::Keepalive,W9TransferContext::Relay,W9TransferContext::RelayConnect,W9TransferContext::HolePunch};W9LiveTransferResponse response;if(RunW9LiveTransferApi(transfer,port,response)){W8StatusContext::Send(Data.pSocket,W9BuildLiveTransferHeader(response),response.body);return;}}
	ese::web::W9SearchRequest search; bool hasSearch=false; switch(Data.webRoute){case ese::web::WebRouteId::ApiDebugSourceResolutions:search.operation=ese::web::W9SearchOperation::SourceResolutions;search.loopback=Data.inadr.S_un.S_addr==htonl(INADDR_LOOPBACK);search.after=W8Legacy(_ParseURL(Data.sURL,_T("after")));hasSearch=true;break;case ese::web::WebRouteId::ApiLivePrivacySubscriptions:search.operation=ese::web::W9SearchOperation::PrivacySubscriptions;search.add=W8Legacy(_ParseURL(Data.sURL,_T("add")));search.remove=W8Legacy(_ParseURL(Data.sURL,_T("remove")));search.name=W8Legacy(_ParseURL(Data.sURL,_T("name")));hasSearch=true;break;case ese::web::WebRouteId::ApiLivePrivacyTunnelSearch:{search.operation=ese::web::W9SearchOperation::TunnelSearch;CStringA keyword(_ParseURL(Data.sURL,_T("keyword")));if(!keyword.IsEmpty())keyword.MakeLower();search.keyword=W9Bytes(keyword);search.keyword_lowered=true;hasSearch=true;break;}case ese::web::WebRouteId::ApiLiveDiagnose:search.operation=ese::web::W9SearchOperation::Diagnose;search.key=W8Legacy(_ParseURL(Data.sURL,_T("key")));hasSearch=true;break;case ese::web::WebRouteId::ApiLiveKadStreams:search.operation=ese::web::W9SearchOperation::KadStreams;hasSearch=true;break;default:break;}
	if(hasSearch){ese::web::W9SearchPort port{nullptr,W9SearchContext::Now,W9SearchContext::Sources,W9SearchContext::Add,W9SearchContext::Remove,W9SearchContext::List,W9SearchContext::Tunnel,W9SearchContext::Diagnose,W9SearchContext::Refresh,W9SearchContext::Streams};ese::web::W9SearchResponse response;if(ese::web::RunW9LiveSearchApi(search,port,response)){W8StatusContext::Send(Data.pSocket,response.header,response.body);return;}}
	// W10 owns settings and diagnostics below the unchanged common auth/CSRF/role gate.
	W10SettingsRequest settings;bool hasSettings=false;switch(Data.webRoute){case ese::web::WebRouteId::ApiEseV9:settings.operation=W10SettingsOperation::EseV9;settings.on=W8Legacy(_ParseURL(Data.sURL,_T("on")));hasSettings=true;break;case ese::web::WebRouteId::ApiLivePrivacy:settings.operation=W10SettingsOperation::Privacy;settings.mode=W8Legacy(_ParseURL(Data.sURL,_T("mode")));settings.fallback=W8Legacy(_ParseURL(Data.sURL,_T("fallback")));settings.add_sensitive=W8Utf8(_ParseURL(Data.sURL,_T("add_sensitive")));settings.rm_sensitive=W8Utf8(_ParseURL(Data.sURL,_T("rm_sensitive")));hasSettings=true;break;
#ifdef ESE_TEST_HOOKS
	case ese::web::WebRouteId::ApiLiveEdgeSabotage:settings.operation=W10SettingsOperation::EdgeSabotage;settings.loopback=Data.inadr.S_un.S_addr==htonl(INADDR_LOOPBACK);settings.on=W8Legacy(_ParseURL(Data.sURL,_T("on")));settings.mode=W8Legacy(_ParseURL(Data.sURL,_T("mode")));settings.delay=W8Legacy(_ParseURL(Data.sURL,_T("delay")));hasSettings=true;break;
#endif
	default:break;}if(hasSettings){const W10SettingsPort port=W10SettingsContext::Port();W10SettingsResponse response;if(RunW10LiveSettingsApi(settings,port,response)){W8StatusContext::Send(Data.pSocket,response.header,response.body);return;}}
	ese::web::W10DiagnosticsRequest diagnostics;bool hasDiagnostics=false;switch(Data.webRoute){case ese::web::WebRouteId::ApiKrpStatus:diagnostics.operation=ese::web::W10DiagnosticsOperation::KrpStatus;hasDiagnostics=true;break;case ese::web::WebRouteId::ApiReachStatus:diagnostics.operation=ese::web::W10DiagnosticsOperation::ReachStatus;hasDiagnostics=true;break;case ese::web::WebRouteId::ApiLivePreflight:diagnostics.operation=ese::web::W10DiagnosticsOperation::Preflight;hasDiagnostics=true;break;case ese::web::WebRouteId::ApiLiveMetrics:diagnostics.operation=ese::web::W10DiagnosticsOperation::Metrics;hasDiagnostics=true;break;case ese::web::WebRouteId::ApiLiveLog:diagnostics.operation=ese::web::W10DiagnosticsOperation::Log;diagnostics.log_n=_ttoi(_ParseURL(Data.sURL,_T("n")));hasDiagnostics=true;break;case ese::web::WebRouteId::ApiLiveDebug:diagnostics.operation=ese::web::W10DiagnosticsOperation::Debug;hasDiagnostics=true;break;case ese::web::WebRouteId::ApiEseNetlabIpv6Echo:diagnostics.operation=ese::web::W10DiagnosticsOperation::Ipv6Echo;diagnostics.target=W8Utf8(_ParseURL(Data.sURL,_T("target")));diagnostics.tcp_port=_ttoi(_ParseURL(Data.sURL,_T("tcp_port")));diagnostics.udp_port=_ttoi(_ParseURL(Data.sURL,_T("udp_port")));diagnostics.nonce=W8Legacy(_ParseURL(Data.sURL,_T("nonce")));diagnostics.timeout_ms=_ttoi(_ParseURL(Data.sURL,_T("timeout_ms")));if(diagnostics.timeout_ms==0)diagnostics.timeout_ms=5000;hasDiagnostics=true;break;default:break;}
	if(hasDiagnostics){W10DiagnosticsContext context;const ese::web::W10DiagnosticsPort port{&context,W10DiagnosticsContext::Krp,W10DiagnosticsContext::Preflight,W10DiagnosticsContext::Metrics,W10DiagnosticsContext::Percentiles,W10DiagnosticsContext::Mean,W10DiagnosticsContext::Samples,W10DiagnosticsContext::Kad6,W10DiagnosticsContext::Log,W10DiagnosticsContext::Debug,W10DiagnosticsContext::Ipv6Echo,W10DiagnosticsContext::Reach};ese::web::W10DiagnosticsResponse response;if(ese::web::RunW10LiveDiagnosticsApi(diagnostics,port,response)){W8StatusContext::Send(Data.pSocket,response.header,response.body);return;}}
	// W11 owns the remaining compatibility pages, media files and privacy operations.
	ese::web::W11LegacyRequest legacy;legacy.loopback=Data.inadr.S_un.S_addr==htonl(INADDR_LOOPBACK);bool hasLegacy=false;
	switch(Data.webRoute){
	case ese::web::WebRouteId::LegacyHls:{CStringA resource=sURL.Mid(5);const int query=resource.Find('?');if(query>=0)resource=resource.Left(query);legacy.operation=ese::web::W11LegacyOperation::Hls;legacy.resource=W9Bytes(resource);legacy.range=W9Bytes(Data.sRange);hasLegacy=true;break;}
	case ese::web::WebRouteId::Dashboard:legacy.operation=ese::web::W11LegacyOperation::Dashboard;hasLegacy=true;break;
	case ese::web::WebRouteId::ApiEseNetlabReport:legacy.operation=ese::web::W11LegacyOperation::NetlabReport;hasLegacy=true;break;
	case ese::web::WebRouteId::ApiLivePrivacyTunnelEcho:legacy.operation=ese::web::W11LegacyOperation::TunnelEcho;legacy.bytes=W8Legacy(_ParseURL(Data.sURL,_T("bytes")));hasLegacy=true;break;
	case ese::web::WebRouteId::ApiLivePrivacyTunnelPing:legacy.operation=ese::web::W11LegacyOperation::TunnelPing;legacy.text=W8Legacy(_ParseURL(Data.sURL,_T("text")));hasLegacy=true;break;
	case ese::web::WebRouteId::ApiLivePrivacyCircuits:legacy.operation=ese::web::W11LegacyOperation::Circuits;hasLegacy=true;break;
	case ese::web::WebRouteId::ApiLivePrivacyPeers:legacy.operation=ese::web::W11LegacyOperation::Peers;hasLegacy=true;break;
	case ese::web::WebRouteId::ApiLivePrivacyTestCircuit:legacy.operation=ese::web::W11LegacyOperation::TestCircuit;legacy.hops=W8Legacy(_ParseURL(Data.sURL,_T("hops")));hasLegacy=true;break;
	case ese::web::WebRouteId::ApiLivePrivacyKad6Release:legacy.operation=ese::web::W11LegacyOperation::Kad6Release;legacy.enabled=W8Legacy(_ParseURL(Data.sURL,_T("enabled")));legacy.challenge=W8Utf8(_ParseURL(Data.sURL,_T("challenge")));legacy.confirm=W8Legacy(_ParseURL(Data.sURL,_T("confirm")));legacy.field_sha256=W8Legacy(_ParseURL(Data.sURL,_T("field_sha256")));legacy.audit_sha256=W8Legacy(_ParseURL(Data.sURL,_T("audit_sha256")));legacy.observed_from=W8Legacy(_ParseURL(Data.sURL,_T("observed_from")));legacy.observed_to=W8Legacy(_ParseURL(Data.sURL,_T("observed_to")));legacy.admission_attempts=W8Legacy(_ParseURL(Data.sURL,_T("admission_attempts")));legacy.admission_ppm=W8Legacy(_ParseURL(Data.sURL,_T("admission_ppm")));legacy.headroom_bps=W8Legacy(_ParseURL(Data.sURL,_T("headroom_bps")));legacy.gate_mask=W8Legacy(_ParseURL(Data.sURL,_T("gate_mask")));legacy.valid_until=W8Legacy(_ParseURL(Data.sURL,_T("valid_until")));legacy.drain_seconds=W8Legacy(_ParseURL(Data.sURL,_T("drain_seconds")));hasLegacy=true;break;
	case ese::web::WebRouteId::ApiLivePrivacyKad6Hardening:legacy.operation=ese::web::W11LegacyOperation::Kad6Hardening;legacy.service=W8Legacy(_ParseURL(Data.sURL,_T("service")));legacy.enabled=W8Legacy(_ParseURL(Data.sURL,_T("enabled")));legacy.drain_seconds=W8Legacy(_ParseURL(Data.sURL,_T("drain_seconds")));hasLegacy=true;break;
	case ese::web::WebRouteId::LiveIndex:legacy.operation=ese::web::W11LegacyOperation::LiveIndex;hasLegacy=true;break;
	case ese::web::WebRouteId::LivePlayer:legacy.operation=ese::web::W11LegacyOperation::LivePlayer;legacy.resource=W9Bytes(sURL.Mid(6,32));hasLegacy=true;break;
	default:break;}
	if(hasLegacy){const ese::web::W11LegacyPort port=W11LegacyContext::Port();ese::web::W11LegacyResponse response;if(ese::web::RunW11LiveLegacyApi(legacy,port,response)){
		if (bTokenAuth && legacy.operation == ese::web::W11LegacyOperation::LiveIndex &&
			!ese::web::RewriteLiveIndexForCookieSession(response.header,response.body)) { Data.pSocket->SendReply("HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n");return; }
		if (bTokenAuth &&
			legacy.operation == ese::web::W11LegacyOperation::LivePlayer) {
			const W12PlayerCapabilityResult result = W12RewritePlayerCapability(
				pThis->m_authPolicy, authenticatedSessionId, legacy.resource,
				response.header, response.body);
			if (result == W12PlayerCapabilityResult::NoLiveSource) {
				Data.pSocket->SendReply(
					"HTTP/1.1 409 Conflict\r\nCache-Control: no-store\r\n"
					"Referrer-Policy: no-referrer\r\nContent-Length: 0\r\n\r\n");
				return;
			}
			if (result == W12PlayerCapabilityResult::Failed) {
				Data.pSocket->SendReply(
					"HTTP/1.1 500 Internal Server Error\r\n"
					"Cache-Control: no-store\r\n"
					"Referrer-Policy: no-referrer\r\n"
					"Content-Length: 0\r\n\r\n");
				return;
			}
		}
		SendW11Response(Data,response);return;}}

	// Fallback 404
	Data.pSocket->SendReply("HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\n\r\nNot found");
}

void CWebServer::_ProcessFileReq(const ThreadData &Data)
{
	RunW11LiveLegacyStaticFile(Data);
}

CString CWebServer::_GetWebImageNameForFileType(const CString &filename)
{
	LPCTSTR p;
	switch (GetED2KFileTypeID(filename)) {
	case ED2KFT_AUDIO:
		p = _T("audio");
		break;
	case ED2KFT_VIDEO:
		p = _T("video");
		break;
	case ED2KFT_IMAGE:
		p = _T("picture");
		break;
	case ED2KFT_PROGRAM:
		p = _T("program");
		break;
	case ED2KFT_DOCUMENT:
		p = _T("document");
		break;
	case ED2KFT_ARCHIVE:
		p = _T("archive");
		break;
	case ED2KFT_CDIMAGE:
		p = _T("cdimage");
		break;
	case ED2KFT_EMULECOLLECTION:
		p = _T("emulecollection");
		break;
	default: /*ED2KFT_ANY:*/
		p = _T("other");
	}
	return CString(p);
}

CString CWebServer::_GetClientSummary(const CUpDownClient &client)
{
	CString buffer(GetResString(IDS_CD_UNAME));
	// name
	buffer.AppendFormat(_T(" %s\n"), client.GetUserName());
	// client version
	buffer.AppendFormat(_T("%s: %s\n"), (LPCTSTR)GetResString(IDS_CD_CSOFT), (LPCTSTR)client.GetClientSoftVer());

	// uploading file
	buffer.AppendFormat(_T("%s "), (LPCTSTR)GetResString(IDS_CD_UPLOADREQ));
	const CKnownFile *file = theApp.sharedfiles->GetFileByID(client.GetUploadFileID());
	ASSERT(file);
	if (file)
		buffer += file->GetFileName();

	// transferring time
	buffer.AppendFormat(_T("\n\n%s: %s\n"), (LPCTSTR)GetResString(IDS_UPLOADTIME), (LPCTSTR)CastSecondsToHM(client.GetUpStartTimeDelay() / SEC2MS(1)));

	// transferred data (up, down, global, session)
	buffer.AppendFormat(_T("%s (%s):\n"), (LPCTSTR)GetResString(IDS_FD_TRANS), (LPCTSTR)GetResString(IDS_STATS_SESSION));
	buffer.AppendFormat(_T(".....%s: %s (%s )\n"), (LPCTSTR)GetResString(IDS_PW_CON_UPLBL), (LPCTSTR)CastItoXBytes(client.GetTransferredUp()), (LPCTSTR)CastItoXBytes(client.GetSessionUp()));
	buffer.AppendFormat(_T(".....%s: %s (%s )\n"), (LPCTSTR)GetResString(IDS_DOWNLOAD), (LPCTSTR)CastItoXBytes(client.GetTransferredDown()), (LPCTSTR)CastItoXBytes(client.GetSessionDown()));

	return buffer;
}

void CWebServer::_GetClientversionImage(const CUpDownClient &client, TCHAR pSoft[2])
{
	switch (client.GetClientSoft()) {
	case SO_EMULE:
	case SO_OLDEMULE:
		*pSoft = _T('1');
		break;
	case SO_EDONKEYHYBRID:
		*pSoft = _T('h');
		break;
	case SO_AMULE:
		*pSoft = _T('a');
		break;
	case SO_SHAREAZA:
		*pSoft = _T('s');
		break;
	case SO_MLDONKEY:
		*pSoft = _T('m');
		break;
	case SO_LPHANT:
		*pSoft = _T('l');
		break;
	case SO_URL:
		*pSoft = _T('u');
		break;
	//case SO_EDONKEY:
	default:
		*pSoft = _T('0');
	}
	pSoft[1] = _T('\0');
}

CString CWebServer::_GetCommentlist(const ThreadData &Data)
{
	const CWebServer* owner = reinterpret_cast<CWebServer*>(Data.pThis); if (owner == NULL) return CString(); uchar hash[MDX_DIGEST_SIZE]; if (!strmd4(_ParseURL(Data.sURL, _T("filehash")), hash)) return CString();
	WebCommentListInput input; input.found = theApp.downloadqueue->WithFileByID(hash, [&](CPartFile* file) { input.fileName = file->GetFileName(); for (POSITION position = file->srclist.GetHeadPosition(); position != NULL;) { const CUpDownClient* client = file->srclist.GetNext(position); if (client->HasFileRating() || !client->GetFileComment().IsEmpty()) input.rows.push_back({client->GetUserName(), client->GetClientFilename(), client->GetFileComment(), GetRateString(client->GetFileRating())}); } const CTypedPtrList<CPtrList, Kademlia::CEntry*>& entries = file->getNotes(); for (POSITION position = entries.GetHeadPosition(); position != NULL;) { const Kademlia::CEntry* entry = entries.GetNext(position); input.rows.push_back({_T(""), entry->GetCommonFileName(), entry->GetStrTagValue(Kademlia::CKadTagNameString(TAG_DESCRIPTION)), GetRateString(static_cast<UINT>(entry->GetIntTagValue(Kademlia::CKadTagNameString(TAG_FILERATING))))}); } });
	return RenderWebCommentList(input, GetWebTemplate(WebTemplateParent(owner), WebTemplateId::CommentList), GetWebTemplate(WebTemplateParent(owner), WebTemplateId::CommentListLine));
}
