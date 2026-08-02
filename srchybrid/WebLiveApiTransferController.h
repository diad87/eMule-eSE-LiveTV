#pragma once

#include "M2ABindingPort.h"

#include <array>
#include <cstdint>
#include <string>

enum class W9LiveTransferOperation { NetworkConnect, Rendezvous, KeepaliveStart,
	KeepaliveStop, RelayAccept, RelayEgress, RelaySelector, RelayConnect, HolePunch };
enum class W9LiveTransferRate { NetworkConnect, ManualRendezvous, KeepaliveToggle, ManualHolePunch };
enum class W9LiveRelayToggle { Accept, Egress, Selector };
enum class W9LiveTransferGuard { Ok, InvalidIpPort, KadNotReady, HolePunchDisabled,
	RendezvousDisabled, NetlabConsentRequired, NetlabTargetRequired, UtpNotReady };

struct W9LiveTransferRequest {
	W9LiveTransferOperation operation = W9LiveTransferOperation::NetworkConnect;
	std::string ed2k, kad, target_ip, target_udp_port, rdv_ip, rdv_udp_port;
	std::string on, stream, buddy_ip, buddy_port, ip, udp_port, spread;
};
struct W9LiveTransferRateDecision { bool allowed = false; std::uint64_t retry_after_ms = 0; };
struct W9LiveHolePunchResult {
	W9LiveTransferGuard guard = W9LiveTransferGuard::InvalidIpPort;
	std::uint32_t attempts_before = 0;
	std::uint16_t spread = 0;
};
struct W9LiveTransferSnapshot {
	bool ed2k_connected = false, ed2k_connecting = false, kad_running = false, kad_connected = false;
	bool kad2_running = false, kad2_connected = false, kad6_running = false, kad6_connected = false;
	bool netlab_active = false, kad_udp_ready = false, utp_hole_punch_enabled = false;
	bool kad3_rendezvous_enabled = false, client_utp_ready = false, keepalive_running = false;
	bool relay_accept = false, relay_egress = false, relay_selector = false, port_predict = false;
	std::uint32_t kad_configured_mask = 0, kad_running_mask = 0, kad6_verified_contacts = 0;
	std::uint32_t kad3_rdv_req_sent = 0, kad3_rdv_req_recv = 0, kad3_rdv_challenge_sent = 0, kad3_rdv_fwd = 0, kad3_rdv_success = 0;
	std::uint32_t keepalive_pings_sent = 0, keepalive_pongs_recv = 0, keepalive_supernodes = 0;
	std::uint32_t relay_req_recv = 0, relay_accepted = 0, relay_active = 0, relay_bytes_fwd_kb = 0, relay_budget_drops = 0, relay_max_kbps = 0;
	std::uint32_t reach_direct = 0, reach_punch2 = 0, reach_punch3 = 0, reach_relay = 0;
	std::uint32_t hole_attempts = 0, hole_success = 0, hole_sym_nat_fail = 0, hole_encrypted = 0, hole_plaintext = 0, hole_spray_reqs = 0, hole_req_recv = 0, hole_challenge_sent = 0;
	std::uint16_t port_predict_spread = 0;
};
struct W9LiveTransferResponse {
	unsigned status = 200; std::string reason = "OK", content_type = "application/json", body;
	bool cors = true, nosniff = true, cache_no_store = false;
};

struct W9LiveTransferPort {
	void* context = nullptr;
	std::uint64_t (*now_ms)(void*) = nullptr;
	W9LiveTransferRateDecision (*check_rate)(void*, W9LiveTransferRate, std::uint64_t, std::uint64_t) = nullptr;
	bool (*parse_ipv4_legacy)(void*, const std::string&, std::uint32_t&) = nullptr;
	bool (*read_snapshot)(void*, W9LiveTransferSnapshot&) = nullptr;
	void (*request_network)(void*, bool, bool, bool&, bool&) = nullptr;
	W9LiveTransferGuard (*request_rendezvous)(void*, std::uint32_t, std::uint16_t, std::uint32_t, std::uint16_t) = nullptr;
	W9LiveTransferGuard (*request_keepalive)(void*, bool) = nullptr;
	void (*set_relay)(void*, W9LiveRelayToggle, bool) = nullptr;
	void (*request_relay_connect)(void*, const std::array<unsigned char, 16>&, std::uint32_t, std::uint16_t) = nullptr;
	W9LiveHolePunchResult (*request_hole_punch)(void*, std::uint32_t, std::uint16_t, bool, int) = nullptr;
};

std::string W9BuildLiveTransferHeader(const W9LiveTransferResponse& response);
bool RunW9LiveTransferApi(const W9LiveTransferRequest&, W9LiveTransferPort&, W9LiveTransferResponse&);
bool RunW9LiveTransferCharacterizationSelfTest(std::string& failure);

namespace eSELive {
class WebLiveApiTransferController final { public: explicit WebLiveApiTransferController(const M2AParentPort&) noexcept; private: M2AParentPort m_parent; };
M2AModuleHandle M2A_BIND_W9_52CC9DEBDD(const M2AParentPort&);
void M2A_UNBIND_W9_52CC9DEBDD(const M2AParentPort&);
} // namespace eSELive
