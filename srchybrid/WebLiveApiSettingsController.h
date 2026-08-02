#pragma once

#include "M2ABindingPort.h"

#include <cstdint>
#include <string>
#include <vector>

enum class W10SettingsOperation { EseV9, Privacy, EdgeSabotage };

struct W10SettingsRequest {
	W10SettingsOperation operation = W10SettingsOperation::EseV9;
	bool loopback = false;
	std::string on, mode, fallback, add_sensitive, rm_sensitive, delay;
};

struct W10NetlabSnapshot {
	std::string consent = "undecided", advanced_consent = "undecided", contribution_consent = "undecided";
	bool enabled = false, capability_advertised = false, ipv6_auto = false, hole_punch = false;
	bool auto_keepalive = false, selector = false, port_predict = false, ed2k_punch3 = false;
	bool kad3_rendezvous = false, relay_accept = false, relay_egress = false, krp = false;
	bool kad6_beta_exit = false, kad6_stable_public_exit = false, keepalive_running = false;
	bool experimental = false, hole_punch_master = false;
	std::uint32_t reach_direct = 0, reach_punch2 = 0, reach_punch3 = 0, reach_relay = 0;
};

struct W10PrivacySnapshot {
	std::string mode = "adaptive", fallback = "balanced", public_ipv6;
	std::vector<std::string> sensitive_keywords, caps_human;
	std::uint32_t caps_bits = 0, circuits_active = 0, circuits_pending = 0, tunnel_pool_size = 0;
	std::uint32_t subscriptions_loaded = 0, mean_rtt_ms = 0;
	std::uint64_t cells_sent = 0, cells_recv = 0, bytes_sent = 0, bytes_recv = 0;
	bool kad6_preferred = false, kad6_circuit_active = false;
	std::string route_state = "kad2_direct";
};

struct W10SettingsResponse {
	unsigned status = 200;
	std::string reason = "OK", header, body;
};

struct W10SettingsPort {
	void* context = nullptr;
	bool (*read_netlab)(void*, W10NetlabSnapshot&) = nullptr;
	bool (*netlab_consent_accepted)(void*) = nullptr;
	void (*apply_netlab)(void*, bool) = nullptr;
	void (*refresh_preview_caps)(void*) = nullptr;
	void (*request_keepalive)(void*, bool) = nullptr;
	bool (*persist_disable_and_verify)(void*) = nullptr;
	bool (*save_preferences)(void*) = nullptr; // true means native save error
	void (*post_krp_event)(void*) = nullptr;
	bool (*read_privacy_policy)(void*, W10PrivacySnapshot&) = nullptr;
	void (*set_privacy_mode)(void*, const std::string&) = nullptr;
	void (*set_fallback)(void*, const std::string&) = nullptr;
	void (*add_sensitive)(void*, const std::string&) = nullptr;
	void (*remove_sensitive)(void*, const std::string&) = nullptr;
	void (*mirror_privacy_preferences)(void*) = nullptr;
	bool (*read_privacy_runtime)(void*, W10PrivacySnapshot&) = nullptr;
	bool test_hooks_enabled = false;
	void (*set_edge_sabotage)(void*, bool, int, std::uint32_t) = nullptr;
};

bool RunW10LiveSettingsApi(const W10SettingsRequest&, const W10SettingsPort&, W10SettingsResponse&);
bool RunW10LiveSettingsCharacterizationSelfTest(std::string& failure);

namespace eSELive {
class WebLiveApiSettingsController final {
public:
	explicit WebLiveApiSettingsController(const M2AParentPort& parent) noexcept;
private:
	M2AParentPort m_parent;
};
M2AModuleHandle M2A_BIND_W10_E9722EA045(const M2AParentPort& parent);
void M2A_UNBIND_W10_E9722EA045(const M2AParentPort& parent);
} // namespace eSELive
