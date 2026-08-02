#pragma once

#include "M2ABindingPort.h"

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace ese { namespace web {

enum class W9SearchOperation { SourceResolutions, PrivacySubscriptions, TunnelSearch, Diagnose, KadStreams };
struct W9SearchRequest { W9SearchOperation operation = W9SearchOperation::SourceResolutions; bool loopback = false, keyword_lowered = false; std::string after, add, remove, name, keyword, key; };
struct W9SourceCandidate { std::string family, endpoint_sha256, outcome, source_origin; };
struct W9SourceEvent { std::uint64_t sequence = 0; std::string hostname_sha256, file_ed2k_hash, resolver_result, resolved_endpoint_set_sha256, materialized_endpoint_set_sha256; std::uint32_t port = 0, resolved_ipv4 = 0, resolved_ipv6 = 0, materialized_ipv4 = 0, materialized_ipv6 = 0; bool simultaneously_retained = false; std::vector<W9SourceCandidate> candidates; };
struct W9Subscription { std::array<std::uint8_t, 32> pubkey{}; std::string name; std::uint64_t added = 0; };
struct W9DirectoryEntry { std::string title, broadcaster_ip; std::uint32_t broadcaster_port = 0, bitrate = 0, viewers = 0, last_seen_age_ms = 0; bool own = false; };
struct W9DiagnoseSnapshot { bool kad_connected = false, broadcasting = false, viewing = false, in_directory = false, public_ip_available = false; std::string public_ip; std::uint16_t tcp_port = 0; std::uint32_t directory_size = 0; W9DirectoryEntry entry; };
struct W9KadStream { std::array<std::uint8_t, 16> key{}; std::string title, category, language; std::uint32_t bitrate = 0, viewers = 0, broadcaster_ip = 0, broadcaster_port = 0, started_at = 0, last_seen = 0; bool own = false, kad6_tunnel = false; };
struct W9SearchPort {
	void* context = nullptr;
	std::uint32_t (*now_ms)(void*) = nullptr;
	bool (*read_source_events)(void*, std::uint64_t, std::uint64_t&, std::vector<W9SourceEvent>&) = nullptr;
	bool (*add_subscription)(void*, const std::array<std::uint8_t, 32>&, const std::string&, std::string&) = nullptr;
	bool (*remove_subscription)(void*, const std::array<std::uint8_t, 32>&, std::string&) = nullptr;
	bool (*list_subscriptions)(void*, std::vector<W9Subscription>&) = nullptr;
	bool (*tunnel_search)(void*, const std::string&, std::string&, unsigned) = nullptr;
	bool (*read_diagnose)(void*, const std::array<std::uint8_t, 16>*, W9DiagnoseSnapshot&) = nullptr;
	void (*request_kad_refresh)(void*) = nullptr;
	bool (*read_kad_streams)(void*, bool&, std::vector<W9KadStream>&) = nullptr;
};
struct W9SearchResponse { std::string header, body; };

bool RunW9LiveSearchApi(const W9SearchRequest&, const W9SearchPort&, W9SearchResponse&);
bool RunW9LiveSearchCharacterizationSelfTest(std::string& failure);

} } // namespace ese::web

namespace eSELive {
class WebLiveApiSearchController final { public: explicit WebLiveApiSearchController(const M2AParentPort& parent) noexcept; private: M2AParentPort m_parent; };
M2AModuleHandle M2A_BIND_W9_3B359EBB1A(const M2AParentPort& parent);
void M2A_UNBIND_W9_3B359EBB1A(const M2AParentPort& parent);
} // namespace eSELive
