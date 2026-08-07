#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace ese {
namespace web {

enum class WebRouteMethod : std::uint8_t {
	Get = 0,
	Post,
	Options
};

enum class WebRouteStatus : std::uint8_t {
	Matched = 0,
	NotFound,
	MethodNotAllowed
};

enum class WebHandler : std::uint8_t {
	None = 0,
	ClassicPage,
	StaticAsset,
	LiveApi,
	CorsPreflight
};

enum class WebRouteId : std::uint8_t {
	None = 0,
	ClassicPage,
	StaticAsset,
	Dashboard,
	LegacyHls,
	LiveIndex,
	LivePlayer,
	ApiNetworkConnect,
	ApiDebugSourceResolutions,
	ApiStatus,
	ApiLiveJoin,
	ApiLiveLeave,
	ApiLivePlayerAlive,
	ApiLiveBroadcastStart,
	ApiLiveBroadcastStop,
	ApiHolePunchRendezvousTest,
	ApiKeepaliveStart,
	ApiKeepaliveStop,
	ApiEseV9,
	ApiEseNetlabIpv6Echo,
	ApiEseNetlabReport,
	ApiKrpStatus,
	ApiRelayAccept,
	ApiRelayEgress,
	ApiRelaySelector,
	ApiRelayConnect,
	ApiHolePunchTest,
	ApiLivePreflight,
	ApiLivePrivacySubscriptions,
	ApiLivePrivacyTunnelSearch,
	ApiLivePrivacyTunnelEcho,
	ApiLivePrivacyTunnelPing,
	ApiLivePrivacyCircuits,
	ApiLivePrivacyPeers,
	ApiLivePrivacyTestCircuit,
	ApiLivePrivacyKad6Release,
	ApiLivePrivacyKad6Hardening,
	ApiLivePrivacy,
	ApiLiveMetrics,
	ApiLiveLog,
	ApiLiveDiagnose,
	ApiLiveDirectJoin,
	ApiLiveChannels,
	ApiLiveMesh,
	ApiLiveKadStreams,
	ApiLiveEdgeSabotage,
	ApiLiveDebug,
	ApiLiveStream,
	ApiReachStatus
};

struct WebRouteMatch {
	WebRouteStatus status = WebRouteStatus::NotFound;
	WebHandler handler = WebHandler::None;
	WebRouteId route = WebRouteId::None;
	bool token_prefixed = false;
	bool hls_capability_prefixed = false;
	std::string canonical_path;
};

struct WebHlsCapabilityPath {
	std::string token;
	std::string stream_hash;
	std::string resource;
	std::string canonical_path;
	std::uint64_t generation = 0;
};

WebRouteMatch ResolveWebRoute(WebRouteMethod method, const std::string& target);
bool ParseWebHlsCapabilityPath(
	const std::string& target,
	WebHlsCapabilityPath& capability);
std::size_t RegisteredExactWebRouteCount();
bool RunWebRouteTableSelfTest(std::string& failure);

} // namespace web
} // namespace ese
