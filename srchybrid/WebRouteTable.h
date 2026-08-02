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
	ApiLiveStream
};

struct WebRouteMatch {
	WebRouteStatus status = WebRouteStatus::NotFound;
	WebHandler handler = WebHandler::None;
	WebRouteId route = WebRouteId::None;
	bool token_prefixed = false;
	std::string canonical_path;
};

WebRouteMatch ResolveWebRoute(WebRouteMethod method, const std::string& target);
std::size_t RegisteredExactWebRouteCount();
bool RunWebRouteTableSelfTest(std::string& failure);

} // namespace web
} // namespace ese
