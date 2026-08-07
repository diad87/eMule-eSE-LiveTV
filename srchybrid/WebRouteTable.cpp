#include "WebRouteTable.h"

#include <cctype>
#include <climits>
#include <limits>

namespace ese {
namespace web {
namespace {

struct RouteDefinition {
	const char* path;
	WebRouteId route;
};

constexpr RouteDefinition kExactRoutes[] = {
	{"/dashboard", WebRouteId::Dashboard},
	{"/dashboard/", WebRouteId::Dashboard},
	{"/live", WebRouteId::LiveIndex},
	{"/live/", WebRouteId::LiveIndex},
	{"/api/network/connect", WebRouteId::ApiNetworkConnect},
	{"/api/debug/source-resolutions", WebRouteId::ApiDebugSourceResolutions},
	{"/api/status", WebRouteId::ApiStatus},
	{"/api/live/join", WebRouteId::ApiLiveJoin},
	{"/api/live/leave", WebRouteId::ApiLiveLeave},
	{"/api/live/player-alive", WebRouteId::ApiLivePlayerAlive},
	{"/api/live/broadcast/start", WebRouteId::ApiLiveBroadcastStart},
	{"/api/live/broadcast/stop", WebRouteId::ApiLiveBroadcastStop},
	{"/api/holepunch/rdv_test", WebRouteId::ApiHolePunchRendezvousTest},
	{"/api/keepalive/start", WebRouteId::ApiKeepaliveStart},
	{"/api/keepalive/stop", WebRouteId::ApiKeepaliveStop},
	{"/api/ese/v9", WebRouteId::ApiEseV9},
	{"/api/ese/netlab/ipv6_echo", WebRouteId::ApiEseNetlabIpv6Echo},
	{"/api/ese/netlab/report", WebRouteId::ApiEseNetlabReport},
	{"/api/krp/status", WebRouteId::ApiKrpStatus},
	{"/api/reach/status", WebRouteId::ApiReachStatus},
	{"/api/relay/accept", WebRouteId::ApiRelayAccept},
	{"/api/relay/egress", WebRouteId::ApiRelayEgress},
	{"/api/relay/selector", WebRouteId::ApiRelaySelector},
	{"/api/relay/connect", WebRouteId::ApiRelayConnect},
	{"/api/holepunch/test", WebRouteId::ApiHolePunchTest},
	{"/api/live/preflight", WebRouteId::ApiLivePreflight},
	{"/api/live/privacy/subscriptions", WebRouteId::ApiLivePrivacySubscriptions},
	{"/api/live/privacy/tunnel_search", WebRouteId::ApiLivePrivacyTunnelSearch},
	{"/api/live/privacy/tunnel_echo", WebRouteId::ApiLivePrivacyTunnelEcho},
	{"/api/live/privacy/tunnel_ping", WebRouteId::ApiLivePrivacyTunnelPing},
	{"/api/live/privacy/circuits", WebRouteId::ApiLivePrivacyCircuits},
	{"/api/live/privacy/peers", WebRouteId::ApiLivePrivacyPeers},
	{"/api/live/privacy/test_circuit", WebRouteId::ApiLivePrivacyTestCircuit},
	{"/api/live/privacy/kad6/release", WebRouteId::ApiLivePrivacyKad6Release},
	{"/api/live/privacy/kad6/hardening", WebRouteId::ApiLivePrivacyKad6Hardening},
	{"/api/live/privacy", WebRouteId::ApiLivePrivacy},
	{"/api/live/metrics", WebRouteId::ApiLiveMetrics},
	{"/api/live/log", WebRouteId::ApiLiveLog},
	{"/api/live/diagnose", WebRouteId::ApiLiveDiagnose},
	{"/api/live/direct_join", WebRouteId::ApiLiveDirectJoin},
	{"/api/live/channels", WebRouteId::ApiLiveChannels},
	{"/api/live/mesh", WebRouteId::ApiLiveMesh},
	{"/api/live/kad/streams", WebRouteId::ApiLiveKadStreams},
	{"/api/live/test/edge_sabotage", WebRouteId::ApiLiveEdgeSabotage},
	{"/api/live/debug", WebRouteId::ApiLiveDebug}
};

bool SplitTarget(const std::string& target, std::string& path)
{
	if (target.empty() || target.front() != '/' ||
		target.find('#') != std::string::npos ||
		target.find('\0') != std::string::npos)
		return false;
	const std::size_t query = target.find('?');
	path.assign(target, 0, query);
	return !path.empty();
}

bool IsAsciiHex(char value)
{
	return (value >= '0' && value <= '9') ||
		(value >= 'a' && value <= 'f') ||
		(value >= 'A' && value <= 'F');
}

bool IsHexSpan(const std::string& value, std::size_t offset, std::size_t length)
{
	if (offset > value.size() || length > value.size() - offset)
		return false;
	for (std::size_t index = offset; index < offset + length; ++index) {
		if (!IsAsciiHex(value[index]))
			return false;
	}
	return true;
}

bool HasCaseInsensitiveSuffix(const std::string& value, const char* suffix)
{
	const std::string expected(suffix);
	if (value.size() < expected.size())
		return false;
	const std::size_t offset = value.size() - expected.size();
	for (std::size_t index = 0; index < expected.size(); ++index) {
		const unsigned char left =
			static_cast<unsigned char>(value[offset + index]);
		const unsigned char right =
			static_cast<unsigned char>(expected[index]);
		if (std::tolower(left) != std::tolower(right))
			return false;
	}
	return true;
}

bool IsSafeLeaf(const std::string& value, std::size_t maxLength)
{
	if (value.empty() || value.size() >= maxLength ||
		value.find("..") != std::string::npos)
		return false;
	for (const unsigned char byte : value) {
		const bool asciiAlphaNumeric =
			(byte >= '0' && byte <= '9') ||
			(byte >= 'A' && byte <= 'Z') ||
			(byte >= 'a' && byte <= 'z');
		if (!(asciiAlphaNumeric || byte == '.' || byte == '_' || byte == '-'))
			return false;
	}
	return true;
}

bool IsSafeHlsResource(const std::string& resource)
{
	if (!IsSafeLeaf(resource, 256))
		return false;
	if (resource == "stream.m3u8")
		return true;
	auto variant = [](const std::string& value) {
		// Runtime ABR currently emits at most five numeric variants.  The
		// disabled multi-audio branch must extend this grammar explicitly before
		// language-named outputs can ever become capability-addressable.
		return value.size() == 1 && value[0] >= '0' && value[0] <= '4';
	};
	auto sequence = [](const std::string& value) {
		if (value.size() < 5 || value.size() > 10)
			return false;
		std::uint64_t parsed = 0;
		for (const char character : value) {
			if (character < '0' || character > '9')
				return false;
			parsed = parsed * 10u +
				static_cast<std::uint64_t>(character - '0');
		}
		return parsed <= (std::numeric_limits<std::uint32_t>::max)();
	};
	if (resource.size() == 13 &&
		resource.compare(0, 7, "stream_") == 0 &&
		resource.compare(8, 5, ".m3u8") == 0)
		return variant(resource.substr(7, 1));
	if (resource.size() < 12 ||
		resource.compare(0, 4, "seg_") != 0 ||
		resource.compare(resource.size() - 3, 3, ".ts") != 0)
		return false;
	const std::string identity = resource.substr(4, resource.size() - 7);
	const std::size_t separator = identity.find('_');
	if (separator == std::string::npos)
		return sequence(identity);
	return separator == 1 &&
		identity.find('_', separator + 1) == std::string::npos &&
		variant(identity.substr(0, separator)) &&
		sequence(identity.substr(separator + 1));
}

bool ParseUnsigned64(const std::string& value, std::uint64_t& parsed)
{
	if (value.empty() || (value.size() > 1 && value.front() == '0'))
		return false;
	parsed = 0;
	for (const char character : value) {
		if (character < '0' || character > '9')
			return false;
		const std::uint64_t digit =
			static_cast<std::uint64_t>(character - '0');
		if (parsed > ((std::numeric_limits<std::uint64_t>::max)() - digit) / 10u)
			return false;
		parsed = parsed * 10u + digit;
	}
	return parsed != 0;
}

bool ParseHlsCapabilityPathOnly(
	const std::string& path,
	WebHlsCapabilityPath& capability)
{
	capability = WebHlsCapabilityPath();
	if (path.compare(0, 3, "/h/") != 0)
		return false;
	const std::size_t generationAt = path.find('/', 3);
	const std::size_t streamAt = generationAt == std::string::npos
		? std::string::npos : path.find('/', generationAt + 1);
	const std::size_t resourceAt = streamAt == std::string::npos
		? std::string::npos : path.find('/', streamAt + 1);
	if (generationAt != 3 + 64 || streamAt == std::string::npos ||
		resourceAt == std::string::npos || resourceAt != streamAt + 33 ||
		!IsHexSpan(path, 3, 64) || !IsHexSpan(path, streamAt + 1, 32))
		return false;
	for (std::size_t index = 3; index < generationAt; ++index) {
		if (path[index] >= 'A' && path[index] <= 'F')
			return false;
	}
	for (std::size_t index = streamAt + 1; index < resourceAt; ++index) {
		if (path[index] >= 'A' && path[index] <= 'F')
			return false;
	}
	const std::string generationText = path.substr(
		generationAt + 1, streamAt - generationAt - 1);
	if (!ParseUnsigned64(generationText, capability.generation))
		return false;
	capability.token = path.substr(3, 64);
	capability.stream_hash = path.substr(streamAt + 1, 32);
	capability.resource = path.substr(resourceAt + 1);
	if (!IsSafeHlsResource(capability.resource)) {
		capability = WebHlsCapabilityPath();
		return false;
	}
	capability.canonical_path = "/api/live/" + capability.stream_hash +
		"/" + capability.resource;
	return true;
}

bool IsStaticAssetPath(const std::string& path)
{
	if (path.size() < 3 || path.front() != '/' ||
		path.find("..") != std::string::npos ||
		path.find('\\') != std::string::npos)
		return false;
	for (const unsigned char byte : path) {
		const bool asciiAlphaNumeric =
			(byte >= '0' && byte <= '9') ||
			(byte >= 'A' && byte <= 'Z') ||
			(byte >= 'a' && byte <= 'z');
		if (!(asciiAlphaNumeric || byte == '/' || byte == '.' ||
			byte == '_' || byte == '-'))
			return false;
	}
	return HasCaseInsensitiveSuffix(path, ".gif") ||
		HasCaseInsensitiveSuffix(path, ".jpg") ||
		HasCaseInsensitiveSuffix(path, ".png") ||
		HasCaseInsensitiveSuffix(path, ".ico") ||
		HasCaseInsensitiveSuffix(path, ".css") ||
		HasCaseInsensitiveSuffix(path, ".bmp") ||
		HasCaseInsensitiveSuffix(path, ".js") ||
		HasCaseInsensitiveSuffix(path, ".jpeg");
}

bool ParseSessionPrefix(
	const std::string& path,
	std::string& suffix)
{
	if (path.compare(0, 3, "/s/") != 0)
		return false;
	const std::size_t separator = path.find('/', 3);
	if (separator == std::string::npos || separator == 3)
		return false;

	std::uint64_t token = 0;
	for (std::size_t index = 3; index < separator; ++index) {
		const char value = path[index];
		if (value < '0' || value > '9')
			return false;
		const unsigned digit = static_cast<unsigned>(value - '0');
		if (token >
			(static_cast<std::uint64_t>(INT_MAX) - digit) / 10u)
			return false;
		token = token * 10u + digit;
	}
	if (token == 0)
		return false;
	suffix.assign(path, separator, std::string::npos);
	return true;
}

WebRouteMatch MatchGetPath(
	const std::string& path,
	bool allowSessionPrefix)
{
	WebRouteMatch result;
	result.canonical_path = path;

	if (path == "/") {
		result.status = WebRouteStatus::Matched;
		result.handler = WebHandler::ClassicPage;
		result.route = WebRouteId::ClassicPage;
		return result;
	}

	for (const RouteDefinition& definition : kExactRoutes) {
		if (path == definition.path) {
			result.status = WebRouteStatus::Matched;
			result.handler = WebHandler::LiveApi;
			result.route = definition.route;
			return result;
		}
	}

	if (path.compare(0, 5, "/hls/") == 0) {
		const std::string resource = path.substr(5);
		if (IsSafeLeaf(resource, 64) &&
			(HasCaseInsensitiveSuffix(resource, ".m3u8") ||
			 HasCaseInsensitiveSuffix(resource, ".ts"))) {
			result.status = WebRouteStatus::Matched;
			result.handler = WebHandler::LiveApi;
			result.route = WebRouteId::LegacyHls;
			return result;
		}
	}

	if (path.size() == 38 && path.compare(0, 6, "/live/") == 0 &&
		IsHexSpan(path, 6, 32)) {
		result.status = WebRouteStatus::Matched;
		result.handler = WebHandler::LiveApi;
		result.route = WebRouteId::LivePlayer;
		return result;
	}

	if (path.size() > 43 && path.compare(0, 10, "/api/live/") == 0 &&
		path[42] == '/' && IsHexSpan(path, 10, 32) &&
		IsSafeHlsResource(path.substr(43))) {
		result.status = WebRouteStatus::Matched;
		result.handler = WebHandler::LiveApi;
		result.route = WebRouteId::ApiLiveStream;
		return result;
	}

	WebHlsCapabilityPath capability;
	if (ParseHlsCapabilityPathOnly(path, capability)) {
		result.status = WebRouteStatus::Matched;
		result.handler = WebHandler::LiveApi;
		result.route = WebRouteId::ApiLiveStream;
		result.hls_capability_prefixed = true;
		result.canonical_path = capability.canonical_path;
		return result;
	}

	if (allowSessionPrefix) {
		std::string suffix;
		if (ParseSessionPrefix(path, suffix)) {
			WebRouteMatch nested = MatchGetPath(suffix, false);
			if (nested.status == WebRouteStatus::Matched &&
				nested.handler == WebHandler::LiveApi &&
				nested.route != WebRouteId::ApiLiveStream &&
				nested.route != WebRouteId::LegacyHls) {
				nested.token_prefixed = true;
				return nested;
			}
		}
		if (path.compare(0, 3, "/s/") == 0)
			return result;
	}
	if (path.compare(0, 3, "/h/") == 0)
		return result;

	if (IsStaticAssetPath(path)) {
		result.status = WebRouteStatus::Matched;
		result.handler = WebHandler::StaticAsset;
		result.route = WebRouteId::StaticAsset;
	}
	return result;
}

} // namespace

bool ParseWebHlsCapabilityPath(
	const std::string& target,
	WebHlsCapabilityPath& capability)
{
	std::string path;
	if (target.find('?') != std::string::npos || !SplitTarget(target, path)) {
		capability = WebHlsCapabilityPath();
		return false;
	}
	return ParseHlsCapabilityPathOnly(path, capability);
}

WebRouteMatch ResolveWebRoute(WebRouteMethod method, const std::string& target)
{
	std::string path;
	if (target.compare(0, 3, "/h/") == 0 &&
		target.find('?') != std::string::npos)
		return {};
	if (!SplitTarget(target, path))
		return {};

	WebRouteMatch getMatch = MatchGetPath(path, true);
	if (getMatch.status != WebRouteStatus::Matched)
		return getMatch;

	if (method == WebRouteMethod::Get)
		return getMatch;
	if (method == WebRouteMethod::Post &&
		getMatch.handler == WebHandler::ClassicPage)
		return getMatch;
	if (method == WebRouteMethod::Options &&
		getMatch.handler == WebHandler::LiveApi &&
		!getMatch.hls_capability_prefixed) {
		getMatch.handler = WebHandler::CorsPreflight;
		return getMatch;
	}

	getMatch.status = WebRouteStatus::MethodNotAllowed;
	getMatch.handler = WebHandler::None;
	return getMatch;
}

std::size_t RegisteredExactWebRouteCount()
{
	return sizeof(kExactRoutes) / sizeof(kExactRoutes[0]);
}

bool RunWebRouteTableSelfTest(std::string& failure)
{
	failure.clear();
	const WebRouteMatch status =
		ResolveWebRoute(WebRouteMethod::Get, "/api/status?ignored=1");
	if (status.status != WebRouteStatus::Matched ||
		status.route != WebRouteId::ApiStatus ||
		status.handler != WebHandler::LiveApi) {
		failure = "web route table failed exact API dispatch";
		return false;
	}
	if (ResolveWebRoute(WebRouteMethod::Get, "/api/status/future").status !=
		WebRouteStatus::NotFound) {
		failure = "web route table accepted unknown route";
		return false;
	}
	if (ResolveWebRoute(WebRouteMethod::Post, "/api/status").status !=
		WebRouteStatus::MethodNotAllowed) {
		failure = "web route table accepted unknown method";
		return false;
	}
	const WebRouteMatch ipv6Echo = ResolveWebRoute(
		WebRouteMethod::Get,
		"/api/ese/netlab/ipv6_echo?target=2001:db8::1");
	if (ipv6Echo.status != WebRouteStatus::Matched ||
		ipv6Echo.route != WebRouteId::ApiEseNetlabIpv6Echo ||
		ipv6Echo.handler != WebHandler::LiveApi) {
		failure = "web route table failed IPv6 echo dispatch";
		return false;
	}
	const WebRouteMatch prefixed = ResolveWebRoute(
		WebRouteMethod::Get,
		"/s/123/live/0123456789abcdef0123456789abcdef");
	if (prefixed.status != WebRouteStatus::Matched ||
		!prefixed.token_prefixed ||
		prefixed.route != WebRouteId::LivePlayer) {
		failure = "web route table failed token-prefixed page locator";
		return false;
	}
	const std::string capabilityToken(64, 'a');
	const std::string capabilityTarget = "/h/" + capabilityToken +
		"/7/0123456789abcdef0123456789abcdef/stream.m3u8";
	const WebRouteMatch hlsCapability = ResolveWebRoute(
		WebRouteMethod::Get, capabilityTarget);
	WebHlsCapabilityPath parsedCapability;
	if (hlsCapability.status != WebRouteStatus::Matched ||
		!hlsCapability.hls_capability_prefixed ||
		hlsCapability.route != WebRouteId::ApiLiveStream ||
		!ParseWebHlsCapabilityPath(capabilityTarget, parsedCapability) ||
		parsedCapability.token != capabilityToken ||
		parsedCapability.generation != 7 ||
		parsedCapability.stream_hash !=
			"0123456789abcdef0123456789abcdef" ||
		parsedCapability.resource != "stream.m3u8") {
		failure = "web route table failed HLS capability path";
		return false;
	}
	const std::string abrCapabilityTarget = "/h/" + capabilityToken +
		"/7/0123456789abcdef0123456789abcdef/seg_4_00001.ts";
	if (ResolveWebRoute(
			WebRouteMethod::Get, abrCapabilityTarget).status !=
				WebRouteStatus::Matched ||
		!ParseWebHlsCapabilityPath(
			abrCapabilityTarget, parsedCapability) ||
		parsedCapability.resource != "seg_4_00001.ts") {
		failure = "web route table failed bounded ABR capability path";
		return false;
	}
	for (const char* invalidResource : {
			"stream_eng.m3u8", "stream_5.m3u8", "seg_secret.ts",
			"seg_0001.ts", "seg_4294967296.ts", "seg_5_00001.ts"}) {
		const std::string invalidTarget = "/h/" + capabilityToken +
			"/7/0123456789abcdef0123456789abcdef/" + invalidResource;
		if (ResolveWebRoute(
				WebRouteMethod::Get, invalidTarget).status !=
					WebRouteStatus::NotFound) {
			failure = "web route table widened runtime HLS output grammar";
			return false;
		}
	}
	if (ResolveWebRoute(
			WebRouteMethod::Get,
			"/s/123/api/live/0123456789abcdef0123456789abcdef/stream.m3u8").status !=
		WebRouteStatus::NotFound) {
		failure = "web route table retained session credential in HLS path";
		return false;
	}
	if (ResolveWebRoute(
			WebRouteMethod::Get,
			"/s/999999999999999999999999999999999999999/api/status").status !=
		WebRouteStatus::NotFound) {
		failure = "web route table accepted overflowing session token";
		return false;
	}
	if (ResolveWebRoute(WebRouteMethod::Get, "/style.css:secret.css").status !=
		WebRouteStatus::NotFound) {
		failure = "web route table accepted unsafe static path";
		return false;
	}
	if (ResolveWebRoute(
			WebRouteMethod::Get,
			"/api/live/0123456789abcdef0123456789abcdef/stream_eng.M3U8").status !=
		WebRouteStatus::NotFound) {
		failure = "web route table widened dynamic HLS extension case";
		return false;
	}
	return true;
}

} // namespace web
} // namespace ese
