#include "../WebRouteTable.h"

#include <cstdio>
#include <string>

namespace {

int failures = 0;

void Check(bool condition, const char* message)
{
	if (!condition) {
		std::fprintf(stderr, "FAIL: %s\n", message);
		++failures;
	}
}

void CheckRoute(
	const char* target,
	ese::web::WebRouteId expected,
	const char* message)
{
	const ese::web::WebRouteMatch match =
		ese::web::ResolveWebRoute(ese::web::WebRouteMethod::Get, target);
	Check(
		match.status == ese::web::WebRouteStatus::Matched &&
		match.route == expected &&
		match.handler != ese::web::WebHandler::None,
		message);
}

void TestExactRoutes()
{
	using namespace ese::web;
	struct Vector {
		const char* path;
		WebRouteId route;
	};
	const Vector vectors[] = {
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
	Check(
		RegisteredExactWebRouteCount() ==
			sizeof(vectors) / sizeof(vectors[0]),
		"registered exact route count must match the characterized inventory");
	for (const Vector& vector : vectors)
		CheckRoute(vector.path, vector.route, "registered exact route must dispatch");

	CheckRoute(
		"/api/status?ignored=/api/future",
		WebRouteId::ApiStatus,
		"query text must not alter exact path dispatch");
	CheckRoute("/api/reach/status?x=1", WebRouteId::ApiReachStatus,
		"reach-status query must be ignored");
	const WebRouteMatch reachSuffix = ResolveWebRoute(
		WebRouteMethod::Get, "/api/reach/status/future");
	Check(reachSuffix.status == WebRouteStatus::NotFound &&
		reachSuffix.handler == WebHandler::None,
		"reach-status path suffix must fail closed");
}

void TestDynamicRoutes()
{
	using namespace ese::web;
	const char* hash = "0123456789abcdef0123456789ABCDEF";
	CheckRoute(
		"/live/0123456789abcdef0123456789ABCDEF",
		WebRouteId::LivePlayer,
		"exact hex player path must dispatch");
	CheckRoute(
		"/api/live/0123456789abcdef0123456789ABCDEF/stream.m3u8",
		WebRouteId::ApiLiveStream,
		"canonical stream playlist must dispatch");
	CheckRoute(
		"/api/live/0123456789abcdef0123456789ABCDEF/stream_0.m3u8",
		WebRouteId::ApiLiveStream,
		"first ABR rendition playlist must dispatch");
	CheckRoute(
		"/api/live/0123456789abcdef0123456789ABCDEF/stream_4.m3u8",
		WebRouteId::ApiLiveStream,
		"highest runtime ABR rendition playlist must dispatch");
	CheckRoute(
		"/api/live/0123456789abcdef0123456789ABCDEF/seg_00042.ts",
		WebRouteId::ApiLiveStream,
		"canonical segment must dispatch");
	CheckRoute(
		"/api/live/0123456789abcdef0123456789ABCDEF/seg_4_00042.ts",
		WebRouteId::ApiLiveStream,
		"canonical ABR segment must dispatch");
	CheckRoute("/hls/stream.m3u8", WebRouteId::LegacyHls,
		"legacy playlist must dispatch");
	CheckRoute("/hls/seg_1.TS", WebRouteId::LegacyHls,
		"legacy segment extension remains case-insensitive");
	CheckRoute("/style.css?v=1", WebRouteId::StaticAsset,
		"static cache-busting query must preserve canonical path");

	const WebRouteMatch prefixed = ResolveWebRoute(
		WebRouteMethod::Get,
		std::string("/s/2147483647/api/live/") + hash + "/stream.m3u8?x=1");
	Check(
		prefixed.status == WebRouteStatus::NotFound &&
		prefixed.handler == WebHandler::None,
		"numeric session locator must never authorize an HLS resource");

	const std::string token(64, 'a');
	const std::string stream(32, 'b');
	const std::string capability =
		"/h/" + token + "/7/" + stream + "/stream.m3u8";
	const WebRouteMatch capabilityRoute = ResolveWebRoute(
		WebRouteMethod::Get, capability);
	WebHlsCapabilityPath parsed;
	Check(
		capabilityRoute.status == WebRouteStatus::Matched &&
		capabilityRoute.route == WebRouteId::ApiLiveStream &&
		capabilityRoute.handler == WebHandler::LiveApi &&
		capabilityRoute.hls_capability_prefixed &&
		capabilityRoute.canonical_path ==
			"/api/live/" + stream + "/stream.m3u8" &&
		ParseWebHlsCapabilityPath(capability, parsed) &&
		parsed.token == token && parsed.generation == 7 &&
		parsed.stream_hash == stream && parsed.resource == "stream.m3u8",
		"canonical HLS capability must preserve every scope component");
	Check(
		ResolveWebRoute(WebRouteMethod::Options, capability).status ==
			WebRouteStatus::MethodNotAllowed,
		"HLS capabilities must not expose a CORS preflight route");
	for (const std::string& resource : {
			std::string("stream_0.m3u8"), std::string("stream_4.m3u8"),
			std::string("seg_00000.ts"), std::string("seg_4294967295.ts"),
			std::string("seg_0_00001.ts"),
			std::string("seg_4_4294967295.ts")}) {
		const std::string target =
			"/h/" + token + "/7/" + stream + "/" + resource;
		WebHlsCapabilityPath abr;
		Check(
			ResolveWebRoute(WebRouteMethod::Get, target).status ==
				WebRouteStatus::Matched &&
			ParseWebHlsCapabilityPath(target, abr) && abr.resource == resource,
			"runtime ABR HLS capability output must dispatch");
	}
}

void TestMethods()
{
	using namespace ese::web;
	Check(
		ResolveWebRoute(WebRouteMethod::Get, "/").handler == WebHandler::ClassicPage,
		"GET root must dispatch to classic page");
	Check(
		ResolveWebRoute(WebRouteMethod::Post, "/").handler == WebHandler::ClassicPage,
		"POST root must preserve classic form compatibility");
	Check(
		ResolveWebRoute(WebRouteMethod::Options, "/api/status").handler ==
			WebHandler::CorsPreflight,
		"OPTIONS known API must dispatch to constrained preflight");
	for (const WebRouteMethod method : {
		WebRouteMethod::Post, WebRouteMethod::Options}) {
		const WebRouteMatch match = ResolveWebRoute(method, "/style.css");
		Check(
			match.status == WebRouteStatus::MethodNotAllowed &&
			match.handler == WebHandler::None,
			"unsupported static method must fail closed");
	}
	Check(
		ResolveWebRoute(WebRouteMethod::Post, "/api/status").status ==
			WebRouteStatus::MethodNotAllowed,
		"POST API method must fail closed");
	Check(
		ResolveWebRoute(WebRouteMethod::Options, "/").status ==
			WebRouteStatus::MethodNotAllowed,
		"OPTIONS classic page must fail closed");
}

void TestHostileRoutes()
{
	using namespace ese::web;
	const char* rejected[] = {
		"",
		"api/status",
		"/api",
		"/api/",
		"/api/future/operator",
		"/api/status/",
		"/api/statusXYZ",
		"/api/live/joined",
		"/api/relay/",
		"/api/relay/unknown",
		"/api/keepalive/",
		"/api/keepalive/restart",
		"/api/live/privacy/future",
		"/dashboard/extra",
		"/live/not-a-hash",
		"/live/0123456789abcdef0123456789ABCDEF/extra",
		"/api/live/0123456789abcdef0123456789ABCDEG/stream.m3u8",
		"/api/live/0123456789abcdef0123456789ABCDEF/../secret.ts",
		"/api/live/0123456789abcdef0123456789ABCDEF/bad.exe",
		"/api/live/0123456789abcdef0123456789ABCDEF/stream_eng.M3U8",
		"/api/live/0123456789abcdef0123456789ABCDEF/seg_1.TS",
		"/hls/",
		"/hls/../secret.ts",
		"/hls/sub/seg_1.ts",
		"/s/0/api/status",
		"/s/-1/api/status",
		"/s/+1/api/status",
		"/s/1x/api/status",
		"/s/2147483648/api/status",
		"/s/999999999999999999999999999999999999999/api/status",
		"/s/1/api/future",
		"/s/1/style.css",
		"/style.css:secret.css",
		"/style%2ecss",
		"/api/status#fragment",
		"/%61pi/status",
		"/anything"
	};
	for (const char* target : rejected) {
		const WebRouteMatch match =
			ResolveWebRoute(WebRouteMethod::Get, target);
		if (match.status != WebRouteStatus::NotFound ||
			match.handler != WebHandler::None) {
			std::fprintf(
				stderr,
				"FAIL: unknown or hostile route must fail closed: %s\n",
				target);
			++failures;
		}
	}

	const std::string token(64, 'a');
	const std::string stream(32, 'b');
	const std::string prefix = "/h/" + token + "/";
	const std::string validTail = "/" + stream + "/stream.m3u8";
	const std::string hostileCapabilities[] = {
		"/h/" + std::string(63, 'a') + "/1" + validTail,
		"/h/" + std::string(65, 'a') + "/1" + validTail,
		"/h/" + std::string(63, 'a') + "A/1" + validTail,
		prefix + "0" + validTail,
		prefix + "00" + validTail,
		prefix + "01" + validTail,
		prefix + "+1" + validTail,
		prefix + "-1" + validTail,
		prefix + "18446744073709551616" + validTail,
		prefix + "1/" + std::string(31, 'b') + "/stream.m3u8",
		prefix + "1/" + std::string(33, 'b') + "/stream.m3u8",
		prefix + "1/" + std::string(31, 'b') + "B/stream.m3u8",
		prefix + "1/" + stream + "/stream.M3U8",
		prefix + "1/" + stream + "/seg_1.TS",
		prefix + "1/" + stream + "/stream_.m3u8",
		prefix + "1/" + stream + "/stream_5.m3u8",
		prefix + "1/" + stream + "/stream_00.m3u8",
		prefix + "1/" + stream + "/stream_eng.m3u8",
		prefix + "1/" + stream + "/seg_.ts",
		prefix + "1/" + stream + "/seg_0001.ts",
		prefix + "1/" + stream + "/seg_00000000000.ts",
		prefix + "1/" + stream + "/seg_4294967296.ts",
		prefix + "1/" + stream + "/seg_secret.ts",
		prefix + "1/" + stream + "/seg_5_00001.ts",
		prefix + "1/" + stream + "/seg_0_.ts",
		prefix + "1/" + stream + "/seg_0_0001.ts",
		prefix + "1/" + stream + "/seg_0_4294967296.ts",
		prefix + "1/" + stream + "/seg_0_00001_extra.ts",
		prefix + "1/" + stream + "/../stream.m3u8",
		prefix + "1/" + stream + "/sub/stream.m3u8",
		prefix + "1/" + stream + "/stream.m3u8/extra",
		prefix + "1/" + stream + "/stream.m3u8?range=1",
		prefix + "1/" + stream + "/stream.m3u8#fragment",
		prefix + "1/" + stream + "/stream%2em3u8",
		prefix + "1/" + stream + "/stream%252em3u8",
		prefix + "1/" + stream + "/stream.m3u8:secret.css",
		prefix + "1/" + stream + "//stream.m3u8"
	};
	for (const std::string& target : hostileCapabilities) {
		WebHlsCapabilityPath parsed;
		const WebRouteMatch match = ResolveWebRoute(WebRouteMethod::Get, target);
		if (match.status != WebRouteStatus::NotFound ||
			match.handler != WebHandler::None ||
			ParseWebHlsCapabilityPath(target, parsed)) {
			std::fprintf(
				stderr,
				"FAIL: hostile HLS capability must fail closed: %s\n",
				target.c_str());
			++failures;
		}
	}
}

} // namespace

int main()
{
	TestExactRoutes();
	TestDynamicRoutes();
	TestMethods();
	TestHostileRoutes();
	std::string selfTestFailure;
	Check(
		ese::web::RunWebRouteTableSelfTest(selfTestFailure),
		"production WebRouteTable self-test must pass");
	if (failures != 0) {
		std::fprintf(stderr, "%d WebRouteTable test(s) failed.\n", failures);
		return 1;
	}
	std::puts("WebRouteTable tests passed.");
	return 0;
}
