#include "../WebAuthPolicy.h"

#include <atomic>
#include <cstdio>
#include <string>
#include <thread>
#include <vector>

namespace {

std::atomic<int> failures{0};

void Check(bool condition, const char* message)
{
	if (!condition) {
		std::fprintf(stderr, "FAIL: %s\n", message);
		++failures;
	}
}

std::string Token(char value)
{
	return std::string(ese::web::WebAuthPolicy::kCsrfTokenHexLength, value);
}

std::string Stream(char value)
{
	return std::string(ese::web::WebAuthPolicy::kStreamKeyHexLength, value);
}

std::string IndexedToken(unsigned value)
{
	static const char hex[] = "0123456789abcdef";
	std::string token = Token('0');
	token[0] = hex[(value >> 4) & 0x0fu];
	token[1] = hex[value & 0x0fu];
	return token;
}

void TestSessions()
{
	using namespace ese::web;
	WebAuthPolicy policy;
	Check(!policy.AddSession(0, WebRole::Admin, 1, 100, Token('a')),
		"zero session ID must fail closed");
	Check(!policy.AddSession(1, WebRole::None, 1, 100, Token('a')),
		"unauthenticated session role must fail closed");
	Check(!policy.AddSession(1, WebRole::Admin, 1, 100, "short"),
		"invalid CSRF token must fail closed");
	Check(policy.AddSession(1, WebRole::Admin, -2, 100, Token('a')),
		"valid admin session must be added");
	Check(!policy.AddSession(1, WebRole::Guest, 7, 101, Token('b')),
		"duplicate session ID must fail closed");

	WebSessionSnapshot snapshot;
	Check(policy.TouchSession(1, 400, 300, &snapshot),
		"session must remain valid at exact timeout boundary");
	Check(snapshot.role == WebRole::Admin && snapshot.last_category == -2,
		"session snapshot must preserve role and category");
	Check(WebAuthPolicy::ValidateCsrf(snapshot, Token('a')),
		"matching CSRF token must pass");
	Check(!WebAuthPolicy::ValidateCsrf(snapshot, Token('b')),
		"mismatched CSRF token must fail");
	Check(!WebAuthPolicy::ValidateCsrf(snapshot, "short"),
		"malformed CSRF token must fail");
	Check(WebAuthPolicy::ValidateCsrfRequest(snapshot, "", "same-origin"),
		"same-origin request may use the legacy explicit session credential");
	Check(WebAuthPolicy::ValidateCsrfRequest(snapshot, "", "same-site"),
		"same-site request may use the legacy explicit session credential");
	Check(WebAuthPolicy::ValidateCsrfRequest(snapshot, "", ""),
		"non-browser client without fetch metadata must remain compatible");
	Check(!WebAuthPolicy::ValidateCsrfRequest(snapshot, "", "cross-site"),
		"cross-site credentialed request without CSRF token must fail");
	Check(WebAuthPolicy::ValidateCsrfRequest(snapshot, Token('a'), "cross-site"),
		"cross-site request with the exact CSRF token must pass");
	Check(!WebAuthPolicy::ValidateCsrfRequest(snapshot, Token('b'), "same-origin"),
		"supplied but incorrect CSRF token must always fail");
	Check(!policy.TouchSession(1, 701, 300),
		"expired session must fail and be removed");
	Check(policy.SessionCount() == 0, "expired session must not remain stored");

	Check(policy.AddSession(2, WebRole::Guest, 4, 1000, Token('b')),
		"guest session must be added");
	int category = 0;
	Check(policy.GetLastCategory(2, category, 1001, 300) && category == 4,
		"category lookup must touch a valid session");
	Check(policy.SetLastCategory(2, 9, 1002, 300),
		"category update must touch a valid session");
	Check(policy.GetLastCategory(2, category, 1003, 300) && category == 9,
		"category update must be observable");
	Check(policy.RemoveSession(2), "session removal must succeed once");
	Check(!policy.RemoveSession(2), "session removal must be idempotent");
	Check(!policy.GetSession(2, snapshot), "removed session must not be readable");

	Check(WebAuthPolicy::HasPermission(WebRole::Admin, WebRole::Admin),
		"admin must have admin permission");
	Check(WebAuthPolicy::HasPermission(WebRole::Admin, WebRole::Guest),
		"admin must inherit guest permission");
	Check(WebAuthPolicy::HasPermission(WebRole::Guest, WebRole::Guest),
		"guest must have guest permission");
	Check(!WebAuthPolicy::HasPermission(WebRole::Guest, WebRole::Admin),
		"guest must not have admin permission");
	Check(
		WebAuthPolicy::RequiredRoleForLivePath("/api/status") == WebRole::Guest &&
		WebAuthPolicy::RequiredRoleForLivePath("/api/live/join?key=x") == WebRole::Guest &&
		WebAuthPolicy::RequiredRoleForLivePath("/hls/stream.m3u8") == WebRole::Guest,
		"viewer and read-only paths must remain guest-accessible");
	for (const char* path : {
		"/api/debug/source-resolutions",
		"/api/ese/v9?on=1",
		"/api/holepunch/test",
		"/api/keepalive/start",
		"/api/krp/status",
		"/api/reach/status",
		"/api/network/connect",
		"/api/relay/accept?on=1",
		"/api/live/broadcast/start",
		"/api/live/log",
		"/api/live/preflight",
		"/api/live/privacy/subscriptions?add=x",
		"/api/live/privacy/kad6/release?on=1",
		"/api/live/privacy/kad6/hardening?on=1",
		"/api/live/reachability/fire",
		"/api/live/test/edge_sabotage?on=1",
		"/api/future/operator"
	}) {
		Check(
			WebAuthPolicy::RequiredRoleForLivePath(path) == WebRole::Admin,
			"operator and sensitive paths must require admin");
	}
	for (const char* path : {
		"/api/live/join?key=x",
		"/api/live/leave?key=x",
		"/api/live/player-alive?key=x",
		"/api/relay/accept?on=1",
		"/api/ese/v9?on=1",
		"/api/live/privacy/subscriptions?add=x",
		"/api/live/privacy/kad6/release?on=1",
		"/api/live/privacy/kad6/hardening?on=1",
		"/api/live/broadcast/start",
		"/api/live/reachability/fire",
		"/api/network/connect",
		"/api/keepalive/start",
		"/api/holepunch/test",
		"/api/live/test/edge_sabotage?on=1",
		"/api/future/operator"
	}) {
		Check(WebAuthPolicy::IsLivePathStateChanging(path),
			"viewer mutations, operator routes and unknown APIs must be state-changing");
	}
	for (const char* path : {
		"/api/status",
		"/api/reach/status",
		"/api/live/metrics",
		"/api/live/channels",
		"/api/live/mesh",
		"/api/live/kad/streams",
		"/api/live/0123456789abcdef0123456789ABCDEF/stream.m3u8",
		"/hls/stream.m3u8"
	}) {
		Check(!WebAuthPolicy::IsLivePathStateChanging(path),
			"explicit viewer read paths must remain read-only");
	}
	for (const char* authority : {
		"localhost", "LOCALHOST:4711", "127.0.0.1:80", "[::1]:4711"
	}) {
		Check(WebAuthPolicy::IsLocalWebAuthority(authority),
			"literal loopback web authority must be accepted");
	}
	for (const char* authority : {
		"", "evil.example", "evil.example:4711", "127.0.0.1.evil.example",
		"127.0.0.1:bad", "[::1", "[::2]:4711"
	}) {
		Check(!WebAuthPolicy::IsLocalWebAuthority(authority),
			"non-local or malformed web authority must fail closed");
	}
	Check(WebAuthPolicy::IsLocalWebOrigin("http://localhost:4711"),
		"local HTTP origin must be accepted");
	Check(WebAuthPolicy::IsLocalWebOrigin("https://[::1]:4711/"),
		"local HTTPS origin must be accepted");
	Check(!WebAuthPolicy::IsLocalWebOrigin("http://evil.example"),
		"foreign origin must be rejected");
	Check(!WebAuthPolicy::IsLocalWebOrigin("null"),
		"opaque origin must be rejected");
	Check(WebAuthPolicy::AuthorizeLiveRequest(
		"/api/live/join", true, nullptr, "", "same-origin",
		"localhost:4711", "http://localhost:4711"),
		"same-origin literal loopback viewer mutation must pass");
	Check(!WebAuthPolicy::AuthorizeLiveRequest(
		"/api/live/join", true, nullptr, "", "same-origin",
		"evil.example:4711", "http://evil.example:4711"),
		"DNS-rebound same-origin loopback mutation must fail");
	Check(!WebAuthPolicy::AuthorizeLiveRequest(
		"/api/live/join", true, nullptr, "", "cross-site",
		"localhost:4711", ""),
		"cross-site loopback mutation must fail");
	Check(!WebAuthPolicy::AuthorizeLiveRequest(
		"/api/live/join", false, &snapshot, "", "same-origin", "", ""),
		"browser session mutation without exact CSRF token must fail");
	Check(WebAuthPolicy::AuthorizeLiveRequest(
		"/api/live/join", false, &snapshot, Token('a'), "same-origin", "", ""),
		"browser session mutation with exact CSRF token must pass");
	Check(WebAuthPolicy::AuthorizeLiveRequest(
		"/api/live/join", false, &snapshot, "", "", "", ""),
		"non-browser session automation must remain compatible");
	Check(!WebAuthPolicy::AuthorizeLiveRequest(
		"/api/status", true, nullptr, "", "same-origin",
		"evil.example:4711", "http://evil.example:4711"),
		"DNS-rebound same-origin read request must fail");
	Check(WebAuthPolicy::AuthorizeLiveRequest(
		"/api/status", true, nullptr, "", "same-origin",
		"localhost:4711", "http://localhost:4711"),
		"same-origin literal loopback read request must pass");
	Check(WebAuthPolicy::AuthorizeLiveRequest(
		"/api/status", false, &snapshot, "", "same-origin", "", ""),
		"authenticated remote read request must pass without mutation CSRF");
}

void TestBrowserSessionBearer()
{
	using namespace ese::web;
	WebAuthPolicy policy;
	const std::string browserDigest = Token('b');
	Check(policy.AddSession(
		90, WebRole::Guest, 0, 10, Token('a'), browserDigest),
		"browser session digest must be stored with its session");
	Check(!policy.AddSession(
		91, WebRole::Guest, 0, 10, Token('c'), browserDigest),
		"browser session digests must be unique");
	WebSessionSnapshot snapshot;
	Check(!policy.ResolveBrowserSessionDigest(
		Token('c'), 20, 100, &snapshot),
		"wrong browser bearer digest must fail");
	Check(!policy.ResolveBrowserSessionDigest(
		browserDigest, 20, 100, &snapshot, 91),
		"numeric locator must match the cookie-owned session");
	Check(policy.GetSession(90, snapshot) && snapshot.last_seen_ms == 10,
		"failed bearer lookup must not keep the session alive");
	Check(policy.ResolveBrowserSessionDigest(
		browserDigest, 20, 100, &snapshot, 90) &&
		snapshot.id == 90 && snapshot.last_seen_ms == 20,
		"matching cookie digest and locator must resolve together");
	Check(policy.ResolveBrowserSessionDigest(
		browserDigest, 120, 100, &snapshot, 90),
		"browser session remains valid at exact timeout boundary");
	Check(!policy.ResolveBrowserSessionDigest(
		browserDigest, 221, 100, &snapshot, 90) &&
		policy.SessionCount() == 0,
		"browser session expires immediately after the timeout boundary");
}

void TestHlsCapabilities()
{
	using namespace ese::web;
	const std::string csrf = Token('a');
	const std::string streamA = Stream('1');
	const std::string streamB = Stream('2');
	WebAuthPolicy policy;
	Check(policy.AddSession(10, WebRole::Guest, 0, 100, csrf, Token('b')),
		"capability owner session must be added");
	WebHlsCapabilitySnapshot capability;
	Check(!policy.IssueHlsReadCapability(
		99, streamA, WebHlsSourceRole::Viewer, 7, Token('c'),
		100, 1000, capability),
		"capability cannot bind to a missing owner");
	Check(!policy.IssueHlsReadCapability(
		10, Stream('A'), WebHlsSourceRole::Viewer, 7, Token('c'),
		100, 1000, capability),
		"capability stream key must be canonical lowercase hex");
	Check(!policy.IssueHlsReadCapability(
		10, streamA, WebHlsSourceRole::Viewer, 0, Token('c'),
		100, 1000, capability),
		"capability cannot bind generation zero");
	Check(!policy.IssueHlsReadCapability(
		10, streamA, static_cast<WebHlsSourceRole>(9), 7, Token('c'),
		100, 1000, capability),
		"capability cannot bind an unknown source role");
	Check(policy.IssueHlsReadCapability(
		10, streamA, WebHlsSourceRole::Viewer, 7, Token('c'),
		100, 1000, capability) &&
		capability.token_digest == Token('c') &&
		capability.stream_key == streamA &&
		capability.owner_session_id == 10 &&
		capability.generation == 7 &&
		capability.scope == WebCapabilityScope::HlsRead &&
		capability.source_role == WebHlsSourceRole::Viewer,
		"issued capability snapshot must preserve the full scope binding");
	Check(!policy.InspectHlsReadCapability(
		Token('d'), 7, streamA, 110, 1000),
		"wrong capability digest must fail Inspect");
	Check(!policy.InspectHlsReadCapability(
		Token('c'), 8, streamA, 110, 1000),
		"wrong path generation must fail Inspect");
	Check(!policy.InspectHlsReadCapability(
		Token('c'), 7, streamB, 110, 1000),
		"wrong path stream must fail Inspect");
	WebSessionSnapshot owner;
	Check(policy.GetSession(10, owner) && owner.last_seen_ms == 100,
		"invalid capability probes must not touch their owner");
	Check(policy.InspectHlsReadCapability(
		Token('c'), 7, streamA, 110, 1000),
		"matching capability must pass Inspect");
	Check(policy.GetSession(10, owner) && owner.last_seen_ms == 100,
		"Inspect must not refresh the owner session");
	Check(policy.CommitHlsReadCapability(
		Token('c'), streamA, WebHlsSourceRole::Viewer, 7,
		200, 1000),
		"matching live role and generation must Commit");
	Check(policy.GetSession(10, owner) && owner.last_seen_ms == 200,
		"Commit keeps the owning browser session alive");

	Check(policy.IssueHlsReadCapability(
		10, streamA, WebHlsSourceRole::Viewer, 7, Token('d'),
		201, 1000, capability),
		"role mismatch vector capability must issue");
	Check(!policy.CommitHlsReadCapability(
		Token('d'), streamA, WebHlsSourceRole::Broadcast, 7,
		202, 1000) && policy.HlsCapabilityCount() == 1,
		"authoritative role mismatch must revoke only the stale capability");
	Check(policy.IssueHlsReadCapability(
		10, streamA, WebHlsSourceRole::Viewer, 7, Token('e'),
		203, 1000, capability),
		"generation rollover vector capability must issue");
	Check(!policy.CommitHlsReadCapability(
		Token('e'), streamA, WebHlsSourceRole::Viewer, 8,
		204, 1000) && policy.HlsCapabilityCount() == 1,
		"generation rollover must permanently revoke the stale capability");

	Check(policy.IssueHlsReadCapability(
		10, streamB, WebHlsSourceRole::Broadcast, 9, Token('f'),
		300, 0, capability),
		"absolute TTL vector capability must issue");
	Check(policy.InspectHlsReadCapability(
		Token('f'), 9, streamB,
		300 + WebAuthPolicy::kHlsCapabilityLifetimeMs - 1, 0),
		"capability remains valid one tick before absolute TTL");
	Check(!policy.InspectHlsReadCapability(
		Token('f'), 9, streamB,
		300 + WebAuthPolicy::kHlsCapabilityLifetimeMs, 0),
		"capability expires at the exact absolute TTL boundary");

	WebAuthPolicy paused;
	Check(paused.AddSession(20, WebRole::Guest, 0, 100, csrf, Token('1')) &&
		paused.IssueHlsReadCapability(
			20, streamA, WebHlsSourceRole::Viewer, 1, Token('2'),
			100, 300, capability),
		"paused-owner vector must initialize");
	Check(paused.InspectHlsReadCapability(
		Token('2'), 1, streamA, 400, 300),
		"owner remains valid at exact browser timeout");
	Check(paused.GetSession(20, owner) && owner.last_seen_ms == 100,
		"capability Inspect cannot mask a paused browser");
	Check(!paused.InspectHlsReadCapability(
		Token('2'), 1, streamA, 401, 300) &&
		paused.SessionCount() == 0 && paused.HlsCapabilityCount() == 0,
		"paused browser expiry revokes all owned capabilities");

	WebAuthPolicy logout;
	Check(logout.AddSession(30, WebRole::Guest, 0, 10, csrf, Token('3')) &&
		logout.AddSession(31, WebRole::Guest, 0, 10, Token('4'), Token('5')) &&
		logout.IssueHlsReadCapability(
			30, streamA, WebHlsSourceRole::Viewer, 1, Token('6'),
			10, 1000, capability) &&
		logout.IssueHlsReadCapability(
			31, streamB, WebHlsSourceRole::Broadcast, 1, Token('7'),
			10, 1000, capability),
		"logout revocation vectors must initialize");
	Check(logout.RemoveSession(30) && logout.HlsCapabilityCount() == 1 &&
		!logout.InspectHlsReadCapability(
			Token('6'), 1, streamA, 11, 1000) &&
		logout.InspectHlsReadCapability(
			Token('7'), 1, streamB, 11, 1000),
		"logout revokes only capabilities owned by that session");
	logout.RevokeAllHlsCapabilities();
	Check(logout.HlsCapabilityCount() == 0,
		"server restart revocation clears every capability");

	WebAuthPolicy bounded;
	Check(bounded.AddSession(40, WebRole::Guest, 0, 10, csrf, Token('8')),
		"bounded capability owner must initialize");
	for (unsigned index = 0;
		index < WebAuthPolicy::kMaxHlsCapabilitiesPerSession + 1; ++index) {
		Check(bounded.IssueHlsReadCapability(
			40, streamA, WebHlsSourceRole::Viewer, 1,
			IndexedToken(index + 16), 10 + index, 1000, capability),
			"bounded per-session capability insertion must succeed");
	}
	Check(bounded.HlsCapabilityCount() ==
		WebAuthPolicy::kMaxHlsCapabilitiesPerSession,
		"per-session capability store must remain bounded");
	Check(!bounded.InspectHlsReadCapability(
		IndexedToken(16), 1, streamA, 30, 1000),
		"per-session bound evicts the oldest capability");
}

void TestConcurrentCapabilities()
{
	using namespace ese::web;
	constexpr unsigned workerCount = 8;
	const std::string stream = Stream('a');
	WebHlsCapabilitySnapshot capability;
	WebAuthPolicy valid;
	Check(valid.AddSession(50, WebRole::Guest, 0, 10, Token('b'), Token('c')) &&
		valid.IssueHlsReadCapability(
			50, stream, WebHlsSourceRole::Viewer, 5, Token('d'),
			10, 1000, capability),
		"concurrent valid capability vector must initialize");
	std::atomic<unsigned> validCommits{0};
	std::vector<std::thread> workers;
	for (unsigned index = 0; index < workerCount; ++index) {
		workers.emplace_back([&valid, &stream, &validCommits]() {
			if (valid.InspectHlsReadCapability(
					Token('d'), 5, stream, 20, 1000) &&
				valid.CommitHlsReadCapability(
					Token('d'), stream, WebHlsSourceRole::Viewer, 5,
					20, 1000))
				++validCommits;
		});
	}
	for (std::thread& worker : workers)
		worker.join();
	Check(validCommits == workerCount,
		"at least eight concurrent valid GET authorizations must serialize safely");

	WebAuthPolicy raced;
	Check(raced.AddSession(60, WebRole::Guest, 0, 10, Token('e'), Token('f')) &&
		raced.IssueHlsReadCapability(
			60, stream, WebHlsSourceRole::Viewer, 6, Token('1'),
			10, 1000, capability),
		"logout race capability vector must initialize");
	std::atomic<unsigned> ready{0};
	std::atomic<unsigned> inspections{0};
	std::atomic<unsigned> commitsAfterLogout{0};
	std::atomic<bool> release{false};
	workers.clear();
	for (unsigned index = 0; index < workerCount; ++index) {
		workers.emplace_back([
			&raced, &stream, &ready, &inspections,
			&commitsAfterLogout, &release]() {
			if (raced.InspectHlsReadCapability(
				Token('1'), 6, stream, 20, 1000))
				++inspections;
			++ready;
			while (!release.load())
				std::this_thread::yield();
			if (raced.CommitHlsReadCapability(
				Token('1'), stream, WebHlsSourceRole::Viewer, 6,
				21, 1000))
				++commitsAfterLogout;
		});
	}
	while (ready.load() != workerCount)
		std::this_thread::yield();
	Check(raced.RemoveSession(60),
		"logout must linearize after all capability inspections");
	release = true;
	for (std::thread& worker : workers)
		worker.join();
	Check(inspections == workerCount && commitsAfterLogout == 0 &&
		raced.HlsCapabilityCount() == 0,
		"logout wins every Inspect/Commit race before file authorization");
}

void TestChallenges()
{
	using namespace ese::web;
	WebAuthPolicy policy;
	const std::string nonce = Token('c');
	Check(!policy.AddChallenge("invalid", 7, 100),
		"malformed challenge must fail closed");
	Check(policy.AddChallenge(nonce, 7, 100),
		"valid challenge must be accepted");
	Check(!policy.ConsumeChallenge(nonce, 8, 101),
		"challenge must remain bound to its client IP");
	Check(policy.ConsumeChallenge(nonce, 7, 101),
		"matching challenge must be consumed");
	Check(!policy.ConsumeChallenge(nonce, 7, 102),
		"challenge replay must fail");

	Check(policy.AddChallenge(nonce, 7, 200),
		"fresh challenge must be accepted");
	Check(!policy.ConsumeChallenge(nonce, 7, 300200),
		"challenge must expire at the exact lifetime boundary");
	Check(policy.AddChallenge(nonce, 7, 400),
		"challenge may be issued again after consumption");
	Check(!policy.ConsumeChallenge(nonce, 7, 300401),
		"expired challenge must fail");

	for (std::size_t index = 0;
		index < WebAuthPolicy::kMaxPendingChallenges + 5; ++index) {
		std::string unique = Token('0');
		const char hex[] = "0123456789abcdef";
		unique[0] = hex[(index >> 4) & 0xF];
		unique[1] = hex[index & 0xF];
		Check(policy.AddChallenge(unique, 9, 500 + index),
			"bounded challenge insertion must succeed");
	}
	Check(policy.PendingChallengeCount() == WebAuthPolicy::kMaxPendingChallenges,
		"pending challenge store must remain bounded");
}

void TestLoginFailures()
{
	using namespace ese::web;
	WebAuthPolicy policy;
	const std::uint32_t ip = 42;
	for (std::size_t attempt = 0;
		attempt < WebAuthPolicy::kMaxLoginFailuresPerIp; ++attempt) {
		Check(!policy.IsLoginBlocked(ip, 100 + attempt),
			"client must not be blocked before fifth failure is recorded");
		policy.RecordLoginFailure(ip, 100 + attempt);
	}
	Check(policy.IsLoginBlocked(ip, 200),
		"fifth failure must block the client");
	Check(!policy.IsLoginBlocked(ip + 1, 200),
		"login failures must be isolated by client IP");
	policy.RecordLoginSuccess(ip);
	Check(!policy.IsLoginBlocked(ip, 201),
		"successful login must clear failures for that IP");

	for (std::size_t attempt = 0;
		attempt < WebAuthPolicy::kMaxLoginFailuresPerIp; ++attempt)
		policy.RecordLoginFailure(ip, 1000 + attempt);
	Check(!policy.IsLoginBlocked(
		ip, 1004 + WebAuthPolicy::kLoginFailureWindowMs + 1),
		"failures must expire after the login window");
}

void TestActionLimits()
{
	using namespace ese::web;
	WebAuthPolicy policy;
	WebRateDecision decision =
		policy.CheckRateLimit(WebAction::NetworkConnect, 0, 2000);
	Check(decision.allowed && decision.retry_after_ms == 0,
		"first action must be allowed even at tick zero");
	decision = policy.CheckRateLimit(WebAction::NetworkConnect, 500, 2000);
	Check(!decision.allowed && decision.retry_after_ms == 1500,
		"early repeat must return an exact retry interval");
	decision = policy.CheckRateLimit(WebAction::NetworkConnect, 2000, 2000);
	Check(decision.allowed, "action must pass at exact interval boundary");
	decision = policy.CheckRateLimit(WebAction::ManualHolePunch, 1, 5000);
	Check(decision.allowed, "different actions must have isolated clocks");
	decision = policy.CheckRateLimit(WebAction::Count, 1, 5000);
	Check(!decision.allowed, "invalid action must fail closed");
	decision = policy.CheckRateLimit(WebAction::ManualRendezvous, 1, 0);
	Check(!decision.allowed, "zero rate interval must fail closed");
}

void TestConcurrentSessions()
{
	using namespace ese::web;
	WebAuthPolicy policy;
	constexpr std::uint32_t threadCount = 8;
	constexpr std::uint32_t sessionsPerThread = 100;
	std::vector<std::thread> workers;
	for (std::uint32_t worker = 0; worker < threadCount; ++worker) {
		workers.emplace_back([worker, &policy, sessionsPerThread]() {
			for (std::uint32_t index = 1; index <= sessionsPerThread; ++index) {
				const std::uint32_t id = worker * sessionsPerThread + index;
				Check(policy.AddSession(
					id, WebRole::Guest, 0, 10, Token('d')),
					"concurrent unique session insertion must succeed");
				Check(policy.TouchSession(id, 11, 1000),
					"concurrent session touch must succeed");
			}
		});
	}
	for (std::thread& worker : workers)
		worker.join();
	Check(
		policy.SessionCount() ==
			static_cast<std::size_t>(threadCount * sessionsPerThread),
		"concurrent session store must retain every unique session");
}

} // namespace

int main()
{
	TestSessions();
	TestBrowserSessionBearer();
	TestHlsCapabilities();
	TestChallenges();
	TestLoginFailures();
	TestActionLimits();
	TestConcurrentSessions();
	TestConcurrentCapabilities();
	std::string selfTestFailure;
	Check(ese::web::RunWebAuthPolicySelfTest(selfTestFailure),
		"production WebAuthPolicy self-test must pass");
	if (failures.load() != 0) {
		std::fprintf(
			stderr, "%d WebAuthPolicy test(s) failed.\n", failures.load());
		return 1;
	}
	std::puts("WebAuthPolicy tests passed.");
	return 0;
}
