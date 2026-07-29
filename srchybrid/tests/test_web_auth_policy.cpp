#include "../WebAuthPolicy.h"

#include <cstdio>
#include <string>
#include <thread>
#include <vector>

namespace {

int failures = 0;

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
	TestChallenges();
	TestLoginFailures();
	TestActionLimits();
	TestConcurrentSessions();
	std::string selfTestFailure;
	Check(ese::web::RunWebAuthPolicySelfTest(selfTestFailure),
		"production WebAuthPolicy self-test must pass");
	if (failures != 0) {
		std::fprintf(stderr, "%d WebAuthPolicy test(s) failed.\n", failures);
		return 1;
	}
	std::puts("WebAuthPolicy tests passed.");
	return 0;
}
