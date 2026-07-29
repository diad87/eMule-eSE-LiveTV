#include "WebAuthPolicy.h"

#include <algorithm>
#include <cctype>

namespace ese {
namespace web {

WebSessionSnapshot WebAuthPolicy::MakeSnapshot(const SessionRecord& record)
{
	WebSessionSnapshot snapshot;
	snapshot.id = record.id;
	snapshot.role = record.role;
	snapshot.last_category = record.last_category;
	snapshot.last_seen_ms = record.last_seen_ms;
	snapshot.csrf_token = record.csrf_token;
	return snapshot;
}

bool WebAuthPolicy::IsExpired(
	std::uint64_t nowMs,
	std::uint64_t thenMs,
	std::uint64_t lifetimeMs)
{
	return lifetimeMs != 0 && (nowMs < thenMs || nowMs - thenMs > lifetimeMs);
}

bool WebAuthPolicy::IsExpiredInclusive(
	std::uint64_t nowMs,
	std::uint64_t thenMs,
	std::uint64_t lifetimeMs)
{
	return lifetimeMs != 0 && (nowMs < thenMs || nowMs - thenMs >= lifetimeMs);
}

bool WebAuthPolicy::AddSession(
	std::uint32_t id,
	WebRole role,
	int lastCategory,
	std::uint64_t nowMs,
	const std::string& csrfToken)
{
	if (id == 0 || role == WebRole::None ||
		!IsValidHexToken(csrfToken, kCsrfTokenHexLength))
		return false;

	std::lock_guard<std::mutex> guard(m_mutex);
	const auto duplicate = std::find_if(
		m_sessions.begin(), m_sessions.end(),
		[id](const SessionRecord& record) { return record.id == id; });
	if (duplicate != m_sessions.end())
		return false;

	m_sessions.push_back({id, role, lastCategory, nowMs, csrfToken});
	return true;
}

bool WebAuthPolicy::TouchSession(
	std::uint32_t id,
	std::uint64_t nowMs,
	std::uint64_t timeoutMs,
	WebSessionSnapshot* snapshot)
{
	if (id == 0)
		return false;

	std::lock_guard<std::mutex> guard(m_mutex);
	for (auto it = m_sessions.begin(); it != m_sessions.end();) {
		if (IsExpired(nowMs, it->last_seen_ms, timeoutMs)) {
			it = m_sessions.erase(it);
			continue;
		}
		if (it->id == id) {
			it->last_seen_ms = nowMs;
			if (snapshot != nullptr)
				*snapshot = MakeSnapshot(*it);
			return true;
		}
		++it;
	}
	return false;
}

bool WebAuthPolicy::GetSession(
	std::uint32_t id,
	WebSessionSnapshot& snapshot) const
{
	if (id == 0)
		return false;

	std::lock_guard<std::mutex> guard(m_mutex);
	const auto found = std::find_if(
		m_sessions.begin(), m_sessions.end(),
		[id](const SessionRecord& record) { return record.id == id; });
	if (found == m_sessions.end())
		return false;
	snapshot = MakeSnapshot(*found);
	return true;
}

bool WebAuthPolicy::RemoveSession(std::uint32_t id)
{
	if (id == 0)
		return false;

	std::lock_guard<std::mutex> guard(m_mutex);
	const auto found = std::find_if(
		m_sessions.begin(), m_sessions.end(),
		[id](const SessionRecord& record) { return record.id == id; });
	if (found == m_sessions.end())
		return false;
	m_sessions.erase(found);
	return true;
}

std::size_t WebAuthPolicy::PurgeExpiredSessions(
	std::uint64_t nowMs,
	std::uint64_t timeoutMs)
{
	std::lock_guard<std::mutex> guard(m_mutex);
	const std::size_t before = m_sessions.size();
	m_sessions.erase(
		std::remove_if(
			m_sessions.begin(), m_sessions.end(),
			[nowMs, timeoutMs](const SessionRecord& record) {
				return IsExpired(nowMs, record.last_seen_ms, timeoutMs);
			}),
		m_sessions.end());
	return before - m_sessions.size();
}

std::size_t WebAuthPolicy::SessionCount() const
{
	std::lock_guard<std::mutex> guard(m_mutex);
	return m_sessions.size();
}

bool WebAuthPolicy::SetLastCategory(
	std::uint32_t id,
	int category,
	std::uint64_t nowMs,
	std::uint64_t timeoutMs)
{
	std::lock_guard<std::mutex> guard(m_mutex);
	for (auto it = m_sessions.begin(); it != m_sessions.end();) {
		if (IsExpired(nowMs, it->last_seen_ms, timeoutMs)) {
			it = m_sessions.erase(it);
			continue;
		}
		if (it->id == id && id != 0) {
			it->last_category = category;
			it->last_seen_ms = nowMs;
			return true;
		}
		++it;
	}
	return false;
}

bool WebAuthPolicy::GetLastCategory(
	std::uint32_t id,
	int& category,
	std::uint64_t nowMs,
	std::uint64_t timeoutMs)
{
	std::lock_guard<std::mutex> guard(m_mutex);
	for (auto it = m_sessions.begin(); it != m_sessions.end();) {
		if (IsExpired(nowMs, it->last_seen_ms, timeoutMs)) {
			it = m_sessions.erase(it);
			continue;
		}
		if (it->id == id && id != 0) {
			category = it->last_category;
			it->last_seen_ms = nowMs;
			return true;
		}
		++it;
	}
	return false;
}

void WebAuthPolicy::PurgeChallengesLocked(std::uint64_t nowMs)
{
	m_challenges.erase(
		std::remove_if(
			m_challenges.begin(), m_challenges.end(),
			[nowMs](const ChallengeRecord& record) {
				return IsExpiredInclusive(
					nowMs, record.issued_ms, kChallengeLifetimeMs);
			}),
		m_challenges.end());
}

bool WebAuthPolicy::AddChallenge(
	const std::string& nonce,
	std::uint32_t clientIp,
	std::uint64_t nowMs)
{
	if (!IsValidHexToken(nonce, kNonceHexLength))
		return false;

	std::lock_guard<std::mutex> guard(m_mutex);
	PurgeChallengesLocked(nowMs);
	m_challenges.erase(
		std::remove_if(
			m_challenges.begin(), m_challenges.end(),
			[&nonce, clientIp](const ChallengeRecord& record) {
				return record.nonce == nonce && record.client_ip == clientIp;
			}),
		m_challenges.end());
	m_challenges.push_back({nonce, clientIp, nowMs});
	while (m_challenges.size() > kMaxPendingChallenges)
		m_challenges.erase(m_challenges.begin());
	return true;
}

bool WebAuthPolicy::ConsumeChallenge(
	const std::string& nonce,
	std::uint32_t clientIp,
	std::uint64_t nowMs)
{
	if (!IsValidHexToken(nonce, kNonceHexLength))
		return false;

	std::lock_guard<std::mutex> guard(m_mutex);
	PurgeChallengesLocked(nowMs);
	const auto found = std::find_if(
		m_challenges.begin(), m_challenges.end(),
		[&nonce, clientIp](const ChallengeRecord& record) {
			return record.nonce == nonce && record.client_ip == clientIp;
		});
	if (found == m_challenges.end())
		return false;
	m_challenges.erase(found);
	return true;
}

std::size_t WebAuthPolicy::PendingChallengeCount() const
{
	std::lock_guard<std::mutex> guard(m_mutex);
	return m_challenges.size();
}

void WebAuthPolicy::PurgeLoginFailuresLocked(std::uint64_t nowMs)
{
	m_loginFailures.erase(
		std::remove_if(
			m_loginFailures.begin(), m_loginFailures.end(),
			[nowMs](const LoginFailureRecord& record) {
				return IsExpiredInclusive(
					nowMs, record.occurred_ms, kLoginFailureWindowMs);
			}),
		m_loginFailures.end());
}

std::size_t WebAuthPolicy::LoginFailureCount(
	std::uint32_t clientIp,
	std::uint64_t nowMs)
{
	std::lock_guard<std::mutex> guard(m_mutex);
	PurgeLoginFailuresLocked(nowMs);
	return static_cast<std::size_t>(std::count_if(
		m_loginFailures.begin(), m_loginFailures.end(),
		[clientIp](const LoginFailureRecord& record) {
			return record.client_ip == clientIp;
		}));
}

bool WebAuthPolicy::IsLoginBlocked(
	std::uint32_t clientIp,
	std::uint64_t nowMs)
{
	return LoginFailureCount(clientIp, nowMs) >= kMaxLoginFailuresPerIp;
}

void WebAuthPolicy::RecordLoginFailure(
	std::uint32_t clientIp,
	std::uint64_t nowMs)
{
	std::lock_guard<std::mutex> guard(m_mutex);
	PurgeLoginFailuresLocked(nowMs);
	m_loginFailures.push_back({clientIp, nowMs});
	while (m_loginFailures.size() > kMaxTrackedLoginFailures)
		m_loginFailures.erase(m_loginFailures.begin());
}

void WebAuthPolicy::RecordLoginSuccess(std::uint32_t clientIp)
{
	std::lock_guard<std::mutex> guard(m_mutex);
	m_loginFailures.erase(
		std::remove_if(
			m_loginFailures.begin(), m_loginFailures.end(),
			[clientIp](const LoginFailureRecord& record) {
				return record.client_ip == clientIp;
			}),
		m_loginFailures.end());
}

WebRateDecision WebAuthPolicy::CheckRateLimit(
	WebAction action,
	std::uint64_t nowMs,
	std::uint64_t intervalMs)
{
	const std::size_t index = static_cast<std::size_t>(action);
	if (index >= m_actionClocks.size() || intervalMs == 0)
		return {false, 0};

	std::lock_guard<std::mutex> guard(m_mutex);
	ActionClock& clock = m_actionClocks[index];
	if (!clock.initialized || nowMs < clock.last_allowed_ms ||
		nowMs - clock.last_allowed_ms >= intervalMs) {
		clock.initialized = true;
		clock.last_allowed_ms = nowMs;
		return {true, 0};
	}
	return {false, intervalMs - (nowMs - clock.last_allowed_ms)};
}

bool WebAuthPolicy::IsValidHexToken(
	const std::string& token,
	std::size_t length)
{
	if (token.size() != length)
		return false;
	for (const char value : token) {
		if (!((value >= '0' && value <= '9') ||
			(value >= 'a' && value <= 'f')))
			return false;
	}
	return true;
}

bool WebAuthPolicy::ConstantTimeEqual(
	const std::string& lhs,
	const std::string& rhs)
{
	const std::size_t maximum = lhs.size() > rhs.size() ? lhs.size() : rhs.size();
	std::size_t difference = lhs.size() ^ rhs.size();
	for (std::size_t index = 0; index < maximum; ++index) {
		const unsigned char left =
			index < lhs.size() ? static_cast<unsigned char>(lhs[index]) : 0;
		const unsigned char right =
			index < rhs.size() ? static_cast<unsigned char>(rhs[index]) : 0;
		difference |= static_cast<std::size_t>(left ^ right);
	}
	return difference == 0;
}

bool WebAuthPolicy::ValidateCsrf(
	const WebSessionSnapshot& session,
	const std::string& suppliedToken)
{
	return session.id != 0 &&
		IsValidHexToken(session.csrf_token, kCsrfTokenHexLength) &&
		IsValidHexToken(suppliedToken, kCsrfTokenHexLength) &&
		ConstantTimeEqual(session.csrf_token, suppliedToken);
}

bool WebAuthPolicy::ValidateCsrfRequest(
	const WebSessionSnapshot& session,
	const std::string& suppliedToken,
	const std::string& fetchSite)
{
	if (!suppliedToken.empty())
		return ValidateCsrf(session, suppliedToken);
	return fetchSite.empty() || fetchSite == "same-origin" ||
		fetchSite == "same-site" || fetchSite == "none";
}

bool WebAuthPolicy::HasPermission(WebRole role, WebRole required)
{
	if (required == WebRole::None)
		return true;
	if (required == WebRole::Guest)
		return role == WebRole::Guest || role == WebRole::Admin;
	return role == WebRole::Admin;
}

WebRole WebAuthPolicy::RequiredRoleForLivePath(const std::string& path)
{
	static const char* const guestPaths[] = {
		"/api/status",
		"/api/live/join",
		"/api/live/leave",
		"/api/live/player-alive",
		"/api/live/metrics",
		"/api/live/channels",
		"/api/live/mesh",
		"/api/live/kad/streams"
	};
	for (const char* const guestPath : guestPaths) {
		const std::size_t length = std::char_traits<char>::length(guestPath);
		if (path.compare(0, length, guestPath) == 0 &&
			(path.size() == length || path[length] == '?'))
			return WebRole::Guest;
	}
	if (path.compare(0, 10, "/api/live/") == 0 && path.size() >= 43) {
		bool hash = true;
		for (std::size_t index = 10; index < 42; ++index) {
			const char value = path[index];
			hash = hash &&
				((value >= '0' && value <= '9') ||
				 (value >= 'a' && value <= 'f') ||
				 (value >= 'A' && value <= 'F'));
		}
		if (hash && path[42] == '/')
			return WebRole::Guest;
	}
	// Fail closed for every API endpoint not explicitly classified as a
	// viewer/read-only route. This also protects future and test-only handlers.
	if (path.compare(0, 5, "/api/") == 0)
		return WebRole::Admin;
	return WebRole::Guest;
}

bool WebAuthPolicy::IsLivePathStateChanging(const std::string& path)
{
	static const char* const readOnlyPaths[] = {
		"/api/status",
		"/api/live/metrics",
		"/api/live/channels",
		"/api/live/mesh",
		"/api/live/kad/streams"
	};
	for (const char* const readOnlyPath : readOnlyPaths) {
		const std::size_t length = std::char_traits<char>::length(readOnlyPath);
		if (path.compare(0, length, readOnlyPath) == 0 &&
			(path.size() == length || path[length] == '?'))
			return false;
	}
	if (path.compare(0, 10, "/api/live/") == 0 && path.size() >= 43) {
		bool hash = true;
		for (std::size_t index = 10; index < 42; ++index) {
			const char value = path[index];
			hash = hash &&
				((value >= '0' && value <= '9') ||
				 (value >= 'a' && value <= 'f') ||
				 (value >= 'A' && value <= 'F'));
		}
		if (hash && path[42] == '/')
			return false;
	}
	// Unknown APIs are treated as mutations until explicitly proven read-only.
	return path.compare(0, 5, "/api/") == 0;
}

bool WebAuthPolicy::IsLocalWebAuthority(const std::string& authority)
{
	if (authority.empty())
		return false;
	std::string lower(authority);
	std::transform(lower.begin(), lower.end(), lower.begin(),
		[](unsigned char value) { return static_cast<char>(std::tolower(value)); });
	const std::size_t colon = lower.find(':');
	std::string host;
	if (lower[0] == '[') {
		const std::size_t bracket = lower.find(']');
		if (bracket == std::string::npos)
			return false;
		host = lower.substr(0, bracket + 1);
	} else {
		host = lower.substr(0, colon);
	}
	if (host != "localhost" && host != "127.0.0.1" && host != "[::1]")
		return false;
	const std::size_t suffix = host.size();
	if (lower.size() == suffix)
		return true;
	if (lower[suffix] != ':' || suffix + 1 == lower.size())
		return false;
	for (std::size_t index = suffix + 1; index < lower.size(); ++index) {
		if (lower[index] < '0' || lower[index] > '9')
			return false;
	}
	return true;
}

bool WebAuthPolicy::IsLocalWebOrigin(const std::string& origin)
{
	std::string lower(origin);
	std::transform(lower.begin(), lower.end(), lower.begin(),
		[](unsigned char value) { return static_cast<char>(std::tolower(value)); });
	const std::string http = "http://";
	const std::string https = "https://";
	std::size_t offset = std::string::npos;
	if (lower.compare(0, http.size(), http) == 0)
		offset = http.size();
	else if (lower.compare(0, https.size(), https) == 0)
		offset = https.size();
	if (offset == std::string::npos)
		return false;
	const std::size_t end = lower.find('/', offset);
	const std::string authority = lower.substr(
		offset, end == std::string::npos ? end : end - offset);
	return IsLocalWebAuthority(authority) &&
		(end == std::string::npos || end + 1 == lower.size());
}

bool WebAuthPolicy::AuthorizeLiveRequest(
	const std::string& path,
	bool loopback,
	const WebSessionSnapshot* session,
	const std::string& suppliedToken,
	const std::string& fetchSite,
	const std::string& host,
	const std::string& origin)
{
	const bool browserRequest = !fetchSite.empty() || !origin.empty();
	if (session != nullptr) {
		if (!IsLivePathStateChanging(path))
			return true;
		return browserRequest
			? ValidateCsrf(*session, suppliedToken)
			: ValidateCsrfRequest(*session, suppliedToken, fetchSite);
	}
	if (!loopback || !IsLocalWebAuthority(host) || fetchSite == "cross-site")
		return false;
	return origin.empty() || IsLocalWebOrigin(origin);
}

bool RunWebAuthPolicySelfTest(std::string& failure)
{
	failure.clear();
	const std::string token(WebAuthPolicy::kCsrfTokenHexLength, 'a');
	WebAuthPolicy policy;
	if (!policy.AddSession(7, WebRole::Admin, 3, 100, token) ||
		policy.AddSession(7, WebRole::Guest, 0, 101, token)) {
		failure = "web auth session identity failed";
		return false;
	}
	WebSessionSnapshot session;
	if (!policy.TouchSession(7, 400, 300, &session) ||
		WebAuthPolicy::ValidateCsrfRequest(session, "", "cross-site") ||
		!WebAuthPolicy::ValidateCsrfRequest(session, token, "cross-site")) {
		failure = "web auth CSRF/session expiry failed";
		return false;
	}
	const std::string nonce(WebAuthPolicy::kNonceHexLength, 'b');
	if (!policy.AddChallenge(nonce, 9, 1000) ||
		!policy.ConsumeChallenge(nonce, 9, 1001) ||
		policy.ConsumeChallenge(nonce, 9, 1002)) {
		failure = "web auth challenge replay failed";
		return false;
	}
	for (std::size_t attempt = 0;
		attempt < WebAuthPolicy::kMaxLoginFailuresPerIp; ++attempt)
		policy.RecordLoginFailure(9, 2000 + attempt);
	if (!policy.IsLoginBlocked(9, 2100)) {
		failure = "web auth login limit failed";
		return false;
	}
	const WebRateDecision first =
		policy.CheckRateLimit(WebAction::NetworkConnect, 0, 2000);
	const WebRateDecision second =
		policy.CheckRateLimit(WebAction::NetworkConnect, 500, 2000);
	if (!first.allowed || second.allowed || second.retry_after_ms != 1500) {
		failure = "web auth action rate limit failed";
		return false;
	}
	if (WebAuthPolicy::RequiredRoleForLivePath("/api/status") != WebRole::Guest ||
		WebAuthPolicy::RequiredRoleForLivePath("/api/live/join?key=x") != WebRole::Guest ||
		WebAuthPolicy::RequiredRoleForLivePath("/api/relay/accept?on=1") != WebRole::Admin ||
		WebAuthPolicy::RequiredRoleForLivePath("/api/live/test/edge_sabotage?on=1") != WebRole::Admin ||
		WebAuthPolicy::RequiredRoleForLivePath("/api/future/operator") != WebRole::Admin ||
		!WebAuthPolicy::IsLivePathStateChanging("/api/live/join?key=x") ||
		!WebAuthPolicy::IsLivePathStateChanging("/api/relay/accept?on=1") ||
		WebAuthPolicy::IsLivePathStateChanging("/api/status") ||
		!WebAuthPolicy::IsLocalWebAuthority("localhost:4711") ||
		!WebAuthPolicy::IsLocalWebAuthority("127.0.0.1") ||
		WebAuthPolicy::IsLocalWebAuthority("evil.example") ||
		!WebAuthPolicy::IsLocalWebOrigin("http://localhost:4711") ||
		WebAuthPolicy::IsLocalWebOrigin("http://evil.example") ||
		!WebAuthPolicy::AuthorizeLiveRequest(
			"/api/live/join", true, nullptr, "", "same-origin",
			"localhost:4711", "http://localhost:4711") ||
		WebAuthPolicy::AuthorizeLiveRequest(
			"/api/live/join", true, nullptr, "", "same-origin",
			"evil.example:4711", "http://evil.example:4711") ||
		WebAuthPolicy::AuthorizeLiveRequest(
			"/api/live/join", true, nullptr, "", "cross-site",
			"localhost:4711", "") ||
		WebAuthPolicy::AuthorizeLiveRequest(
			"/api/live/join", false, &session, "", "same-origin", "", "") ||
		!WebAuthPolicy::AuthorizeLiveRequest(
			"/api/live/join", false, &session, token, "same-origin", "", "") ||
		WebAuthPolicy::AuthorizeLiveRequest(
			"/api/status", true, nullptr, "", "same-origin",
			"evil.example:4711", "http://evil.example:4711") ||
		!WebAuthPolicy::AuthorizeLiveRequest(
			"/api/status", false, &session, "", "same-origin", "", "")) {
		failure = "web auth live permission matrix failed";
		return false;
	}
	return true;
}

} // namespace web
} // namespace ese
