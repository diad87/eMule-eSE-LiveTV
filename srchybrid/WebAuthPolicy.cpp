#include "WebAuthPolicy.h"

#include <algorithm>

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
	static const char* const adminPrefixes[] = {
		"/api/debug/",
		"/api/ese/",
		"/api/holepunch/",
		"/api/keepalive/",
		"/api/krp/",
		"/api/network/",
		"/api/relay/",
		"/api/live/broadcast/",
		"/api/live/log",
		"/api/live/preflight",
		"/api/live/privacy/",
		"/api/live/reachability/"
	};
	for (const char* const prefix : adminPrefixes) {
		const std::size_t length = std::char_traits<char>::length(prefix);
		if (path.size() >= length && path.compare(0, length, prefix) == 0)
			return WebRole::Admin;
	}
	return WebRole::Guest;
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
		WebAuthPolicy::RequiredRoleForLivePath("/api/ese/v9?on=1") != WebRole::Admin) {
		failure = "web auth live permission matrix failed";
		return false;
	}
	return true;
}

} // namespace web
} // namespace ese
