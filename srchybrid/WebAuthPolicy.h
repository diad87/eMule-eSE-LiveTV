#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

namespace ese {
namespace web {

enum class WebRole : std::uint8_t {
	None = 0,
	Guest,
	Admin
};

enum class WebAction : std::uint8_t {
	NetworkConnect = 0,
	ManualRendezvous,
	KeepaliveToggle,
	ManualHolePunch,
	Count
};

struct WebSessionSnapshot {
	std::uint32_t id = 0;
	WebRole role = WebRole::None;
	int last_category = 0;
	std::uint64_t last_seen_ms = 0;
	std::string csrf_token;
};

struct WebRateDecision {
	bool allowed = false;
	std::uint64_t retry_after_ms = 0;
};

class WebAuthPolicy {
public:
	static constexpr std::uint64_t kChallengeLifetimeMs = 300000;
	static constexpr std::size_t kMaxPendingChallenges = 64;
	static constexpr std::uint64_t kLoginFailureWindowMs = 900000;
	static constexpr std::size_t kMaxLoginFailuresPerIp = 5;
	static constexpr std::size_t kMaxTrackedLoginFailures = 1024;
	static constexpr std::size_t kNonceHexLength = 64;
	static constexpr std::size_t kCsrfTokenHexLength = 64;

	bool AddSession(
		std::uint32_t id,
		WebRole role,
		int lastCategory,
		std::uint64_t nowMs,
		const std::string& csrfToken);
	bool TouchSession(
		std::uint32_t id,
		std::uint64_t nowMs,
		std::uint64_t timeoutMs,
		WebSessionSnapshot* snapshot = nullptr);
	bool GetSession(std::uint32_t id, WebSessionSnapshot& snapshot) const;
	bool RemoveSession(std::uint32_t id);
	std::size_t PurgeExpiredSessions(
		std::uint64_t nowMs,
		std::uint64_t timeoutMs);
	std::size_t SessionCount() const;
	bool SetLastCategory(
		std::uint32_t id,
		int category,
		std::uint64_t nowMs,
		std::uint64_t timeoutMs);
	bool GetLastCategory(
		std::uint32_t id,
		int& category,
		std::uint64_t nowMs,
		std::uint64_t timeoutMs);

	bool AddChallenge(
		const std::string& nonce,
		std::uint32_t clientIp,
		std::uint64_t nowMs);
	bool ConsumeChallenge(
		const std::string& nonce,
		std::uint32_t clientIp,
		std::uint64_t nowMs);
	std::size_t PendingChallengeCount() const;

	bool IsLoginBlocked(std::uint32_t clientIp, std::uint64_t nowMs);
	void RecordLoginFailure(std::uint32_t clientIp, std::uint64_t nowMs);
	void RecordLoginSuccess(std::uint32_t clientIp);
	std::size_t LoginFailureCount(
		std::uint32_t clientIp,
		std::uint64_t nowMs);

	WebRateDecision CheckRateLimit(
		WebAction action,
		std::uint64_t nowMs,
		std::uint64_t intervalMs);

	static bool IsValidHexToken(const std::string& token, std::size_t length);
	static bool ConstantTimeEqual(const std::string& lhs, const std::string& rhs);
	static bool ValidateCsrf(
		const WebSessionSnapshot& session,
		const std::string& suppliedToken);
	static bool ValidateCsrfRequest(
		const WebSessionSnapshot& session,
		const std::string& suppliedToken,
		const std::string& fetchSite);
	static bool HasPermission(WebRole role, WebRole required);

private:
	struct SessionRecord {
		std::uint32_t id = 0;
		WebRole role = WebRole::None;
		int last_category = 0;
		std::uint64_t last_seen_ms = 0;
		std::string csrf_token;
	};

	struct ChallengeRecord {
		std::string nonce;
		std::uint32_t client_ip = 0;
		std::uint64_t issued_ms = 0;
	};

	struct LoginFailureRecord {
		std::uint32_t client_ip = 0;
		std::uint64_t occurred_ms = 0;
	};

	struct ActionClock {
		bool initialized = false;
		std::uint64_t last_allowed_ms = 0;
	};

	static bool IsExpired(
		std::uint64_t nowMs,
		std::uint64_t thenMs,
		std::uint64_t lifetimeMs);
	static WebSessionSnapshot MakeSnapshot(const SessionRecord& record);
	void PurgeChallengesLocked(std::uint64_t nowMs);
	void PurgeLoginFailuresLocked(std::uint64_t nowMs);

	mutable std::mutex m_mutex;
	std::vector<SessionRecord> m_sessions;
	std::vector<ChallengeRecord> m_challenges;
	std::vector<LoginFailureRecord> m_loginFailures;
	std::array<ActionClock, static_cast<std::size_t>(WebAction::Count)> m_actionClocks{};
};

} // namespace web
} // namespace ese
