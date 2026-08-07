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

enum class WebCapabilityScope : std::uint8_t {
	HlsRead = 0
};

enum class WebHlsSourceRole : std::uint8_t {
	Viewer = 0,
	Broadcast
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

struct WebHlsCapabilitySnapshot {
	std::string token_digest;
	std::string stream_key;
	std::uint32_t owner_session_id = 0;
	std::uint64_t generation = 0;
	std::uint64_t issued_ms = 0;
	std::uint64_t expires_at_ms = 0;
	WebCapabilityScope scope = WebCapabilityScope::HlsRead;
	WebHlsSourceRole source_role = WebHlsSourceRole::Viewer;
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
	static constexpr std::size_t kHlsCapabilityTokenHexLength = 64;
	static constexpr std::size_t kBrowserSessionTokenHexLength = 64;
	static constexpr std::size_t kStreamKeyHexLength = 32;
	static constexpr std::uint64_t kHlsCapabilityLifetimeMs = 12ull * 60ull * 60ull * 1000ull;
	static constexpr std::size_t kMaxHlsCapabilities = 256;
	static constexpr std::size_t kMaxHlsCapabilitiesPerSession = 8;

	bool AddSession(
		std::uint32_t id,
		WebRole role,
		int lastCategory,
		std::uint64_t nowMs,
		const std::string& csrfToken,
		const std::string& browserTokenDigest = std::string());
	bool ResolveBrowserSessionDigest(
		const std::string& browserTokenDigest,
		std::uint64_t nowMs,
		std::uint64_t timeoutMs,
		WebSessionSnapshot* snapshot = nullptr,
		std::uint32_t expectedSessionId = 0);
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

	bool IssueHlsReadCapability(
		std::uint32_t ownerSessionId,
		const std::string& streamKey,
		WebHlsSourceRole sourceRole,
		std::uint64_t streamGeneration,
		const std::string& capabilityTokenDigest,
		std::uint64_t nowMs,
		std::uint64_t sessionTimeoutMs,
		WebHlsCapabilitySnapshot& snapshot);
	bool InspectHlsReadCapability(
		const std::string& capabilityTokenDigest,
		std::uint64_t pathGeneration,
		const std::string& streamKey,
		std::uint64_t nowMs,
		std::uint64_t sessionTimeoutMs,
		WebHlsCapabilitySnapshot* snapshot = nullptr);
	bool CommitHlsReadCapability(
		const std::string& capabilityTokenDigest,
		const std::string& streamKey,
		WebHlsSourceRole currentSourceRole,
		std::uint64_t currentStreamGeneration,
		std::uint64_t nowMs,
		std::uint64_t sessionTimeoutMs,
		WebHlsCapabilitySnapshot* snapshot = nullptr);
	bool RevokeHlsCapabilityDigest(const std::string& capabilityTokenDigest);
	void RevokeAllHlsCapabilities();
	std::size_t PurgeExpiredHlsCapabilities(std::uint64_t nowMs);
	std::size_t HlsCapabilityCount() const;

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
	static WebRole RequiredRoleForLivePath(const std::string& path);
	static bool IsLivePathStateChanging(const std::string& path);
	static bool IsLocalWebAuthority(const std::string& authority);
	static bool IsLocalWebOrigin(const std::string& origin);
	static bool AuthorizeLiveRequest(
		const std::string& path,
		bool loopback,
		const WebSessionSnapshot* session,
		const std::string& suppliedToken,
		const std::string& fetchSite,
		const std::string& host,
		const std::string& origin);

private:
	struct SessionRecord {
		std::uint32_t id = 0;
		WebRole role = WebRole::None;
		int last_category = 0;
		std::uint64_t last_seen_ms = 0;
		std::string csrf_token;
		std::string browser_token_digest;
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

	struct HlsCapabilityRecord {
		std::string token_digest;
		std::string stream_key;
		std::uint32_t owner_session_id = 0;
		std::uint64_t generation = 0;
		std::uint64_t issued_ms = 0;
		std::uint64_t expires_at_ms = 0;
		WebCapabilityScope scope = WebCapabilityScope::HlsRead;
		WebHlsSourceRole source_role = WebHlsSourceRole::Viewer;
	};

	static bool IsExpired(
		std::uint64_t nowMs,
		std::uint64_t thenMs,
		std::uint64_t lifetimeMs);
	static bool IsExpiredInclusive(
		std::uint64_t nowMs,
		std::uint64_t thenMs,
		std::uint64_t lifetimeMs);
	static WebSessionSnapshot MakeSnapshot(const SessionRecord& record);
	static WebHlsCapabilitySnapshot MakeSnapshot(
		const HlsCapabilityRecord& record);
	static bool IsValidStreamKey(const std::string& streamKey);
	void PurgeChallengesLocked(std::uint64_t nowMs);
	void PurgeLoginFailuresLocked(std::uint64_t nowMs);
	void RemoveHlsCapabilitiesForSessionLocked(std::uint32_t sessionId);
	std::size_t PurgeExpiredHlsCapabilitiesLocked(std::uint64_t nowMs);

	mutable std::mutex m_mutex;
	std::vector<SessionRecord> m_sessions;
	std::vector<ChallengeRecord> m_challenges;
	std::vector<LoginFailureRecord> m_loginFailures;
	std::vector<HlsCapabilityRecord> m_hlsCapabilities;
	std::array<ActionClock, static_cast<std::size_t>(WebAction::Count)> m_actionClocks{};
};

bool RunWebAuthPolicySelfTest(std::string& failure);

} // namespace web
} // namespace ese
