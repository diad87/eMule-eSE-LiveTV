#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace ese {
namespace live {

struct LiveRecoveryEndpoint {
	static constexpr std::size_t kAddressCapacity = 46u;

	std::uint8_t family = 0u;
	std::uint16_t port = 0u;
	char address[kAddressCapacity] = {};

	static LiveRecoveryEndpoint FromText(
		std::uint8_t family,
		const char* address,
		std::uint16_t port) noexcept;

	bool IsValid() const noexcept;
	bool operator==(const LiveRecoveryEndpoint& other) const noexcept;
	bool operator!=(const LiveRecoveryEndpoint& other) const noexcept
	{
		return !(*this == other);
	}
};

enum class LiveMissingProbeResult : std::uint8_t {
	Ready,
	Suppressed,
	Retry
};

struct LiveMissingProbe {
	LiveMissingProbeResult result = LiveMissingProbeResult::Ready;
	LiveRecoveryEndpoint previous_endpoint;
	std::uint32_t attempts = 0u;
	bool charge_previous_failure = false;
};

enum class LiveEmergencyTransition : std::uint8_t {
	None,
	Entered,
	Exited
};

struct LiveFecParityDecision {
	std::uint8_t parity = 0u;
	bool reset_window = false;
};

class LiveStreamRecovery final {
public:
	static constexpr std::size_t kInflightCapacity = 64u;
	static constexpr std::size_t kMissingBlockCapacity = 16u;
	static constexpr std::uint32_t kInflightTimeoutMs = 4000u;
	static constexpr std::uint32_t kPeerLossGraceMs = 2000u;
	static constexpr std::uint32_t kPeerRequestCooldownMs = 15000u;
	static constexpr std::uint32_t kMinimumSourcePeers = 3u;
	static constexpr std::uint32_t kNackInitialDelayMs = 3000u;
	static constexpr std::uint32_t kNackCooldownMs = 2000u;
	static constexpr std::uint32_t kParityWindowMs = 10000u;
	static constexpr std::uint8_t kMinimumParity = 2u;
	static constexpr std::uint8_t kDefaultParity = 3u;
	static constexpr std::uint8_t kMaximumParity = 8u;

	LiveStreamRecovery();
	LiveStreamRecovery(const LiveStreamRecovery&) = delete;
	LiveStreamRecovery& operator=(const LiveStreamRecovery&) = delete;

	void Reset() noexcept;
	void ResetViewer() noexcept;

	void OnSourceLost(
		std::uint32_t now,
		std::uint32_t remaining_sources) noexcept;
	bool ShouldRequestPeers(
		std::uint32_t now,
		std::uint32_t source_count) noexcept;
	std::uint32_t TakePeerCandidate(std::uint32_t source_count) noexcept;
	bool IsPeerRefreshPending() const noexcept;

	LiveMissingProbe InspectMissing(
		std::uint32_t sequence,
		std::uint32_t now) noexcept;
	bool RecordRequest(
		std::uint32_t sequence,
		std::uint32_t now,
		const LiveRecoveryEndpoint& endpoint,
		std::uint32_t attempts,
		bool edge_critical) noexcept;
	bool CompleteRequest(
		std::uint32_t sequence,
		bool& was_edge_critical) noexcept;
	void PruneRequests(
		const std::vector<std::uint32_t>& present_sequences,
		bool has_window,
		std::uint32_t oldest_sequence) noexcept;
	std::size_t InflightCount() const noexcept;

	LiveEmergencyTransition ObservePeerHealth(
		std::uint32_t now,
		std::uint32_t total_super_seeders,
		std::uint32_t alive_super_seeders,
		std::uint32_t drop_threshold_percent,
		std::uint32_t emergency_duration_ms) noexcept;
	bool IsEmergencyMode() const noexcept;

	static bool ShouldSendNack(
		std::uint32_t now,
		std::uint32_t first_seen_tick,
		std::uint32_t last_nack_tick) noexcept;
	static std::vector<std::uint8_t> MissingFecBlocks(
		const std::vector<std::uint8_t>& required,
		const std::vector<std::uint8_t>& received);
	static LiveFecParityDecision AdvanceParity(
		std::uint8_t current_parity,
		std::uint32_t nack_count,
		std::uint32_t elapsed_ms) noexcept;
	static std::uint32_t NextAttempt(std::uint32_t attempts) noexcept;

private:
	struct InflightRequest {
		std::uint32_t sequence = 0u;
		std::uint32_t sent_tick = 0u;
		LiveRecoveryEndpoint endpoint;
		std::uint32_t attempts = 0u;
		bool edge_critical = false;
		bool failure_charged = false;
	};

	std::vector<InflightRequest>::iterator FindRequest(
		std::uint32_t sequence) noexcept;
	std::vector<InflightRequest>::const_iterator FindRequest(
		std::uint32_t sequence) const noexcept;
	static bool IsSequenceNewer(
		std::uint32_t lhs,
		std::uint32_t rhs) noexcept;

	std::vector<InflightRequest> inflight_;
	bool refresh_pending_ = false;
	bool refresh_has_not_before_ = false;
	std::uint32_t refresh_not_before_tick_ = 0u;
	bool refresh_has_requested_ = false;
	std::uint32_t refresh_last_request_tick_ = 0u;
	std::uint32_t next_candidate_ = 0u;
	bool emergency_mode_ = false;
	std::uint32_t emergency_start_tick_ = 0u;
};

} // namespace live
} // namespace ese
