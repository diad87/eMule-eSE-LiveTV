#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <vector>

namespace ese {
namespace live {

using LiveStreamKey = std::array<std::uint8_t, 16>;
using LivePublicKey = std::array<std::uint8_t, 32>;

enum class LivePinResult : std::uint8_t {
	Pinned = 0,
	AlreadyPinned = 1,
	Conflict = 2,
	CapacityExceeded = 3,
	InvalidInput = 4,
};

enum class LiveReplayResult : std::uint8_t {
	Accepted = 0,
	Duplicate = 1,
	TooOld = 2,
	AmbiguousSequence = 3,
	UnpinnedStream = 4,
	CapacityExceeded = 5,
};

enum class LiveTrustLevel : std::uint8_t {
	SuperSeeder = 0,
	Middle = 1,
	Leaf = 2,
};

struct LiveTrustSnapshot {
	std::uint32_t joined_at = 0u;
	std::uint32_t requests_received = 0u;
	std::uint32_t requests_served = 0u;
	std::int32_t fail_count = 0;
	LiveTrustLevel current_level = LiveTrustLevel::Leaf;
	bool is_banned = false;

	float ResponseRate() const;
};

class LiveStreamSecurity final
{
public:
	static constexpr std::size_t kPinCapacity = 256u;
	static constexpr std::size_t kReplayCapacity = 256u;
	static constexpr std::uint32_t kReplayWindowSequences = 64u;

	LiveStreamSecurity();
	LiveStreamSecurity(const LiveStreamSecurity&) = delete;
	LiveStreamSecurity& operator=(const LiveStreamSecurity&) = delete;

	LivePinResult PinValidatedPublicKey(
		const LiveStreamKey& stream_key,
		const LivePublicKey& public_key,
		std::uint32_t pinned_at);
	bool GetPinnedPublicKey(
		const LiveStreamKey& stream_key,
		LivePublicKey& public_key) const;
	LiveReplayResult AcceptVerifiedSequence(
		const LiveStreamKey& stream_key,
		std::uint32_t sequence_number);
	std::size_t PinCount() const;
	std::size_t ReplayStreamCount() const;
	void Clear();
	static LiveTrustLevel EvaluateTrust(
		const LiveTrustSnapshot& trust,
		std::uint32_t now,
		bool can_promote_to_super_seeder);
	static bool ShouldBan(
		const LiveTrustSnapshot& trust,
		std::uint32_t now);
	static bool ShouldDemote(
		const LiveTrustSnapshot& trust,
		std::uint32_t now);
	static std::int32_t ChargeFailure(
		std::int32_t fail_count,
		std::int32_t weight);
	static std::int32_t RewardCriticalDelivery(std::int32_t fail_count);

private:
	struct PinEntry {
		LiveStreamKey stream_key = {};
		LivePublicKey public_key = {};
		std::uint32_t pinned_at = 0u;
	};

	struct ReplayEntry {
		LiveStreamKey stream_key = {};
		std::uint32_t newest_sequence = 0u;
		std::uint64_t seen_bitmap = 0u;
	};

	std::vector<PinEntry>::const_iterator FindPinLocked(
		const LiveStreamKey& stream_key) const;
	std::vector<ReplayEntry>::iterator FindReplayLocked(
		const LiveStreamKey& stream_key);

	mutable std::mutex mutex_;
	std::vector<PinEntry> pins_;
	std::vector<ReplayEntry> replay_;
};

} // namespace live
} // namespace ese
