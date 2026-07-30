#include "LiveStreamSecurity.h"

#include <algorithm>

namespace ese {
namespace live {

namespace {

constexpr std::uint32_t kSerialHalfRange = 0x80000000u;
constexpr std::uint32_t kPromoteMiddleTime = 2u * 60u * 1000u;
constexpr std::uint32_t kPromoteSuperTime = 5u * 60u * 1000u;
constexpr float kPromoteMiddleRate = 0.80f;
constexpr float kPromoteSuperRate = 0.90f;
constexpr float kBanResponseRate = 0.20f;
constexpr float kDemoteResponseRate = 0.50f;
constexpr std::int32_t kFailureCap = 10;

bool IsAllZero(const LiveStreamKey& value)
{
	return std::all_of(value.begin(), value.end(), [](std::uint8_t byte) {
		return byte == 0u;
	});
}

bool IsAllZero(const LivePublicKey& value)
{
	return std::all_of(value.begin(), value.end(), [](std::uint8_t byte) {
		return byte == 0u;
	});
}

bool IsValid(const LiveTrustIdentity& identity)
{
	std::size_t meaningful_size = 0u;
	switch (identity.kind) {
	case LiveTrustIdentityKind::UserHash:
		meaningful_size = 16u;
		break;
	case LiveTrustIdentityKind::PublicKey:
		meaningful_size = identity.bytes.size();
		break;
	default:
		return false;
	}
	return std::any_of(
		identity.bytes.begin(),
		identity.bytes.begin() + meaningful_size,
		[](std::uint8_t byte) { return byte != 0u; });
}

} // namespace

float LiveTrustSnapshot::ResponseRate() const
{
	if (requests_received == 0u)
		return 1.0f;
	return static_cast<float>(requests_served) /
		static_cast<float>(requests_received);
}

float LiveTrustRecord::ResponseRate() const
{
	if (requests_received == 0u)
		return 1.0f;
	return static_cast<float>(requests_served) /
		static_cast<float>(requests_received);
}

LiveStreamSecurity::LiveStreamSecurity()
{
	pins_.reserve(kPinCapacity);
	replay_.reserve(kReplayCapacity);
	trust_.reserve(kTrustCapacity);
}

std::vector<LiveStreamSecurity::PinEntry>::const_iterator
LiveStreamSecurity::FindPinLocked(const LiveStreamKey& stream_key) const
{
	return std::find_if(
		pins_.begin(),
		pins_.end(),
		[&stream_key](const PinEntry& entry) {
			return entry.stream_key == stream_key;
		});
}

std::vector<LiveStreamSecurity::ReplayEntry>::iterator
LiveStreamSecurity::FindReplayLocked(const LiveStreamKey& stream_key)
{
	return std::find_if(
		replay_.begin(),
		replay_.end(),
		[&stream_key](const ReplayEntry& entry) {
			return entry.stream_key == stream_key;
		});
}

std::vector<LiveStreamSecurity::ReplayEntry>::const_iterator
LiveStreamSecurity::FindReplayLocked(const LiveStreamKey& stream_key) const
{
	return std::find_if(
		replay_.begin(),
		replay_.end(),
		[&stream_key](const ReplayEntry& entry) {
			return entry.stream_key == stream_key;
		});
}

std::vector<LiveStreamSecurity::TrustEntry>::iterator
LiveStreamSecurity::FindTrustLocked(const LiveTrustIdentity& identity)
{
	return std::find_if(
		trust_.begin(),
		trust_.end(),
		[&identity](const TrustEntry& entry) {
			return entry.identity == identity;
		});
}

std::vector<LiveStreamSecurity::TrustEntry>::const_iterator
LiveStreamSecurity::FindTrustLocked(const LiveTrustIdentity& identity) const
{
	return std::find_if(
		trust_.begin(),
		trust_.end(),
		[&identity](const TrustEntry& entry) {
			return entry.identity == identity;
		});
}

LivePinResult LiveStreamSecurity::PinValidatedPublicKey(
	const LiveStreamKey& stream_key,
	const LivePublicKey& public_key,
	std::uint32_t pinned_at)
{
	if (IsAllZero(stream_key) || IsAllZero(public_key))
		return LivePinResult::InvalidInput;

	std::lock_guard<std::mutex> lock(mutex_);
	const auto existing = FindPinLocked(stream_key);
	if (existing != pins_.end()) {
		return existing->public_key == public_key
			? LivePinResult::AlreadyPinned
			: LivePinResult::Conflict;
	}
	if (pins_.size() >= kPinCapacity)
		return LivePinResult::CapacityExceeded;

	PinEntry entry;
	entry.stream_key = stream_key;
	entry.public_key = public_key;
	entry.pinned_at = pinned_at;
	pins_.push_back(entry);
	return LivePinResult::Pinned;
}

bool LiveStreamSecurity::GetPinnedPublicKey(
	const LiveStreamKey& stream_key,
	LivePublicKey& public_key) const
{
	std::lock_guard<std::mutex> lock(mutex_);
	const auto existing = FindPinLocked(stream_key);
	if (existing == pins_.end())
		return false;
	public_key = existing->public_key;
	return true;
}

LiveReplayResult LiveStreamSecurity::ClassifyVerifiedSequenceLocked(
	const LiveStreamKey& stream_key,
	std::uint32_t sequence_number) const
{
	if (FindPinLocked(stream_key) == pins_.end())
		return LiveReplayResult::UnpinnedStream;

	const auto entry = FindReplayLocked(stream_key);
	if (entry == replay_.end()) {
		if (replay_.size() >= kReplayCapacity)
			return LiveReplayResult::CapacityExceeded;
		return LiveReplayResult::Accepted;
	}
	const std::uint32_t forward =
		sequence_number - entry->newest_sequence;
	if (forward == 0u)
		return LiveReplayResult::Duplicate;
	if (forward == kSerialHalfRange)
		return LiveReplayResult::AmbiguousSequence;
	if (forward < kSerialHalfRange)
		return LiveReplayResult::Accepted;
	const std::uint32_t age =
		entry->newest_sequence - sequence_number;
	if (age >= kReplayWindowSequences)
		return LiveReplayResult::TooOld;
	const std::uint64_t bit = std::uint64_t{1u} << age;
	return (entry->seen_bitmap & bit) != 0u
		? LiveReplayResult::Duplicate
		: LiveReplayResult::Accepted;
}

LiveReplayResult LiveStreamSecurity::ClassifyVerifiedSequence(
	const LiveStreamKey& stream_key,
	std::uint32_t sequence_number) const
{
	std::lock_guard<std::mutex> lock(mutex_);
	return ClassifyVerifiedSequenceLocked(stream_key, sequence_number);
}

LiveReplayResult LiveStreamSecurity::CommitVerifiedSequence(
	const LiveStreamKey& stream_key,
	std::uint32_t sequence_number)
{
	std::lock_guard<std::mutex> lock(mutex_);
	const LiveReplayResult classification =
		ClassifyVerifiedSequenceLocked(stream_key, sequence_number);
	if (classification != LiveReplayResult::Accepted)
		return classification;

	auto entry = FindReplayLocked(stream_key);
	if (entry == replay_.end()) {
		ReplayEntry fresh;
		fresh.stream_key = stream_key;
		fresh.newest_sequence = sequence_number;
		fresh.seen_bitmap = 1u;
		replay_.push_back(fresh);
		return LiveReplayResult::Accepted;
	}

	const std::uint32_t forward =
		sequence_number - entry->newest_sequence;
	if (forward < kSerialHalfRange) {
		entry->seen_bitmap = forward >= kReplayWindowSequences
			? 1u
			: (entry->seen_bitmap << forward) | 1u;
		entry->newest_sequence = sequence_number;
		return LiveReplayResult::Accepted;
	}

	const std::uint32_t age =
		entry->newest_sequence - sequence_number;
	const std::uint64_t bit = std::uint64_t{1u} << age;
	entry->seen_bitmap |= bit;
	return LiveReplayResult::Accepted;
}

void LiveStreamSecurity::ReleaseStream(const LiveStreamKey& stream_key)
{
	std::lock_guard<std::mutex> lock(mutex_);
	pins_.erase(std::remove_if(
		pins_.begin(), pins_.end(), [&stream_key](const PinEntry& entry) {
			return entry.stream_key == stream_key;
		}), pins_.end());
	replay_.erase(std::remove_if(
		replay_.begin(), replay_.end(), [&stream_key](const ReplayEntry& entry) {
			return entry.stream_key == stream_key;
		}), replay_.end());
}

std::size_t LiveStreamSecurity::PinCount() const
{
	std::lock_guard<std::mutex> lock(mutex_);
	return pins_.size();
}

std::size_t LiveStreamSecurity::ReplayStreamCount() const
{
	std::lock_guard<std::mutex> lock(mutex_);
	return replay_.size();
}

LiveTrustStoreResult LiveStreamSecurity::TouchTrust(
	const LiveTrustIdentity& identity,
	std::uint32_t now,
	LiveTrustRecord& record)
{
	if (!IsValid(identity))
		return LiveTrustStoreResult::InvalidIdentity;
	std::lock_guard<std::mutex> lock(mutex_);
	auto entry = FindTrustLocked(identity);
	if (entry == trust_.end()) {
		if (trust_.size() >= kTrustCapacity)
			return LiveTrustStoreResult::CapacityExceeded;
		TrustEntry fresh;
		fresh.identity = identity;
		fresh.record.joined_at = now;
		fresh.record.last_seen = now;
		trust_.push_back(fresh);
		record = fresh.record;
		return LiveTrustStoreResult::Stored;
	}
	entry->record.last_seen = now;
	record = entry->record;
	return LiveTrustStoreResult::Stored;
}

bool LiveStreamSecurity::GetTrust(
	const LiveTrustIdentity& identity,
	LiveTrustRecord& record) const
{
	if (!IsValid(identity))
		return false;
	std::lock_guard<std::mutex> lock(mutex_);
	const auto entry = FindTrustLocked(identity);
	if (entry == trust_.end())
		return false;
	record = entry->record;
	return true;
}

LiveTrustStoreResult LiveStreamSecurity::SetTrust(
	const LiveTrustIdentity& identity,
	const LiveTrustRecord& record)
{
	if (!IsValid(identity))
		return LiveTrustStoreResult::InvalidIdentity;
	std::lock_guard<std::mutex> lock(mutex_);
	auto entry = FindTrustLocked(identity);
	if (entry != trust_.end()) {
		entry->record = record;
		return LiveTrustStoreResult::Stored;
	}
	if (trust_.size() >= kTrustCapacity)
		return LiveTrustStoreResult::CapacityExceeded;
	TrustEntry fresh;
	fresh.identity = identity;
	fresh.record = record;
	trust_.push_back(fresh);
	return LiveTrustStoreResult::Stored;
}

std::size_t LiveStreamSecurity::PruneTrust(
	std::uint32_t now,
	std::uint32_t ttl)
{
	std::lock_guard<std::mutex> lock(mutex_);
	const std::size_t before = trust_.size();
	trust_.erase(std::remove_if(
		trust_.begin(), trust_.end(), [now, ttl](const TrustEntry& entry) {
			const std::uint32_t anchor = entry.record.last_seen != 0u
				? entry.record.last_seen : entry.record.joined_at;
			return anchor != 0u && now - anchor > ttl;
		}), trust_.end());
	return before - trust_.size();
}

std::size_t LiveStreamSecurity::TrustCount() const
{
	std::lock_guard<std::mutex> lock(mutex_);
	return trust_.size();
}

void LiveStreamSecurity::ClearTrust()
{
	std::lock_guard<std::mutex> lock(mutex_);
	trust_.clear();
}

void LiveStreamSecurity::Clear()
{
	std::lock_guard<std::mutex> lock(mutex_);
	pins_.clear();
	replay_.clear();
	trust_.clear();
}

LiveTrustLevel LiveStreamSecurity::EvaluateTrust(
	const LiveTrustSnapshot& trust,
	std::uint32_t now,
	bool can_promote_to_super_seeder)
{
	if (trust.is_banned)
		return LiveTrustLevel::Leaf;
	const std::uint32_t uptime = now - trust.joined_at;
	const float response_rate = trust.ResponseRate();
	if (uptime < kPromoteMiddleTime)
		return LiveTrustLevel::Leaf;
	if (trust.requests_received > 5u &&
		response_rate < kPromoteMiddleRate)
		return LiveTrustLevel::Leaf;
	if (trust.fail_count > 2)
		return LiveTrustLevel::Leaf;
	if (uptime < kPromoteSuperTime)
		return LiveTrustLevel::Middle;
	if (trust.requests_received > 10u &&
		response_rate < kPromoteSuperRate)
		return LiveTrustLevel::Middle;
	return can_promote_to_super_seeder
		? LiveTrustLevel::SuperSeeder
		: LiveTrustLevel::Middle;
}

bool LiveStreamSecurity::ShouldBan(
	const LiveTrustSnapshot& trust,
	std::uint32_t now)
{
	return now - trust.joined_at > kPromoteMiddleTime &&
		trust.requests_received > 10u &&
		trust.ResponseRate() < kBanResponseRate;
}

bool LiveStreamSecurity::ShouldDemote(
	const LiveTrustSnapshot& trust,
	std::uint32_t now)
{
	return now - trust.joined_at > kPromoteMiddleTime &&
		trust.requests_received > 5u &&
		trust.ResponseRate() < kDemoteResponseRate;
}

std::int32_t LiveStreamSecurity::ChargeFailure(
	std::int32_t fail_count,
	std::int32_t weight)
{
	if (fail_count < 0)
		fail_count = 0;
	if (weight < 0)
		weight = 0;
	if (fail_count >= kFailureCap - weight)
		return kFailureCap;
	return fail_count + weight;
}

std::int32_t LiveStreamSecurity::RewardCriticalDelivery(
	std::int32_t fail_count)
{
	return fail_count > 0 ? fail_count - 1 : 0;
}

} // namespace live
} // namespace ese
