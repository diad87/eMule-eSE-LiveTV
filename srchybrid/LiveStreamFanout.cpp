#include "LiveStreamFanout.h"

#include <algorithm>
#include <limits>

namespace ese {
namespace live {

LiveStreamFanout::LiveStreamFanout()
	: next_token_(1u)
{
	children_.reserve(kChildCapacity);
	reservations_.reserve(kReservationCapacity);
}

std::vector<LiveStreamFanout::ChildEntry>::iterator
LiveStreamFanout::FindChildLocked(LiveFanoutChild child)
{
	return std::find_if(
		children_.begin(), children_.end(),
		[child](const ChildEntry& entry) { return entry.child == child; });
}

std::vector<LiveStreamFanout::ChildEntry>::const_iterator
LiveStreamFanout::FindChildLocked(LiveFanoutChild child) const
{
	return std::find_if(
		children_.cbegin(), children_.cend(),
		[child](const ChildEntry& entry) { return entry.child == child; });
}

LiveFanoutRegisterResult LiveStreamFanout::RegisterChild(
	LiveFanoutChild child)
{
	if (child == 0u)
		return LiveFanoutRegisterResult::InvalidChild;
	std::lock_guard<std::mutex> lock(mutex_);
	if (FindChildLocked(child) != children_.end())
		return LiveFanoutRegisterResult::AlreadyRegistered;
	if (children_.size() >= kChildCapacity)
		return LiveFanoutRegisterResult::CapacityExceeded;
	ChildEntry entry;
	entry.child = child;
	children_.push_back(entry);
	return LiveFanoutRegisterResult::Registered;
}

bool LiveStreamFanout::ReplaceChild(
	LiveFanoutChild previous,
	LiveFanoutChild replacement)
{
	if (previous == 0u || replacement == 0u || previous == replacement)
		return false;
	std::lock_guard<std::mutex> lock(mutex_);
	auto found = FindChildLocked(previous);
	if (found == children_.end() ||
		FindChildLocked(replacement) != children_.end())
		return false;
	found->child = replacement;
	for (ReservationEntry& reservation : reservations_) {
		if (reservation.child == previous)
			reservation.child = replacement;
	}
	return true;
}

bool LiveStreamFanout::ReleaseChild(LiveFanoutChild child)
{
	if (child == 0u)
		return false;
	std::lock_guard<std::mutex> lock(mutex_);
	auto found = FindChildLocked(child);
	if (found == children_.end())
		return false;
	reservations_.erase(
		std::remove_if(
			reservations_.begin(), reservations_.end(),
			[child](const ReservationEntry& reservation) {
				return reservation.child == child;
			}),
		reservations_.end());
	children_.erase(found);
	return true;
}

void LiveStreamFanout::Clear()
{
	std::lock_guard<std::mutex> lock(mutex_);
	reservations_.clear();
	children_.clear();
	next_token_ = 1u;
}

std::vector<LiveFanoutChild> LiveStreamFanout::SelectRecipients(
	LiveFanoutChild sender,
	const std::vector<LiveFanoutChild>& blocked,
	std::size_t limit) const
{
	std::vector<LiveFanoutChild> selected;
	if (limit == 0u)
		return selected;
	selected.reserve(std::min(limit, kChildCapacity));
	std::lock_guard<std::mutex> lock(mutex_);
	for (const ChildEntry& entry : children_) {
		if (selected.size() >= limit)
			break;
		if (entry.child == sender)
			continue;
		if (std::find(blocked.begin(), blocked.end(), entry.child) !=
			blocked.end())
			continue;
		if (std::find(selected.begin(), selected.end(), entry.child) !=
			selected.end())
			continue;
		selected.push_back(entry.child);
	}
	return selected;
}

std::uint64_t LiveStreamFanout::NextTokenLocked()
{
	for (std::size_t attempt = 0u;
		attempt <= reservations_.size();
		++attempt) {
		const std::uint64_t candidate = next_token_++;
		if (next_token_ == 0u)
			next_token_ = 1u;
		if (candidate == 0u)
			continue;
		const bool exists = std::any_of(
			reservations_.cbegin(), reservations_.cend(),
			[candidate](const ReservationEntry& reservation) {
				return reservation.token == candidate;
			});
		if (!exists)
			return candidate;
	}
	return 0u;
}

LiveFanoutReservation LiveStreamFanout::BeginDelivery(
	LiveFanoutChild child,
	std::uint32_t first_sequence,
	std::uint32_t last_sequence,
	std::uint64_t external_queued_bytes,
	std::uint64_t wire_bytes)
{
	LiveFanoutReservation result;
	if (child == 0u || wire_bytes == 0u) {
		result.result = LiveFanoutDeliveryResult::InvalidInput;
		return result;
	}

	std::lock_guard<std::mutex> lock(mutex_);
	auto found = FindChildLocked(child);
	if (found == children_.end()) {
		result.result = LiveFanoutDeliveryResult::UnknownChild;
		return result;
	}

	if (wire_bytes > kPeerQueueLimitBytes ||
		external_queued_bytes > kPeerQueueLimitBytes - wire_bytes ||
		found->pending_bytes >
			kPeerQueueLimitBytes - wire_bytes - external_queued_bytes) {
		++found->backpressure_rejections;
		result.result = LiveFanoutDeliveryResult::Backpressured;
		return result;
	}

	const bool duplicate = std::any_of(
		reservations_.cbegin(), reservations_.cend(),
		[child, first_sequence, last_sequence](
			const ReservationEntry& reservation) {
			return reservation.child == child &&
				reservation.first_sequence == first_sequence &&
				reservation.last_sequence == last_sequence;
		});
	if (duplicate) {
		result.result = LiveFanoutDeliveryResult::DuplicatePending;
		return result;
	}
	if (reservations_.size() >= kReservationCapacity) {
		result.result = LiveFanoutDeliveryResult::CapacityExceeded;
		return result;
	}

	const std::uint64_t token = NextTokenLocked();
	if (token == 0u) {
		result.result = LiveFanoutDeliveryResult::CapacityExceeded;
		return result;
	}
	ReservationEntry reservation;
	reservation.token = token;
	reservation.child = child;
	reservation.first_sequence = first_sequence;
	reservation.last_sequence = last_sequence;
	reservation.wire_bytes = wire_bytes;
	reservations_.push_back(reservation);
	found->pending_bytes += wire_bytes;
	++found->pending_deliveries;
	result.result = LiveFanoutDeliveryResult::Reserved;
	result.token = token;
	return result;
}

bool LiveStreamFanout::CompleteDelivery(std::uint64_t token, bool sent)
{
	if (token == 0u)
		return false;
	std::lock_guard<std::mutex> lock(mutex_);
	auto reservation = std::find_if(
		reservations_.begin(), reservations_.end(),
		[token](const ReservationEntry& entry) {
			return entry.token == token;
		});
	if (reservation == reservations_.end())
		return false;
	auto child = FindChildLocked(reservation->child);
	if (child == children_.end())
		return false;
	if (child->pending_bytes < reservation->wire_bytes ||
		child->pending_deliveries == 0u)
		return false;
	child->pending_bytes -= reservation->wire_bytes;
	--child->pending_deliveries;
	if (sent) {
		++child->completed_deliveries;
		child->completed_bytes += reservation->wire_bytes;
	} else {
		++child->failed_deliveries;
	}
	reservations_.erase(reservation);
	return true;
}

bool LiveStreamFanout::GetChildSnapshot(
	LiveFanoutChild child,
	LiveFanoutChildSnapshot& snapshot) const
{
	std::lock_guard<std::mutex> lock(mutex_);
	const auto found = FindChildLocked(child);
	if (found == children_.end())
		return false;
	snapshot.pending_deliveries = found->pending_deliveries;
	snapshot.pending_bytes = found->pending_bytes;
	snapshot.completed_deliveries = found->completed_deliveries;
	snapshot.completed_bytes = found->completed_bytes;
	snapshot.failed_deliveries = found->failed_deliveries;
	snapshot.backpressure_rejections = found->backpressure_rejections;
	return true;
}

std::size_t LiveStreamFanout::ChildCount() const
{
	std::lock_guard<std::mutex> lock(mutex_);
	return children_.size();
}

std::size_t LiveStreamFanout::ReservationCount() const
{
	std::lock_guard<std::mutex> lock(mutex_);
	return reservations_.size();
}

std::uint64_t LiveStreamFanout::PendingBytes() const
{
	std::lock_guard<std::mutex> lock(mutex_);
	std::uint64_t total = 0u;
	for (const ChildEntry& child : children_) {
		if (total > std::numeric_limits<std::uint64_t>::max() -
			child.pending_bytes)
			return std::numeric_limits<std::uint64_t>::max();
		total += child.pending_bytes;
	}
	return total;
}

} // namespace live
} // namespace ese
