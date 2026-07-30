#pragma once

#include <cstddef>
#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <vector>

namespace ese {
namespace live {

using LiveFanoutChild = std::uintptr_t;

enum class LiveFanoutRegisterResult : std::uint8_t {
	Registered = 0,
	AlreadyRegistered = 1,
	CapacityExceeded = 2,
	InvalidChild = 3,
};

enum class LiveFanoutDeliveryResult : std::uint8_t {
	Reserved = 0,
	InvalidInput = 1,
	UnknownChild = 2,
	DuplicatePending = 3,
	Backpressured = 4,
	CapacityExceeded = 5,
};

struct LiveFanoutReservation {
	LiveFanoutDeliveryResult result =
		LiveFanoutDeliveryResult::InvalidInput;
	std::uint64_t token = 0u;

	bool IsReserved() const
	{
		return result == LiveFanoutDeliveryResult::Reserved && token != 0u;
	}
};

struct LiveFanoutChildSnapshot {
	std::size_t pending_deliveries = 0u;
	std::uint64_t pending_bytes = 0u;
	std::uint64_t completed_deliveries = 0u;
	std::uint64_t completed_bytes = 0u;
	std::uint64_t failed_deliveries = 0u;
	std::uint64_t backpressure_rejections = 0u;
};

struct LiveFanoutReplacementTicket {
	std::uint64_t token = 0u;
	LiveFanoutChild previous = 0u;
	LiveFanoutChild replacement = 0u;

	bool IsActive() const { return token != 0u; }
};

class LiveStreamFanout final
{
public:
	static constexpr std::size_t kChildCapacity = 64u;
	static constexpr std::size_t kReservationCapacity = 256u;
	static constexpr std::uint64_t kPeerQueueLimitBytes = 8u * 1024u * 1024u;

	LiveStreamFanout();
	LiveStreamFanout(const LiveStreamFanout&) = delete;
	LiveStreamFanout& operator=(const LiveStreamFanout&) = delete;

	LiveFanoutRegisterResult RegisterChild(LiveFanoutChild child);
	bool ReplaceChild(
		LiveFanoutChild previous,
		LiveFanoutChild replacement,
		std::uint64_t replacement_external_queued_bytes = 0u);
	LiveFanoutReplacementTicket BeginChildReplacement(
		LiveFanoutChild previous,
		LiveFanoutChild replacement);
	bool CommitChildReplacement(
		const LiveFanoutReplacementTicket& ticket,
		std::uint64_t replacement_external_queued_bytes);
	bool AbortChildReplacement(
		const LiveFanoutReplacementTicket& ticket);
	bool ReleaseChild(LiveFanoutChild child);
	void Clear();

	std::vector<LiveFanoutChild> SelectRecipients(
		LiveFanoutChild sender,
		const std::vector<LiveFanoutChild>& blocked,
		std::size_t limit) const;

	LiveFanoutReservation BeginDelivery(
		LiveFanoutChild child,
		std::uint32_t first_sequence,
		std::uint32_t last_sequence,
		std::uint64_t external_queued_bytes,
		std::uint64_t wire_bytes);
	bool BeginTransport(
		std::uint64_t token,
		LiveFanoutChild& child);
	bool CompleteDelivery(std::uint64_t token, bool sent);

	bool GetChildSnapshot(
		LiveFanoutChild child,
		LiveFanoutChildSnapshot& snapshot) const;
	std::size_t ChildCount() const;
	std::size_t ReservationCount() const;
	std::uint64_t PendingBytes() const;

private:
	struct ChildEntry {
		LiveFanoutChild child = 0u;
		std::uint64_t pending_bytes = 0u;
		std::size_t pending_deliveries = 0u;
		std::uint64_t completed_deliveries = 0u;
		std::uint64_t completed_bytes = 0u;
		std::uint64_t failed_deliveries = 0u;
		std::uint64_t backpressure_rejections = 0u;
	};

	struct ReservationEntry {
		std::uint64_t token = 0u;
		LiveFanoutChild child = 0u;
		std::uint32_t first_sequence = 0u;
		std::uint32_t last_sequence = 0u;
		std::uint64_t wire_bytes = 0u;
		bool transport_active = false;
	};

	std::vector<ChildEntry>::iterator FindChildLocked(
		LiveFanoutChild child);
	std::vector<ChildEntry>::const_iterator FindChildLocked(
		LiveFanoutChild child) const;
	std::uint64_t NextTokenLocked();
	bool HasActiveTransportLocked(LiveFanoutChild child) const;
	bool IsReplacementPausedLocked(LiveFanoutChild child) const;
	void FinishReplacementLocked();

	mutable std::mutex mutex_;
	std::condition_variable transport_idle_;
	std::vector<ChildEntry> children_;
	std::vector<ReservationEntry> reservations_;
	std::uint64_t next_token_;
	std::uint64_t next_replacement_token_;
	std::uint64_t replacement_token_;
	LiveFanoutChild replacement_previous_;
	LiveFanoutChild replacement_target_;
};

} // namespace live
} // namespace ese
