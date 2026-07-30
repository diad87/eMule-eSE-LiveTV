#include "../LiveStreamFanout.h"

#include <atomic>
#include <cstdint>
#include <iostream>
#include <limits>
#include <thread>
#include <type_traits>
#include <vector>

namespace {

int failures = 0;

void Check(bool condition, const char* message)
{
	if (!condition) {
		std::cerr << "FAIL: " << message << '\n';
		++failures;
	}
}

} // namespace

int main()
{
	using ese::live::LiveFanoutDeliveryResult;
	using ese::live::LiveFanoutRegisterResult;
	using ese::live::LiveStreamFanout;

	static_assert(!std::is_copy_constructible_v<LiveStreamFanout>);
	static_assert(LiveStreamFanout::kChildCapacity == 64u);
	static_assert(LiveStreamFanout::kReservationCapacity == 256u);
	static_assert(
		LiveStreamFanout::kPeerQueueLimitBytes == 8u * 1024u * 1024u);

	LiveStreamFanout fanout;
	for (std::uintptr_t child = 1u; child <= 5u; ++child) {
		Check(
			fanout.RegisterChild(child) ==
				LiveFanoutRegisterResult::Registered,
			"child registration succeeds within capacity");
	}
	const std::vector<std::uintptr_t> selected =
		fanout.SelectRecipients(2u, {4u}, 2u);
	Check(
		selected == std::vector<std::uintptr_t>({1u, 3u}),
		"selection preserves registration order and caps children not fragments");
	Check(
		fanout.RegisterChild(1u) ==
			LiveFanoutRegisterResult::AlreadyRegistered &&
			fanout.SelectRecipients(2u, {1u, 4u}, 8u) ==
				std::vector<std::uintptr_t>({3u, 5u}),
		"selection excludes sender, blocked and duplicate children");
	Check(
		fanout.SelectRecipients(0u, {}, 0u).empty(),
		"zero upload cap selects no recipients");

	const std::uint64_t limit = LiveStreamFanout::kPeerQueueLimitBytes;
	auto exact = fanout.BeginDelivery(1u, 10u, 12u, limit - 100u, 100u);
	Check(
		exact.IsReserved(),
		"exact whole-batch queue boundary is accepted");
	Check(
		fanout.CompleteDelivery(exact.token, true),
		"accepted whole batch completes once");
	auto beyond = fanout.BeginDelivery(1u, 13u, 13u, limit - 100u, 101u);
	Check(
		beyond.result == LiveFanoutDeliveryResult::Backpressured &&
			fanout.ReservationCount() == 0u,
		"one byte beyond the queue boundary is rejected atomically");
	Check(
		fanout.BeginDelivery(1u, 14u, 14u, 0u, limit + 1u).result ==
				LiveFanoutDeliveryResult::Backpressured &&
			fanout.BeginDelivery(
				1u, 15u, 15u,
				std::numeric_limits<std::uint64_t>::max(), 1u).result ==
				LiveFanoutDeliveryResult::Backpressured,
		"oversize and overflow-like queue inputs fail closed");

	auto pending = fanout.BeginDelivery(1u, 20u, 20u, 0u, 10u);
	Check(
		pending.IsReserved() &&
			fanout.BeginDelivery(1u, 20u, 20u, 0u, 10u).result ==
				LiveFanoutDeliveryResult::DuplicatePending &&
			fanout.ReservationCount() == 1u,
		"duplicate pending delivery is rejected");
	Check(
		fanout.CompleteDelivery(pending.token, false),
		"failed transport completion releases its reservation");

	std::vector<std::uint64_t> capacity_tokens;
	capacity_tokens.reserve(LiveStreamFanout::kReservationCapacity);
	for (std::uint32_t index = 0u;
		index < LiveStreamFanout::kReservationCapacity;
		++index) {
		auto reservation =
			fanout.BeginDelivery(1u, 1000u + index, 1000u + index, 0u, 1u);
		Check(
			reservation.IsReserved(),
			"reservation capacity accepts every bounded slot");
		if (reservation.IsReserved())
			capacity_tokens.push_back(reservation.token);
	}
	Check(
		fanout.BeginDelivery(1u, 9999u, 9999u, 0u, 1u).result ==
				LiveFanoutDeliveryResult::CapacityExceeded &&
			fanout.ReservationCount() ==
				LiveStreamFanout::kReservationCapacity &&
			fanout.PendingBytes() ==
				LiveStreamFanout::kReservationCapacity,
		"reservation capacity failure does not partially mutate state");
	for (const std::uint64_t token : capacity_tokens)
		Check(fanout.CompleteDelivery(token, true), "capacity token completes");

	Check(
		fanout.RegisterChild(40u) ==
			LiveFanoutRegisterResult::Registered,
		"replacement fixture registers");
	auto replaced = fanout.BeginDelivery(40u, 7u, 9u, 0u, 321u);
	ese::live::LiveFanoutChildSnapshot snapshot;
	Check(
		replaced.IsReserved() &&
			fanout.ReplaceChild(40u, 41u) &&
			!fanout.GetChildSnapshot(40u, snapshot) &&
			fanout.GetChildSnapshot(41u, snapshot) &&
			snapshot.pending_deliveries == 1u &&
			snapshot.pending_bytes == 321u &&
			fanout.CompleteDelivery(replaced.token, true),
		"replacement preserves pending delivery ownership");

	Check(
		fanout.RegisterChild(50u) ==
				LiveFanoutRegisterResult::Registered &&
			fanout.RegisterChild(51u) ==
				LiveFanoutRegisterResult::Registered,
		"slow and healthy child fixtures register");
	const auto slow =
		fanout.BeginDelivery(50u, 1u, 1u, limit, 1u);
	const auto healthy =
		fanout.BeginDelivery(51u, 1u, 1u, 0u, 1u);
	Check(
		slow.result == LiveFanoutDeliveryResult::Backpressured &&
			healthy.IsReserved() &&
			fanout.CompleteDelivery(healthy.token, true),
		"slow child does not block a healthy sibling");

	Check(
		fanout.RegisterChild(60u) ==
			LiveFanoutRegisterResult::Registered,
		"close fixture registers");
	auto closing = fanout.BeginDelivery(60u, 1u, 3u, 0u, 500u);
	Check(
		closing.IsReserved() &&
			fanout.ReleaseChild(60u) &&
			fanout.ReservationCount() == 0u &&
			!fanout.CompleteDelivery(closing.token, true) &&
			fanout.BeginDelivery(60u, 4u, 4u, 0u, 1u).result ==
				LiveFanoutDeliveryResult::UnknownChild,
		"release cancels pending work and rejects future delivery");

	fanout.Clear();
	Check(
		fanout.RegisterChild(88u) ==
			LiveFanoutRegisterResult::Registered,
		"concurrency fixture registers");
	std::atomic<bool> start{false};
	std::atomic<std::uint32_t> attempted{0u};
	std::atomic<std::uint32_t> reserved_count{0u};
	std::atomic<std::uint32_t> unknown_count{0u};
	std::vector<std::thread> workers;
	for (std::uint32_t worker = 0u; worker < 8u; ++worker) {
		workers.emplace_back(
			[&fanout, &start, &attempted, &reserved_count, &unknown_count,
				worker]() {
				while (!start.load(std::memory_order_acquire))
					std::this_thread::yield();
				for (std::uint32_t index = 0u; index < 1000u; ++index) {
					const std::uint32_t sequence =
						(worker << 20u) | index;
					auto reservation = fanout.BeginDelivery(
						88u, sequence, sequence, 0u, 1u);
					if (reservation.IsReserved()) {
						++reserved_count;
						fanout.CompleteDelivery(reservation.token, true);
					} else if (
						reservation.result ==
						LiveFanoutDeliveryResult::UnknownChild) {
						++unknown_count;
					}
					++attempted;
				}
			});
	}
	std::thread releaser(
		[&fanout, &start, &attempted]() {
			while (!start.load(std::memory_order_acquire))
				std::this_thread::yield();
			while (attempted.load(std::memory_order_acquire) < 100u)
				std::this_thread::yield();
			fanout.ReleaseChild(88u);
		});
	start.store(true, std::memory_order_release);
	for (std::thread& worker : workers)
		worker.join();
	releaser.join();
	Check(
		attempted == 8000u &&
			reserved_count + unknown_count == attempted &&
			fanout.ChildCount() == 0u &&
			fanout.ReservationCount() == 0u &&
			fanout.PendingBytes() == 0u,
		"concurrent reservation accounting remains bounded");

	fanout.RegisterChild(99u);
	auto final_pending = fanout.BeginDelivery(99u, 1u, 1u, 0u, 20u);
	Check(final_pending.IsReserved(), "clear fixture reserves");
	fanout.Clear();
	Check(
		fanout.ChildCount() == 0u &&
			fanout.ReservationCount() == 0u &&
			fanout.PendingBytes() == 0u,
		"clear reclaims every child and reservation");

	if (failures != 0)
		return 1;
	std::cout << "live stream fanout tests: PASS\n";
	return 0;
}
