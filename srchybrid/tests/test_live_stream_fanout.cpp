#include "../LiveStreamFanout.h"

#include <atomic>
#include <chrono>
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

	LiveStreamFanout child_capacity;
	for (std::uintptr_t child = 1u;
		child <= LiveStreamFanout::kChildCapacity;
		++child) {
		Check(
			child_capacity.RegisterChild(child) ==
				LiveFanoutRegisterResult::Registered,
			"child capacity accepts every bounded slot");
	}
	Check(
		child_capacity.RegisterChild(999u) ==
				LiveFanoutRegisterResult::CapacityExceeded &&
			child_capacity.ChildCount() ==
				LiveStreamFanout::kChildCapacity,
		"child capacity failure does not partially mutate state");

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
	auto wrapped = fanout.BeginDelivery(
		1u, std::numeric_limits<std::uint32_t>::max(), 0u, 0u, 1u);
	Check(
		wrapped.IsReserved() &&
			fanout.CompleteDelivery(wrapped.token, true),
		"whole-batch identity accepts uint32 sequence wrap");

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
	ese::live::LiveFanoutChild replacement_target = 0u;
	Check(
		replaced.IsReserved() &&
			fanout.ReplaceChild(40u, 41u) &&
			!fanout.GetChildSnapshot(40u, snapshot) &&
			fanout.GetChildSnapshot(41u, snapshot) &&
			snapshot.pending_deliveries == 1u &&
			snapshot.pending_bytes == 321u &&
			fanout.BeginTransport(
				replaced.token, replacement_target) &&
			replacement_target == 41u &&
			fanout.CompleteDelivery(replaced.token, true),
		"replacement retargets and preserves pending delivery ownership");

	LiveStreamFanout collision;
	for (std::uintptr_t child : {101u, 102u, 103u})
		collision.RegisterChild(child);
	auto prior_pending =
		collision.BeginDelivery(101u, 10u, 10u, 0u, 10u);
	auto replacement_pending =
		collision.BeginDelivery(103u, 11u, 11u, 0u, 11u);
	ese::live::LiveFanoutChild collision_target = 0u;
	Check(
		prior_pending.IsReserved() &&
			replacement_pending.IsReserved() &&
			collision.ReplaceChild(101u, 103u) &&
			collision.SelectRecipients(0u, {}, 3u) ==
				std::vector<std::uintptr_t>({103u, 102u}) &&
			collision.ChildCount() == 2u &&
			collision.BeginTransport(
				prior_pending.token, collision_target) &&
			collision_target == 103u &&
			collision.CompleteDelivery(prior_pending.token, true) &&
			collision.CompleteDelivery(
				replacement_pending.token, true),
		"collision replacement preserves canonical order and retargets work");

	LiveStreamFanout duplicate_collision;
	duplicate_collision.RegisterChild(201u);
	duplicate_collision.RegisterChild(202u);
	auto canceled_duplicate =
		duplicate_collision.BeginDelivery(201u, 1u, 1u, 0u, 1u);
	auto retained_duplicate =
		duplicate_collision.BeginDelivery(202u, 1u, 1u, 0u, 1u);
	ese::live::LiveFanoutChild canceled_target = 0u;
	Check(
		canceled_duplicate.IsReserved() &&
			retained_duplicate.IsReserved() &&
			duplicate_collision.ReplaceChild(201u, 202u) &&
			duplicate_collision.ReservationCount() == 1u &&
			!duplicate_collision.BeginTransport(
				canceled_duplicate.token, canceled_target) &&
			duplicate_collision.BeginTransport(
				retained_duplicate.token, canceled_target) &&
			canceled_target == 202u &&
			duplicate_collision.CompleteDelivery(
				retained_duplicate.token, true),
		"collision replacement cancels duplicate pending identity");

	LiveStreamFanout bounded_collision;
	bounded_collision.RegisterChild(301u);
	bounded_collision.RegisterChild(302u);
	auto canceled_overflow = bounded_collision.BeginDelivery(
		301u, 1u, 1u, 0u, 1u);
	auto retained_limit = bounded_collision.BeginDelivery(
		302u, 2u, 2u, 0u, limit);
	ese::live::LiveFanoutChild bounded_target = 0u;
	Check(
		canceled_overflow.IsReserved() &&
			retained_limit.IsReserved() &&
			bounded_collision.ReplaceChild(301u, 302u) &&
			bounded_collision.ReservationCount() == 1u &&
			bounded_collision.PendingBytes() == limit &&
			!bounded_collision.BeginTransport(
				canceled_overflow.token, bounded_target) &&
			bounded_collision.BeginTransport(
				retained_limit.token, bounded_target) &&
			bounded_target == 302u &&
			bounded_collision.CompleteDelivery(
				retained_limit.token, true),
		"collision replacement cancels work beyond the peer queue limit");

	LiveStreamFanout external_collision;
	external_collision.RegisterChild(401u);
	external_collision.RegisterChild(402u);
	auto external_collision_pending =
		external_collision.BeginDelivery(401u, 1u, 1u, 0u, 1u);
	Check(
		external_collision_pending.IsReserved() &&
			external_collision.ReplaceChild(401u, 402u, limit) &&
			external_collision.ReservationCount() == 0u &&
			external_collision.PendingBytes() == 0u &&
			!external_collision.BeginTransport(
				external_collision_pending.token, bounded_target),
		"collision replacement includes destination socket queue headroom");

	LiveStreamFanout external_replacement;
	external_replacement.RegisterChild(403u);
	auto external_replacement_pending =
		external_replacement.BeginDelivery(403u, 1u, 1u, 0u, 1u);
	Check(
		external_replacement_pending.IsReserved() &&
			external_replacement.ReplaceChild(403u, 404u, limit) &&
			external_replacement.ReservationCount() == 0u &&
			external_replacement.PendingBytes() == 0u &&
			!external_replacement.BeginTransport(
				external_replacement_pending.token, bounded_target),
		"noncollision replacement includes destination socket queue headroom");

	LiveStreamFanout quiesced_collision;
	quiesced_collision.RegisterChild(501u);
	quiesced_collision.RegisterChild(502u);
	auto quiesced_prior =
		quiesced_collision.BeginDelivery(501u, 1u, 1u, 0u, 1u);
	auto quiesced_active =
		quiesced_collision.BeginDelivery(502u, 2u, 2u, 0u, 1u);
	ese::live::LiveFanoutChild quiesced_target = 0u;
	std::atomic<bool> replacement_began{false};
	std::atomic<bool> allow_replacement_commit{false};
	std::atomic<bool> replacement_committed{false};
	Check(
		quiesced_prior.IsReserved() &&
			quiesced_active.IsReserved() &&
			quiesced_collision.BeginTransport(
				quiesced_active.token, quiesced_target),
		"quiesced replacement fixture owns destination transport");
	std::thread replacement_thread(
		[&quiesced_collision, &replacement_began,
			&allow_replacement_commit, &replacement_committed, limit]() {
			if (!quiesced_collision.BeginChildReplacement(501u, 502u))
				return;
			replacement_began.store(true, std::memory_order_release);
			while (!allow_replacement_commit.load(
				std::memory_order_acquire))
				std::this_thread::yield();
			replacement_committed.store(
				quiesced_collision.CommitChildReplacement(
					501u, 502u, limit),
				std::memory_order_release);
		});
	while (!quiesced_collision.SelectRecipients(0u, {}, 2u).empty())
		std::this_thread::yield();
	std::atomic<bool> quiesced_release_finished{false};
	std::thread quiesced_release(
		[&quiesced_collision, &quiesced_release_finished]() {
			quiesced_collision.ReleaseChild(502u);
			quiesced_release_finished.store(
				true, std::memory_order_release);
		});
	std::this_thread::sleep_for(std::chrono::milliseconds(20));
	Check(
		!replacement_began.load(std::memory_order_acquire) &&
			!quiesced_release_finished.load(std::memory_order_acquire),
		"replacement and release wait for active destination transport");
	Check(
		quiesced_collision.CompleteDelivery(
			quiesced_active.token, true),
		"active destination completion unblocks replacement capture");
	while (!replacement_began.load(std::memory_order_acquire))
		std::this_thread::yield();
	Check(
		!quiesced_release_finished.load(std::memory_order_acquire),
		"release stays blocked while replacement queue capture is paused");
	allow_replacement_commit.store(true, std::memory_order_release);
	replacement_thread.join();
	quiesced_release.join();
	Check(
		replacement_committed.load(std::memory_order_acquire) &&
			quiesced_release_finished.load(std::memory_order_acquire) &&
			quiesced_collision.ChildCount() == 0u,
		"quiesced replacement commits before release removes destination");

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

	LiveStreamFanout leased;
	leased.RegisterChild(70u);
	auto leased_delivery =
		leased.BeginDelivery(70u, 1u, 1u, 0u, 10u);
	ese::live::LiveFanoutChild leased_target = 0u;
	std::atomic<bool> release_started{false};
	std::atomic<bool> release_finished{false};
	Check(
		leased_delivery.IsReserved() &&
			leased.BeginTransport(
				leased_delivery.token, leased_target) &&
			leased_target == 70u,
		"transport lease resolves a live child");
	std::thread closing_thread(
		[&leased, &release_started, &release_finished]() {
			release_started.store(true, std::memory_order_release);
			leased.ReleaseChild(70u);
			release_finished.store(true, std::memory_order_release);
		});
	while (!release_started.load(std::memory_order_acquire))
		std::this_thread::yield();
	std::this_thread::sleep_for(std::chrono::milliseconds(20));
	Check(
		!release_finished.load(std::memory_order_acquire),
		"release waits while transport owns the child lifetime");
	Check(
		leased.CompleteDelivery(leased_delivery.token, true),
		"transport completion releases the child lifetime");
	closing_thread.join();
	Check(
		release_finished.load(std::memory_order_acquire) &&
			leased.ChildCount() == 0u,
		"release completes after transport becomes idle");

	LiveStreamFanout double_release;
	double_release.RegisterChild(71u);
	auto double_delivery =
		double_release.BeginDelivery(71u, 1u, 1u, 0u, 10u);
	ese::live::LiveFanoutChild double_target = 0u;
	std::atomic<std::uint32_t> release_waiters{0u};
	std::atomic<std::uint32_t> release_successes{0u};
	Check(
		double_delivery.IsReserved() &&
			double_release.BeginTransport(
				double_delivery.token, double_target),
		"double release fixture owns an active transport");
	auto release_worker = [&double_release, &release_waiters,
		&release_successes]() {
		release_waiters.fetch_add(1u, std::memory_order_release);
		if (double_release.ReleaseChild(71u))
			release_successes.fetch_add(1u, std::memory_order_release);
	};
	std::thread first_release(release_worker);
	std::thread second_release(release_worker);
	while (release_waiters.load(std::memory_order_acquire) != 2u)
		std::this_thread::yield();
	std::this_thread::sleep_for(std::chrono::milliseconds(20));
	Check(
		double_release.CompleteDelivery(double_delivery.token, true),
		"double release fixture completes its transport");
	first_release.join();
	second_release.join();
	Check(
		release_successes.load(std::memory_order_acquire) == 1u &&
			double_release.ChildCount() == 0u,
		"concurrent release waiters revalidate child after wake");

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
