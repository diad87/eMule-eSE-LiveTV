#include "../LiveStreamSecurity.h"

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

ese::live::LiveStreamKey StreamKey(std::uint32_t value)
{
	ese::live::LiveStreamKey key = {};
	key[0] = 1u;
	key[12] = static_cast<std::uint8_t>(value >> 24u);
	key[13] = static_cast<std::uint8_t>(value >> 16u);
	key[14] = static_cast<std::uint8_t>(value >> 8u);
	key[15] = static_cast<std::uint8_t>(value);
	return key;
}

ese::live::LivePublicKey PublicKey(std::uint32_t value)
{
	ese::live::LivePublicKey key = {};
	key[0] = 2u;
	key[28] = static_cast<std::uint8_t>(value >> 24u);
	key[29] = static_cast<std::uint8_t>(value >> 16u);
	key[30] = static_cast<std::uint8_t>(value >> 8u);
	key[31] = static_cast<std::uint8_t>(value);
	return key;
}

} // namespace

int main()
{
	using ese::live::LivePinResult;
	using ese::live::LiveReplayResult;
	using ese::live::LiveStreamSecurity;
	using ese::live::LiveTrustLevel;
	using ese::live::LiveTrustSnapshot;

	static_assert(!std::is_copy_constructible_v<LiveStreamSecurity>);
	static_assert(LiveStreamSecurity::kPinCapacity == 256u);
	static_assert(LiveStreamSecurity::kReplayWindowSequences == 64u);

	LiveStreamSecurity security;
	const auto stream = StreamKey(1u);
	const auto public_key = PublicKey(1u);
	Check(
		security.AcceptVerifiedSequence(stream, 1u) ==
			LiveReplayResult::UnpinnedStream,
		"unverified or unpinned input cannot poison replay state");
	Check(
		security.PinValidatedPublicKey(stream, public_key, 10u) ==
			LivePinResult::Pinned,
		"first validated public key is pinned");
	Check(
		security.PinValidatedPublicKey(stream, public_key, 11u) ==
			LivePinResult::AlreadyPinned,
		"same public key is idempotent");
	Check(
		security.PinValidatedPublicKey(stream, PublicKey(2u), 12u) ==
			LivePinResult::Conflict,
		"public key switch fails closed");
	ese::live::LivePublicKey copied = {};
	Check(
		security.GetPinnedPublicKey(stream, copied) && copied == public_key,
		"pinned key lookup returns an immutable value copy");

	Check(
		security.AcceptVerifiedSequence(stream, 10u) ==
			LiveReplayResult::Accepted,
		"first verified sequence is accepted");
	Check(
		security.AcceptVerifiedSequence(stream, 10u) ==
			LiveReplayResult::Duplicate,
		"exact verified replay is rejected");
	Check(
		security.AcceptVerifiedSequence(stream, 12u) ==
			LiveReplayResult::Accepted &&
			security.AcceptVerifiedSequence(stream, 11u) ==
				LiveReplayResult::Accepted &&
			security.AcceptVerifiedSequence(stream, 11u) ==
				LiveReplayResult::Duplicate,
		"bounded reorder is accepted once");
	Check(
		security.AcceptVerifiedSequence(stream, 100u) ==
			LiveReplayResult::Accepted &&
			security.AcceptVerifiedSequence(stream, 35u) ==
				LiveReplayResult::TooOld,
		"verified sequence outside replay window is rejected");

	security.Clear();
	const std::uint32_t maximum = std::numeric_limits<std::uint32_t>::max();
	Check(
		security.PinValidatedPublicKey(stream, public_key, 20u) ==
			LivePinResult::Pinned,
		"clear permits a fresh pin");
	for (const std::uint32_t sequence :
		{maximum - 1u, maximum, 0u, 1u}) {
		Check(
			security.AcceptVerifiedSequence(stream, sequence) ==
				LiveReplayResult::Accepted,
			"verified replay window accepts uint32 wrap");
	}
	Check(
		security.AcceptVerifiedSequence(stream, 0x80000001u) ==
			LiveReplayResult::AmbiguousSequence,
		"half-range serial ambiguity fails closed");

	security.Clear();
	for (std::uint32_t index = 0u;
		index < LiveStreamSecurity::kPinCapacity;
		++index) {
		Check(
			security.PinValidatedPublicKey(
				StreamKey(index), PublicKey(index), index) ==
				LivePinResult::Pinned,
			"pin capacity accepts every bounded slot");
	}
	Check(
		security.PinValidatedPublicKey(
			StreamKey(999u), PublicKey(999u), 999u) ==
			LivePinResult::CapacityExceeded,
		"pin capacity fails closed");
	Check(
		security.PinCount() == LiveStreamSecurity::kPinCapacity,
		"capacity rejection does not partially mutate state");

	LiveTrustSnapshot trust;
	trust.joined_at = 100u;
	Check(
		LiveStreamSecurity::EvaluateTrust(trust, 100u + 119999u, true) ==
			LiveTrustLevel::Leaf,
		"new peer remains leaf before the exact middle threshold");
	trust.requests_received = 10u;
	trust.requests_served = 9u;
	Check(
		LiveStreamSecurity::EvaluateTrust(trust, 100u + 120000u, true) ==
			LiveTrustLevel::Middle,
		"responsive peer reaches middle at the exact threshold");
	Check(
		LiveStreamSecurity::EvaluateTrust(trust, 100u + 300000u, true) ==
			LiveTrustLevel::SuperSeeder,
		"responsive peer reaches super-seeder with diversity approval");
	Check(
		LiveStreamSecurity::EvaluateTrust(trust, 100u + 300000u, false) ==
			LiveTrustLevel::Middle,
		"subnet diversity veto keeps a peer at middle");
	trust.requests_received = 11u;
	trust.requests_served = 2u;
	Check(
		LiveStreamSecurity::ShouldBan(trust, 100u + 120001u),
		"response rate below twenty percent after ten requests bans");
	trust.requests_received = 6u;
	trust.requests_served = 2u;
	Check(
		LiveStreamSecurity::ShouldDemote(trust, 100u + 120001u),
		"response rate below fifty percent after five requests demotes");
	Check(
		LiveStreamSecurity::ChargeFailure(9, 2) == 10 &&
			LiveStreamSecurity::RewardCriticalDelivery(10) == 9 &&
			LiveStreamSecurity::RewardCriticalDelivery(0) == 0,
		"failure charge is capped and critical reward cannot underflow");

	security.Clear();
	Check(
		security.PinValidatedPublicKey({}, public_key, 0u) ==
			LivePinResult::InvalidInput &&
			security.PinValidatedPublicKey(stream, {}, 0u) ==
				LivePinResult::InvalidInput,
		"zero identities fail closed");
	Check(
		security.PinValidatedPublicKey(stream, public_key, 1u) ==
			LivePinResult::Pinned,
		"concurrency fixture is pinned");
	std::atomic<int> accepted{0};
	std::atomic<int> duplicates{0};
	std::vector<std::thread> workers;
	for (int index = 0; index < 8; ++index) {
		workers.emplace_back([&security, &stream, &accepted, &duplicates]() {
			ese::live::LivePublicKey observed = {};
			if (!security.GetPinnedPublicKey(stream, observed))
				return;
			const LiveReplayResult result =
				security.AcceptVerifiedSequence(stream, 500u);
			if (result == LiveReplayResult::Accepted)
				++accepted;
			else if (result == LiveReplayResult::Duplicate)
				++duplicates;
		});
	}
	for (std::thread& worker : workers)
		worker.join();
	Check(
		accepted == 1 && duplicates == 7,
		"concurrent replay mutation accepts exactly one verified sequence");
	security.Clear();
	Check(
		security.PinCount() == 0u && security.ReplayStreamCount() == 0u,
		"clear atomically removes pins and replay state");

	if (failures != 0)
		return 1;
	std::cout << "live stream security tests: PASS\n";
	return 0;
}
