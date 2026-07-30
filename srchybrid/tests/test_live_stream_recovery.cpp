#include "../LiveStreamRecovery.h"

#include <cstdint>
#include <iostream>
#include <limits>
#include <type_traits>
#include <vector>

namespace {

int failures = 0;

void Check(const bool condition, const char* const message)
{
	if (!condition) {
		std::cerr << "FAIL: " << message << '\n';
		++failures;
	}
}

} // namespace

int main()
{
	using ese::live::LiveEmergencyTransition;
	using ese::live::LiveMissingProbeResult;
	using ese::live::LiveRecoveryEndpoint;
	using ese::live::LiveStreamRecovery;

	static_assert(!std::is_copy_constructible_v<LiveStreamRecovery>);
	static_assert(LiveStreamRecovery::kInflightCapacity == 64u);

	const LiveRecoveryEndpoint ipv4 =
		LiveRecoveryEndpoint::FromText(4u, "203.0.113.10", 4662u);
	const LiveRecoveryEndpoint ipv6 =
		LiveRecoveryEndpoint::FromText(6u, "2001:db8::1", 4662u);
	Check(ipv4.IsValid() && ipv6.IsValid() && ipv4 != ipv6,
		"typed IPv4 and IPv6 recovery endpoints are bounded and distinct");
	Check(!LiveRecoveryEndpoint::FromText(4u, "", 4662u).IsValid() &&
		!LiveRecoveryEndpoint::FromText(4u, "203.0.113.10", 0u).IsValid(),
		"invalid recovery endpoints fail closed");

	LiveStreamRecovery recovery;
	Check(recovery.RecordRequest(10u, 100u, ipv4, 1u, true),
		"first missing segment request is recorded");
	Check(recovery.InspectMissing(10u, 4099u).result ==
			LiveMissingProbeResult::Suppressed,
		"in-flight request is suppressed before its exact deadline");
	const auto retry = recovery.InspectMissing(10u, 4100u);
	Check(retry.result == LiveMissingProbeResult::Retry &&
		retry.previous_endpoint == ipv4 && retry.attempts == 1u &&
		retry.charge_previous_failure,
		"timed-out edge request rotates away and charges exactly once");
	Check(!recovery.InspectMissing(10u, 4101u).charge_previous_failure,
		"repeated inspection never double-charges a timed-out request");
	Check(recovery.RecordRequest(10u, 4101u, ipv6, 2u, true),
		"retry atomically replaces the in-flight endpoint");
	bool critical = false;
	Check(recovery.CompleteRequest(10u, critical) && critical &&
		recovery.InflightCount() == 0u,
		"completion returns edge classification and removes ownership");

	for (std::uint32_t index = 0u;
		index < LiveStreamRecovery::kInflightCapacity;
		++index) {
		Check(recovery.RecordRequest(
			100u + index, 1u, ipv4, 1u, false),
			"bounded in-flight table accepts every slot");
	}
	Check(!recovery.RecordRequest(999u, 1u, ipv4, 1u, false) &&
		recovery.InflightCount() == LiveStreamRecovery::kInflightCapacity,
		"in-flight capacity failure is atomic");
	Check(LiveStreamRecovery::NextAttempt(
			std::numeric_limits<std::uint32_t>::max()) ==
			std::numeric_limits<std::uint32_t>::max(),
		"request attempt counter saturates without wrapping");
	recovery.PruneRequests({100u, 101u}, true, 130u);
	Check(recovery.InflightCount() == 34u,
		"pruning removes present and obsolete requests");

	recovery.Reset();
	const std::uint32_t near_wrap = 0xFFFFFF00u;
	Check(recovery.RecordRequest(
		std::numeric_limits<std::uint32_t>::max(), near_wrap, ipv4, 1u, false),
		"wrapped sequence request is accepted");
	Check(recovery.InspectMissing(
		std::numeric_limits<std::uint32_t>::max(),
		near_wrap + LiveStreamRecovery::kInflightTimeoutMs).result ==
			LiveMissingProbeResult::Retry,
		"in-flight deadline survives uint32 clock wrap");
	recovery.PruneRequests({}, true,
		std::numeric_limits<std::uint32_t>::max());
	Check(recovery.InflightCount() == 1u,
		"current uint32-max request is retained at the wrap boundary");
	recovery.PruneRequests({}, true, 0u);
	Check(recovery.InflightCount() == 0u,
		"wrapped obsolete sequence is eventually pruned");

	recovery.Reset();
	recovery.OnSourceLost(1000u, 2u);
	Check(recovery.IsPeerRefreshPending() &&
		!recovery.ShouldRequestPeers(2999u, 2u) &&
		recovery.ShouldRequestPeers(3000u, 2u) &&
		!recovery.ShouldRequestPeers(3001u, 2u),
		"source replenishment observes grace and cooldown");
	Check(recovery.TakePeerCandidate(3u) == 0u &&
		recovery.TakePeerCandidate(3u) == 1u &&
		recovery.TakePeerCandidate(3u) == 2u &&
		recovery.TakePeerCandidate(3u) == 0u,
		"source replenishment rotates candidates deterministically");
	recovery.Reset();
	recovery.OnSourceLost(near_wrap, 1u);
	Check(!recovery.ShouldRequestPeers(
		near_wrap + LiveStreamRecovery::kPeerLossGraceMs - 1u, 1u) &&
		recovery.ShouldRequestPeers(
			near_wrap + LiveStreamRecovery::kPeerLossGraceMs, 1u),
		"source-loss grace survives uint32 clock wrap");

	recovery.Reset();
	Check(recovery.ObservePeerHealth(100u, 10u, 5u, 25u, 1000u) ==
			LiveEmergencyTransition::Entered &&
		recovery.IsEmergencyMode(),
		"drop threshold enters emergency mode once");
	Check(recovery.ObservePeerHealth(1100u, 0u, 0u, 25u, 1000u) ==
			LiveEmergencyTransition::None,
		"emergency remains active through its exact duration");
	Check(recovery.ObservePeerHealth(1101u, 0u, 0u, 25u, 1000u) ==
			LiveEmergencyTransition::Exited &&
		!recovery.IsEmergencyMode(),
		"emergency exits even after every super-seeder disappears");

	Check(!LiveStreamRecovery::ShouldSendNack(3000u, 0u, 0u) &&
		LiveStreamRecovery::ShouldSendNack(3001u, 0u, 0u) &&
		!LiveStreamRecovery::ShouldSendNack(5000u, 0u, 3001u) &&
		LiveStreamRecovery::ShouldSendNack(5002u, 0u, 3001u),
		"NACK initial delay and cooldown use strict wire-compatible boundaries");
	const auto missing = LiveStreamRecovery::MissingFecBlocks(
		std::vector<std::uint8_t>(20u, 4u),
		std::vector<std::uint8_t>(20u, 3u));
	Check(missing.size() == LiveStreamRecovery::kMissingBlockCapacity &&
		missing.front() == 0u && missing.back() == 15u,
		"missing FEC block plan is ordered and capped");
	Check(LiveStreamRecovery::MissingFecBlocks({1u}, {}).empty(),
		"mismatched FEC observations fail closed");

	auto parity = LiveStreamRecovery::AdvanceParity(3u, 0u, 10000u);
	Check(parity.reset_window && parity.parity == 2u,
		"quiet FEC window reduces parity to its floor");
	parity = LiveStreamRecovery::AdvanceParity(2u, 2u, 10000u);
	Check(parity.parity == 3u,
		"light NACK pressure restores default parity");
	parity = LiveStreamRecovery::AdvanceParity(8u, 100u, 10000u);
	Check(parity.parity == 8u,
		"heavy NACK pressure saturates without overflow");
	parity = LiveStreamRecovery::AdvanceParity(255u, 0u, 9999u);
	Check(!parity.reset_window && parity.parity == 3u,
		"invalid parity is normalized before the next window");

	if (failures == 0)
		std::cout << "Live stream recovery tests passed.\n";
	return failures == 0 ? 0 : 1;
}
