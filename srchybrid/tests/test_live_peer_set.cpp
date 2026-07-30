#include "../LivePeerSet.h"

#include <cstdint>
#include <iostream>
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
	using ese::live::LivePeerAddResult;
	using ese::live::LivePeerDiversityDecision;
	using ese::live::LivePeerDiversityReason;
	using ese::live::LivePeerRole;
	using ese::live::LivePeerSet;

	static_assert(!std::is_copy_constructible_v<LivePeerSet>);
	static_assert(!std::is_copy_assignable_v<LivePeerSet>);

	LivePeerSet peers;
	Check(peers.Empty(LivePeerRole::Source), "sources start empty");
	Check(peers.Empty(LivePeerRole::Downstream), "downstreams start empty");
	Check(
		peers.Add(LivePeerRole::Source, 0u, 0u) ==
			LivePeerAddResult::Invalid,
		"zero handle is invalid");
	Check(
		peers.Add(LivePeerRole::Source, 11u, 2u) ==
			LivePeerAddResult::Added,
		"first source is added");
	Check(
		peers.Add(LivePeerRole::Source, 12u, 2u) ==
			LivePeerAddResult::Added,
		"second source is added");
	Check(
		peers.Add(LivePeerRole::Source, 13u, 2u) ==
			LivePeerAddResult::Full,
		"source cap rejects without partial state");
	Check(
		peers.Add(LivePeerRole::Source, 11u, 2u) ==
			LivePeerAddResult::AlreadyPresent &&
			peers.Count(LivePeerRole::Source) == 2u,
		"duplicate is idempotent even when the set is full");
	Check(
		peers.Add(LivePeerRole::Downstream, 11u, 0u) ==
			LivePeerAddResult::Added &&
			peers.Contains(LivePeerRole::Source, 11u) &&
			peers.Contains(LivePeerRole::Downstream, 11u),
		"one handle may independently occupy both roles");

	std::uintptr_t selected = 0u;
	Check(
		peers.Select(LivePeerRole::Source, 0u, selected) && selected == 11u,
		"selection preserves insertion order");
	Check(
		peers.Select(LivePeerRole::Source, 1u, selected) && selected == 12u,
		"second selection is stable");
	Check(
		!peers.Select(LivePeerRole::Source, 2u, selected) && selected == 0u,
		"out-of-range selection fails closed");

	Check(
		peers.Replace(LivePeerRole::Source, 11u, 21u) &&
			peers.Select(LivePeerRole::Source, 0u, selected) &&
			selected == 21u,
		"replacement preserves the original position");
	Check(
		peers.Replace(LivePeerRole::Source, 21u, 12u) &&
			peers.Count(LivePeerRole::Source) == 1u &&
			peers.Select(LivePeerRole::Source, 0u, selected) &&
			selected == 12u,
		"replacement by an existing handle removes the old duplicate");
	peers.Add(LivePeerRole::Source, 31u, 0u);
	peers.Add(LivePeerRole::Source, 32u, 0u);
	Check(
		peers.Replace(LivePeerRole::Source, 32u, 12u) &&
			peers.Count(LivePeerRole::Source) == 2u &&
			peers.Select(LivePeerRole::Source, 1u, selected) &&
			selected == 12u,
		"existing replacement keeps the replaced handle's position");
	Check(
		!peers.Replace(LivePeerRole::Source, 99u, 31u) &&
			peers.Count(LivePeerRole::Source) == 2u,
		"missing replacement source cannot mutate the set");

	Check(
		peers.Remove(LivePeerRole::Downstream, 11u) &&
			!peers.Remove(LivePeerRole::Downstream, 11u),
		"remove is exact and idempotent");
	peers.Clear(LivePeerRole::Source);
	Check(peers.Empty(LivePeerRole::Source), "role clear removes every source");

	std::vector<std::uint32_t> superIps = {
		0x0a000001u, 0x0a000002u, 0x0a000003u, 0x0a000004u
	};
	LivePeerDiversityDecision diversity =
		LivePeerSet::EvaluateIpv4SuperSeederDiversity(
			0x0a0000feu, superIps.data(), superIps.size());
	Check(
		diversity.allowed &&
			diversity.same_subnet_24 == 4u &&
			diversity.reason == LivePeerDiversityReason::Allowed,
		"four existing peers in one /24 remain allowed");
	superIps.push_back(0x0a000005u);
	diversity = LivePeerSet::EvaluateIpv4SuperSeederDiversity(
		0x0a0000feu, superIps.data(), superIps.size());
	Check(
		!diversity.allowed &&
			diversity.reason == LivePeerDiversityReason::Subnet24Limit,
		"five existing peers in one /24 block promotion");

	superIps = {
		0x0a010001u, 0x0a010101u, 0x0a010201u,
		0x0b000001u, 0x0c000001u, 0x0d000001u,
		0x0e000001u, 0x0f000001u, 0x10000001u,
		0x11000001u, 0x12000001u
	};
	diversity = LivePeerSet::EvaluateIpv4SuperSeederDiversity(
		0x0a01ff01u, superIps.data(), superIps.size());
	Check(
		!diversity.allowed &&
			diversity.total_super_seeders == 11u &&
			diversity.same_subnet_16 == 3u &&
			diversity.reason == LivePeerDiversityReason::Subnet16Ratio,
		"legacy greater-than 20 percent /16 rule is preserved");
	diversity = LivePeerSet::EvaluateIpv4SuperSeederDiversity(
		0u, superIps.data(), superIps.size());
	Check(diversity.allowed, "unknown IPv4 remains compatible and allowed");
	diversity = LivePeerSet::EvaluateIpv4SuperSeederDiversity(
		0x0a01ff01u, nullptr, 1u);
	Check(
		!diversity.allowed &&
			diversity.reason == LivePeerDiversityReason::InvalidInput,
		"nonzero count with null census fails closed");

	if (failures != 0)
		return 1;
	std::cout << "live peer set tests: PASS\n";
	return 0;
}
