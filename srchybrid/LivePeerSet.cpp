#include "LivePeerSet.h"

#include <algorithm>

namespace ese {
namespace live {

std::vector<LivePeerHandle>& LivePeerSet::Peers(LivePeerRole role)
{
	return role == LivePeerRole::Source ? sources_ : downstream_;
}

const std::vector<LivePeerHandle>& LivePeerSet::Peers(LivePeerRole role) const
{
	return role == LivePeerRole::Source ? sources_ : downstream_;
}

LivePeerAddResult LivePeerSet::Add(
	LivePeerRole role,
	LivePeerHandle peer,
	std::size_t limit)
{
	if (peer == 0u)
		return LivePeerAddResult::Invalid;

	std::vector<LivePeerHandle>& peers = Peers(role);
	if (std::find(peers.begin(), peers.end(), peer) != peers.end())
		return LivePeerAddResult::AlreadyPresent;
	if (limit != 0u && peers.size() >= limit)
		return LivePeerAddResult::Full;

	peers.push_back(peer);
	return LivePeerAddResult::Added;
}

bool LivePeerSet::Replace(
	LivePeerRole role,
	LivePeerHandle previous,
	LivePeerHandle replacement)
{
	if (previous == 0u || replacement == 0u)
		return false;

	std::vector<LivePeerHandle>& peers = Peers(role);
	const auto previous_it = std::find(peers.begin(), peers.end(), previous);
	if (previous_it == peers.end())
		return false;
	if (previous == replacement)
		return true;

	const auto replacement_it =
		std::find(peers.begin(), peers.end(), replacement);
	if (replacement_it != peers.end()) {
		peers.erase(previous_it);
		return true;
	}

	*previous_it = replacement;
	return true;
}

bool LivePeerSet::Remove(LivePeerRole role, LivePeerHandle peer)
{
	if (peer == 0u)
		return false;

	std::vector<LivePeerHandle>& peers = Peers(role);
	const auto position = std::find(peers.begin(), peers.end(), peer);
	if (position == peers.end())
		return false;
	peers.erase(position);
	return true;
}

void LivePeerSet::Clear(LivePeerRole role)
{
	Peers(role).clear();
}

void LivePeerSet::ClearAll()
{
	sources_.clear();
	downstream_.clear();
}

bool LivePeerSet::Contains(
	LivePeerRole role,
	LivePeerHandle peer) const
{
	if (peer == 0u)
		return false;
	const std::vector<LivePeerHandle>& peers = Peers(role);
	return std::find(peers.begin(), peers.end(), peer) != peers.end();
}

bool LivePeerSet::Select(
	LivePeerRole role,
	std::size_t index,
	LivePeerHandle& peer) const
{
	peer = 0u;
	const std::vector<LivePeerHandle>& peers = Peers(role);
	if (index >= peers.size())
		return false;
	peer = peers[index];
	return true;
}

std::vector<LivePeerHandle> LivePeerSet::Snapshot(LivePeerRole role) const
{
	return Peers(role);
}

std::size_t LivePeerSet::Count(LivePeerRole role) const
{
	return Peers(role).size();
}

bool LivePeerSet::Empty(LivePeerRole role) const
{
	return Peers(role).empty();
}

LivePeerDiversityDecision
LivePeerSet::EvaluateIpv4SuperSeederDiversity(
	std::uint32_t candidate_ipv4,
	const std::uint32_t* existing_super_seeders,
	std::size_t existing_count)
{
	LivePeerDiversityDecision decision;
	decision.total_super_seeders = existing_count;
	if (existing_count != 0u && existing_super_seeders == nullptr)
		return decision;

	decision.allowed = true;
	decision.reason = LivePeerDiversityReason::Allowed;
	if (candidate_ipv4 == 0u)
		return decision;

	const std::uint32_t candidate_24 = candidate_ipv4 & 0xffffff00u;
	const std::uint32_t candidate_16 = candidate_ipv4 & 0xffff0000u;
	for (std::size_t index = 0u; index < existing_count; ++index) {
		const std::uint32_t address = existing_super_seeders[index];
		if ((address & 0xffffff00u) == candidate_24)
			++decision.same_subnet_24;
		if ((address & 0xffff0000u) == candidate_16)
			++decision.same_subnet_16;
	}

	if (decision.same_subnet_24 >= 5u) {
		decision.allowed = false;
		decision.reason = LivePeerDiversityReason::Subnet24Limit;
		return decision;
	}
	if (decision.total_super_seeders > 10u &&
		decision.same_subnet_16 > decision.total_super_seeders / 5u) {
		decision.allowed = false;
		decision.reason = LivePeerDiversityReason::Subnet16Ratio;
	}
	return decision;
}

} // namespace live
} // namespace ese
