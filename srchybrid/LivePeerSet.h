#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace ese {
namespace live {

using LivePeerHandle = std::uintptr_t;

enum class LivePeerRole : std::uint8_t {
	Source = 0,
	Downstream = 1,
};

enum class LivePeerAddResult : std::uint8_t {
	Added = 0,
	AlreadyPresent = 1,
	Full = 2,
	Invalid = 3,
};

enum class LivePeerDiversityReason : std::uint8_t {
	Allowed = 0,
	Subnet24Limit = 1,
	Subnet16Ratio = 2,
	InvalidInput = 3,
};

struct LivePeerDiversityDecision {
	bool allowed = false;
	LivePeerDiversityReason reason = LivePeerDiversityReason::InvalidInput;
	std::size_t same_subnet_24 = 0u;
	std::size_t same_subnet_16 = 0u;
	std::size_t total_super_seeders = 0u;
};

class LivePeerSet final
{
public:
	LivePeerSet() = default;
	LivePeerSet(const LivePeerSet&) = delete;
	LivePeerSet& operator=(const LivePeerSet&) = delete;

	LivePeerAddResult Add(
		LivePeerRole role,
		LivePeerHandle peer,
		std::size_t limit);
	bool Replace(
		LivePeerRole role,
		LivePeerHandle previous,
		LivePeerHandle replacement);
	bool Remove(LivePeerRole role, LivePeerHandle peer);
	void Clear(LivePeerRole role);
	void ClearAll();

	bool Contains(LivePeerRole role, LivePeerHandle peer) const;
	bool Select(
		LivePeerRole role,
		std::size_t index,
		LivePeerHandle& peer) const;
	std::vector<LivePeerHandle> Snapshot(LivePeerRole role) const;
	std::size_t Count(LivePeerRole role) const;
	bool Empty(LivePeerRole role) const;

	LivePeerAddResult AddSource(
		LivePeerHandle peer,
		std::size_t limit = 0u)
	{
		return Add(LivePeerRole::Source, peer, limit);
	}
	LivePeerAddResult AddDownstream(
		LivePeerHandle peer,
		std::size_t limit = 0u)
	{
		return Add(LivePeerRole::Downstream, peer, limit);
	}
	bool RemoveSource(LivePeerHandle peer)
	{
		return Remove(LivePeerRole::Source, peer);
	}
	bool RemoveDownstream(LivePeerHandle peer)
	{
		return Remove(LivePeerRole::Downstream, peer);
	}
	void ClearSources() { Clear(LivePeerRole::Source); }
	void ClearDownstreams() { Clear(LivePeerRole::Downstream); }
	bool HasSource(LivePeerHandle peer) const
	{
		return Contains(LivePeerRole::Source, peer);
	}
	bool HasDownstream(LivePeerHandle peer) const
	{
		return Contains(LivePeerRole::Downstream, peer);
	}
	std::vector<LivePeerHandle> SourceSnapshot() const
	{
		return Snapshot(LivePeerRole::Source);
	}
	std::vector<LivePeerHandle> DownstreamSnapshot() const
	{
		return Snapshot(LivePeerRole::Downstream);
	}
	std::size_t SourceCount() const { return Count(LivePeerRole::Source); }
	std::size_t DownstreamCount() const
	{
		return Count(LivePeerRole::Downstream);
	}
	bool SourcesEmpty() const { return Empty(LivePeerRole::Source); }
	bool DownstreamsEmpty() const
	{
		return Empty(LivePeerRole::Downstream);
	}
	bool SelectSource(std::size_t index, LivePeerHandle& peer) const
	{
		return Select(LivePeerRole::Source, index, peer);
	}

	static LivePeerDiversityDecision EvaluateIpv4SuperSeederDiversity(
		std::uint32_t candidate_ipv4,
		const std::uint32_t* existing_super_seeders,
		std::size_t existing_count);

private:
	std::vector<LivePeerHandle>& Peers(LivePeerRole role);
	const std::vector<LivePeerHandle>& Peers(LivePeerRole role) const;

	std::vector<LivePeerHandle> sources_;
	std::vector<LivePeerHandle> downstream_;
};

} // namespace live
} // namespace ese
