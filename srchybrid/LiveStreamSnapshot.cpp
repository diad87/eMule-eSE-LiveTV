#include "LiveStreamSnapshot.h"

#include <algorithm>
#include <limits>

LiveStreamCounters::LiveStreamCounters() noexcept
	: kadPublishes(0)
	, kadSearches(0)
	, kadResultsAccepted(0)
	, kadResultsRejected(0)
	, sourceDialAttempts(0)
	, subscribeSent(0)
	, subscribeAccepted(0)
	, chunksRequested(0)
	, chunksReceived(0)
	, chunksMissing(0)
	, hlsSegmentsWritten(0)
	, hlsPlaylistRefresh(0)
	, peerDisconnects(0)
	, lastChunkReceivedAt(0)
	, skippedInitialPushes(0)
	, subscribesRateLimited(0)
	, requestsRateLimited(0)
	, endsRejectedNoAuth(0)
	, tombstonesEvicted(0)
	, kadSearchesEmpty(0)
	, kadSearchesRateLimited(0)
	, pendingDialsDropped(0)
	, joinToFirstChunkSamples(0)
	, joinToFirstChunkSumMs(0)
	, duplicateChunksReceived(0)
	, requestsSuppressedInflight(0)
{
}

LiveDebugSnapshot LiveStreamSnapshot::Build(
	const LiveStreamSnapshotInput& input) noexcept
{
	LiveDebugSnapshot snapshot;
	snapshot.broadcasting = input.broadcasting;
	snapshot.viewing = input.viewing;
	snapshot.emergencyMode = input.emergency_mode;
	snapshot.uptimeMs = input.started_at > 0u
		? (input.now_seconds - input.started_at) * 1000u : 0u;
	snapshot.kad = input.kad;
	snapshot.viewPeers = input.view_peers;
	snapshot.broadcastPeers = input.broadcast_peers;
	snapshot.meshPeers = input.mesh_peers;
	snapshot.pendingRequests = input.pending_requests;
	snapshot.chunksServed = input.chunks_served;
	snapshot.superSeeders = input.super_seeders;
	snapshot.middlePeers = input.middle_peers;
	snapshot.leafPeers = input.leaf_peers;
	snapshot.bufCount = input.buffer_count;
	snapshot.oldestSeq = input.oldest_sequence;
	snapshot.newestSeq = input.newest_sequence;
	snapshot.bitmap = input.bitmap;
	if (input.buffer_count > 0) {
		const std::uint32_t span =
			input.newest_sequence - input.oldest_sequence + 1u;
		const std::uint32_t bounded_count = static_cast<std::uint32_t>(
			(std::max)(input.buffer_count, 0));
		const std::uint32_t missing = span > bounded_count
			? span - bounded_count : 0u;
		snapshot.missingChunks = static_cast<int>(
			(std::min)(
				missing,
				static_cast<std::uint32_t>(
					(std::numeric_limits<int>::max)())));
	}
	snapshot.totalRedistributed = input.total_redistributed;
	snapshot.minUploadRequired = input.minimum_upload_required;
	snapshot.counters = input.counters;
	return snapshot;
}
