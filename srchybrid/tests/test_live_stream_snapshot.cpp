#include "../LiveStreamSnapshot.h"

#include <cstdint>
#include <iostream>
#include <limits>

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
	LiveStreamSnapshotInput input;
	input.broadcasting = true;
	input.emergency_mode = true;
	input.now_seconds = 105u;
	input.started_at = 100u;
	input.kad.kadConnected = true;
	input.view_peers = 2;
	input.broadcast_peers = 3;
	input.mesh_peers = 4;
	input.pending_requests = 5;
	input.chunks_served = 6;
	input.super_seeders = 1;
	input.middle_peers = 2;
	input.leaf_peers = 3;
	input.buffer_count = 3;
	input.oldest_sequence = 40u;
	input.newest_sequence = 44u;
	input.bitmap = 0x15u;
	input.total_redistributed = 0x100000002ull;
	input.minimum_upload_required = 700u;
	input.counters.chunksReceived = 9;

	const LiveDebugSnapshot snapshot = LiveStreamSnapshot::Build(input);
	Check(snapshot.broadcasting && !snapshot.viewing &&
		snapshot.emergencyMode && snapshot.uptimeMs == 5000u,
		"state and uptime projection are exact");
	Check(snapshot.kad.kadConnected &&
		snapshot.viewPeers == 2 && snapshot.broadcastPeers == 3 &&
		snapshot.meshPeers == 4 && snapshot.pendingRequests == 5 &&
		snapshot.chunksServed == 6,
		"Kad and peer projections are exact");
	Check(snapshot.superSeeders == 1 && snapshot.middlePeers == 2 &&
		snapshot.leafPeers == 3,
		"tier census projection is exact");
	Check(snapshot.bufCount == 3 && snapshot.oldestSeq == 40u &&
		snapshot.newestSeq == 44u && snapshot.bitmap == 0x15u &&
		snapshot.missingChunks == 2,
		"chunk gap projection is exact");
	Check(snapshot.totalRedistributed == 0x100000002ull &&
		snapshot.minUploadRequired == 700u &&
		snapshot.counters.chunksReceived == 9,
		"mesh and counter projection is exact");
	Check(snapshot.peerDetailCount == 0,
		"production snapshot never invents test-only peer detail");

	LiveStreamSnapshotInput empty;
	empty.buffer_count = 0;
	empty.oldest_sequence = 10u;
	empty.newest_sequence = 20u;
	Check(LiveStreamSnapshot::Build(empty).missingChunks == 0,
		"empty buffer has no inferred gap");

	LiveStreamSnapshotInput hostile_gap;
	hostile_gap.buffer_count = 1;
	hostile_gap.oldest_sequence = 1u;
	hostile_gap.newest_sequence =
		(std::numeric_limits<std::uint32_t>::max)() - 1u;
	Check(
		LiveStreamSnapshot::Build(hostile_gap).missingChunks ==
			(std::numeric_limits<int>::max)(),
		"hostile serial gap saturates without signed overflow");

	LiveStreamSnapshotInput wrapped;
	wrapped.started_at =
		(std::numeric_limits<std::uint32_t>::max)() - 1u;
	wrapped.now_seconds = 1u;
	Check(LiveStreamSnapshot::Build(wrapped).uptimeMs == 3000u,
		"uptime projection survives uint32 wrap");

	if (failures != 0)
		return 1;
	std::cout << "Live stream snapshot tests passed.\n";
	return 0;
}
