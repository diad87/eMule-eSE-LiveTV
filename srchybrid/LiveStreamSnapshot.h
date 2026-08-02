#pragma once

#include <Windows.h>

#include <cstdint>

struct LiveStreamCounters {
	LONG kadPublishes;
	LONG kadSearches;
	LONG kadResultsAccepted;
	LONG kadResultsRejected;
	LONG sourceDialAttempts;
	LONG subscribeSent;
	LONG subscribeAccepted;
	LONG chunksRequested;
	LONG chunksReceived;
	LONG chunksMissing;
	LONG hlsSegmentsWritten;
	LONG hlsPlaylistRefresh;
	LONG peerDisconnects;
	LONG lastChunkReceivedAt;
	LONG skippedInitialPushes;
	LONG subscribesRateLimited;
	LONG requestsRateLimited;
	LONG endsRejectedNoAuth;
	LONG tombstonesEvicted;
	LONG kadSearchesEmpty;
	LONG kadSearchesRateLimited;
	LONG pendingDialsDropped;
	LONG joinToFirstChunkSamples;
	LONG joinToFirstChunkSumMs;
	LONG duplicateChunksReceived;
	LONG requestsSuppressedInflight;

	LiveStreamCounters() noexcept;
};

struct KadDebugSnapshot {
	bool kadConnected = false;
	int knownStreams = 0;
	DWORD lastPublishTime = 0u;
	DWORD lastSearchTime = 0u;
	DWORD lastResultTime = 0u;
	std::uint32_t lastResultIP = 0u;
	std::uint16_t lastResultPort = 0u;
	int knownStreamsClean = 0;
	int knownStreamsLegacy = 0;
};

struct LiveDebugSnapshot {
	struct PeerDbg {
		char ip[46] = {};
		std::uint16_t port = 0u;
		int level = 0;
		int failCount = 0;
		int respPct = 0;
		std::uint32_t rttMs = 0u;
	};
	static constexpr int MAX_PEER_DBG = 16;

	bool broadcasting = false;
	bool viewing = false;
	bool emergencyMode = false;
	std::uint32_t uptimeMs = 0u;
	KadDebugSnapshot kad;
	int viewPeers = 0;
	int broadcastPeers = 0;
	int meshPeers = 0;
	int pendingRequests = 0;
	int chunksServed = 0;
	int superSeeders = 0;
	int middlePeers = 0;
	int leafPeers = 0;
	int bufCount = 0;
	std::uint32_t oldestSeq = 0u;
	std::uint32_t newestSeq = 0u;
	std::uint16_t bitmap = 0u;
	int missingChunks = 0;
	std::uint64_t totalRedistributed = 0u;
	std::uint32_t minUploadRequired = 0u;
	PeerDbg peerDetail[MAX_PEER_DBG];
	int peerDetailCount = 0;
	LiveStreamCounters counters;
};

struct LiveStreamSnapshotInput {
	bool broadcasting = false;
	bool viewing = false;
	bool emergency_mode = false;
	std::uint32_t now_seconds = 0u;
	std::uint32_t started_at = 0u;
	KadDebugSnapshot kad;
	int view_peers = 0;
	int broadcast_peers = 0;
	int mesh_peers = 0;
	int pending_requests = 0;
	int chunks_served = 0;
	int super_seeders = 0;
	int middle_peers = 0;
	int leaf_peers = 0;
	int buffer_count = 0;
	std::uint32_t oldest_sequence = 0u;
	std::uint32_t newest_sequence = 0u;
	std::uint16_t bitmap = 0u;
	std::uint64_t total_redistributed = 0u;
	std::uint32_t minimum_upload_required = 0u;
	LiveStreamCounters counters;
};

class LiveStreamSnapshot final {
public:
	static LiveDebugSnapshot Build(
		const LiveStreamSnapshotInput& input) noexcept;

private:
	LiveStreamSnapshot() = delete;
};
