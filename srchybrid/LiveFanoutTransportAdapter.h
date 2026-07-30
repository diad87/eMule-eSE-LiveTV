#pragma once

#include "LivePeerSet.h"
#include "LiveStreamFanout.h"

#include <cstdint>
#include <vector>

class Packet;
class CUpDownClient;
struct LiveChunk;

struct LiveFanoutPacketBatch final {
	LiveFanoutPacketBatch() = default;
	~LiveFanoutPacketBatch();
	LiveFanoutPacketBatch(const LiveFanoutPacketBatch&) = delete;
	LiveFanoutPacketBatch& operator=(const LiveFanoutPacketBatch&) = delete;
	LiveFanoutPacketBatch(LiveFanoutPacketBatch&& other) noexcept;
	LiveFanoutPacketBatch& operator=(LiveFanoutPacketBatch&& other) noexcept;

	ese::live::LiveFanoutChild child = 0u;
	ese::live::LiveStreamFanout* owner = nullptr;
	std::uint64_t reservation_token = 0u;
	std::uint32_t payload_bytes = 0u;
	std::vector<Packet*> packets;

	bool IsReserved() const { return reservation_token != 0u; }
	void Reset() noexcept;
};

class LiveStreamFanoutAdapter final
{
public:
	static bool RegisterChild(
		ese::live::LiveStreamFanout& fanout,
		ese::live::LivePeerSet& peers,
		ese::live::LiveFanoutChild child,
		std::size_t limit);
	static bool ReplaceChild(
		ese::live::LiveStreamFanout& fanout,
		ese::live::LivePeerSet& peers,
		ese::live::LiveFanoutChild previous,
		ese::live::LiveFanoutChild replacement);
	static bool ReleaseChild(
		ese::live::LiveStreamFanout& fanout,
		ese::live::LivePeerSet& peers,
		ese::live::LiveFanoutChild child);

	static ese::live::LiveFanoutDeliveryResult ReservePackets(
		ese::live::LiveStreamFanout& fanout,
		ese::live::LiveFanoutChild child,
		std::uint32_t first_sequence,
		std::uint32_t last_sequence,
		std::uint32_t payload_bytes,
		std::vector<Packet*>& packets,
		LiveFanoutPacketBatch& batch);

	static void PrepareRelayBatches(
		ese::live::LiveStreamFanout& fanout,
		ese::live::LiveFanoutChild sender,
		const std::vector<ese::live::LiveFanoutChild>& blocked,
		std::size_t limit,
		const LiveChunk& chunk,
		std::vector<LiveFanoutPacketBatch>& batches);

	static bool SendReserved(
		ese::live::LiveStreamFanout& fanout,
		LiveFanoutPacketBatch& batch);
	// Caller must serialize LivePeerSet membership for the returned pointer's
	// entire use (CLiveStreamManager does so with m_lock).
	static CUpDownClient* ResolveDeliveredChild(
		const ese::live::LivePeerSet& peers,
		ese::live::LiveFanoutChild child);

private:
	LiveStreamFanoutAdapter() = delete;
};
