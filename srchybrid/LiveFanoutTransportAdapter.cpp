#include "stdafx.h"
#include "LiveFanoutTransportAdapter.h"

#include "LivePackets.h"
#include "Packets.h"
#include "Statistics.h"
#include "UpDownClient.h"

#include <limits>
#include <utility>

namespace {

CUpDownClient* FanoutChild(
	ese::live::LiveFanoutChild child)
{
	return reinterpret_cast<CUpDownClient*>(child);
}

void DeletePackets(std::vector<Packet*>& packets) noexcept
{
	for (Packet* packet : packets)
		delete packet;
	packets.clear();
}

} // namespace

LiveFanoutPacketBatch::~LiveFanoutPacketBatch()
{
	Reset();
}

LiveFanoutPacketBatch::LiveFanoutPacketBatch(
	LiveFanoutPacketBatch&& other) noexcept
	: child(other.child)
	, owner(other.owner)
	, reservation_token(other.reservation_token)
	, payload_bytes(other.payload_bytes)
	, packets(std::move(other.packets))
{
	other.child = 0u;
	other.owner = nullptr;
	other.reservation_token = 0u;
	other.payload_bytes = 0u;
}

LiveFanoutPacketBatch& LiveFanoutPacketBatch::operator=(
	LiveFanoutPacketBatch&& other) noexcept
{
	if (this == &other)
		return *this;
	Reset();
	child = other.child;
	owner = other.owner;
	reservation_token = other.reservation_token;
	payload_bytes = other.payload_bytes;
	packets = std::move(other.packets);
	other.child = 0u;
	other.owner = nullptr;
	other.reservation_token = 0u;
	other.payload_bytes = 0u;
	return *this;
}

bool LiveStreamFanoutAdapter::RegisterChild(
	ese::live::LiveStreamFanout& fanout,
	ese::live::LivePeerSet& peers,
	ese::live::LiveFanoutChild child,
	std::size_t limit)
{
	if (child == 0u || limit == 0u)
		return false;
	const ese::live::LivePeerAddResult peer_result =
		peers.AddDownstream(child, limit);
	const ese::live::LiveFanoutRegisterResult fanout_result =
		fanout.RegisterChild(child);
	if ((peer_result == ese::live::LivePeerAddResult::Added ||
		 peer_result == ese::live::LivePeerAddResult::AlreadyPresent) &&
		(fanout_result == ese::live::LiveFanoutRegisterResult::Registered ||
		 fanout_result ==
			ese::live::LiveFanoutRegisterResult::AlreadyRegistered))
		return true;
	peers.RemoveDownstream(child);
	fanout.ReleaseChild(child);
	return false;
}

bool LiveStreamFanoutAdapter::ReplaceChild(
	ese::live::LiveStreamFanout& fanout,
	ese::live::LivePeerSet& peers,
	ese::live::LiveFanoutChild previous,
	ese::live::LiveFanoutChild replacement)
{
	if (previous == 0u || replacement == 0u ||
		previous == replacement ||
		!peers.HasDownstream(previous))
		return false;
	if (!fanout.ReplaceChild(previous, replacement))
		return false;
	if (peers.ReplaceDownstream(previous, replacement))
		return true;
	// PeerSet is manager-lock serialized, so this is a fail-closed rollback
	// for invariant drift rather than a normal race.
	fanout.ReplaceChild(replacement, previous);
	return false;
}

bool LiveStreamFanoutAdapter::ReleaseChild(
	ese::live::LiveStreamFanout& fanout,
	ese::live::LivePeerSet& peers,
	ese::live::LiveFanoutChild child)
{
	const bool removed = peers.RemoveDownstream(child);
	fanout.ReleaseChild(child);
	return removed;
}

void LiveFanoutPacketBatch::Reset() noexcept
{
	if (owner != nullptr && reservation_token != 0u)
		owner->CompleteDelivery(reservation_token, false);
	DeletePackets(packets);
	child = 0u;
	owner = nullptr;
	reservation_token = 0u;
	payload_bytes = 0u;
}

ese::live::LiveFanoutDeliveryResult
LiveStreamFanoutAdapter::ReservePackets(
	ese::live::LiveStreamFanout& fanout,
	ese::live::LiveFanoutChild child,
	std::uint32_t first_sequence,
	std::uint32_t last_sequence,
	std::uint32_t payload_bytes,
	std::vector<Packet*>& packets,
	LiveFanoutPacketBatch& batch)
{
	batch.Reset();
	batch.child = child;
	batch.payload_bytes = payload_bytes;
	batch.packets.swap(packets);

	std::uint64_t wire_bytes = 0u;
	for (const Packet* packet : batch.packets) {
		if (packet == NULL ||
			wire_bytes > (std::numeric_limits<std::uint64_t>::max)() -
				packet->size) {
			return ese::live::LiveFanoutDeliveryResult::InvalidInput;
		}
		wire_bytes += packet->size;
	}
	CUpDownClient* peer = FanoutChild(child);
	if (peer == NULL)
		return ese::live::LiveFanoutDeliveryResult::InvalidInput;
	const ese::live::LiveFanoutReservation reservation =
		fanout.BeginDelivery(
			child, first_sequence, last_sequence,
			peer->GetSocketQueuedBytes(), wire_bytes);
	batch.reservation_token = reservation.token;
	if (reservation.IsReserved())
		batch.owner = &fanout;
	return reservation.result;
}

void LiveStreamFanoutAdapter::PrepareRelayBatches(
	ese::live::LiveStreamFanout& fanout,
	ese::live::LiveFanoutChild sender,
	const std::vector<ese::live::LiveFanoutChild>& blocked,
	std::size_t limit,
	const LiveChunk& chunk,
	std::vector<LiveFanoutPacketBatch>& batches)
{
	const std::vector<ese::live::LiveFanoutChild> recipients =
		fanout.SelectRecipients(sender, blocked, limit);
	batches.reserve(batches.size() + recipients.size());
	for (const ese::live::LiveFanoutChild recipient : recipients) {
		CUpDownClient* child = FanoutChild(recipient);
		if (child == NULL)
			continue;
		Packet* packet = eSELive::CreateChunkPacket(&chunk);
		if (packet == NULL)
			continue;
		const bool fragments =
			(child->GetEseCapabilities() & ESE_CAP_LIVE_CHUNK_FRAG) != 0;
		CArray<Packet*> native_batch;
		eSELive::AppendChunkSendPackets(packet, fragments, native_batch);
		std::vector<Packet*> packets;
		packets.reserve(static_cast<std::size_t>(native_batch.GetCount()));
		for (INT_PTR index = 0; index < native_batch.GetCount(); ++index)
			packets.push_back(native_batch[index]);

		LiveFanoutPacketBatch batch;
		const ese::live::LiveFanoutDeliveryResult result =
			ReservePackets(
				fanout, recipient, chunk.sequenceNumber,
				chunk.sequenceNumber, chunk.dataSize, packets, batch);
		if (result == ese::live::LiveFanoutDeliveryResult::Reserved)
			batches.push_back(std::move(batch));
	}
}

bool LiveStreamFanoutAdapter::SendReserved(
	ese::live::LiveStreamFanout& fanout,
	LiveFanoutPacketBatch& batch)
{
	if (!batch.IsReserved())
		return false;
	if (batch.owner != &fanout) {
		batch.Reset();
		return false;
	}
	ese::live::LiveFanoutChild current_child = 0u;
	if (!fanout.BeginTransport(
			batch.reservation_token, current_child)) {
		batch.Reset();
		return false;
	}
	batch.child = current_child;
	CUpDownClient* child = FanoutChild(current_child);
	bool sent_all = child != NULL;
	for (Packet*& packet : batch.packets) {
		if (packet == NULL)
			continue;
		theStats.AddUpDataOverheadOther(packet->size);
		if (child == NULL) {
			delete packet;
			sent_all = false;
		} else if (!child->SendPacket(packet, true)) {
			sent_all = false;
		}
		packet = NULL;
	}
	batch.packets.clear();
	const bool completed =
		fanout.CompleteDelivery(batch.reservation_token, sent_all);
	batch.owner = nullptr;
	batch.reservation_token = 0u;
	return sent_all && completed;
}

CUpDownClient* LiveStreamFanoutAdapter::ResolveDeliveredChild(
	const ese::live::LivePeerSet& peers,
	ese::live::LiveFanoutChild child)
{
	if (child == 0u || !peers.HasDownstream(child))
		return NULL;
	return FanoutChild(child);
}
