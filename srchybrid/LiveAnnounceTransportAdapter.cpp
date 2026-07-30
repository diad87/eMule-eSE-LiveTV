#include "stdafx.h"
#include "LiveAnnounceTransportAdapter.h"

#include "LivePackets.h"
#include "Packets.h"
#include "Statistics.h"
#include "UpDownClient.h"

std::size_t LiveAnnounceTransportAdapter::Send(
	const ese::live::LiveAnnounceDescriptor& descriptor,
	const std::vector<CUpDownClient*>& peers)
{
	if (!descriptor.valid)
		return 0u;
	std::size_t sent = 0u;
	for (CUpDownClient* peer : peers) {
		if (peer == NULL)
			continue;
		Packet* packet = eSELive::CreateAnnouncePacket(
			descriptor.stream_key.data(),
			descriptor.newest_sequence,
			descriptor.bitrate,
			descriptor.public_key.data());
		if (packet == NULL)
			continue;
		theStats.AddUpDataOverheadOther(packet->size);
		if (peer->SendPacket(packet))
			++sent;
	}
	return sent;
}
