#include "LiveStreamAnnouncer.h"

#include <algorithm>
#include <cstring>
#include <limits>

namespace ese {
namespace live {

void LiveStreamAnnouncer::ResetBroadcast() noexcept
{
	last_announce_tick_ = 0u;
	last_kad_publish_tick_ = 0u;
}

LiveAnnounceActions LiveStreamAnnouncer::Poll(
	const std::uint32_t now,
	const bool broadcasting) noexcept
{
	LiveAnnounceActions actions;
	if (!broadcasting)
		return actions;
	if (now - last_announce_tick_ >= kAnnounceIntervalMs) {
		actions.send_announce = true;
		last_announce_tick_ = now;
	}
	if (now - last_kad_publish_tick_ >= kKadPublishIntervalMs) {
		actions.publish_kad = true;
		last_kad_publish_tick_ = now;
	}
	return actions;
}

LiveAnnounceDescriptor LiveStreamAnnouncer::Describe(
	const bool broadcasting,
	const std::size_t chunk_count,
	const std::uint32_t newest_sequence,
	const std::uint32_t bitrate,
	const std::uint8_t* const stream_key,
	const std::uint8_t* const public_key) noexcept
{
	LiveAnnounceDescriptor descriptor;
	if (!broadcasting || chunk_count == 0u ||
		stream_key == nullptr || public_key == nullptr)
		return descriptor;
	std::copy_n(
		stream_key, descriptor.stream_key.size(),
		descriptor.stream_key.begin());
	std::copy_n(
		public_key, descriptor.public_key.size(),
		descriptor.public_key.begin());
	descriptor.newest_sequence = newest_sequence;
	descriptor.bitrate = static_cast<std::uint16_t>(
		std::min<std::uint32_t>(
			bitrate,
			(std::numeric_limits<std::uint16_t>::max)()));
	descriptor.valid = true;
	return descriptor;
}

} // namespace live
} // namespace ese
