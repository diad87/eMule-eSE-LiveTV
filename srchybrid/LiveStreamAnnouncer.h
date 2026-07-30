#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace ese {
namespace live {

struct LiveAnnounceActions {
	bool send_announce = false;
	bool publish_kad = false;
};

struct LiveAnnounceDescriptor {
	std::array<std::uint8_t, 16u> stream_key{};
	std::array<std::uint8_t, 32u> public_key{};
	std::uint32_t newest_sequence = 0u;
	std::uint16_t bitrate = 0u;
	bool valid = false;
};

class LiveStreamAnnouncer final {
public:
	static constexpr std::uint32_t kAnnounceIntervalMs = 2000u;
	static constexpr std::uint32_t kKadPublishIntervalMs = 60000u;

	void ResetBroadcast() noexcept;
	LiveAnnounceActions Poll(
		std::uint32_t now,
		bool broadcasting) noexcept;

	static LiveAnnounceDescriptor Describe(
		bool broadcasting,
		std::size_t chunk_count,
		std::uint32_t newest_sequence,
		std::uint32_t bitrate,
		const std::uint8_t* stream_key,
		const std::uint8_t* public_key) noexcept;

private:
	std::uint32_t last_announce_tick_ = 0u;
	std::uint32_t last_kad_publish_tick_ = 0u;
};

} // namespace live
} // namespace ese
