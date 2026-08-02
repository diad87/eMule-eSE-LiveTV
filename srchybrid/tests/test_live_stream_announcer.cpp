#include "../LiveStreamAnnouncer.h"

#include <cstdint>
#include <cstring>
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
	using ese::live::LiveStreamAnnouncer;

	LiveStreamAnnouncer announcer;
	Check(!announcer.Poll(1999u, true).send_announce,
		"announce waits for its exact initial boundary");
	const auto first = announcer.Poll(2000u, true);
	Check(first.send_announce && !first.publish_kad,
		"announce fires at 2000 ms without early Kad publish");
	Check(!announcer.Poll(3999u, true).send_announce,
		"announce cooldown suppresses the preceding millisecond");
	Check(announcer.Poll(4000u, true).send_announce,
		"announce cadence fires at its exact boundary");
	Check(announcer.Poll(60000u, true).publish_kad,
		"Kad cadence fires at its exact boundary");

	announcer.ResetKadPublish();
	Check(!announcer.Poll(60001u, false).send_announce,
		"inactive polling neither announces nor consumes a deadline");
	Check(!announcer.Poll(60001u, true).send_announce,
		"broadcast restart preserves the legacy announce cooldown");
	LiveStreamAnnouncer kad_reset;
	Check(kad_reset.Poll(60000u, true).publish_kad,
		"initial Kad boundary publishes");
	kad_reset.ResetKadPublish();
	const auto restarted = kad_reset.Poll(60001u, true);
	Check(!restarted.send_announce && restarted.publish_kad,
		"broadcast restart resets only the legacy Kad timer");

	LiveStreamAnnouncer wrapped;
	const std::uint32_t near_wrap =
		(std::numeric_limits<std::uint32_t>::max)() - 1000u;
	Check(wrapped.Poll(near_wrap, true).send_announce,
		"large initial tick announces before uint32 wrap");
	Check(!wrapped.Poll(998u, true).send_announce,
		"announce cooldown survives uint32 wrap");
	Check(wrapped.Poll(999u, true).send_announce,
		"announce exact boundary survives uint32 wrap");

	std::uint8_t stream_key[16] = {};
	std::uint8_t public_key[32] = {};
	for (std::size_t i = 0u; i < sizeof stream_key; ++i)
		stream_key[i] = static_cast<std::uint8_t>(i + 1u);
	for (std::size_t i = 0u; i < sizeof public_key; ++i)
		public_key[i] = static_cast<std::uint8_t>(0x80u + i);
	Check(!LiveStreamAnnouncer::Describe(
			false, 1u, 7u, 900u, stream_key, public_key).valid,
		"inactive descriptor fails closed");
	Check(!LiveStreamAnnouncer::Describe(
			true, 0u, 7u, 900u, stream_key, public_key).valid,
		"empty chunk window descriptor fails closed");
	Check(!LiveStreamAnnouncer::Describe(
			true, 1u, 7u, 900u, nullptr, public_key).valid,
		"null stream key descriptor fails closed");
	const auto descriptor = LiveStreamAnnouncer::Describe(
		true, 1u, 0x10203040u, 70000u, stream_key, public_key);
	Check(descriptor.valid &&
		descriptor.newest_sequence == 0x10203040u &&
		descriptor.bitrate == 0xFFFFu &&
		std::memcmp(descriptor.stream_key.data(), stream_key, 16u) == 0 &&
		std::memcmp(descriptor.public_key.data(), public_key, 32u) == 0,
		"descriptor preserves wire fields and saturates bitrate");

	if (failures != 0)
		return 1;
	std::cout << "Live stream announcer tests passed.\n";
	return 0;
}
