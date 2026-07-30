#include "../LiveBroadcastSession.h"
#include "../LiveViewerSession.h"

#include <algorithm>
#include <cstdint>
#include <iostream>

namespace {

int failures = 0;

void Check(bool condition, const char* message)
{
	if (!condition) {
		std::cerr << "FAIL: " << message << '\n';
		++failures;
	}
}

ese::live::LiveBroadcastIdentity BroadcastIdentity(std::uint8_t seed)
{
	ese::live::LiveBroadcastIdentity identity;
	for (std::size_t index = 0; index < identity.stream_key.size(); ++index)
		identity.stream_key[index] = static_cast<std::uint8_t>(seed + index);
	for (std::size_t index = 0; index < identity.public_key.size(); ++index) {
		identity.public_key[index] =
			static_cast<std::uint8_t>(seed + index + 16u);
		identity.private_key[index] =
			static_cast<std::uint8_t>(seed + index + 48u);
	}
	return identity;
}

} // namespace

int main()
{
	using ese::live::LiveBroadcastSession;
	using ese::live::LiveViewerSession;

	const auto identity = BroadcastIdentity(3u);
	const auto replacementIdentity = BroadcastIdentity(91u);
	LiveBroadcastSession broadcast;
	Check(!broadcast.IsActive(), "broadcast starts inactive");
	Check(broadcast.Start(identity), "broadcast starts once");
	Check(
		!broadcast.Start(replacementIdentity),
		"broadcast rejects overlapping start");
	Check(
		broadcast.Matches(identity.stream_key.data(), identity.stream_key.size()),
		"rejected broadcast replacement preserves the original key");
	Check(
		!broadcast.Matches(
			replacementIdentity.stream_key.data(),
			replacementIdentity.stream_key.size()) &&
			broadcast.PrivateKey() == identity.private_key,
		"rejected broadcast replacement cannot partially replace identity");
	std::uint32_t sequence = 99u;
	Check(
		broadcast.NextSequence(sequence) && sequence == 0u,
		"broadcast sequence starts at zero");
	Check(
		broadcast.NextSequence(sequence) && sequence == 1u,
		"broadcast sequence is monotonic");
	const std::uint64_t firstBroadcastGeneration = broadcast.Generation();
	Check(broadcast.Stop(), "broadcast stops once");
	Check(!broadcast.Stop(), "broadcast stop is idempotent");
	Check(
		std::all_of(
			broadcast.PrivateKey().begin(),
			broadcast.PrivateKey().end(),
			[](std::uint8_t byte) { return byte == 0u; }),
		"broadcast stop wipes the private key");
	Check(
		!broadcast.NextSequence(sequence),
		"inactive broadcast cannot allocate a sequence");
	Check(broadcast.Start(identity), "broadcast can restart");
	Check(
		broadcast.Generation() > firstBroadcastGeneration,
		"broadcast restart advances generation");
	Check(
		broadcast.NextSequence(sequence) && sequence == 0u,
		"broadcast restart resets sequence");

	LiveViewerSession viewer;
	std::uint8_t viewerKey[16] = {};
	std::uint8_t replacementViewerKey[16] = {};
	for (std::size_t index = 0; index < 16u; ++index)
		viewerKey[index] = static_cast<std::uint8_t>(0xa0u + index);
	for (std::size_t index = 0; index < 16u; ++index)
		replacementViewerKey[index] = static_cast<std::uint8_t>(0x30u + index);
	Check(
		!viewer.Join(nullptr, sizeof viewerKey, 1u) &&
			!viewer.Join(viewerKey, sizeof viewerKey - 1u, 1u) &&
			!viewer.IsActive(),
		"invalid viewer joins fail without partial state");
	Check(viewer.Join(viewerKey, sizeof viewerKey, 0xfffffff0u), "viewer joins");
	Check(
		!viewer.Join(replacementViewerKey, sizeof replacementViewerKey, 2u),
		"viewer replacement requires explicit leave");
	Check(
		viewer.Matches(viewerKey, sizeof viewerKey) &&
			!viewer.Matches(replacementViewerKey, sizeof replacementViewerKey),
		"rejected viewer replacement preserves the original key");
	Check(
		broadcast.IsActive() && viewer.IsActive(),
		"broadcast and viewer roles remain independent");

	viewer.TouchActivity(0xfffffffdu);
	Check(
		!viewer.IsActivityExpired(2u, 5u) &&
			viewer.IsActivityExpired(3u, 5u),
		"viewer activity timeout is wrap-safe and strict");
	std::uint32_t elapsed = 0u;
	Check(
		viewer.RecordFirstChunk(5u, elapsed) && elapsed == 21u,
		"first-chunk latency is wrap-safe");
	Check(
		!viewer.RecordFirstChunk(6u, elapsed),
		"first-chunk latency records once");

	Check(
		!viewer.SearchRetryDue(4u, 20u, 2u) &&
			viewer.SearchRetryDue(5u, 20u, 2u),
		"search retry deadline is wrap-safe and strict");
	viewer.RecordSearchRetry(5u);
	viewer.RecordSearchRetry(26u);
	Check(
		viewer.SearchRetries() == 2u &&
			!viewer.SearchRetryDue(100u, 20u, 2u),
		"search retries are bounded");

	Check(
		viewer.SecondaryPublishDue(31u, 30u),
		"secondary publish is due after its strict deadline");
	viewer.RecordSecondaryPublish(31u);
	Check(
		!viewer.SecondaryPublishDue(61u, 30u) &&
			viewer.SecondaryPublishDue(62u, 30u),
		"secondary publish timestamp advances with strict deadline");

	viewer.MarkWebPlayerSession(0xfffffffdu);
	Check(
		!viewer.IsWebPlayerExpired(2u, 5u) &&
			viewer.IsWebPlayerExpired(3u, 5u),
		"web-player watchdog is wrap-safe and strict");
	viewer.NotePlayerFetch(3u);
	Check(
		!viewer.IsWebPlayerExpired(8u, 5u),
		"web-player fetch refreshes the watchdog");

	viewer.ConfigureTunnelSource(0x01020304u, 4662u, 0xfffffffdu);
	viewer.SetStrictTunnelOnly(true);
	Check(
		viewer.TunnelSourceIp() == 0x01020304u &&
			viewer.TunnelSourcePort() == 4662u &&
			viewer.StrictTunnelOnly(),
		"viewer owns tunnel session state");
	Check(
		!viewer.TunnelResubscribeDue(5u, 8u, 2u) &&
			viewer.TunnelResubscribeDue(6u, 8u, 2u),
		"tunnel resubscribe deadline is wrap-safe and strict");
	viewer.RecordTunnelResubscribe(6u);
	viewer.RecordTunnelResubscribe(15u);
	Check(
		viewer.TunnelResubscribeCount() == 2u &&
			!viewer.TunnelResubscribeDue(100u, 8u, 2u),
		"tunnel resubscribe retries are bounded");

	const std::uint64_t firstViewerGeneration = viewer.Generation();
	Check(viewer.Leave(), "viewer leaves once");
	Check(!viewer.Leave(), "viewer leave is idempotent");
	Check(
		!viewer.IsActive() && !viewer.Matches(viewerKey, sizeof viewerKey) &&
			!viewer.StrictTunnelOnly() && viewer.TunnelSourceIp() == 0u &&
			std::all_of(
				viewer.StreamKey().begin(),
				viewer.StreamKey().end(),
				[](std::uint8_t byte) { return byte == 0u; }),
		"viewer leave clears all transient authority");
	Check(
		viewer.Join(viewerKey, sizeof viewerKey, 10u) &&
			viewer.Generation() > firstViewerGeneration,
		"viewer can rejoin with a fresh generation");

	if (failures != 0)
		return 1;
	std::cout << "live stream session tests: PASS\n";
	return 0;
}
