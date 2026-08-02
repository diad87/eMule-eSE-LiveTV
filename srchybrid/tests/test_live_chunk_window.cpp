#include "../LiveChunkWindow.h"

#include <array>
#include <cstdint>
#include <iostream>
#include <limits>
#include <memory>
#include <type_traits>
#include <vector>

namespace {

int failures = 0;

void Check(bool condition, const char* message)
{
	if (!condition) {
		std::cerr << "FAIL: " << message << '\n';
		++failures;
	}
}

ese::live::LiveChunkInput Input(
	const std::array<std::uint8_t, 16>& key,
	std::uint32_t sequence,
	const std::vector<std::uint8_t>& bytes)
{
	ese::live::LiveChunkInput input;
	input.stream_key = key.data();
	input.sequence_number = sequence;
	input.timestamp = sequence + 1000u;
	input.bitrate_kbps = 4096u;
	input.data = bytes.data();
	input.data_size = bytes.size();
	return input;
}

} // namespace

int main()
{
	using ese::live::LiveChunkAddResult;
	using ese::live::LiveChunkRecord;
	using ese::live::LiveChunkWindow;
	using ese::live::LiveChunkWindowSnapshot;

	static_assert(!std::is_copy_constructible_v<LiveChunkWindow>);
	static_assert(!std::is_copy_assignable_v<LiveChunkWindow>);
	static_assert(
		std::is_same_v<
			decltype(std::declval<LiveChunkWindow>().GetSegment(0u)),
			std::shared_ptr<const LiveChunkRecord>>);
	static_assert(LiveChunkWindow::kCapacity == 15u);
	static_assert(LiveChunkWindow::kMaximumChunkBytes == 12u * 1024u * 1024u);

	const std::array<std::uint8_t, 16> key = {
		0x10u, 0x11u, 0x12u, 0x13u, 0x14u, 0x15u, 0x16u, 0x17u,
		0x18u, 0x19u, 0x1au, 0x1bu, 0x1cu, 0x1du, 0x1eu, 0x1fu
	};
	std::array<std::uint8_t, 16> other_key = key;
	other_key[0] ^= 0xffu;
	const std::vector<std::uint8_t> bytes = {1u, 2u, 3u, 4u};

	LiveChunkWindow window;
	Check(
		window.Add(Input(key, 10u, bytes)) == LiveChunkAddResult::Stored,
		"first chunk binds and stores");
	const LiveChunkWindowSnapshot first = window.Snapshot();
	Check(
		first.count == 1u && first.oldest_sequence == 10u &&
			first.newest_sequence == 10u && first.availability_bitmap == 1u,
		"first snapshot is exact");
	Check(
		window.Add(Input(key, 10u, bytes)) == LiveChunkAddResult::Duplicate,
		"duplicate is rejected without mutation");
	Check(
		window.Add(Input(other_key, 11u, bytes)) ==
			LiveChunkAddResult::WrongStream,
		"window stays bound to the first stream");

	Check(
		window.Add(Input(key, 12u, bytes)) == LiveChunkAddResult::Stored,
		"newer chunk advances the serial window");
	Check(
		window.Add(Input(key, 11u, bytes)) == LiveChunkAddResult::Stored,
		"reordered chunk inside the serial window is accepted");
	for (std::uint32_t sequence = 13u; sequence <= 26u; ++sequence)
		window.Add(Input(key, sequence, bytes));
	const LiveChunkWindowSnapshot reordered = window.Snapshot();
	Check(
		reordered.count == 15u && reordered.oldest_sequence == 12u &&
			reordered.newest_sequence == 26u,
		"capacity and serial range remain bounded");
	Check(
		!window.HasSegment(11u) && window.HasSegment(12u) &&
			window.HasSegment(26u),
		"arrival evicted by capacity is never advertised");

	std::shared_ptr<const LiveChunkRecord> retained = window.GetSegment(12u);
	Check(retained && retained->data == bytes, "lookup returns immutable bytes");
	Check(
		window.Add(Input(key, 1000000u, bytes)) == LiveChunkAddResult::Stored,
		"large forward jump is accepted without walking the gap");
	const LiveChunkWindowSnapshot jumped = window.Snapshot();
	Check(
		jumped.count == 1u && jumped.oldest_sequence == 1000000u &&
			jumped.newest_sequence == 1000000u &&
			jumped.availability_bitmap == 1u,
		"large jump expires every prior chunk");
	Check(
		!window.HasSegment(26u) && retained && retained->data == bytes,
		"expired chunks are unavailable while prior snapshots stay valid");
	Check(
		window.Add(Input(key, 999985u, bytes)) == LiveChunkAddResult::TooOld,
		"chunk at the expired boundary is rejected");

	window.Clear();
	Check(window.GetCount() == 0u && retained && retained->data == bytes,
		"clear does not invalidate an immutable snapshot");
	const std::uint32_t maximum = std::numeric_limits<std::uint32_t>::max();
	for (const std::uint32_t sequence : {maximum - 1u, maximum, 0u, 1u})
		Check(
			window.Add(Input(key, sequence, bytes)) == LiveChunkAddResult::Stored,
			"serial order accepts uint32 wrap");
	const LiveChunkWindowSnapshot wrapped = window.Snapshot();
	Check(
		wrapped.count == 4u && wrapped.oldest_sequence == maximum - 1u &&
			wrapped.newest_sequence == 1u &&
			wrapped.availability_bitmap == 0x000fu,
		"wrapped range and bitmap are exact");
	Check(
		LiveChunkWindow::IsSequenceAvailable(0x000fu, maximum - 1u, maximum - 1u) &&
			LiveChunkWindow::IsSequenceAvailable(0x000fu, maximum - 1u, maximum) &&
			LiveChunkWindow::IsSequenceAvailable(0x000fu, maximum - 1u, 0u) &&
			LiveChunkWindow::IsSequenceAvailable(0x000fu, maximum - 1u, 1u),
		"peer bitmap selects every advertised segment across uint32 wrap");
	Check(
		!LiveChunkWindow::IsSequenceAvailable(
			0x000fu, maximum - 1u, maximum - 2u) &&
			!LiveChunkWindow::IsSequenceAvailable(
				0x000fu, maximum - 1u, 14u),
		"peer bitmap rejects serial values outside its advertised window");
	bool reentrant_callback_ran = false;
	Check(
		window.WithSegment(0u, [&](const LiveChunkRecord& chunk) {
			reentrant_callback_ran = chunk.data == bytes;
			window.Clear();
		}),
		"immutable callback can reenter and clear the window");
	Check(
		reentrant_callback_ran && window.GetCount() == 0,
		"external callback runs without the internal lock");
	for (const std::uint32_t sequence : {maximum - 1u, maximum, 0u, 1u})
		window.Add(Input(key, sequence, bytes));
	Check(
		window.Add(Input(key, 0x80000001u, bytes)) ==
			LiveChunkAddResult::AmbiguousSequence,
		"half-range serial ambiguity fails closed");

	ese::live::LiveChunkInput invalid = Input(key, 2u, bytes);
	invalid.data = nullptr;
	Check(
		window.Add(invalid) == LiveChunkAddResult::InvalidData,
		"null bytes fail closed");
	invalid = Input(key, 2u, bytes);
	invalid.data_size = LiveChunkWindow::kMaximumChunkBytes + 1u;
	Check(
		window.Add(invalid) == LiveChunkAddResult::InvalidData,
		"oversized bytes fail before allocation");

	if (failures != 0)
		return 1;
	std::cout << "live chunk window tests: PASS\n";
	return 0;
}
