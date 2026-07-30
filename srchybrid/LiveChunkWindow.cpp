#include "LiveChunkWindow.h"

#include <algorithm>
#include <cstring>
#include <new>

namespace ese {
namespace live {

namespace {

constexpr std::uint32_t kSerialHalfRange = 0x80000000u;

} // namespace

LiveChunkWindow::LiveChunkWindow()
{
	chunks_.reserve(kCapacity);
}

bool LiveChunkWindow::IsNewerSequence(
	std::uint32_t candidate,
	std::uint32_t reference)
{
	const std::uint32_t distance = candidate - reference;
	return distance != 0u && distance < kSerialHalfRange;
}

bool LiveChunkWindow::IsSequenceAvailable(
	std::uint16_t bitmap,
	std::uint32_t oldest_sequence,
	std::uint32_t sequence_number)
{
	const std::uint32_t bit = sequence_number - oldest_sequence;
	return bit < 16u && (bitmap & (std::uint16_t(1u) << bit)) != 0u;
}

std::vector<LiveChunkWindow::ChunkPointer>::const_iterator
LiveChunkWindow::FindLocked(std::uint32_t sequence_number) const
{
	return std::find_if(
		chunks_.cbegin(),
		chunks_.cend(),
		[sequence_number](const ChunkPointer& chunk) {
			return chunk && chunk->sequence_number == sequence_number;
		});
}

LiveChunkAddResult LiveChunkWindow::Add(const LiveChunkInput& input)
{
	if (input.stream_key == nullptr ||
		input.data == nullptr ||
		input.data_size == 0u ||
		input.data_size > kMaximumChunkBytes) {
		return LiveChunkAddResult::InvalidData;
	}

	std::array<std::uint8_t, 16> candidate_key = {};
	std::memcpy(
		candidate_key.data(),
		input.stream_key,
		candidate_key.size());

	std::lock_guard<std::mutex> lock(mutex_);
	if (has_stream_ && candidate_key != stream_key_)
		return LiveChunkAddResult::WrongStream;
	if (FindLocked(input.sequence_number) != chunks_.cend())
		return LiveChunkAddResult::Duplicate;

	bool advances_window = chunks_.empty();
	if (!chunks_.empty()) {
		const std::uint32_t forward_distance =
			input.sequence_number - newest_sequence_;
		if (forward_distance == kSerialHalfRange)
			return LiveChunkAddResult::AmbiguousSequence;
		advances_window =
			IsNewerSequence(input.sequence_number, newest_sequence_);
		if (!advances_window) {
			const std::uint32_t age =
				newest_sequence_ - input.sequence_number;
			if (age >= kCapacity)
				return LiveChunkAddResult::TooOld;
		}
	}

	std::shared_ptr<LiveChunkRecord> stored;
	try {
		stored = std::make_shared<LiveChunkRecord>();
		stored->stream_key = candidate_key;
		stored->sequence_number = input.sequence_number;
		stored->timestamp = input.timestamp;
		stored->bitrate_kbps = input.bitrate_kbps;
		stored->data.assign(input.data, input.data + input.data_size);
	}
	catch (const std::bad_alloc&) {
		return LiveChunkAddResult::AllocationFailure;
	}

	if (!has_stream_) {
		stream_key_ = candidate_key;
		has_stream_ = true;
	}
	if (advances_window) {
		newest_sequence_ = input.sequence_number;
		chunks_.erase(
			std::remove_if(
				chunks_.begin(),
				chunks_.end(),
				[this](const ChunkPointer& chunk) {
					return !chunk ||
						newest_sequence_ - chunk->sequence_number >=
							kCapacity;
				}),
			chunks_.end());
	}
	chunks_.push_back(std::move(stored));
	return LiveChunkAddResult::Stored;
}

bool LiveChunkWindow::AddSegment(
	const std::uint8_t* stream_key,
	std::uint32_t sequence_number,
	std::uint32_t timestamp,
	const std::uint8_t* data,
	std::uint32_t data_size,
	std::uint16_t bitrate_kbps)
{
	LiveChunkInput input;
	input.stream_key = stream_key;
	input.sequence_number = sequence_number;
	input.timestamp = timestamp;
	input.bitrate_kbps = bitrate_kbps;
	input.data = data;
	input.data_size = data_size;
	return Add(input) == LiveChunkAddResult::Stored;
}

std::shared_ptr<const LiveChunkRecord> LiveChunkWindow::GetSegment(
	std::uint32_t sequence_number) const
{
	std::lock_guard<std::mutex> lock(mutex_);
	const auto found = FindLocked(sequence_number);
	return found == chunks_.cend() ? ChunkPointer() : *found;
}

bool LiveChunkWindow::HasSegment(std::uint32_t sequence_number) const
{
	std::lock_guard<std::mutex> lock(mutex_);
	return FindLocked(sequence_number) != chunks_.cend();
}

LiveChunkWindowSnapshot LiveChunkWindow::Snapshot() const
{
	std::lock_guard<std::mutex> lock(mutex_);
	LiveChunkWindowSnapshot snapshot;
	if (chunks_.empty())
		return snapshot;

	snapshot.count = chunks_.size();
	snapshot.newest_sequence = newest_sequence_;
	std::uint32_t maximum_age = 0u;
	for (const ChunkPointer& chunk : chunks_) {
		if (!chunk)
			continue;
		const std::uint32_t age =
			newest_sequence_ - chunk->sequence_number;
		if (age > maximum_age)
			maximum_age = age;
	}
	snapshot.oldest_sequence = newest_sequence_ - maximum_age;
	for (const ChunkPointer& chunk : chunks_) {
		if (!chunk)
			continue;
		const std::uint32_t offset =
			chunk->sequence_number - snapshot.oldest_sequence;
		if (offset < 16u)
			snapshot.availability_bitmap |=
				static_cast<std::uint16_t>(1u << offset);
	}
	return snapshot;
}

std::uint32_t LiveChunkWindow::GetOldestSeq() const
{
	return Snapshot().oldest_sequence;
}

std::uint32_t LiveChunkWindow::GetNewestSeq() const
{
	return Snapshot().newest_sequence;
}

int LiveChunkWindow::GetCount() const
{
	return static_cast<int>(Snapshot().count);
}

std::uint16_t LiveChunkWindow::GetBitmap() const
{
	return Snapshot().availability_bitmap;
}

void LiveChunkWindow::Clear()
{
	std::lock_guard<std::mutex> lock(mutex_);
	chunks_.clear();
	stream_key_.fill(0u);
	newest_sequence_ = 0u;
	has_stream_ = false;
}

} // namespace live
} // namespace ese
