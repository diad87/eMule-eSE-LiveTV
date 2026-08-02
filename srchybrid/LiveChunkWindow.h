#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <utility>
#include <vector>

namespace ese {
namespace live {

enum class LiveChunkAddResult : std::uint8_t {
	Stored = 0,
	InvalidData = 1,
	WrongStream = 2,
	Duplicate = 3,
	TooOld = 4,
	AmbiguousSequence = 5,
	AllocationFailure = 6,
};

struct LiveChunkInput {
	const std::uint8_t* stream_key = nullptr;
	std::uint32_t sequence_number = 0u;
	std::uint32_t timestamp = 0u;
	std::uint16_t bitrate_kbps = 0u;
	const std::uint8_t* data = nullptr;
	std::size_t data_size = 0u;
};

struct LiveChunkRecord {
	std::array<std::uint8_t, 16> stream_key = {};
	std::uint32_t sequence_number = 0u;
	std::uint32_t timestamp = 0u;
	std::uint16_t bitrate_kbps = 0u;
	std::vector<std::uint8_t> data;
};

struct LiveChunkWindowSnapshot {
	std::size_t count = 0u;
	std::uint32_t oldest_sequence = 0u;
	std::uint32_t newest_sequence = 0u;
	std::uint16_t availability_bitmap = 0u;
};

class LiveChunkWindow final
{
public:
	static constexpr std::size_t kCapacity = 15u;
	static constexpr std::size_t kMaximumChunkBytes =
		12u * 1024u * 1024u;

	LiveChunkWindow();
	LiveChunkWindow(const LiveChunkWindow&) = delete;
	LiveChunkWindow& operator=(const LiveChunkWindow&) = delete;

	LiveChunkAddResult Add(const LiveChunkInput& input);
	bool AddSegment(
		const std::uint8_t* stream_key,
		std::uint32_t sequence_number,
		std::uint32_t timestamp,
		const std::uint8_t* data,
		std::uint32_t data_size,
		std::uint16_t bitrate_kbps);

	std::shared_ptr<const LiveChunkRecord> GetSegment(
		std::uint32_t sequence_number) const;

	template <typename Callback>
	bool WithSegment(
		std::uint32_t sequence_number,
		Callback&& callback) const
	{
		std::shared_ptr<const LiveChunkRecord> chunk =
			GetSegment(sequence_number);
		if (!chunk)
			return false;
		callback(*chunk);
		return true;
	}

	bool HasSegment(std::uint32_t sequence_number) const;
	LiveChunkWindowSnapshot Snapshot() const;
	std::uint32_t GetOldestSeq() const;
	std::uint32_t GetNewestSeq() const;
	int GetCount() const;
	std::uint16_t GetBitmap() const;
	void Clear();
	static bool IsNewerSequence(
		std::uint32_t candidate,
		std::uint32_t reference);
	static bool IsSequenceAvailable(
		std::uint16_t bitmap,
		std::uint32_t oldest_sequence,
		std::uint32_t sequence_number);

private:
	using ChunkPointer = std::shared_ptr<const LiveChunkRecord>;

	std::vector<ChunkPointer>::const_iterator FindLocked(
		std::uint32_t sequence_number) const;

	mutable std::mutex mutex_;
	std::vector<ChunkPointer> chunks_;
	std::array<std::uint8_t, 16> stream_key_ = {};
	std::uint32_t newest_sequence_ = 0u;
	bool has_stream_ = false;
};

} // namespace live
} // namespace ese
