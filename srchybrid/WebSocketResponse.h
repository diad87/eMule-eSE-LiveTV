#pragma once

#include <cstddef>
#include <cstdint>
#include <deque>
#include <memory>
#include <string>
#include <vector>

namespace ese {
namespace web {

class IWebResponseSource
{
public:
	virtual ~IWebResponseSource() = default;
	virtual bool Read(
		std::uint8_t* destination,
		std::size_t capacity,
		std::size_t& bytesRead) = 0;
};

class WebSocketResponse final
{
public:
	static constexpr std::size_t kMaxQueuedBytes = 2u * 1024u * 1024u;
	static constexpr std::size_t kMaxQueuedChunks = 64u;

	bool Enqueue(const void* bytes, std::size_t byteCount);
	bool AttachSource(
		std::unique_ptr<IWebResponseSource> source,
		std::uint64_t byteCount);
	bool PumpSource(std::size_t maximumChunkBytes);
	const std::uint8_t* FrontData() const;
	std::size_t FrontSize() const;
	bool Consume(std::size_t byteCount);

	void RequestClose();
	void Fail();
	bool CloseRequested() const;
	bool Failed() const;
	bool Empty() const;
	bool SourceAttached() const;
	bool Pending() const;
	std::size_t QueuedBytes() const;
	std::size_t QueuedChunks() const;

private:
	struct Chunk {
		std::vector<std::uint8_t> bytes;
		std::size_t offset = 0;
	};

	std::deque<Chunk> m_chunks;
	std::unique_ptr<IWebResponseSource> m_source;
	std::uint64_t m_sourceBytesRemaining = 0;
	std::size_t m_queuedBytes = 0;
	bool m_closeRequested = false;
	bool m_failed = false;
};

bool RunWebSocketResponseSelfTest(std::string& failure);

} // namespace web
} // namespace ese
