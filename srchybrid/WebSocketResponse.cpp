#include "WebSocketResponse.h"

#include <cstring>
#include <limits>
#include <new>

namespace ese {
namespace web {

bool WebSocketResponse::Enqueue(const void* bytes, std::size_t byteCount)
{
	if (m_failed || m_closeRequested || m_source ||
		(bytes == nullptr && byteCount != 0u) ||
		byteCount > kMaxQueuedBytes - m_queuedBytes ||
		m_chunks.size() >= kMaxQueuedChunks) {
		m_failed = true;
		return false;
	}
	if (byteCount == 0u)
		return true;

	try {
		Chunk chunk;
		const std::uint8_t* begin = static_cast<const std::uint8_t*>(bytes);
		chunk.bytes.assign(begin, begin + byteCount);
		m_chunks.push_back(std::move(chunk));
		m_queuedBytes += byteCount;
	} catch (...) {
		m_failed = true;
		return false;
	}
	return true;
}

bool WebSocketResponse::AttachSource(
	std::unique_ptr<IWebResponseSource> source,
	std::uint64_t byteCount)
{
	if (m_failed || m_closeRequested || m_source || !source ||
		byteCount == 0u) {
		m_failed = true;
		return false;
	}
	m_source = std::move(source);
	m_sourceBytesRemaining = byteCount;
	return true;
}

bool WebSocketResponse::PumpSource(std::size_t maximumChunkBytes)
{
	if (m_failed || !m_source || maximumChunkBytes == 0u ||
		m_chunks.size() >= kMaxQueuedChunks ||
		m_queuedBytes >= kMaxQueuedBytes)
		return false;

	const std::uint64_t permitted64 = std::min<std::uint64_t>(
		m_sourceBytesRemaining,
		std::min<std::size_t>(
			maximumChunkBytes,
			kMaxQueuedBytes - m_queuedBytes));
	const std::size_t permitted = static_cast<std::size_t>(permitted64);
	if (permitted == 0u) {
		m_failed = true;
		return false;
	}

	try {
		Chunk chunk;
		chunk.bytes.resize(permitted);
		std::size_t bytesRead = 0;
		if (!m_source->Read(chunk.bytes.data(), permitted, bytesRead) ||
			bytesRead == 0u || bytesRead > permitted ||
			bytesRead > m_sourceBytesRemaining) {
			Fail();
			return false;
		}
		chunk.bytes.resize(bytesRead);
		m_chunks.push_back(std::move(chunk));
		m_queuedBytes += bytesRead;
		m_sourceBytesRemaining -= bytesRead;
		if (m_sourceBytesRemaining == 0u)
			m_source.reset();
	} catch (...) {
		Fail();
		return false;
	}
	return true;
}

const std::uint8_t* WebSocketResponse::FrontData() const
{
	return m_chunks.empty()
		? nullptr
		: m_chunks.front().bytes.data() + m_chunks.front().offset;
}

std::size_t WebSocketResponse::FrontSize() const
{
	return m_chunks.empty()
		? 0u
		: m_chunks.front().bytes.size() - m_chunks.front().offset;
}

bool WebSocketResponse::Consume(std::size_t byteCount)
{
	if (m_chunks.empty() || byteCount == 0u || byteCount > FrontSize()) {
		m_failed = true;
		return false;
	}
	m_chunks.front().offset += byteCount;
	m_queuedBytes -= byteCount;
	if (m_chunks.front().offset == m_chunks.front().bytes.size())
		m_chunks.pop_front();
	return true;
}

void WebSocketResponse::RequestClose()
{
	m_closeRequested = true;
}

void WebSocketResponse::Fail()
{
	m_failed = true;
	m_chunks.clear();
	m_source.reset();
	m_sourceBytesRemaining = 0;
	m_queuedBytes = 0;
}

bool WebSocketResponse::CloseRequested() const
{
	return m_closeRequested;
}

bool WebSocketResponse::Failed() const
{
	return m_failed;
}

bool WebSocketResponse::Empty() const
{
	return m_chunks.empty();
}

bool WebSocketResponse::SourceAttached() const
{
	return m_source != nullptr;
}

bool WebSocketResponse::Pending() const
{
	return !m_chunks.empty() || m_source != nullptr;
}

std::size_t WebSocketResponse::QueuedBytes() const
{
	return m_queuedBytes;
}

std::size_t WebSocketResponse::QueuedChunks() const
{
	return m_chunks.size();
}

} // namespace web
} // namespace ese
