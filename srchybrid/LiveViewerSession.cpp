#include "LiveViewerSession.h"

#include <algorithm>
#include <cstring>

namespace ese {
namespace live {

std::uint64_t LiveViewerSession::NextGeneration(std::uint64_t current)
{
	++current;
	return current == 0u ? 1u : current;
}

void LiveViewerSession::ResetTransient(std::uint32_t now)
{
	joined_tick_ = now;
	last_activity_ = now;
	first_chunk_logged_ = false;
	last_search_tick_ = now;
	search_retries_ = 0u;
	last_secondary_publish_ = 0u;
	last_player_fetch_.store(now, std::memory_order_release);
	web_player_session_.store(false, std::memory_order_release);
	tunnel_source_ip_ = 0u;
	tunnel_source_port_ = 0u;
	strict_tunnel_only_ = false;
	tunnel_subscribe_tick_ = 0u;
	tunnel_resubscribe_count_ = 0u;
}

bool LiveViewerSession::Join(
	const std::uint8_t* stream_key,
	std::size_t size,
	std::uint32_t now)
{
	if (active_ || stream_key == nullptr || size != stream_key_.size())
		return false;

	std::memcpy(stream_key_.data(), stream_key, stream_key_.size());
	generation_ = NextGeneration(generation_);
	ResetTransient(now);
	active_ = true;
	return true;
}

bool LiveViewerSession::Leave()
{
	if (!active_)
		return false;

	active_ = false;
	ResetTransient(0u);
	std::fill(stream_key_.begin(), stream_key_.end(), std::uint8_t{0});
	return true;
}

bool LiveViewerSession::Matches(
	const std::uint8_t* stream_key,
	std::size_t size) const
{
	return active_ && stream_key != nullptr && size == stream_key_.size() &&
		std::memcmp(stream_key_.data(), stream_key, stream_key_.size()) == 0;
}

bool LiveViewerSession::IsActivityExpired(
	std::uint32_t now,
	std::uint32_t timeout) const
{
	return ActivityAge(now) > timeout;
}

std::uint32_t LiveViewerSession::ActivityAge(std::uint32_t now) const
{
	return active_ && last_activity_ != 0u
		? now - last_activity_
		: 0u;
}

bool LiveViewerSession::RecordFirstChunk(
	std::uint32_t now,
	std::uint32_t& elapsed)
{
	if (!active_ || first_chunk_logged_ || joined_tick_ == 0u)
		return false;

	elapsed = now - joined_tick_;
	first_chunk_logged_ = true;
	return true;
}

bool LiveViewerSession::SearchRetryDue(
	std::uint32_t now,
	std::uint32_t interval,
	std::uint32_t retry_limit) const
{
	return active_ && search_retries_ < retry_limit &&
		now - last_search_tick_ > interval;
}

void LiveViewerSession::RecordSearchRetry(std::uint32_t now)
{
	if (!active_)
		return;
	++search_retries_;
	last_search_tick_ = now;
}

bool LiveViewerSession::SecondaryPublishDue(
	std::uint32_t now,
	std::uint32_t interval) const
{
	return active_ && now - last_secondary_publish_ > interval;
}

void LiveViewerSession::NotePlayerFetch(std::uint32_t now)
{
	last_player_fetch_.store(now, std::memory_order_release);
}

void LiveViewerSession::MarkWebPlayerSession(std::uint32_t now)
{
	last_player_fetch_.store(now, std::memory_order_relaxed);
	web_player_session_.store(true, std::memory_order_release);
}

bool LiveViewerSession::IsWebPlayerExpired(
	std::uint32_t now,
	std::uint32_t timeout) const
{
	return WebPlayerIdleAge(now) > timeout;
}

std::uint32_t LiveViewerSession::WebPlayerIdleAge(std::uint32_t now) const
{
	if (!active_ ||
		!web_player_session_.load(std::memory_order_acquire)) {
		return 0u;
	}
	const std::uint32_t last =
		last_player_fetch_.load(std::memory_order_acquire);
	return last != 0u ? now - last : 0u;
}

void LiveViewerSession::ConfigureTunnelSource(
	std::uint32_t ip,
	std::uint16_t port,
	std::uint32_t subscribe_tick)
{
	if (!active_)
		return;
	tunnel_source_ip_ = ip;
	tunnel_source_port_ = port;
	tunnel_subscribe_tick_ = subscribe_tick;
	tunnel_resubscribe_count_ = 0u;
}

bool LiveViewerSession::TunnelResubscribeDue(
	std::uint32_t now,
	std::uint32_t interval,
	std::uint32_t retry_limit) const
{
	return active_ && tunnel_source_ip_ != 0u &&
		tunnel_resubscribe_count_ < retry_limit &&
		tunnel_subscribe_tick_ != 0u &&
		now - tunnel_subscribe_tick_ > interval;
}

void LiveViewerSession::RecordTunnelResubscribe(std::uint32_t now)
{
	if (!active_)
		return;
	++tunnel_resubscribe_count_;
	tunnel_subscribe_tick_ = now;
}

} // namespace live
} // namespace ese
