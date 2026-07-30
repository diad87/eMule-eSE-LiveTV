#pragma once

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>

namespace ese {
namespace live {

class LiveViewerSession final
{
public:
	LiveViewerSession() = default;
	LiveViewerSession(const LiveViewerSession&) = delete;
	LiveViewerSession& operator=(const LiveViewerSession&) = delete;
	LiveViewerSession(LiveViewerSession&&) = delete;
	LiveViewerSession& operator=(LiveViewerSession&&) = delete;

	bool Join(
		const std::uint8_t* stream_key,
		std::size_t size,
		std::uint32_t now);
	bool Leave();

	bool IsActive() const
	{
		return active_.load(std::memory_order_acquire);
	}
	bool Matches(const std::uint8_t* stream_key, std::size_t size) const;
	std::uint64_t Generation() const { return generation_; }
	const std::array<std::uint8_t, 16>& StreamKey() const
	{
		return stream_key_;
	}

	void TouchActivity(std::uint32_t now) { last_activity_ = now; }
	std::uint32_t ActivityAge(std::uint32_t now) const;
	bool IsActivityExpired(std::uint32_t now, std::uint32_t timeout) const;
	bool RecordFirstChunk(std::uint32_t now, std::uint32_t& elapsed);

	bool SearchRetryDue(
		std::uint32_t now,
		std::uint32_t interval,
		std::uint32_t retry_limit) const;
	void RecordSearchRetry(std::uint32_t now);
	std::uint32_t SearchRetries() const { return search_retries_; }

	bool SecondaryPublishDue(
		std::uint32_t now,
		std::uint32_t interval) const;
	void RecordSecondaryPublish(std::uint32_t now)
	{
		last_secondary_publish_ = now;
	}

	void NotePlayerFetch(std::uint32_t now);
	void MarkWebPlayerSession(std::uint32_t now);
	std::uint32_t WebPlayerIdleAge(std::uint32_t now) const;
	bool IsWebPlayerExpired(std::uint32_t now, std::uint32_t timeout) const;

	void ConfigureTunnelSource(
		std::uint32_t ip,
		std::uint16_t port,
		std::uint32_t subscribe_tick);
	void SetStrictTunnelOnly(bool strict) { strict_tunnel_only_ = strict; }
	bool StrictTunnelOnly() const { return strict_tunnel_only_; }
	std::uint32_t TunnelSourceIp() const { return tunnel_source_ip_; }
	std::uint16_t TunnelSourcePort() const { return tunnel_source_port_; }
	bool TunnelResubscribeDue(
		std::uint32_t now,
		std::uint32_t interval,
		std::uint32_t retry_limit) const;
	void RecordTunnelResubscribe(std::uint32_t now);
	void StopTunnelWatch() { tunnel_subscribe_tick_ = 0u; }
	std::uint32_t TunnelResubscribeCount() const
	{
		return tunnel_resubscribe_count_;
	}

private:
	static std::uint64_t NextGeneration(std::uint64_t current);
	void ResetTransient(std::uint32_t now);

	std::atomic<bool> active_{false};
	std::uint64_t generation_ = 0;
	std::array<std::uint8_t, 16> stream_key_{};
	std::uint32_t joined_tick_ = 0;
	std::uint32_t last_activity_ = 0;
	bool first_chunk_logged_ = false;
	std::uint32_t last_search_tick_ = 0;
	std::uint32_t search_retries_ = 0;
	std::uint32_t last_secondary_publish_ = 0;
	std::atomic<std::uint32_t> last_player_fetch_{0};
	std::atomic<bool> web_player_session_{false};
	std::uint32_t tunnel_source_ip_ = 0;
	std::uint16_t tunnel_source_port_ = 0;
	bool strict_tunnel_only_ = false;
	std::uint32_t tunnel_subscribe_tick_ = 0;
	std::uint32_t tunnel_resubscribe_count_ = 0;
};

} // namespace live
} // namespace ese
