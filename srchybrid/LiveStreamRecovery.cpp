#include "LiveStreamRecovery.h"

#include <algorithm>
#include <cstring>
#include <limits>

#pragma warning(disable : 4710 4711 5045)

namespace ese {
namespace live {

LiveRecoveryEndpoint LiveRecoveryEndpoint::FromText(
	const std::uint8_t family_value,
	const char* const address_value,
	const std::uint16_t port_value) noexcept
{
	LiveRecoveryEndpoint endpoint;
	if (family_value == 0u || address_value == nullptr || port_value == 0u)
		return endpoint;
	const std::size_t length = std::strlen(address_value);
	if (length == 0u || length >= kAddressCapacity)
		return endpoint;
	endpoint.family = family_value;
	endpoint.port = port_value;
	std::memcpy(endpoint.address, address_value, length);
	endpoint.address[length] = '\0';
	return endpoint;
}

bool LiveRecoveryEndpoint::IsValid() const noexcept
{
	return family != 0u && port != 0u && address[0] != '\0' &&
		address[kAddressCapacity - 1u] == '\0';
}

bool LiveRecoveryEndpoint::operator==(
	const LiveRecoveryEndpoint& other) const noexcept
{
	return family == other.family && port == other.port &&
		std::memcmp(address, other.address, kAddressCapacity) == 0;
}

LiveStreamRecovery::LiveStreamRecovery()
{
	inflight_.reserve(kInflightCapacity);
}

void LiveStreamRecovery::Reset() noexcept
{
	ResetViewer();
	emergency_mode_ = false;
	emergency_start_tick_ = 0u;
}

void LiveStreamRecovery::ResetViewer() noexcept
{
	inflight_.clear();
	refresh_pending_ = false;
	refresh_has_not_before_ = false;
	refresh_not_before_tick_ = 0u;
	refresh_has_requested_ = false;
	refresh_last_request_tick_ = 0u;
	next_candidate_ = 0u;
}

void LiveStreamRecovery::OnSourceLost(
	const std::uint32_t now,
	const std::uint32_t remaining_sources) noexcept
{
	if (remaining_sources >= kMinimumSourcePeers) {
		refresh_pending_ = false;
		refresh_has_not_before_ = false;
		return;
	}
	refresh_pending_ = true;
	refresh_has_not_before_ = true;
	refresh_not_before_tick_ = now + kPeerLossGraceMs;
}

bool LiveStreamRecovery::ShouldRequestPeers(
	const std::uint32_t now,
	const std::uint32_t source_count) noexcept
{
	if (source_count >= kMinimumSourcePeers) {
		refresh_pending_ = false;
		refresh_has_not_before_ = false;
		return false;
	}
	if (!refresh_pending_) {
		refresh_pending_ = true;
		refresh_has_not_before_ = true;
		refresh_not_before_tick_ = now;
	}
	if (source_count == 0u)
		return false;
	if (refresh_has_not_before_ &&
		static_cast<std::int32_t>(now - refresh_not_before_tick_) < 0)
		return false;
	if (refresh_has_requested_ &&
		now - refresh_last_request_tick_ < kPeerRequestCooldownMs)
		return false;
	refresh_has_requested_ = true;
	refresh_last_request_tick_ = now;
	refresh_has_not_before_ = false;
	return true;
}

std::uint32_t LiveStreamRecovery::TakePeerCandidate(
	const std::uint32_t source_count) noexcept
{
	if (source_count == 0u)
		return 0u;
	const std::uint32_t selected = next_candidate_ % source_count;
	next_candidate_ = (selected + 1u) % source_count;
	return selected;
}

bool LiveStreamRecovery::IsPeerRefreshPending() const noexcept
{
	return refresh_pending_;
}

LiveMissingProbe LiveStreamRecovery::InspectMissing(
	const std::uint32_t sequence,
	const std::uint32_t now) noexcept
{
	LiveMissingProbe probe;
	auto request = FindRequest(sequence);
	if (request == inflight_.end())
		return probe;
	if (now - request->sent_tick < kInflightTimeoutMs) {
		probe.result = LiveMissingProbeResult::Suppressed;
		probe.attempts = request->attempts;
		return probe;
	}
	probe.result = LiveMissingProbeResult::Retry;
	probe.previous_endpoint = request->endpoint;
	probe.attempts = request->attempts;
	probe.charge_previous_failure =
		request->edge_critical && !request->failure_charged;
	if (probe.charge_previous_failure)
		request->failure_charged = true;
	return probe;
}

bool LiveStreamRecovery::RecordRequest(
	const std::uint32_t sequence,
	const std::uint32_t now,
	const LiveRecoveryEndpoint& endpoint,
	const std::uint32_t attempts,
	const bool edge_critical) noexcept
{
	if (!endpoint.IsValid())
		return false;
	auto request = FindRequest(sequence);
	if (request == inflight_.end()) {
		if (inflight_.size() >= kInflightCapacity)
			return false;
		inflight_.push_back(InflightRequest{});
		request = inflight_.end() - 1;
		request->sequence = sequence;
	}
	request->sent_tick = now;
	request->endpoint = endpoint;
	request->attempts = attempts;
	request->edge_critical = edge_critical;
	request->failure_charged = false;
	return true;
}

bool LiveStreamRecovery::CompleteRequest(
	const std::uint32_t sequence,
	bool& was_edge_critical) noexcept
{
	auto request = FindRequest(sequence);
	if (request == inflight_.end()) {
		was_edge_critical = false;
		return false;
	}
	was_edge_critical = request->edge_critical;
	inflight_.erase(request);
	return true;
}

void LiveStreamRecovery::PruneRequests(
	const std::vector<std::uint32_t>& present_sequences,
	const bool has_window,
	const std::uint32_t oldest_sequence) noexcept
{
	inflight_.erase(
		std::remove_if(
			inflight_.begin(),
			inflight_.end(),
			[&](const InflightRequest& request) {
				const bool present = std::find(
					present_sequences.begin(),
					present_sequences.end(),
					request.sequence) != present_sequences.end();
				return present ||
					(has_window &&
						IsSequenceNewer(oldest_sequence, request.sequence));
			}),
		inflight_.end());
}

std::size_t LiveStreamRecovery::InflightCount() const noexcept
{
	return inflight_.size();
}

LiveEmergencyTransition LiveStreamRecovery::ObservePeerHealth(
	const std::uint32_t now,
	const std::uint32_t total_super_seeders,
	const std::uint32_t alive_super_seeders,
	const std::uint32_t drop_threshold_percent,
	const std::uint32_t emergency_duration_ms) noexcept
{
	if (emergency_mode_ &&
		now - emergency_start_tick_ > emergency_duration_ms) {
		emergency_mode_ = false;
		return LiveEmergencyTransition::Exited;
	}
	if (emergency_mode_ || total_super_seeders == 0u)
		return LiveEmergencyTransition::None;
	const std::uint32_t bounded_alive =
		std::min(alive_super_seeders, total_super_seeders);
	const std::uint64_t dropped =
		static_cast<std::uint64_t>(total_super_seeders - bounded_alive) * 100u;
	const std::uint64_t threshold =
		static_cast<std::uint64_t>(total_super_seeders) *
		std::min(drop_threshold_percent, 100u);
	if (dropped <= threshold)
		return LiveEmergencyTransition::None;
	emergency_mode_ = true;
	emergency_start_tick_ = now;
	return LiveEmergencyTransition::Entered;
}

bool LiveStreamRecovery::IsEmergencyMode() const noexcept
{
	return emergency_mode_;
}

bool LiveStreamRecovery::ShouldSendNack(
	const std::uint32_t now,
	const std::uint32_t first_seen_tick,
	const std::uint32_t last_nack_tick) noexcept
{
	return now - first_seen_tick > kNackInitialDelayMs &&
		now - last_nack_tick > kNackCooldownMs;
}

std::vector<std::uint8_t> LiveStreamRecovery::MissingFecBlocks(
	const std::vector<std::uint8_t>& required,
	const std::vector<std::uint8_t>& received)
{
	std::vector<std::uint8_t> missing;
	if (required.size() != received.size())
		return missing;
	const std::size_t count = std::min(
		required.size(),
		static_cast<std::size_t>(std::numeric_limits<std::uint8_t>::max()) + 1u);
	missing.reserve(std::min(count, kMissingBlockCapacity));
	for (std::size_t block = 0u;
		block < count && missing.size() < kMissingBlockCapacity;
		++block) {
		if (required[block] != 0u && received[block] < required[block])
			missing.push_back(static_cast<std::uint8_t>(block));
	}
	return missing;
}

LiveFecParityDecision LiveStreamRecovery::AdvanceParity(
	std::uint8_t current_parity,
	const std::uint32_t nack_count,
	const std::uint32_t elapsed_ms) noexcept
{
	if (current_parity < kMinimumParity ||
		current_parity > kMaximumParity)
		current_parity = kDefaultParity;
	LiveFecParityDecision decision{current_parity, false};
	if (elapsed_ms < kParityWindowMs)
		return decision;
	if (nack_count == 0u) {
		if (decision.parity > kMinimumParity)
			--decision.parity;
	} else if (nack_count <= 3u) {
		if (decision.parity < kDefaultParity)
			decision.parity = kDefaultParity;
	} else if (decision.parity < kMaximumParity) {
		++decision.parity;
	}
	decision.reset_window = true;
	return decision;
}

std::uint32_t LiveStreamRecovery::NextAttempt(
	const std::uint32_t attempts) noexcept
{
	return attempts == std::numeric_limits<std::uint32_t>::max()
		? attempts : attempts + 1u;
}

std::vector<LiveStreamRecovery::InflightRequest>::iterator
LiveStreamRecovery::FindRequest(const std::uint32_t sequence) noexcept
{
	return std::find_if(
		inflight_.begin(),
		inflight_.end(),
		[sequence](const InflightRequest& request) {
			return request.sequence == sequence;
		});
}

std::vector<LiveStreamRecovery::InflightRequest>::const_iterator
LiveStreamRecovery::FindRequest(const std::uint32_t sequence) const noexcept
{
	return std::find_if(
		inflight_.cbegin(),
		inflight_.cend(),
		[sequence](const InflightRequest& request) {
			return request.sequence == sequence;
		});
}

bool LiveStreamRecovery::IsSequenceNewer(
	const std::uint32_t lhs,
	const std::uint32_t rhs) noexcept
{
	return lhs != rhs &&
		static_cast<std::int32_t>(lhs - rhs) > 0;
}

} // namespace live
} // namespace ese
