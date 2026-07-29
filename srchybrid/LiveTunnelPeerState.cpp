// this file is part of eMule eSE - tunnel peer policy and source history owner
#include "LiveTunnelPeerState.h"

#include <algorithm>
#include <limits>
#include <numeric>

namespace eSELive {

std::string LiveTunnelPeerState::SourceScoreKey(
    const LiveSourceEndpointKey& endpoint)
{
    std::string key;
    key.reserve(20);
    key.push_back(static_cast<char>(endpoint.network_origin));
    key.push_back(static_cast<char>(endpoint.address_family));
    key.append(reinterpret_cast<const char*>(endpoint.address.data()),
               endpoint.address.size());
    key.push_back(static_cast<char>(endpoint.tcp_port));
    key.push_back(static_cast<char>(endpoint.tcp_port >> 8));
    return key;
}

std::uint32_t LiveTunnelPeerState::ApplySourceScore(
    std::uint32_t base_score,
    const LiveSourceEndpointKey& endpoint) const noexcept
{
    const auto history = m_source_scores.find(SourceScoreKey(endpoint));
    if (history == m_source_scores.end())
        return base_score;

    const std::uint32_t bonus = (std::min<std::uint32_t>)(
        100, history->second.successes * 20u);
    const std::uint32_t penalty = (std::min<std::uint32_t>)(
        80, history->second.failures * 10u);
    const std::uint32_t rewarded = base_score + bonus;
    return rewarded > penalty ? rewarded - penalty : 0;
}

void LiveTunnelPeerState::RecordSourceResult(
    const LiveSourceEndpointKey& endpoint, bool success,
    std::uint64_t now_seconds) noexcept
{
    SourceScore& score = m_source_scores[SourceScoreKey(endpoint)];
    if (success) {
        if (score.successes != (std::numeric_limits<std::uint32_t>::max)())
            ++score.successes;
    } else if (score.failures !=
               (std::numeric_limits<std::uint32_t>::max)()) {
        ++score.failures;
    }
    score.last_seen = now_seconds;
}

void LiveTunnelPeerState::RecordSourceFailure(
    const LiveSourceEndpointKey& endpoint, std::uint64_t now_seconds) noexcept
{
    RecordSourceResult(endpoint, false, now_seconds);
}

void LiveTunnelPeerState::SweepSourceHistory(std::uint64_t now_seconds)
{
    for (auto it = m_source_scores.begin(); it != m_source_scores.end(); ) {
        if (it->second.last_seen != 0 &&
            it->second.last_seen + kSourceHistoryTtlSeconds <= now_seconds) {
            it = m_source_scores.erase(it);
        } else {
            ++it;
        }
    }
    while (m_source_scores.size() > kMaximumSourceHistories)
        m_source_scores.erase(m_source_scores.begin());
}

std::size_t LiveTunnelPeerState::SourceHistorySize() const noexcept
{
    return m_source_scores.size();
}

void LiveTunnelPeerState::ClearSourceHistory() noexcept
{
    m_source_scores.clear();
}

std::vector<std::size_t> LiveTunnelPeerState::RankSources(
    std::size_t count,
    const std::function<std::uint32_t(std::size_t)>& score_at)
{
    std::vector<std::size_t> ranked(count);
    std::iota(ranked.begin(), ranked.end(), static_cast<std::size_t>(0));
    std::stable_sort(ranked.begin(), ranked.end(),
        [&score_at](std::size_t left, std::size_t right) {
            return score_at(left) > score_at(right);
        });
    return ranked;
}

std::uint32_t LiveTunnelPeerState::SelectOriginCircuit(
    const std::vector<LiveOriginCircuitCandidate>& candidates,
    std::uint32_t required_caps, std::uint32_t pinned_circuit_id,
    std::size_t minimum_hops, std::uint32_t strict3_capability) noexcept
{
    for (const LiveOriginCircuitCandidate& circuit : candidates) {
        if (circuit.circuit_id == 0 ||
            (pinned_circuit_id != 0 &&
             circuit.circuit_id != pinned_circuit_id) ||
            !circuit.originator || circuit.quota_issuer || !circuit.active ||
            circuit.hop_count < minimum_hops || !circuit.has_first_hop ||
            !circuit.multicell || !circuit.authenticated ||
            (circuit.exit_signed_caps & required_caps) != required_caps ||
            ((required_caps & strict3_capability) != 0 &&
             (!circuit.strict3 || !circuit.path_diverse || !circuit.shaped ||
              circuit.hop_count != 3))) {
            continue;
        }
        return circuit.circuit_id;
    }
    return 0;
}

LivePeerDisconnectPlan LiveTunnelPeerState::PlanDisconnect(
    const LivePeerDisconnectView& view) noexcept
{
    LivePeerDisconnectPlan plan;
    plan.affected = view.lost_first || view.lost_previous ||
                    view.lost_next || view.lost_pending;
    if (!plan.affected)
        return plan;

    plan.notify_next = view.relay && view.lost_previous &&
                       view.has_next_survivor && view.has_next_circuit;
    plan.notify_previous = view.relay && view.lost_next &&
                           view.has_previous_survivor;
    plan.clear_first = view.lost_first;
    plan.clear_previous = view.lost_previous;
    plan.clear_next = view.lost_next;
    plan.clear_pending = view.lost_pending;
    plan.destroy = true;
    return plan;
}

bool RunLiveTunnelPeerStateCharacterizationSelfTest()
{
    LiveTunnelPeerState state;
    LiveSourceEndpointKey endpoint;
    endpoint.address_family = 1;
    endpoint.address = {1, 2, 3, 4};
    endpoint.tcp_port = 4662;
    endpoint.network_origin = 1;

    if (state.ApplySourceScore(100, endpoint) != 100)
        return false;
    state.RecordSourceResult(endpoint, true, 10);
    state.RecordSourceFailure(endpoint, 11);
    if (state.ApplySourceScore(100, endpoint) != 110)
        return false;
    LiveSourceEndpointKey other_network = endpoint;
    other_network.network_origin = 2;
    if (state.ApplySourceScore(100, other_network) != 100) return false;

    const std::vector<std::uint32_t> sources{10, 20, 20};
    const std::vector<std::size_t> ranked =
        LiveTunnelPeerState::RankSources(sources.size(),
            [&sources](std::size_t index) { return sources[index]; });
    if (ranked.size() != 3 || ranked[0] != 1 || ranked[1] != 2 ||
        ranked[2] != 0)
        return false;

    LiveOriginCircuitCandidate rejected;
    rejected.circuit_id = 7;
    LiveOriginCircuitCandidate accepted;
    accepted.circuit_id = 9;
    accepted.originator = accepted.active = accepted.has_first_hop = true;
    accepted.multicell = accepted.authenticated = true;
    accepted.hop_count = 2;
    accepted.exit_signed_caps = 0x10;
    if (LiveTunnelPeerState::SelectOriginCircuit(
            {rejected, accepted}, 0x10, 0, 2, 0x20) != 9)
        return false;

    LivePeerDisconnectView disconnect;
    disconnect.relay = disconnect.lost_previous =
        disconnect.has_next_survivor = disconnect.has_next_circuit = true;
    const LivePeerDisconnectPlan plan =
        LiveTunnelPeerState::PlanDisconnect(disconnect);
    if (!plan.destroy || !plan.notify_next || plan.notify_previous)
        return false;

    state.SweepSourceHistory(
        11 + LiveTunnelPeerState::kSourceHistoryTtlSeconds);
    return state.SourceHistorySize() == 0;
}

} // namespace eSELive
