// this file is part of eMule eSE - tunnel peer policy and source history owner
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <string>
#include <vector>

namespace eSELive {

struct LiveSourceEndpointKey {
    std::uint8_t network_origin = 0;
    std::uint8_t address_family = 0;
    std::array<std::uint8_t, 16> address{};
    std::uint16_t tcp_port = 0;
};

struct LiveOriginCircuitCandidate {
    std::uint32_t circuit_id = 0;
    bool originator = false;
    bool quota_issuer = false;
    bool active = false;
    std::size_t hop_count = 0;
    bool has_first_hop = false;
    bool multicell = false;
    bool authenticated = false;
    std::uint32_t exit_signed_caps = 0;
    bool strict3 = false;
    bool path_diverse = false;
    bool shaped = false;
};

struct LivePeerDisconnectView {
    bool relay = false;
    bool lost_first = false;
    bool lost_previous = false;
    bool lost_next = false;
    bool lost_pending = false;
    bool has_previous_survivor = false;
    bool has_next_survivor = false;
    bool has_next_circuit = false;
};

struct LivePeerDisconnectPlan {
    bool affected = false;
    bool notify_previous = false;
    bool notify_next = false;
    bool clear_first = false;
    bool clear_previous = false;
    bool clear_next = false;
    bool clear_pending = false;
    bool destroy = false;
};

class LiveTunnelPeerState {
public:
    static const std::uint64_t kSourceHistoryTtlSeconds = 24ull * 60 * 60;
    static const std::size_t kMaximumSourceHistories = 4096;

    LiveTunnelPeerState() = default;
    LiveTunnelPeerState(const LiveTunnelPeerState&) = delete;
    LiveTunnelPeerState& operator=(const LiveTunnelPeerState&) = delete;

    // The coordinator serializes these methods with m_pendingLock. Keeping this
    // owner lock-free avoids adding a new rank to the established lock order.
    std::uint32_t ApplySourceScore(
        std::uint32_t base_score,
        const LiveSourceEndpointKey& endpoint) const;
    void RecordSourceResult(const LiveSourceEndpointKey& endpoint, bool success,
                            std::uint64_t now_seconds);
    void RecordSourceFailure(const LiveSourceEndpointKey& endpoint,
                             std::uint64_t now_seconds);
    void SweepSourceHistory(std::uint64_t now_seconds);
    std::size_t SourceHistorySize() const noexcept;
    void ClearSourceHistory() noexcept;

    static std::string SourceScoreKey(const LiveSourceEndpointKey& endpoint);
    static std::vector<std::size_t> RankSources(
        std::size_t count,
        const std::function<std::uint32_t(std::size_t)>& score_at);
    static std::uint32_t SelectOriginCircuit(
        const std::vector<LiveOriginCircuitCandidate>& candidates,
        std::uint32_t required_caps, std::uint32_t pinned_circuit_id,
        std::size_t minimum_hops, std::uint32_t strict3_capability) noexcept;
    static LivePeerDisconnectPlan PlanDisconnect(
        const LivePeerDisconnectView& view) noexcept;

private:
    struct SourceScore {
        std::uint32_t successes = 0;
        std::uint32_t failures = 0;
        std::uint64_t last_seen = 0;
    };

    std::map<std::string, SourceScore> m_source_scores;
};

bool RunLiveTunnelPeerStateCharacterizationSelfTest();

} // namespace eSELive
