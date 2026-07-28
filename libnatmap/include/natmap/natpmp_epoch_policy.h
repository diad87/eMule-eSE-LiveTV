#pragma once

#include <cstdint>

namespace natmap {

struct NatPmpEpochObservation {
    bool observed = false;
    bool accepted = false;
    std::uint32_t epoch = 0;
    std::uint64_t observed_at_seconds = 0;
};

struct NatPmpEpochSequence {
    NatPmpEpochObservation previous_snapshot{};
    NatPmpEpochObservation external_address{};
    NatPmpEpochObservation tcp_map{};
    NatPmpEpochObservation udp_map{};
    bool udp_required = true;
};

enum class NatPmpEpochBoundary : std::uint8_t {
    Continuous = 0,
    ResetBeforeExternalAddress = 1,
    ResetBeforeTcpMap = 2,
    ResetBetweenTcpAndUdp = 3,
};

struct NatPmpEpochDecision {
    NatPmpEpochBoundary strongest_boundary =
        NatPmpEpochBoundary::Continuous;
    bool previous_pair_invalidated = false;
    bool external_address_current = false;
    bool pair_can_commit = false;
    bool should_retry_pair = false;
    bool has_latest_epoch = false;
    std::uint32_t latest_epoch = 0;
    bool has_continuity_epoch = false;
    std::uint32_t continuity_epoch = 0;
    std::uint64_t continuity_observed_at_seconds = 0;
};

NatPmpEpochDecision EvaluateNatPmpEpochSequence(
    const NatPmpEpochSequence& sequence) noexcept;

} // namespace natmap
