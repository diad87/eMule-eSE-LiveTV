#include "natmap/natpmp_epoch_policy.h"

#include "natmap/natpmp_codec.h"

#include <limits>

namespace natmap {
namespace {

std::uint32_t ProjectEpoch(
    std::uint32_t epoch,
    std::uint64_t observed_at_seconds,
    std::uint64_t now_seconds) noexcept {
    const std::uint64_t elapsed = now_seconds > observed_at_seconds
        ? now_seconds - observed_at_seconds
        : 0;
    const std::uint64_t remaining =
        std::numeric_limits<std::uint32_t>::max() - epoch;
    return elapsed > remaining
        ? std::numeric_limits<std::uint32_t>::max()
        : epoch + static_cast<std::uint32_t>(elapsed);
}

bool ObserveEpoch(
    const NatPmpEpochObservation& observation,
    NatPmpEpochDecision& decision) noexcept {
    if (!observation.observed)
        return false;
    decision.has_latest_epoch = true;
    decision.latest_epoch = observation.epoch;
    if (!decision.has_continuity_epoch) {
        decision.has_continuity_epoch = true;
        decision.continuity_epoch = observation.epoch;
        decision.continuity_observed_at_seconds =
            observation.observed_at_seconds;
        return false;
    }
    const std::uint32_t conservative_epoch = ProjectEpoch(
        decision.continuity_epoch,
        decision.continuity_observed_at_seconds,
        observation.observed_at_seconds);
    if (NatPmpEpochAppearsReset(
            conservative_epoch, observation.epoch)) {
        decision.continuity_epoch = observation.epoch;
        decision.continuity_observed_at_seconds =
            observation.observed_at_seconds;
        return true;
    }
    if (observation.epoch > conservative_epoch) {
        decision.continuity_epoch = observation.epoch;
        decision.continuity_observed_at_seconds =
            observation.observed_at_seconds;
    }
    return false;
}

} // namespace

NatPmpEpochDecision EvaluateNatPmpEpochSequence(
    const NatPmpEpochSequence& sequence) noexcept {
    NatPmpEpochDecision decision{};
    ObserveEpoch(sequence.previous_snapshot, decision);

    const bool resetBeforeExternal =
        ObserveEpoch(sequence.external_address, decision);
    if (resetBeforeExternal) {
        decision.strongest_boundary =
            NatPmpEpochBoundary::ResetBeforeExternalAddress;
        decision.previous_pair_invalidated = true;
    }
    const bool resetBeforeTcp =
        ObserveEpoch(sequence.tcp_map, decision);
    if (resetBeforeTcp) {
        decision.strongest_boundary =
            NatPmpEpochBoundary::ResetBeforeTcpMap;
        decision.previous_pair_invalidated = true;
    }
    const bool resetBetweenPair =
        ObserveEpoch(sequence.udp_map, decision);
    if (resetBetweenPair) {
        decision.strongest_boundary =
            NatPmpEpochBoundary::ResetBetweenTcpAndUdp;
        decision.previous_pair_invalidated = true;
    }
    decision.external_address_current =
        sequence.external_address.observed &&
        sequence.external_address.accepted &&
        !resetBeforeTcp &&
        !resetBetweenPair;
    decision.pair_can_commit =
        sequence.tcp_map.observed &&
        sequence.tcp_map.accepted &&
        (!sequence.udp_required ||
         (sequence.udp_map.observed &&
          sequence.udp_map.accepted)) &&
        !resetBetweenPair;
    decision.should_retry_pair =
        decision.previous_pair_invalidated &&
        !decision.pair_can_commit;
    return decision;
}

} // namespace natmap
