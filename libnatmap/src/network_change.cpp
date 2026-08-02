#include "natmap/network_change.h"

#include "natmap/natmap_state.h"

#include <limits>

namespace natmap {
namespace {

std::uint64_t AttemptId(const PlaneSnapshot& plane) noexcept {
    return plane.verification_attempt.attempt_id;
}

bool WasAdvertised(const PlaneSnapshot& plane) noexcept {
    return plane.state != ReachabilityState::Disabled &&
           plane.advertised.IsUsable();
}

}  // namespace

NetworkChangeTransition PrepareNetworkChange(
    const ReachabilitySnapshot& current) noexcept {
    NetworkChangeTransition transition{};
    transition.snapshot = current;
    transition.previous_generation = current.topology_generation;
    transition.current_generation = current.topology_generation;
    transition.cancelled_attempt_ids = {
        AttemptId(current.ed2k_tcp_v4),
        AttemptId(current.kad_udp_v4),
        AttemptId(current.direct_v6),
    };
    transition.withdrew_advertisement =
        WasAdvertised(current.ed2k_tcp_v4) ||
        WasAdvertised(current.kad_udp_v4) ||
        WasAdvertised(current.direct_v6);

    if (current.topology_generation == 0 ||
        current.ed2k_tcp_v4.generation > current.topology_generation ||
        current.kad_udp_v4.generation > current.topology_generation ||
        current.direct_v6.generation > current.topology_generation ||
        !IsSnapshotConsistent(current.ed2k_tcp_v4) ||
        !IsSnapshotConsistent(current.kad_udp_v4) ||
        !IsSnapshotConsistent(current.direct_v6))
        return transition;
    if (current.topology_generation ==
        (std::numeric_limits<std::uint64_t>::max)()) {
        transition.status = NetworkChangeStatus::GenerationExhausted;
        return transition;
    }

    const std::uint64_t next_generation =
        current.topology_generation + 1;
    const StateEvent invalidation{
        EventType::Disable,
        next_generation,
        ReasonCode::InterfaceChanged,
    };
    const TransitionResult tcp =
        ApplyEvent(current.ed2k_tcp_v4, invalidation);
    const TransitionResult udp =
        ApplyEvent(current.kad_udp_v4, invalidation);
    const TransitionResult v6 =
        ApplyEvent(current.direct_v6, invalidation);
    if (tcp.disposition != TransitionDisposition::Applied ||
        udp.disposition != TransitionDisposition::Applied ||
        v6.disposition != TransitionDisposition::Applied)
        return transition;

    ReachabilitySnapshot candidate = current;
    candidate.topology_generation = next_generation;
    candidate.ed2k_tcp_v4 = tcp.snapshot;
    candidate.kad_udp_v4 = udp.snapshot;
    candidate.direct_v6 = v6.snapshot;
    transition.snapshot = candidate;
    transition.current_generation = next_generation;
    transition.status = NetworkChangeStatus::Applied;
    return transition;
}

bool IsNetworkChangeRediscovery(
    std::uint64_t prepared_generation,
    std::uint64_t current_generation,
    std::uint64_t result_generation,
    bool has_mapper_identity,
    bool refresh) noexcept {
    return prepared_generation != 0 &&
           prepared_generation == current_generation &&
           result_generation == prepared_generation &&
           !has_mapper_identity &&
           !refresh;
}

}  // namespace natmap
