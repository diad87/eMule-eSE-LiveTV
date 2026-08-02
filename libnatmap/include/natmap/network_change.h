#pragma once

#include "natmap/natmap_types.h"

#include <array>
#include <cstdint>

namespace natmap {

enum class NetworkChangeStatus : std::uint8_t {
    Applied = 0,
    InvalidSnapshot = 1,
    GenerationExhausted = 2,
};

struct NetworkChangeTransition {
    NetworkChangeStatus status = NetworkChangeStatus::InvalidSnapshot;
    ReachabilitySnapshot snapshot{};
    std::uint64_t previous_generation = 0;
    std::uint64_t current_generation = 0;
    std::array<std::uint64_t, 3> cancelled_attempt_ids{};
    bool withdrew_advertisement = false;

    bool IsApplied() const noexcept {
        return status == NetworkChangeStatus::Applied &&
               previous_generation != 0 &&
               current_generation == previous_generation + 1 &&
               snapshot.topology_generation == current_generation;
    }
};

// Builds the complete fail-closed state for a real network identity change.
// The caller receives either all three planes at exactly generation + 1 or
// the original snapshot unchanged. Request/callback cancellation remains an
// integration concern, but the attempt IDs to fence are preserved for audit.
NetworkChangeTransition PrepareNetworkChange(
    const ReachabilitySnapshot& current) noexcept;

bool IsNetworkChangeRediscovery(
    std::uint64_t prepared_generation,
    std::uint64_t current_generation,
    std::uint64_t result_generation,
    bool has_mapper_identity,
    bool refresh) noexcept;

}  // namespace natmap
