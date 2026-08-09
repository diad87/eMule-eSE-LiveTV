#pragma once

#include "natmap/natmap_types.h"

namespace natmap {

inline unsigned MappingRoundFailurePriority(ReasonCode reason) noexcept {
    switch (reason) {
    case ReasonCode::InvalidResponse: return 60;
    case ReasonCode::MappingConflict: return 55;
    case ReasonCode::MappingDenied:
    case ReasonCode::RouterRejectedAllCandidates: return 50;
    case ReasonCode::MappingTimeout: return 45;
    case ReasonCode::NoGateway: return 30;
    case ReasonCode::NoMappingProtocol: return 20;
    default: return reason == ReasonCode::None ? 0 : 40;
    }
}

inline ReasonCode SelectMappingRoundFailureReason(
    ReasonCode aggregate, ReasonCode observation) noexcept {
    return MappingRoundFailurePriority(observation) >
            MappingRoundFailurePriority(aggregate)
        ? observation : aggregate;
}

} // namespace natmap
