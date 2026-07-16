#pragma once

#include "natmap/natmap_types.h"

namespace natmap {

enum class EventType : std::uint8_t {
    BeginGeneration = 0,
    Disable = 1,
    MappingStarted = 2,
    MappingSucceeded = 3,
    VerificationStarted = 4,
    VerificationSucceeded = 5,
    RenewalDue = 6,
    RenewalSucceeded = 7,
    LeaseLost = 8,
    CgnatDetected = 9,
    RouterBlocked = 10,
    ServerEvidenceObserved = 11,
    InboundEvidenceObserved = 12,
    VerificationFailed = 13,
};

enum class TransitionDisposition : std::uint8_t {
    Applied = 0,
    Stale = 1,
    Invalid = 2,
};

struct StateEvent {
    EventType type = EventType::BeginGeneration;
    std::uint64_t generation = 0;
    ReasonCode reason = ReasonCode::None;
    PortLease lease{};
    Endpoint advertised{};
    Evidence primary_evidence{};
    Evidence inbound_evidence{};
};

struct TransitionResult {
    PlaneSnapshot snapshot{};
    TransitionDisposition disposition = TransitionDisposition::Invalid;
};

TransitionResult ApplyEvent(const PlaneSnapshot& current,
                            const StateEvent& event) noexcept;
bool IsSnapshotConsistent(const PlaneSnapshot& snapshot) noexcept;

} // namespace natmap
