#pragma once

#include "natmap/natmap_types.h"
#include <limits>

namespace natmap {
inline bool NextTopologyGeneration(std::uint64_t current,std::uint64_t& next) noexcept {
    next=0;
    if(current==(std::numeric_limits<std::uint64_t>::max)()) return false;
    next=current+1; return true;
}
inline bool MatchesLocalMappingPorts(std::uint16_t expectedTcp,std::uint16_t expectedUdp,
    std::uint16_t observedTcp,std::uint16_t observedUdp) noexcept {
    return expectedTcp!=0 && observedTcp==expectedTcp && observedUdp==expectedUdp;
}
inline bool IsCurrentProofGeneration(std::uint64_t captured,std::uint64_t plane,std::uint64_t topology) noexcept {
    return captured!=0 && captured==plane && captured==topology;
}

inline bool IsCurrentInboundProof(std::uint64_t captured,std::uint64_t plane,
    std::uint64_t topology,std::uint16_t observedLocalPort,std::uint16_t currentLocalPort) noexcept {
    return IsCurrentProofGeneration(captured,plane,topology) &&
        observedLocalPort!=0 && observedLocalPort==currentLocalPort;
}

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
