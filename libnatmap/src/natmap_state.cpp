#include "natmap/natmap_state.h"

namespace natmap {
namespace {

TransitionResult Reject(const PlaneSnapshot& current,
                        TransitionDisposition disposition) noexcept {
    TransitionResult result{};
    result.snapshot = current;
    result.disposition = disposition;
    return result;
}

bool In(ReachabilityState value, ReachabilityState a,
        ReachabilityState b = ReachabilityState::Disabled) noexcept {
    return value == a || value == b;
}

bool SameEndpoint(const Endpoint& left, const Endpoint& right) noexcept {
    return left.port == right.port && left.address.family == right.address.family &&
           left.address.bytes == right.address.bytes;
}

bool HasBothReachabilityEvidence(const PlaneSnapshot& snapshot) noexcept {
    return snapshot.primary_evidence.kind == EvidenceKind::ServerHighId &&
           snapshot.primary_evidence.IsCurrent(snapshot.generation) &&
           snapshot.inbound_evidence.kind == EvidenceKind::InboundTcpAccept &&
           snapshot.inbound_evidence.IsCurrent(snapshot.generation);
}

} // namespace

bool IsSnapshotConsistent(const PlaneSnapshot& snapshot) noexcept {
    if (snapshot.state != ReachabilityState::Disabled && snapshot.generation == 0)
        return false;
    if (snapshot.state == ReachabilityState::CandidateMapped ||
        snapshot.state == ReachabilityState::Verifying ||
        snapshot.state == ReachabilityState::Reachable ||
        snapshot.state == ReachabilityState::Renewing) {
        if (!snapshot.lease.IsStructurallyValid() ||
            snapshot.lease.generation != snapshot.generation ||
            !snapshot.advertised.IsUsable() ||
            snapshot.advertised.port != snapshot.lease.granted_external_port)
            return false;
    }
    if (snapshot.state == ReachabilityState::Reachable) {
        if (!snapshot.primary_evidence.IsCurrent(snapshot.generation))
            return false;
    }
    return true;
}

TransitionResult ApplyEvent(const PlaneSnapshot& current,
                            const StateEvent& event) noexcept {
    if (event.type == EventType::BeginGeneration) {
        if (event.generation <= current.generation)
            return Reject(current, TransitionDisposition::Stale);
        PlaneSnapshot next{};
        next.state = ReachabilityState::Discovering;
        next.local = current.local;
        next.generation = event.generation;
        return TransitionResult{next, TransitionDisposition::Applied};
    }

    if (event.type == EventType::Disable) {
        if (event.generation < current.generation)
            return Reject(current, TransitionDisposition::Stale);
        PlaneSnapshot next{};
        next.state = ReachabilityState::Disabled;
        next.reason = event.reason == ReasonCode::None
            ? ReasonCode::DisabledByPreference : event.reason;
        next.local = current.local;
        next.advertised = current.local;
        next.generation = event.generation;
        return TransitionResult{next, TransitionDisposition::Applied};
    }

    if (event.generation != current.generation)
        return Reject(current, TransitionDisposition::Stale);

    PlaneSnapshot next = current;
    next.reason = event.reason;

    switch (event.type) {
    case EventType::MappingStarted:
        if (!In(current.state, ReachabilityState::Discovering,
                ReachabilityState::Degraded))
            return Reject(current, TransitionDisposition::Invalid);
        next.state = ReachabilityState::Mapping;
        break;

    case EventType::MappingSucceeded:
        if (current.state != ReachabilityState::Mapping ||
            !event.lease.IsStructurallyValid() ||
            event.lease.generation != current.generation)
            return Reject(current, TransitionDisposition::Invalid);
        next.state = ReachabilityState::CandidateMapped;
        next.lease = event.lease;
        next.mapped = event.lease.public_endpoint;
        next.advertised = event.lease.public_endpoint;
        break;

    case EventType::VerificationStarted:
        if (!(current.state == ReachabilityState::CandidateMapped ||
              current.state == ReachabilityState::Degraded ||
              current.state == ReachabilityState::Reachable) ||
            !current.lease.IsStructurallyValid() ||
            current.lease.generation != current.generation ||
            !current.advertised.IsUsable())
            return Reject(current, TransitionDisposition::Invalid);
        next.state = ReachabilityState::Verifying;
        next.reason = ReasonCode::None;
        next.primary_evidence = Evidence{};
        break;

    case EventType::VerificationSucceeded:
        if (current.state != ReachabilityState::Verifying ||
            !event.primary_evidence.IsCurrent(current.generation) ||
            !event.advertised.IsUsable() ||
            event.advertised.port != current.lease.granted_external_port)
            return Reject(current, TransitionDisposition::Invalid);
        next.state = ReachabilityState::Reachable;
        next.advertised = event.advertised;
        next.primary_evidence = event.primary_evidence;
        next.inbound_evidence = event.inbound_evidence;
        break;

    case EventType::RenewalDue:
        if (current.state != ReachabilityState::Reachable)
            return Reject(current, TransitionDisposition::Invalid);
        next.state = ReachabilityState::Renewing;
        break;

    case EventType::RenewalSucceeded:
        if (current.state != ReachabilityState::Renewing ||
            !event.lease.IsStructurallyValid() ||
            event.lease.generation != current.generation ||
            event.lease.public_endpoint.port != current.advertised.port)
            return Reject(current, TransitionDisposition::Invalid);
        next.state = ReachabilityState::Reachable;
        next.lease = event.lease;
        break;

    case EventType::LeaseLost:
        if (current.state == ReachabilityState::Disabled)
            return Reject(current, TransitionDisposition::Invalid);
        next = PlaneSnapshot{};
        next.state = ReachabilityState::Degraded;
        next.reason = event.reason == ReasonCode::None
            ? ReasonCode::LeaseExpired : event.reason;
        next.local = current.local;
        next.generation = current.generation;
        break;

    case EventType::CgnatDetected:
        next = PlaneSnapshot{};
        next.state = ReachabilityState::BlockedByCgnat;
        next.reason = event.reason == ReasonCode::None
            ? ReasonCode::CgnatWithoutLease : event.reason;
        next.local = current.local;
        next.generation = current.generation;
        break;

    case EventType::RouterBlocked:
        next = PlaneSnapshot{};
        next.state = ReachabilityState::BlockedByRouter;
        next.reason = event.reason == ReasonCode::None
            ? ReasonCode::RouterRejectedAllCandidates : event.reason;
        next.local = current.local;
        next.generation = current.generation;
        break;

    case EventType::ServerEvidenceObserved:
        if (!In(current.state, ReachabilityState::Verifying,
                ReachabilityState::Reachable) ||
            event.primary_evidence.kind != EvidenceKind::ServerHighId ||
            !event.primary_evidence.IsCurrent(current.generation) ||
            !SameEndpoint(event.primary_evidence.endpoint, current.advertised))
            return Reject(current, TransitionDisposition::Invalid);
        next.primary_evidence = event.primary_evidence;
        if (HasBothReachabilityEvidence(next))
            next.state = ReachabilityState::Reachable;
        break;

    case EventType::InboundEvidenceObserved:
        if (!(current.state == ReachabilityState::CandidateMapped ||
              current.state == ReachabilityState::Verifying ||
              current.state == ReachabilityState::Reachable ||
              current.state == ReachabilityState::Degraded) ||
            event.inbound_evidence.kind != EvidenceKind::InboundTcpAccept ||
            !event.inbound_evidence.IsCurrent(current.generation) ||
            !SameEndpoint(event.inbound_evidence.endpoint, current.advertised))
            return Reject(current, TransitionDisposition::Invalid);
        next.inbound_evidence = event.inbound_evidence;
        if ((current.state == ReachabilityState::Verifying ||
             current.state == ReachabilityState::Reachable) &&
            HasBothReachabilityEvidence(next))
            next.state = ReachabilityState::Reachable;
        break;

    case EventType::VerificationFailed:
        if (current.state != ReachabilityState::Verifying)
            return Reject(current, TransitionDisposition::Invalid);
        next.state = ReachabilityState::Degraded;
        next.reason = event.reason == ReasonCode::None
            ? ReasonCode::ServerCallbackFailed : event.reason;
        next.primary_evidence = Evidence{};
        break;

    case EventType::BeginGeneration:
    case EventType::Disable:
        return Reject(current, TransitionDisposition::Invalid);
    }

    if (!IsSnapshotConsistent(next))
        return Reject(current, TransitionDisposition::Invalid);
    return TransitionResult{next, TransitionDisposition::Applied};
}

} // namespace natmap
