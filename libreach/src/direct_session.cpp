// SPDX-License-Identifier: MIT
#include "reach/direct_session.h"

#include <algorithm>
#include <limits>

namespace reach {
bool DirectSession::AwaitingAuthentication(std::uint32_t id,std::uint64_t epoch) const noexcept
{
    if (Terminal() || epoch != epoch_) return false;
    for (const auto& route : routes_)
        if (route.spec.id == id) return route.phase == Phase::Authenticating;
    return false;
}
bool DirectSession::AuthorizesStart(const DirectSessionRoute& spec,std::uint64_t epoch) const noexcept
{
    if (Terminal() || epoch != epoch_) return false;
    for (const auto& route : routes_) {
        if (route.phase != Phase::Connecting || route.spec.id != spec.id ||
            route.spec.transport != spec.transport ||
            route.spec.recovery_authentication != spec.recovery_authentication) continue;
        const auto& a=route.spec.candidate; const auto& b=spec.candidate;
        return a.id==b.id && a.kind==b.kind && a.family==b.family &&
            a.address==b.address && a.port==b.port && a.transport_mask==b.transport_mask &&
            a.evidence==b.evidence && a.scope==b.scope &&
            a.topology_generation==b.topology_generation &&
            a.expires_monotonic_ms==b.expires_monotonic_ms &&
            a.interface_id==b.interface_id && a.rtt_ms==b.rtt_ms;
    }
    return false;
}
namespace {
std::uint64_t AddTime(std::uint64_t time, std::uint64_t delta) noexcept
{
    const auto maximum = std::numeric_limits<std::uint64_t>::max();
    return time > maximum - delta ? maximum : time + delta;
}
bool DirectTcpRoute(const DirectSessionRoute& route) noexcept
{
    return route.transport == DirectTcp &&
        (route.candidate.kind == DirectKind::DirectV6 ||
         route.candidate.kind == DirectKind::DirectV4);
}
std::uint64_t ConnectBudget(const DirectSessionRoute& route) noexcept
{
    if (route.candidate.kind == DirectKind::Callback) return 2500;
    if (route.candidate.kind == DirectKind::Punch2) return 3500;
    return route.transport == DirectTcp ? 1500 : 4000;
}
}

DirectSession::DirectSession(DirectHandle handle, std::uint64_t generation,
                             std::uint64_t now_ms)
    : handle_(handle), topology_generation_(generation), last_now_ms_(now_ms),
      deadline_ms_(AddTime(now_ms, 15000))
{
    if (!handle.generation || !generation) {
        state_ = DirectSessionState::Failed;
        reason_ = DirectReason::ResourceLimit;
        RememberReason(0,reason_);
    }
}

bool DirectSession::Terminal() const noexcept
{
    return state_ == DirectSessionState::Failed || state_ == DirectSessionState::Cancelled;
}

bool DirectSession::RecordRecoveryOutcome(std::uint64_t epoch,DirectRecoveryOutcome outcome) noexcept
{
    if(state_!=DirectSessionState::Recovering || epoch!=epoch_ ||
        recovery_cause_==DirectReason::None) return false;
    switch(outcome) {
    case DirectRecoveryOutcome::AcquiringEvidence:
    case DirectRecoveryOutcome::NoCandidate:
    case DirectRecoveryOutcome::EvidenceExpired:
    case DirectRecoveryOutcome::NoAuthenticatedIdentity:
    case DirectRecoveryOutcome::IdentityRejected:
    case DirectRecoveryOutcome::AuthenticationTimedOut:
    case DirectRecoveryOutcome::ConnectionFailed:
    case DirectRecoveryOutcome::Exhausted:
    case DirectRecoveryOutcome::Cancelled:
    case DirectRecoveryOutcome::NetworkChanged:
        recovery_outcome_=outcome;
        return true;
    default:
        return false; // connection, authentication and data milestones require actual events
    }
}

void DirectSession::RememberReason(std::uint32_t route, DirectReason reason) noexcept
{
    if (reason == DirectReason::None) return;
    if (reason_count_ && reasons_[reason_count_-1].route_id == route &&
        reasons_[reason_count_-1].reason == reason) return;
    if (reason_count_ == reasons_.size()) {
        std::move(reasons_.begin()+1,reasons_.end(),reasons_.begin());
        --reason_count_;
    }
    reasons_[reason_count_++] = {route,reason};
}

void DirectSession::Close(Route& route, DirectReason reason,
                           std::vector<DirectSessionAction>& actions)
{
    if (route.phase == Phase::Closed) return;
    RememberReason(route.spec.id,reason);
    if (reason != DirectReason::None) reason_ = reason;
    if (route.phase != Phase::Pending)
        actions.push_back({DirectActionType::Close, route.spec.id, epoch_, reason});
    route.phase = Phase::Closed;
}

std::vector<DirectSessionAction> DirectSession::Finish(
    DirectSessionState state, DirectReason reason)
{
    std::vector<DirectSessionAction> actions;
    if (Terminal()) return actions;
    // Complete allocation before changing state or ownership. In particular,
    // authenticated identity merges must not half-cancel on allocation failure.
    actions.reserve(routes_.size()+1);
    if(recovery_cause_!=DirectReason::None) {
        // Preserve an acquisition failure supplied by the host. Terminal reason
        // still describes the attempt, independently of why recovery began.
        if(reason==DirectReason::StaleTopology)
            recovery_outcome_=DirectRecoveryOutcome::NetworkChanged;
        else if(state==DirectSessionState::Cancelled &&
            (reason==DirectReason::Disabled || reason==DirectReason::PeerGone))
            recovery_outcome_=DirectRecoveryOutcome::Cancelled;
        else if(recovery_outcome_<DirectRecoveryOutcome::NoCandidate ||
            recovery_outcome_==DirectRecoveryOutcome::RouteAuthenticated) {
            switch(reason) {
            case DirectReason::IdentityMismatch:
            case DirectReason::PinChanged:recovery_outcome_=DirectRecoveryOutcome::IdentityRejected;break;
            case DirectReason::AuthTimeout:recovery_outcome_=DirectRecoveryOutcome::AuthenticationTimedOut;break;
            case DirectReason::NoCandidate:recovery_outcome_=DirectRecoveryOutcome::NoCandidate;break;
            case DirectReason::DirectUnreachable:recovery_outcome_=DirectRecoveryOutcome::ConnectionFailed;break;
            default:recovery_outcome_=DirectRecoveryOutcome::Exhausted;break;
            }
        }
    }
    state_ = state;
    reason_ = reason;
    for (auto& route : routes_) Close(route, reason, actions);
    RememberReason(0,reason);
    winner_ = 0;
    actions.push_back({DirectActionType::Terminal, 0, epoch_, reason});
    return actions;
}

std::vector<DirectSessionAction> DirectSession::SetRoutes(
    const std::vector<DirectSessionRoute>& routes, std::uint64_t now_ms)
{
    if ((state_ != DirectSessionState::Gathering &&
         state_ != DirectSessionState::Recovering) || now_ms < last_now_ms_) return {};
    last_now_ms_ = now_ms;
    if (now_ms >= deadline_ms_) return Finish(DirectSessionState::Failed, DirectReason::Deadline);
    if (routes.size() > kDirectMaxRoutes)
        return Finish(DirectSessionState::Failed, DirectReason::ResourceLimit);
    routes_.clear();
    for (const auto& spec : routes) {
        if (!spec.id || spec.id <= highest_route_id_ ||
            (spec.transport != DirectTcp && spec.transport != DirectUtp &&
                         spec.transport != DirectQuic) ||
            !(spec.candidate.transport_mask & spec.transport) ||
            spec.candidate.topology_generation != topology_generation_ ||
            spec.candidate.expires_monotonic_ms <= now_ms ||
            (spec.recovery_authentication &&
                (state_!=DirectSessionState::Recovering || !epoch_ || spec.transport!=DirectTcp ||
                 !spec.candidate.id || !spec.candidate.port || spec.candidate.transport_mask!=DirectTcp ||
                 (spec.candidate.kind!=DirectKind::DirectV4 && spec.candidate.kind!=DirectKind::VerifiedMapping) ||
                 spec.candidate.family!=4 ||
                 spec.candidate.evidence!=DirectEvidence::Advertised ||
                 spec.candidate.scope!=DirectScope::Global || spec.candidate.interface_id)) ||
            std::any_of(routes_.begin(), routes_.end(),
                [&](const Route& old) { return old.spec.id == spec.id; }))
            return Finish(DirectSessionState::Failed, DirectReason::NoCandidate);
        routes_.push_back({spec});
    }
    for (const auto& route : routes_) highest_route_id_ = std::max(highest_route_id_, route.spec.id);
    if (routes_.empty()) return Finish(DirectSessionState::Failed, DirectReason::NoCandidate);
    state_ = DirectSessionState::Connecting;
    std::vector<DirectSessionAction> actions;
    Schedule(now_ms, actions);
    return actions;
}

void DirectSession::Schedule(std::uint64_t now_ms,
                              std::vector<DirectSessionAction>& actions)
{
    if (Terminal() || winner_ || state_ == DirectSessionState::Recovering ||
        state_ == DirectSessionState::Gathering) return;
    std::size_t active = 0;
    const Route* existing = nullptr;
    for (const auto& route : routes_) {
        if (route.phase == Phase::Connecting || route.phase == Phase::Authenticating) {
            ++active;
            existing = &route;
        }
    }
    for (auto& route : routes_) {
        if (route.phase != Phase::Pending) continue;
        if (route.spec.candidate.expires_monotonic_ms <= now_ms) {
            route.phase = Phase::Closed;
            if(recovery_cause_!=DirectReason::None)
                recovery_outcome_=DirectRecoveryOutcome::EvidenceExpired;
            continue;
        }
        if (active) {
            // Only IPv6/IPv4 TCP direct Happy Eyeballs may overlap.
            if (active != 1 || !existing || !DirectTcpRoute(existing->spec) ||
                existing->spec.candidate.family != 6 || !DirectTcpRoute(route.spec) ||
                route.spec.candidate.family != 4 ||
                now_ms < AddTime(existing->started_ms, 200)) return;
        }
        if(!active && route_started_ && fallback_count_!=(std::numeric_limits<std::uint64_t>::max)()) ++fallback_count_;
        route_started_=true;
        route.phase = Phase::Connecting;
        route.started_ms = now_ms;
        route.deadline_ms = std::min(deadline_ms_, AddTime(now_ms, ConnectBudget(route.spec)));
        actions.push_back({DirectActionType::Start, route.spec.id, epoch_, DirectReason::None});
        ++active;
        existing = &route;
        if (active == 2 || route.spec.candidate.family != 6 || !DirectTcpRoute(route.spec)) return;
    }
    if (!active) {
        auto terminal = Finish(DirectSessionState::Failed,
            reason_ == DirectReason::None ? DirectReason::NoRoute : reason_);
        actions.insert(actions.end(), terminal.begin(), terminal.end());
    }
}

std::vector<DirectSessionAction> DirectSession::Advance(std::uint64_t now_ms,
    const std::vector<DirectSessionEvent>& events)
{
    if (Terminal() || now_ms < last_now_ms_) return {};
    if (events.size() > 4096) return {}; // bounded queue owner retries with backpressure
    last_now_ms_ = now_ms;
    // Core deadline applies to connection/recovery; a useful established session
    // is governed by its consumer's application-progress deadline.
    if (!winner_ && now_ms >= deadline_ms_)
        return Finish(DirectSessionState::Failed, DirectReason::Deadline);
    std::vector<DirectSessionAction> actions;
    for (auto& route : routes_) {
        if ((route.phase == Phase::Connecting || route.phase == Phase::Authenticating) &&
            (now_ms >= route.deadline_ms ||
             now_ms >= route.spec.candidate.expires_monotonic_ms))
        {
            if(recovery_cause_!=DirectReason::None && now_ms>=route.spec.candidate.expires_monotonic_ms)
                recovery_outcome_=DirectRecoveryOutcome::EvidenceExpired;
            Close(route, route.phase == Phase::Authenticating ?
                DirectReason::AuthTimeout : DirectReason::DirectUnreachable, actions);
        }
    }
    // Keep per-route ordering, then nominate all successes in plan order.
    auto ordered = events;
    std::stable_sort(ordered.begin(), ordered.end(), [](const auto& a, const auto& b) {
        return a.route_id != b.route_id ? a.route_id < b.route_id : a.sequence < b.sequence;
    });
    std::vector<std::uint32_t> authenticated;
    for (const auto& event : ordered) {
        if (event.handle.slot != handle_.slot || event.handle.generation != handle_.generation ||
            event.topology_generation != topology_generation_ ||
            event.session_epoch != epoch_) continue;
        auto it = std::find_if(routes_.begin(), routes_.end(),
            [&](const Route& route) { return route.spec.id == event.route_id; });
        if (it == routes_.end() || it->phase == Phase::Pending || it->phase == Phase::Closed ||
            !event.sequence || event.sequence <= it->last_sequence) continue;
        if ((event.type == DirectEventType::UsefulRange || event.type == DirectEventType::VerifiedPart) &&
            (it->phase != Phase::Winner || event.session_epoch != epoch_)) continue;
        it->last_sequence = event.sequence;
        switch (event.type) {
        case DirectEventType::Connected:
            if (it->phase == Phase::Connecting) {
                it->phase = Phase::Authenticating;
                it->deadline_ms = std::min(deadline_ms_, AddTime(now_ms, 5000));
                state_ = DirectSessionState::Authenticating;
                if(recovery_cause_!=DirectReason::None)
                    recovery_outcome_=it->spec.transport==DirectTcp ?
                        DirectRecoveryOutcome::TcpConnected : DirectRecoveryOutcome::Authenticating;
            }
            break;
        case DirectEventType::Authenticated:
            if (it->phase == Phase::Authenticating) authenticated.push_back(it->spec.id);
            break;
        case DirectEventType::AuthenticationFailed:
            if (it->phase == Phase::Authenticating)
                Close(*it, event.reason==DirectReason::None ? DirectReason::IdentityMismatch : event.reason, actions);
            break;
        case DirectEventType::Closed:
            Close(*it, event.reason==DirectReason::None ? DirectReason::NoRoute : event.reason, actions);
            if (winner_ == it->spec.id) {
                // An authenticated peer changing identity is not a network outage.
                // Preserve the typed failure and already queued close actions.
                if (event.reason == DirectReason::IdentityMismatch ||
                    event.reason == DirectReason::PinChanged) {
                    auto terminal = Finish(DirectSessionState::Failed, event.reason);
                    actions.insert(actions.end(), terminal.begin(), terminal.end());
                    return actions;
                }
                winner_ = 0;
                state_ = DirectSessionState::Recovering;
                deadline_ms_ = AddTime(now_ms, 15000);
                if(recovery_cause_==DirectReason::None)
                    recovery_cause_=event.reason==DirectReason::None ? DirectReason::NoRoute : event.reason;
                recovery_outcome_=DirectRecoveryOutcome::AcquiringEvidence;
            }
            break;
        case DirectEventType::UsefulRange:
            if (event.useful_bytes && event.useful_bytes <=
                std::numeric_limits<std::uint64_t>::max() - useful_bytes_) {
                useful_bytes_ += event.useful_bytes;
                epoch_useful_bytes_ += event.useful_bytes; // bounded by cumulative counter above
                state_ = DirectSessionState::Transferring;
                if(recovery_cause_!=DirectReason::None && !epoch_transfer_verified_)
                    recovery_outcome_=DirectRecoveryOutcome::Receiving;
            }
            break;
        case DirectEventType::VerifiedPart:
            transfer_verified_ = true;
            epoch_transfer_verified_ = true;
            if(recovery_cause_!=DirectReason::None)
                recovery_outcome_=DirectRecoveryOutcome::VerifiedData;
            break;
        }
    }
    if (!winner_) {
        for (auto& route : routes_) {
            if (route.phase != Phase::Authenticating ||
                std::find(authenticated.begin(), authenticated.end(), route.spec.id) == authenticated.end())
                continue;
            winner_ = route.spec.id;
            ++epoch_;
            epoch_useful_bytes_=0;
            epoch_transfer_verified_=false;
            route.phase = Phase::Winner;
            state_ = DirectSessionState::Ready;
            reason_ = DirectReason::None;
            if(recovery_cause_!=DirectReason::None)
                recovery_outcome_=route.spec.transport==DirectTcp ?
                    DirectRecoveryOutcome::TcpAuthenticated : DirectRecoveryOutcome::RouteAuthenticated;
            actions.push_back({DirectActionType::Attach, winner_, epoch_, DirectReason::None});
            for (auto& other : routes_)
                if (other.spec.id != winner_) Close(other, DirectReason::None, actions);
            break;
        }
    }
    Schedule(now_ms, actions);
    return actions;
}

std::vector<DirectSessionAction> DirectSession::Cancel(DirectReason reason)
{
    return Finish(DirectSessionState::Cancelled, reason);
}

std::vector<DirectSessionAction> DirectSession::InvalidateTopology(std::uint64_t generation)
{
    return generation == topology_generation_ ? std::vector<DirectSessionAction>{}
        : Finish(DirectSessionState::Failed, DirectReason::StaleTopology);
}
} // namespace reach
