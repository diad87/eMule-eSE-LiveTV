// SPDX-License-Identifier: MIT
#pragma once

#include "reach/direct_attempt.h"

namespace reach {

struct DirectHandle {
    std::uint32_t slot = 0;
    std::uint32_t generation = 0;
};

enum class DirectSessionState : std::uint8_t {
    Gathering, Connecting, Authenticating, Ready, Transferring, Recovering,
    Failed, Cancelled
};

enum class DirectReason : std::uint8_t {
    None, NoCandidate, NoRoute, Deadline, IdentityMismatch,
    StaleTopology, Disabled, PeerGone, ResourceLimit, AuthTimeout, DirectUnreachable,
    PeerIncompatible, CapabilityMissing, PinChanged, UdpBlocked, QuicNoProgress,
    MtuTooSmall, BootstrapRequired, DiscoveryUnavailable, StaleDescriptor,
    RendezvousUnavailable, LegacyCallbackUnavailable, UnsupportedRemote
};

enum class DirectEventType : std::uint8_t {
    Connected, Authenticated, AuthenticationFailed, Closed,
    UsefulRange, VerifiedPart
};

struct DirectSessionEvent {
    DirectHandle handle;
    std::uint64_t topology_generation = 0;
    std::uint32_t route_id = 0;
    std::uint64_t sequence = 0;
    std::uint64_t session_epoch = 0;
    DirectEventType type = DirectEventType::Connected;
    std::uint64_t useful_bytes = 0;
    DirectReason reason = DirectReason::None;
};

enum class DirectActionType : std::uint8_t { Start, Close, Attach, Terminal };

inline constexpr std::size_t kDirectMaxReasons = 16;
struct DirectReasonEntry {
    std::uint32_t route_id = 0; // zero denotes the attempt itself
    DirectReason reason = DirectReason::None;
};

struct DirectSessionAction {
    DirectActionType type = DirectActionType::Start;
    std::uint32_t route_id = 0;
    std::uint64_t session_epoch = 0;
    DirectReason reason = DirectReason::None;
};

struct DirectSessionRoute {
    std::uint32_t id = 0;
    DirectCandidate candidate;
    std::uint8_t transport = 0; // exactly one DirectTransport bit
};

// Main-thread-owned controller. Adapters execute returned actions after this
// call returns; no callbacks or host pointers enter the state machine.
// Authentication events are submitted as one main-loop batch so simultaneous
// successes choose by route priority, independently of callback arrival order.
class DirectSession {
public:
    DirectSession(DirectHandle handle, std::uint64_t topology_generation,
                  std::uint64_t now_ms);
    std::vector<DirectSessionAction> SetRoutes(
        const std::vector<DirectSessionRoute>& routes, std::uint64_t now_ms);
    std::vector<DirectSessionAction> Advance(std::uint64_t now_ms,
        const std::vector<DirectSessionEvent>& events = {});
    std::vector<DirectSessionAction> Cancel(DirectReason reason);
    std::vector<DirectSessionAction> InvalidateTopology(std::uint64_t generation);

    DirectSessionState State() const noexcept { return state_; }
    DirectReason Reason() const noexcept { return reason_; }
    // Sequential route starts after the first; HE overlap is not a fallback.
    std::uint64_t FallbackCount() const noexcept { return fallback_count_; }
    std::uint32_t Winner() const noexcept { return winner_; }
    std::uint32_t HighestRouteId() const noexcept { return highest_route_id_; }
    std::uint64_t Epoch() const noexcept { return epoch_; }
    std::uint64_t UsefulBytes() const noexcept { return useful_bytes_; }
    bool TransferVerified() const noexcept { return transfer_verified_; }
    const std::array<DirectReasonEntry,kDirectMaxReasons>& ReasonChain() const noexcept { return reasons_; }
    std::size_t ReasonCount() const noexcept { return reason_count_; }
    bool AwaitingAuthentication(std::uint32_t route, std::uint64_t epoch) const noexcept;
    bool AuthorizesStart(const DirectSessionRoute&, std::uint64_t epoch) const noexcept;
    std::vector<DirectSessionRoute> RoutesSnapshot() const {
        std::vector<DirectSessionRoute> result;
        result.reserve(routes_.size());
        for(const auto& route:routes_) result.push_back(route.spec);
        return result;
    }
    bool UsesOnlyTransport(std::uint8_t transport) const noexcept {
        for(const auto& route:routes_) if(route.spec.transport!=transport) return false;
        return true; // no routes means no adapter was started
    }

private:
    enum class Phase : std::uint8_t { Pending, Connecting, Authenticating, Winner, Closed };
    struct Route {
        DirectSessionRoute spec;
        Phase phase = Phase::Pending;
        std::uint64_t deadline_ms = 0;
        std::uint64_t last_sequence = 0;
        std::uint64_t started_ms = 0;
    };
    bool Terminal() const noexcept;
    void RememberReason(std::uint32_t route, DirectReason reason) noexcept;
    std::vector<DirectSessionAction> Finish(DirectSessionState state, DirectReason reason);
    void Schedule(std::uint64_t now_ms, std::vector<DirectSessionAction>& actions);
    void Close(Route& route, DirectReason reason, std::vector<DirectSessionAction>& actions);

    DirectHandle handle_;
    std::uint64_t topology_generation_;
    std::uint64_t last_now_ms_;
    std::uint64_t deadline_ms_;
    std::vector<Route> routes_;
    DirectSessionState state_ = DirectSessionState::Gathering;
    DirectReason reason_ = DirectReason::None;
    std::uint32_t winner_ = 0;
    std::uint32_t highest_route_id_ = 0; // route IDs cannot be reused within this handle
    std::uint64_t epoch_ = 0;
    std::uint64_t useful_bytes_ = 0;
    std::uint64_t fallback_count_=0;
    bool route_started_=false;
    bool transfer_verified_ = false;
    std::array<DirectReasonEntry,kDirectMaxReasons> reasons_{};
    std::size_t reason_count_ = 0;
};

} // namespace reach
