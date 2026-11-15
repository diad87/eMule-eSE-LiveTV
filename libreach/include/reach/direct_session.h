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

// Diagnostic milestones for an established-session recovery. These values do
// not grant route authority. In particular, TcpAuthenticated is not evidence
// that the requested file is available, or that any new bytes were received.
enum class DirectRecoveryOutcome : std::uint8_t {
    None, AcquiringEvidence, TcpConnected, Authenticating, TcpAuthenticated,
    Receiving, VerifiedData, NoCandidate, EvidenceExpired,
    NoAuthenticatedIdentity, IdentityRejected, AuthenticationTimedOut,
    ConnectionFailed, FileUnavailable, RemoteQueue, Exhausted, Cancelled,
    NetworkChanged, RouteAuthenticated
};

inline const char* DirectRecoveryOutcomeName(DirectRecoveryOutcome outcome) noexcept {
    switch(outcome) {
    case DirectRecoveryOutcome::None:return "NONE";
    case DirectRecoveryOutcome::AcquiringEvidence:return "ACQUIRING_EVIDENCE";
    case DirectRecoveryOutcome::TcpConnected:return "TCP_CONNECTED";
    case DirectRecoveryOutcome::Authenticating:return "AUTHENTICATING";
    case DirectRecoveryOutcome::TcpAuthenticated:return "TCP_AUTHENTICATED";
    case DirectRecoveryOutcome::Receiving:return "RECEIVING";
    case DirectRecoveryOutcome::VerifiedData:return "VERIFIED_DATA";
    case DirectRecoveryOutcome::NoCandidate:return "NO_CANDIDATE";
    case DirectRecoveryOutcome::EvidenceExpired:return "EVIDENCE_EXPIRED";
    case DirectRecoveryOutcome::NoAuthenticatedIdentity:return "NO_AUTHENTICATED_IDENTITY";
    case DirectRecoveryOutcome::IdentityRejected:return "IDENTITY_REJECTED";
    case DirectRecoveryOutcome::AuthenticationTimedOut:return "AUTHENTICATION_TIMED_OUT";
    case DirectRecoveryOutcome::ConnectionFailed:return "CONNECTION_FAILED";
    case DirectRecoveryOutcome::FileUnavailable:return "FILE_UNAVAILABLE";
    case DirectRecoveryOutcome::RemoteQueue:return "REMOTE_QUEUE";
    case DirectRecoveryOutcome::Exhausted:return "EXHAUSTED";
    case DirectRecoveryOutcome::Cancelled:return "CANCELLED";
    case DirectRecoveryOutcome::NetworkChanged:return "NETWORK_CHANGED";
    case DirectRecoveryOutcome::RouteAuthenticated:return "ROUTE_AUTHENTICATED";
    }
    return "UNAVAILABLE";
}

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
    // Explicit host-issued purpose, never inferred from Advertised evidence.
    // The adapter must claim its scoped permission before opening the socket.
    bool recovery_authentication = false;
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
    // Owner-side acquisition diagnostics only: no actions, counter changes,
    // authentication, or writable-route permission can be produced here.
    bool RecordRecoveryOutcome(std::uint64_t epoch, DirectRecoveryOutcome) noexcept;

    DirectSessionState State() const noexcept { return state_; }
    DirectReason Reason() const noexcept { return reason_; }
    // Sequential route starts after the first; HE overlap is not a fallback.
    std::uint64_t FallbackCount() const noexcept { return fallback_count_; }
    std::uint32_t Winner() const noexcept { return winner_; }
    std::uint32_t HighestRouteId() const noexcept { return highest_route_id_; }
    std::uint64_t Epoch() const noexcept { return epoch_; }
    std::uint64_t UsefulBytes() const noexcept { return useful_bytes_; }
    bool TransferVerified() const noexcept { return transfer_verified_; }
    DirectReason RecoveryCause() const noexcept { return recovery_cause_; }
    DirectRecoveryOutcome RecoveryOutcome() const noexcept { return recovery_outcome_; }
    std::uint64_t EpochUsefulBytes() const noexcept { return epoch_useful_bytes_; }
    bool EpochTransferVerified() const noexcept { return epoch_transfer_verified_; }
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
    // The original cause survives a successful attach and later failed retries.
    // Cumulative file contributions above are never reset by a new transport.
    DirectReason recovery_cause_ = DirectReason::None;
    DirectRecoveryOutcome recovery_outcome_ = DirectRecoveryOutcome::None;
    std::uint64_t epoch_useful_bytes_ = 0;
    bool epoch_transfer_verified_ = false;
    std::array<DirectReasonEntry,kDirectMaxReasons> reasons_{};
    std::size_t reason_count_ = 0;
};

} // namespace reach
