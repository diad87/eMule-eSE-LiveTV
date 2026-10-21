// SPDX-License-Identifier: MIT
#pragma once
#include "reach/direct_session.h"
#include <optional>
#include <limits>

namespace reach {
inline constexpr std::size_t kDirectMaxAttempts = 256;
inline constexpr std::size_t kDirectMaxSubscribers = 16;

// Identity domains stay distinct even when their byte representation matches.
enum class DirectPeerDomain : std::uint8_t { NodePublicKey, UserHash, Provisional };
struct DirectPeerKey {
    DirectPeerDomain domain = DirectPeerDomain::Provisional;
    std::array<std::uint8_t, 32> identity{};
    std::uint64_t source_record_id = 0;
    std::uint64_t source_epoch = 0;
};
using DirectAttemptId = std::array<std::uint8_t, 16>;

enum class DirectRequestStatus : std::uint8_t {
    Created, Joined, InvalidRequest, ResourceLimit, AwaitingRelease, StaleTopology
};
struct DirectRequestResult {
    DirectRequestStatus status = DirectRequestStatus::InvalidRequest;
    DirectHandle handle;
};
struct DirectCoordinatorBatch {
    DirectHandle handle;
    std::vector<DirectSessionAction> actions;
    std::vector<std::uint64_t> terminal_subscribers;
};
struct DirectCoordinatorSnapshot {
    DirectHandle handle;
    DirectAttemptId attempt_id{};
    DirectPeerKey peer;
    DirectSessionState state = DirectSessionState::Gathering;
    DirectReason reason = DirectReason::None;
    std::uint32_t winner = 0;
    std::uint64_t epoch = 0;
    std::uint64_t useful_bytes = 0;
    bool transfer_verified = false;
    std::size_t subscribers = 0;
    std::uint64_t topology_generation = 0;
    std::uint32_t highest_route_id = 0;
    std::array<DirectReasonEntry,kDirectMaxReasons> reason_chain{};
    std::size_t reason_count = 0;
    std::uint64_t fallback_count=0;
    // Allocation floor only, never permission to start or authenticate a route.
    std::uint32_t NextRouteId(std::uint32_t requested=1) const noexcept {
        if(!requested || highest_route_id==(std::numeric_limits<std::uint32_t>::max)()) return 0;
        return requested>highest_route_id ? requested : highest_route_id+1;
    }
};

enum class DirectIdentityResolution : std::uint8_t {
    Rejected, Unchanged, Promoted, Merged, ResourceLimit
};
struct DirectIdentityResult {
    DirectIdentityResolution status = DirectIdentityResolution::Rejected;
    DirectHandle destination;
    DirectCoordinatorBatch retired;
    std::vector<std::uint64_t> moved_subscribers;
};

// Main-thread-only bounded registry; it never stores a CUpDownClient pointer.
// The host supplies CSPRNG attempt IDs and executes actions outside callbacks.
// Release is explicit after adapters have drained, preventing slot reuse while
// a transport still owns resources. Reused slots receive a new generation.
class DirectCoordinator {
public:
    DirectRequestResult Request(const DirectPeerKey& peer, std::uint64_t subscriber,
        const DirectAttemptId& attempt_id, std::uint64_t topology_generation,
        std::uint64_t now_ms);
    // Caller must authenticate incoming consent before calling this API.
    // Unlike local Request, never join a different wire attempt for the peer.
    // This admission creates no route, identity trust or transport permission.
    DirectRequestResult RequestSharedAttempt(const DirectPeerKey&,std::uint64_t subscriber,
        const DirectAttemptId&,std::uint64_t topology_generation,std::uint64_t now_ms);
    DirectCoordinatorBatch SetRoutes(DirectHandle handle,
        const std::vector<DirectSessionRoute>& routes, std::uint64_t now_ms);
    DirectCoordinatorBatch Advance(DirectHandle handle, std::uint64_t now_ms,
        const std::vector<DirectSessionEvent>& events = {});
    DirectCoordinatorBatch Cancel(DirectHandle handle, DirectReason reason);
    // Owning host calls only after cryptographic identity verification, before
    // publishing Authenticated. Never derive this key from an endpoint/HELLO.
    // Merged closes the redundant source; caller must rebind moved subscribers
    // and execute retired actions before delivering any source payload.
    DirectIdentityResult ResolveAuthenticatedPeer(DirectHandle,std::uint32_t route,
        std::uint64_t epoch,const DirectPeerKey& authenticated);
    std::vector<DirectCoordinatorBatch> AdvanceAll(std::uint64_t now_ms,
        const std::vector<DirectSessionEvent>& events = {});
    DirectCoordinatorBatch Unsubscribe(DirectHandle handle, std::uint64_t subscriber);
    std::vector<DirectCoordinatorBatch> InvalidateTopology(std::uint64_t generation);
    bool Release(DirectHandle handle);
    std::optional<DirectCoordinatorSnapshot> Snapshot(DirectHandle handle) const;
    // Owner-thread inventory, bounded by kDirectMaxAttempts; not route authority.
    std::vector<DirectHandle> ActiveHandles() const;
    bool AuthorizesStart(DirectHandle,const DirectSessionRoute&,std::uint64_t epoch) const noexcept;
    bool UsesOnlyTransport(DirectHandle,std::uint8_t) const noexcept;
    std::optional<std::vector<DirectSessionRoute>> RoutesSnapshot(DirectHandle) const;
    std::size_t Size() const noexcept { return size_; }

private:
    struct Slot {
        std::uint32_t generation = 0;
        DirectPeerKey peer;
        DirectAttemptId attempt_id{};
        std::uint64_t topology_generation = 0;
        std::vector<std::uint64_t> subscribers;
        std::optional<DirectSession> session;
    };
    Slot* Resolve(DirectHandle handle) noexcept;
    const Slot* Resolve(DirectHandle handle) const noexcept;
    static DirectCoordinatorBatch Batch(DirectHandle handle, const Slot& slot,
        std::vector<DirectSessionAction> actions);
    std::array<Slot, kDirectMaxAttempts> slots_{};
    std::size_t size_ = 0;
};
} // namespace reach
