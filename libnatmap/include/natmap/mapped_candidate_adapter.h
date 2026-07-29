#pragma once

#include "natmap/address_policy.h"
#include "natmap/mapper_result.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <thread>

namespace natmap {

struct MappedCandidatePublisherTestAccess;

enum class MappedCandidateVerification : std::uint8_t {
    Candidate = 0,
    Verified = 1,
};

enum class MappedCandidateUpdate : std::uint8_t {
    Published = 0,
    Renewed = 1,
    Replaced = 2,
    Rejected = 3,
    Stale = 4,
    Closed = 5,
    WrongThread = 6,
    Exhausted = 7,
};

enum class MappedCandidatePromotion : std::uint8_t {
    Promoted = 0,
    AlreadyVerified = 1,
    Rejected = 2,
    Stale = 3,
    Closed = 4,
    WrongThread = 5,
};

enum class MappedCandidateRetirement : std::uint8_t {
    Retired = 0,
    NoChange = 1,
    Closed = 2,
    WrongThread = 3,
    Rejected = 4,
};

struct MappedCandidateProof {
    VerificationAttempt attempt{};
    Evidence primary{};
    Evidence inbound{};
};

// Process-local actionable view. It intentionally exposes real Endpoint
// values through const accessors and has no JSON or serialization surface.
// The sanitized DirectCandidateSnapshotV1 projection must never be used to
// reconstruct this object.
class MappedCandidate {
public:
    MappedCandidate() noexcept = default;

    std::uint64_t candidate_id() const noexcept {
        return candidate_id_;
    }
    Transport transport() const noexcept { return transport_; }
    const Endpoint& local_endpoint() const noexcept {
        return local_endpoint_;
    }
    const Endpoint& published_endpoint() const noexcept {
        return published_endpoint_;
    }
    const Endpoint& gateway() const noexcept { return gateway_; }
    const RouteBindingIdentity& route_binding() const noexcept {
        return route_binding_;
    }
    MapperKind mapper() const noexcept { return mapper_; }
    MapperSource mapper_source() const noexcept {
        return mapper_source_;
    }
    std::uint32_t mapper_epoch() const noexcept {
        return mapper_epoch_;
    }
    std::uint64_t topology_generation() const noexcept {
        return topology_generation_;
    }
    std::uint64_t effective_expiry_monotonic_ms() const noexcept {
        return effective_expiry_monotonic_ms_;
    }
    MappedCandidateVerification verification() const noexcept {
        return verification_;
    }
    bool SameOwnedMapping(
        const MapperResultData& data) const noexcept;

private:
    friend class MappedCandidatePublisher;

    std::uint64_t candidate_id_ = 0;
    Transport transport_ = Transport::Tcp;
    Endpoint local_endpoint_{};
    Endpoint published_endpoint_{};
    Endpoint gateway_{};
    RouteBindingIdentity route_binding_{};
    MapperKind mapper_ = MapperKind::None;
    MapperSource mapper_source_ = MapperSource::None;
    std::uint32_t mapper_epoch_ = 0;
    std::array<std::uint8_t, 12> ownership_nonce_{};
    std::array<std::uint8_t, 32> ownership_identity_digest_{};
    std::uint64_t topology_generation_ = 0;
    std::uint64_t effective_expiry_monotonic_ms_ = 0;
    MappedCandidateVerification verification_ =
        MappedCandidateVerification::Candidate;
    VerificationAttempt verification_attempt_{};
    Evidence primary_evidence_{};
    Evidence inbound_evidence_{};
};

class MappedCandidateSnapshot {
public:
    std::uint64_t topology_generation() const noexcept {
        return topology_generation_;
    }
    std::uint64_t publication_sequence() const noexcept {
        return publication_sequence_;
    }
    std::size_t candidate_count() const noexcept {
        return candidate_count_;
    }
    const MappedCandidate* Find(Transport transport) const noexcept;
    bool HasVerifiedGlobalCandidate() const noexcept;

private:
    friend class MappedCandidatePublisher;
    friend struct MappedCandidatePublisherTestAccess;

    std::array<MappedCandidate, 2> candidates_{};
    std::size_t candidate_count_ = 0;
    std::uint64_t topology_generation_ = 0;
    std::uint64_t publication_sequence_ = 0;
};

// Main-thread owner. Every mutation constructs and validates a complete next
// snapshot and publishes it with one value assignment. Mapper-reported
// verification bits are never sufficient for promotion.
class MappedCandidatePublisher {
public:
    explicit MappedCandidatePublisher(
        std::uint64_t initial_generation) noexcept;
    MappedCandidatePublisher(const MappedCandidatePublisher&) = delete;
    MappedCandidatePublisher& operator=(
        const MappedCandidatePublisher&) = delete;

    const MappedCandidateSnapshot& snapshot() const noexcept {
        return snapshot_;
    }
    bool is_closed() const noexcept { return closed_; }

    bool Reset(std::uint64_t initial_generation) noexcept;
    bool RequiresReplacement(
        const MapperResult& result,
        const RouteBindingIdentity& route_binding,
        std::uint64_t now_monotonic_ms) const noexcept;
    MappedCandidateUpdate ApplyMapping(
        const MapperResult& result,
        const RouteBindingIdentity& route_binding,
        std::uint64_t now_monotonic_ms,
        std::uint64_t committed_generation = 0) noexcept;
    MappedCandidatePromotion Promote(
        const MappedCandidateProof& proof,
        std::uint64_t now_monotonic_ms) noexcept;
    MappedCandidateRetirement WithdrawExpired(
        std::uint64_t now_monotonic_ms) noexcept;
    // A completed mapper observation that cannot be admitted supersedes any
    // earlier pair. Clear both transports in one publication and advance the
    // topology generation. The fence makes all proof captured for the prior
    // pair permanently stale before another result can enter.
    MappedCandidateRetirement WithdrawRejectedObservation() noexcept;
    MappedCandidateRetirement Invalidate(
        std::uint64_t next_generation) noexcept;
    MappedCandidateRetirement Shutdown() noexcept;

private:
    friend struct MappedCandidatePublisherTestAccess;

    bool IsOwnerThread() const noexcept;
    bool Publish(MappedCandidateSnapshot next) noexcept;
    void CloseFailClosed(
        std::uint64_t desired_generation = 0) noexcept;
    MappedCandidateRetirement RetireExpiredPair() noexcept;

    std::thread::id owner_thread_;
    MappedCandidateSnapshot snapshot_{};
    std::uint64_t next_candidate_id_ = 1;
    bool closed_ = false;
};

} // namespace natmap
