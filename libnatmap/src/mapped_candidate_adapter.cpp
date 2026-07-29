#include "natmap/mapped_candidate_adapter.h"

#include <algorithm>
#include <limits>

namespace natmap {
namespace {

bool SameAddress(const IpAddress& left,
                 const IpAddress& right) noexcept {
    return left.family == right.family &&
           left.bytes == right.bytes;
}

bool SameEndpoint(const Endpoint& left,
                  const Endpoint& right) noexcept {
    return left.source == right.source &&
           left.SameSocketEndpoint(right);
}

bool IsPublicV4(const Endpoint& endpoint) noexcept {
    return endpoint.IsUsable() &&
           endpoint.address.family == AddressFamily::IPv4 &&
           ClassifyAddress(endpoint.address).address_class ==
               AddressClass::Public;
}

const TransportMappingResult* FindMapping(
    const MapperResultData& data,
    Transport transport) noexcept {
    for (std::size_t i = 0; i < data.mapping_count; ++i)
        if (data.mappings[i].transport == transport)
            return &data.mappings[i];
    return nullptr;
}

bool IsCoherentPair(const MapperResultData& data,
                    const RouteBindingIdentity& route,
                    std::uint64_t now_ms) noexcept {
    const TransportMappingResult* tcp =
        FindMapping(data, Transport::Tcp);
    const TransportMappingResult* udp =
        FindMapping(data, Transport::Udp);
    if (tcp == nullptr || udp == nullptr ||
        !SameAddress(tcp->local_endpoint.address,
                     route.local_address) ||
        !SameAddress(udp->local_endpoint.address,
                     route.local_address) ||
        !SameAddress(tcp->granted_external_endpoint.address,
                     udp->granted_external_endpoint.address) ||
        tcp->lifetime_seconds != udp->lifetime_seconds ||
        !IsPublicV4(tcp->granted_external_endpoint) ||
        !IsPublicV4(udp->granted_external_endpoint))
        return false;
    if (tcp->lifetime_seconds == 0)
        return tcp->effective_expiry_monotonic_ms == 0 &&
               udp->effective_expiry_monotonic_ms == 0;
    return tcp->effective_expiry_monotonic_ms > now_ms &&
           udp->effective_expiry_monotonic_ms > now_ms;
}

bool CandidateMatches(
    const MappedCandidate& candidate,
    const MapperResultData& data,
    const TransportMappingResult& mapping,
    const RouteBindingIdentity& route) noexcept {
    return candidate.transport() == mapping.transport &&
           SameEndpoint(candidate.local_endpoint(),
                        mapping.local_endpoint) &&
           SameEndpoint(candidate.published_endpoint(),
                        mapping.granted_external_endpoint) &&
           SameEndpoint(candidate.gateway(), data.gateway) &&
           SameRouteBinding(candidate.route_binding(), route) &&
           candidate.SameOwnedMapping(data);
}

bool SameMappingIdentity(
    const MappedCandidateSnapshot& snapshot,
    const MapperResultData& data,
    const RouteBindingIdentity& route) noexcept {
    if (snapshot.candidate_count() != 2 ||
        data.mapper_epoch_reset)
        return false;
    const TransportMappingResult* tcp =
        FindMapping(data, Transport::Tcp);
    const TransportMappingResult* udp =
        FindMapping(data, Transport::Udp);
    const MappedCandidate* current_tcp =
        snapshot.Find(Transport::Tcp);
    const MappedCandidate* current_udp =
        snapshot.Find(Transport::Udp);
    return tcp != nullptr && udp != nullptr &&
           current_tcp != nullptr && current_udp != nullptr &&
           CandidateMatches(*current_tcp, data, *tcp, route) &&
           CandidateMatches(*current_udp, data, *udp, route);
}

bool AnyCandidateExpired(
    const MappedCandidateSnapshot& snapshot,
    std::uint64_t now_ms) noexcept {
    for (Transport transport :
         {Transport::Tcp, Transport::Udp}) {
        const MappedCandidate* candidate =
            snapshot.Find(transport);
        if (candidate == nullptr)
            return snapshot.candidate_count() != 0;
        if (candidate->effective_expiry_monotonic_ms() != 0 &&
            now_ms >=
                candidate->effective_expiry_monotonic_ms())
            return true;
    }
    return false;
}

bool IsCompleteSnapshot(
    const MappedCandidateSnapshot& snapshot) noexcept {
    if (snapshot.candidate_count() == 0)
        return true;
    const MappedCandidate* tcp =
        snapshot.Find(Transport::Tcp);
    const MappedCandidate* udp =
        snapshot.Find(Transport::Udp);
    return snapshot.candidate_count() == 2 &&
           tcp != nullptr && udp != nullptr &&
           tcp->topology_generation() ==
               snapshot.topology_generation() &&
           udp->topology_generation() ==
               snapshot.topology_generation();
}

bool IsFreshTcpProof(const MappedCandidateProof& proof,
                     const MappedCandidate& candidate,
                     std::uint64_t now_ms) noexcept {
    return proof.attempt.IsValid() &&
           proof.attempt.transport == Transport::Tcp &&
           proof.attempt.topology_generation ==
               candidate.topology_generation() &&
           proof.attempt.endpoint.SameSocketEndpoint(
               candidate.published_endpoint()) &&
           now_ms >= proof.attempt.started_monotonic_ms &&
           now_ms <= proof.attempt.deadline_monotonic_ms &&
           proof.primary.kind == EvidenceKind::ServerHighId &&
           proof.primary.IsFreshFor(proof.attempt) &&
           proof.primary.observed_monotonic_ms <= now_ms &&
           proof.inbound.kind == EvidenceKind::InboundTcpAccept &&
           proof.inbound.IsFreshFor(proof.attempt) &&
           proof.inbound.observed_monotonic_ms <= now_ms;
}

} // namespace

bool MappedCandidate::SameOwnedMapping(
    const MapperResultData& data) const noexcept {
    return mapper_ == data.mapper &&
           mapper_source_ == data.source &&
           ownership_nonce_ == data.ownership_nonce &&
           ownership_identity_digest_ ==
               data.ownership_identity_digest;
}

const MappedCandidate* MappedCandidateSnapshot::Find(
    Transport transport) const noexcept {
    for (std::size_t i = 0; i < candidate_count_; ++i)
        if (candidates_[i].transport() == transport)
            return &candidates_[i];
    return nullptr;
}

bool MappedCandidateSnapshot::HasVerifiedGlobalCandidate()
    const noexcept {
    for (std::size_t i = 0; i < candidate_count_; ++i)
        if (candidates_[i].verification() ==
            MappedCandidateVerification::Verified)
            return true;
    return false;
}

MappedCandidatePublisher::MappedCandidatePublisher(
    std::uint64_t initial_generation) noexcept
    : owner_thread_(std::this_thread::get_id()) {
    snapshot_.topology_generation_ = initial_generation;
}

bool MappedCandidatePublisher::IsOwnerThread() const noexcept {
    return owner_thread_ == std::this_thread::get_id();
}

bool MappedCandidatePublisher::Reset(
    std::uint64_t initial_generation) noexcept {
    if (!IsOwnerThread() || initial_generation == 0)
        return false;
    MappedCandidateSnapshot next{};
    next.topology_generation_ = initial_generation;
    snapshot_ = next;
    next_candidate_id_ = 1;
    closed_ = false;
    return true;
}

bool MappedCandidatePublisher::Publish(
    MappedCandidateSnapshot next) noexcept {
    if (!IsCompleteSnapshot(next) ||
        snapshot_.publication_sequence_ ==
        (std::numeric_limits<std::uint64_t>::max)())
        return false;
    next.publication_sequence_ =
        snapshot_.publication_sequence_ + 1;
    snapshot_ = next;
    return true;
}

void MappedCandidatePublisher::CloseFailClosed(
    std::uint64_t desired_generation) noexcept {
    MappedCandidateSnapshot empty{};
    empty.topology_generation_ =
        desired_generation > snapshot_.topology_generation_
        ? desired_generation
        : snapshot_.topology_generation_;
    empty.publication_sequence_ =
        snapshot_.publication_sequence_ ==
            (std::numeric_limits<std::uint64_t>::max)()
        ? snapshot_.publication_sequence_
        : snapshot_.publication_sequence_ + 1;
    snapshot_ = empty;
    closed_ = true;
}

MappedCandidateRetirement
MappedCandidatePublisher::RetireExpiredPair() noexcept {
    if (snapshot_.candidate_count_ == 0)
        return MappedCandidateRetirement::NoChange;
    if (snapshot_.topology_generation_ ==
        (std::numeric_limits<std::uint64_t>::max)()) {
        CloseFailClosed();
        return MappedCandidateRetirement::Closed;
    }
    MappedCandidateSnapshot empty{};
    empty.topology_generation_ =
        snapshot_.topology_generation_ + 1;
    if (!Publish(empty)) {
        CloseFailClosed(empty.topology_generation_);
        return MappedCandidateRetirement::Closed;
    }
    return MappedCandidateRetirement::Retired;
}

bool MappedCandidatePublisher::RequiresReplacement(
    const MapperResult& result,
    const RouteBindingIdentity& route_binding,
    std::uint64_t now_monotonic_ms) const noexcept {
    if (closed_ || snapshot_.candidate_count_ == 0)
        return false;
    if (now_monotonic_ms == 0 ||
        !result.IsStructurallyValid())
        return true;
    const MapperResultData& data = result.data();
    return data.operation != MappingOperation::Refresh ||
           data.status != MappingStatus::Renewed ||
           AnyCandidateExpired(snapshot_, now_monotonic_ms) ||
           !SameMappingIdentity(
               snapshot_, data, route_binding);
}

MappedCandidateUpdate MappedCandidatePublisher::ApplyMapping(
    const MapperResult& result,
    const RouteBindingIdentity& route_binding,
    std::uint64_t now_monotonic_ms,
    std::uint64_t committed_generation) noexcept {
    if (!IsOwnerThread())
        return MappedCandidateUpdate::WrongThread;
    if (closed_)
        return MappedCandidateUpdate::Closed;
    const bool prior_pair_expired =
        now_monotonic_ms != 0 &&
        AnyCandidateExpired(snapshot_, now_monotonic_ms);
    const auto RejectAfterExpiryCheck =
        [this, prior_pair_expired]() noexcept {
            if (prior_pair_expired)
                RetireExpiredPair();
            return MappedCandidateUpdate::Rejected;
        };
    if (now_monotonic_ms == 0 ||
        snapshot_.topology_generation_ == 0 ||
        !result.IsStructurallyValid())
        return RejectAfterExpiryCheck();

    const MapperResultData& data = result.data();
    if (!result.IsCurrent(snapshot_.topology_generation_) ||
        (data.operation != MappingOperation::Initial &&
         data.operation != MappingOperation::Refresh) ||
        (data.status != MappingStatus::Created &&
         data.status != MappingStatus::Renewed) ||
        data.ownership != OwnershipState::OwnedByUs ||
        ValidateRouteBinding(route_binding) !=
            RouteBindingStatus::Valid ||
        route_binding.origin != NetworkOrigin::Native ||
        data.request_interface_index !=
            route_binding.interface_index ||
        !SameAddress(data.request_local_address,
                     route_binding.local_address) ||
        !IsCoherentPair(data, route_binding,
                        now_monotonic_ms))
        return RejectAfterExpiryCheck();

    const bool identical =
        data.operation == MappingOperation::Refresh &&
        data.status == MappingStatus::Renewed &&
        !AnyCandidateExpired(snapshot_, now_monotonic_ms) &&
        SameMappingIdentity(snapshot_, data, route_binding);
    const bool had_candidates = snapshot_.candidate_count_ != 0;
    std::uint64_t generation = snapshot_.topology_generation_;
    if (!identical && snapshot_.candidate_count_ != 0) {
        if (generation ==
            (std::numeric_limits<std::uint64_t>::max)()) {
            CloseFailClosed();
            return MappedCandidateUpdate::Exhausted;
        }
        ++generation;
    }
    if (committed_generation != 0) {
        const bool allowed_empty_advance =
            snapshot_.candidate_count_ == 0 &&
            generation !=
                (std::numeric_limits<std::uint64_t>::max)() &&
            committed_generation == generation + 1;
        if (committed_generation != generation &&
            !allowed_empty_advance)
            return RejectAfterExpiryCheck();
        generation = committed_generation;
    }

    MappedCandidateSnapshot next{};
    next.topology_generation_ = generation;
    if (!identical &&
        (next_candidate_id_ == 0 ||
         next_candidate_id_ ==
             (std::numeric_limits<std::uint64_t>::max)())) {
        CloseFailClosed(generation);
        return MappedCandidateUpdate::Exhausted;
    }
    const Transport transports[] = {
        Transport::Tcp, Transport::Udp};
    for (Transport transport : transports) {
        const TransportMappingResult* mapping =
            FindMapping(data, transport);
        if (mapping == nullptr)
            return RejectAfterExpiryCheck();
        MappedCandidate candidate{};
        const MappedCandidate* current =
            identical ? snapshot_.Find(transport) : nullptr;
        if (current != nullptr) {
            candidate = *current;
        } else {
            candidate.candidate_id_ = next_candidate_id_++;
        }
        candidate.transport_ = transport;
        candidate.local_endpoint_ = mapping->local_endpoint;
        candidate.published_endpoint_ =
            mapping->granted_external_endpoint;
        candidate.gateway_ = data.gateway;
        candidate.route_binding_ = route_binding;
        candidate.mapper_ = data.mapper;
        candidate.mapper_source_ = data.source;
        candidate.mapper_epoch_ = data.mapper_epoch;
        candidate.ownership_nonce_ = data.ownership_nonce;
        candidate.ownership_identity_digest_ =
            data.ownership_identity_digest;
        candidate.topology_generation_ = generation;
        candidate.effective_expiry_monotonic_ms_ =
            mapping->effective_expiry_monotonic_ms;
        if (!identical) {
            candidate.verification_ =
                MappedCandidateVerification::Candidate;
            candidate.verification_attempt_ =
                VerificationAttempt{};
            candidate.primary_evidence_ = Evidence{};
            candidate.inbound_evidence_ = Evidence{};
        }
        next.candidates_[next.candidate_count_++] = candidate;
    }
    if (!Publish(next)) {
        CloseFailClosed(generation);
        return MappedCandidateUpdate::Exhausted;
    }
    if (identical)
        return MappedCandidateUpdate::Renewed;
    return had_candidates
        ? MappedCandidateUpdate::Replaced
        : MappedCandidateUpdate::Published;
}

MappedCandidatePromotion MappedCandidatePublisher::Promote(
    const MappedCandidateProof& proof,
    std::uint64_t now_monotonic_ms) noexcept {
    if (!IsOwnerThread())
        return MappedCandidatePromotion::WrongThread;
    if (closed_)
        return MappedCandidatePromotion::Closed;
    if (AnyCandidateExpired(
            snapshot_, now_monotonic_ms)) {
        const MappedCandidateRetirement retirement =
            RetireExpiredPair();
        return retirement == MappedCandidateRetirement::Closed
            ? MappedCandidatePromotion::Closed
            : MappedCandidatePromotion::Stale;
    }
    if (proof.attempt.topology_generation !=
            snapshot_.topology_generation_ ||
        now_monotonic_ms < proof.attempt.started_monotonic_ms ||
        now_monotonic_ms > proof.attempt.deadline_monotonic_ms)
        return MappedCandidatePromotion::Stale;

    const MappedCandidate* found =
        snapshot_.Find(proof.attempt.transport);
    if (found == nullptr)
        return MappedCandidatePromotion::Rejected;
    if (!IsFreshTcpProof(proof, *found, now_monotonic_ms))
        return MappedCandidatePromotion::Rejected;
    if (found->verification() ==
        MappedCandidateVerification::Verified)
        return MappedCandidatePromotion::AlreadyVerified;

    MappedCandidateSnapshot next = snapshot_;
    for (std::size_t i = 0; i < next.candidate_count_; ++i) {
        MappedCandidate& candidate = next.candidates_[i];
        if (candidate.transport() != proof.attempt.transport)
            continue;
        candidate.verification_ =
            MappedCandidateVerification::Verified;
        candidate.verification_attempt_ = proof.attempt;
        candidate.primary_evidence_ = proof.primary;
        candidate.inbound_evidence_ = proof.inbound;
    }
    if (!Publish(next)) {
        CloseFailClosed();
        return MappedCandidatePromotion::Closed;
    }
    return MappedCandidatePromotion::Promoted;
}

MappedCandidateRetirement
MappedCandidatePublisher::WithdrawExpired(
    std::uint64_t now_monotonic_ms) noexcept {
    if (!IsOwnerThread())
        return MappedCandidateRetirement::WrongThread;
    if (closed_)
        return MappedCandidateRetirement::Closed;
    if (!AnyCandidateExpired(snapshot_, now_monotonic_ms))
        return MappedCandidateRetirement::NoChange;
    return RetireExpiredPair();
}

MappedCandidateRetirement MappedCandidatePublisher::Invalidate(
    std::uint64_t next_generation) noexcept {
    if (!IsOwnerThread())
        return MappedCandidateRetirement::WrongThread;
    if (closed_)
        return MappedCandidateRetirement::Closed;
    if (next_generation <= snapshot_.topology_generation_)
        return MappedCandidateRetirement::Rejected;
    MappedCandidateSnapshot next{};
    next.topology_generation_ = next_generation;
    if (!Publish(next)) {
        CloseFailClosed(next_generation);
        return MappedCandidateRetirement::Closed;
    }
    return MappedCandidateRetirement::Retired;
}

MappedCandidateRetirement
MappedCandidatePublisher::Shutdown() noexcept {
    if (!IsOwnerThread())
        return MappedCandidateRetirement::WrongThread;
    if (closed_)
        return MappedCandidateRetirement::Closed;
    const bool had_candidates = snapshot_.candidate_count_ != 0;
    MappedCandidateSnapshot next{};
    next.topology_generation_ = snapshot_.topology_generation_;
    if (!Publish(next)) {
        CloseFailClosed();
        return MappedCandidateRetirement::Closed;
    }
    closed_ = true;
    return had_candidates
        ? MappedCandidateRetirement::Retired
        : MappedCandidateRetirement::NoChange;
}

} // namespace natmap
