// SPDX-License-Identifier: MIT
#pragma once
#include "reach/direct_attempt.h"
#include <optional>

namespace reach {
enum class DirectIdentityTrust : std::uint8_t { Unknown, Tofu, Pinned };
struct DirectPeerIdentity {
    std::optional<std::array<std::uint8_t,16>> expected_user_hash;
    std::optional<std::array<std::uint8_t,32>> expected_node_pub;
    std::optional<std::array<std::uint8_t,16>> kad_id;
    DirectIdentityTrust trust=DirectIdentityTrust::Unknown;
    std::uint64_t pin_version=0;
};
enum class DirectCandidateSource : std::uint8_t { NativeEndpoint, ReachRecord, KadSource, ServerSource, Observed };
struct NativeDirectCandidate {
    DirectCandidate route;
    DirectCandidateSource source=DirectCandidateSource::NativeEndpoint;
    std::optional<std::uint64_t> mapping_id;
};
// Internal owned input, never the UI/API hash-only projection. Source record
// validators retain responsibility for signatures, freshness and capabilities;
// this type confers no route/identity authority by itself.
struct NativeDirectCandidateSnapshotV1 {
    DirectPeerIdentity peer;
    std::uint64_t local_generation=0;
    std::optional<std::uint64_t> remote_generation;
    std::array<NativeDirectCandidate,kDirectMaxCandidates> candidates{};
    std::size_t count=0;
};
enum class NativeSnapshotStatus : std::uint8_t { Ok, InvalidGeneration, TooManyCandidates, InvalidIdentity, InvalidSource };
template<std::size_t N> inline bool NonzeroIdentity(const std::array<std::uint8_t,N>& value) {
    for(const auto byte:value) if(byte) return true;
    return false;
}
inline NativeSnapshotStatus ValidateNativeSnapshot(const NativeDirectCandidateSnapshotV1& snapshot,std::uint64_t currentLocalGeneration) {
    if(!currentLocalGeneration || snapshot.local_generation!=currentLocalGeneration ||
        (snapshot.remote_generation && !*snapshot.remote_generation)) return NativeSnapshotStatus::InvalidGeneration;
    if(snapshot.count>snapshot.candidates.size()) return NativeSnapshotStatus::TooManyCandidates;
    const auto& peer=snapshot.peer;
    if(static_cast<std::uint8_t>(peer.trust)>static_cast<std::uint8_t>(DirectIdentityTrust::Pinned) ||
        (peer.expected_user_hash && !NonzeroIdentity(*peer.expected_user_hash)) ||
        (peer.expected_node_pub && !NonzeroIdentity(*peer.expected_node_pub)) ||
        (peer.kad_id && !NonzeroIdentity(*peer.kad_id))) return NativeSnapshotStatus::InvalidIdentity;
    for(std::size_t i=0;i<snapshot.count;++i) {
        const auto& candidate=snapshot.candidates[i];
        if(static_cast<std::uint8_t>(candidate.source)>static_cast<std::uint8_t>(DirectCandidateSource::Observed) ||
            (candidate.mapping_id && !*candidate.mapping_id)) return NativeSnapshotStatus::InvalidSource;
    }
    return NativeSnapshotStatus::Ok; // Endpoint policy/auth checks still mandatory before starting any route.
}
struct NativeDirectPlan {
    NativeSnapshotStatus snapshot_status=NativeSnapshotStatus::InvalidGeneration;
    DirectPlan plan{DirectStatus::InvalidPolicy,{}};
};
// Candidate generations are local route provenance. Never rebase a stale
// candidate to the current generation, or compare it to the peer's generation.
// The remote generation stays in the caller's owned snapshot for peer protocol
// checks. This selector does not authenticate identities or start transports.
inline NativeDirectPlan BuildNativeDirectPlan(const NativeDirectCandidateSnapshotV1& snapshot,const DirectPolicy& policy) {
    NativeDirectPlan result;
    result.snapshot_status=ValidateNativeSnapshot(snapshot,policy.topology_generation);
    if(result.snapshot_status!=NativeSnapshotStatus::Ok) return result;
    std::vector<DirectCandidate> candidates;
    candidates.reserve(snapshot.count);
    for(std::size_t i=0;i<snapshot.count;++i) candidates.push_back(snapshot.candidates[i].route);
    result.plan=BuildDirectPlan(policy,candidates);
    return result;
}
}
