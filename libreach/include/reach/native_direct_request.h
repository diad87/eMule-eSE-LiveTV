// SPDX-License-Identifier: MIT
#pragma once
#include "reach/native_direct_snapshot.h"
#include "reach/direct_coordinator.h"
#include <algorithm>

namespace reach {
// Prefer the expected node key, then the classic user hash. Kad IDs and IPs
// are never peer keys. An identity-free source requires a host-owned record
// ID and epoch, not a hash of its endpoint. Expected identity is not proof.
inline std::optional<DirectPeerKey> NativeDirectPeerKey(const DirectPeerIdentity& peer,
    std::uint64_t sourceRecordId,std::uint64_t sourceEpoch) {
    if(static_cast<std::uint8_t>(peer.trust)>static_cast<std::uint8_t>(DirectIdentityTrust::Pinned) ||
        (peer.expected_node_pub && !NonzeroIdentity(*peer.expected_node_pub)) ||
        (peer.expected_user_hash && !NonzeroIdentity(*peer.expected_user_hash)) ||
        (peer.kad_id && !NonzeroIdentity(*peer.kad_id))) return std::nullopt;
    DirectPeerKey key;
    if(peer.expected_node_pub && NonzeroIdentity(*peer.expected_node_pub)) {
        key.domain=DirectPeerDomain::NodePublicKey;
        key.identity=*peer.expected_node_pub;
    } else if(peer.expected_user_hash && NonzeroIdentity(*peer.expected_user_hash)) {
        key.domain=DirectPeerDomain::UserHash;
        std::copy(peer.expected_user_hash->begin(),peer.expected_user_hash->end(),key.identity.begin());
    } else {
        if(!sourceRecordId || !sourceEpoch) return std::nullopt;
        key.source_record_id=sourceRecordId; key.source_epoch=sourceEpoch;
    }
    return key;
}
struct NativeDirectRequestResult {
    NativeSnapshotStatus snapshot_status=NativeSnapshotStatus::InvalidGeneration;
    DirectRequestResult request;
};
// Incoming admission is distinct from local join-by-peer. The owning host
// must verify consent before supplying the shared wire attempt; this helper
// validates the owned snapshot but does not authenticate or enable data.
inline NativeDirectRequestResult RequestNativeDirectShared(DirectCoordinator& coordinator,
    const NativeDirectCandidateSnapshotV1& snapshot,std::uint64_t currentLocalGeneration,
    std::uint64_t subscriber,const DirectAttemptId& attemptId,std::uint64_t nowMs) {
    NativeDirectRequestResult result;
    result.snapshot_status=ValidateNativeSnapshot(snapshot,currentLocalGeneration);
    if(result.snapshot_status!=NativeSnapshotStatus::Ok) return result;
    const auto key=NativeDirectPeerKey(snapshot.peer,0,0);
    if(!key || key->domain!=DirectPeerDomain::NodePublicKey) return result;
    result.request=coordinator.RequestSharedAttempt(*key,subscriber,attemptId,snapshot.local_generation,nowMs);
    return result;
}
// Admission only: routes/actions are installed by the owning host after it
// supplies adapters and validates protocol capabilities. No transport starts
// here, and a joined subscriber must not replace another consumer's routes.
inline NativeDirectRequestResult RequestNativeDirect(DirectCoordinator& coordinator,
    const NativeDirectCandidateSnapshotV1& snapshot,std::uint64_t currentLocalGeneration,
    std::uint64_t sourceRecordId,std::uint64_t sourceEpoch,std::uint64_t subscriber,
    const DirectAttemptId& attemptId,std::uint64_t nowMs) {
    NativeDirectRequestResult result;
    result.snapshot_status=ValidateNativeSnapshot(snapshot,currentLocalGeneration);
    if(result.snapshot_status!=NativeSnapshotStatus::Ok) return result;
    const auto key=NativeDirectPeerKey(snapshot.peer,sourceRecordId,sourceEpoch);
    if(!key) return result;
    result.request=coordinator.Request(*key,subscriber,attemptId,snapshot.local_generation,nowMs);
    return result;
}
}
