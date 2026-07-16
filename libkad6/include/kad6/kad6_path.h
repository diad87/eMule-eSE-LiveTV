// SPDX-License-Identifier: MIT
//
// Strict three-hop path selection for Kad6.  This module is deliberately
// transport-agnostic: the host supplies authenticated/live candidates and a
// CSPRNG callback; libkad6 enforces identity and network diversity.
#pragma once

#include "kad6/kad6_address.h"
#include "kad6/kad6_types.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace kad6 {

constexpr std::size_t kK6StrictHopCount = 3;
constexpr std::size_t kK6PathMaxCandidates = 64;
constexpr std::size_t kK6PathEvidenceMaxRecords = 4096;
constexpr std::size_t kK6PathEvidenceMaxObservers = 64;
constexpr std::size_t kK6PathTraceMaxSamples = 10000000;

using K6PathRandom = bool (*)(void* context, Byte* out, std::size_t length);

struct K6PathCandidate {
    std::array<Byte, kEd25519PubSize> node_pub{};
    Hash16 user_hash{};
    Kad6Address address;
    std::uint32_t asn = 0;
    std::uint32_t operator_group = 0; // zero means not classified
    std::uint32_t weight = 1;

    // Optional multi-vantage path evidence.  Access paths describe
    // origin<->candidate and egress paths describe candidate<->destination.
    // Forward and reverse sets are separate inputs because BGP is asymmetric.
    std::vector<std::uint32_t> access_forward_as;
    std::vector<std::uint32_t> access_reverse_as;
    std::vector<std::uint64_t> access_forward_ixp;
    std::vector<std::uint64_t> access_reverse_ixp;
    std::vector<std::uint32_t> egress_forward_as;
    std::vector<std::uint32_t> egress_reverse_as;
    std::vector<std::uint64_t> egress_forward_ixp;
    std::vector<std::uint64_t> egress_reverse_ixp;
    bool access_multi_vantage = false;
    bool egress_multi_vantage = false;

    bool authenticated = false;
    bool endpoint_verified = false;
    bool connected = false;
    bool supports_strict3 = false;
    bool supports_shaping = false;
    bool supports_exit = false;
    bool has_capacity = false;
    bool current_content_peer = false;
};

enum class K6PathStatus {
    Ok = 0,
    NullArgument,
    TooManyCandidates,
    NoEligibleGuard,
    PinnedGuardUnavailable,
    NotDiverse,
    MissingPathEvidence,
    NetworkObserverOverlap,
    RandomFailed
};

struct K6StrictPath {
    std::array<std::size_t, kK6StrictHopCount> index{}; // guard, middle, exit
};

struct K6NetworkPathPolicy {
    bool require_multi_vantage = true;
    bool fail_closed = true;
    std::vector<std::uint32_t> high_risk_transit_as;
    std::vector<std::uint64_t> high_risk_ixp;
};

// Offline path evidence consumed by the production selector.  It is keyed by
// authenticated NodeIdentity and is never learned from the candidate itself.
// The host loads a bounded snapshot prepared from historical, multi-vantage
// route data; expiry and sequence are checked before it can affect selection.
struct K6PathEvidenceRecord {
    std::array<Byte, kEd25519PubSize> node_pub{};
    std::vector<std::uint32_t> access_forward_as;
    std::vector<std::uint32_t> access_reverse_as;
    std::vector<std::uint64_t> access_forward_ixp;
    std::vector<std::uint64_t> access_reverse_ixp;
    std::vector<std::uint32_t> egress_forward_as;
    std::vector<std::uint32_t> egress_reverse_as;
    std::vector<std::uint64_t> egress_forward_ixp;
    std::vector<std::uint64_t> egress_reverse_ixp;
    bool access_multi_vantage = false;
    bool egress_multi_vantage = false;
};

struct K6PathEvidenceSnapshot {
    std::uint64_t sequence = 0;
    std::uint64_t generated_at = 0;
    std::uint64_t valid_until = 0;
    Hash32 dataset_hash{};
    std::vector<K6PathEvidenceRecord> records;
};

struct K6PathTraceSample {
    bool baseline_overlap = false;
    bool selected_overlap = false;
    bool baseline_unknown = false;
    bool selected_unknown = false;
};

struct K6PathTraceReport {
    std::uint64_t samples = 0;
    std::uint64_t baseline_overlaps = 0;
    std::uint64_t selected_overlaps = 0;
    std::uint64_t baseline_unknown = 0;
    std::uint64_t selected_unknown = 0;
    double baseline_probability = 0.0;
    double selected_probability = 0.0;
    double baseline_upper_probability = 0.0;
    double selected_upper_probability = 0.0;
};

Kad6Status EncodeK6PathEvidenceSnapshot(const K6PathEvidenceSnapshot& snapshot,
                                         std::vector<Byte>& out) noexcept;
Kad6Status DecodeK6PathEvidenceSnapshot(const Byte* data, std::size_t length,
                                         K6PathEvidenceSnapshot& out) noexcept;
bool ApplyK6PathEvidence(const K6PathEvidenceSnapshot& snapshot,
                         const Byte node_pub[kEd25519PubSize],
                         std::uint64_t now_seconds,
                         K6PathCandidate& candidate) noexcept;

Kad6Status EncodeK6PathTraceFile(const std::vector<K6PathTraceSample>& samples,
                                  std::vector<Byte>& out) noexcept;
Kad6Status DecodeK6PathTraceFile(const Byte* data, std::size_t length,
                                  std::vector<K6PathTraceSample>& out) noexcept;

// `pinned_guard` is an optional 32-byte NodeIdentity.  When supplied it is a
// hard pin: selection does not silently rotate to another guard.  The caller
// may explicitly retry without the pin after recording guard failure.
K6PathStatus SelectK6StrictPath(const std::vector<K6PathCandidate>& candidates,
                                const Byte* pinned_guard,
                                K6PathRandom random,
                                void* random_context,
                                K6StrictPath& out) noexcept;

// L5/Q24 selector.  A candidate exit is eligible only when the union of
// forward/reverse AS and IXP observers on origin<->guard is disjoint from the
// corresponding exit<->destination union.  Missing evidence fails closed when
// policy.fail_closed is set; callers must explicitly report any downgrade.
K6PathStatus SelectK6StrictPathV2(const std::vector<K6PathCandidate>& candidates,
                                  const Byte* pinned_guard,
                                  const K6NetworkPathPolicy& policy,
                                  K6PathRandom random,
                                  void* random_context,
                                  K6StrictPath& out) noexcept;

K6PathStatus CheckK6NetworkPathDiversity(const K6PathCandidate& guard,
                                         const K6PathCandidate& exit,
                                         const K6NetworkPathPolicy& policy) noexcept;
K6PathTraceReport EvaluateK6PathTraces(
    const std::vector<K6PathTraceSample>& samples) noexcept;

const char* K6PathStatusName(K6PathStatus status) noexcept;

} // namespace kad6
