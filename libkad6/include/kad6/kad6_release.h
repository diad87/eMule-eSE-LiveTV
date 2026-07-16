// SPDX-License-Identifier: MIT
// Tamper-evident operator attestation for enabling a public Kad6 exit.
#pragma once

#include "kad6/kad6_crypto.h"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace kad6 {

constexpr std::uint16_t kK6ReleaseEvidenceVersion = 1;
constexpr std::uint16_t kK6ReleaseRequiredGateMask = 0xffffu; // G0..G15
constexpr std::uint64_t kK6ReleaseMinObservationSeconds = 30ull * 24 * 60 * 60;
constexpr std::uint64_t kK6ReleaseMaxValiditySeconds = 90ull * 24 * 60 * 60;
constexpr std::uint32_t kK6ReleaseMinAdmissionPpm = 950000;
constexpr std::uint64_t kK6ReleaseMinAdmissionAttempts = 100;
constexpr std::uint64_t kK6ReleaseMinHeadroomBps = 3500;
constexpr std::size_t kK6ReleaseEvidenceWireSize = 228;

struct K6ReleaseEvidence {
    std::uint16_t version = kK6ReleaseEvidenceVersion;
    std::uint16_t gate_mask = 0;
    std::array<Byte, kEd25519PubSize> node_pub{};
    std::uint64_t issued_at = 0;
    std::uint64_t valid_until = 0;
    std::uint64_t observed_from = 0;
    std::uint64_t observed_to = 0;
    std::uint64_t admission_attempts = 0;
    std::uint32_t admission_success_ppm = 0;
    std::uint64_t useful_headroom_bps = 0;
    Hash32 field_digest{};
    Hash32 external_audit_digest{};
    std::array<Byte, kEd25519SigSize> signature{};
};

enum class K6ReleaseGateStatus : Byte {
    Ok = 0,
    Missing,
    BadEncoding,
    WrongNode,
    BadSignature,
    GatesIncomplete,
    ObservationTooShort,
    EvidenceStale,
    AdmissionTooLow,
    HeadroomTooLow,
    MissingArtifactDigest,
    RuntimeUnhealthy,
    OperatorOptOut
};

const char* K6ReleaseGateStatusName(K6ReleaseGateStatus status) noexcept;
Kad6Status EncodeK6ReleaseEvidence(const K6ReleaseEvidence& value,
                                   std::vector<Byte>& out);
Kad6Status DecodeK6ReleaseEvidence(const Byte* in, std::size_t len,
                                   K6ReleaseEvidence& value) noexcept;
Kad6Status SignK6ReleaseEvidence(const Kad6CryptoHooks& crypto,
                                 K6ReleaseEvidence& value,
                                 std::vector<Byte>& signed_wire);
K6ReleaseGateStatus EvaluateK6ReleaseEvidence(
    const Kad6CryptoHooks& crypto, const K6ReleaseEvidence& value,
    const Byte expected_node_pub[kEd25519PubSize],
    std::uint64_t now_seconds) noexcept;

} // namespace kad6
