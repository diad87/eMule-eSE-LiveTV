// SPDX-License-Identifier: MIT
#include "kad6/kad6_release.h"

#include "kad6/kad6_bytes.h"

#include <cstring>

namespace kad6 {
namespace {
constexpr Byte kMagic[8] = {'K','6','R','E','L','1',0,0};
constexpr std::size_t kUnsignedSize = kK6ReleaseEvidenceWireSize - kEd25519SigSize;

template <std::size_t N>
bool Any(const std::array<Byte, N>& value) noexcept {
    Byte any = 0;
    for (Byte b : value) any = static_cast<Byte>(any | b);
    return any != 0;
}

Kad6Status EncodeUnsigned(const K6ReleaseEvidence& value,
                          std::vector<Byte>& out) {
    out.clear();
    ByteWriter writer(out);
    writer.bytes(kMagic, sizeof kMagic);
    writer.u16le(value.version);
    writer.u16le(value.gate_mask);
    writer.u32le(0);
    writer.bytes(value.node_pub.data(), value.node_pub.size());
    writer.u64le(value.issued_at);
    writer.u64le(value.valid_until);
    writer.u64le(value.observed_from);
    writer.u64le(value.observed_to);
    writer.u64le(value.admission_attempts);
    writer.u32le(value.admission_success_ppm);
    writer.u64le(value.useful_headroom_bps);
    writer.bytes(value.field_digest.data(), value.field_digest.size());
    writer.bytes(value.external_audit_digest.data(),
                 value.external_audit_digest.size());
    return out.size() == kUnsignedSize ? Kad6Status::Ok : Kad6Status::Malformed;
}
} // namespace

const char* K6ReleaseGateStatusName(K6ReleaseGateStatus status) noexcept {
    switch (status) {
    case K6ReleaseGateStatus::Ok: return "ok";
    case K6ReleaseGateStatus::Missing: return "missing";
    case K6ReleaseGateStatus::BadEncoding: return "bad_encoding";
    case K6ReleaseGateStatus::WrongNode: return "wrong_node";
    case K6ReleaseGateStatus::BadSignature: return "bad_signature";
    case K6ReleaseGateStatus::GatesIncomplete: return "gates_incomplete";
    case K6ReleaseGateStatus::ObservationTooShort: return "observation_too_short";
    case K6ReleaseGateStatus::EvidenceStale: return "evidence_stale";
    case K6ReleaseGateStatus::AdmissionTooLow: return "admission_too_low";
    case K6ReleaseGateStatus::HeadroomTooLow: return "headroom_too_low";
    case K6ReleaseGateStatus::MissingArtifactDigest: return "missing_artifact_digest";
    case K6ReleaseGateStatus::RuntimeUnhealthy: return "runtime_unhealthy";
    case K6ReleaseGateStatus::OperatorOptOut: return "operator_opt_out";
    }
    return "invalid";
}

Kad6Status EncodeK6ReleaseEvidence(const K6ReleaseEvidence& value,
                                   std::vector<Byte>& out) {
    Kad6Status status = EncodeUnsigned(value, out);
    if (status != Kad6Status::Ok) return status;
    ByteWriter writer(out);
    writer.bytes(value.signature.data(), value.signature.size());
    return out.size() == kK6ReleaseEvidenceWireSize
        ? Kad6Status::Ok : Kad6Status::Malformed;
}

Kad6Status DecodeK6ReleaseEvidence(const Byte* in, std::size_t len,
                                   K6ReleaseEvidence& value) noexcept {
    value = K6ReleaseEvidence{};
    if (!in && len != 0) return Kad6Status::NullArgument;
    if (len < kK6ReleaseEvidenceWireSize) return Kad6Status::Truncated;
    if (len != kK6ReleaseEvidenceWireSize) return Kad6Status::Malformed;
    ByteReader reader(in, len);
    Byte magic[8]{};
    reader.bytes(magic, sizeof magic);
    K6ReleaseEvidence candidate;
    candidate.version = reader.u16le();
    candidate.gate_mask = reader.u16le();
    const std::uint32_t reserved = reader.u32le();
    reader.bytes(candidate.node_pub.data(), candidate.node_pub.size());
    candidate.issued_at = reader.u64le();
    candidate.valid_until = reader.u64le();
    candidate.observed_from = reader.u64le();
    candidate.observed_to = reader.u64le();
    candidate.admission_attempts = reader.u64le();
    candidate.admission_success_ppm = reader.u32le();
    candidate.useful_headroom_bps = reader.u64le();
    reader.bytes(candidate.field_digest.data(), candidate.field_digest.size());
    reader.bytes(candidate.external_audit_digest.data(),
                 candidate.external_audit_digest.size());
    reader.bytes(candidate.signature.data(), candidate.signature.size());
    if (!reader.ok()) return Kad6Status::Truncated;
    if (reader.remaining() != 0 || std::memcmp(magic, kMagic, sizeof magic) != 0 ||
        reserved != 0 || candidate.version != kK6ReleaseEvidenceVersion ||
        candidate.admission_success_ppm > 1000000)
        return candidate.version != kK6ReleaseEvidenceVersion
            ? Kad6Status::UnsupportedVersion : Kad6Status::Malformed;
    value = candidate;
    return Kad6Status::Ok;
}

Kad6Status SignK6ReleaseEvidence(const Kad6CryptoHooks& crypto,
                                 K6ReleaseEvidence& value,
                                 std::vector<Byte>& signed_wire) {
    signed_wire.clear();
    if (!crypto.ed25519_sign) return Kad6Status::AuthFailed;
    std::vector<Byte> unsigned_wire;
    Kad6Status status = EncodeUnsigned(value, unsigned_wire);
    if (status != Kad6Status::Ok) return status;
    if (!crypto.ed25519_sign(nullptr, 0, unsigned_wire.data(),
            unsigned_wire.size(), value.signature.data()))
        return Kad6Status::AuthFailed;
    return EncodeK6ReleaseEvidence(value, signed_wire);
}

K6ReleaseGateStatus EvaluateK6ReleaseEvidence(
    const Kad6CryptoHooks& crypto, const K6ReleaseEvidence& value,
    const Byte expected_node_pub[kEd25519PubSize],
    std::uint64_t now_seconds) noexcept {
    if (!expected_node_pub || now_seconds == 0)
        return K6ReleaseGateStatus::BadEncoding;
    if (!Kad6CtEqual(value.node_pub.data(), expected_node_pub,
                     value.node_pub.size()))
        return K6ReleaseGateStatus::WrongNode;
    std::vector<Byte> unsigned_wire;
    if (EncodeUnsigned(value, unsigned_wire) != Kad6Status::Ok)
        return K6ReleaseGateStatus::BadEncoding;
    if (!crypto.ed25519_verify || !crypto.ed25519_verify(value.node_pub.data(),
            unsigned_wire.data(), unsigned_wire.size(), value.signature.data()))
        return K6ReleaseGateStatus::BadSignature;
    if (value.gate_mask != kK6ReleaseRequiredGateMask)
        return K6ReleaseGateStatus::GatesIncomplete;
    if (value.observed_from == 0 || value.observed_to < value.observed_from ||
        value.observed_to - value.observed_from < kK6ReleaseMinObservationSeconds)
        return K6ReleaseGateStatus::ObservationTooShort;
    if (value.issued_at < value.observed_to || value.issued_at > now_seconds + 300 ||
        value.valid_until <= now_seconds || value.valid_until <= value.issued_at ||
        value.valid_until - value.issued_at > kK6ReleaseMaxValiditySeconds)
        return K6ReleaseGateStatus::EvidenceStale;
    if (value.admission_attempts < kK6ReleaseMinAdmissionAttempts ||
        value.admission_success_ppm < kK6ReleaseMinAdmissionPpm)
        return K6ReleaseGateStatus::AdmissionTooLow;
    if (value.useful_headroom_bps < kK6ReleaseMinHeadroomBps)
        return K6ReleaseGateStatus::HeadroomTooLow;
    if (!Any(value.field_digest) || !Any(value.external_audit_digest))
        return K6ReleaseGateStatus::MissingArtifactDigest;
    return K6ReleaseGateStatus::Ok;
}

} // namespace kad6
