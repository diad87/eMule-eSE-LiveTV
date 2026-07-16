// SPDX-License-Identifier: MIT
#include "kad6/kad6_lease.h"

#include <algorithm>
#include <cstring>
#include <limits>

namespace kad6 {
namespace {

constexpr char kCompatProofDomain[] = "Kad6-CompatProof-v1";
constexpr char kSourceBoundDomain[] = "Kad6-SourceBound-v1";

template <std::size_t N>
bool AllZero(const std::array<Byte, N>& value) noexcept {
    Byte any = 0;
    for (Byte b : value) any = static_cast<Byte>(any | b);
    return any == 0;
}

bool ValidMode(K6BindingMode mode, bool allow_auto) noexcept {
    return mode == K6BindingMode::DedicatedVep || mode == K6BindingMode::Cohort ||
           (allow_auto && mode == K6BindingMode::Auto);
}

bool ValidCommitment(K6CommitmentKind kind) noexcept {
    return kind == K6CommitmentKind::None || kind == K6CommitmentKind::AichRoot ||
           kind == K6CommitmentKind::Sha256Hashset;
}

bool SameFrontDoor(const K6Endpoint& a, const K6Endpoint& b) noexcept {
    return a.addr == b.addr && a.tcp_port == b.tcp_port &&
           a.udp_port == b.udp_port;
}

Kad6Status ValidateSuccessfulBound(const K6SourceBind& bind,
                                   const K6SourceBound& bound) noexcept {
    if (bound.status != K6SourceBoundStatus::Ok)
        return Kad6Status::Ok;
    if (bound.source_lease_id == 0 || bound.transport_mask == 0 ||
        (bound.transport_mask & ~bind.transport_mask) != 0 ||
        (bound.flags & ~bind.flags) != 0 ||
        bound.lifetime_s < kK6SourceMinLifetimeSeconds ||
        bound.lifetime_s > bind.requested_lifetime_s ||
        bound.lifetime_s > kK6SourceMaxLifetimeSeconds ||
        bound.refresh_after_s == 0 || bound.refresh_after_s >= bound.lifetime_s ||
        bound.endpoint_slot == 0 || bound.virtual_endpoint.valid_until == 0 ||
        bound.commitment_kind != bind.commitment_kind ||
        !Kad6CtEqual(bound.content_commitment.data(), bind.content_commitment.data(),
                     bind.content_commitment.size()) ||
        !(bound.virtual_endpoint.addr == bound.exit_apparent_ip))
        return Kad6Status::BadValue;
    if (bind.desired_family == 4 &&
        bound.virtual_endpoint.addr.family != Kad6Address::Family::IPv4)
        return Kad6Status::BadValue;
    if (bind.desired_family == 6 &&
        bound.virtual_endpoint.addr.family != Kad6Address::Family::IPv6)
        return Kad6Status::BadValue;
    if ((bound.transport_mask & kK6TransportTcp) != 0 &&
        (bound.virtual_endpoint.tcp_port == 0 ||
         (bound.virtual_endpoint.transport_flags & kK6EpTcpEd2k) == 0))
        return Kad6Status::BadValue;
    if ((bound.transport_mask & kK6TransportUdp) != 0 &&
        bound.virtual_endpoint.udp_port == 0)
        return Kad6Status::BadValue;
    if ((bind.requested_mode == K6BindingMode::DedicatedVep &&
         bound.binding_mode != K6BindingMode::DedicatedVep) ||
        (bind.requested_mode == K6BindingMode::Cohort &&
         bound.binding_mode != K6BindingMode::Cohort))
        return Kad6Status::BadValue;
    if (bound.binding_mode == K6BindingMode::DedicatedVep) {
        if (bound.identity_mode != K6IdentityMode::OriginatorVep ||
            !AllZero(bound.cohort_id))
            return Kad6Status::BadValue;
    } else if (bound.binding_mode == K6BindingMode::Cohort) {
        if (bound.identity_mode != K6IdentityMode::ExitTerminated ||
            AllZero(bound.cohort_id) ||
            bound.commitment_kind == K6CommitmentKind::None)
            return Kad6Status::BadValue;
    } else {
        return Kad6Status::BadValue;
    }
    return Kad6Status::Ok;
}

Kad6Status ValidateBind(const K6SourceBind& value, bool wire) noexcept {
    const Kad6Status bad = wire ? Kad6Status::Malformed : Kad6Status::BadValue;
    if (AllZero(value.file_hash) || value.file_size == 0 ||
        AllZero(value.compat_user_hash) || AllZero(value.compat_pub_fingerprint) ||
        AllZero(value.bind_nonce) || value.source_epoch == 0)
        return bad;
    if (value.desired_family != 0 && value.desired_family != 4 && value.desired_family != 6)
        return bad;
    if (value.transport_mask == 0 || (value.transport_mask & ~kK6TransportMask) != 0 ||
        (value.flags & ~kK6SourceFlagMask) != 0)
        return bad;
    if (value.requested_lifetime_s < kK6SourceMinLifetimeSeconds ||
        value.requested_lifetime_s > kK6SourceMaxLifetimeSeconds ||
        value.max_upload_bps > kK6SourceMaxUploadBps ||
        !ValidMode(value.requested_mode, true) || value.requested_endpoint_slots != 1 ||
        !ValidCommitment(value.commitment_kind))
        return bad;
    if ((value.commitment_kind == K6CommitmentKind::None) != AllZero(value.content_commitment))
        return bad;
    if (value.requested_mode == K6BindingMode::Cohort &&
        value.commitment_kind == K6CommitmentKind::None)
        return bad;
    if (value.compat_proof.size() > kK6SourceBindMaxProof)
        return Kad6Status::TooLarge;
    return Kad6Status::Ok;
}

Kad6Status SerializeBind(const K6SourceBind& value, bool include_proof,
                         std::vector<Byte>& out) {
    out.clear();
    const Kad6Status valid = ValidateBind(value, false);
    if (valid != Kad6Status::Ok) return valid;
    ByteWriter w(out);
    w.bytes(value.file_hash.data(), value.file_hash.size());
    w.u64le(value.file_size);
    w.bytes(value.compat_user_hash.data(), value.compat_user_hash.size());
    w.bytes(value.compat_pub_fingerprint.data(), value.compat_pub_fingerprint.size());
    w.u8(value.desired_family);
    w.u8(value.transport_mask);
    w.u16le(value.flags);
    w.u32le(value.requested_lifetime_s);
    w.u32le(value.max_upload_bps);
    w.u64le(value.source_epoch);
    w.bytes(value.bind_nonce.data(), value.bind_nonce.size());
    w.u8(static_cast<Byte>(value.requested_mode));
    w.u8(0);
    w.u16le(value.requested_endpoint_slots);
    w.u8(static_cast<Byte>(value.commitment_kind));
    w.u8(0); w.u8(0); w.u8(0);
    w.bytes(value.content_commitment.data(), value.content_commitment.size());
    if (include_proof) {
        w.u16le(static_cast<std::uint16_t>(value.compat_proof.size()));
        w.bytes(value.compat_proof.data(), value.compat_proof.size());
    }
    return Kad6Status::Ok;
}

Kad6Status SerializeBoundUnsigned(const K6SourceBound& value,
                                  std::vector<Byte>& out) {
    out.clear();
    if (static_cast<Byte>(value.status) > static_cast<Byte>(K6SourceBoundStatus::Unsupported) ||
        (value.transport_mask & ~kK6TransportMask) != 0 ||
        (value.flags & ~kK6SourceFlagMask) != 0 ||
        !ValidMode(value.binding_mode, true) ||
        static_cast<Byte>(value.identity_mode) > static_cast<Byte>(K6IdentityMode::ExitTerminated) ||
        !ValidCommitment(value.commitment_kind))
        return Kad6Status::BadValue;
    std::vector<Byte> endpoint;
    Kad6Status s = EncodeK6Endpoint(value.virtual_endpoint, endpoint);
    if (s != Kad6Status::Ok) return s;
    std::vector<Byte> apparent;
    s = EncodeKad6Address(value.exit_apparent_ip, apparent);
    if (s != Kad6Status::Ok) return s;
    ByteWriter w(out);
    w.u8(static_cast<Byte>(value.status));
    w.u8(value.transport_mask);
    w.u16le(value.flags);
    w.u8(static_cast<Byte>(value.binding_mode));
    w.u8(static_cast<Byte>(value.identity_mode));
    w.u16le(value.endpoint_slot);
    w.u64le(value.source_lease_id);
    w.u32le(value.lifetime_s);
    w.u32le(value.refresh_after_s);
    w.bytes(value.cohort_id.data(), value.cohort_id.size());
    w.u8(static_cast<Byte>(value.commitment_kind));
    w.bytes(value.content_commitment.data(), value.content_commitment.size());
    w.bytes(endpoint.data(), endpoint.size());
    w.bytes(apparent.data(), apparent.size());
    w.bytes(value.exit_node_pub.data(), value.exit_node_pub.size());
    w.bytes(value.bind_nonce.data(), value.bind_nonce.size());
    return Kad6Status::Ok;
}

} // namespace

Kad6Status EncodeK6SourceBind(const K6SourceBind& value, std::vector<Byte>& out) {
    return SerializeBind(value, true, out);
}

Kad6Status K6SourceBindSerializeProofContext(const K6SourceBind& value,
                                              std::vector<Byte>& out) {
    return SerializeBind(value, false, out);
}

Kad6Status DecodeK6SourceBind(const Byte* in, std::size_t len, K6SourceBind& out,
                              std::size_t* consumed) noexcept {
    out = K6SourceBind{};
    if (consumed) *consumed = 0;
    if (!in && len != 0) return Kad6Status::NullArgument;
    ByteReader r(in, len);
    K6SourceBind candidate;
    r.bytes(candidate.file_hash.data(), candidate.file_hash.size());
    candidate.file_size = r.u64le();
    r.bytes(candidate.compat_user_hash.data(), candidate.compat_user_hash.size());
    r.bytes(candidate.compat_pub_fingerprint.data(), candidate.compat_pub_fingerprint.size());
    candidate.desired_family = r.u8();
    candidate.transport_mask = r.u8();
    candidate.flags = r.u16le();
    candidate.requested_lifetime_s = r.u32le();
    candidate.max_upload_bps = r.u32le();
    candidate.source_epoch = r.u64le();
    r.bytes(candidate.bind_nonce.data(), candidate.bind_nonce.size());
    candidate.requested_mode = static_cast<K6BindingMode>(r.u8());
    const Byte reserved = r.u8();
    candidate.requested_endpoint_slots = r.u16le();
    candidate.commitment_kind = static_cast<K6CommitmentKind>(r.u8());
    const Byte reserved0 = r.u8(), reserved1 = r.u8(), reserved2 = r.u8();
    r.bytes(candidate.content_commitment.data(), candidate.content_commitment.size());
    const std::uint16_t proof_len = r.u16le();
    if (!r.ok()) return Kad6Status::Truncated;
    if (proof_len > kK6SourceBindMaxProof) return Kad6Status::TooLarge;
    if (reserved != 0 || reserved0 != 0 || reserved1 != 0 || reserved2 != 0)
        return Kad6Status::Malformed;
    const Byte* proof = r.take(proof_len);
    if (!r.ok()) return Kad6Status::Truncated;
    candidate.compat_proof.assign(proof, proof + proof_len);
    const Kad6Status valid = ValidateBind(candidate, true);
    if (valid != Kad6Status::Ok) return valid;
    out = std::move(candidate);
    if (consumed) *consumed = r.pos();
    return Kad6Status::Ok;
}

Kad6Status MakeK6CompatProofV1(const Kad6CryptoHooks& hooks,
                               const Byte* secret, std::size_t secret_len,
                               const Byte pub[kEd25519PubSize], K6SourceBind& value) {
    if (!hooks.sha256 || !hooks.ed25519_sign || !pub) return Kad6Status::NullArgument;
    if (!hooks.sha256(pub, kEd25519PubSize, value.compat_pub_fingerprint.data()))
        return Kad6Status::AuthFailed;
    value.compat_proof.clear();
    std::vector<Byte> context;
    Kad6Status s = K6SourceBindSerializeProofContext(value, context);
    if (s != Kad6Status::Ok) return s;
    std::vector<Byte> message;
    message.insert(message.end(), kCompatProofDomain,
                   kCompatProofDomain + sizeof(kCompatProofDomain) - 1);
    message.insert(message.end(), context.begin(), context.end());
    value.compat_proof.resize(kK6CompatProofV1Size);
    std::memcpy(value.compat_proof.data(), pub, kEd25519PubSize);
    if (!hooks.ed25519_sign(secret, secret_len, message.data(), message.size(),
                            value.compat_proof.data() + kEd25519PubSize)) {
        value.compat_proof.clear();
        return Kad6Status::AuthFailed;
    }
    return Kad6Status::Ok;
}

Kad6Status VerifyK6CompatProofV1(const Kad6CryptoHooks& hooks,
                                 const K6SourceBind& value) {
    if (!hooks.sha256 || !hooks.ed25519_verify) return Kad6Status::NullArgument;
    if (value.compat_proof.size() != kK6CompatProofV1Size) return Kad6Status::AuthFailed;
    Hash32 fingerprint{};
    if (!hooks.sha256(value.compat_proof.data(), kEd25519PubSize, fingerprint.data()) ||
        !Kad6CtEqual(fingerprint.data(), value.compat_pub_fingerprint.data(), fingerprint.size()))
        return Kad6Status::AuthFailed;
    std::vector<Byte> context;
    Kad6Status s = K6SourceBindSerializeProofContext(value, context);
    if (s != Kad6Status::Ok) return s;
    std::vector<Byte> message;
    message.insert(message.end(), kCompatProofDomain,
                   kCompatProofDomain + sizeof(kCompatProofDomain) - 1);
    message.insert(message.end(), context.begin(), context.end());
    return hooks.ed25519_verify(value.compat_proof.data(), message.data(), message.size(),
                                value.compat_proof.data() + kEd25519PubSize)
        ? Kad6Status::Ok : Kad6Status::AuthFailed;
}

Kad6Status K6SourceBoundSerializeSigned(const K6SourceBind& bind,
                                         const K6SourceBound& bound,
                                         std::vector<Byte>& out) {
    out.clear();
    std::vector<Byte> bind_context, bound_wire;
    Kad6Status s = K6SourceBindSerializeProofContext(bind, bind_context);
    if (s != Kad6Status::Ok) return s;
    s = SerializeBoundUnsigned(bound, bound_wire);
    if (s != Kad6Status::Ok) return s;
    out.insert(out.end(), kSourceBoundDomain,
               kSourceBoundDomain + sizeof(kSourceBoundDomain) - 1);
    out.insert(out.end(), bind_context.begin(), bind_context.end());
    out.insert(out.end(), bound_wire.begin(), bound_wire.end());
    return Kad6Status::Ok;
}

Kad6Status EncodeK6SourceBound(const K6SourceBound& value, std::vector<Byte>& out) {
    Kad6Status s = SerializeBoundUnsigned(value, out);
    if (s != Kad6Status::Ok) return s;
    out.insert(out.end(), value.signature.begin(), value.signature.end());
    return Kad6Status::Ok;
}

Kad6Status DecodeK6SourceBound(const Byte* in, std::size_t len, K6SourceBound& out,
                               std::size_t* consumed) noexcept {
    out = K6SourceBound{};
    if (consumed) *consumed = 0;
    if (!in && len != 0) return Kad6Status::NullArgument;
    ByteReader r(in, len);
    K6SourceBound candidate;
    candidate.status = static_cast<K6SourceBoundStatus>(r.u8());
    candidate.transport_mask = r.u8();
    candidate.flags = r.u16le();
    candidate.binding_mode = static_cast<K6BindingMode>(r.u8());
    candidate.identity_mode = static_cast<K6IdentityMode>(r.u8());
    candidate.endpoint_slot = r.u16le();
    candidate.source_lease_id = r.u64le();
    candidate.lifetime_s = r.u32le();
    candidate.refresh_after_s = r.u32le();
    r.bytes(candidate.cohort_id.data(), candidate.cohort_id.size());
    candidate.commitment_kind = static_cast<K6CommitmentKind>(r.u8());
    r.bytes(candidate.content_commitment.data(), candidate.content_commitment.size());
    if (!r.ok()) return Kad6Status::Truncated;
    std::size_t used = 0;
    Kad6Status s = DecodeK6Endpoint(in + r.pos(), len - r.pos(), candidate.virtual_endpoint, &used);
    if (s != Kad6Status::Ok) return s;
    r.take(used);
    used = 0;
    s = DecodeKad6Address(in + r.pos(), len - r.pos(), candidate.exit_apparent_ip, &used);
    if (s != Kad6Status::Ok) return s;
    r.take(used);
    r.bytes(candidate.exit_node_pub.data(), candidate.exit_node_pub.size());
    r.bytes(candidate.bind_nonce.data(), candidate.bind_nonce.size());
    r.bytes(candidate.signature.data(), candidate.signature.size());
    if (!r.ok()) return Kad6Status::Truncated;
    std::vector<Byte> check;
    if (SerializeBoundUnsigned(candidate, check) != Kad6Status::Ok)
        return Kad6Status::Malformed;
    out = std::move(candidate);
    if (consumed) *consumed = r.pos();
    return Kad6Status::Ok;
}

Kad6Status SignK6SourceBound(const Kad6CryptoHooks& hooks,
                             const Byte* secret, std::size_t secret_len,
                             const K6SourceBind& bind, K6SourceBound& bound,
                             std::vector<Byte>& out) {
    out.clear();
    if (!hooks.ed25519_sign) return Kad6Status::NullArgument;
    std::vector<Byte> message;
    Kad6Status s = K6SourceBoundSerializeSigned(bind, bound, message);
    if (s != Kad6Status::Ok) return s;
    if (!hooks.ed25519_sign(secret, secret_len, message.data(), message.size(),
                            bound.signature.data()))
        return Kad6Status::AuthFailed;
    return EncodeK6SourceBound(bound, out);
}

Kad6Status VerifyK6SourceBound(const Kad6CryptoHooks& hooks,
                               const K6SourceBind& bind,
                               const K6SourceBound& bound,
                               const Byte expected_exit_pub[kEd25519PubSize]) {
    if (!hooks.ed25519_verify || !expected_exit_pub) return Kad6Status::NullArgument;
    if (AllZero(bound.exit_node_pub) ||
        !Kad6CtEqual(expected_exit_pub, bound.exit_node_pub.data(),
                     bound.exit_node_pub.size()) ||
        !Kad6CtEqual(bind.bind_nonce.data(), bound.bind_nonce.data(), bind.bind_nonce.size()))
        return Kad6Status::AuthFailed;
    const Kad6Status semantic = ValidateSuccessfulBound(bind, bound);
    if (semantic != Kad6Status::Ok) return semantic;
    std::vector<Byte> message;
    Kad6Status s = K6SourceBoundSerializeSigned(bind, bound, message);
    if (s != Kad6Status::Ok) return s;
    return hooks.ed25519_verify(bound.exit_node_pub.data(), message.data(), message.size(),
                                bound.signature.data())
        ? Kad6Status::Ok : Kad6Status::AuthFailed;
}

Kad6Status EncodeK6SourceUnbind(const K6SourceUnbind& value, std::vector<Byte>& out) {
    out.clear();
    if (value.source_lease_id == 0 || value.source_epoch == 0 ||
        static_cast<Byte>(value.reason) > static_cast<Byte>(K6SourceUnbindReason::Policy) ||
        AllZero(value.bind_nonce))
        return Kad6Status::BadValue;
    for (Byte b : value.reserved) if (b != 0) return Kad6Status::BadValue;
    ByteWriter w(out);
    w.u64le(value.source_lease_id);
    w.u64le(value.source_epoch);
    w.u8(static_cast<Byte>(value.reason));
    w.bytes(value.reserved.data(), value.reserved.size());
    w.bytes(value.bind_nonce.data(), value.bind_nonce.size());
    return Kad6Status::Ok;
}

Kad6Status DecodeK6SourceUnbind(const Byte* in, std::size_t len, K6SourceUnbind& out,
                                std::size_t* consumed) noexcept {
    out = K6SourceUnbind{};
    if (consumed) *consumed = 0;
    if (!in && len != 0) return Kad6Status::NullArgument;
    ByteReader r(in, len);
    K6SourceUnbind candidate;
    candidate.source_lease_id = r.u64le();
    candidate.source_epoch = r.u64le();
    candidate.reason = static_cast<K6SourceUnbindReason>(r.u8());
    r.bytes(candidate.reserved.data(), candidate.reserved.size());
    r.bytes(candidate.bind_nonce.data(), candidate.bind_nonce.size());
    if (!r.ok()) return Kad6Status::Truncated;
    if (candidate.source_lease_id == 0 || candidate.source_epoch == 0 ||
        static_cast<Byte>(candidate.reason) > static_cast<Byte>(K6SourceUnbindReason::Policy) ||
        AllZero(candidate.bind_nonce))
        return Kad6Status::Malformed;
    for (Byte b : candidate.reserved) if (b != 0) return Kad6Status::Malformed;
    out = candidate;
    if (consumed) *consumed = r.pos();
    return Kad6Status::Ok;
}

Kad6Status K6SourceLeaseTable::AddBound(std::uint32_t circuit_id,
                                        const Hash16& pseudonym,
                                        const K6SourceBind& bind,
                                        const K6SourceBound& bound,
                                        std::uint64_t now) {
    if (circuit_id == 0 || AllZero(pseudonym) ||
        ValidateSuccessfulBound(bind, bound) != Kad6Status::Ok ||
        bound.status != K6SourceBoundStatus::Ok || bound.source_lease_id == 0 ||
        bound.lifetime_s < kK6SourceMinLifetimeSeconds ||
        bound.lifetime_s > kK6SourceMaxLifetimeSeconds ||
        bound.refresh_after_s == 0 || bound.refresh_after_s >= bound.lifetime_s ||
        leases_.find(bound.source_lease_id) != leases_.end() ||
        !Kad6CtEqual(bind.bind_nonce.data(), bound.bind_nonce.data(), bind.bind_nonce.size()) ||
        bind.commitment_kind != bound.commitment_kind ||
        !Kad6CtEqual(bind.content_commitment.data(), bound.content_commitment.data(),
                     bind.content_commitment.size()) ||
        now > (std::numeric_limits<std::uint64_t>::max)() - bound.lifetime_s)
        return Kad6Status::BadValue;
    if (bound.binding_mode == K6BindingMode::DedicatedVep) {
        if (bound.identity_mode != K6IdentityMode::OriginatorVep ||
            !AllZero(bound.cohort_id) || bound.endpoint_slot == 0)
            return Kad6Status::BadValue;
    } else if (bound.binding_mode == K6BindingMode::Cohort) {
        if (bound.identity_mode != K6IdentityMode::ExitTerminated ||
            AllZero(bound.cohort_id) || bound.endpoint_slot == 0 ||
            bound.commitment_kind == K6CommitmentKind::None)
            return Kad6Status::BadValue;
    } else {
        return Kad6Status::BadValue;
    }
    if (bound.binding_mode == K6BindingMode::Cohort) {
        for (const auto& pair : leases_) {
            const K6SourceLease& existing = pair.second;
            if (existing.state == K6SourceLeaseState::Closed ||
                existing.state == K6SourceLeaseState::Draining ||
                existing.bound.binding_mode != K6BindingMode::Cohort ||
                !SameFrontDoor(existing.bound.virtual_endpoint, bound.virtual_endpoint) ||
                !Kad6CtEqual(existing.bind.file_hash.data(), bind.file_hash.data(),
                             bind.file_hash.size()))
                continue;
            if (existing.bind.file_size != bind.file_size ||
                existing.bound.commitment_kind != bound.commitment_kind ||
                !Kad6CtEqual(existing.bound.content_commitment.data(),
                             bound.content_commitment.data(),
                             bound.content_commitment.size()) ||
                !Kad6CtEqual(existing.bound.cohort_id.data(), bound.cohort_id.data(),
                             bound.cohort_id.size()))
                return Kad6Status::BadValue;
        }
    }
    K6SourceLease lease;
    lease.lease_id = bound.source_lease_id;
    lease.circuit_id = circuit_id;
    lease.pseudonym = pseudonym;
    lease.bind = bind;
    lease.bound = bound;
    lease.state = bound.binding_mode == K6BindingMode::DedicatedVep
        ? K6SourceLeaseState::BoundDedicatedNotPublished
        : K6SourceLeaseState::JoinedCohortNotPublished;
    lease.created_at = now;
    lease.expires_at = now + bound.lifetime_s;
    lease.next_refresh_at = now + bound.refresh_after_s;
    const std::uint64_t leaseId = lease.lease_id;
    const std::uint64_t expiresAt = lease.expires_at;
    leases_.emplace(leaseId, std::move(lease));
    circuit_index_[circuit_id].insert(leaseId);
    const ExpiryIndex::iterator expiry = expiry_index_.emplace(expiresAt, leaseId);
    expiry_refs_.emplace(leaseId, expiry);
    return Kad6Status::Ok;
}

K6SourceLease* K6SourceLeaseTable::Find(std::uint64_t id) {
    auto it = leases_.find(id); return it == leases_.end() ? nullptr : &it->second;
}
const K6SourceLease* K6SourceLeaseTable::Find(std::uint64_t id) const {
    auto it = leases_.find(id); return it == leases_.end() ? nullptr : &it->second;
}
bool K6SourceLeaseTable::CanPublish(std::uint64_t id) const {
    const K6SourceLease* l = Find(id);
    return l && (l->state == K6SourceLeaseState::BoundDedicatedNotPublished ||
                 l->state == K6SourceLeaseState::JoinedCohortNotPublished ||
                 l->state == K6SourceLeaseState::Published ||
                 l->state == K6SourceLeaseState::Serving);
}
bool K6SourceLeaseTable::CanAccept(std::uint64_t id) const {
    const K6SourceLease* l = Find(id);
    return l && l->accept_new_sessions && l->state == K6SourceLeaseState::Serving;
}
Kad6Status K6SourceLeaseTable::MarkPublished(std::uint64_t id) {
    K6SourceLease* l = Find(id);
    if (!l || (l->state != K6SourceLeaseState::BoundDedicatedNotPublished &&
               l->state != K6SourceLeaseState::JoinedCohortNotPublished))
        return Kad6Status::BadValue;
    l->state = K6SourceLeaseState::Published;
    return Kad6Status::Ok;
}
Kad6Status K6SourceLeaseTable::MarkServing(std::uint64_t id) {
    K6SourceLease* l = Find(id);
    if (!l || (l->state != K6SourceLeaseState::Published &&
               l->state != K6SourceLeaseState::Serving))
        return Kad6Status::BadValue;
    l->state = K6SourceLeaseState::Serving;
    l->accept_new_sessions = true;
    return Kad6Status::Ok;
}
Kad6Status K6SourceLeaseTable::BeginDrain(std::uint64_t id) {
    K6SourceLease* l = Find(id);
    if (!l || l->state == K6SourceLeaseState::Closed) return Kad6Status::BadValue;
    l->state = K6SourceLeaseState::Draining;
    l->accept_new_sessions = false;
    RemoveCircuitIndex(*l);
    return Kad6Status::Ok;
}
std::size_t K6SourceLeaseTable::DrainCircuit(std::uint32_t circuit_id,
                                              std::vector<std::uint64_t>* transitioned) {
    return DrainCircuitSome(circuit_id,
        (std::numeric_limits<std::size_t>::max)(), transitioned);
}
std::size_t K6SourceLeaseTable::DrainCircuitSome(
        std::uint32_t circuit_id, std::size_t maxTransitions,
        std::vector<std::uint64_t>* transitioned) {
    if (maxTransitions == 0) return 0;
    auto circuit = circuit_index_.find(circuit_id);
    if (circuit == circuit_index_.end()) return 0;
    std::size_t count = 0;
    while (circuit != circuit_index_.end() && !circuit->second.empty() &&
           count < maxTransitions) {
        const std::uint64_t leaseId = *circuit->second.begin();
        circuit->second.erase(circuit->second.begin());
        K6SourceLease* lease = Find(leaseId);
        if (!lease || lease->state == K6SourceLeaseState::Closed ||
            lease->state == K6SourceLeaseState::Draining)
            continue;
        lease->state = K6SourceLeaseState::Draining;
        lease->accept_new_sessions = false;
        if (transitioned) transitioned->push_back(leaseId);
        ++count;
    }
    if (circuit != circuit_index_.end() && circuit->second.empty())
        circuit_index_.erase(circuit);
    return count;
}
void K6SourceLeaseTable::QueueCircuitTeardown(std::uint32_t circuit_id) {
    if (circuit_id != 0) teardown_queue_.insert(circuit_id);
}
std::size_t K6SourceLeaseTable::DrainQueuedCircuits(
        std::size_t maxTransitions, std::vector<std::uint64_t>* transitioned) {
    std::size_t count = 0;
    while (!teardown_queue_.empty() && count < maxTransitions) {
        const std::uint32_t circuitId = *teardown_queue_.begin();
        // This queue is fed only after the transport has disappeared. Closing
        // directly avoids retaining a dead-circuit lease until its publication
        // TTL and lets 4,096 independent losses finish in sixteen 256-item
        // ticks. Explicit UNBIND and service drains remain graceful.
        const std::size_t changed = CloseCircuitSome(
            circuitId, maxTransitions - count, transitioned);
        count += changed;
        if (circuit_index_.find(circuitId) == circuit_index_.end())
            teardown_queue_.erase(teardown_queue_.begin());
        else if (changed == 0)
            break;
    }
    return count;
}
std::size_t K6SourceLeaseTable::CloseCircuitSome(
        std::uint32_t circuit_id, std::size_t maxTransitions,
        std::vector<std::uint64_t>* transitioned) {
    if (maxTransitions == 0) return 0;
    auto circuit = circuit_index_.find(circuit_id);
    if (circuit == circuit_index_.end()) return 0;
    std::size_t count = 0;
    while (circuit != circuit_index_.end() && !circuit->second.empty() &&
           count < maxTransitions) {
        const std::uint64_t leaseId = *circuit->second.begin();
        K6SourceLease* lease = Find(leaseId);
        if (!lease || lease->state == K6SourceLeaseState::Closed) {
            circuit->second.erase(circuit->second.begin());
            continue;
        }
        MarkClosed(*lease);
        if (transitioned) transitioned->push_back(leaseId);
        ++count;
        circuit = circuit_index_.find(circuit_id);
    }
    return count;
}
std::size_t K6SourceLeaseTable::Expire(std::uint64_t now) {
    return ExpireSome(now, (std::numeric_limits<std::size_t>::max)(), nullptr);
}
std::size_t K6SourceLeaseTable::ExpireSome(
        std::uint64_t now, std::size_t maxTransitions,
        std::vector<std::uint64_t>* transitioned) {
    if (maxTransitions == 0) return 0;
    std::size_t count = 0;
    while (!expiry_index_.empty() && expiry_index_.begin()->first <= now &&
           count < maxTransitions) {
        const ExpiryIndex::iterator expiry = expiry_index_.begin();
        const std::uint64_t leaseId = expiry->second;
        expiry_refs_.erase(leaseId);
        expiry_index_.erase(expiry);
        K6SourceLease* lease = Find(leaseId);
        if (!lease || lease->state == K6SourceLeaseState::Closed)
            continue;
        MarkClosed(*lease);
        if (transitioned) transitioned->push_back(leaseId);
        ++count;
    }
    return count;
}
std::size_t K6SourceLeaseTable::EraseClosed() {
    return EraseClosedSome((std::numeric_limits<std::size_t>::max)());
}
std::size_t K6SourceLeaseTable::EraseClosedSome(std::size_t maxErase) {
    std::size_t count = 0;
    while (!closed_index_.empty() && count < maxErase) {
        const std::uint64_t leaseId = *closed_index_.begin();
        closed_index_.erase(closed_index_.begin());
        const auto lease = leases_.find(leaseId);
        if (lease == leases_.end()) continue;
        RemoveIndexes(lease->second);
        leases_.erase(lease);
        ++count;
    }
    return count;
}
std::size_t K6SourceLeaseTable::ActiveSize() const noexcept {
    std::size_t count = 0;
    for (const auto& pair : leases_)
        if (pair.second.state != K6SourceLeaseState::Closed)
            ++count;
    return count;
}
bool K6SourceLeaseTable::Close(std::uint64_t id) {
    K6SourceLease* l = Find(id);
    if (!l) return false;
    MarkClosed(*l);
    return true;
}

std::vector<std::uint32_t> K6SourceLeaseTable::TrackedCircuits() const {
    std::vector<std::uint32_t> result;
    result.reserve(circuit_index_.size());
    for (const auto& circuit : circuit_index_)
        result.push_back(circuit.first);
    return result;
}

void K6SourceLeaseTable::MarkClosed(K6SourceLease& lease) {
    lease.state = K6SourceLeaseState::Closed;
    lease.accept_new_sessions = false;
    closed_index_.insert(lease.lease_id);
    RemoveCircuitIndex(lease);
    const auto expiry = expiry_refs_.find(lease.lease_id);
    if (expiry != expiry_refs_.end()) {
        expiry_index_.erase(expiry->second);
        expiry_refs_.erase(expiry);
    }
}

void K6SourceLeaseTable::RemoveCircuitIndex(const K6SourceLease& lease) {
    const auto circuit = circuit_index_.find(lease.circuit_id);
    if (circuit == circuit_index_.end()) return;
    circuit->second.erase(lease.lease_id);
    if (circuit->second.empty()) circuit_index_.erase(circuit);
}

void K6SourceLeaseTable::RemoveIndexes(const K6SourceLease& lease) {
    RemoveCircuitIndex(lease);
    const auto expiry = expiry_refs_.find(lease.lease_id);
    if (expiry != expiry_refs_.end()) {
        expiry_index_.erase(expiry->second);
        expiry_refs_.erase(expiry);
    }
}

} // namespace kad6
