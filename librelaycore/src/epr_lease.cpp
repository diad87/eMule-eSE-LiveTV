// SPDX-License-Identifier: MIT
#include "relay/epr_lease.h"

#include <algorithm>

namespace relay {

namespace {

template <typename Array>
bool IsAllZero(const Array& value) noexcept {
    return std::all_of(value.begin(), value.end(), [](Byte byte) {
        return byte == 0;
    });
}

bool IsKnownClass(EprLeaseClass lease_class) noexcept {
    return lease_class >= EprLeaseClass::LabOnly &&
           lease_class <= EprLeaseClass::ServerDedicated;
}

bool IsTerminal(EprLeaseState state) noexcept {
    return state == EprLeaseState::Revoked || state == EprLeaseState::Expired ||
           state == EprLeaseState::Released || state == EprLeaseState::Failed;
}

RelayStatus ValidateTimes(std::uint64_t issued_at,
                          std::uint64_t expires_at,
                          std::uint64_t grace_expires_at) noexcept {
    if (issued_at == 0 || expires_at <= issued_at || grace_expires_at < expires_at)
        return RelayStatus::InvalidArgument;
    if (expires_at - issued_at > kEprMaxLeaseTtlSeconds ||
        grace_expires_at - expires_at > kEprMaxGraceSeconds)
        return RelayStatus::TooLarge;
    return RelayStatus::Ok;
}

} // namespace

bool EprPublicAddressAllowed(const EprPublicAddress& address) noexcept {
    const Byte* p = address.bytes.data();
    if (address.family == EprAddressFamily::IPv4) {
        for (std::size_t index = 4; index < address.bytes.size(); ++index) {
            if (p[index] != 0)
                return false;
        }
        const Byte a = p[0], b = p[1], c = p[2];
        if (a == 0 || a == 10 || a == 127 || a >= 224)
            return false;
        if (a == 100 && b >= 64 && b <= 127)
            return false;
        if (a == 169 && b == 254)
            return false;
        if (a == 172 && b >= 16 && b <= 31)
            return false;
        if (a == 192 && (b == 168 || (b == 0 && c == 2)))
            return false;
        if (a == 198 && (b == 18 || b == 19 || (b == 51 && c == 100)))
            return false;
        if (a == 203 && b == 0 && c == 113)
            return false;
        return true;
    }
    if (address.family == EprAddressFamily::IPv6) {
        if ((p[0] & 0xE0u) != 0x20u || IsAllZero(address.bytes))
            return false;
        if (p[0] == 0x20 && p[1] == 0x01 && p[2] == 0x0D && p[3] == 0xB8)
            return false;
        return true;
    }
    return false;
}

RelayStatus EprLease::Initialize(const EprLeaseRequest& request,
                                 const KrpSession& session,
                                 KrpTransportPhase transport_phase) noexcept {
    if (initialized_)
        return RelayStatus::InvalidState;
    if (request.lease_id == 0 || request.generation == 0 ||
        IsAllZero(request.session_id) || IsAllZero(request.node_id) ||
        !IsKnownClass(request.lease_class) ||
        (!request.request_tcp && !request.request_udp))
        return RelayStatus::InvalidArgument;
    const RelayStatus times = ValidateTimes(
        request.issued_at, request.expires_at, request.grace_expires_at);
    if (times != RelayStatus::Ok)
        return times;
    if (!session.has_binding() || request.session_id != session.binding().session_id ||
        request.node_id != session.binding().node_id)
        return RelayStatus::AuthFailed;
    const RelayStatus admission = session.AuthorizeOperation(
        KrpSessionOperation::LeaseMutation,
        transport_phase,
        session.binding().session_epoch,
        session.binding().route_generation);
    if (admission != RelayStatus::Ok)
        return admission;

    record_.request = request;
    record_.session_epoch = session.binding().session_epoch;
    record_.route_generation = session.binding().route_generation;
    record_.state = EprLeaseState::Requested;
    initialized_ = true;
    return RelayStatus::Ok;
}

RelayStatus EprLease::Allocate(std::uint64_t expected_generation,
                               const EprPublicAddress& address,
                               std::uint16_t tcp_port,
                               std::uint16_t udp_port) noexcept {
    if (!initialized_ || record_.state != EprLeaseState::Requested)
        return RelayStatus::InvalidState;
    if (expected_generation != record_.request.generation)
        return RelayStatus::StaleGeneration;
    if (!EprPublicAddressAllowed(address) ||
        record_.request.request_tcp != (tcp_port != 0) ||
        record_.request.request_udp != (udp_port != 0))
        return RelayStatus::InvalidArgument;
    record_.public_address = address;
    record_.tcp_port = tcp_port;
    record_.udp_port = udp_port;
    record_.state = EprLeaseState::Allocated;
    return RelayStatus::Ok;
}

RelayStatus EprLease::MarkBound() noexcept {
    if (record_.state != EprLeaseState::Allocated)
        return RelayStatus::InvalidState;
    record_.state = EprLeaseState::Bound;
    return RelayStatus::Ok;
}

RelayStatus EprLease::BeginProbe(const EprProbeNonce& nonce) noexcept {
    if (record_.state != EprLeaseState::Bound)
        return RelayStatus::InvalidState;
    if (IsAllZero(nonce))
        return RelayStatus::InvalidArgument;
    record_.probe_nonce = nonce;
    record_.state = EprLeaseState::Probing;
    return RelayStatus::Ok;
}

RelayStatus EprLease::CompleteProbe(const EprProbeNonce& nonce, bool succeeded) noexcept {
    if (record_.state != EprLeaseState::Probing)
        return RelayStatus::InvalidState;
    if (nonce != record_.probe_nonce)
        return RelayStatus::AuthFailed;
    record_.probe_nonce.fill(0);
    record_.state = succeeded ? EprLeaseState::Active : EprLeaseState::Failed;
    return succeeded ? RelayStatus::Ok : RelayStatus::TargetForbidden;
}

RelayStatus EprLease::Renew(std::uint64_t expected_generation,
                            std::uint64_t new_generation,
                            std::uint64_t now,
                            std::uint64_t new_expires_at,
                            std::uint64_t new_grace_expires_at,
                            const KrpSession& session,
                            KrpTransportPhase transport_phase) noexcept {
    if (record_.state != EprLeaseState::Active &&
        record_.state != EprLeaseState::Grace)
        return RelayStatus::InvalidState;
    if (expected_generation != record_.request.generation ||
        new_generation <= expected_generation)
        return RelayStatus::StaleGeneration;
    if (now < record_.request.issued_at)
        return RelayStatus::InvalidArgument;
    if (now >= record_.request.grace_expires_at)
        return RelayStatus::Expired;
    const RelayStatus times = ValidateTimes(now, new_expires_at, new_grace_expires_at);
    if (times != RelayStatus::Ok)
        return times;
    if (!session.has_binding() ||
        record_.request.session_id != session.binding().session_id ||
        record_.request.node_id != session.binding().node_id ||
        record_.session_epoch != session.binding().session_epoch)
        return RelayStatus::AuthFailed;
    const RelayStatus admission = session.AuthorizeOperation(
        KrpSessionOperation::LeaseMutation,
        transport_phase,
        session.binding().session_epoch,
        session.binding().route_generation);
    if (admission != RelayStatus::Ok)
        return admission;

    record_.request.generation = new_generation;
    record_.request.issued_at = now;
    record_.request.expires_at = new_expires_at;
    record_.request.grace_expires_at = new_grace_expires_at;
    record_.route_generation = session.binding().route_generation;
    record_.state = EprLeaseState::Active;
    return RelayStatus::Ok;
}

RelayStatus EprLease::EnterGrace() noexcept {
    if (record_.state != EprLeaseState::Active)
        return RelayStatus::InvalidState;
    record_.state = EprLeaseState::Grace;
    return RelayStatus::Ok;
}

RelayStatus EprLease::ResumeFromGrace(std::uint64_t expected_generation,
                                      std::uint64_t now,
                                      const KrpSession& session,
                                      KrpTransportPhase transport_phase) noexcept {
    if (record_.state != EprLeaseState::Grace)
        return RelayStatus::InvalidState;
    if (expected_generation != record_.request.generation)
        return RelayStatus::StaleGeneration;
    if (now < record_.request.issued_at)
        return RelayStatus::InvalidArgument;
    if (now >= record_.request.grace_expires_at)
        return RelayStatus::Expired;
    if (!session.has_binding() ||
        record_.request.session_id != session.binding().session_id ||
        record_.request.node_id != session.binding().node_id ||
        record_.session_epoch != session.binding().session_epoch)
        return RelayStatus::AuthFailed;
    const RelayStatus admission = session.AuthorizeOperation(
        KrpSessionOperation::LeaseMutation,
        transport_phase,
        session.binding().session_epoch,
        session.binding().route_generation);
    if (admission != RelayStatus::Ok)
        return admission;
    record_.route_generation = session.binding().route_generation;
    record_.state = EprLeaseState::Active;
    return RelayStatus::Ok;
}

RelayStatus EprLease::BeginDrain() noexcept {
    if (record_.state != EprLeaseState::Active &&
        record_.state != EprLeaseState::Grace)
        return RelayStatus::InvalidState;
    record_.state = EprLeaseState::Draining;
    return RelayStatus::Ok;
}

RelayStatus EprLease::Revoke() noexcept {
    if (!initialized_ || IsTerminal(record_.state))
        return RelayStatus::InvalidState;
    record_.state = EprLeaseState::Revoked;
    record_.probe_nonce.fill(0);
    return RelayStatus::Ok;
}

RelayStatus EprLease::Release() noexcept {
    if (!initialized_ || IsTerminal(record_.state))
        return RelayStatus::InvalidState;
    record_.state = EprLeaseState::Released;
    record_.probe_nonce.fill(0);
    return RelayStatus::Ok;
}

RelayStatus EprLease::MarkFailed() noexcept {
    if (!initialized_ || IsTerminal(record_.state))
        return RelayStatus::InvalidState;
    record_.state = EprLeaseState::Failed;
    record_.probe_nonce.fill(0);
    return RelayStatus::Ok;
}

RelayStatus EprLease::AdvanceTime(std::uint64_t now) noexcept {
    if (!initialized_ || IsTerminal(record_.state))
        return RelayStatus::InvalidState;
    if (now < record_.request.expires_at)
        return RelayStatus::Ok;
    if (now < record_.request.grace_expires_at &&
        (record_.state == EprLeaseState::Active || record_.state == EprLeaseState::Grace)) {
        record_.state = EprLeaseState::Grace;
        return RelayStatus::Ok;
    }
    record_.state = EprLeaseState::Expired;
    record_.probe_nonce.fill(0);
    return RelayStatus::Expired;
}

const char* EprLeaseStateName(EprLeaseState state) noexcept {
    switch (state) {
        case EprLeaseState::None:      return "NONE";
        case EprLeaseState::Requested: return "REQUESTED";
        case EprLeaseState::Allocated: return "ALLOCATED";
        case EprLeaseState::Bound:     return "BOUND";
        case EprLeaseState::Probing:   return "PROBING";
        case EprLeaseState::Active:    return "ACTIVE";
        case EprLeaseState::Grace:     return "GRACE";
        case EprLeaseState::Draining:  return "DRAINING";
        case EprLeaseState::Revoked:   return "REVOKED";
        case EprLeaseState::Expired:   return "EXPIRED";
        case EprLeaseState::Released:  return "RELEASED";
        case EprLeaseState::Failed:    return "FAILED";
    }
    return "UNKNOWN";
}

} // namespace relay
