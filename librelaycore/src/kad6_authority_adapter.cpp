// SPDX-License-Identifier: MIT
#include "relay/kad6_authority_adapter.h"

#include <algorithm>

namespace relay {

namespace {

RelayStatus MapKad6Status(kad6::Kad6Status status) noexcept {
    switch (status) {
        case kad6::Kad6Status::Ok:                 return RelayStatus::Ok;
        case kad6::Kad6Status::Truncated:          return RelayStatus::Truncated;
        case kad6::Kad6Status::Malformed:           return RelayStatus::Malformed;
        case kad6::Kad6Status::UnsupportedVersion: return RelayStatus::UnsupportedVersion;
        case kad6::Kad6Status::UnsupportedOption:  return RelayStatus::UnsupportedOption;
        case kad6::Kad6Status::TooLarge:            return RelayStatus::TooLarge;
        case kad6::Kad6Status::BadValue:
        case kad6::Kad6Status::NullArgument:        return RelayStatus::InvalidArgument;
        case kad6::Kad6Status::AuthFailed:          return RelayStatus::AuthFailed;
        case kad6::Kad6Status::StaleEpoch:          return RelayStatus::StaleEpoch;
        case kad6::Kad6Status::TargetForbidden:     return RelayStatus::TargetForbidden;
        case kad6::Kad6Status::Expired:             return RelayStatus::Expired;
    }
    return RelayStatus::Malformed;
}

} // namespace

Kad6TargetAuthorityVerifier::Kad6TargetAuthorityVerifier(
    const kad6::Kad6CryptoHooks& crypto,
    const kad6::K6TargetPolicy& policy,
    const Byte* secret,
    std::size_t secret_size) noexcept
    : crypto_(crypto), policy_(policy) {
    if (secret == nullptr || secret_size == 0 ||
        secret_size > secret_.size() || crypto_.hmac_sha256 == nullptr ||
        policy_.allow_target == nullptr || policy_.consume_use == nullptr)
        return;
    std::copy(secret, secret + secret_size, secret_.begin());
    secret_size_ = secret_size;
    ready_ = true;
}

RelayStatus Kad6TargetAuthorityVerifier::VerifyAndConsume(
    const KrpAuthorityRequest& request,
    std::uint64_t now,
    KrpAuthorityGrant& grant) noexcept {
    if (!ready_)
        return RelayStatus::Disabled;
    if ((request.service != KrpService::LegacyTcpOutbound &&
         request.service != KrpService::FileTransfer) ||
        request.kind != KrpAuthorityKind::Kad6TargetTicket)
        return RelayStatus::TargetForbidden;
    if (request.evidence.empty() || request.evidence.size() > kKrpMaxAuthorityEvidence)
        return RelayStatus::InvalidArgument;

    kad6::K6TargetTicket ticket;
    const kad6::Kad6Status status = kad6::VerifyK6TargetTicket(
        crypto_,
        policy_,
        secret_.data(),
        secret_size_,
        request.evidence.data(),
        request.evidence.size(),
        now,
        ticket);
    if (status != kad6::Kad6Status::Ok)
        return MapKad6Status(status);
    if (ticket.service != static_cast<kad6::Byte>(kad6::K6TicketService::Ed2kTcp))
        return RelayStatus::TargetForbidden;

    KrpAuthorityGrant verified;
    std::copy(ticket.nonce.begin(), ticket.nonce.end(), verified.grant_id.begin());
    verified.service = request.service;
    verified.kind = request.kind;
    verified.expires_at = ticket.expires_at;
    verified.max_bytes = ticket.max_bytes;
    verified.max_flows = ticket.max_connections;
    verified.effective_priority = 4;
    grant = verified;
    return RelayStatus::Ok;
}

} // namespace relay
