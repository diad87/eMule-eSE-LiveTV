// SPDX-License-Identifier: MIT
#include "relay/krp_authority.h"

#include <algorithm>

namespace relay {

namespace {

template <typename Array>
bool IsAllZero(const Array& value) noexcept {
    return std::all_of(value.begin(), value.end(), [](Byte byte) {
        return byte == 0;
    });
}

bool IsKnownService(KrpService service) noexcept {
    return service >= KrpService::Control && service <= KrpService::Diagnostic;
}

bool IsKnownKind(KrpAuthorityKind kind) noexcept {
    return kind >= KrpAuthorityKind::InternalControl &&
           kind <= KrpAuthorityKind::Administrative;
}

} // namespace

bool IsAuthorityKindAllowed(KrpService service, KrpAuthorityKind kind) noexcept {
    switch (service) {
        case KrpService::Control:
            return kind == KrpAuthorityKind::InternalControl;
        case KrpService::Ed2kServer:
            return kind == KrpAuthorityKind::SelectedServer;
        case KrpService::LegacyTcpInbound:
            return kind == KrpAuthorityKind::InboundLease;
        case KrpService::LegacyTcpOutbound:
            return kind == KrpAuthorityKind::Kad6TargetTicket ||
                   kind == KrpAuthorityKind::FilePeerTicket;
        case KrpService::Kad6Native:
            return kind == KrpAuthorityKind::RendezvousTicket;
        case KrpService::FileTransfer:
            return kind == KrpAuthorityKind::FilePeerTicket ||
                   kind == KrpAuthorityKind::Kad6TargetTicket;
        case KrpService::LiveControl:
        case KrpService::LiveReliableMedia:
            return kind == KrpAuthorityKind::PriorityGrant;
        case KrpService::PortTest:
            return kind == KrpAuthorityKind::PortProbe;
        case KrpService::Diagnostic:
            return kind == KrpAuthorityKind::Administrative;
    }
    return false;
}

RelayStatus AuthorizeKrpService(const KrpSession& session,
                                const KrpAuthorityRequest& request,
                                std::uint64_t now,
                                KrpTransportPhase transport_phase,
                                IServiceAuthorityVerifier& verifier,
                                KrpAuthorityGrant& grant) {
    if (!IsKnownService(request.service) || !IsKnownKind(request.kind))
        return RelayStatus::UnsupportedOption;
    if (!IsAuthorityKindAllowed(request.service, request.kind))
        return RelayStatus::TargetForbidden;
    if (request.evidence.size() > kKrpMaxAuthorityEvidence)
        return RelayStatus::TooLarge;
    if (request.kind != KrpAuthorityKind::InternalControl && request.evidence.empty())
        return RelayStatus::AuthFailed;
    if (!session.has_binding() || request.session_id != session.binding().session_id)
        return RelayStatus::AuthFailed;

    const RelayStatus admission = session.AuthorizeOperation(
        KrpSessionOperation::FlowOpen,
        transport_phase,
        request.session_epoch,
        request.route_generation);
    if (admission != RelayStatus::Ok)
        return admission;

    KrpAuthorityGrant verified;
    const RelayStatus verification = verifier.VerifyAndConsume(request, now, verified);
    if (verification != RelayStatus::Ok)
        return verification;
    if (verified.service != request.service || verified.kind != request.kind ||
        IsAllZero(verified.grant_id))
        return RelayStatus::AuthFailed;
    if (verified.expires_at <= now ||
        verified.expires_at - now > kKrpMaxAuthorityTtlSeconds)
        return RelayStatus::Expired;
    if (verified.max_bytes == 0 || verified.max_bytes > kKrpMaxGrantBytes ||
        verified.max_flows == 0 || verified.max_flows > kKrpMaxGrantFlows ||
        verified.effective_priority > 5)
        return RelayStatus::QuotaExceeded;

    grant = verified;
    return RelayStatus::Ok;
}

} // namespace relay
