#include "natmap/upnp_recovery_policy.h"

namespace natmap {

UpnpRecoveryAction EvaluateUpnpRecovery(
    UpnpRecoveryObservation observation) noexcept {
    switch (observation) {
    case UpnpRecoveryObservation::ExactOwnedMapping:
        return UpnpRecoveryAction::DeleteOwnedMapping;
    case UpnpRecoveryObservation::MappingAbsent:
    case UpnpRecoveryObservation::OwnershipMismatch:
    case UpnpRecoveryObservation::GatewayMismatch:
        return UpnpRecoveryAction::DropLocalProof;
    case UpnpRecoveryObservation::TransientReadbackFailure:
    default:
        return UpnpRecoveryAction::KeepLocalProof;
    }
}

UpnpRecoveryAction EvaluateUpnpRecovery(
    OwnershipDecision decision) noexcept {
    switch (decision) {
    case OwnershipDecision::Owned:
        return UpnpRecoveryAction::DeleteOwnedMapping;
    case OwnershipDecision::GatewayMismatch:
    case OwnershipDecision::TransportMismatch:
    case OwnershipDecision::ExternalPortMismatch:
    case OwnershipDecision::InternalClientMismatch:
    case OwnershipDecision::InternalPortMismatch:
    case OwnershipDecision::DescriptionMismatch:
        return UpnpRecoveryAction::DropLocalProof;
    case OwnershipDecision::InvalidRecord:
    case OwnershipDecision::InvalidObservation:
    default:
        return UpnpRecoveryAction::KeepLocalProof;
    }
}

bool ParseUpnpDecimalPort(
    const char* text, std::uint16_t& port) noexcept {
    port = 0;
    if (text == nullptr || text[0] == 0)
        return false;
    std::uint32_t value = 0;
    for (const unsigned char* cursor =
             reinterpret_cast<const unsigned char*>(text);
         *cursor != 0; ++cursor) {
        if (*cursor < '0' || *cursor > '9')
            return false;
        const std::uint32_t digit = *cursor - '0';
        if (value > (65535u - digit) / 10u)
            return false;
        value = value * 10u + digit;
    }
    if (value == 0)
        return false;
    port = static_cast<std::uint16_t>(value);
    return true;
}

} // namespace natmap
