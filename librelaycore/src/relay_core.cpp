// SPDX-License-Identifier: MIT
#include "relay/relay_core.h"

namespace relay {

namespace {

constexpr RelayCoreBuildInfo kBuildInfo = {
    kKrpVersionMajor,
    kKrpVersionMinor,
    false, // Core semantics exist, but no carrier/integration enables KRP wire.
    false, // Public mode remains fail-closed through P1.
};

} // namespace

const RelayCoreBuildInfo& GetRelayCoreBuildInfo() noexcept {
    return kBuildInfo;
}

const char* RelayStatusName(RelayStatus status) noexcept {
    switch (status) {
        case RelayStatus::Ok:                 return "Ok";
        case RelayStatus::Disabled:           return "Disabled";
        case RelayStatus::InvalidArgument:    return "InvalidArgument";
        case RelayStatus::InvalidState:       return "InvalidState";
        case RelayStatus::UnsupportedVersion: return "UnsupportedVersion";
        case RelayStatus::UnsupportedMessage: return "UnsupportedMessage";
        case RelayStatus::UnsupportedOption:  return "UnsupportedOption";
        case RelayStatus::Truncated:          return "Truncated";
        case RelayStatus::Malformed:          return "Malformed";
        case RelayStatus::TooLarge:           return "TooLarge";
        case RelayStatus::AuthFailed:         return "AuthFailed";
        case RelayStatus::OneRttRequired:     return "OneRttRequired";
        case RelayStatus::ReplayDetected:     return "ReplayDetected";
        case RelayStatus::ReplayCheckUnavailable: return "ReplayCheckUnavailable";
        case RelayStatus::StaleEpoch:         return "StaleEpoch";
        case RelayStatus::StaleGeneration:    return "StaleGeneration";
        case RelayStatus::SequenceError:      return "SequenceError";
        case RelayStatus::QuotaExceeded:      return "QuotaExceeded";
        case RelayStatus::TargetForbidden:    return "TargetForbidden";
        case RelayStatus::Expired:            return "Expired";
    }
    return "Unknown";
}

bool RelayCoreCanOpenNetwork() noexcept {
    return kBuildInfo.wire_enabled && kBuildInfo.public_mode_enabled;
}

} // namespace relay
