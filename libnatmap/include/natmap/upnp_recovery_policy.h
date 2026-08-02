#pragma once

#include "natmap/ownership_ledger.h"

#include <cstdint>

namespace natmap {

enum class UpnpRecoveryObservation : std::uint8_t {
    ExactOwnedMapping = 0,
    MappingAbsent = 1,
    OwnershipMismatch = 2,
    GatewayMismatch = 3,
    TransientReadbackFailure = 4
};

enum class UpnpRecoveryAction : std::uint8_t {
    DeleteOwnedMapping = 0,
    DropLocalProof = 1,
    KeepLocalProof = 2
};

// Recovery never authorizes a router mutation unless readback has already
// proved the exact recorded rule. Unknown/transient observations retain the
// local proof so a later retry can repeat the complete ownership gate.
UpnpRecoveryAction EvaluateUpnpRecovery(
    UpnpRecoveryObservation observation) noexcept;
UpnpRecoveryAction EvaluateUpnpRecovery(
    OwnershipDecision decision) noexcept;
bool ParseUpnpDecimalPort(
    const char* text, std::uint16_t& port) noexcept;

} // namespace natmap
