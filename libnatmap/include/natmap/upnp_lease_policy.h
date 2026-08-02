#pragma once

#include <cstdint>

namespace natmap {

enum class UpnpExistingLeaseAction : std::uint8_t {
    Reuse = 0,
    RenewFinite = 1,
    Create = 2
};

struct UpnpExistingLeaseObservation {
    bool refresh = false;
    bool query_succeeded = false;
    bool target_matches = false;
    bool ownership_matches = false;
    std::uint32_t remaining_lifetime_seconds = 0;
};

UpnpExistingLeaseAction EvaluateUpnpExistingLease(
    const UpnpExistingLeaseObservation& observation) noexcept;

enum class UpnpLeaseRequestKind : std::uint8_t {
    Finite = 0,
    Permanent = 1
};

enum class UpnpLeaseAttemptAction : std::uint8_t {
    AcceptFinite = 0,
    TryPermanent = 1,
    AcceptPermanent = 2,
    Fail = 3
};

UpnpLeaseAttemptAction EvaluateUpnpLeaseAttempt(
    UpnpLeaseRequestKind request,
    bool succeeded) noexcept;

} // namespace natmap
