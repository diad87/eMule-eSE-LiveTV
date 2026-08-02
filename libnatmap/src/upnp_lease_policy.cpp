#include "natmap/upnp_lease_policy.h"

namespace natmap {

UpnpExistingLeaseAction EvaluateUpnpExistingLease(
    const UpnpExistingLeaseObservation& observation) noexcept {
    if (!observation.query_succeeded || !observation.target_matches)
        return UpnpExistingLeaseAction::Create;

    if (observation.refresh &&
        observation.ownership_matches &&
        observation.remaining_lifetime_seconds != 0)
        return UpnpExistingLeaseAction::RenewFinite;

    return UpnpExistingLeaseAction::Reuse;
}

UpnpLeaseAttemptAction EvaluateUpnpLeaseAttempt(
    UpnpLeaseRequestKind request,
    bool succeeded) noexcept {
    switch (request) {
    case UpnpLeaseRequestKind::Finite:
        return succeeded
            ? UpnpLeaseAttemptAction::AcceptFinite
            : UpnpLeaseAttemptAction::TryPermanent;
    case UpnpLeaseRequestKind::Permanent:
        return succeeded
            ? UpnpLeaseAttemptAction::AcceptPermanent
            : UpnpLeaseAttemptAction::Fail;
    default:
        return UpnpLeaseAttemptAction::Fail;
    }
}

} // namespace natmap
