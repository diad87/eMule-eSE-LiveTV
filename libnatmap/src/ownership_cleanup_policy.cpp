#include "natmap/ownership_cleanup_policy.h"

namespace natmap {
namespace {
int Index(Transport transport) noexcept {
    if (transport == Transport::Tcp) return 0;
    if (transport == Transport::Udp) return 1;
    return -1;
}
}

bool OwnershipCleanupSnapshot::may_delete() const noexcept {
    return state == OwnershipCleanupState::Ready ||
           state == OwnershipCleanupState::Partial;
}

bool OwnershipCleanupSnapshot::may_clear_journal() const noexcept {
    return state == OwnershipCleanupState::Complete && absent[0] && absent[1];
}

OwnershipCleanupSnapshot BeginOwnershipCleanup(
    const std::array<OwnershipCleanupAuthorization, 2>& authorizations)
    noexcept {
    OwnershipCleanupSnapshot snapshot{};
    bool tcp = false;
    bool udp = false;
    for (const OwnershipCleanupAuthorization& authorization : authorizations) {
        if (authorization.decision != OwnershipDecision::Owned)
            return snapshot;
        const int index = Index(authorization.transport);
        if (index < 0 || (index == 0 ? tcp : udp))
            return snapshot;
        if (index == 0) tcp = true; else udp = true;
    }
    if (tcp && udp)
        snapshot.state = OwnershipCleanupState::Ready;
    return snapshot;
}

bool IsCoherentOwnershipPair(const OwnershipLedger& ledger) noexcept {
    if (ledger.count != 2 || !ledger.IsStructurallyValid())
        return false;
    const UpnpOwnershipRecord* tcp = nullptr;
    const UpnpOwnershipRecord* udp = nullptr;
    for (std::uint8_t i = 0; i < ledger.count; ++i) {
        const UpnpOwnershipRecord& record = ledger.records[i];
        if (record.transport == Transport::Tcp) {
            if (tcp != nullptr) return false;
            tcp = &record;
        } else if (record.transport == Transport::Udp) {
            if (udp != nullptr) return false;
            udp = &record;
        } else return false;
    }
    return tcp != nullptr && udp != nullptr &&
        tcp->owner_token == udp->owner_token &&
        tcp->gateway_fingerprint == udp->gateway_fingerprint &&
        tcp->generation == udp->generation &&
        tcp->local_address.family == udp->local_address.family &&
        tcp->local_address.bytes == udp->local_address.bytes;
}

bool RecordOwnershipCleanupAttempt(
    OwnershipCleanupSnapshot& snapshot,
    Transport transport,
    bool delete_succeeded,
    bool absence_verified) noexcept {
    const int index = Index(transport);
    if (!snapshot.may_delete() || index < 0 || snapshot.absent[index] ||
        snapshot.delete_attempts[index] >= 2)
        return false;
    ++snapshot.delete_attempts[index];
    // 714/absence is authoritative even if DeletePortMapping raced and did
    // not report success. No other failure is promoted to absence.
    snapshot.absent[index] = absence_verified;
    if (snapshot.absent[0] && snapshot.absent[1]) {
        snapshot.state = OwnershipCleanupState::Complete;
        return true;
    }
    const bool tcp_exhausted = snapshot.absent[0] ||
        snapshot.delete_attempts[0] >= 2;
    const bool udp_exhausted = snapshot.absent[1] ||
        snapshot.delete_attempts[1] >= 2;
    snapshot.state = tcp_exhausted && udp_exhausted
        ? OwnershipCleanupState::RetryExhausted
        : OwnershipCleanupState::Partial;
    (void)delete_succeeded;
    return true;
}

} // namespace natmap
