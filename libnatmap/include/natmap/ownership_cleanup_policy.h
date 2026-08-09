#pragma once

#include "natmap/ownership_ledger.h"

#include <array>
#include <cstdint>

namespace natmap {

enum class OwnershipCleanupState : std::uint8_t {
    Blocked = 0,
    Ready = 1,
    Partial = 2,
    Complete = 3,
    RetryExhausted = 4,
};

struct OwnershipCleanupAuthorization {
    Transport transport = Transport::Tcp;
    OwnershipDecision decision = OwnershipDecision::InvalidRecord;
};

struct OwnershipCleanupSnapshot {
    OwnershipCleanupState state = OwnershipCleanupState::Blocked;
    std::array<std::uint8_t, 2> delete_attempts{};
    std::array<bool, 2> absent{};

    bool may_delete() const noexcept;
    bool may_clear_journal() const noexcept;
};

// All readbacks are completed before this gate. Any mismatch, duplicate
// protocol or incomplete pair produces Blocked and therefore zero deletes.
OwnershipCleanupSnapshot BeginOwnershipCleanup(
    const std::array<OwnershipCleanupAuthorization, 2>& authorizations)
    noexcept;

bool IsCoherentOwnershipPair(const OwnershipLedger& ledger) noexcept;

// One call represents DeletePortMapping followed by an exact absence probe.
// A failed/ambiguous probe remains retryable, bounded to two attempts per
// transport. The journal is clearable only after both mappings are absent.
bool RecordOwnershipCleanupAttempt(
    OwnershipCleanupSnapshot& snapshot,
    Transport transport,
    bool delete_succeeded,
    bool absence_verified) noexcept;

} // namespace natmap
