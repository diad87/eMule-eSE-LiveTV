#pragma once

#include "natmap/natmap_types.h"

#include <cstdint>

namespace natmap {

PortIntent BuildAutomaticPortIntent(Transport transport,
                                    const Endpoint& local,
                                    std::uint32_t lifetime_seconds,
                                    std::uint32_t entropy) noexcept;

struct LeaseTiming {
    std::uint64_t acquired_monotonic_ms = 0;
    std::uint64_t renew_monotonic_ms = 0;
    std::uint64_t expires_monotonic_ms = 0;
};

// Drives application-level refresh attempts for a finite mapping lease.
// The first attempt is due at 45% of the granted lifetime. Failed attempts
// use a bounded exponential backoff, leaving the caller free to perform the
// actual network I/O on its own event loop.
class LeaseRefreshSchedule {
public:
    bool Activate(std::uint32_t lifetime_seconds,
                  std::uint64_t now_ms) noexcept;
    bool ShouldAttempt(std::uint64_t now_ms) const noexcept;
    bool IsExpired(std::uint64_t now_ms) const noexcept;
    void MarkAttempt(std::uint64_t now_ms) noexcept;
    void Clear() noexcept;

    bool IsFinite() const noexcept { return finite_; }
    std::uint64_t next_attempt_ms() const noexcept {
        return next_attempt_ms_;
    }
    const LeaseTiming& timing() const noexcept { return timing_; }
    std::uint32_t attempt_count() const noexcept { return attempt_count_; }

private:
    LeaseTiming timing_{};
    std::uint64_t next_attempt_ms_ = 0;
    std::uint32_t attempt_count_ = 0;
    bool finite_ = false;
};

// Permanent IGD mappings have no renewal deadline, but can disappear after a
// router reboot without any local interface/gateway change. Probe them at a
// low fixed cadence and retry failures with bounded backoff.
class PermanentMappingProbeSchedule {
public:
    void Activate(std::uint64_t now_ms) noexcept;
    bool ShouldAttempt(std::uint64_t now_ms) const noexcept;
    void MarkAttempt(std::uint64_t now_ms) noexcept;
    void Clear() noexcept;

    bool IsActive() const noexcept { return active_; }
    std::uint64_t next_attempt_ms() const noexcept {
        return next_attempt_ms_;
    }
    std::uint32_t attempt_count() const noexcept { return attempt_count_; }

private:
    std::uint64_t next_attempt_ms_ = 0;
    std::uint32_t attempt_count_ = 0;
    bool active_ = false;
};

// Owns lease timing and identity rules, but performs no network I/O.
class LeaseController {
public:
    bool Activate(const PortLease& lease, std::uint64_t now_ms) noexcept;
    bool AcceptRenewal(const PortLease& lease, std::uint64_t now_ms) noexcept;
    bool ShouldRenew(std::uint64_t now_ms) const noexcept;
    bool IsExpired(std::uint64_t now_ms) const noexcept;
    bool TakeOwnedForDeletion(std::uint64_t generation,
                              PortLease& lease) noexcept;

    bool HasLease() const noexcept { return has_lease_; }
    bool LastRenewalObservedEpochReset() const noexcept {
        return last_epoch_reset_;
    }
    const PortLease& lease() const noexcept { return lease_; }
    const LeaseTiming& timing() const noexcept { return timing_; }

private:
    static bool SameIdentity(const PortLease& left,
                             const PortLease& right) noexcept;
    static LeaseTiming Schedule(const PortLease& lease,
                                std::uint64_t now_ms) noexcept;

    PortLease lease_{};
    LeaseTiming timing_{};
    bool has_lease_ = false;
    bool last_epoch_reset_ = false;
};

} // namespace natmap
