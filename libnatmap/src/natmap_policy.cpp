#include "natmap/natmap_policy.h"

#include <limits>

namespace natmap {
namespace {

bool SameAddress(const IpAddress& left, const IpAddress& right) noexcept {
    return left.family == right.family && left.bytes == right.bytes;
}

bool SameEndpoint(const Endpoint& left, const Endpoint& right) noexcept {
    return left.port == right.port && SameAddress(left.address, right.address);
}

std::uint64_t SaturatingAdd(std::uint64_t left, std::uint64_t right) noexcept {
    const auto maximum = (std::numeric_limits<std::uint64_t>::max)();
    return right > maximum - left ? maximum : left + right;
}

void AddCandidate(PortIntent& intent, std::uint16_t candidate) noexcept {
    for (std::uint8_t i = 0; i < intent.candidate_count; ++i)
        if (intent.external_candidates[i] == candidate)
            return;
    if (intent.candidate_count < intent.external_candidates.size())
        intent.external_candidates[intent.candidate_count++] = candidate;
}

std::uint32_t NextRandom(std::uint32_t& value) noexcept {
    if (value == 0)
        value = 0xA341316Cu;
    value ^= value << 13;
    value ^= value >> 17;
    value ^= value << 5;
    return value;
}

LeaseTiming ScheduleLifetime(std::uint32_t lifetime_seconds,
                             std::uint64_t now_ms) noexcept {
    LeaseTiming timing{};
    timing.acquired_monotonic_ms = now_ms;
    if (lifetime_seconds == 0) {
        timing.renew_monotonic_ms =
            (std::numeric_limits<std::uint64_t>::max)();
        timing.expires_monotonic_ms = timing.renew_monotonic_ms;
        return timing;
    }

    const std::uint64_t lifetime_ms =
        static_cast<std::uint64_t>(lifetime_seconds) * 1000u;
    // Renew at 45%, leaving more than half the lease for bounded retries.
    timing.renew_monotonic_ms =
        SaturatingAdd(now_ms, lifetime_ms * 45u / 100u);
    timing.expires_monotonic_ms = SaturatingAdd(now_ms, lifetime_ms);
    return timing;
}

} // namespace

PortIntent BuildAutomaticPortIntent(Transport transport,
                                    const Endpoint& local,
                                    std::uint32_t lifetime_seconds,
                                    std::uint32_t entropy) noexcept {
    PortIntent intent{};
    intent.transport = transport;
    intent.local = local;
    intent.requested_lifetime_seconds = lifetime_seconds;
    intent.allow_any_external_port = true;
    if (!local.IsUsable())
        return intent;

    AddCandidate(intent, local.port);
    AddCandidate(intent, 0); // PCP/NAT-PMP/IGDv2 chooses a free port.
    for (int i = 0; i < 3; ++i) {
        const std::uint16_t high = static_cast<std::uint16_t>(
            49152u + (NextRandom(entropy) % (65536u - 49152u)));
        AddCandidate(intent, high);
    }
    AddCandidate(intent, 443);
    AddCandidate(intent, 80);
    return intent;
}

LeaseTiming LeaseController::Schedule(const PortLease& lease,
                                      std::uint64_t now_ms) noexcept {
    return ScheduleLifetime(lease.lifetime_seconds, now_ms);
}

bool LeaseRefreshSchedule::Activate(std::uint32_t lifetime_seconds,
                                    std::uint64_t now_ms) noexcept {
    timing_ = ScheduleLifetime(lifetime_seconds, now_ms);
    next_attempt_ms_ = timing_.renew_monotonic_ms;
    attempt_count_ = 0;
    finite_ = lifetime_seconds != 0;
    return finite_;
}

bool LeaseRefreshSchedule::ShouldAttempt(std::uint64_t now_ms) const noexcept {
    return finite_ && now_ms >= next_attempt_ms_ &&
           now_ms < timing_.expires_monotonic_ms;
}

bool LeaseRefreshSchedule::IsExpired(std::uint64_t now_ms) const noexcept {
    return finite_ && now_ms >= timing_.expires_monotonic_ms;
}

void LeaseRefreshSchedule::MarkAttempt(std::uint64_t now_ms) noexcept {
    if (!finite_)
        return;

    ++attempt_count_;
    // 30, 60, 120, 240, then 300 seconds. Clamp the shift so a long outage
    // cannot overflow or create a retry storm.
    const std::uint32_t shift = attempt_count_ > 4 ? 4 : attempt_count_ - 1;
    std::uint64_t delay_ms = 30000u << shift;
    if (delay_ms > 300000u)
        delay_ms = 300000u;
    next_attempt_ms_ = SaturatingAdd(now_ms, delay_ms);
    if (next_attempt_ms_ > timing_.expires_monotonic_ms)
        next_attempt_ms_ = timing_.expires_monotonic_ms;
}

void LeaseRefreshSchedule::Clear() noexcept {
    timing_ = LeaseTiming{};
    next_attempt_ms_ = 0;
    attempt_count_ = 0;
    finite_ = false;
}

void PermanentMappingProbeSchedule::Activate(std::uint64_t now_ms) noexcept {
    next_attempt_ms_ = SaturatingAdd(now_ms, 15u * 60u * 1000u);
    attempt_count_ = 0;
    active_ = true;
}

bool PermanentMappingProbeSchedule::ShouldAttempt(
    std::uint64_t now_ms) const noexcept {
    return active_ && now_ms >= next_attempt_ms_;
}

void PermanentMappingProbeSchedule::MarkAttempt(
    std::uint64_t now_ms) noexcept {
    if (!active_)
        return;
    ++attempt_count_;
    // 60, 120, 240, then at most 300 seconds while the router is absent.
    const std::uint32_t shift = attempt_count_ > 3 ? 3 : attempt_count_ - 1;
    std::uint64_t delay_ms = 60000u << shift;
    if (delay_ms > 300000u)
        delay_ms = 300000u;
    next_attempt_ms_ = SaturatingAdd(now_ms, delay_ms);
}

void PermanentMappingProbeSchedule::Clear() noexcept {
    next_attempt_ms_ = 0;
    attempt_count_ = 0;
    active_ = false;
}

bool LeaseController::SameIdentity(const PortLease& left,
                                   const PortLease& right) noexcept {
    return left.mapper == right.mapper && left.transport == right.transport &&
           left.generation == right.generation &&
           left.granted_external_port == right.granted_external_port &&
           SameEndpoint(left.local, right.local) &&
           SameEndpoint(left.public_endpoint, right.public_endpoint);
}

bool LeaseController::Activate(const PortLease& lease,
                               std::uint64_t now_ms) noexcept {
    if (!lease.IsStructurallyValid() || !lease.owned_by_us)
        return false;
    lease_ = lease;
    timing_ = Schedule(lease, now_ms);
    has_lease_ = true;
    last_epoch_reset_ = false;
    return true;
}

bool LeaseController::AcceptRenewal(const PortLease& lease,
                                    std::uint64_t now_ms) noexcept {
    if (!has_lease_ || !lease.IsStructurallyValid() || !lease.owned_by_us ||
        !SameIdentity(lease_, lease))
        return false;
    last_epoch_reset_ = lease_.mapper_epoch != 0 && lease.mapper_epoch != 0 &&
                        lease.mapper_epoch < lease_.mapper_epoch;
    lease_ = lease;
    timing_ = Schedule(lease, now_ms);
    return true;
}

bool LeaseController::ShouldRenew(std::uint64_t now_ms) const noexcept {
    return has_lease_ && now_ms >= timing_.renew_monotonic_ms &&
           now_ms < timing_.expires_monotonic_ms;
}

bool LeaseController::IsExpired(std::uint64_t now_ms) const noexcept {
    return has_lease_ && now_ms >= timing_.expires_monotonic_ms;
}

bool LeaseController::TakeOwnedForDeletion(std::uint64_t generation,
                                           PortLease& lease) noexcept {
    if (!has_lease_ || !lease_.owned_by_us || lease_.generation != generation)
        return false;
    lease = lease_;
    lease_ = PortLease{};
    timing_ = LeaseTiming{};
    has_lease_ = false;
    last_epoch_reset_ = false;
    return true;
}

} // namespace natmap
