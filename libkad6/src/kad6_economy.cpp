// SPDX-License-Identifier: MIT
//
// libkad6 — kad6_economy.cpp: exit-supply economics (spec §20.7). Pure math.
#include "kad6/kad6_economy.h"

#include <algorithm>
#include <cmath>
#include <limits>

namespace kad6 {

static const double kInf = std::numeric_limits<double>::infinity();

double K6ResourceRatio(double demanded, double available) noexcept {
    if (!std::isfinite(demanded) || !std::isfinite(available) ||
        demanded < 0.0 || available < 0.0)
        return kInf;                  // invalid/unmeasurable input is fail-closed
    if (demanded == 0.0)
        return 0.0;
    if (available == 0.0)
        return kInf;
    return demanded / available;
}

double K6Rho(const K6SaturationInputs& in) noexcept {
    if (!std::isfinite(in.overhead_factor) || in.overhead_factor < 1.0)
        return kInf;
    const double o = in.overhead_factor;
    double rho = 0.0;
    const double terms[5] = {
        K6ResourceRatio(in.demanded_useful_bps * o, in.available_useful_bps),
        K6ResourceRatio(static_cast<double>(in.active_streams),
                        static_cast<double>(in.available_stream_slots)),
        K6ResourceRatio(static_cast<double>(in.occupied_preauth_slots),
                        static_cast<double>(in.available_preauth_slots)),
        K6ResourceRatio(in.demanded_publish_qps, in.available_publish_qps),
        K6ResourceRatio(in.measured_exit_cpu, in.exit_cpu_budget),
    };
    for (double t : terms)
        if (t > rho) rho = t;
    return rho;
}

bool K6AdmitLease(const K6SaturationInputs& in, double target) noexcept {
    if (!std::isfinite(target) || target <= 0.0 || target > 1.0)
        return false;                 // invalid utilization target admits nothing
    return K6Rho(in) < target;
}

double K6MinExitRatio(const K6SupplyInputs& s) noexcept {
    if (!std::isfinite(s.r_bps) || !std::isfinite(s.c_bps) ||
        !std::isfinite(s.overhead_factor) || !std::isfinite(s.eta) ||
        s.r_bps < 0.0 || s.c_bps < 0.0 || s.overhead_factor < 1.0 ||
        s.eta <= 0.0 || s.eta > 1.0)
        return kInf;                  // invalid/unmeasurable supply is fail-closed
    const double o = s.overhead_factor;
    if (s.c_bps == 0.0)
        return kInf;                  // no per-exit capacity => no finite count suffices
    if (s.r_bps == 0.0)
        return 0.0;                   // no demand per client
    const double ratio = (s.r_bps * o) / (s.c_bps * s.eta);
    return std::isfinite(ratio) ? ratio : kInf;
}

uint64_t K6MinExits(const K6SupplyInputs& s) noexcept {
    if (s.clients == 0)
        return 0;
    const double ratio = K6MinExitRatio(s);
    if (!std::isfinite(ratio))
        return UINT64_MAX;
    const double need = std::ceil(static_cast<double>(s.clients) * ratio);
    if (need >= static_cast<double>(UINT64_MAX))
        return UINT64_MAX;
    return static_cast<uint64_t>(need);
}

bool K6SupplySufficient(uint64_t activeExits, const K6SupplyInputs& s) noexcept {
    const uint64_t need = K6MinExits(s);
    if (need == UINT64_MAX)
        return false;                 // unmeetable demand
    return activeExits >= need;
}

bool K6MayRecommendStrict(uint64_t activeExits, const K6SupplyInputs& s,
                          double marginFrac) noexcept {
    if (!std::isfinite(marginFrac) || marginFrac < 0.0)
        return false;
    if (s.clients == 0)
        return true;                  // no demand => trivially fine
    const double ratio = K6MinExitRatio(s);
    if (!std::isfinite(ratio))
        return false;
    const double need = std::ceil(static_cast<double>(s.clients) * ratio *
                                  (1.0 + marginFrac));
    if (!std::isfinite(need) || need >= static_cast<double>(UINT64_MAX))
        return false;
    return static_cast<double>(activeExits) >= need;
}

namespace {

bool AnyHash(const Hash32& value) noexcept {
    Byte any = 0;
    for (Byte byte : value) any = static_cast<Byte>(any | byte);
    return any != 0;
}

double HistogramPercentile(
    const std::array<std::uint64_t, kK6RhoHistogramBuckets>& histogram,
    std::uint64_t count, double percentile) noexcept {
    if (count == 0) return 0.0;
    const std::uint64_t rank = static_cast<std::uint64_t>(
        std::ceil(static_cast<double>(count) * percentile));
    std::uint64_t cumulative = 0;
    for (std::size_t i = 0; i < histogram.size(); ++i) {
        cumulative += histogram[i];
        if (cumulative >= rank)
            return i + 1 == histogram.size() ? 2.0 :
                static_cast<double>(i + 1) / 10.0;
    }
    return 2.0;
}

std::uint64_t SaturatingAdd(std::uint64_t a, std::uint64_t b) noexcept {
    return b > UINT64_MAX - a ? UINT64_MAX : a + b;
}

} // namespace

void K6EconomyTelemetry::Reset() noexcept {
    current_start_ = 0;
    current_ = {};
    latest_ = {};
}

void K6EconomyTelemetry::SealCurrent() noexcept {
    if (current_start_ == 0) return;
    for (std::size_t service = 0; service < current_.size(); ++service) {
        const Counters& source = current_[service];
        K6EconomyWindowSnapshot snapshot;
        snapshot.sealed = true;
        snapshot.starts_at = current_start_;
        snapshot.ends_at = current_start_ + kK6EconomyWindowSeconds;
        snapshot.samples = source.samples;
        snapshot.admission_attempts = source.attempts;
        snapshot.admission_successes = source.successes;
        snapshot.admission_ratio = source.attempts == 0 ? 0.0 :
            static_cast<double>(source.successes) / static_cast<double>(source.attempts);
        snapshot.rho_p50 = HistogramPercentile(source.rho, source.samples, 0.50);
        snapshot.rho_p95 = HistogramPercentile(source.rho, source.samples, 0.95);
        latest_[service] = snapshot;
    }
    current_ = {};
}

void K6EconomyTelemetry::SealThrough(std::uint64_t now_seconds) noexcept {
    if (current_start_ == 0 || now_seconds < current_start_ + kK6EconomyWindowSeconds)
        return;
    SealCurrent();
    current_start_ = (now_seconds / kK6EconomyWindowSeconds) * kK6EconomyWindowSeconds;
}

bool K6EconomyTelemetry::Observe(Byte service_class, std::uint64_t now_seconds,
                                 double rho, bool admission_attempt,
                                 bool admitted) noexcept {
    if (service_class >= kK6EconomyServiceClasses || now_seconds == 0 ||
        !std::isfinite(rho) || rho < 0.0 || (admitted && !admission_attempt))
        return false;
    const std::uint64_t window =
        (now_seconds / kK6EconomyWindowSeconds) * kK6EconomyWindowSeconds;
    if (window == 0) return false;
    if (current_start_ == 0) current_start_ = window;
    if (window < current_start_) return false;
    if (window > current_start_) {
        SealCurrent();
        current_start_ = window;
    }
    Counters& counters = current_[service_class];
    ++counters.samples;
    if (admission_attempt) {
        ++counters.attempts;
        if (admitted) ++counters.successes;
    }
    const std::size_t bucket = rho >= 2.0 ? kK6RhoHistogramBuckets - 1 :
        static_cast<std::size_t>(rho * 10.0);
    ++counters.rho[bucket];
    return true;
}

K6EconomyWindowSnapshot K6EconomyTelemetry::Latest(Byte service_class) const noexcept {
    return service_class < latest_.size() ? latest_[service_class] :
        K6EconomyWindowSnapshot{};
}

bool K6MayRecommendStrictObserved(
    std::uint64_t active_exits, const K6SupplyInputs& supply,
    const K6EconomyWindowSnapshot& observed,
    const K6StrictReleaseEvidence& evidence, double margin_frac,
    double min_admission_ratio, std::uint64_t min_attempts) noexcept {
    if (!evidence.thirty_days_complete || !evidence.top_five_loss_passed ||
        !evidence.external_quota_audit_passed || !observed.sealed ||
        observed.admission_attempts < min_attempts ||
        !std::isfinite(min_admission_ratio) || min_admission_ratio < 0.0 ||
        min_admission_ratio > 1.0 ||
        !std::isfinite(observed.admission_ratio) ||
        observed.admission_ratio < min_admission_ratio)
        return false;
    return K6MayRecommendStrict(active_exits, supply, margin_frac);
}

void K6FairScheduler::Reset() noexcept {
    allocations_ = {};
    streams_ = {};
    allocation_cursor_ = 0;
    queued_bytes_ = 0;
}

bool K6FairScheduler::RegisterAllocation(
    std::uint64_t allocation_id, const Hash32& issuer,
    std::uint64_t allocation_max_bytes, std::uint64_t issuer_max_bytes,
    std::uint16_t weight) noexcept {
    if (allocation_id == 0 || !AnyHash(issuer) || allocation_max_bytes == 0 ||
        issuer_max_bytes < allocation_max_bytes || weight == 0 || weight > 16)
        return false;
    std::size_t issuer_count = 0;
    Allocation* free_slot = nullptr;
    for (Allocation& allocation : allocations_) {
        if (allocation.used && allocation.id == allocation_id) return false;
        if (allocation.used && allocation.issuer == issuer) ++issuer_count;
        if (!allocation.used && !free_slot) free_slot = &allocation;
    }
    if (!free_slot || issuer_count >= kK6FairMaxAllocationsPerIssuer) return false;
    free_slot->id = allocation_id;
    free_slot->issuer = issuer;
    free_slot->max_bytes = allocation_max_bytes;
    free_slot->issuer_max_bytes = issuer_max_bytes;
    free_slot->weight = weight;
    free_slot->used = true;
    return true;
}

bool K6FairScheduler::RegisterStream(
    std::uint64_t allocation_id, std::uint64_t stream_id, const Hash32& target,
    std::uint64_t stream_max_bytes, std::uint64_t target_max_bytes,
    std::uint64_t quantum) noexcept {
    if (allocation_id == 0 || stream_id == 0 || !AnyHash(target) ||
        stream_max_bytes == 0 || target_max_bytes < stream_max_bytes ||
        quantum == 0 || quantum > 1024ull * 1024ull)
        return false;
    bool allocation_found = false;
    std::size_t allocation_streams = 0;
    Stream* free_slot = nullptr;
    for (const Allocation& allocation : allocations_)
        if (allocation.used && allocation.id == allocation_id) allocation_found = true;
    for (Stream& stream : streams_) {
        if (stream.used && stream.id == stream_id) return false;
        if (stream.used && stream.allocation_id == allocation_id) ++allocation_streams;
        if (!stream.used && !free_slot) free_slot = &stream;
    }
    if (!allocation_found || !free_slot ||
        allocation_streams >= kK6FairMaxStreamsPerAllocation) return false;
    free_slot->allocation_id = allocation_id;
    free_slot->id = stream_id;
    free_slot->target = target;
    free_slot->max_bytes = stream_max_bytes;
    free_slot->target_max_bytes = target_max_bytes;
    free_slot->quantum = quantum;
    free_slot->used = true;
    return true;
}

bool K6FairScheduler::Enqueue(std::uint64_t stream_id, std::uint64_t bytes) noexcept {
    if (stream_id == 0 || bytes == 0 || bytes > kK6FairMaxQueuedBytes ||
        bytes > kK6FairMaxQueuedBytes - queued_bytes_)
        return false;
    Stream* selected = nullptr;
    Allocation* allocation = nullptr;
    for (Stream& stream : streams_)
        if (stream.used && stream.id == stream_id) { selected = &stream; break; }
    if (!selected) return false;
    for (Allocation& candidate : allocations_)
        if (candidate.used && candidate.id == selected->allocation_id) {
            allocation = &candidate; break;
        }
    if (!allocation) return false;

    std::uint64_t allocation_committed = allocation->used_bytes;
    std::uint64_t issuer_committed = 0;
    std::uint64_t target_committed = 0;
    for (const Allocation& candidate : allocations_)
        if (candidate.used && candidate.issuer == allocation->issuer)
            issuer_committed = SaturatingAdd(issuer_committed, candidate.used_bytes);
    for (const Stream& stream : streams_) if (stream.used) {
        if (stream.allocation_id == allocation->id)
            allocation_committed = SaturatingAdd(allocation_committed, stream.queued_bytes);
        const Allocation* owner = nullptr;
        for (const Allocation& candidate : allocations_)
            if (candidate.used && candidate.id == stream.allocation_id) {
                owner = &candidate; break;
            }
        if (owner && owner->issuer == allocation->issuer)
            issuer_committed = SaturatingAdd(issuer_committed, stream.queued_bytes);
        if (stream.target == selected->target)
            target_committed = SaturatingAdd(target_committed,
                SaturatingAdd(stream.used_bytes, stream.queued_bytes));
    }
    const std::uint64_t stream_committed =
        SaturatingAdd(selected->used_bytes, selected->queued_bytes);
    if (stream_committed > selected->max_bytes || bytes > selected->max_bytes - stream_committed ||
        allocation_committed > allocation->max_bytes ||
        bytes > allocation->max_bytes - allocation_committed ||
        issuer_committed > allocation->issuer_max_bytes ||
        bytes > allocation->issuer_max_bytes - issuer_committed ||
        target_committed > selected->target_max_bytes ||
        bytes > selected->target_max_bytes - target_committed)
        return false;
    selected->queued_bytes += bytes;
    queued_bytes_ += bytes;
    return true;
}

std::size_t K6FairScheduler::Poll(std::uint64_t max_bytes,
                                  std::size_t max_grants,
                                  std::vector<K6FairGrant>& out) {
    out.clear();
    if (max_bytes == 0 || max_grants == 0 || queued_bytes_ == 0) return 0;
    std::uint64_t remaining = max_bytes;
    std::size_t empty_visits = 0;
    const std::size_t visit_limit = allocations_.size() * 2;
    while (remaining != 0 && out.size() < max_grants && queued_bytes_ != 0 &&
           empty_visits < visit_limit) {
        Allocation& allocation = allocations_[allocation_cursor_++ % allocations_.size()];
        if (!allocation.used) { ++empty_visits; continue; }
        bool has_queued = false;
        for (const Stream& stream : streams_)
            if (stream.used && stream.allocation_id == allocation.id && stream.queued_bytes != 0) {
                has_queued = true; break;
            }
        if (!has_queued) { allocation.deficit = 0; ++empty_visits; continue; }
        allocation.deficit = SaturatingAdd(allocation.deficit,
            kK6FairDefaultQuantum * allocation.weight);

        bool granted = false;
        for (std::size_t visited = 0; visited < streams_.size(); ++visited) {
            Stream& stream = streams_[allocation.stream_cursor++ % streams_.size()];
            if (!stream.used || stream.allocation_id != allocation.id ||
                stream.queued_bytes == 0) continue;
            stream.deficit = SaturatingAdd(stream.deficit, stream.quantum);
            const std::uint64_t bytes = (std::min)({stream.queued_bytes,
                stream.deficit, allocation.deficit, remaining});
            if (bytes == 0) continue;
            K6FairGrant grant;
            grant.allocation_id = allocation.id;
            grant.stream_id = stream.id;
            grant.bytes = bytes;
            out.push_back(grant);
            stream.queued_bytes -= bytes;
            stream.used_bytes += bytes;
            stream.deficit -= bytes;
            allocation.used_bytes += bytes;
            allocation.deficit -= bytes;
            queued_bytes_ -= bytes;
            remaining -= bytes;
            granted = true;
            break;
        }
        if (granted) empty_visits = 0;
        else ++empty_visits;
    }
    return out.size();
}

bool K6FairScheduler::ReleaseStream(std::uint64_t stream_id) noexcept {
    for (Stream& stream : streams_) if (stream.used && stream.id == stream_id) {
        queued_bytes_ -= stream.queued_bytes;
        stream = Stream{};
        return true;
    }
    return false;
}

bool K6FairScheduler::ReleaseAllocation(std::uint64_t allocation_id) noexcept {
    Allocation* allocation = nullptr;
    for (Allocation& candidate : allocations_)
        if (candidate.used && candidate.id == allocation_id) { allocation = &candidate; break; }
    if (!allocation) return false;
    for (Stream& stream : streams_)
        if (stream.used && stream.allocation_id == allocation_id) {
            queued_bytes_ -= stream.queued_bytes;
            stream = Stream{};
        }
    *allocation = Allocation{};
    return true;
}

std::size_t K6FairScheduler::allocation_count() const noexcept {
    std::size_t count = 0;
    for (const Allocation& allocation : allocations_) if (allocation.used) ++count;
    return count;
}

std::size_t K6FairScheduler::stream_count() const noexcept {
    std::size_t count = 0;
    for (const Stream& stream : streams_) if (stream.used) ++count;
    return count;
}

} // namespace kad6
