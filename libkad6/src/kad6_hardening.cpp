// SPDX-License-Identifier: MIT
#include "kad6/kad6_hardening.h"

#include <algorithm>
#include <cmath>
#include <iomanip>
#include <limits>
#include <sstream>

namespace kad6 {
namespace {

constexpr std::size_t Count(K6Service) noexcept {
    return static_cast<std::size_t>(K6Service::Count);
}

struct FamilyDef {
    const char* name;
    const char* help;
    bool gauge;
    const char* key_a;
    const char* const* values_a;
    std::uint8_t count_a;
    const char* key_b;
    const char* const* values_b;
    std::uint8_t count_b;
    const char* key_c;
    const char* const* values_c;
    std::uint8_t count_c;
};

const char* const kNone[] = {""};
const char* const kCircuitStates[] = {"pending", "half_built", "built", "active", "destroyed"};
const char* const kHops[] = {"0", "1", "2", "3"};
const char* const kBuildResults[] = {"ok", "failed"};
const char* const kBuildReasons[] = {
    "success", "no_peer", "auth", "timeout", "diversity", "shaping", "internal"};
const char* const kServices[] = {"control", "exit_kad", "exit_ed2k_dial", "exit_ed2k_full"};
const char* const kProfiles[] = {"direct", "private", "strict"};
const char* const kSessionStates[] = {"pending", "active", "draining", "closed"};
const char* const kDirections[] = {"in", "out"};
const char* const kReasons[] = {
    "malformed", "auth", "policy", "rate_limit", "overloaded", "no_route",
    "timeout", "backpressure", "kill_switch", "other"};
const char* const kResources[] = {"bandwidth", "streams", "preauth", "publish", "cpu"};
const char* const kResults[] = {"ok", "rejected", "failed", "timeout"};
const char* const kSlotStates[] = {"free", "occupied"};
const char* const kCohortStates[] = {"pending", "active", "draining", "closed"};
const char* const kNetworks[] = {"kad2", "kad6"};
const char* const kPaddingClasses[] = {"0", "1", "2", "3", "4", "5", "6"};
const char* const kAuthStages[] = {"create", "extend", "frame", "ticket", "vep", "shaped"};
const char* const kSearchMilestones[] = {"first_source", "five_connectable"};
const char* const kLookupAlphas[] = {"3", "5", "8"};
const char* const kTransportKinds[] = {"goodput", "overhead"};

const FamilyDef kFamilies[] = {
    {"kad6_circuits", "Kad6 circuits in a fixed state and hop bucket", true,
     "state", kCircuitStates, 5, "hop_count", kHops, 4, nullptr, kNone, 1},
    {"kad6_build_total", "Completed Kad6 circuit build attempts", false,
     "result", kBuildResults, 2, "reason", kBuildReasons, 7, nullptr, kNone, 1},
    {"kad6_sessions", "Kad6 sessions by coarse service/profile/state", true,
     "service", kServices, 4, "profile", kProfiles, 3, "state", kSessionStates, 4},
    {"kad6_exit_bytes_total", "Bytes relayed by a Kad6 exit", false,
     "direction", kDirections, 2, "service", kServices, 4, nullptr, kNone, 1},
    {"kad6_exit_reject_total", "Kad6 exit admission rejections", false,
     "reason", kReasons, 10, nullptr, kNone, 1, nullptr, kNone, 1},
    {"kad6_exit_capacity_ratio", "Aggregated Kad6 exit capacity ratio", true,
     "service", kServices, 4, nullptr, kNone, 1, nullptr, kNone, 1},
    {"kad6_exit_utilization", "Aggregated Kad6 exit resource utilization", true,
     "resource", kResources, 5, "service", kServices, 4, nullptr, kNone, 1},
    {"kad6_exit_admission_total", "Kad6 exit admission outcomes", false,
     "service", kServices, 4, "result", kResults, 4, nullptr, kNone, 1},
    {"kad6_exit_preauth_slots", "Kad6 fixed pre-authentication slots", true,
     "state", kSlotStates, 2, nullptr, kNone, 1, nullptr, kNone, 1},
    {"kad6_exit_publish_qps", "Kad6 exit publish operations per second over a sealed window", true,
     "result", kResults, 4, nullptr, kNone, 1, nullptr, kNone, 1},
    {"kad6_exit_cohorts", "Kad6 source cohorts by coarse state", true,
     "state", kCohortStates, 4, nullptr, kNone, 1, nullptr, kNone, 1},
    {"kad6_search_total", "Kad6 search outcomes", false,
     "network", kNetworks, 2, "result", kResults, 4, nullptr, kNone, 1},
    {"kad6_publish_total", "Kad6 publish outcomes", false,
     "network", kNetworks, 2, "result", kResults, 4, nullptr, kNone, 1},
    {"kad6_padding_bytes_total", "Kad6 padding bytes by fixed shaping class", false,
     "class", kPaddingClasses, 7, nullptr, kNone, 1, nullptr, kNone, 1},
    {"kad6_auth_fail_total", "Kad6 authentication failures by fixed stage", false,
     "stage", kAuthStages, 6, nullptr, kNone, 1, nullptr, kNone, 1},
    {"kad6_downgrade_block_total", "Kad6 fail-closed downgrade blocks", false,
     "reason", kReasons, 10, nullptr, kNone, 1, nullptr, kNone, 1},
    {"kad6_legacy_proxy_total", "Kad6 legacy proxy outcomes", false,
     "direction", kDirections, 2, "result", kResults, 4, nullptr, kNone, 1},
    {"kad6_search_latency_ms", "Kad6 source discovery latency to a fixed milestone", true,
     "milestone", kSearchMilestones, 2, "network", kNetworks, 2, nullptr, kNone, 1},
    {"kad6_search_rpc_total", "Kad6 source lookup RPC outcomes by bounded alpha", false,
     "network", kNetworks, 2, "alpha", kLookupAlphas, 3, "result", kResults, 4},
    {"kad6_source_candidate_total", "Kad6 source candidate admission outcomes", false,
     "network", kNetworks, 2, "result", kResults, 4, nullptr, kNone, 1},
    {"kad6_source_dial_total", "Kad6 source dial outcomes", false,
     "network", kNetworks, 2, "result", kResults, 4, nullptr, kNone, 1},
    {"kad6_source_stale_total", "Kad6 stale source records rejected", false,
     "network", kNetworks, 2, nullptr, kNone, 1, nullptr, kNone, 1},
    {"kad6_circuit_build_ms", "Kad6 strict circuit build latency", true,
     "result", kBuildResults, 2, nullptr, kNone, 1, nullptr, kNone, 1},
    {"kad6_transport_bytes_total", "Kad6 transport goodput and protocol overhead", false,
     "kind", kTransportKinds, 2, "direction", kDirections, 2, nullptr, kNone, 1},
};

static_assert(sizeof(kFamilies) / sizeof(kFamilies[0]) ==
              static_cast<std::size_t>(K6MetricFamily::Count),
              "every metric family needs a fixed descriptor");

const FamilyDef* Definition(K6MetricFamily family) noexcept {
    const std::size_t index = static_cast<std::size_t>(family);
    return index < sizeof(kFamilies) / sizeof(kFamilies[0]) ? &kFamilies[index] : nullptr;
}

std::uint64_t SaturatingAdd(std::uint64_t a, std::uint64_t b) noexcept {
    return b > (std::numeric_limits<std::uint64_t>::max)() - a
        ? (std::numeric_limits<std::uint64_t>::max)() : a + b;
}

} // namespace

const char* K6ServiceName(K6Service service) noexcept {
    const std::size_t index = static_cast<std::size_t>(service);
    return index < 4 ? kServices[index] : "invalid";
}

const char* K6ServiceStateName(K6ServiceState state) noexcept {
    switch (state) {
    case K6ServiceState::Enabled: return "enabled";
    case K6ServiceState::Draining: return "draining";
    case K6ServiceState::Disabled: return "disabled";
    default: return "invalid";
    }
}

K6HardeningController::K6HardeningController() noexcept {
    state_.admission_mask = (1u << static_cast<std::uint8_t>(K6Service::Count)) - 1u;
    for (std::size_t i = 0; i < state_.services.size(); ++i) {
        state_.services[i].service = static_cast<K6Service>(i);
        state_.services[i].state = K6ServiceState::Enabled;
    }
}

bool K6HardeningController::Valid(K6Service service) noexcept {
    return static_cast<std::size_t>(service) < Count(service);
}

bool K6HardeningController::SetEnabled(K6Service service, bool enabled,
                                       std::uint64_t now_seconds,
                                       std::uint32_t drain_seconds,
                                       std::uint64_t active_sessions) noexcept {
    if (!Valid(service) || now_seconds == 0) return false;
    std::lock_guard<std::mutex> lock(mutex_);
    K6ServiceSnapshot& slot = state_.services[static_cast<std::size_t>(service)];
    const std::uint32_t bit = K6ServiceBit(service);
    if (enabled) {
        if (slot.state == K6ServiceState::Enabled) return true;
        slot.state = K6ServiceState::Enabled;
        slot.changed_at = now_seconds;
        slot.drain_deadline = 0;
        state_.admission_mask |= bit;
        ++state_.revision;
        return true;
    }

    state_.admission_mask &= ~bit; // admissions stop before any drain begins
    drain_seconds = (std::min)(drain_seconds, kK6MaxDrainSeconds);
    if (active_sessions == 0 || drain_seconds == 0) {
        if (slot.state == K6ServiceState::Disabled) return true;
        slot.state = K6ServiceState::Disabled;
        slot.changed_at = now_seconds;
        slot.drain_deadline = 0;
        ++state_.revision;
        return true;
    }

    const std::uint64_t requested = now_seconds + drain_seconds;
    if (slot.state == K6ServiceState::Draining) {
        if (slot.drain_deadline == 0 || requested < slot.drain_deadline) {
            slot.drain_deadline = requested; // a local stop may become stricter, never looser
            slot.changed_at = now_seconds;
            ++state_.revision;
        }
        return true;
    }
    slot.state = K6ServiceState::Draining;
    slot.changed_at = now_seconds;
    slot.drain_deadline = requested;
    ++state_.revision;
    return true;
}

K6DrainResult K6HardeningController::Tick(std::uint64_t now_seconds,
    const std::array<std::uint64_t, static_cast<std::size_t>(K6Service::Count)>& active) noexcept {
    K6DrainResult result;
    if (now_seconds == 0) return result;
    std::lock_guard<std::mutex> lock(mutex_);
    for (std::size_t i = 0; i < state_.services.size(); ++i) {
        K6ServiceSnapshot& slot = state_.services[i];
        if (slot.state != K6ServiceState::Draining) continue;
        const bool empty = active[i] == 0;
        const bool expired = slot.drain_deadline != 0 && now_seconds >= slot.drain_deadline;
        if (!empty && !expired) continue;
        const std::uint32_t bit = K6ServiceBit(static_cast<K6Service>(i));
        slot.state = K6ServiceState::Disabled;
        slot.changed_at = now_seconds;
        slot.drain_deadline = 0;
        result.completed_mask |= bit;
        if (!empty) result.force_close_mask |= bit;
        ++state_.revision;
    }
    return result;
}

bool K6HardeningController::CanAdmit(K6Service service) const noexcept {
    if (!Valid(service)) return false;
    std::lock_guard<std::mutex> lock(mutex_);
    return (state_.admission_mask & K6ServiceBit(service)) != 0;
}

K6HardeningSnapshot K6HardeningController::Snapshot() const noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    return state_;
}

K6Metrics::K6Metrics() noexcept = default;

std::size_t K6Metrics::Index(K6MetricFamily family, std::uint8_t a,
                             std::uint8_t b, std::uint8_t c) noexcept {
    return (((static_cast<std::size_t>(family) * kMaxA + a) * kMaxB + b) * kMaxC + c);
}

bool K6Metrics::ValidLabels(K6MetricFamily family, std::uint8_t a,
                            std::uint8_t b, std::uint8_t c) noexcept {
    const FamilyDef* def = Definition(family);
    return def && a < def->count_a && b < def->count_b && c < def->count_c;
}

void K6Metrics::RotateLocked(std::uint64_t now_seconds) noexcept {
    if (now_seconds == 0) return;
    const std::uint64_t aligned = now_seconds - now_seconds % kK6MetricsWindowSeconds;
    if (!active_initialized_) {
        active_initialized_ = true;
        active_start_ = aligned;
        return;
    }
    if (aligned < active_start_) {
        // A wall-clock rollback must not merge observations from unrelated
        // periods or publish a malformed window.
        active_.fill(Cell{});
        sealed_.fill(Cell{});
        active_start_ = aligned;
        sealed_start_ = sealed_end_ = 0;
        return;
    }
    if (aligned == active_start_) return;
    sealed_ = active_;
    sealed_start_ = active_start_;
    sealed_end_ = active_start_ + kK6MetricsWindowSeconds;
    active_.fill(Cell{});
    active_start_ = aligned;
}

bool K6Metrics::Add(K6MetricFamily family, std::uint8_t a,
                    std::uint8_t b, std::uint8_t c,
                    std::uint64_t amount, std::uint64_t now_seconds) noexcept {
    const FamilyDef* def = Definition(family);
    if (!def || def->gauge || !ValidLabels(family, a, b, c) || now_seconds == 0)
        return false;
    std::lock_guard<std::mutex> lock(mutex_);
    RotateLocked(now_seconds);
    Cell& cell = active_[Index(family, a, b, c)];
    cell.counter = SaturatingAdd(cell.counter, amount);
    cell.observations = SaturatingAdd(cell.observations, 1);
    return true;
}

bool K6Metrics::Observe(K6MetricFamily family, std::uint8_t a,
                        std::uint8_t b, std::uint8_t c,
                        double value, std::uint64_t now_seconds) noexcept {
    const FamilyDef* def = Definition(family);
    if (!def || !def->gauge || !ValidLabels(family, a, b, c) || now_seconds == 0 ||
        !std::isfinite(value) || value < 0.0)
        return false;
    std::lock_guard<std::mutex> lock(mutex_);
    RotateLocked(now_seconds);
    Cell& cell = active_[Index(family, a, b, c)];
    if (cell.gauge_sum > (std::numeric_limits<double>::max)() - value)
        return false;
    cell.gauge_sum += value;
    cell.observations = SaturatingAdd(cell.observations, 1);
    return true;
}

std::size_t K6Metrics::FixedSeriesCardinality() noexcept {
    std::size_t total = 0;
    for (const FamilyDef& def : kFamilies)
        total += static_cast<std::size_t>(def.count_a) * def.count_b * def.count_c;
    return total;
}

K6MetricsWindowInfo K6Metrics::InfoLocked() const noexcept {
    K6MetricsWindowInfo info;
    info.ready = sealed_end_ > sealed_start_;
    info.start = sealed_start_;
    info.end = sealed_end_;
    info.fixed_series = FixedSeriesCardinality();
    if (!info.ready) return info;
    for (std::size_t f = 0; f < kFamilyCount; ++f) {
        const FamilyDef& def = kFamilies[f];
        for (std::uint8_t a = 0; a < def.count_a; ++a)
            for (std::uint8_t b = 0; b < def.count_b; ++b)
                for (std::uint8_t c = 0; c < def.count_c; ++c)
                    if (sealed_[Index(static_cast<K6MetricFamily>(f), a, b, c)].observations >=
                        kK6MetricsMinPublicEvents)
                        ++info.exported_series;
    }
    return info;
}

K6MetricsWindowInfo K6Metrics::WindowInfo(std::uint64_t now_seconds) noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    RotateLocked(now_seconds);
    return InfoLocked();
}

std::string K6Metrics::ExportPrometheus(std::uint64_t now_seconds) {
    std::lock_guard<std::mutex> lock(mutex_);
    RotateLocked(now_seconds);
    const K6MetricsWindowInfo info = InfoLocked();
    std::ostringstream out;
    out << "# HELP kad6_metrics_window_ready Whether one complete private 15-minute window is available\n"
        << "# TYPE kad6_metrics_window_ready gauge\n"
        << "kad6_metrics_window_ready " << (info.ready ? 1 : 0) << '\n'
        << "# HELP kad6_metrics_fixed_series Fixed upper bound of the Kad6 metric registry\n"
        << "# TYPE kad6_metrics_fixed_series gauge\n"
        << "kad6_metrics_fixed_series " << info.fixed_series << '\n';
    if (info.ready) {
        out << "kad6_metrics_window_start_seconds " << info.start << '\n'
            << "kad6_metrics_window_end_seconds " << info.end << '\n';
    }
    for (std::size_t f = 0; f < kFamilyCount; ++f) {
        const FamilyDef& def = kFamilies[f];
        out << "# HELP " << def.name << ' ' << def.help << '\n'
            << "# TYPE " << def.name << (def.gauge ? " gauge\n" : " counter\n");
        if (!info.ready) continue;
        for (std::uint8_t a = 0; a < def.count_a; ++a) {
            for (std::uint8_t b = 0; b < def.count_b; ++b) {
                for (std::uint8_t c = 0; c < def.count_c; ++c) {
                    const Cell& cell = sealed_[Index(static_cast<K6MetricFamily>(f), a, b, c)];
                    if (cell.observations < kK6MetricsMinPublicEvents) continue;
                    out << def.name << '{' << def.key_a << "=\"" << def.values_a[a] << '"';
                    if (def.key_b)
                        out << ',' << def.key_b << "=\"" << def.values_b[b] << '"';
                    if (def.key_c)
                        out << ',' << def.key_c << "=\"" << def.values_c[c] << '"';
                    out << "} ";
                    if (def.gauge)
                        out << std::setprecision(12)
                            << cell.gauge_sum / static_cast<double>(cell.observations);
                    else
                        out << cell.counter;
                    out << '\n';
                }
            }
        }
    }
    return out.str();
}

} // namespace kad6
