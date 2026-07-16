// SPDX-License-Identifier: MIT
//
// libkad6 — kad6_economy.h: the exit-supply economics of spec §20.7 as a pure,
// side-effect-free calculation module (ticket K6-8 support). No wire, no crypto,
// no state — just the saturation ratio rho and the supply-sufficiency gate, so
// the admission control and the "recommend STRICT?" decision are computed from
// ONE reviewed formula instead of ad-hoc arithmetic scattered across the host.
//
// This is the honest core of "criptografía no crea ancho de banda": with too few
// exits the correct behaviour is queue/reject fail-closed, never a silent
// downgrade to direct. These functions make "too few" a number, not a vibe.
#pragma once

#include "kad6/kad6_types.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace kad6 {

// Per-resource saturation inputs for ONE exit / service class (spec §20.7).
// bps = bits per second, USEFUL (already corrected for the exit's double I/O —
// one byte onion-side, one legacy-side — see K6-PERF-004). overhead_factor `o`
// is the measured protocol overhead multiplier, >= 1.
struct K6SaturationInputs {
    double   demanded_useful_bps   = 0.0;
    double   available_useful_bps  = 0.0;
    double   overhead_factor       = 1.0;   // o >= 1
    uint64_t active_streams        = 0;
    uint64_t available_stream_slots = 0;
    uint64_t occupied_preauth_slots = 0;
    uint64_t available_preauth_slots = 0;
    double   demanded_publish_qps  = 0.0;
    double   available_publish_qps = 0.0;
    double   measured_exit_cpu     = 0.0;
    double   exit_cpu_budget       = 0.0;
};

// Default admission target: begin rejecting new leases well before rho = 1
// (spec K6-ECON-001).
constexpr double kK6RhoTarget = 0.65;

// One resource's ratio demanded/available. A resource with zero capacity but
// non-zero demand is fully saturated (+inf); finite zero demand is 0. NaN,
// infinity, and negative measurements return +inf (fail-closed).
double K6ResourceRatio(double demanded, double available) noexcept;

// rho = max over {bw*o, streams, preauth, publish, cpu} (spec §20.7). The bw
// term multiplies demand by the overhead factor. Returns +inf if any resource
// has demand against zero capacity or any floating input is invalid; overhead
// must be finite and >= 1.
double K6Rho(const K6SaturationInputs& in) noexcept;

// Admission: true iff there is headroom to accept a new lease, i.e. the current
// rho is strictly below `target`. Fail-closed by construction — an exhausted or
// unmeasurable resource yields rho >= target => reject (spec K6-ECON-001).
bool K6AdmitLease(const K6SaturationInputs& in, double target = kK6RhoTarget) noexcept;

// ── supply-sufficiency gate (spec §20.7 E*c*eta >= N*r*o) ────────────────────
// r = mean useful bps demanded per active client; c = mean useful bps offered
// per exit in the limiting direction; o = overhead (>=1); eta = target
// utilization (default 0.65); N = active clients demanding the class.
struct K6SupplyInputs {
    double   r_bps = 0.0;
    double   c_bps = 0.0;
    double   overhead_factor = 1.0; // o
    double   eta = kK6RhoTarget;    // target utilization
    uint64_t clients = 0;           // N
};

// Minimum exits-per-client ratio E/N = (r*o)/(c*eta). Returns +inf if c is
// zero, eta is outside (0,1], overhead is below 1, or any input is non-finite
// or negative.
double K6MinExitRatio(const K6SupplyInputs& s) noexcept;

// Minimum whole exits needed to serve `clients` at the target utilization
// (ceil(N * E/N)). Returns UINT64_MAX if the ratio is not finite.
uint64_t K6MinExits(const K6SupplyInputs& s) noexcept;

// True iff `activeExits` meets or exceeds the minimum for `s`. With s.clients==0
// the demand is zero and any exit count (incl. 0) is sufficient.
bool K6SupplySufficient(uint64_t activeExits, const K6SupplyInputs& s) noexcept;

// True iff STRICT-of-transfer may be RECOMMENDED as default: supply must exceed
// demand with a headroom margin (spec K6-ECON-003 uses 35%). `marginFrac` is the
// required spare fraction (0.35 => need 35% more exits than the bare minimum).
bool K6MayRecommendStrict(uint64_t activeExits, const K6SupplyInputs& s,
                          double marginFrac = 0.35) noexcept;

// A 15-minute local aggregate. No identity, circuit, target, keyword or token
// enters this structure. Only a completed window is exposed for policy.
constexpr std::uint64_t kK6EconomyWindowSeconds = 15u * 60u;
constexpr std::size_t kK6EconomyServiceClasses = 4;
constexpr std::size_t kK6RhoHistogramBuckets = 21; // [0,.1), ... [1.9,2), >=2

struct K6EconomyWindowSnapshot {
    bool sealed = false;
    std::uint64_t starts_at = 0;
    std::uint64_t ends_at = 0;
    std::uint64_t samples = 0;
    std::uint64_t admission_attempts = 0;
    std::uint64_t admission_successes = 0;
    double admission_ratio = 0.0;
    double rho_p50 = 0.0;
    double rho_p95 = 0.0;
};

class K6EconomyTelemetry {
public:
    bool Observe(Byte service_class, std::uint64_t now_seconds, double rho,
                 bool admission_attempt, bool admitted) noexcept;
    void SealThrough(std::uint64_t now_seconds) noexcept;
    K6EconomyWindowSnapshot Latest(Byte service_class) const noexcept;
    void Reset() noexcept;
private:
    struct Counters {
        std::uint64_t samples = 0;
        std::uint64_t attempts = 0;
        std::uint64_t successes = 0;
        std::array<std::uint64_t, kK6RhoHistogramBuckets> rho{};
    };
    std::uint64_t current_start_ = 0;
    std::array<Counters, kK6EconomyServiceClasses> current_{};
    std::array<K6EconomyWindowSnapshot, kK6EconomyServiceClasses> latest_{};
    void SealCurrent() noexcept;
};

// Recommendation is a release decision, not an instantaneous local guess.
struct K6StrictReleaseEvidence {
    bool thirty_days_complete = false;
    bool top_five_loss_passed = false;
    bool external_quota_audit_passed = false;
};

bool K6MayRecommendStrictObserved(
    std::uint64_t active_exits, const K6SupplyInputs& supply,
    const K6EconomyWindowSnapshot& observed,
    const K6StrictReleaseEvidence& evidence,
    double margin_frac = 0.35, double min_admission_ratio = 0.95,
    std::uint64_t min_attempts = 20) noexcept;

// Two-level DRR: allocation first, then stream. Payload stays in the host; this
// scheduler grants byte budgets only and retains no sensitive traffic.
constexpr std::size_t kK6FairMaxAllocations = 512;
constexpr std::size_t kK6FairMaxStreams = 1024;
constexpr std::size_t kK6FairMaxStreamsPerAllocation = 64;
constexpr std::size_t kK6FairMaxAllocationsPerIssuer = 16;
constexpr std::uint64_t kK6FairDefaultQuantum = 16u * 1024u;
constexpr std::uint64_t kK6FairMaxQueuedBytes = 64ull * 1024ull * 1024ull;

struct K6FairGrant {
    std::uint64_t allocation_id = 0;
    std::uint64_t stream_id = 0;
    std::uint64_t bytes = 0;
};

class K6FairScheduler {
public:
    void Reset() noexcept;
    bool RegisterAllocation(std::uint64_t allocation_id, const Hash32& issuer,
                            std::uint64_t allocation_max_bytes,
                            std::uint64_t issuer_max_bytes,
                            std::uint16_t weight = 1) noexcept;
    bool RegisterStream(std::uint64_t allocation_id, std::uint64_t stream_id,
                        const Hash32& target, std::uint64_t stream_max_bytes,
                        std::uint64_t target_max_bytes,
                        std::uint64_t quantum = kK6FairDefaultQuantum) noexcept;
    bool Enqueue(std::uint64_t stream_id, std::uint64_t bytes) noexcept;
    std::size_t Poll(std::uint64_t max_bytes, std::size_t max_grants,
                     std::vector<K6FairGrant>& out);
    bool ReleaseStream(std::uint64_t stream_id) noexcept;
    bool ReleaseAllocation(std::uint64_t allocation_id) noexcept;
    std::uint64_t queued_bytes() const noexcept { return queued_bytes_; }
    std::size_t allocation_count() const noexcept;
    std::size_t stream_count() const noexcept;
private:
    struct Allocation {
        std::uint64_t id = 0;
        Hash32 issuer{};
        std::uint64_t max_bytes = 0;
        std::uint64_t issuer_max_bytes = 0;
        std::uint64_t used_bytes = 0;
        std::uint64_t deficit = 0;
        std::uint16_t weight = 1;
        std::size_t stream_cursor = 0;
        bool used = false;
    };
    struct Stream {
        std::uint64_t allocation_id = 0;
        std::uint64_t id = 0;
        Hash32 target{};
        std::uint64_t max_bytes = 0;
        std::uint64_t target_max_bytes = 0;
        std::uint64_t used_bytes = 0;
        std::uint64_t queued_bytes = 0;
        std::uint64_t deficit = 0;
        std::uint64_t quantum = kK6FairDefaultQuantum;
        bool used = false;
    };
    std::array<Allocation, kK6FairMaxAllocations> allocations_{};
    std::array<Stream, kK6FairMaxStreams> streams_{};
    std::size_t allocation_cursor_ = 0;
    std::uint64_t queued_bytes_ = 0;
};

} // namespace kad6
