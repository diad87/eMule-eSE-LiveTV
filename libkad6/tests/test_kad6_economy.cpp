// SPDX-License-Identifier: MIT
//
// test_kad6_economy.cpp — exit-supply economics (spec §20.7), ticket K6-8 support.
// Pure math: rho saturation, admission gate, and supply sufficiency (E/N).
//
//   from libkad6/:  make.bat test_kad6_economy tests\test_kad6_economy.cpp src\kad6_economy.cpp
#include "kad6/kad6_economy.h"

#include <cmath>
#include <cstdio>
#include <limits>

using namespace kad6;

static int g_fail = 0;
static int g_pass = 0;

#define CHECK(cond, msg) do { if (cond) { ++g_pass; } else { ++g_fail; \
    std::printf("  FAIL: %s  (%s:%d)\n", msg, __FILE__, __LINE__); } } while (0)

static bool approx(double a, double b) { return std::fabs(a - b) < 1e-9; }

static void test_resource_ratio() {
    CHECK(approx(K6ResourceRatio(0.0, 10.0), 0.0), "no demand -> 0");
    CHECK(approx(K6ResourceRatio(5.0, 10.0), 0.5), "half");
    CHECK(std::isinf(K6ResourceRatio(1.0, 0.0)), "demand vs zero cap -> inf");
    CHECK(approx(K6ResourceRatio(0.0, 0.0), 0.0), "no demand vs zero cap -> 0");
    const double nan = std::numeric_limits<double>::quiet_NaN();
    const double inf = std::numeric_limits<double>::infinity();
    CHECK(std::isinf(K6ResourceRatio(nan, 10.0)), "NaN demand -> inf fail-closed");
    CHECK(std::isinf(K6ResourceRatio(0.0, nan)), "NaN capacity -> inf fail-closed");
    CHECK(std::isinf(K6ResourceRatio(1.0, inf)), "infinite capacity measurement rejected");
    CHECK(std::isinf(K6ResourceRatio(-1.0, 10.0)), "negative demand rejected");
    CHECK(std::isinf(K6ResourceRatio(1.0, -10.0)), "negative capacity rejected");
}

static void test_rho_picks_max_with_overhead() {
    K6SaturationInputs in;
    in.demanded_useful_bps  = 6.5e6;
    in.available_useful_bps = 10.0e6;
    in.overhead_factor      = 1.0;
    in.active_streams       = 30;
    in.available_stream_slots = 64;   // 0.469
    in.occupied_preauth_slots = 100;
    in.available_preauth_slots = 512; // 0.195
    in.demanded_publish_qps = 5.0;
    in.available_publish_qps = 50.0;  // 0.1
    in.measured_exit_cpu    = 0.4;
    in.exit_cpu_budget      = 1.0;    // 0.4
    // bw term = 6.5e6/10e6 = 0.65 is the max.
    CHECK(approx(K6Rho(in), 0.65), "rho = max component (bw 0.65)");

    // Overhead multiplies bw demand: o=1.2 -> 0.78, now the max.
    in.overhead_factor = 1.2;
    CHECK(approx(K6Rho(in), 0.78), "overhead scales bw term");

    // A saturated resource (zero cap, non-zero demand) -> inf.
    in.available_stream_slots = 0;
    CHECK(std::isinf(K6Rho(in)), "zero-cap resource -> inf rho");

    K6SaturationInputs invalid;
    invalid.demanded_useful_bps = std::numeric_limits<double>::quiet_NaN();
    invalid.available_useful_bps = 10.0;
    CHECK(std::isinf(K6Rho(invalid)), "NaN saturation input -> inf rho");
    invalid = K6SaturationInputs{};
    invalid.overhead_factor = 0.99;
    CHECK(std::isinf(K6Rho(invalid)), "overhead below 1 -> inf rho");
    invalid.overhead_factor = std::numeric_limits<double>::infinity();
    CHECK(std::isinf(K6Rho(invalid)), "non-finite overhead -> inf rho");
}

static void test_admission_fail_closed() {
    K6SaturationInputs in;
    in.demanded_useful_bps = 6.4e6;
    in.available_useful_bps = 10.0e6;   // rho 0.64
    CHECK(K6AdmitLease(in), "0.64 < 0.65 target -> admit");

    in.demanded_useful_bps = 6.5e6;     // rho 0.65 == target
    CHECK(!K6AdmitLease(in), "at target -> reject (strict <)");

    in.demanded_useful_bps = 9.0e6;     // rho 0.9
    CHECK(!K6AdmitLease(in), "0.9 -> reject");

    // Unmeasurable resource (zero cap w/ demand) -> inf -> reject: fail-closed.
    K6SaturationInputs bad;
    bad.active_streams = 1; bad.available_stream_slots = 0;
    CHECK(!K6AdmitLease(bad), "inf rho -> reject (fail-closed)");

    // A non-positive target admits nothing.
    CHECK(!K6AdmitLease(in, 0.0), "target 0 admits nothing");
    CHECK(!K6AdmitLease(in, 1.01), "target above 1 rejected");
    CHECK(!K6AdmitLease(in, std::numeric_limits<double>::quiet_NaN()),
          "NaN target rejects fail-closed");
    CHECK(!K6AdmitLease(in, std::numeric_limits<double>::infinity()),
          "infinite target rejects fail-closed");
}

static void test_supply_gate_worked_example() {
    // Spec §20.7 illustrative: r=1 Mbit/s, c=10 Mbit/s, o=1.15, eta=0.65
    //   -> E/N = (1e6*1.15)/(10e6*0.65) = 0.17692...
    K6SupplyInputs s;
    s.r_bps = 1.0e6; s.c_bps = 10.0e6; s.overhead_factor = 1.15; s.eta = 0.65;
    CHECK(std::fabs(K6MinExitRatio(s) - 0.176923076923) < 1e-9, "E/N ~= 0.177");

    s.clients = 100;
    CHECK(K6MinExits(s) == 18, "N=100 -> ceil(17.69) = 18 exits");
    CHECK(!K6SupplySufficient(17, s), "17 exits insufficient");
    CHECK(K6SupplySufficient(18, s), "18 exits sufficient");

    // r=5 Mbit/s, same exit -> ratio ~0.885; a single client needs a whole exit.
    s.r_bps = 5.0e6; s.clients = 1;
    CHECK(K6MinExits(s) == 1, "5 Mbit/s client needs ~1 whole exit");

    // No demand => any exit count (incl. 0) suffices.
    K6SupplyInputs none; none.clients = 0; none.c_bps = 10e6;
    CHECK(K6MinExits(none) == 0, "no clients -> 0 exits");
    CHECK(K6SupplySufficient(0, none), "no clients -> 0 sufficient");
}

static void test_supply_unmeetable_and_strict_margin() {
    // c=0 => no per-exit capacity => unmeetable => not sufficient at any count.
    K6SupplyInputs s;
    s.r_bps = 1e6; s.c_bps = 0.0; s.eta = 0.65; s.clients = 10;
    CHECK(!std::isfinite(K6MinExitRatio(s)), "c=0 -> inf ratio");
    CHECK(K6MinExits(s) == std::numeric_limits<uint64_t>::max(), "c=0 -> UINT64_MAX");
    CHECK(!K6SupplySufficient(1000000, s), "unmeetable -> never sufficient");

    // STRICT recommendation needs 35% headroom over the bare minimum.
    K6SupplyInputs t;
    t.r_bps = 1.0e6; t.c_bps = 10.0e6; t.overhead_factor = 1.15; t.eta = 0.65;
    t.clients = 100;                              // bare min 18; +35% -> ceil(17.69*1.35)=ceil(23.88)=24
    CHECK(!K6MayRecommendStrict(18, t), "bare-min supply does NOT justify STRICT default");
    CHECK(!K6MayRecommendStrict(23, t), "23 < 24 margin -> no STRICT");
    CHECK(K6MayRecommendStrict(24, t), "24 exits (35% margin) -> STRICT ok");
    CHECK(!K6MayRecommendStrict(1000, t, -0.1), "negative headroom margin rejected");
    CHECK(!K6MayRecommendStrict(1000, t, std::numeric_limits<double>::quiet_NaN()),
          "NaN headroom margin rejected");

    K6SupplyInputs invalid = t;
    invalid.r_bps = std::numeric_limits<double>::quiet_NaN();
    CHECK(std::isinf(K6MinExitRatio(invalid)), "NaN client demand -> inf ratio");
    invalid = t; invalid.c_bps = -1.0;
    CHECK(std::isinf(K6MinExitRatio(invalid)), "negative exit capacity -> inf ratio");
    invalid = t; invalid.overhead_factor = 0.5;
    CHECK(std::isinf(K6MinExitRatio(invalid)), "supply overhead below 1 -> inf ratio");
    invalid = t; invalid.eta = 1.01;
    CHECK(std::isinf(K6MinExitRatio(invalid)), "eta above 1 -> inf ratio");
    // No demand -> trivially recommendable.
    K6SupplyInputs z; z.clients = 0;
    CHECK(K6MayRecommendStrict(0, z), "no demand -> STRICT trivially ok");
}

static void test_sealed_economy_telemetry() {
    K6EconomyTelemetry telemetry;
    for (int i = 0; i < 20; ++i)
        CHECK(telemetry.Observe(2, 901 + i, i < 10 ? 0.2 : 0.8,
              true, i < 19), "economy observation accepted");
    CHECK(!telemetry.Latest(2).sealed, "open window is not policy evidence");
    telemetry.SealThrough(1800);
    const K6EconomyWindowSnapshot sealed = telemetry.Latest(2);
    CHECK(sealed.sealed && sealed.starts_at == 900 && sealed.ends_at == 1800,
          "fifteen-minute window seals");
    CHECK(sealed.samples == 20 && sealed.admission_attempts == 20 &&
          sealed.admission_successes == 19, "sealed counters exact");
    CHECK(approx(sealed.admission_ratio, 0.95), "sealed admission ratio");
    CHECK(approx(sealed.rho_p50, 0.3) && approx(sealed.rho_p95, 0.9),
          "rho histogram p50/p95 use conservative upper bounds");
    CHECK(!telemetry.Observe(4, 1801, 0.1, false, false),
          "unknown service cannot increase cardinality");
    CHECK(!telemetry.Observe(1, 1801, std::numeric_limits<double>::infinity(),
          false, false), "invalid rho fails closed");

    K6SupplyInputs supply;
    supply.r_bps = 1e6; supply.c_bps = 10e6; supply.overhead_factor = 1.15;
    supply.clients = 100;
    K6StrictReleaseEvidence evidence;
    CHECK(!K6MayRecommendStrictObserved(24, supply, sealed, evidence),
          "local telemetry alone never flips release default");
    evidence.thirty_days_complete = true;
    evidence.top_five_loss_passed = true;
    evidence.external_quota_audit_passed = true;
    CHECK(K6MayRecommendStrictObserved(24, supply, sealed, evidence),
          "supply, p95 admission and independent evidence permit recommendation");
    K6EconomyWindowSnapshot low = sealed;
    low.admission_ratio = 0.949;
    CHECK(!K6MayRecommendStrictObserved(24, supply, low, evidence),
          "admission below 95 percent blocks recommendation");
}

static Hash32 economy_hash(Byte seed) {
    Hash32 out{};
    for (std::size_t i = 0; i < out.size(); ++i)
        out[i] = static_cast<Byte>(seed + i);
    return out;
}

static void test_two_level_fair_scheduler() {
    K6FairScheduler scheduler;
    const Hash32 issuer = economy_hash(1);
    const Hash32 target_a = economy_hash(40);
    const Hash32 target_b = economy_hash(80);
    CHECK(scheduler.RegisterAllocation(1, issuer, 64 * 1024, 128 * 1024),
          "allocation one registered");
    CHECK(scheduler.RegisterAllocation(2, issuer, 64 * 1024, 128 * 1024),
          "allocation two registered under issuer ceiling");
    CHECK(!scheduler.RegisterAllocation(1, issuer, 64 * 1024, 128 * 1024),
          "allocation id cannot be multiplied by circuit churn");
    CHECK(scheduler.RegisterStream(1, 11, target_a, 32 * 1024, 64 * 1024),
          "first allocation stream registered");
    CHECK(scheduler.RegisterStream(1, 12, target_b, 32 * 1024, 64 * 1024),
          "second stream under same allocation registered");
    CHECK(scheduler.RegisterStream(2, 21, target_a, 32 * 1024, 64 * 1024),
          "second allocation stream registered");
    CHECK(scheduler.Enqueue(11, 32 * 1024) && scheduler.Enqueue(12, 32 * 1024) &&
          scheduler.Enqueue(21, 32 * 1024), "bounded queues accept committed bytes");
    CHECK(!scheduler.Enqueue(11, 1), "stream byte ceiling includes queued bytes");
    CHECK(scheduler.queued_bytes() == 96 * 1024, "queued accounting exact");

    std::vector<K6FairGrant> grants;
    CHECK(scheduler.Poll(48 * 1024, 8, grants) == 3,
          "DRR grants requested byte budget");
    CHECK(grants.size() == 3 && grants[0].allocation_id == 1 &&
          grants[1].allocation_id == 2 && grants[2].allocation_id == 1,
          "outer DRR alternates allocations before inner streams");
    CHECK(grants[0].stream_id != grants[2].stream_id,
          "inner DRR alternates streams within allocation");
    CHECK(scheduler.queued_bytes() == 48 * 1024, "grant decrements queue exactly");
    CHECK(scheduler.ReleaseStream(11), "stream release succeeds");
    CHECK(scheduler.ReleaseAllocation(2), "allocation release drops its streams");
    CHECK(scheduler.allocation_count() == 1 && scheduler.stream_count() == 1,
          "release leaves bounded state consistent");
    scheduler.Reset();
    CHECK(scheduler.queued_bytes() == 0 && scheduler.allocation_count() == 0 &&
          scheduler.stream_count() == 0, "scheduler reset clears accounting");
}

int main() {
    test_resource_ratio();
    test_rho_picks_max_with_overhead();
    test_admission_fail_closed();
    test_supply_gate_worked_example();
    test_supply_unmeetable_and_strict_margin();
    test_sealed_economy_telemetry();
    test_two_level_fair_scheduler();

    std::printf("test_kad6_economy: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
