// SPDX-License-Identifier: MIT
#include "kad6/kad6_hardening.h"

#include <array>
#include <cstdio>
#include <string>

using namespace kad6;

static int g_pass = 0;
static int g_fail = 0;
#define CHECK(c, m) do { if (c) ++g_pass; else { ++g_fail; \
    std::printf("  FAIL: %s (%s:%d)\n", m, __FILE__, __LINE__); } } while (0)

static void TestKillSwitchDrain() {
    K6HardeningController control;
    CHECK(control.CanAdmit(K6Service::ExitEd2kFull), "FULL enabled by default");
    CHECK(control.SetEnabled(K6Service::ExitEd2kFull, false, 1000, 300, 2),
          "local FULL stop accepted");
    CHECK(!control.CanAdmit(K6Service::ExitEd2kFull), "new FULL admissions stop immediately");
    K6HardeningSnapshot snap = control.Snapshot();
    const auto i = static_cast<std::size_t>(K6Service::ExitEd2kFull);
    CHECK(snap.services[i].state == K6ServiceState::Draining, "active FULL sessions drain");
    CHECK(snap.services[i].drain_deadline == 1300, "drain deadline fixed");

    // Repeating a stop cannot accidentally extend the exposure window.
    CHECK(control.SetEnabled(K6Service::ExitEd2kFull, false, 1050, 600, 2),
          "repeated stop idempotent");
    CHECK(control.Snapshot().services[i].drain_deadline == 1300, "drain never extended");
    CHECK(control.SetEnabled(K6Service::ExitEd2kFull, false, 1100, 30, 2),
          "stricter stop accepted");
    CHECK(control.Snapshot().services[i].drain_deadline == 1130, "drain may be shortened");

    std::array<std::uint64_t, 4> active{{0, 0, 0, 2}};
    K6DrainResult tick = control.Tick(1129, active);
    CHECK(tick.force_close_mask == 0, "no premature stream close");
    tick = control.Tick(1130, active);
    CHECK((tick.force_close_mask & K6ServiceBit(K6Service::ExitEd2kFull)) != 0,
          "deadline requests explicit stream close");
    CHECK(control.Snapshot().services[i].state == K6ServiceState::Disabled,
          "FULL disabled after deadline");
    CHECK(control.SetEnabled(K6Service::ExitEd2kFull, true, 1200, 0, 0),
          "local operator can re-enable");
    CHECK(control.CanAdmit(K6Service::ExitEd2kFull), "FULL admissions restored");
}

static void TestNaturalDrainAndImmediateStop() {
    K6HardeningController control;
    CHECK(control.SetEnabled(K6Service::ExitEd2kDial, false, 2000, 60, 1),
          "DIAL enters drain");
    std::array<std::uint64_t, 4> active{{0, 0, 0, 0}};
    K6DrainResult tick = control.Tick(2001, active);
    CHECK((tick.completed_mask & K6ServiceBit(K6Service::ExitEd2kDial)) != 0,
          "empty service finishes before deadline");
    CHECK(tick.force_close_mask == 0, "natural drain closes nothing");
    CHECK(control.SetEnabled(K6Service::ExitKad, false, 2100, 0, 99),
          "zero-second emergency stop accepted");
    CHECK(control.Snapshot().services[1].state == K6ServiceState::Disabled,
          "emergency stop is immediate despite active leases");
    CHECK(!control.SetEnabled(static_cast<K6Service>(99), false, 2100, 0, 0),
          "unknown service rejected");
    CHECK(!control.SetEnabled(K6Service::Control, false, 0, 0, 0),
          "invalid timestamp rejected");
}

static void TestPrivateMetricsWindow() {
    K6Metrics metrics;
    const std::uint64_t start = 9000; // aligned 15-minute boundary
    CHECK(K6Metrics::FixedSeriesCardinality() == 249, "registry cardinality is fixed and reviewed");
    CHECK(metrics.Add(K6MetricFamily::ExitAdmissionTotal, 3, 0, 0, 1, start + 1),
          "valid fixed-label counter accepted");
    for (int i = 0; i < 3; ++i)
        CHECK(metrics.Add(K6MetricFamily::ExitAdmissionTotal, 3, 0, 0, 1,
                          start + 2 + i), "low-count event accepted locally");
    std::string live = metrics.ExportPrometheus(start + 899);
    CHECK(live.find("kad6_metrics_window_ready 0") != std::string::npos,
          "active window is never public");
    CHECK(live.find("kad6_exit_admission_total{service=") == std::string::npos,
          "real-time event series absent");

    // Four events are still suppressed after the window seals.
    std::string sealed = metrics.ExportPrometheus(start + 900);
    CHECK(sealed.find("kad6_metrics_window_ready 1") != std::string::npos,
          "complete window becomes available");
    CHECK(sealed.find("kad6_exit_admission_total{service=") == std::string::npos,
          "k<5 series suppressed");
    CHECK(sealed.find("ip=") == std::string::npos &&
          sealed.find("peer=") == std::string::npos &&
          sealed.find("hash=") == std::string::npos &&
          sealed.find("keyword=") == std::string::npos &&
          sealed.find("ticket=") == std::string::npos,
          "export has no forbidden/high-cardinality label keys");

    for (int i = 0; i < 5; ++i)
        CHECK(metrics.Add(K6MetricFamily::ExitRejectTotal, 8, 0, 0, 1,
                          start + 901 + i), "kill-switch rejection counted");
    CHECK(metrics.Observe(K6MetricFamily::ExitCapacityRatio, 3, 0, 0, 0.5, start + 910),
          "capacity gauge accepted");
    CHECK(!metrics.Add(K6MetricFamily::ExitCapacityRatio, 3, 0, 0, 1, start + 910),
          "gauge cannot be mutated as counter");
    CHECK(!metrics.Observe(K6MetricFamily::ExitRejectTotal, 8, 0, 0, 1.0, start + 910),
          "counter cannot be observed as gauge");
    CHECK(!metrics.Add(K6MetricFamily::ExitRejectTotal, 10, 0, 0, 1, start + 910),
          "out-of-registry label rejected");
    CHECK(!metrics.Observe(K6MetricFamily::ExitCapacityRatio, 3, 0, 0, -1.0, start + 910),
          "negative gauge rejected");
    CHECK(metrics.Observe(K6MetricFamily::SearchLatencyMs, 0, 1, 0, 125.0, start + 910),
          "source milestone latency accepts fixed labels");
    CHECK(metrics.Add(K6MetricFamily::SearchRpcTotal, 1, 2, 3, 1, start + 910),
          "native alpha=8 timeout counter accepts fixed labels");
    CHECK(!metrics.Add(K6MetricFamily::SearchRpcTotal, 1, 3, 0, 1, start + 910),
          "unregistered alpha label rejected");
    CHECK(metrics.Add(K6MetricFamily::TransportBytesTotal, 0, 1, 0, 4096, start + 910),
          "goodput bytes accept fixed direction");

    std::string next = metrics.ExportPrometheus(start + 1800);
    CHECK(next.find("kad6_exit_reject_total{reason=\"kill_switch\"} 5") != std::string::npos,
          "five-event series exported only after its complete window");
    CHECK(next.find("kad6_exit_capacity_ratio{service=") == std::string::npos,
          "gauge with fewer than five samples suppressed");
    K6MetricsWindowInfo info = metrics.WindowInfo(start + 1800);
    CHECK(info.start == start + 900 && info.end == start + 1800,
          "public window is exactly 15 minutes");
    CHECK(info.exported_series == 1, "only one non-suppressed series exported");
}

static void TestClockRollbackFailsClosed() {
    K6Metrics epochZero;
    for (int i = 0; i < 5; ++i)
        CHECK(epochZero.Add(K6MetricFamily::AuthFailTotal, 0, 0, 0, 1,
                            1 + i), "epoch-zero-window event accepted");
    CHECK(epochZero.ExportPrometheus(901).find(
        "kad6_auth_fail_total{stage=\"create\"} 5") != std::string::npos,
        "window aligned to Unix epoch zero seals correctly");

    K6Metrics metrics;
    for (int i = 0; i < 5; ++i)
        CHECK(metrics.Add(K6MetricFamily::AuthFailTotal, 0, 0, 0, 1, 4000 + i),
              "auth event accepted");
    (void)metrics.ExportPrometheus(5000);
    std::string rollback = metrics.ExportPrometheus(1000);
    CHECK(rollback.find("kad6_metrics_window_ready 0") != std::string::npos,
          "clock rollback clears potentially mixed window");
}

int main() {
    TestKillSwitchDrain();
    TestNaturalDrainAndImmediateStop();
    TestPrivateMetricsWindow();
    TestClockRollbackFailsClosed();
    std::printf("test_kad6_hardening: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
