// SPDX-License-Identifier: MIT
// K6-7 beta hardening: local service kill switches and privacy-preserving,
// fixed-cardinality telemetry. This module is portable and contains no MFC or
// host networking dependencies.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>

namespace kad6 {

constexpr std::uint64_t kK6MetricsWindowSeconds = 15u * 60u;
constexpr std::uint64_t kK6MetricsMinPublicEvents = 5;
constexpr std::uint32_t kK6MaxDrainSeconds = 24u * 60u * 60u;

enum class K6Service : std::uint8_t {
    Control = 0,
    ExitKad = 1,
    ExitEd2kDial = 2,
    ExitEd2kFull = 3,
    Count = 4
};

enum class K6ServiceState : std::uint8_t {
    Enabled = 0,
    Draining = 1,
    Disabled = 2
};

constexpr std::uint32_t K6ServiceBit(K6Service service) noexcept {
    return 1u << static_cast<std::uint8_t>(service);
}

struct K6ServiceSnapshot {
    K6Service service = K6Service::Control;
    K6ServiceState state = K6ServiceState::Enabled;
    std::uint64_t changed_at = 0;
    std::uint64_t drain_deadline = 0;
};

struct K6HardeningSnapshot {
    std::array<K6ServiceSnapshot, static_cast<std::size_t>(K6Service::Count)> services{};
    std::uint64_t revision = 0;
    std::uint32_t admission_mask = 0;
};

struct K6DrainResult {
    std::uint32_t completed_mask = 0;
    std::uint32_t force_close_mask = 0;
};

// A local-only control plane. Disabling a service immediately makes
// CanAdmit() false. Existing work may drain until its deadline; Tick() tells
// the host when a deadline requires explicit closure. A repeated disable can
// shorten, but never extend, an existing drain.
class K6HardeningController {
public:
    K6HardeningController() noexcept;

    bool SetEnabled(K6Service service, bool enabled, std::uint64_t now_seconds,
                    std::uint32_t drain_seconds,
                    std::uint64_t active_sessions) noexcept;
    K6DrainResult Tick(std::uint64_t now_seconds,
        const std::array<std::uint64_t, static_cast<std::size_t>(K6Service::Count)>&
            active_sessions) noexcept;
    bool CanAdmit(K6Service service) const noexcept;
    K6HardeningSnapshot Snapshot() const noexcept;

private:
    static bool Valid(K6Service service) noexcept;
    mutable std::mutex mutex_;
    K6HardeningSnapshot state_{};
};

// Every label value below is an enum/index selected by trusted local code.
// There is deliberately no API accepting a peer, IP, hash, keyword, ticket or
// arbitrary string as a label (K6-MET-001/002).
enum class K6MetricFamily : std::uint8_t {
    Circuits = 0,
    BuildTotal,
    Sessions,
    ExitBytesTotal,
    ExitRejectTotal,
    ExitCapacityRatio,
    ExitUtilization,
    ExitAdmissionTotal,
    ExitPreauthSlots,
    ExitPublishQps,
    ExitCohorts,
    SearchTotal,
    PublishTotal,
    PaddingBytesTotal,
    AuthFailTotal,
    DowngradeBlockTotal,
    LegacyProxyTotal,
    SearchLatencyMs,
    SearchRpcTotal,
    SourceCandidateTotal,
    SourceDialTotal,
    SourceStaleTotal,
    CircuitBuildMs,
    TransportBytesTotal,
    Count
};

struct K6MetricsWindowInfo {
    bool ready = false;
    std::uint64_t start = 0;
    std::uint64_t end = 0;
    std::size_t fixed_series = 0;
    std::size_t exported_series = 0;
};

// Tumbling, UTC-aligned 15-minute windows. The public exporter never emits the
// active window and suppresses every series with fewer than five observations.
class K6Metrics {
public:
    K6Metrics() noexcept;

    bool Add(K6MetricFamily family, std::uint8_t label_a,
             std::uint8_t label_b, std::uint8_t label_c,
             std::uint64_t amount, std::uint64_t now_seconds) noexcept;
    bool Observe(K6MetricFamily family, std::uint8_t label_a,
                 std::uint8_t label_b, std::uint8_t label_c,
                 double value, std::uint64_t now_seconds) noexcept;

    std::string ExportPrometheus(std::uint64_t now_seconds);
    K6MetricsWindowInfo WindowInfo(std::uint64_t now_seconds) noexcept;
    static std::size_t FixedSeriesCardinality() noexcept;

private:
    static constexpr std::size_t kFamilyCount =
        static_cast<std::size_t>(K6MetricFamily::Count);
    static constexpr std::size_t kMaxA = 10;
    static constexpr std::size_t kMaxB = 8;
    static constexpr std::size_t kMaxC = 4;
    static constexpr std::size_t kStorage = kFamilyCount * kMaxA * kMaxB * kMaxC;

    struct Cell {
        std::uint64_t counter = 0;
        std::uint64_t observations = 0;
        double gauge_sum = 0.0;
    };

    static std::size_t Index(K6MetricFamily family, std::uint8_t a,
                             std::uint8_t b, std::uint8_t c) noexcept;
    static bool ValidLabels(K6MetricFamily family, std::uint8_t a,
                            std::uint8_t b, std::uint8_t c) noexcept;
    void RotateLocked(std::uint64_t now_seconds) noexcept;
    K6MetricsWindowInfo InfoLocked() const noexcept;

    mutable std::mutex mutex_;
    std::array<Cell, kStorage> active_{};
    std::array<Cell, kStorage> sealed_{};
    bool active_initialized_ = false;
    std::uint64_t active_start_ = 0;
    std::uint64_t sealed_start_ = 0;
    std::uint64_t sealed_end_ = 0;
};

const char* K6ServiceName(K6Service service) noexcept;
const char* K6ServiceStateName(K6ServiceState state) noexcept;

} // namespace kad6
