#pragma once

#include <cstdint>

namespace natmap {

// Ordered from the best usable IGD state to the weakest one. The values
// intentionally mirror miniupnpc's documented UPNP_* IGD states, while this
// contract remains independent from that third-party header.
enum class UpnpIgdQuality : std::uint8_t {
    None = 0,
    Connected = 1,
    PrivateAddress = 2,
    Disconnected = 3,
    UnknownDevice = 4,
};

struct UpnpIgdObservation {
    UpnpIgdQuality quality = UpnpIgdQuality::None;
    bool has_control_url = false;
    bool has_service_type = false;
};

enum class UpnpDiscoveryStatus : std::uint8_t {
    Searching = 0,
    Selected = 1,
    TimedOut = 2,
    Cancelled = 3,
};

// Pure main/worker-neutral selection policy. It retains no URLs or pointers:
// the mapper owns those resources and moves them only when Consider returns
// true. Cancellation remains authoritative until publication.
class UpnpDiscoverySelection {
public:
    UpnpDiscoverySelection() noexcept = default;
    UpnpDiscoverySelection(const UpnpDiscoverySelection&) = delete;
    UpnpDiscoverySelection& operator=(const UpnpDiscoverySelection&) = delete;
    UpnpDiscoverySelection(UpnpDiscoverySelection&&) = delete;
    UpnpDiscoverySelection& operator=(UpnpDiscoverySelection&&) = delete;

    bool Consider(const UpnpIgdObservation& observation) noexcept;
    void Complete() noexcept;
    void Cancel() noexcept;

    bool should_continue() const noexcept;
    bool has_candidate() const noexcept;
    UpnpIgdQuality selected_quality() const noexcept {
        return selected_quality_;
    }
    UpnpDiscoveryStatus status() const noexcept { return status_; }

private:
    UpnpIgdQuality selected_quality_ = UpnpIgdQuality::None;
    UpnpDiscoveryStatus status_ = UpnpDiscoveryStatus::Searching;
};

static_assert(static_cast<std::uint8_t>(UpnpIgdQuality::UnknownDevice) == 4,
              "UPnP IGD quality ordering changed");
static_assert(static_cast<std::uint8_t>(UpnpDiscoveryStatus::Cancelled) == 3,
              "UPnP discovery status contract changed");

} // namespace natmap
