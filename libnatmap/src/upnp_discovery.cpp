#include "natmap/upnp_discovery.h"

namespace natmap {
namespace {

bool IsUsable(const UpnpIgdObservation& observation) noexcept {
    const auto quality = static_cast<std::uint8_t>(observation.quality);
    return quality >= static_cast<std::uint8_t>(UpnpIgdQuality::Connected) &&
           quality <=
               static_cast<std::uint8_t>(UpnpIgdQuality::UnknownDevice) &&
           observation.has_control_url && observation.has_service_type;
}

} // namespace

bool UpnpDiscoverySelection::Consider(
    const UpnpIgdObservation& observation) noexcept {
    if (status_ != UpnpDiscoveryStatus::Searching ||
        !IsUsable(observation)) {
        return false;
    }
    if (selected_quality_ != UpnpIgdQuality::None &&
        static_cast<std::uint8_t>(observation.quality) >=
            static_cast<std::uint8_t>(selected_quality_)) {
        return false;
    }

    selected_quality_ = observation.quality;
    if (selected_quality_ == UpnpIgdQuality::Connected ||
        selected_quality_ == UpnpIgdQuality::PrivateAddress) {
        status_ = UpnpDiscoveryStatus::Selected;
    }
    return true;
}

void UpnpDiscoverySelection::Complete() noexcept {
    if (status_ != UpnpDiscoveryStatus::Searching)
        return;
    status_ = selected_quality_ == UpnpIgdQuality::None
        ? UpnpDiscoveryStatus::TimedOut
        : UpnpDiscoveryStatus::Selected;
}

void UpnpDiscoverySelection::Cancel() noexcept {
    if (status_ == UpnpDiscoveryStatus::TimedOut ||
        status_ == UpnpDiscoveryStatus::Cancelled) {
        return;
    }
    selected_quality_ = UpnpIgdQuality::None;
    status_ = UpnpDiscoveryStatus::Cancelled;
}

bool UpnpDiscoverySelection::should_continue() const noexcept {
    return status_ == UpnpDiscoveryStatus::Searching;
}

bool UpnpDiscoverySelection::has_candidate() const noexcept {
    return status_ != UpnpDiscoveryStatus::TimedOut &&
           status_ != UpnpDiscoveryStatus::Cancelled &&
           selected_quality_ != UpnpIgdQuality::None;
}

} // namespace natmap
