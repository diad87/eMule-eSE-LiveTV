#pragma once

#include "natmap/natmap_types.h"

#include <array>
#include <cstdint>

namespace natmap {

enum class PcpRouteBindingStatus : std::uint8_t {
    Valid = 0,
    InvalidInterface = 1,
    UnsupportedFamily = 2,
    InvalidClientAddress = 3,
    InvalidGatewayAddress = 4,
    AmbiguousPair = 5,
};

struct PcpRouteBinding {
    std::uint32_t interface_index = 0;
    std::array<std::uint8_t, 4> gateway_address{};
    std::array<std::uint8_t, 16> client_address{};

    bool IsValid() const noexcept;
};

struct PcpRouteBindingSelection {
    PcpRouteBindingStatus status =
        PcpRouteBindingStatus::UnsupportedFamily;
    PcpRouteBinding binding{};

    bool IsSelected() const noexcept {
        return status == PcpRouteBindingStatus::Valid
            && binding.IsValid();
    }
};

// The caller supplies both addresses from one route snapshot. This function
// validates and freezes that pair so PCP never rediscovers either half
// independently while a mapping request is in flight.
PcpRouteBindingSelection SelectPcpRouteBinding(
    const IpAddress& client_address,
    const IpAddress& gateway_address,
    std::uint32_t interface_index) noexcept;

} // namespace natmap
