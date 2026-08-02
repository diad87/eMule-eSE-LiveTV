#pragma once

#include "natmap/natmap_types.h"
#include "natmap/natpmp_codec.h"

#include <array>
#include <cstdint>

namespace natmap {

constexpr std::uint32_t kNatPmpMaximumInterfaceIndex = 0x00ffffffu;

enum class NatPmpGatewayStatus : std::uint8_t {
    Selected = 0,
    MissingInterface = 1,
    InvalidAddress = 2,
};

struct NatPmpGatewaySelection {
    NatPmpGatewayStatus status = NatPmpGatewayStatus::InvalidAddress;
    std::uint32_t interface_index = 0;
    std::array<std::uint8_t, 4> gateway_address{};

    bool IsSelected() const noexcept {
        return status == NatPmpGatewayStatus::Selected &&
               interface_index != 0 &&
               interface_index <= kNatPmpMaximumInterfaceIndex;
    }
};

NatPmpGatewaySelection SelectNatPmpGateway(
    const IpAddress& gateway_address,
    std::uint32_t interface_index) noexcept;

enum class NatPmpExternalAddressStatus : std::uint8_t {
    Public = 0,
    Missing = 1,
    Rejected = 2,
    Private = 3,
    Cgnat = 4,
    Invalid = 5,
};

struct NatPmpExternalAddressDecision {
    NatPmpExternalAddressStatus status =
        NatPmpExternalAddressStatus::Missing;
    IpAddress address{};
    std::uint32_t epoch = 0;
    bool should_attempt_map = true;
    bool can_publish_direct = false;

    bool HasAddress() const noexcept {
        return address.family == AddressFamily::IPv4 &&
               !address.IsUnspecified();
    }
};

NatPmpExternalAddressDecision ClassifyNatPmpExternalAddress(
    bool response_received,
    const NatPmpExternalAddressResponse& response) noexcept;
NatPmpExternalAddressDecision ResolveNatPmpPublishAddress(
    const NatPmpExternalAddressDecision& current_query,
    const NatPmpExternalAddressDecision& retained_address,
    bool mapping_epoch_reset) noexcept;

} // namespace natmap
