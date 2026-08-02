#include "natmap/pcp_route_binding.h"

#include <algorithm>

namespace natmap {
namespace {

constexpr std::uint32_t kMaximumIpv4InterfaceIndex = 0x00ffffffu;

bool HasCanonicalV4Tail(const IpAddress& address) noexcept {
    return std::all_of(
        address.bytes.begin() + 4, address.bytes.end(),
        [](std::uint8_t byte) { return byte == 0; });
}

bool IsUsableUnicastV4(const IpAddress& address) noexcept {
    if (address.family != AddressFamily::IPv4
        || !HasCanonicalV4Tail(address))
        return false;
    const bool all_zero = address.bytes[0] == 0
        && address.bytes[1] == 0
        && address.bytes[2] == 0
        && address.bytes[3] == 0;
    const bool all_ones = address.bytes[0] == 255
        && address.bytes[1] == 255
        && address.bytes[2] == 255
        && address.bytes[3] == 255;
    return !all_zero && !all_ones
        && address.bytes[0] != 0
        && address.bytes[0] != 127
        && address.bytes[0] < 224;
}

template <std::size_t Size>
bool IsUsableUnicastBytes(
    const std::array<std::uint8_t, Size>& address,
    std::size_t offset) noexcept {
    const std::uint8_t first = address[offset];
    const bool all_zero =
        address[offset] == 0 && address[offset + 1] == 0
        && address[offset + 2] == 0 && address[offset + 3] == 0;
    const bool all_ones =
        address[offset] == 255 && address[offset + 1] == 255
        && address[offset + 2] == 255 && address[offset + 3] == 255;
    return !all_zero && !all_ones && first != 0
        && first != 127 && first < 224;
}

bool EqualV4(
    const IpAddress& left, const IpAddress& right) noexcept {
    return std::equal(
        left.bytes.begin(), left.bytes.begin() + 4,
        right.bytes.begin());
}

} // namespace

bool PcpRouteBinding::IsValid() const noexcept {
    const bool mapped_prefix = std::all_of(
        client_address.begin(), client_address.begin() + 10,
        [](std::uint8_t byte) { return byte == 0; })
        && client_address[10] == 0xff
        && client_address[11] == 0xff;
    return interface_index != 0
        && interface_index <= kMaximumIpv4InterfaceIndex
        && mapped_prefix
        && IsUsableUnicastBytes(gateway_address, 0)
        && IsUsableUnicastBytes(client_address, 12)
        && !std::equal(
            gateway_address.begin(), gateway_address.end(),
            client_address.begin() + 12);
}

PcpRouteBindingSelection SelectPcpRouteBinding(
    const IpAddress& client_address,
    const IpAddress& gateway_address,
    std::uint32_t interface_index) noexcept {
    PcpRouteBindingSelection result{};
    if (interface_index == 0
        || interface_index > kMaximumIpv4InterfaceIndex) {
        result.status = PcpRouteBindingStatus::InvalidInterface;
        return result;
    }
    if (client_address.family != AddressFamily::IPv4
        || gateway_address.family != AddressFamily::IPv4) {
        result.status = PcpRouteBindingStatus::UnsupportedFamily;
        return result;
    }
    if (!IsUsableUnicastV4(client_address)) {
        result.status = PcpRouteBindingStatus::InvalidClientAddress;
        return result;
    }
    if (!IsUsableUnicastV4(gateway_address)) {
        result.status = PcpRouteBindingStatus::InvalidGatewayAddress;
        return result;
    }
    if (EqualV4(client_address, gateway_address)) {
        result.status = PcpRouteBindingStatus::AmbiguousPair;
        return result;
    }

    std::copy_n(
        gateway_address.bytes.begin(),
        result.binding.gateway_address.size(),
        result.binding.gateway_address.begin());
    result.binding.interface_index = interface_index;
    result.binding.client_address[10] = 0xff;
    result.binding.client_address[11] = 0xff;
    std::copy_n(
        client_address.bytes.begin(), 4,
        result.binding.client_address.begin() + 12);
    result.status = PcpRouteBindingStatus::Valid;
    return result;
}

} // namespace natmap
