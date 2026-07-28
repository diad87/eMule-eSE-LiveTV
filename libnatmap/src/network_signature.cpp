#include "natmap/network_signature.h"

#include "natmap/address_policy.h"

namespace natmap {
namespace {

bool SameAddress(const IpAddress& left, const IpAddress& right) noexcept {
    return left.family == right.family && left.bytes == right.bytes;
}

std::size_t AddressLength(AddressFamily family) noexcept {
    return family == AddressFamily::IPv4
               ? 4u
               : family == AddressFamily::IPv6 ? 16u : 0u;
}

bool IsCanonical(const IpAddress& address) noexcept {
    const std::size_t length = AddressLength(address.family);
    if (length == 0)
        return false;
    for (std::size_t i = length; i < address.bytes.size(); ++i)
        if (address.bytes[i] != 0)
            return false;
    return true;
}

bool IsUsableRouteEndpoint(const IpAddress& address) noexcept {
    if (!IsCanonical(address))
        return false;
    const AddressClass address_class =
        ClassifyAddress(address).address_class;
    return address_class != AddressClass::Unspecified &&
           address_class != AddressClass::Loopback &&
           address_class != AddressClass::Multicast &&
           address_class != AddressClass::Reserved &&
           address_class != AddressClass::Documentation;
}

bool IsCanonicalRouteNetwork(const IpAddress& address,
                             std::uint8_t prefix_length) noexcept {
    if (!IsCanonical(address))
        return false;
    const std::size_t length = AddressLength(address.family);
    if (prefix_length > length * 8u)
        return false;
    const std::size_t whole_bytes = prefix_length / 8u;
    const std::uint8_t remainder =
        static_cast<std::uint8_t>(prefix_length % 8u);
    if (remainder != 0) {
        const std::uint8_t host_mask =
            static_cast<std::uint8_t>((1u << (8u - remainder)) - 1u);
        if ((address.bytes[whole_bytes] & host_mask) != 0)
            return false;
    }
    const std::size_t first_host =
        whole_bytes + (remainder == 0 ? 0u : 1u);
    for (std::size_t i = first_host; i < length; ++i)
        if (address.bytes[i] != 0)
            return false;
    return true;
}

bool SameIdentity(const NetworkSignatureInput& left,
                  const NetworkSignatureInput& right) noexcept {
    return left.adapter_luid == right.adapter_luid &&
           left.interface_index == right.interface_index &&
           SameAddress(left.local_address, right.local_address) &&
           SameAddress(left.gateway_address, right.gateway_address) &&
           SameAddress(left.route_destination, right.route_destination) &&
           left.route_prefix_length == right.route_prefix_length &&
           left.compartment_id == right.compartment_id &&
           left.compartment_present == right.compartment_present;
}

}  // namespace

NetworkSignatureStatus BuildNetworkSignature(
    const NetworkSignatureInput& input,
    NetworkSignature& signature) noexcept {
    if (input.adapter_luid == 0)
        return NetworkSignatureStatus::AdapterInvalid;
    if (input.interface_index == 0)
        return NetworkSignatureStatus::InterfaceInvalid;
    if (input.local_address.family == AddressFamily::Unspecified ||
        input.gateway_address.family != input.local_address.family ||
        input.route_destination.family != input.local_address.family)
        return NetworkSignatureStatus::FamilyMismatch;
    if (!IsUsableRouteEndpoint(input.local_address))
        return NetworkSignatureStatus::LocalAddressInvalid;
    if (!IsUsableRouteEndpoint(input.gateway_address))
        return NetworkSignatureStatus::GatewayInvalid;
    if (!IsCanonicalRouteNetwork(
            input.route_destination, input.route_prefix_length))
        return NetworkSignatureStatus::RouteInvalid;
    if ((input.compartment_present && input.compartment_id == 0) ||
        (!input.compartment_present && input.compartment_id != 0))
        return NetworkSignatureStatus::CompartmentInvalid;

    NetworkSignature candidate;
    candidate.identity_ = input;
    candidate.valid_ = true;
    signature = candidate;
    return NetworkSignatureStatus::Valid;
}

bool SameNetworkSignature(const NetworkSignature& left,
                          const NetworkSignature& right) noexcept {
    return left.valid_ && right.valid_ &&
           SameIdentity(left.identity_, right.identity_);
}

}  // namespace natmap
