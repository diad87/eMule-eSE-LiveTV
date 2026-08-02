#include "natmap/natpmp_gateway_policy.h"

namespace natmap {
namespace {

bool HasCanonicalV4Tail(const IpAddress& address) noexcept {
    for (std::size_t i = 4; i < address.bytes.size(); ++i)
        if (address.bytes[i] != 0)
            return false;
    return true;
}

bool IsUsableGatewayV4(const IpAddress& address) noexcept {
    if (address.family != AddressFamily::IPv4 ||
        !HasCanonicalV4Tail(address) || address.IsUnspecified())
        return false;
    const std::uint8_t first = address.bytes[0];
    if (first == 0 || first == 127 || first >= 224)
        return false;
    if (first == 169 && address.bytes[1] == 254)
        return false;
    return !(address.bytes[0] == 255 && address.bytes[1] == 255 &&
             address.bytes[2] == 255 && address.bytes[3] == 255);
}

IpAddress DecodeNetworkOrderV4(std::uint32_t network_order) noexcept {
    const std::uint8_t* bytes =
        reinterpret_cast<const std::uint8_t*>(&network_order);
    return IpAddress::V4(bytes[0], bytes[1], bytes[2], bytes[3]);
}

} // namespace

NatPmpGatewaySelection SelectNatPmpGateway(
    const IpAddress& gateway_address,
    std::uint32_t interface_index) noexcept {
    NatPmpGatewaySelection result{};
    if (interface_index == 0 ||
        interface_index > kNatPmpMaximumInterfaceIndex) {
        result.status = NatPmpGatewayStatus::MissingInterface;
        return result;
    }
    if (!IsUsableGatewayV4(gateway_address)) {
        result.status = NatPmpGatewayStatus::InvalidAddress;
        return result;
    }
    result.status = NatPmpGatewayStatus::Selected;
    result.interface_index = interface_index;
    for (std::size_t i = 0; i < result.gateway_address.size(); ++i)
        result.gateway_address[i] = gateway_address.bytes[i];
    return result;
}

NatPmpExternalAddressDecision ClassifyNatPmpExternalAddress(
    bool response_received,
    const NatPmpExternalAddressResponse& response) noexcept {
    NatPmpExternalAddressDecision result{};
    if (!response_received) {
        result.status = NatPmpExternalAddressStatus::Missing;
        return result;
    }
    // Epoch is valid gateway evidence for every decoded response, even when
    // the requested address is rejected or its value is unusable.
    result.epoch = response.epoch;
    if (response.result_code > 5) {
        result.status = NatPmpExternalAddressStatus::Invalid;
        return result;
    }
    if (response.result_code != 0) {
        result.status = NatPmpExternalAddressStatus::Rejected;
        return result;
    }

    result.address =
        DecodeNetworkOrderV4(response.external_ip_network_order);
    if (!IsUsableGatewayV4(result.address)) {
        result.status = NatPmpExternalAddressStatus::Invalid;
        result.address = IpAddress{};
        return result;
    }
    if (result.address.IsSharedCgnatV4()) {
        result.status = NatPmpExternalAddressStatus::Cgnat;
        return result;
    }
    if (result.address.IsRfc1918V4()) {
        result.status = NatPmpExternalAddressStatus::Private;
        return result;
    }
    result.status = NatPmpExternalAddressStatus::Public;
    result.can_publish_direct = true;
    return result;
}

NatPmpExternalAddressDecision ResolveNatPmpPublishAddress(
    const NatPmpExternalAddressDecision& current_query,
    const NatPmpExternalAddressDecision& retained_address,
    bool mapping_epoch_reset) noexcept {
    if (mapping_epoch_reset) {
        NatPmpExternalAddressDecision invalidated{};
        invalidated.status = NatPmpExternalAddressStatus::Invalid;
        return invalidated;
    }
    if ((current_query.status == NatPmpExternalAddressStatus::Missing ||
         current_query.status == NatPmpExternalAddressStatus::Rejected) &&
        retained_address.can_publish_direct)
        return retained_address;
    return current_query;
}

} // namespace natmap
