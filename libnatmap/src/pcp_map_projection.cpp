#include "natmap/pcp_map_projection.h"

#include <algorithm>

namespace natmap {
namespace {

std::uint8_t ProtocolFor(Transport transport) noexcept {
    return transport == Transport::Tcp ? 6
        : transport == Transport::Udp ? 17 : 0;
}

bool IsUsableExternalV4(const IpAddress& address) noexcept {
    if (address.family != AddressFamily::IPv4)
        return false;
    const bool canonical_tail = std::all_of(
        address.bytes.begin() + 4, address.bytes.end(),
        [](std::uint8_t byte) { return byte == 0; });
    const bool all_ones = address.bytes[0] == 255
        && address.bytes[1] == 255
        && address.bytes[2] == 255
        && address.bytes[3] == 255;
    return canonical_tail && !address.IsUnspecified() && !all_ones
        && address.bytes[0] != 0 && address.bytes[0] != 127
        && address.bytes[0] < 224;
}

bool DecodeMappedV4(
    const std::array<std::uint8_t, 16>& encoded,
    IpAddress& decoded) noexcept {
    if (!std::all_of(
            encoded.begin(), encoded.begin() + 10,
            [](std::uint8_t byte) { return byte == 0; })
        || encoded[10] != 0xff || encoded[11] != 0xff)
        return false;
    decoded = IpAddress::V4(
        encoded[12], encoded[13], encoded[14], encoded[15]);
    return IsUsableExternalV4(decoded);
}

} // namespace

bool PcpMapProjection::IsValid() const noexcept {
    const std::uint8_t protocol = ProtocolFor(transport);
    const bool nonce_nonzero = std::any_of(
        nonce.begin(), nonce.end(),
        [](std::uint8_t byte) { return byte != 0; });
    return protocol != 0 && internal_port != 0
        && granted_external_port != 0
        && IsUsableExternalV4(external_address)
        && lifetime_seconds != 0 && nonce_nonzero;
}

PcpMapProjectionResult ProjectPcpMapResponse(
    const PcpMappingIdentity& identity,
    std::uint16_t requested_external_port,
    const PcpMapResponse& response) noexcept {
    PcpMapProjectionResult result{};
    if (!identity.IsValid())
        return result;
    if (response.result != PcpResultCode::Success) {
        result.status = PcpMapProjectionStatus::Rejected;
        return result;
    }
    if (response.nonce != identity.nonce) {
        result.status = PcpMapProjectionStatus::WrongNonce;
        return result;
    }
    if (response.protocol != ProtocolFor(identity.transport)) {
        result.status = PcpMapProjectionStatus::WrongProtocol;
        return result;
    }
    if (response.internal_port != identity.internal_port) {
        result.status = PcpMapProjectionStatus::WrongInternalPort;
        return result;
    }
    if (response.external_port == 0) {
        result.status = PcpMapProjectionStatus::InvalidGrantedPort;
        return result;
    }
    if (response.lifetime_seconds == 0) {
        result.status = PcpMapProjectionStatus::InvalidLifetime;
        return result;
    }
    IpAddress external{};
    if (!DecodeMappedV4(response.external_ip, external)) {
        result.status = PcpMapProjectionStatus::InvalidExternalAddress;
        return result;
    }

    result.value.transport = identity.transport;
    result.value.internal_port = identity.internal_port;
    result.value.requested_external_port = requested_external_port;
    result.value.granted_external_port = response.external_port;
    result.value.external_address = external;
    result.value.lifetime_seconds = response.lifetime_seconds;
    result.value.epoch = response.epoch;
    result.value.nonce = identity.nonce;
    result.status = PcpMapProjectionStatus::Valid;
    return result;
}

} // namespace natmap
