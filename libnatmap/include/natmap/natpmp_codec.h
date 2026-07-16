#pragma once

#include <cstddef>
#include <cstdint>

namespace natmap {

enum class NatPmpTransport : std::uint8_t {
    Udp = 1,
    Tcp = 2,
};

enum class NatPmpDecodeStatus : std::uint8_t {
    Ok = 0,
    Truncated = 1,
    BadVersion = 2,
    BadOpcode = 3,
    WrongInternalPort = 4,
};

struct NatPmpMapResponse {
    std::uint16_t result_code = 0;
    std::uint32_t epoch = 0;
    std::uint16_t internal_port = 0;
    std::uint16_t external_port = 0;
    std::uint32_t lifetime_seconds = 0;
};

struct NatPmpExternalAddressResponse {
    std::uint16_t result_code = 0;
    std::uint32_t epoch = 0;
    std::uint32_t external_ip_network_order = 0;
};

bool EncodeNatPmpExternalAddressRequest(std::uint8_t* out,
                                        std::size_t capacity) noexcept;
NatPmpDecodeStatus DecodeNatPmpExternalAddressResponse(
    const std::uint8_t* data, std::size_t size,
    NatPmpExternalAddressResponse& out) noexcept;
bool EncodeNatPmpMapRequest(NatPmpTransport transport,
                            std::uint16_t internal_port,
                            std::uint16_t suggested_external_port,
                            std::uint32_t lifetime_seconds,
                            std::uint8_t* out,
                            std::size_t capacity) noexcept;
NatPmpDecodeStatus DecodeNatPmpMapResponse(
    const std::uint8_t* data, std::size_t size,
    NatPmpTransport expected_transport, std::uint16_t expected_internal_port,
    NatPmpMapResponse& out) noexcept;

} // namespace natmap
