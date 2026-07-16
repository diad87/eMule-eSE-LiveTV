#include "natmap/natpmp_codec.h"

#include <cstring>

namespace natmap {
namespace {

void Put16(std::uint8_t* p, std::uint16_t value) noexcept {
    p[0] = static_cast<std::uint8_t>(value >> 8);
    p[1] = static_cast<std::uint8_t>(value);
}

void Put32(std::uint8_t* p, std::uint32_t value) noexcept {
    p[0] = static_cast<std::uint8_t>(value >> 24);
    p[1] = static_cast<std::uint8_t>(value >> 16);
    p[2] = static_cast<std::uint8_t>(value >> 8);
    p[3] = static_cast<std::uint8_t>(value);
}

std::uint16_t Get16(const std::uint8_t* p) noexcept {
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(p[0]) << 8) |
                                      static_cast<std::uint16_t>(p[1]));
}

std::uint32_t Get32(const std::uint8_t* p) noexcept {
    return (static_cast<std::uint32_t>(p[0]) << 24) |
           (static_cast<std::uint32_t>(p[1]) << 16) |
           (static_cast<std::uint32_t>(p[2]) << 8) |
            static_cast<std::uint32_t>(p[3]);
}

} // namespace

bool EncodeNatPmpExternalAddressRequest(std::uint8_t* out,
                                        std::size_t capacity) noexcept {
    if (out == nullptr || capacity < 2)
        return false;
    out[0] = 0;
    out[1] = 0;
    return true;
}

NatPmpDecodeStatus DecodeNatPmpExternalAddressResponse(
    const std::uint8_t* data, std::size_t size,
    NatPmpExternalAddressResponse& out) noexcept {
    if (data == nullptr || size < 12)
        return NatPmpDecodeStatus::Truncated;
    if (data[0] != 0)
        return NatPmpDecodeStatus::BadVersion;
    if (data[1] != 128)
        return NatPmpDecodeStatus::BadOpcode;
    NatPmpExternalAddressResponse decoded{};
    decoded.result_code = Get16(data + 2);
    decoded.epoch = Get32(data + 4);
    std::memcpy(&decoded.external_ip_network_order, data + 8, 4);
    out = decoded;
    return NatPmpDecodeStatus::Ok;
}

bool EncodeNatPmpMapRequest(NatPmpTransport transport,
                            std::uint16_t internal_port,
                            std::uint16_t suggested_external_port,
                            std::uint32_t lifetime_seconds,
                            std::uint8_t* out,
                            std::size_t capacity) noexcept {
    if (out == nullptr || capacity < 12 || internal_port == 0 ||
        (transport != NatPmpTransport::Tcp && transport != NatPmpTransport::Udp))
        return false;
    std::memset(out, 0, 12);
    out[1] = static_cast<std::uint8_t>(transport);
    Put16(out + 4, internal_port);
    // RFC 6886 requires zero in this field for explicit deletion.
    Put16(out + 6, lifetime_seconds == 0 ? 0 : suggested_external_port);
    Put32(out + 8, lifetime_seconds);
    return true;
}

NatPmpDecodeStatus DecodeNatPmpMapResponse(
    const std::uint8_t* data, std::size_t size,
    NatPmpTransport expected_transport, std::uint16_t expected_internal_port,
    NatPmpMapResponse& out) noexcept {
    if (data == nullptr || size < 16)
        return NatPmpDecodeStatus::Truncated;
    if (data[0] != 0)
        return NatPmpDecodeStatus::BadVersion;
    const std::uint8_t expected_opcode =
        static_cast<std::uint8_t>(128 + static_cast<std::uint8_t>(expected_transport));
    if (data[1] != expected_opcode)
        return NatPmpDecodeStatus::BadOpcode;
    if (Get16(data + 8) != expected_internal_port)
        return NatPmpDecodeStatus::WrongInternalPort;

    NatPmpMapResponse decoded{};
    decoded.result_code = Get16(data + 2);
    decoded.epoch = Get32(data + 4);
    decoded.internal_port = Get16(data + 8);
    decoded.external_port = Get16(data + 10);
    decoded.lifetime_seconds = Get32(data + 12);
    out = decoded;
    return NatPmpDecodeStatus::Ok;
}

} // namespace natmap
