#include "natmap/pcp_codec.h"

#include <cstring>

namespace natmap {
namespace {

constexpr std::uint8_t kPcpVersion = 2;
constexpr std::uint8_t kOpcodeAnnounce = 0;
constexpr std::uint8_t kOpcodeMap = 1;
constexpr std::uint8_t kResponseBit = 0x80;
constexpr std::uint8_t kOptionPreferFailure = 2;
constexpr std::uint8_t kOptionPortSet = 130;

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

std::size_t PaddedOptionSize(std::uint16_t data_size) noexcept {
    return 4u + ((static_cast<std::size_t>(data_size) + 3u) & ~std::size_t(3u));
}

} // namespace

std::array<std::uint8_t, 16> PcpIpv4Mapped(std::uint8_t a, std::uint8_t b,
                                           std::uint8_t c, std::uint8_t d) noexcept {
    std::array<std::uint8_t, 16> result{};
    result[10] = 0xFF;
    result[11] = 0xFF;
    result[12] = a;
    result[13] = b;
    result[14] = c;
    result[15] = d;
    return result;
}

std::size_t EncodePcpAnnounceRequest(
    const std::array<std::uint8_t, 16>& client_ip,
    std::uint8_t* out, std::size_t capacity) noexcept {
    if (out == nullptr || capacity < 24)
        return 0;
    std::memset(out, 0, 24);
    out[0] = kPcpVersion;
    out[1] = kOpcodeAnnounce;
    std::memcpy(out + 8, client_ip.data(), client_ip.size());
    return 24;
}

std::size_t EncodePcpMapRequest(const PcpMapRequest& request,
                                std::uint8_t* out,
                                std::size_t capacity) noexcept {
    if (out == nullptr || request.protocol == 0 || request.internal_port == 0)
        return 0;
    if (request.prefer_failure &&
        (request.lifetime_seconds == 0 || request.suggested_external_port == 0))
        return 0;
    if (request.port_set_size != 0 &&
        request.first_internal_port != request.internal_port)
        return 0;

    std::size_t required = kPcpBaseMessageSize;
    if (request.prefer_failure)
        required += 4;
    if (request.port_set_size != 0)
        required += PaddedOptionSize(5);
    if (required > capacity || required > kPcpMaximumMessageSize)
        return 0;

    std::memset(out, 0, required);
    out[0] = kPcpVersion;
    out[1] = kOpcodeMap;
    Put32(out + 4, request.lifetime_seconds);
    std::memcpy(out + 8, request.client_ip.data(), request.client_ip.size());
    std::memcpy(out + 24, request.nonce.data(), request.nonce.size());
    out[36] = request.protocol;
    Put16(out + 40, request.internal_port);
    Put16(out + 42, request.lifetime_seconds == 0
        ? 0 : request.suggested_external_port);
    if (request.lifetime_seconds != 0)
        std::memcpy(out + 44, request.suggested_external_ip.data(),
                    request.suggested_external_ip.size());

    std::size_t offset = kPcpBaseMessageSize;
    if (request.prefer_failure) {
        out[offset] = kOptionPreferFailure;
        offset += 4;
    }
    if (request.port_set_size != 0) {
        out[offset] = kOptionPortSet;
        Put16(out + offset + 2, 5);
        Put16(out + offset + 4, request.port_set_size);
        Put16(out + offset + 6, request.first_internal_port);
        out[offset + 8] = request.preserve_parity ? 1 : 0;
    }
    return required;
}

PcpDecodeStatus DecodePcpMapResponse(
    const std::uint8_t* data, std::size_t size,
    const PcpMapRequest& request, PcpMapResponse& out) noexcept {
    if (data == nullptr || size < kPcpBaseMessageSize)
        return PcpDecodeStatus::Truncated;
    if (size > kPcpMaximumMessageSize)
        return PcpDecodeStatus::Oversized;
    if ((size & 3u) != 0)
        return PcpDecodeStatus::Misaligned;
    if (data[0] != kPcpVersion)
        return PcpDecodeStatus::BadVersion;
    if ((data[1] & kResponseBit) == 0)
        return PcpDecodeStatus::NotResponse;
    if ((data[1] & 0x7Fu) != kOpcodeMap)
        return PcpDecodeStatus::WrongOpcode;
    if (std::memcmp(data + 24, request.nonce.data(), request.nonce.size()) != 0)
        return PcpDecodeStatus::WrongNonce;
    if (data[36] != request.protocol)
        return PcpDecodeStatus::WrongProtocol;
    if (Get16(data + 40) != request.internal_port)
        return PcpDecodeStatus::WrongInternalPort;

    PcpMapResponse decoded{};
    // RFC 6887 common response header: byte 2 is reserved, byte 3 is result.
    decoded.result = static_cast<PcpResultCode>(data[3]);
    decoded.lifetime_seconds = Get32(data + 4);
    decoded.epoch = Get32(data + 8);
    std::memcpy(decoded.nonce.data(), data + 24, decoded.nonce.size());
    decoded.protocol = data[36];
    decoded.internal_port = Get16(data + 40);
    decoded.external_port = Get16(data + 42);
    std::memcpy(decoded.external_ip.data(), data + 44, decoded.external_ip.size());

    bool seen_port_set = false;
    std::size_t offset = kPcpBaseMessageSize;
    while (offset < size) {
        if (size - offset < 4)
            return PcpDecodeStatus::MalformedOption;
        const std::uint8_t code = data[offset];
        const std::uint16_t length = Get16(data + offset + 2);
        const std::size_t option_size = PaddedOptionSize(length);
        if (option_size > size - offset)
            return PcpDecodeStatus::MalformedOption;
        if (code == kOptionPortSet) {
            if (seen_port_set || length != 5)
                return PcpDecodeStatus::MalformedOption;
            seen_port_set = true;
            decoded.has_port_set = true;
            decoded.port_set_size = Get16(data + offset + 4);
            decoded.first_internal_port = Get16(data + offset + 6);
            decoded.preserve_parity = (data[offset + 8] & 1u) != 0;
            if (decoded.port_set_size == 0)
                return PcpDecodeStatus::MalformedOption;
        }
        offset += option_size;
    }

    out = decoded;
    return PcpDecodeStatus::Ok;
}

PcpDecodeStatus DecodePcpAnnounceResponse(
    const std::uint8_t* data, std::size_t size,
    PcpAnnounceResponse& out) noexcept {
    if (data == nullptr || size < 24)
        return PcpDecodeStatus::Truncated;
    if (size > kPcpMaximumMessageSize)
        return PcpDecodeStatus::Oversized;
    if ((size & 3u) != 0)
        return PcpDecodeStatus::Misaligned;
    if (data[0] != kPcpVersion)
        return PcpDecodeStatus::BadVersion;
    if ((data[1] & kResponseBit) == 0)
        return PcpDecodeStatus::NotResponse;
    if ((data[1] & 0x7Fu) != kOpcodeAnnounce)
        return PcpDecodeStatus::WrongOpcode;
    PcpAnnounceResponse decoded{};
    decoded.result = static_cast<PcpResultCode>(data[3]);
    decoded.epoch = Get32(data + 8);
    out = decoded;
    return PcpDecodeStatus::Ok;
}

} // namespace natmap
