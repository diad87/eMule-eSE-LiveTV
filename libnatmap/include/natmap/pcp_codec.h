#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace natmap {

constexpr std::size_t kPcpBaseMessageSize = 60;
constexpr std::size_t kPcpMaximumMessageSize = 1100;

enum class PcpResultCode : std::uint8_t {
    Success = 0,
    UnsupportedVersion = 1,
    NotAuthorized = 2,
    MalformedRequest = 3,
    UnsupportedOpcode = 4,
    UnsupportedOption = 5,
    MalformedOption = 6,
    NetworkFailure = 7,
    NoResources = 8,
    UnsupportedProtocol = 9,
    UserExceededQuota = 10,
    CannotProvideExternal = 11,
    AddressMismatch = 12,
    ExcessiveRemotePeers = 13,
};

enum class PcpDecodeStatus : std::uint8_t {
    Ok = 0,
    Truncated = 1,
    Oversized = 2,
    Misaligned = 3,
    BadVersion = 4,
    NotResponse = 5,
    WrongOpcode = 6,
    WrongNonce = 7,
    WrongProtocol = 8,
    WrongInternalPort = 9,
    MalformedOption = 10,
};

struct PcpMapRequest {
    std::uint32_t lifetime_seconds = 0;
    std::array<std::uint8_t, 16> client_ip{};
    std::array<std::uint8_t, 12> nonce{};
    std::uint8_t protocol = 0;
    std::uint16_t internal_port = 0;
    std::uint16_t suggested_external_port = 0;
    std::array<std::uint8_t, 16> suggested_external_ip{};
    bool prefer_failure = false;
    std::uint16_t port_set_size = 0;
    std::uint16_t first_internal_port = 0;
    bool preserve_parity = false;
};

struct PcpMapResponse {
    PcpResultCode result = PcpResultCode::Success;
    std::uint32_t lifetime_seconds = 0;
    std::uint32_t epoch = 0;
    std::array<std::uint8_t, 12> nonce{};
    std::uint8_t protocol = 0;
    std::uint16_t internal_port = 0;
    std::uint16_t external_port = 0;
    std::array<std::uint8_t, 16> external_ip{};
    bool has_port_set = false;
    std::uint16_t port_set_size = 0;
    std::uint16_t first_internal_port = 0;
    bool preserve_parity = false;
};

struct PcpAnnounceResponse {
    PcpResultCode result = PcpResultCode::Success;
    std::uint32_t epoch = 0;
};

std::array<std::uint8_t, 16> PcpIpv4Mapped(std::uint8_t a, std::uint8_t b,
                                           std::uint8_t c, std::uint8_t d) noexcept;
std::size_t EncodePcpAnnounceRequest(
    const std::array<std::uint8_t, 16>& client_ip,
    std::uint8_t* out, std::size_t capacity) noexcept;
std::size_t EncodePcpMapRequest(const PcpMapRequest& request,
                                std::uint8_t* out,
                                std::size_t capacity) noexcept;
PcpDecodeStatus DecodePcpMapResponse(
    const std::uint8_t* data, std::size_t size,
    const PcpMapRequest& request, PcpMapResponse& out) noexcept;
PcpDecodeStatus DecodePcpAnnounceResponse(
    const std::uint8_t* data, std::size_t size,
    PcpAnnounceResponse& out) noexcept;

} // namespace natmap
