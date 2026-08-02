#pragma once

#include "natmap/natmap_types.h"

#include <array>
#include <cstdint>

namespace natmap {

enum class PcpIdentityStatus : std::uint8_t {
    Valid = 0,
    Empty = 1,
    InvalidTransport = 2,
    InvalidPort = 3,
    ZeroNonce = 4,
    IdentityMismatch = 5,
    CorruptIdentity = 6,
};

struct PcpMappingIdentity {
    Transport transport = static_cast<Transport>(0);
    std::uint16_t internal_port = 0;
    std::array<std::uint8_t, 12> nonce{};

    bool IsEmpty() const noexcept;
    bool IsValid() const noexcept;
    bool Matches(
        Transport expected_transport,
        std::uint16_t expected_internal_port) const noexcept;
    void Clear() noexcept;
};

PcpIdentityStatus InitializePcpMappingIdentity(
    PcpMappingIdentity& identity,
    Transport transport,
    std::uint16_t internal_port,
    const std::array<std::uint8_t, 12>& nonce) noexcept;

PcpIdentityStatus ValidatePcpMappingIdentity(
    const PcpMappingIdentity& identity,
    Transport expected_transport,
    std::uint16_t expected_internal_port) noexcept;

} // namespace natmap
