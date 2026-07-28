#pragma once

#include "natmap/pcp_codec.h"
#include "natmap/pcp_mapping_identity.h"

#include <array>
#include <cstdint>

namespace natmap {

enum class PcpMapProjectionStatus : std::uint8_t {
    Valid = 0,
    InvalidIdentity = 1,
    Rejected = 2,
    WrongNonce = 3,
    WrongProtocol = 4,
    WrongInternalPort = 5,
    InvalidGrantedPort = 6,
    InvalidLifetime = 7,
    InvalidExternalAddress = 8,
};

struct PcpMapProjection {
    Transport transport = static_cast<Transport>(0);
    std::uint16_t internal_port = 0;
    std::uint16_t requested_external_port = 0;
    std::uint16_t granted_external_port = 0;
    IpAddress external_address{};
    std::uint32_t lifetime_seconds = 0;
    std::uint32_t epoch = 0;
    std::array<std::uint8_t, 12> nonce{};

    bool IsValid() const noexcept;
};

struct PcpMapProjectionResult {
    PcpMapProjectionStatus status =
        PcpMapProjectionStatus::InvalidIdentity;
    PcpMapProjection value{};

    bool IsProjected() const noexcept {
        return status == PcpMapProjectionStatus::Valid
            && value.IsValid();
    }
};

PcpMapProjectionResult ProjectPcpMapResponse(
    const PcpMappingIdentity& identity,
    std::uint16_t requested_external_port,
    const PcpMapResponse& response) noexcept;

} // namespace natmap
