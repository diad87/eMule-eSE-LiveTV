#pragma once

#include "natmap/mapping_request.h"

#include <array>
#include <cstdint>

namespace natmap {

struct UpnpTransportObservation {
    Transport transport = Transport::Tcp;
    std::uint16_t local_port = 0;
    std::uint16_t requested_external_port = 0;
    std::uint16_t granted_external_port = 0;
    bool readback_matches = false;
    bool ownership_matches = false;
    bool created_by_operation = false;
};

struct UpnpPairResultInput {
    MappingRequestContext request{};
    IpAddress gateway_address{};
    IpAddress local_address{};
    IpAddress external_address{};
    UpnpTransportObservation tcp{};
    UpnpTransportObservation udp{Transport::Udp};
    std::uint32_t lifetime_seconds = 0;
    std::uint64_t now_monotonic_ms = 0;
    std::array<std::uint8_t, 32> ownership_identity_digest{};
    std::uint32_t failure_protocol_code = 0;
    ReasonCode failure_reason = ReasonCode::InvalidResponse;
};

MapperResultData BuildUpnpPairMapperResult(
    const UpnpPairResultInput& input) noexcept;

bool ShouldRollbackUpnpMappingAfterAtomicFailure(
    const UpnpTransportObservation& observation) noexcept;

} // namespace natmap
