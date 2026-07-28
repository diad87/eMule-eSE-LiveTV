#pragma once

#include "natmap/mapper_result.h"

#include <cstdint>

namespace natmap {

// Mechanical projection used only while the three native mapper integrations
// migrate to the strict common-result producer. It contains exactly the values
// consumed by the pre-v9.2 ObserveMappedPorts path and makes no publication or
// verification decision.
struct LegacyMapperObservation {
    MapperKind mapper = MapperKind::None;
    IpAddress external_address{};
    std::uint16_t local_tcp_port = 0;
    std::uint16_t external_tcp_port = 0;
    std::uint16_t local_udp_port = 0;
    std::uint16_t external_udp_port = 0;
    std::uint32_t lifetime_seconds = 0;
    std::uint32_t mapper_epoch = 0;
    bool refresh = false;
};

// Deliberately projects only the legacy-compatible success subset. Strict
// MapperResult validation remains the responsibility of the final producer
// integrations (H/I/J); this bridge must not be used to publish a verified
// endpoint.
bool ProjectLegacyMapperObservation(
    const MapperResult& result,
    LegacyMapperObservation& observation) noexcept;

} // namespace natmap
