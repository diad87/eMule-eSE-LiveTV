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
    MapperSource mapper_source = MapperSource::None;
    IpAddress gateway_address{};
    IpAddress external_address{};
    std::uint16_t local_tcp_port = 0;
    std::uint16_t external_tcp_port = 0;
    std::uint16_t local_udp_port = 0;
    std::uint16_t external_udp_port = 0;
    std::uint32_t lifetime_seconds = 0;
    std::uint32_t mapper_epoch = 0;
    std::uint64_t topology_generation = 0;
    bool mapper_epoch_reset = false;
    bool refresh = false;
};

struct MapperTopologyIdentity {
    MapperKind mapper = MapperKind::None;
    MapperSource mapper_source = MapperSource::None;
    IpAddress gateway_address{};
    IpAddress external_address{};
    std::uint16_t local_tcp_port = 0;
    std::uint16_t external_tcp_port = 0;
    std::uint16_t local_udp_port = 0;
    std::uint16_t external_udp_port = 0;

    bool IsValid() const noexcept;
};

enum class TopologyGenerationDisposition : std::uint8_t {
    RejectInvalid = 0,
    RejectStale = 1,
    Keep = 2,
    Advance = 3,
    RejectOverflow = 4,
};

struct TopologyGenerationDecision {
    TopologyGenerationDisposition disposition =
        TopologyGenerationDisposition::RejectInvalid;
    std::uint64_t generation = 0;
};

enum class LegacyMapperAdmissionStatus : std::uint8_t {
    Accepted = 0,
    InvalidResult = 1,
    StaleGeneration = 2,
    UnsupportedResult = 3,
    UnroutableEndpoint = 4,
};

// Deliberately projects only the legacy-compatible success subset. Strict
// MapperResult validation remains the responsibility of the final producer
// integrations (H/I/J); this bridge must not be used to publish a verified
// endpoint.
bool ProjectLegacyMapperObservation(
    const MapperResult& result,
    LegacyMapperObservation& observation) noexcept;

// Strict fail-closed boundary used by the product integration. The output is
// committed only after validation, generation correlation, projection and
// route-safety checks all succeed.
LegacyMapperAdmissionStatus AdmitLegacyMapperObservation(
    const MapperResult& result,
    std::uint64_t expected_topology_generation,
    LegacyMapperObservation& observation) noexcept;

// A mapper-proven epoch reset is a topology boundary even when the newly
// granted address and ports are byte-for-byte identical to the old pair.
bool LegacyObservationAllowsSilentRenewal(
    const LegacyMapperObservation& observation) noexcept;

bool BuildMapperTopologyIdentity(
    const LegacyMapperObservation& observation,
    MapperTopologyIdentity& identity) noexcept;

TopologyGenerationDecision ResolveTopologyGeneration(
    std::uint64_t current_generation,
    const MapperTopologyIdentity& current_identity,
    const LegacyMapperObservation& observation) noexcept;

} // namespace natmap
