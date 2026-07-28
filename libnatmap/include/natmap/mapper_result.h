#pragma once

#include "natmap/natmap_types.h"

#include <array>
#include <cstdint>

namespace natmap {

// Persisted diagnostic values. Append only; never renumber.
enum class MapperSource : std::uint8_t {
    None = 0,
    PcpCpe = 1,
    PcpUpstream = 2,
    UpnpIgd = 3,
    NatPmp = 4,
};

enum class OwnershipState : std::uint8_t {
    Unknown = 0,
    OwnedByUs = 1,
    Foreign = 2,
    Unverifiable = 3,
};

enum class VerificationState : std::uint8_t {
    NotAttempted = 0,
    Pending = 1,
    Verified = 2,
    Failed = 3,
};

enum class MappingOperation : std::uint8_t {
    Initial = 0,
    Refresh = 1,
    Delete = 2,
};

enum class MappingStatus : std::uint8_t {
    None = 0,
    Created = 1,
    Renewed = 2,
    Deleted = 3,
    Partial = 4,
    Failed = 5,
};

struct TransportMappingResult {
    Transport transport = Transport::Tcp;
    Endpoint local_endpoint{};
    std::uint16_t requested_external_port = 0;
    Endpoint granted_external_endpoint{};
    std::uint32_t lifetime_seconds = 0;
    std::uint64_t effective_expiry_monotonic_ms = 0;

    bool IsStructurallyValid(MapperKind mapper) const noexcept;
    bool IsEmpty() const noexcept;
};

struct MapperResultData {
    MapperKind mapper = MapperKind::None;
    MapperSource source = MapperSource::None;
    Endpoint gateway{};
    std::array<TransportMappingResult, 2> mappings{};
    std::uint8_t mapping_count = 0;
    std::uint32_t mapper_epoch = 0;
    std::array<std::uint8_t, 12> ownership_nonce{};
    std::array<std::uint8_t, 32> ownership_identity_digest{};
    OwnershipState ownership = OwnershipState::Unknown;
    VerificationState verification = VerificationState::NotAttempted;
    std::array<std::uint8_t, 32> evidence_digest{};
    std::uint64_t request_id = 0;
    std::uint64_t generation = 0;
    MappingOperation operation = MappingOperation::Initial;
    MappingStatus status = MappingStatus::None;
    std::uint32_t protocol_result_code = 0;
    ReasonCode reason = ReasonCode::None;
};

// Value-only boundary between mapper workers and the main thread. Construction
// snapshots every byte; callers receive no mutable access to the stored result.
class MapperResult {
public:
    explicit MapperResult(MapperResultData data) noexcept;

    const MapperResultData& data() const noexcept { return data_; }
    bool IsStructurallyValid() const noexcept;
    bool IsCurrent(std::uint64_t expected_generation) const noexcept;
    bool IsPublishable(std::uint64_t expected_generation) const noexcept;

private:
    MapperResultData data_{};
};

static_assert(static_cast<std::uint8_t>(MapperSource::NatPmp) == 4,
              "mapper-source persistence contract changed");
static_assert(static_cast<std::uint8_t>(MappingStatus::Failed) == 5,
              "mapping-status persistence contract changed");
static_assert(sizeof(MapperResultData::ownership_nonce) == 12,
              "PCP ownership nonce must remain 96 bits");
static_assert(sizeof(MapperResultData::evidence_digest) == 32,
              "evidence digest must remain SHA-256 sized");

} // namespace natmap
