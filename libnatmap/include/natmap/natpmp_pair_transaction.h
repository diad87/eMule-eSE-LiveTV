#pragma once
#include "natmap/mapper_result.h"

#include "natmap/natpmp_codec.h"
#include "natmap/natpmp_gateway_policy.h"

#include <array>
#include <cstddef>
#include <cstdint>

namespace natmap {

struct NatPmpMapProjection {
    NatPmpTransport transport = NatPmpTransport::Tcp;
    std::uint16_t requested_external_port = 0;
    NatPmpMapResponse response{};

    bool IsValid() const noexcept;
};

bool HasCorrelatedNatPmpMapObservation(
    const NatPmpMapResponse& response,
    std::uint16_t expected_internal_port) noexcept;

struct NatPmpPairCommit {
    NatPmpMapProjection tcp{};
    NatPmpMapProjection udp{};
    bool has_udp = false;

    bool IsValid() const noexcept;
};

enum class NatPmpPairTransactionStatus : std::uint8_t {
    AwaitingTcp = 0,
    AwaitingUdp = 1,
    Ready = 2,
    Failed = 3,
    TcpRollbackRequired = 4,
    Committed = 5,
};

enum class NatPmpPairFailureDisposition : std::uint8_t {
    ClearProvisional = 0,
    PreservePrevious = 1,
    InvalidatePrevious = 2,
};

NatPmpPairFailureDisposition ResolveNatPmpPairFailureDisposition(
    bool initial_operation,
    bool mapping_epoch_reset) noexcept;

std::uint64_t ConservativeNatPmpLeaseDeadline(
    std::uint64_t observed_before_map_seconds,
    std::uint32_t granted_lifetime_seconds) noexcept;

std::uint64_t ResolveNatPmpCleanupGeneration(
    std::uint64_t request_generation,
    bool has_atomic_pair_result,
    bool can_publish_direct,
    bool mapper_epoch_reset,
    bool visible_endpoint_change) noexcept;

struct NatPmpCleanupMapping {
    NatPmpTransport transport = NatPmpTransport::Tcp;
    std::uint16_t internal_port = 0;
    std::uint16_t external_port = 0;

    bool IsValid() const noexcept;
};

struct NatPmpCleanupProof {
    std::array<std::uint8_t, 4> gateway_address{};
    std::uint32_t interface_index = 0;
    std::uint64_t generation = 0;
    std::uint64_t expires_monotonic_seconds = 0;
    std::array<NatPmpCleanupMapping, 3> mappings{};
    std::size_t mapping_count = 0;
    bool in_process_proof = false;

    bool IsValid() const noexcept;
};

struct NatPmpCleanupRequest {
    std::array<std::uint8_t, 4> gateway_address{};
    std::uint32_t interface_index = 0;
    std::uint64_t generation = 0;
    std::uint64_t observed_monotonic_seconds = 0;
    NatPmpCleanupMapping mapping{};
};

struct NatPmpCleanupContext {
    std::array<std::uint8_t, 4> gateway_address{};
    std::uint32_t interface_index = 0;
    std::uint64_t generation = 0;
    std::uint64_t observed_monotonic_seconds = 0;
};

struct NatPmpCleanupPlan {
    std::array<NatPmpCleanupMapping, 3> mappings{};
    std::size_t mapping_count = 0;

    bool IsEmpty() const noexcept { return mapping_count == 0; }
};

bool AllowsNatPmpCleanup(
    const NatPmpCleanupProof& proof,
    const NatPmpCleanupRequest& request) noexcept;
NatPmpCleanupPlan TakeNatPmpCleanupPlan(
    NatPmpCleanupProof& proof,
    const NatPmpCleanupContext& context) noexcept;

bool CorrelatesNatPmpOwnershipProof(
    const NatPmpCleanupProof& proof,
    const MapperResultData& data,
    std::uint64_t request_generation) noexcept;
bool ApplyNatPmpOwnershipProof(
    const NatPmpCleanupProof& proof,
    std::uint64_t request_generation,
    const std::array<std::uint8_t, 32>& identity_digest,
    MapperResultData& data) noexcept;

struct NatPmpRollbackTarget {
    NatPmpTransport transport = NatPmpTransport::Tcp;
    std::uint16_t internal_port = 0;

    bool IsValid() const noexcept {
        return internal_port != 0 &&
               (transport == NatPmpTransport::Tcp ||
                transport == NatPmpTransport::Udp);
    }
};

class NatPmpPairTransaction final {
public:
    NatPmpPairTransaction(
        bool udp_required,
        bool initial_operation) noexcept;

    bool StageTcp(const NatPmpMapProjection& projection) noexcept;
    bool StageUdp(const NatPmpMapProjection& projection) noexcept;
    void RecordTcpFailure() noexcept;
    void RecordUdpFailure() noexcept;

    bool TryCommit(NatPmpPairCommit& output) noexcept;
    bool GetTcpRollbackTarget(
        NatPmpRollbackTarget& target) const noexcept;

    NatPmpPairTransactionStatus status() const noexcept {
        return status_;
    }

private:
    void ClearStagedProjections() noexcept;

    bool udp_required_;
    bool initial_operation_;
    NatPmpPairTransactionStatus status_;
    NatPmpMapProjection tcp_{};
    NatPmpMapProjection udp_{};
    NatPmpRollbackTarget tcp_rollback_target_{};
};

} // namespace natmap
