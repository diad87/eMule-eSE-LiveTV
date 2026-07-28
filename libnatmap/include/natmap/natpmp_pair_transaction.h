#pragma once

#include "natmap/natpmp_codec.h"

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
