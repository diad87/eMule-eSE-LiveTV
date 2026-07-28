#include "natmap/natpmp_pair_transaction.h"

namespace natmap {
namespace {

bool IsTransport(
    NatPmpTransport transport,
    NatPmpTransport expected) noexcept {
    return transport == expected;
}

} // namespace

bool NatPmpMapProjection::IsValid() const noexcept {
    return (transport == NatPmpTransport::Tcp ||
            transport == NatPmpTransport::Udp) &&
           response.result_code == 0 &&
           response.internal_port != 0 &&
           response.external_port != 0 &&
           response.lifetime_seconds != 0;
}

bool HasCorrelatedNatPmpMapObservation(
    const NatPmpMapResponse& response,
    std::uint16_t expected_internal_port) noexcept {
    return expected_internal_port != 0 &&
           response.internal_port == expected_internal_port;
}

bool NatPmpPairCommit::IsValid() const noexcept {
    return tcp.IsValid() &&
           IsTransport(tcp.transport, NatPmpTransport::Tcp) &&
           (!has_udp ||
            (udp.IsValid() &&
             IsTransport(udp.transport, NatPmpTransport::Udp)));
}

NatPmpPairFailureDisposition ResolveNatPmpPairFailureDisposition(
    bool initial_operation,
    bool mapping_epoch_reset) noexcept {
    if (mapping_epoch_reset)
        return NatPmpPairFailureDisposition::InvalidatePrevious;
    return initial_operation
        ? NatPmpPairFailureDisposition::ClearProvisional
        : NatPmpPairFailureDisposition::PreservePrevious;
}

NatPmpPairTransaction::NatPmpPairTransaction(
    bool udp_required,
    bool initial_operation) noexcept
    : udp_required_(udp_required),
      initial_operation_(initial_operation),
      status_(NatPmpPairTransactionStatus::AwaitingTcp) {
}

bool NatPmpPairTransaction::StageTcp(
    const NatPmpMapProjection& projection) noexcept {
    if (status_ != NatPmpPairTransactionStatus::AwaitingTcp ||
        !projection.IsValid() ||
        !IsTransport(projection.transport, NatPmpTransport::Tcp))
        return false;

    tcp_ = projection;
    tcp_rollback_target_.transport = NatPmpTransport::Tcp;
    tcp_rollback_target_.internal_port =
        projection.response.internal_port;
    status_ = udp_required_
        ? NatPmpPairTransactionStatus::AwaitingUdp
        : NatPmpPairTransactionStatus::Ready;
    return true;
}

bool NatPmpPairTransaction::StageUdp(
    const NatPmpMapProjection& projection) noexcept {
    if (status_ != NatPmpPairTransactionStatus::AwaitingUdp ||
        !projection.IsValid() ||
        !IsTransport(projection.transport, NatPmpTransport::Udp))
        return false;
    udp_ = projection;
    status_ = NatPmpPairTransactionStatus::Ready;
    return true;
}

void NatPmpPairTransaction::RecordTcpFailure() noexcept {
    if (status_ != NatPmpPairTransactionStatus::AwaitingTcp)
        return;
    ClearStagedProjections();
    tcp_rollback_target_ = NatPmpRollbackTarget{};
    status_ = NatPmpPairTransactionStatus::Failed;
}

void NatPmpPairTransaction::RecordUdpFailure() noexcept {
    if (status_ != NatPmpPairTransactionStatus::AwaitingUdp)
        return;
    ClearStagedProjections();
    status_ = initial_operation_
        ? NatPmpPairTransactionStatus::TcpRollbackRequired
        : NatPmpPairTransactionStatus::Failed;
    if (!initial_operation_)
        tcp_rollback_target_ = NatPmpRollbackTarget{};
}

bool NatPmpPairTransaction::TryCommit(
    NatPmpPairCommit& output) noexcept {
    output = NatPmpPairCommit{};
    if (status_ != NatPmpPairTransactionStatus::Ready)
        return false;

    NatPmpPairCommit candidate{};
    candidate.tcp = tcp_;
    candidate.udp = udp_;
    candidate.has_udp = udp_required_;
    if (!candidate.IsValid()) {
        ClearStagedProjections();
        tcp_rollback_target_ = NatPmpRollbackTarget{};
        status_ = NatPmpPairTransactionStatus::Failed;
        return false;
    }

    output = candidate;
    ClearStagedProjections();
    tcp_rollback_target_ = NatPmpRollbackTarget{};
    status_ = NatPmpPairTransactionStatus::Committed;
    return true;
}

bool NatPmpPairTransaction::GetTcpRollbackTarget(
    NatPmpRollbackTarget& target) const noexcept {
    target = NatPmpRollbackTarget{};
    if (status_ != NatPmpPairTransactionStatus::TcpRollbackRequired ||
        !tcp_rollback_target_.IsValid())
        return false;
    target = tcp_rollback_target_;
    return true;
}

void NatPmpPairTransaction::ClearStagedProjections() noexcept {
    tcp_ = NatPmpMapProjection{};
    udp_ = NatPmpMapProjection{};
}

} // namespace natmap
