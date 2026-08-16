#include "natmap/pcp_pair_transaction.h"

namespace natmap {
namespace {

bool IsProjectionFor(
    const PcpMapProjection& projection,
    Transport transport) noexcept {
    return projection.IsValid() && projection.transport == transport;
}

bool IsPairEpochCoherent(
    std::uint32_t previous_epoch,
    std::uint32_t current_epoch) noexcept {
    return current_epoch >= previous_epoch
        || previous_epoch - current_epoch <= 1;
}

bool SameAddress(
    const IpAddress& left,
    const IpAddress& right) noexcept {
    return left.family == right.family && left.bytes == right.bytes;
}

} // namespace

bool PcpPairCommit::IsValid() const noexcept {
    return IsProjectionFor(tcp, Transport::Tcp)
        && (!has_udp || (IsProjectionFor(udp, Transport::Udp)
            && SameAddress(tcp.external_address, udp.external_address)));
}

PcpPairTransaction::PcpPairTransaction(
    bool udp_required,
    bool initial_operation) noexcept
    : udp_required_(udp_required),
      initial_operation_(initial_operation),
      status_(PcpPairTransactionStatus::AwaitingTcp) {
}

bool PcpPairTransaction::StageTcp(
    const PcpMapProjection& projection) noexcept {
    if (status_ != PcpPairTransactionStatus::AwaitingTcp
        || !IsProjectionFor(projection, Transport::Tcp))
        return false;

    PcpMappingIdentity rollback_identity{};
    if (InitializePcpMappingIdentity(
            rollback_identity, projection.transport,
            projection.internal_port, projection.nonce)
        != PcpIdentityStatus::Valid)
        return false;

    tcp_ = projection;
    tcp_rollback_identity_ = rollback_identity;
    status_ = udp_required_
        ? PcpPairTransactionStatus::AwaitingUdp
        : PcpPairTransactionStatus::Ready;
    return true;
}

bool PcpPairTransaction::StageUdp(
    const PcpMapProjection& projection) noexcept {
    if (status_ != PcpPairTransactionStatus::AwaitingUdp
        || !IsProjectionFor(projection, Transport::Udp)
        || !IsPairEpochCoherent(tcp_.epoch, projection.epoch)
        || !SameAddress(tcp_.external_address,
                        projection.external_address))
        return false;
    udp_ = projection;
    status_ = PcpPairTransactionStatus::Ready;
    return true;
}

void PcpPairTransaction::RecordTcpFailure() noexcept {
    if (status_ != PcpPairTransactionStatus::AwaitingTcp)
        return;
    ClearStagedProjections();
    tcp_rollback_identity_.Clear();
    status_ = PcpPairTransactionStatus::Failed;
}

void PcpPairTransaction::RecordUdpFailure() noexcept {
    if (status_ != PcpPairTransactionStatus::AwaitingUdp)
        return;
    ClearStagedProjections();
    status_ = initial_operation_
        ? PcpPairTransactionStatus::TcpRollbackRequired
        : PcpPairTransactionStatus::Failed;
    if (!initial_operation_)
        tcp_rollback_identity_.Clear();
}

bool PcpPairTransaction::TryCommit(
    PcpPairCommit& output) noexcept {
    output = PcpPairCommit{};
    if (status_ != PcpPairTransactionStatus::Ready)
        return false;

    PcpPairCommit candidate{};
    candidate.tcp = tcp_;
    candidate.udp = udp_;
    candidate.has_udp = udp_required_;
    if (!candidate.IsValid()) {
        ClearStagedProjections();
        tcp_rollback_identity_.Clear();
        status_ = PcpPairTransactionStatus::Failed;
        return false;
    }

    output = candidate;
    ClearStagedProjections();
    tcp_rollback_identity_.Clear();
    status_ = PcpPairTransactionStatus::Committed;
    return true;
}

bool PcpPairTransaction::GetTcpRollbackIdentity(
    PcpMappingIdentity& identity) const noexcept {
    identity.Clear();
    if (status_ != PcpPairTransactionStatus::TcpRollbackRequired
        || !tcp_rollback_identity_.IsValid())
        return false;
    identity = tcp_rollback_identity_;
    return true;
}

void PcpPairTransaction::ClearStagedProjections() noexcept {
    tcp_ = PcpMapProjection{};
    udp_ = PcpMapProjection{};
}

} // namespace natmap
