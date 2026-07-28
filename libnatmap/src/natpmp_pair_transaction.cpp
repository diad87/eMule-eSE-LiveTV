#include "natmap/natpmp_pair_transaction.h"

#include <limits>

namespace natmap {
namespace {

bool IsTransport(
    NatPmpTransport transport,
    NatPmpTransport expected) noexcept {
    return transport == expected;
}

bool IsGateway(
    const std::array<std::uint8_t, 4>& address) noexcept {
    return address[0] != 0 && address[0] != 127 &&
           !(address[0] == 169 && address[1] == 254) &&
           address[0] < 224;
}

bool SameCleanupIdentity(
    const NatPmpCleanupMapping& left,
    const NatPmpCleanupMapping& right) noexcept {
    return left.transport == right.transport &&
           left.internal_port == right.internal_port;
}

bool SameCleanupMapping(
    const NatPmpCleanupMapping& left,
    const NatPmpCleanupMapping& right) noexcept {
    return left.transport == right.transport &&
           left.internal_port == right.internal_port &&
           left.external_port == right.external_port;
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

std::uint64_t ConservativeNatPmpLeaseDeadline(
    std::uint64_t observed_before_map_seconds,
    std::uint32_t granted_lifetime_seconds) noexcept {
    if (observed_before_map_seconds == 0 ||
        granted_lifetime_seconds == 0)
        return 0;
    const std::uint64_t maximum =
        (std::numeric_limits<std::uint64_t>::max)();
    return observed_before_map_seconds >
            maximum - granted_lifetime_seconds
        ? maximum
        : observed_before_map_seconds +
            granted_lifetime_seconds;
}

std::uint64_t ResolveNatPmpCleanupGeneration(
    std::uint64_t request_generation,
    bool has_atomic_pair_result,
    bool can_publish_direct,
    bool mapper_epoch_reset,
    bool visible_endpoint_change) noexcept {
    if (request_generation == 0)
        return 0;
    const bool successful_result_advances =
        has_atomic_pair_result && can_publish_direct &&
        visible_endpoint_change;
    const bool reset_result_advances =
        mapper_epoch_reset &&
        (!can_publish_direct || has_atomic_pair_result);
    if (!successful_result_advances && !reset_result_advances)
        return request_generation;
    const std::uint64_t maximum =
        (std::numeric_limits<std::uint64_t>::max)();
    return request_generation == maximum
        ? 0 : request_generation + 1;
}

bool NatPmpCleanupMapping::IsValid() const noexcept {
    return (transport == NatPmpTransport::Tcp ||
            transport == NatPmpTransport::Udp) &&
           internal_port != 0 && external_port != 0;
}

bool NatPmpCleanupProof::IsValid() const noexcept {
    if (!in_process_proof || !IsGateway(gateway_address) ||
        interface_index == 0 ||
        interface_index > kNatPmpMaximumInterfaceIndex ||
        generation == 0 || expires_monotonic_seconds == 0 ||
        mapping_count == 0 || mapping_count > mappings.size())
        return false;
    for (std::size_t index = 0; index < mapping_count; ++index) {
        if (!mappings[index].IsValid())
            return false;
        for (std::size_t previous = 0; previous < index; ++previous)
            if (SameCleanupIdentity(
                    mappings[index], mappings[previous]))
                return false;
    }
    for (std::size_t index = mapping_count;
         index < mappings.size(); ++index)
        if (mappings[index].IsValid())
            return false;
    return true;
}

bool AllowsNatPmpCleanup(
    const NatPmpCleanupProof& proof,
    const NatPmpCleanupRequest& request) noexcept {
    constexpr std::uint64_t kDeliverySafetyMarginSeconds = 1;
    const std::uint64_t latest_safe_observation =
        proof.expires_monotonic_seconds >
                kDeliverySafetyMarginSeconds
            ? proof.expires_monotonic_seconds -
                kDeliverySafetyMarginSeconds
            : 0;
    if (!proof.IsValid() || !IsGateway(request.gateway_address) ||
        request.interface_index == 0 ||
        request.interface_index > kNatPmpMaximumInterfaceIndex ||
        request.generation == 0 ||
        request.observed_monotonic_seconds >=
            latest_safe_observation ||
        !request.mapping.IsValid() ||
        proof.gateway_address != request.gateway_address ||
        proof.interface_index != request.interface_index ||
        proof.generation != request.generation)
        return false;
    for (std::size_t index = 0; index < proof.mapping_count; ++index)
        if (SameCleanupMapping(
                proof.mappings[index], request.mapping))
            return true;
    return false;
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
