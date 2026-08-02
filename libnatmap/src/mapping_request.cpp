#include "natmap/mapping_request.h"

#include <limits>

namespace natmap {
namespace {

bool IsKnownOperation(MappingOperation operation) noexcept {
    switch (operation) {
    case MappingOperation::Initial:
    case MappingOperation::Refresh:
    case MappingOperation::Delete:
        return true;
    }
    return false;
}

bool SameAddress(const IpAddress& left,
                 const IpAddress& right) noexcept {
    return left.family == right.family &&
           left.bytes == right.bytes;
}

} // namespace

bool MappingRequestContext::IsValid() const noexcept {
    return request_id != 0 &&
           topology_generation != 0 &&
           IsKnownOperation(operation);
}

bool MappingRouteIdentity::IsValid() const noexcept {
    return interface_index != 0 &&
           local_address.IsSpecified() &&
           !local_address.IsUnspecified() &&
           gateway_address.IsSpecified() &&
           !gateway_address.IsUnspecified();
}

bool IsMapperResultRouteCurrent(
    const MapperResultData& data,
    const MappingRouteIdentity& current_route) noexcept {
    return current_route.IsValid() &&
           data.request_interface_index != 0 &&
           data.request_interface_index == current_route.interface_index &&
           SameAddress(
               data.request_local_address,
               current_route.local_address) &&
           SameAddress(
               data.gateway.address,
               current_route.gateway_address);
}

MappingRequestSequence::MappingRequestSequence(
    std::uint64_t first_request_id) noexcept
    : next_request_id_(first_request_id),
      exhausted_(first_request_id == 0) {
}

RequestIssue MappingRequestSequence::Issue(
    std::uint64_t topology_generation,
    MappingOperation operation) noexcept {
    RequestIssue issue{};
    if (topology_generation == 0) {
        issue.status = RequestIssueStatus::InvalidTopology;
        return issue;
    }
    if (!IsKnownOperation(operation)) {
        issue.status = RequestIssueStatus::InvalidOperation;
        return issue;
    }
    if (exhausted_) {
        issue.status = RequestIssueStatus::Exhausted;
        return issue;
    }

    issue.status = RequestIssueStatus::Issued;
    issue.context.request_id = next_request_id_;
    issue.context.topology_generation = topology_generation;
    issue.context.operation = operation;
    if (next_request_id_ == std::numeric_limits<std::uint64_t>::max()) {
        exhausted_ = true;
    } else {
        ++next_request_id_;
    }
    return issue;
}

bool MappingResultGate::Arm(
    const MappingRequestContext& context,
    std::uint64_t current_topology_generation) noexcept {
    if (!context.IsValid() ||
        current_topology_generation == 0 ||
        context.topology_generation != current_topology_generation ||
        context.request_id <= last_request_id_)
        return false;

    pending_ = context;
    last_request_id_ = context.request_id;
    has_pending_ = true;
    return true;
}

ResultAcceptance MappingResultGate::Consume(
    const MapperResult& result,
    std::uint64_t current_topology_generation) noexcept {
    if (has_pending_ &&
        current_topology_generation != 0 &&
        pending_.topology_generation == current_topology_generation &&
        !result.IsStructurallyValid())
        return ResultAcceptance::Invalid;
    return ConsumeCorrelatedData(
        result.data(), current_topology_generation, nullptr);
}

ResultAcceptance MappingResultGate::ConsumeForCurrentRoute(
    const MapperResult& result,
    std::uint64_t current_topology_generation,
    const MappingRouteIdentity& current_route) noexcept {
    if (has_pending_ &&
        current_topology_generation != 0 &&
        pending_.topology_generation == current_topology_generation &&
        !result.IsStructurallyValid())
        return ResultAcceptance::Invalid;
    return ConsumeCorrelatedData(
        result.data(), current_topology_generation, &current_route);
}

ResultAcceptance MappingResultGate::ConsumeLegacyEnvelope(
    const MapperResultData& data,
    std::uint64_t current_topology_generation) noexcept {
    const MappingRequestContext envelope{
        data.request_id, data.topology_generation, data.operation};
    if (has_pending_ &&
        current_topology_generation != 0 &&
        pending_.topology_generation == current_topology_generation &&
        !envelope.IsValid())
        return ResultAcceptance::Invalid;
    return ConsumeCorrelatedData(
        data, current_topology_generation, nullptr);
}

ResultAcceptance
MappingResultGate::ConsumeLegacyEnvelopeForCurrentRoute(
    const MapperResultData& data,
    std::uint64_t current_topology_generation,
    const MappingRouteIdentity& current_route) noexcept {
    const MappingRequestContext envelope{
        data.request_id, data.topology_generation, data.operation};
    if (has_pending_ &&
        current_topology_generation != 0 &&
        pending_.topology_generation == current_topology_generation &&
        !envelope.IsValid())
        return ResultAcceptance::Invalid;
    return ConsumeCorrelatedData(
        data, current_topology_generation, &current_route);
}

ResultAcceptance MappingResultGate::ConsumeCorrelatedData(
    const MapperResultData& data,
    std::uint64_t current_topology_generation,
    const MappingRouteIdentity* current_route) noexcept {
    if (!has_pending_)
        return ResultAcceptance::NoPendingRequest;
    if (current_topology_generation == 0 ||
        pending_.topology_generation != current_topology_generation) {
        pending_ = {};
        has_pending_ = false;
        return ResultAcceptance::StaleTopology;
    }
    if (data.topology_generation != current_topology_generation)
        return ResultAcceptance::StaleTopology;
    if (data.request_id != pending_.request_id)
        return ResultAcceptance::StaleRequest;
    if (data.operation != pending_.operation)
        return ResultAcceptance::OperationMismatch;
    if (current_route != nullptr &&
        !IsMapperResultRouteCurrent(data, *current_route)) {
        pending_ = {};
        has_pending_ = false;
        return ResultAcceptance::RouteMismatch;
    }

    pending_ = {};
    has_pending_ = false;
    return ResultAcceptance::Apply;
}

bool MappingResultGate::CancelPending() noexcept {
    if (!has_pending_)
        return false;
    pending_ = {};
    has_pending_ = false;
    return true;
}

} // namespace natmap
