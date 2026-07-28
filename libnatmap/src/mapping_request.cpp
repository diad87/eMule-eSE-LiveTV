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

} // namespace

bool MappingRequestContext::IsValid() const noexcept {
    return request_id != 0 &&
           topology_generation != 0 &&
           IsKnownOperation(operation);
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
    if (!has_pending_)
        return ResultAcceptance::NoPendingRequest;
    if (current_topology_generation == 0 ||
        pending_.topology_generation != current_topology_generation) {
        pending_ = {};
        has_pending_ = false;
        return ResultAcceptance::StaleTopology;
    }
    if (!result.IsStructurallyValid())
        return ResultAcceptance::Invalid;

    const MapperResultData& data = result.data();
    if (data.topology_generation != current_topology_generation)
        return ResultAcceptance::StaleTopology;
    if (data.request_id != pending_.request_id)
        return ResultAcceptance::StaleRequest;
    if (data.operation != pending_.operation)
        return ResultAcceptance::OperationMismatch;

    pending_ = {};
    has_pending_ = false;
    return ResultAcceptance::Apply;
}

} // namespace natmap
