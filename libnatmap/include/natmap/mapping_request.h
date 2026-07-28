#pragma once

#include "natmap/mapper_result.h"

#include <cstdint>

namespace natmap {

struct MappingRequestContext {
    std::uint64_t request_id = 0;
    std::uint64_t topology_generation = 0;
    MappingOperation operation = MappingOperation::Initial;

    bool IsValid() const noexcept;
};

enum class RequestIssueStatus : std::uint8_t {
    Issued = 0,
    InvalidTopology = 1,
    InvalidOperation = 2,
    Exhausted = 3,
};

struct RequestIssue {
    RequestIssueStatus status = RequestIssueStatus::InvalidTopology;
    MappingRequestContext context{};

    bool IsIssued() const noexcept {
        return status == RequestIssueStatus::Issued &&
               context.IsValid();
    }
};

class MappingRequestSequence {
public:
    explicit MappingRequestSequence(
        std::uint64_t first_request_id = 1) noexcept;
    MappingRequestSequence(const MappingRequestSequence&) = delete;
    MappingRequestSequence& operator=(
        const MappingRequestSequence&) = delete;
    MappingRequestSequence(MappingRequestSequence&&) = delete;
    MappingRequestSequence& operator=(MappingRequestSequence&&) = delete;

    RequestIssue Issue(std::uint64_t topology_generation,
                       MappingOperation operation) noexcept;

private:
    std::uint64_t next_request_id_ = 1;
    bool exhausted_ = false;
};

enum class ResultAcceptance : std::uint8_t {
    Apply = 0,
    Invalid = 1,
    NoPendingRequest = 2,
    StaleTopology = 3,
    StaleRequest = 4,
    OperationMismatch = 5,
};

// Main-thread gate. Only one current request may be armed. A successful result
// is consumed exactly once; mismatched responses never displace a newer one.
class MappingResultGate {
public:
    MappingResultGate() noexcept = default;
    MappingResultGate(const MappingResultGate&) = delete;
    MappingResultGate& operator=(const MappingResultGate&) = delete;
    MappingResultGate(MappingResultGate&&) = delete;
    MappingResultGate& operator=(MappingResultGate&&) = delete;

    bool Arm(const MappingRequestContext& context,
             std::uint64_t current_topology_generation) noexcept;
    ResultAcceptance Consume(
        const MapperResult& result,
        std::uint64_t current_topology_generation) noexcept;

    bool has_pending() const noexcept { return has_pending_; }
    const MappingRequestContext& pending() const noexcept { return pending_; }

private:
    MappingRequestContext pending_{};
    std::uint64_t last_request_id_ = 0;
    bool has_pending_ = false;
};

static_assert(static_cast<std::uint8_t>(RequestIssueStatus::Exhausted) == 3,
              "request issue status persistence contract changed");
static_assert(static_cast<std::uint8_t>(
                  ResultAcceptance::OperationMismatch) == 5,
              "result acceptance persistence contract changed");

} // namespace natmap
