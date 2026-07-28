#include "natmap/pcp_response_guard.h"

#include <algorithm>

namespace natmap {
namespace {

constexpr std::array<std::uint32_t, 3> kPcpExchangeTimeouts{
    1000, 2000, 4000};
constexpr std::uint16_t kFirstPcpExchangePort = 16384;
constexpr std::uint32_t kPcpExchangePortCount =
    65536u - kFirstPcpExchangePort;

template <std::size_t Size>
bool IsZero(const std::array<std::uint8_t, Size>& value) noexcept {
    return std::all_of(
        value.begin(), value.end(),
        [](std::uint8_t byte) { return byte == 0; });
}

} // namespace

bool PcpResponseExpectation::IsValid() const noexcept {
    return !IsZero(source_address) && source_port != 0
        && request_id != 0 && !IsZero(nonce);
}

PcpResponseGuardStatus ValidatePcpResponseObservation(
    const PcpResponseExpectation& expectation,
    const PcpResponseObservation& observation) noexcept {
    if (!expectation.IsValid())
        return PcpResponseGuardStatus::InvalidExpectation;
    if (observation.shutdown)
        return PcpResponseGuardStatus::Shutdown;
    if (observation.active_request_id != expectation.request_id)
        return PcpResponseGuardStatus::StaleRequest;
    if (observation.source_address != expectation.source_address)
        return PcpResponseGuardStatus::WrongSource;
    if (observation.source_port != expectation.source_port)
        return PcpResponseGuardStatus::WrongPort;
    if (observation.nonce != expectation.nonce)
        return PcpResponseGuardStatus::WrongNonce;
    return PcpResponseGuardStatus::Valid;
}

PcpCleanupCommitStatus EvaluatePcpCleanupCommit(
    bool response_decoded,
    PcpResponseGuardStatus guard_status,
    bool mapper_succeeded,
    std::uint32_t lifetime_seconds) noexcept {
    if (!response_decoded)
        return PcpCleanupCommitStatus::InvalidResponse;
    if (guard_status != PcpResponseGuardStatus::Valid)
        return PcpCleanupCommitStatus::GuardRejected;
    if (!mapper_succeeded)
        return PcpCleanupCommitStatus::MapperRejected;
    return lifetime_seconds == 0
        ? PcpCleanupCommitStatus::Commit
        : PcpCleanupCommitStatus::NonZeroLifetime;
}

std::uint32_t PcpExchangeTimeoutMilliseconds(
    std::uint8_t attempt) noexcept {
    return attempt < kPcpExchangeTimeouts.size()
        ? kPcpExchangeTimeouts[attempt] : 0;
}

std::uint32_t PcpExchangeMaximumWaitMilliseconds() noexcept {
    std::uint32_t total = 0;
    for (std::uint32_t timeout : kPcpExchangeTimeouts)
        total += timeout + timeout / 10;
    return total;
}

std::uint16_t PcpExchangeLocalPort(
    std::uint64_t request_id) noexcept {
    if (request_id == 0 || request_id > kPcpExchangePortCount)
        return 0;
    return static_cast<std::uint16_t>(
        kFirstPcpExchangePort + request_id - 1);
}

bool PcpInitialMappingNeedsCleanup(
    bool initial_mapping_in_flight,
    bool has_mapping_identity) noexcept {
    return initial_mapping_in_flight && has_mapping_identity;
}

} // namespace natmap
