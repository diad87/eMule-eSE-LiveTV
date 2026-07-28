#pragma once

#include <array>
#include <cstdint>

namespace natmap {

enum class PcpResponseGuardStatus : std::uint8_t {
    Valid = 0,
    Shutdown = 1,
    StaleRequest = 2,
    WrongSource = 3,
    WrongPort = 4,
    WrongNonce = 5,
    InvalidExpectation = 6,
};

struct PcpResponseExpectation {
    std::array<std::uint8_t, 4> source_address{};
    std::uint16_t source_port = 0;
    std::uint64_t request_id = 0;
    std::array<std::uint8_t, 12> nonce{};

    bool IsValid() const noexcept;
};

struct PcpResponseObservation {
    std::array<std::uint8_t, 4> source_address{};
    std::uint16_t source_port = 0;
    std::uint64_t active_request_id = 0;
    std::array<std::uint8_t, 12> nonce{};
    bool shutdown = false;
};

PcpResponseGuardStatus ValidatePcpResponseObservation(
    const PcpResponseExpectation& expectation,
    const PcpResponseObservation& observation) noexcept;

std::uint32_t PcpExchangeTimeoutMilliseconds(
    std::uint8_t attempt) noexcept;
std::uint32_t PcpExchangeMaximumWaitMilliseconds() noexcept;
std::uint16_t PcpExchangeLocalPort(
    std::uint64_t request_id) noexcept;
bool PcpInitialMappingNeedsCleanup(
    bool initial_mapping_in_flight,
    bool has_mapping_identity) noexcept;

} // namespace natmap
