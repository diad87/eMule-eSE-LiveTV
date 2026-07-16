// SPDX-License-Identifier: MIT
//
// Carrier-independent Relay/KRP core. This library is deliberately unable to
// open network paths: carriers and public-mode policy live outside the core.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace relay {

using Byte = std::uint8_t;

constexpr std::size_t kNodeIdSize = 32;
constexpr std::size_t kSessionIdSize = 16;
constexpr std::uint16_t kKrpVersionMajor = 1;
constexpr std::uint16_t kKrpVersionMinor = 0;

using NodeId = std::array<Byte, kNodeIdSize>;
using SessionId = std::array<Byte, kSessionIdSize>;

enum class RelayStatus : std::uint8_t {
    Ok = 0,
    Disabled,
    InvalidArgument,
    InvalidState,
    UnsupportedVersion,
    UnsupportedMessage,
    UnsupportedOption,
    Truncated,
    Malformed,
    TooLarge,
    AuthFailed,
    OneRttRequired,
    ReplayDetected,
    ReplayCheckUnavailable,
    StaleEpoch,
    StaleGeneration,
    SequenceError,
    QuotaExceeded,
    TargetForbidden,
    Expired,
};

struct RelayCoreBuildInfo {
    std::uint16_t version_major;
    std::uint16_t version_minor;
    bool wire_enabled;
    bool public_mode_enabled;
};

const RelayCoreBuildInfo& GetRelayCoreBuildInfo() noexcept;
const char* RelayStatusName(RelayStatus status) noexcept;

// P0/P1 invariant: the core cannot authorize a listener, connection or public
// claim. A later phase must replace this compile-time floor with gated state.
bool RelayCoreCanOpenNetwork() noexcept;

} // namespace relay
