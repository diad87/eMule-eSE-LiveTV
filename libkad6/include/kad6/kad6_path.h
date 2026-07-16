// SPDX-License-Identifier: MIT
//
// Strict three-hop path selection for Kad6.  This module is deliberately
// transport-agnostic: the host supplies authenticated/live candidates and a
// CSPRNG callback; libkad6 enforces identity and network diversity.
#pragma once

#include "kad6/kad6_address.h"
#include "kad6/kad6_types.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace kad6 {

constexpr std::size_t kK6StrictHopCount = 3;
constexpr std::size_t kK6PathMaxCandidates = 64;

using K6PathRandom = bool (*)(void* context, Byte* out, std::size_t length);

struct K6PathCandidate {
    std::array<Byte, kEd25519PubSize> node_pub{};
    Hash16 user_hash{};
    Kad6Address address;
    std::uint32_t asn = 0;
    std::uint32_t operator_group = 0; // zero means not classified
    std::uint32_t weight = 1;

    bool authenticated = false;
    bool endpoint_verified = false;
    bool connected = false;
    bool supports_strict3 = false;
    bool supports_shaping = false;
    bool supports_exit = false;
    bool has_capacity = false;
    bool current_content_peer = false;
};

enum class K6PathStatus {
    Ok = 0,
    NullArgument,
    TooManyCandidates,
    NoEligibleGuard,
    PinnedGuardUnavailable,
    NotDiverse,
    RandomFailed
};

struct K6StrictPath {
    std::array<std::size_t, kK6StrictHopCount> index{}; // guard, middle, exit
};

// `pinned_guard` is an optional 32-byte NodeIdentity.  When supplied it is a
// hard pin: selection does not silently rotate to another guard.  The caller
// may explicitly retry without the pin after recording guard failure.
K6PathStatus SelectK6StrictPath(const std::vector<K6PathCandidate>& candidates,
                                const Byte* pinned_guard,
                                K6PathRandom random,
                                void* random_context,
                                K6StrictPath& out) noexcept;

const char* K6PathStatusName(K6PathStatus status) noexcept;

} // namespace kad6
