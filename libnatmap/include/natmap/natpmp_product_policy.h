#pragma once

#include "natmap/natpmp_pair_transaction.h"

#include <array>
#include <cstddef>
#include <cstdint>

namespace natmap {

struct NatPmpOwnershipPreimage {
    std::array<std::uint8_t, 64> bytes{};
    std::size_t size = 0;
    bool valid = false;
};

NatPmpOwnershipPreimage BuildNatPmpOwnershipPreimage(
    const NatPmpCleanupProof& proof,
    const MapperResultData& data,
    std::uint64_t request_generation,
    std::uint64_t owner_token) noexcept;

bool ApplyNatPmpOwnershipDigest(
    const NatPmpOwnershipPreimage& preimage,
    const std::array<std::uint8_t, 32>& digest,
    const NatPmpCleanupProof& proof,
    std::uint64_t request_generation,
    MapperResultData& data) noexcept;

std::uint64_t ResolveNatPmpCleanupGeneration(
    const NatPmpCleanupProof& proof,
    std::uint64_t requested_generation) noexcept;

} // namespace natmap
