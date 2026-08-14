#include "natmap/natpmp_product_policy.h"

#include <algorithm>
#include <limits>

namespace natmap {
namespace {

void AppendInteger(
    NatPmpOwnershipPreimage& output,
    std::uint64_t value,
    std::size_t width) noexcept {
    if (width > 8 || output.size > output.bytes.size() - width) {
        output = NatPmpOwnershipPreimage{};
        return;
    }
    for (std::size_t index = 0; index < width; ++index)
        output.bytes[output.size + width - 1 - index] =
            static_cast<std::uint8_t>(value >> (index * 8));
    output.size += width;
}

} // namespace

NatPmpOwnershipPreimage BuildNatPmpOwnershipPreimage(
    const NatPmpCleanupProof& proof,
    const MapperResultData& data,
    std::uint64_t request_generation,
    std::uint64_t owner_token) noexcept {
    NatPmpOwnershipPreimage output{};
    if (owner_token == 0 ||
        !CorrelatesNatPmpOwnershipProof(
            proof, data, request_generation))
        return output;

    static constexpr std::uint8_t domain[] = {
        'e','s','e','.','n','a','t','p','m','p','.',
        'o','w','n','e','r','.','v','1'
    };
    std::copy(std::begin(domain), std::end(domain), output.bytes.begin());
    output.size = sizeof(domain);
    std::copy(proof.gateway_address.begin(), proof.gateway_address.end(),
        output.bytes.begin() + output.size);
    output.size += proof.gateway_address.size();
    AppendInteger(output, owner_token, 8);
    AppendInteger(output, proof.interface_index, 4);
    AppendInteger(output, proof.generation, 8);
    for (const Transport transport : {Transport::Tcp, Transport::Udp})
        for (std::size_t index = 0; index < data.mapping_count; ++index)
            if (data.mappings[index].transport == transport) {
                AppendInteger(output,
                    static_cast<std::uint64_t>(transport), 1);
                AppendInteger(output,
                    data.mappings[index].local_endpoint.port, 2);
                AppendInteger(output,
                    data.mappings[index].granted_external_endpoint.port, 2);
            }
    output.valid = output.size != 0;
    return output;
}

bool ApplyNatPmpOwnershipDigest(
    const NatPmpOwnershipPreimage& preimage,
    const std::array<std::uint8_t, 32>& digest,
    const NatPmpCleanupProof& proof,
    std::uint64_t request_generation,
    MapperResultData& data) noexcept {
    if (!preimage.valid || preimage.size == 0 ||
        preimage.size > preimage.bytes.size() ||
        !CorrelatesNatPmpOwnershipProof(
            proof, data, request_generation) ||
        std::none_of(digest.begin(), digest.end(),
            [](std::uint8_t byte) { return byte != 0; }))
        return false;
    data.ownership_identity_digest = digest;
    data.ownership = OwnershipState::OwnedByUs;
    return true;
}

std::uint64_t ResolveNatPmpCleanupGeneration(
    const NatPmpCleanupProof& proof,
    std::uint64_t requested_generation) noexcept {
    if (!proof.IsValid())
        return requested_generation;
    if (requested_generation == 0 ||
        proof.generation == requested_generation)
        return proof.generation;
    const std::uint64_t maximum =
        (std::numeric_limits<std::uint64_t>::max)();
    return requested_generation != maximum &&
            proof.generation == requested_generation + 1
        ? proof.generation : requested_generation;
}

} // namespace natmap
