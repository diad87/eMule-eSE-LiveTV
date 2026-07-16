// SPDX-License-Identifier: MIT
#pragma once

#include "relay/krp_auth.h"
#include "relay/krp_tcp_wire.h"

#include <array>
#include <cstddef>
#include <string>
#include <vector>

namespace relayedge {

constexpr std::size_t kKrpAuthTokenSize = 32;
using KrpAuthToken = std::array<relay::Byte, kKrpAuthTokenSize>;

// Reads exactly 64 hexadecimal characters plus optional surrounding ASCII
// whitespace. The token is deployment authorization and is never put on wire.
relay::RelayStatus LoadKrpAuthToken(const char* path, KrpAuthToken& token) noexcept;

relay::RelayStatus ComputeKrpTokenProof(
    const KrpAuthToken& token,
    const std::vector<relay::Byte>& transcript,
    const relay::KrpAuthSignature& signature,
    relay::KrpTokenProof& proof) noexcept;

bool ConstantTimeEqual(const relay::KrpTokenProof& left,
                       const relay::KrpTokenProof& right) noexcept;

relay::RelayStatus SecureRandom(relay::Byte* output, std::size_t size) noexcept;

class Ed25519IdentityVerifier final : public relay::IKrpIdentityVerifier {
public:
    bool Verify(const relay::NodeId& public_node_id,
                const relay::Byte* message,
                std::size_t message_size,
                const relay::KrpAuthSignature& signature) noexcept override;
};

} // namespace relayedge
