// SPDX-License-Identifier: MIT
// KRP authentication transcript bound to the carrier exporter and NodeIdentity.
#pragma once

#include "relay/relay_core.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace relay {

constexpr std::size_t kKrpAuthNonceSize = 32;
constexpr std::size_t kKrpRelayIdSize = 16;
constexpr std::size_t kKrpCarrierBindingSize = 32;
constexpr std::size_t kKrpSettingsHashSize = 32;
constexpr std::size_t kKrpAuthSignatureSize = 64;
constexpr std::size_t kKrpMaxAuthTranscriptSize = 256;

using KrpAuthNonce = std::array<Byte, kKrpAuthNonceSize>;
using KrpRelayId = std::array<Byte, kKrpRelayIdSize>;
using KrpCarrierBinding = std::array<Byte, kKrpCarrierBindingSize>;
using KrpSettingsHash = std::array<Byte, kKrpSettingsHashSize>;
using KrpAuthSignature = std::array<Byte, kKrpAuthSignatureSize>;

enum class KrpCarrierProfile : std::uint8_t {
    LabTlsTcp = 1,
    WssH1 = 2,
    H2 = 3,
    H3 = 4,
};

struct KrpAuthTranscriptContext {
    std::uint16_t version_major = kKrpVersionMajor;
    std::uint16_t version_minor = kKrpVersionMinor;
    KrpCarrierProfile carrier_profile = KrpCarrierProfile::LabTlsTcp;
    std::uint64_t challenge_timestamp = 0;
    NodeId node_id{};
    KrpAuthNonce client_nonce{};
    KrpRelayId relay_id{};
    KrpAuthNonce relay_nonce{};
    KrpCarrierBinding carrier_binding{};
    KrpSettingsHash settings_hash{};
};

struct KrpAuthResponse {
    NodeId node_id{};
    KrpAuthSignature signature{};
};

class INodeIdentitySigner {
public:
    virtual ~INodeIdentitySigner() = default;
    virtual bool IsPersistent() const noexcept = 0;
    virtual const NodeId& PublicNodeId() const noexcept = 0;
    virtual bool Sign(const Byte* message,
                      std::size_t message_size,
                      KrpAuthSignature& signature) noexcept = 0;
};

class IKrpIdentityVerifier {
public:
    virtual ~IKrpIdentityVerifier() = default;
    virtual bool Verify(const NodeId& public_node_id,
                        const Byte* message,
                        std::size_t message_size,
                        const KrpAuthSignature& signature) noexcept = 0;
};

RelayStatus BuildKrpAuthTranscript(const KrpAuthTranscriptContext& context,
                                   std::vector<Byte>& transcript);

RelayStatus SignKrpAuthTranscript(const KrpAuthTranscriptContext& context,
                                  INodeIdentitySigner& signer,
                                  KrpAuthResponse& response);

RelayStatus VerifyKrpAuthTranscript(const KrpAuthTranscriptContext& context,
                                    const KrpAuthResponse& response,
                                    IKrpIdentityVerifier& verifier);

} // namespace relay
