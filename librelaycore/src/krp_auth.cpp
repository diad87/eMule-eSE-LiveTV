// SPDX-License-Identifier: MIT
#include "relay/krp_auth.h"

#include "relay/relay_bytes.h"

#include <algorithm>

namespace relay {

namespace {

constexpr char kAuthDomain[] = "eSE-KRP-AUTH-v1";

template <typename Array>
bool IsAllZero(const Array& value) noexcept {
    return std::all_of(value.begin(), value.end(), [](Byte byte) {
        return byte == 0;
    });
}

bool IsKnownCarrier(KrpCarrierProfile profile) noexcept {
    switch (profile) {
        case KrpCarrierProfile::LabTlsTcp:
        case KrpCarrierProfile::WssH1:
        case KrpCarrierProfile::H2:
        case KrpCarrierProfile::H3:
            return true;
    }
    return false;
}

RelayStatus ValidateContext(const KrpAuthTranscriptContext& context) noexcept {
    if (context.version_major != kKrpVersionMajor ||
        context.version_minor > kKrpVersionMinor)
        return RelayStatus::UnsupportedVersion;
    if (!IsKnownCarrier(context.carrier_profile))
        return RelayStatus::UnsupportedOption;
    if (context.challenge_timestamp == 0 || IsAllZero(context.node_id) ||
        IsAllZero(context.client_nonce) || IsAllZero(context.relay_id) ||
        IsAllZero(context.relay_nonce) || IsAllZero(context.carrier_binding) ||
        IsAllZero(context.settings_hash))
        return RelayStatus::InvalidArgument;
    return RelayStatus::Ok;
}

} // namespace

RelayStatus BuildKrpAuthTranscript(const KrpAuthTranscriptContext& context,
                                   std::vector<Byte>& transcript) {
    const RelayStatus validation = ValidateContext(context);
    if (validation != RelayStatus::Ok)
        return validation;

    std::vector<Byte> encoded;
    encoded.reserve(kKrpMaxAuthTranscriptSize);
    RelayByteWriter writer(encoded);
    RelayStatus status = writer.WriteBytes(
        reinterpret_cast<const Byte*>(kAuthDomain), sizeof(kAuthDomain) - 1u);
    if (status != RelayStatus::Ok)
        return status;
    writer.WriteVarint(context.version_major);
    writer.WriteVarint(context.version_minor);
    writer.WriteVarint(static_cast<std::uint64_t>(context.carrier_profile));
    writer.WriteVarint(context.challenge_timestamp);
    status = writer.WriteBytes(context.node_id.data(), context.node_id.size());
    if (status == RelayStatus::Ok)
        status = writer.WriteBytes(context.client_nonce.data(), context.client_nonce.size());
    if (status == RelayStatus::Ok)
        status = writer.WriteBytes(context.relay_id.data(), context.relay_id.size());
    if (status == RelayStatus::Ok)
        status = writer.WriteBytes(context.relay_nonce.data(), context.relay_nonce.size());
    if (status == RelayStatus::Ok)
        status = writer.WriteBytes(context.carrier_binding.data(), context.carrier_binding.size());
    if (status == RelayStatus::Ok)
        status = writer.WriteBytes(context.settings_hash.data(), context.settings_hash.size());
    if (status != RelayStatus::Ok || encoded.size() > kKrpMaxAuthTranscriptSize)
        return status == RelayStatus::Ok ? RelayStatus::TooLarge : status;

    transcript.swap(encoded);
    return RelayStatus::Ok;
}

RelayStatus SignKrpAuthTranscript(const KrpAuthTranscriptContext& context,
                                  INodeIdentitySigner& signer,
                                  KrpAuthResponse& response) {
    if (!signer.IsPersistent())
        return RelayStatus::AuthFailed;
    if (signer.PublicNodeId() != context.node_id)
        return RelayStatus::AuthFailed;

    std::vector<Byte> transcript;
    const RelayStatus status = BuildKrpAuthTranscript(context, transcript);
    if (status != RelayStatus::Ok)
        return status;

    KrpAuthResponse signed_response;
    signed_response.node_id = context.node_id;
    if (!signer.Sign(transcript.data(), transcript.size(), signed_response.signature))
        return RelayStatus::AuthFailed;
    response = signed_response;
    return RelayStatus::Ok;
}

RelayStatus VerifyKrpAuthTranscript(const KrpAuthTranscriptContext& context,
                                    const KrpAuthResponse& response,
                                    IKrpIdentityVerifier& verifier) {
    if (response.node_id != context.node_id || IsAllZero(response.signature))
        return RelayStatus::AuthFailed;

    std::vector<Byte> transcript;
    const RelayStatus status = BuildKrpAuthTranscript(context, transcript);
    if (status != RelayStatus::Ok)
        return status;
    return verifier.Verify(response.node_id,
                           transcript.data(),
                           transcript.size(),
                           response.signature)
               ? RelayStatus::Ok
               : RelayStatus::AuthFailed;
}

} // namespace relay
