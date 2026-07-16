// SPDX-License-Identifier: MIT
#include "edge/edge_auth.h"

#include <algorithm>

namespace relayedge {

namespace {

template <typename Array>
bool IsAllZero(const Array& value) noexcept {
    return std::all_of(value.begin(), value.end(), [](relay::Byte byte) {
        return byte == 0;
    });
}

} // namespace

relay::RelayStatus AuthenticateEdgeSession(
    EdgeSessionTable& sessions,
    EdgeSessionHandle handle,
    const relay::KrpAuthTranscriptContext& context,
    const relay::KrpAuthResponse& response,
    relay::IKrpIdentityVerifier& verifier,
    const relay::KrpSessionBinding& binding,
    std::uint64_t now_ms) noexcept {
    if (context.carrier_profile != relay::KrpCarrierProfile::WssH1 &&
        context.carrier_profile != relay::KrpCarrierProfile::LabTlsTcp) {
        (void)sessions.FailAuthentication(handle, now_ms);
        return relay::RelayStatus::UnsupportedOption;
    }
    if (IsAllZero(context.carrier_binding) || response.node_id != context.node_id ||
        binding.node_id != context.node_id) {
        (void)sessions.FailAuthentication(handle, now_ms);
        return relay::RelayStatus::AuthFailed;
    }
    const relay::RelayStatus verified =
        relay::VerifyKrpAuthTranscript(context, response, verifier);
    if (verified != relay::RelayStatus::Ok) {
        (void)sessions.FailAuthentication(handle, now_ms);
        return verified;
    }
    return sessions.Activate(handle, binding, now_ms);
}

} // namespace relayedge
