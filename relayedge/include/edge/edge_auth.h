// SPDX-License-Identifier: MIT
#pragma once

#include "edge/edge_session_table.h"
#include "relay/krp_auth.h"

namespace relayedge {

// Verifies the carrier-bound KRP transcript before promoting a pre-auth slot.
// Any failure destroys the slot, so callers cannot reserve flows or leases.
relay::RelayStatus AuthenticateEdgeSession(
    EdgeSessionTable& sessions,
    EdgeSessionHandle handle,
    const relay::KrpAuthTranscriptContext& context,
    const relay::KrpAuthResponse& response,
    relay::IKrpIdentityVerifier& verifier,
    const relay::KrpSessionBinding& binding,
    std::uint64_t now_ms) noexcept;

} // namespace relayedge
