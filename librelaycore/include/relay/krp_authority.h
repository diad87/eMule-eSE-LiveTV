// SPDX-License-Identifier: MIT
// Service-specific flow authority. There is deliberately no host/port field.
#pragma once

#include "relay/krp_session.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace relay {

constexpr std::size_t kKrpAuthorityIdSize = 16;
constexpr std::size_t kKrpMaxAuthorityEvidence = 4096;
constexpr std::uint64_t kKrpMaxAuthorityTtlSeconds = 300;
constexpr std::uint64_t kKrpMaxGrantBytes = 1ull << 40; // 1 TiB hard protocol cap
constexpr std::uint16_t kKrpMaxGrantFlows = 1024;

using KrpAuthorityId = std::array<Byte, kKrpAuthorityIdSize>;

enum class KrpService : std::uint8_t {
    Control = 1,
    Ed2kServer = 2,
    LegacyTcpInbound = 3,
    LegacyTcpOutbound = 4,
    Kad6Native = 5,
    FileTransfer = 6,
    LiveControl = 7,
    LiveReliableMedia = 8,
    PortTest = 9,
    Diagnostic = 10,
};

enum class KrpAuthorityKind : std::uint8_t {
    InternalControl = 1,
    SelectedServer = 2,
    InboundLease = 3,
    Kad6TargetTicket = 4,
    RendezvousTicket = 5,
    FilePeerTicket = 6,
    PriorityGrant = 7,
    PortProbe = 8,
    Administrative = 9,
};

struct KrpAuthorityRequest {
    KrpService service = KrpService::Control;
    KrpAuthorityKind kind = KrpAuthorityKind::InternalControl;
    SessionId session_id{};
    std::uint64_t session_epoch = 0;
    std::uint64_t route_generation = 0;
    std::vector<Byte> evidence;
};

struct KrpAuthorityGrant {
    KrpAuthorityId grant_id{};
    KrpService service = KrpService::Control;
    KrpAuthorityKind kind = KrpAuthorityKind::InternalControl;
    std::uint64_t expires_at = 0;
    std::uint64_t max_bytes = 0;
    std::uint16_t max_flows = 0;
    std::uint8_t effective_priority = 5;
};

class IServiceAuthorityVerifier {
public:
    virtual ~IServiceAuthorityVerifier() = default;

    // Implementations adapt existing authorities (for example
    // K6TargetTicket) and atomically consume single-use evidence. They must
    // re-evaluate target policy at use time. The core never accepts a raw
    // destination.
    virtual RelayStatus VerifyAndConsume(const KrpAuthorityRequest& request,
                                         std::uint64_t now,
                                         KrpAuthorityGrant& grant) noexcept = 0;
};

bool IsAuthorityKindAllowed(KrpService service, KrpAuthorityKind kind) noexcept;

RelayStatus AuthorizeKrpService(const KrpSession& session,
                                const KrpAuthorityRequest& request,
                                std::uint64_t now,
                                KrpTransportPhase transport_phase,
                                IServiceAuthorityVerifier& verifier,
                                KrpAuthorityGrant& grant);

} // namespace relay
