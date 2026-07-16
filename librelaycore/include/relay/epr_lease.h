// SPDX-License-Identifier: MIT
// Endpoint Public Relay lease lifecycle, separate from Kad6 SourceLease.
#pragma once

#include "relay/krp_session.h"

#include <array>
#include <cstddef>
#include <cstdint>

namespace relay {

constexpr std::size_t kEprAddressSize = 16;
constexpr std::size_t kEprProbeNonceSize = 16;
constexpr std::uint64_t kEprMaxLeaseTtlSeconds = 3600;
constexpr std::uint64_t kEprMaxGraceSeconds = 180;

using EprAddressBytes = std::array<Byte, kEprAddressSize>;
using EprProbeNonce = std::array<Byte, kEprProbeNonceSize>;

enum class EprAddressFamily : std::uint8_t {
    None = 0,
    IPv4 = 4,
    IPv6 = 6,
};

enum class EprLeaseClass : std::uint8_t {
    LabOnly = 1,
    PeerShared = 2,
    ServerDedicated = 3,
};

enum class EprLeaseState : std::uint8_t {
    None = 0,
    Requested,
    Allocated,
    Bound,
    Probing,
    Active,
    Grace,
    Draining,
    Revoked,
    Expired,
    Released,
    Failed,
};

struct EprPublicAddress {
    EprAddressFamily family = EprAddressFamily::None;
    EprAddressBytes bytes{};
};

struct EprLeaseRequest {
    std::uint64_t lease_id = 0;
    std::uint64_t generation = 0;
    SessionId session_id{};
    NodeId node_id{};
    EprLeaseClass lease_class = EprLeaseClass::LabOnly;
    bool request_tcp = false;
    bool request_udp = false;
    std::uint64_t issued_at = 0;
    std::uint64_t expires_at = 0;
    std::uint64_t grace_expires_at = 0;
};

struct EprLeaseRecord {
    EprLeaseRequest request{};
    std::uint64_t session_epoch = 0;
    std::uint64_t route_generation = 0;
    EprPublicAddress public_address{};
    std::uint16_t tcp_port = 0;
    std::uint16_t udp_port = 0;
    EprProbeNonce probe_nonce{};
    EprLeaseState state = EprLeaseState::None;
};

class EprLease {
public:
    EprLease() noexcept = default;

    RelayStatus Initialize(const EprLeaseRequest& request,
                           const KrpSession& session,
                           KrpTransportPhase transport_phase) noexcept;
    RelayStatus Allocate(std::uint64_t expected_generation,
                         const EprPublicAddress& address,
                         std::uint16_t tcp_port,
                         std::uint16_t udp_port) noexcept;
    RelayStatus MarkBound() noexcept;
    RelayStatus BeginProbe(const EprProbeNonce& nonce) noexcept;
    RelayStatus CompleteProbe(const EprProbeNonce& nonce, bool succeeded) noexcept;

    RelayStatus Renew(std::uint64_t expected_generation,
                      std::uint64_t new_generation,
                      std::uint64_t now,
                      std::uint64_t new_expires_at,
                      std::uint64_t new_grace_expires_at,
                      const KrpSession& session,
                      KrpTransportPhase transport_phase) noexcept;
    RelayStatus EnterGrace() noexcept;
    RelayStatus ResumeFromGrace(std::uint64_t expected_generation,
                                std::uint64_t now,
                                const KrpSession& session,
                                KrpTransportPhase transport_phase) noexcept;
    RelayStatus BeginDrain() noexcept;
    RelayStatus Revoke() noexcept;
    RelayStatus Release() noexcept;
    RelayStatus MarkFailed() noexcept;
    RelayStatus AdvanceTime(std::uint64_t now) noexcept;

    bool initialized() const noexcept { return initialized_; }
    bool CanAcceptNewTraffic() const noexcept {
        return initialized_ && record_.state == EprLeaseState::Active;
    }
    const EprLeaseRecord& record() const noexcept { return record_; }

private:
    bool initialized_ = false;
    EprLeaseRecord record_{};
};

bool EprPublicAddressAllowed(const EprPublicAddress& address) noexcept;
const char* EprLeaseStateName(EprLeaseState state) noexcept;

} // namespace relay
