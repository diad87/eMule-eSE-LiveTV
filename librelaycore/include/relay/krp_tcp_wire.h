// SPDX-License-Identifier: MIT
// Canonical bounded KRP v1 payloads needed by the classic TCP data plane.
#pragma once

#include "relay/epr_lease.h"
#include "relay/krp_auth.h"
#include "relay/krp_control.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace relay {

constexpr std::size_t kKrpTokenProofSize = 32;
constexpr std::size_t kKrpMaxFlowDataBytes = 32u * 1024u;
using KrpTokenProof = std::array<Byte, kKrpTokenProofSize>;

enum class KrpClassicFlowKind : std::uint8_t {
    Ed2kServer = 2,
    LegacyTcpInbound = 3,
};

struct KrpHelloPayload {
    std::uint16_t version_major = kKrpVersionMajor;
    std::uint16_t version_minor = kKrpVersionMinor;
    NodeId node_id{};
    KrpAuthNonce client_nonce{};
};

struct KrpAuthChallengePayload {
    KrpRelayId relay_id{};
    KrpAuthNonce relay_nonce{};
    std::uint64_t timestamp = 0;
    KrpSettingsHash settings_hash{};
};

struct KrpAuthResponsePayload {
    KrpAuthResponse response{};
    KrpTokenProof token_proof{};
};

struct KrpAuthOkPayload {
    SessionId session_id{};
    std::uint64_t session_epoch = 0;
    std::uint64_t route_generation = 0;
};

struct KrpLeaseRequestPayload {
    std::uint64_t session_epoch = 0;
    std::uint64_t requested_lease_id = 0;
};

struct KrpLeaseGrantedPayload {
    std::uint64_t session_epoch = 0;
    std::uint64_t lease_id = 0;
    std::uint64_t lease_generation = 0;
    std::array<Byte, 4> public_ipv4{};
    std::uint16_t tcp_port = 0;
};

struct KrpServerBindPayload {
    std::uint64_t session_epoch = 0;
    std::uint64_t route_generation = 0;
    std::uint64_t lease_id = 0;
    std::uint64_t lease_generation = 0;
    std::uint64_t flow_id = 0;
    EprAddressFamily target_family = EprAddressFamily::None;
    EprAddressBytes target_address{};
    std::uint16_t target_port = 0;
};

struct KrpServerStatusPayload {
    std::uint64_t flow_id = 0;
    RelayStatus status = RelayStatus::InvalidState;
};

struct KrpFlowOpenPayload {
    std::uint64_t session_epoch = 0;
    std::uint64_t route_generation = 0;
    std::uint64_t lease_id = 0;
    std::uint64_t lease_generation = 0;
    std::uint64_t flow_id = 0;
    KrpClassicFlowKind kind = KrpClassicFlowKind::LegacyTcpInbound;
    EprAddressFamily remote_family = EprAddressFamily::None;
    EprAddressBytes remote_address{};
    std::uint16_t remote_port = 0;
};

struct KrpFlowDataPayload {
    std::uint64_t flow_id = 0;
    std::uint64_t sequence = 0;
    std::vector<Byte> bytes;
};

struct KrpFlowTerminalPayload {
    std::uint64_t flow_id = 0;
    RelayStatus reason = RelayStatus::Ok;
};

RelayStatus EncodeKrpHello(const KrpHelloPayload& value, std::vector<Byte>& out);
RelayStatus DecodeKrpHello(const Byte* data, std::size_t size, KrpHelloPayload& value) noexcept;
RelayStatus EncodeKrpAuthChallenge(const KrpAuthChallengePayload& value, std::vector<Byte>& out);
RelayStatus DecodeKrpAuthChallenge(const Byte* data, std::size_t size, KrpAuthChallengePayload& value) noexcept;
RelayStatus EncodeKrpAuthResponsePayload(const KrpAuthResponsePayload& value, std::vector<Byte>& out);
RelayStatus DecodeKrpAuthResponsePayload(const Byte* data, std::size_t size, KrpAuthResponsePayload& value) noexcept;
RelayStatus EncodeKrpAuthOk(const KrpAuthOkPayload& value, std::vector<Byte>& out);
RelayStatus DecodeKrpAuthOk(const Byte* data, std::size_t size, KrpAuthOkPayload& value) noexcept;
RelayStatus EncodeKrpLeaseRequest(const KrpLeaseRequestPayload& value, std::vector<Byte>& out);
RelayStatus DecodeKrpLeaseRequest(const Byte* data, std::size_t size, KrpLeaseRequestPayload& value) noexcept;
RelayStatus EncodeKrpLeaseGranted(const KrpLeaseGrantedPayload& value, std::vector<Byte>& out);
RelayStatus DecodeKrpLeaseGranted(const Byte* data, std::size_t size, KrpLeaseGrantedPayload& value) noexcept;
RelayStatus EncodeKrpServerBind(const KrpServerBindPayload& value, std::vector<Byte>& out);
RelayStatus DecodeKrpServerBind(const Byte* data, std::size_t size, KrpServerBindPayload& value) noexcept;
RelayStatus EncodeKrpServerStatus(const KrpServerStatusPayload& value, std::vector<Byte>& out);
RelayStatus DecodeKrpServerStatus(const Byte* data, std::size_t size, KrpServerStatusPayload& value) noexcept;
RelayStatus EncodeKrpFlowOpen(const KrpFlowOpenPayload& value, std::vector<Byte>& out);
RelayStatus DecodeKrpFlowOpen(const Byte* data, std::size_t size, KrpFlowOpenPayload& value) noexcept;
RelayStatus EncodeKrpFlowData(const KrpFlowDataPayload& value, std::vector<Byte>& out);
RelayStatus DecodeKrpFlowData(const Byte* data, std::size_t size, KrpFlowDataPayload& value);
RelayStatus EncodeKrpFlowTerminal(const KrpFlowTerminalPayload& value, std::vector<Byte>& out);
RelayStatus DecodeKrpFlowTerminal(const Byte* data, std::size_t size, KrpFlowTerminalPayload& value) noexcept;

} // namespace relay
