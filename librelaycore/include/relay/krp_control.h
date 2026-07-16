// SPDX-License-Identifier: MIT
// Minimal KRP v1 control-frame envelope. Message values remain
// `reserved-proposed`; no network code emits them in P1.
#pragma once

#include "relay/relay_core.h"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace relay {

enum class KrpMessageType : std::uint64_t {
    KRP_HELLO = 0x00,
    KRP_WELCOME = 0x01,
    KRP_AUTH_CHALLENGE = 0x02,
    KRP_AUTH_RESPONSE = 0x03,
    KRP_AUTH_OK = 0x04,
    KRP_CAPABILITIES = 0x05,
    KRP_SETTINGS = 0x06,
    KRP_RESUME_PROBE = 0x07,
    KRP_RESUME_COMMIT = 0x08,
    KRP_RESUME_RESULT = 0x09,
    KRP_PRIORITY_GRANT = 0x0A,

    KRP_LEASE_REQUEST = 0x10,
    KRP_LEASE_GRANTED = 0x11,
    KRP_LEASE_RENEW = 0x12,
    KRP_LEASE_STATUS = 0x13,
    KRP_LEASE_RELEASE = 0x14,
    KRP_LEASE_REVOKED = 0x15,

    KRP_FLOW_OPEN = 0x20,
    KRP_FLOW_ACCEPT = 0x21,
    KRP_FLOW_REJECT = 0x22,
    KRP_FLOW_CLOSE = 0x23,
    KRP_FLOW_RESET = 0x24,
    KRP_FLOW_PRESSURE = 0x25,
    // WSS has no native independent byte streams. KRP v1 therefore uses this
    // bounded envelope only on streamless carriers; H2/H3 carry bytes after
    // FlowPreamble directly on the selected stream.
    KRP_FLOW_DATA = 0x26,

    KRP_SERVER_BIND = 0x40,
    KRP_SERVER_STATUS = 0x41,
    KRP_LEGACY_ENDPOINT_UPDATE = 0x42,
    KRP_CLASSIC_REACHABILITY = 0x43,
    KRP_PEER_PROBE_CHALLENGE = 0x44,
    KRP_PEER_PROBE_RESPONSE = 0x45,
    KRP_REACHABILITY_STATUS = 0x46,
    KRP_SERVER_CANDIDATE_SET = 0x47,

    KRP_PING = 0x50,
    KRP_PONG = 0x51,
    KRP_STATS = 0x52,
    KRP_GOAWAY = 0x60,
    KRP_ERROR = 0x61,
};

enum KrpControlFlag : std::uint64_t {
    kKrpFlagCritical = 1ull << 0,
    kKrpFlagIdempotent = 1ull << 1,
    kKrpFlagRequiresOneRtt = 1ull << 2,
    kKrpFlagHasSessionEpoch = 1ull << 3,
    kKrpFlagHasRouteGeneration = 1ull << 4,
    kKrpFlagHasLeaseGeneration = 1ull << 5,
};

constexpr std::uint64_t kKrpKnownControlFlags =
    kKrpFlagCritical | kKrpFlagIdempotent | kKrpFlagRequiresOneRtt |
    kKrpFlagHasSessionEpoch | kKrpFlagHasRouteGeneration |
    kKrpFlagHasLeaseGeneration;
constexpr std::size_t kKrpMaxControlPayload = 64u * 1024u;

struct KrpControlFrame {
    std::uint64_t type = 0;
    std::uint64_t flags = 0;
    std::vector<Byte> payload;
};

bool IsReservedKrpMessageType(std::uint64_t type) noexcept;

RelayStatus EncodeKrpControlFrame(const KrpControlFrame& frame,
                                  std::vector<Byte>& output);

// Decodes one frame and returns its byte count through `consumed`. Trailing
// bytes are left for the caller's stream parser. On failure, `frame` is reset
// and `consumed` is zero.
RelayStatus DecodeKrpControlFrame(const Byte* input,
                                  std::size_t input_size,
                                  KrpControlFrame& frame,
                                  std::size_t& consumed);

} // namespace relay
