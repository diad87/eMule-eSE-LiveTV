// SPDX-License-Identifier: MIT
//
// libkad6 — kad6_ticket.h: K6TargetTicketV1 (spec §14.2). The anti-open-proxy
// capability: an exit issues one ticket per destination it is authorized to
// dial, MAC'd with its own secret and bound to provenance + object + expiry +
// a single connection. A ticket is opaque to the originator; only the issuing
// exit can mint or check it. libkad6 owns canonical serialization and a
// conservative special-purpose-address deny gate; the host injects both the
// current IPFilter/admin-port policy and HMAC-SHA256.
//
// Wire layout (little-endian; target_endpoint is itself variable-length):
//   version u8=1 | service u8 | flags u16 | lease_id u64 | provenance_kind u8 |
//   reserved u8=0 | provenance_flags u16 | provenance_session u64 |
//   provenance_stream u64 | provenance_seq u64 | provenance_digest[32] |
//   target_endpoint (K6EndpointV1) | object_hash[16] | issued_at u64 |
//   expires_at u64 | max_bytes u64 | max_connections u16 | nonce[16] | mac[32]
//
//   mac = HMAC-SHA256(exit_ticket_secret,
//                     "eSE-Kad6-TargetTicket-v1" || <all fields except mac>)
#pragma once

#include "kad6/kad6_crypto.h"
#include "kad6/kad6_endpoint.h"
#include "kad6/kad6_types.h"

#include <array>
#include <cstdint>
#include <vector>

namespace kad6 {

enum class K6TicketService : Byte { Kad2Udp = 1, Ed2kTcp = 2, Ed2kUdp = 3 };
enum class K6Provenance     : Byte { KadResult = 1, Routing = 2, Pex = 3, Invite = 4, Admin = 5 };

// flags bit 0: reusable. Default (bit clear) = single-use (spec K6-TKT-003).
constexpr std::uint16_t kK6TicketFlagReusable = 0x0001;

// Fixed provenance flag: the signed discovery result originated on native
// Kad6. Clear means the compatibility Kad2 plane (or non-search provenance).
// This lets an exit keep bounded success statistics without adding endpoint
// identities to exported telemetry.
constexpr std::uint16_t kK6ProvenanceFlagNativeKad6 = 0x0001;

// A dial ticket lives at most 5 minutes (spec K6-TKT-001).
constexpr std::uint64_t kK6TicketMaxTtlSeconds = 300;

struct K6TargetTicket {
    Byte          version = 1;
    Byte          service = static_cast<Byte>(K6TicketService::Ed2kTcp);
    std::uint16_t flags = 0;
    std::uint64_t lease_id = 0;
    Byte          provenance_kind = static_cast<Byte>(K6Provenance::KadResult);
    std::uint16_t provenance_flags = 0;
    std::uint64_t provenance_session = 0;
    std::uint64_t provenance_stream = 0;
    std::uint64_t provenance_seq = 0;
    Hash32        provenance_digest{};
    K6Endpoint    target_endpoint;
    Hash16        object_hash{};   // all-zero if not applicable
    std::uint64_t issued_at = 0;
    std::uint64_t expires_at = 0;
    std::uint64_t max_bytes = 0;
    std::uint16_t max_connections = 0;
    std::array<Byte, kNonce16Size> nonce{};
    Hash32        mac{};           // filled by Issue; read by Decode
};

// Host policy gate for the part a standalone codec cannot decide safely:
// IPFilter/operator deny-lists and service-specific administrative ports.
// Returning false denies the target. Issue/Verify fail closed when this hook
// is absent; a target ticket must never silently become a generic proxy grant.
struct K6TargetPolicy {
    void* context = nullptr;
    bool (*allow_target)(void* context, Byte service,
                         const K6Endpoint& endpoint) = nullptr;
    // Called exactly once after canonical decode, MAC, time and target policy
    // all pass. The host must atomically reserve one use keyed by the issuing
    // secret scope + ticket nonce/lease and enforce max_connections. False
    // means replay/exhausted authority. Required by Verify, unused by Issue.
    bool (*consume_use)(void* context, const K6TargetTicket& ticket) = nullptr;
};

// Baseline, side-effect-free deny gate. True iff the target is not an ordinary
// globally reachable unicast endpoint according to the IANA special-purpose
// registries (including TEST-NET/benchmark/CGNAT/translation ranges), or the
// port used by `service` is 0. IPv4-mapped IPv6 is normalized first.
//
// This deliberately does NOT replace K6TargetPolicy: the host must additionally
// apply its current IPFilter and service/admin-port policy at issue and use time.
bool K6TicketTargetForbidden(const K6TargetTicket& t) noexcept;

// Baseline gate + mandatory host policy. Missing policy -> BadValue (fail
// closed); denied target -> TargetForbidden.
Kad6Status K6TicketCheckTarget(const K6TargetTicket& t,
                               const K6TargetPolicy& policy) noexcept;

// Serialize the signed portion (every field EXCEPT mac). Deterministic; this is
// exactly the byte string the MAC is taken over (after the domain prefix).
Kad6Status K6TicketSerializeSigned(const K6TargetTicket& t, std::vector<Byte>& out);

// mac = HMAC-SHA256(secret, "eSE-Kad6-TargetTicket-v1" || signed-bytes).
// Requires h.hmac_sha256; returns AuthFailed if the hook fails.
Kad6Status K6TicketComputeMac(const Kad6CryptoHooks& h,
                              const Byte* secret, std::size_t secretLen,
                              const K6TargetTicket& t, Byte macOut[kMacSize]);

// Validate ranges (service, provenance, quotas, TTL <= 300, endpoint lifetime,
// target policy), compute mac into t.mac, then serialize signed || mac to out.
Kad6Status IssueK6TargetTicket(const Kad6CryptoHooks& h,
                               const K6TargetPolicy& policy,
                               const Byte* secret, std::size_t secretLen,
                               K6TargetTicket& t, std::vector<Byte>& out);

// Serialize an already-mac'd ticket (round-trip / storage). Does NOT recompute
// the mac — it emits t.mac verbatim.
Kad6Status EncodeK6TargetTicket(const K6TargetTicket& t, std::vector<Byte>& out);

// Parse wire bytes into a ticket. Does NOT verify the mac (use Verify for that).
Kad6Status DecodeK6TargetTicket(const Byte* in, std::size_t len,
                                K6TargetTicket& out, std::size_t* consumed = nullptr) noexcept;

// Full check on receipt: decode, reject version != 1 (UnsupportedVersion),
// recompute the mac and constant-time compare (AuthFailed on mismatch), enforce
// issued_at <= nowUnix < expires_at, re-evaluate target policy, then atomically
// consume one authorized use through policy.consume_use. Exact input
// consumption is required: trailing bytes are Malformed. Missing consume hook
// fails closed; a replay/exhausted ticket returns AuthFailed.
Kad6Status VerifyK6TargetTicket(const Kad6CryptoHooks& h,
                                const K6TargetPolicy& policy,
                                const Byte* secret, std::size_t secretLen,
                                const Byte* in, std::size_t len,
                                std::uint64_t nowUnix, K6TargetTicket& out);

} // namespace kad6
