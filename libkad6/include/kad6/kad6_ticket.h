// SPDX-License-Identifier: MIT
//
// libkad6 — kad6_ticket.h: K6TargetTicketV1 (spec §14.2). The anti-open-proxy
// capability: an exit issues one ticket per destination it is authorized to
// dial, MAC'd with its own secret and bound to provenance + object + expiry +
// a single connection. A ticket is opaque to the originator; only the issuing
// exit can mint or check it. libkad6 owns the canonical serialization and the
// forbidden-target policy; the HMAC-SHA256 primitive is injected (IoC).
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

// True iff the ticket's target is non-routable / policy-forbidden: the address
// is loopback, RFC1918/ULA LAN, link-local, multicast, broadcast or unspecified
// (IPv4-mapped IPv6 is normalized first), OR the port used by `service` is 0.
// (spec K6-TKT-004.)
bool K6TicketTargetForbidden(const K6TargetTicket& t) noexcept;

// Serialize the signed portion (every field EXCEPT mac). Deterministic; this is
// exactly the byte string the MAC is taken over (after the domain prefix).
Kad6Status K6TicketSerializeSigned(const K6TargetTicket& t, std::vector<Byte>& out);

// mac = HMAC-SHA256(secret, "eSE-Kad6-TargetTicket-v1" || signed-bytes).
// Requires h.hmac_sha256; returns AuthFailed if the hook fails.
Kad6Status K6TicketComputeMac(const Kad6CryptoHooks& h,
                              const Byte* secret, std::size_t secretLen,
                              const K6TargetTicket& t, Byte macOut[kMacSize]);

// Validate ranges (service, provenance_kind, TTL <= 300, forbidden target),
// compute mac into t.mac, then serialize the full ticket (signed || mac) to out.
Kad6Status IssueK6TargetTicket(const Kad6CryptoHooks& h,
                               const Byte* secret, std::size_t secretLen,
                               K6TargetTicket& t, std::vector<Byte>& out);

// Serialize an already-mac'd ticket (round-trip / storage). Does NOT recompute
// the mac — it emits t.mac verbatim.
Kad6Status EncodeK6TargetTicket(const K6TargetTicket& t, std::vector<Byte>& out);

// Parse wire bytes into a ticket. Does NOT verify the mac (use Verify for that).
Kad6Status DecodeK6TargetTicket(const Byte* in, std::size_t len,
                                K6TargetTicket& out, std::size_t* consumed = nullptr) noexcept;

// Full check on receipt: decode, reject version != 1 (UnsupportedVersion),
// recompute the mac and constant-time compare (AuthFailed on mismatch), reject
// an elapsed window nowUnix >= expires_at (Expired), and reject a forbidden
// target (TargetForbidden). Returns Ok only if every check passes; `out` holds
// the decoded ticket on Ok.
Kad6Status VerifyK6TargetTicket(const Kad6CryptoHooks& h,
                                const Byte* secret, std::size_t secretLen,
                                const Byte* in, std::size_t len,
                                std::uint64_t nowUnix, K6TargetTicket& out);

} // namespace kad6
