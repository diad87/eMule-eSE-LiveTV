// SPDX-License-Identifier: MIT
//
// libreach — reference library for KEP-1 (reachability vector + connection
// cascade), the abolition of the LowID/HighID binary in Kademlia-derived
// networks. See docs/THESIS_KAD_SIN_LOWID.md §13 and Appendix A.
//
// reach_types.h — the normative on-wire types for the reachability vector
// (`TAG_REACH`, Appendix A). Pure C++17: no MFC, no wxWidgets, no sockets,
// no threads, no Kad. Brand-neutral by design (the spec is `TAG_REACH` /
// `KAD_CAP_*`, never `ESE_*`; eSE keeps internal aliases — thesis §13.4).
//
// Single-translation-unit dependency surface: <cstdint>, <array>, <vector>.
#pragma once

#include <cstddef>
#include <cstdint>
#include <array>
#include <vector>

namespace reach {

using Byte = std::uint8_t;

// ── Fixed wire constants (Appendix A) ─────────────────────────────────────
inline constexpr Byte        kReachLegacyVersion = 1;
inline constexpr Byte        kReachVersion   = 2;   // v2 adds egress + reserved-rdv semantics
inline constexpr std::size_t kKadIdSize      = 16;  // NodeID width (128-bit Kad ID)
inline constexpr std::size_t kIPv4Size       = 4;   // raw IPv4 address octets
inline constexpr std::size_t kMaxRdv         = 3;   // nRdv ∈ [0,3]
inline constexpr std::size_t kRdvTokenSize   = 16;
inline constexpr std::size_t kRdvWireSizeV1  = kKadIdSize + kIPv4Size + 2; // 22
inline constexpr std::size_t kRdvWireSizeV2  = kRdvWireSizeV1 + kRdvTokenSize + 4; // 42
inline constexpr std::size_t kReachHeaderSize = 4;  // version(1) + capflags(2) + nRdv(1)
// Largest *known* v1 vector, excluding any optional trailing TLV (e.g. the
// optional vector signature, appended after the known prefix — Appendix A).
inline constexpr std::size_t kReachMaxKnownSize =
    kReachHeaderSize + kMaxRdv * kRdvWireSizeV2;      // 4 + 126 = 130
inline constexpr std::size_t kReachMaxWireSize = 255; // Kad BSOB length is uint8

// A 128-bit Kademlia NodeID as 16 opaque bytes (big-endian on the wire — the
// same byte order the host's Kad already uses for NodeIDs; libreach never
// interprets it).
using KadId = std::array<Byte, kKadIdSize>;

// ── Capability bitfield (Appendix A, capflags u16, little-endian) ─────────
// Brand-neutral names. bit7..15 are reserved and MUST be 0 when emitting v1.
enum KadCap : std::uint16_t {
    KAD_CAP_V4_TCP_IN   = 1u << 0,  // positive inbound v4 TCP firewall-check
    KAD_CAP_V4_UDP_IN   = 1u << 1,  // verified inbound v4 UDP (UDPFirewallTester or successor)
    KAD_CAP_V6_IN       = 1u << 2,  // positive inbound v6 probe (address travels in TAG 0x66)
    KAD_CAP_PUNCH_2W    = 1u << 3,  // supports 2-way hole-punch (OP_ESE_HOLEPUNCH_REQ/ACK)
    KAD_CAP_PUNCH_3W    = 1u << 4,  // supports being the target of 3-way rendezvous punch
    KAD_CAP_KEEPALIVE   = 1u << 5,  // maintains a pinhole (reachable via rendezvous)
    KAD_CAP_RELAY_OFFER = 1u << 6,  // v1 legacy: service offer (never means client consent)
    KAD_CAP_V6_OUT      = 1u << 7,  // can originate native IPv6 connections
    KAD_CAP_RELAY_CLIENT  = 1u << 8, // consents to using a reserved relay circuit
    KAD_CAP_RELAY_SERVICE = 1u << 9, // volunteers bounded relay service
    KAD_CAP_NETLAB_V1     = 1u << 10, // explicitly joined the bounded beta connectivity cohort
    // bits 11..15 reserved (=0) in v2
};

// Mask of the bits defined by v1. Used to enforce "reserved bits = 0" on emit
// (strict producer) while preserving unknown bits on decode (lenient consumer,
// Postel's law — a future minor version may light reserved bits).
inline constexpr std::uint16_t kKadCapV1KnownMask = 0x007F; // bits 0..6
inline constexpr std::uint16_t kKadCapKnownMask   = 0x07FF; // bits 0..10

// ── Rendezvous anchor (Appendix A: KadID(16) + IPv4(4) + udpPort(2)) ───────
// A `verified` open node with which the publisher holds a live keepalived
// session, able to forward signaling / coordinate punches (generalisation of
// the upstream buddy). Addressed by v4 only in wire v1 — an rdv is by
// definition an open node, and open v4 nodes are plentiful (Appendix A).
struct RdvEntry {
    KadId                         nodeId{};   // 16 opaque NodeID bytes
    std::array<Byte, kIPv4Size>   ipv4{};     // 4 raw address octets, network order
    std::uint16_t                 udpPort = 0; // Kad UDP port; serialized little-endian
                                               // (TAG_SOURCEPORT convention)
    std::array<Byte, kRdvTokenSize> token{};   // opaque reservation voucher, CSPRNG
    std::uint32_t                 expiresAt = 0; // absolute Unix seconds, little-endian
};

// ── The reachability vector ───────────────────────────────────────────────
struct ReachVector {
    Byte                  version  = kReachVersion; // emitted version byte
    std::uint16_t         capFlags = 0;             // KadCap bitfield (raw, as on wire)
    std::vector<RdvEntry> rdv;                      // 0..kMaxRdv anchors
    // Opaque bytes that followed the known v1 prefix on decode (e.g. an
    // optional vector signature TLV). Preserved verbatim so that re-encoding a
    // decoded vector is byte-stable, and so a v1 parser does not destroy data
    // a newer producer appended. Empty for a freshly built v1 vector.
    std::vector<Byte>     trailing;
};

// ── Status / error model ──────────────────────────────────────────────────
// No exceptions cross the codec boundary (C-ABI friendly, host thread models
// are hostile). Every codec entry point returns one of these.
enum class ReachStatus : int {
    Ok = 0,
    Truncated,        // input shorter than the structure it declares
    BadVersionZero,   // version byte 0 is invalid in any wire version
    UnsupportedVersion,
    TooManyRdv,       // nRdv > kMaxRdv
    ReservedBitsSet,  // (emit) a reserved capflag bit was set on a v1 vector
    InvalidReservation,
    MalformedTlv,
    TooLarge,
    BufferTooSmall,   // (emit) output capacity < required serialized length
    NullArgument,     // (emit/decode) a required pointer argument was null
};

// Human-readable status name (stable identifiers; safe for logs and the
// conformance harness). Never returns null.
const char* ReachStatusName(ReachStatus s) noexcept;

// Convenience: the connection-cascade layers (Appendix B). Declared here so
// the codec and the cascade share one vocabulary; the state machine lives in
// a later translation unit.
enum class ReachLayer : int {
    DirectV6 = 0,
    DirectV4,
    Callback,
    Punch2W,
    Punch3W,
    Relay,
    Classic,          // terminal fallback: upstream 0.70b path (never worse)
    Count
};

} // namespace reach
