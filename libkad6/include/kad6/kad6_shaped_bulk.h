// SPDX-License-Identifier: MIT
//
// libkad6 — kad6_shaped_bulk.h: OP_LIVE_BULK_CELL shaped carrier for class-5
// anti-watermark bulk (spec §9.6.1, K6-BULK-005..010, K6-PAD-022/023). The
// shaped carrier makes every class-5 slot byte-indistinguishable at the carrier
// level: one opcode (OP_LIVE_BULK_CELL), one bcmd (BULK_DATA), one total size
// (17000), one length field (16983) — regardless of whether the slot carries
// real DATA, a PADDING filler, a CREDIT ack or a CLOSE. The *kind* lives inside
// the sealed plaintext, never in the header, so a passive observer cannot tell
// data from cover.
//
// Wire layout of the 17000-byte shaped OP_LIVE_BULK_CELL payload:
//   off 0    circ_id          u32 LE   (link-local; rewritten every hop)
//   off 4    bcmd             u8 = 0x01 BULK_DATA (single value for ALL slots)
//   off 5    link_nonce_seq   u64 LE   (distinct per link/direction; HKDF-seeded)
//   off 13   length           u32 LE = 16983 (ALWAYS, even if useful prefix < L)
//   off 17   onion prefix     L bytes, authenticated; L is DERIVED from depth
//   off 17+L tail padding     CSPRNG, regenerated every relay, NOT authenticated
//   off 17000                 exact end (17 header + 16983 = 17000)
//
// Final plaintext (before onion layers), EXACTLY 16414 bytes (K6ShapedBulkPlainV1):
//   version u8=1 | kind u8 | flags u16 LE | stream_id u64 LE |
//   logical_sequence u64 LE | inner_len u32 LE (0..16390) | inner[inner_len] |
//   random_padding  (up to a total of exactly 16414 bytes)
//
// AEAD boundary (IoC — see kad6_crypto.h): libkad6 owns only the shaping and the
// exact-size invariants. The real per-layer onion AEAD (seal/open, tag, nonce
// placement) is the host's. At the codec level the onion is modeled as IDENTITY:
// the 16414-byte plaintext sits at the front of the L-byte prefix and each
// remaining layer contributes exactly 24 opaque bytes (next_link_nonce || tag),
// filled by the injected CSPRNG. Parse, given the known remaining depth, recovers
// the plaintext from the first 16414 bytes of the prefix and NEVER decrypts the
// tail. See kad6_shaped_bulk.cpp header for the full rationale.
#pragma once

#include "kad6/kad6_crypto.h"
#include "kad6/kad6_types.h"

#include <cstdint>
#include <vector>

namespace kad6 {

// ── exact carrier sizes (hard requirements; spec §9.6.1) ────────────────────
constexpr std::size_t   kK6ShapedTotal        = 17000; // whole OP_LIVE_BULK_CELL payload
constexpr std::size_t   kK6ShapedHeaderSize   = 17;    // circ_id+bcmd+nonce+length
constexpr std::uint32_t kK6ShapedLengthField  = 16983; // fixed `length`, == 17000-17
constexpr std::size_t   kK6ShapedPlainSize    = 16414; // final plaintext, exact
constexpr std::size_t   kK6ShapedPlainHeader  = 24;    // 1+1+2+8+8+4
constexpr std::size_t   kK6ShapedInnerMax      = kK6ShapedPlainSize - kK6ShapedPlainHeader; // 16390
constexpr std::size_t   kK6OnionLayerOverhead  = 24;   // next_link_nonce(8) || AEAD tag(16)

// The single carrier command carried by EVERY shaped slot (K6-BULK-008). Value
// 0x01 == BULK_DATA (V8.1.1 §2.1); the real per-slot kind is inside the plaintext.
constexpr Byte kK6ShapedBcmd = 0x01;

static_assert(kK6ShapedHeaderSize + kK6ShapedLengthField == kK6ShapedTotal, "17+16983==17000");
static_assert(kK6ShapedPlainHeader + kK6ShapedInnerMax == kK6ShapedPlainSize, "24+16390==16414");

// Per-slot kind — lives INSIDE the sealed plaintext, never in the carrier header.
enum class K6BulkKind : Byte { Data = 1, Padding = 2, Credit = 3, Close = 4 };

// The final plaintext of one shaped slot (before onion layering). `inner` is the
// useful payload (inner_len bytes); the remainder up to 16414 is random padding
// that the receiver ignores.
struct K6ShapedBulkPlainV1 {
    Byte              version = 1;
    Byte              kind = static_cast<Byte>(K6BulkKind::Data);
    std::uint16_t     flags = 0;
    std::uint64_t     stream_id = 0;
    std::uint64_t     logical_sequence = 0;
    std::vector<Byte> inner;   // inner_len == inner.size(), MUST be <= 16390
};

// The parsed outer header of a shaped frame (diagnostics / re-link support).
struct K6ShapedHeader {
    std::uint32_t circ_id = 0;
    Byte          bcmd = kK6ShapedBcmd;
    std::uint64_t link_nonce_seq = 0;
    std::uint32_t length = kK6ShapedLengthField;
};

// Authenticated onion-prefix length for a given remaining depth. Returns 0 for
// any depth other than 2 or 3 (class-5 is 2- or 3-hop only; K6-BULK-007). The
// formula is fixed to a 16-byte tag suite; a different suite requires a new
// shaped version, never an implicit change here (K6-BULK-009).
//   K6ShapedPrefixLen(2) = 16414 + 48 = 16462
//   K6ShapedPrefixLen(3) = 16414 + 72 = 16486
std::size_t K6ShapedPrefixLen(int depth) noexcept;

// ── plaintext (de)serialization ─────────────────────────────────────────────

// Serialize a plaintext to EXACTLY 16414 bytes. Fills random_padding via
// h.random_bytes (K6-PAD: the fill is CSPRNG). Rejects kind out of 1..4
// (BadValue), inner larger than 16390 (TooLarge), or a null random_bytes hook
// (BadValue).
Kad6Status EncodeK6ShapedPlain(const K6ShapedBulkPlainV1& p, const Kad6CryptoHooks& h,
                               std::vector<Byte>& out);

// Parse a 16414-byte plaintext. Requires exact size (Malformed otherwise),
// version==1 (UnsupportedVersion), kind in 1..4 (Malformed) and inner_len<=16390
// (Malformed). Trailing random_padding is ignored.
Kad6Status DecodeK6ShapedPlain(const Byte* in, std::size_t len,
                               K6ShapedBulkPlainV1& out) noexcept;

// ── shaped frame build / parse / re-link ────────────────────────────────────

// Build a 17000-byte shaped frame carrying `plain` at `depth` (2 or 3), with the
// given link-local circ_id and link_nonce_seq. The onion prefix (L bytes) is
// modeled as identity: the 16414-byte plaintext followed by depth*24 opaque
// per-layer bytes (filled by h.random_bytes), then a CSPRNG tail fills to 17000.
//
// link_nonce_seq is the INITIAL/current sequence value for this (mapping,
// direction, epoch). It MUST be an independent HKDF-derived value, never a shared
// zero start (K6-PAD-022); passing 0 is accepted structurally but is
// non-conformant per spec. Rejects bad depth (BadValue), bad kind (BadValue),
// inner too large (TooLarge), or a null random_bytes hook (BadValue).
Kad6Status BuildK6ShapedBulk(const K6ShapedBulkPlainV1& plain, int depth,
                             std::uint32_t circ_id, std::uint64_t link_nonce_seq,
                             const Kad6CryptoHooks& h, std::vector<Byte>& out);

// Peek the 17-byte outer header WITHOUT depth: validates total size == 17000,
// bcmd == 0x01 and length == 16983 (each else Malformed). Never touches the
// prefix or tail. Handy for diagnostics and for verifying carrier-level
// indistinguishability across kinds.
Kad6Status PeekK6ShapedHeader(const Byte* in, std::size_t len, K6ShapedHeader& out) noexcept;

// Parse a shaped frame given the known remaining `depth` (2 or 3). Enforces:
// total size EXACTLY 17000 (else Malformed), depth in {2,3} (else BadValue),
// bcmd == 0x01 (else Malformed), length == 16983 (else Malformed). Derives
// L = K6ShapedPrefixLen(depth), authenticates/uses ONLY that prefix and recovers
// the plaintext from its first 16414 bytes; NEVER decrypts the tail. Returns the
// plaintext in `out` on Ok, and (optionally) the outer header in `hdr`.
Kad6Status ParseK6ShapedBulk(const Byte* in, std::size_t len, int depth,
                             K6ShapedBulkPlainV1& out,
                             K6ShapedHeader* hdr = nullptr) noexcept;

// Re-link a frame in place for the next hop: rewrite circ_id and link_nonce_seq,
// and regenerate the whole tail via h.random_bytes — WITHOUT touching the
// authenticated onion prefix [17, 17+L) or the fixed bcmd/length (K6-BULK-005,
// K6-PAD-022/023). Validates size==17000, depth in {2,3}, and that the frame is
// already a shaped frame (bcmd/length); else Malformed/BadValue.
Kad6Status RelinkK6ShapedBulk(std::vector<Byte>& frame, int depth,
                              std::uint32_t new_circ_id, std::uint64_t new_link_nonce_seq,
                              const Kad6CryptoHooks& h);

} // namespace kad6
