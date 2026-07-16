// SPDX-License-Identifier: MIT
//
// libkad6 — fixed-size class-5 shaped bulk carrier.
//
// The carrier codec deliberately treats the onion prefix as OPAQUE bytes. It
// never models AEAD as identity, never places plaintext directly on the wire,
// and never decodes a frame prefix as plaintext. The host must seal/open each
// onion layer with its real AEAD implementation.
#pragma once

#include "kad6/kad6_crypto.h"
#include "kad6/kad6_types.h"

#include <cstdint>
#include <limits>
#include <vector>

namespace kad6 {

constexpr std::size_t   kK6ShapedTotal         = 17000;
constexpr std::size_t   kK6ShapedHeaderSize    = 17;
constexpr std::uint32_t kK6ShapedLengthField   = 16983;
// 24 bytes of class-5 metadata plus one complete legacy BulkData payload
// (30-byte header + 16384-byte FEC symbol).  The previous 16414-byte value
// accidentally left only 16390 bytes for `inner`, so no real bulk symbol
// could ever enter the shaped carrier.
constexpr std::size_t   kK6ShapedPlainSize     = 16438;
constexpr std::size_t   kK6ShapedPlainHeader   = 24;
constexpr std::size_t   kK6ShapedInnerMax      = kK6ShapedPlainSize - kK6ShapedPlainHeader;
constexpr std::size_t   kK6OnionLayerOverhead  = 24; // next_link_nonce(8) + AEAD tag(16)
constexpr Byte          kK6ShapedBcmd           = 0x01; // BULK_DATA for every kind
constexpr std::uint64_t kK6ShapedPaddingSentinel =
    (std::numeric_limits<std::uint64_t>::max)();

static_assert(kK6ShapedHeaderSize + kK6ShapedLengthField == kK6ShapedTotal,
              "17+16983==17000");
static_assert(kK6ShapedPlainHeader + kK6ShapedInnerMax == kK6ShapedPlainSize,
              "24+16414==16438");

enum class K6BulkKind : Byte { Data = 1, Padding = 2, Credit = 3, Close = 4 };

// Terminal-only plaintext, before the origin seals it or after the terminal
// authenticates and opens the final onion layer.
struct K6ShapedBulkPlainV1 {
    Byte              version = 1;
    Byte              kind = static_cast<Byte>(K6BulkKind::Data);
    std::uint16_t     flags = 0;
    std::uint64_t     stream_id = 0;
    std::uint64_t     logical_sequence = 0;
    std::vector<Byte> inner;
};

struct K6ShapedHeader {
    std::uint32_t circ_id = 0;
    Byte          bcmd = kK6ShapedBcmd;
    std::uint64_t link_nonce_seq = 0;
    std::uint32_t length = kK6ShapedLengthField;
};

// Size of the authenticated opaque prefix at the current link. A circuit is
// negotiated with 2 or 3 hops, but after a relay peels one layer there may be
// only 1 or 2 remaining. Hence this wire helper accepts remaining_layers 1..3.
// Route construction must still reject total hop counts outside 2..3.
std::size_t K6ShapedPrefixLen(int remaining_layers) noexcept;

// Terminal-only plaintext codec. Encode fills terminal padding with CSPRNG.
Kad6Status EncodeK6ShapedPlain(const K6ShapedBulkPlainV1& p,
                               const Kad6CryptoHooks& h,
                               std::vector<Byte>& out);
Kad6Status DecodeK6ShapedPlain(const Byte* in, std::size_t len,
                               K6ShapedBulkPlainV1& out) noexcept;

// Build one link carrier around an already AEAD-sealed/authenticated opaque
// prefix. prefix_len MUST equal K6ShapedPrefixLen(remaining_layers). The host
// supplies a non-zero, link-local nonce sequence and MUST enforce monotonicity
// and replay state. The unauthenticated tail is generated here with CSPRNG.
Kad6Status BuildK6ShapedCarrier(const Byte* authenticated_prefix,
                                std::size_t prefix_len,
                                int remaining_layers,
                                std::uint32_t circ_id,
                                std::uint64_t link_nonce_seq,
                                const Kad6CryptoHooks& h,
                                std::vector<Byte>& out);

// Validate and read only the fixed outer header. No onion bytes are interpreted.
Kad6Status PeekK6ShapedHeader(const Byte* in, std::size_t len,
                              K6ShapedHeader& out) noexcept;

// Validate the carrier and copy exactly its opaque authenticated prefix. This
// function DOES NOT authenticate it. On success, the host MUST AEAD-open the
// prefix for this mapping/direction/nonce before either forwarding the returned
// inner prefix or passing final plaintext to DecodeK6ShapedPlain.
Kad6Status ExtractK6ShapedPrefix(const Byte* in, std::size_t len,
                                 int remaining_layers,
                                 std::vector<Byte>& authenticated_prefix,
                                 K6ShapedHeader* hdr = nullptr);

// There is intentionally no in-place "relink" operation: forwarding requires
// a successful host AEAD open/peel and then BuildK6ShapedCarrier with the new
// shorter prefix, new circ_id, new nonce sequence and regenerated tail.

} // namespace kad6
