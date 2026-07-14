// SPDX-License-Identifier: MIT
//
// libkad6 — kad6_frame.h: K6FrameV1 codec, the common header carried inside
// the TUN_OP_KAD6_GATEWAY service body of every Kad6 gateway message. Every
// higher-level Kad6 message (OPEN, OPEN_OK, request/response, ...) rides
// inside a K6Frame's `body`; this file only serializes/parses the envelope.
//
// Wire layout (all multi-byte scalars little-endian):
//   offset size  field
//   0      1     version = 1
//   1      1     msg_type
//   2      2     flags u16 LE
//   4      4     request_id u32 LE
//   8      8     session_id u64 LE (0 before OPEN_OK)
//   16     4     body_len u32 LE
//   20     N     body (N == body_len)
//
// Producer strict, consumer prudent (Postel): the encoder refuses to emit
// anything it cannot round-trip (unknown version, reserved flag bits, an
// oversized body); the decoder accepts a well-formed frame with unknown
// reserved flag bits set (bits 9..15) and preserves them as-is in `flags` —
// it neither strips them nor fails because of them, since a future minor
// revision may define their meaning and old decoders must stay usable.
#pragma once

#include "kad6/kad6_bytes.h"
#include "kad6/kad6_types.h"

#include <cstdint>
#include <vector>

namespace kad6 {

// Size of the fixed K6FrameV1 header (everything before `body`).
constexpr std::size_t kK6FrameHeaderSize = 20;

// Control-plane body size cap (1 MiB). Chosen to keep gateway control
// messages small; bulk data does not travel inside a K6Frame body.
constexpr std::size_t kK6FrameMaxBody = 1u << 20;

// Flag bits (see spec: Kad6 gateway frame flags). Bits 9..15 are reserved for
// future revisions.
constexpr std::uint16_t kK6FlagResponse     = 0x0001; // bit 0
constexpr std::uint16_t kK6FlagMore         = 0x0002; // bit 1
constexpr std::uint16_t kK6FlagFinal        = 0x0004; // bit 2
constexpr std::uint16_t kK6FlagPadded       = 0x0008; // bit 3
constexpr std::uint16_t kK6FlagStrict       = 0x0010; // bit 4
constexpr std::uint16_t kK6FlagLegacyKad2   = 0x0020; // bit 5
constexpr std::uint16_t kK6FlagLegacyEd2k   = 0x0040; // bit 6
constexpr std::uint16_t kK6FlagNativeKad6   = 0x0080; // bit 7
constexpr std::uint16_t kK6FlagCancelable   = 0x0100; // bit 8

// Bits 9..15: reserved for future flags. The encoder rejects a frame that
// sets any of these (BadValue) so this build never emits one; the decoder
// ignores them (leaves them intact in K6Frame::flags) per Postel.
constexpr std::uint16_t kK6FlagReservedMask = 0xFE00;

// In-memory model of a K6FrameV1. `body` carries the inner Kad6 message
// bytes (opaque to this codec).
struct K6Frame {
    Byte version = 1;
    Byte msg_type = 0;
    std::uint16_t flags = 0;
    std::uint32_t request_id = 0;
    std::uint64_t session_id = 0;
    std::vector<Byte> body;
};

// Exact serialized length of `f` (header + body.size()). Does not validate
// `f`; pair with EncodeK6Frame for the checked path.
std::size_t K6FrameEncodedSize(const K6Frame& f) noexcept;

// Serialize `f` into `out` (out is cleared first, and cleared again on any
// failure). Producer-strict validation, in order:
//   - version != 1                       -> UnsupportedVersion
//   - flags has any reserved bit (9..15) -> BadValue
//   - body.size() > kK6FrameMaxBody      -> TooLarge
// On success `out` holds exactly K6FrameEncodedSize(f) bytes.
Kad6Status EncodeK6Frame(const K6Frame& f, std::vector<Byte>& out);

// Parse a K6FrameV1 from [in, in+len). Uses ByteReader for every field; never
// indexes the buffer directly.
//   - (in == nullptr, len != 0) is a caller bug -> NullArgument.
//   - len < kK6FrameHeaderSize                  -> Truncated.
//   - version != 1                              -> UnsupportedVersion.
//   - body_len > kK6FrameMaxBody (checked BEFORE sizing `out.body`) -> TooLarge.
//   - fewer than body_len bytes follow the header (buffer shorter than the
//     declared frame)                           -> Truncated.
//   - more than body_len bytes follow the header (declared length doesn't
//     match the buffer actually supplied)        -> Malformed.
//   - a reserved flag bit (9..15) set in the input is NOT an error: it is
//     preserved as-is in `out.flags`.
// On success `out` is fully overwritten; on any failure `out` is reset to a
// default-constructed K6Frame. `consumed`, if non-null, receives
// kK6FrameHeaderSize + body_len.
Kad6Status DecodeK6Frame(const Byte* in, std::size_t len, K6Frame& out,
                          std::size_t* consumed = nullptr) noexcept;

} // namespace kad6
