// SPDX-License-Identifier: MIT
//
// libkad6 — kad6_tags.h: K6TagListV1, a canonical bounded tag-list codec
// (ticket K6-1.3). A "tag" is a small typed name/value pair — the Kad6
// analogue of eMule's classic CTag, but with a hard byte budget and no
// implicit trust in attacker-controlled lengths.
//
// Wire layout (all multi-byte scalars little-endian):
//   K6TagListV1:
//     version   u8  = 1
//     count     u16 LE
//     total_len u32 LE   (serialized byte length of the whole list, incl.
//                          this header — a bound check, not a cross-check
//                          the parser trusts blindly: Decode verifies it
//                          against the bytes actually consumed)
//     then `count` * K6TagV1
//
//   K6TagV1:
//     name_kind  u8   (0 = numeric_u8, 1 = utf8 — kK6NameKindNumericU8/Utf8)
//     name_len   u8   (== 1 when name_kind == numeric_u8; 1..64 when utf8)
//     name       name_len bytes
//     value_kind u8   (see the kK6Val* constants below)
//     value_len  u32 LE
//     value      value_len bytes
//
// value_kind assigns stable wire integers 0..9. U8/U16/U32/U64/HASH16/
// HASH20/HASH32 are fixed-width: value_len must equal the exact width or
// Decode/Encode reject with BadValue. UTF8/BYTES/CADDRESS are variable
// length, bounded only by kK6MaxTagValueBytes. UTF8 values (and utf8-kind
// names) must be valid UTF-8 with no interior NUL byte, else Malformed.
//
// Producer strict, consumer prudent (Postel): every limit (tag count,
// per-value size, total serialized size) is checked against the header
// fields BEFORE any per-tag buffer is allocated; a partial parse is an
// error, never a partial result. Decode uses ByteReader exclusively — no
// raw indexing into the input buffer.
#pragma once

#include "kad6/kad6_types.h"

#include <cstdint>
#include <vector>

namespace kad6 {

// ── Wire version ───────────────────────────────────────────────────────────
constexpr Byte kK6TagListVersion = 1;

// ── Limits (spec K6-TAG-003) ────────────────────────────────────────────────
constexpr std::size_t kK6MaxTags          = 128;
constexpr std::size_t kK6MaxTagListBytes  = 64 * 1024;
constexpr std::size_t kK6MaxTagValueBytes = 16 * 1024;

// ── name_kind (K6TagV1::name_kind) ──────────────────────────────────────────
constexpr Byte kK6NameKindNumericU8 = 0;
constexpr Byte kK6NameKindUtf8      = 1;
constexpr std::size_t kK6MaxUtf8NameLen = 64;

// ── value_kind (K6TagV1::value_kind) — stable wire integers ────────────────
constexpr Byte kK6ValU8       = 0;
constexpr Byte kK6ValU16      = 1;
constexpr Byte kK6ValU32      = 2;
constexpr Byte kK6ValU64      = 3;
constexpr Byte kK6ValUtf8     = 4;
constexpr Byte kK6ValBytes    = 5;
constexpr Byte kK6ValHash16   = 6;
constexpr Byte kK6ValHash20   = 7;
constexpr Byte kK6ValHash32   = 8;
constexpr Byte kK6ValCAddress = 9;

// ── Model ────────────────────────────────────────────────────────────────
struct K6Tag {
    Byte name_kind = kK6NameKindNumericU8;
    std::vector<Byte> name;
    Byte value_kind = kK6ValU8;
    std::vector<Byte> value;
};
using K6TagList = std::vector<K6Tag>;

// Serialize `list` into `out` in canonical order. Validates every rule in the
// file header comment (fixed-width exactness, name_len ranges, UTF-8 validity,
// structurally valid CAddress values, no exact duplicate tags, and all three
// size limits) BEFORE writing a single byte. Clears `out` on failure.
Kad6Status EncodeK6TagList(const K6TagList& list, std::vector<Byte>& out);

// Parse a K6TagListV1 from [in, in+len) using ByteReader (bounded cursor —
// never indexes the buffer directly). On success `out` is fully overwritten
// and, if `consumed` is non-null, receives the number of bytes the list
// occupies (== the header's total_len, which Decode cross-checks against
// what it actually consumed). On any failure `out` is left empty — a
// partial parse never leaks a partial K6TagList.
//   - (in == nullptr, len == 0)  -> Truncated (empty input)
//   - (in == nullptr, len != 0)  -> NullArgument (caller bug)
//   - count > kK6MaxTags, any value_len > kK6MaxTagValueBytes, or
//     total_len > kK6MaxTagListBytes -> TooLarge, checked before any
//     per-tag vector is allocated
//   - fixed-width value_kind with the wrong value_len -> BadValue
//   - name_kind rules violated (numeric_u8 name_len != 1; utf8 name_len
//     outside 1..64) -> BadValue
//   - unknown name_kind / value_kind -> BadValue
//   - invalid UTF-8 or an interior NUL in a utf8 name/value -> Malformed
//   - malformed/trailing bytes in a CADDRESS value -> Malformed
//   - non-canonical ordering or an exact duplicate tag -> Malformed
//   - declared total_len does not match bytes actually consumed -> Malformed
Kad6Status DecodeK6TagList(const Byte* in, std::size_t len, K6TagList& out,
                           std::size_t* consumed = nullptr) noexcept;

// Reorder `list` in place into the canonical, deterministic order:
//   1. name_kind ascending (numeric_u8 before utf8)
//   2. name bytes, lexicographic (unsigned byte-wise)
//   3. value_kind ascending
//   4. value bytes, lexicographic (unsigned byte-wise)
// Exact duplicates are adjacent after sorting and are rejected by the wire
// encoder/decoder because they would otherwise admit multiple encodings of the
// same signed semantic value.
void Kad6TagsCanonicalSort(K6TagList& list);

// Minimal UTF-8 validator: rejects any 0x00 byte (Postel-strict — a tag
// name/value has no separate terminator, so every NUL in the buffer is
// "interior"), overlong encodings, unpaired surrogates (U+D800..U+DFFF),
// codepoints above U+10FFFF, and truncated/malformed continuation
// sequences. Exposed so it can be exercised directly by tests.
bool Kad6IsValidUtf8NoNul(const Byte* p, std::size_t n) noexcept;

} // namespace kad6
