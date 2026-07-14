// SPDX-License-Identifier: MIT
//
// libkad6 — kad6_address.h: codec for the Kad6 address wire object (ticket
// K6-0.3). Same wire layout eMule AI already documents in
// srchybrid/eMuleAI/Address.h lines 50-54 (CAddress::WriteToBuffer /
// ReadFromBuffer), re-hosted here as a standalone, MFC-free, C-ABI-friendly
// codec so libkad6 consumers never need CAddress/CSafeMemFile.
//
// Wire layout (all scalars single bytes; no endianness to speak of):
//   offset size  field
//   0      1     family: 0=None, 4=IPv4, 6=IPv6
//   1      1     addr_len: 0, 4, or 16 (MUST match family; see below)
//   2      N     address bytes, network order, N = addr_len
//
// Exactly three (family, addr_len) combinations are valid:
//   family=None (0) : addr_len=0  -> total 2 bytes
//   family=IPv4 (4) : addr_len=4  -> total 6 bytes
//   family=IPv6 (6) : addr_len=16 -> total 18 bytes
// Any other combination (including a "right" family with a mismatched
// addr_len, e.g. family=4/addr_len=16) is malformed. A port is NOT part of
// this object — ports live in the enclosing endpoint, exactly as in CAddress.
//
// Producer strict / consumer prudent (Postel): Encode rejects an invalid
// Family before writing anything; Decode validates the (family, addr_len)
// pair before it ever reads address bytes, so a bad header can never lead to
// an out-of-bounds read or a partial/garbage address escaping as "Ok".
#pragma once

#include "kad6/kad6_types.h"

#include <array>
#include <vector>

namespace kad6 {

// ── Wire constants ─────────────────────────────────────────────────────────
inline constexpr std::size_t kKad6AddressHeaderSize   = 2;  // family(1) + addr_len(1)
inline constexpr std::size_t kKad6AddressLenIPv4       = 4;
inline constexpr std::size_t kKad6AddressLenIPv6       = 16;
inline constexpr std::size_t kKad6AddressMaxWireSize   =
    kKad6AddressHeaderSize + kKad6AddressLenIPv6;            // 18

// ── The address value ───────────────────────────────────────────────────────
// `addr` always holds 16 bytes of storage; only the first N are meaningful,
// where N is determined by `family` (0 for None, 4 for IPv4, 16 for IPv6).
// Bytes beyond N are never interpreted by this codec (Encode never reads them
// for family=None/IPv4, and comparisons only ever look at the first N bytes
// of the *normalized* form — see Kad6AddressNormalize / operator==).
struct Kad6Address {
    enum class Family : int { None = 0, IPv4 = 4, IPv6 = 6 };

    Family family = Family::None;
    std::array<Byte, 16> addr{};
};

// Exact serialized length for `a`'s family (2, 6, or 18). Does NOT validate
// `a` — an unrecognized Family yields the header-only size (2); pair with
// EncodeKad6Address for the checked path. Never allocates, never fails.
std::size_t Kad6AddressEncodedSize(const Kad6Address& a) noexcept;

// Serialize `a` into a freshly sized buffer.
//   - Validates a.family is one of {None, IPv4, IPv6}; anything else is
//     Kad6Status::Malformed and `out` is left empty.
//   - On success `out` holds exactly Kad6AddressEncodedSize(a) bytes.
Kad6Status EncodeKad6Address(const Kad6Address& a, std::vector<Byte>& out);

// Serialize `a` into [out, out+cap).
//   - `out` may be null only if cap == 0 (in which case the call still fails,
//     since even the smallest valid address needs 2 bytes — use
//     Kad6AddressEncodedSize for a true size probe).
//   - On success writes Kad6AddressEncodedSize(a) bytes and stores it in
//     *written; *written is set to 0 on any failure.
//   - Returns Malformed for an unrecognized family, TooLarge if `cap` is
//     smaller than the required size, NullArgument for a null buffer with
//     cap > 0.
Kad6Status EncodeKad6Address(const Kad6Address& a, Byte* out, std::size_t cap,
                              std::size_t* written) noexcept;

// Parse a Kad6 address from [in, in+len).
//   - MUST reject any (family, addr_len) pair other than the three valid
//     combinations, with no out-of-bounds read — checked via ByteReader.
//   - Fewer than 2 bytes present (including len==0), or a valid header whose
//     declared addr_len bytes are not fully present, => Truncated.
//   - A structurally invalid header (bad family, or addr_len that does not
//     match family) => Malformed. This check happens BEFORE the address
//     bytes are read (reject before doing more work — Postel).
//   - (in == nullptr, len == 0) is an empty input => Truncated; a null
//     buffer with a non-zero len is a caller bug => NullArgument.
//   - On success `out` is fully overwritten (unused tail of `addr` zeroed);
//     on failure `out` is reset to Family::None / all-zero.
// `consumed`, if non-null, receives the number of bytes the address occupies
// on the wire (2, 6, or 18) on success, 0 otherwise.
Kad6Status DecodeKad6Address(const Byte* in, std::size_t len, Kad6Address& out,
                              std::size_t* consumed = nullptr) noexcept;

// Canonicalize in place. Currently the only normalization rule is IPv4-mapped
// IPv6 (::ffff:a.b.c.d — first 10 bytes 0, bytes 10-11 = 0xFF 0xFF) folding
// down to family=IPv4 with the trailing 4 bytes. Also zeroes the unused tail
// of `addr` for the two other recognized families so the normalized form is
// byte-deterministic. An unrecognized family is left untouched (there is no
// well-defined normal form for it).
// MUST be applied before any comparison/dedup (operator== and the subnet
// helpers below already do this internally).
void Kad6AddressNormalize(Kad6Address& a) noexcept;

// Returns a copy of `a`, normalized, with all host bits beyond `prefixBits`
// zeroed. `prefixBits` is clamped to [0, 32] for IPv4 and [0, 128] for IPv6
// (after normalization — an IPv4-mapped IPv6 input is masked as IPv4).
// family=None (or any unrecognized family) is returned unchanged: there are
// no address bits to mask.
Kad6Address Kad6AddressSubnet(const Kad6Address& a, int prefixBits) noexcept;

// True iff `a` and `b` share the same /prefixBits subnet (same family, and
// the masked network bits are equal). Two addresses in different families
// (e.g. IPv4 vs. a non-mapped IPv6) are never in the same subnet.
bool Kad6AddressInSameSubnet(const Kad6Address& a, const Kad6Address& b,
                              int prefixBits) noexcept;

// Compares NORMALIZED forms: family must match, and only the first N bytes of
// `addr` (N per family) are compared — the unused tail never participates.
bool operator==(const Kad6Address& a, const Kad6Address& b) noexcept;
inline bool operator!=(const Kad6Address& a, const Kad6Address& b) noexcept {
    return !(a == b);
}

} // namespace kad6
