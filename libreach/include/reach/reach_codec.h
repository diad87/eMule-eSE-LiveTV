// SPDX-License-Identifier: MIT
//
// libreach — reach_codec.h: serialize / parse the `TAG_REACH` reachability
// vector TLV (KEP-1 Appendix A). This is the normative wire format; the
// golden vectors in libreach/tests/test_reach_codec.cpp pin it byte-for-byte.
//
// Wire layout (all multi-byte scalars little-endian):
//   offset size  field
//   0      1     version (=1 legacy, =2 current)
//   1      2     capflags (KadCap bitfield, LE)
//   3      1     nRdv (0..3)
//   4      22×n  rdv[n] = NodeID(16) ++ IPv4(4) ++ udpPort(2 LE)
//   4+22n  ...   optional trailing TLV(s), preserved opaquely (e.g. signature)
//
// v1 rendezvous entries are 22 bytes. v2 entries are 42 bytes: the v1 fields
// plus reservationToken(16) and expiresAt(4 LE). The extension area is a real
// <type:u8><len:u16le><value> TLV sequence.
// Producer and consumer reject unsupported major versions and malformed tails;
// well-formed unknown TLVs are preserved.
#pragma once

#include "reach/reach_types.h"

namespace reach {

// Exact serialized length of `v`'s known prefix plus its trailing bytes.
// Does not validate `v`; pair with EncodeReachVector for the checked path.
std::size_t ReachEncodedSize(const ReachVector& v) noexcept;

// Serialize `v` into [out, out+outCap).
//   - `out` may be null only if outCap == 0 (size-probe via ReachEncodedSize).
//   - On success writes ReachEncodedSize(v) bytes and stores it in *written.
//   - Validates: version != 0, rdv.size() <= kMaxRdv, no reserved capflag bits.
// Returns Ok or the first failing condition; on failure *written is set to 0.
ReachStatus EncodeReachVector(const ReachVector& v,
                              Byte* out, std::size_t outCap,
                              std::size_t* written) noexcept;

// Convenience overload returning a freshly sized buffer. Returns Ok and fills
// `out` on success; on failure `out` is left empty and the status explains.
ReachStatus EncodeReachVector(const ReachVector& v, std::vector<Byte>& out);

// Parse a `TAG_REACH` payload from [in, in+len).
//   - Requires len >= kReachHeaderSize and a complete rdv array.
//   - version 0 and unsupported major versions are rejected.
//   - On success `out` is fully overwritten; on failure `out` is cleared.
//   - (in == null, len == 0) is treated as an empty input → Truncated; a null
//     buffer with a non-zero len is a caller bug → NullArgument.
// `consumed`, if non-null, receives the number of bytes the vector occupies
// (kReachHeaderSize + 22*nRdv + trailing). For a bare TAG_REACH payload that
// equals `len`; callers embedding the vector in a larger buffer use it to
// advance.
ReachStatus DecodeReachVector(const Byte* in, std::size_t len,
                              ReachVector& out,
                              std::size_t* consumed = nullptr) noexcept;

// ── Small pure helpers on the vector (no wire I/O) ─────────────────────────

// capFlags masked to the bits this build understands (bits 0..6 in v1).
inline std::uint16_t ReachKnownCaps(const ReachVector& v) noexcept {
    return static_cast<std::uint16_t>(v.capFlags & kKadCapKnownMask);
}

// True iff every capability in `required` is advertised by `v` (mutual-cap
// gating for the cascade: never attempt an eSE layer without the mutual bit —
// Appendix B invariant 1).
inline bool ReachHasCaps(const ReachVector& v, std::uint16_t required) noexcept {
    return (v.capFlags & required) == required;
}

} // namespace reach
