// SPDX-License-Identifier: MIT
//
// libkad6 — kad6_records.h: the four Ed25519-signed Kad6 wire objects
// (ticket K6-0.6). Each is domain-separated: the signature covers
//   domainString || <every field except the signature(s)>
// where domainString is the exact ASCII label shown per object (NO trailing
// NUL). All multi-byte scalars are little-endian (via kad6_bytes.h).
//
// libkad6 embeds NO crypto: the Ed25519 sign/verify primitives are injected
// through Kad6CryptoHooks (see kad6_crypto.h). This header owns only the
// canonical serialization, the structural limits, and the sign/verify plumbing.
//
// Producer strict / consumer prudent: every Decode / Verify rejects bad
// version, out-of-range counts, over-cap compat pubkeys and out-of-policy TTLs
// BEFORE the (expensive) Ed25519 verify — spec K6-NATIVE-003.
//
// The four objects:
//   K6NodeBind      §6.2  "eSE-Kad6-NodeBind-v1"      one sig (node_pub)
//   K6Rotate        §6.3  "eSE-Kad6-Rotate-v1"        two sigs (old_pub+new_pub)
//   K6RouterRecord  §17.2 "eSE-Kad6-RouterRecord-v1"  one sig (node_pub)
//   K6SourceRecord  §17.5 "eSE-Kad6-SourceRecord-v1"  one sig (pub_key — see below)
//
// DESIGN DECISION (source-record signer key). §17.5 lists a 16-byte
// `source_pseudonym` and leaves the signing key implicit. 16 bytes is NOT an
// Ed25519 public key, so it cannot be the verify key. We make the signer key
// EXPLICIT: an added `pub_key[32]` field placed on the wire immediately before
// the signature (and therefore inside the signed bytes). VerifyK6SourceRecord
// verifies with `pub_key`. A deployment that binds pub_key -> pseudonym does so
// one layer up (e.g. pseudonym = H(pub_key)[0..16)); this codec only guarantees
// the record is self-consistently signed by the key it carries.
//
// The on-wire endpoint_count / exit_count / compat_pub_len are DERIVED from the
// corresponding container sizes (endpoints, exits, compat_pub) — there is no
// separate, desyncable struct member for them. Decode validates the wire count
// against the [min,max] range before it ever allocates or reads the elements.
#pragma once

#include "kad6/kad6_crypto.h"
#include "kad6/kad6_endpoint.h"
#include "kad6/kad6_types.h"

#include <array>
#include <cstdint>
#include <vector>

namespace kad6 {

// ── shared limits (all checked before the Ed25519 verify) ────────────────────
constexpr Byte          kK6RecordVersion         = 1;
constexpr std::size_t   kK6RouterMinEndpoints    = 1;
constexpr std::size_t   kK6RouterMaxEndpoints    = 4;   // §17.2 endpoint_count 1..4
constexpr std::size_t   kK6SourceMinExits        = 1;
constexpr std::size_t   kK6SourceMaxExits        = 3;   // §17.5 exit_count 1..3
constexpr std::uint16_t kK6SourceMaxCompatPubLen = 256; // policy cap on compat_pub
constexpr std::uint64_t kK6RouterMaxTtlSeconds   = 7ull * 24 * 3600; // valid window cap
constexpr std::uint64_t kK6SourceMaxTtlSeconds   = 7ull * 24 * 3600; // created..expires cap

using Ed25519Pub = std::array<Byte, kEd25519PubSize>;
using Ed25519Sig = std::array<Byte, kEd25519SigSize>;

// ── epoch monotonicity (spec K6-ID-005) ──────────────────────────────────────
// StaleEpoch unless the candidate epoch STRICTLY exceeds the last-seen one.
// Applies to any epoch field (NodeBind.epoch, Rotate.rotation_epoch,
// RouterRecord.epoch, SourceRecord.source_epoch).
inline Kad6Status K6CheckEpochAdvance(std::uint64_t seenEpoch,
                                      std::uint64_t candidateEpoch) noexcept {
    return candidateEpoch > seenEpoch ? Kad6Status::Ok : Kad6Status::StaleEpoch;
}

// ════════════════════════════════════════════════════════════════════════════
// 1) K6NodeBind (§6.2). Binds a KadID to a node signing key at an epoch.
//    Domain "eSE-Kad6-NodeBind-v1".
//    Signed: kad_id[16] || node_pub[32] || epoch u64 || caps u64.
//    Wire  : <signed> || signature[64].    Verify key: node_pub.
// ════════════════════════════════════════════════════════════════════════════
struct K6NodeBind {
    KadId         kad_id{};
    Ed25519Pub    node_pub{};
    std::uint64_t epoch = 0;
    std::uint64_t caps = 0;
    Ed25519Sig    signature{};
};

// Serialize the signed portion (all fields EXCEPT signature) — exactly the byte
// string the signature is taken over, after the domain prefix.
Kad6Status K6NodeBindSerializeSigned(const K6NodeBind& b, std::vector<Byte>& out);
// signed || signature (verbatim; does NOT recompute the signature).
Kad6Status EncodeK6NodeBind(const K6NodeBind& b, std::vector<Byte>& out);
// Parse. Does NOT verify the signature (use Verify).
Kad6Status DecodeK6NodeBind(const Byte* in, std::size_t len, K6NodeBind& out,
                            std::size_t* consumed = nullptr) noexcept;
// sig = Ed25519(sk, domain||signed); stores it into b.signature, then encodes.
Kad6Status SignK6NodeBind(const Kad6CryptoHooks& h, const Byte* sk, std::size_t skLen,
                          K6NodeBind& b, std::vector<Byte>& out);
// Ok iff version==1 and ed25519_verify(node_pub, domain||signed, signature).
Kad6Status VerifyK6NodeBind(const Kad6CryptoHooks& h, const K6NodeBind& b);

// ════════════════════════════════════════════════════════════════════════════
// 2) K6Rotate (§6.3). Authorizes old_pub -> new_pub; signed by BOTH keys.
//    Domain "eSE-Kad6-Rotate-v1".
//    Signed: kad_id[16] || old_pub[32] || new_pub[32] || rotation_epoch u64
//            || not_after u64.
//    Wire  : <signed> || sig_old[64] || sig_new[64].
//    Verify: ed25519_verify(old_pub, msg, sig_old) AND
//            ed25519_verify(new_pub, msg, sig_new) — both must pass.
// ════════════════════════════════════════════════════════════════════════════
struct K6Rotate {
    KadId         kad_id{};
    Ed25519Pub    old_pub{};
    Ed25519Pub    new_pub{};
    std::uint64_t rotation_epoch = 0;
    std::uint64_t not_after = 0;   // record is invalid once now >= not_after
    Ed25519Sig    sig_old{};
    Ed25519Sig    sig_new{};
};

Kad6Status K6RotateSerializeSigned(const K6Rotate& r, std::vector<Byte>& out);
Kad6Status EncodeK6Rotate(const K6Rotate& r, std::vector<Byte>& out);
Kad6Status DecodeK6Rotate(const Byte* in, std::size_t len, K6Rotate& out,
                          std::size_t* consumed = nullptr) noexcept;
// Dual-key sign: fills sig_old with skOld and sig_new with skNew, then encodes.
// (Deviates from the single-sk SignX shape because a rotation is co-signed by
// the outgoing and incoming keys — documented on the struct above.)
Kad6Status SignK6Rotate(const Kad6CryptoHooks& h,
                        const Byte* skOld, std::size_t skOldLen,
                        const Byte* skNew, std::size_t skNewLen,
                        K6Rotate& r, std::vector<Byte>& out);
// AuthFailed if EITHER signature fails.
Kad6Status VerifyK6Rotate(const Kad6CryptoHooks& h, const K6Rotate& r);
// now >= not_after => Expired, else Ok.
inline Kad6Status K6RotateCheckFresh(const K6Rotate& r, std::uint64_t now) noexcept {
    return now >= r.not_after ? Kad6Status::Expired : Kad6Status::Ok;
}

// ════════════════════════════════════════════════════════════════════════════
// 3) K6RouterRecord (§17.2). A node's reachable endpoints for a validity window.
//    Domain "eSE-Kad6-RouterRecord-v1".
//    Wire: version u8=1 | flags u8 | endpoint_count u8(1..4) | reserved u8=0 |
//          kad_id[16] | node_pub[32] | epoch u64 | caps u64 | valid_from u64 |
//          valid_until u64 | endpoints(K6Endpoint * endpoint_count) | sig[64].
//    Signed = everything except signature.   Verify key: node_pub.
//    endpoint_count is DERIVED from endpoints.size().
// ════════════════════════════════════════════════════════════════════════════
struct K6RouterRecord {
    Byte          version = kK6RecordVersion;
    Byte          flags = 0;
    KadId         kad_id{};
    Ed25519Pub    node_pub{};
    std::uint64_t epoch = 0;
    std::uint64_t caps = 0;
    std::uint64_t valid_from = 0;
    std::uint64_t valid_until = 0;
    std::vector<K6Endpoint> endpoints; // 1..4, validated
    Ed25519Sig    signature{};
};

Kad6Status K6RouterRecordSerializeSigned(const K6RouterRecord& r, std::vector<Byte>& out);
Kad6Status EncodeK6RouterRecord(const K6RouterRecord& r, std::vector<Byte>& out);
Kad6Status DecodeK6RouterRecord(const Byte* in, std::size_t len, K6RouterRecord& out,
                                std::size_t* consumed = nullptr) noexcept;
Kad6Status SignK6RouterRecord(const Kad6CryptoHooks& h, const Byte* sk, std::size_t skLen,
                              K6RouterRecord& r, std::vector<Byte>& out);
// Cheap gate (version, endpoint count, valid window <= cap and non-inverted)
// then ed25519_verify(node_pub, ...). Does NOT consult the clock.
Kad6Status VerifyK6RouterRecord(const Kad6CryptoHooks& h, const K6RouterRecord& r);
// now >= valid_until => Expired, else Ok (a "not yet valid" now < valid_from is
// NOT flagged here — this call answers only "has the window elapsed?").
inline Kad6Status K6RouterRecordCheckFresh(const K6RouterRecord& r,
                                           std::uint64_t now) noexcept {
    return now >= r.valid_until ? Kad6Status::Expired : Kad6Status::Ok;
}

// ════════════════════════════════════════════════════════════════════════════
// 4) K6SourceRecord (§17.5). Where/how to reach a content object via exit nodes.
//    Domain "eSE-Kad6-SourceRecord-v1". Carries NO originator IP (by design).
//    Wire: version u8=1 | flags u8 | exit_count u8(1..3) | reserved u8=0 |
//          object_hash[16] | source_pseudonym[16] | source_epoch u64 |
//          created_at u64 | expires_at u64 | service_token[16] |
//          exits(K6ExitDescriptor * exit_count) | metadata_hash[32] |
//          compat_pub_len u16 | compat_pub[compat_pub_len] |
//          pub_key[32] | signature[64].
//    Signed = everything except signature (INCLUDING pub_key).
//    Verify key: pub_key (see DESIGN DECISION at the top of this header).
//    exit_count derived from exits.size(); compat_pub_len from compat_pub.size().
// ════════════════════════════════════════════════════════════════════════════
struct K6ExitDescriptor {
    Ed25519Pub    exit_node_pub{};
    K6Endpoint    endpoint;        // carries the EXIT's contact, never the originator's
    std::uint64_t lease_hint = 0;
    std::uint64_t caps = 0;
    std::uint64_t exit_expires_at = 0;
};

struct K6SourceRecord {
    Byte          version = kK6RecordVersion;
    Byte          flags = 0;
    Hash16        object_hash{};
    Hash16        source_pseudonym{};   // 16-byte pseudonym; NOT the signing key
    std::uint64_t source_epoch = 0;
    std::uint64_t created_at = 0;
    std::uint64_t expires_at = 0;
    std::array<Byte, kNonce16Size> service_token{};
    std::vector<K6ExitDescriptor> exits;  // 1..3, validated
    Hash32        metadata_hash{};
    std::vector<Byte> compat_pub;         // 0..kK6SourceMaxCompatPubLen bytes
    Ed25519Pub    pub_key{};              // explicit signer key (our addition)
    Ed25519Sig    signature{};
};

Kad6Status K6SourceRecordSerializeSigned(const K6SourceRecord& s, std::vector<Byte>& out);
Kad6Status EncodeK6SourceRecord(const K6SourceRecord& s, std::vector<Byte>& out);
Kad6Status DecodeK6SourceRecord(const Byte* in, std::size_t len, K6SourceRecord& out,
                                std::size_t* consumed = nullptr) noexcept;
Kad6Status SignK6SourceRecord(const Kad6CryptoHooks& h, const Byte* sk, std::size_t skLen,
                              K6SourceRecord& s, std::vector<Byte>& out);
// Cheap gate (version, exit count, compat_pub cap, created..expires window)
// then ed25519_verify(pub_key, ...). Does NOT consult the clock.
Kad6Status VerifyK6SourceRecord(const Kad6CryptoHooks& h, const K6SourceRecord& s);
// now >= expires_at => Expired, else Ok.
inline Kad6Status K6SourceRecordCheckFresh(const K6SourceRecord& s,
                                           std::uint64_t now) noexcept {
    return now >= s.expires_at ? Kad6Status::Expired : Kad6Status::Ok;
}

} // namespace kad6
