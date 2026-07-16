// SPDX-License-Identifier: MIT
//
// libkad6 — kad6_records.cpp: the four Ed25519-signed Kad6 wire objects
// (ticket K6-0.6). See kad6_records.h for the wire layouts, the domain labels
// and the source-record signer-key design decision (explicit pub_key[32]).
#include "kad6/kad6_records.h"

#include <algorithm>

namespace kad6 {

// ── domain-separation labels (exact ASCII, NO trailing NUL on the wire) ──────
static const char kNodeBindDomain[] = "eSE-Kad6-NodeBind-v1";
static const char kRotateDomain[]   = "eSE-Kad6-Rotate-v1";
static const char kRouterDomain[]   = "eSE-Kad6-RouterRecord-v1";
static const char kSourceDomain[]   = "eSE-Kad6-SourceRecord-v1";
static const char kSourcePseudonymDomain[] = "eSE-Kad6-SourcePseudonym-v1";

// msg = domain || body. This is exactly what the Ed25519 signature covers.
static void BuildSignedMessage(const char* domain, std::size_t domainLen,
                               const std::vector<Byte>& body, std::vector<Byte>& msg) {
    msg.clear();
    msg.reserve(domainLen + body.size());
    const Byte* d = reinterpret_cast<const Byte*>(domain);
    msg.insert(msg.end(), d, d + domainLen);
    msg.insert(msg.end(), body.begin(), body.end());
}

static Kad6Status ValidateRouterScalars(const K6RouterRecord& r) noexcept {
    if (r.version != kK6RecordVersion)
        return Kad6Status::UnsupportedVersion;
    Byte idAccum = 0;
    for (Byte part : r.kad_id)
        idAccum = static_cast<Byte>(idAccum | part);
    Byte pubAccum = 0;
    for (Byte part : r.node_pub)
        pubAccum = static_cast<Byte>(pubAccum | part);
    if (r.flags != 0 || idAccum == 0 || pubAccum == 0 || r.epoch == 0)
        return Kad6Status::BadValue;
    if (r.valid_from == 0 || r.valid_until <= r.valid_from ||
        r.valid_until - r.valid_from > kK6RouterMaxTtlSeconds)
        return Kad6Status::BadValue;
    return Kad6Status::Ok;
}

static Kad6Status ValidateRouterFields(const K6RouterRecord& r) noexcept {
    const Kad6Status scalars = ValidateRouterScalars(r);
    if (scalars != Kad6Status::Ok)
        return scalars;
    const std::size_t n = r.endpoints.size();
    if (n < kK6RouterMinEndpoints || n > kK6RouterMaxEndpoints)
        return Kad6Status::Malformed;
    for (std::size_t i = 0; i < n; ++i) {
        if (r.endpoints[i].valid_until <= r.valid_from ||
            r.endpoints[i].valid_until > r.valid_until)
            return Kad6Status::BadValue;
        for (std::size_t j = i + 1; j < n; ++j) {
            if (r.endpoints[i].addr == r.endpoints[j].addr &&
                r.endpoints[i].udp_port == r.endpoints[j].udp_port &&
                r.endpoints[i].tcp_port == r.endpoints[j].tcp_port)
                return Kad6Status::BadValue;
        }
    }
    return Kad6Status::Ok;
}

static Kad6Status ValidateSourceFields(const K6SourceRecord& s) noexcept {
    if (s.version != kK6RecordVersion)
        return Kad6Status::UnsupportedVersion;
    const std::size_t n = s.exits.size();
    if (n < kK6SourceMinExits || n > kK6SourceMaxExits)
        return Kad6Status::Malformed;
    if (s.compat_pub.size() > kK6SourceMaxCompatPubLen)
        return Kad6Status::TooLarge;
    if (s.expires_at <= s.created_at ||
        s.expires_at - s.created_at > kK6SourceMaxTtlSeconds)
        return Kad6Status::BadValue;
    return Kad6Status::Ok;
}

// ════════════════════════════════════════════════════════════════════════════
// 1) K6NodeBind
// ════════════════════════════════════════════════════════════════════════════
Kad6Status K6NodeBindSerializeSigned(const K6NodeBind& b, std::vector<Byte>& out) {
    out.clear();
    ByteWriter w(out);
    w.bytes(b.kad_id.data(), b.kad_id.size());
    w.bytes(b.node_pub.data(), b.node_pub.size());
    w.u64le(b.epoch);
    w.u64le(b.caps);
    return Kad6Status::Ok;
}

Kad6Status EncodeK6NodeBind(const K6NodeBind& b, std::vector<Byte>& out) {
    const Kad6Status s = K6NodeBindSerializeSigned(b, out);
    if (s != Kad6Status::Ok) { out.clear(); return s; }
    ByteWriter w(out);
    w.bytes(b.signature.data(), b.signature.size());
    return Kad6Status::Ok;
}

Kad6Status DecodeK6NodeBind(const Byte* in, std::size_t len, K6NodeBind& out,
                            std::size_t* consumed) noexcept {
    out = K6NodeBind{};
    if (consumed) *consumed = 0;
    if (in == nullptr && len != 0) return Kad6Status::NullArgument;

    ByteReader r(in, len);
    if (!r.bytes(out.kad_id.data(), out.kad_id.size()) ||
        !r.bytes(out.node_pub.data(), out.node_pub.size())) {
        out = K6NodeBind{};
        return Kad6Status::Truncated;
    }
    out.epoch = r.u64le();
    out.caps  = r.u64le();
    if (!r.bytes(out.signature.data(), out.signature.size()) || !r.ok()) {
        out = K6NodeBind{};
        return Kad6Status::Truncated;
    }
    if (consumed) *consumed = r.pos();
    return Kad6Status::Ok;
}

Kad6Status SignK6NodeBind(const Kad6CryptoHooks& h, const Byte* sk, std::size_t skLen,
                          K6NodeBind& b, std::vector<Byte>& out) {
    out.clear();
    if (!h.ed25519_sign) return Kad6Status::BadValue;
    std::vector<Byte> body;
    (void)K6NodeBindSerializeSigned(b, body);
    std::vector<Byte> msg;
    BuildSignedMessage(kNodeBindDomain, sizeof(kNodeBindDomain) - 1, body, msg);
    Byte sig[kEd25519SigSize];
    if (!h.ed25519_sign(sk, skLen, msg.data(), msg.size(), sig))
        return Kad6Status::AuthFailed;
    std::copy(sig, sig + kEd25519SigSize, b.signature.begin());
    return EncodeK6NodeBind(b, out);
}

Kad6Status VerifyK6NodeBind(const Kad6CryptoHooks& h, const K6NodeBind& b) {
    if (!h.ed25519_verify) return Kad6Status::BadValue;
    std::vector<Byte> body;
    (void)K6NodeBindSerializeSigned(b, body);
    std::vector<Byte> msg;
    BuildSignedMessage(kNodeBindDomain, sizeof(kNodeBindDomain) - 1, body, msg);
    if (!h.ed25519_verify(b.node_pub.data(), msg.data(), msg.size(), b.signature.data()))
        return Kad6Status::AuthFailed;
    return Kad6Status::Ok;
}

// ════════════════════════════════════════════════════════════════════════════
// 2) K6Rotate (dual-signed)
// ════════════════════════════════════════════════════════════════════════════
Kad6Status K6RotateSerializeSigned(const K6Rotate& r, std::vector<Byte>& out) {
    out.clear();
    ByteWriter w(out);
    w.bytes(r.kad_id.data(), r.kad_id.size());
    w.bytes(r.old_pub.data(), r.old_pub.size());
    w.bytes(r.new_pub.data(), r.new_pub.size());
    w.u64le(r.rotation_epoch);
    w.u64le(r.not_after);
    return Kad6Status::Ok;
}

Kad6Status EncodeK6Rotate(const K6Rotate& r, std::vector<Byte>& out) {
    const Kad6Status s = K6RotateSerializeSigned(r, out);
    if (s != Kad6Status::Ok) { out.clear(); return s; }
    ByteWriter w(out);
    w.bytes(r.sig_old.data(), r.sig_old.size());
    w.bytes(r.sig_new.data(), r.sig_new.size());
    return Kad6Status::Ok;
}

Kad6Status DecodeK6Rotate(const Byte* in, std::size_t len, K6Rotate& out,
                          std::size_t* consumed) noexcept {
    out = K6Rotate{};
    if (consumed) *consumed = 0;
    if (in == nullptr && len != 0) return Kad6Status::NullArgument;

    ByteReader r(in, len);
    if (!r.bytes(out.kad_id.data(), out.kad_id.size()) ||
        !r.bytes(out.old_pub.data(), out.old_pub.size()) ||
        !r.bytes(out.new_pub.data(), out.new_pub.size())) {
        out = K6Rotate{};
        return Kad6Status::Truncated;
    }
    out.rotation_epoch = r.u64le();
    out.not_after      = r.u64le();
    if (!r.bytes(out.sig_old.data(), out.sig_old.size()) ||
        !r.bytes(out.sig_new.data(), out.sig_new.size()) || !r.ok()) {
        out = K6Rotate{};
        return Kad6Status::Truncated;
    }
    if (consumed) *consumed = r.pos();
    return Kad6Status::Ok;
}

Kad6Status SignK6Rotate(const Kad6CryptoHooks& h,
                        const Byte* skOld, std::size_t skOldLen,
                        const Byte* skNew, std::size_t skNewLen,
                        K6Rotate& r, std::vector<Byte>& out) {
    out.clear();
    if (!h.ed25519_sign) return Kad6Status::BadValue;
    if (r.old_pub == r.new_pub) return Kad6Status::BadValue;
    std::vector<Byte> body;
    (void)K6RotateSerializeSigned(r, body);
    std::vector<Byte> msg;
    BuildSignedMessage(kRotateDomain, sizeof(kRotateDomain) - 1, body, msg);

    Byte sigOld[kEd25519SigSize];
    Byte sigNew[kEd25519SigSize];
    if (!h.ed25519_sign(skOld, skOldLen, msg.data(), msg.size(), sigOld))
        return Kad6Status::AuthFailed;
    if (!h.ed25519_sign(skNew, skNewLen, msg.data(), msg.size(), sigNew))
        return Kad6Status::AuthFailed;
    std::copy(sigOld, sigOld + kEd25519SigSize, r.sig_old.begin());
    std::copy(sigNew, sigNew + kEd25519SigSize, r.sig_new.begin());
    return EncodeK6Rotate(r, out);
}

Kad6Status VerifyK6Rotate(const Kad6CryptoHooks& h, const K6Rotate& r) {
    if (!h.ed25519_verify) return Kad6Status::BadValue;
    if (r.old_pub == r.new_pub) return Kad6Status::BadValue;
    std::vector<Byte> body;
    (void)K6RotateSerializeSigned(r, body);
    std::vector<Byte> msg;
    BuildSignedMessage(kRotateDomain, sizeof(kRotateDomain) - 1, body, msg);
    // BOTH signatures must validate (co-signature; spec §6.3).
    if (!h.ed25519_verify(r.old_pub.data(), msg.data(), msg.size(), r.sig_old.data()))
        return Kad6Status::AuthFailed;
    if (!h.ed25519_verify(r.new_pub.data(), msg.data(), msg.size(), r.sig_new.data()))
        return Kad6Status::AuthFailed;
    return Kad6Status::Ok;
}

Kad6Status AcceptK6NodeBind(const Kad6CryptoHooks& h,
                            const K6NodeBind& b,
                            K6IdentityState& state,
                            const K6Rotate* rotation,
                            std::uint64_t nowUnix) {
    const Kad6Status auth = VerifyK6NodeBind(h, b);
    if (auth != Kad6Status::Ok)
        return auth;
    if (!state.initialized) {
        state.initialized = true;
        state.kad_id = b.kad_id;
        state.node_pub = b.node_pub;
        state.epoch = b.epoch;
        return Kad6Status::Ok; // first-seen TOFU
    }
    if (b.kad_id != state.kad_id)
        return Kad6Status::AuthFailed;
    const Kad6Status epoch = K6CheckEpochAdvance(state.epoch, b.epoch);
    if (epoch != Kad6Status::Ok)
        return epoch;
    if (b.node_pub == state.node_pub) {
        state.epoch = b.epoch;
        return Kad6Status::Ok;
    }
    if (!rotation)
        return Kad6Status::AuthFailed;
    if (rotation->kad_id != state.kad_id ||
        rotation->old_pub != state.node_pub ||
        rotation->new_pub != b.node_pub ||
        rotation->rotation_epoch != b.epoch)
        return Kad6Status::AuthFailed;
    const Kad6Status fresh = K6RotateCheckFresh(*rotation, nowUnix);
    if (fresh != Kad6Status::Ok)
        return fresh;
    if (K6CheckEpochAdvance(state.epoch, rotation->rotation_epoch) != Kad6Status::Ok)
        return Kad6Status::StaleEpoch;
    const Kad6Status rotated = VerifyK6Rotate(h, *rotation);
    if (rotated != Kad6Status::Ok)
        return rotated;
    state.node_pub = b.node_pub;
    state.epoch = b.epoch;
    return Kad6Status::Ok;
}

// ════════════════════════════════════════════════════════════════════════════
// 3) K6RouterRecord
// ════════════════════════════════════════════════════════════════════════════
Kad6Status K6RouterRecordSerializeSigned(const K6RouterRecord& r, std::vector<Byte>& out) {
    out.clear();
    const Kad6Status fields = ValidateRouterFields(r);
    if (fields != Kad6Status::Ok)
        return fields;
    const std::size_t n = r.endpoints.size();

    // Pre-encode endpoints first (validates address families) so a failure never
    // leaves a partial header in `out`.
    std::vector<Byte> eps;
    for (const K6Endpoint& e : r.endpoints) {
        std::vector<Byte> one;
        const Kad6Status s = EncodeK6Endpoint(e, one);
        if (s != Kad6Status::Ok) { out.clear(); return s; }
        eps.insert(eps.end(), one.begin(), one.end());
    }

    ByteWriter w(out);
    w.u8(r.version);
    w.u8(r.flags);
    w.u8(static_cast<Byte>(n));
    w.u8(0); // reserved
    w.bytes(r.kad_id.data(), r.kad_id.size());
    w.bytes(r.node_pub.data(), r.node_pub.size());
    w.u64le(r.epoch);
    w.u64le(r.caps);
    w.u64le(r.valid_from);
    w.u64le(r.valid_until);
    w.bytes(eps.data(), eps.size());
    return Kad6Status::Ok;
}

Kad6Status EncodeK6RouterRecord(const K6RouterRecord& r, std::vector<Byte>& out) {
    const Kad6Status s = K6RouterRecordSerializeSigned(r, out);
    if (s != Kad6Status::Ok) { out.clear(); return s; }
    ByteWriter w(out);
    w.bytes(r.signature.data(), r.signature.size());
    return Kad6Status::Ok;
}

Kad6Status DecodeK6RouterRecord(const Byte* in, std::size_t len, K6RouterRecord& out,
                                std::size_t* consumed) noexcept {
    out = K6RouterRecord{};
    if (consumed) *consumed = 0;
    if (in == nullptr && len != 0) return Kad6Status::NullArgument;

    ByteReader r(in, len);
    out.version      = r.u8();
    out.flags        = r.u8();
    const Byte count = r.u8();
    const Byte reserved = r.u8();
    if (!r.ok()) { out = K6RouterRecord{}; return Kad6Status::Truncated; }
    if (reserved != 0) { out = K6RouterRecord{}; return Kad6Status::Malformed; }
    // Count range BEFORE reading/allocating endpoints (spec K6-NATIVE-003).
    if (count < kK6RouterMinEndpoints || count > kK6RouterMaxEndpoints) {
        out = K6RouterRecord{};
        return Kad6Status::Malformed;
    }

    if (!r.bytes(out.kad_id.data(), out.kad_id.size()) ||
        !r.bytes(out.node_pub.data(), out.node_pub.size())) {
        out = K6RouterRecord{};
        return Kad6Status::Truncated;
    }
    out.epoch       = r.u64le();
    out.caps        = r.u64le();
    out.valid_from  = r.u64le();
    out.valid_until = r.u64le();
    if (!r.ok()) { out = K6RouterRecord{}; return Kad6Status::Truncated; }

    const Kad6Status fields = ValidateRouterScalars(out);
    if (fields != Kad6Status::Ok) {
        out = K6RouterRecord{};
        return fields == Kad6Status::UnsupportedVersion
            ? fields : Kad6Status::Malformed;
    }

    out.endpoints.reserve(count); // count <= 4
    for (Byte i = 0; i < count; ++i) {
        K6Endpoint e;
        std::size_t epConsumed = 0;
        const Kad6Status es = DecodeK6Endpoint(in + r.pos(), len - r.pos(), e, &epConsumed);
        if (es != Kad6Status::Ok) { out = K6RouterRecord{}; return es; }
        (void)r.take(epConsumed);
        out.endpoints.push_back(e);
    }

    if (!r.bytes(out.signature.data(), out.signature.size()) || !r.ok()) {
        out = K6RouterRecord{};
        return Kad6Status::Truncated;
    }
    // Validate endpoint uniqueness after all endpoints are available. The
    // cheap scalar checks above deliberately precede allocation and parsing.
    const Kad6Status complete = ValidateRouterFields(out);
    if (complete != Kad6Status::Ok) {
        out = K6RouterRecord{};
        return complete == Kad6Status::UnsupportedVersion
            ? complete : Kad6Status::Malformed;
    }
    if (consumed) *consumed = r.pos();
    return Kad6Status::Ok;
}

Kad6Status SignK6RouterRecord(const Kad6CryptoHooks& h, const Byte* sk, std::size_t skLen,
                              K6RouterRecord& r, std::vector<Byte>& out) {
    out.clear();
    if (!h.ed25519_sign) return Kad6Status::BadValue;
    const Kad6Status fields = ValidateRouterFields(r);
    if (fields != Kad6Status::Ok) return fields;
    std::vector<Byte> body;
    const Kad6Status ss = K6RouterRecordSerializeSigned(r, body);
    if (ss != Kad6Status::Ok) return ss;
    std::vector<Byte> msg;
    BuildSignedMessage(kRouterDomain, sizeof(kRouterDomain) - 1, body, msg);
    Byte sig[kEd25519SigSize];
    if (!h.ed25519_sign(sk, skLen, msg.data(), msg.size(), sig))
        return Kad6Status::AuthFailed;
    std::copy(sig, sig + kEd25519SigSize, r.signature.begin());
    return EncodeK6RouterRecord(r, out);
}

Kad6Status VerifyK6RouterRecord(const Kad6CryptoHooks& h, const K6RouterRecord& r) {
    if (!h.ed25519_verify) return Kad6Status::BadValue;
    // ── cheap structural gate, BEFORE the expensive Ed25519 (spec K6-NATIVE-003)
    const Kad6Status fields = ValidateRouterFields(r);
    if (fields != Kad6Status::Ok) return fields;

    std::vector<Byte> body;
    const Kad6Status ss = K6RouterRecordSerializeSigned(r, body);
    if (ss != Kad6Status::Ok) return ss;
    std::vector<Byte> msg;
    BuildSignedMessage(kRouterDomain, sizeof(kRouterDomain) - 1, body, msg);
    if (!h.ed25519_verify(r.node_pub.data(), msg.data(), msg.size(), r.signature.data()))
        return Kad6Status::AuthFailed;
    return Kad6Status::Ok;
}

Kad6Status AcceptK6RouterRecord(const Kad6CryptoHooks& h,
                                const K6RouterRecord& r,
                                std::uint64_t& seenEpoch,
                                std::uint64_t nowUnix) {
    const Kad6Status shape = VerifyK6RouterRecord(h, r);
    if (shape != Kad6Status::Ok)
        return shape;
    const Kad6Status fresh = K6RouterRecordCheckFresh(r, nowUnix);
    if (fresh != Kad6Status::Ok)
        return fresh;
    const Kad6Status epoch = K6CheckEpochAdvance(seenEpoch, r.epoch);
    if (epoch != Kad6Status::Ok)
        return epoch;
    seenEpoch = r.epoch;
    return Kad6Status::Ok;
}

// ════════════════════════════════════════════════════════════════════════════
// 4) K6SourceRecord (+ K6ExitDescriptor)
// ════════════════════════════════════════════════════════════════════════════
// One exit descriptor: exit_node_pub[32] | endpoint | lease_hint u64 | caps u64
// | exit_expires_at u64. Appends to `out`; no partial write on endpoint error.
static Kad6Status SerializeExitDescriptor(const K6ExitDescriptor& e, std::vector<Byte>& out) {
    std::vector<Byte> ep;
    const Kad6Status s = EncodeK6Endpoint(e.endpoint, ep); // validates address family
    if (s != Kad6Status::Ok) return s;
    ByteWriter w(out);
    w.bytes(e.exit_node_pub.data(), e.exit_node_pub.size());
    w.bytes(ep.data(), ep.size());
    w.u64le(e.lease_hint);
    w.u64le(e.caps);
    w.u64le(e.exit_expires_at);
    return Kad6Status::Ok;
}

static Kad6Status DecodeExitDescriptor(const Byte* in, std::size_t len,
                                       K6ExitDescriptor& out, std::size_t* consumed) noexcept {
    out = K6ExitDescriptor{};
    if (consumed) *consumed = 0;

    ByteReader r(in, len);
    if (!r.bytes(out.exit_node_pub.data(), out.exit_node_pub.size()) || !r.ok()) {
        out = K6ExitDescriptor{};
        return Kad6Status::Truncated;
    }
    std::size_t epConsumed = 0;
    const Kad6Status es = DecodeK6Endpoint(in + r.pos(), len - r.pos(), out.endpoint, &epConsumed);
    if (es != Kad6Status::Ok) { out = K6ExitDescriptor{}; return es; }
    (void)r.take(epConsumed);
    out.lease_hint      = r.u64le();
    out.caps            = r.u64le();
    out.exit_expires_at = r.u64le();
    if (!r.ok()) { out = K6ExitDescriptor{}; return Kad6Status::Truncated; }
    if (consumed) *consumed = r.pos();
    return Kad6Status::Ok;
}

Kad6Status K6SourceRecordSerializeSigned(const K6SourceRecord& s, std::vector<Byte>& out) {
    out.clear();
    const std::size_t n = s.exits.size();
    if (n < kK6SourceMinExits || n > kK6SourceMaxExits)
        return Kad6Status::Malformed;
    if (s.compat_pub.size() > kK6SourceMaxCompatPubLen)
        return Kad6Status::TooLarge;

    std::vector<Byte> exitsBuf;
    for (const K6ExitDescriptor& e : s.exits) {
        const Kad6Status es = SerializeExitDescriptor(e, exitsBuf);
        if (es != Kad6Status::Ok) { out.clear(); return es; }
    }

    ByteWriter w(out);
    w.u8(s.version);
    w.u8(s.flags);
    w.u8(static_cast<Byte>(n));
    w.u8(0); // reserved
    w.bytes(s.object_hash.data(), s.object_hash.size());
    w.bytes(s.source_pseudonym.data(), s.source_pseudonym.size());
    w.u64le(s.source_epoch);
    w.u64le(s.created_at);
    w.u64le(s.expires_at);
    w.bytes(s.service_token.data(), s.service_token.size());
    w.bytes(exitsBuf.data(), exitsBuf.size());
    w.bytes(s.metadata_hash.data(), s.metadata_hash.size());
    w.u16le(static_cast<std::uint16_t>(s.compat_pub.size()));
    w.bytes(s.compat_pub.data(), s.compat_pub.size());
    w.bytes(s.pub_key.data(), s.pub_key.size());
    return Kad6Status::Ok;
}

Kad6Status EncodeK6SourceRecord(const K6SourceRecord& s, std::vector<Byte>& out) {
    const Kad6Status st = K6SourceRecordSerializeSigned(s, out);
    if (st != Kad6Status::Ok) { out.clear(); return st; }
    ByteWriter w(out);
    w.bytes(s.signature.data(), s.signature.size());
    return Kad6Status::Ok;
}

Kad6Status DecodeK6SourceRecord(const Byte* in, std::size_t len, K6SourceRecord& out,
                                std::size_t* consumed) noexcept {
    out = K6SourceRecord{};
    if (consumed) *consumed = 0;
    if (in == nullptr && len != 0) return Kad6Status::NullArgument;

    ByteReader r(in, len);
    out.version         = r.u8();
    out.flags           = r.u8();
    const Byte count    = r.u8();
    const Byte reserved = r.u8();
    if (!r.ok()) { out = K6SourceRecord{}; return Kad6Status::Truncated; }
    if (reserved != 0) { out = K6SourceRecord{}; return Kad6Status::Malformed; }
    if (count < kK6SourceMinExits || count > kK6SourceMaxExits) {
        out = K6SourceRecord{};
        return Kad6Status::Malformed;
    }

    if (!r.bytes(out.object_hash.data(), out.object_hash.size()) ||
        !r.bytes(out.source_pseudonym.data(), out.source_pseudonym.size())) {
        out = K6SourceRecord{};
        return Kad6Status::Truncated;
    }
    out.source_epoch = r.u64le();
    out.created_at   = r.u64le();
    out.expires_at   = r.u64le();
    if (!r.bytes(out.service_token.data(), out.service_token.size()) || !r.ok()) {
        out = K6SourceRecord{};
        return Kad6Status::Truncated;
    }

    out.exits.reserve(count); // count <= 3
    for (Byte i = 0; i < count; ++i) {
        K6ExitDescriptor e;
        std::size_t exConsumed = 0;
        const Kad6Status es = DecodeExitDescriptor(in + r.pos(), len - r.pos(), e, &exConsumed);
        if (es != Kad6Status::Ok) { out = K6SourceRecord{}; return es; }
        (void)r.take(exConsumed);
        out.exits.push_back(e);
    }

    if (!r.bytes(out.metadata_hash.data(), out.metadata_hash.size())) {
        out = K6SourceRecord{};
        return Kad6Status::Truncated;
    }
    const std::uint16_t compatLen = r.u16le();
    if (!r.ok()) { out = K6SourceRecord{}; return Kad6Status::Truncated; }
    // Length cap BEFORE allocating/reading the bytes (spec K6-NATIVE-003).
    if (compatLen > kK6SourceMaxCompatPubLen) {
        out = K6SourceRecord{};
        return Kad6Status::TooLarge;
    }
    out.compat_pub.resize(compatLen);
    if (compatLen != 0 && !r.bytes(out.compat_pub.data(), compatLen)) {
        out = K6SourceRecord{};
        return Kad6Status::Truncated;
    }
    if (!r.bytes(out.pub_key.data(), out.pub_key.size()) ||
        !r.bytes(out.signature.data(), out.signature.size()) || !r.ok()) {
        out = K6SourceRecord{};
        return Kad6Status::Truncated;
    }
    if (consumed) *consumed = r.pos();
    return Kad6Status::Ok;
}

Kad6Status SignK6SourceRecord(const Kad6CryptoHooks& h, const Byte* sk, std::size_t skLen,
                              K6SourceRecord& s, std::vector<Byte>& out) {
    out.clear();
    if (!h.ed25519_sign || !h.sha256) return Kad6Status::BadValue;
    const Kad6Status fields = ValidateSourceFields(s);
    if (fields != Kad6Status::Ok) return fields;
    const Kad6Status ps = K6DeriveSourcePseudonym(h, s.pub_key, s.source_pseudonym);
    if (ps != Kad6Status::Ok) return ps;
    std::vector<Byte> body;
    const Kad6Status ss = K6SourceRecordSerializeSigned(s, body);
    if (ss != Kad6Status::Ok) return ss;
    std::vector<Byte> msg;
    BuildSignedMessage(kSourceDomain, sizeof(kSourceDomain) - 1, body, msg);
    Byte sig[kEd25519SigSize];
    if (!h.ed25519_sign(sk, skLen, msg.data(), msg.size(), sig))
        return Kad6Status::AuthFailed;
    std::copy(sig, sig + kEd25519SigSize, s.signature.begin());
    return EncodeK6SourceRecord(s, out);
}

Kad6Status K6DeriveSourcePseudonym(const Kad6CryptoHooks& h,
                                   const Ed25519Pub& pubKey,
                                   Hash16& out) {
    out.fill(0);
    if (!h.sha256)
        return Kad6Status::BadValue;
    std::vector<Byte> msg;
    const Byte* domain = reinterpret_cast<const Byte*>(kSourcePseudonymDomain);
    msg.insert(msg.end(), domain, domain + sizeof(kSourcePseudonymDomain) - 1);
    msg.insert(msg.end(), pubKey.begin(), pubKey.end());
    Byte digest[kHash32Size];
    if (!h.sha256(msg.data(), msg.size(), digest))
        return Kad6Status::AuthFailed;
    std::copy(digest, digest + kHash16Size, out.begin());
    return Kad6Status::Ok;
}

Kad6Status VerifyK6SourceRecord(const Kad6CryptoHooks& h, const K6SourceRecord& s) {
    if (!h.ed25519_verify || !h.sha256) return Kad6Status::BadValue;
    // ── cheap structural gate, BEFORE the expensive Ed25519 (spec K6-NATIVE-003)
    const Kad6Status fields = ValidateSourceFields(s);
    if (fields != Kad6Status::Ok) return fields;

    Hash16 expectedPseudonym{};
    const Kad6Status ps = K6DeriveSourcePseudonym(h, s.pub_key, expectedPseudonym);
    if (ps != Kad6Status::Ok) return ps;
    if (!Kad6CtEqual(expectedPseudonym.data(), s.source_pseudonym.data(), kHash16Size))
        return Kad6Status::AuthFailed;

    std::vector<Byte> body;
    const Kad6Status ss = K6SourceRecordSerializeSigned(s, body);
    if (ss != Kad6Status::Ok) return ss;
    std::vector<Byte> msg;
    BuildSignedMessage(kSourceDomain, sizeof(kSourceDomain) - 1, body, msg);
    if (!h.ed25519_verify(s.pub_key.data(), msg.data(), msg.size(), s.signature.data()))
        return Kad6Status::AuthFailed;
    return Kad6Status::Ok;
}

Kad6Status AcceptK6SourceRecord(const Kad6CryptoHooks& h,
                                const K6SourceRecord& s,
                                std::uint64_t& seenEpoch,
                                std::uint64_t nowUnix) {
    const Kad6Status shape = VerifyK6SourceRecord(h, s);
    if (shape != Kad6Status::Ok)
        return shape;
    const Kad6Status fresh = K6SourceRecordCheckFresh(s, nowUnix);
    if (fresh != Kad6Status::Ok)
        return fresh;
    const Kad6Status epoch = K6CheckEpochAdvance(seenEpoch, s.source_epoch);
    if (epoch != Kad6Status::Ok)
        return epoch;
    seenEpoch = s.source_epoch;
    return Kad6Status::Ok;
}

} // namespace kad6
