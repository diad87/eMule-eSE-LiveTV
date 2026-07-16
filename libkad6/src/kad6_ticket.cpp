// SPDX-License-Identifier: MIT
//
// libkad6 — kad6_ticket.cpp: K6TargetTicketV1 codec + MAC + policy (ticket K6-0.5).
#include "kad6/kad6_ticket.h"

#include <algorithm>

namespace kad6 {

// Exact ASCII of the domain-separation label (no trailing NUL on the wire).
static const char kTicketDomain[] = "eSE-Kad6-TargetTicket-v1";
static constexpr std::size_t kTicketDomainLen = sizeof(kTicketDomain) - 1; // drop NUL

// ── forbidden-target policy (spec K6-TKT-004) ──────────────────────────────
static bool V4Prefix(const Byte* p, Byte a, Byte b, int prefixBits) noexcept {
    if (p[0] != a)
        return false;
    if (prefixBits <= 8)
        return true;
    const Byte mask = static_cast<Byte>(0xFFu << (16 - prefixBits));
    return (p[1] & mask) == (b & mask);
}

static bool V4Prefix24(const Byte* p, Byte a, Byte b, Byte c) noexcept {
    return p[0] == a && p[1] == b && p[2] == c;
}

static bool V6Prefix(const Byte* p, const Byte* prefix, std::size_t bits) noexcept {
    const std::size_t whole = bits / 8;
    const std::size_t rem = bits % 8;
    for (std::size_t i = 0; i < whole; ++i) {
        if (p[i] != prefix[i])
            return false;
    }
    if (rem == 0)
        return true;
    const Byte mask = static_cast<Byte>(0xFFu << (8 - rem));
    return (p[whole] & mask) == (prefix[whole] & mask);
}

static bool AddressForbidden(const Kad6Address& in) noexcept {
    Kad6Address a = in;
    Kad6AddressNormalize(a); // IPv4-mapped IPv6 folds to IPv4 first
    const Byte* p = a.addr.data();

    if (a.family == Kad6Address::Family::IPv4) {
        const Byte b0 = p[0], b1 = p[1];
        if (b0 == 0 || b0 == 10 || b0 == 127) return true;
        if (V4Prefix(p, 100, 64, 10)) return true;        // shared/CGNAT
        if (b0 == 169 && b1 == 254) return true;          // link-local
        if (b0 == 172 && b1 >= 16 && b1 <= 31) return true;
        if (V4Prefix24(p, 192, 0, 0)) return true;        // IETF protocol assignments
        if (V4Prefix24(p, 192, 0, 2)) return true;        // TEST-NET-1
        if (V4Prefix24(p, 192, 31, 196)) return true;     // AS112-v4
        if (V4Prefix24(p, 192, 52, 193)) return true;     // AMT
        if (V4Prefix24(p, 192, 88, 99)) return true;      // deprecated 6to4 relay
        if (b0 == 192 && b1 == 168) return true;
        if (V4Prefix24(p, 192, 175, 48)) return true;     // AS112 direct delegation
        if (b0 == 198 && (b1 == 18 || b1 == 19)) return true; // benchmarking
        if (V4Prefix24(p, 198, 51, 100)) return true;     // TEST-NET-2
        if (V4Prefix24(p, 203, 0, 113)) return true;      // TEST-NET-3
        if (b0 >= 224) return true;                       // multicast/reserved/broadcast
        return false;
    }
    if (a.family == Kad6Address::Family::IPv6) {
        bool allZero = true;
        for (int i = 0; i < 16; ++i) { if (p[i]) { allZero = false; break; } }
        if (allZero) return true;                         // :: unspecified
        bool loop = true;
        for (int i = 0; i < 15; ++i) { if (p[i]) { loop = false; break; } }
        if (loop && p[15] == 1) return true;              // ::1 loopback
        // Only ordinary 2000::/3 global unicast is eligible. Translation,
        // discard, ULA, link-local and future/special ranges fail closed.
        if ((p[0] & 0xE0) != 0x20) return true;
        const Byte ietf2001[16] = {0x20,0x01};
        const Byte doc2001db8[16] = {0x20,0x01,0x0D,0xB8};
        const Byte sixToFour[16] = {0x20,0x02};
        const Byte doc3fff[16] = {0x3F,0xFF};
        if (V6Prefix(p, ietf2001, 23)) return true;        // IETF assignments/Teredo/etc.
        if (V6Prefix(p, doc2001db8, 32)) return true;     // documentation
        if (V6Prefix(p, sixToFour, 16)) return true;      // 6to4
        if (V6Prefix(p, doc3fff, 20)) return true;        // documentation
        return false;
    }
    return true; // Family::None or unknown => never a valid dial target
}

bool K6TicketTargetForbidden(const K6TargetTicket& t) noexcept {
    if (AddressForbidden(t.target_endpoint.addr))
        return true;
    const bool tcp = (t.service == static_cast<Byte>(K6TicketService::Ed2kTcp));
    const std::uint16_t port = tcp ? t.target_endpoint.tcp_port : t.target_endpoint.udp_port;
    return port == 0;
}

Kad6Status K6TicketCheckTarget(const K6TargetTicket& t,
                               const K6TargetPolicy& policy) noexcept {
    if (K6TicketTargetForbidden(t))
        return Kad6Status::TargetForbidden;
    if (!policy.allow_target)
        return Kad6Status::BadValue;
    if (!policy.allow_target(policy.context, t.service, t.target_endpoint))
        return Kad6Status::TargetForbidden;
    return Kad6Status::Ok;
}

static Kad6Status ValidateTicketFields(const K6TargetTicket& t) noexcept {
    if (t.version != 1)
        return Kad6Status::UnsupportedVersion;
    if (t.service < static_cast<Byte>(K6TicketService::Kad2Udp) ||
        t.service > static_cast<Byte>(K6TicketService::Ed2kUdp))
        return Kad6Status::BadValue;
    if (t.provenance_kind < static_cast<Byte>(K6Provenance::KadResult) ||
        t.provenance_kind > static_cast<Byte>(K6Provenance::Admin))
        return Kad6Status::BadValue;
    if ((t.flags & ~kK6TicketFlagReusable) != 0)
        return Kad6Status::BadValue;
    if (t.max_bytes == 0 || t.max_connections == 0)
        return Kad6Status::BadValue;
    if ((t.flags & kK6TicketFlagReusable) == 0 && t.max_connections != 1)
        return Kad6Status::BadValue;
    if (t.expires_at <= t.issued_at)
        return Kad6Status::BadValue;
    if (t.expires_at - t.issued_at > kK6TicketMaxTtlSeconds)
        return Kad6Status::BadValue;
    // A ticket must never outlive the endpoint record that authorized it.
    if (t.target_endpoint.valid_until == 0 ||
        t.expires_at > t.target_endpoint.valid_until)
        return Kad6Status::BadValue;
    return Kad6Status::Ok;
}

// ── serialization ──────────────────────────────────────────────────────────
Kad6Status K6TicketSerializeSigned(const K6TargetTicket& t, std::vector<Byte>& out) {
    out.clear();
    std::vector<Byte> ep;
    const Kad6Status s = EncodeK6Endpoint(t.target_endpoint, ep); // validates address family
    if (s != Kad6Status::Ok)
        return s;

    ByteWriter w(out);
    w.u8(t.version);
    w.u8(t.service);
    w.u16le(t.flags);
    w.u64le(t.lease_id);
    w.u8(t.provenance_kind);
    w.u8(0); // reserved
    w.u16le(t.provenance_flags);
    w.u64le(t.provenance_session);
    w.u64le(t.provenance_stream);
    w.u64le(t.provenance_seq);
    w.bytes(t.provenance_digest.data(), t.provenance_digest.size());
    w.bytes(ep.data(), ep.size());
    w.bytes(t.object_hash.data(), t.object_hash.size());
    w.u64le(t.issued_at);
    w.u64le(t.expires_at);
    w.u64le(t.max_bytes);
    w.u16le(t.max_connections);
    w.bytes(t.nonce.data(), t.nonce.size());
    return Kad6Status::Ok;
}

Kad6Status EncodeK6TargetTicket(const K6TargetTicket& t, std::vector<Byte>& out) {
    const Kad6Status s = K6TicketSerializeSigned(t, out); // fills out with signed bytes
    if (s != Kad6Status::Ok) {
        out.clear();
        return s;
    }
    ByteWriter w(out); // appends after the signed bytes
    w.bytes(t.mac.data(), t.mac.size());
    return Kad6Status::Ok;
}

Kad6Status K6TicketComputeMac(const Kad6CryptoHooks& h,
                              const Byte* secret, std::size_t secretLen,
                              const K6TargetTicket& t, Byte macOut[kMacSize]) {
    if (!h.hmac_sha256)
        return Kad6Status::BadValue;
    if (!secret || secretLen == 0)
        return Kad6Status::BadValue;
    std::vector<Byte> body;
    const Kad6Status s = K6TicketSerializeSigned(t, body);
    if (s != Kad6Status::Ok)
        return s;

    std::vector<Byte> msg;
    msg.reserve(kTicketDomainLen + body.size());
    msg.insert(msg.end(),
               reinterpret_cast<const Byte*>(kTicketDomain),
               reinterpret_cast<const Byte*>(kTicketDomain) + kTicketDomainLen);
    msg.insert(msg.end(), body.begin(), body.end());

    if (!h.hmac_sha256(secret, secretLen, msg.data(), msg.size(), macOut))
        return Kad6Status::AuthFailed;
    return Kad6Status::Ok;
}

Kad6Status IssueK6TargetTicket(const Kad6CryptoHooks& h,
                               const K6TargetPolicy& policy,
                               const Byte* secret, std::size_t secretLen,
                               K6TargetTicket& t, std::vector<Byte>& out) {
    out.clear();
    t.version = 1;
    const Kad6Status fields = ValidateTicketFields(t);
    if (fields != Kad6Status::Ok)
        return fields;
    const Kad6Status target = K6TicketCheckTarget(t, policy);
    if (target != Kad6Status::Ok)
        return target;

    Byte mac[kMacSize];
    const Kad6Status s = K6TicketComputeMac(h, secret, secretLen, t, mac);
    if (s != Kad6Status::Ok)
        return s;
    std::copy(mac, mac + kMacSize, t.mac.begin());
    return EncodeK6TargetTicket(t, out);
}

Kad6Status DecodeK6TargetTicket(const Byte* in, std::size_t len,
                                K6TargetTicket& out, std::size_t* consumed) noexcept {
    out = K6TargetTicket{};
    if (consumed)
        *consumed = 0;
    if (in == nullptr && len != 0)
        return Kad6Status::NullArgument;

    ByteReader r(in, len);
    out.version         = r.u8();
    out.service         = r.u8();
    out.flags           = r.u16le();
    out.lease_id        = r.u64le();
    out.provenance_kind = r.u8();
    const Byte reserved = r.u8();
    out.provenance_flags   = r.u16le();
    out.provenance_session = r.u64le();
    out.provenance_stream  = r.u64le();
    out.provenance_seq     = r.u64le();
    if (!r.ok()) {
        out = K6TargetTicket{};
        return Kad6Status::Truncated;
    }
    if (reserved != 0) {
        out = K6TargetTicket{};
        return Kad6Status::Malformed;
    }
    if (!r.bytes(out.provenance_digest.data(), out.provenance_digest.size()) || !r.ok()) {
        out = K6TargetTicket{};
        return Kad6Status::Truncated;
    }

    std::size_t epConsumed = 0;
    const Kad6Status es = DecodeK6Endpoint(in + r.pos(), len - r.pos(),
                                           out.target_endpoint, &epConsumed);
    if (es != Kad6Status::Ok) {
        out = K6TargetTicket{};
        return es;
    }
    (void)r.take(epConsumed); // advance the cursor past the endpoint

    if (!r.bytes(out.object_hash.data(), out.object_hash.size())) {
        out = K6TargetTicket{};
        return Kad6Status::Truncated;
    }
    out.issued_at       = r.u64le();
    out.expires_at      = r.u64le();
    out.max_bytes       = r.u64le();
    out.max_connections = r.u16le();
    if (!r.bytes(out.nonce.data(), out.nonce.size()) ||
        !r.bytes(out.mac.data(), out.mac.size()) || !r.ok()) {
        out = K6TargetTicket{};
        return Kad6Status::Truncated;
    }
    if (consumed)
        *consumed = r.pos();
    return Kad6Status::Ok;
}

Kad6Status VerifyK6TargetTicket(const Kad6CryptoHooks& h,
                                const K6TargetPolicy& policy,
                                const Byte* secret, std::size_t secretLen,
                                const Byte* in, std::size_t len,
                                std::uint64_t nowUnix, K6TargetTicket& out) {
    out = K6TargetTicket{};
    K6TargetTicket candidate;
    std::size_t consumed = 0;
    const Kad6Status ds = DecodeK6TargetTicket(in, len, candidate, &consumed);
    if (ds != Kad6Status::Ok)
        return ds;
    if (consumed != len)
        return Kad6Status::Malformed;
    const Kad6Status fields = ValidateTicketFields(candidate);
    if (fields != Kad6Status::Ok)
        return fields;
    if (K6TicketTargetForbidden(candidate))
        return Kad6Status::TargetForbidden;

    Byte mac[kMacSize];
    const Kad6Status ms = K6TicketComputeMac(h, secret, secretLen, candidate, mac);
    if (ms != Kad6Status::Ok)
        return ms;
    if (!Kad6CtEqual(mac, candidate.mac.data(), kMacSize))
        return Kad6Status::AuthFailed;

    if (nowUnix >= candidate.expires_at)
        return Kad6Status::Expired;
    if (nowUnix < candidate.issued_at)
        return Kad6Status::BadValue;
    const Kad6Status target = K6TicketCheckTarget(candidate, policy);
    if (target != Kad6Status::Ok)
        return target;
    if (!policy.consume_use)
        return Kad6Status::BadValue;
    if (!policy.consume_use(policy.context, candidate))
        return Kad6Status::AuthFailed;
    out = candidate;
    return Kad6Status::Ok;
}

} // namespace kad6
