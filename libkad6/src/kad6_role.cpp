// SPDX-License-Identifier: MIT
#include "kad6/kad6_role.h"

#include <algorithm>

namespace kad6 {
namespace {

const char kRendezvousDomain[] = "eSE-Kad6-Rendezvous-v1";

bool Any(const Byte* bytes, std::size_t size) noexcept {
    Byte aggregate = 0;
    for (std::size_t i = 0; i < size; ++i) aggregate = static_cast<Byte>(aggregate | bytes[i]);
    return aggregate != 0;
}

bool ValidPref64Bits(Byte bits) noexcept {
    return bits == 32 || bits == 40 || bits == 48 || bits == 56 ||
           bits == 64 || bits == 96;
}

bool PrefixEqual(const std::array<Byte, 16>& a, const std::array<Byte, 16>& b,
                 Byte bits) noexcept {
    const std::size_t bytes = bits / 8;
    return Kad6CtEqual(a.data(), b.data(), bytes);
}

Kad6Status ValidateRendezvous(const K6RendezvousDescriptor& value) noexcept {
    if (value.version != kK6RendezvousVersion) return Kad6Status::UnsupportedVersion;
    if (value.flags || !Any(value.origin_node_pub.data(), value.origin_node_pub.size()) ||
        !Any(value.router_node_pub.data(), value.router_node_pub.size()) ||
        !Any(value.introduction_token.data(), value.introduction_token.size()) ||
        value.origin_node_pub == value.router_node_pub || value.valid_from == 0 ||
        value.valid_until <= value.valid_from ||
        value.valid_until - value.valid_from > kK6RendezvousMaxTtlSeconds)
        return Kad6Status::BadValue;
    return Kad6Status::Ok;
}

Kad6Status SerializeRendezvousSigned(const K6RendezvousDescriptor& value,
                                     std::vector<Byte>& out) {
    out.clear();
    const Kad6Status status = ValidateRendezvous(value);
    if (status != Kad6Status::Ok) return status;
    ByteWriter writer(out); writer.u8(value.version); writer.u8(value.flags); writer.u16le(0);
    writer.bytes(value.origin_node_pub.data(), value.origin_node_pub.size());
    writer.bytes(value.router_node_pub.data(), value.router_node_pub.size());
    writer.bytes(value.introduction_token.data(), value.introduction_token.size());
    writer.u64le(value.valid_from); writer.u64le(value.valid_until);
    return Kad6Status::Ok;
}

void SignatureMessage(const std::vector<Byte>& body, std::vector<Byte>& message) {
    const Byte* domain = reinterpret_cast<const Byte*>(kRendezvousDomain);
    message.assign(domain, domain + sizeof(kRendezvousDomain) - 1);
    message.insert(message.end(), body.begin(), body.end());
}

} // namespace

Kad6Status EncodeK6EndpointSet(const K6EndpointSet& value,
                                std::vector<Byte>& out) {
    return EncodeK6RouterRecord(value, out);
}

Kad6Status DecodeK6EndpointSet(const Byte* in, std::size_t len,
        K6EndpointSet& out, std::size_t* consumed) noexcept {
    return DecodeK6RouterRecord(in, len, out, consumed);
}

Kad6Status SignK6EndpointSet(const Kad6CryptoHooks& hooks,
        const Byte* secret, std::size_t secretLen, K6EndpointSet& value,
        std::vector<Byte>& out) {
    return SignK6RouterRecord(hooks, secret, secretLen, value, out);
}

Kad6Status VerifyK6EndpointSet(const Kad6CryptoHooks& hooks,
        const K6EndpointSet& value, std::uint64_t nowUnix) {
    const Kad6Status verified = VerifyK6RouterRecord(hooks, value);
    return verified != Kad6Status::Ok ? verified :
        K6RouterRecordCheckFresh(value, nowUnix);
}

Kad6Status BuildK6EndpointRace(const K6EndpointSet& endpointSet,
        const std::vector<K6EndpointCandidateHealth>& health,
        std::uint64_t nowUnix, std::uint32_t delayMs,
        std::vector<K6EndpointAttempt>& attempts) {
    attempts.clear();
    if (endpointSet.endpoints.empty() ||
        endpointSet.endpoints.size() > kK6RouterMaxEndpoints || nowUnix == 0)
        return Kad6Status::BadValue;
    if (delayMs > kK6HappyEyeballsMaxDelayMs) return Kad6Status::BadValue;
    struct Candidate { std::size_t index; const K6EndpointCandidateHealth* health; };
    Candidate best4 = {0, nullptr}, best6 = {0, nullptr};
    auto better = [](const K6EndpointCandidateHealth& candidate,
                     const K6EndpointCandidateHealth& current) {
        if (candidate.consecutive_failures != current.consecutive_failures)
            return candidate.consecutive_failures < current.consecutive_failures;
        if (candidate.endpoint.priority != current.endpoint.priority)
            return candidate.endpoint.priority < current.endpoint.priority;
        return candidate.last_success > current.last_success;
    };
    for (std::size_t i = 0; i < endpointSet.endpoints.size(); ++i) {
        const K6Endpoint& declared = endpointSet.endpoints[i];
        const K6EndpointCandidateHealth* state = nullptr;
        for (const K6EndpointCandidateHealth& candidate : health)
            if (candidate.endpoint.addr == declared.addr &&
                candidate.endpoint.udp_port == declared.udp_port) {
                state = &candidate; break;
            }
        if (!state || !state->verified || declared.valid_until <= nowUnix ||
            declared.udp_port == 0 ||
            (declared.transport_flags & kK6EpUdpKad6) == 0)
            continue;
        Candidate* family = declared.addr.family == Kad6Address::Family::IPv6
            ? &best6 : declared.addr.family == Kad6Address::Family::IPv4
                ? &best4 : nullptr;
        if (family && (!family->health || better(*state, *family->health)))
            *family = {i, state};
    }
    if (!best4.health && !best6.health) return Kad6Status::TargetForbidden;
    if (best6.health) attempts.push_back({best6.index,
        endpointSet.endpoints[best6.index], 0});
    if (best4.health) attempts.push_back({best4.index,
        endpointSet.endpoints[best4.index], best6.health ? delayMs : 0});
    return Kad6Status::Ok;
}

Kad6Status SelectK6EndpointRaceWinner(
        const std::vector<K6EndpointAttempt>& attempts,
        std::size_t successfulAttempt, K6Endpoint& winner,
        std::vector<std::size_t>& cancelledAttempts) noexcept {
    winner = K6Endpoint{}; cancelledAttempts.clear();
    if (successfulAttempt >= attempts.size()) return Kad6Status::BadValue;
    winner = attempts[successfulAttempt].endpoint;
    for (std::size_t i = 0; i < attempts.size(); ++i)
        if (i != successfulAttempt) cancelledAttempts.push_back(i);
    return Kad6Status::Ok;
}

bool K6AddressMatchesPref64(const Kad6Address& address, const K6Pref64& pref64,
                            std::uint64_t nowUnix) noexcept {
    return address.family == Kad6Address::Family::IPv6 &&
        ValidPref64Bits(pref64.prefix_bits) && pref64.valid_until > nowUnix &&
        PrefixEqual(address.addr, pref64.prefix, pref64.prefix_bits);
}

bool K6RoleEndpointAdvertisable(const K6RoleEvidence& evidence,
                                std::uint64_t nowUnix) noexcept {
    if (!evidence.actual_public_endpoint ||
        (evidence.local_endpoint.family != Kad6Address::Family::IPv6 &&
         evidence.local_endpoint.family != Kad6Address::Family::IPv4) ||
        evidence.endpoint_generation == 0 || evidence.observed_at == 0 ||
        nowUnix < evidence.observed_at || nowUnix >= evidence.valid_until)
        return false;
    for (const K6Pref64& pref64 : evidence.pref64)
        if (K6AddressMatchesPref64(evidence.local_endpoint, pref64, nowUnix)) return false;
    return true;
}

K6NodeRole ClassifyK6NodeRole(const K6RoleEvidence& evidence,
                              std::uint64_t nowUnix) noexcept {
    if (!evidence.outbound_authenticated_kad6) return K6NodeRole::Unavailable;
    if (!K6RoleEndpointAdvertisable(evidence, nowUnix)) return K6NodeRole::OriginOnly;
    std::vector<std::uint32_t> probeAsns;
    for (const K6InboundProbe& probe : evidence.probes) {
        if (!probe.probe_asn || probe.endpoint_generation != evidence.endpoint_generation ||
            !probe.udp_return_ok || !probe.tcp_return_ok ||
            (std::find)(probeAsns.begin(), probeAsns.end(), probe.probe_asn) != probeAsns.end())
            continue;
        probeAsns.push_back(probe.probe_asn);
    }
    if (probeAsns.size() < 3) return K6NodeRole::OriginOnly;
    if (evidence.legacy_egress_ok && evidence.exit_service_policy_ok)
        return K6NodeRole::Exit;
    return K6NodeRole::Router;
}

Kad6Status EncodeK6RendezvousDescriptor(const K6RendezvousDescriptor& value,
                                         std::vector<Byte>& out) {
    const Kad6Status status = SerializeRendezvousSigned(value, out);
    if (status != Kad6Status::Ok) { out.clear(); return status; }
    ByteWriter writer(out); writer.bytes(value.signature.data(), value.signature.size());
    return Kad6Status::Ok;
}

Kad6Status DecodeK6RendezvousDescriptor(const Byte* in, std::size_t len,
        K6RendezvousDescriptor& out, std::size_t* consumed) noexcept {
    out = {}; if (consumed) *consumed = 0; if (!in && len) return Kad6Status::NullArgument;
    ByteReader reader(in, len); out.version = reader.u8(); out.flags = reader.u8();
    const std::uint16_t reserved = reader.u16le();
    reader.bytes(out.origin_node_pub.data(), out.origin_node_pub.size());
    reader.bytes(out.router_node_pub.data(), out.router_node_pub.size());
    reader.bytes(out.introduction_token.data(), out.introduction_token.size());
    out.valid_from = reader.u64le(); out.valid_until = reader.u64le();
    reader.bytes(out.signature.data(), out.signature.size());
    if (!reader.ok()) { out = {}; return Kad6Status::Truncated; }
    if (reader.pos() != len || reserved) { out = {}; return Kad6Status::Malformed; }
    const Kad6Status status = ValidateRendezvous(out);
    if (status != Kad6Status::Ok) { out = {}; return status; }
    if (consumed) *consumed = len;
    return Kad6Status::Ok;
}

Kad6Status SignK6RendezvousDescriptor(const Kad6CryptoHooks& hooks,
        const Byte* secret, std::size_t secretLen, K6RendezvousDescriptor& value,
        std::vector<Byte>& out) {
    out.clear(); if (!hooks.ed25519_sign) return Kad6Status::BadValue;
    std::vector<Byte> body, message;
    const Kad6Status status = SerializeRendezvousSigned(value, body);
    if (status != Kad6Status::Ok) return status;
    SignatureMessage(body, message);
    if (!hooks.ed25519_sign(secret, secretLen, message.data(), message.size(),
            value.signature.data())) return Kad6Status::AuthFailed;
    return EncodeK6RendezvousDescriptor(value, out);
}

Kad6Status VerifyK6RendezvousDescriptor(const Kad6CryptoHooks& hooks,
        const K6RendezvousDescriptor& value, std::uint64_t nowUnix) {
    if (!hooks.ed25519_verify) return Kad6Status::BadValue;
    std::vector<Byte> body, message;
    const Kad6Status status = SerializeRendezvousSigned(value, body);
    if (status != Kad6Status::Ok) return status;
    if (nowUnix < value.valid_from) return Kad6Status::BadValue;
    if (nowUnix >= value.valid_until) return Kad6Status::Expired;
    SignatureMessage(body, message);
    return hooks.ed25519_verify(value.origin_node_pub.data(), message.data(), message.size(),
        value.signature.data()) ? Kad6Status::Ok : Kad6Status::AuthFailed;
}

} // namespace kad6
