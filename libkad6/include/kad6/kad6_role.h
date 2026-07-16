// SPDX-License-Identifier: MIT
// Kad6 v2 role classification and short-lived origin rendezvous descriptors.
#pragma once

#include "kad6/kad6_address.h"
#include "kad6/kad6_crypto.h"
#include "kad6/kad6_records.h"

#include <array>
#include <cstdint>
#include <vector>

namespace kad6 {

enum class K6NodeRole : Byte { Unavailable = 0, OriginOnly = 1, Router = 2, Exit = 3 };
enum class K6AccessKind : Byte {
    Unknown = 0, NativeIpv6 = 1, Nat64Dns64 = 2, Xlat464 = 3,
    FirewalledGlobalIpv6 = 4, PrefixChurn = 5, PublicIpv4 = 6,
    CgnatIpv4 = 7
};

// Rev3 calls the signed, family-tagged locator declaration an EndpointSet.
// The wire object is deliberately the existing RouterRecord rather than a
// second competing identity record: one signature binds NodeIdentity, KadID,
// epoch, capabilities and up to four IPv4/IPv6 candidates.
using K6EndpointSet = K6RouterRecord;

Kad6Status EncodeK6EndpointSet(const K6EndpointSet& value,
                                std::vector<Byte>& out);
Kad6Status DecodeK6EndpointSet(const Byte* in, std::size_t len,
                                K6EndpointSet& out,
                                std::size_t* consumed = nullptr) noexcept;
Kad6Status SignK6EndpointSet(const Kad6CryptoHooks& hooks,
                              const Byte* secret, std::size_t secretLen,
                              K6EndpointSet& value, std::vector<Byte>& out);
Kad6Status VerifyK6EndpointSet(const Kad6CryptoHooks& hooks,
                                const K6EndpointSet& value,
                                std::uint64_t nowUnix);

struct K6EndpointCandidateHealth {
    K6Endpoint endpoint;
    bool verified = false;
    Byte consecutive_failures = 0;
    std::uint64_t last_success = 0;
    std::uint64_t last_failure = 0;
};

struct K6EndpointAttempt {
    std::size_t candidate_index = 0;
    K6Endpoint endpoint;
    std::uint32_t start_after_ms = 0;
};

constexpr std::uint32_t kK6HappyEyeballsDefaultDelayMs = 250;
constexpr std::uint32_t kK6HappyEyeballsMaxDelayMs = 1000;

// Produces at most one attempt per family. IPv6 starts first when both are
// healthy; IPv4 follows after a bounded delay. Health is receiver-local and
// cannot be promoted merely by a third-party EndpointSet advertisement.
Kad6Status BuildK6EndpointRace(const K6EndpointSet& endpointSet,
                                const std::vector<K6EndpointCandidateHealth>& health,
                                std::uint64_t nowUnix,
                                std::uint32_t delayMs,
                                std::vector<K6EndpointAttempt>& attempts);
Kad6Status SelectK6EndpointRaceWinner(
    const std::vector<K6EndpointAttempt>& attempts,
    std::size_t successfulAttempt,
    K6Endpoint& winner,
    std::vector<std::size_t>& cancelledAttempts) noexcept;

struct K6Pref64 {
    std::array<Byte, 16> prefix{};
    Byte prefix_bits = 0;
    std::uint64_t valid_until = 0;
};

struct K6InboundProbe {
    std::uint32_t probe_asn = 0;
    std::uint64_t endpoint_generation = 0;
    bool udp_return_ok = false;
    bool tcp_return_ok = false;
};

struct K6RoleEvidence {
    K6AccessKind access_kind = K6AccessKind::Unknown;
    Kad6Address local_endpoint;
    std::uint64_t endpoint_generation = 0;
    std::uint64_t observed_at = 0;
    std::uint64_t valid_until = 0;
    std::vector<K6Pref64> pref64;
    std::vector<K6InboundProbe> probes;
    bool outbound_authenticated_kad6 = false;
    bool actual_public_endpoint = false;
    bool legacy_egress_ok = false;
    bool exit_service_policy_ok = false;
};

bool K6AddressMatchesPref64(const Kad6Address& address,
                            const K6Pref64& pref64,
                            std::uint64_t nowUnix) noexcept;
bool K6RoleEndpointAdvertisable(const K6RoleEvidence& evidence,
                                std::uint64_t nowUnix) noexcept;
K6NodeRole ClassifyK6NodeRole(const K6RoleEvidence& evidence,
                              std::uint64_t nowUnix) noexcept;

constexpr Byte kK6RendezvousVersion = 1;
constexpr std::uint64_t kK6RendezvousMaxTtlSeconds = 10u * 60u;

struct K6RendezvousDescriptor {
    Byte version = kK6RendezvousVersion;
    Byte flags = 0;
    Ed25519Pub origin_node_pub{};
    Ed25519Pub router_node_pub{};
    std::array<Byte, kNonce16Size> introduction_token{};
    std::uint64_t valid_from = 0;
    std::uint64_t valid_until = 0;
    Ed25519Sig signature{};
};

Kad6Status EncodeK6RendezvousDescriptor(const K6RendezvousDescriptor& value,
                                         std::vector<Byte>& out);
Kad6Status DecodeK6RendezvousDescriptor(const Byte* in, std::size_t len,
                                         K6RendezvousDescriptor& out,
                                         std::size_t* consumed = nullptr) noexcept;
Kad6Status SignK6RendezvousDescriptor(const Kad6CryptoHooks& hooks,
                                       const Byte* secret, std::size_t secretLen,
                                       K6RendezvousDescriptor& value,
                                       std::vector<Byte>& out);
Kad6Status VerifyK6RendezvousDescriptor(const Kad6CryptoHooks& hooks,
                                         const K6RendezvousDescriptor& value,
                                         std::uint64_t nowUnix);

} // namespace kad6
