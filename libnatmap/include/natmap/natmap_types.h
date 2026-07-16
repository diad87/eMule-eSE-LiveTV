#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace natmap {

enum class AddressFamily : std::uint8_t {
    Unspecified = 0,
    IPv4 = 4,
    IPv6 = 6,
};

enum class Transport : std::uint8_t {
    Tcp = 1,
    Udp = 2,
};

enum class MapperKind : std::uint8_t {
    None = 0,
    Existing = 1,
    UpnpIgd = 2,
    Pcp = 3,
    NatPmp = 4,
    FirewallPinhole = 5,
};

enum class EndpointSource : std::uint8_t {
    None = 0,
    LocalInterface = 1,
    ServerObserved = 2,
    UpnpExternalAddress = 3,
    PcpMap = 4,
    NatPmpPublicAddress = 5,
    PeerProbe = 6,
    ServerIdChange = 7,
};

enum class ReachabilityState : std::uint8_t {
    Disabled = 0,
    Discovering = 1,
    Mapping = 2,
    CandidateMapped = 3,
    Verifying = 4,
    Reachable = 5,
    Renewing = 6,
    Degraded = 7,
    BlockedByCgnat = 8,
    BlockedByRouter = 9,
};

enum class ReachabilityPlane : std::uint8_t {
    Ed2kTcpV4 = 0,
    KadUdpV4 = 1,
    DirectV6 = 2,
};

// Values are persisted in diagnostics. Append only; never renumber.
enum class ReasonCode : std::uint16_t {
    None = 0,
    DisabledByPreference = 1,
    NoListener = 2,
    NoRoute = 3,
    NoGateway = 4,
    NoMappingProtocol = 5,
    OperatorDenied = 6,
    MappingDenied = 7,
    MappingConflict = 8,
    MappingTimeout = 9,
    InvalidResponse = 10,
    StaleGeneration = 11,
    LeaseExpired = 12,
    InterfaceChanged = 13,
    EndpointDependentMapping = 14,
    InboundFiltered = 15,
    ServerCallbackFailed = 16,
    PeerIncompatible = 17,
    PortInUse = 18,
    VerificationTimeout = 19,
    CgnatWithoutLease = 20,
    RouterRejectedAllCandidates = 21,
};

enum class EvidenceKind : std::uint8_t {
    None = 0,
    MappingLease = 1,
    ServerObservedEndpoint = 2,
    ServerHighId = 3,
    InboundTcpAccept = 4,
    DirectPeerHandshake = 5,
};

struct IpAddress {
    AddressFamily family = AddressFamily::Unspecified;
    std::array<std::uint8_t, 16> bytes{};

    static IpAddress V4(std::uint8_t a, std::uint8_t b,
                        std::uint8_t c, std::uint8_t d) noexcept {
        IpAddress result{};
        result.family = AddressFamily::IPv4;
        result.bytes[0] = a;
        result.bytes[1] = b;
        result.bytes[2] = c;
        result.bytes[3] = d;
        return result;
    }

    bool IsSpecified() const noexcept {
        return family == AddressFamily::IPv4 || family == AddressFamily::IPv6;
    }

    bool IsUnspecified() const noexcept {
        if (!IsSpecified())
            return true;
        const std::size_t length = family == AddressFamily::IPv4 ? 4u : 16u;
        for (std::size_t i = 0; i < length; ++i)
            if (bytes[i] != 0)
                return false;
        return true;
    }

    bool IsPrivateOrSharedV4() const noexcept {
        if (family != AddressFamily::IPv4)
            return false;
        return IsRfc1918V4() || IsSharedCgnatV4() || bytes[0] == 127 ||
               (bytes[0] == 169 && bytes[1] == 254);
    }

    bool IsRfc1918V4() const noexcept {
        if (family != AddressFamily::IPv4)
            return false;
        const std::uint8_t a = bytes[0];
        const std::uint8_t b = bytes[1];
        return a == 10 || (a == 172 && b >= 16 && b <= 31) ||
               (a == 192 && b == 168);
    }

    bool IsSharedCgnatV4() const noexcept {
        return family == AddressFamily::IPv4 && bytes[0] == 100 &&
               bytes[1] >= 64 && bytes[1] <= 127;
    }
};

struct Endpoint {
    IpAddress address{};
    std::uint16_t port = 0;
    EndpointSource source = EndpointSource::None;

    bool IsUsable() const noexcept {
        return address.IsSpecified() && port != 0;
    }
};

struct PortIntent {
    Transport transport = Transport::Tcp;
    Endpoint local{};
    // local, gateway-selected, three high ports, 443 and 80.
    std::array<std::uint16_t, 7> external_candidates{};
    std::uint8_t candidate_count = 0;
    std::uint32_t requested_lifetime_seconds = 0;
    bool allow_any_external_port = true;

    bool IsValid() const noexcept {
        return local.IsUsable() && candidate_count <= external_candidates.size();
    }
};

struct PortLease {
    MapperKind mapper = MapperKind::None;
    Transport transport = Transport::Tcp;
    Endpoint gateway{};
    Endpoint local{};
    Endpoint public_endpoint{};
    std::uint16_t requested_external_port = 0;
    std::uint16_t granted_external_port = 0;
    std::uint32_t lifetime_seconds = 0;
    std::uint32_t mapper_epoch = 0;
    std::array<std::uint8_t, 12> ownership_nonce{};
    std::uint64_t generation = 0;
    bool owned_by_us = false;

    bool IsStructurallyValid() const noexcept {
        return mapper != MapperKind::None && local.IsUsable() &&
               public_endpoint.IsUsable() && !public_endpoint.address.IsUnspecified() &&
               granted_external_port != 0 &&
               public_endpoint.port == granted_external_port && generation != 0;
    }
};

struct Evidence {
    EvidenceKind kind = EvidenceKind::None;
    Endpoint endpoint{};
    std::uint64_t generation = 0;
    std::uint64_t observed_monotonic_ms = 0;

    bool IsCurrent(std::uint64_t current_generation) const noexcept {
        return kind != EvidenceKind::None && generation == current_generation;
    }
};

struct PlaneSnapshot {
    ReachabilityState state = ReachabilityState::Disabled;
    ReasonCode reason = ReasonCode::None;
    Endpoint local{};
    Endpoint mapped{};
    Endpoint advertised{};
    PortLease lease{};
    Evidence primary_evidence{};
    Evidence inbound_evidence{};
    std::uint64_t generation = 0;

    bool HasClassicHighIdEvidence() const noexcept {
        return state == ReachabilityState::Reachable &&
               primary_evidence.kind == EvidenceKind::ServerHighId &&
               primary_evidence.IsCurrent(generation) &&
               inbound_evidence.kind == EvidenceKind::InboundTcpAccept &&
               inbound_evidence.IsCurrent(generation) &&
               advertised.IsUsable();
    }
};

struct ReachabilitySnapshot {
    PlaneSnapshot ed2k_tcp_v4{};
    PlaneSnapshot kad_udp_v4{};
    PlaneSnapshot direct_v6{};
    std::uint64_t topology_generation = 0;
};

static_assert(static_cast<std::uint16_t>(ReasonCode::RouterRejectedAllCandidates) == 21,
              "reason-code persistence contract changed");
static_assert(sizeof(PortLease::ownership_nonce) == 12,
              "PCP ownership nonce must remain 96 bits");

} // namespace natmap
