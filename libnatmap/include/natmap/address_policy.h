#pragma once

#include "natmap/natmap_types.h"

#include <cstdint>

namespace natmap {

enum class AddressClass : std::uint8_t {
    Unspecified = 0,
    Loopback = 1,
    LinkLocal = 2,
    Rfc1918 = 3,
    SharedCgnat = 4,
    Multicast = 5,
    Reserved = 6,
    Documentation = 7,
    Public = 8,
    UniqueLocal = 9,
    Global = 10,
};

enum class AddressReason : std::uint8_t {
    FamilyUnspecified = 0,
    NonCanonical = 1,
    Ipv4Unspecified = 2,
    Ipv4Loopback = 3,
    Ipv4LinkLocal = 4,
    Ipv4Rfc1918 = 5,
    Ipv4SharedCgnat = 6,
    Ipv4Multicast = 7,
    Ipv4Reserved = 8,
    Ipv4Documentation = 9,
    Ipv4Public = 10,
    Ipv6Unspecified = 11,
    Ipv6Loopback = 12,
    Ipv6LinkLocal = 13,
    Ipv6UniqueLocal = 14,
    Ipv6Multicast = 15,
    Ipv6Documentation = 16,
    Ipv6Global = 17,
    Ipv6Reserved = 18,
};

struct AddressDecision {
    AddressClass address_class = AddressClass::Unspecified;
    AddressReason reason = AddressReason::FamilyUnspecified;
    bool globally_routable = false;
    bool direct_publishable = false;
};

AddressDecision ClassifyAddress(const IpAddress& address) noexcept;
const char* StableAddressReason(AddressReason reason) noexcept;

enum class NetworkOrigin : std::uint8_t {
    Native = 0,
    Overlay = 1,
    Unknown = 2,
};

enum class NetworkOriginReason : std::uint8_t {
    NativeDefaultRoute = 0,
    KnownOverlay = 1,
    UnknownTunnel = 2,
    LoopbackAdapter = 3,
    EvidenceMissing = 4,
};

struct NetworkOriginEvidence {
    const char* adapter_name = nullptr;
    const char* adapter_description = nullptr;
    bool is_tunnel = false;
    bool is_loopback = false;
    bool has_default_gateway = false;
};

struct NetworkOriginDecision {
    NetworkOrigin origin = NetworkOrigin::Unknown;
    NetworkOriginReason reason = NetworkOriginReason::EvidenceMissing;
};

NetworkOriginDecision ClassifyNetworkOrigin(
    const NetworkOriginEvidence& evidence) noexcept;
const char* StableNetworkOriginReason(NetworkOriginReason reason) noexcept;
bool IsNativeCgnatEvidence(const IpAddress& address,
                           NetworkOrigin origin) noexcept;

enum class RouteBindingStatus : std::uint8_t {
    Valid = 0,
    InterfaceInvalid = 1,
    InterfaceMissing = 2,
    FamilyMismatch = 3,
    AddressUnusable = 4,
    OriginInvalid = 5,
};

struct RouteBindingIdentity {
    IpAddress local_address{};
    std::uint32_t interface_index = 0;
    AddressFamily family = AddressFamily::Unspecified;
    NetworkOrigin origin = NetworkOrigin::Unknown;
    bool interface_present = false;
};

RouteBindingStatus ValidateRouteBinding(
    const RouteBindingIdentity& binding) noexcept;
bool SameRouteBinding(const RouteBindingIdentity& left,
                      const RouteBindingIdentity& right) noexcept;

struct PrivateAddressScope {
    bool enabled = false;
    std::uint32_t interface_index = 0;
    AddressFamily family = AddressFamily::Unspecified;
    IpAddress network{};
    std::uint8_t prefix_length = 0;
};

bool AllowsScopedPrivateAddress(const PrivateAddressScope& scope,
                                const IpAddress& address,
                                std::uint32_t interface_index) noexcept;

}  // namespace natmap
