#include "natmap/address_policy.h"

#include <cstddef>

namespace natmap {
namespace {

bool IsCanonicalV4(const IpAddress& address) noexcept {
    if (address.family != AddressFamily::IPv4)
        return false;
    for (std::size_t i = 4; i < address.bytes.size(); ++i)
        if (address.bytes[i] != 0)
            return false;
    return true;
}

bool AllZero(const IpAddress& address, std::size_t length) noexcept {
    for (std::size_t i = 0; i < length; ++i)
        if (address.bytes[i] != 0)
            return false;
    return true;
}

bool IsV6Loopback(const IpAddress& address) noexcept {
    for (std::size_t i = 0; i < 15; ++i)
        if (address.bytes[i] != 0)
            return false;
    return address.bytes[15] == 1;
}

bool MatchesV6Prefix(const IpAddress& address,
                     const std::array<std::uint8_t, 4>& prefix,
                     std::uint8_t prefix_length) noexcept {
    if (address.family != AddressFamily::IPv6 || prefix_length > 32)
        return false;
    const std::size_t wholeBytes = prefix_length / 8u;
    const std::uint8_t remainder =
        static_cast<std::uint8_t>(prefix_length % 8u);
    for (std::size_t i = 0; i < wholeBytes; ++i)
        if (address.bytes[i] != prefix[i])
            return false;
    if (remainder == 0)
        return true;
    const std::uint8_t mask =
        static_cast<std::uint8_t>(0xffu << (8u - remainder));
    return (address.bytes[wholeBytes] & mask) ==
           (prefix[wholeBytes] & mask);
}

bool IsAllocatedV6Global(const IpAddress& address) noexcept {
    struct Prefix {
        std::array<std::uint8_t, 4> bytes;
        std::uint8_t length;
    };
    // IANA IPv6 Global Unicast Address Space, 2025-10-10. Keep this
    // allow-list fail-closed: unallocated 2000::/3 space is not publishable.
    static constexpr Prefix prefixes[] = {
        {{0x20, 0x01, 0x02, 0x00}, 23},
        {{0x20, 0x01, 0x04, 0x00}, 23},
        {{0x20, 0x01, 0x06, 0x00}, 23},
        {{0x20, 0x01, 0x08, 0x00}, 22},
        {{0x20, 0x01, 0x0c, 0x00}, 23},
        {{0x20, 0x01, 0x0e, 0x00}, 23},
        {{0x20, 0x01, 0x12, 0x00}, 23},
        {{0x20, 0x01, 0x14, 0x00}, 22},
        {{0x20, 0x01, 0x18, 0x00}, 23},
        {{0x20, 0x01, 0x1a, 0x00}, 23},
        {{0x20, 0x01, 0x1c, 0x00}, 22},
        {{0x20, 0x01, 0x20, 0x00}, 19},
        {{0x20, 0x01, 0x40, 0x00}, 23},
        {{0x20, 0x01, 0x42, 0x00}, 23},
        {{0x20, 0x01, 0x44, 0x00}, 23},
        {{0x20, 0x01, 0x46, 0x00}, 23},
        {{0x20, 0x01, 0x48, 0x00}, 23},
        {{0x20, 0x01, 0x4a, 0x00}, 23},
        {{0x20, 0x01, 0x4c, 0x00}, 23},
        {{0x20, 0x01, 0x50, 0x00}, 20},
        {{0x20, 0x01, 0x80, 0x00}, 19},
        {{0x20, 0x01, 0xa0, 0x00}, 20},
        {{0x20, 0x01, 0xb0, 0x00}, 20},
        {{0x20, 0x03, 0x00, 0x00}, 18},
        {{0x24, 0x00, 0x00, 0x00}, 12},
        {{0x24, 0x10, 0x00, 0x00}, 12},
        {{0x26, 0x00, 0x00, 0x00}, 12},
        {{0x26, 0x10, 0x00, 0x00}, 23},
        {{0x26, 0x20, 0x00, 0x00}, 23},
        {{0x26, 0x30, 0x00, 0x00}, 12},
        {{0x28, 0x00, 0x00, 0x00}, 12},
        {{0x2a, 0x00, 0x00, 0x00}, 12},
        {{0x2a, 0x10, 0x00, 0x00}, 12},
        {{0x2c, 0x00, 0x00, 0x00}, 12},
    };
    for (const Prefix& prefix : prefixes)
        if (MatchesV6Prefix(address, prefix.bytes, prefix.length))
            return true;
    return false;
}

bool IsV4Documentation(const IpAddress& address) noexcept {
    return (address.bytes[0] == 192 && address.bytes[1] == 0 &&
            address.bytes[2] == 2) ||
           (address.bytes[0] == 198 && address.bytes[1] == 51 &&
            address.bytes[2] == 100) ||
           (address.bytes[0] == 203 && address.bytes[1] == 0 &&
            address.bytes[2] == 113);
}

bool IsV4Reserved(const IpAddress& address) noexcept {
    const std::uint8_t a = address.bytes[0];
    const std::uint8_t b = address.bytes[1];
    const std::uint8_t c = address.bytes[2];
    return a == 0 || a >= 240 ||
           (a == 192 && b == 0 && c == 0) ||
           (a == 192 && b == 88 && c == 99) ||
           (a == 198 && (b == 18 || b == 19));
}

char AsciiLower(char value) noexcept {
    return value >= 'A' && value <= 'Z'
               ? static_cast<char>(value + ('a' - 'A'))
               : value;
}

bool ContainsAsciiInsensitive(const char* text, const char* needle) noexcept {
    if (text == nullptr || needle == nullptr || *needle == '\0')
        return false;
    for (const char* start = text; *start != '\0'; ++start) {
        const char* source = start;
        const char* expected = needle;
        while (*source != '\0' && *expected != '\0' &&
               AsciiLower(*source) == AsciiLower(*expected)) {
            ++source;
            ++expected;
        }
        if (*expected == '\0')
            return true;
    }
    return false;
}

bool HasText(const char* text) noexcept {
    return text != nullptr && *text != '\0';
}

bool IsAsciiAlphaNumeric(char value) noexcept {
    const char lower = AsciiLower(value);
    return (lower >= 'a' && lower <= 'z') ||
           (value >= '0' && value <= '9');
}

bool ContainsAsciiTokenInsensitive(const char* text,
                                   const char* token) noexcept {
    if (text == nullptr || token == nullptr || *token == '\0')
        return false;
    for (const char* start = text; *start != '\0'; ++start) {
        if (start != text && IsAsciiAlphaNumeric(start[-1]))
            continue;
        const char* source = start;
        const char* expected = token;
        while (*source != '\0' && *expected != '\0' &&
               AsciiLower(*source) == AsciiLower(*expected)) {
            ++source;
            ++expected;
        }
        if (*expected == '\0' && !IsAsciiAlphaNumeric(*source))
            return true;
    }
    return false;
}

bool IsKnownOverlayText(const char* text) noexcept {
    static const char* const names[] = {
        "tailscale", "cloudflarewarp", "cloudflare warp", "wireguard",
        "wintun", "zerotier", "zero tier", "mullvad", "nordlynx",
        "openvpn", "hamachi", "protonvpn", "proton vpn", "headscale",
        "netbird", "netmaker", "nebula"};
    for (const char* name : names)
        if (ContainsAsciiInsensitive(text, name))
            return true;
    return ContainsAsciiTokenInsensitive(text, "warp");
}

std::size_t AddressLength(AddressFamily family) noexcept {
    return family == AddressFamily::IPv4
               ? 4u
               : family == AddressFamily::IPv6 ? 16u : 0u;
}

bool HostBitsAreZero(const IpAddress& network,
                     std::uint8_t prefix_length) noexcept {
    const std::size_t length = AddressLength(network.family);
    if (length == 0 || prefix_length == 0 ||
        prefix_length > length * 8u)
        return false;
    const std::size_t wholeBytes = prefix_length / 8u;
    const std::uint8_t remainder =
        static_cast<std::uint8_t>(prefix_length % 8u);
    if (remainder != 0) {
        const std::uint8_t hostMask =
            static_cast<std::uint8_t>((1u << (8u - remainder)) - 1u);
        if ((network.bytes[wholeBytes] & hostMask) != 0)
            return false;
    }
    const std::size_t firstHostByte =
        wholeBytes + (remainder == 0 ? 0u : 1u);
    for (std::size_t i = firstHostByte; i < length; ++i)
        if (network.bytes[i] != 0)
            return false;
    return true;
}

bool PrefixMatches(const IpAddress& network, const IpAddress& address,
                   std::uint8_t prefix_length) noexcept {
    const std::size_t wholeBytes = prefix_length / 8u;
    const std::uint8_t remainder =
        static_cast<std::uint8_t>(prefix_length % 8u);
    for (std::size_t i = 0; i < wholeBytes; ++i)
        if (network.bytes[i] != address.bytes[i])
            return false;
    if (remainder == 0)
        return true;
    const std::uint8_t mask =
        static_cast<std::uint8_t>(0xffu << (8u - remainder));
    return (network.bytes[wholeBytes] & mask) ==
           (address.bytes[wholeBytes] & mask);
}

bool SameAddress(const IpAddress& left, const IpAddress& right) noexcept {
    return left.family == right.family && left.bytes == right.bytes;
}

}  // namespace

AddressDecision ClassifyAddress(const IpAddress& address) noexcept {
    if (address.family == AddressFamily::Unspecified)
        return {AddressClass::Unspecified,
                AddressReason::FamilyUnspecified, false, false};

    if (address.family == AddressFamily::IPv4) {
        if (!IsCanonicalV4(address))
            return {AddressClass::Reserved, AddressReason::NonCanonical,
                    false, false};
        if (AllZero(address, 4))
            return {AddressClass::Unspecified,
                    AddressReason::Ipv4Unspecified, false, false};
        if (address.bytes[0] == 127)
            return {AddressClass::Loopback, AddressReason::Ipv4Loopback,
                    false, false};
        if (address.bytes[0] == 169 && address.bytes[1] == 254)
            return {AddressClass::LinkLocal,
                    AddressReason::Ipv4LinkLocal, false, false};
        if (address.IsRfc1918V4())
            return {AddressClass::Rfc1918, AddressReason::Ipv4Rfc1918,
                    false, false};
        if (address.IsSharedCgnatV4())
            return {AddressClass::SharedCgnat,
                    AddressReason::Ipv4SharedCgnat, false, false};
        if (address.bytes[0] >= 224 && address.bytes[0] <= 239)
            return {AddressClass::Multicast,
                    AddressReason::Ipv4Multicast, false, false};
        if (IsV4Documentation(address))
            return {AddressClass::Documentation,
                    AddressReason::Ipv4Documentation, false, false};
        if (IsV4Reserved(address))
            return {AddressClass::Reserved, AddressReason::Ipv4Reserved,
                    false, false};
        return {AddressClass::Public, AddressReason::Ipv4Public,
                true, true};
    }

    if (address.family != AddressFamily::IPv6)
        return {AddressClass::Reserved, AddressReason::NonCanonical,
                false, false};
    if (AllZero(address, 16))
        return {AddressClass::Unspecified,
                AddressReason::Ipv6Unspecified, false, false};
    if (IsV6Loopback(address))
        return {AddressClass::Loopback, AddressReason::Ipv6Loopback,
                false, false};
    if (address.bytes[0] == 0xfe &&
        (address.bytes[1] & 0xc0u) == 0x80u)
        return {AddressClass::LinkLocal, AddressReason::Ipv6LinkLocal,
                false, false};
    if ((address.bytes[0] & 0xfeu) == 0xfcu)
        return {AddressClass::UniqueLocal,
                AddressReason::Ipv6UniqueLocal, false, false};
    if (address.bytes[0] == 0xff)
        return {AddressClass::Multicast, AddressReason::Ipv6Multicast,
                false, false};
    if (MatchesV6Prefix(address, {0x20, 0x01, 0x0d, 0xb8}, 32) ||
        MatchesV6Prefix(address, {0x3f, 0xff, 0x00, 0x00}, 20))
        return {AddressClass::Documentation,
                AddressReason::Ipv6Documentation, false, false};
    if (IsAllocatedV6Global(address))
        return {AddressClass::Global, AddressReason::Ipv6Global,
                true, true};
    return {AddressClass::Reserved, AddressReason::Ipv6Reserved,
            false, false};
}

const char* StableAddressReason(AddressReason reason) noexcept {
    switch (reason) {
    case AddressReason::FamilyUnspecified: return "family-unspecified";
    case AddressReason::NonCanonical: return "non-canonical";
    case AddressReason::Ipv4Unspecified: return "ipv4-unspecified";
    case AddressReason::Ipv4Loopback: return "ipv4-loopback";
    case AddressReason::Ipv4LinkLocal: return "ipv4-link-local";
    case AddressReason::Ipv4Rfc1918: return "ipv4-rfc1918";
    case AddressReason::Ipv4SharedCgnat: return "ipv4-shared-cgnat";
    case AddressReason::Ipv4Multicast: return "ipv4-multicast";
    case AddressReason::Ipv4Reserved: return "ipv4-reserved";
    case AddressReason::Ipv4Documentation: return "ipv4-documentation";
    case AddressReason::Ipv4Public: return "ipv4-public";
    case AddressReason::Ipv6Unspecified: return "ipv6-unspecified";
    case AddressReason::Ipv6Loopback: return "ipv6-loopback";
    case AddressReason::Ipv6LinkLocal: return "ipv6-link-local";
    case AddressReason::Ipv6UniqueLocal: return "ipv6-unique-local";
    case AddressReason::Ipv6Multicast: return "ipv6-multicast";
    case AddressReason::Ipv6Documentation: return "ipv6-documentation";
    case AddressReason::Ipv6Global: return "ipv6-global";
    case AddressReason::Ipv6Reserved: return "ipv6-reserved";
    }
    return "unknown-address-reason";
}

NetworkOriginDecision ClassifyNetworkOrigin(
    const NetworkOriginEvidence& evidence) noexcept {
    if (evidence.is_loopback)
        return {NetworkOrigin::Unknown,
                NetworkOriginReason::LoopbackAdapter};
    if (IsKnownOverlayText(evidence.adapter_name) ||
        IsKnownOverlayText(evidence.adapter_description))
        return {NetworkOrigin::Overlay,
                NetworkOriginReason::KnownOverlay};
    if (evidence.is_tunnel)
        return {NetworkOrigin::Unknown,
                NetworkOriginReason::UnknownTunnel};
    if (evidence.has_default_gateway &&
        (HasText(evidence.adapter_name) ||
         HasText(evidence.adapter_description)))
        return {NetworkOrigin::Native,
                NetworkOriginReason::NativeDefaultRoute};
    return {NetworkOrigin::Unknown,
            NetworkOriginReason::EvidenceMissing};
}

const char* StableNetworkOriginReason(
    NetworkOriginReason reason) noexcept {
    switch (reason) {
    case NetworkOriginReason::NativeDefaultRoute:
        return "native-default-route";
    case NetworkOriginReason::KnownOverlay:
        return "known-overlay";
    case NetworkOriginReason::UnknownTunnel:
        return "unknown-tunnel";
    case NetworkOriginReason::LoopbackAdapter:
        return "loopback-adapter";
    case NetworkOriginReason::EvidenceMissing:
        return "evidence-missing";
    }
    return "unknown-origin-reason";
}

bool IsNativeCgnatEvidence(const IpAddress& address,
                           NetworkOrigin origin) noexcept {
    return origin == NetworkOrigin::Native &&
           ClassifyAddress(address).address_class ==
               AddressClass::SharedCgnat;
}

RouteBindingStatus ValidateRouteBinding(
    const RouteBindingIdentity& binding) noexcept {
    if (binding.interface_index == 0)
        return RouteBindingStatus::InterfaceInvalid;
    if (!binding.interface_present)
        return RouteBindingStatus::InterfaceMissing;
    if (binding.family == AddressFamily::Unspecified ||
        binding.local_address.family != binding.family)
        return RouteBindingStatus::FamilyMismatch;
    if (binding.origin != NetworkOrigin::Native &&
        binding.origin != NetworkOrigin::Overlay &&
        binding.origin != NetworkOrigin::Unknown)
        return RouteBindingStatus::OriginInvalid;
    const AddressClass addressClass =
        ClassifyAddress(binding.local_address).address_class;
    if (addressClass == AddressClass::Unspecified ||
        addressClass == AddressClass::Loopback ||
        addressClass == AddressClass::Multicast ||
        addressClass == AddressClass::Reserved ||
        addressClass == AddressClass::Documentation)
        return RouteBindingStatus::AddressUnusable;
    return RouteBindingStatus::Valid;
}

bool SameRouteBinding(const RouteBindingIdentity& left,
                      const RouteBindingIdentity& right) noexcept {
    return SameAddress(left.local_address, right.local_address) &&
           left.interface_index == right.interface_index &&
           left.family == right.family && left.origin == right.origin &&
           left.interface_present == right.interface_present;
}

RouteBindingContinuity EvaluateRouteBindingContinuity(
    const RouteBindingIdentity& established,
    const RouteBindingIdentity& observed) noexcept {
    if (ValidateRouteBinding(established) != RouteBindingStatus::Valid ||
        ValidateRouteBinding(observed) != RouteBindingStatus::Valid)
        return RouteBindingContinuity::Invalid;
    return SameRouteBinding(established, observed)
               ? RouteBindingContinuity::Stable
               : RouteBindingContinuity::Changed;
}

bool AllowsScopedPrivateAddress(const PrivateAddressScope& scope,
                                const IpAddress& address,
                                std::uint32_t interface_index) noexcept {
    if (!scope.enabled || scope.interface_index == 0 ||
        interface_index != scope.interface_index ||
        scope.family == AddressFamily::Unspecified ||
        scope.network.family != scope.family ||
        address.family != scope.family)
        return false;
    if ((scope.family == AddressFamily::IPv4 &&
         (!IsCanonicalV4(scope.network) || !IsCanonicalV4(address))) ||
        !HostBitsAreZero(scope.network, scope.prefix_length))
        return false;
    const AddressClass networkClass =
        ClassifyAddress(scope.network).address_class;
    const AddressClass addressClass =
        ClassifyAddress(address).address_class;
    const bool permittedClass =
        (networkClass == AddressClass::Rfc1918 &&
         addressClass == AddressClass::Rfc1918) ||
        (networkClass == AddressClass::UniqueLocal &&
         addressClass == AddressClass::UniqueLocal) ||
        (networkClass == AddressClass::LinkLocal &&
         addressClass == AddressClass::LinkLocal);
    return permittedClass &&
           PrefixMatches(scope.network, address, scope.prefix_length);
}

}  // namespace natmap
