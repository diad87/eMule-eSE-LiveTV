#include "natmap/address_policy.h"

#include <array>
#include <cstdint>
#include <cstring>
#include <iostream>

namespace {

int checks = 0;
int failures = 0;

#define CHECK(expr)                                                           \
    do {                                                                      \
        ++checks;                                                             \
        if (!(expr)) {                                                        \
            ++failures;                                                       \
            std::cerr << "FAIL line " << __LINE__ << ": " #expr "\n";       \
        }                                                                     \
    } while (false)

natmap::IpAddress V6(std::array<std::uint8_t, 16> bytes) {
    natmap::IpAddress address{};
    address.family = natmap::AddressFamily::IPv6;
    address.bytes = bytes;
    return address;
}

natmap::IpAddress V6Prefix(std::uint8_t a, std::uint8_t b,
                           std::uint8_t c = 0, std::uint8_t d = 0) {
    std::array<std::uint8_t, 16> bytes{};
    bytes[0] = a;
    bytes[1] = b;
    bytes[2] = c;
    bytes[3] = d;
    return V6(bytes);
}

void CheckClass(const natmap::IpAddress& address,
                natmap::AddressClass expected,
                natmap::AddressReason reason,
                bool publishable) {
    const natmap::AddressDecision decision =
        natmap::ClassifyAddress(address);
    CHECK(decision.address_class == expected);
    CHECK(decision.reason == reason);
    CHECK(decision.globally_routable == publishable);
    CHECK(decision.direct_publishable == publishable);
    CHECK(std::strlen(natmap::StableAddressReason(decision.reason)) > 0);
}

void TestIpv4Table() {
    using namespace natmap;
    CheckClass(IpAddress{}, AddressClass::Unspecified,
               AddressReason::FamilyUnspecified, false);
    CheckClass(IpAddress::V4(0, 0, 0, 0), AddressClass::Unspecified,
               AddressReason::Ipv4Unspecified, false);
    CheckClass(IpAddress::V4(127, 0, 0, 1), AddressClass::Loopback,
               AddressReason::Ipv4Loopback, false);
    CheckClass(IpAddress::V4(169, 254, 10, 20), AddressClass::LinkLocal,
               AddressReason::Ipv4LinkLocal, false);
    CheckClass(IpAddress::V4(10, 1, 2, 3), AddressClass::Rfc1918,
               AddressReason::Ipv4Rfc1918, false);
    CheckClass(IpAddress::V4(172, 16, 0, 1), AddressClass::Rfc1918,
               AddressReason::Ipv4Rfc1918, false);
    CheckClass(IpAddress::V4(172, 31, 255, 254), AddressClass::Rfc1918,
               AddressReason::Ipv4Rfc1918, false);
    CheckClass(IpAddress::V4(192, 168, 71, 23), AddressClass::Rfc1918,
               AddressReason::Ipv4Rfc1918, false);
    CheckClass(IpAddress::V4(100, 64, 0, 1), AddressClass::SharedCgnat,
               AddressReason::Ipv4SharedCgnat, false);
    CheckClass(IpAddress::V4(100, 127, 255, 254),
               AddressClass::SharedCgnat,
               AddressReason::Ipv4SharedCgnat, false);
    CheckClass(IpAddress::V4(100, 63, 255, 255), AddressClass::Public,
               AddressReason::Ipv4Public, true);
    CheckClass(IpAddress::V4(100, 128, 0, 0), AddressClass::Public,
               AddressReason::Ipv4Public, true);
    CheckClass(IpAddress::V4(172, 15, 255, 255), AddressClass::Public,
               AddressReason::Ipv4Public, true);
    CheckClass(IpAddress::V4(172, 32, 0, 0), AddressClass::Public,
               AddressReason::Ipv4Public, true);
    CheckClass(IpAddress::V4(223, 255, 255, 255), AddressClass::Public,
               AddressReason::Ipv4Public, true);
    CheckClass(IpAddress::V4(224, 0, 0, 1), AddressClass::Multicast,
               AddressReason::Ipv4Multicast, false);
    CheckClass(IpAddress::V4(240, 0, 0, 1), AddressClass::Reserved,
               AddressReason::Ipv4Reserved, false);
    CheckClass(IpAddress::V4(198, 18, 0, 1), AddressClass::Reserved,
               AddressReason::Ipv4Reserved, false);
    CheckClass(IpAddress::V4(192, 0, 0, 8), AddressClass::Reserved,
               AddressReason::Ipv4Reserved, false);
    CheckClass(IpAddress::V4(192, 0, 2, 1), AddressClass::Documentation,
               AddressReason::Ipv4Documentation, false);
    CheckClass(IpAddress::V4(198, 51, 100, 1),
               AddressClass::Documentation,
               AddressReason::Ipv4Documentation, false);
    CheckClass(IpAddress::V4(203, 0, 113, 1),
               AddressClass::Documentation,
               AddressReason::Ipv4Documentation, false);
    CheckClass(IpAddress::V4(88, 11, 22, 4), AddressClass::Public,
               AddressReason::Ipv4Public, true);

    IpAddress noncanonical = IpAddress::V4(88, 11, 22, 4);
    noncanonical.bytes[4] = 1;
    CheckClass(noncanonical, AddressClass::Reserved,
               AddressReason::NonCanonical, false);
}

void TestIpv6Table() {
    using namespace natmap;
    CheckClass(V6({}), AddressClass::Unspecified,
               AddressReason::Ipv6Unspecified, false);
    std::array<std::uint8_t, 16> loopback{};
    loopback[15] = 1;
    CheckClass(V6(loopback), AddressClass::Loopback,
               AddressReason::Ipv6Loopback, false);
    CheckClass(V6Prefix(0xfe, 0x80), AddressClass::LinkLocal,
               AddressReason::Ipv6LinkLocal, false);
    CheckClass(V6Prefix(0xfe, 0xbf), AddressClass::LinkLocal,
               AddressReason::Ipv6LinkLocal, false);
    CheckClass(V6Prefix(0xfe, 0xc0), AddressClass::Reserved,
               AddressReason::Ipv6Reserved, false);
    CheckClass(V6Prefix(0xfc, 0x00), AddressClass::UniqueLocal,
               AddressReason::Ipv6UniqueLocal, false);
    CheckClass(V6Prefix(0xfd, 0x71), AddressClass::UniqueLocal,
               AddressReason::Ipv6UniqueLocal, false);
    CheckClass(V6Prefix(0xff, 0x02), AddressClass::Multicast,
               AddressReason::Ipv6Multicast, false);
    CheckClass(V6Prefix(0x20, 0x01, 0x0d, 0xb8),
               AddressClass::Documentation,
               AddressReason::Ipv6Documentation, false);
    CheckClass(V6Prefix(0x20, 0x01, 0x0d, 0xb7),
               AddressClass::Global,
               AddressReason::Ipv6Global, true);
    CheckClass(V6Prefix(0x20, 0x01, 0x0d, 0xb9),
               AddressClass::Global,
               AddressReason::Ipv6Global, true);
    CheckClass(V6Prefix(0x20, 0x01, 0x00, 0x02),
               AddressClass::Reserved,
               AddressReason::Ipv6Reserved, false);
    CheckClass(V6Prefix(0x20, 0x02), AddressClass::Reserved,
               AddressReason::Ipv6Reserved, false);
    CheckClass(V6Prefix(0x20, 0x03, 0x00, 0x00),
               AddressClass::Global,
               AddressReason::Ipv6Global, true);
    CheckClass(V6Prefix(0x24, 0x00), AddressClass::Global,
               AddressReason::Ipv6Global, true);
    CheckClass(V6Prefix(0x24, 0x10), AddressClass::Global,
               AddressReason::Ipv6Global, true);
    CheckClass(V6Prefix(0x24, 0x20), AddressClass::Reserved,
               AddressReason::Ipv6Reserved, false);
    CheckClass(V6Prefix(0x26, 0x10), AddressClass::Global,
               AddressReason::Ipv6Global, true);
    CheckClass(V6Prefix(0x26, 0x10, 0x01, 0xff),
               AddressClass::Global,
               AddressReason::Ipv6Global, true);
    CheckClass(V6Prefix(0x26, 0x10, 0x02, 0x00),
               AddressClass::Reserved,
               AddressReason::Ipv6Reserved, false);
    CheckClass(V6Prefix(0x26, 0x20), AddressClass::Global,
               AddressReason::Ipv6Global, true);
    CheckClass(V6Prefix(0x26, 0x22), AddressClass::Reserved,
               AddressReason::Ipv6Reserved, false);
    CheckClass(V6Prefix(0x26, 0x30), AddressClass::Global,
               AddressReason::Ipv6Global, true);
    CheckClass(V6Prefix(0x26, 0x40), AddressClass::Reserved,
               AddressReason::Ipv6Reserved, false);
    CheckClass(V6Prefix(0x2a, 0x10), AddressClass::Global,
               AddressReason::Ipv6Global, true);
    CheckClass(V6Prefix(0x2a, 0x20), AddressClass::Reserved,
               AddressReason::Ipv6Reserved, false);
    CheckClass(V6Prefix(0x2c, 0x0f), AddressClass::Global,
               AddressReason::Ipv6Global, true);
    CheckClass(V6Prefix(0x2d, 0x00), AddressClass::Reserved,
               AddressReason::Ipv6Reserved, false);
    CheckClass(V6Prefix(0x30, 0x00), AddressClass::Reserved,
               AddressReason::Ipv6Reserved, false);
    CheckClass(V6Prefix(0x3f, 0xfe), AddressClass::Reserved,
               AddressReason::Ipv6Reserved, false);
    CheckClass(V6Prefix(0x3f, 0xff), AddressClass::Documentation,
               AddressReason::Ipv6Documentation, false);
    CheckClass(V6Prefix(0x3f, 0xff, 0x0f, 0xff),
               AddressClass::Documentation,
               AddressReason::Ipv6Documentation, false);
    CheckClass(V6Prefix(0x3f, 0xff, 0x10, 0x00),
               AddressClass::Reserved,
               AddressReason::Ipv6Reserved, false);
    CheckClass(V6Prefix(0x1f, 0xff), AddressClass::Reserved,
               AddressReason::Ipv6Reserved, false);
    CheckClass(V6Prefix(0x20, 0x01, 0x48, 0x60),
               AddressClass::Global,
               AddressReason::Ipv6Global, true);
    CheckClass(V6Prefix(0x40, 0x01), AddressClass::Reserved,
               AddressReason::Ipv6Reserved, false);
}

void TestNetworkOrigin() {
    using namespace natmap;
    const auto overlay = [](const char* name, const char* description,
                            bool tunnel = true) {
        NetworkOriginEvidence evidence{};
        evidence.adapter_name = name;
        evidence.adapter_description = description;
        evidence.is_tunnel = tunnel;
        evidence.has_default_gateway = true;
        return ClassifyNetworkOrigin(evidence);
    };
    for (const auto& decision : {
             overlay("Tailscale", ""),
             overlay("WARP", ""),
             overlay("CloudflareWARP", "Wintun userspace tunnel"),
             overlay("WireGuard Tunnel", ""),
             overlay("ZeroTier One", ""),
             overlay("wg-mullvad", "Mullvad"),
             overlay("OpenVPN TAP", ""),
             overlay("Hamachi", ""),
             overlay("NetBird", ""),
             overlay("Nebula", "")}) {
        CHECK(decision.origin == NetworkOrigin::Overlay);
        CHECK(decision.reason == NetworkOriginReason::KnownOverlay);
        CHECK(std::strcmp(StableNetworkOriginReason(decision.reason),
                          "known-overlay") == 0);
    }

    NetworkOriginEvidence native{};
    native.adapter_name = "Intel Ethernet";
    native.adapter_description = "PCIe physical adapter";
    native.has_default_gateway = true;
    const NetworkOriginDecision nativeDecision =
        ClassifyNetworkOrigin(native);
    CHECK(nativeDecision.origin == NetworkOrigin::Native);
    CHECK(nativeDecision.reason == NetworkOriginReason::NativeDefaultRoute);

    NetworkOriginEvidence unknown{};
    CHECK(ClassifyNetworkOrigin(unknown).origin == NetworkOrigin::Unknown);
    unknown.adapter_name = "Mystery tunnel";
    unknown.is_tunnel = true;
    unknown.has_default_gateway = true;
    CHECK(ClassifyNetworkOrigin(unknown).origin == NetworkOrigin::Unknown);
    unknown.is_loopback = true;
    CHECK(ClassifyNetworkOrigin(unknown).reason ==
          NetworkOriginReason::LoopbackAdapter);
    CHECK(overlay("WarpDrive Ethernet", "", false).origin ==
          NetworkOrigin::Native);

    CHECK(IsNativeCgnatEvidence(IpAddress::V4(100, 64, 1, 2),
                                NetworkOrigin::Native));
    CHECK(!IsNativeCgnatEvidence(IpAddress::V4(100, 64, 1, 2),
                                 NetworkOrigin::Overlay));
    CHECK(!IsNativeCgnatEvidence(IpAddress::V4(100, 64, 1, 2),
                                 NetworkOrigin::Unknown));
    CHECK(!IsNativeCgnatEvidence(IpAddress::V4(88, 11, 22, 4),
                                 NetworkOrigin::Native));
    CHECK(!IsNativeCgnatEvidence(
        IpAddress::V4(100, 64, 1, 2),
        static_cast<NetworkOrigin>(255)));
}

void TestRouteBindingIdentity() {
    using namespace natmap;
    RouteBindingIdentity binding{};
    binding.local_address = IpAddress::V4(192, 168, 71, 23);
    binding.interface_index = 17;
    binding.family = AddressFamily::IPv4;
    binding.origin = NetworkOrigin::Native;
    binding.interface_present = true;
    CHECK(ValidateRouteBinding(binding) == RouteBindingStatus::Valid);

    RouteBindingIdentity changed = binding;
    changed.interface_index = 18;
    CHECK(!SameRouteBinding(binding, changed));
    changed = binding;
    changed.family = AddressFamily::IPv6;
    CHECK(ValidateRouteBinding(changed) ==
          RouteBindingStatus::FamilyMismatch);
    changed = binding;
    changed.interface_present = false;
    CHECK(ValidateRouteBinding(changed) ==
          RouteBindingStatus::InterfaceMissing);
    changed = binding;
    changed.interface_index = 0;
    CHECK(ValidateRouteBinding(changed) ==
          RouteBindingStatus::InterfaceInvalid);
    changed = binding;
    changed.local_address = IpAddress::V4(224, 0, 0, 1);
    CHECK(ValidateRouteBinding(changed) ==
          RouteBindingStatus::AddressUnusable);
    changed = binding;
    changed.origin = static_cast<NetworkOrigin>(255);
    CHECK(ValidateRouteBinding(changed) ==
          RouteBindingStatus::OriginInvalid);
}

void TestScopedPrivateException() {
    using namespace natmap;
    PrivateAddressScope scope{};
    scope.enabled = true;
    scope.interface_index = 17;
    scope.family = AddressFamily::IPv4;
    scope.network = IpAddress::V4(192, 168, 71, 0);
    scope.prefix_length = 24;
    CHECK(AllowsScopedPrivateAddress(
        scope, IpAddress::V4(192, 168, 71, 23), 17));
    CHECK(!AllowsScopedPrivateAddress(
        scope, IpAddress::V4(192, 168, 71, 23), 18));
    CHECK(!AllowsScopedPrivateAddress(
        scope, IpAddress::V4(192, 168, 72, 23), 17));
    CHECK(!AllowsScopedPrivateAddress(
        scope, IpAddress::V4(88, 11, 22, 4), 17));
    CHECK(!AllowsScopedPrivateAddress(
        scope, IpAddress::V4(100, 64, 1, 2), 17));

    PrivateAddressScope broad = scope;
    broad.prefix_length = 0;
    CHECK(!AllowsScopedPrivateAddress(
        broad, IpAddress::V4(192, 168, 71, 23), 17));
    PrivateAddressScope hostBits = scope;
    hostBits.network = IpAddress::V4(192, 168, 71, 1);
    CHECK(!AllowsScopedPrivateAddress(
        hostBits, IpAddress::V4(192, 168, 71, 23), 17));
    PrivateAddressScope hostOnly = scope;
    hostOnly.network = IpAddress::V4(192, 168, 71, 23);
    hostOnly.prefix_length = 32;
    CHECK(AllowsScopedPrivateAddress(
        hostOnly, IpAddress::V4(192, 168, 71, 23), 17));
    CHECK(!AllowsScopedPrivateAddress(
        hostOnly, IpAddress::V4(192, 168, 71, 22), 17));
    PrivateAddressScope nonByte = scope;
    nonByte.network = IpAddress::V4(192, 168, 64, 0);
    nonByte.prefix_length = 19;
    CHECK(AllowsScopedPrivateAddress(
        nonByte, IpAddress::V4(192, 168, 71, 23), 17));
    CHECK(!AllowsScopedPrivateAddress(
        nonByte, IpAddress::V4(192, 168, 96, 23), 17));

    PrivateAddressScope ula{};
    ula.enabled = true;
    ula.interface_index = 41;
    ula.family = AddressFamily::IPv6;
    ula.network = V6Prefix(0xfd, 0x71);
    ula.prefix_length = 64;
    std::array<std::uint8_t, 16> ulaHost =
        ula.network.bytes;
    ulaHost[15] = 9;
    CHECK(AllowsScopedPrivateAddress(ula, V6(ulaHost), 41));
    CHECK(!AllowsScopedPrivateAddress(ula, V6(ulaHost), 42));
    PrivateAddressScope ulaHostOnly = ula;
    ulaHostOnly.network = V6(ulaHost);
    ulaHostOnly.prefix_length = 128;
    CHECK(AllowsScopedPrivateAddress(
        ulaHostOnly, V6(ulaHost), 41));
    ulaHost[14] = 1;
    CHECK(!AllowsScopedPrivateAddress(
        ulaHostOnly, V6(ulaHost), 41));
    PrivateAddressScope ulaNonByte = ula;
    ulaNonByte.prefix_length = 57;
    ulaNonByte.network.bytes[7] = 0x80;
    std::array<std::uint8_t, 16> ulaNonByteHost =
        ulaNonByte.network.bytes;
    ulaNonByteHost[7] = 0x9f;
    ulaNonByteHost[15] = 1;
    CHECK(AllowsScopedPrivateAddress(
        ulaNonByte, V6(ulaNonByteHost), 41));
    ulaNonByteHost[7] = 0x7f;
    CHECK(!AllowsScopedPrivateAddress(
        ulaNonByte, V6(ulaNonByteHost), 41));
}

}  // namespace

int main() {
    TestIpv4Table();
    TestIpv6Table();
    TestNetworkOrigin();
    TestRouteBindingIdentity();
    TestScopedPrivateException();
    std::cout << "test_address_policy: " << checks << " checks, "
              << failures << " failures\n";
    return failures == 0 ? 0 : 1;
}
