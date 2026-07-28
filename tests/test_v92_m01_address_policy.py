#!/usr/bin/env python3
"""Host contract for V9.2 M01 address and origin policy."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class M01AddressPolicyHostContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        def read(relative: str) -> str:
            return (ROOT / relative).read_text(encoding="utf-8")

        cls.header = read("libnatmap/include/natmap/address_policy.h")
        cls.source = read("libnatmap/src/address_policy.cpp")
        cls.native_test = read("libnatmap/tests/test_address_policy.cpp")
        cls.project = read("srchybrid/emule.vcxproj")
        cls.make = read("libnatmap/make.bat")

    def test_policy_is_built_by_product_and_complete_gate(self) -> None:
        self.assertIn(
            r"..\libnatmap\src\address_policy.cpp", self.project
        )
        self.assertIn(
            r"..\libnatmap\include\natmap\address_policy.h", self.project
        )
        self.assertIn("test_address_policy.exe", self.make)

    def test_ipv4_and_ipv6_classes_have_stable_reasons(self) -> None:
        for value in (
            "Unspecified", "Loopback", "LinkLocal", "Rfc1918",
            "SharedCgnat", "Multicast", "Reserved", "Documentation",
            "Public", "UniqueLocal", "Global",
        ):
            self.assertIn(value, self.header)
        for reason in (
            "ipv4-unspecified", "ipv4-loopback", "ipv4-link-local",
            "ipv4-rfc1918", "ipv4-shared-cgnat", "ipv4-multicast",
            "ipv4-reserved", "ipv4-documentation", "ipv4-public",
            "ipv6-unspecified", "ipv6-loopback", "ipv6-link-local",
            "ipv6-unique-local", "ipv6-multicast",
            "ipv6-documentation", "ipv6-global", "ipv6-reserved",
        ):
            self.assertIn(reason, self.source)
        self.assertIn("TestIpv4Table", self.native_test)
        self.assertIn("TestIpv6Table", self.native_test)
        self.assertIn("IsAllocatedV6Global", self.source)
        self.assertIn("0x3f, 0xff", self.native_test)
        self.assertIn("0x20, 0x01, 0x00, 0x02", self.native_test)

    def test_origin_is_independent_and_known_overlays_are_closed(self) -> None:
        for value in ("Native", "Overlay", "Unknown"):
            self.assertIn(value, self.header)
        for overlay in (
            "tailscale", "cloudflare warp", "wireguard", "zerotier",
            "mullvad", "openvpn", "hamachi", "netbird", "nebula",
        ):
            self.assertIn(f'"{overlay}"', self.source)
        self.assertIn("UnknownTunnel", self.source)
        self.assertIn("NativeDefaultRoute", self.source)
        self.assertIn('overlay("WARP", "")', self.native_test)

    def test_overlay_cgnat_never_proves_native_cgnat(self) -> None:
        self.assertIn("IsNativeCgnatEvidence", self.header)
        body = self.source[
            self.source.index("bool IsNativeCgnatEvidence(") :
            self.source.index(
                "RouteBindingStatus ValidateRouteBinding("
            )
        ]
        self.assertIn("origin == NetworkOrigin::Native", body)
        self.assertIn("AddressClass::SharedCgnat", body)
        self.assertIn(
            "NetworkOrigin::Overlay", self.native_test
        )

    def test_bind_identity_requires_live_interface_and_family(self) -> None:
        self.assertIn("interface_index", self.header)
        self.assertIn("interface_present", self.header)
        self.assertIn("AddressFamily family", self.header)
        self.assertIn("RouteBindingStatus::InterfaceMissing", self.source)
        self.assertIn("RouteBindingStatus::FamilyMismatch", self.source)
        self.assertIn("RouteBindingStatus::OriginInvalid", self.source)
        self.assertIn("SameRouteBinding", self.source)

    def test_private_exception_is_scoped_to_interface_and_subnet(self) -> None:
        body = self.source[
            self.source.index("bool AllowsScopedPrivateAddress(") :
        ]
        self.assertIn(
            "interface_index != scope.interface_index", body
        )
        self.assertIn("HostBitsAreZero", body)
        self.assertIn("PrefixMatches", body)
        self.assertIn("AddressClass::Rfc1918", body)
        self.assertIn("AddressClass::UniqueLocal", body)
        self.assertNotIn("AddressClass::SharedCgnat", body)


if __name__ == "__main__":
    unittest.main(verbosity=2)
