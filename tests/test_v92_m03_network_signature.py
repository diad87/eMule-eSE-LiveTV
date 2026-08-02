#!/usr/bin/env python3
"""Host contract for V9.2 M03 stable network topology identity."""

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]


class M03NetworkSignatureHostContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        def read(relative: str) -> str:
            return (ROOT / relative).read_text(encoding="utf-8")

        cls.header = read("libnatmap/include/natmap/network_signature.h")
        cls.source = read("libnatmap/src/network_signature.cpp")
        cls.native_test = read(
            "libnatmap/tests/test_network_signature.cpp"
        )
        cls.dialog = read("srchybrid/EmuleDlg.cpp")
        cls.dialog_h = read("srchybrid/EmuleDlg.h")
        cls.project = read("srchybrid/emule.vcxproj")
        cls.make = read("libnatmap/make.bat")
        cls.wp0 = read("tools/lab/test_t8_wp0.ps1")

    def test_signature_contains_every_required_topology_identity(self) -> None:
        for field in (
            "adapter_luid",
            "interface_index",
            "local_address",
            "gateway_address",
            "route_destination",
            "route_prefix_length",
            "compartment_id",
            "compartment_present",
        ):
            self.assertIn(field, self.header)

    def test_signature_excludes_continuously_changing_fields(self) -> None:
        match = re.search(
            r"struct NetworkSignatureInput \{(.*?)\n\};",
            self.header,
            re.DOTALL,
        )
        self.assertIsNotNone(match)
        fields = match.group(1).lower()
        for forbidden in (
            "metric",
            "timestamp",
            "clock",
            "lease",
            "counter",
            "adapter_name",
            "description",
            "connectivity",
        ):
            self.assertNotIn(forbidden, fields)

    def test_windows_capture_uses_exact_route_identity(self) -> None:
        for marker in (
            "ConvertInterfaceIndexToLuid",
            "GetCurrentThreadCompartmentId",
            "route.dwForwardDest",
            "route.dwForwardMask",
            "route.dwForwardNextHop",
            "route.dwForwardIfIndex",
        ):
            self.assertIn(marker, self.dialog)
        self.assertIn("UPnPPrefixLength", self.dialog)

    def test_product_uses_exact_signature_not_a_hash(self) -> None:
        self.assertIn("natmap::NetworkSignature m_upnpNetworkSignature", self.dialog_h)
        self.assertIn("SameNetworkSignature(", self.dialog)
        signature_body = self.dialog[
            self.dialog.index("static natmap::NetworkSignature GetUPnPNetworkSignature"):
            self.dialog.index("#ifdef HAVE_WIN7_SDK_H")
        ]
        self.assertNotIn("FNV", signature_body)
        self.assertNotIn("signature ^=", signature_body)
        self.assertNotIn("adapterLuid", re.findall(
            r'LIVE_LOG\((.*?)\);', self.dialog, re.DOTALL
        ).__str__())

    def test_native_tests_change_every_field_and_reject_partial_input(self) -> None:
        for marker in (
            "changed.adapter_luid",
            "changed.interface_index",
            "changed.local_address",
            "changed.gateway_address",
            "changed.route_destination",
            "changed.route_prefix_length",
            "changed.compartment_id",
            "changed.compartment_present",
            "MustRejectWithoutMutation",
            "NetworkSignatureStatus::RouteInvalid",
            "NetworkSignatureStatus::CompartmentInvalid",
        ):
            self.assertIn(marker, self.native_test)
        self.assertIn("TestIpv6DefaultRouteIsSupported", self.native_test)
        self.assertIn("prefix_changed.route_prefix_length", self.native_test)
        self.assertIn("destination_changed.route_destination", self.native_test)
        self.assertIn("invalid.route_prefix_length = 129", self.native_test)

    def test_wp0_requires_the_exact_native_signature(self) -> None:
        self.assertIn(
            "'test_network_signature: (59) checks, 0 failures'",
            self.wp0,
        )
        self.assertIn("$m03NativeChecks -eq 59", self.wp0)

    def test_signature_is_built_by_product_and_complete_gate(self) -> None:
        self.assertIn("src\\network_signature.cpp", self.make)
        self.assertIn("test_network_signature.exe", self.make)
        self.assertIn(
            '..\\libnatmap\\src\\network_signature.cpp', self.project
        )
        self.assertIn(
            '..\\libnatmap\\include\\natmap\\network_signature.h',
            self.project,
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
