#!/usr/bin/env python3
"""Host contract for V9.2 M02 bounded double-NAT policy."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class M02DoubleNatHostContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        def read(relative: str) -> str:
            return (ROOT / relative).read_text(encoding="utf-8")

        cls.header = read("libnatmap/include/natmap/natmap_chain.h")
        cls.source = read("libnatmap/src/natmap_chain.cpp")
        cls.native_test = read("libnatmap/tests/test_nat_chain.cpp")
        cls.manager_h = read("srchybrid/DirectReachabilityManager.h")
        cls.manager_cpp = read("srchybrid/DirectReachabilityManager.cpp")
        cls.emule_dlg = read("srchybrid/EmuleDlg.cpp")
        cls.legacy_projection = read(
            "libnatmap/src/legacy_mapper_projection.cpp"
        )
        cls.legacy_test = read(
            "libnatmap/tests/test_legacy_mapper_projection.cpp"
        )
        cls.probe = read("tools/natmap_probe.cpp")
        cls.make = read("libnatmap/make.bat")

    def test_discovery_accepts_only_typed_authorized_evidence(self) -> None:
        for value in (
            "InterfaceRoute", "DhcpOption", "ExplicitConfiguration",
            "OperatorPolicy",
        ):
            self.assertIn(value, self.header)
        self.assertIn("interface_present", self.header)
        self.assertIn(
            "evidence.interface_index != input.interface_index", self.source
        )
        self.assertIn("IsAuthorizedSource", self.source)
        self.assertIn(
            "input.mapper_origin != NetworkOrigin::Native", self.source
        )

    def test_no_gateway_is_invented_or_subnet_scanned(self) -> None:
        self.assertNotIn("bytes[3] = 1", self.source)
        self.assertNotIn("bytes[3] = 254", self.source)
        self.assertNotIn("Bounded upstream probes", self.probe)
        self.assertNotIn("BuildUpstreamGatewayCandidates(wan_address)", self.probe)
        self.assertIn("no probes sent", self.probe)

    def test_publication_uses_m01_fail_closed_policy(self) -> None:
        self.assertIn('#include "natmap/address_policy.h"', self.source)
        self.assertIn("decision.direct_publishable", self.source)
        self.assertIn("NatChainStatus::NonPublishableEndpoint", self.source)
        self.assertIn("192, 0, 2, 1", self.native_test)

    def test_depth_is_exactly_bounded_to_double_nat(self) -> None:
        self.assertIn("kMaximumLayers = 2", self.header)
        self.assertIn("NatChainStatus::DepthLimitReached", self.source)
        self.assertIn("TestDepthAndNonRoutablePromotionFailClosed", self.native_test)

    def test_product_owns_wan_address_and_caller_only_evidence(self) -> None:
        self.assertIn("UpstreamDiscoveryInput", self.manager_h)
        self.assertIn(
            "input.mapper_wan_address = m_tcpChain.FinalEndpoint().address",
            self.manager_cpp,
        )
        self.assertIn("authorizedEvidence", self.manager_cpp)
        self.assertIn(
            "input.mapper_origin = m_mapperRouteBinding.origin",
            self.manager_cpp,
        )
        self.assertIn(
            "input.interface_index = m_mapperRouteBinding.interface_index",
            self.manager_cpp,
        )
        self.assertIn(
            "EvaluateRouteBindingContinuity(", self.manager_cpp
        )
        self.assertIn(
            "return DisableMappedPlanes(", self.manager_cpp
        )
        self.assertIn(
            "natmap::ReasonCode::InterfaceChanged", self.manager_cpp
        )

    def test_product_publication_switches_on_chain_evaluation(self) -> None:
        self.assertIn(
            "switch (m_tcpChain.Evaluate())", self.manager_cpp
        )
        self.assertIn(
            "case natmap::NatChainStatus::CompletePublic:", self.manager_cpp
        )
        self.assertIn(
            "case natmap::NatChainStatus::NonPublishableEndpoint:",
            self.manager_cpp,
        )
        self.assertIn("ClassifyAddress(address)", self.legacy_projection)
        for address in (
            "192, 0, 2, 1",
            "198, 51, 100, 1",
            "203, 0, 113, 1",
            "224, 0, 0, 1",
            "240, 0, 0, 1",
        ):
            self.assertIn(address, self.legacy_test)

    def test_route_origin_is_captured_from_windows_adapter_evidence(self) -> None:
        self.assertIn(
            "ClassifyNetworkOrigin(originEvidence).origin",
            self.emule_dlg,
        )
        self.assertIn("adapter->AdapterName", self.emule_dlg)
        self.assertIn("adapter->Description", self.emule_dlg)
        self.assertIn("adapter->Type == IF_TYPE_TUNNEL", self.emule_dlg)
        self.assertIn("mapperRouteBinding", self.emule_dlg)
        self.assertNotIn(
            "operator CGNAT; no probes sent", self.probe
        )

    def test_no_route_and_cgnat_are_distinct_bounded_results(self) -> None:
        self.assertIn("NoAuthorizedCandidate", self.header)
        self.assertIn("ReasonCode::NoRoute", self.source)
        self.assertIn("ReasonCode::CgnatWithoutLease", self.source)
        self.assertIn("OperatorCgnat", self.native_test)
        self.assertIn("NetworkOrigin::Overlay", self.native_test)
        self.assertIn("src\\address_policy.cpp", self.make)


if __name__ == "__main__":
    unittest.main(verbosity=2)
