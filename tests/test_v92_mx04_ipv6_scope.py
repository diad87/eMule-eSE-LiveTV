#!/usr/bin/env python3
"""Executable MX04 / TH92-4 IPv6 and LAN scope contract."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
POLICY_HEADER = ROOT / "libnatmap/include/natmap/ipv6_scope_policy.h"
POLICY_SOURCE = ROOT / "libnatmap/src/ipv6_scope_policy.cpp"
POLICY_NATIVE = ROOT / "libnatmap/tests/test_ipv6_scope_policy.cpp"


# Frozen MX04 matrix.  `reason` is the public, append-only ReasonCode name;
# `address_reason` retains the precise non-public address classification.
MX04_MATRIX = (
    {
        "id": "MX04-01",
        "given": "current global IPv6, inbound firewall closed",
        "disposition": "Candidate",
        "readiness": "Candidate",
        "reason": "InboundFiltered",
        "address_reason": "Ipv6Global",
        "may_select_direct_v6": False,
    },
    {
        "id": "MX04-02",
        "given": "current global IPv6, exact authorized unexpired pinhole",
        "disposition": "VerifiedGlobal",
        "readiness": "Verified",
        "reason": "None",
        "address_reason": "Ipv6Global",
        "may_select_direct_v6": True,
    },
    {
        "id": "MX04-03",
        "given": "global IPv6 pinhole expired",
        "disposition": "Withdraw",
        "readiness": "Absent",
        "reason": "LeaseExpired",
        "address_reason": "Ipv6Global",
        "may_select_direct_v6": False,
    },
    {
        "id": "MX04-04",
        "given": "interface or topology generation changed after evidence",
        "disposition": "Withdraw",
        "readiness": "Absent",
        "reason": "InterfaceChanged|StaleGeneration",
        "address_reason": "Ipv6Global",
        "may_select_direct_v6": False,
    },
    {
        "id": "MX04-05",
        "given": "ULA, RFC1918 or link-local presented for GLOBAL admission",
        "disposition": "RejectGlobal",
        "readiness": "Absent",
        "reason": "NoRoute",
        "address_reason": "Ipv6UniqueLocal|Ipv4Rfc1918",
        "may_select_direct_v6": False,
    },
    {
        "id": "MX04-06",
        "given": "private or link-local address with exact positive same-LAN-domain proof",
        "disposition": "SameLanOnly",
        "readiness": "Verified",
        "reason": "None",
        "address_reason": "Ipv6UniqueLocal|Ipv4Rfc1918",
        "may_select_direct_v6": False,
    },
    {
        "id": "MX04-07",
        "given": "same-LAN proof replayed on another interface or generation",
        "disposition": "RejectSameLan",
        "readiness": "Absent",
        "reason": "InterfaceChanged|StaleGeneration",
        "address_reason": "Ipv6UniqueLocal|Ipv4Rfc1918",
        "may_select_direct_v6": False,
    },
)


class Mx04Ipv6ScopeRedContract(unittest.TestCase):
    """Frozen policy and product-consumer contracts for MX04."""

    def policy_text(self) -> tuple[str, str, str]:
        self.assertTrue(
            POLICY_HEADER.is_file(),
            "MX04 policy header is absent: no executable IPv6/scope admission gate",
        )
        self.assertTrue(
            POLICY_SOURCE.is_file(),
            "MX04 policy source is absent: no executable IPv6/scope admission gate",
        )
        self.assertTrue(
            POLICY_NATIVE.is_file(),
            "MX04 native scenarios are absent",
        )
        return (
            POLICY_HEADER.read_text(encoding="utf-8"),
            POLICY_SOURCE.read_text(encoding="utf-8"),
            POLICY_NATIVE.read_text(encoding="utf-8"),
        )

    def test_frozen_matrix_has_exactly_the_seven_th92_4_cases(self) -> None:
        self.assertEqual(
            [row["id"] for row in MX04_MATRIX],
            [f"MX04-{number:02d}" for number in range(1, 8)],
        )
        for row in MX04_MATRIX:
            self.assertIn(row["readiness"], {"Absent", "Candidate", "Verified"})
            self.assertIn("disposition", row)
            self.assertIn("reason", row)
            self.assertIn("address_reason", row)

    def test_global_v6_with_closed_firewall_is_candidate_not_winner(self) -> None:
        header, source, native = self.policy_text()
        for marker in (
            "Ipv6ScopeDisposition::Candidate",
            "ReasonCode::InboundFiltered",
            "may_select_direct_v6 = false",
            "TestGlobalV6ClosedFirewallDoesNotWin",
        ):
            self.assertIn(marker, header + source + native)

    def test_current_global_v6_with_exact_live_pinhole_can_verify(self) -> None:
        header, source, native = self.policy_text()
        for marker in (
            "PinholeEvidence",
            "public_endpoint",
            "SameRouteBinding(",
            "Ipv6ScopeDisposition::VerifiedGlobal",
            "TestGlobalV6ExactLivePinholeVerifies",
        ):
            self.assertIn(marker, header + source + native)

    def test_expired_pinhole_withdraws_the_candidate(self) -> None:
        header, source, native = self.policy_text()
        for marker in (
            "ReasonCode::LeaseExpired",
            "Ipv6ScopeDisposition::Withdraw",
            "expires_monotonic_ms",
            "TestExpiredPinholeWithdrawsCandidate",
        ):
            self.assertIn(marker, header + source + native)

    def test_interface_or_generation_change_invalidates_evidence(self) -> None:
        header, source, native = self.policy_text()
        for marker in (
            "ReasonCode::InterfaceChanged",
            "ReasonCode::StaleGeneration",
            "IsEvidenceStale(",
            "TestInterfaceAndGenerationChangeInvalidate",
        ):
            self.assertIn(marker, header + source + native)

    def test_ula_and_rfc1918_are_rejected_as_global(self) -> None:
        header, source, native = self.policy_text()
        for marker in (
            "AddressClass::UniqueLocal",
            "AddressClass::Rfc1918",
            "AddressClass::LinkLocal",
            "Ipv6ScopeDisposition::RejectGlobal",
            "TestPrivateAddressesNeverAdmitAsGlobal",
        ):
            self.assertIn(marker, header + source + native)

    def test_same_lan_requires_positive_proof_and_never_selects_direct_v6(self) -> None:
        header, source, native = self.policy_text()
        for marker in (
            "PrivateAddressScope",
            "AllowsScopedPrivateAddress(",
            "peer_endpoint",
            "peer_endpoint.IsUsable()",
            "Ipv6ScopeDisposition::SameLanOnly",
            "TestSameLanRequiresRemotePeerInExactScope",
            "TestLinkLocalSameLanRequiresExactInterface",
        ):
            self.assertIn(marker, header + source + native)

    def test_product_consumes_only_the_global_projection(self) -> None:
        prober = (ROOT / "srchybrid/FirewallProberV6.cpp").read_text(
            encoding="utf-8"
        )
        base_client = (ROOT / "srchybrid/BaseClient.cpp").read_text(
            encoding="utf-8"
        )
        kad = (ROOT / "srchybrid/Kademlia/net/KademliaUDPListener.cpp").read_text(
            encoding="utf-8"
        )
        search = (ROOT / "srchybrid/Kademlia/Kademlia/Search.cpp").read_text(
            encoding="utf-8"
        )
        self.assertIn("EvaluateIpv6ScopeAdmission(input)", prober)
        self.assertIn("GlobalRouteObservation(", prober)
        self.assertIn("m_nPcpV6Generation", prober)
        self.assertIn("MonotonicMilliseconds64()", prober)
        self.assertNotIn("DWORD acquiredTick", (ROOT / "srchybrid/FirewallProberV6.h").read_text(encoding="utf-8"))
        self.assertIn("PCP-v6 pinhole expired; direct IPv6 withdrawn", prober)
        self.assertIn("SetDetectedV6IP(addr, currentGeneration)", prober)
        self.assertIn("discarded stale PCP-v6 MAP result after topology change", prober)
        self.assertNotIn("m_ipv6Address.IsUniqueLocalIPv6()", base_client)
        self.assertIn("ObserveSameLanRouteToPeer(", base_client)
        self.assertIn("CanUseSameLanEndpoint(", base_client)
        self.assertIn("GetOnLinkRouteV6(", prober)
        self.assertIn("route.NextHop", prober)
        self.assertIn("IN6ADDR_ANY_INIT", prober)
        self.assertNotIn("bool positiveSameLan", prober)
        hello = base_client[
            base_client.index("void CUpDownClient::SendHelloTypePacket("):
            base_client.index("void CUpDownClient::ProcessMuleCommentPacket(")
        ]
        self.assertIn("GetDirectRouteObservation(", hello)
        self.assertIn("natmap::Transport::Tcp", hello)
        self.assertIn("helloV6Observation.IsVerifiedFor(helloGeneration)", hello)
        for consumer in (kad, search):
            self.assertIn("IsVerifiedFor(topologyGeneration)", consumer)
            self.assertIn("natmap::Transport::Udp", consumer)
        self.assertIn("TestTransportProofDoesNotCross", (ROOT / "libnatmap/tests/test_ipv6_scope_policy.cpp").read_text(encoding="utf-8"))
        self.assertIn("TestPinholeReassignedEndpointDoesNotVerify", (ROOT / "libnatmap/tests/test_ipv6_scope_policy.cpp").read_text(encoding="utf-8"))
        self.assertIn("TestIndependentInboundSurvivesExpiredPinhole", (ROOT / "libnatmap/tests/test_ipv6_scope_policy.cpp").read_text(encoding="utf-8"))
        self.assertIn("ReasonCode::MappingConflict", (ROOT / "libnatmap/src/ipv6_scope_policy.cpp").read_text(encoding="utf-8"))

    def test_native_origin_and_pcp_lifecycle_are_fail_closed(self) -> None:
        prober = (ROOT / "srchybrid/FirewallProberV6.cpp").read_text(
            encoding="utf-8"
        )
        native = POLICY_NATIVE.read_text(encoding="utf-8")
        for marker in (
            "NetworkOriginEvidence",
            "ClassifyNetworkOrigin(originEvidence)",
            "IsNativeV6Interface",
            "IsPcpEpochDiscontinuity",
            "ArePcpPairEpochsCoherent",
            "m_pcpPolicyAuthorized",
            "independentInbound",
            "tcpLifetimeZero",
        ):
            self.assertIn(marker, prober)
        self.assertIn("Tailscale Tunnel", native)
        self.assertIn("NetworkOrigin::Overlay", native)
        self.assertIn("TestOverlayOriginNeverAdmitsGlobalRoute", native)

    def test_product_lifecycle_consumers_and_scope_binding_are_fenced(self) -> None:
        prober = (ROOT / "srchybrid/FirewallProberV6.cpp").read_text(encoding="utf-8")
        header = (ROOT / "srchybrid/FirewallProberV6.h").read_text(encoding="utf-8")
        base = (ROOT / "srchybrid/BaseClient.cpp").read_text(encoding="utf-8")
        kad = (ROOT / "srchybrid/Kademlia/net/KademliaUDPListener.cpp").read_text(encoding="utf-8")
        gateway = (ROOT / "srchybrid/Kad6GatewaySocket.cpp").read_text(encoding="utf-8")
        dlg = (ROOT / "srchybrid/EmuleDlg.cpp").read_text(encoding="utf-8")
        native_test = (ROOT / "libnatmap/tests/test_ipv6_scope_policy.cpp").read_text(
            encoding="utf-8"
        )
        # Product code only wires the decisions; input mutation and edge cases
        # live in the portable libnatmap gate instead of marker-only tests.
        for helper in (
            "natmap::CanPublishProbeVerdict",
            "natmap::MustCleanupPcpNonce",
            "natmap::IsCurrentPcpLeaseOwner",
            "natmap::EvaluateTopologyGenerationApply",
            "natmap::MayPublishCascadeVerdict",
            "natmap::SelectPcpBusyRetryOwner",
        ):
            self.assertIn(helper, prober)
        self.assertIn("BeginShutdownFence", prober + header)
        self.assertIn("m_lShuttingDown", prober + header)
        self.assertIn("TestProbeAndPcpLifecycleFences", native_test)
        self.assertIn("PcpCascadeOutcome::Deferred", native_test)
        self.assertIn("PcpBusyRetryOwner::WaitingWorker", native_test)
        self.assertIn("UiPcpCleanupMayScheduleRetry", native_test)
        self.assertIn("udpRefreshResult = ExchangePcpMapV6", prober)
        self.assertIn("cleanupUdpRefreshNonce", prober)
        self.assertIn("cleanupTcpRefreshNonce", prober)
        self.assertIn("UiPcpCleanupMayScheduleRetry", prober)
        startup = dlg[dlg.index("currentTopologyGeneration") :
                      dlg.index("CFirewallProberV6::Instance().ProbeAsync()", dlg.index("currentTopologyGeneration"))]
        self.assertIn("OnTopologyGenerationChanged", startup)
        self.assertNotIn("ConfirmPcpInboundV6", prober + header)
        self.assertIn("m_sameLanEvidence.peer_endpoint.SameSocketEndpoint", prober)
        self.assertIn("sin6_scope_id", base)
        self.assertIn("IPV6_UNICAST_IF", base)
        self.assertIn("EvaluateScopedSocketBind", base)
        self.assertIn("InterlockedCompareExchange", base)
        self.assertIn("TAG_ESE_KADIP_V6", kad)
        self.assertIn("natmap::Transport::Udp", kad)
        self.assertIn("v6UdpObservation.IsVerifiedFor", kad)
        self.assertIn("natmap::Transport::Tcp", gateway)
        self.assertIn("v6TcpObservation.IsVerifiedFor", gateway)
        ipv6_gateway = gateway[
            gateway.index("ticket.target_endpoint.addr.family == kad6::Kad6Address::Family::IPv6") :
            gateway.index("apparent.addr.family = kad6::Kad6Address::Family::IPv6")
        ]
        self.assertIn("!v6TcpObservation.IsVerifiedFor(topologyGeneration)", ipv6_gateway)
        self.assertIn("reject(kad6::K6DialStatus::PolicyDenied)", ipv6_gateway)
        self.assertGreaterEqual(dlg.count("OnTopologyGenerationChanged("), 2)

    def test_build_wiring_contains_the_policy_and_native_gate(self) -> None:
        make = (ROOT / "libnatmap/make.bat").read_text(encoding="utf-8")
        project = (ROOT / "srchybrid/emule.vcxproj").read_text(encoding="utf-8")
        self.assertIn("test_ipv6_scope_policy.exe", make)
        self.assertIn("ipv6_scope_policy.cpp", make)
        self.assertIn("ipv6_scope_policy.cpp", project)
        self.assertIn("ipv6_scope_policy.h", project)

    def test_other_interface_or_generation_cannot_inherit_same_lan_exception(self) -> None:
        header, source, native = self.policy_text()
        for marker in (
            "Ipv6ScopeDisposition::RejectSameLan",
            "SameRouteBinding(",
            "ReasonCode::InterfaceChanged",
            "TestSameLanDoesNotCrossInterfaceOrGeneration",
        ):
            self.assertIn(marker, header + source + native)

    def test_stop_lan_never_reaches_global_consumers_or_unsanitized_reporting(self) -> None:
        header, source, native = self.policy_text()
        for marker in (
            "may_advertise_kad = false",
            "may_advertise_remote_hello = false",
            "may_publish_global = false",
            "may_emit_unsanitized_report = false",
            "TestSameLanCannotReachGlobalConsumers",
            "TestSameLanRequiresRemotePeerInExactScope",
        ):
            self.assertIn(marker, header + source + native)


if __name__ == "__main__":
    unittest.main(verbosity=2)
