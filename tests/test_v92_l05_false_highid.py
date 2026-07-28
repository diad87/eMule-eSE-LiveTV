#!/usr/bin/env python3
"""Unattended product-integration gate for V9.2 L05."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class L05FalseHighIdHostContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        def read(relative: str) -> str:
            return (ROOT / relative).read_text(
                encoding="utf-8", errors="strict"
            )

        cls.types = read("libnatmap/include/natmap/natmap_types.h")
        cls.state = read("libnatmap/src/natmap_state.cpp")
        cls.focused = read("libnatmap/tests/test_false_highid.cpp")
        cls.make = read("libnatmap/make.bat")
        cls.manager_h = read("srchybrid/DirectReachabilityManager.h")
        cls.manager = read("srchybrid/DirectReachabilityManager.cpp")
        cls.server_connect = read("srchybrid/ServerConnect.cpp")
        cls.server_socket = read("srchybrid/ServerSocket.cpp")
        cls.server_socket_h = read("srchybrid/ServerSocket.h")
        cls.listen_socket = read("srchybrid/ListenSocket.cpp")
        cls.listen_socket_h = read("srchybrid/ListenSocket.h")
        cls.emule = read("srchybrid/Emule.cpp")
        cls.emule_h = read("srchybrid/Emule.h")
        cls.dialog = read("srchybrid/EmuleDlg.cpp")
        cls.web = read("srchybrid/WebServer.cpp")
        cls.live_dialog = read("srchybrid/LiveStreamDlgUI.cpp")
        cls.network_info = read("srchybrid/NetworkInfoDlg.cpp")
        cls.shared_files = read("srchybrid/SharedFileList.cpp")

    def test_focused_red_contract_runs_in_complete_gate(self) -> None:
        self.assertIn("test_false_highid.cpp", self.make)
        self.assertIn("build\\test_false_highid.exe", self.make)
        for marker in (
            "TestMappingAndServerHighIdWithoutInboundStayUnverified",
            "TestDerivedSuccessCannotBypassMissingInboundEvidence",
            "TestForgedReachableServerOnlySnapshotIsInconsistent",
            "TestWrongAttemptCannotBeRelabeledAsCurrent",
            "TestExpiredEvidenceCannotPromoteReachable",
            "TestOldGenerationCallbacksCannotPromoteNewEndpoint",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, self.focused)

    def test_reachable_snapshot_requires_both_evidence_kinds(self) -> None:
        consistency = self.state[
            self.state.index("bool IsSnapshotConsistent(") :
            self.state.index("TransitionResult ApplyEvent(")
        ]
        self.assertIn("HasBothReachabilityEvidence(snapshot)", consistency)
        predicate = self.state[
            self.state.index("bool HasBothReachabilityEvidence(") :
            self.state.index("} // namespace")
        ]
        self.assertIn(
            "snapshot.HasCompleteClassicHighIdEvidence()", predicate
        )
        self.assertIn(
            "snapshot.lease.public_endpoint", consistency
        )

    def test_public_highid_predicate_is_mapping_and_endpoint_bound(self) -> None:
        predicate = self.types[
            self.types.index("bool HasCompleteClassicHighIdEvidence()") :
            self.types.index("};", self.types.index(
                "bool HasCompleteClassicHighIdEvidence()"
            ))
        ]
        for marker in (
            "lease.IsStructurallyValid()",
            "lease.generation == generation",
            "lease.public_endpoint.SameSocketEndpoint(advertised)",
            "verification_attempt.endpoint.SameSocketEndpoint(advertised)",
            "EvidenceKind::ServerHighId",
            "EvidenceKind::InboundTcpAccept",
            "primary_evidence.IsFreshFor(verification_attempt)",
            "inbound_evidence.IsFreshFor(verification_attempt)",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, predicate)
        public_predicate = self.types[
            self.types.index("bool HasClassicHighIdEvidence()") :
            self.types.index("};", self.types.index(
                "bool HasClassicHighIdEvidence()"
            ))
        ]
        self.assertIn(
            "HasCompleteClassicHighIdEvidence()", public_predicate
        )

    def test_server_login_starts_verification_before_advertisement(self) -> None:
        established = self.server_connect[
            self.server_connect.index(
                "void CServerConnect::ConnectionEstablished("
            ) :
            self.server_connect.index(
                "void CServerConnect::ConnectionFailed("
            )
        ]
        self.assertLess(
            established.index("BeginEd2kVerification("),
            established.index("GetAdvertisedTcpPort()"),
        )

    def test_idchange_only_records_server_evidence(self) -> None:
        observer = self.manager[
            self.manager.index(
                "bool CDirectReachabilityManager::ObserveServerIdChange("
            ) :
            self.manager.index(
                "bool CDirectReachabilityManager::ObserveInboundTcpAccept("
            )
        ]
        self.assertIn("EvidenceKind::ServerHighId", observer)
        self.assertNotIn("EvidenceKind::InboundTcpAccept", observer)
        idchange = self.server_socket[
            self.server_socket.index("case OP_IDCHANGE:") :
            self.server_socket.index("case OP_SEARCHRESULT:")
        ]
        self.assertIn("ObserveServerIdChange(", idchange)

    def test_inbound_evidence_has_a_separate_real_accept_callsite(self) -> None:
        self.assertEqual(
            self.listen_socket.count("ObserveInboundTcpAccept("), 1
        )
        call = self.listen_socket.index("ObserveInboundTcpAccept(")
        guard = self.listen_socket.rfind(
            "IsGoodIP(SockAddr.sin_addr.s_addr, true)", 0, call
        )
        self.assertNotEqual(guard, -1)
        observer = self.manager[
            self.manager.index(
                "bool CDirectReachabilityManager::ObserveInboundTcpAccept("
            ) :
            self.manager.index(
                "bool CDirectReachabilityManager::ObserveMappedPorts("
            )
        ]
        self.assertIn("EvidenceKind::InboundTcpAccept", observer)
        self.assertNotIn("EvidenceKind::ServerHighId", observer)

    def test_callbacks_carry_captured_attempt_and_deadline(self) -> None:
        for marker in (
            "struct VerificationAttempt",
            "attempt_id",
            "topology_generation",
            "started_monotonic_ms",
            "deadline_monotonic_ms",
            "verification_attempt_id",
            "IsFreshFor",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, self.types)

        server_observer = self.manager[
            self.manager.index(
                "bool CDirectReachabilityManager::ObserveServerIdChange("
            ) :
            self.manager.index(
                "bool CDirectReachabilityManager::ObserveInboundTcpAccept("
            )
        ]
        inbound_observer = self.manager[
            self.manager.index(
                "bool CDirectReachabilityManager::ObserveInboundTcpAccept("
            ) :
            self.manager.index(
                "bool CDirectReachabilityManager::ObserveMappedPorts("
            )
        ]
        for observer in (server_observer, inbound_observer):
            self.assertIn(
                "const natmap::VerificationAttempt& attempt", observer
            )
            self.assertIn("attempt.endpoint", observer)
            self.assertIn("attempt.topology_generation", observer)
            self.assertIn("attempt.attempt_id", observer)
            self.assertNotIn("m_snapshot.ed2k_tcp_v4.advertised", observer)

        self.assertIn(
            "natmap::VerificationAttempt m_ed2kVerificationAttempt",
            self.server_socket_h,
        )
        self.assertIn(
            "m_ed2kVerificationAttempt);", self.server_socket
        )
        self.assertIn(
            "ArmDirectReachabilityVerification(", self.listen_socket_h
        )
        self.assertIn(
            "m_ed2kVerificationAttempt)", self.listen_socket
        )

    def test_ui_and_firewall_status_consume_verified_predicate(self) -> None:
        self.assertIn("HasVerifiedEd2kHighId() const", self.emule_h)
        verdict = self.emule[
            self.emule.index("bool CemuleApp::HasVerifiedEd2kHighId()") :
            self.emule.index("bool CemuleApp::IsFirewalled()")
        ]
        self.assertIn("serverconnect->IsLowID()", verdict)
        self.assertIn("HasVerifiedEd2kReachability()", verdict)
        firewalled = self.emule[
            self.emule.index("bool CemuleApp::IsFirewalled()") :
            self.emule.index("bool CemuleApp::CanDoCallback(")
        ]
        self.assertIn("HasVerifiedEd2kHighId()", firewalled)
        self.assertIn(
            "return m_snapshot.ed2k_tcp_v4.HasClassicHighIdEvidence();",
            self.manager,
        )
        self.assertIn("theApp.HasVerifiedEd2kHighId()", self.dialog)
        self.assertIn("theApp.HasVerifiedEd2kHighId()", self.live_dialog)
        self.assertGreaterEqual(
            self.web.count("theApp.HasVerifiedEd2kHighId()"), 3
        )
        self.assertGreaterEqual(
            self.network_info.count(
                "theApp.HasVerifiedEd2kHighId()"
            ),
            2,
        )
        self.assertGreaterEqual(
            self.shared_files.count(
                "theApp.HasVerifiedEd2kHighId()"
            ),
            2,
        )
        self.assertNotRegex(
            self.web,
            r"IsLowID\(\)\s*\?\s*_T\(\"low\"\)\s*:\s*_T\(\"high\"\)",
        )

    def test_relay_does_not_fabricate_direct_evidence(self) -> None:
        self.assertIn("if (!sender->IsRelayRouted()", self.server_connect)
        self.assertIn("if (!m_bRelayRouted", self.server_socket)
        manager_api = self.manager_h[
            self.manager_h.index("bool BeginEd2kVerification(") :
            self.manager_h.index("uint64 GetTopologyGeneration()")
        ]
        self.assertNotIn("Relay", manager_api)
        verdict = self.emule[
            self.emule.index("bool CemuleApp::HasVerifiedEd2kHighId()") :
            self.emule.index("bool CemuleApp::IsFirewalled()")
        ]
        self.assertIn("serverconnect->IsConnectedViaRelay()", verdict)
        self.assertLess(
            verdict.index("serverconnect->IsConnectedViaRelay()"),
            verdict.index("HasVerifiedEd2kReachability()"),
        )
        relay_guard = verdict[
            verdict.index("serverconnect->IsConnectedViaRelay()") :
            verdict.index("HasVerifiedEd2kReachability()")
        ]
        self.assertIn("return false;", relay_guard)

    def test_same_port_different_address_renewal_is_rejected(self) -> None:
        renewal = self.state[
            self.state.index("case EventType::RenewalSucceeded:") :
            self.state.index("case EventType::LeaseLost:")
        ]
        self.assertIn("SameEndpoint(", renewal)
        self.assertNotIn(
            "event.lease.public_endpoint.port !=",
            renewal,
        )
        self.assertIn(
            "TestSamePortDifferentAddressRenewalFailsClosed",
            self.focused,
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
