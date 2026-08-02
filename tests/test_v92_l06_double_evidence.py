#!/usr/bin/env python3
"""Unattended product-integration gate for V9.2 L06."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class L06DoubleEvidenceHostContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        def read(relative: str) -> str:
            return (ROOT / relative).read_text(encoding="utf-8")

        cls.focused = read("libnatmap/tests/test_false_highid.cpp")
        cls.types = read("libnatmap/include/natmap/natmap_types.h")
        cls.state = read("libnatmap/src/natmap_state.cpp")
        cls.manager = read("srchybrid/DirectReachabilityManager.cpp")
        cls.server_connect = read("srchybrid/ServerConnect.cpp")
        cls.server_socket = read("srchybrid/ServerSocket.cpp")
        cls.listen_socket = read("srchybrid/ListenSocket.cpp")
        cls.emule = read("srchybrid/Emule.cpp")

    def test_all_l06_behavior_cases_are_executable(self) -> None:
        main = self.focused[self.focused.index("int main()") :]
        for marker in (
            "TestServerThenInboundReachesVerifiedOnlyAfterDerivedSuccess",
            "TestInboundThenServerIsAllowedForSameAttempt",
            "TestDifferentGenerationEvidenceNeverCombines",
            "TestDuplicateInboundDoesNotPromoteOrChangeAttempt",
            "TestEndpointChangeBetweenEvidenceFencesOldInbound",
            "TestRelayAttemptIsRejectedBehaviorally",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, self.focused)
                self.assertIn(f"{marker}();", main)
        self.assertIn(
            '"double evidence L06: %d checks, %d failures\\n"', main
        )

    def test_both_orders_require_the_same_complete_predicate(self) -> None:
        self.assertGreaterEqual(
            self.focused.count("HasCompleteClassicHighIdEvidence()"), 5
        )
        predicate = self.types[
            self.types.index("bool HasCompleteClassicHighIdEvidence()") :
            self.types.index("bool HasClassicHighIdEvidence()")
        ]
        self.assertIn(
            "primary_evidence.IsFreshFor(verification_attempt)", predicate
        )
        self.assertIn(
            "inbound_evidence.IsFreshFor(verification_attempt)", predicate
        )
        success = self.state[
            self.state.index("case EventType::VerificationSucceeded:") :
            self.state.index("case EventType::RenewalDue:")
        ]
        self.assertIn("HasBothReachabilityEvidence(current)", success)

    def test_generation_attempt_endpoint_and_deadline_are_joint(self) -> None:
        freshness = self.types[
            self.types.index("bool IsFreshFor(") :
            self.types.index("};", self.types.index("bool IsFreshFor("))
        ]
        for marker in (
            "generation == attempt.topology_generation",
            "verification_attempt_id == attempt.attempt_id",
            "endpoint.SameSocketEndpoint(attempt.endpoint)",
            "observed_monotonic_ms >= attempt.started_monotonic_ms",
            "observed_monotonic_ms <= attempt.deadline_monotonic_ms",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, freshness)

    def test_relay_route_cannot_start_or_supply_direct_evidence(self) -> None:
        relay_behavior = self.focused[
            self.focused.index(
                "void TestRelayAttemptIsRejectedBehaviorally()"
            ) :
            self.focused.index("} // namespace")
        ]
        self.assertIn(
            "relayAttempt.path = VerificationPath::Relay", relay_behavior
        )
        self.assertIn(
            "TransitionDisposition::Invalid", relay_behavior
        )
        self.assertIn(
            "ReachabilityState::CandidateMapped", relay_behavior
        )
        self.assertIn(
            "path == VerificationPath::Direct", self.types
        )
        established = self.server_connect[
            self.server_connect.index(
                "void CServerConnect::ConnectionEstablished("
            ) :
            self.server_connect.index(
                "void CServerConnect::ConnectionFailed("
            )
        ]
        self.assertIn("if (!sender->IsRelayRouted()", established)
        idchange = self.server_socket[
            self.server_socket.index("case OP_IDCHANGE:") :
            self.server_socket.index("case OP_SEARCHRESULT:")
        ]
        self.assertIn("if (!m_bRelayRouted", idchange)
        verdict = self.emule[
            self.emule.index("bool CemuleApp::HasVerifiedEd2kHighId()") :
            self.emule.index("bool CemuleApp::IsFirewalled()")
        ]
        self.assertIn("serverconnect->IsConnectedViaRelay()", verdict)
        self.assertIn("return false;", verdict)

    def test_duplicate_inbound_never_creates_server_evidence(self) -> None:
        duplicate = self.focused[
            self.focused.index(
                "void TestDuplicateInboundDoesNotPromoteOrChangeAttempt()"
            ) :
            self.focused.index(
                "void TestEndpointChangeBetweenEvidenceFencesOldInbound()"
            )
        ]
        self.assertIn(
            "primary_evidence.kind == EvidenceKind::None", duplicate
        )
        self.assertIn(
            "!duplicate.snapshot.HasCompleteClassicHighIdEvidence()",
            duplicate,
        )
        observer = self.manager[
            self.manager.index(
                "bool CDirectReachabilityManager::ObserveInboundTcpAccept("
            ) :
            self.manager.index(
                "bool CDirectReachabilityManager::ObserveMappedPorts("
            )
        ]
        self.assertNotIn("EvidenceKind::ServerHighId", observer)

    def test_product_callbacks_keep_the_captured_attempt(self) -> None:
        self.assertIn(
            "m_ed2kVerificationAttempt);", self.server_socket
        )
        self.assertIn(
            "m_ed2kVerificationAttempt)", self.listen_socket
        )
        for marker in (
            "attempt.endpoint",
            "attempt.topology_generation",
            "attempt.attempt_id",
        ):
            with self.subTest(marker=marker):
                self.assertGreaterEqual(self.manager.count(marker), 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
