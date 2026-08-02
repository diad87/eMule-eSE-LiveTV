#!/usr/bin/env python3
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def function_body(source: str, signature: str, next_signature: str) -> str:
    start = source.index(signature)
    end = source.index(next_signature, start)
    return source[start:end]


class M04NetworkChangeHostContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.header = read("libnatmap/include/natmap/network_change.h")
        cls.native = read("libnatmap/src/network_change.cpp")
        cls.native_test = read("libnatmap/tests/test_network_change.cpp")
        cls.policy = read("libnatmap/src/natmap_policy.cpp")
        cls.policy_test = read("libnatmap/tests/test_lease_policy.cpp")
        cls.manager = read("srchybrid/DirectReachabilityManager.cpp")
        cls.dialog = read("srchybrid/EmuleDlg.cpp")
        cls.server = read("srchybrid/ServerConnect.cpp")
        cls.project = read("srchybrid/emule.vcxproj")
        cls.make = read("libnatmap/make.bat")
        cls.wp0 = read("tools/lab/test_t8_wp0.ps1")

    def test_transition_preserves_generation_and_attempt_audit(self) -> None:
        for marker in (
            "previous_generation",
            "current_generation",
            "cancelled_attempt_ids",
            "withdrew_advertisement",
            "GenerationExhausted",
        ):
            self.assertIn(marker, self.header)
        self.assertIn("current_generation == previous_generation + 1", self.header)

    def test_transition_invalidates_all_planes_transactionally(self) -> None:
        body = function_body(
            self.native,
            "NetworkChangeTransition PrepareNetworkChange(",
            "}  // namespace natmap",
        )
        for plane in ("ed2k_tcp_v4", "kad_udp_v4", "direct_v6"):
            self.assertIn(f"current.{plane}", body)
            self.assertIn(f"candidate.{plane}", body)
        self.assertLess(body.index("const TransitionResult tcp"), body.index("candidate.ed2k_tcp_v4"))
        self.assertIn("ReasonCode::InterfaceChanged", body)
        self.assertIn("std::numeric_limits<std::uint64_t>::max", body)

    def test_native_cases_fence_original_request_and_stale_callback(self) -> None:
        for marker in (
            "TestInvalidatesEveryPlaneAndAdvancesExactlyOnce",
            "cancelled.request_id == 90",
            "cancelled.topology_generation == 7",
            "ResultAcceptance::NoPendingRequest",
            "ResultAcceptance::StaleTopology",
            "rediscovery.context.request_id == 91",
            "rediscovery.context.topology_generation == 8",
            "TestInvalidAndExhaustedInputsAreTransactional",
            "TestRediscoveryCompletesThePreparedGeneration",
            "RequiresAdvertisementRelogin(",
            "ShouldRestartAdvertisementLogin(",
            "new_attempt.attempt_id != 41",
            "mapped.verification_attempt.attempt_id == 42",
        ):
            self.assertIn(marker, self.native_test)

    def test_manager_commits_prepared_state_before_clearing_mapping_state(self) -> None:
        body = function_body(
            self.manager,
            "bool CDirectReachabilityManager::ObserveNetworkRouteChange(",
            "bool CDirectReachabilityManager::DisableMappedPlanes(",
        )
        self.assertIn("natmap::PrepareNetworkChange(m_snapshot)", body)
        self.assertIn("prepared.IsApplied()", body)
        self.assertLess(body.index("m_snapshot = prepared.snapshot"), body.index("m_tcpLease ="))
        self.assertIn("FailClosedAtGenerationLimit", body)
        invalid_branch = body[
            body.index("if (!prepared.IsApplied())") :
            body.index("m_snapshot = prepared.snapshot")
        ]
        self.assertIn("FailClosedAtGenerationLimit", invalid_branch)
        self.assertNotIn("DisableMappedPlanes(", body)
        self.assertIn(
            "m_nNetworkChangeRediscoveryGeneration =\n\t\tprepared.current_generation",
            body,
        )
        emergency = function_body(
            self.manager,
            "void CDirectReachabilityManager::FailClosedAtGenerationLimit(",
            "void CDirectReachabilityManager::AssertMainThread()",
        )
        self.assertNotIn("ApplyEvent(", emergency)
        for plane in ("ed2k_tcp_v4", "kad_udp_v4", "direct_v6"):
            self.assertIn(f"m_snapshot.{plane} = DisabledPlane", emergency)
        self.assertIn("m_nNetworkChangeRediscoveryGeneration = 0", emergency)

    def test_signature_change_is_checked_before_waiting_for_inflight_work(self) -> None:
        body = function_body(
            self.dialog,
            "bool CemuleDlg::CheckUPnPLease()",
            "LRESULT CemuleDlg::OnUPnPResult",
        )
        change = body.index("HandleUPnPNetworkChange(networkSignature)")
        self.assertLess(change, body.index("theApp.m_pUPnPFinder == NULL"))
        self.assertLess(change, body.index("m_bUPnPRouteRecoveryPending"))
        self.assertLess(change, body.index("impl->IsLeaseExpired()"))
        self.assertLess(change, body.index("m_hUPnPTimeOutTimer != 0"))

    def test_product_fences_then_rediscovers_and_fails_closed_on_generation_error(self) -> None:
        body = function_body(
            self.dialog,
            "bool CemuleDlg::HandleUPnPNetworkChange(",
            "bool CemuleDlg::CheckUPnPLease()",
        )
        ordered = (
            "ObserveNetworkRouteChange(",
            "m_mappingResultGate.CancelPending()",
            "impl->SetMessageOnResult(NULL, 0)",
            "impl->StopAsyncFind()",
            "m_mappingResultMailbox->Clear()",
            "m_upnpNetworkSignature = theApp.directreachability != NULL",
            "StartUPnP(true, 0, 0, m_bUPnPExplicitRequest)",
        )
        positions = [body.index(marker) for marker in ordered]
        self.assertEqual(positions, sorted(positions))
        self.assertIn("if (!generationAdvanced)", body)
        fail_closed = body.index("if (!generationAdvanced)")
        self.assertLess(fail_closed, body.index("StartUPnP(true"))
        self.assertNotIn("impl->IsReady()", body)
        self.assertIn("ShouldRestartAdvertisementLogin", body)
        pre_fence = body[: body.index("CUPnPImpl *impl")]
        self.assertNotIn("if (!observedSignature.IsValid()", pre_fence)
        self.assertIn("!observedSignature.IsValid() || impl == NULL", body)
        self.assertIn(
            "m_upnpNetworkSignature = theApp.directreachability != NULL",
            body,
        )

        manager_mapping = self.manager[
            self.manager.index(
                "bool CDirectReachabilityManager::ObserveMappedPorts("
            ) :
        ]
        self.assertIn("natmap::IsNetworkChangeRediscovery(", manager_mapping)
        self.assertIn("completesNetworkChange\n\t\t? natmap::PlaneSnapshot{}", manager_mapping)
        self.assertIn("m_nNetworkChangeRediscoveryGeneration = 0", manager_mapping)
        self.assertIn(
            "|| (!observation.was_enabled && observation.is_enabled)",
            self.policy,
        )
        self.assertIn("CHECK(observe(3, 3, false, true))", self.policy_test)

        result_body = function_body(
            self.dialog,
            "LRESULT CemuleDlg::OnUPnPResult",
            "void CemuleDlg::StartUPnP(",
        )
        for marker in (
            "wasDirectReachabilityEnabled",
            "ObserveMapperResult(",
            "ShouldRestartAdvertisementLogin(",
            "theApp.serverconnect->IsConnecting()",
            "theApp.serverconnect->StopConnectionTry()",
            "theApp.serverconnect->Disconnect()",
            "theApp.serverconnect->ConnectToAnyServer()",
        ):
            self.assertIn(marker, result_body)
        self.assertIn("BeginEd2kVerification(attempt)", self.server)

    def test_complete_gates_compile_product_and_require_exact_counts(self) -> None:
        self.assertIn("src\\network_change.cpp", self.make)
        self.assertIn("test_network_change.exe", self.make)
        self.assertIn("..\\libnatmap\\src\\network_change.cpp", self.project)
        self.assertIn("..\\libnatmap\\include\\natmap\\network_change.h", self.project)
        self.assertIn("'test_network_change: (71) checks, 0 failures'", self.wp0)
        self.assertIn("$m04NativeChecks -eq 71", self.wp0)
        self.assertIn("Ran 7 tests", self.wp0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
