#!/usr/bin/env python3
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def function_body(source: str, signature: str, next_signature: str) -> str:
    start = source.index(signature)
    return source[start : source.index(next_signature, start)]


class M05BackoffHostContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.header = read("libnatmap/include/natmap/natmap_policy.h")
        cls.policy = read("libnatmap/src/natmap_policy.cpp")
        cls.native = read("libnatmap/tests/test_mapping_recovery.cpp")
        cls.dialog = read("srchybrid/EmuleDlg.cpp")
        cls.dialog_h = read("srchybrid/EmuleDlg.h")
        cls.manager = read("srchybrid/DirectReachabilityManager.cpp")
        cls.manager_h = read("srchybrid/DirectReachabilityManager.h")
        cls.make = read("libnatmap/make.bat")
        cls.wp0 = read("tools/lab/test_t8_wp0.ps1")

    def test_scheduler_is_generation_bound_and_bounded(self) -> None:
        for marker in (
            "class MappingRecoverySchedule",
            "kMaximumAttempts = 6",
            "kFirstRetryDelayMs = 30000",
            "kMaximumRetryDelayMs = 300000",
            "ResetForNetworkChange",
            "RecordSuccess",
            "Cancel",
        ):
            self.assertIn(marker, self.header)
        self.assertIn("generation <= generation_", self.policy)
        self.assertIn("attempt_count_ < kMaximumAttempts", self.policy)
        self.assertIn("SaturatingAdd(now_ms, delay_ms)", self.policy)

    def test_fake_clock_covers_every_required_reset(self) -> None:
        for marker in (
            "TestFirstRetryAndGrowth",
            "next_attempt_ms() == 31000",
            "next_attempt_ms() == 91000",
            "TestMaximumAttemptsAndDelay",
            "IsExhausted()",
            "TestSuccessResetIsGenerationBound",
            "TestNetworkChangeResetIsControlled",
            "TestOverflowAndShutdownCancellation",
        ):
            self.assertIn(marker, self.native)

    def test_network_change_arms_one_immediate_round(self) -> None:
        body = function_body(
            self.dialog,
            "bool CemuleDlg::HandleUPnPNetworkChange(",
            "bool CemuleDlg::CheckUPnPLease()",
        )
        reset = body.index("m_upnpRecoverySchedule.ResetForNetworkChange(")
        begin = body.index("m_upnpRecoverySchedule.BeginAttempt(")
        start = body.index("StartUPnP(true")
        self.assertLess(reset, begin)
        self.assertLess(begin, start)
        self.assertIn("if (!generationAdvanced)", body)

    def test_pending_recovery_obeys_due_time_and_maximum(self) -> None:
        body = function_body(
            self.dialog,
            "bool CemuleDlg::CheckUPnPLease()",
            "LRESULT CemuleDlg::OnUPnPResult",
        )
        for marker in (
            "m_upnpRecoverySchedule.IsExhausted()",
            "m_mappingResultGate.has_pending()",
            "m_hUPnPTimeOutTimer != 0",
            "m_upnpRecoverySchedule.ShouldAttempt(",
            "m_upnpRecoverySchedule.BeginAttempt(",
        ):
            self.assertIn(marker, body)
        begin = body.index("m_upnpRecoverySchedule.BeginAttempt(")
        self.assertLess(begin, body.index("StartUPnP(true"))

    def test_mapper_chain_is_one_round_and_success_resets(self) -> None:
        body = function_body(
            self.dialog,
            "LRESULT CemuleDlg::OnUPnPResult",
            "LRESULT CemuleDlg::OnPowerBroadcast",
        )
        switch = body.index("SwitchImplentation()")
        exhausted = body.index("No more available UPnP implementations left")
        pending = body.index("m_bUPnPRouteRecoveryPending = true", exhausted)
        self.assertLess(switch, exhausted)
        self.assertLess(exhausted, pending)
        self.assertIn("One recovery attempt is a complete mapper round", body)
        self.assertIn("m_upnpRecoverySchedule.RecordSuccess(", body)
        self.assertIn("backoff reset", body)

    def test_expiry_and_epoch_reset_enter_recovery(self) -> None:
        body = function_body(
            self.dialog,
            "bool CemuleDlg::CheckUPnPLease()",
            "LRESULT CemuleDlg::OnUPnPResult",
        )
        expiry = body[body.index("if (impl->IsLeaseExpired())") :]
        self.assertIn("ObserveFiniteMappingExpiry()", expiry)
        self.assertIn("ResetForNetworkChange(", expiry)
        self.assertIn("BeginAttempt(", expiry)

        result = function_body(
            self.dialog,
            "LRESULT CemuleDlg::OnUPnPResult",
            "LRESULT CemuleDlg::OnPowerBroadcast",
        )
        epoch = result[result.index("mapper_epoch_reset") :]
        self.assertIn("ObserveMapperEpochReset()", epoch)
        self.assertIn("ResetForNetworkChange(", epoch)
        self.assertIn("m_bUPnPRouteRecoveryPending = true", epoch)

    def test_failed_permanent_health_probe_withdraws_before_recovery(self) -> None:
        result = function_body(
            self.dialog,
            "LRESULT CemuleDlg::OnUPnPResult",
            "LRESULT CemuleDlg::OnPowerBroadcast",
        )
        comment = "// A failed refresh of a finite lease"
        health_loss = result[
            result.index(comment)
            : result.index("//>>> WiZaRd", result.index(comment))
        ]
        for marker in (
            "bWasRefresh",
            "resultCode != CUPnPImpl::UPNP_OK",
            "impl->GetMappingLeaseLifetime() == 0",
            "impl->SupportsMappingHealthCheck()",
            "ObserveMappingLoss()",
            "ShouldRestartAdvertisementLogin(",
            "ResetForNetworkChange(",
            "m_bUPnPRouteRecoveryPending = true",
        ):
            self.assertIn(marker, health_loss)
        self.assertLess(
            health_loss.index("ObserveMappingLoss()"),
            health_loss.index("ResetForNetworkChange("),
        )
        self.assertIn("bool ObserveMappingLoss();", self.manager_h)
        mapping_loss = function_body(
            self.manager,
            "bool CDirectReachabilityManager::ObserveMappingLoss()",
            "bool CDirectReachabilityManager::HasVerifiedEd2kReachability()",
        )
        self.assertIn("DisableMappedPlanes(", mapping_loss)

    def test_shutdown_cancels_budget_and_complete_gates_are_exact(self) -> None:
        stop = function_body(
            self.dialog,
            "void CemuleDlg::StopUPnP()",
            "void CemuleDlg::RefreshUPnP(",
        )
        self.assertIn("m_upnpRecoverySchedule.Cancel()", stop)
        self.assertIn(
            "natmap::MappingRecoverySchedule m_upnpRecoverySchedule",
            self.dialog_h,
        )
        self.assertIn("test_mapping_recovery.exe", self.make)
        self.assertIn(
            "'test_mapping_recovery: (65) checks, 0 failures'",
            self.wp0,
        )
        self.assertIn("$m05NativeChecks -eq 65", self.wp0)
        self.assertIn("$m05HostText -match 'Ran 8 tests'", self.wp0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
