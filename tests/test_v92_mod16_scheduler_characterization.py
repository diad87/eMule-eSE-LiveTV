"""MOD-1.6 pre-extraction scheduler and deferred-work characterization."""

from __future__ import annotations

import importlib.util
import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
COORDINATOR = ROOT / "srchybrid" / "LiveTunnel.cpp"
INTERFACE = ROOT / "srchybrid" / "LiveTunnel.h"
SCHEDULER = ROOT / "srchybrid" / "LiveTunnelScheduler.cpp"
SCHEDULER_INTERFACE = ROOT / "srchybrid" / "LiveTunnelScheduler.h"
PROJECT = ROOT / "srchybrid" / "emule.vcxproj"
VERIFIER_PATH = ROOT / "tools" / "architecture" / "verify_mod02_characterization.py"

SPEC = importlib.util.spec_from_file_location("mod16_verifier", VERIFIER_PATH)
assert SPEC is not None and SPEC.loader is not None
VERIFIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFIER)


class Mod16SchedulerCharacterizationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = COORDINATOR.read_text(encoding="utf-8")
        cls.interface = INTERFACE.read_text(encoding="utf-8")
        cls.scheduler = SCHEDULER.read_text(encoding="utf-8")
        cls.scheduler_interface = SCHEDULER_INTERFACE.read_text(encoding="utf-8")

    def body(self, symbol: str) -> str:
        return VERIFIER.function_body(self.source, symbol)

    def test_deferred_drain_is_bounded_and_rebuilds_snapshot(self) -> None:
        body = self.body("CLiveTunnel::ProcessMainThreadWork")
        self.assertIn("LiveTunnelScheduler::kDefaultDrainBudget", body)
        self.assertIn("m_scheduler.TryTake(req)", body)
        self.assertLess(body.index("m_scheduler.TryTake(req)"), body.index("switch (req.op)"))
        self.assertIn("catch (...)", body)
        self.assertLess(body.index("catch (...)"), body.rindex("RebuildPeersCache()"))

    def test_queue_lock_is_released_before_external_work(self) -> None:
        body = self.body("CLiveTunnel::ProcessMainThreadWork")
        take = body.index("m_scheduler.TryTake(req)")
        send = body.index("SendThrough(", take)
        self.assertLess(take, send)
        take_body = VERIFIER.function_body(
            self.scheduler, "LiveTunnelScheduler::TryTake")
        self.assertIn("std::lock_guard<std::mutex>", take_body)
        self.assertIn("m_deferred_work.pop_front()", take_body)

    def test_timer_callback_is_shutdown_and_exception_safe(self) -> None:
        body = self.body("K6Class5TimerProc")
        self.assertIn("theApp.IsClosing()", body)
        self.assertGreaterEqual(body.count("::KillTimer(NULL, timerId)"), 2)
        self.assertIn("CLiveTunnel::Get().Stop()", body)
        self.assertIn("catch (...)", body)

    def test_class5_timer_keeps_fair_allocations_alive(self) -> None:
        fair = self.body("CLiveTunnel::ProcessK6FairTick")
        tick = self.body("CLiveTunnel::ProcessClass5Tick")
        self.assertIn("!m_k6FairAllocationByStream.empty()", fair)
        self.assertGreaterEqual(tick.count("ShouldStopClass5Timer"), 2)
        decision = VERIFIER.function_body(
            self.scheduler,
            "LiveTunnelScheduler::ShouldStopClass5Timer",
        )
        self.assertIn("!has_shaped_links && !fair_work_active", decision)

    def test_tick_deadlines_are_wrap_safe(self) -> None:
        tick = self.body("CLiveTunnel::Tick")
        for marker in (
            "HasStrictlyElapsed32",
            "DueRttProbe",
            "DueBulkSubscription",
            "MarkBulkSubscription",
            "RecordTick",
        ):
            self.assertIn(marker, tick)
        due = self.body("CLiveTunnel::FinishDueSearchJobs")
        self.assertIn("DeadlineReached32", due)
        elapsed = VERIFIER.function_body(
            self.scheduler, "LiveTunnelScheduler::Elapsed32")
        deadline = VERIFIER.function_body(
            self.scheduler, "LiveTunnelScheduler::DeadlineReached32")
        self.assertIn("return now - since", elapsed)
        self.assertIn("static_cast<std::int32_t>(now - deadline) >= 0", deadline)
        self.assertIn("FakeClock32", self.scheduler)
        self.assertIn("numeric_limits<std::uint32_t>::max", self.scheduler)

    def test_retry_publication_preserves_pending_then_queue_order(self) -> None:
        tick = self.body("CLiveTunnel::Tick")
        collect = tick.index("m_pendingRequests.CollectRetries")
        publish = tick.index("m_scheduler.EnqueueBatch", collect)
        self.assertLess(collect, publish)

    def test_shutdown_stops_timer_before_releasing_tunnel_state(self) -> None:
        body = self.body("CLiveTunnel::Stop")
        stop_timer = body.index("StopK6ShapeTimerLocked()")
        clear_registry = body.index("m_circuitRegistry.Clear()")
        clear_pending = body.index("m_exitServices.Clear()")
        self.assertLess(stop_timer, clear_registry)
        self.assertLess(clear_registry, clear_pending)
        self.assertIn("m_scheduler.ClearDeferredWork()", body)
        for marker in (
            "m_k6ShapeReverse.clear()",
            "m_k6FairAllocationByStream.clear()",
            "m_k6FairScheduler.Reset()",
        ):
            self.assertIn(marker, body)

    def test_scheduler_state_has_one_declared_owner_after_transfer(self) -> None:
        for removed in (
            "m_mtQueue", "m_mtLock", "m_k6ShapeTimer",
            "m_lastTickMs", "m_lastRttPingTick", "m_lastBulkSubTick",
            "struct MainThreadReq", "enum MtOp",
        ):
            self.assertNotIn(removed, self.interface)
        for owned in (
            "std::deque<LiveDeferredWork> m_deferred_work",
            "std::uint32_t m_last_tick",
            "std::uint32_t m_last_rtt_probe",
            "std::uint32_t m_last_bulk_subscription",
            "std::uintptr_t m_class5_timer",
        ):
            self.assertEqual(self.scheduler_interface.count(owned), 1)

    def test_module_is_project_owned_and_coordinator_independent(self) -> None:
        project = PROJECT.read_text(encoding="utf-8")
        self.assertIn('ClCompile Include="LiveTunnelScheduler.cpp"', project)
        self.assertIn('ClInclude Include="LiveTunnelScheduler.h"', project)
        self.assertNotIn('#include "LiveTunnel.h"', self.scheduler)
        self.assertNotIn('#include "LiveTunnel.h"', self.scheduler_interface)
        self.assertIn(
            "RunLiveTunnelSchedulerCharacterizationSelfTest()",
            self.body("CLiveTunnel::RunCharacterizationSelfTest"),
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
