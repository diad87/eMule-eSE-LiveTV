"""MOD-1.6 pre-extraction scheduler and deferred-work characterization."""

from __future__ import annotations

import importlib.util
import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
COORDINATOR = ROOT / "srchybrid" / "LiveTunnel.cpp"
INTERFACE = ROOT / "srchybrid" / "LiveTunnel.h"
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

    def body(self, symbol: str) -> str:
        return VERIFIER.function_body(self.source, symbol)

    def test_deferred_drain_is_bounded_and_rebuilds_snapshot(self) -> None:
        body = self.body("CLiveTunnel::ProcessMainThreadWork")
        self.assertIn("budget < 256", body)
        self.assertIn("m_mtQueue.front()", body)
        self.assertIn("m_mtQueue.pop_front()", body)
        self.assertLess(body.index("m_mtQueue.pop_front()"), body.index("switch (req.op)"))
        self.assertIn("catch (...)", body)
        self.assertLess(body.index("catch (...)"), body.rindex("RebuildPeersCache()"))

    def test_queue_lock_is_released_before_external_work(self) -> None:
        body = self.body("CLiveTunnel::ProcessMainThreadWork")
        lock = body.index("CSingleLock lk(&m_mtLock, TRUE)")
        pop = body.index("m_mtQueue.pop_front()", lock)
        send = body.index("SendThrough(", pop)
        self.assertIn("}", body[pop:send])

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
        self.assertIn("if (!fairActive) StopK6ShapeTimerLocked()", tick)
        self.assertIn("m_k6ShapeReverse.empty() && !fairActive", tick)

    def test_tick_deadlines_are_wrap_safe(self) -> None:
        tick = self.body("CLiveTunnel::Tick")
        for marker in (
            "(DWORD)(now - c->m_extendStartedTick)",
            "(DWORD)(now - m_lastRttPingTick)",
            "(DWORD)(now - it->second.first_seen_tick)",
            "(DWORD)(now - it->second.started)",
            "(DWORD)(now - m_lastBulkSubTick)",
            "(DWORD)(now - cit->second.lastSeen)",
        ):
            self.assertIn(marker, tick)
        due = self.body("CLiveTunnel::FinishDueSearchJobs")
        self.assertIn("(int)(now - it->second.deadline) >= 0", due)

    def test_retry_publication_preserves_pending_then_queue_order(self) -> None:
        tick = self.body("CLiveTunnel::Tick")
        collect = tick.index("m_pendingRequests.CollectRetries")
        queue_lock = tick.index("CSingleLock lk(&m_mtLock, TRUE)", collect)
        publish = tick.index("m_mtQueue.push_back", queue_lock)
        self.assertLess(collect, queue_lock)
        self.assertLess(queue_lock, publish)

    def test_shutdown_stops_timer_before_releasing_tunnel_state(self) -> None:
        body = self.body("CLiveTunnel::Stop")
        stop_timer = body.index("StopK6ShapeTimerLocked()")
        clear_registry = body.index("m_circuitRegistry.Clear()")
        clear_pending = body.index("m_exitServices.Clear()")
        self.assertLess(stop_timer, clear_registry)
        self.assertLess(clear_registry, clear_pending)
        for marker in (
            "m_k6ShapeReverse.clear()",
            "m_k6FairAllocationByStream.clear()",
            "m_k6FairScheduler.Reset()",
        ):
            self.assertIn(marker, body)

    def test_scheduler_state_has_one_declared_owner_before_transfer(self) -> None:
        for declaration in (
            "std::deque<MainThreadReq> m_mtQueue",
            "UINT_PTR m_k6ShapeTimer = 0",
            "DWORD m_lastTickMs",
            "DWORD    m_lastRttPingTick = 0",
            "DWORD    m_lastBulkSubTick  = 0",
        ):
            self.assertEqual(self.interface.count(declaration), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
