"""MOD-1.6 pre-extraction scheduler and deferred-work characterization."""

from __future__ import annotations

import importlib.util
import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
COORDINATOR = ROOT / "srchybrid" / "LiveTunnel.cpp"
COORDINATOR_METHODS = ROOT / "srchybrid" / "LiveTunnelCoordinatorMethods.inl"
BULK_FACADE = ROOT / "srchybrid" / "LiveTunnelBulkFacade.inl"
SEARCH_FACADE = ROOT / "srchybrid" / "LiveTunnelSearchFacade.inl"
SEARCH_SERVICE = ROOT / "srchybrid" / "LiveTunnelSearchService.cpp"
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
        cls.owner_sources = [
            path.read_text(encoding="utf-8")
            for path in (
                COORDINATOR, COORDINATOR_METHODS, BULK_FACADE, SEARCH_FACADE,
            )
        ]
        cls.source = "\n".join(cls.owner_sources)
        cls.interface = INTERFACE.read_text(encoding="utf-8")
        cls.scheduler = SCHEDULER.read_text(encoding="utf-8")
        cls.scheduler_interface = SCHEDULER_INTERFACE.read_text(encoding="utf-8")
        cls.search_service = SEARCH_SERVICE.read_text(encoding="utf-8")

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
        self.assertIn("m_scheduler.HasFairWork()", fair)
        self.assertEqual(tick.count("ShouldStopClass5Timer"), 1)
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
        self.assertIn("m_relayDispatcher.LT8TakeDue(now)", due)
        search_due = VERIFIER.function_body(
            self.search_service, "LiveTunnelSearchService::TakeDue"
        )
        self.assertIn("DeadlineReached32(now,it->second.deadline)", search_due)
        search_deadline = VERIFIER.function_body(
            self.search_service, "DeadlineReached32"
        )
        self.assertIn(
            "static_cast<std::int32_t>(now-deadline)>=0", search_deadline
        )
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
        close_queue = body.index("m_scheduler.CloseDeferredWork()")
        cancel_pending = body.index("m_pendingRequests.CancelAll()")
        stop_timer = body.index("StopK6ShapeTimerLocked()")
        clear_registry = body.index("m_circuitRegistry.Clear()")
        clear_pending = body.index("m_exitServices.Clear()")
        self.assertLess(close_queue, cancel_pending)
        self.assertLess(cancel_pending, stop_timer)
        self.assertLess(close_queue, stop_timer)
        self.assertLess(stop_timer, clear_registry)
        self.assertLess(clear_registry, clear_pending)
        for marker in (
            "m_scheduler.ClearShaping()",
            "m_scheduler.ClearFair()",
        ):
            self.assertIn(marker, body)

    def test_shutdown_boundary_rejects_racing_publication(self) -> None:
        enqueue = VERIFIER.function_body(
            self.scheduler, "LiveTunnelScheduler::Enqueue")
        close = VERIFIER.function_body(
            self.scheduler, "LiveTunnelScheduler::CloseDeferredWork")
        self.assertIn("std::lock_guard<std::mutex>", enqueue)
        self.assertIn("!m_accepting_deferred_work", enqueue)
        self.assertLess(
            close.index("m_accepting_deferred_work = false"),
            close.index("while (!m_deferred_work.empty())"),
        )
        self.assertIn("CharacterizeConcurrentClosePublication", self.scheduler)
        self.assertIn("scheduler.PendingCount() != 0", self.scheduler)
        self.assertIn("AllRequestsAre(cancelled, {iteration})", self.scheduler)

    def test_rejected_synchronous_work_wakes_waiters_immediately(self) -> None:
        for symbol in (
            "CLiveTunnel::RequestTestCircuit",
            "CLiveTunnel::RequestK6ServiceSwitch",
            "CLiveTunnel::RequestK6PublicRelease",
        ):
            body = self.body(symbol)
            reject = body.index("!m_scheduler.Enqueue")
            signal = body.index("SignalReply(reqId", reject)
            wait = body.index("WaitPending", signal)
            self.assertLess(reject, signal)
            self.assertLess(signal, wait)
        marshaled = self.body("CLiveTunnel::EnqueueSendMsg")
        self.assertIn("!m_scheduler.Enqueue", marshaled)
        self.assertIn("SignalReply(req_id", marshaled)

    def test_only_real_pool_rebuild_reopens_after_shutdown(self) -> None:
        pool = self.body("CLiveTunnel::BuildPool")
        startup = self.body("CLiveTunnel::CLiveTunnel")
        self.assertLess(
            pool.index("theApp.IsClosing()"),
            pool.index("m_scheduler.ReopenDeferredWork()"),
        )
        self.assertLess(
            pool.index("CSingleLock lock(&m_lock, TRUE)"),
            pool.index("m_scheduler.ReopenDeferredWork()"),
        )
        # Construction opens the queue initially; after shutdown only a real
        # pool rebuild is allowed to reopen it.
        self.assertEqual(startup.count("m_scheduler.ReopenDeferredWork()"), 1)
        self.assertEqual(pool.count("m_scheduler.ReopenDeferredWork()"), 1)
        self.assertEqual(self.source.count("m_scheduler.ReopenDeferredWork()"), 2)

    def test_scheduler_state_has_one_declared_owner_after_transfer(self) -> None:
        for removed in (
            "m_mtQueue", "m_mtLock", "m_k6ShapeTimer",
            "m_lastTickMs", "m_lastRttPingTick", "m_lastBulkSubTick",
            "struct MainThreadReq", "enum MtOp",
            "struct K6ShapedQueuedRecord", "struct K6ShapedLinkState",
            "m_k6ShapeReverse", "m_k6ShapeReplay",
            "m_k6FairScheduler", "m_k6FairPayloads", "m_k6FairCredits",
            "m_k6FairAllocationByStream", "m_k6FairPayloadBytes",
        ):
            self.assertNotIn(removed, self.interface)
        for owned in (
            "std::deque<LiveDeferredWork> m_deferred_work",
            "std::uint32_t m_last_tick",
            "std::uint32_t m_last_rtt_probe",
            "std::uint32_t m_last_bulk_subscription",
            "std::uintptr_t m_class5_timer",
            "bool m_accepting_deferred_work",
            "std::map<std::uint32_t, ShapedLinkState> m_shaped_links",
            "std::map<std::uint64_t, Bulk::BulkReplayWindow> m_shaped_replay",
            "kad6::K6FairScheduler m_fair_scheduler",
            "std::map<std::uint64_t, std::deque<FairPayload>> m_fair_payloads",
            "std::map<std::uint64_t, std::uint64_t> m_fair_allocation_by_stream",
        ):
            self.assertEqual(self.scheduler_interface.count(owned), 1)

    def test_shaping_policy_and_replay_are_scheduler_owned(self) -> None:
        tick = self.body("CLiveTunnel::ProcessClass5Tick")
        self.assertIn("m_scheduler.PollShapedLinks", tick)
        self.assertNotIn("K6Class5Scheduler", tick)
        for forbidden in ("m_k6ShapeReverse", "m_k6ShapeReplay"):
            self.assertNotIn(forbidden, self.source)
        for marker in (
            "ConfigureShapedLink",
            "QueueShapedRecord",
            "PrepareShapedEmission",
            "AcceptShapedReplay",
            "SweepShapedReplay",
            "ClearShaping",
            "CharacterizeShapingOwnership",
        ):
            self.assertIn(marker, self.scheduler + self.scheduler_interface)
        fair = self.body("CLiveTunnel::ProcessK6FairTick")
        self.assertIn("m_scheduler.PollFair", fair)
        self.assertIn("m_scheduler.HasFairWork", fair)
        self.assertNotIn("K6FairScheduler", fair)
        prepare = self.body("CLiveTunnel::PrepareK6ShapedEmissionLocked")
        emit = self.body("CLiveTunnel::EmitK6ShapedEmission")
        self.assertIn("m_scheduler.PrepareShapedEmission", prepare)
        self.assertNotIn("SendBulkCellToPeer", prepare)
        self.assertIn("SendBulkCellToPeer", emit)
        self.assertNotIn("m_scheduler.PrepareShapedEmission", emit)
        self.assertLess(
            tick.index("StopK6ShapeTimerLocked()"),
            tick.index("EmitK6ShapedEmission"),
        )

    def test_module_is_project_owned_and_coordinator_independent(self) -> None:
        project = PROJECT.read_text(encoding="utf-8")
        module_loc = (
            len(self.scheduler.splitlines())
            + len(self.scheduler_interface.splitlines())
        )
        self.assertGreaterEqual(module_loc, 300)
        self.assertLessEqual(module_loc, 1500)
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
