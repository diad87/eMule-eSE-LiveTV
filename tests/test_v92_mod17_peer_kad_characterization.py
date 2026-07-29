"""MOD-1.7 pre-extraction peer-state and Kad-boundary characterization."""

from __future__ import annotations

import importlib.util
import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
COORDINATOR = ROOT / "srchybrid" / "LiveTunnel.cpp"
INTERFACE = ROOT / "srchybrid" / "LiveTunnel.h"
PROJECT = ROOT / "srchybrid" / "emule.vcxproj"
VERIFIER_PATH = ROOT / "tools" / "architecture" / "verify_mod02_characterization.py"

SPEC = importlib.util.spec_from_file_location("mod17_verifier", VERIFIER_PATH)
assert SPEC is not None and SPEC.loader is not None
VERIFIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFIER)


class Mod17PeerKadCharacterizationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = COORDINATOR.read_text(encoding="utf-8")
        cls.interface = INTERFACE.read_text(encoding="utf-8")

    def body(self, symbol: str) -> str:
        return VERIFIER.function_body(self.source, symbol)

    def test_kad2_source_score_formula_is_frozen(self) -> None:
        body = self.body("CLiveTunnel::OnKad6GatewaySourceResult")
        self.assertIn("candidate.score = 100 + (ipv6OrNull != NULL ? 10 : 0)", body)
        self.assertIn("(reachCaps & 0x0001u) != 0 ? 5 : 0", body)
        self.assertIn("(std::min<uint32>)(100, history->second.successes * 20u)", body)
        self.assertIn("(std::min<uint32>)(80, history->second.failures * 10u)", body)
        self.assertIn(
            "candidate.score = candidate.score > penalty ? candidate.score - penalty : 0",
            body,
        )

    def test_kad6_source_score_formula_and_duplicate_replacement_are_frozen(self) -> None:
        body = self.body("CLiveTunnel::OnKad6NativeSourceRecord")
        self.assertIn("candidate.score = 200u + static_cast<uint32_t>(remaining / 3600u)", body)
        self.assertIn("K6SourceScoreKey(", body)
        self.assertIn("if (candidate.score > old.score) old = candidate", body)
        self.assertIn("job->second.maxResults * 2u", body)
        self.assertIn("job->second.maxResults + 8u", body)

    def test_score_history_is_network_scoped_saturating_and_bounded(self) -> None:
        key = self.body("CLiveTunnel::K6SourceScoreKey")
        self.assertIn("key.push_back(static_cast<char>(networkOrigin))", key)
        connect = self.body("CLiveTunnel::OnK6ExitSocketConnect")
        self.assertIn("(std::numeric_limits<uint32>::max)()", connect)
        sweep = self.body("CLiveTunnel::SweepK6Gateway")
        self.assertIn("24ull * 60 * 60", sweep)
        self.assertIn("while (m_k6SourceScores.size() > 4096)", sweep)

    def test_source_result_order_is_stable_descending_score(self) -> None:
        body = self.body("CLiveTunnel::SendK6SearchResults")
        self.assertIn("std::stable_sort", body)
        self.assertIn("return a->score > b->score", body)
        self.assertIn("ranked.size(), (size_t)job.maxResults", body)

    def test_origin_circuit_selection_is_fail_closed(self) -> None:
        body = self.body("CLiveTunnel::K6SelectOriginCircuit")
        for marker in (
            "CircuitRole::Originator",
            "CircuitState::Active",
            "circuit->m_k6QuotaIssuerCircuit",
            "circuit->HopCount() < minimumHops",
            "!circuit->m_multicell_ok",
            "!circuit->m_auth_ok",
            "(circuit->m_exit_signed_caps & requiredCaps) != requiredCaps",
        ):
            self.assertIn(marker, body)
        self.assertIn("return 0", body)

    def test_disconnect_scrubs_pointer_state_before_registry_state(self) -> None:
        body = self.body("CLiveTunnel::OnPeerDisconnected")
        pending = body.index("CSingleLock pl(&m_pendingLock, TRUE)")
        registry = body.index("CSingleLock lock(&m_lock, TRUE)")
        self.assertLess(pending, registry)
        for marker in (
            "m_k6DownloadActivations.erase",
            "stream.second.client = NULL",
            "lostFirst",
            "lostPrev",
            "lostNext",
            "lostPending",
            "CELL_DESTROY",
            "TransitionCircuitDestroyed",
        ):
            self.assertIn(marker, body)

    def test_kad_network_mask_and_wire_flags_remain_independent(self) -> None:
        body = self.body("CLiveTunnel::StartK6SourceLookup")
        self.assertIn("KadNetworkPolicy::HasKad2(selectedNetworks)", body)
        self.assertIn("start.network_mask |= kad6::kK6NetMaskKad2", body)
        self.assertIn("KadNetworkPolicy::HasKad6(selectedNetworks)", body)
        self.assertIn("start.network_mask |= kad6::kK6NetMaskKad6", body)
        self.assertIn("kad6::kK6FlagLegacyKad2", body)
        self.assertIn("kad6::kK6FlagNativeKad6", body)
        self.assertIn("if (start.network_mask == 0)", body)

    def test_kad_route_search_and_stop_boundaries_are_explicit(self) -> None:
        route = self.body("CLiveTunnel::ShouldRouteThroughTunnel")
        self.assertIn("CKadV2ModeSelector::Get()", route)
        self.assertIn("sel.Decide(q)", route)
        self.assertIn("CKadV2Mode::Tunneled", route)
        stop = self.body("CLiveTunnel::StopSearchJobKad")
        self.assertIn("for (size_t i = 0; i < job.kadSearchIds.size(); ++i)", stop)
        self.assertIn("CSearchManager::StopSearch(job.kadSearchIds[i], true)", stop)
        self.assertIn("catch (...)", stop)

    def test_planned_modules_do_not_exist_before_atomic_transfer(self) -> None:
        self.assertFalse((ROOT / "srchybrid" / "LiveTunnelPeerState.h").exists())
        self.assertFalse((ROOT / "srchybrid" / "LiveTunnelPeerState.cpp").exists())
        self.assertFalse((ROOT / "srchybrid" / "LiveTunnelKadBridge.h").exists())
        self.assertFalse((ROOT / "srchybrid" / "LiveTunnelKadBridge.cpp").exists())
        project = PROJECT.read_text(encoding="utf-8")
        self.assertNotIn("LiveTunnelPeerState.cpp", project)
        self.assertNotIn("LiveTunnelKadBridge.cpp", project)


if __name__ == "__main__":
    unittest.main(verbosity=2)
