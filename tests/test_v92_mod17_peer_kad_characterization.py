"""MOD-1.7 pre-extraction peer-state and Kad-boundary characterization."""

from __future__ import annotations

import importlib.util
import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
COORDINATOR = ROOT / "srchybrid" / "LiveTunnel.cpp"
INTERFACE = ROOT / "srchybrid" / "LiveTunnel.h"
PROJECT = ROOT / "srchybrid" / "emule.vcxproj"
PEER_STATE = ROOT / "srchybrid" / "LiveTunnelPeerState.cpp"
PEER_INTERFACE = ROOT / "srchybrid" / "LiveTunnelPeerState.h"
KAD_BRIDGE = ROOT / "srchybrid" / "LiveTunnelKadBridge.cpp"
KAD_INTERFACE = ROOT / "srchybrid" / "LiveTunnelKadBridge.h"
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
        cls.peer_state = PEER_STATE.read_text(encoding="utf-8")
        cls.peer_interface = PEER_INTERFACE.read_text(encoding="utf-8")
        cls.kad_bridge = KAD_BRIDGE.read_text(encoding="utf-8")
        cls.kad_interface = KAD_INTERFACE.read_text(encoding="utf-8")

    def body(self, symbol: str) -> str:
        return VERIFIER.function_body(self.source, symbol)

    def test_kad2_source_score_formula_is_frozen(self) -> None:
        body = self.body("CLiveTunnel::OnKad6GatewaySourceResult")
        self.assertIn("candidate.score = 100 + (ipv6OrNull != NULL ? 10 : 0)", body)
        self.assertIn("(reachCaps & 0x0001u) != 0 ? 5 : 0", body)
        self.assertIn("m_peerState.ApplySourceScore(", body)
        score = VERIFIER.function_body(
            self.peer_state, "LiveTunnelPeerState::ApplySourceScore"
        )
        self.assertIn("100, history->second.successes * 20u", score)
        self.assertIn("80, history->second.failures * 10u", score)
        self.assertIn(
            "return rewarded > penalty ? rewarded - penalty : 0", score
        )

    def test_kad6_source_score_formula_and_duplicate_replacement_are_frozen(self) -> None:
        body = self.body("CLiveTunnel::OnKad6NativeSourceRecord")
        self.assertIn("candidate.score = 200u + static_cast<uint32_t>(remaining / 3600u)", body)
        self.assertIn("m_peerState.ApplySourceScore(", body)
        self.assertIn("if (candidate.score > old.score) old = candidate", body)
        self.assertIn("job->second.maxResults * 2u", body)
        self.assertIn("job->second.maxResults + 8u", body)

    def test_score_history_is_network_scoped_saturating_and_bounded(self) -> None:
        for signature in (
            "ApplySourceScore(\n        std::uint32_t base_score,\n"
            "        const LiveSourceEndpointKey& endpoint) const noexcept",
            "RecordSourceResult(const LiveSourceEndpointKey& endpoint, bool success,\n"
            "                            std::uint64_t now_seconds) noexcept",
            "RecordSourceFailure(const LiveSourceEndpointKey& endpoint,\n"
            "                             std::uint64_t now_seconds) noexcept",
        ):
            self.assertNotIn(signature, self.peer_interface)
        key = VERIFIER.function_body(
            self.peer_state, "LiveTunnelPeerState::SourceScoreKey"
        )
        self.assertIn(
            "key.push_back(static_cast<char>(endpoint.network_origin))", key
        )
        connect = self.body("CLiveTunnel::OnK6ExitSocketConnect")
        self.assertIn("m_peerState.RecordSourceResult(", connect)
        record = VERIFIER.function_body(
            self.peer_state, "LiveTunnelPeerState::RecordSourceResult"
        )
        self.assertIn("numeric_limits<std::uint32_t>::max", record)
        sweep = self.body("CLiveTunnel::SweepK6Gateway")
        self.assertIn("m_peerState.SweepSourceHistory(nowSeconds)", sweep)
        self.assertIn("24ull * 60 * 60", self.peer_interface)
        self.assertIn("kMaximumSourceHistories = 4096", self.peer_interface)

    def test_source_result_order_is_stable_descending_score(self) -> None:
        body = self.body("CLiveTunnel::SendK6SearchResults")
        self.assertIn("LiveTunnelPeerState::RankSources", body)
        self.assertIn("ranked.size(), (size_t)job.maxResults", body)
        rank = VERIFIER.function_body(
            self.peer_state, "LiveTunnelPeerState::RankSources"
        )
        self.assertIn("std::stable_sort", rank)
        self.assertIn("score_at(left) > score_at(right)", rank)

    def test_origin_circuit_selection_is_fail_closed(self) -> None:
        body = self.body("CLiveTunnel::K6SelectOriginCircuit")
        self.assertIn("LiveOriginCircuitCandidate candidate", body)
        self.assertIn("LiveTunnelPeerState::SelectOriginCircuit(", body)
        policy = VERIFIER.function_body(
            self.peer_state, "LiveTunnelPeerState::SelectOriginCircuit"
        )
        for marker in (
            "!circuit.originator", "circuit.quota_issuer", "!circuit.active",
            "circuit.hop_count < minimum_hops", "!circuit.multicell",
            "!circuit.authenticated",
            "(circuit.exit_signed_caps & required_caps) != required_caps",
        ):
            self.assertIn(marker, policy)
        self.assertIn("return 0", policy)

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
            "LiveTunnelPeerState::PlanDisconnect",
            "CELL_DESTROY",
            "TransitionCircuitDestroyed",
        ):
            self.assertIn(marker, body)

    def test_kad_network_mask_and_wire_flags_remain_independent(self) -> None:
        body = self.body("CLiveTunnel::StartK6SourceLookup")
        self.assertIn("m_kadBridge.SelectedNetworkMask(", body)
        self.assertIn("LiveTunnelKadBridge::BuildSearchFlags(", body)
        self.assertIn("if (start.network_mask == 0)", body)
        mask = VERIFIER.function_body(
            self.kad_bridge, "LiveTunnelKadBridge::BuildNetworkMask"
        )
        self.assertIn("if (kad2_selected)", mask)
        self.assertIn("if (kad6_selected)", mask)

    def test_kad_route_search_and_stop_boundaries_are_explicit(self) -> None:
        route = self.body("CLiveTunnel::ShouldRouteThroughTunnel")
        self.assertIn("m_kadBridge.ShouldRouteThroughTunnel", route)
        self.assertIn("ports.should_route", self.source)
        self.assertIn("CKadV2ModeSelector::Get().Decide(query)", self.source)
        stop = self.body("CLiveTunnel::StopSearchJobKad")
        self.assertIn("m_kadBridge.StopSearches(job.kadSearchIds)", stop)
        stop_bridge = VERIFIER.function_body(
            self.kad_bridge, "LiveTunnelKadBridge::StopSearches"
        )
        self.assertIn("for (std::uint32_t search_id : search_ids)", stop_bridge)
        self.assertIn("catch (...)", stop_bridge)

    def test_modules_are_project_owned_and_coordinator_independent(self) -> None:
        for path in (PEER_STATE, PEER_INTERFACE, KAD_BRIDGE, KAD_INTERFACE):
            self.assertTrue(path.exists())
        project = PROJECT.read_text(encoding="utf-8")
        for marker in (
            'ClCompile Include="LiveTunnelPeerState.cpp"',
            'ClInclude Include="LiveTunnelPeerState.h"',
            'ClCompile Include="LiveTunnelKadBridge.cpp"',
            'ClInclude Include="LiveTunnelKadBridge.h"',
        ):
            self.assertIn(marker, project)
        modules = (
            self.peer_state + self.peer_interface +
            self.kad_bridge + self.kad_interface
        )
        self.assertGreaterEqual(len(modules.splitlines()), 300)
        self.assertLessEqual(len(modules.splitlines()), 900)
        self.assertNotIn('#include "LiveTunnel.h"', modules)
        self.assertNotIn("m_k6SourceScores", self.interface)
        self.assertNotIn("struct K6SourceScore", self.interface)
        self.assertIn(
            "RunLiveTunnelPeerStateCharacterizationSelfTest()",
            self.body("CLiveTunnel::RunCharacterizationSelfTest"),
        )
        self.assertIn(
            "RunLiveTunnelKadBridgeCharacterizationSelfTest()",
            self.body("CLiveTunnel::RunCharacterizationSelfTest"),
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
