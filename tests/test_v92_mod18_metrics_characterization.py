"""MOD-1.8 pre-extraction observability and immutable-facade characterization."""

from __future__ import annotations

import importlib.util
import json
import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
COORDINATOR = ROOT / "srchybrid" / "LiveTunnel.cpp"
INTERFACE = ROOT / "srchybrid" / "LiveTunnel.h"
WEB = ROOT / "srchybrid" / "WebServer.cpp"
PANEL = ROOT / "srchybrid" / "NetworkInfoDlg.cpp"
CONTRACT = ROOT / "docs" / "architecture" / "mod03_ownership_layering_contract_v1.json"
VERIFIER_PATH = ROOT / "tools" / "architecture" / "verify_mod02_characterization.py"

SPEC = importlib.util.spec_from_file_location("mod18_verifier", VERIFIER_PATH)
assert SPEC is not None and SPEC.loader is not None
VERIFIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFIER)


class Mod18MetricsCharacterizationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = COORDINATOR.read_text(encoding="utf-8")
        cls.interface = INTERFACE.read_text(encoding="utf-8")
        cls.web = WEB.read_text(encoding="utf-8")
        cls.panel = PANEL.read_text(encoding="utf-8")
        cls.contract = json.loads(CONTRACT.read_text(encoding="utf-8"))

    def body(self, symbol: str) -> str:
        return VERIFIER.function_body(self.source, symbol)

    def test_circuit_snapshot_is_a_complete_copy_under_registry_lock(self) -> None:
        body = self.body("CLiveTunnel::GetCircuitsSnapshot")
        self.assertIn("CSingleLock lock(&m_lock, TRUE)", body)
        self.assertIn("out.clear()", body)
        self.assertIn("out.reserve(m_circuitRegistry.Size())", body)
        self.assertIn("DWORD now = GetTickCount()", body)
        for field in (
            "circ_id", "role", "state", "age_ms", "hop_count",
            "next_hop_set", "next_circ_id", "auth_ok", "strict3",
            "shaped", "shaping_exposed", "abort_reason",
        ):
            self.assertIn(f"s.{field}", body)
        self.assertIn("out.push_back(s)", body)

    def test_hardening_snapshot_preserves_lock_domains_and_privacy(self) -> None:
        body = self.body("CLiveTunnel::GetK6HardeningSnapshot")
        pending = body.index("CSingleLock pl(&m_pendingLock, TRUE)")
        registry = body.index("CSingleLock lock(&m_lock, TRUE)")
        self.assertLess(pending, registry)
        for marker in (
            "m_k6Hardening.Snapshot()",
            "m_k6Metrics.WindowInfo(",
            "pair.second.state != kad6::K6SourceLeaseState::Closed",
            "m_k6Publishes.size()",
            "if (pair.second.inbound) ++out.full_streams",
            "out.source_epoch_store_failed = m_k6SourceEpochsLoadFailed",
            "out.economy_measurement_ready = m_k6EconomyReady",
            "numeric_limits<double>::infinity()",
            "m_k6EconomyTelemetry.Latest(",
            "kad6::K6MayRecommendStrictObserved(",
            "if (circuit && circuit->m_traffic_shaping_exposed)",
        ):
            self.assertIn(marker, body)
        # A local snapshot must not manufacture external release evidence.
        self.assertIn("kad6::K6StrictReleaseEvidence evidence", body)
        self.assertIn("kad6::K6SupplyInputs supply", body)

    def test_release_snapshot_copies_locked_state_then_validates(self) -> None:
        body = self.body("CLiveTunnel::GetK6ReleaseSnapshot")
        lock = body.index("CSingleLock release(&m_k6ReleaseLock, TRUE)")
        validation = body.index("out.evidence_valid =")
        self.assertLess(lock, validation)
        for marker in (
            "thePrefs.GetKad6PublicExitOptIn()",
            "thePrefs.GetKad6BetaExitOptIn()",
            "m_k6ReleaseEvidencePresent",
            "m_k6ReleaseRuntimeHealthy",
            "m_k6PublicStableEnabled",
            "m_k6PublicBetaEnabled",
            "m_k6ReleaseStatus",
            "m_k6ReleaseEvidence",
            "kad6::EvaluateK6ReleaseEvidence(",
        ):
            self.assertIn(marker, body)

    def test_peer_snapshot_cache_never_lends_client_pointers(self) -> None:
        rebuild = self.body("CLiveTunnel::RebuildPeersCache")
        for marker in (
            "GetConnectedSnapshot(snapAll, 50, /*tunnelOnly=*/false)",
            "GetConnectedSnapshot(snapTun, 50, /*tunnelOnly=*/true)",
            "p.ip        = c->GetIP()",
            "p.port      = c->GetUserPort()",
            "p.fork_caps = c->GetForkCaps()",
            "p.ese_caps  = c->GetEseCapabilities()",
            "p.has_ipv4  = !c->IsIPv6OnlyEndpoint()",
            "p.address = c->GetIPv6Address().ToString()",
            "CAddress::FromIPv4NetworkOrder(c->GetIP()).ToString()",
            "CSingleLock lk(&m_peersCacheLock, TRUE)",
            "m_peersCacheAll.swap(all)",
        ):
            self.assertIn(marker, rebuild)
        read = self.body("CLiveTunnel::GetPeersSnapshot")
        self.assertIn("CSingleLock lk(&m_peersCacheLock, TRUE)", read)
        self.assertIn("outAll            = m_peersCacheAll", read)
        self.assertIn(
            "outTunnelingCount = m_peersCacheTunnelingCount", read
        )

    def test_scalar_totals_and_rtt_formula_are_frozen(self) -> None:
        for accessor, field in (
            ("CellsSentTotal", "m_cellsSentTotal"),
            ("CellsRecvTotal", "m_cellsRecvTotal"),
            ("BytesSentTotal", "m_bytesSentTotal"),
            ("BytesRecvTotal", "m_bytesRecvTotal"),
            ("MeanRttMs", "m_meanRttMs"),
        ):
            self.assertIn(
                f"{accessor}() const {{ return {field}; }}", self.interface
            )
        for marker in (
            "++m_cellsSentTotal",
            "m_bytesSentTotal += CELL_TOTAL_BYTES",
            "++m_cellsRecvTotal",
            "m_bytesRecvTotal += CELL_TOTAL_BYTES",
            "m_bytesSentTotal += size",
            "m_bytesRecvTotal += size",
            "(m_meanRttMs * 3 + rtt) / 4",
        ):
            self.assertIn(marker, self.source)

    def test_exporters_delegate_to_fixed_cardinality_producers(self) -> None:
        prometheus = self.body("CLiveTunnel::GetK6PrometheusMetrics")
        self.assertIn("m_k6Metrics.ExportPrometheus(", prometheus)
        notice = self.body("CLiveTunnel::GetK6ExitNoticeSnapshot")
        self.assertIn("m_k6ExitNoticeServer.Snapshot()", notice)

    def test_web_and_panel_consume_only_value_snapshots(self) -> None:
        for marker in (
            "GetCircuitsSnapshot(snap)",
            "GetPeersSnapshot(all, tunnelingCount)",
            "GetK6ReleaseSnapshot(release)",
            "GetK6HardeningSnapshot(snap)",
            "GetK6ExitNoticeSnapshot()",
            "GetK6PrometheusMetrics()",
            "CellsSentTotal()",
            "BytesRecvTotal()",
        ):
            self.assertIn(marker, self.web)
        for marker in (
            "GetCircuitsSnapshot(snapshots)",
            "CellsSentTotal()",
            "CellsRecvTotal()",
            "BytesSentTotal()",
            "BytesRecvTotal()",
            "MeanRttMs()",
        ):
            self.assertIn(marker, self.panel)

    def test_planned_module_has_exact_owner_layer_and_responsibility(self) -> None:
        live_tunnel = next(
            item for item in self.contract["coordinators"]
            if item["name"] == "LiveTunnel"
        )
        module = next(
            item for item in live_tunnel["planned_modules"]
            if item["module"] == "LiveTunnelMetrics"
        )
        self.assertEqual(module["owner_before"], "CLiveTunnel")
        self.assertEqual(module["owner_after"], "LiveTunnelMetrics")
        self.assertEqual(module["layer"], "application")
        self.assertEqual(
            module["responsibility"], "immutable snapshots and counters"
        )


if __name__ == "__main__":
    unittest.main()
