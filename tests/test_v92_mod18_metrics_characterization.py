"""MOD-1.8 pre-extraction observability and immutable-facade characterization."""

from __future__ import annotations

import importlib.util
import json
import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
COORDINATOR = ROOT / "srchybrid" / "LiveTunnel.cpp"
COORDINATOR_METHODS = ROOT / "srchybrid" / "LiveTunnelCoordinatorMethods.inl"
BULK_FACADE = ROOT / "srchybrid" / "LiveTunnelBulkFacade.inl"
INTERFACE = ROOT / "srchybrid" / "LiveTunnel.h"
WEB = ROOT / "srchybrid" / "WebServer.cpp"
PANEL = ROOT / "srchybrid" / "NetworkInfoDlg.cpp"
METRICS = ROOT / "srchybrid" / "LiveTunnelMetrics.cpp"
METRICS_INTERFACE = ROOT / "srchybrid" / "LiveTunnelMetrics.h"
SCHEDULER = ROOT / "srchybrid" / "LiveTunnelScheduler.cpp"
GATEWAY_OWNER = ROOT / "srchybrid" / "Kad6GatewaySocket.cpp"
QUOTA_OWNER = ROOT / "srchybrid" / "LiveTunnelQuotaAuthority.cpp"
RELEASE_GATE = ROOT / "srchybrid" / "LiveTunnelReleaseGate.cpp"
EXIT_NOTICE_OWNER = ROOT / "srchybrid" / "Kad6ExitNoticeServer.cpp"
CONTRACT = ROOT / "docs" / "architecture" / "mod03_ownership_layering_contract_v1.json"
VERIFIER_PATH = ROOT / "tools" / "architecture" / "verify_mod02_characterization.py"

SPEC = importlib.util.spec_from_file_location("mod18_verifier", VERIFIER_PATH)
assert SPEC is not None and SPEC.loader is not None
VERIFIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFIER)


class Mod18MetricsCharacterizationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = "\n".join(
            path.read_text(encoding="utf-8")
            for path in (COORDINATOR, COORDINATOR_METHODS, BULK_FACADE)
        )
        cls.interface = INTERFACE.read_text(encoding="utf-8")
        cls.web = WEB.read_text(encoding="utf-8")
        cls.panel = PANEL.read_text(encoding="utf-8")
        cls.metrics = METRICS.read_text(encoding="utf-8")
        cls.metrics_interface = METRICS_INTERFACE.read_text(encoding="utf-8")
        cls.scheduler = SCHEDULER.read_text(encoding="utf-8")
        cls.gateway_owner = GATEWAY_OWNER.read_text(encoding="utf-8")
        cls.quota_owner = QUOTA_OWNER.read_text(encoding="utf-8")
        cls.release_gate = RELEASE_GATE.read_text(encoding="utf-8")
        cls.exit_notice_owner = EXIT_NOTICE_OWNER.read_text(encoding="utf-8")
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
        wrapper = self.body("CLiveTunnel::GetK6HardeningSnapshot")
        self.assertIn("CKad6OriginSocket::LT3GetHardeningSnapshot", wrapper)
        body = VERIFIER.function_body(
            self.gateway_owner, "CKad6OriginSocket::LT3GetHardeningSnapshot"
        )
        pending = body.index("CSingleLock pl(&host.m_pendingLock, TRUE)")
        registry = body.index("CSingleLock lock(&host.m_lock, TRUE)")
        self.assertLess(pending, registry)
        for marker in (
            "host.m_scheduler.LT2HardeningSnapshot()",
            "host.m_metrics.WindowInfo(",
            "pair.second.state != kad6::K6SourceLeaseState::Closed",
            "host.m_exitServices.LT4PublishCount()",
            "if (pair.second.inbound) ++out.full_streams",
            "out.source_epoch_store_failed = host.m_kadBridge.LT3SourceEpochStoreFailed()",
            "host.m_scheduler.LT2FillEconomySnapshot(",
            "kad6::K6MayRecommendStrictObserved(",
            "if (circuit && circuit->m_traffic_shaping_exposed)",
        ):
            self.assertIn(marker, body)
        # Economy values remain copied under their extracted owner's lock.
        for marker in (
            "std::lock_guard<std::mutex> lock(owner.m_k6EconomyMutex)",
            "std::numeric_limits<double>::infinity()",
            "telemetry->Latest(",
        ):
            self.assertIn(marker, self.quota_owner)
        # A local snapshot must not manufacture external release evidence.
        self.assertIn("kad6::K6StrictReleaseEvidence evidence", body)
        self.assertIn("kad6::K6SupplyInputs supply", body)

    def test_release_snapshot_copies_locked_state_then_validates(self) -> None:
        wrapper = self.body("CLiveTunnel::GetK6ReleaseSnapshot")
        self.assertIn("m_scheduler.GetReleaseSnapshot", wrapper)
        scheduler = VERIFIER.function_body(
            self.scheduler, "LiveTunnelScheduler::GetReleaseSnapshot"
        )
        self.assertIn("M2A_LT1_GetSnapshotBridge", scheduler)
        snapshot = VERIFIER.function_body(
            self.release_gate, "LiveTunnelReleaseGate::Snapshot"
        )
        self.assertIn("std::lock_guard<std::mutex> guard(m_k6ReleaseLock)", snapshot)
        bridge = VERIFIER.function_body(
            self.exit_notice_owner, "M2A_LT1_GetSnapshotBridge"
        )
        copy = bridge.index("const auto state = gate->Snapshot()")
        validation = bridge.index("out.evidence_valid =")
        self.assertLess(copy, validation)
        for marker in (
            "thePrefs.GetKad6PublicExitOptIn()",
            "thePrefs.GetKad6BetaExitOptIn()",
            "thePrefs.IsEseNetLabContributionActive()",
        ):
            self.assertIn(marker, wrapper)
        for marker in (
            "m_k6ReleaseEvidencePresent", "m_k6ReleaseRuntimeHealthy",
            "m_k6PublicStableEnabled", "m_k6PublicBetaEnabled",
            "m_k6ReleaseStatus", "m_k6ReleaseEvidence",
        ):
            self.assertIn(marker, snapshot)
        self.assertIn("kad6::EvaluateK6ReleaseEvidence(", bridge)

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
            "m_metrics.ReplacePeers(std::move(all), tunnelingCount)",
        ):
            self.assertIn(marker, rebuild)
        read = self.body("CLiveTunnel::GetPeersSnapshot")
        self.assertIn("m_metrics.GetPeers(outAll, outTunnelingCount)", read)
        replace = VERIFIER.function_body(
            self.metrics, "LiveTunnelMetrics::ReplacePeers"
        )
        read_copy = VERIFIER.function_body(
            self.metrics, "LiveTunnelMetrics::GetPeers"
        )
        self.assertIn("std::lock_guard<std::mutex> lock(peers_mutex_)", replace)
        self.assertIn("peers_.swap(peers)", replace)
        self.assertIn("std::lock_guard<std::mutex> lock(peers_mutex_)", read_copy)
        self.assertIn("peers = peers_", read_copy)

    def test_scalar_totals_and_rtt_formula_are_frozen(self) -> None:
        for accessor, field in (
            ("CellsSentTotal", "cells_sent"),
            ("CellsRecvTotal", "cells_received"),
            ("BytesSentTotal", "bytes_sent"),
            ("BytesRecvTotal", "bytes_received"),
            ("MeanRttMs", "mean_rtt_ms"),
        ):
            self.assertIn(
                f"{accessor}() const {{ return m_metrics.Totals().{field}; }}",
                self.interface,
            )
        for marker in (
            "m_metrics.RecordCellSent(CELL_TOTAL_BYTES)",
            "m_metrics.RecordCellReceived(CELL_TOTAL_BYTES)",
            "m_metrics.RecordCellSent(size)",
            "m_metrics.RecordCellReceived(size)",
            "m_metrics.ObserveMeanRtt(static_cast<uint32_t>(rtt))",
        ):
            self.assertIn(marker, self.source)
        totals = VERIFIER.function_body(self.metrics, "LiveTunnelMetrics::Totals")
        for field in (
            "cells_sent_", "cells_received_", "bytes_sent_",
            "bytes_received_", "mean_rtt_ms_",
        ):
            self.assertIn(f"{field}.load(std::memory_order_relaxed)", totals)
        rtt = VERIFIER.function_body(
            self.metrics, "LiveTunnelMetrics::ObserveMeanRtt"
        )
        self.assertIn("static_cast<std::uint64_t>(current) * 3u + rtt_ms", rtt)
        self.assertIn("compare_exchange_weak(", rtt)

    def test_exporters_delegate_to_fixed_cardinality_producers(self) -> None:
        prometheus = self.body("CLiveTunnel::GetK6PrometheusMetrics")
        self.assertIn("m_metrics.ExportPrometheus(", prometheus)
        export = VERIFIER.function_body(
            self.metrics, "LiveTunnelMetrics::ExportPrometheus"
        )
        self.assertIn("k6_metrics_.ExportPrometheus(now_seconds)", export)
        notice = self.body("CLiveTunnel::GetK6ExitNoticeSnapshot")
        self.assertIn("m_scheduler.GetReleaseNoticeSnapshot()", notice)
        scheduler_notice = VERIFIER.function_body(
            self.scheduler, "LiveTunnelScheduler::GetReleaseNoticeSnapshot"
        )
        self.assertIn("M2A_LT1_NoticeSnapshotBridge", scheduler_notice)
        notice_owner = VERIFIER.function_body(
            self.exit_notice_owner, "M2A_LT1_NoticeSnapshotBridge"
        )
        self.assertIn("NoticeSnapshot()", notice_owner)

    def test_extracted_owner_is_portable_and_coordinator_independent(self) -> None:
        self.assertNotIn('#include "LiveTunnel.h"', self.metrics_interface)
        self.assertNotIn('#include "LiveTunnel.h"', self.metrics)
        self.assertIn("std::atomic<std::uint64_t> cells_sent_", self.metrics_interface)
        self.assertIn("mutable std::mutex peers_mutex_", self.metrics_interface)
        self.assertIn("kad6::K6Metrics k6_metrics_", self.metrics_interface)
        self.assertIn("LiveTunnelMetrics m_metrics", self.interface)
        for old_owner in (
            "m_k6Metrics", "m_cellsSentTotal", "m_cellsRecvTotal",
            "m_bytesSentTotal", "m_bytesRecvTotal", "m_meanRttMs",
            "m_peersCacheLock", "m_peersCacheAll",
            "m_peersCacheTunnelingCount",
        ):
            self.assertNotIn(old_owner, self.interface)

    def test_web_and_panel_consume_only_value_snapshots(self) -> None:
        for marker in (
            "GetCircuitsSnapshot(",
            "GetPeersSnapshot(",
            "GetK6ReleaseSnapshot(",
            "GetK6HardeningSnapshot(",
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
