"""MOD-0.2 gate: all MOD-0.1 seams have an honest characterization plan."""

from __future__ import annotations

import json
import hashlib
import importlib.util
import pathlib
import re
import subprocess
import sys
import unittest
from collections import Counter


ROOT = pathlib.Path(__file__).resolve().parents[1]
MATRIX = ROOT / "docs" / "architecture" / "mod02_characterization_matrix_v1.json"
INVENTORY = ROOT / "docs" / "architecture" / "mod01_architecture_inventory_v1.json"
GOLDENS = ROOT / "docs" / "architecture" / "mod02_characterization_goldens_v1.json"
SCRIPT = ROOT / "tools" / "architecture" / "verify_mod02_characterization.py"
RUNTIME_RUNNER = ROOT / "tools" / "architecture" / "run_mod02_stream_selftest.ps1"
BUILD_MANIFEST = ROOT / "docs" / "architecture" / "mod02_build_manifest_v1.json"
IDENTITY_HEADER = ROOT / "srchybrid" / "Mod02BuildIdentity.h"
CRITICAL_SOURCE_PATHS = [
    "srchybrid/EmuleDlg.cpp", "srchybrid/EmuleDlg.h",
    "srchybrid/LiveTunnel.cpp", "srchybrid/LiveTunnel.h",
    "srchybrid/LiveCellQueue.cpp", "srchybrid/LiveCellQueue.h",
    "srchybrid/LiveTunnelFraming.cpp", "srchybrid/LiveTunnelFraming.h",
    "srchybrid/LiveHandshakeWire.cpp", "srchybrid/LiveHandshakeWire.h",
    "srchybrid/LiveRelayDispatcher.cpp", "srchybrid/LiveRelayDispatcher.h",
    "srchybrid/LiveExitServices.cpp", "srchybrid/LiveExitServices.h",
    "srchybrid/LiveRelayTypes.h",
    "srchybrid/LiveTunnelScheduler.cpp", "srchybrid/LiveTunnelScheduler.h",
    "srchybrid/LiveTunnelPeerState.cpp", "srchybrid/LiveTunnelPeerState.h",
    "srchybrid/LiveTunnelKadBridge.cpp", "srchybrid/LiveTunnelKadBridge.h",
    "srchybrid/LiveTunnelMetrics.cpp", "srchybrid/LiveTunnelMetrics.h",
    "srchybrid/LiveTunnelPending.cpp", "srchybrid/LiveTunnelPending.h",
    "srchybrid/LiveCircuitRegistry.cpp", "srchybrid/LiveCircuitRegistry.h",
    "srchybrid/LiveCircuitHandshake.cpp", "srchybrid/LiveCircuitHandshake.h",
    "srchybrid/LiveCircuit.cpp", "srchybrid/LiveCircuit.h",
    "srchybrid/WebServer.cpp", "srchybrid/WebServer.h",
    "srchybrid/WebSocket.cpp", "srchybrid/WebSocket.h",
    "srchybrid/WebRequestParser.cpp", "srchybrid/WebRequestParser.h",
    "srchybrid/WebAuthPolicy.cpp", "srchybrid/WebAuthPolicy.h",
    "srchybrid/WebRouteTable.cpp", "srchybrid/WebRouteTable.h",
    "srchybrid/WebRequestDispatch.cpp", "srchybrid/WebRequestDispatch.h",
    "srchybrid/WebTemplateRenderer.cpp", "srchybrid/WebTemplateRenderer.h", "srchybrid/WebHeaderFooter.cpp", "srchybrid/WebHeaderFooter.h",
    "srchybrid/WebServerListController.cpp", "srchybrid/WebServerListController.h",
    "srchybrid/WebTransferProjection.cpp", "srchybrid/WebTransferProjection.h",
    "srchybrid/WebApiSerializer.cpp", "srchybrid/WebApiSerializer.h",
    "srchybrid/WebTransferController.cpp", "srchybrid/WebTransferController.h",
    "srchybrid/WebTransferActions.cpp", "srchybrid/WebTransferActions.h",
    "srchybrid/WebSearchController.cpp", "srchybrid/WebSearchController.h",
    "srchybrid/WebSharedController.cpp", "srchybrid/WebSharedController.h",
    "srchybrid/WebStaticAssets.cpp", "srchybrid/WebStaticAssets.h",
    "srchybrid/WebSocketResponse.cpp", "srchybrid/WebSocketResponse.h",
    "srchybrid/WebDiagnostics.cpp", "srchybrid/WebDiagnostics.h",
    "srchybrid/eMule.tmpl",
    "srchybrid/ListenSocket.cpp",
    "srchybrid/LiveProtocol.h",
    "srchybrid/LivePackets.cpp", "srchybrid/LivePackets.h",
    "srchybrid/LiveStreamManager.cpp", "srchybrid/LiveStreamManager.h",
    "srchybrid/LiveBroadcastSession.cpp", "srchybrid/LiveBroadcastSession.h",
    "srchybrid/LiveViewerSession.cpp", "srchybrid/LiveViewerSession.h",
    "srchybrid/LivePeerSet.cpp", "srchybrid/LivePeerSet.h",
    "srchybrid/LiveChunkWindow.cpp", "srchybrid/LiveChunkWindow.h",
    "srchybrid/LiveStreamSecurity.cpp", "srchybrid/LiveStreamSecurity.h",
    "srchybrid/LiveStreamFanout.cpp", "srchybrid/LiveStreamFanout.h",
    "srchybrid/LiveFanoutTransportAdapter.cpp", "srchybrid/LiveFanoutTransportAdapter.h",
    "srchybrid/LiveStreamRecovery.cpp", "srchybrid/LiveStreamRecovery.h",
    "srchybrid/LiveRecoveryTransportAdapter.cpp", "srchybrid/LiveRecoveryTransportAdapter.h",
    "srchybrid/LiveStreamAnnouncer.cpp", "srchybrid/LiveStreamAnnouncer.h",
    "srchybrid/LiveAnnounceTransportAdapter.cpp", "srchybrid/LiveAnnounceTransportAdapter.h",
    "srchybrid/LiveStreamSnapshot.cpp", "srchybrid/LiveStreamSnapshot.h",
    "srchybrid/LiveStreamTrustAdapter.cpp", "srchybrid/LiveStreamTrustAdapter.h",
    "srchybrid/ClientList.cpp", "srchybrid/ClientList.h",
    "srchybrid/LiveMeshManager.cpp", "srchybrid/LiveMeshManager.h",
    "srchybrid/LiveBuddyRelay.cpp", "srchybrid/LiveBuddyRelay.h",
    "srchybrid/LiveStreamDlgUI.cpp", "srchybrid/LiveStreamDlg.h",
]

SPEC = importlib.util.spec_from_file_location("mod02_verifier", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
VERIFIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFIER)
# Keep the evidence test bound to the verifier's complete, versioned source
# set instead of maintaining a second list that can silently go stale.
CRITICAL_SOURCE_PATHS = VERIFIER.CRITICAL_SOURCE_PATHS


class Mod02CharacterizationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.matrix = json.loads(MATRIX.read_text(encoding="utf-8"))
        cls.inventory = json.loads(INVENTORY.read_text(encoding="utf-8"))
        cls.goldens = json.loads(GOLDENS.read_text(encoding="utf-8"))

    def test_all_nine_existing_seams_are_classified_once(self) -> None:
        rows = self.matrix["rows"]
        self.assertEqual(len(rows), 9)
        self.assertEqual([row["id"] for row in rows], [
            "LT-01", "LT-02", "LT-03", "LT-04", "WS-01", "WS-02", "WS-03", "WS-04", "LS-01",
        ])
        self.assertEqual({row["coordinator"] for row in rows}, {"CLiveTunnel", "CWebServer", "CLiveStreamManager"})
        expected = Counter(
            (record["owner"], seam["file"])
            for record in self.inventory["monoliths"]
            for seam in record["existing_test_seams"]
        )
        actual = Counter((row["coordinator"], row["seam"]) for row in rows)
        self.assertEqual(actual, expected)
        self.assertTrue(all(count == 1 for count in actual.values()))
        for row in rows:
            self.assertIn(row["classification"], {"source_scan_only", "algorithm_replica; not production execution", "gap_replaced_by_production_boundary", "mixed_source_scan_and_real_node_edge"})
            self.assertTrue(row["input"] and row["observable"] and row["golden"] and row["runner"] and row["dependency"] and row["gap"])
            self.assertNotEqual(row["runner"], "simple_regex")
            self.assertNotEqual(row["execution_kind"], "algorithm_replica")
            self.assertIn(row["golden"], self.goldens["goldens"])

    def test_runtime_golden_is_source_bound_and_bounded(self) -> None:
        gate = self.matrix["runtime_gate"]
        self.assertEqual(gate["runner"], "tools/architecture/run_mod02_stream_selftest.ps1")
        self.assertEqual(gate["build_manifest"], "docs/architecture/mod02_build_manifest_v1.json")
        self.assertEqual(gate["status"], "PASS")
        evidence = gate["evidence"]
        summary_path = ROOT / gate["summary"]
        summary_bytes = summary_path.read_bytes()
        self.assertFalse(summary_bytes.startswith(b"\xef\xbb\xbf"))
        self.assertNotIn(b"\r", summary_bytes)
        self.assertTrue(summary_bytes.endswith(b"\n"))
        self.assertEqual(
            hashlib.sha256(summary_bytes).hexdigest(),
            evidence["summary_sha256"],
        )
        summary = json.loads(summary_bytes.decode("utf-8"))
        for field in (
            "source_commit", "source_identity_sha256", "executable_sha256",
            "build_manifest_sha256", "marker_sha256", "timeout_seconds",
            "timed_out", "termination_confirmed", "exit_code",
            "source_tree_clean", "markers_verified",
        ):
            self.assertEqual(summary[field], evidence[field], field)
        self.assertEqual(summary["verdict"], gate["status"])
        self.assertEqual(evidence["exit_code"], 0)
        self.assertTrue(evidence["source_tree_clean"])
        self.assertTrue(evidence["termination_confirmed"])
        self.assertTrue(evidence["markers_verified"])
        self.assertFalse(evidence["timed_out"])
        for field in (
            "source_identity_sha256", "executable_sha256",
            "build_manifest_sha256", "summary_sha256", "marker_sha256",
        ):
            self.assertRegex(evidence[field], r"^[0-9a-f]{64}$")
        runner = RUNTIME_RUNNER.read_text(encoding="utf-8")
        for required in ("BuildManifest", "source_identity_sha256", "Get-NormalizedTextSha256", "Get-Mod02SourceIdentity", "Mod02BuildIdentity.h", "ReadAllBytes", "normalizedBytes", "merge-base --is-ancestor", "diff --name-only", "Critical sources changed after manifest commit", "taskkill.exe", "WaitForExit(10000)", "WaitForExit(5000)", "SOURCE $sourceIdentity", "source_tree_clean", "WriteAllText", "UTF8Encoding"):
            self.assertIn(required, runner)
        self.assertNotIn("$actualCommit -ne $manifest.source_commit", runner)
        self.assertNotIn("ExpectedSourceCommit", runner)
        self.assertNotIn("ExpectedExecutableSha256", runner)
        manifest = json.loads(BUILD_MANIFEST.read_text(encoding="utf-8"))
        self.assertEqual(set(manifest), {
            "schema", "source_commit", "source_identity_sha256", "executable_sha256",
        })
        self.assertEqual(manifest["schema"], "ese.mod02.build-manifest/v1")
        self.assertRegex(evidence["source_commit"], r"^[0-9a-f]{40}$")
        evidence_descends_from_manifest = subprocess.run(
            [
                "git", "merge-base", "--is-ancestor",
                manifest["source_commit"], evidence["source_commit"],
            ],
            cwd=ROOT, text=True, capture_output=True, check=False,
        )
        self.assertEqual(
            evidence_descends_from_manifest.returncode, 0,
            "Runtime evidence commit must descend from the build manifest commit.",
        )
        evidence_drift = subprocess.run(
            [
                "git", "diff", "--name-only",
                manifest["source_commit"], evidence["source_commit"], "--",
                *CRITICAL_SOURCE_PATHS, "srchybrid/Mod02BuildIdentity.h",
            ],
            cwd=ROOT, text=True, capture_output=True, check=False,
        )
        self.assertEqual(evidence_drift.returncode, 0, evidence_drift.stderr)
        self.assertEqual(evidence_drift.stdout.strip(), "")
        self.assertEqual(
            evidence["source_identity_sha256"], manifest["source_identity_sha256"])
        self.assertEqual(
            evidence["executable_sha256"], manifest["executable_sha256"])
        self.assertEqual(
            evidence["build_manifest_sha256"],
            hashlib.sha256(
                VERIFIER.normalize_source_bytes(BUILD_MANIFEST.read_bytes())
            ).hexdigest(),
        )
        lines = [
            f"{path}={hashlib.sha256(VERIFIER.normalize_source_bytes((ROOT / path).read_bytes())).hexdigest()}"
            for path in CRITICAL_SOURCE_PATHS
        ]
        current_identity = hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()
        self.assertEqual(manifest["source_identity_sha256"], current_identity)
        header = IDENTITY_HEADER.read_text(encoding="utf-8")
        header_identity = re.search(
            r'ESE_MOD02_CRITICAL_SOURCE_SHA256\s+"([0-9a-f]{64})"', header)
        self.assertIsNotNone(header_identity)
        self.assertEqual(header_identity.group(1), current_identity)

    def test_runtime_manifest_commit_is_ancestor_without_critical_drift(self) -> None:
        manifest = json.loads(BUILD_MANIFEST.read_text(encoding="utf-8"))
        source_commit = manifest["source_commit"]
        self.assertRegex(source_commit, r"^[0-9a-f]{40}$")
        ancestor = subprocess.run(
            ["git", "merge-base", "--is-ancestor", source_commit, "HEAD"],
            cwd=ROOT, text=True, capture_output=True, check=False,
        )
        self.assertEqual(
            ancestor.returncode, 0,
            f"Manifest commit {source_commit} is not an ancestor of HEAD.",
        )
        drift = subprocess.run(
            [
                "git", "diff", "--name-only", source_commit, "HEAD", "--",
                *CRITICAL_SOURCE_PATHS, "srchybrid/Mod02BuildIdentity.h",
            ],
            cwd=ROOT, text=True, capture_output=True, check=False,
        )
        self.assertEqual(drift.returncode, 0, drift.stderr)
        self.assertEqual(
            drift.stdout.strip(), "",
            f"Critical sources changed after manifest commit:\n{drift.stdout}",
        )

    def test_source_identity_is_line_ending_invariant(self) -> None:
        lf = b"alpha\nbeta\ngamma\n"
        crlf = b"alpha\r\nbeta\r\ngamma\r\n"
        cr = b"alpha\rbeta\rgamma\r"
        self.assertEqual(
            VERIFIER.normalize_source_bytes(lf),
            VERIFIER.normalize_source_bytes(crlf),
        )
        self.assertEqual(
            VERIFIER.normalize_source_bytes(lf),
            VERIFIER.normalize_source_bytes(cr),
        )

    def test_verifier_and_runtime_critical_sources_are_exactly_paired(self) -> None:
        runner_paths = VERIFIER.runtime_runner_critical_source_paths()
        VERIFIER.validate_critical_source_contract(
            VERIFIER.CRITICAL_SOURCE_PATHS, runner_paths
        )
        self.assertEqual(len(runner_paths), 157)
        self.assertEqual(
            runner_paths[:13], VERIFIER.EXPECTED_CRITICAL_SOURCE_PREFIX
        )
        self.assertEqual(
            len({path.casefold() for path in runner_paths}), len(runner_paths)
        )

    def test_critical_source_contract_rejects_add_remove_reorder_and_casefold(self) -> None:
        paths = list(VERIFIER.CRITICAL_SOURCE_PATHS)
        with self.assertRaisesRegex(ValueError, "count drift"):
            VERIFIER.validate_critical_source_contract(paths + ["extra.cpp"], paths)
        with self.assertRaisesRegex(ValueError, "count drift"):
            VERIFIER.validate_critical_source_contract(paths[:-1], paths[:-1])
        reordered = list(paths)
        reordered[2], reordered[3] = reordered[3], reordered[2]
        with self.assertRaisesRegex(ValueError, "prefix/order drift"):
            VERIFIER.validate_critical_source_contract(reordered, reordered)
        duplicate = list(paths)
        duplicate[-1] = paths[0].upper()
        with self.assertRaisesRegex(ValueError, "casefold duplicate"):
            VERIFIER.validate_critical_source_contract(duplicate, duplicate)
        runner_reordered = list(paths)
        runner_reordered[-1], runner_reordered[-2] = (
            runner_reordered[-2], runner_reordered[-1]
        )
        with self.assertRaisesRegex(ValueError, "parity drift"):
            VERIFIER.validate_critical_source_contract(paths, runner_reordered)

    def test_critical_source_lf_identity_is_independently_recomputed_and_pinned(self) -> None:
        paths = VERIFIER.runtime_runner_critical_source_paths()
        lines = []
        for path in paths:
            raw = (ROOT / path).read_bytes()
            normalized = raw.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
            lines.append(f"{path}={hashlib.sha256(normalized).hexdigest()}")
        identity = hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()
        self.assertEqual(
            identity,
            "036c7d8ac161431b5ddf1133cefd2a09b793fd6471cc1cc76088976e0a68a9e5",
        )
        header = IDENTITY_HEADER.read_text(encoding="utf-8")
        self.assertIn(identity, header)

    def test_runtime_runner_parses_in_windows_powershell(self) -> None:
        runner_path = str(RUNTIME_RUNNER).replace("'", "''")
        command = (
            "$errors=$null; $tokens=$null; "
            "[void][System.Management.Automation.Language.Parser]::ParseFile("
            f"'{runner_path}',[ref]$tokens,[ref]$errors); "
            "if ($errors.Count) { $errors | Out-String | Write-Error; exit 1 }"
        )
        completed = subprocess.run(
            ["powershell.exe", "-NoProfile", "-Command", command],
            cwd=ROOT, text=True, capture_output=True, check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)

    def test_goldens_cover_required_domains_and_use_production_files(self) -> None:
        expected = {
            "live_circuit_handshake", "live_circuit_registry",
            "live_relay_dispatcher", "live_exit_services",
            "live_tunnel_framing", "live_tunnel_pending",
            "live_tunnel_dispatch", "web_parser_security", "web_request_dispatch",
            "web_serialization", "web_live_dispatch", "live_stream_session_chunk_callback",
        }
        self.assertEqual(set(self.goldens["goldens"]), expected)
        for spec in self.goldens["goldens"].values():
            self.assertTrue((ROOT / spec["production_file"]).is_file())
            self.assertTrue(spec["symbols"])
            self.assertTrue(spec["token_sha256"])
        self.assertIn(
            "CompressWebGzip",
            self.goldens["goldens"]["web_request_dispatch"]["symbols"],
        )

    def test_production_characterization_and_negative_fixture_detect_drift(self) -> None:
        for mode in ("--verify", "--negative-fixture"):
            completed = subprocess.run([sys.executable, str(SCRIPT), mode], cwd=ROOT, text=True, capture_output=True)
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
