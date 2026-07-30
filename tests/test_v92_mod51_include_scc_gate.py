"""MOD-5.1 locks a reproducible, cycle-free include graph for MOD-1..MOD-3."""

from __future__ import annotations

import copy
import importlib.util
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools" / "architecture"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))
SCRIPT = TOOLS / "verify_mod51_include_scc_gate.py"
CONTRACT_PATH = ROOT / "docs" / "architecture" / "mod51_include_scc_contract_v1.json"
MOD04_PATH = ROOT / "docs" / "architecture" / "mod04_architecture_gate_baseline_v1.json"
MOD03_PATH = ROOT / "docs" / "architecture" / "mod03_ownership_layering_contract_v1.json"
WORKFLOW = ROOT / ".github" / "workflows" / "build.yml"

SPEC = importlib.util.spec_from_file_location("mod51_include_scc", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
GATE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = GATE
SPEC.loader.exec_module(GATE)


class Mod51IncludeSccGateTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))
        cls.mod04 = json.loads(MOD04_PATH.read_text(encoding="utf-8"))
        cls.mod03 = json.loads(MOD03_PATH.read_text(encoding="utf-8"))

    def test_baseline_graph_is_reproducible_and_scc_free(self) -> None:
        graph_one = GATE.build_graph(self.mod04, self.mod03)
        graph_two = GATE.build_graph(self.mod04, self.mod03)
        self.assertEqual(graph_one, graph_two)
        self.assertEqual(graph_one, self.contract["baseline_graph"])
        report = GATE.validate(self.contract, self.mod04, self.mod03)
        self.assertEqual(report["status"], "PASS")
        self.assertEqual(report["current_graph"], self.contract["baseline_graph"])
        self.assertEqual(report["baseline_sccs"], [])
        self.assertEqual(report["new_sccs"], [])
        self.assertEqual(
            report["current_graph_sha256"],
            self.contract["baseline_graph_sha256"],
        )

    def test_cycle_variants_are_rejected_with_the_same_canonical_scc(self) -> None:
        source = "srchybrid/LiveTunnelFraming.cpp"
        raw = (ROOT / source).read_bytes()
        expected = "new include SCCs forbidden: LiveHandshakeWire,LiveTunnelFraming"
        for suffix in (
            b'\n#include "LiveHandshakeWire.h"\n',
            b'\n#include "subdir\\..\\LiveHandshakeWire.h"\n',
            b'\n#include "SUBDIR\\..\\livehandshakewire.h"\n',
            b'\r\n#include \\\r\n "LiveHandshakeWire.h"\r\n',
        ):
            graph = GATE.build_graph(self.mod04, self.mod03, {source: raw + suffix})
            with self.assertRaisesRegex(GATE.GateError, expected):
                GATE.verify_scc_policy(self.contract, graph)

    def test_active_nonliteral_include_fails_closed(self) -> None:
        source = "srchybrid/LiveTunnelFraming.cpp"
        raw = (ROOT / source).read_bytes()
        with self.assertRaisesRegex(
            GATE.GateError, f"non-literal active #include forbidden: {source}",
        ):
            GATE.build_graph(
                self.mod04, self.mod03,
                {source: raw + b'\n#define MOD51_TARGET "LiveHandshakeWire.h"\n#include MOD51_TARGET\n'},
            )

    def test_comments_and_strings_do_not_create_active_include_directives(self) -> None:
        source = "srchybrid/LiveTunnelFraming.cpp"
        raw = (ROOT / source).read_bytes()
        decoration = (
            b'\r\n/*\r\n#include MOD51_COMMENT_ONLY\r\n*/\r\n'
            b'const char* mod51_text = "#include MOD51_STRING_ONLY";\r\n'
            b'// #include MOD51_LINE_COMMENT_ONLY\r\n'
        )
        self.assertEqual(
            GATE.build_graph(self.mod04, self.mod03, {source: raw + decoration}),
            self.contract["baseline_graph"],
        )

    def test_baseline_cannot_self_authorize_a_cycle(self) -> None:
        mutated = copy.deepcopy(self.contract)
        graph = mutated["baseline_graph"]
        graph["edges"].append(["LiveTunnelFraming", "LiveCircuitHandshake"])
        graph["includes"].append({
            "source_module": "LiveTunnelFraming",
            "source_file": "srchybrid/LiveTunnelFraming.cpp",
            "target_module": "LiveCircuitHandshake",
            "target_file": "srchybrid/LiveCircuitHandshake.h",
        })
        graph["sccs"] = [[
            "LiveCircuitHandshake", "LiveHandshakeWire", "LiveTunnelFraming",
        ]]
        mutated["baseline_graph_sha256"] = GATE.canonical_sha256(graph)
        with self.assertRaisesRegex(
            GATE.GateError, "baseline graph digest is not the approved MOD-5.1 baseline",
        ):
            GATE.validate_contract(mutated, self.mod04, self.mod03)

    def test_cli_writes_deterministic_artifact_only_under_artifacts(self) -> None:
        artifacts = (ROOT / "artifacts").resolve()
        created = pathlib.Path(tempfile.mkdtemp(prefix="mod51-test-", dir=artifacts)).resolve()
        self.assertTrue(created.is_relative_to(artifacts))
        first = created / "one.json"
        second = created / "two.json"
        try:
            for output in (first, second):
                completed = subprocess.run(
                    [sys.executable, str(SCRIPT), "--verify", "--write-json", str(output)],
                    cwd=ROOT, text=True, capture_output=True, check=False,
                )
                self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
                self.assertIn("modules=30; edges=3; includes=3", completed.stdout)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            blocked = subprocess.run(
                [sys.executable, str(SCRIPT), "--verify", "--write-json", "docs/mod51-blocked.json"],
                cwd=ROOT, text=True, capture_output=True, check=False,
            )
            self.assertNotEqual(blocked.returncode, 0)
            self.assertIn("report path must remain under artifacts/", blocked.stderr)
            self.assertFalse((ROOT / "docs" / "mod51-blocked.json").exists())
        finally:
            # The directory was created by this test and is constrained again
            # before cleanup, so no pre-existing artifact can be removed.
            if created.is_relative_to(artifacts) and created.name.startswith("mod51-test-"):
                shutil.rmtree(created, ignore_errors=True)

    def test_cli_positive_and_exact_negative_fixtures(self) -> None:
        for mode, needle in (
            ("--verify", "new_sccs=0"),
            ("--negative-fixtures", "7 negative include-SCC fixtures"),
        ):
            completed = subprocess.run(
                [sys.executable, str(SCRIPT), mode], cwd=ROOT,
                text=True, capture_output=True, check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            self.assertIn(needle, completed.stdout)

    def test_workflow_binds_mod51_before_build(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("Architecture gates (MOD-0.1 through MOD-5.1)", workflow)
        self.assertIn('python -m unittest discover -s tests -p "test_v92_mod*.py"', workflow)
        self.assertLess(
            workflow.index("Architecture gates (MOD-0.1 through MOD-5.1)"),
            workflow.index("Build ese-server.exe (pkg)"),
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
