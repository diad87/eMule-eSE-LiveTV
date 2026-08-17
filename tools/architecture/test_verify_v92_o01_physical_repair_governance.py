import copy
import importlib.util
import json
import pathlib
import unittest
from unittest.mock import patch


PATH = pathlib.Path(__file__).with_name("verify_v92_o01_physical_repair_governance.py")
SPEC = importlib.util.spec_from_file_location("o01_physical_repair_governance", PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class TestO01PhysicalRepairGovernance(unittest.TestCase):
    def _scenario(self):
        return json.loads((MODULE.ROOT / MODULE.SCENARIO).read_text(encoding="utf-8"))

    def _m_fixture(self):
        a_commit, m_commit = "a" * 40, "b" * 40
        a_tree, executable = "c" * 40, "1" * 64
        manifest = MODULE.canonical({
            "schema": "ese.mod02.build-manifest/v1",
            "source_commit": a_commit,
            "source_identity_sha256": MODULE.MOD02_IDENTITY,
            "executable_sha256": executable,
        })
        receipt_path = MODULE.release_receipt_path(a_commit)
        receipt_value = {
            "schema": 1, "component": "emule", "releaseTag": MODULE.RELEASE_TAG,
            "commit": a_commit, "sourceFingerprint": MODULE.RELEASE_FINGERPRINT,
            "binarySha256": executable.upper(), "binaryLength": 12_345_678,
            "builtAtUtc": "2026-08-17T12:00:00Z",
        }
        receipt = MODULE.canonical(receipt_value) + b"\n"
        markers = MODULE.mod02_markers()
        summary_value = {
            "schema": "ese.mod02.stream-selftest/v1",
            "build_manifest_sha256": MODULE.sha(manifest), "source_commit": a_commit,
            "source_identity_sha256": MODULE.MOD02_IDENTITY, "source_tree_clean": True,
            "executable_sha256": executable, "executable_write_utc": "2026-08-17T11:59:59Z",
            "latest_critical_source_write_utc": "2026-08-17T11:59:58Z",
            "timeout_seconds": 180, "timed_out": False, "taskkill_started": False,
            "taskkill_finished": True, "taskkill_exit_code": None,
            "termination_confirmed": True, "exit_code": 0,
            "expected_markers": markers, "observed_markers_sanitized": markers,
            "markers_verified": True, "marker_sha256": MODULE.MOD02_MARKER_SHA,
            "verdict": "PASS", "command": "--portable --ignoreinstances --selftest",
            "isolation": "portable unique output root; no UI",
        }
        summary = json.dumps(summary_value, indent=2).encode() + b"\n"
        summary_path = f"artifacts/mod02-runtime-v92-{a_commit[:8]}/summary.json"
        evidence = {
            field: summary_value[field] for field in (
                "source_commit", "source_identity_sha256", "executable_sha256",
                "build_manifest_sha256", "marker_sha256", "timeout_seconds",
                "timed_out", "termination_confirmed", "exit_code", "source_tree_clean",
                "markers_verified",
            )
        }
        evidence["summary_sha256"] = MODULE.sha(summary)
        prior_matrix = {"matrix_id": "fixture", "runtime_gate": {"acceptance": "frozen"}, "rows": []}
        matrix = copy.deepcopy(prior_matrix)
        matrix["runtime_gate"] = {
            "runner": "tools/architecture/run_mod02_stream_selftest.ps1",
            "build_manifest": MODULE.M_MANIFEST, "summary": summary_path, "status": "PASS",
            "required_summary": MODULE.MOD02_REQUIRED, "acceptance": "frozen",
            "release_build_receipt": {
                "path": receipt_path, "sha256": MODULE.sha(receipt), "source_tree": a_tree,
            },
            "evidence": evidence,
        }
        blobs = {
            (m_commit, MODULE.M_MANIFEST): manifest, (m_commit, receipt_path): receipt,
            (m_commit, summary_path): summary, (m_commit, MODULE.M_MATRIX): MODULE.canonical(matrix),
            (a_commit, MODULE.M_MATRIX): MODULE.canonical(prior_matrix),
        }
        return {
            "a": a_commit, "m": m_commit, "a_tree": a_tree, "receipt_path": receipt_path,
            "receipt_value": receipt_value, "summary_path": summary_path,
            "summary_value": summary_value, "matrix": matrix, "blobs": blobs,
        }

    def _run_m(self, fixture):
        def fake_git(*args):
            if args == ("rev-parse", f"{fixture['a']}^{{tree}}"):
                return fixture["a_tree"]
            if args == ("show", "-s", "--format=%cI", fixture["a"]):
                return "2026-08-17T13:00:00+02:00"
            raise AssertionError(args)

        with patch.object(MODULE, "parents", return_value=[fixture["a"]]), patch.object(
            MODULE, "changed", return_value=MODULE.m_paths(fixture["a"])
        ), patch.object(MODULE, "git", side_effect=fake_git), patch.object(
            MODULE, "blob", side_effect=lambda commit, path: fixture["blobs"][(commit, path)]
        ), patch.object(MODULE, "release_source_fingerprint", return_value=MODULE.RELEASE_FINGERPRINT):
            MODULE.verify_m(fixture["m"], fixture["a"])

    def _rebind_receipt(self, fixture):
        raw = MODULE.canonical(fixture["receipt_value"]) + b"\n"
        fixture["blobs"][(fixture["m"], fixture["receipt_path"])] = raw
        fixture["matrix"]["runtime_gate"]["release_build_receipt"]["sha256"] = MODULE.sha(raw)
        fixture["blobs"][(fixture["m"], MODULE.M_MATRIX)] = MODULE.canonical(fixture["matrix"])

    def _h_fixture(self):
        g, a, m, h = (character * 40 for character in "gamh")
        a_tree, m_tree, amendment = "1" * 40, "2" * 40, b"{}\n"

        def review(role):
            return MODULE.canonical({
                "schema": "ese.v92.o01-review/v1", "role": role,
                "reviewed_commit": a, "reviewed_tree": a_tree,
                "verdict": "APPROVE", "findings": [],
            })

        gates = []
        for name, command, marker in MODULE.OFFLINE:
            body = [marker]
            gates.append({
                "name": name, "command": command, "exit_code": 0, "marker": marker,
                "body": body, "body_sha256": MODULE.sha(MODULE.canonical(body)),
            })
        children = {
            MODULE.H_PATHS[1]: MODULE.canonical({
                "schema": "ese.v92.o01-physical-repair-offline-summary/v1",
                "source_commit": a, "source_tree": a_tree, "m_commit": m,
                "m_tree": m_tree, "amendment_sha256": MODULE.sha(amendment), "gates": gates,
            }),
            MODULE.H_PATHS[2]: review("Sol"), MODULE.H_PATHS[3]: review("Terra"),
        }
        children[MODULE.H_PATHS[0]] = MODULE.canonical({
            "schema": "ese.v92.o01-physical-repair-activation/v1",
            "predecessor_h_commit": MODULE.PRED_H, "g_commit": g, "a_commit": a,
            "a_tree": a_tree, "m_commit": m, "m_tree": m_tree,
            "amendment_sha256": MODULE.sha(amendment),
            "candidate_paths_sha256": MODULE.CANDIDATE_SHA256,
            "a38_paths_sha256": MODULE.sha(MODULE.canonical(MODULE.A_PATHS)),
            "runtime_paths_sha256": MODULE.sha(MODULE.canonical(MODULE.RUNTIME_PATHS)),
            "test_paths_sha256": MODULE.sha(MODULE.canonical(MODULE.TEST_PATHS)),
            "documentation_paths_sha256": MODULE.sha(MODULE.canonical(MODULE.DOC_PATHS)),
            "scenario_sha256": MODULE.SCENARIO_SHA256,
            "product_mapper_blob": MODULE.PRODUCT_MAPPER_BLOB,
            "product_mapper_sha256": MODULE.PRODUCT_MAPPER_SHA256,
            "artifact_sha256": {path: MODULE.sha(raw) for path, raw in children.items()},
        })
        return {"g": g, "a": a, "m": m, "h": h, "a_tree": a_tree, "m_tree": m_tree,
                "amendment": amendment, "children": children}

    def _run_h(self, fixture):
        def fake_git(*args):
            if args == ("rev-parse", f"{fixture['a']}^{{tree}}"):
                return fixture["a_tree"]
            if args == ("rev-parse", f"{fixture['m']}^{{tree}}"):
                return fixture["m_tree"]
            raise AssertionError(args)

        def fake_blob(commit, path):
            if commit == fixture["g"] and path == MODULE.DOC:
                return fixture["amendment"]
            if commit == fixture["h"]:
                return fixture["children"][path]
            raise AssertionError((commit, path))

        with patch.object(MODULE, "parents", return_value=[fixture["m"]]), patch.object(
            MODULE, "changed", return_value=MODULE.H_PATHS
        ), patch.object(MODULE, "git", side_effect=fake_git), patch.object(
            MODULE, "blob", side_effect=fake_blob
        ):
            MODULE.verify_h(fixture["h"], fixture["m"], fixture["a"], fixture["g"])

    def _r_fixture(self):
        a, m, h, r = (character * 40 for character in "amhr")
        tree, executable = "1" * 40, "2" * 64
        scenario = (MODULE.ROOT / MODULE.SCENARIO).read_bytes()
        a_blobs = {path: f"A38:{path}".encode() for path in MODULE.BOUND_FILES}
        a_blobs[MODULE.SCENARIO] = scenario
        validator_path = "tools/lab/nat_gateway/v92_o01_validate_formal.js"
        validator = a_blobs[validator_path]
        bound = [{"path": path, "sha256": MODULE.sha(a_blobs[path])} for path in MODULE.BOUND_FILES]
        result = {
            "source_commit": a, "source_tree": tree, "verdict": "PASS",
            "checkpoint_count": 95, "chain_tip_sha256": "3" * 64, "bound_files": bound,
        }
        controller_path = "artifacts/v92-o01-formal/controller-result.json"
        run_path = "artifacts/v92-o01-formal/formal-run-result.json"
        validation_path = "artifacts/v92-o01-formal/formal-validation.json"
        controller_raw = MODULE.canonical(result)
        run = {
            "schema": "ese.v92.o01-formal-run/v1", "verdict": "PASS", "release_gate": True,
            "source_commit": a, "source_tree": tree, "governance_h_commit": h,
            "governance_s_commit": None, "executable_sha256": executable,
            "build_info_sha256": "4" * 64, "node_sha256": "5" * 64,
            "duration_ms": 28800000, "product_records": 482, "checkpoints": 95,
            "fault_slots": 96, "baseline_restored": True, "independent_validation": True,
        }
        run_raw = MODULE.canonical(run)
        blobs = {
            (m, MODULE.M_MANIFEST): MODULE.canonical({
                "schema": "ese.mod02.build-manifest/v1", "source_commit": a,
                "source_identity_sha256": MODULE.MOD02_IDENTITY,
                "executable_sha256": executable,
            }),
            (r, controller_path): controller_raw, (r, run_path): run_raw,
            (a, validator_path): validator, (a, MODULE.SCENARIO): scenario,
        }
        raw = {controller_path: controller_raw, run_path: run_raw}
        for index in range(1, 96):
            path = f"artifacts/v92-o01-formal/checkpoint-{index:02}.json"
            data = MODULE.canonical({"checkpoint": index})
            blobs[(r, path)] = data
            raw[path] = data
        validation = {
            "schema": "ese.v92.o01-formal-validation/v2", "verdict": "PASS",
            "source_commit": a, "source_tree": tree, "governance_h_commit": h,
            "governance_s_commit": None, "validator_sha256": MODULE.sha(validator),
            "scenario_sha256": MODULE.sha(scenario),
            "artifacts_sha256": {path: MODULE.sha(data) for path, data in sorted(raw.items())},
            "chain_tip_sha256": result["chain_tip_sha256"], "checkpoints": 95,
            "fault_slots": 96, "ticks": 2880, "samples": 480,
        }
        blobs[(r, validation_path)] = MODULE.canonical(validation)
        for path, data in a_blobs.items():
            blobs[(a, path)] = data
        return {"a": a, "m": m, "h": h, "r": r, "tree": tree, "run": run,
                "run_path": run_path, "validation_path": validation_path,
                "validation": validation, "blobs": blobs}

    def _run_r(self, fixture):
        with patch.object(MODULE, "parents", return_value=[fixture["h"]]), patch.object(
            MODULE, "changed", return_value=MODULE.r_paths()
        ), patch.object(MODULE, "git", return_value=fixture["tree"]), patch.object(
            MODULE, "blob", side_effect=lambda commit, path: fixture["blobs"][(commit, path)]
        ), patch.object(MODULE, "run_product_validator"):
            MODULE.verify_r(fixture["r"], fixture["h"], fixture["a"], fixture["m"])

    def _rebind_r_run(self, fixture):
        raw = MODULE.canonical(fixture["run"])
        fixture["blobs"][(fixture["r"], fixture["run_path"])] = raw
        fixture["validation"]["artifacts_sha256"][fixture["run_path"]] = MODULE.sha(raw)
        fixture["blobs"][(fixture["r"], fixture["validation_path"])] = MODULE.canonical(fixture["validation"])

    def test_document_and_current_worktree_are_exact(self):
        self.assertTrue(MODULE.validate(MODULE.load()))
        self.assertTrue(MODULE.worktree_stats())
        self.assertEqual(MODULE.BUDGET, (30, 992, 316, 676))
        self.assertEqual(MODULE.RUNTIME_BUDGET, (14, 616, 137, 479))
        self.assertEqual(MODULE.TEST_BUDGET, (14, 368, 176, 192))
        self.assertEqual(MODULE.DOC_BUDGET, (2, 8, 3, 5))
        self.assertEqual(MODULE.CUMULATIVE_BUDGET, (62, 2694, 452, 2242))
        self.assertEqual(set(MODULE.A_PATHS) - set(MODULE.HISTORICAL_CANDIDATE), set())

    def test_document_normative_mutations_are_rejected(self):
        original = MODULE.load()
        mutations = [
            lambda value: value.__setitem__("status", "DRAFT_PRE_G9"),
            lambda value: value["predecessor"].__setitem__("h37_tree", "0" * 40),
            lambda value: value["runtime_paths"].append("path-25"),
            lambda value: value["runtime_budget"].__setitem__("add_exact", 438),
            lambda value: value["a38_sha256"].__setitem__(MODULE.A_PATHS[0], "0" * 64),
            lambda value: value["release_contract"].__setitem__("fault_slot_ms", 30000),
            lambda value: value["release_contract"].__setitem__("bound_file_count", 20),
            lambda value: value["phase_contract"]["R"].__setitem__("parent", "H38_or_S"),
        ]
        for mutation in mutations:
            value = copy.deepcopy(original)
            mutation(value)
            with self.assertRaises(MODULE.GateError):
                MODULE.validate(value)

    def test_real_predecessor_chain_trees_governance_and_mapper_are_pinned(self):
        MODULE.verify_predecessor()

    def test_budget_rejects_path_25_and_compensated_cross_slice_rebalance(self):
        MODULE.validate_budget(dict(MODULE.PATH_BUDGET), "fixture")
        extra = dict(MODULE.PATH_BUDGET)
        extra["tools/lab/path-25.js"] = (0, 0)
        with self.assertRaisesRegex(MODULE.GateError, "allowlist"):
            MODULE.validate_budget(extra, "fixture")
        rebalanced = dict(MODULE.PATH_BUDGET)
        runtime, test = MODULE.RUNTIME_PATHS[0], MODULE.TEST_PATHS[0]
        rebalanced[runtime] = (rebalanced[runtime][0] + 1, rebalanced[runtime][1])
        rebalanced[test] = (rebalanced[test][0] - 1, rebalanced[test][1])
        with self.assertRaisesRegex(MODULE.GateError, "path budget"):
            MODULE.validate_budget(rebalanced, "fixture")

    def test_hash_pin_detects_one_byte_drift(self):
        raw = {path: path.encode() for path in MODULE.A_PATHS}
        pins = {path: MODULE.sha(data) for path, data in raw.items()}
        with patch.object(MODULE, "A_SHA256", pins):
            MODULE.verify_a_hashes(lambda path: raw[path], "fixture")
            raw[MODULE.A_PATHS[-1]] += b"x"
            with self.assertRaisesRegex(MODULE.GateError, "byte identity"):
                MODULE.verify_a_hashes(lambda path: raw[path], "fixture")

    def test_scenario_rejects_every_timing_plus_or_minus_one_and_legacy_30s(self):
        base = self._scenario()
        for field, expected in (("fault_slot_ms", 300000), ("lease_ms", 120000), ("late_delay_ms", 8000)):
            for value in (expected - 1, expected + 1):
                hostile = copy.deepcopy(base)
                hostile[field] = value
                raw = MODULE.canonical(hostile)
                with patch.object(MODULE, "SCENARIO_SHA256", MODULE.sha(raw)):
                    with self.assertRaisesRegex(MODULE.GateError, "scenario timing"):
                        MODULE.verify_scenario(raw, "fixture")
        hostile = copy.deepcopy(base)
        hostile["fault_slot_ms"] = 30000
        raw = MODULE.canonical(hostile)
        with patch.object(MODULE, "SCENARIO_SHA256", MODULE.sha(raw)):
            with self.assertRaisesRegex(MODULE.GateError, "scenario timing"):
                MODULE.verify_scenario(raw, "fixture")

    def test_scenario_rejects_bound_count_and_boolean_socket(self):
        for mutate, message in (
            (lambda value: value["bound_files"].pop(), "bound files"),
            (lambda value: value["limits"].__setitem__("sockets", True), "socket limit"),
        ):
            hostile = self._scenario()
            mutate(hostile)
            raw = MODULE.canonical(hostile)
            with patch.object(MODULE, "SCENARIO_SHA256", MODULE.sha(raw)):
                with self.assertRaisesRegex(MODULE.GateError, message):
                    MODULE.verify_scenario(raw, "fixture")

    def test_product_mapper_requires_both_blob_and_sha256(self):
        raw = (MODULE.ROOT / MODULE.PRODUCT_MAPPER).read_bytes()
        MODULE.verify_product_mapper(raw, "fixture")
        with self.assertRaisesRegex(MODULE.GateError, "product mapper identity"):
            MODULE.verify_product_mapper(raw + b"x", "fixture")

    def test_worktree_and_g10_reject_wrong_predecessor_or_extra_governance_path(self):
        with patch.object(MODULE, "git", return_value="0" * 40):
            with self.assertRaisesRegex(MODULE.GateError, "worktree base"):
                MODULE.worktree_stats()
        document = MODULE.load()
        with patch.object(MODULE, "parents", return_value=["0" * 40]):
            with self.assertRaisesRegex(MODULE.GateError, "G10 parent"):
                MODULE.verify_g("g" * 40, document)
        with patch.object(MODULE, "parents", return_value=[MODULE.PRED_H]), patch.object(
            MODULE, "changed", return_value=sorted(MODULE.GOV + ["fourth"])
        ):
            with self.assertRaisesRegex(MODULE.GateError, "G10 delta"):
                MODULE.verify_g("g" * 40, document)

    def test_a38_requires_direct_g10_exact_30_budget_hash_scenario_and_mapper(self):
        with patch.object(MODULE, "parents", return_value=["g" * 40]), patch.object(
            MODULE, "changed", return_value=MODULE.A_PATHS
        ), patch.object(MODULE, "commit_budget") as budget, patch.object(
            MODULE, "verify_a_hashes") as hashes, patch.object(
            MODULE, "verify_scenario") as scenario, patch.object(
            MODULE, "verify_product_mapper") as mapper, patch.object(MODULE, "blob", return_value=b"x"):
            MODULE.verify_a("a" * 40, "g" * 40)
        budget.assert_called_once()
        hashes.assert_called_once()
        scenario.assert_called_once_with(b"x", "A38")
        mapper.assert_called_once_with(b"x", "A38")

    def test_m38_happy_path_and_fresh_a38_binding(self):
        self._run_m(self._m_fixture())
        fixture = self._m_fixture()
        fixture["receipt_value"]["commit"] = MODULE.A37
        self._rebind_receipt(fixture)
        with self.assertRaisesRegex(MODULE.GateError, "Release build receipt"):
            self._run_m(fixture)

    def test_m38_requires_direct_a38_and_exact_four_carriers(self):
        fixture = self._m_fixture()
        with patch.object(MODULE, "parents", return_value=["0" * 40]):
            with self.assertRaisesRegex(MODULE.GateError, "M38 parent"):
                MODULE.verify_m(fixture["m"], fixture["a"])
        with patch.object(MODULE, "parents", return_value=[fixture["a"]]), patch.object(
            MODULE, "changed", return_value=MODULE.m_paths(fixture["a"]) + ["fifth"]
        ):
            with self.assertRaisesRegex(MODULE.GateError, "M38 delta"):
                MODULE.verify_m(fixture["m"], fixture["a"])

    def test_h38_happy_path_and_review_binding(self):
        self._run_h(self._h_fixture())
        fixture = self._h_fixture()
        review = json.loads(fixture["children"][MODULE.H_PATHS[3]])
        review["findings"] = [{"priority": "P3"}]
        fixture["children"][MODULE.H_PATHS[3]] = MODULE.canonical(review)
        activation = json.loads(fixture["children"][MODULE.H_PATHS[0]])
        activation["artifact_sha256"] = {
            path: MODULE.sha(fixture["children"][path]) for path in MODULE.H_PATHS[1:]
        }
        fixture["children"][MODULE.H_PATHS[0]] = MODULE.canonical(activation)
        with self.assertRaisesRegex(MODULE.GateError, "review content"):
            self._run_h(fixture)

    def test_h38_requires_direct_m38_and_exact_four_carriers(self):
        fixture = self._h_fixture()
        with patch.object(MODULE, "parents", return_value=[fixture["a"]]):
            with self.assertRaisesRegex(MODULE.GateError, "H38 parent"):
                MODULE.verify_h(fixture["h"], fixture["m"], fixture["a"], fixture["g"])
        with patch.object(MODULE, "parents", return_value=[fixture["m"]]), patch.object(
            MODULE, "changed", return_value=MODULE.H_PATHS + ["fifth"]
        ):
            with self.assertRaisesRegex(MODULE.GateError, "H38 delta"):
                MODULE.verify_h(fixture["h"], fixture["m"], fixture["a"], fixture["g"])

    def test_r_happy_path_binds_h38_a38_m38_exact98_and_96_slots(self):
        self._run_r(self._r_fixture())

    def test_r_rejects_legacy_960_slots_h_m_and_executable_rebinding(self):
        for mutation in (
            lambda fixture: fixture["run"].__setitem__("fault_slots", 960),
            lambda fixture: fixture["run"].__setitem__("governance_h_commit", "x" * 40),
            lambda fixture: fixture["run"].__setitem__("source_commit", MODULE.A37),
            lambda fixture: fixture["run"].__setitem__("executable_sha256", "9" * 64),
        ):
            fixture = self._r_fixture()
            mutation(fixture)
            self._rebind_r_run(fixture)
            with self.assertRaisesRegex(MODULE.GateError, "formal run"):
                self._run_r(fixture)

    def test_r_requires_direct_h38_and_exact_98_paths(self):
        fixture = self._r_fixture()
        with patch.object(MODULE, "parents", return_value=["0" * 40]):
            with self.assertRaisesRegex(MODULE.GateError, "R parent"):
                MODULE.verify_r(fixture["r"], fixture["h"], fixture["a"], fixture["m"])
        with patch.object(MODULE, "parents", return_value=[fixture["h"]]), patch.object(
            MODULE, "changed", return_value=MODULE.r_paths()[:-1]
        ):
            with self.assertRaisesRegex(MODULE.GateError, "R delta"):
                MODULE.verify_r(fixture["r"], fixture["h"], fixture["a"], fixture["m"])

    def test_autodetect_rejects_s_or_any_intermediate(self):
        g, a, m, h, s, r = (character * 40 for character in "gamh sr".replace(" ", ""))
        parent = {g: MODULE.PRED_H, a: g, m: a, h: m, s: h, r: s}
        with patch.object(MODULE, "git", return_value=r), patch.object(
            MODULE, "parents", side_effect=lambda commit: [parent[commit]]
        ), patch.object(MODULE, "verify_g"), patch.object(MODULE, "verify_a"), patch.object(
            MODULE, "verify_m"), patch.object(MODULE, "verify_h"):
            with self.assertRaisesRegex(MODULE.GateError, "intermediate before R"):
                MODULE.autodetect(MODULE.load())

    def test_release_claim_is_direct_eight_hour_only(self):
        document = MODULE.load()
        self.assertNotIn("S", document["topology"])
        self.assertEqual(document["phase_contract"]["R"]["parent"], "H38")
        self.assertEqual(document["carrier_paths"]["M38"]["file_count"], 4)
        self.assertEqual(document["carrier_paths"]["H38"], MODULE.H_PATHS)
        self.assertEqual(document["carrier_paths"]["R"]["file_count"], 98)
        self.assertIn("28800000", document["physical_policy"]["formal"])
        self.assertIn("96 five-minute", document["physical_policy"]["formal"])


if __name__ == "__main__":
    unittest.main()
