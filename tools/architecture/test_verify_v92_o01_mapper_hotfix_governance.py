import copy
import importlib.util
import json
import pathlib
import unittest
from unittest.mock import patch


PATH = pathlib.Path(__file__).with_name(
    "verify_v92_o01_mapper_hotfix_governance.py"
)
SPEC = importlib.util.spec_from_file_location("o01_runtime_fix_governance", PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class TestO01RuntimeFixGovernance(unittest.TestCase):
    def _m_fixture(self):
        a_commit, m_commit = "a" * 40, "b" * 40
        a_tree = "c" * 40
        executable = "1" * 64
        manifest = MODULE.canonical({
            "schema": "ese.mod02.build-manifest/v1",
            "source_commit": a_commit,
            "source_identity_sha256": MODULE.MOD02_IDENTITY,
            "executable_sha256": executable,
        })
        receipt_path = MODULE.release_receipt_path(a_commit)
        receipt_value = {
            "schema": 1,
            "component": "emule",
            "releaseTag": MODULE.RELEASE_TAG,
            "commit": a_commit,
            "sourceFingerprint": MODULE.RELEASE_FINGERPRINT,
            "binarySha256": executable.upper(),
            "binaryLength": 12_345_678,
            "builtAtUtc": "2026-08-16T12:00:00Z",
        }
        receipt = MODULE.canonical(receipt_value) + b"\n"
        markers = MODULE.mod02_markers()
        summary_value = {
            "schema": "ese.mod02.stream-selftest/v1",
            "build_manifest_sha256": MODULE.sha(manifest),
            "source_commit": a_commit,
            "source_identity_sha256": MODULE.MOD02_IDENTITY,
            "source_tree_clean": True,
            "executable_sha256": executable,
            "executable_write_utc": "2026-08-16T11:59:59Z",
            "latest_critical_source_write_utc": "2026-08-16T11:59:58Z",
            "timeout_seconds": 180,
            "timed_out": False,
            "taskkill_started": False,
            "taskkill_finished": True,
            "taskkill_exit_code": None,
            "termination_confirmed": True,
            "exit_code": 0,
            "expected_markers": markers,
            "observed_markers_sanitized": markers,
            "markers_verified": True,
            "marker_sha256": MODULE.MOD02_MARKER_SHA,
            "verdict": "PASS",
            "command": "--portable --ignoreinstances --selftest",
            "isolation": "portable unique output root; no UI",
        }
        summary = json.dumps(summary_value, indent=2).encode() + b"\n"
        summary_path = f"artifacts/mod02-runtime-v92-{a_commit[:8]}/summary.json"
        evidence = {
            field: summary_value[field] for field in (
                "source_commit", "source_identity_sha256", "executable_sha256",
                "build_manifest_sha256", "marker_sha256", "timeout_seconds",
                "timed_out", "termination_confirmed", "exit_code",
                "source_tree_clean", "markers_verified",
            )
        }
        evidence["summary_sha256"] = MODULE.sha(summary)
        prior_matrix = {
            "matrix_id": "fixture",
            "runtime_gate": {"acceptance": "frozen acceptance"},
            "rows": [],
        }
        matrix = copy.deepcopy(prior_matrix)
        matrix["runtime_gate"] = {
            "runner": "tools/architecture/run_mod02_stream_selftest.ps1",
            "build_manifest": MODULE.M_MANIFEST,
            "summary": summary_path,
            "status": "PASS",
            "required_summary": MODULE.MOD02_REQUIRED,
            "acceptance": "frozen acceptance",
            "release_build_receipt": {
                "path": receipt_path,
                "sha256": MODULE.sha(receipt),
                "source_tree": a_tree,
            },
            "evidence": evidence,
        }
        blobs = {
            (m_commit, MODULE.M_MANIFEST): manifest,
            (m_commit, receipt_path): receipt,
            (m_commit, summary_path): summary,
            (m_commit, MODULE.M_MATRIX): MODULE.canonical(matrix),
            (a_commit, MODULE.M_MATRIX): MODULE.canonical(prior_matrix),
        }
        return {
            "a": a_commit, "m": m_commit, "a_tree": a_tree,
            "receipt_path": receipt_path, "receipt_value": receipt_value,
            "summary_path": summary_path, "summary_value": summary_value,
            "matrix": matrix, "prior_matrix": prior_matrix, "blobs": blobs,
        }

    def _run_m(self, fixture):
        def fake_git(*args):
            if args == ("rev-parse", f"{fixture['a']}^{{tree}}"):
                return fixture["a_tree"]
            if args == ("show", "-s", "--format=%cI", fixture["a"]):
                return "2026-08-16T13:00:00+02:00"
            raise AssertionError(args)

        with patch.object(MODULE, "parents", return_value=[fixture["a"]]), patch.object(
            MODULE, "changed", return_value=MODULE.m_paths(fixture["a"])
        ), patch.object(MODULE, "git", side_effect=fake_git), patch.object(
            MODULE, "blob", side_effect=lambda commit, path: fixture["blobs"][(commit, path)]
        ), patch.object(
            MODULE, "release_source_fingerprint", return_value=MODULE.RELEASE_FINGERPRINT
        ):
            MODULE.verify_m(fixture["m"], fixture["a"])

    def _rebind_receipt(self, fixture):
        raw = MODULE.canonical(fixture["receipt_value"]) + b"\n"
        fixture["blobs"][(fixture["m"], fixture["receipt_path"])] = raw
        fixture["matrix"]["runtime_gate"]["release_build_receipt"]["sha256"] = MODULE.sha(raw)
        fixture["blobs"][(fixture["m"], MODULE.M_MATRIX)] = MODULE.canonical(fixture["matrix"])

    def _rebind_summary(self, fixture):
        raw = json.dumps(fixture["summary_value"], indent=2).encode() + b"\n"
        fixture["blobs"][(fixture["m"], fixture["summary_path"])] = raw
        evidence = fixture["matrix"]["runtime_gate"]["evidence"]
        for field in (
            "source_commit", "source_identity_sha256", "executable_sha256",
            "build_manifest_sha256", "marker_sha256", "timeout_seconds",
            "timed_out", "termination_confirmed", "exit_code",
            "source_tree_clean", "markers_verified",
        ):
            evidence[field] = fixture["summary_value"][field]
        evidence["summary_sha256"] = MODULE.sha(raw)
        fixture["blobs"][(fixture["m"], MODULE.M_MATRIX)] = MODULE.canonical(fixture["matrix"])

    def _h_fixture(self):
        g_commit, a_commit, m_commit, h_commit = (
            "1" * 40, "2" * 40, "3" * 40, "4" * 40,
        )
        a_tree, m_tree = "5" * 40, "6" * 40
        amendment = b"{}\n"

        def review(role):
            return MODULE.canonical({
                "schema": "ese.v92.o01-review/v1",
                "role": role,
                "reviewed_commit": a_commit,
                "reviewed_tree": a_tree,
                "verdict": "APPROVE",
                "findings": [],
            })

        gates = []
        for name, command, marker in MODULE.OFFLINE:
            body = [marker]
            gates.append({
                "name": name, "command": command, "exit_code": 0,
                "marker": marker, "body": body,
                "body_sha256": MODULE.sha(MODULE.canonical(body)),
            })
        children = {
            MODULE.H_PATHS[1]: MODULE.canonical({
                "schema": "ese.v92.o01-runtime-fix-offline-summary/v1",
                "source_commit": a_commit, "source_tree": a_tree,
                "m_commit": m_commit, "m_tree": m_tree,
                "amendment_sha256": MODULE.sha(amendment), "gates": gates,
            }),
            MODULE.H_PATHS[2]: review("Sol"),
            MODULE.H_PATHS[3]: review("Terra"),
        }
        children[MODULE.H_PATHS[0]] = MODULE.canonical({
            "schema": "ese.v92.o01-runtime-fix-activation/v1",
            "predecessor_h_commit": MODULE.PRED_H,
            "g_commit": g_commit, "a_commit": a_commit, "a_tree": a_tree,
            "m_commit": m_commit, "m_tree": m_tree,
            "amendment_sha256": MODULE.sha(amendment),
            "historical_candidate_paths_sha256": MODULE.HISTORICAL_CANDIDATE_SHA256,
            "formal_runtime_fix_paths_sha256": MODULE.sha(MODULE.canonical(MODULE.FORMAL_RUNTIME_FIX)),
            "mod02_test_ratchet_paths_sha256": MODULE.sha(MODULE.canonical(MODULE.MOD02_TEST_RATCHET)),
            "historical_overlap_paths_sha256": MODULE.sha(MODULE.canonical(MODULE.HISTORICAL_OVERLAP)),
            "new_candidate_paths_sha256": MODULE.sha(MODULE.canonical(MODULE.NEW_CANDIDATE)),
            "candidate_paths_sha256": MODULE.CANDIDATE_SHA256,
            "artifact_sha256": {path: MODULE.sha(raw) for path, raw in children.items()},
        })
        return {
            "g": g_commit, "a": a_commit, "m": m_commit, "h": h_commit,
            "a_tree": a_tree, "m_tree": m_tree,
            "amendment": amendment, "children": children,
        }

    def _rehash_activation(self, fixture):
        activation = json.loads(fixture["children"][MODULE.H_PATHS[0]])
        activation["artifact_sha256"] = {
            path: MODULE.sha(fixture["children"][path]) for path in MODULE.H_PATHS[1:]
        }
        fixture["children"][MODULE.H_PATHS[0]] = MODULE.canonical(activation)

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

    def test_document_is_exact_closed_and_uses_union_not_sum(self):
        self.assertTrue(MODULE.validate(MODULE.load()))
        self.assertEqual(len(MODULE.FORMAL_RUNTIME_FIX), 6)
        self.assertEqual(len(MODULE.MOD02_TEST_RATCHET), 1)
        self.assertEqual(len(MODULE.HISTORICAL_CANDIDATE), 59)
        self.assertEqual(len(MODULE.candidate_paths()), 62)
        self.assertEqual(MODULE.BUDGET, (7, 48, 10, 38))
        self.assertEqual(MODULE.CANDIDATE_BUDGET, (62, 1702, 136, 1566))
        self.assertEqual(
            set(MODULE.A_PATHS) & set(MODULE.HISTORICAL_CANDIDATE),
            set(MODULE.HISTORICAL_OVERLAP),
        )
        self.assertEqual(len(MODULE.HISTORICAL_OVERLAP), 4)

    def test_document_normative_mutations_are_rejected(self):
        original = MODULE.load()
        variants = []
        value = copy.deepcopy(original); value["extra"] = True; variants.append(value)
        value = copy.deepcopy(original); value["status"] = "draft_pre_g9"; variants.append(value)
        value = copy.deepcopy(original); value["budget"]["add_exact"] += 1; variants.append(value)
        value = copy.deepcopy(original); value["cumulative_candidate_budget"]["path_count"] = 66; variants.append(value)
        value = copy.deepcopy(original); value["historical_overlap_paths"].pop(); variants.append(value)
        value = copy.deepcopy(original); value["release_contract"]["scenario_socket_limit"] = True; variants.append(value)
        value = copy.deepcopy(original); value["phase_contract"]["R"]["parent"] = "H37_or_S"; variants.append(value)
        value = copy.deepcopy(original); value["formal_runtime_fix_sha256"][MODULE.FORMAL_RUNTIME_FIX[0]] = "A" * 64; variants.append(value)
        value = copy.deepcopy(original); value["mod02_test_ratchet_paths"] = []; variants.append(value)
        for variant in variants:
            with self.subTest(variant=variants.index(variant)), self.assertRaises(MODULE.GateError):
                MODULE.validate(variant)

    def test_git_commit_offset_is_normalized_to_utc(self):
        self.assertEqual(
            MODULE.parse_utc("2026-08-16T13:00:00+02:00", "commit", True),
            MODULE.parse_utc("2026-08-16T11:00:00Z", "utc"),
        )

    def test_real_predecessor_chain_trees_blobs_and_scenario_are_pinned(self):
        MODULE.verify_predecessor()

    def test_budget_requires_exact_seven_paths_and_each_numstat(self):
        MODULE.validate_budget(dict(MODULE.PATH_BUDGET), "fixture")
        extra = dict(MODULE.PATH_BUDGET); extra["tools/lab/eighth.ps1"] = (0, 0)
        with self.assertRaisesRegex(MODULE.GateError, "allowlist"):
            MODULE.validate_budget(extra, "fixture")
        plus = dict(MODULE.PATH_BUDGET)
        path = MODULE.FORMAL_RUNTIME_FIX[0]
        plus[path] = (plus[path][0] + 1, plus[path][1])
        with self.assertRaisesRegex(MODULE.GateError, "budget"):
            MODULE.validate_budget(plus, "fixture")
        minus = dict(MODULE.PATH_BUDGET)
        minus[path] = (minus[path][0], minus[path][1] - 1)
        with self.assertRaisesRegex(MODULE.GateError, "budget"):
            MODULE.validate_budget(minus, "fixture")
        rebalance = dict(MODULE.PATH_BUDGET)
        other = MODULE.FORMAL_RUNTIME_FIX[1]
        rebalance[path] = (rebalance[path][0] + 1, rebalance[path][1])
        rebalance[other] = (rebalance[other][0] - 1, rebalance[other][1])
        with self.assertRaisesRegex(MODULE.GateError, "path budget"):
            MODULE.validate_budget(rebalance, "fixture")

    def test_hash_pins_cover_both_slices_and_detect_drift(self):
        raw = {path: path.encode() for path in MODULE.A_PATHS}
        runtime_hashes = {path: MODULE.sha(raw[path]) for path in MODULE.FORMAL_RUNTIME_FIX}
        ratchet_hashes = {path: MODULE.sha(raw[path]) for path in MODULE.MOD02_TEST_RATCHET}
        with patch.object(MODULE, "FORMAL_RUNTIME_FIX_SHA256", runtime_hashes), patch.object(
            MODULE, "MOD02_TEST_RATCHET_SHA256", ratchet_hashes
        ):
            MODULE.verify_fix_hashes(lambda path: raw[path], "fixture")
            raw[MODULE.MOD02_TEST_RATCHET[0]] += b"drift"
            with self.assertRaisesRegex(MODULE.GateError, "ratchet identity"):
                MODULE.verify_fix_hashes(lambda path: raw[path], "fixture")

    def test_scenario_requires_unchanged_blob_and_integer_two(self):
        good = MODULE.canonical({"limits": {"sockets": 2}})
        with patch.object(MODULE, "SCENARIO_SHA256", MODULE.sha(good)):
            MODULE.verify_scenario(good, "fixture")
            boolean = MODULE.canonical({"limits": {"sockets": True}})
            with patch.object(MODULE, "SCENARIO_SHA256", MODULE.sha(boolean)):
                with self.assertRaisesRegex(MODULE.GateError, "socket limit"):
                    MODULE.verify_scenario(boolean, "fixture")
            with self.assertRaisesRegex(MODULE.GateError, "scenario identity"):
                MODULE.verify_scenario(good + b"\n", "fixture")

    def test_worktree_gate_rejects_wrong_base_before_reading_payload(self):
        with patch.object(MODULE, "git", return_value="f" * 40):
            with self.assertRaisesRegex(MODULE.GateError, "worktree base"):
                MODULE.worktree_stats()

    def test_worktree_gate_rejects_eighth_path(self):
        rows = dict(MODULE.PATH_BUDGET)
        rows["tools/lab/eighth.ps1"] = (0, 0)
        numstat = "\n".join(
            f"{add}\t{delete}\t{path}" for path, (add, delete) in rows.items()
        )

        def fake_git(*args):
            if args == ("rev-parse", "HEAD"):
                return MODULE.PRED_H
            if args == ("diff", "HEAD", "--numstat", "--"):
                return numstat
            if args == ("ls-files", "--others", "--exclude-standard"):
                return ""
            raise AssertionError(args)

        with patch.object(MODULE, "git", side_effect=fake_git):
            with self.assertRaisesRegex(MODULE.GateError, "allowlist"):
                MODULE.worktree_stats()

    def test_g9_requires_direct_h36_parent_and_exact_three_paths(self):
        document = MODULE.load()
        g_commit = "1" * 40
        with patch.object(MODULE, "parents", return_value=[MODULE.PRED_H]), patch.object(
            MODULE, "changed", return_value=sorted(MODULE.GOV)
        ), patch.object(MODULE, "blob", return_value=MODULE.canonical(document)):
            MODULE.verify_g(g_commit, document)
        with patch.object(MODULE, "parents", return_value=["0" * 40]):
            with self.assertRaisesRegex(MODULE.GateError, "parent"):
                MODULE.verify_g(g_commit, document)

    def test_a37_binds_parent_allowlist_budget_hashes_and_scenario(self):
        with patch.object(MODULE, "parents", return_value=["g" * 40]), patch.object(
            MODULE, "changed", return_value=MODULE.A_PATHS
        ), patch.object(MODULE, "commit_budget") as budget_gate, patch.object(
            MODULE, "verify_fix_hashes") as hash_gate, patch.object(
            MODULE, "verify_scenario") as scenario_gate, patch.object(
            MODULE, "blob", return_value=b"fixture"
        ):
            MODULE.verify_a("a" * 40, "g" * 40)
        budget_gate.assert_called_once_with("g" * 40, "a" * 40)
        hash_gate.assert_called_once()
        scenario_gate.assert_called_once_with(b"fixture", "A37")

    def test_a37_rejects_an_eighth_path(self):
        with patch.object(MODULE, "parents", return_value=["g" * 40]), patch.object(
            MODULE, "changed", return_value=MODULE.A_PATHS + ["eighth"]
        ):
            with self.assertRaisesRegex(MODULE.GateError, "A37 delta"):
                MODULE.verify_a("a" * 40, "g" * 40)

    def test_m37_happy_path_binds_new_receipt_manifest_summary_and_matrix(self):
        self._run_m(self._m_fixture())

    def test_m37_requires_direct_a37_parent_and_exact_four_carriers(self):
        fixture = self._m_fixture()
        with patch.object(MODULE, "parents", return_value=["0" * 40]):
            with self.assertRaisesRegex(MODULE.GateError, "M37 parent"):
                MODULE.verify_m(fixture["m"], fixture["a"])
        with patch.object(MODULE, "parents", return_value=[fixture["a"]]), patch.object(
            MODULE, "changed", return_value=MODULE.m_paths(fixture["a"]) + ["extra"]
        ):
            with self.assertRaisesRegex(MODULE.GateError, "M37 delta"):
                MODULE.verify_m(fixture["m"], fixture["a"])

    def test_m37_rejects_reused_or_unbound_release_receipt(self):
        fixture = self._m_fixture()
        fixture["receipt_value"]["commit"] = MODULE.A36
        self._rebind_receipt(fixture)
        with self.assertRaisesRegex(MODULE.GateError, "Release build receipt"):
            self._run_m(fixture)

    def test_m37_rejects_boolean_schema_and_boolean_summary_exit(self):
        fixture = self._m_fixture()
        fixture["receipt_value"]["schema"] = True
        self._rebind_receipt(fixture)
        with self.assertRaisesRegex(MODULE.GateError, "Release build receipt"):
            self._run_m(fixture)
        fixture = self._m_fixture()
        fixture["summary_value"]["exit_code"] = False
        self._rebind_summary(fixture)
        with self.assertRaisesRegex(MODULE.GateError, "MOD02 termination"):
            self._run_m(fixture)

    def test_m37_rejects_build_timestamps_before_a37(self):
        fixture = self._m_fixture()
        fixture["receipt_value"]["builtAtUtc"] = "2026-08-16T10:59:59Z"
        self._rebind_receipt(fixture)
        with self.assertRaisesRegex(MODULE.GateError, "Release build receipt"):
            self._run_m(fixture)

    def test_h37_happy_path_binds_m37_a37_reviews_and_artifacts(self):
        self._run_h(self._h_fixture())

    def test_h37_rejects_nonempty_review_even_after_activation_rehash(self):
        fixture = self._h_fixture()
        review = json.loads(fixture["children"][MODULE.H_PATHS[3]])
        review["findings"] = [{"priority": "P3", "message": "not empty"}]
        fixture["children"][MODULE.H_PATHS[3]] = MODULE.canonical(review)
        self._rehash_activation(fixture)
        with self.assertRaisesRegex(MODULE.GateError, "review content"):
            self._run_h(fixture)

    def test_h37_rejects_boolean_offline_exit_after_activation_rehash(self):
        fixture = self._h_fixture()
        offline = json.loads(fixture["children"][MODULE.H_PATHS[1]])
        offline["gates"][0]["exit_code"] = False
        fixture["children"][MODULE.H_PATHS[1]] = MODULE.canonical(offline)
        self._rehash_activation(fixture)
        with self.assertRaisesRegex(MODULE.GateError, "offline gate"):
            self._run_h(fixture)

    def test_h37_requires_m37_as_direct_parent(self):
        fixture = self._h_fixture()
        with patch.object(MODULE, "parents", return_value=[fixture["a"]]):
            with self.assertRaisesRegex(MODULE.GateError, "H37 parent"):
                MODULE.verify_h(fixture["h"], fixture["m"], fixture["a"], fixture["g"])

    def test_r_is_direct_h37_and_uses_exact_m37_executable(self):
        r_commit, h_commit, a_commit, m_commit = (
            "r" * 40, "h" * 40, "a" * 40, "m" * 40,
        )
        executable = "1" * 64
        manifest = MODULE.canonical({
            "schema": "ese.mod02.build-manifest/v1",
            "source_commit": a_commit,
            "source_identity_sha256": MODULE.MOD02_IDENTITY,
            "executable_sha256": executable,
        })
        run = MODULE.canonical({"executable_sha256": executable})

        def fake_blob(commit, path):
            if commit == m_commit and path == MODULE.M_MANIFEST:
                return manifest
            if commit == r_commit and path.endswith("formal-run-result.json"):
                return run
            raise AssertionError((commit, path))

        with patch.object(MODULE, "parents", return_value=[h_commit]), patch.object(
            MODULE.LEGACY, "verify_r"
        ) as legacy_gate, patch.object(MODULE, "blob", side_effect=fake_blob):
            MODULE.verify_r(r_commit, h_commit, a_commit, m_commit)
        legacy_gate.assert_called_once_with(r_commit, h_commit, a_commit, h_commit, None)

        run = MODULE.canonical({"executable_sha256": "2" * 64})
        with patch.object(MODULE, "parents", return_value=[h_commit]), patch.object(
            MODULE.LEGACY, "verify_r"
        ), patch.object(MODULE, "blob", side_effect=fake_blob):
            with self.assertRaisesRegex(MODULE.GateError, "formal executable binding"):
                MODULE.verify_r(r_commit, h_commit, a_commit, m_commit)

    def test_r_rejects_optional_s_or_any_intermediate_commit(self):
        g, a, m, h, s, r = [letter * 40 for letter in "gamh sr".replace(" ", "")]
        parent = {g: MODULE.PRED_H, a: g, m: a, h: m, s: h, r: s}

        def fake_git(*args):
            if args == ("rev-parse", "HEAD"):
                return r
            raise AssertionError(args)

        with patch.object(MODULE, "git", side_effect=fake_git), patch.object(
            MODULE, "parents", side_effect=lambda commit: [parent[commit]]
        ), patch.object(MODULE, "verify_g"), patch.object(
            MODULE, "verify_a"
        ), patch.object(MODULE, "verify_m"), patch.object(MODULE, "verify_h"):
            with self.assertRaisesRegex(MODULE.GateError, "intermediate before R"):
                MODULE.autodetect(MODULE.load())

    def test_autodetect_routes_only_h36_g9_a37_m37_h37_r(self):
        g, a, m, h, r = [letter * 40 for letter in "gamhr"]
        parent = {g: MODULE.PRED_H, a: g, m: a, h: m, r: h}

        def fake_git(*args):
            if args == ("rev-parse", "HEAD"):
                return r
            raise AssertionError(args)

        with patch.object(MODULE, "git", side_effect=fake_git), patch.object(
            MODULE, "parents", side_effect=lambda commit: [parent[commit]]
        ), patch.object(MODULE, "verify_g") as vg, patch.object(
            MODULE, "verify_a") as va, patch.object(MODULE, "verify_m") as vm, patch.object(
            MODULE, "verify_h") as vh, patch.object(MODULE, "verify_r") as vr:
            self.assertEqual(MODULE.autodetect(MODULE.load()), "R")
        vg.assert_called_once_with(g, MODULE.load())
        va.assert_called_once_with(a, g)
        vm.assert_called_once_with(m, a)
        vh.assert_called_once_with(h, m, a, g)
        vr.assert_called_once_with(r, h, a, m)

    def test_release_claim_remains_direct_formal_only(self):
        document = MODULE.load()
        self.assertNotIn("S", document["topology"])
        self.assertEqual(document["phase_contract"]["R"]["parent"], "H37")
        self.assertTrue(document["phase_contract"]["R"]["release_gate"])
        self.assertIn("28800000", document["physical_policy"]["formal"])
        self.assertIn("NON_RELEASE", document["physical_policy"]["preflight"])


if __name__ == "__main__":
    unittest.main()
