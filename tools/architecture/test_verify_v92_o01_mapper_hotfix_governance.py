import copy
import importlib.util
import json
import pathlib
import unittest
from unittest.mock import patch


PATH = pathlib.Path(__file__).with_name(
    "verify_v92_o01_mapper_hotfix_governance.py"
)
SPEC = importlib.util.spec_from_file_location("o01_hotfix_governance", PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class TestO01MapperHotfixGovernance(unittest.TestCase):
    def _m_fixture(self):
        a_commit, m_commit = "a" * 40, "b" * 40
        a_tree = "c" * 40
        executable = "1" * 64
        fingerprint = "F" * 64
        manifest = MODULE.canonical({
            "schema": "ese.mod02.build-manifest/v1",
            "source_commit": a_commit,
            "source_identity_sha256": MODULE.MOD02_IDENTITY,
            "executable_sha256": executable,
        })
        receipt_path = MODULE.release_receipt_path(a_commit)
        receipt = MODULE.canonical({
            "schema": 1,
            "component": "emule",
            "releaseTag": MODULE.RELEASE_TAG,
            "commit": a_commit,
            "sourceFingerprint": fingerprint,
            "binarySha256": executable.upper(),
            "binaryLength": 12_345_678,
            "builtAtUtc": "2026-08-16T12:00:00+00:00",
        }) + b"\n"
        expected_markers = [
            "BEGIN CUPnPImplMiniLib deferred reaper",
            "PASS CUPnPImplMiniLib deferred reaper",
            f"SOURCE {MODULE.MOD02_IDENTITY}",
            "BEGIN CLiveTunnel", "PASS CLiveTunnel",
            "BEGIN CWebServer", "PASS CWebServer",
            "BEGIN CLiveStreamManager", "PASS CLiveStreamManager",
        ]
        summary = {
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
            "expected_markers": expected_markers,
            "observed_markers_sanitized": expected_markers,
            "markers_verified": True,
            "marker_sha256": MODULE.MOD02_MARKER_SHA,
            "verdict": "PASS",
            "command": "--portable --ignoreinstances --selftest",
            "isolation": "portable unique output root; no UI",
        }
        summary_raw = json.dumps(summary, indent=2).encode() + b"\n"
        summary_path = f"artifacts/mod02-runtime-v92-{a_commit[:8]}/summary.json"
        evidence = {
            field: summary[field] for field in (
                "source_commit", "source_identity_sha256", "executable_sha256",
                "build_manifest_sha256", "marker_sha256", "timeout_seconds",
                "timed_out", "termination_confirmed", "exit_code",
                "source_tree_clean", "markers_verified",
            )
        }
        evidence["summary_sha256"] = MODULE.sha(summary_raw)
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
            (m_commit, summary_path): summary_raw,
            (m_commit, MODULE.M_MATRIX): MODULE.canonical(matrix),
            (a_commit, MODULE.M_MATRIX): MODULE.canonical(prior_matrix),
        }
        return {
            "a": a_commit, "m": m_commit, "a_tree": a_tree,
            "fingerprint": fingerprint, "receipt_path": receipt_path,
            "summary_path": summary_path, "blobs": blobs,
        }

    def _run_m_fixture(self, fixture):
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
            MODULE, "release_source_fingerprint", return_value=fixture["fingerprint"]
        ):
            MODULE.verify_m(fixture["m"], fixture["a"])

    def _h_fixture(self):
        g_commit, a_commit, m_commit, h_commit = (
            "1" * 40, "2" * 40, "3" * 40, "4" * 40,
        )
        a_tree, m_tree = "5" * 40, "6" * 40
        amendment = b"{}\n"
        review = lambda role: MODULE.canonical({
            "schema": "ese.v92.o01-review/v1", "role": role,
            "reviewed_commit": a_commit, "reviewed_tree": a_tree,
            "verdict": "APPROVE", "findings": [],
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
                "schema": "ese.v92.o01-hotfix-offline-summary/v1",
                "source_commit": a_commit, "source_tree": a_tree,
                "m_commit": m_commit, "m_tree": m_tree,
                "amendment_sha256": MODULE.sha(amendment), "gates": gates,
            }),
            MODULE.H_PATHS[2]: review("Sol"),
            MODULE.H_PATHS[3]: review("Terra"),
        }
        children[MODULE.H_PATHS[0]] = MODULE.canonical({
            "schema": "ese.v92.o01-hotfix-activation/v1",
            "predecessor_h_commit": MODULE.PRED_H,
            "g_commit": g_commit, "a_commit": a_commit, "a_tree": a_tree,
            "m_commit": m_commit, "m_tree": m_tree,
            "amendment_sha256": MODULE.sha(amendment),
            "historical_functional_paths_sha256": MODULE.sha(MODULE.canonical(MODULE.LEGACY.functional_paths())),
            "hotfix_functional_paths_sha256": MODULE.sha(MODULE.canonical(MODULE.FUNCTIONAL)),
            "cumulative_functional_paths_sha256": MODULE.sha(MODULE.canonical(MODULE.cumulative_paths())),
            "release_metadata_paths_sha256": MODULE.sha(MODULE.canonical(MODULE.RELEASE_METADATA)),
            "build_gate_paths_sha256": MODULE.sha(MODULE.canonical(MODULE.BUILD_GATE)),
            "package_documentation_paths_sha256": MODULE.sha(MODULE.canonical(MODULE.PACKAGE_DOCUMENTATION)),
            "mod02_reseal_paths_sha256": MODULE.sha(MODULE.canonical(MODULE.MOD02_RESEAL)),
            "candidate_paths_sha256": MODULE.sha(MODULE.canonical(MODULE.candidate_paths())),
            "artifact_sha256": {path: MODULE.sha(raw) for path, raw in children.items()},
        })
        return {
            "g": g_commit, "a": a_commit, "m": m_commit, "h": h_commit,
            "a_tree": a_tree, "m_tree": m_tree,
            "amendment": amendment, "children": children,
        }

    def _run_h_fixture(self, fixture):
        def fake_git(*args):
            if args == ("rev-parse", f"{fixture['a']}^{{tree}}"):
                return fixture["a_tree"]
            if args == ("rev-parse", f"{fixture['m']}^{{tree}}"):
                return fixture["m_tree"]
            raise AssertionError(args)

        def fake_blob(commit, path):
            return fixture["amendment"] if commit == fixture["g"] else fixture["children"][path]

        with patch.object(MODULE, "parents", return_value=[fixture["m"]]), patch.object(
            MODULE, "changed", return_value=MODULE.H_PATHS
        ), patch.object(MODULE, "git", side_effect=fake_git), patch.object(
            MODULE, "blob", side_effect=fake_blob
        ):
            MODULE.verify_h(fixture["h"], fixture["m"], fixture["a"], fixture["g"])

    def test_document_is_exact_and_closed(self):
        self.assertTrue(MODULE.validate(MODULE.load()))
        self.assertEqual(len(MODULE.FUNCTIONAL), 8)
        self.assertEqual(len(MODULE.RELEASE_METADATA), 5)
        self.assertEqual(len(MODULE.BUILD_GATE), 2)
        self.assertEqual(len(MODULE.PACKAGE_DOCUMENTATION), 6)
        self.assertEqual(len(MODULE.MOD02_RESEAL), 2)
        self.assertEqual(len(MODULE.cumulative_paths()), 44)
        self.assertEqual(len(MODULE.candidate_paths()), 59)
        self.assertEqual(MODULE.BUDGET, (23, 417, 63, 354))

    def test_git_commit_offset_is_normalized_to_the_same_utc_instant(self):
        self.assertEqual(
            MODULE.parse_utc(
                "2026-08-16T13:00:00+02:00", "commit",
                allow_timezone_offset=True,
            ),
            MODULE.parse_utc("2026-08-16T11:00:00Z", "utc"),
        )

    def test_normative_mutations_are_rejected(self):
        mutations = [
            lambda value: value["predecessor"].__setitem__("h_commit", "0" * 40),
            lambda value: value.__setitem__("scope", value["scope"].replace("six packaged", "five packaged")),
            lambda value: value["stop_conditions"].__setitem__(7, value["stop_conditions"][7].replace("candidate-facing entrypoint", "packaged document")),
            lambda value: value["functional_paths"].reverse(),
            lambda value: value["budget"].__setitem__("add_exact", 355),
            lambda value: value["mapper_budget"].__setitem__("add_exact", 204),
            lambda value: value["historical_contract"].__setitem__("candidate_path_count", 58),
            lambda value: value["release_metadata_paths"].reverse(),
            lambda value: value["release_metadata_sha256"].__setitem__(MODULE.RELEASE_METADATA[0], "0" * 64),
            lambda value: value["release_metadata_budget"].__setitem__("add_exact", 152),
            lambda value: value["build_gate_paths"].reverse(),
            lambda value: value["build_gate_sha256"].__setitem__(MODULE.BUILD_GATE[0], "0" * 64),
            lambda value: value["build_gate_budget"].__setitem__("add_exact", 20),
            lambda value: value["package_documentation_paths"].reverse(),
            lambda value: value["package_documentation_sha256"].__setitem__(MODULE.PACKAGE_DOCUMENTATION[0], "0" * 64),
            lambda value: value["package_documentation_budget"].__setitem__("add_exact", 43),
            lambda value: value["mod02_reseal_paths"].reverse(),
            lambda value: value["mod02_reseal_sha256"].__setitem__(MODULE.MOD02_RESEAL[0], "0" * 64),
            lambda value: value["mod02_reseal_budget"].__setitem__("add_exact", 3),
            lambda value: value["phase_contract"]["M"].__setitem__("parent", "G"),
            lambda value: value["carrier_paths"]["M"].__setitem__("file_count", 3),
            lambda value: value["stop_conditions"].pop(),
        ]
        for mutation in mutations:
            value = copy.deepcopy(MODULE.load())
            mutation(value)
            with self.assertRaises(MODULE.GateError):
                MODULE.validate(value)

    def test_worktree_gate_requires_exact_predecessor_and_closed_paths(self):
        def wrong_path_git(*args):
            if args == ("rev-parse", "HEAD"):
                return MODULE.PRED_H
            if args[:3] == ("diff", "HEAD", "--numstat"):
                return "1\t0\tsrchybrid/unlisted.cpp"
            if args[:3] == ("ls-files", "--others", "--exclude-standard"):
                return ""
            raise AssertionError(args)

        with patch.object(MODULE, "git", side_effect=wrong_path_git):
            with self.assertRaisesRegex(MODULE.GateError, "worktree allowlist"):
                MODULE.worktree_stats()
        with patch.object(MODULE, "git", return_value=MODULE.PRED_A):
            with self.assertRaisesRegex(MODULE.GateError, "worktree base"):
                MODULE.worktree_stats()

    def test_untracked_path_cannot_bypass_worktree_gate(self):
        def fake_git(*args):
            if args == ("rev-parse", "HEAD"):
                return MODULE.PRED_H
            if args[:3] == ("diff", "HEAD", "--numstat"):
                return ""
            if args[:3] == ("ls-files", "--others", "--exclude-standard"):
                return "unlisted.txt"
            raise AssertionError(args)

        with patch.object(MODULE, "git", side_effect=fake_git), patch.object(
            pathlib.Path, "read_bytes", return_value=b"x\n"
        ):
            with self.assertRaisesRegex(MODULE.GateError, "worktree allowlist"):
                MODULE.worktree_stats()

    def test_predecessor_commit_parent_tree_and_h_delta_are_all_pinned(self):
        MODULE.verify_predecessor()
        with patch.object(MODULE, "parents", return_value=["wrong"]):
            with self.assertRaisesRegex(MODULE.GateError, "predecessor topology"):
                MODULE.verify_predecessor()

    def test_g_requires_one_exact_parent_and_three_exact_paths(self):
        document = MODULE.load()
        raw = MODULE.canonical(document)
        with patch.object(MODULE, "parents", return_value=[MODULE.PRED_H]), patch.object(
            MODULE, "changed", return_value=sorted(MODULE.GOV)
        ), patch.object(MODULE, "blob", return_value=raw):
            MODULE.verify_g("g", document)
        with patch.object(MODULE, "parents", return_value=[MODULE.PRED_H, "merge"]):
            with self.assertRaisesRegex(MODULE.GateError, "G parent"):
                MODULE.verify_g("g", document)
        with patch.object(MODULE, "parents", return_value=[MODULE.PRED_H]), patch.object(
            MODULE, "changed", return_value=sorted(MODULE.GOV) + ["extra"]
        ):
            with self.assertRaisesRegex(MODULE.GateError, "G delta"):
                MODULE.verify_g("g", document)

    def test_a_budget_allowlist_order_and_case_are_exact(self):
        rows = "\n".join(
            f"{203 if path == MODULE.FUNCTIONAL[0] else 151 if path == MODULE.RELEASE_METADATA[0] else 19 if path == MODULE.BUILD_GATE[0] else 42 if path == MODULE.PACKAGE_DOCUMENTATION[0] else 2 if path == MODULE.MOD02_RESEAL[0] else 0}\t"
            f"{10 if path == MODULE.FUNCTIONAL[0] else 6 if path == MODULE.RELEASE_METADATA[0] else 1 if path == MODULE.BUILD_GATE[0] else 44 if path == MODULE.PACKAGE_DOCUMENTATION[0] else 2 if path == MODULE.MOD02_RESEAL[0] else 0}\t{path}"
            for path in MODULE.A_PATHS
        )
        with patch.object(MODULE, "git", return_value=rows):
            MODULE.budget("g", "a")
        with patch.object(MODULE, "git", return_value=rows.replace("203\t10", "204\t10", 1)):
            with self.assertRaisesRegex(MODULE.GateError, "A budget"):
                MODULE.budget("g", "a")
        compensated = rows.replace("203\t10", "204\t10", 1).replace("151\t6", "150\t6", 1)
        with patch.object(MODULE, "git", return_value=compensated):
            with self.assertRaisesRegex(MODULE.GateError, "A mapper budget"):
                MODULE.budget("g", "a")
        compensated_reseal = rows.replace("19\t1", "20\t1", 1).replace("2\t2", "1\t2", 1)
        with patch.object(MODULE, "git", return_value=compensated_reseal):
            with self.assertRaisesRegex(MODULE.GateError, "A build gate budget"):
                MODULE.budget("g", "a")
        compensated_documentation = rows.replace("42\t44", "43\t44", 1).replace("2\t2", "1\t2", 1)
        with patch.object(MODULE, "git", return_value=compensated_documentation):
            with self.assertRaisesRegex(MODULE.GateError, "A package documentation budget"):
                MODULE.budget("g", "a")
        for hostile in (
            MODULE.A_PATHS + ["twenty-fourth"],
            list(reversed(MODULE.A_PATHS)),
            [MODULE.A_PATHS[0].upper(), *MODULE.A_PATHS[1:]],
        ):
            with patch.object(MODULE, "parents", return_value=["g"]), patch.object(
                MODULE, "changed", return_value=hostile
            ):
                with self.assertRaisesRegex(MODULE.GateError, "A delta"):
                    MODULE.verify_a("a", "g")

    def test_a_release_metadata_content_is_byte_pinned(self):
        current = {
            path: (MODULE.ROOT / path).read_bytes()
            for path in MODULE.RELEASE_METADATA + MODULE.BUILD_GATE + MODULE.PACKAGE_DOCUMENTATION + MODULE.MOD02_RESEAL
        }
        with patch.object(MODULE, "parents", return_value=["g"]), patch.object(
            MODULE, "changed", return_value=MODULE.A_PATHS
        ), patch.object(MODULE, "budget"), patch.object(
            MODULE, "blob", side_effect=lambda commit, path: current[path]
        ):
            MODULE.verify_a("a", "g")
        current[MODULE.RELEASE_METADATA[0]] += b"hostile\n"
        with patch.object(MODULE, "parents", return_value=["g"]), patch.object(
            MODULE, "changed", return_value=MODULE.A_PATHS
        ), patch.object(MODULE, "budget"), patch.object(
            MODULE, "blob", side_effect=lambda commit, path: current[path]
        ):
            with self.assertRaisesRegex(MODULE.GateError, "A release metadata content"):
                MODULE.verify_a("a", "g")

    def test_worktree_rejects_compensated_mapper_metadata_rebalance(self):
        rows = "\n".join(
            f"{204 if path == MODULE.FUNCTIONAL[0] else 150 if path == MODULE.RELEASE_METADATA[0] else 19 if path == MODULE.BUILD_GATE[0] else 42 if path == MODULE.PACKAGE_DOCUMENTATION[0] else 2 if path == MODULE.MOD02_RESEAL[0] else 0}\t"
            f"{10 if path == MODULE.FUNCTIONAL[0] else 6 if path == MODULE.RELEASE_METADATA[0] else 1 if path == MODULE.BUILD_GATE[0] else 44 if path == MODULE.PACKAGE_DOCUMENTATION[0] else 2 if path == MODULE.MOD02_RESEAL[0] else 0}\t{path}"
            for path in MODULE.A_PATHS
        )

        def fake_git(*args):
            if args == ("rev-parse", "HEAD"):
                return MODULE.PRED_H
            if args[:3] == ("diff", "HEAD", "--numstat"):
                return rows
            if args[:3] == ("ls-files", "--others", "--exclude-standard"):
                return ""
            raise AssertionError(args)

        with patch.object(MODULE, "git", side_effect=fake_git):
            with self.assertRaisesRegex(MODULE.GateError, "worktree mapper budget"):
                MODULE.worktree_stats()

    def test_worktree_rejects_compensated_build_mod02_reseal_rebalance(self):
        rows = "\n".join(
            f"{203 if path == MODULE.FUNCTIONAL[0] else 151 if path == MODULE.RELEASE_METADATA[0] else 20 if path == MODULE.BUILD_GATE[0] else 42 if path == MODULE.PACKAGE_DOCUMENTATION[0] else 1 if path == MODULE.MOD02_RESEAL[0] else 0}\t"
            f"{10 if path == MODULE.FUNCTIONAL[0] else 6 if path == MODULE.RELEASE_METADATA[0] else 1 if path == MODULE.BUILD_GATE[0] else 44 if path == MODULE.PACKAGE_DOCUMENTATION[0] else 2 if path == MODULE.MOD02_RESEAL[0] else 0}\t{path}"
            for path in MODULE.A_PATHS
        )

        def fake_git(*args):
            if args == ("rev-parse", "HEAD"):
                return MODULE.PRED_H
            if args[:3] == ("diff", "HEAD", "--numstat"):
                return rows
            if args[:3] == ("ls-files", "--others", "--exclude-standard"):
                return ""
            raise AssertionError(args)

        with patch.object(MODULE, "git", side_effect=fake_git):
            with self.assertRaisesRegex(MODULE.GateError, "worktree build gate budget"):
                MODULE.worktree_stats()

    def test_worktree_rejects_compensated_package_documentation_rebalance(self):
        rows = "\n".join(
            f"{203 if path == MODULE.FUNCTIONAL[0] else 151 if path == MODULE.RELEASE_METADATA[0] else 19 if path == MODULE.BUILD_GATE[0] else 43 if path == MODULE.PACKAGE_DOCUMENTATION[0] else 1 if path == MODULE.MOD02_RESEAL[0] else 0}\t"
            f"{10 if path == MODULE.FUNCTIONAL[0] else 6 if path == MODULE.RELEASE_METADATA[0] else 1 if path == MODULE.BUILD_GATE[0] else 44 if path == MODULE.PACKAGE_DOCUMENTATION[0] else 2 if path == MODULE.MOD02_RESEAL[0] else 0}\t{path}"
            for path in MODULE.A_PATHS
        )

        def fake_git(*args):
            if args == ("rev-parse", "HEAD"):
                return MODULE.PRED_H
            if args[:3] == ("diff", "HEAD", "--numstat"):
                return rows
            if args[:3] == ("ls-files", "--others", "--exclude-standard"):
                return ""
            raise AssertionError(args)

        with patch.object(MODULE, "git", side_effect=fake_git):
            with self.assertRaisesRegex(MODULE.GateError, "worktree package documentation budget"):
                MODULE.worktree_stats()

    def test_a_build_gate_content_is_byte_pinned(self):
        current = {
            path: (MODULE.ROOT / path).read_bytes()
            for path in MODULE.RELEASE_METADATA + MODULE.BUILD_GATE + MODULE.PACKAGE_DOCUMENTATION + MODULE.MOD02_RESEAL
        }
        with patch.object(MODULE, "parents", return_value=["g"]), patch.object(
            MODULE, "changed", return_value=MODULE.A_PATHS
        ), patch.object(MODULE, "budget"), patch.object(
            MODULE, "blob", side_effect=lambda commit, path: current[path]
        ):
            MODULE.verify_a("a", "g")
        current[MODULE.BUILD_GATE[0]] += b"hostile\r\n"
        with patch.object(MODULE, "parents", return_value=["g"]), patch.object(
            MODULE, "changed", return_value=MODULE.A_PATHS
        ), patch.object(MODULE, "budget"), patch.object(
            MODULE, "blob", side_effect=lambda commit, path: current[path]
        ):
            with self.assertRaisesRegex(MODULE.GateError, "A build gate content"):
                MODULE.verify_a("a", "g")

    def test_a_package_documentation_is_byte_pinned_and_semantically_closed(self):
        current = {
            path: (MODULE.ROOT / path).read_bytes()
            for path in MODULE.RELEASE_METADATA + MODULE.BUILD_GATE + MODULE.PACKAGE_DOCUMENTATION + MODULE.MOD02_RESEAL
        }
        MODULE.validate_package_documentation(
            {path: current[path] for path in MODULE.PACKAGE_DOCUMENTATION},
            "fixture",
        )
        hostile_docs = {
            path: current[path] for path in MODULE.PACKAGE_DOCUMENTATION
        }
        hostile_docs["README.md"] += b"\nThis source tree builds the final `9.1.0`\n"
        with self.assertRaisesRegex(MODULE.GateError, "package documentation stale identity"):
            MODULE.validate_package_documentation(hostile_docs, "fixture")
        with patch.object(MODULE, "parents", return_value=["g"]), patch.object(
            MODULE, "changed", return_value=MODULE.A_PATHS
        ), patch.object(MODULE, "budget"), patch.object(
            MODULE, "blob", side_effect=lambda commit, path: current[path]
        ):
            MODULE.verify_a("a", "g")
        current[MODULE.PACKAGE_DOCUMENTATION[0]] += b"hostile\n"
        with patch.object(MODULE, "parents", return_value=["g"]), patch.object(
            MODULE, "changed", return_value=MODULE.A_PATHS
        ), patch.object(MODULE, "budget"), patch.object(
            MODULE, "blob", side_effect=lambda commit, path: current[path]
        ):
            with self.assertRaisesRegex(MODULE.GateError, "A package documentation content"):
                MODULE.verify_a("a", "g")

    def test_a_mod02_reseal_is_byte_pinned_and_semantically_exact(self):
        current = {
            path: (MODULE.ROOT / path).read_bytes()
            for path in MODULE.RELEASE_METADATA + MODULE.BUILD_GATE + MODULE.PACKAGE_DOCUMENTATION + MODULE.MOD02_RESEAL
        }
        header = current["srchybrid/Mod02BuildIdentity.h"].decode("utf-8")
        regression = current[
            "srchybrid/eSE/test/live_tv_regression.test.js"
        ].decode("utf-8")
        self.assertIn(MODULE.MOD02_IDENTITY, header)
        self.assertEqual(regression.count("assert.equal(pkg.version, '9.2.0-rc.1');"), 1)
        self.assertNotIn("assert.equal(pkg.version, '9.1.0');", regression)
        with patch.object(MODULE, "parents", return_value=["g"]), patch.object(
            MODULE, "changed", return_value=MODULE.A_PATHS
        ), patch.object(MODULE, "budget"), patch.object(
            MODULE, "blob", side_effect=lambda commit, path: current[path]
        ):
            MODULE.verify_a("a", "g")
        current[MODULE.MOD02_RESEAL[0]] += b"hostile\n"
        with patch.object(MODULE, "parents", return_value=["g"]), patch.object(
            MODULE, "changed", return_value=MODULE.A_PATHS
        ), patch.object(MODULE, "budget"), patch.object(
            MODULE, "blob", side_effect=lambda commit, path: current[path]
        ):
            with self.assertRaisesRegex(MODULE.GateError, "A MOD02 reseal content"):
                MODULE.verify_a("a", "g")

    def test_m_requires_direct_parent_and_exact_four_paths(self):
        with patch.object(MODULE, "parents", return_value=["wrong"]):
            with self.assertRaisesRegex(MODULE.GateError, "M parent"):
                MODULE.verify_m("m", "a")
        with patch.object(MODULE, "parents", return_value=["a"]), patch.object(
            MODULE, "changed", return_value=[MODULE.M_MANIFEST]
        ):
            with self.assertRaisesRegex(MODULE.GateError, "M delta"):
                MODULE.verify_m("m", "a")

    def test_m_rejects_manifest_not_bound_to_a(self):
        manifest = MODULE.canonical({
            "schema": "ese.mod02.build-manifest/v1",
            "source_commit": "b" * 40,
            "source_identity_sha256": MODULE.MOD02_IDENTITY,
            "executable_sha256": "1" * 64,
        })
        with patch.object(MODULE, "parents", return_value=["a" * 40]), patch.object(
            MODULE, "changed", return_value=MODULE.m_paths("a" * 40)
        ), patch.object(MODULE, "blob", return_value=manifest):
            with self.assertRaisesRegex(MODULE.GateError, "MOD02 manifest"):
                MODULE.verify_m("m", "a" * 40)

    def test_m_happy_path_binds_clean_release_receipt_and_mod02(self):
        self._run_m_fixture(self._m_fixture())

    def test_m_rejects_stale_self_consistent_executable_receipt(self):
        fixture = self._m_fixture()
        receipt = json.loads(fixture["blobs"][(fixture["m"], fixture["receipt_path"])])
        receipt["sourceFingerprint"] = "0" * 64
        receipt_raw = MODULE.canonical(receipt) + b"\n"
        fixture["blobs"][(fixture["m"], fixture["receipt_path"])] = receipt_raw
        matrix_key = (fixture["m"], MODULE.M_MATRIX)
        matrix = json.loads(fixture["blobs"][matrix_key])
        matrix["runtime_gate"]["release_build_receipt"]["sha256"] = MODULE.sha(receipt_raw)
        fixture["blobs"][matrix_key] = MODULE.canonical(matrix)
        with self.assertRaisesRegex(MODULE.GateError, "Release build receipt"):
            self._run_m_fixture(fixture)

    def test_m_rejects_forged_receipt_hash_and_timestamp_order(self):
        fixture = self._m_fixture()
        matrix_key = (fixture["m"], MODULE.M_MATRIX)
        matrix = json.loads(fixture["blobs"][matrix_key])
        matrix["runtime_gate"]["release_build_receipt"]["sha256"] = "0" * 64
        fixture["blobs"][matrix_key] = MODULE.canonical(matrix)
        with self.assertRaisesRegex(MODULE.GateError, "MOD02 matrix binding"):
            self._run_m_fixture(fixture)

        fixture = self._m_fixture()
        receipt_key = (fixture["m"], fixture["receipt_path"])
        receipt = json.loads(fixture["blobs"][receipt_key])
        receipt["builtAtUtc"] = "2026-08-16T10:00:00Z"
        receipt_raw = MODULE.canonical(receipt) + b"\n"
        fixture["blobs"][receipt_key] = receipt_raw
        matrix_key = (fixture["m"], MODULE.M_MATRIX)
        matrix = json.loads(fixture["blobs"][matrix_key])
        matrix["runtime_gate"]["release_build_receipt"]["sha256"] = MODULE.sha(receipt_raw)
        fixture["blobs"][matrix_key] = MODULE.canonical(matrix)
        with self.assertRaisesRegex(MODULE.GateError, "Release build receipt"):
            self._run_m_fixture(fixture)

    def test_m_rejects_executable_older_than_a_with_all_hashes_consistent(self):
        fixture = self._m_fixture()
        summary_key = (fixture["m"], fixture["summary_path"])
        summary = json.loads(fixture["blobs"][summary_key])
        summary["latest_critical_source_write_utc"] = "2026-08-16T10:59:58Z"
        summary["executable_write_utc"] = "2026-08-16T10:59:59Z"
        summary_raw = json.dumps(summary, indent=2).encode() + b"\n"
        fixture["blobs"][summary_key] = summary_raw
        matrix_key = (fixture["m"], MODULE.M_MATRIX)
        matrix = json.loads(fixture["blobs"][matrix_key])
        matrix["runtime_gate"]["evidence"]["summary_sha256"] = MODULE.sha(summary_raw)
        fixture["blobs"][matrix_key] = MODULE.canonical(matrix)
        with self.assertRaisesRegex(MODULE.GateError, "MOD02 build ordering"):
            self._run_m_fixture(fixture)

    def test_m_rejects_boolean_receipt_schema_and_exit_code(self):
        fixture = self._m_fixture()
        receipt_key = (fixture["m"], fixture["receipt_path"])
        receipt = json.loads(fixture["blobs"][receipt_key])
        receipt["schema"] = True
        receipt_raw = MODULE.canonical(receipt) + b"\n"
        fixture["blobs"][receipt_key] = receipt_raw
        matrix_key = (fixture["m"], MODULE.M_MATRIX)
        matrix = json.loads(fixture["blobs"][matrix_key])
        matrix["runtime_gate"]["release_build_receipt"]["sha256"] = MODULE.sha(receipt_raw)
        fixture["blobs"][matrix_key] = MODULE.canonical(matrix)
        with self.assertRaisesRegex(MODULE.GateError, "Release build receipt"):
            self._run_m_fixture(fixture)

        fixture = self._m_fixture()
        summary_key = (fixture["m"], fixture["summary_path"])
        summary = json.loads(fixture["blobs"][summary_key])
        summary["exit_code"] = False
        summary_raw = json.dumps(summary, indent=2).encode() + b"\n"
        fixture["blobs"][summary_key] = summary_raw
        matrix_key = (fixture["m"], MODULE.M_MATRIX)
        matrix = json.loads(fixture["blobs"][matrix_key])
        matrix["runtime_gate"]["evidence"]["exit_code"] = False
        matrix["runtime_gate"]["evidence"]["summary_sha256"] = MODULE.sha(summary_raw)
        fixture["blobs"][matrix_key] = MODULE.canonical(matrix)
        with self.assertRaisesRegex(MODULE.GateError, "MOD02 termination"):
            self._run_m_fixture(fixture)

    def test_review_requires_empty_findings(self):
        value = {
            "schema": "ese.v92.o01-review/v1", "role": "Sol",
            "reviewed_commit": "a", "reviewed_tree": "tree",
            "verdict": "APPROVE", "findings": ["P3"],
        }
        with self.assertRaisesRegex(MODULE.GateError, "review content"):
            MODULE.validate_review(json.dumps(value).encode(), "Sol", "a", "tree")

    def test_h_happy_path_and_orphan_hash_rejection(self):
        fixture = self._h_fixture()
        self._run_h_fixture(fixture)
        activation_key = MODULE.H_PATHS[0]
        activation = json.loads(fixture["children"][activation_key])
        activation["artifact_sha256"][MODULE.H_PATHS[1]] = "0" * 64
        fixture["children"][activation_key] = MODULE.canonical(activation)
        with self.assertRaisesRegex(MODULE.GateError, "activation content"):
            self._run_h_fixture(fixture)

    def test_h_rejects_boolean_offline_exit_code_after_rehash(self):
        fixture = self._h_fixture()
        offline_key = MODULE.H_PATHS[1]
        offline = json.loads(fixture["children"][offline_key])
        offline["gates"][0]["exit_code"] = False
        offline_raw = MODULE.canonical(offline)
        fixture["children"][offline_key] = offline_raw
        activation_key = MODULE.H_PATHS[0]
        activation = json.loads(fixture["children"][activation_key])
        activation["artifact_sha256"][offline_key] = MODULE.sha(offline_raw)
        fixture["children"][activation_key] = MODULE.canonical(activation)
        with self.assertRaisesRegex(MODULE.GateError, "offline gate"):
            self._run_h_fixture(fixture)

    def test_h_parent_is_m_not_a(self):
        with patch.object(MODULE, "parents", return_value=["a"]):
            with self.assertRaisesRegex(MODULE.GateError, "H parent"):
                MODULE.verify_h("h", "m", "a", "g")

    def test_r_must_use_the_executable_validated_by_m(self):
        executable = "a" * 64
        manifest = MODULE.canonical({
            "schema": "ese.mod02.build-manifest/v1",
            "source_commit": "a", "source_identity_sha256": MODULE.MOD02_IDENTITY,
            "executable_sha256": executable,
        })
        run_holder = {"raw": MODULE.canonical({"executable_sha256": executable})}

        def fake_blob(commit, path):
            return manifest if path == MODULE.M_MANIFEST else run_holder["raw"]

        with patch.object(MODULE.LEGACY, "verify_r"), patch.object(
            MODULE, "blob", side_effect=fake_blob
        ):
            MODULE.verify_r_hotfix("r", "h", "a", "h", None, "m")
            run_holder["raw"] = MODULE.canonical({"executable_sha256": "b" * 64})
            with self.assertRaisesRegex(MODULE.GateError, "formal executable binding"):
                MODULE.verify_r_hotfix("r", "h", "a", "h", None, "m")

    def test_autodetect_routes_direct_and_smoke_r_through_m_binding(self):
        commits = {key: str(index) * 40 for index, key in enumerate("gamhsr", 1)}

        def exercise(with_smoke):
            if with_smoke:
                ancestry = {
                    commits["r"]: [commits["s"]], commits["s"]: [commits["h"]],
                    commits["h"]: [commits["m"]], commits["m"]: [commits["a"]],
                    commits["a"]: [commits["g"]], commits["g"]: [MODULE.PRED_H],
                }
            else:
                ancestry = {
                    commits["r"]: [commits["h"]], commits["h"]: [commits["m"]],
                    commits["m"]: [commits["a"]], commits["a"]: [commits["g"]],
                    commits["g"]: [MODULE.PRED_H],
                }

            def fake_git(*args):
                if args == ("rev-parse", "HEAD"):
                    return commits["r"]
                raise AssertionError(args)

            def fake_changed(parent, child):
                if with_smoke and (parent, child) == (commits["h"], commits["s"]):
                    return MODULE.S_PATHS
                return ["formal"]

            with patch.object(MODULE, "git", side_effect=fake_git), patch.object(
                MODULE, "parents", side_effect=lambda commit: ancestry[commit]
            ), patch.object(MODULE, "changed", side_effect=fake_changed), patch.object(
                MODULE, "verify_g"
            ), patch.object(MODULE, "verify_a"), patch.object(
                MODULE, "verify_m"
            ), patch.object(MODULE, "verify_h"), patch.object(
                MODULE.LEGACY, "verify_s"
            ) as verify_s, patch.object(MODULE, "verify_r_hotfix") as verify_r:
                self.assertEqual(MODULE.autodetect(MODULE.load()), "R")
                if with_smoke:
                    verify_s.assert_called_once_with(
                        commits["s"], commits["h"], commits["a"]
                    )
                    verify_r.assert_called_once_with(
                        commits["r"], commits["s"], commits["a"],
                        commits["h"], commits["s"], commits["m"],
                    )
                else:
                    verify_s.assert_not_called()
                    verify_r.assert_called_once_with(
                        commits["r"], commits["h"], commits["a"],
                        commits["h"], None, commits["m"],
                    )

        exercise(False)
        exercise(True)

    def test_release_claim_remains_formal_only(self):
        self.assertEqual(
            MODULE.load()["physical_policy"]["claim_rule"],
            "Only independently validated R evidence with exact cleanup and baseline restoration may award V92-O01 PASS.",
        )


if __name__ == "__main__":
    unittest.main()
