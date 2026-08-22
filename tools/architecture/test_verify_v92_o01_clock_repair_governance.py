import contextlib
import copy
import importlib.util
import io
import json
import pathlib
import sys
import unittest
from unittest.mock import patch


PATH = pathlib.Path(__file__).with_name("verify_v92_o01_clock_repair_governance.py")
SPEC = importlib.util.spec_from_file_location("o01_clock_repair_governance", PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class TestO01ClockRepairGovernance(unittest.TestCase):
    def _assert_gate_error(self, call):
        with self.assertRaises(MODULE.GateError):
            call()

    def _scenario(self):
        return json.loads((MODULE.ROOT / MODULE.SCENARIO).read_text(encoding="utf-8"))

    def test_document_history_diagnostic_epoch_and_worktree_are_exact(self):
        self.assertTrue(MODULE.validate_document(MODULE.load()))
        MODULE.verify_historical_h38()
        MODULE.verify_diagnostic_epoch()
        head = MODULE.git("rev-parse", "HEAD")
        if head == MODULE.H62:
            self.assertTrue(MODULE.worktree_stats())
        else:
            self.assertIn(MODULE.autodetect(MODULE.load()), {"G11", "A63", "M63", "H63", "R63"})
        self.assertEqual(MODULE.BUDGET, (7, 114, 25, 89))
        self.assertEqual(MODULE.RUNTIME_BUDGET, (3, 98, 20, 78))
        self.assertEqual(MODULE.TEST_BUDGET, (4, 16, 5, 11))
        self.assertEqual(len(MODULE.DIAGNOSTIC_COMMITS), 47)
        self.assertEqual(len(MODULE.DIAGNOSTIC_ALIASES), 24)
        self.assertEqual(MODULE.DIAGNOSTIC_BUDGET, (17, 188, 58, 130))

    def test_document_rejects_normative_mutations(self):
        original = MODULE.load()
        mutations = [
            ("base", lambda value: value["base"].__setitem__("h62_tree", "0" * 40)),
            ("history", lambda value: value["historical_contract"]["governance_sha256"].__setitem__(MODULE.OLD_VERIFIER, "0" * 64)),
            ("classification", lambda value: value["diagnostic_epoch"].__setitem__("release_gate", True)),
            ("commit list", lambda value: value["diagnostic_epoch"]["first_parent_commits"].pop()),
            ("alias", lambda value: value["diagnostic_epoch"]["candidate_aliases"].__setitem__("A62", MODULE.H62)),
            ("path", lambda value: value["functional_paths"]["all"].append("extra")),
            ("hash", lambda value: value["functional_paths"]["sha256"].__setitem__(MODULE.A_PATHS[0], "0" * 64)),
            ("budget", lambda value: value["budget"].__setitem__("add_exact", value["budget"]["add_exact"] + 1)),
            ("scenario", lambda value: value["immutable_contract"].__setitem__("scenario_sha256", "0" * 64)),
            ("mapper", lambda value: value["immutable_contract"].__setitem__("checkpoint_max_gap_ms", 370001)),
            ("scheduler", lambda value: value["immutable_contract"].__setitem__("controller_schedule_jitter_ms", 70001)),
            ("watchdog", lambda value: value["immutable_contract"].__setitem__("subsequent_rpc_watchdog_ms", 90000)),
            ("topology", lambda value: value["phase_contract"]["A63"].__setitem__("parent", "H62")),
            ("R files", lambda value: value["carrier_paths"]["R63"].__setitem__("file_count", 99)),
        ]
        for label, mutate in mutations:
            with self.subTest(label=label):
                value = copy.deepcopy(original)
                mutate(value)
                self._assert_gate_error(lambda value=value: MODULE.validate_document(value))

    def test_budget_is_per_path_and_has_no_compensation_headroom(self):
        cases = []
        missing = dict(MODULE.PATH_BUDGET)
        missing.pop(MODULE.A_PATHS[0])
        cases.append(missing)
        extra = dict(MODULE.PATH_BUDGET)
        extra["unexpected"] = (0, 0)
        cases.append(extra)
        changed = dict(MODULE.PATH_BUDGET)
        path = MODULE.A_PATHS[0]
        changed[path] = (changed[path][0] + 1, changed[path][1])
        cases.append(changed)
        compensated = dict(MODULE.PATH_BUDGET)
        first, second = MODULE.A_PATHS[:2]
        compensated[first] = (compensated[first][0] + 1, compensated[first][1])
        compensated[second] = (compensated[second][0] - 1, compensated[second][1])
        self.assertEqual(MODULE.observed_budget(compensated), MODULE.BUDGET)
        cases.append(compensated)
        for stats in cases:
            self._assert_gate_error(lambda stats=stats: MODULE.validate_budget(stats, "hostile"))

    def test_each_A63_byte_identity_is_closed(self):
        MODULE.verify_a_hashes(lambda path: (MODULE.ROOT / path).read_bytes(), "fixture")
        for target in MODULE.A_PATHS:
            with self.subTest(path=target):
                def reader(path, target=target):
                    raw = (MODULE.ROOT / path).read_bytes()
                    return raw + b" " if path == target else raw
                self._assert_gate_error(lambda reader=reader: MODULE.verify_a_hashes(reader, "hostile"))

    def test_scenario_identity_and_semantics_are_immutable(self):
        raw = (MODULE.ROOT / MODULE.SCENARIO).read_bytes()
        MODULE.verify_scenario(raw, "fixture")
        self._assert_gate_error(lambda: MODULE.verify_scenario(raw + b" ", "hostile"))
        mutations = [
            lambda value: value.__setitem__("formal_duration_ms", 1),
            lambda value: value.__setitem__("tick_ms", 10001),
            lambda value: value.__setitem__("checkpoint_ms", 299999),
            lambda value: value.__setitem__("node_major", 21),
            lambda value: value["limits"].__setitem__("checkpoint_max_gap_ms", 370001),
            lambda value: value["limits"].__setitem__("sockets", 3),
            lambda value: value["bound_files"].pop(),
        ]
        for mutate in mutations:
            value = self._scenario()
            mutate(value)
            hostile = MODULE.canonical(value)
            self._assert_gate_error(
                lambda hostile=hostile: MODULE.verify_scenario(hostile, "hostile", MODULE.sha(hostile))
            )

    def test_mapper_identity_and_370000_threshold_are_immutable(self):
        raw = (MODULE.ROOT / MODULE.PRODUCT_MAPPER).read_bytes()
        MODULE.verify_mapper(raw, "fixture")
        self._assert_gate_error(lambda: MODULE.verify_mapper(raw + b" ", "hostile"))
        hostile = raw.replace(MODULE.MAPPER_THRESHOLD_GUARD, MODULE.MAPPER_THRESHOLD_GUARD.replace(b"370000", b"370001"))
        self.assertNotEqual(hostile, raw)
        self._assert_gate_error(
            lambda: MODULE.verify_mapper(hostile, "hostile", MODULE.sha(hostile))
        )

    def test_diagnostic_chain_rejects_merge_and_commit_list_substitution(self):
        target = MODULE.DIAGNOSTIC_COMMITS[9]
        original_parents = MODULE.parents

        def merged(commit):
            if commit == target:
                return ["a" * 40, "b" * 40]
            return original_parents(commit)

        with patch.object(MODULE, "parents", side_effect=merged):
            self._assert_gate_error(MODULE.verify_diagnostic_epoch)

        original_git = MODULE.git

        def substituted(*args):
            if args == ("rev-list", "--first-parent", "--reverse", f"{MODULE.H38}..{MODULE.H62}"):
                commits = list(MODULE.DIAGNOSTIC_COMMITS)
                commits[3] = "0" * 40
                return "\n".join(commits)
            return original_git(*args)

        with patch.object(MODULE, "git", side_effect=substituted):
            self._assert_gate_error(MODULE.verify_diagnostic_epoch)

    def test_phase_deltas_are_closed_and_R63_forbids_failure_artifacts(self):
        g, a, m, h, r = (letter * 40 for letter in "gamhr")
        self.assertEqual(len(MODULE.GOV), 3)
        self.assertEqual(len(MODULE.A_PATHS), 7)
        self.assertEqual(len(MODULE.m_paths(a)), 4)
        self.assertEqual(len(MODULE.H_PATHS), 4)
        self.assertEqual(len(MODULE.r_paths()), 98)

        with patch.object(MODULE, "parents", return_value=[MODULE.H62]), patch.object(
            MODULE, "changed", return_value=MODULE.GOV + ["extra"]
        ):
            self._assert_gate_error(lambda: MODULE.verify_g(g, MODULE.load()))
        with patch.object(MODULE, "parents", return_value=[g]), patch.object(
            MODULE, "changed", return_value=MODULE.A_PATHS + ["extra"]
        ):
            self._assert_gate_error(lambda: MODULE.verify_a(a, g))
        with patch.object(MODULE, "parents", return_value=[a]), patch.object(
            MODULE, "changed", return_value=MODULE.m_paths(a) + ["extra"]
        ):
            self._assert_gate_error(lambda: MODULE.verify_m(m, a))
        with patch.object(MODULE, "parents", return_value=[m]), patch.object(
            MODULE, "changed", return_value=MODULE.H_PATHS + ["extra"]
        ):
            self._assert_gate_error(lambda: MODULE.verify_h(h, m, a, g))
        for forbidden in ("artifacts/v92-o01-formal/clock-failure.json", "artifacts/v92-o01-formal/failure.json"):
            with self.subTest(path=forbidden), patch.object(MODULE, "parents", return_value=[h]), patch.object(
                MODULE, "changed", return_value=sorted(MODULE.r_paths() + [forbidden])
            ):
                self._assert_gate_error(lambda: MODULE.verify_r(r, h, a, m))

    def test_reviews_require_empty_findings_and_exact_binding(self):
        a, tree = "a" * 40, "1" * 40
        valid = {
            "schema": "ese.v92.o01-review/v1", "role": "Sol",
            "reviewed_commit": a, "reviewed_tree": tree,
            "verdict": "APPROVE", "findings": [],
        }
        MODULE.validate_review(MODULE.canonical(valid), "Sol", a, tree)
        for key, value in (("findings", ["P2"]), ("verdict", "REJECT"), ("reviewed_commit", "b" * 40)):
            hostile = dict(valid)
            hostile[key] = value
            self._assert_gate_error(lambda hostile=hostile: MODULE.validate_review(MODULE.canonical(hostile), "Sol", a, tree))

    def test_autodetect_rejects_merges_and_intermediate_commits(self):
        with patch.object(MODULE, "git", return_value="x" * 40), patch.object(
            MODULE, "parents", return_value=["a" * 40, "b" * 40]
        ):
            self._assert_gate_error(lambda: MODULE.autodetect(MODULE.load()))

        chain = ["g" * 40, "a" * 40, "m" * 40, "h" * 40, "r" * 40, "x" * 40]
        ancestry = {chain[index]: [MODULE.H62 if index == 0 else chain[index - 1]] for index in range(len(chain))}
        with patch.object(MODULE, "git", return_value=chain[-1]), patch.object(
            MODULE, "parents", side_effect=lambda commit: ancestry[commit]
        ), patch.object(MODULE, "verify_g"), patch.object(MODULE, "verify_a"), patch.object(
            MODULE, "verify_m"
        ), patch.object(MODULE, "verify_h"):
            self._assert_gate_error(lambda: MODULE.autodetect(MODULE.load()))

    def test_cli_document_check_worktree_and_verify_modes(self):
        common = [
            patch.object(MODULE, "load", return_value=MODULE.expected_document()),
            patch.object(MODULE, "validate_document", return_value=True),
            patch.object(MODULE, "verify_historical_h38"),
            patch.object(MODULE, "verify_diagnostic_epoch"),
        ]
        for args, expected, verify_state in (
            (["verifier"], "state=DOCUMENT", None),
            (["verifier", "--check-worktree"], "state=DRAFT_WORKTREE", None),
            (["verifier", "--verify"], "state=A63", "A63"),
        ):
            with self.subTest(args=args), contextlib.ExitStack() as stack:
                for manager in common:
                    stack.enter_context(manager)
                stack.enter_context(patch.object(sys, "argv", args))
                stack.enter_context(patch.object(MODULE, "worktree_stats", return_value=True))
                stack.enter_context(patch.object(MODULE, "autodetect", return_value=verify_state or "unused"))
                stack.enter_context(patch.object(MODULE, "git", return_value=""))
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    self.assertEqual(MODULE.main(), 0)
                self.assertIn(expected, output.getvalue())


if __name__ == "__main__":
    unittest.main()
