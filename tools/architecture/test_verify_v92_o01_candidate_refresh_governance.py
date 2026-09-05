#!/usr/bin/env python3
"""Hostile offline tests for the G14/H66 candidate-refresh verifier."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import io
import json
import types
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
VERIFIER = ROOT / "tools/architecture/verify_v92_o01_candidate_refresh_governance.py"
SPEC = importlib.util.spec_from_file_location("v92_o01_candidate_refresh", VERIFIER)
assert SPEC is not None and SPEC.loader is not None
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)


class CandidateRefreshHostileTests(unittest.TestCase):
    def setUp(self) -> None:
        self.g14 = {
            "commit": "1" * 40,
            "tree": "2" * 40,
            "governance_sha256": {
                gate.DOCUMENT_PATH: "3" * 64,
                gate.TEST_PATH: "4" * 64,
                gate.VERIFIER_PATH: "5" * 64,
            },
        }
        self.offline = {
            "schema": "ese.v92.o01-candidate-refresh-offline-summary/v1",
            "status": "PASS_OFFLINE_ONLY_NOT_GATE",
            "release_gate": False,
            "physical_gate": "NOT_RUN",
            "promotion_authorized": False,
            "candidate_commit": gate.CANDIDATE,
            "candidate_tree": gate.CANDIDATE_TREE,
            "g14_commit": self.g14["commit"],
            "g14_tree": self.g14["tree"],
            "governance_sha256": copy.deepcopy(self.g14["governance_sha256"]),
            "harness_projection_sha256": gate.HARNESS_PROJECTION_SHA256,
            "runtime_bindings": copy.deepcopy(gate.RUNTIME_BINDINGS),
            "distribution_binding": copy.deepcopy(gate.DISTRIBUTION_BINDING),
            "tests": {
                "node22": {"tests": 143, "pass": 143, "fail": 0,
                             "exit_code": 0},
                "powershell": {"mocks": 4, "pass": 4, "fail": 0,
                                 "hyperv_executed": False,
                                 "release_gate_emitted": False,
                                 "exit_code": 0},
                "governance": {"tests": 49, "pass": 49, "fail": 0,
                                "positive_cases": 8, "negative_cases": 41,
                                "verify_g14_exit_code": 0},
            },
        }
        self.offline_sha = "6" * 64
        self.review = {
            "schema": "ese.v92.o01-candidate-refresh-review/v1",
            "reviewer_model": "sol",
            "independent": True,
            "verdict": "APPROVE",
            "findings": [],
            "candidate_commit": gate.CANDIDATE,
            "candidate_tree": gate.CANDIDATE_TREE,
            "g14_commit": self.g14["commit"],
            "g14_tree": self.g14["tree"],
            "governance_sha256": copy.deepcopy(self.g14["governance_sha256"]),
            "offline_summary_sha256": self.offline_sha,
            "runtime_bindings_sha256": gate.sha256(
                gate.canonical_sorted(gate.RUNTIME_BINDINGS)),
            "distribution_binding_sha256": gate.sha256(
                gate.canonical_sorted(gate.DISTRIBUTION_BINDING)),
            "physical_gate": "NOT_RUN",
            "promotion_authorized": False,
        }
        self.activation = {
            "schema": "ese.v92.o01-candidate-refresh-activation/v1",
            "status": "ACTIVATED_H66_PREPARED_NOT_RUN",
            "release_gate": False,
            "physical_gate": "NOT_RUN",
            "promotion_authorized": False,
            "evidence_reuse": False,
            "candidate_commit": gate.CANDIDATE,
            "candidate_tree": gate.CANDIDATE_TREE,
            "historical_h65_commit": gate.H65_COMMIT,
            "g14_commit": self.g14["commit"],
            "g14_tree": self.g14["tree"],
            "h66_parent_commit": self.g14["commit"],
            "governance_sha256": copy.deepcopy(self.g14["governance_sha256"]),
            "harness_projection_sha256": gate.HARNESS_PROJECTION_SHA256,
            "runtime_bindings": copy.deepcopy(gate.RUNTIME_BINDINGS),
            "distribution_binding": copy.deepcopy(gate.DISTRIBUTION_BINDING),
            "offline_summary_sha256": self.offline_sha,
            "review_sol_sha256": "7" * 64,
            "review_terra_sha256": "8" * 64,
        }

    def assertGateError(self, call) -> None:
        with self.assertRaises(gate.GateError):
            call()

    def run_formal_fixture(self, exercise, *,
                           source_head: str = gate.CANDIDATE,
                           source_tree: str = gate.CANDIDATE_TREE,
                           formal_state: dict[str, str] | None = None):
        h66 = "a" * 40
        g14 = {
            "commit": "b" * 40,
            "tree": "c" * 40,
            "governance_sha256": {},
        }
        activation = {"runtime_bindings": copy.deepcopy(gate.RUNTIME_BINDINGS)}
        h_state = {"activation": activation, "g14": g14}
        old_document = {"immutable_contract": {}}
        fake = types.SimpleNamespace()

        def git_text(command: str, value: str) -> str:
            self.assertEqual(command, "rev-parse")
            if value == "HEAD":
                return source_head
            if value == "HEAD^{tree}":
                return source_tree
            self.fail(f"unexpected git query: {value}")

        fake._git_text = git_text
        fake._blob = lambda *_args: b"old-governance"
        fake.load_json_bytes = lambda *_args: old_document
        fake.validate_document = lambda document: self.assertIs(
            document, old_document)
        fake._assert_python_runtime = lambda immutable: self.assertIs(
            immutable, old_document["immutable_contract"])

        def run_formal(args, document, immutable) -> int:
            return exercise(fake, args, document, immutable, h66, g14,
                            old_document)

        fake._run_formal_gate_and_emit = run_formal
        if formal_state is None:
            formal_state = {"physical_gate": "NOT_RUN",
                            "physical_execution": "NOT_RUN"}
        with mock.patch.object(gate, "load_g13", return_value=fake), \
                mock.patch.object(gate, "verify_g14", return_value=g14) as vg14, \
                mock.patch.object(gate, "verify_h66", return_value=h_state) as vh66:
            result = gate._formal_run(
                h66, str(gate.ROOT), str(gate.ROOT / "evidence"),
                str(gate.ROOT / "node.exe"), str(gate.ROOT / "credential"),
                formal_state)
        return result, g14, fake, old_document, vg14, vh66

    def test_01_strict_json_accepts_integer_object(self) -> None:
        self.assertEqual(gate.strict_json(b'{"a":1,"b":false}', "T"),
                         {"a": 1, "b": False})

    def test_02_strict_json_rejects_duplicate(self) -> None:
        self.assertGateError(lambda: gate.strict_json(b'{"a":1,"a":1}', "T"))

    def test_03_strict_json_rejects_float(self) -> None:
        self.assertGateError(lambda: gate.strict_json(b'{"a":1.0}', "T"))

    def test_04_strict_json_rejects_nan(self) -> None:
        self.assertGateError(lambda: gate.strict_json(b'{"a":NaN}', "T"))

    def test_05_strict_json_rejects_infinity(self) -> None:
        self.assertGateError(lambda: gate.strict_json(b'{"a":Infinity}', "T"))

    def test_06_strict_json_rejects_bom(self) -> None:
        self.assertGateError(lambda: gate.strict_json(b'\xef\xbb\xbf{}', "T"))

    def test_07_strict_json_rejects_scalar(self) -> None:
        self.assertGateError(lambda: gate.strict_json(b'1', "T"))

    def test_08_strict_json_rejects_array(self) -> None:
        self.assertGateError(lambda: gate.strict_json(b'[]', "T"))

    def test_09_document_is_strict_and_non_promoting(self) -> None:
        raw = gate.DOCUMENT.read_bytes()
        gate.validate_document(gate.strict_json(raw, "DOCUMENT"))
        self.assertEqual(hashlib.sha256(raw).hexdigest(), gate.DOCUMENT_SHA256)

    def test_10_document_rejects_extra_key(self) -> None:
        value = gate.strict_json(gate.DOCUMENT.read_bytes(), "DOCUMENT")
        value["extra"] = True
        self.assertGateError(lambda: gate.validate_document(value))

    def test_11_document_rejects_old_evidence_reuse(self) -> None:
        value = gate.strict_json(gate.DOCUMENT.read_bytes(), "DOCUMENT")
        value["historical_chain"]["physical_evidence_reusable"] = True
        self.assertGateError(lambda: gate.validate_document(value))

    def test_11b_document_rejects_nested_semantic_mutation(self) -> None:
        value = gate.strict_json(gate.DOCUMENT.read_bytes(), "DOCUMENT")
        value["topology"]["R66"]["resume_allowed"] = True
        self.assertGateError(lambda: gate.validate_document(value))

    def test_12_offline_accepts_closed_fixture(self) -> None:
        gate._validate_offline(self.offline, self.g14)

    def test_13_offline_rejects_extra_key(self) -> None:
        value = copy.deepcopy(self.offline)
        value["extra"] = 1
        self.assertGateError(lambda: gate._validate_offline(value, self.g14))

    def test_14_offline_rejects_release_true(self) -> None:
        value = copy.deepcopy(self.offline)
        value["release_gate"] = True
        self.assertGateError(lambda: gate._validate_offline(value, self.g14))

    def test_15_offline_rejects_physical_pass(self) -> None:
        value = copy.deepcopy(self.offline)
        value["physical_gate"] = "PASS"
        self.assertGateError(lambda: gate._validate_offline(value, self.g14))

    def test_16_offline_rejects_string_count(self) -> None:
        value = copy.deepcopy(self.offline)
        value["tests"]["node22"]["tests"] = "143"
        self.assertGateError(lambda: gate._validate_offline(value, self.g14))

    def test_17_offline_rejects_integer_false(self) -> None:
        value = copy.deepcopy(self.offline)
        value["tests"]["powershell"]["hyperv_executed"] = 0
        self.assertGateError(lambda: gate._validate_offline(value, self.g14))

    def test_18_offline_rejects_runtime_coercion(self) -> None:
        value = copy.deepcopy(self.offline)
        value["runtime_bindings"]["package_file_count"] = "277"
        self.assertGateError(lambda: gate._validate_offline(value, self.g14))

    def test_19_review_accepts_sol(self) -> None:
        gate._validate_review(self.review, "sol", self.g14, self.offline_sha)

    def test_20_review_accepts_independent_terra(self) -> None:
        value = copy.deepcopy(self.review)
        value["reviewer_model"] = "terra"
        gate._validate_review(value, "terra", self.g14, self.offline_sha)

    def test_21_review_rejects_findings(self) -> None:
        value = copy.deepcopy(self.review)
        value["findings"] = ["finding"]
        self.assertGateError(lambda: gate._validate_review(
            value, "sol", self.g14, self.offline_sha))

    def test_22_review_rejects_non_boolean_independence(self) -> None:
        value = copy.deepcopy(self.review)
        value["independent"] = 1
        self.assertGateError(lambda: gate._validate_review(
            value, "sol", self.g14, self.offline_sha))

    def test_23_review_rejects_wrong_offline_hash(self) -> None:
        value = copy.deepcopy(self.review)
        value["offline_summary_sha256"] = "9" * 64
        self.assertGateError(lambda: gate._validate_review(
            value, "sol", self.g14, self.offline_sha))

    def test_24_review_rejects_runtime_hash(self) -> None:
        value = copy.deepcopy(self.review)
        value["runtime_bindings_sha256"] = "9" * 64
        self.assertGateError(lambda: gate._validate_review(
            value, "sol", self.g14, self.offline_sha))

    def test_25_activation_accepts_closed_fixture(self) -> None:
        gate._validate_activation(self.activation, self.g14, self.offline_sha,
                                  "7" * 64, "8" * 64)

    def test_26_activation_rejects_extra_key(self) -> None:
        value = copy.deepcopy(self.activation)
        value["extra"] = 1
        self.assertGateError(lambda: gate._validate_activation(
            value, self.g14, self.offline_sha, "7" * 64, "8" * 64))

    def test_27_activation_rejects_release_true(self) -> None:
        value = copy.deepcopy(self.activation)
        value["release_gate"] = True
        self.assertGateError(lambda: gate._validate_activation(
            value, self.g14, self.offline_sha, "7" * 64, "8" * 64))

    def test_28_activation_rejects_evidence_reuse(self) -> None:
        value = copy.deepcopy(self.activation)
        value["evidence_reuse"] = True
        self.assertGateError(lambda: gate._validate_activation(
            value, self.g14, self.offline_sha, "7" * 64, "8" * 64))

    def test_29_activation_rejects_old_runtime(self) -> None:
        value = copy.deepcopy(self.activation)
        value["runtime_bindings"]["executable_sha256"] = "0" * 64
        self.assertGateError(lambda: gate._validate_activation(
            value, self.g14, self.offline_sha, "7" * 64, "8" * 64))

    def test_30_activation_rejects_review_substitution(self) -> None:
        value = copy.deepcopy(self.activation)
        value["review_terra_sha256"] = "7" * 64
        self.assertGateError(lambda: gate._validate_activation(
            value, self.g14, self.offline_sha, "7" * 64, "8" * 64))

    def test_31_exact_rejects_bool_integer_equivalence(self) -> None:
        self.assertGateError(lambda: gate.exact(1, True, "TYPE"))

    def test_32_canonical_runtime_identity_is_stable(self) -> None:
        value = gate.sha256(gate.canonical_sorted(gate.RUNTIME_BINDINGS))
        self.assertRegex(value, r"^[0-9a-f]{64}$")
        self.assertEqual(value, gate.sha256(gate.canonical_sorted(
            copy.deepcopy(gate.RUNTIME_BINDINGS))))

    def test_33_offline_rejects_boolean_governance_fail_count(self) -> None:
        value = copy.deepcopy(self.offline)
        value["tests"]["governance"]["fail"] = False
        self.assertGateError(lambda: gate._validate_offline(value, self.g14))

    def test_34_offline_rejects_boolean_governance_exit_code(self) -> None:
        value = copy.deepcopy(self.offline)
        value["tests"]["governance"]["verify_g14_exit_code"] = False
        self.assertGateError(lambda: gate._validate_offline(value, self.g14))

    def test_35_formal_run_rebinds_hardened_launcher_to_g14_h66(self) -> None:
        def exercise(fake, args, document, immutable, h66, g14,
                     old_document) -> int:
            self.assertEqual(args.h_commit, h66)
            self.assertEqual(args.package_root, str(
                gate.ROOT / "dist" / gate.TAG_NAME / "package"))
            self.assertIs(document, old_document)
            self.assertIs(immutable, old_document["immutable_contract"])
            fake.verify_m(g14["commit"], gate.CANDIDATE)
            fake.verify_h(h66, g14["commit"], gate.CANDIDATE,
                          gate.CANDIDATE_PARENT, document)
            rebound = fake._validate_runtime_bindings(
                copy.deepcopy(gate.RUNTIME_BINDINGS), object(), immutable)
            self.assertEqual(rebound, gate.RUNTIME_BINDINGS)
            self.assertIsNot(rebound, gate.RUNTIME_BINDINGS)
            return 0

        result, g14, fake, _document, vg14, vh66 = self.run_formal_fixture(
            exercise)
        self.assertEqual(result, 0)
        vg14.assert_called_once_with(fake, g14["commit"], disk_root=gate.ROOT)
        self.assertEqual(vh66.call_count, 2)

    def test_36_offline_rejects_reduced_hostile_suite(self) -> None:
        value = copy.deepcopy(self.offline)
        value["tests"]["governance"]["tests"] -= 1
        value["tests"]["governance"]["pass"] -= 1
        self.assertGateError(lambda: gate._validate_offline(value, self.g14))

    def test_37_formal_run_rejects_historical_h65_as_h66(self) -> None:
        def exercise(fake, _args, _document, _immutable, _h66, g14,
                     old_document) -> int:
            fake.verify_h(gate.H65_COMMIT, g14["commit"], gate.CANDIDATE,
                          gate.CANDIDATE_PARENT, old_document)
            return 0

        self.assertGateError(lambda: self.run_formal_fixture(exercise))

    def test_38_formal_run_rejects_wrong_g14(self) -> None:
        def exercise(fake, _args, _document, _immutable, _h66, _g14,
                     _old_document) -> int:
            fake.verify_m("d" * 40, gate.CANDIDATE)
            return 0

        self.assertGateError(lambda: self.run_formal_fixture(exercise))

    def test_39_formal_run_rejects_wrong_candidate_argument(self) -> None:
        def exercise(fake, _args, _document, _immutable, _h66, g14,
                     _old_document) -> int:
            fake.verify_m(g14["commit"], "d" * 40)
            return 0

        self.assertGateError(lambda: self.run_formal_fixture(exercise))

    def test_40_formal_run_rejects_wrong_candidate_parent(self) -> None:
        def exercise(fake, _args, _document, _immutable, h66, g14,
                     old_document) -> int:
            fake.verify_h(h66, g14["commit"], gate.CANDIDATE, "d" * 40,
                          old_document)
            return 0

        self.assertGateError(lambda: self.run_formal_fixture(exercise))

    def test_41_formal_run_rejects_document_substitution(self) -> None:
        def exercise(fake, _args, _document, _immutable, h66, g14,
                     old_document) -> int:
            fake.verify_h(h66, g14["commit"], gate.CANDIDATE,
                          gate.CANDIDATE_PARENT, copy.deepcopy(old_document))
            return 0

        self.assertGateError(lambda: self.run_formal_fixture(exercise))

    def test_42_formal_run_rejects_runtime_drift(self) -> None:
        def exercise(fake, _args, _document, immutable, _h66, _g14,
                     _old_document) -> int:
            value = copy.deepcopy(gate.RUNTIME_BINDINGS)
            value["executable_sha256"] = "0" * 64
            fake._validate_runtime_bindings(value, object(), immutable)
            return 0

        self.assertGateError(lambda: self.run_formal_fixture(exercise))

    def test_43_formal_run_rejects_wrong_source_head(self) -> None:
        self.assertGateError(lambda: self.run_formal_fixture(
            lambda *_args: 0, source_head="d" * 40))

    def test_44_formal_run_rejects_wrong_source_tree(self) -> None:
        self.assertGateError(lambda: self.run_formal_fixture(
            lambda *_args: 0, source_tree="d" * 40))

    def test_45_main_rejects_noncanonical_formal_argv(self) -> None:
        stderr = io.BytesIO()
        isolated = types.SimpleNamespace(
            isolated=1, no_site=1, ignore_environment=1, safe_path=True,
            dont_write_bytecode=1)
        with mock.patch.object(gate.sys, "flags", isolated), \
                mock.patch.object(gate.sys, "stderr",
                                  types.SimpleNamespace(buffer=stderr)):
            result = gate.main(["--formal-run", "--h66", "a" * 40,
                                "--source-root", str(gate.ROOT),
                                "--evidence-root", str(gate.ROOT / "evidence"),
                                "--node", str(gate.ROOT / "node.exe"),
                                "--credential-path", str(gate.ROOT / "credential"),
                                "--document"])
        self.assertEqual(result, 1)
        failure = json.loads(stderr.getvalue())
        self.assertEqual(failure["failure"], "ARGUMENTS")

    def test_46_pre_handoff_failure_reports_physical_not_run(self) -> None:
        stderr = io.BytesIO()
        isolated = types.SimpleNamespace(
            isolated=1, no_site=1, ignore_environment=1, safe_path=True,
            dont_write_bytecode=1)

        def fail_before(_h66, _source, _evidence, _node, _credential,
                        _state) -> int:
            raise gate.GateError("PRE_HANDOFF_REJECTION")

        argv = ["--formal-run", "--h66", "a" * 40,
                "--source-root", str(gate.ROOT),
                "--evidence-root", str(gate.ROOT / "evidence"),
                "--node", str(gate.ROOT / "node.exe"),
                "--credential-path", str(gate.ROOT / "credential")]
        with mock.patch.object(gate.sys, "flags", isolated), \
                mock.patch.object(gate.sys, "stderr",
                                  types.SimpleNamespace(buffer=stderr)), \
                mock.patch.object(gate, "_formal_run", side_effect=fail_before):
            result = gate.main(argv)
        self.assertEqual(result, 1)
        failure = json.loads(stderr.getvalue())
        self.assertEqual(failure["physical_gate"], "NOT_RUN")
        self.assertEqual(failure["physical_execution"], "NOT_RUN")

    def test_47_post_handoff_failure_never_reports_physical_not_run(self) -> None:
        stderr = io.BytesIO()
        isolated = types.SimpleNamespace(
            isolated=1, no_site=1, ignore_environment=1, safe_path=True,
            dont_write_bytecode=1)

        def fail_after(_h66, _source, _evidence, _node, _credential,
                       state) -> int:
            state["physical_gate"] = "NOT_PASS"
            state["physical_execution"] = "MAY_HAVE_STARTED"
            raise gate.GateError("POST_HANDOFF_FAILURE")

        argv = ["--formal-run", "--h66", "a" * 40,
                "--source-root", str(gate.ROOT),
                "--evidence-root", str(gate.ROOT / "evidence"),
                "--node", str(gate.ROOT / "node.exe"),
                "--credential-path", str(gate.ROOT / "credential")]
        with mock.patch.object(gate.sys, "flags", isolated), \
                mock.patch.object(gate.sys, "stderr",
                                  types.SimpleNamespace(buffer=stderr)), \
                mock.patch.object(gate, "_formal_run", side_effect=fail_after):
            result = gate.main(argv)
        self.assertEqual(result, 1)
        failure = json.loads(stderr.getvalue())
        self.assertEqual(failure["physical_gate"], "NOT_PASS")
        self.assertEqual(failure["physical_execution"], "MAY_HAVE_STARTED")

    def test_48_delegate_exception_marks_execution_uncertain(self) -> None:
        state = {"physical_gate": "NOT_RUN", "physical_execution": "NOT_RUN"}

        def fail_delegate(*_args) -> int:
            raise gate.GateError("DELEGATE_FAILURE")

        self.assertGateError(lambda: self.run_formal_fixture(
            fail_delegate, formal_state=state))
        self.assertEqual(state["physical_gate"], "NOT_PASS")
        self.assertEqual(state["physical_execution"], "MAY_HAVE_STARTED")


if __name__ == "__main__":
    unittest.main(verbosity=2)
