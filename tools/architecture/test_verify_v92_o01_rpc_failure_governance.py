#!/usr/bin/env python3
"""Hostile tests for the sealed G12/A64 governance verifier."""

from __future__ import annotations

import ast
import copy
import hashlib
import inspect
import json
import os
import py_compile
import re
import stat
import subprocess
import sys
import tempfile
import types
import unittest
import zipfile
from pathlib import Path
from unittest import mock


HERE = Path(__file__).resolve().parent
VERIFIER_PATH = HERE / "verify_v92_o01_rpc_failure_governance.py"
DOCUMENT_PATH = HERE.parents[1] / "docs/architecture/v92_o01_rpc_failure_governance_v1.json"
DOCUMENT_ASSIGNMENT = re.compile(br'(?m)^DOCUMENT_SHA256 = "[0-9a-f]{64}"$')


def load_authenticated_verifier(path: Path, expected_normalized_sha256: str):
    raw = path.read_bytes()
    normalized, count = DOCUMENT_ASSIGNMENT.subn(
        b'DOCUMENT_SHA256 = "' + (b"0" * 64) + b'"', raw,
    )
    if (count != 1 or
            hashlib.sha256(normalized).hexdigest() != expected_normalized_sha256):
        raise RuntimeError("sealed verifier source identity")
    code = compile(raw, str(path), "exec", dont_inherit=True, optimize=0)
    module = types.ModuleType("g12_verifier")
    module.__file__ = str(path)
    module.__package__ = None
    exec(code, module.__dict__)
    if path.read_bytes() != raw:
        raise RuntimeError("sealed verifier source changed")
    return module


DOCUMENT_BOOTSTRAP = json.loads(DOCUMENT_PATH.read_bytes().decode("utf-8"))
verifier = load_authenticated_verifier(
    VERIFIER_PATH,
    DOCUMENT_BOOTSTRAP["governance_tool_identity"]["verifier_normalized_sha256"],
)


class G12SealedGovernanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.document, cls.raw = verifier.load_json(verifier.DOCUMENT)
        cls.tuples, cls.codes, cls.tuple_strings = verifier.derive_rpc_allowlists()

    def mutated(self):
        return copy.deepcopy(self.document)

    def assert_rejected(self, document) -> None:
        with self.assertRaises(verifier.GateError):
            verifier.validate_document(document)

    @staticmethod
    def rpc_sample(pair="FORMAL_HOST:HOST_EXIT", code="O01_RPC_HOST_FAILED"):
        origin, stage = pair.split(":", 1)
        handled = 32 if origin == "LOCAL_PRODUCT" else 31
        return {
            "schema": "ese.v92.o01-rpc-failure/v1",
            "verdict": "FAIL",
            "release_gate": False,
            "origin": origin,
            "stage": stage,
            "failure_code": code,
            "requests_handled": handled,
            "next_sequence": handled + 1,
            "maximum_requests": 482,
            "host_exit_code": 1 if origin == "FORMAL_HOST" else None,
            "stderr_tail_chars": 73,
            "stderr_tail_utf8_bytes": 73,
            "stderr_tail_sha256": "a" * 64,
            "last_checkpoint_ordinal": 6,
            "last_checkpoint_record_sha256":
                "e8ad8bcbac7a1c7e7d40c6de39053a4a42c5dd4b50af845c6a65354e02683ae5",
            "last_checkpoint_file_sha256":
                "76ceb45c21aee4251f0447e892ef40fe9e38a68dde0db4222c1d9d12887bff73",
        }

    @staticmethod
    def runtime_bindings():
        return {
            "node_version": "22.23.2",
            "node_sha256": "0d0f5e39f9f3d9587bc19f73eab3c2c9c4903fd02d6dbf9c853dd81b3d95fad4",
            "executable_sha256": "a865743a3113b81e097d8f7f4cda14ef63524384e9cc60a2803a16c6da0962ab",
            "build_info_sha256": "60156884bbd154986930bdd6e38808c7a96161f98b78d01fb63c8945cd488b6f",
            "package_manifest_sha256": "7c284c58a55f01d9d7daf50a47c458f09990c7c79e6c7b9a9c2813736042941a",
            "package_manifest_entry_count": 274,
            "package_file_count": 275,
        }

    @staticmethod
    def build_bindings():
        zip_sha = "0ac7039b024c61ea1bde709a54eb7e9dd9e74b607dad091ec2820c2873910272"
        sidecar = (zip_sha.upper() + "  " + verifier.PACKAGE_ZIP_BASENAME + "\r\n").encode("ascii")
        return {
            "release_tag": verifier.RELEASE_TAG,
            "package_zip_path": verifier.PACKAGE_ZIP_PATH,
            "package_zip_sha256": zip_sha,
            "package_zip_bytes": 213389864,
            "package_zip_entry_count": 275,
            "package_zip_sidecar_path": verifier.PACKAGE_ZIP_SIDECAR_PATH,
            "package_zip_sidecar_bytes": len(sidecar),
            "package_zip_sidecar_sha256": verifier.sha256(sidecar),
        }

    @classmethod
    def gate_records(cls):
        runtime = cls.runtime_bindings()
        build = cls.build_bindings()
        a_commit = verifier.BASE["a63_commit"]
        a_tree = verifier.BASE["a63_tree"]
        m_commit = verifier.BASE["m63_commit"]
        m_tree = verifier.BASE["m63_tree"]
        records = []
        for name, phase, argv, _ in verifier.OFFLINE_GATES:
            gate_result = verifier._gate_result(
                name, runtime, build, a_commit, a_tree, m_commit, m_tree,
            )
            source_commit, source_tree = ((a_commit, a_tree) if phase == "A64" else
                                          (m_commit, m_tree))
            stdout_sha = "a" * 64
            stderr_sha = "b" * 64
            if name in {"G12_HOSTILE", "G12_VERIFY", "NODE22_FULL", "A64_FOCAL",
                        "POWERSHELL_PARSE", "BUILD_ALL", "PACKAGE_AUDIT",
                        "MOD02_RUNTIME", "RPC_PUMP_MOCK", "FORMAL_RUNNER_MOCK",
                        "VM_SESSION_MOCK", "FORMAL_PRODUCT_MOCK", "DIFF_CHECK"}:
                stdout_sha = verifier.sha256(
                    json.dumps(gate_result, sort_keys=True,
                               separators=(",", ":")).encode("ascii") + b"\n"
                )
            cwd = verifier._gate_cwd(name)
            records.append({
                "evidence_kind": "REVIEW_ATTESTED_EXECUTION", "name": name,
                "phase": phase, "source_commit": source_commit,
                "source_tree": source_tree, "input_worktree_state": "CLEAN",
                "normalized_cwd": cwd,
                "cwd_sha256": verifier.sha256(verifier.canonical(cwd)),
                "normalized_argv": list(argv),
                "argv_sha256": verifier.sha256(verifier.canonical(list(argv))),
                "exit_code": 0, "result": gate_result,
                "stdout_sha256": stdout_sha, "stderr_sha256": stderr_sha,
            })
        return records, runtime, build, a_commit, a_tree, m_commit, m_tree

    def test_01_document_self_identity_and_exact_freeze(self) -> None:
        verifier.validate_document(self.document)
        self.assertEqual(verifier.sha256(self.raw), verifier.DOCUMENT_SHA256)
        surface = self.document["functional_surface"]
        self.assertEqual(surface["frozen_paths"], verifier.A_PATHS)
        self.assertEqual(surface["path_sha256"], verifier.A_SHA256)
        self.assertEqual(surface["per_path_numstat"],
                         verifier.budget_document(verifier.PATH_BUDGET))
        self.assertEqual(surface["budget"]["all"]["headroom"], 0)
        verifier.verify_governance_tool_identity(
            self.document, lambda path: (verifier.REPO / path).read_bytes(),
        )
        hostile = self.mutated()
        hostile["governance_tool_identity"]["hostile_test_sha256"] = "0" * 64
        with self.assertRaises(verifier.GateError):
            verifier.verify_governance_tool_identity(
                hostile, lambda path: (verifier.REPO / path).read_bytes(),
            )

    def test_02_history_and_immutable_blobs_are_exact(self) -> None:
        verifier.verify_history(self.document)
        immutable = self.document["immutable_contract"]
        self.assertEqual(immutable["scenario_blob"],
                         "720a1359ebdab210f7a670963fb721fc2b8b878f")
        self.assertEqual(immutable["product_mapper_blob"],
                         "bf2494f1b61a27ca0e2af5e4d0197d2137cb06d6")
        self.assertEqual(immutable["initial_rpc_watchdog_ms"], 300000)
        self.assertEqual(immutable["subsequent_rpc_watchdog_ms"], 140000)

    def test_03_every_closed_rpc_tuple_is_accepted(self) -> None:
        observed = 0
        for pair, codes in self.tuples.items():
            for code in codes:
                with self.subTest(pair=pair, code=code):
                    verifier.validate_rpc_failure(self.rpc_sample(pair, code))
                observed += 1
        self.assertEqual(observed, 158)
        self.assertEqual(len(self.codes), 158)
        self.assertEqual(len(self.tuple_strings), 158)

    def test_04_cross_tuple_unknown_and_open_codes_are_rejected(self) -> None:
        pairs = list(self.tuples)
        for index, pair in enumerate(pairs):
            wrong_pair = pairs[(index + 1) % len(pairs)]
            wrong_code = self.tuples[wrong_pair][0]
            with self.subTest(pair=pair, wrong_code=wrong_code), self.assertRaises(verifier.GateError):
                verifier.validate_rpc_failure(self.rpc_sample(pair, wrong_code))
        for code in ("O01_UNKNOWN_CLOSED_LOOKING", "secret path C:\\private"):
            with self.subTest(code=code), self.assertRaises(verifier.GateError):
                verifier.validate_rpc_failure(self.rpc_sample(code=code))

    def test_05_origin_exit_contract_is_exact(self) -> None:
        cases = []
        host = self.rpc_sample()
        host["host_exit_code"] = None
        cases.append(host)
        host = self.rpc_sample()
        host["host_exit_code"] = 0
        cases.append(host)
        local = self.rpc_sample("LOCAL_PRODUCT:PRODUCT_READ",
                                self.tuples["LOCAL_PRODUCT:PRODUCT_READ"][0])
        local["host_exit_code"] = 1
        cases.append(local)
        for stage in ("REQUEST_PARSE", "REQUEST_WAIT", "RESPONSE_WRITE"):
            pair = f"RPC_PUMP:{stage}"
            pump = self.rpc_sample(pair, self.tuples[pair][0])
            pump["host_exit_code"] = 0
            cases.append(pump)
        for case in cases:
            with self.subTest(case=cases.index(case)), self.assertRaises(verifier.GateError):
                verifier.validate_rpc_failure(case)

    def test_06_request_and_checkpoint_causality_boundaries(self) -> None:
        host = self.rpc_sample()
        host["requests_handled"] = 6
        host["next_sequence"] = 7
        host["last_checkpoint_ordinal"] = 1
        verifier.validate_rpc_failure(host)
        local_code = self.tuples["LOCAL_PRODUCT:PRODUCT_READ"][0]
        local = self.rpc_sample("LOCAL_PRODUCT:PRODUCT_READ", local_code)
        local["requests_handled"] = 6
        local["next_sequence"] = 7
        local["last_checkpoint_ordinal"] = 1
        with self.assertRaises(verifier.GateError):
            verifier.validate_rpc_failure(local)
        local["requests_handled"] = 7
        local["next_sequence"] = 8
        verifier.validate_rpc_failure(local)
        local["requests_handled"] = 0
        local["next_sequence"] = 1
        local["last_checkpoint_ordinal"] = 0
        local["last_checkpoint_record_sha256"] = None
        local["last_checkpoint_file_sha256"] = None
        with self.assertRaises(verifier.GateError):
            verifier.validate_rpc_failure(local)

    def test_07_sequence_integer_and_boolean_forgery_is_rejected(self) -> None:
        mutations = []
        for key, value in (
            ("requests_handled", True), ("maximum_requests", 483),
            ("next_sequence", 484), ("last_checkpoint_ordinal", 96),
        ):
            sample = self.rpc_sample()
            sample[key] = value
            mutations.append(sample)
        sample = self.rpc_sample()
        sample["next_sequence"] = sample["requests_handled"]
        mutations.append(sample)
        for sample in mutations:
            with self.subTest(sample=mutations.index(sample)), self.assertRaises(verifier.GateError):
                verifier.validate_rpc_failure(sample)

    def test_08_stderr_three_way_relation_and_bounds_are_exact(self) -> None:
        empty = self.rpc_sample()
        empty["stderr_tail_chars"] = 0
        empty["stderr_tail_utf8_bytes"] = 0
        empty["stderr_tail_sha256"] = verifier.EMPTY_SHA256
        verifier.validate_rpc_failure(empty)
        mutations = []
        for chars, byte_count, digest in (
            (0, 1, verifier.EMPTY_SHA256),
            (0, 0, "a" * 64),
            (1, 1, verifier.EMPTY_SHA256),
            (2, 1, "a" * 64),
            (16385, 16385, "a" * 64),
            (1, 49153, "a" * 64),
        ):
            sample = self.rpc_sample()
            sample["stderr_tail_chars"] = chars
            sample["stderr_tail_utf8_bytes"] = byte_count
            sample["stderr_tail_sha256"] = digest
            mutations.append(sample)
        for sample in mutations:
            with self.subTest(sample=mutations.index(sample)), self.assertRaises(verifier.GateError):
                verifier.validate_rpc_failure(sample)

    def test_09_checkpoint_nullability_and_privacy_are_closed(self) -> None:
        zero = self.rpc_sample()
        zero["last_checkpoint_ordinal"] = 0
        zero["last_checkpoint_record_sha256"] = None
        zero["last_checkpoint_file_sha256"] = None
        verifier.validate_rpc_failure(zero)
        half = copy.deepcopy(zero)
        half["last_checkpoint_record_sha256"] = "a" * 64
        with self.assertRaises(verifier.GateError):
            verifier.validate_rpc_failure(half)
        for key in verifier.FORBIDDEN_RPC_FIELDS:
            hostile = self.rpc_sample()
            hostile[key] = "private"
            with self.subTest(key=key), self.assertRaises(verifier.GateError):
                verifier.validate_rpc_failure(hostile)

    def test_10_document_pin_budget_causal_and_threat_mutations_fail(self) -> None:
        cases = []
        mutations = (
            ("status", lambda v: v.__setitem__("status", "DRAFT")),
            ("path", lambda v: v["functional_surface"]["frozen_paths"].pop()),
            ("sha", lambda v: v["functional_surface"]["path_sha256"].__setitem__(
                verifier.A_PATHS[0], "0" * 64)),
            ("budget", lambda v: v["functional_surface"]["budget"]["all"].__setitem__(
                "headroom", 1)),
            ("budget-bool", lambda v: v["functional_surface"]["budget"]["all"].__setitem__(
                "headroom", False)),
            ("numstat-bool", lambda v: v["functional_surface"]["per_path_numstat"]
             ["tools/lab/nat_gateway/test/v92_o01_t8_daemon.test.js"].__setitem__(
                 "delete", True)),
            ("checkpoint-count-float", lambda v: v["diagnostic_attempt"].__setitem__(
                "checkpoint_count", 6.0)),
            ("checkpoint-ordinal-bool", lambda v: v["diagnostic_attempt"]
             ["checkpoint_ordinals"].__setitem__(0, True)),
            ("phase-release-bool", lambda v: v["phase_contract"]["R64"].__setitem__(
                "release_gate", 1)),
            ("bound-bool", lambda v: v["rpc_failure_contract"]["integer_bounds"]
             ["requests_handled"].__setitem__(0, False)),
            ("causal", lambda v: v["functional_surface"]["causal_closure"].__setitem__(
                "historical_attribution", "fallback proves root cause")),
            ("threat", lambda v: v["threat_model"].__setitem__(
                "claim_limit", "universal protection")),
            ("tuple", lambda v: v["rpc_failure_contract"]["origin_stage_pairs"].pop()),
            ("codehash", lambda v: v["rpc_failure_contract"]["code_allowlist"].__setitem__(
                "code_allowlist_sha256", "0" * 64)),
            ("watchdog", lambda v: v["immutable_contract"].__setitem__(
                "initial_rpc_watchdog_ms", 300001)),
            ("activation", lambda v: v["h64_activation_contract"]["required_exact_keys"].pop()),
            ("gate-cwd", lambda v: v["gate_attestation_contract"].__setitem__(
                "cwd_normalization", "ambient cwd")),
        )
        for _, mutate in mutations:
            value = self.mutated()
            mutate(value)
            cases.append(value)
        for case in cases:
            with self.subTest(case=cases.index(case)):
                self.assert_rejected(case)

    def test_11_a163_is_non_release_and_not_reusable(self) -> None:
        attempt = self.document["diagnostic_attempt"]
        self.assertFalse(attempt["release_gate"])
        self.assertEqual(attempt["evidence_reuse"], "FORBIDDEN")
        self.assertEqual(attempt["checkpoint_ordinals"], list(range(1, 7)))
        for key, value in (("release_gate", True), ("evidence_reuse", "ALLOWED")):
            hostile = self.mutated()
            hostile["diagnostic_attempt"][key] = value
            self.assert_rejected(hostile)

    def test_12_r64_is_exact98_and_forbids_failure_artifacts(self) -> None:
        paths = [f"checkpoint-{ordinal:02d}.json" for ordinal in range(1, 96)] + [
            "controller-result.json", "formal-run-result.json", "formal-validation.json",
        ]
        verifier.validate_r64_paths(paths)
        for forbidden in ("failure.json", "clock-failure.json", "rpc-failure.json"):
            with self.subTest(forbidden=forbidden), self.assertRaises(verifier.GateError):
                verifier.validate_r64_paths(paths[:-1] + [forbidden])

    def test_13_h64_gate_review_runtime_and_run_v2_bindings_are_closed(self) -> None:
        records, runtime, build, a_commit, a_tree, m_commit, m_tree = self.gate_records()
        gate_sha = verifier._validate_gate_records(
            records, a_commit, a_tree, m_commit, m_tree, runtime, build,
        )
        self.assertEqual(gate_sha, verifier.sha256(verifier.canonical(records)))
        manifest = {"executable_sha256": runtime["executable_sha256"]}
        verifier._validate_runtime_bindings(
            runtime, manifest, self.document["immutable_contract"],
        )
        verifier._validate_build_artifact_bindings(build, runtime)
        with tempfile.TemporaryDirectory(prefix="g12-zip-hostile-") as temporary:
            root = Path(temporary)
            package_root = root / "package"
            package_root.mkdir()
            package_payload = b"manifested"
            (package_root / "file.txt").write_bytes(package_payload)
            (package_root / "SHA256SUMS.txt").write_bytes(
                (verifier.sha256(package_payload).upper() + "  file.txt\r\n").encode("ascii")
            )
            verifier._audit_package_manifest(package_root)
            empty_directory = package_root / "UNMANIFESTED_EMPTY"
            empty_directory.mkdir()
            with self.assertRaises(verifier.GateError):
                verifier._audit_package_manifest(package_root)
            archive_path = root / "base.zip"
            payload = b"data"
            with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("file.txt", payload)
            archive_bytes = bytearray(archive_path.read_bytes())
            initial_eocd = archive_bytes.rfind(b"PK\x05\x06")
            initial_central = int.from_bytes(
                archive_bytes[initial_eocd + 16:initial_eocd + 20], "little",
            )
            archive_bytes[initial_central + 4:initial_central + 6] = (20).to_bytes(2, "little")
            archive_bytes[initial_central + 36:initial_central + 42] = b"\0" * 6
            archive_path.write_bytes(archive_bytes)
            expected_hashes = {"file.txt": verifier.sha256(payload)}
            expected_sizes = {"file.txt": len(payload)}
            verifier._audit_zip(archive_path, expected_hashes, expected_sizes)
            archive_raw = archive_path.read_bytes()
            eocd_offset = archive_raw.rfind(b"PK\x05\x06")
            central_offset = int.from_bytes(archive_raw[eocd_offset + 16:eocd_offset + 20],
                                            "little")
            name_length = int.from_bytes(archive_raw[26:28], "little")
            extra_length = int.from_bytes(archive_raw[28:30], "little")
            compressed_size = int.from_bytes(archive_raw[18:22], "little")
            compressed_end = 30 + name_length + extra_length + compressed_size
            hidden = b"SECRET"
            embedded = bytearray(
                archive_raw[:compressed_end] + hidden + archive_raw[compressed_end:]
            )
            embedded[18:22] = (compressed_size + len(hidden)).to_bytes(4, "little")
            shifted_central = central_offset + len(hidden)
            embedded[shifted_central + 20:shifted_central + 24] = \
                (compressed_size + len(hidden)).to_bytes(4, "little")
            shifted_eocd = eocd_offset + len(hidden)
            embedded[shifted_eocd + 16:shifted_eocd + 20] = \
                shifted_central.to_bytes(4, "little")
            malformed_deflate = bytearray(archive_raw)
            malformed_deflate[30 + name_length + extra_length] = 0x07
            zero_date = bytearray(archive_raw)
            zero_date[10:14] = b"\0" * 4
            zero_date[central_offset + 12:central_offset + 16] = b"\0" * 4
            for name, hostile_raw in (
                ("prefix.zip", b"SECRET" + archive_raw),
                ("suffix.zip", archive_raw + b"SECRET"),
                ("embedded-deflate.zip", bytes(embedded)),
                ("malformed-deflate.zip", bytes(malformed_deflate)),
                ("zero-date.zip", bytes(zero_date)),
            ):
                hostile_path = root / name
                hostile_path.write_bytes(hostile_raw)
                with self.subTest(zip_container=name), self.assertRaises(verifier.GateError):
                    verifier._audit_zip(hostile_path, expected_hashes, expected_sizes)
        for field, value in (
            ("normalized_cwd", "<WRONG>"), ("cwd_sha256", "0" * 64),
            ("normalized_argv", ["forged"]), ("argv_sha256", "0" * 64),
            ("source_commit", "0" * 40), ("source_tree", "0" * 40),
            ("input_worktree_state", "DIRTY"), ("exit_code", True),
            ("stdout_sha256", "0" * 64),
        ):
            hostile = copy.deepcopy(records)
            hostile[0][field] = value
            with self.subTest(field=field), self.assertRaises(verifier.GateError):
                verifier._validate_gate_records(
                    hostile, a_commit, a_tree, m_commit, m_tree, runtime, build,
                )
        hostile = copy.deepcopy(records)
        node_index = next(index for index, row in enumerate(hostile)
                          if row["name"] == "NODE22_FULL")
        hostile[node_index]["result"]["failed"] = False
        with self.assertRaises(verifier.GateError):
            verifier._validate_gate_records(
                hostile, a_commit, a_tree, m_commit, m_tree, runtime, build,
            )
        hostile_runtime = copy.deepcopy(runtime)
        hostile_runtime["package_file_count"] = runtime["package_manifest_entry_count"]
        with self.assertRaises(verifier.GateError):
            verifier._validate_runtime_bindings(
                hostile_runtime, manifest, self.document["immutable_contract"],
            )
        hostile_build = copy.deepcopy(build)
        hostile_build["package_zip_entry_count"] -= 1
        with self.assertRaises(verifier.GateError):
            verifier._validate_build_artifact_bindings(hostile_build, runtime)

        offline_sha = "1" * 64
        runtime_sha = verifier.sha256(verifier.canonical(runtime))
        build_sha = verifier.sha256(verifier.canonical(build))
        review = {
            "schema": "ese.v92.o01-review/v2", "role": "Sol",
            "g_commit": verifier.BASE["g11_commit"], "g_tree": verifier.BASE["g11_tree"],
            "a_commit": a_commit, "a_tree": a_tree,
            "m_commit": m_commit, "m_tree": m_tree,
            "offline_summary_sha256": offline_sha,
            "gate_attestations_sha256": gate_sha,
            "runtime_bindings_sha256": runtime_sha,
            "build_artifact_bindings_sha256": build_sha,
            "verdict": "APPROVE", "findings": [],
        }
        review_raw = verifier.ordered_canonical(review) + b"\n"
        verifier._validate_review(
            review_raw, "Sol", verifier.BASE["g11_commit"], verifier.BASE["g11_tree"],
            a_commit, a_tree, m_commit, m_tree, offline_sha, gate_sha,
            runtime_sha, build_sha,
        )
        forged_review = copy.deepcopy(review)
        forged_review["offline_summary_sha256"] = "2" * 64
        with self.assertRaises(verifier.GateError):
            verifier._validate_review(
                verifier.ordered_canonical(forged_review) + b"\n", "Sol",
                verifier.BASE["g11_commit"], verifier.BASE["g11_tree"],
                a_commit, a_tree, m_commit, m_tree, offline_sha, gate_sha,
                runtime_sha, build_sha,
            )

        run = {
            "schema": "ese.v92.o01-formal-run/v2", "verdict": "PASS",
            "release_gate": True, "source_commit": a_commit, "source_tree": a_tree,
            "governance_h_commit": verifier.BASE["h63_commit"],
            "governance_s_commit": None, **runtime, "duration_ms": 28800000,
            "product_records": 482, "checkpoints": 95, "fault_slots": 96,
            "baseline_restored": True, "independent_validation": True,
        }
        verifier._validate_formal_run(
            run, runtime, a_commit, a_tree, verifier.BASE["h63_commit"],
        )
        for field, value in (
            ("node_version", "22.23.1"), ("package_manifest_entry_count", True),
            ("package_file_count", 274), ("release_gate", 1),
        ):
            hostile_run = copy.deepcopy(run)
            hostile_run[field] = value
            with self.subTest(run_field=field), self.assertRaises(verifier.GateError):
                verifier._validate_formal_run(
                    hostile_run, runtime, a_commit, a_tree, verifier.BASE["h63_commit"],
                )

    def test_14_duplicate_json_keys_and_noncanonical_encoding_fail(self) -> None:
        with self.assertRaises(verifier.GateError):
            verifier.load_json_bytes(b'{"schema":1,"schema":2}\n', "duplicate")
        for raw in (b'\xef\xbb\xbf{}\n', b'{}\r\n', b'{}'):
            with self.subTest(raw=raw), self.assertRaises(verifier.GateError):
                verifier.load_json_bytes(raw, "encoding")

    def test_15_worktree_or_committed_phase_is_exact(self) -> None:
        dirty = verifier._git_text(
            "status", "--porcelain", "--untracked-files=all",
            "--ignore-submodules=dirty",
        ) != ""
        if dirty:
            verifier.verify_check_worktree(self.document, self.raw)
            self.assertEqual(verifier._changed_paths(),
                             set(verifier.GOVERNANCE_PATHS) | set(verifier.A_PATHS))
        else:
            self.assertIn(verifier.autodetect(self.document),
                          {"G12", "A64", "M64", "H64", "R64"})

    def test_16_cli_is_state_adaptive_and_fail_closed(self) -> None:
        dirty = verifier._git_text(
            "status", "--porcelain", "--untracked-files=all",
            "--ignore-submodules=dirty",
        ) != ""
        cases = [("--document", 0, "DOCUMENT")]
        if dirty:
            cases.extend((("--check-worktree", 0, "SEALED_WORKTREE"),
                          ("--verify", 1, None)))
        else:
            cases.append(("--verify", 0, verifier.autodetect(self.document)))
        for option, expected_code, expected_state in cases:
            process = subprocess.run(
                [sys.executable, "-I", "-S", "-B", str(VERIFIER_PATH), option],
                cwd=verifier.REPO, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, check=False,
            )
            payload = json.loads(process.stdout)
            with self.subTest(option=option):
                self.assertEqual(process.returncode, expected_code, process.stdout)
                if expected_state is not None:
                    self.assertEqual(payload["verdict"], "PASS")
                    self.assertEqual(payload["state"], expected_state)
                else:
                    self.assertEqual(payload["verdict"], "FAIL")
                    self.assertIn("dirty", payload["reason"])
                    self.assertNotIn("pending", payload["reason"].lower())

    def test_17_formal_launch_receipt_guard_and_contract_are_closed(self) -> None:
        verifier.validate_document(self.document)
        self.assertEqual(self.document["formal_launch_contract"],
                         verifier.FORMAL_LAUNCH_CONTRACT)
        for field in ("stream_rule", "cleanup_rule"):
            hostile = self.mutated()
            hostile["formal_launch_contract"][field] += " forged"
            with self.subTest(contract_field=field):
                self.assert_rejected(hostile)
        hostile = self.mutated()
        hostile["formal_launch_contract"]["receipt_exact_keys"].pop()
        self.assert_rejected(hostile)

        def child_argv(stdout: bytes, stderr: bytes = b"",
                       returncode: int = 0) -> list[str]:
            script = (
                "import sys;"
                f"sys.stdout.buffer.write({stdout!r});"
                f"sys.stderr.buffer.write({stderr!r});"
                f"raise SystemExit({returncode})"
            )
            return [sys.executable, "-I", "-S", "-B", "-c", script]

        nominal_receipt = b'{"schema":"probe"}\r\n'
        with tempfile.TemporaryDirectory(prefix="g12-launch-closed-") as temporary:
            root = Path(temporary)
            environment = dict(verifier.os.environ)
            returncode, parsed = verifier._capture_formal_runner_receipt(
                child_argv(nominal_receipt), root, environment,
            )
            self.assertEqual(returncode, 0)
            self.assertEqual(parsed, {"schema": "probe"})

            malformed = (
                ("lf", b'{"schema":"probe"}\n', b"", 0),
                ("bom", b'\xef\xbb\xbf{"schema":"probe"}\r\n', b"", 0),
                ("two-lines", nominal_receipt + nominal_receipt, b"", 0),
                ("duplicate", b'{"schema":1,"schema":2}\r\n', b"", 0),
                ("return-code", nominal_receipt, b"", 1),
            )
            for name, stdout, stderr, returncode in malformed:
                with self.subTest(receipt=name), self.assertRaises(verifier.GateError):
                    verifier._capture_formal_runner_receipt(
                        child_argv(stdout, stderr, returncode), root, environment,
                    )

            secret = b"SECRET_STDERR_MUST_NOT_SURVIVE"
            with self.assertRaises(verifier.GateError) as secret_failure:
                verifier._capture_formal_runner_receipt(
                    child_argv(nominal_receipt, secret), root, environment,
                )
            self.assertNotIn(secret.decode("ascii"), str(secret_failure.exception))

            oversize_script = (
                "import sys;sys.stdout.buffer.write(b'A' * "
                f"{verifier.MAX_FORMAL_LAUNCH_RECEIPT_BYTES + 1} + b'\\r\\n')"
            )
            with self.assertRaises(verifier.GateError):
                verifier._capture_formal_runner_receipt(
                    [sys.executable, "-I", "-S", "-B", "-c", oversize_script],
                    root, environment,
                )
            self.assertEqual(list(root.iterdir()), [])

            original_start = verifier.threading.Thread.start
            start_count = [0]

            def fail_second_worker_start(thread, *args, **kwargs):
                start_count[0] += 1
                if start_count[0] == 2:
                    raise RuntimeError("SECRET_THREAD_START")
                return original_start(thread, *args, **kwargs)

            with mock.patch.object(
                    verifier.threading.Thread, "start",
                    new=fail_second_worker_start), mock.patch.object(
                        verifier.subprocess, "Popen") as popen:
                with self.assertRaises(verifier.GateError) as worker_failure:
                    verifier._capture_formal_runner_receipt(
                        child_argv(nominal_receipt), root, environment,
                    )
                popen.assert_not_called()
            self.assertEqual(start_count[0], 2)
            self.assertNotIn("SECRET_THREAD_START", str(worker_failure.exception))
            self.assertFalse(any(
                thread.name == "g12-formal-stdout" and thread.is_alive()
                for thread in verifier.threading.enumerate()
            ))

            evidence_root = root / "eSE-v9.2-o01-formal-0123456789ab"
            controller = evidence_root / "controller"
            controller.mkdir(parents=True)
            names = [f"checkpoint-{ordinal:02d}.json" for ordinal in range(1, 96)] + [
                "controller-result.json", "formal-run-result.json",
                "formal-validation.json",
            ]
            artifacts = {}
            for name in names:
                payload = (f'{{"artifact":"{name}"}}\r\n').encode("ascii")
                (controller / name).write_bytes(payload)
                artifacts[name] = payload
            metadata_limit = 2 * 1024 * 1024
            plan_raw = b"P" * (metadata_limit - 2) + b"\r\n"
            state_raw = b'{"phase":"TORN_DOWN"}\r\n'
            (evidence_root / "plan.json").write_bytes(plan_raw)
            (evidence_root / "state.json").write_bytes(state_raw)

            with verifier._formal_evidence_read_guard(controller) as held:
                guarded, metadata_guarded = held
                cache = verifier._read_formal_evidence_guard(guarded)
                self.assertEqual(len(cache), 98)
                self.assertEqual(set(cache), set(names))
                metadata = verifier._formal_evidence_root_metadata(
                    evidence_root, metadata_guarded,
                )
                self.assertEqual(metadata["plan.json"], plan_raw)
                self.assertEqual(metadata["state.json"], state_raw)

                expected_receipt = verifier._expected_formal_launch_receipt(
                    cache, metadata, "a" * 40, "b" * 40, "c" * 40,
                )
                self.assertEqual(list(expected_receipt),
                                 verifier.FORMAL_LAUNCH_RECEIPT_KEYS)
                self.assertEqual(expected_receipt["artifact_count"], 98)
                self.assertFalse(expected_receipt["raw_streams_retained"])
                verifier.require_exact_value(
                    expected_receipt,
                    verifier._expected_formal_launch_receipt(
                        cache, metadata, "a" * 40, "b" * 40, "c" * 40,
                    ),
                    "formal launch receipt",
                )
                forged_receipt = copy.deepcopy(expected_receipt)
                forged_receipt["raw_streams_retained"] = True
                with self.assertRaises(verifier.GateError):
                    verifier.require_exact_value(
                        forged_receipt, expected_receipt, "formal launch receipt",
                    )

                for guarded_path in (
                        controller / "checkpoint-01.json",
                        evidence_root / "plan.json"):
                    with self.subTest(guarded_path=guarded_path.name), \
                            self.assertRaises(OSError):
                        guarded_path.write_bytes(b"forged")

                extra = controller / "extra.json"
                extra.write_bytes(b"extra")
                try:
                    with self.assertRaises(verifier.GateError):
                        verifier._assert_formal_evidence_guard_unchanged(
                            controller, guarded, cache,
                        )
                finally:
                    extra.unlink()
                verifier._assert_formal_evidence_guard_unchanged(
                    controller, guarded, cache,
                )

            checkpoint_one = controller / "checkpoint-01.json"
            checkpoint_one.write_bytes(b"released\r\n")
            checkpoint_one.write_bytes(artifacts["checkpoint-01.json"])
            state_path = evidence_root / "state.json"
            state_path.write_bytes(b'{"phase":"TORN_DOWN"}\n')
            with self.assertRaises(verifier.GateError):
                verifier._formal_evidence_root_metadata(evidence_root)
            state_path.write_bytes(state_raw)
            plan_path = evidence_root / "plan.json"
            plan_path.write_bytes(b"P" * (metadata_limit + 1))
            with self.assertRaises(verifier.GateError):
                verifier._formal_evidence_root_metadata(evidence_root)
            plan_path.write_bytes(plan_raw)

            checkpoint_fifty = controller / "checkpoint-50.json"
            with checkpoint_fifty.open("r+b", buffering=0):
                with self.assertRaises(verifier.GateError):
                    with verifier._formal_evidence_read_guard(controller):
                        pass
                checkpoint_one.write_bytes(b"partial acquisition released\r\n")
                checkpoint_one.write_bytes(artifacts["checkpoint-01.json"])

            unowned = {}
            with self.assertRaisesRegex(RuntimeError, "unowned failure"):
                with verifier._invalidate_formal_pass_on_failure(
                        evidence_root, unowned):
                    raise RuntimeError("unowned failure")
            self.assertTrue((controller / "formal-run-result.json").is_file())
            self.assertTrue((controller / "formal-validation.json").is_file())

            ownership = {}
            with self.assertRaisesRegex(RuntimeError, "owned failure"):
                with verifier._invalidate_formal_pass_on_failure(
                        evidence_root, ownership), \
                        verifier._formal_evidence_read_guard(
                            controller, ownership,
                        ):
                    verifier._claim_formal_pass_ownership(
                        evidence_root, ownership,
                    )
                    raise RuntimeError("owned failure")
            self.assertFalse((controller / "formal-run-result.json").exists())
            self.assertFalse((controller / "formal-validation.json").exists())

            for name in ("formal-run-result.json", "formal-validation.json"):
                (controller / name).write_bytes(artifacts[name])
            readonly_paths = [
                controller / "formal-run-result.json",
                controller / "formal-validation.json",
            ]
            readonly_ownership = {}
            try:
                with self.assertRaisesRegex(RuntimeError, "readonly failure"):
                    with verifier._invalidate_formal_pass_on_failure(
                            evidence_root, readonly_ownership), \
                            verifier._formal_evidence_read_guard(
                                controller, readonly_ownership,
                            ):
                        verifier._claim_formal_pass_ownership(
                            evidence_root, readonly_ownership,
                        )
                        for path in readonly_paths:
                            path.chmod(stat.S_IREAD)
                            self.assertEqual(path.stat().st_mode & stat.S_IWRITE, 0)
                        raise RuntimeError("readonly failure")
            finally:
                for path in readonly_paths:
                    if path.exists():
                        path.chmod(stat.S_IREAD | stat.S_IWRITE)
            self.assertTrue(all(not path.exists() for path in readonly_paths))

            for name in ("formal-run-result.json", "formal-validation.json"):
                (controller / name).write_bytes(artifacts[name])
            successful_ownership = {}
            with verifier._invalidate_formal_pass_on_failure(
                    evidence_root, successful_ownership), \
                    verifier._formal_evidence_read_guard(
                        controller, successful_ownership,
                    ) as successful_guard:
                verifier._claim_formal_pass_ownership(
                    evidence_root, successful_ownership,
                )
                self.assertEqual(
                    len(verifier._read_formal_evidence_guard(successful_guard[0])),
                    98,
                )
            self.assertTrue((controller / "formal-run-result.json").is_file())
            self.assertTrue((controller / "formal-validation.json").is_file())

            formal_run_path = controller / "formal-run-result.json"
            with formal_run_path.open("rb", buffering=0) as ordinary_reader:
                self.assertTrue(ordinary_reader.read(1))
                with self.assertRaises(verifier.GateError):
                    with verifier._formal_evidence_read_guard(controller):
                        pass
            with verifier._formal_evidence_read_guard(controller) as reopened_guard:
                self.assertEqual(
                    len(verifier._read_formal_evidence_guard(reopened_guard[0])),
                    98,
                )

            ownership = {}
            verifier._claim_formal_pass_ownership(evidence_root, ownership)
            validation = controller / "formal-validation.json"
            validation.rename(controller / "owned-validation.backup")
            foreign = b"foreign validation carrier"
            validation.write_bytes(foreign)
            with self.assertRaisesRegex(
                    verifier.GateError, "formal PASS carrier invalidation"):
                with verifier._invalidate_formal_pass_on_failure(
                        evidence_root, ownership):
                    raise RuntimeError("replacement failure")
            self.assertFalse((controller / "formal-run-result.json").exists())
            self.assertEqual(validation.read_bytes(), foreign)

        def call_names(function) -> list[str]:
            tree = ast.parse(inspect.getsource(function))
            return [
                (node.func.id if isinstance(node.func, ast.Name)
                 else node.func.attr)
                for node in ast.walk(tree) if isinstance(node, ast.Call) and
                isinstance(node.func, (ast.Name, ast.Attribute))
            ]

        emit_calls = call_names(verifier._run_formal_gate_and_emit)
        formal_calls = call_names(verifier.formal_run_gate)
        self.assertEqual(emit_calls.count("formal_run_gate"), 1)
        self.assertEqual(emit_calls.count("ExitStack"), 1)
        self.assertEqual(emit_calls.count("_formal_evidence_read_guard"), 0)
        self.assertEqual(formal_calls.count("_formal_evidence_read_guard"), 1)
        self.assertEqual(formal_calls.count("enter_context"), 1)

        checkout_source = inspect.getsource(verifier._assert_external_checkout)
        changed_source = inspect.getsource(verifier._changed_paths)
        check_worktree_source = inspect.getsource(verifier.verify_check_worktree)
        build_environment_source = inspect.getsource(verifier._build_environment)
        build_gate_source = inspect.getsource(verifier.build_all_gate)
        powershell_gate_source = inspect.getsource(verifier.powershell_gate)
        formal_environment_source = inspect.getsource(verifier._formal_runner_environment)
        legacy_m_source = inspect.getsource(verifier._verify_m_with_closed_legacy)
        source_loader_source = inspect.getsource(
            verifier._load_authenticated_source_module
        )
        legacy_fingerprint_source = inspect.getsource(
            verifier._closed_legacy_release_source_fingerprint
        )
        verify_m_source = inspect.getsource(verifier.verify_m)
        main_source = inspect.getsource(verifier.main)
        self.assertEqual(checkout_source.count('"--ignore-submodules=dirty"'), 2)
        self.assertNotIn('"--ignore-submodules=none"', checkout_source)
        self.assertIn("_assert_external_checkout(submodule", checkout_source)
        self.assertIn(
            "return _git_command(root, *args, "
            "libutp_checkout=libutp_checkout)",
            checkout_source,
        )
        self.assertIn(
            'not libutp_checkout and relative == "libutp"', checkout_source,
        )
        recursive_libutp_calls = [
            node for node in ast.walk(ast.parse(checkout_source))
            if isinstance(node, ast.Call) and
            isinstance(node.func, ast.Name) and
            node.func.id == "_assert_external_checkout" and
            node.args and isinstance(node.args[0], ast.Name) and
            node.args[0].id == "submodule" and
            any(
                keyword.arg == "libutp_checkout" and
                isinstance(keyword.value, ast.Constant) and
                keyword.value.value is True
                for keyword in node.keywords
            )
        ]
        self.assertEqual(len(recursive_libutp_calls), 1)
        self.assertIn('("diff", "--ignore-submodules=dirty", "--name-only", "HEAD")',
                      changed_source)
        self.assertIn('_assert_libutp_checkout(head, "worktree libutp source")',
                      check_worktree_source)
        self.assertIn("_assert_external_checkout(REPO, gate_commit, gate_tree,",
                      main_source)
        self.assertIn('("core.autocrlf", "true")', build_environment_source)
        self.assertIn('("core.autocrlf", "true")', formal_environment_source)
        self.assertIn(
            'resolved_python_executable = shutil.which("python.exe"',
            build_environment_source,
        )
        self.assertIn("resolved_python_executable is None", build_environment_source)
        self.assertNotIn("str(python_path.parent)", build_environment_source)
        self.assertIn("str(powershell.parent)", build_environment_source)
        self.assertIn(
            'resolved_powershell = shutil.which("powershell.exe"',
            build_environment_source,
        )
        self.assertIn(
            '"resolved Windows PowerShell") == powershell',
            build_environment_source,
        )
        self.assertNotIn("PKG_EXECPATH", build_environment_source)
        self.assertEqual(
            build_gate_source.count(
                'pkg_probe_environment, "PKG_EXECPATH", "PKG_INVOKE_NODEJS"'
            ), 1,
        )
        self.assertEqual(
            build_gate_source.count("environment=pkg_probe_environment"), 2,
        )
        self.assertEqual(build_gate_source.count("function global:python.exe"), 1)
        self.assertIn("$args.Count -eq 1", build_gate_source)
        self.assertNotIn("$args.Count -gt 0", build_gate_source)
        self.assertEqual(build_gate_source.count("BUILD_PYTHON_DEPENDENCY_BOOTSTRAP"), 1)
        self.assertEqual(build_gate_source.count("_prepare_build_python_dependency"), 1)
        self.assertIn('" -I -S -B -c "', build_gate_source)
        self.assertIn('" -E -s -S -B @args } }; & "', build_gate_source)
        self.assertLess(
            build_gate_source.index("function global:python.exe"),
            build_gate_source.index("_powershell_single_quote(str(build_script))"),
        )
        self.assertEqual(
            powershell_gate_source.count('temporary / "mod02-runtime"'), 1,
        )
        self.assertIn(
            '"emule.exe": (\n                        mod02_inputs["executable"],',
            powershell_gate_source,
        )
        self.assertIn(
            '"ffmpeg.exe": (\n                        mod02_inputs["package_ffmpeg"],',
            powershell_gate_source,
        )
        self.assertNotIn('"ffprobe.exe"', powershell_gate_source)
        self.assertIn(
            '_powershell_single_quote(str(isolated_mod02["emule.exe"]))',
            powershell_gate_source,
        )
        self.assertEqual(
            powershell_gate_source.count("_assert_mod02_runtime_initial("), 1,
        )
        self.assertEqual(
            powershell_gate_source.count("_assert_mod02_runtime_post("), 1,
        )
        powershell_gate_tree = ast.parse(powershell_gate_source)
        self.assertFalse(any(
            isinstance(node, ast.Name) and
            isinstance(node.ctx, (ast.Store, ast.Del)) and
            node.id == "name"
            for node in ast.walk(powershell_gate_tree)
        ))
        self.assertLess(
            powershell_gate_source.index("isolated MOD02 runtime initial set"),
            powershell_gate_source.index("process = subprocess.run("),
        )
        self.assertIn("MOD02_PORTABLE_SEED", powershell_gate_source)
        self.assertIn("MOD02_PORTABLE_SEED_SHA256", powershell_gate_source)
        self.assertEqual(powershell_gate_source.count("os.utime("), 1)
        self.assertIn('"executable_mtime_ns"', powershell_gate_source)
        self.assertIn('"ffmpeg_mtime_ns"', powershell_gate_source)
        self.assertNotIn('isolated_mod02["emule.exe"].unlink()',
                         powershell_gate_source)
        self.assertIn("isolated MOD02 runtime cleanup", powershell_gate_source)
        self.assertIn("_verify_m_with_closed_legacy", verify_m_source)
        self.assertNotIn("_import_old_verifier().verify_m", verify_m_source)
        for closed_assignment in (
                "module.sh = reject_legacy_shell",
                "module.git = closed_git",
                "module.blob = closed_blob",
                "module.parents = closed_parents",
                "module.changed = closed_changed"):
            self.assertIn(closed_assignment, legacy_m_source)
        self.assertIn("_closed_legacy_release_source_fingerprint(a_commit)",
                      legacy_m_source)
        self.assertIn("module.subprocess = RejectLegacySubprocess()",
                      legacy_m_source)
        self.assertIn("legacy.import_old_verifier = lambda: physical",
                      legacy_m_source)
        self.assertIn('compile(raw, str(path), "exec"', source_loader_source)
        self.assertIn("types.ModuleType", source_loader_source)
        self.assertNotIn("spec_from_file_location", source_loader_source)
        hostile_loader_source = inspect.getsource(load_authenticated_verifier)
        self.assertNotIn("spec_from_file_location", hostile_loader_source)
        self.assertIn("compile(raw, str(path), \"exec\"",
                      hostile_loader_source)
        self.assertIn("_formal_runner_environment", legacy_fingerprint_source)
        self.assertIn('"-NoProfile", "-NonInteractive"',
                      legacy_fingerprint_source)
        self.assertIn("env=environment", legacy_fingerprint_source)
        self.assertIn('("core.autocrlf", "true")', legacy_fingerprint_source)
        self.assertNotIn('"powershell.exe"', legacy_fingerprint_source)

        fake_legacy = type("FakeLegacy", (), {})()
        fake_legacy.OLD_VERIFIER = (
            "tools/architecture/verify_v92_o01_physical_repair_governance.py"
        )
        fake_legacy.HISTORICAL_GOV_SHA256 = {
            fake_legacy.OLD_VERIFIER: verifier.LEGACY_PHYSICAL_VERIFIER_SHA256,
        }
        adapter_observed = []

        def fake_legacy_verify(m_commit, a_commit):
            physical = fake_legacy.import_old_verifier()
            with self.assertRaises(verifier.GateError):
                fake_legacy.subprocess.run([])
            with self.assertRaises(verifier.GateError):
                physical.subprocess.run([])
            with self.assertRaises(verifier.GateError):
                fake_legacy.sh("git", "status")
            with self.assertRaises(verifier.GateError):
                physical.sh("git", "status")
            self.assertEqual(fake_legacy.git("rev-parse", "HEAD"), m_commit)
            self.assertEqual(physical.git("rev-parse", "HEAD"), m_commit)
            self.assertEqual(physical.parents(m_commit), verifier._parents(m_commit))
            self.assertEqual(
                physical.changed(a_commit, m_commit),
                verifier._changed_between(a_commit, m_commit),
            )
            self.assertEqual(
                physical.blob(m_commit, fake_legacy.OLD_VERIFIER),
                verifier._blob(m_commit, fake_legacy.OLD_VERIFIER),
            )
            self.assertEqual(physical.release_source_fingerprint(), "CLOSED")
            adapter_observed.append(True)

        fake_legacy.verify_m = fake_legacy_verify
        current_commit = verifier._git_text("rev-parse", "HEAD")
        current_parent = verifier._parents(current_commit)[0]
        with mock.patch.object(
                verifier, "_import_old_verifier", return_value=fake_legacy), \
                mock.patch.object(
                    verifier, "_closed_legacy_release_source_fingerprint",
                    return_value="CLOSED",
                ):
            verifier._verify_m_with_closed_legacy(current_commit, current_parent)
        self.assertEqual(adapter_observed, [True])
        with mock.patch.object(
                verifier, "_closed_legacy_release_source_fingerprint",
                return_value="3E1B51DCE2A83DF5DDA10697385FD8C7F05D8C81EB391B967D30E0CD6761ED23",
                ):
            verifier._verify_m_with_closed_legacy(
                verifier.BASE["m63_commit"], verifier.BASE["a63_commit"],
            )

        with tempfile.TemporaryDirectory(
                prefix="g12-legacy-source-loader-") as temporary_name:
            loader_root = Path(temporary_name)
            source_path = loader_root / "legacy.py"
            source_path.write_bytes(b"VALUE = 'evil'\n")
            cache = loader_root / "__pycache__" / "legacy.cpython-312.pyc"
            cache.parent.mkdir()
            py_compile.compile(str(source_path), cfile=str(cache), doraise=True)
            source_path.write_bytes(b"VALUE = 'good'\n")
            source_sha = verifier._file_sha256(source_path)
            loaded = verifier._load_authenticated_source_module(
                "closed_source_loader_probe", source_path, source_sha,
                "closed source loader probe",
            )
            self.assertEqual(loaded.VALUE, "good")

            verifier_source = loader_root / "verifier-probe.py"
            verifier_source.write_bytes(
                b'DOCUMENT_SHA256 = "' + (b"0" * 64) +
                b'"\nVALUE = "evil"\n'
            )
            verifier_cache = (
                loader_root / "__pycache__" / "verifier-probe.cpython-312.pyc"
            )
            py_compile.compile(
                str(verifier_source), cfile=str(verifier_cache), doraise=True,
            )
            verifier_source.write_bytes(
                b'DOCUMENT_SHA256 = "' + (b"0" * 64) +
                b'"\nVALUE = "good"\n'
            )
            normalized, count = DOCUMENT_ASSIGNMENT.subn(
                b'DOCUMENT_SHA256 = "' + (b"0" * 64) + b'"',
                verifier_source.read_bytes(),
            )
            self.assertEqual(count, 1)
            loaded_verifier = load_authenticated_verifier(
                verifier_source, hashlib.sha256(normalized).hexdigest(),
            )
            self.assertEqual(loaded_verifier.VALUE, "good")

        with tempfile.TemporaryDirectory(
                prefix="g12-mod02-runtime-hostile-") as temporary_name:
            fixture = Path(temporary_name)
            emule_source = fixture / "source-emule.exe"
            ffmpeg_source = fixture / "source-ffmpeg.exe"
            emule_source.write_bytes(b"pinned emule executable")
            ffmpeg_source.write_bytes(b"pinned ffmpeg executable")
            runtime = fixture / "runtime"
            isolated, expected = verifier._copy_isolated_executable_set(
                {
                    "emule.exe": (
                        emule_source, verifier._file_sha256(emule_source),
                    ),
                    "ffmpeg.exe": (
                        ffmpeg_source, verifier._file_sha256(ffmpeg_source),
                    ),
                },
                runtime,
                "hostile MOD02 capsule",
            )
            source_mtimes = {
                "emule.exe": emule_source.stat().st_mtime_ns,
                "ffmpeg.exe": ffmpeg_source.stat().st_mtime_ns,
            }
            for name in ("emule.exe", "ffmpeg.exe"):
                os.utime(
                    isolated[name],
                    ns=(isolated[name].stat().st_atime_ns, source_mtimes[name]),
                )
                self.assertEqual(isolated[name].stat().st_mtime_ns,
                                 source_mtimes[name])
            verifier._assert_isolated_executable_set(
                runtime, expected, "hostile MOD02 capsule",
            )
            with self.assertRaises(verifier.GateError):
                verifier._assert_mod02_runtime_initial(
                    runtime, expected,
                    (verifier.MOD02_PORTABLE_SEED_SHA256,
                     len(verifier.MOD02_PORTABLE_SEED)),
                    "hostile MOD02 capsule",
                )
            generated_config = runtime / "config"
            generated_config.mkdir()
            preference = generated_config / "preferences.ini"
            preference.write_bytes(verifier.MOD02_PORTABLE_SEED)
            verifier._assert_mod02_runtime_initial(
                runtime, expected,
                (verifier.MOD02_PORTABLE_SEED_SHA256,
                 len(verifier.MOD02_PORTABLE_SEED)),
                "hostile MOD02 capsule",
            )
            preference.write_bytes(b"[forged]\r\n")
            with self.assertRaises(verifier.GateError):
                verifier._assert_mod02_runtime_initial(
                    runtime, expected,
                    (verifier.MOD02_PORTABLE_SEED_SHA256,
                     len(verifier.MOD02_PORTABLE_SEED)),
                    "hostile MOD02 capsule",
                )
            preference.write_bytes(verifier.MOD02_PORTABLE_SEED)
            extra_config = generated_config / "extra.ini"
            extra_config.write_bytes(b"hostile\r\n")
            with self.assertRaises(verifier.GateError):
                verifier._assert_mod02_runtime_initial(
                    runtime, expected,
                    (verifier.MOD02_PORTABLE_SEED_SHA256,
                     len(verifier.MOD02_PORTABLE_SEED)),
                    "hostile MOD02 capsule",
                )
            extra_config.unlink()
            extra = runtime / "extra.dll"
            extra.write_bytes(b"hostile")
            with self.assertRaises(verifier.GateError):
                verifier._assert_mod02_runtime_initial(
                    runtime, expected,
                    (verifier.MOD02_PORTABLE_SEED_SHA256,
                     len(verifier.MOD02_PORTABLE_SEED)),
                    "hostile MOD02 capsule",
                )
            extra.unlink()
            original_emule = isolated["emule.exe"].read_bytes()
            isolated["emule.exe"].write_bytes(original_emule + b"hostile")
            with self.assertRaises(verifier.GateError):
                verifier._assert_mod02_runtime_post(
                    runtime, expected, "hostile MOD02 capsule",
                )
            isolated["emule.exe"].write_bytes(original_emule)
            os.utime(
                isolated["emule.exe"],
                ns=(isolated["emule.exe"].stat().st_atime_ns,
                    source_mtimes["emule.exe"]),
            )
            verifier._assert_mod02_runtime_post(
                runtime, expected, "hostile MOD02 capsule",
            )
            preference.write_bytes(
                b"portable runtime output\n"
            )
            generated_state = generated_config / "cryptkey.dat"
            generated_state.write_bytes(b"portable state")
            verifier._assert_mod02_runtime_post(
                runtime, expected, "hostile MOD02 capsule",
            )
            extra.write_bytes(b"hostile post-start DLL")
            with self.assertRaises(verifier.GateError):
                verifier._assert_mod02_runtime_post(
                    runtime, expected, "hostile MOD02 capsule",
                )
            extra.unlink()
            nested_executable = generated_config / "hostile.exe"
            nested_executable.write_bytes(b"hostile nested executable")
            with self.assertRaises(verifier.GateError):
                verifier._assert_mod02_runtime_post(
                    runtime, expected, "hostile MOD02 capsule",
                )
            nested_executable.unlink()
            generated_state.unlink()
            preference.unlink()
            generated_config.rmdir()
            isolated["emule.exe"].unlink()
            isolated["ffmpeg.exe"].unlink()
            runtime.rmdir()
            self.assertFalse(runtime.exists())

        dependency_root = Path(sys.executable).parent / "Lib/site-packages"
        dependency_identity, dependency_sha = \
            verifier._build_python_dependency_inventory(dependency_root)
        immutable = self.document["immutable_contract"]
        self.assertEqual(len(dependency_identity["files"]),
                         immutable["build_python_dependency_file_count"])
        self.assertEqual(len(dependency_identity["directories"]),
                         immutable["build_python_dependency_directory_count"])
        self.assertEqual(dependency_sha,
                         immutable["build_python_dependency_identity_sha256"])
        with tempfile.TemporaryDirectory(
                prefix="g12-build-python-dependency-hostile-") as temporary_name:
            binding = verifier._prepare_build_python_dependency(
                Path(sys.executable), Path(temporary_name), immutable,
            )
            completed = subprocess.run(
                [sys.executable, "-I", "-S", "-B", "-c",
                 verifier.BUILD_PYTHON_DEPENDENCY_BOOTSTRAP,
                 str(binding["root"]),
                 str(verifier.REPO / "tests/test_v92_mx05_handoff.py")],
                cwd=verifier.REPO, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr[-4096:])
            final_identity, final_sha = verifier._build_python_dependency_inventory(
                binding["root"], strict_root=True,
            )
            self.assertEqual(verifier.canonical(final_identity),
                             verifier.canonical(binding["identity"]))
            self.assertEqual(final_sha, binding["identity_sha256"])
            victim = binding["root"] / binding["identity"]["files"][0]["path"]
            original_victim = victim.read_bytes()
            victim.write_bytes(original_victim + b"hostile")
            _, mutated_sha = verifier._build_python_dependency_inventory(
                binding["root"], strict_root=True,
            )
            self.assertNotEqual(mutated_sha, binding["identity_sha256"])
            victim.write_bytes(original_victim)
            extra = binding["root"] / "unexpected-top-level.txt"
            extra.write_bytes(b"unexpected\n")
            with self.assertRaises(verifier.GateError):
                verifier._build_python_dependency_inventory(
                    binding["root"], strict_root=True,
                )
            extra.unlink()
            cache = binding["root"] / "jsonschema/__pycache__"
            cache.mkdir()
            hostile_pyc = cache / "__init__.cpython-312.pyc"
            hostile_pyc.write_bytes(b"hostile unchecked bytecode")
            with self.assertRaises(verifier.GateError):
                verifier._build_python_dependency_inventory(
                    binding["root"], strict_root=True,
                )
            hostile_pyc.unlink()
            cache.rmdir()
            without_projection = subprocess.run(
                [sys.executable, "-I", "-S", "-B", "-c", "import jsonschema"],
                cwd=verifier.REPO, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                check=False,
            )
            self.assertNotEqual(without_projection.returncode, 0)

        verifier._assert_libutp_checkout(
            verifier._git_text("rev-parse", "HEAD"), "hostile recursive libutp",
        )
        whitespace_configuration = (
            "core.whitespace="
            "blank-at-eol,blank-at-eof,space-before-tab,cr-at-eol"
        )
        with tempfile.TemporaryDirectory(
                prefix="g12-diff-check-crlf-hostile-") as temporary_name:
            fixture = Path(temporary_name)
            empty_path = fixture / "empty.json"
            clean_crlf_path = fixture / "clean-crlf.json"
            hostile_paths = {
                "space-crlf": (
                    fixture / "space-crlf.json",
                    b'{"schema":"probe"} \r\n',
                ),
                "tab-crlf": (
                    fixture / "tab-crlf.json",
                    b'{"schema":"probe"}\t\r\n',
                ),
                "space-lf": (
                    fixture / "space-lf.json",
                    b'{"schema":"probe"} \n',
                ),
            }
            fixture_inputs = {
                empty_path: b"",
                clean_crlf_path: b'{"schema":"probe"}\r\n',
                **{path: raw for path, raw in hostile_paths.values()},
            }
            for path, raw in fixture_inputs.items():
                path.write_bytes(raw)
            input_identities = {
                path: (raw, hashlib.sha256(raw).hexdigest())
                for path, raw in fixture_inputs.items()
            }

            probe_command = verifier._git_command(fixture, "status")
            self.assertEqual(probe_command.count(whitespace_configuration), 1)
            self.assertEqual(
                [argument for argument in probe_command
                 if argument.startswith("core.whitespace=")],
                [whitespace_configuration],
            )

            def diff_check(candidate: Path) -> subprocess.CompletedProcess:
                return subprocess.run(
                    verifier._git_command(
                        fixture, "diff", "--no-index", "--check", "--",
                        str(empty_path), str(candidate),
                    ),
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    check=False, env=verifier._closed_git_environment(),
                )

            clean = diff_check(clean_crlf_path)
            self.assertEqual(clean.returncode, 1)
            self.assertEqual(clean.stdout, b"")
            self.assertEqual(clean.stderr, b"")
            for name, (path, _) in hostile_paths.items():
                process = diff_check(path)
                with self.subTest(diff_check_whitespace=name):
                    self.assertNotIn(process.returncode, (0, 1))
                    self.assertTrue(process.stdout or process.stderr)
                    self.assertIn(
                        b"trailing whitespace",
                        (process.stdout + process.stderr).lower(),
                    )

            for path, (raw, digest) in input_identities.items():
                with self.subTest(diff_check_input_identity=path.name):
                    observed = path.read_bytes()
                    self.assertEqual(observed, raw)
                    self.assertEqual(hashlib.sha256(observed).hexdigest(), digest)

        with tempfile.TemporaryDirectory(prefix="g12-libutp-name-hostile-") as temporary_name:
            decoy = Path(temporary_name) / "libutp"
            decoy.mkdir()
            def autocrlf_configuration(command):
                return [
                    argument for argument in command
                    if argument.startswith("core.autocrlf=")
                ]

            self.assertEqual(
                autocrlf_configuration(verifier._git_command(decoy, "status")),
                ["core.autocrlf=false"],
            )
            self.assertEqual(
                autocrlf_configuration(verifier._git_command(
                    verifier.REPO / "libutp", "status",
                )),
                ["core.autocrlf=false"],
            )
            for root in (decoy, verifier.REPO / "libutp"):
                self.assertEqual(
                    autocrlf_configuration(verifier._git_command(
                        root, "status", libutp_checkout=True,
                    )),
                    ["core.autocrlf=true"],
                )
            for hostile_context in (None, 1, "true"):
                with self.subTest(libutp_checkout_context=hostile_context):
                    with self.assertRaises(verifier.GateError):
                        verifier._git_command(
                            decoy, "status", libutp_checkout=hostile_context,
                        )
        with tempfile.TemporaryDirectory(prefix="g12-config-hostile-") as temporary_name:
            fixture = Path(temporary_name)
            root = fixture / "worktree"
            metadata = fixture / "git-meta"
            wrong = fixture / "wrong"
            root.mkdir()
            metadata.mkdir()
            wrong.mkdir()
            config_path = metadata / "config"
            foreign_path = metadata / "foreign"
            config_path.write_bytes(b"[core]\n\tworktree = ../worktree\n")
            foreign_path.write_bytes(b"[core]\n\tworktree = ../worktree\n")

            def config_results(rows: bytes):
                return [
                    subprocess.CompletedProcess([], 0, rows, b""),
                    subprocess.CompletedProcess(
                        [], 0, str(config_path).encode("utf-8") + b"\n", b"",
                    ),
                ]

            origin = "file:" + config_path.as_posix()
            nominal = f"{origin}\tcore.worktree {root}\n".encode("utf-8")
            with mock.patch.object(verifier, "_git_executable",
                                   return_value=Path("git.exe")), \
                    mock.patch.object(verifier.subprocess, "run",
                                      side_effect=config_results(nominal)):
                verifier._assert_plain_git_configuration_safe(root, "nominal config")
            for hostile_rows in (
                f"{origin}\tcore.worktree {wrong}\n".encode("utf-8"),
                nominal + nominal,
                f"file:{foreign_path.as_posix()}\tcore.worktree {root}\n".encode(
                    "utf-8"
                ),
            ):
                with self.subTest(config_rows=hostile_rows), \
                        mock.patch.object(verifier, "_git_executable",
                                          return_value=Path("git.exe")), \
                        mock.patch.object(verifier.subprocess, "run",
                                          side_effect=config_results(hostile_rows)), \
                        self.assertRaises(verifier.GateError):
                    verifier._assert_plain_git_configuration_safe(root, "hostile config")


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(G12SealedGovernanceTests)
    outcome = unittest.TextTestRunner(verbosity=2).run(suite)
    payload = json.dumps({
        "schema": "ese.v92.o01-rpc-failure-governance-hostile-tests/v1",
        "verdict": "PASS" if outcome.wasSuccessful() else "FAIL",
        "tests_run": outcome.testsRun,
        "failures": len(outcome.failures),
        "errors": len(outcome.errors),
        "a64_freeze": "FROZEN_EXACT13",
    }, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"
    sys.stdout.buffer.write(payload)
    sys.exit(0 if outcome.wasSuccessful() else 1)
