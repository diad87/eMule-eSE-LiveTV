"""MX05 / TH92-5 executable v9.2 -> v9.3 handoff contract."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import pathlib
import subprocess
import unittest
from typing import Any

import jsonschema


ROOT = pathlib.Path(__file__).resolve().parents[1]
MX01_SCHEMA = ROOT / "docs" / "reachability" / "direct_candidate_snapshot_v1.schema.json"
PACKAGE = ROOT / "docs" / "reachability" / "v92_to_v93_handoff_v1"
MATRIX = PACKAGE / "handoff_matrix_v1.json"
MANIFEST = PACKAGE / "handoff_manifest_v1.json"
GOLDENS = PACKAGE / "goldens"
FAKE = ROOT / "tests" / "fixtures" / "v93_candidate_gatherer_fake.py"
MX01_CONSUMER = ROOT / "tests" / "fixtures" / "direct_candidate_snapshot_v1_consumer.py"
BASELINE = "176296cdc6585f68974684801371d05215bbffbc"


def load_json(path: pathlib.Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_module(name: str, path: pathlib.Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Mx05HandoffTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schema = load_json(MX01_SCHEMA)
        cls.matrix = load_json(MATRIX)
        cls.manifest = load_json(MANIFEST)
        cls.compat = load_module("mx01_compat", MX01_CONSUMER)
        cls.gatherer = load_module("v93_fake_gatherer", FAKE)

    def test_versioned_manifest_hashes_and_absent_features_are_frozen(self) -> None:
        self.assertEqual(self.manifest["schema_id"], self.schema["$id"])
        self.assertEqual(self.manifest["schema_sha256"], sha256(MX01_SCHEMA))
        self.assertEqual(self.manifest["producer_baseline_commit"], BASELINE)
        self.assertEqual(self.manifest["producer_baseline_semantics"], "producer baseline only")
        self.assertNotIn("handoff_manifest_v1.json", self.manifest["artifacts"])
        expected_inventory = {
            "docs/reachability/v92_to_v93_handoff_v1/handoff_matrix_v1.json",
            "docs/reachability/v92_to_v93_handoff_v1/V92_TO_V93_HANDOFF_OPERATION.md",
            "tests/fixtures/v93_candidate_gatherer_fake.py",
            "tests/fixtures/direct_candidate_snapshot_v1_consumer.py",
            "tests/test_v92_mx05_handoff.py",
            *(f"docs/reachability/v92_to_v93_handoff_v1/goldens/{name}.json" for name in ("map", "ipv6_global", "renewal_identity", "lan_same_lan", "generation_isolation")),
            *(f"docs/reachability/goldens/{name}.json" for name in ("empty", "candidate", "verified", "expired", "stale")),
        }
        self.assertEqual(set(self.manifest["artifacts"]), expected_inventory)
        package_files = {
            path.relative_to(ROOT).as_posix()
            for path in PACKAGE.rglob("*") if path.is_file()
        }
        self.assertEqual(package_files, {
            "docs/reachability/v92_to_v93_handoff_v1/handoff_manifest_v1.json",
            "docs/reachability/v92_to_v93_handoff_v1/handoff_matrix_v1.json",
            "docs/reachability/v92_to_v93_handoff_v1/V92_TO_V93_HANDOFF_OPERATION.md",
            *(f"docs/reachability/v92_to_v93_handoff_v1/goldens/{name}.json" for name in ("map", "ipv6_global", "renewal_identity", "lan_same_lan", "generation_isolation")),
        })
        for relative, digest in self.manifest["artifacts"].items():
            self.assertEqual(sha256(ROOT / relative), digest, relative)
        self.assertEqual(
            self.manifest["excluded_features"],
            ["DCO", "PUNCH2", "PUNCH3", "PREDICTION", "BIRTHDAY", "DVL", "RELAY", "QUIC"],
        )
        self.assertEqual(self.manifest["excluded_features_verified"], {name: False for name in self.manifest["excluded_features"]})
        executable_payload = FAKE.read_text(encoding="utf-8") + MX01_SCHEMA.read_text(encoding="utf-8")
        executable_payload += "".join(path.read_text(encoding="utf-8") for path in GOLDENS.glob("*.json"))
        for excluded in self.manifest["excluded_features"]:
            self.assertNotIn(excluded, executable_payload.upper())

    def test_producer_baseline_schema_is_reproducibly_semantic(self) -> None:
        command = ["git", "show", f"{BASELINE}:docs/reachability/direct_candidate_snapshot_v1.schema.json"]
        try:
            baseline_text = subprocess.check_output(command, cwd=ROOT, text=True, encoding="utf-8")
        except (OSError, subprocess.CalledProcessError):
            self.fail("the frozen producer baseline schema object must be available")
        baseline_bytes = baseline_text.encode("utf-8")
        self.assertEqual(hashlib.sha256(baseline_bytes).hexdigest(), self.manifest["producer_baseline_schema_sha256"])
        baseline_schema = json.loads(baseline_text)
        for field in ("$id", "$comment", "required"):
            self.assertEqual(baseline_schema[field], self.schema[field])
        self.assertEqual(baseline_schema["$defs"]["reason"]["enum"], self.schema["$defs"]["reason"]["enum"])
        consumer_command = ["git", "show", f"{BASELINE}:tests/fixtures/direct_candidate_snapshot_v1_consumer.py"]
        try:
            baseline_consumer = subprocess.check_output(consumer_command, cwd=ROOT, text=True, encoding="utf-8")
        except (OSError, subprocess.CalledProcessError):
            self.fail("the frozen MX01 compatibility consumer object must be available")
        self.assertEqual(
            hashlib.sha256(baseline_consumer.encode("utf-8")).hexdigest(),
            self.manifest["producer_baseline_consumer_sha256"],
        )
        self.assertEqual(self.manifest["producer_baseline_consumer_sha256"], sha256(MX01_CONSUMER))

    def test_machine_readable_matrix_is_exact_and_complete(self) -> None:
        rows = self.matrix["rows"]
        self.assertEqual([row["id"] for row in rows], [
            "map", "ipv6_global", "renewal_identity", "lan_same_lan", "generation_isolation"
        ])
        expected_falsification_ids = {
            "map": ["missing_owned_mapping", "withdrawn_inbound_proof", "uncontrolled_cgn_without_lease"],
            "ipv6_global": ["firewall_closed", "pinhole_withdrawn"],
            "renewal_identity": [
                "public_ip_changed", "port_or_endpoint_changed", "mapping_identity_changed",
                "gateway_interface_changed", "epoch_generation_changed", "lease_null", "lease_zero",
            ],
            "lan_same_lan": ["global_promotion_attempt", "other_interface_domain"],
            "generation_isolation": ["stale_callback_relabelled_current", "current_event_reuses_stale_identity"],
        }
        reason_enum = set(self.schema["$defs"]["reason"]["enum"])
        for row in rows:
            self.assertTrue(row["hypothesis"])
            self.assertTrue(row["positive_golden"])
            self.assertTrue(row["falsifications"])
            self.assertIn(row["positive_reason_code"], reason_enum)
            self.assertEqual(
                [falsification["id"] for falsification in row["falsifications"]],
                expected_falsification_ids[row["id"]],
            )
            for falsification in row["falsifications"]:
                self.assertEqual(falsification["expected_status"], "MALFORMED")
                self.assertIn(falsification["reason_code"], reason_enum)
        renewal = next(row for row in rows if row["id"] == "renewal_identity")
        self.assertEqual(renewal["positive_transition"], {
            "id": "renewed_positive_deadline",
            "changes": [{
                "path": ["candidates", "0", "lease_expires_at", "remaining_ms"],
                "value": 7200001,
            }],
            "expected_status": "OK",
        })

    def test_each_positive_golden_and_reason_is_consumable(self) -> None:
        validator_type = jsonschema.validators.validator_for(self.schema)
        validator = validator_type(self.schema)
        for row in self.matrix["rows"]:
            snapshot = load_json(PACKAGE / row["positive_golden"])
            with self.subTest(row=row["id"]):
                validator.validate(snapshot)
                self.assertEqual(snapshot["candidates"][0]["reason_code"], row["positive_reason_code"])
                result = self.gatherer.gather(snapshot, self.schema, self.compat)
                self.assertEqual(result["status"], "OK")
                self.assertNotIn("actionable_endpoint", json.dumps(result))

    def test_falsifications_stale_callbacks_and_stable_reasons_fail_closed(self) -> None:
        for row in self.matrix["rows"]:
            snapshot = load_json(PACKAGE / row["positive_golden"])
            for falsification in row["falsifications"]:
                mutated = copy.deepcopy(snapshot)
                changes = falsification.get("changes", [falsification])
                for change in changes:
                    target: Any = mutated
                    for part in change["path"][:-1]:
                        target = target[int(part)] if isinstance(target, list) else target[part]
                    leaf = change["path"][-1]
                    if isinstance(target, list):
                        target[int(leaf)] = change["value"]
                    else:
                        target[leaf] = change["value"]
                with self.subTest(row=row["id"], falsification=falsification["id"]):
                    result = (
                        self.gatherer.gather_transition(snapshot, mutated, self.schema, self.compat)
                        if falsification.get("transition")
                        else self.gatherer.gather(mutated, self.schema, self.compat)
                    )
                    self.assertEqual(result["status"], falsification["expected_status"])
                    self.assertEqual(result["rejection_reason_codes"], [falsification["reason_code"]])
                    self.assertEqual(result["verified_candidate_ids"], [])
        renewal = next(row for row in self.matrix["rows"] if row["id"] == "renewal_identity")
        renewed = load_json(PACKAGE / renewal["positive_golden"])
        for change in renewal["positive_transition"]["changes"]:
            target: Any = renewed
            for part in change["path"][:-1]:
                target = target[int(part)] if isinstance(target, list) else target[part]
            target[change["path"][-1]] = change["value"]
        self.assertEqual(
            self.gatherer.gather_transition(
                load_json(PACKAGE / renewal["positive_golden"]), renewed, self.schema, self.compat,
            )["status"],
            renewal["positive_transition"]["expected_status"],
        )
        stale = load_json(GOLDENS / "generation_isolation.json")
        result = self.gatherer.gather(stale, self.schema, self.compat)
        self.assertEqual(result["status"], "OK")
        self.assertEqual(result["ignored_stale_candidate_ids"], [stale["candidates"][0]["candidate_id"]])
        current = copy.deepcopy(stale)
        candidate = current["candidates"][0]
        current["topology_generation"] = 8
        candidate["topology_generation"] = 8
        candidate["candidate_id"] = "candidate-v1:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        candidate["verification_state"] = "VERIFIED"
        candidate["verification_attempt_id"] = "attempt-v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        candidate["evidence_digest"] = "evidence-v1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        candidate["reason_code"] = "NONE"
        current_result = self.gatherer.gather_transition(stale, current, self.schema, self.compat)
        self.assertEqual(current_result["status"], "OK")
        self.assertEqual(current_result["verified_candidate_ids"], [candidate["candidate_id"]])
        current_to_stale = copy.deepcopy(current)
        current_to_stale["topology_generation"] = 9
        current_to_stale["candidates"][0]["topology_generation"] = 8
        current_to_stale["candidates"][0]["verification_state"] = "STALE"
        current_to_stale["candidates"][0]["verification_attempt_id"] = None
        current_to_stale["candidates"][0]["evidence_digest"] = None
        current_to_stale["candidates"][0]["reason_code"] = "STALE_GENERATION"
        stale_result = self.gatherer.gather_transition(current, current_to_stale, self.schema, self.compat)
        self.assertEqual(stale_result, current_result)

    def test_mapped_lease_malformed_forms_are_typed_and_non_throwing(self) -> None:
        malformed_values: list[Any] = [
            None, "bad", 3, True, "missing", {},
            {"remaining_ms": 1},
            {"basis": "WRONG", "remaining_ms": 1},
            {"basis": "SNAPSHOT_RELATIVE", "remaining_ms": "1"},
            {"basis": "SNAPSHOT_RELATIVE", "remaining_ms": True},
            {"basis": "SNAPSHOT_RELATIVE", "remaining_ms": -1},
            {"basis": "SNAPSHOT_RELATIVE", "remaining_ms": 1, "extra": 1},
        ]
        for value in malformed_values:
            snapshot = load_json(GOLDENS / "map.json")
            if value == "missing":
                del snapshot["candidates"][0]["lease_expires_at"]
            else:
                snapshot["candidates"][0]["lease_expires_at"] = value
            with self.subTest(value=value):
                result = self.gatherer.gather(snapshot, self.schema, self.compat)
                self.assertEqual(result["status"], "MALFORMED")
                self.assertEqual(result["rejection_reason_codes"], ["NO_MAPPING_PROTOCOL"])
        expired = load_json(GOLDENS / "map.json")
        expired["candidates"][0]["lease_expires_at"]["remaining_ms"] = 0
        expired_result = self.gatherer.gather(expired, self.schema, self.compat)
        self.assertEqual(expired_result["status"], "MALFORMED")
        self.assertEqual(expired_result["rejection_reason_codes"], ["LEASE_EXPIRED"])

    def test_transition_is_order_independent_and_checks_every_candidate(self) -> None:
        previous = load_json(GOLDENS / "map.json")
        second = copy.deepcopy(previous["candidates"][0])
        second["candidate_id"] = "candidate-v1:9999999999999999999999999999999999999999999999999999999999999999"
        second["transport"] = "UDP"
        second["local_endpoint"]["identity_digest"] = "endpoint-v1:2222222222222222222222222222222222222222222222222222222222222222"
        previous["candidates"].append(second)
        current = copy.deepcopy(previous)
        current["candidates"].reverse()
        self.assertEqual(self.gatherer.gather_transition(previous, current, self.schema, self.compat)["status"], "OK")
        changed_transport = copy.deepcopy(current)
        changed_transport["candidates"][0]["transport"] = "TCP"
        changed_transport_result = self.gatherer.gather_transition(previous, changed_transport, self.schema, self.compat)
        self.assertEqual(changed_transport_result["status"], "MALFORMED")
        self.assertEqual(changed_transport_result["rejection_reason_codes"], ["MAPPING_CONFLICT"])
        changed_kind = copy.deepcopy(current)
        changed_kind["candidates"][0].update({
            "kind": "DIRECT_V4", "mapping_identity": None,
            "lease_expires_at": None, "ownership_state": "NOT_APPLICABLE", "source": "OS",
        })
        changed_kind["candidates"][0]["local_endpoint"]["address_class"] = "PUBLIC"
        changed_kind_result = self.gatherer.gather_transition(previous, changed_kind, self.schema, self.compat)
        self.assertEqual(changed_kind_result["status"], "MALFORMED")
        self.assertEqual(changed_kind_result["rejection_reason_codes"], ["MAPPING_CONFLICT"])
        reidentified = copy.deepcopy(current)
        reidentified["candidates"][0]["candidate_id"] = "candidate-v1:abababababababababababababababababababababababababababababababab"
        reidentified_result = self.gatherer.gather_transition(previous, reidentified, self.schema, self.compat)
        self.assertEqual(reidentified_result["status"], "MALFORMED")
        self.assertEqual(reidentified_result["rejection_reason_codes"], ["MAPPING_CONFLICT"])
        changed_class = copy.deepcopy(previous)
        changed_class["candidates"][0]["local_endpoint"]["address_class"] = "DOCUMENTATION"
        changed_class_result = self.gatherer.gather_transition(previous, changed_class, self.schema, self.compat)
        self.assertEqual(changed_class_result["status"], "MALFORMED")
        self.assertEqual(changed_class_result["rejection_reason_codes"], ["MAPPING_CONFLICT"])
        lan_previous = load_json(GOLDENS / "lan_same_lan.json")
        changed_family = copy.deepcopy(lan_previous)
        changed_family["candidates"][0]["published_endpoint"]["address_family"] = "IPV4"
        changed_family_result = self.gatherer.gather_transition(lan_previous, changed_family, self.schema, self.compat)
        self.assertEqual(changed_family_result["status"], "MALFORMED")
        self.assertEqual(changed_family_result["rejection_reason_codes"], ["MAPPING_CONFLICT"])

    def test_transition_hostile_inputs_are_typed_before_indexing(self) -> None:
        valid = load_json(GOLDENS / "map.json")
        hostile_cases: list[tuple[Any, str]] = [
            ({"schema_version": 0}, "UNSUPPORTED_SCHEMA"),
            ({"schema_version": 1}, "MALFORMED"),
            ({**valid, "candidates": "not-a-list"}, "MALFORMED"),
            ({**valid, "candidates": [{}]}, "MALFORMED"),
            ({**valid, "candidates": [{**valid["candidates"][0], "local_endpoint": None}]}, "MALFORMED"),
            (None, "MALFORMED"),
        ]
        for hostile, expected_status in hostile_cases:
            with self.subTest(side="current", hostile=hostile):
                result = self.gatherer.gather_transition(valid, hostile, self.schema, self.compat)
                self.assertEqual(result["status"], expected_status)
            with self.subTest(side="previous", hostile=hostile):
                result = self.gatherer.gather_transition(hostile, valid, self.schema, self.compat)
                self.assertEqual(result["status"], expected_status)

    def test_mixed_stale_callback_preserves_all_previous_current_facts(self) -> None:
        previous = load_json(GOLDENS / "map.json")
        second = copy.deepcopy(previous["candidates"][0])
        second["candidate_id"] = "candidate-v1:9999999999999999999999999999999999999999999999999999999999999999"
        second["transport"] = "UDP"
        previous["candidates"].append(second)
        expected = self.gatherer.gather(previous, self.schema, self.compat)
        callback = copy.deepcopy(previous)
        callback["topology_generation"] = 8
        callback["candidates"][0]["verification_state"] = "STALE"
        callback["candidates"][0]["verification_attempt_id"] = None
        callback["candidates"][0]["evidence_digest"] = None
        callback["candidates"][0]["reason_code"] = "STALE_GENERATION"
        callback["candidates"][1]["topology_generation"] = 8
        callback["candidates"].reverse()
        self.assertEqual(
            self.gatherer.gather_transition(previous, callback, self.schema, self.compat),
            expected,
        )

    def test_unknown_stale_callback_also_preserves_the_entire_previous_result(self) -> None:
        previous = load_json(GOLDENS / "map.json")
        second = copy.deepcopy(previous["candidates"][0])
        second["candidate_id"] = "candidate-v1:9999999999999999999999999999999999999999999999999999999999999999"
        second["transport"] = "UDP"
        second["local_endpoint"]["identity_digest"] = "endpoint-v1:2222222222222222222222222222222222222222222222222222222222222222"
        previous["candidates"].append(second)
        expected = self.gatherer.gather(previous, self.schema, self.compat)

        stale_only = copy.deepcopy(previous)
        stale_only["topology_generation"] = 8
        stale = stale_only["candidates"][0]
        stale["candidate_id"] = "candidate-v1:abababababababababababababababababababababababababababababababab"
        stale["verification_state"] = "STALE"
        stale["verification_attempt_id"] = None
        stale["evidence_digest"] = None
        stale["reason_code"] = "STALE_GENERATION"
        stale_only["candidates"] = [stale]
        self.assertEqual(
            self.gatherer.gather_transition(previous, stale_only, self.schema, self.compat),
            expected,
        )

        stale_and_fresh = copy.deepcopy(stale_only)
        fresh = copy.deepcopy(previous["candidates"][1])
        fresh["candidate_id"] = "candidate-v1:bcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbc"
        fresh["topology_generation"] = 8
        stale_and_fresh["candidates"] = [fresh, stale]
        self.assertEqual(
            self.gatherer.gather_transition(previous, stale_and_fresh, self.schema, self.compat),
            expected,
        )

    def test_compatibility_sanitization_and_fake_consumer_boundary(self) -> None:
        snapshot = load_json(GOLDENS / "map.json")
        snapshot["future_note"] = {"retry_count": 2}
        self.assertEqual(self.gatherer.gather(snapshot, self.schema, self.compat)["status"], "OK")
        old_schema = copy.deepcopy(snapshot)
        old_schema["schema_version"] = 0
        self.assertEqual(self.gatherer.gather(old_schema, self.schema, self.compat)["status"], "UNSUPPORTED_SCHEMA")
        leaked = copy.deepcopy(snapshot)
        leaked["future_note"] = {"raw_ip": "198.51.100.99"}
        self.assertEqual(self.gatherer.gather(leaked, self.schema, self.compat)["status"], "MALFORMED")
        payload = FAKE.read_text(encoding="utf-8").lower()
        for forbidden in ("mapper", "socket", "actionable_endpoint", "connect(", "sendto("):
            self.assertNotIn(forbidden, payload)


if __name__ == "__main__":
    unittest.main(verbosity=2)
