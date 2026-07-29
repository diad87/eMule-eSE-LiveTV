#!/usr/bin/env python3
"""Executable contract checks for MX01 / DirectCandidateSnapshotV1."""

from __future__ import annotations

import copy
import importlib.util
import ipaddress
import json
import pathlib
import unittest
from typing import Any, Iterator

import jsonschema


ROOT = pathlib.Path(__file__).resolve().parents[1]
CONTRACT_DIR = ROOT / "docs" / "reachability"
SCHEMA_PATH = CONTRACT_DIR / "direct_candidate_snapshot_v1.schema.json"
GOLDEN_DIR = CONTRACT_DIR / "goldens"
CONSUMER_PATH = (
    ROOT / "tests" / "fixtures" / "direct_candidate_snapshot_v1_consumer.py"
)
MAX_SAFE_INTEGER = 9007199254740991


def _load_json(path: pathlib.Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _walk(value: Any) -> Iterator[Any]:
    yield value
    if isinstance(value, dict):
        for key, child in value.items():
            yield key
            yield from _walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk(child)


def _load_consumer() -> Any:
    spec = importlib.util.spec_from_file_location("mx01_fake_consumer", CONSUMER_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load MX01 fake consumer")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class DirectCandidateSnapshotV1ContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schema = _load_json(SCHEMA_PATH)
        validator_type = jsonschema.validators.validator_for(cls.schema)
        validator_type.check_schema(cls.schema)
        cls.validator = validator_type(cls.schema)
        cls.goldens = {
            path.stem: _load_json(path)
            for path in sorted(GOLDEN_DIR.glob("*.json"))
        }
        cls.consumer = _load_consumer()

    def _verified_snapshot_for_kind(self, kind: str) -> dict[str, Any]:
        snapshot = copy.deepcopy(self.goldens["verified"])
        candidate = snapshot["candidates"][0]
        if kind == "MAPPED_V4":
            return snapshot

        candidate.update(
            {
                "kind": kind,
                "source": "OS",
                "mapping_identity": None,
                "lease_expires_at": None,
                "ownership_state": "NOT_APPLICABLE",
            }
        )
        candidate["local_endpoint"]["address_class"] = "PUBLIC"
        if kind == "HOST_V6":
            for endpoint_field in ("local_endpoint", "published_endpoint"):
                candidate[endpoint_field]["address_family"] = "IPV6"
                candidate[endpoint_field]["address_class"] = "GLOBAL"
        return snapshot

    def test_exact_required_goldens_validate(self) -> None:
        self.assertEqual(
            set(self.goldens),
            {"empty", "candidate", "verified", "expired", "stale"},
        )
        for name, golden in self.goldens.items():
            with self.subTest(name=name):
                self.validator.validate(golden)

    def test_every_domain_object_is_closed(self) -> None:
        open_objects = []
        for node in _walk(self.schema):
            if isinstance(node, dict) and node.get("type") == "object":
                if node.get("additionalProperties") is not False:
                    open_objects.append(node.get("title", node.get("required")))
        self.assertEqual(open_objects, [])

    def test_normative_enums_are_exactly_frozen(self) -> None:
        expected = {
            "kind": ["HOST_V6", "DIRECT_V4", "MAPPED_V4", "LAN"],
            "source": ["OS", "STATIC", "UPNP_IGD", "PCP", "NAT_PMP"],
            "scope": ["GLOBAL", "SAME_LAN"],
            "verification": ["CANDIDATE", "VERIFIED", "EXPIRED", "STALE"],
            "reason": [
                "NONE",
                "DISABLED_BY_PREFERENCE",
                "NO_LISTENER",
                "NO_ROUTE",
                "NO_GATEWAY",
                "NO_MAPPING_PROTOCOL",
                "OPERATOR_DENIED",
                "MAPPING_DENIED",
                "MAPPING_CONFLICT",
                "MAPPING_TIMEOUT",
                "INVALID_RESPONSE",
                "STALE_GENERATION",
                "LEASE_EXPIRED",
                "INTERFACE_CHANGED",
                "ENDPOINT_DEPENDENT_MAPPING",
                "INBOUND_FILTERED",
                "SERVER_CALLBACK_FAILED",
                "PEER_INCOMPATIBLE",
                "PORT_IN_USE",
                "VERIFICATION_TIMEOUT",
                "CGNAT_WITHOUT_LEASE",
                "ROUTER_REJECTED_ALL_CANDIDATES",
            ],
        }
        for definition, values in expected.items():
            with self.subTest(definition=definition):
                self.assertEqual(self.schema["$defs"][definition]["enum"], values)

    def test_lifecycle_goldens_distinguish_candidate_and_verified(self) -> None:
        candidate = self.goldens["candidate"]["candidates"][0]
        verified = self.goldens["verified"]["candidates"][0]
        expired = self.goldens["expired"]["candidates"][0]
        stale = self.goldens["stale"]["candidates"][0]

        identity_fields = (
            "candidate_id",
            "kind",
            "transport",
            "local_endpoint",
            "published_endpoint",
            "network_kind",
            "interface_identity_digest",
            "source",
            "scope",
            "mapping_identity",
            "ownership_state",
        )
        for field in identity_fields:
            self.assertEqual(candidate[field], verified[field], field)

        self.assertEqual(candidate["verification_state"], "CANDIDATE")
        self.assertIsNone(candidate["verification_attempt_id"])
        self.assertIsNone(candidate["evidence_digest"])
        self.assertEqual(verified["verification_state"], "VERIFIED")
        self.assertIsNotNone(verified["verification_attempt_id"])
        self.assertIsNotNone(verified["evidence_digest"])
        self.assertEqual(expired["verification_state"], "EXPIRED")
        self.assertEqual(expired["lease_expires_at"]["remaining_ms"], 0)
        self.assertEqual(stale["verification_state"], "STALE")
        self.assertLess(
            stale["topology_generation"],
            self.goldens["stale"]["topology_generation"],
        )
        self.assertEqual(self.goldens["expired"]["terminal_reason"], "NONE")
        self.assertEqual(self.goldens["stale"]["terminal_reason"], "NONE")

    def test_fake_consumer_needs_only_the_contract(self) -> None:
        candidate_result = self.consumer.consume_snapshot(
            self.goldens["candidate"], self.schema
        )
        verified_result = self.consumer.consume_snapshot(
            self.goldens["verified"], self.schema
        )
        self.assertEqual(candidate_result["status"], "OK")
        self.assertEqual(
            candidate_result["verified_native_global_candidate_ids"], []
        )
        self.assertEqual(verified_result["status"], "OK")
        self.assertEqual(
            verified_result["verified_native_global_candidate_ids"],
            [
                self.goldens["verified"]["candidates"][0]["candidate_id"]
            ],
        )

    def test_fake_consumer_does_not_depend_on_mapper_classes_or_text_traces(
        self,
    ) -> None:
        source = CONSUMER_PATH.read_text(encoding="utf-8")
        forbidden_dependencies = (
            "CDirectReachabilityManager",
            "CUPnPImpl",
            "CNATPMP",
            "PCPImpl",
            "\"PCP\"",
            "UPNP_IGD",
            "NAT_PMP",
            "parse_log",
            "logfile",
            ".log",
            "theApp",
        )
        for forbidden in forbidden_dependencies:
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)

    def test_unknown_enum_is_never_promoted(self) -> None:
        mutated = copy.deepcopy(self.goldens["verified"])
        mutated["candidates"][0]["source"] = "FUTURE_MAPPER"
        self.assertFalse(self.validator.is_valid(mutated))
        result = self.consumer.consume_snapshot(mutated, self.schema)
        self.assertEqual(result["status"], "UNSUPPORTED_ENUM")
        self.assertEqual(result["verified_native_global_candidate_ids"], [])
        self.assertEqual(
            result["unsupported_enum_fields"], ["candidates[0].source"]
        )

    def test_unknown_verification_state_is_never_promoted(self) -> None:
        mutated = copy.deepcopy(self.goldens["verified"])
        mutated["candidates"][0]["verification_state"] = "PROBABLY_OK"
        result = self.consumer.consume_snapshot(mutated, self.schema)
        self.assertEqual(result["status"], "UNSUPPORTED_ENUM")
        self.assertEqual(result["verified_native_global_candidate_ids"], [])

    def test_additive_fields_are_ignored_only_by_compatibility_consumer(
        self,
    ) -> None:
        mutated = copy.deepcopy(self.goldens["verified"])
        mutated["future_snapshot_note"] = "ignored"
        mutated["future_enum_note"] = "NATIVE"
        mutated["future_digest_note"] = (
            mutated["candidates"][0]["local_endpoint"]["identity_digest"]
        )
        mutated["retry_count"] = 3
        mutated["enum"] = "NATIVE"
        mutated["digest"] = mutated["future_digest_note"]
        mutated["relationship_note"] = "still-redacted"
        mutated["future_unicode_note"] = "München résumé — válido"
        mutated["future_metadata"] = {
            "nested": {"counts": [1, 2, 3]}
        }
        mutated["candidates"][0]["future_candidate_note"] = "ignored"
        mutated["candidates"][0]["local_endpoint"]["future_note"] = "redacted"
        self.assertFalse(self.validator.is_valid(mutated))
        result = self.consumer.consume_snapshot(mutated, self.schema)
        self.assertEqual(result["status"], "OK")
        self.assertEqual(len(result["verified_native_global_candidate_ids"]), 1)

    def test_missing_required_field_fails_closed(self) -> None:
        mutated = copy.deepcopy(self.goldens["verified"])
        del mutated["candidates"][0]["evidence_digest"]
        self.assertFalse(self.validator.is_valid(mutated))
        result = self.consumer.consume_snapshot(mutated, self.schema)
        self.assertEqual(result["status"], "MALFORMED")
        self.assertEqual(result["verified_native_global_candidate_ids"], [])

    def test_malformed_known_structure_is_never_promoted(self) -> None:
        mutated = copy.deepcopy(self.goldens["verified"])
        mutated["candidates"][0]["published_endpoint"]["identity_digest"] = (
            "endpoint-v1:malformed"
        )
        result = self.consumer.consume_snapshot(mutated, self.schema)
        self.assertEqual(result["status"], "MALFORMED")
        self.assertEqual(result["verified_native_global_candidate_ids"], [])

    def test_unknown_schema_version_fails_closed(self) -> None:
        mutated = copy.deepcopy(self.goldens["verified"])
        mutated["schema_version"] = 2
        result = self.consumer.consume_snapshot(mutated, self.schema)
        self.assertEqual(result["status"], "UNSUPPORTED_SCHEMA")
        self.assertEqual(result["verified_native_global_candidate_ids"], [])

    def test_js_safe_integer_boundaries_are_exact(self) -> None:
        at_limit = copy.deepcopy(self.goldens["verified"])
        at_limit["topology_generation"] = MAX_SAFE_INTEGER
        at_limit["created_at_monotonic"] = MAX_SAFE_INTEGER
        at_limit["candidates"][0]["topology_generation"] = MAX_SAFE_INTEGER
        self.validator.validate(at_limit)
        self.assertEqual(
            self.consumer.consume_snapshot(at_limit, self.schema)["status"],
            "OK",
        )

        generation_overflow = copy.deepcopy(at_limit)
        generation_overflow["topology_generation"] = MAX_SAFE_INTEGER + 1
        generation_overflow["candidates"][0]["topology_generation"] = (
            MAX_SAFE_INTEGER + 1
        )
        self.assertFalse(self.validator.is_valid(generation_overflow))
        self.assertEqual(
            self.consumer.consume_snapshot(
                generation_overflow, self.schema
            )["status"],
            "MALFORMED",
        )

        time_overflow = copy.deepcopy(at_limit)
        time_overflow["created_at_monotonic"] = MAX_SAFE_INTEGER + 1
        self.assertFalse(self.validator.is_valid(time_overflow))
        self.assertEqual(
            self.consumer.consume_snapshot(time_overflow, self.schema)["status"],
            "MALFORMED",
        )

    def test_terminal_reason_matches_candidate_emptiness(self) -> None:
        nonempty_with_reason = copy.deepcopy(self.goldens["verified"])
        nonempty_with_reason["terminal_reason"] = "NO_ROUTE"
        self.assertFalse(self.validator.is_valid(nonempty_with_reason))
        self.assertEqual(
            self.consumer.consume_snapshot(
                nonempty_with_reason, self.schema
            )["status"],
            "MALFORMED",
        )

    def test_mapped_lease_zero_boundary_is_fail_closed(self) -> None:
        positive = copy.deepcopy(self.goldens["verified"])
        positive["candidates"][0]["lease_expires_at"]["remaining_ms"] = 1
        self.validator.validate(positive)
        result = self.consumer.consume_snapshot(positive, self.schema)
        self.assertEqual(result["status"], "OK")
        self.assertEqual(len(result["verified_native_global_candidate_ids"]), 1)

        verified_at_zero = copy.deepcopy(positive)
        verified_at_zero["candidates"][0]["lease_expires_at"][
            "remaining_ms"
        ] = 0
        self.assertFalse(self.validator.is_valid(verified_at_zero))
        result = self.consumer.consume_snapshot(verified_at_zero, self.schema)
        self.assertEqual(result["status"], "MALFORMED")
        self.assertEqual(result["verified_native_global_candidate_ids"], [])

        permanent = copy.deepcopy(self.goldens["verified"])
        permanent["candidates"][0]["lease_expires_at"] = None
        self.validator.validate(permanent)
        self.assertEqual(
            self.consumer.consume_snapshot(permanent, self.schema)["status"],
            "OK",
        )

        self.validator.validate(self.goldens["expired"])
        expired_result = self.consumer.consume_snapshot(
            self.goldens["expired"], self.schema
        )
        self.assertEqual(expired_result["status"], "OK")
        self.assertEqual(
            expired_result["verified_native_global_candidate_ids"], []
        )

        expired_above_zero = copy.deepcopy(self.goldens["expired"])
        expired_above_zero["candidates"][0]["lease_expires_at"][
            "remaining_ms"
        ] = 1
        self.assertFalse(self.validator.is_valid(expired_above_zero))
        self.assertEqual(
            self.consumer.consume_snapshot(
                expired_above_zero, self.schema
            )["status"],
            "MALFORMED",
        )

        candidate_at_zero = copy.deepcopy(self.goldens["candidate"])
        candidate_at_zero["candidates"][0]["lease_expires_at"][
            "remaining_ms"
        ] = 0
        self.assertFalse(self.validator.is_valid(candidate_at_zero))
        self.assertEqual(
            self.consumer.consume_snapshot(
                candidate_at_zero, self.schema
            )["status"],
            "MALFORMED",
        )

    def test_candidate_ids_are_snapshot_wide_unique(self) -> None:
        exact_duplicate = copy.deepcopy(self.goldens["verified"])
        exact_duplicate["candidates"].append(
            copy.deepcopy(exact_duplicate["candidates"][0])
        )
        self.assertFalse(self.validator.is_valid(exact_duplicate))
        result = self.consumer.consume_snapshot(exact_duplicate, self.schema)
        self.assertEqual(result["status"], "MALFORMED")
        self.assertEqual(result["verified_native_global_candidate_ids"], [])

        identity_collision = copy.deepcopy(self.goldens["verified"])
        second = copy.deepcopy(identity_collision["candidates"][0])
        second["transport"] = "UDP"
        identity_collision["candidates"].append(second)
        self.validator.validate(identity_collision)
        result = self.consumer.consume_snapshot(identity_collision, self.schema)
        self.assertEqual(result["status"], "MALFORMED")
        self.assertEqual(result["verified_native_global_candidate_ids"], [])

        reverse_collision = copy.deepcopy(self.goldens["verified"])
        same_identity = copy.deepcopy(reverse_collision["candidates"][0])
        same_identity["candidate_id"] = "candidate-v1:" + "9" * 64
        reverse_collision["candidates"].append(same_identity)
        self.validator.validate(reverse_collision)
        result = self.consumer.consume_snapshot(reverse_collision, self.schema)
        self.assertEqual(result["status"], "MALFORMED")
        self.assertEqual(result["verified_native_global_candidate_ids"], [])

    def test_recursive_sensitive_addition_matrix_is_fail_closed(self) -> None:
        cases = (
            ("top.public_ip", "top", "public_ip", "198.51.100.1"),
            ("top.publicIP", "top", "publicIP", "198.51.100.1"),
            ("top.publicip", "top", "publicip", "198.51.100.1"),
            ("top.public_port", "top", "public_port", 4662),
            (
                "candidate.external_port",
                "candidate",
                "external_port",
                4662,
            ),
            (
                "candidate.externalPort",
                "candidate",
                "externalPort",
                4662,
            ),
            (
                "candidate.socket_address",
                "candidate",
                "socket_address",
                "198.51.100.1:4662",
            ),
            (
                "endpoint.public_port",
                "endpoint",
                "public_port",
                4662,
            ),
            ("endpoint.ip", "endpoint", "ip", "198.51.100.1"),
            (
                "endpoint.locator",
                "endpoint",
                "locator",
                "ignored",
            ),
            (
                "endpoint.socketAddress",
                "endpoint",
                "socketAddress",
                "198.51.100.1:4662",
            ),
            (
                "top.innocent_ip_value",
                "top",
                "future_note",
                "198.51.100.1",
            ),
            (
                "top.nested_gateway",
                "top",
                "future_metadata",
                {"details": {"gateway": "redacted"}},
            ),
            (
                "top.innocent_url_value",
                "top",
                "future_note",
                "https://example.test:443/path",
            ),
            (
                "candidate.innocent_host_port",
                "candidate",
                "future_note",
                "example.test:4662",
            ),
            (
                "endpoint.innocent_ipv6_endpoint",
                "endpoint",
                "future_note",
                "[2001:db8::1]:4662",
            ),
            ("top.ipaddr", "top", "ipaddr", "redacted"),
            ("top.hostport", "top", "hostport", "redacted"),
            ("top.dstport", "top", "dstport", "redacted"),
            ("top.srcip", "top", "srcip", "redacted"),
            ("top.wanip", "top", "wanip", "redacted"),
            ("top.srcport", "top", "srcport", "redacted"),
            ("top.dstip", "top", "dstip", "redacted"),
            ("top.lanip", "top", "lanip", "redacted"),
            ("top.natport", "top", "natport", "redacted"),
            ("top.hostaddr", "top", "hostaddr", "redacted"),
            ("top.dport", "top", "dport", "redacted"),
            ("top.sport", "top", "sport", "redacted"),
            ("top.rport", "top", "rport", "redacted"),
            ("top.lport", "top", "lport", "redacted"),
            ("top.pubip", "top", "pubip", "redacted"),
            ("top.pubport", "top", "pubport", "redacted"),
            ("top.extip", "top", "extip", "redacted"),
            ("top.extport", "top", "extport", "redacted"),
            ("top.intip", "top", "intip", "redacted"),
            ("top.intport", "top", "intport", "redacted"),
            ("top.sockaddr", "top", "sockaddr", "redacted"),
            ("top.sockport", "top", "sockport", "redacted"),
            ("top.dip", "top", "dip", "redacted"),
            ("top.sip", "top", "sip", "redacted"),
            ("top.rip", "top", "rip", "redacted"),
            ("top.lip", "top", "lip", "redacted"),
            ("top.pubaddr", "top", "pubaddr", "redacted"),
            ("top.extaddr", "top", "extaddr", "redacted"),
            ("top.intaddr", "top", "intaddr", "redacted"),
            ("top.sockip", "top", "sockip", "redacted"),
            ("top.sockhost", "top", "sockhost", "redacted"),
            (
                "top.innocent_single_label_endpoint",
                "top",
                "future_note",
                "router:4662",
            ),
            (
                "top.innocent_trailing_dot_endpoint",
                "top",
                "future_note",
                "example.test.:4662",
            ),
            (
                "top.nested_single_label_endpoint",
                "top",
                "future_metadata",
                {
                    "relationship_note": {
                        "future_note": "router:4662"
                    }
                },
            ),
            (
                "top.nested_trailing_dot_endpoint",
                "top",
                "future_metadata",
                {
                    "relationship_note": {
                        "future_note": "example.test.:4662"
                    }
                },
            ),
            (
                "key.ip_literal",
                "top",
                "198.51.100.1",
                "redacted",
            ),
            (
                "key.ipv4_endpoint",
                "top",
                "198.51.100.1:4662",
                "redacted",
            ),
            (
                "key.ipv6_endpoint",
                "top",
                "[2001:db8::1]:4662",
                "redacted",
            ),
            (
                "key.url_locator",
                "top",
                "https://example.test:443/x",
                "redacted",
            ),
            (
                "value.idn_fqdn",
                "top",
                "future_note",
                "münchen.example:4662",
            ),
            (
                "value.idn_single_label",
                "top",
                "future_note",
                "über:4662",
            ),
            (
                "value.unicode_separator",
                "top",
                "future_note",
                "example。test:4662",
            ),
            (
                "value.network_path",
                "top",
                "future_note",
                "//example.test:443/x",
            ),
            (
                "key.idn_fqdn",
                "top",
                "münchen.example:4662",
                "redacted",
            ),
            (
                "key.idn_single_label",
                "top",
                "über:4662",
                "redacted",
            ),
            (
                "key.unicode_separator",
                "top",
                "example。test:4662",
                "redacted",
            ),
            (
                "key.network_path",
                "top",
                "//example.test:443/x",
                "redacted",
            ),
            (
                "nested.idn_fqdn",
                "top",
                "future_metadata",
                {"relationship_note": {"future_note": "münchen.example:4662"}},
            ),
            (
                "nested.idn_single_label",
                "top",
                "future_metadata",
                {"relationship_note": {"future_note": "über:4662"}},
            ),
            (
                "nested.unicode_separator",
                "top",
                "future_metadata",
                {"relationship_note": {"future_note": "example。test:4662"}},
            ),
            (
                "nested.network_path",
                "top",
                "future_metadata",
                {
                    "relationship_note": {
                        "future_note": "//example.test:443/x"
                    }
                },
            ),
            (
                "value.bracketed_ipv6_no_port",
                "top",
                "future_note",
                "[2001:db8::1]",
            ),
            (
                "key.bracketed_ipv6_no_port",
                "top",
                "[2001:db8::1]",
                "redacted",
            ),
            (
                "nested.bracketed_ipv6_no_port",
                "top",
                "future_metadata",
                {"relationship_note": {"future_note": "[2001:db8::1]"}},
            ),
            (
                "value.ipv4_trailing_dot",
                "top",
                "future_note",
                "198.51.100.1.",
            ),
            (
                "key.ipv4_trailing_dot",
                "top",
                "198.51.100.1.",
                "redacted",
            ),
            (
                "nested.ipv4_trailing_dot",
                "top",
                "future_metadata",
                {"relationship_note": {"future_note": "198.51.100.1."}},
            ),
            (
                "value.ipv6_zone",
                "top",
                "future_note",
                "[fe80::1%eth0]",
            ),
            (
                "value.parenthesized_ip",
                "top",
                "future_note",
                "(198.51.100.1)",
            ),
            (
                "value.single_quoted_ip",
                "top",
                "future_note",
                "'198.51.100.1'",
            ),
            (
                "value.embedded_ipv4",
                "top",
                "future_note",
                "peer=198.51.100.1",
            ),
            (
                "value.embedded_ipv6",
                "top",
                "future_note",
                "note [2001:db8::1]",
            ),
            (
                "key.embedded_ipv4",
                "top",
                "peer=198.51.100.1",
                "redacted",
            ),
            (
                "nested.embedded_ipv6",
                "top",
                "future_metadata",
                {
                    "relationship_note": {
                        "future_note": "note [2001:db8::1]"
                    }
                },
            ),
            (
                "value.ipv4_cidr",
                "top",
                "future_note",
                "198.51.100.1/32",
            ),
            (
                "key.ipv4_cidr",
                "top",
                "198.51.100.1/32",
                "redacted",
            ),
            (
                "nested.ipv4_cidr",
                "top",
                "future_metadata",
                {
                    "relationship_note": {
                        "future_note": "198.51.100.1/32"
                    }
                },
            ),
            (
                "value.ipv6_cidr",
                "top",
                "future_note",
                "2001:db8::1/128",
            ),
            (
                "key.ipv6_cidr",
                "top",
                "2001:db8::1/128",
                "redacted",
            ),
            (
                "nested.ipv6_cidr",
                "top",
                "future_metadata",
                {
                    "relationship_note": {
                        "future_note": "2001:db8::1/128"
                    }
                },
            ),
            (
                "value.ipv4_authority_path",
                "top",
                "future_note",
                "198.51.100.1:4662/path",
            ),
            (
                "value.hostname_authority_path",
                "top",
                "future_note",
                "example.test:4662/path",
            ),
            (
                "value.ambiguous_version",
                "top",
                "future_note",
                "version:2",
            ),
            (
                "value.ambiguous_ticket",
                "top",
                "future_note",
                "ticket:12345",
            ),
            (
                "value.ambiguous_time",
                "top",
                "future_note",
                "12:34",
            ),
            (
                "value.ambiguous_ratio",
                "top",
                "future_note",
                "ratio:1",
            ),
            (
                "value.ambiguous_chapter",
                "top",
                "future_note",
                "chapter:7",
            ),
        )
        for name, level, key, value in cases:
            mutated = copy.deepcopy(self.goldens["verified"])
            if level == "top":
                target = mutated
            elif level == "candidate":
                target = mutated["candidates"][0]
            else:
                target = mutated["candidates"][0]["local_endpoint"]
            target[key] = value
            with self.subTest(name=name):
                self.assertFalse(self.validator.is_valid(mutated))
                result = self.consumer.consume_snapshot(mutated, self.schema)
                self.assertEqual(result["status"], "MALFORMED")
                self.assertEqual(
                    result["verified_native_global_candidate_ids"], []
                )

    def test_secret_and_authorization_fields_are_recursive_fail_closed(
        self,
    ) -> None:
        sensitive_fields = (
            "owner_token",
            "protocol_nonce",
            "ownership_nonce",
            "cleanup_token",
            "object_pointer",
            "raw_evidence",
            "secret",
            "credential",
            "password",
            "auth",
            "authorization",
        )
        for field in sensitive_fields:
            for level in ("top", "candidate", "endpoint", "nested"):
                mutated = copy.deepcopy(self.goldens["verified"])
                if level == "top":
                    target = mutated
                elif level == "candidate":
                    target = mutated["candidates"][0]
                elif level == "endpoint":
                    target = mutated["candidates"][0]["local_endpoint"]
                else:
                    mutated["future_metadata"] = {"relationship_note": {}}
                    target = mutated["future_metadata"]["relationship_note"]
                target[field] = "redacted"
                with self.subTest(field=field, level=level):
                    self.assertFalse(self.validator.is_valid(mutated))
                    result = self.consumer.consume_snapshot(
                        mutated, self.schema
                    )
                    self.assertEqual(result["status"], "MALFORMED")
                    self.assertEqual(
                        result["verified_native_global_candidate_ids"], []
                    )

    def test_invalid_unicode_and_non_json_values_never_escape_typed_failure(
        self,
    ) -> None:
        cases: list[tuple[str, dict[str, Any]]] = []

        surrogate_value = copy.deepcopy(self.goldens["verified"])
        surrogate_value["future_note"] = "\ud800"
        cases.append(("surrogate_value", surrogate_value))

        surrogate_key = copy.deepcopy(self.goldens["verified"])
        surrogate_key["\ud800"] = "redacted"
        cases.append(("surrogate_key", surrogate_key))

        nested_surrogate = copy.deepcopy(self.goldens["verified"])
        nested_surrogate["future_metadata"] = {
            "relationship_note": {"future_note": "\ud800"}
        }
        cases.append(("nested_surrogate", nested_surrogate))

        for name, value in (
            ("set", {1, 2}),
            ("tuple", ("not", "json")),
            ("bytes", b"not-json"),
            ("nan", float("nan")),
            ("positive_infinity", float("inf")),
            ("negative_infinity", float("-inf")),
            ("pathological_integer", 10**100000),
        ):
            mutated = copy.deepcopy(self.goldens["verified"])
            mutated["future_value"] = value
            cases.append((name, mutated))

        known_non_finite = copy.deepcopy(self.goldens["verified"])
        known_non_finite["created_at_monotonic"] = float("nan")
        cases.append(("known_non_finite", known_non_finite))

        for name, mutated in cases:
            with self.subTest(name=name):
                result = self.consumer.consume_snapshot(mutated, self.schema)
                self.assertEqual(result["status"], "MALFORMED")
                self.assertEqual(
                    result["verified_native_global_candidate_ids"], []
                )

    def test_iterative_scanner_budgets_fail_closed_without_exceptions(
        self,
    ) -> None:
        def nested_chain(levels: int) -> Any:
            value: Any = "safe"
            for _ in range(levels):
                value = {"relationship_note": value}
            return value

        under_depth = copy.deepcopy(self.goldens["empty"])
        under_depth["future_tree"] = nested_chain(
            self.consumer.MAX_V1_DEPTH - 1
        )
        self.assertEqual(
            self.consumer.consume_snapshot(under_depth, self.schema)["status"],
            "OK",
        )

        over_depth = copy.deepcopy(self.goldens["empty"])
        over_depth["future_tree"] = nested_chain(
            self.consumer.MAX_V1_DEPTH
        )
        result = self.consumer.consume_snapshot(over_depth, self.schema)
        self.assertEqual(result["status"], "MALFORMED")
        self.assertEqual(result["verified_native_global_candidate_ids"], [])

        depth_1500 = copy.deepcopy(self.goldens["verified"])
        depth_1500["future_tree"] = nested_chain(1500)
        result = self.consumer.consume_snapshot(depth_1500, self.schema)
        self.assertEqual(result["status"], "MALFORMED")
        self.assertEqual(result["verified_native_global_candidate_ids"], [])

        under_string = copy.deepcopy(self.goldens["empty"])
        under_string["future_note"] = (
            "x" * self.consumer.MAX_V1_STRING_BYTES
        )
        self.assertEqual(
            self.consumer.consume_snapshot(under_string, self.schema)["status"],
            "OK",
        )
        over_string = copy.deepcopy(under_string)
        over_string["future_note"] += "x"
        self.assertEqual(
            self.consumer.consume_snapshot(over_string, self.schema)["status"],
            "MALFORMED",
        )

        under_nodes = copy.deepcopy(self.goldens["empty"])
        under_nodes["future_values"] = list(
            range(self.consumer.MAX_V1_NODES - 7)
        )
        self.assertEqual(
            self.consumer.consume_snapshot(under_nodes, self.schema)["status"],
            "OK",
        )
        over_nodes = copy.deepcopy(under_nodes)
        over_nodes["future_values"].append(0)
        self.assertEqual(
            self.consumer.consume_snapshot(over_nodes, self.schema)["status"],
            "MALFORMED",
        )

        under_containers = copy.deepcopy(self.goldens["empty"])
        under_containers["future_containers"] = [
            [] for _ in range(self.consumer.MAX_V1_CONTAINERS - 3)
        ]
        self.assertEqual(
            self.consumer.consume_snapshot(
                under_containers, self.schema
            )["status"],
            "OK",
        )
        over_containers = copy.deepcopy(under_containers)
        over_containers["future_containers"].append([])
        self.assertEqual(
            self.consumer.consume_snapshot(
                over_containers, self.schema
            )["status"],
            "MALFORMED",
        )

        under_additive_bytes = copy.deepcopy(self.goldens["empty"])
        under_additive_bytes["future_payload"] = [
            "x" * self.consumer.MAX_V1_STRING_BYTES for _ in range(15)
        ]
        self.assertEqual(
            self.consumer.consume_snapshot(
                under_additive_bytes, self.schema
            )["status"],
            "OK",
        )
        over_additive_bytes = copy.deepcopy(under_additive_bytes)
        over_additive_bytes["future_payload"].append(
            "x" * self.consumer.MAX_V1_STRING_BYTES
        )
        self.assertEqual(
            self.consumer.consume_snapshot(
                over_additive_bytes, self.schema
            )["status"],
            "MALFORMED",
        )

        def reviewer_accounting_case(tail_length: int) -> dict[str, Any]:
            snapshot = copy.deepcopy(self.goldens["empty"])
            snapshot["x"] = (
                [512] * 100
                + ["x" * self.consumer.MAX_V1_STRING_BYTES] * 15
                + ["x" * tail_length]
            )
            return snapshot

        for total, tail_length, expected in (
            (65535, 3792, "OK"),
            (65536, 3793, "OK"),
            (65537, 3794, "MALFORMED"),
        ):
            with self.subTest(additive_bytes=total):
                result = self.consumer.consume_snapshot(
                    reviewer_accounting_case(tail_length), self.schema
                )
                self.assertEqual(result["status"], expected)
                if expected == "MALFORMED":
                    self.assertEqual(
                        result["verified_native_global_candidate_ids"], []
                    )

    def test_sanitized_endpoints_never_export_raw_ports(self) -> None:
        endpoint_schema = self.schema["$defs"]["endpoint"]
        self.assertNotIn("port", endpoint_schema["required"])
        self.assertNotIn("port", endpoint_schema["properties"])

        payload = SCHEMA_PATH.read_text(encoding="utf-8")
        payload += "\n" + "\n".join(
            path.read_text(encoding="utf-8")
            for path in sorted(GOLDEN_DIR.glob("*.json"))
        )
        self.assertNotIn('"port"', payload)
        self.assertNotIn("4662", payload)
        self.assertNotIn("55000", payload)

        for field, value in (
            ("port", 4662),
            ("raw_port", 4662),
            ("ip_address", "198.51.100.1"),
        ):
            leaked = copy.deepcopy(self.goldens["verified"])
            leaked["candidates"][0]["local_endpoint"][field] = value
            with self.subTest(field=field):
                self.assertFalse(self.validator.is_valid(leaked))
                result = self.consumer.consume_snapshot(leaked, self.schema)
                self.assertEqual(result["status"], "MALFORMED")
                self.assertEqual(
                    result["verified_native_global_candidate_ids"], []
                )

        empty_without_reason = copy.deepcopy(self.goldens["empty"])
        empty_without_reason["terminal_reason"] = "NONE"
        self.assertFalse(self.validator.is_valid(empty_without_reason))
        self.assertEqual(
            self.consumer.consume_snapshot(
                empty_without_reason, self.schema
            )["status"],
            "MALFORMED",
        )

    def test_non_native_global_kinds_cannot_be_verified(self) -> None:
        for kind in ("HOST_V6", "DIRECT_V4", "MAPPED_V4"):
            for network_kind in ("OVERLAY", "UNKNOWN"):
                mutated = self._verified_snapshot_for_kind(kind)
                mutated["candidates"][0]["network_kind"] = network_kind
                with self.subTest(kind=kind, network_kind=network_kind):
                    self.assertFalse(self.validator.is_valid(mutated))
                    result = self.consumer.consume_snapshot(
                        mutated, self.schema
                    )
                    self.assertEqual(result["status"], "MALFORMED")
                    self.assertEqual(
                        result["verified_native_global_candidate_ids"], []
                    )

    def test_direct_and_host_endpoint_classes_are_exact(self) -> None:
        direct = self._verified_snapshot_for_kind("DIRECT_V4")
        self.validator.validate(direct)

        bad_direct = copy.deepcopy(direct)
        bad_direct["candidates"][0]["local_endpoint"]["address_class"] = (
            "RFC1918"
        )
        self.assertFalse(self.validator.is_valid(bad_direct))
        bad_direct = copy.deepcopy(direct)
        bad_direct["candidates"][0]["published_endpoint"]["address_class"] = (
            "RFC1918"
        )
        self.assertFalse(self.validator.is_valid(bad_direct))

        host = self._verified_snapshot_for_kind("HOST_V6")
        self.validator.validate(host)

        bad_host = copy.deepcopy(host)
        bad_host["candidates"][0]["local_endpoint"]["address_class"] = (
            "UNIQUE_LOCAL"
        )
        self.assertFalse(self.validator.is_valid(bad_host))
        bad_host = copy.deepcopy(host)
        bad_host["candidates"][0]["published_endpoint"]["address_class"] = (
            "UNIQUE_LOCAL"
        )
        self.assertFalse(self.validator.is_valid(bad_host))

    def test_sanitized_projection_boundary_is_frozen(self) -> None:
        self.assertEqual(
            self.schema["$comment"],
            "SANITIZED_NON_ACTIONABLE_PROJECTION; "
            "INTERNAL_TYPED_VIEW_REQUIRED_FOR_ROUTING; "
            "NEVER_RECONSTRUCT_ENDPOINTS_FROM_DIGESTS",
        )
        contract = (
            ROOT
            / "docs"
            / "V9.2_MX01_DIRECT_CANDIDATE_SNAPSHOT_V1.md"
        ).read_text(encoding="utf-8")
        for marker in (
            "non-actionable diagnostic projection",
            "process-local, typed, non-serializable",
            "MUST NOT attempt to reconstruct",
            "MX02 and any v9.3 handoff",
            "non-exported producer-session key",
            "stable for the full producer session",
            "MUST be regenerated on producer restart",
            "MUST NOT rotate per export",
            "each `candidate_id` MUST occur exactly once",
            "finite mapped lease at zero is never verified",
            "raw TCP/UDP port number",
            "real address and numeric port remain solely",
            "one logical identity MUST map to exactly one",
            "recursively inspect additive keys and values",
            "benign wrapper",
            "depth 1500 without exception",
            "recursion/stack/encoding/conversion exception",
            "without attempting ASCII hostname validation",
            "syntactically ambiguous with a network endpoint",
            "`198.51.100.1/32` and `2001:db8::1/128`",
            "`//host:port/path`",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, contract)
        self.assertNotIn("export-scoped random key", contract)
        self.assertEqual(self.consumer.MAX_V1_DEPTH, 32)
        self.assertEqual(self.consumer.MAX_V1_NODES, 4096)
        self.assertEqual(self.consumer.MAX_V1_CONTAINERS, 512)
        self.assertEqual(self.consumer.MAX_V1_STRING_BYTES, 4096)
        self.assertEqual(self.consumer.MAX_V1_ADDITIVE_BYTES, 65536)

    def test_generation_semantics_fail_closed(self) -> None:
        current_marked_stale = copy.deepcopy(self.goldens["stale"])
        current_marked_stale["candidates"][0]["topology_generation"] = (
            current_marked_stale["topology_generation"]
        )
        result = self.consumer.consume_snapshot(current_marked_stale, self.schema)
        self.assertEqual(result["status"], "MALFORMED")

        verified_from_old_generation = copy.deepcopy(self.goldens["verified"])
        verified_from_old_generation["topology_generation"] += 1
        result = self.consumer.consume_snapshot(
            verified_from_old_generation, self.schema
        )
        self.assertEqual(result["status"], "MALFORMED")
        self.assertEqual(result["verified_native_global_candidate_ids"], [])

    def test_goldens_contain_no_raw_addresses_or_sensitive_identifiers(
        self,
    ) -> None:
        forbidden_keys = {
            "ownership_nonce",
            "owner_token",
            "interface_guid",
            "interface_name",
            "adapter_name",
            "adapter_description",
            "raw_address",
            "ip_address",
            "port",
            "pointer",
            "secret",
        }
        for name, golden in self.goldens.items():
            with self.subTest(name=name):
                keys = {
                    value
                    for value in _walk(golden)
                    if isinstance(value, str)
                }
                self.assertTrue(forbidden_keys.isdisjoint(keys))
                for value in _walk(golden):
                    if not isinstance(value, str):
                        continue
                    try:
                        ipaddress.ip_address(value)
                    except ValueError:
                        continue
                    self.fail(f"{name} exposes an IP address literal: {value}")

    def test_out_of_scope_92_types_are_absent_from_schema_and_goldens(self) -> None:
        payload = SCHEMA_PATH.read_text(encoding="utf-8")
        payload += "\n" + "\n".join(
            path.read_text(encoding="utf-8")
            for path in sorted(GOLDEN_DIR.glob("*.json"))
        )
        for absent in (
            "SRFLX_UDP",
            "RDV",
            "PREDICTED",
            "PUNCH",
            "DCO",
            "BIRTHDAY",
            "DVL",
            "RELAY",
            "REMOTE_MESSAGE",
            "ROUTE_DECISION",
        ):
            with self.subTest(absent=absent):
                self.assertNotIn(absent, payload.upper())


if __name__ == "__main__":
    unittest.main()
