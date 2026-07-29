"""Contract-only consumer used by the MX01 compatibility tests."""

from __future__ import annotations

import ipaddress
import math
import re
from typing import Any
from urllib.parse import urlsplit

import jsonschema


_TOP_LEVEL_FIELDS = {
    "schema_version",
    "topology_generation",
    "created_at_monotonic",
    "candidates",
    "terminal_reason",
}

_CANDIDATE_ENUM_FIELDS = {
    "kind": "kind",
    "transport": "transport",
    "network_kind": "network_kind",
    "source": "source",
    "scope": "scope",
    "ownership_state": "ownership_state",
    "verification_state": "verification",
    "reason_code": "reason",
}

_REQUIRED_CANDIDATE_FIELDS = {
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
    "lease_expires_at",
    "ownership_state",
    "verification_state",
    "verification_attempt_id",
    "evidence_digest",
    "reason_code",
    "topology_generation",
}

_ENDPOINT_FIELDS = {
    "address_family",
    "address_class",
    "identity_digest",
}

_SENSITIVE_ADDITIVE_TOKENS = {
    "addr",
    "adapter",
    "address",
    "auth",
    "authorization",
    "authz",
    "attempt",
    "cleanup",
    "cred",
    "credential",
    "creds",
    "endpoint",
    "evidence",
    "gateway",
    "host",
    "hostname",
    "interface",
    "ip",
    "ipv4",
    "ipv6",
    "locator",
    "nic",
    "nonce",
    "owner",
    "ownership",
    "passwd",
    "password",
    "pointer",
    "port",
    "pwd",
    "raw",
    "secret",
    "socket",
    "token",
}

_LOCATOR_COMPOUND_PREFIXES = {
    "bind",
    "client",
    "d",
    "dst",
    "destination",
    "dest",
    "external",
    "ext",
    "host",
    "int",
    "ip",
    "internal",
    "l",
    "lan",
    "listen",
    "local",
    "nat",
    "peer",
    "private",
    "pub",
    "public",
    "r",
    "remote",
    "s",
    "server",
    "sock",
    "source",
    "src",
    "wan",
}

_LEASE_FIELDS = {
    "basis",
    "remaining_ms",
}

MAX_V1_DEPTH = 32
MAX_V1_NODES = 4096
MAX_V1_CONTAINERS = 512
MAX_V1_STRING_BYTES = 4096
MAX_V1_ADDITIVE_BYTES = 65536


def _enum_values(schema: dict[str, Any], definition: str) -> set[str]:
    return set(schema["$defs"][definition]["enum"])


def _key_tokens(key: str) -> set[str]:
    camel_split = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", key)
    return {
        token
        for token in re.split(r"[^a-z0-9]+", camel_split.lower())
        if token
    }


def _key_denotes_sensitive_locator(key: str) -> bool:
    tokens = _key_tokens(key)
    if not _SENSITIVE_ADDITIVE_TOKENS.isdisjoint(tokens):
        return True

    compact = "".join(tokens)
    long_terms = (
        "adapter",
        "address",
        "endpoint",
        "gateway",
        "hostname",
        "interface",
        "locator",
        "socket",
    )
    if any(
        compact.startswith(term) or compact.endswith(term)
        for term in long_terms
    ):
        return True
    secret_terms = (
        "authorization",
        "cleanup",
        "credential",
        "evidence",
        "nonce",
        "owner",
        "ownership",
        "password",
        "pointer",
        "secret",
        "token",
    )
    if any(
        compact.startswith(term) or compact.endswith(term)
        for term in secret_terms
    ):
        return True
    return any(
        compact.startswith(prefix + term)
        for prefix in _LOCATOR_COMPOUND_PREFIXES
        for term in (
            "addr",
            "address",
            "host",
            "hostname",
            "ip",
            "ipv4",
            "ipv6",
            "port",
        )
    )


def _is_ip_literal(value: str) -> bool:
    candidate = value.strip()
    wrapper_pairs = {
        "'": "'",
        "\"": "\"",
        "(": ")",
        "[": "]",
        "{": "}",
        "<": ">",
    }
    while (
        len(candidate) >= 2
        and candidate[0] in wrapper_pairs
        and candidate[-1] == wrapper_pairs[candidate[0]]
    ):
        candidate = candidate[1:-1].strip()
    if candidate.endswith("."):
        candidate = candidate[:-1]

    candidates = [candidate]
    if ":" in candidate and "%" in candidate:
        candidates.append(candidate.split("%", 1)[0])
    for normalized in candidates:
        try:
            ipaddress.ip_address(normalized)
        except ValueError:
            continue
        return True
    return False


def _is_ip_network_literal(value: str) -> bool:
    candidate = value.strip()
    if "/" not in candidate:
        return False
    try:
        ipaddress.ip_interface(candidate)
    except ValueError:
        try:
            ipaddress.ip_network(candidate, strict=False)
        except ValueError:
            return False
    return True


def _is_endpoint_literal(value: str) -> bool:
    bracketed = re.fullmatch(r"\[([^\]]+)\]:(\d+)", value)
    if bracketed:
        return _is_ip_literal(bracketed.group(1))

    if value.count(":") == 1:
        host, numeric_port = value.rsplit(":", 1)
        if host and numeric_port.isdigit():
            return True

    if value.startswith("//") or re.match(
        r"^[A-Za-z][A-Za-z0-9+.-]*://", value
    ):
        try:
            parsed = urlsplit(value)
        except ValueError:
            return False
        return parsed.hostname is not None

    if re.fullmatch(r"[^/?#\s]+:\d+(?:[/?#].*)", value):
        try:
            parsed = urlsplit("//" + value)
            port = parsed.port
        except ValueError:
            return True
        return parsed.hostname is not None and port is not None

    return False


def _string_exposes_sensitive_locator(value: str) -> bool:
    stripped = value.strip()
    if (
        _is_ip_literal(stripped)
        or _is_ip_network_literal(stripped)
        or _is_endpoint_literal(stripped)
    ):
        return True
    for token in re.split(r"[\s,;=(){}<>\"'\[\]]+", stripped):
        if token and (
            _is_ip_literal(token)
            or _is_ip_network_literal(token)
            or _is_endpoint_literal(token)
        ):
            return True
    return False


def _additive_scalar_size(value: Any) -> int:
    if value is None:
        return 4
    if isinstance(value, bool):
        return 5
    if isinstance(value, int):
        try:
            return len(str(value))
        except (MemoryError, OverflowError, ValueError):
            return MAX_V1_ADDITIVE_BYTES + 1
    if isinstance(value, float):
        return 24
    return 16


def _known_child_context(context: str, key: str) -> str | None:
    if context == "top" and key in _TOP_LEVEL_FIELDS:
        return "candidate_list" if key == "candidates" else "known"
    if context == "candidate" and key in _REQUIRED_CANDIDATE_FIELDS:
        if key in ("local_endpoint", "published_endpoint"):
            return "endpoint"
        if key == "lease_expires_at":
            return "lease"
        return "known"
    if context == "endpoint" and key in _ENDPOINT_FIELDS:
        return "known"
    if context == "lease" and key in _LEASE_FIELDS:
        return "known"
    return None


def _snapshot_violates_privacy_or_budget(value: Any) -> bool:
    stack: list[tuple[Any, str, int, bool]] = [(value, "top", 0, False)]
    node_count = 0
    container_count = 0
    additive_bytes = 0

    while stack:
        current, context, depth, is_additive = stack.pop()
        node_count += 1
        if node_count > MAX_V1_NODES or depth > MAX_V1_DEPTH:
            return True
        if not isinstance(
            current, (dict, list, str, int, float, bool, type(None))
        ):
            return True
        if isinstance(current, float) and not math.isfinite(current):
            return True

        if isinstance(current, str):
            if len(current) > MAX_V1_STRING_BYTES:
                return True
            try:
                encoded_length = len(current.encode("utf-8"))
            except (MemoryError, UnicodeEncodeError):
                return True
            if encoded_length > MAX_V1_STRING_BYTES:
                return True
            if is_additive:
                additive_bytes += encoded_length
                if _string_exposes_sensitive_locator(current):
                    return True
            if additive_bytes > MAX_V1_ADDITIVE_BYTES:
                return True
            continue

        if isinstance(current, (dict, list)):
            container_count += 1
            if container_count > MAX_V1_CONTAINERS:
                return True
            if is_additive:
                additive_bytes += 2
                if additive_bytes > MAX_V1_ADDITIVE_BYTES:
                    return True

        if isinstance(current, dict):
            for key, child in current.items():
                if not isinstance(key, str):
                    return True
                if len(key) > MAX_V1_STRING_BYTES:
                    return True
                try:
                    key_bytes = len(key.encode("utf-8"))
                except (MemoryError, UnicodeEncodeError):
                    return True
                if key_bytes > MAX_V1_STRING_BYTES:
                    return True

                child_context = (
                    None
                    if is_additive
                    else _known_child_context(context, key)
                )
                child_is_additive = is_additive or child_context is None
                if child_is_additive:
                    additive_bytes += key_bytes
                    if additive_bytes > MAX_V1_ADDITIVE_BYTES:
                        return True
                    if _key_denotes_sensitive_locator(
                        key
                    ) or _string_exposes_sensitive_locator(key):
                        return True
                    child_context = "additive"
                stack.append(
                    (child, child_context or "additive", depth + 1,
                     child_is_additive)
                )
        elif isinstance(current, list):
            for child in current:
                if is_additive:
                    child_context = "additive"
                    child_is_additive = True
                elif context == "candidate_list":
                    child_context = "candidate"
                    child_is_additive = False
                else:
                    child_context = "known"
                    child_is_additive = False
                stack.append(
                    (child, child_context, depth + 1, child_is_additive)
                )
        elif is_additive:
            additive_bytes += _additive_scalar_size(current)
            if additive_bytes > MAX_V1_ADDITIVE_BYTES:
                return True

    return False


def _logical_identity_signature(
    candidate: dict[str, Any],
) -> tuple[Any, ...] | None:
    local_endpoint = candidate.get("local_endpoint")
    published_endpoint = candidate.get("published_endpoint")
    if not isinstance(local_endpoint, dict) or not isinstance(
        published_endpoint, dict
    ):
        return None
    signature = (
        candidate.get("kind"),
        candidate.get("transport"),
        local_endpoint.get("identity_digest"),
        published_endpoint.get("identity_digest"),
        candidate.get("interface_identity_digest"),
        candidate.get("mapping_identity"),
        candidate.get("topology_generation"),
    )
    if not all(
        isinstance(item, (str, int)) or item is None for item in signature
    ):
        return None
    return signature


def _project_candidate(candidate: dict[str, Any]) -> dict[str, Any]:
    projected = {
        field: candidate[field]
        for field in _REQUIRED_CANDIDATE_FIELDS
        if field in candidate
    }
    for endpoint_field in ("local_endpoint", "published_endpoint"):
        endpoint = candidate.get(endpoint_field)
        if isinstance(endpoint, dict):
            projected[endpoint_field] = {
                field: endpoint[field]
                for field in _ENDPOINT_FIELDS
                if field in endpoint
            }
    lease = candidate.get("lease_expires_at")
    if isinstance(lease, dict):
        projected["lease_expires_at"] = {
            field: lease[field] for field in _LEASE_FIELDS if field in lease
        }
    return projected


def _project_snapshot(snapshot: dict[str, Any]) -> dict[str, Any]:
    projected = {
        field: snapshot[field] for field in _TOP_LEVEL_FIELDS if field in snapshot
    }
    candidates = snapshot.get("candidates")
    if isinstance(candidates, list):
        projected["candidates"] = [
            _project_candidate(candidate)
            if isinstance(candidate, dict)
            else candidate
            for candidate in candidates
        ]
    return projected


def consume_snapshot(
    snapshot: dict[str, Any], schema: dict[str, Any]
) -> dict[str, Any]:
    """Return facts a V1 observer can safely derive from one snapshot.

    Unknown additive fields are ignored. Unknown enum values, missing V1
    fields, stale generations, and incomplete verification all fail closed.
    """

    if not isinstance(snapshot, dict) or _snapshot_violates_privacy_or_budget(
        snapshot
    ):
        return {
            "status": "MALFORMED",
            "verified_native_global_candidate_ids": [],
            "unsupported_enum_fields": [],
        }

    if snapshot.get("schema_version") != 1:
        return {
            "status": "UNSUPPORTED_SCHEMA",
            "verified_native_global_candidate_ids": [],
            "unsupported_enum_fields": [],
        }

    if not _TOP_LEVEL_FIELDS.issubset(snapshot):
        return {
            "status": "MALFORMED",
            "verified_native_global_candidate_ids": [],
            "unsupported_enum_fields": [],
        }

    generation = snapshot.get("topology_generation")
    candidates = snapshot.get("candidates")
    if (
        not isinstance(generation, int)
        or isinstance(generation, bool)
        or generation < 1
        or not isinstance(candidates, list)
    ):
        return {
            "status": "MALFORMED",
            "verified_native_global_candidate_ids": [],
            "unsupported_enum_fields": [],
        }

    unsupported: list[str] = []
    verified: list[str] = []
    malformed_generation = False
    malformed_semantics = False
    seen_candidate_ids: set[str] = set()
    seen_identity_signatures: set[tuple[Any, ...]] = set()
    reason_values = _enum_values(schema, "reason")
    if snapshot.get("terminal_reason") not in reason_values:
        unsupported.append("terminal_reason")

    for index, candidate in enumerate(candidates):
        if (
            not isinstance(candidate, dict)
            or not _REQUIRED_CANDIDATE_FIELDS.issubset(candidate)
        ):
            return {
                "status": "MALFORMED",
                "verified_native_global_candidate_ids": [],
                "unsupported_enum_fields": [],
            }

        candidate_has_unknown_enum = False
        for field, definition in _CANDIDATE_ENUM_FIELDS.items():
            if candidate.get(field) not in _enum_values(schema, definition):
                unsupported.append(f"candidates[{index}].{field}")
                candidate_has_unknown_enum = True

        if candidate_has_unknown_enum:
            continue

        candidate_id = candidate.get("candidate_id")
        if isinstance(candidate_id, str):
            if candidate_id in seen_candidate_ids:
                malformed_semantics = True
            seen_candidate_ids.add(candidate_id)

        identity_signature = _logical_identity_signature(candidate)
        if identity_signature is not None:
            if identity_signature in seen_identity_signatures:
                malformed_semantics = True
            seen_identity_signatures.add(identity_signature)

        candidate_generation = candidate.get("topology_generation")
        verification_state = candidate.get("verification_state")
        is_stale = verification_state == "STALE"
        if (
            not isinstance(candidate_generation, int)
            or isinstance(candidate_generation, bool)
            or (is_stale and candidate_generation >= generation)
            or (not is_stale and candidate_generation != generation)
        ):
            malformed_generation = True
            continue

        is_current = candidate_generation == generation
        is_verified = verification_state == "VERIFIED"
        lease = candidate.get("lease_expires_at")
        if candidate.get("kind") == "MAPPED_V4" and isinstance(lease, dict):
            remaining = lease.get("remaining_ms")
            if (
                isinstance(remaining, int)
                and not isinstance(remaining, bool)
                and (
                    (remaining == 0 and verification_state != "EXPIRED")
                    or (verification_state == "EXPIRED" and remaining != 0)
                )
            ):
                malformed_semantics = True
        has_bound_evidence = (
            isinstance(candidate.get("verification_attempt_id"), str)
            and isinstance(candidate.get("evidence_digest"), str)
        )
        is_native_global = (
            candidate.get("network_kind") == "NATIVE"
            and candidate.get("scope") == "GLOBAL"
        )
        if is_current and is_verified and has_bound_evidence and is_native_global:
            verified.append(candidate["candidate_id"])

    if malformed_generation or malformed_semantics:
        return {
            "status": "MALFORMED",
            "verified_native_global_candidate_ids": [],
            "unsupported_enum_fields": [],
        }

    if unsupported:
        return {
            "status": "UNSUPPORTED_ENUM",
            "verified_native_global_candidate_ids": [],
            "unsupported_enum_fields": unsupported,
        }

    validator_type = jsonschema.validators.validator_for(schema)
    try:
        validator_type(schema).validate(_project_snapshot(snapshot))
    except (jsonschema.SchemaError, jsonschema.ValidationError):
        return {
            "status": "MALFORMED",
            "verified_native_global_candidate_ids": [],
            "unsupported_enum_fields": [],
        }

    return {
        "status": "OK",
        "verified_native_global_candidate_ids": verified,
        "unsupported_enum_fields": [],
    }
