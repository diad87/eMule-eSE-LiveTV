"""Non-actionable v9.3 handoff consumer for the frozen MX01 JSON contract."""

from __future__ import annotations

from typing import Any


def _result(status: str, reasons: list[str] | None = None) -> dict[str, Any]:
    return {
        "status": status,
        "candidate_facts": [],
        "verified_candidate_ids": [],
        "ignored_stale_candidate_ids": [],
        "rejection_reason_codes": reasons or [],
    }


def _rejection_reason_codes(snapshot: Any) -> list[str]:
    if not isinstance(snapshot, dict):
        return []
    candidates = snapshot.get("candidates", [])
    if not isinstance(candidates, list) or not candidates:
        return []
    reasons: list[str] = []
    for candidate in candidates:
        if not isinstance(candidate, dict):
            continue
        lease = candidate.get("lease_expires_at")
        if candidate.get("verification_state") == "STALE" and candidate.get("topology_generation") == snapshot.get("topology_generation"):
            reasons.append("STALE_GENERATION")
        elif candidate.get("verification_state") != "STALE" and candidate.get("topology_generation") != snapshot.get("topology_generation"):
            reasons.append("STALE_GENERATION")
        elif candidate.get("verification_state") == "VERIFIED" and (
            candidate.get("evidence_digest") is None
            or candidate.get("verification_attempt_id") is None
        ):
            reasons.append("INBOUND_FILTERED")
        elif candidate.get("kind") == "MAPPED_V4" and candidate.get("mapping_identity") is None:
            reasons.append("MAPPING_CONFLICT")
        elif candidate.get("kind") == "MAPPED_V4" and isinstance(candidate.get("local_endpoint"), dict) and candidate["local_endpoint"].get("address_class") == "SHARED_CGNAT":
            reasons.append("CGNAT_WITHOUT_LEASE")
        elif candidate.get("kind") == "MAPPED_V4" and not isinstance(lease, dict):
            reasons.append("NO_MAPPING_PROTOCOL")
        elif candidate.get("kind") == "MAPPED_V4" and set(lease) != {"basis", "remaining_ms"}:
            reasons.append("NO_MAPPING_PROTOCOL")
        elif candidate.get("kind") == "MAPPED_V4" and lease.get("basis") != "SNAPSHOT_RELATIVE":
            reasons.append("NO_MAPPING_PROTOCOL")
        elif candidate.get("kind") == "MAPPED_V4" and (
            not isinstance(lease.get("remaining_ms"), int)
            or isinstance(lease.get("remaining_ms"), bool)
            or lease["remaining_ms"] < 0
        ):
            reasons.append("NO_MAPPING_PROTOCOL")
        elif candidate.get("kind") == "MAPPED_V4" and lease["remaining_ms"] == 0:
            reasons.append("LEASE_EXPIRED")
        elif candidate.get("kind") == "LAN" and candidate.get("scope") != "SAME_LAN":
            reasons.append("NO_ROUTE")
        elif candidate.get("verification_state") == "VERIFIED" and candidate.get("network_kind") != "NATIVE":
            reasons.append("NO_ROUTE")
    return reasons


def gather(snapshot: Any, schema: dict[str, Any], compat: Any) -> dict[str, Any]:
    try:
        observed = compat.consume_snapshot(snapshot, schema)
    except (AttributeError, KeyError, TypeError, ValueError):
        return _result("MALFORMED")
    inferred_rejections = _rejection_reason_codes(snapshot)
    result = _result(observed.get("status", "MALFORMED"))
    if observed["status"] != "OK":
        result["rejection_reason_codes"] = inferred_rejections
        return result
    if inferred_rejections:
        result["status"] = "MALFORMED"
        result["rejection_reason_codes"] = inferred_rejections
        return result
    for candidate in snapshot["candidates"]:
        if candidate["verification_state"] == "STALE":
            result["ignored_stale_candidate_ids"].append(candidate["candidate_id"])
            continue
        result["candidate_facts"].append({
            "candidate_id": candidate["candidate_id"],
            "kind": candidate["kind"],
            "scope": candidate["scope"],
            "verification_state": candidate["verification_state"],
            "reason_code": candidate["reason_code"],
            "topology_generation": candidate["topology_generation"],
        })
        if candidate["verification_state"] == "VERIFIED":
            result["verified_candidate_ids"].append(candidate["candidate_id"])
    return result


def _endpoint_signature(endpoint: dict[str, Any]) -> tuple[Any, ...]:
    return (
        endpoint["address_family"], endpoint["address_class"],
        endpoint["identity_digest"],
    )


def _signature(candidate: dict[str, Any]) -> tuple[Any, ...]:
    return (
        candidate["kind"], candidate["transport"],
        _endpoint_signature(candidate["local_endpoint"]),
        _endpoint_signature(candidate["published_endpoint"]),
        candidate["interface_identity_digest"], candidate["mapping_identity"],
        candidate["topology_generation"],
    )


def gather_transition(previous: Any, current: Any, schema: dict[str, Any], compat: Any) -> dict[str, Any]:
    previous_result = gather(previous, schema, compat)
    if previous_result["status"] != "OK":
        return previous_result
    current_result = gather(current, schema, compat)
    if current_result["status"] != "OK":
        return current_result

    old_by_id = {item["candidate_id"]: item for item in previous["candidates"]}
    old_by_signature = {_signature(item): item["candidate_id"] for item in previous["candidates"]}
    if any(
        item["verification_state"] == "STALE"
        for item in current["candidates"]
    ):
        return previous_result
    for new in current["candidates"]:
        candidate_id = new["candidate_id"]
        signature = _signature(new)
        old = old_by_id.get(candidate_id)
        if old is not None and _signature(old) != signature:
            if old["topology_generation"] != new["topology_generation"]:
                reason = "STALE_GENERATION"
            elif old["interface_identity_digest"] != new["interface_identity_digest"]:
                reason = "INTERFACE_CHANGED"
            else:
                reason = "MAPPING_CONFLICT"
            return _result("MALFORMED", [reason])
        if old is None and signature in old_by_signature:
            return _result("MALFORMED", ["MAPPING_CONFLICT"])
    return current_result
