#!/usr/bin/env python3
"""Normalize raw CDP and verify W12 evidence without persisted browser assertions.

The deterministic production-tree formula is the SHA-256 of the concatenation,
in ascending Git path order, of UTF-8 ``blob_oid + TAB + path + LF`` records.
Tool hashes are SHA-256 over the exact Git blob bytes at the activation commit.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import parse_qsl, urlsplit


ACTIVATION_SCHEMA = "ese.v92.w12.activation/v2"
RUNTIME_SCHEMA = "ese.v92.w12.security-runtime/v2"
CHALLENGE_SCHEMA = "ese.v92.w12.browser-challenge/v2"
HANDOFF_SCHEMA = "ese.v92.w12.browser-handoff/v3"
READY_SCHEMA = "ese.v92.w12.browser-ready/v3"
RAW_SCHEMA = "ese.v92.w12.browser-raw/v3"
DONE_SCHEMA = "ese.v92.w12.browser-done/v3"
CDP_SCHEMA = "ese.v92.w12.browser-cdp/v3"
LEGACY_CDP_SCHEMA = "ese.v92.w12.browser-cdp/v2"
VERDICT_SCHEMA = "ese.v92.w12.security-verdict/v2"
HEX32 = re.compile(r"^[0-9a-f]{32}$")
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEADER_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9a-z-]{1,64}$")
REQUEST_ID = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
SAFE_CACHE_VALUE = re.compile(r"^[A-Za-z0-9=, _-]{1,128}$")
RANGE_VALUE = re.compile(r"^bytes=0-[0-9]{1,9}$")
BODY_FORBIDDEN = re.compile(
    r"(?i)(?:[0-9a-f]{64}|https?://|esewebsession|cookie|csrf|"
    r"capabilit(?:y|ies)|canary|/h/)"
)
HLS_PATH = re.compile(
    r"^/h/(?P<token>[0-9a-f]{64})/(?P<generation>[1-9][0-9]*)/"
    r"(?P<stream>[0-9a-f]{32})/(?P<leaf>stream(?:_[0-4])?\.m3u8|"
    r"seg_(?:[0-4]_)?[0-9]{5,10}\.ts)$"
)
PLAYER_PATH = re.compile(r"^/live/(?P<stream>[0-9a-f]{32})$")
PATH_PLAYER = "/live/{stream_key}"
PATH_PLAYLIST = "/h/{token}/{generation}/{stream_key}/playlist.m3u8"
PATH_SEGMENT = "/h/{token}/{generation}/{stream_key}/segment.ts"
PATH_LOGOUT = "/?w=logout"
PATH_LOG = "/api/live/log?n={count}"
PATH_TEMPLATES = {PATH_PLAYER, PATH_PLAYLIST, PATH_SEGMENT, PATH_LOGOUT, PATH_LOG}

RUNTIME_CASES = (
    "W12-RUNTIME-READY", "W12-RUNTIME-LOGIN", "W12-RUNTIME-BROADCAST",
    "W12-RUNTIME-PLAYER-CAPABILITY", "W12-RUNTIME-PLAYLIST", "W12-RUNTIME-RANGE",
    "W12-RUNTIME-FORGED-CAPABILITY", "W12-RUNTIME-LOG-CANARY",
    "W12-RUNTIME-LOGOUT-REVOCATION", "W12-RUNTIME-STOP-REVOCATION",
    "W12-RUNTIME-ROLLOVER-REVOCATION", "W12-RUNTIME-RESTART-REVOCATION",
    "W12-RUNTIME-TERMINATION", "W12-RUNTIME-ARTIFACT-SCAN",
)
RUNTIME_HTTP_STATUS = dict(zip(
    RUNTIME_CASES,
    (200, 200, 200, 200, 200, 206, 403, 200, 403, 403, 403, 403, None, None),
))
BROWSER_CASES = (
    "W12-BROWSER-PLAYER", "W12-BROWSER-PLAYLIST", "W12-BROWSER-SEGMENT-RANGE",
    "W12-BROWSER-FORGED-CAPABILITY", "W12-BROWSER-LOGOUT-REVOCATION",
    "W12-BROWSER-REFERER-CANARY",
)


class EvidenceError(RuntimeError):
    """Evidence is missing, ambiguous, malformed, or unsuccessful."""


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceError(f"duplicate JSON member: {key}")
        result[key] = value
    return result


def _read_json(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise EvidenceError(f"evidence is unavailable or not UTF-8: {path.name}") from exc
    size = len(raw.encode("utf-8"))
    if not raw or size > 4 * 1024 * 1024 or raw.startswith("\ufeff"):
        raise EvidenceError(f"evidence size or encoding is invalid: {path.name}")
    try:
        value = json.loads(raw, object_pairs_hook=_pairs)
    except (json.JSONDecodeError, EvidenceError) as exc:
        raise EvidenceError(f"evidence is not unambiguous JSON: {path.name}") from exc
    if not isinstance(value, dict):
        raise EvidenceError(f"evidence root must be object: {path.name}")
    return value


def _exact(value: Any, keys: Iterable[str], where: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise EvidenceError(f"{where} must be an object")
    expected, actual = set(keys), set(value)
    if expected != actual:
        raise EvidenceError(
            f"{where} fields differ "
            f"(missing={sorted(expected - actual)}, extra={sorted(actual - expected)})"
        )
    return value


def _hash(value: Any, pattern: re.Pattern[str], where: str) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise EvidenceError(f"{where} must be canonical lowercase hexadecimal")
    return value


def _integer(value: Any, where: str, low: int, high: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise EvidenceError(f"{where} is outside its permitted range")
    return value


def _boolean(value: Any, expected: bool, where: str) -> None:
    if not isinstance(value, bool) or value is not expected:
        raise EvidenceError(f"{where} must be {str(expected).lower()}")


def _safe_text(value: Any, where: str, maximum: int, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or len(value) > maximum or (not allow_empty and not value):
        raise EvidenceError(f"{where} must be bounded text")
    if any(ord(char) < 0x20 for char in value):
        raise EvidenceError(f"{where} contains a control character")
    return value


def _safe_body(value: Any, where: str) -> str:
    if not isinstance(value, str) or len(value.encode("utf-8")) > 16384:
        raise EvidenceError(f"{where} must be a complete bounded body")
    if any(ord(char) < 0x20 and char not in "\t\r\n" for char in value):
        raise EvidenceError(f"{where} contains a forbidden control character")
    if BODY_FORBIDDEN.search(value):
        raise EvidenceError(f"{where} contains secret, canary, URL, or 64-hex material")
    return value


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def canonical_production_tree(entries: Iterable[tuple[str, str]]) -> tuple[str, int]:
    """Return SHA-256/count for UTF-8 ``oid TAB path LF`` records by path."""
    checked: list[tuple[str, str]] = []
    for oid, path in entries:
        _hash(oid, HEX40, "production blob oid")
        if not isinstance(path, str) or not path.startswith("srchybrid/") or "\x00" in path or "\n" in path or "\t" in path:
            raise EvidenceError("production path is not canonical")
        checked.append((oid, path))
    if not checked or len({path for _, path in checked}) != len(checked):
        raise EvidenceError("production tree is empty or has duplicate paths")
    payload = "".join(f"{oid}\t{path}\n" for oid, path in sorted(checked, key=lambda item: item[1]))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest(), len(checked)


def _toolset_hash(tools: dict[str, str]) -> str:
    payload = json.dumps(tools, sort_keys=True, separators=(",", ":"))
    return _sha256_text(payload)


def _candidate(value: Any, where: str) -> dict[str, str]:
    item = _exact(value, {"build_commit", "emule_sha256", "build_info_sha256", "release"}, where)
    return {
        "build_commit": _hash(item["build_commit"], HEX40, f"{where}.build_commit"),
        "emule_sha256": _hash(item["emule_sha256"], HEX64, f"{where}.emule_sha256"),
        "build_info_sha256": _hash(item["build_info_sha256"], HEX64, f"{where}.build_info_sha256"),
        "release": _safe_text(item["release"], f"{where}.release", 96),
    }


def _binding(value: Any, where: str) -> dict[str, str]:
    item = _exact(value, {
        "activation_commit", "production_tree_sha256", "toolset_sha256",
        "run_id_sha256", "challenge_nonce_sha256", "canary_sha256",
    }, where)
    result: dict[str, str] = {}
    for key in item:
        result[key] = _hash(item[key], HEX40 if key == "activation_commit" else HEX64, f"{where}.{key}")
    return result


def validate_activation(value: dict[str, Any]) -> dict[str, Any]:
    root = _exact(value, {
        "schema", "activation_commit", "production_tree_sha256",
        "production_path_count", "tool_sha256",
    }, "activation")
    if root["schema"] != ACTIVATION_SCHEMA:
        raise EvidenceError("activation schema differs")
    tools = _exact(root["tool_sha256"], {"runner", "verifier", "collector", "test", "ratchet"}, "activation.tool_sha256")
    checked_tools = {key: _hash(tools[key], HEX64, f"activation tool {key}") for key in tools}
    return {
        "activation_commit": _hash(root["activation_commit"], HEX40, "activation commit"),
        "production_tree_sha256": _hash(root["production_tree_sha256"], HEX64, "activation production tree"),
        "production_path_count": _integer(root["production_path_count"], "activation path count", 1, 100000),
        "tool_sha256": checked_tools,
        "toolset_sha256": _toolset_hash(checked_tools),
    }


def validate_runtime(value: dict[str, Any]) -> tuple[dict[str, str], dict[str, str]]:
    root = _exact(value, {
        "schema", "candidate", "execution", "cases", "canary", "privacy", "binding", "verdict",
    }, "runtime")
    if root["schema"] != RUNTIME_SCHEMA or root["verdict"] != "PASS":
        raise EvidenceError("runtime schema or verdict differs")
    candidate, binding = _candidate(root["candidate"], "runtime.candidate"), _binding(root["binding"], "runtime.binding")
    execution = _exact(root["execution"], {
        "loopback_only", "portable", "headless", "process_termination_confirmed", "scratch_removed",
    }, "runtime.execution")
    for key in execution:
        _boolean(execution[key], True, f"runtime.execution.{key}")
    cases = root["cases"]
    if not isinstance(cases, list) or len(cases) != len(RUNTIME_CASES):
        raise EvidenceError("runtime.cases must contain exactly all runtime cases")
    for index, case_id in enumerate(RUNTIME_CASES):
        case = _exact(cases[index], {"id", "status", "http_status", "checks"}, f"runtime.cases[{index}]")
        if case["id"] != case_id or case["status"] != "PASS" or case["http_status"] != RUNTIME_HTTP_STATUS[case_id]:
            raise EvidenceError(f"{case_id} does not match the runtime contract")
        checks = case["checks"]
        if not isinstance(checks, list) or not checks or len(checks) > 8:
            raise EvidenceError(f"{case_id}.checks must be a non-empty bounded list")
        for check_index, check in enumerate(checks):
            _safe_text(check, f"{case_id}.checks[{check_index}]", 128)
    canary = _exact(root["canary"], {"sha256", "log_hits", "artifact_hits", "forged_body_hits"}, "runtime.canary")
    _hash(canary["sha256"], HEX64, "runtime canary hash")
    for key in ("log_hits", "artifact_hits", "forged_body_hits"):
        if _integer(canary[key], f"runtime canary {key}", 0, 1000000) != 0:
            raise EvidenceError(f"runtime canary {key} is nonzero")
    privacy = _exact(root["privacy"], {
        "no_store_all_sensitive_responses", "no_referrer_all_sensitive_responses",
        "secrets_persisted", "sensitive_urls_persisted",
    }, "runtime.privacy")
    _boolean(privacy["no_store_all_sensitive_responses"], True, "runtime no-store")
    _boolean(privacy["no_referrer_all_sensitive_responses"], True, "runtime no-referrer")
    _boolean(privacy["secrets_persisted"], False, "runtime secrets persisted")
    _boolean(privacy["sensitive_urls_persisted"], False, "runtime URLs persisted")
    if binding["canary_sha256"] != canary["sha256"]:
        raise EvidenceError("runtime canary binding differs")
    return candidate, binding


def validate_challenge(value: dict[str, Any]) -> tuple[dict[str, str], dict[str, str]]:
    root = _exact(value, {"schema", "candidate", "binding"}, "challenge")
    if root["schema"] != CHALLENGE_SCHEMA:
        raise EvidenceError("challenge schema differs")
    serialized = json.dumps(root, sort_keys=True, separators=(",", ":"))
    if re.search(r"(?i)(?:https?://|esewebsession=|x-csrf-token)", serialized):
        raise EvidenceError("challenge persists raw sensitive material")
    return _candidate(root["candidate"], "challenge.candidate"), _binding(root["binding"], "challenge.binding")


def _validate_handoff_v2(value: dict[str, Any], challenge: dict[str, Any]) -> dict[str, Any]:
    root = _exact(value, {
        "schema", "candidate", "binding", "base_url", "login_password", "csrf_token",
        "stream_key", "canary", "run_id", "challenge_nonce", "raw_cdp_path",
        "normalized_trace_path", "done_signal_path",
    }, "handoff")
    if root["schema"] != "ese.v92.w12.browser-handoff/v2":
        raise EvidenceError("handoff schema differs")
    challenge_candidate, challenge_binding = validate_challenge(challenge)
    if _candidate(root["candidate"], "handoff.candidate") != challenge_candidate:
        raise EvidenceError("handoff candidate differs from challenge")
    binding = _binding(root["binding"], "handoff.binding")
    if binding != challenge_binding:
        raise EvidenceError("handoff binding differs from challenge")
    base = urlsplit(_safe_text(root["base_url"], "handoff.base_url", 96))
    if base.scheme != "http" or base.hostname != "127.0.0.1" or base.username or base.password or base.path != "/" or base.query or base.fragment or not base.port:
        raise EvidenceError("handoff base URL must be exact IPv4 loopback HTTP authority")
    password = _safe_text(root["login_password"], "handoff.login_password", 128)
    csrf = root["csrf_token"]
    if csrf is not None:
        _hash(csrf, HEX64, "handoff CSRF")
    stream_key = _hash(root["stream_key"], HEX32, "handoff stream key")
    canary = _hash(root["canary"], HEX64, "handoff canary")
    run_id = _hash(root["run_id"], HEX64, "handoff run id")
    nonce = _hash(root["challenge_nonce"], HEX64, "handoff challenge nonce")
    if _sha256_text(canary) != binding["canary_sha256"] or _sha256_text(run_id) != binding["run_id_sha256"] or _sha256_text(nonce) != binding["challenge_nonce_sha256"]:
        raise EvidenceError("handoff raw values do not bind challenge hashes")
    paths: dict[str, Path] = {}
    for key in ("raw_cdp_path", "normalized_trace_path", "done_signal_path"):
        text = _safe_text(root[key], f"handoff.{key}", 1024)
        path = Path(text)
        if not path.is_absolute():
            raise EvidenceError(f"handoff.{key} must be absolute")
        paths[key] = path
    return {
        "candidate": challenge_candidate, "binding": binding,
        "authority": f"127.0.0.1:{base.port}", "stream_key": stream_key,
        "canary": canary, "run_id": run_id, "challenge_nonce": nonce,
        "password": password, "csrf": csrf, "paths": paths,
    }


def validate_handoff(value: dict[str, Any], challenge: dict[str, Any]) -> dict[str, Any]:
    root = _exact(value, {
        "schema", "A", "candidate", "binding", "base_url", "login_password",
        "stream_key", "canary", "run_id", "challenge_nonce", "raw_path", "done_path",
    }, "collector handoff")
    if root["schema"] != HANDOFF_SCHEMA:
        raise EvidenceError("collector handoff schema differs")
    candidate, binding = validate_challenge(challenge)
    if _safe_text(root["A"], "collector handoff A", 40) != binding["activation_commit"]:
        raise EvidenceError("collector handoff activation differs")
    if _candidate(root["candidate"], "collector handoff.candidate") != candidate:
        raise EvidenceError("collector handoff candidate differs")
    if _binding(root["binding"], "collector handoff.binding") != binding:
        raise EvidenceError("collector handoff binding differs")
    base = urlsplit(_safe_text(root["base_url"], "collector handoff.base_url", 96))
    if base.scheme != "http" or base.hostname != "127.0.0.1" or base.username or base.password or base.path != "/" or base.query or base.fragment or not base.port:
        raise EvidenceError("collector handoff base URL must be exact IPv4 loopback HTTP authority")
    values = {
        "password": _safe_text(root["login_password"], "collector handoff password", 128),
        "stream_key": _hash(root["stream_key"], HEX32, "collector handoff stream key"),
        "canary": _hash(root["canary"], HEX64, "collector handoff canary"),
        "run_id": _hash(root["run_id"], HEX64, "collector handoff run id"),
        "challenge_nonce": _hash(root["challenge_nonce"], HEX64, "collector handoff nonce"),
    }
    if any(_sha256_text(values[key]) != binding[key + "_sha256"] for key in ("canary", "run_id", "challenge_nonce")):
        raise EvidenceError("collector handoff raw values do not bind challenge hashes")
    paths: dict[str, Path] = {}
    for key in ("raw_path", "done_path"):
        path = Path(_safe_text(root[key], f"collector handoff {key}", 1024))
        if not path.is_absolute():
            raise EvidenceError(f"collector handoff {key} must be absolute")
        paths[key] = path
    return {"candidate": candidate, "binding": binding, "authority": f"127.0.0.1:{base.port}", "paths": paths, **values}


def validate_ready(value: dict[str, Any], handoff_bytes: bytes, activation: dict[str, Any], binding: dict[str, str]) -> dict[str, str]:
    root = _exact(value, {"schema", "A", "run_id_sha256", "challenge_nonce_sha256", "handoff_sha256", "collector_sha256"}, "collector ready")
    if root["schema"] != READY_SCHEMA or root["A"] != binding["activation_commit"]:
        raise EvidenceError("collector ready schema or activation differs")
    for key in ("run_id_sha256", "challenge_nonce_sha256"):
        if _hash(root[key], HEX64, f"collector ready {key}") != binding[key]:
            raise EvidenceError("collector ready binding differs")
    if _hash(root["handoff_sha256"], HEX64, "collector ready handoff") != hashlib.sha256(handoff_bytes).hexdigest():
        raise EvidenceError("collector ready handoff hash differs")
    if _hash(root["collector_sha256"], HEX64, "collector ready source") != activation["tool_sha256"]["collector"]:
        raise EvidenceError("collector ready source hash differs from activation")
    return {key: root[key] for key in root}


def _request_event(value: Any, index: int) -> dict[str, Any]:
    event = _exact(value, {
        "seq", "request_id", "method", "http_method", "authority", "path_template",
        "token_sha256", "header_names", "range",
    }, f"browser.events[{index}]")
    if event["method"] != "Network.requestWillBeSent":
        raise EvidenceError("browser request method marker differs")
    _integer(event["seq"], "browser sequence", 0, 10000000)
    if not isinstance(event["request_id"], str) or not REQUEST_ID.fullmatch(event["request_id"]):
        raise EvidenceError("browser request id is not a sanitized CDP identifier")
    if event["http_method"] not in {"GET", "POST"}:
        raise EvidenceError("browser HTTP method is not allowed")
    authority = _safe_text(event["authority"], "browser authority", 32)
    if not re.fullmatch(r"127\.0\.0\.1:[1-9][0-9]{0,4}", authority):
        raise EvidenceError("browser authority is not exact IPv4 loopback")
    if event["path_template"] not in PATH_TEMPLATES:
        raise EvidenceError("browser path template is unknown")
    token = event["token_sha256"]
    if event["path_template"] in {PATH_PLAYLIST, PATH_SEGMENT}:
        _hash(token, HEX64, "browser token hash")
    elif token is not None:
        raise EvidenceError("non-HLS request carries a token hash")
    names = event["header_names"]
    if not isinstance(names, list) or any(not isinstance(name, str) or not HEADER_NAME.fullmatch(name) for name in names):
        raise EvidenceError("browser header names are not canonical")
    if names != sorted(set(names)):
        raise EvidenceError("browser header names must be sorted and unique")
    if any(name in {"cookie", "x-csrf-token"} for name in names):
        raise EvidenceError("browser trace persists a sensitive request header name")
    range_value = event["range"]
    if range_value is not None and (not isinstance(range_value, str) or not RANGE_VALUE.fullmatch(range_value)):
        raise EvidenceError("browser Range is not safe canonical bytes=0-N")
    if range_value is not None and event["path_template"] != PATH_SEGMENT:
        raise EvidenceError("browser Range appears outside a segment request")
    return event


def _response_event(value: Any, index: int) -> dict[str, Any]:
    event = _exact(value, {"seq", "request_id", "method", "status", "response_headers"}, f"browser.events[{index}]")
    if event["method"] != "Network.responseReceived":
        raise EvidenceError("browser response method marker differs")
    _integer(event["seq"], "browser sequence", 0, 10000000)
    if not isinstance(event["request_id"], str) or not REQUEST_ID.fullmatch(event["request_id"]):
        raise EvidenceError("browser request id is not a sanitized CDP identifier")
    _integer(event["status"], "browser response status", 100, 599)
    headers = _exact(event["response_headers"], {"cache-control", "referrer-policy"}, "browser response headers")
    cache_raw = _safe_text(headers["cache-control"], "browser Cache-Control", 128)
    if not SAFE_CACHE_VALUE.fullmatch(cache_raw) or BODY_FORBIDDEN.search(cache_raw):
        raise EvidenceError("browser Cache-Control is not a safe observable value")
    cache = cache_raw.lower()
    policy = _safe_text(headers["referrer-policy"], "browser Referrer-Policy", 64).lower()
    if "no-store" not in {part.strip() for part in cache.split(",")}:
        raise EvidenceError("browser Cache-Control lacks no-store")
    if policy != "no-referrer":
        raise EvidenceError("browser Referrer-Policy is not no-referrer")
    return event


def _body_event(value: Any, index: int) -> dict[str, Any]:
    event = _exact(value, {"seq", "request_id", "method", "body"}, f"browser.events[{index}]")
    if event["method"] != "Network.getResponseBody":
        raise EvidenceError("browser body method marker differs")
    _integer(event["seq"], "browser sequence", 0, 10000000)
    if not isinstance(event["request_id"], str) or not REQUEST_ID.fullmatch(event["request_id"]):
        raise EvidenceError("browser request id is not a sanitized CDP identifier")
    _safe_body(event["body"], "browser complete response body")
    return event


def _normalized_event(value: Any, index: int) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise EvidenceError(f"browser.events[{index}] must be object")
    method = value.get("method")
    if method == "Network.requestWillBeSent":
        return _request_event(value, index)
    if method == "Network.responseReceived":
        return _response_event(value, index)
    if method == "Network.getResponseBody":
        return _body_event(value, index)
    raise EvidenceError("browser trace contains a non-normalized CDP method")


def derive_browser(trace: dict[str, Any], challenge_binding: dict[str, str]) -> tuple[dict[str, str], list[dict[str, Any]]]:
    root = _exact(trace, {"schema", "activation_commit", "candidate", "binding", "events"}, "browser")
    if root["schema"] not in {CDP_SCHEMA, LEGACY_CDP_SCHEMA}:
        raise EvidenceError("browser trace schema differs")
    if _hash(root["activation_commit"], HEX40, "browser activation commit") != challenge_binding["activation_commit"]:
        raise EvidenceError("browser activation commit differs")
    candidate = _candidate(root["candidate"], "browser.candidate")
    if _binding(root["binding"], "browser.binding") != challenge_binding:
        raise EvidenceError("browser challenge binding differs")
    values = root["events"]
    if not isinstance(values, list) or not values:
        raise EvidenceError("browser CDP events are absent")
    events = [_normalized_event(value, index) for index, value in enumerate(values)]
    if [event["seq"] for event in events] != list(range(len(events))):
        raise EvidenceError("browser CDP sequence must be contiguous and strictly ordered")

    request_events = [event for event in events if event["method"] == "Network.requestWillBeSent"]
    if not request_events or len({event["authority"] for event in request_events}) != 1:
        raise EvidenceError("browser requests must share one exact loopback authority")
    if any(event["http_method"] != "GET" for event in request_events):
        raise EvidenceError("browser W12 protocol requires GET observations")
    records: dict[str, dict[str, Any]] = {}
    request_order: list[str] = []
    for event in events:
        request_id = event["request_id"]
        if event["method"] == "Network.requestWillBeSent":
            if request_id in records:
                raise EvidenceError("browser request ids must be unique")
            if "referer" in event["header_names"]:
                raise EvidenceError("browser request contains Referer")
            records[request_id] = {"request": event, "response": None, "body": None}
            request_order.append(request_id)
        elif request_id not in records:
            raise EvidenceError("browser response/body has no request with the same request_id")
        elif event["method"] == "Network.responseReceived":
            if records[request_id]["response"] is not None or records[request_id]["body"] is not None:
                raise EvidenceError("browser response is duplicate or out of order")
            records[request_id]["response"] = event
        else:
            if records[request_id]["response"] is None or records[request_id]["body"] is not None:
                raise EvidenceError("browser body is duplicate or precedes its response")
            records[request_id]["body"] = event
    if any(record["response"] is None for record in records.values()):
        raise EvidenceError("browser request is missing its response")
    for position, request_id in enumerate(request_order[:-1]):
        record = records[request_id]
        completed_seq = record["body"]["seq"] if record["body"] is not None else record["response"]["seq"]
        next_request_seq = records[request_order[position + 1]]["request"]["seq"]
        if completed_seq >= next_request_seq:
            raise EvidenceError("browser request/response/body groups overlap or are out of order")

    semantics: list[tuple[str, dict[str, Any]]] = []
    valid_token: str | None = None
    logout_complete = False
    logout_response_seq = -1
    for request_id in request_order:
        record = records[request_id]
        request, response, body = record["request"], record["response"], record["body"]
        path, status, token = request["path_template"], response["status"], request["token_sha256"]
        kind: str
        if path == PATH_PLAYER and status == 200:
            kind = "player"
        elif path == PATH_PLAYLIST and status == 200:
            if token == challenge_binding["canary_sha256"]:
                raise EvidenceError("valid playlist uses the forged canary token")
            valid_token = token
            kind = "playlist"
        elif path == PATH_SEGMENT and status == 206:
            if valid_token is None or token != valid_token or request["range"] is None:
                raise EvidenceError("segment/range does not share the valid playlist token")
            kind = "segment-range"
        elif path in {PATH_PLAYLIST, PATH_SEGMENT} and status == 403:
            if token == challenge_binding["canary_sha256"]:
                kind = "forged"
            elif logout_complete and logout_response_seq < request["seq"] and valid_token is not None and token == valid_token:
                kind = "revoked"
            else:
                raise EvidenceError("HLS 403 is neither challenge-forged nor post-logout revoked")
        elif path == PATH_LOG and status == 200:
            kind = "log"
        elif path == PATH_LOGOUT and status == 200:
            logout_complete = True
            logout_response_seq = response["seq"]
            kind = "logout-action"
        else:
            raise EvidenceError("browser request/response is outside the W12 protocol")
        needs_body = kind in {"forged", "revoked", "log"}
        if needs_body != (body is not None):
            raise EvidenceError("complete bodies are required only for forged/revoked/log")
        semantics.append((kind, response))

    required_order = ["player", "playlist", "segment-range", "forged", "log", "logout-action", "revoked"]
    variant_order = ["player", "playlist", "playlist", "segment-range", "forged", "log", "logout-action", "revoked"]
    if tuple(kind for kind, _ in semantics) not in {tuple(required_order), tuple(variant_order)}:
        raise EvidenceError("browser scenario order or cardinality differs")
    statuses = {kind: response["status"] for kind, response in semantics}
    cases = [
        {"id": "W12-BROWSER-PLAYER", "http_status": statuses["player"]},
        {"id": "W12-BROWSER-PLAYLIST", "http_status": statuses["playlist"]},
        {"id": "W12-BROWSER-SEGMENT-RANGE", "http_status": statuses["segment-range"]},
        {"id": "W12-BROWSER-FORGED-CAPABILITY", "http_status": statuses["forged"]},
        {"id": "W12-BROWSER-LOGOUT-REVOCATION", "http_status": statuses["revoked"]},
        {"id": "W12-BROWSER-REFERER-CANARY", "http_status": statuses["log"]},
    ]
    return candidate, cases


def verify(activation_path: Path, runtime_path: Path, challenge_path: Path, browser_path: Path) -> dict[str, Any]:
    activation = validate_activation(_read_json(activation_path))
    runtime_candidate, runtime_binding = validate_runtime(_read_json(runtime_path))
    challenge_candidate, challenge_binding = validate_challenge(_read_json(challenge_path))
    if runtime_candidate != challenge_candidate or runtime_binding != challenge_binding:
        raise EvidenceError("runtime and challenge binding differs")
    if runtime_candidate["build_commit"] != activation["activation_commit"]:
        raise EvidenceError("BUILD_INFO candidate commit is not exactly activation commit")
    if runtime_binding["activation_commit"] != activation["activation_commit"] or runtime_binding["production_tree_sha256"] != activation["production_tree_sha256"]:
        raise EvidenceError("runtime activation binding differs")
    if runtime_binding["toolset_sha256"] != activation["toolset_sha256"]:
        raise EvidenceError("runtime tool hashes differ from activation")
    browser_trace = _read_json(browser_path)
    if browser_trace.get("schema") == CDP_SCHEMA:
        _exact(browser_trace, {"schema", "activation_commit", "candidate", "binding", "collector_sha256", "browser_binding_sha256", "product_sha256", "version_sha256", "user_agent_sha256", "events"}, "collector trace")
        for key in ("collector_sha256", "browser_binding_sha256", "product_sha256", "version_sha256", "user_agent_sha256"):
            _hash(browser_trace[key], HEX64, f"collector trace {key}")
        if browser_trace["collector_sha256"] != activation["tool_sha256"]["collector"]:
            raise EvidenceError("collector trace source differs from activation")
        browser_trace = {key: browser_trace[key] for key in ("schema", "activation_commit", "candidate", "binding", "events")}
        browser_trace["schema"] = LEGACY_CDP_SCHEMA
    browser_candidate, cases = derive_browser(browser_trace, challenge_binding)
    if browser_candidate != runtime_candidate:
        raise EvidenceError("browser and runtime candidate differs")
    return {
        "schema": VERDICT_SCHEMA, "activation_commit": activation["activation_commit"],
        "emule_sha256": runtime_candidate["emule_sha256"], "cases": cases, "verdict": "PASS",
    }


def _classify_raw_url(url: str, handoff: dict[str, Any]) -> tuple[str, str | None]:
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError as exc:
        raise EvidenceError("raw CDP URL is malformed") from exc
    authority = f"{parsed.hostname}:{port}" if parsed.hostname and port else ""
    if parsed.scheme != "http" or authority != handoff["authority"] or parsed.username or parsed.password or parsed.fragment:
        raise EvidenceError("raw CDP authority is not the handoff loopback authority")
    player = PLAYER_PATH.fullmatch(parsed.path)
    if player:
        if player.group("stream") != handoff["stream_key"] or parsed.query:
            raise EvidenceError("raw player URL does not bind the handoff stream")
        return PATH_PLAYER, None
    hls = HLS_PATH.fullmatch(parsed.path)
    if hls:
        if hls.group("stream") != handoff["stream_key"] or parsed.query:
            raise EvidenceError("raw HLS URL does not bind the handoff stream")
        template = PATH_PLAYLIST if hls.group("leaf").endswith(".m3u8") else PATH_SEGMENT
        return template, _sha256_text(hls.group("token"))
    query = parse_qsl(parsed.query, keep_blank_values=True)
    if parsed.path == "/" and query == [("w", "logout")]:
        return PATH_LOGOUT, None
    if parsed.path == "/api/live/log" and len(query) == 1 and query[0][0] == "n" and query[0][1].isdigit():
        _integer(int(query[0][1]), "raw log count", 1, 5000)
        return PATH_LOG, None
    raise EvidenceError("raw CDP URL is outside the W12 browser protocol")


def normalize_cdp(raw_path: Path, challenge_path: Path, handoff_path: Path, handoff_override: dict[str, Any] | None = None, trace_schema: str = LEGACY_CDP_SCHEMA) -> dict[str, Any]:
    challenge = _read_json(challenge_path)
    handoff = _validate_handoff_v2(_read_json(handoff_path), challenge) if handoff_override is None else handoff_override
    raw = _read_json(raw_path)
    if not isinstance(raw.get("events"), list):
        raise EvidenceError("raw CDP events are absent")
    observations: list[dict[str, Any]] = []
    requests: dict[str, dict[str, Any]] = {}
    ignored_requests: set[str] = set()
    for raw_index, raw_event in enumerate(raw["events"]):
        if not isinstance(raw_event, dict) or set(raw_event) != {"method", "params"} or not isinstance(raw_event["params"], dict):
            raise EvidenceError(f"raw CDP event {raw_index} shape differs")
        method, params = raw_event["method"], raw_event["params"]
        if method == "Network.requestWillBeSent":
            request_id, request = params.get("requestId"), params.get("request")
            if not isinstance(request_id, str) or not request_id or request_id in requests or not isinstance(request, dict):
                raise EvidenceError("raw CDP request id/object is missing or duplicate")
            if not isinstance(request.get("url"), str) or not isinstance(request.get("method"), str) or not isinstance(request.get("headers"), dict):
                raise EvidenceError("raw CDP request fields are incomplete")
            parsed_login = urlsplit(request["url"])
            if parsed_login.path == "/" and dict(parse_qsl(parsed_login.query, keep_blank_values=True)).get("w") == "password":
                ignored_requests.add(request_id)
                continue
            template, token_hash = _classify_raw_url(request["url"], handoff)
            header_names: list[str] = []
            range_value: str | None = None
            for name, raw_value in request["headers"].items():
                canonical = str(name).lower()
                if not HEADER_NAME.fullmatch(canonical):
                    raise EvidenceError("raw CDP header name is invalid")
                if canonical == "referer":
                    raise EvidenceError("raw CDP request contains Referer")
                if canonical in {"cookie", "x-csrf-token"}:
                    continue
                header_names.append(canonical)
                if canonical == "range":
                    if not isinstance(raw_value, str) or not RANGE_VALUE.fullmatch(raw_value):
                        raise EvidenceError("raw CDP Range is not safe")
                    range_value = raw_value
            header_names = sorted(set(header_names))
            event = {
                "seq": len(observations), "request_id": request_id,
                "method": "Network.requestWillBeSent", "http_method": request["method"],
                "authority": handoff["authority"], "path_template": template,
                "token_sha256": token_hash, "header_names": header_names, "range": range_value,
            }
            observations.append(_request_event(event, len(observations)))
            requests[request_id] = {"request": event, "response": None, "body": None}
        elif method == "Network.responseReceived":
            request_id, response = params.get("requestId"), params.get("response")
            if request_id in ignored_requests:
                continue
            if not isinstance(request_id, str) or request_id not in requests or not isinstance(response, dict):
                raise EvidenceError("raw CDP response has no same-id request")
            record = requests[request_id]
            if record["response"] is not None or record["body"] is not None:
                raise EvidenceError("raw CDP response is duplicate or out of order")
            status, headers = response.get("status"), response.get("headers")
            if isinstance(status, bool) or not isinstance(status, int) or not isinstance(headers, dict):
                raise EvidenceError("raw CDP response fields are incomplete")
            lowered = {str(name).lower(): value for name, value in headers.items()}
            cache, policy = lowered.get("cache-control"), lowered.get("referrer-policy")
            if not isinstance(cache, str) or not isinstance(policy, str):
                raise EvidenceError("raw CDP response lacks security headers")
            event = {
                "seq": len(observations), "request_id": request_id,
                "method": "Network.responseReceived", "status": status,
                "response_headers": {"cache-control": cache, "referrer-policy": policy},
            }
            observations.append(_response_event(event, len(observations)))
            record["response"] = event
        elif method == "Network.getResponseBody":
            request_id, body = params.get("requestId"), params.get("body")
            if request_id in ignored_requests:
                continue
            if params.get("base64Encoded", False) is not False:
                raise EvidenceError("base64 CDP bodies are not accepted")
            if not isinstance(request_id, str) or request_id not in requests or not isinstance(body, str):
                raise EvidenceError("raw CDP body has no same-id request/response")
            record = requests[request_id]
            if record["response"] is None or record["body"] is not None:
                raise EvidenceError("raw CDP body is duplicate or out of order")
            request, response = record["request"], record["response"]
            log_body = request["path_template"] == PATH_LOG
            allowed = log_body or (
                request["path_template"] in {PATH_PLAYLIST, PATH_SEGMENT} and response["status"] == 403
            )
            if not allowed:
                raise EvidenceError("raw CDP body is retained outside forged/revoked/log")
            if log_body and any(secret and secret in body for secret in (handoff["canary"], handoff["run_id"], handoff["challenge_nonce"], handoff["stream_key"], handoff["password"], handoff["csrf"])):
                raise EvidenceError("transient log body contains raw handoff material")
            body = "transient log checked and discarded" if log_body else body
            event = {
                "seq": len(observations), "request_id": request_id,
                "method": "Network.getResponseBody", "body": body,
            }
            observations.append(_body_event(event, len(observations)))
            record["body"] = event
        else:
            raise EvidenceError("raw CDP contains an unsupported method")
    trace = {
        "schema": trace_schema, "activation_commit": handoff["binding"]["activation_commit"],
        "candidate": handoff["candidate"], "binding": handoff["binding"], "events": observations,
    }
    serialized = json.dumps(trace, sort_keys=True, separators=(",", ":"))
    for raw_secret in (
        handoff["canary"], handoff["run_id"], handoff["challenge_nonce"],
        handoff["stream_key"], handoff["password"], handoff["csrf"],
    ):
        if raw_secret is not None and raw_secret in serialized:
            raise EvidenceError("normalized CDP persists raw handoff material")
    derive_browser(trace, handoff["binding"])
    return trace


def normalize_collector_cdp(raw_path: Path, challenge_path: Path, handoff_path: Path, ready_path: Path, done_path: Path, activation: dict[str, Any]) -> dict[str, Any]:
    challenge = _read_json(challenge_path); candidate, binding = validate_challenge(challenge)
    handoff_bytes = handoff_path.read_bytes(); handoff = validate_handoff(_read_json(handoff_path), challenge)
    ready_bytes = ready_path.read_bytes(); ready = validate_ready(_read_json(ready_path), handoff_bytes, activation, binding)
    raw_bytes = raw_path.read_bytes(); raw = _read_json(raw_path)
    root = _exact(raw, {"schema", "A", "candidate", "binding", "collector_sha256", "ready_sha256", "handoff_sha256", "browser_binding_sha256", "proxy_authority", "browser", "events"}, "collector raw")
    if root["schema"] != RAW_SCHEMA or root["A"] != binding["activation_commit"] or _candidate(root["candidate"], "collector raw candidate") != candidate:
        raise EvidenceError("collector raw identity differs")
    if _binding(root["binding"], "collector raw binding") != binding:
        raise EvidenceError("collector raw binding differs")
    if _hash(root["collector_sha256"], HEX64, "collector raw source") != ready["collector_sha256"] or _hash(root["ready_sha256"], HEX64, "collector raw ready") != hashlib.sha256(ready_bytes).hexdigest() or _hash(root["handoff_sha256"], HEX64, "collector raw handoff") != ready["handoff_sha256"]:
        raise EvidenceError("collector raw hash binding differs")
    authority = _safe_text(root["proxy_authority"], "collector raw proxy authority", 32)
    if not re.fullmatch(r"127\.0\.0\.1:[1-9][0-9]{0,4}", authority): raise EvidenceError("collector raw proxy authority differs")
    browser = _exact(root["browser"], {"browser_id", "product", "version", "user_agent"}, "collector raw browser")
    browser_id = _safe_text(browser["browser_id"], "collector browser id", 1024)
    product, version, user_agent = (_safe_text(browser[key], f"collector browser {key}", maximum) for key, maximum in (("product", 128), ("version", 512), ("user_agent", 1024)))
    if _hash(root["browser_binding_sha256"], HEX64, "collector raw browser binding") != _sha256_text(browser_id): raise EvidenceError("collector raw browser binding differs")
    done = _exact(_read_json(done_path), {"schema", "A", "run_id_sha256", "challenge_nonce_sha256", "collector_sha256", "ready_sha256", "handoff_sha256", "raw_sha256", "browser_binding_sha256", "product_sha256", "version_sha256", "user_agent_sha256"}, "collector done")
    if done["schema"] != DONE_SCHEMA or done["A"] != binding["activation_commit"] or any(done[key] != root[key] for key in ("collector_sha256", "ready_sha256", "handoff_sha256", "browser_binding_sha256")) or done["run_id_sha256"] != binding["run_id_sha256"] or done["challenge_nonce_sha256"] != binding["challenge_nonce_sha256"] or _hash(done["raw_sha256"], HEX64, "collector done raw") != hashlib.sha256(raw_bytes).hexdigest() or done["product_sha256"] != _sha256_text(product) or done["version_sha256"] != _sha256_text(version) or done["user_agent_sha256"] != _sha256_text(user_agent):
        raise EvidenceError("collector done binding differs")
    normalized = normalize_cdp(raw_path, challenge_path, handoff_path, {"candidate": candidate, "binding": binding, "authority": authority, "stream_key": handoff["stream_key"], "canary": handoff["canary"], "run_id": handoff["run_id"], "challenge_nonce": handoff["challenge_nonce"], "password": handoff["password"], "csrf": None}, LEGACY_CDP_SCHEMA)
    trace = {**normalized, "schema": CDP_SCHEMA, "collector_sha256": root["collector_sha256"], "browser_binding_sha256": root["browser_binding_sha256"], "product_sha256": done["product_sha256"], "version_sha256": done["version_sha256"], "user_agent_sha256": done["user_agent_sha256"]}
    return trace


def _write(path: Path, value: dict[str, Any]) -> None:
    if path.exists():
        raise EvidenceError(f"refusing to overwrite evidence: {path.name}")
    temporary = path.with_name(path.name + ".writing")
    if temporary.exists():
        raise EvidenceError(f"stale atomic-write file exists: {temporary.name}")
    try:
        temporary.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def _done_value(trace_path: Path, binding: dict[str, str]) -> dict[str, str]:
    try:
        digest = hashlib.sha256(trace_path.read_bytes()).hexdigest()
    except OSError as exc:
        raise EvidenceError("normalized trace cannot be hashed") from exc
    return {
        "schema": DONE_SCHEMA, "activation_commit": binding["activation_commit"],
        "run_id_sha256": binding["run_id_sha256"],
        "challenge_nonce_sha256": binding["challenge_nonce_sha256"],
        "trace_sha256": digest,
    }


def validate_done_signal(value: dict[str, Any], trace_path: Path, binding: dict[str, str]) -> None:
    done = _exact(value, {
        "schema", "activation_commit", "run_id_sha256",
        "challenge_nonce_sha256", "trace_sha256",
    }, "browser done signal")
    if done["schema"] != DONE_SCHEMA:
        raise EvidenceError("browser done signal schema differs")
    for key in ("activation_commit", "run_id_sha256", "challenge_nonce_sha256"):
        pattern = HEX40 if key == "activation_commit" else HEX64
        if _hash(done[key], pattern, f"browser done {key}") != binding[key]:
            raise EvidenceError("browser done signal challenge binding differs")
    try:
        actual = hashlib.sha256(trace_path.read_bytes()).hexdigest()
    except OSError as exc:
        raise EvidenceError("normalized trace cannot be read for done validation") from exc
    if _hash(done["trace_sha256"], HEX64, "browser done trace hash") != actual:
        raise EvidenceError("browser done trace hash differs")


def _args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--activation", type=Path)
    parser.add_argument("--runtime", type=Path)
    parser.add_argument("--challenge", type=Path, required=True)
    parser.add_argument("--browser-trace", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--normalize-cdp", type=Path)
    parser.add_argument("--handoff", type=Path)
    parser.add_argument("--ready", type=Path)
    parser.add_argument("--done-signal", type=Path)
    parser.add_argument("--check-browser-trace", type=Path)
    parser.add_argument("--normalize-collector", type=Path)
    args = parser.parse_args()
    if args.normalize_collector:
        if args.runtime or args.browser_trace or args.check_browser_trace or args.normalize_cdp or not args.activation or not args.handoff or not args.ready or not args.done_signal or not args.output:
            parser.error("collector normalization requires --activation --normalize-collector --handoff --ready --done-signal --challenge --output only")
    elif args.normalize_cdp:
        if args.activation or args.runtime or args.browser_trace or args.check_browser_trace or not args.handoff or not args.done_signal or not args.output:
            parser.error("normalization requires --normalize-cdp --handoff --challenge --output --done-signal only")
    elif args.check_browser_trace:
        if args.activation or args.runtime or args.browser_trace or args.handoff or args.ready or args.done_signal or args.output:
            parser.error("browser trace check requires --check-browser-trace --challenge only")
    elif not all((args.activation, args.runtime, args.browser_trace, args.output)) or args.handoff or args.ready or args.done_signal:
        parser.error("verification requires --activation --runtime --challenge --browser-trace --output")
    return args


def main() -> int:
    args = _args()
    try:
        if args.normalize_collector:
            challenge = _read_json(args.challenge)
            activation = validate_activation(_read_json(args.activation)) if args.activation else None
            if activation is None:
                # The runner materializes the A verifier and challenge, but the
                # activation identity remains authoritative for collector hash.
                raise EvidenceError("collector normalization requires activation")
            result = normalize_collector_cdp(args.normalize_collector, args.challenge, args.handoff, args.ready, args.done_signal, activation)
            _write(args.output, result)
        elif args.normalize_cdp:
            challenge = _read_json(args.challenge)
            handoff = _validate_handoff_v2(_read_json(args.handoff), challenge)
            if args.normalize_cdp.resolve() != handoff["paths"]["raw_cdp_path"].resolve() or args.output.resolve() != handoff["paths"]["normalized_trace_path"].resolve() or args.done_signal.resolve() != handoff["paths"]["done_signal_path"].resolve():
                raise EvidenceError("normalizer paths do not match transient handoff")
            result = normalize_cdp(args.normalize_cdp, args.challenge, args.handoff)
            _write(args.output, result)
            try:
                done = _done_value(args.output, handoff["binding"])
                validate_done_signal(done, args.output, handoff["binding"])
                _write(args.done_signal, done)
            except Exception:
                args.output.unlink(missing_ok=True)
                raise
        elif args.check_browser_trace:
            _, binding = validate_challenge(_read_json(args.challenge))
            derive_browser(_read_json(args.check_browser_trace), binding)
        else:
            result = verify(args.activation, args.runtime, args.challenge, args.browser_trace)
            _write(args.output, result)
    except (EvidenceError, OSError) as exc:
        print(f"W12 security evidence FAIL: {exc}")
        return 1
    print("W12 security evidence PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
