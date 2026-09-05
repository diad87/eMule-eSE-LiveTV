#!/usr/bin/env python3
"""Fail-closed G14/H66 binding and launcher for the final V92-O01 candidate."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import types
from contextlib import ExitStack
from pathlib import Path, PurePosixPath
from types import SimpleNamespace
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
DOCUMENT_PATH = "docs/architecture/v92_o01_candidate_refresh_governance_v1.json"
VERIFIER_PATH = "tools/architecture/verify_v92_o01_candidate_refresh_governance.py"
TEST_PATH = "tools/architecture/test_verify_v92_o01_candidate_refresh_governance.py"
DOCUMENT = ROOT / DOCUMENT_PATH
DOCUMENT_SHA256 = "3eab80eb9ba7b3181fa0b3e6d539f557b40a582cebf00080a25bfff394eeb77f"
DOCUMENT_SEMANTIC_SHA256 = "ac4896f8bf67da1a44601699d81db187e20be7915d56f9d0aae698827a9276b9"
G13_PATH = "tools/architecture/verify_v92_o01_fault_audit_repair_governance.py"
G13_SHA256 = "a00a5a08faff06c86c6d284c29a82e98a4b364b1684fe7a7d6eedf7efd57c573"
OLD_G11_PATH = "tools/architecture/verify_v92_o01_clock_repair_governance.py"
G12_PATH = "tools/architecture/verify_v92_o01_rpc_failure_governance.py"

CANDIDATE = "b2a9a56cfc25b2604980dee1bb7577a7de7496ad"
CANDIDATE_TREE = "f8367adc1458cba6d499486beb34f0f4697fa4b3"
CANDIDATE_PARENT = "6379d88484091ca1469f9201dc4f61a49db209f6"
CANDIDATE_PARENT_TREE = "b8dc2c1cd7122d33dc777f92ed54d93f292efced"
G13_COMMIT = "ddd2731fe49685ce4ec49482b1bf6ff71bb6c913"
A65_COMMIT = "d41b7a41a736507124578d223cdeb3575b5f04a6"
M65_COMMIT = "6848811238b6d5c7bde7fca87cd699226156cf16"
H65_COMMIT = "4448d3b835f2ecc832117fd7246d650c79daeaf3"
H65_TREE = "778c163634b5d3cd54ef4e57719a50e385221ffc"
TAG_NAME = "v0.70b-eSE9.2.0-rc.1"
TAG_OBJECT = "bf7c165a6acc6cfcd3fc90b756fee1006b44a057"
LIBUTP_GITLINK = "2b364cbb0650bdab64a5de2abb4518f9f228ec44"

G_PATHS = sorted((DOCUMENT_PATH, TEST_PATH, VERIFIER_PATH))
H_PATHS = sorted((
    "artifacts/v92-o01-governance/activation.json",
    "artifacts/v92-o01-governance/offline-summary.json",
    "artifacts/v92-o01-governance/review-sol.json",
    "artifacts/v92-o01-governance/review-terra.json",
))
CANDIDATE_DELTA_PATHS = [
    "docs/RELEASE_NOTES_v9.2.0-rc.1.md",
    "docs/USER_GUIDE.md",
    "srchybrid/Emule.cpp",
    "srchybrid/PPgConnection.cpp",
    "srchybrid/eSE/API_CREDENTIALS.md",
    "srchybrid/eSE/_deprecated/player_combined_test.js",
    "srchybrid/eSE/api_keys.js",
    "srchybrid/eSE/hero_ui.js",
    "srchybrid/eSE/pages/explore_page.js",
    "srchybrid/eSE/pages/main_page.js",
    "srchybrid/eSE/pages/mylist_page.js",
    "srchybrid/eSE/pages/search_page.js",
    "srchybrid/eSE/player.js",
    "srchybrid/eSE/routes/movies_routes.js",
    "srchybrid/eSE/server.js",
    "srchybrid/eSE/test/main_page_async.test.js",
    "srchybrid/eSE/test/omdb_credentials.test.js",
    "srchybrid/eSE/test/tmdb_browser_privacy.test.js",
    "srchybrid/eSE/test/tmdb_credentials.test.js",
    "srchybrid/eSE/tmdb_api.js",
    "tests/test_v92_selftest_startup_isolation.py",
    "tools/run_alpha_tests.ps1",
]
CANDIDATE_DELTA_SHA256 = "494b3abda4a0087709256666330e432b910349b64039adaebbcb79675fe5ef9c"
BOUND_FILES = [
    "tools/lab/handoff93/run_product_mapper_cycle.ps1",
    "tools/lab/nat_gateway/v92_o01_product_stream.js",
    "tools/lab/nat_gateway/v92_o01_formal_controller.js",
    "tools/lab/nat_gateway/v92_o01_validate_formal.js",
    "tools/lab/nat_gateway/v92_o01_scenario.json",
    "tools/lab/nat_gateway/v92_o01_soak.js",
    "tools/lab/nat_gateway/v92_o01_t8_child.js",
    "tools/lab/nat_gateway/v92_o01_t8_daemon.js",
    "tools/lab/nat_gateway/v92_o01_bridge_protocol.js",
    "tools/lab/nat_gateway/v92_o01_t8_network_adapter.js",
    "tools/lab/nat_gateway/v92_o01_t8_gateway_adapter.js",
    "tools/lab/nat_gateway/v92_o01_t8_udp_mux.js",
    "tools/lab/nat_gateway/v92_o01_t8_upnp_edge.js",
    "tools/lab/nat_gateway/v92_o01_t8_fault_controller.js",
    "tools/lab/nat_gateway/v92_o01_formal_host.js",
    "tools/lab/nat_gateway/v92_o01_formal_rpc.js",
    "tools/lab/run_v92_o01_formal.ps1",
    "tools/lab/v92_o01_vm_session.psm1",
    "tools/lab/t8_hyperv.ps1",
    "tools/lab/common.ps1",
    "tools/lab/v91_r01_upnp.ps1",
]
HARNESS_PROJECTION_SHA256 = "438ff9eabff90ec122470176f19c3572d97853bc1d4109280b2c83fc3bfd48e8"
RUNTIME_BINDINGS = {
    "node_version": "22.23.2",
    "node_sha256": "0d0f5e39f9f3d9587bc19f73eab3c2c9c4903fd02d6dbf9c853dd81b3d95fad4",
    "executable_sha256": "4d7eae90c73778a6b147e7798424461889cbea816ce10990389fd1fef775d9f0",
    "build_info_sha256": "627dd148a1c7ae7d40d996c4c6c2d961fb7b364add2f8b7a245c8b9bb980ad54",
    "package_manifest_sha256": "122d814070ea8036cda9ed1d58afad031d66bfba846ba6b7e986bdcccefc30a3",
    "package_manifest_entry_count": 276,
    "package_file_count": 277,
}
DISTRIBUTION_BINDING = {
    "release_tag": TAG_NAME,
    "zip_path": f"dist/{TAG_NAME}/eSE-LiveTV-{TAG_NAME}-x64.zip",
    "zip_bytes": 213436329,
    "zip_sha256": "e2d888a6cb49e9e4918077f130b78b7e0515a0123fa28c590db93b6b4e924bfd",
    "sidecar_path": f"dist/{TAG_NAME}/eSE-LiveTV-{TAG_NAME}-x64.zip.sha256",
    "sidecar_bytes": 107,
    "sidecar_sha256": "71959a370b20fd64553d17e197ed98c60e5a336904fdb85e4746c51f010d7df6",
}
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
OFFLINE_GOVERNANCE_TESTS = 49
OFFLINE_GOVERNANCE_POSITIVE_CASES = 8
OFFLINE_GOVERNANCE_NEGATIVE_CASES = 41


class GateError(RuntimeError):
    pass


def require(condition: bool, code: str) -> None:
    if not condition:
        raise GateError(code)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"),
                      sort_keys=False).encode("ascii")


def canonical_sorted(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"),
                      sort_keys=True).encode("ascii")


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(type(key) is str and key not in result, "JSON_DUPLICATE_OR_KEY")
        result[key] = value
    return result


def strict_json(raw: bytes, label: str) -> dict[str, Any]:
    require(0 < len(raw) <= 1024 * 1024 and not raw.startswith(b"\xef\xbb\xbf"),
            f"{label}_SIZE_OR_BOM")

    def reject_number(_: str) -> Any:
        raise GateError(f"{label}_NON_INTEGER_NUMBER")

    try:
        text = raw.decode("utf-8", "strict")
        value = json.loads(text, object_pairs_hook=_pairs,
                           parse_float=reject_number,
                           parse_constant=reject_number)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise GateError(f"{label}_JSON") from exc
    require(type(value) is dict, f"{label}_OBJECT")
    return value


def exact_keys(value: Any, keys: tuple[str, ...] | list[str], label: str) -> None:
    require(type(value) is dict and list(value.keys()) == list(keys), f"{label}_KEYS")


def exact(value: Any, expected: Any, label: str) -> None:
    require(type(value) is type(expected), label)
    if type(expected) is dict:
        require(list(value.keys()) == list(expected.keys()), label)
        for key in expected:
            exact(value[key], expected[key], label)
        return
    if type(expected) is list:
        require(len(value) == len(expected), label)
        for actual_item, expected_item in zip(value, expected):
            exact(actual_item, expected_item, label)
        return
    require(value == expected, label)


def _load_module(path: Path, expected_sha: str, name: str) -> types.ModuleType:
    require(path.is_absolute() and path.is_file() and not path.is_symlink(),
            "G13_PATH")
    raw = path.read_bytes()
    require(sha256(raw) == expected_sha, "G13_SHA256")
    module = types.ModuleType(name)
    module.__file__ = str(path)
    module.__package__ = None
    exec(compile(raw, str(path), "exec", dont_inherit=True, optimize=0),
         module.__dict__)
    require(path.read_bytes() == raw, "G13_CHANGED")
    return module


def load_g13(repo: Path):
    repo = repo.resolve(strict=True)
    module = _load_module(repo / G13_PATH, G13_SHA256,
                          "v92_o01_g13_for_candidate_refresh")
    module.REPO = repo
    module.DOCUMENT = repo / "docs/architecture/v92_o01_fault_audit_repair_governance_v1.json"
    module.OLD_GOVERNANCE_VERIFIER = repo / OLD_G11_PATH
    module.PREDECESSOR_GOVERNANCE_VERIFIER = repo / G12_PATH
    return module


def _tree(g13, commit: str) -> str:
    value = g13._git_text("rev-parse", f"{commit}^{{tree}}")
    require(HEX40.fullmatch(value) is not None, "TREE_IDENTITY")
    return value


def _delta(g13, parent: str, commit: str) -> list[tuple[str, str]]:
    raw = g13._git("diff", "--name-status", "--no-renames", parent, commit, "--")
    try:
        lines = raw.decode("utf-8", "strict").splitlines()
    except UnicodeDecodeError as exc:
        raise GateError("DELTA_UTF8") from exc
    rows: list[tuple[str, str]] = []
    for line in lines:
        parts = line.split("\t")
        require(len(parts) == 2 and parts[0] in {"A", "M", "D"}, "DELTA_SHAPE")
        path = parts[1]
        pure = PurePosixPath(path)
        require(not pure.is_absolute() and all(part not in {"", ".", ".."}
                                               for part in pure.parts), "DELTA_PATH")
        rows.append((parts[0], path))
    return rows


def _ls_blob(g13, commit: str, path: str) -> str | None:
    raw = g13._git("ls-tree", commit, "--", path)
    if raw == b"":
        return None
    try:
        line = raw.decode("utf-8", "strict").rstrip("\n")
    except UnicodeDecodeError as exc:
        raise GateError("BLOB_UTF8") from exc
    match = re.fullmatch(r"100(?:644|755) blob ([0-9a-f]{40})\t(.+)", line)
    require(match is not None and match.group(2) == path, "BLOB_SHAPE")
    return match.group(1)


def validate_document(document: dict[str, Any]) -> None:
    require(sha256(canonical_sorted(document)) == DOCUMENT_SEMANTIC_SHA256,
            "DOCUMENT_SEMANTIC_IDENTITY")
    exact_keys(document, [
        "schema", "status", "gate", "scope", "candidate", "historical_chain",
        "candidate_refresh_delta", "harness_binding", "runtime_bindings",
        "distribution_binding", "topology", "offline_preflight",
        "physical_contract", "activation_contract", "formal_launch", "decision",
    ], "DOCUMENT")
    exact(document["schema"], "ese.v92.o01-candidate-refresh-governance/v1",
          "DOCUMENT_SCHEMA")
    exact(document["status"], "SEALED_G14_PREPARED_NOT_RUN", "DOCUMENT_STATUS")
    exact(document["gate"], "V92-O01", "DOCUMENT_GATE")
    candidate = document["candidate"]
    require(type(candidate) is dict and candidate.get("commit") == CANDIDATE and
            candidate.get("tree") == CANDIDATE_TREE and
            candidate.get("parent_commit") == CANDIDATE_PARENT and
            candidate.get("parent_tree") == CANDIDATE_PARENT_TREE and
            candidate.get("tag_name") == TAG_NAME and
            candidate.get("annotated_tag_object") == TAG_OBJECT and
            candidate.get("libutp_gitlink") == LIBUTP_GITLINK,
            "DOCUMENT_CANDIDATE")
    history = document["historical_chain"]
    require(type(history) is dict and history.get("g13_commit") == G13_COMMIT and
            history.get("a65_commit") == A65_COMMIT and
            history.get("m65_commit") == M65_COMMIT and
            history.get("h65_commit") == H65_COMMIT and
            history.get("h65_tree") == H65_TREE and
            history.get("physical_evidence_reusable") is False and
            history.get("activation_reusable") is False,
            "DOCUMENT_HISTORY")
    delta = document["candidate_refresh_delta"]
    require(type(delta) is dict and delta.get("from_commit") == H65_COMMIT and
            delta.get("to_commit") == CANDIDATE and delta.get("path_count") == 22 and
            delta.get("projection_sha256") == CANDIDATE_DELTA_SHA256 and
            delta.get("paths") == CANDIDATE_DELTA_PATHS,
            "DOCUMENT_DELTA")
    harness = document["harness_binding"]
    require(type(harness) is dict and harness.get("file_count") == 21 and
            harness.get("projection_sha256") == HARNESS_PROJECTION_SHA256 and
            harness.get("unchanged_h65_to_candidate") is True and
            harness.get("g13_verifier_sha256") == G13_SHA256 and
            harness.get("formal_runner_sha256") ==
                "727f6dbe4603181d973f4fe367eed051e033ea1ce6ec5fe949b0ea93e4e1b88d" and
            harness.get("scenario_sha256") ==
                "602874173a0ad69df7da4020f9a8db6ed6f726585c1f3ff983eadd187f74df5d",
            "DOCUMENT_HARNESS")
    exact(document["runtime_bindings"], RUNTIME_BINDINGS, "DOCUMENT_RUNTIME")
    exact(document["distribution_binding"], DISTRIBUTION_BINDING,
          "DOCUMENT_DISTRIBUTION")
    decision = document["decision"]
    require(type(decision) is dict and decision.get("g14_release_gate") is False and
            decision.get("h66_release_gate") is False and
            decision.get("r66_current_state") == "NOT_RUN" and
            decision.get("promotion_authorized") is False,
            "DOCUMENT_DECISION")


def _verify_candidate_history(g13) -> None:
    require(g13._parents(CANDIDATE) == [CANDIDATE_PARENT] and
            g13._parents(CANDIDATE_PARENT) == [H65_COMMIT] and
            g13._parents(H65_COMMIT) == [M65_COMMIT] and
            g13._parents(M65_COMMIT) == [A65_COMMIT] and
            g13._parents(A65_COMMIT) == [G13_COMMIT], "HISTORY_PARENTAGE")
    require(_tree(g13, CANDIDATE) == CANDIDATE_TREE and
            _tree(g13, CANDIDATE_PARENT) == CANDIDATE_PARENT_TREE and
            _tree(g13, H65_COMMIT) == H65_TREE, "HISTORY_TREES")
    require(g13._git_text("rev-parse", TAG_NAME) == TAG_OBJECT and
            g13._git_text("rev-parse", f"{TAG_NAME}^{{}}") == CANDIDATE,
            "TAG_BINDING")
    libutp = g13._git_text("ls-tree", CANDIDATE, "--", "libutp")
    require(libutp == f"160000 commit {LIBUTP_GITLINK}\tlibutp", "LIBUTP_BINDING")


def _verify_candidate_delta(g13) -> None:
    delta = _delta(g13, H65_COMMIT, CANDIDATE)
    require([path for _, path in delta] == CANDIDATE_DELTA_PATHS and
            len(delta) == 22, "CANDIDATE_DELTA_PATHS")
    rows: list[dict[str, Any]] = []
    for status, path in delta:
        rows.append({
            "status": status,
            "path": path,
            "old_blob": _ls_blob(g13, H65_COMMIT, path),
            "new_blob": _ls_blob(g13, CANDIDATE, path),
        })
    require(sha256(canonical({"files": rows})) == CANDIDATE_DELTA_SHA256,
            "CANDIDATE_DELTA_IDENTITY")


def _verify_harness(g13) -> None:
    require(len(BOUND_FILES) == len(set(BOUND_FILES)) == 21, "HARNESS_PATHS")
    rows: list[dict[str, Any]] = []
    for path in BOUND_FILES:
        blob = _ls_blob(g13, CANDIDATE, path)
        require(blob is not None and _ls_blob(g13, H65_COMMIT, path) == blob,
                "HARNESS_CHANGED")
        raw = g13._blob(CANDIDATE, path)
        rows.append({"path": path, "blob": blob, "sha256": sha256(raw),
                     "bytes": len(raw)})
    require(sha256(canonical({"files": rows})) == HARNESS_PROJECTION_SHA256,
            "HARNESS_IDENTITY")


def verify_g14(g13, g14: str, *, disk_root: Path | None = None) -> dict[str, Any]:
    require(HEX40.fullmatch(g14) is not None and g13._parents(g14) == [CANDIDATE],
            "G14_PARENTAGE")
    _verify_candidate_history(g13)
    _verify_candidate_delta(g13)
    _verify_harness(g13)
    require(_delta(g13, CANDIDATE, g14) == [("A", path) for path in G_PATHS],
            "G14_DELTA")
    blobs = {path: g13._blob(g14, path) for path in G_PATHS}
    require(sha256(blobs[DOCUMENT_PATH]) == DOCUMENT_SHA256, "DOCUMENT_SHA256")
    document = strict_json(blobs[DOCUMENT_PATH], "DOCUMENT")
    validate_document(document)
    if disk_root is not None:
        disk_root = disk_root.resolve(strict=True)
        for path, raw in blobs.items():
            disk = disk_root / PurePosixPath(path)
            require(disk.is_file() and not disk.is_symlink() and
                    disk.read_bytes() == raw, "G14_DISK_IDENTITY")
    return {"commit": g14, "tree": _tree(g13, g14), "document": document,
            "governance_sha256": {path: sha256(raw) for path, raw in blobs.items()}}


def _validate_offline(value: dict[str, Any], g14: dict[str, Any]) -> None:
    exact_keys(value, [
        "schema", "status", "release_gate", "physical_gate",
        "promotion_authorized", "candidate_commit", "candidate_tree",
        "g14_commit", "g14_tree", "governance_sha256",
        "harness_projection_sha256", "runtime_bindings",
        "distribution_binding", "tests",
    ], "OFFLINE")
    exact(value["schema"], "ese.v92.o01-candidate-refresh-offline-summary/v1",
          "OFFLINE_SCHEMA")
    require(value["status"] == "PASS_OFFLINE_ONLY_NOT_GATE" and
            value["release_gate"] is False and value["physical_gate"] == "NOT_RUN" and
            value["promotion_authorized"] is False and
            value["candidate_commit"] == CANDIDATE and
            value["candidate_tree"] == CANDIDATE_TREE and
            value["g14_commit"] == g14["commit"] and
            value["g14_tree"] == g14["tree"] and
            value["governance_sha256"] == g14["governance_sha256"] and
            value["harness_projection_sha256"] == HARNESS_PROJECTION_SHA256 and
            value["runtime_bindings"] == RUNTIME_BINDINGS and
            value["distribution_binding"] == DISTRIBUTION_BINDING,
            "OFFLINE_IDENTITY")
    tests = value["tests"]
    exact_keys(tests, ["node22", "powershell", "governance"], "OFFLINE_TESTS")
    exact(tests["node22"], {"tests": 143, "pass": 143, "fail": 0,
                             "exit_code": 0}, "OFFLINE_NODE")
    exact(tests["powershell"], {"mocks": 4, "pass": 4, "fail": 0,
                                 "hyperv_executed": False,
                                 "release_gate_emitted": False,
                                 "exit_code": 0}, "OFFLINE_POWERSHELL")
    governance = tests["governance"]
    exact(governance, {
        "tests": OFFLINE_GOVERNANCE_TESTS,
        "pass": OFFLINE_GOVERNANCE_TESTS,
        "fail": 0,
        "positive_cases": OFFLINE_GOVERNANCE_POSITIVE_CASES,
        "negative_cases": OFFLINE_GOVERNANCE_NEGATIVE_CASES,
        "verify_g14_exit_code": 0,
    }, "OFFLINE_GOVERNANCE")


def _validate_review(value: dict[str, Any], reviewer: str, g14: dict[str, Any],
                     offline_sha: str) -> None:
    exact_keys(value, [
        "schema", "reviewer_model", "independent", "verdict", "findings",
        "candidate_commit", "candidate_tree", "g14_commit", "g14_tree",
        "governance_sha256", "offline_summary_sha256",
        "runtime_bindings_sha256", "distribution_binding_sha256",
        "physical_gate", "promotion_authorized",
    ], "REVIEW")
    require(value["schema"] == "ese.v92.o01-candidate-refresh-review/v1" and
            value["reviewer_model"] == reviewer and value["independent"] is True and
            value["verdict"] == "APPROVE" and type(value["findings"]) is list and
            value["findings"] == [] and value["candidate_commit"] == CANDIDATE and
            value["candidate_tree"] == CANDIDATE_TREE and
            value["g14_commit"] == g14["commit"] and
            value["g14_tree"] == g14["tree"] and
            value["governance_sha256"] == g14["governance_sha256"] and
            value["offline_summary_sha256"] == offline_sha and
            value["runtime_bindings_sha256"] ==
                sha256(canonical_sorted(RUNTIME_BINDINGS)) and
            value["distribution_binding_sha256"] ==
                sha256(canonical_sorted(DISTRIBUTION_BINDING)) and
            value["physical_gate"] == "NOT_RUN" and
            value["promotion_authorized"] is False, "REVIEW_IDENTITY")


def _validate_activation(activation: dict[str, Any], g14: dict[str, Any],
                         offline_sha: str, sol_sha: str, terra_sha: str) -> None:
    exact_keys(activation, [
        "schema", "status", "release_gate", "physical_gate",
        "promotion_authorized", "evidence_reuse", "candidate_commit",
        "candidate_tree", "historical_h65_commit", "g14_commit", "g14_tree",
        "h66_parent_commit", "governance_sha256", "harness_projection_sha256",
        "runtime_bindings", "distribution_binding", "offline_summary_sha256",
        "review_sol_sha256", "review_terra_sha256",
    ], "ACTIVATION")
    require(activation["schema"] ==
                "ese.v92.o01-candidate-refresh-activation/v1" and
            activation["status"] == "ACTIVATED_H66_PREPARED_NOT_RUN" and
            activation["release_gate"] is False and
            activation["physical_gate"] == "NOT_RUN" and
            activation["promotion_authorized"] is False and
            activation["evidence_reuse"] is False and
            activation["candidate_commit"] == CANDIDATE and
            activation["candidate_tree"] == CANDIDATE_TREE and
            activation["historical_h65_commit"] == H65_COMMIT and
            activation["g14_commit"] == g14["commit"] and
            activation["g14_tree"] == g14["tree"] and
            activation["h66_parent_commit"] == g14["commit"] and
            activation["governance_sha256"] == g14["governance_sha256"] and
            activation["harness_projection_sha256"] == HARNESS_PROJECTION_SHA256 and
            activation["runtime_bindings"] == RUNTIME_BINDINGS and
            activation["distribution_binding"] == DISTRIBUTION_BINDING and
            activation["offline_summary_sha256"] == offline_sha and
            activation["review_sol_sha256"] == sol_sha and
            activation["review_terra_sha256"] == terra_sha,
            "ACTIVATION_IDENTITY")


def verify_h66(g13, h66: str, *, disk_root: Path | None = None) -> dict[str, Any]:
    require(HEX40.fullmatch(h66) is not None, "H66_IDENTITY")
    parents = g13._parents(h66)
    require(len(parents) == 1, "H66_PARENTAGE")
    g14 = verify_g14(g13, parents[0], disk_root=disk_root)
    require(_delta(g13, g14["commit"], h66) == [("M", path) for path in H_PATHS],
            "H66_DELTA")
    blobs = {path: g13._blob(h66, path) for path in H_PATHS}
    if disk_root is not None:
        for path, raw in blobs.items():
            disk = disk_root.resolve(strict=True) / PurePosixPath(path)
            require(disk.is_file() and not disk.is_symlink() and
                    disk.read_bytes() == raw, "H66_DISK_IDENTITY")
    offline_path = "artifacts/v92-o01-governance/offline-summary.json"
    sol_path = "artifacts/v92-o01-governance/review-sol.json"
    terra_path = "artifacts/v92-o01-governance/review-terra.json"
    activation_path = "artifacts/v92-o01-governance/activation.json"
    offline = strict_json(blobs[offline_path], "OFFLINE")
    _validate_offline(offline, g14)
    offline_sha = sha256(blobs[offline_path])
    sol = strict_json(blobs[sol_path], "REVIEW_SOL")
    terra = strict_json(blobs[terra_path], "REVIEW_TERRA")
    _validate_review(sol, "sol", g14, offline_sha)
    _validate_review(terra, "terra", g14, offline_sha)
    activation = strict_json(blobs[activation_path], "ACTIVATION")
    _validate_activation(activation, g14, offline_sha, sha256(blobs[sol_path]),
                         sha256(blobs[terra_path]))
    return {"commit": h66, "tree": _tree(g13, h66), "g14": g14,
            "activation": activation}


def _require_clean_head(g13, commit: str, root: Path) -> None:
    require(g13._git_text("rev-parse", "HEAD") == commit and
            g13._git_text("rev-parse", "HEAD^{tree}") == _tree(g13, commit),
            "WORKTREE_HEAD")
    require(g13._git("status", "--porcelain=v1", "--untracked-files=all",
                     "--ignore-submodules=none") == b"", "WORKTREE_DIRTY")
    root = root.resolve(strict=True)
    require(ROOT.resolve(strict=True) == root, "WORKTREE_ROOT")


def _formal_run(h66: str, source_root: str, evidence_root: str,
                node: str, credential_path: str,
                formal_state: dict[str, str] | None = None) -> int:
    if formal_state is None:
        formal_state = {"physical_gate": "NOT_RUN",
                        "physical_execution": "NOT_RUN"}
    exact(formal_state, {"physical_gate": "NOT_RUN",
                         "physical_execution": "NOT_RUN"},
          "FORMAL_INITIAL_STATE")
    require(os.name == "nt" and Path(source_root).is_absolute() and
            Path(evidence_root).is_absolute() and Path(node).is_absolute() and
            Path(credential_path).is_absolute(), "FORMAL_PATHS")
    source = Path(source_root).resolve(strict=True)
    g13 = load_g13(source)
    h_state = verify_h66(g13, h66, disk_root=ROOT)
    require(g13._git_text("rev-parse", "HEAD") == CANDIDATE and
            g13._git_text("rev-parse", "HEAD^{tree}") == CANDIDATE_TREE,
            "FORMAL_SOURCE_HEAD")
    old_raw = g13._blob(CANDIDATE,
        "docs/architecture/v92_o01_fault_audit_repair_governance_v1.json")
    old_document = g13.load_json_bytes(old_raw, "G13 governance")
    g13.validate_document(old_document)
    immutable = old_document["immutable_contract"]
    g13._assert_python_runtime(immutable)
    activation = h_state["activation"]

    def patched_verify_m(m_commit: str, a_commit: str) -> None:
        require(a_commit == CANDIDATE and m_commit == h_state["g14"]["commit"],
                "FORMAL_G14_ARGUMENTS")
        verify_g14(g13, m_commit, disk_root=ROOT)

    def patched_verify_h(h_commit: str, m_commit: str, a_commit: str,
                         g_commit: str, document: dict[str, Any]) -> None:
        require(h_commit == h66 and m_commit == h_state["g14"]["commit"] and
                a_commit == CANDIDATE and g_commit == CANDIDATE_PARENT and
                document is old_document, "FORMAL_H66_ARGUMENTS")
        verify_h66(g13, h_commit, disk_root=ROOT)

    def patched_bindings(value: Any, _manifest: Any,
                         _immutable: Any) -> dict[str, Any]:
        exact(value, RUNTIME_BINDINGS, "FORMAL_RUNTIME_BINDINGS")
        exact(value, activation["runtime_bindings"], "FORMAL_ACTIVATION_BINDINGS")
        return dict(RUNTIME_BINDINGS)

    g13.verify_m = patched_verify_m
    g13.verify_h = patched_verify_h
    g13._validate_runtime_bindings = patched_bindings
    package_root = source / "dist" / TAG_NAME / "package"
    args = SimpleNamespace(h_commit=h66, evidence_root=evidence_root,
                           package_root=str(package_root), node=node,
                           credential_path=credential_path)
    # The delegated G13 function owns all physical launch and final validation.
    # Once control crosses this boundary, a failure cannot honestly claim that
    # the physical run never started, even when G13 rejects before PowerShell.
    formal_state["physical_gate"] = "NOT_PASS"
    formal_state["physical_execution"] = "MAY_HAVE_STARTED"
    delegated = g13._run_formal_gate_and_emit(args, old_document, immutable)
    require(type(delegated) is int and delegated == 0, "FORMAL_DELEGATE_EXIT")
    return delegated


class ClosedParser(argparse.ArgumentParser):
    def error(self, _message: str) -> None:
        raise GateError("ARGUMENTS")


def _pass(mode: str, **values: Any) -> int:
    result = {"schema": "ese.v92.o01-candidate-refresh-verification/v1",
              "verdict": "PASS", "release_gate": False, "mode": mode,
              "candidate_commit": CANDIDATE, "candidate_tree": CANDIDATE_TREE,
              "physical_gate": "NOT_RUN", "promotion_authorized": False}
    result.update(values)
    sys.stdout.buffer.write(canonical_sorted(result) + b"\n")
    sys.stdout.buffer.flush()
    return 0


def main(argv: list[str] | None = None) -> int:
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    mode = "ARGUMENTS"
    formal_state = {"physical_gate": "NOT_RUN",
                    "physical_execution": "NOT_RUN"}
    try:
        parser = ClosedParser(allow_abbrev=False)
        group = parser.add_mutually_exclusive_group(required=True)
        group.add_argument("--document", action="store_true")
        group.add_argument("--verify-g14", action="store_true")
        group.add_argument("--verify-h66", action="store_true")
        group.add_argument("--formal-run", action="store_true")
        parser.add_argument("--h66")
        parser.add_argument("--source-root")
        parser.add_argument("--evidence-root")
        parser.add_argument("--node")
        parser.add_argument("--credential-path")
        args = parser.parse_args(raw_argv)
        require(sys.flags.isolated == 1 and sys.flags.no_site == 1 and
                sys.flags.ignore_environment == 1 and sys.flags.safe_path == 1 and
                sys.flags.dont_write_bytecode == 1, "PYTHON_ISOLATION")
        if args.document:
            require(raw_argv == ["--document"], "ARGUMENTS")
            raw = DOCUMENT.read_bytes()
            require(sha256(raw) == DOCUMENT_SHA256, "DOCUMENT_SHA256")
            validate_document(strict_json(raw, "DOCUMENT"))
            sys.stdout.buffer.write(raw)
            return 0
        if args.verify_g14:
            mode = "VERIFY_G14"
            require(raw_argv == ["--verify-g14"], "ARGUMENTS")
            g13 = load_g13(ROOT)
            head = g13._git_text("rev-parse", "HEAD")
            state = verify_g14(g13, head, disk_root=ROOT)
            _require_clean_head(g13, head, ROOT)
            return _pass(mode, g14_commit=head, g14_tree=state["tree"],
                         governance_files=3, harness_files=21,
                         candidate_delta_paths=22)
        if args.verify_h66:
            mode = "VERIFY_H66"
            require(raw_argv == ["--verify-h66", "--h66", args.h66], "ARGUMENTS")
            require(type(args.h66) is str, "ARGUMENTS")
            g13 = load_g13(ROOT)
            state = verify_h66(g13, args.h66, disk_root=ROOT)
            _require_clean_head(g13, args.h66, ROOT)
            return _pass(mode, h66_commit=args.h66, h66_tree=state["tree"],
                         g14_commit=state["g14"]["commit"], carrier_files=4)
        mode = "FORMAL_RUN"
        require(args.formal_run and raw_argv == [
            "--formal-run", "--h66", args.h66, "--source-root", args.source_root,
            "--evidence-root", args.evidence_root, "--node", args.node,
            "--credential-path", args.credential_path,
        ], "ARGUMENTS")
        return _formal_run(args.h66, args.source_root, args.evidence_root,
                           args.node, args.credential_path, formal_state)
    except (GateError, OSError, ValueError, RuntimeError) as exc:
        code = (
            str(exc)
            if isinstance(exc, GateError)
            and re.fullmatch(r"[A-Z0-9_]{1,80}", str(exc))
            else "INTERNAL_FAILURE"
        )
        physical_gate = (formal_state["physical_gate"]
                         if mode == "FORMAL_RUN" else "NOT_RUN")
        physical_execution = (formal_state["physical_execution"]
                              if mode == "FORMAL_RUN" else "NOT_RUN")
        failure = {"schema": "ese.v92.o01-candidate-refresh-failure/v1",
                   "verdict": "FAIL", "release_gate": False, "mode": mode,
                   "failure": code, "physical_gate": physical_gate,
                   "physical_execution": physical_execution,
                   "promotion_authorized": False}
        sys.stderr.buffer.write(canonical_sorted(failure) + b"\n")
        sys.stderr.buffer.flush()
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
