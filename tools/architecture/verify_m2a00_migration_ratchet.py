#!/usr/bin/env python3
"""Closed green ratchet for the M2A additional-extraction programme."""
from __future__ import annotations

import argparse
import ast
import collections
import copy
import functools
import hashlib
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any

import generate_mod01_architecture_inventory as mod01
import verify_mod04_architecture_gate as mod04
import verify_mod51_include_scc_gate as mod51

ROOT = Path(__file__).resolve().parents[2]
CONTRACT = ROOT / "docs/architecture/mod52_migration_contract_v1.json"
MATRIX = ROOT / "docs/architecture/mod52_migration_matrix_v1.json"
BASELINE = ROOT / "docs/architecture/mod52_migration_baseline_v1.json"
MOD03 = ROOT / "docs/architecture/mod03_ownership_layering_contract_v1.json"
MOD04 = ROOT / "docs/architecture/mod04_architecture_gate_baseline_v1.json"
MOD51 = ROOT / "docs/architecture/mod51_include_scc_contract_v1.json"
MOD03V2 = ROOT / "docs/architecture/mod03_ownership_layering_contract_v2.json"
MOD04V2 = ROOT / "docs/architecture/mod04_architecture_gate_catalog_v2.json"
ACTIVATION = ROOT / "docs/architecture/mod52_migration_activation_ledger_v1.json"
W12_MATRIX = ROOT / "docs/architecture/mod52_migration_matrix_v2.json"
W12_CONTRACT = ROOT / "docs/architecture/mod52_migration_contract_v2.json"
W12_MOD03 = ROOT / "docs/architecture/mod03_ownership_layering_contract_v3.json"
W12_MOD04 = ROOT / "docs/architecture/mod04_architecture_gate_catalog_v3.json"
W12_BASE_COMMIT = "545cdf45f9f2efaf56899bee6459bc133cf96071"
W12_CARD_BUDGET_PIN = {
    "add_max": 12000,
    "delete_min": 5500,
    "net_max": 6500,
}
W12_CARD_PATH_COUNT = 61
W12_SCOPE_EXPANSION_PATHS = {
    "docs/architecture/mod23_web_route_inventory_v1.json",
    "srchybrid/DirectReachabilityManager.h",
    "srchybrid/DirectReachabilityManager.cpp",
    "srchybrid/WebLiveApiDiagnosticsController.h",
    "srchybrid/WebLiveApiDiagnosticsController.cpp",
    "srchybrid/eSE/test/live_tv_regression.test.js",
    "srchybrid/Kad6GatewaySocket.cpp",
    "tests/test_v92_k03_port_roles.py",
    "tools/architecture/verify_mod04_architecture_gate.py",
    "tests/test_v92_mod04_architecture_gate.py",
}
W12_R_ARTIFACT_NAMES = {
    "activation": "activation.json",
    "runtime": "runtime.json",
    "browser_challenge": "browser-challenge.json",
    "browser_cdp_trace": "browser-cdp-trace.json",
    "verdict": "verdict.json",
}
W12_EVIDENCE_VERIFIER = "tools/architecture/verify_w12_security_evidence.py"
W12_R_TOOL_PATHS = {
    "runner": "tools/architecture/run_w12_security_runtime.ps1",
    "verifier": W12_EVIDENCE_VERIFIER,
    "collector": "tools/architecture/collect_w12_browser_cdp.mjs",
    "test": "tests/test_v92_m2a_w12_security_evidence.py",
    "ratchet": "tools/architecture/verify_m2a00_migration_ratchet.py",
}
W12_COVERAGE_IDS = tuple(f"W12-COV-{index:02d}" for index in range(1, 12))
W12_TYPED_COVERAGE = (
    "card:W12",
    "module:WebServerFacade",
    "binding:WebServerFacade",
    "module:WebHlsCapabilityController",
    "port:LiveHlsReadLease",
    "finding:W7-SEC-02",
    "contract:W12-HLS-SECURITY",
    "endpoint:reach-status",
    "snapshot:direct-reachability",
    "security:reach-status-boundary",
    "contract:advertised-bind-ports",
)
# These historical inputs are evidence, not self-authorising configuration.
# A v2/v3 overlay may refer to them, but cannot replace their digests.
W12_HISTORICAL_HASHES: dict[str, str] = {
    "docs/architecture/mod52_migration_contract_v1.json":
        "b3957aca15b7c25e42229c3f9623bff881b450c7277323a28c7639e0ea9f3caf",
    "docs/architecture/mod52_migration_matrix_v1.json":
        "de7e65410f34813276a3c8ef2f06a54009f2fbbf4ed2175f84eb7d33bdf91a05",
    "docs/architecture/mod03_ownership_layering_contract_v1.json":
        "0d5bd65c29b48f8525f5a5edcf8ee754610366af89d18cec3f2e51ecbfd98e42",
    "docs/architecture/mod03_ownership_layering_contract_v2.json":
        "c3aa3d90bccbc63ff7a0c8ebafd199e9ed2b00acc2c2ef488c5e11515a3f28b1",
    "docs/architecture/mod04_architecture_gate_baseline_v1.json":
        "6d5708dcd3ac5cc7379918e4e5e4b9296a624a77c3bf20861e094a62c537a6e0",
    "docs/architecture/mod04_architecture_gate_catalog_v2.json":
        "a977410c88a95a8d42c8f03950deb1c9d740da644bb42135df0d67d9b91bc2a4",
}
BASELINE_COMMIT = "8534bf9ee48a16084c0368bf33dcafb4ba12558d"
# Deliberately held in executable code rather than in the documents they pin:
# changing a contract cannot silently authorize its own replacement.
EXPECTED_DOC_HASHES: dict[str, str] = {
    "mod52_migration_contract_v1.json": "b3957aca15b7c25e42229c3f9623bff881b450c7277323a28c7639e0ea9f3caf",
    "mod52_migration_matrix_v1.json": "de7e65410f34813276a3c8ef2f06a54009f2fbbf4ed2175f84eb7d33bdf91a05",
    "mod52_migration_baseline_v1.json": "4c162b457059776f13c26341fdab60778088014e183acc48926f22f5d1cbc5c3",
    "mod03_ownership_layering_contract_v2.json": "c3aa3d90bccbc63ff7a0c8ebafd199e9ed2b00acc2c2ef488c5e11515a3f28b1",
    "mod04_architecture_gate_catalog_v2.json": "a977410c88a95a8d42c8f03950deb1c9d740da644bb42135df0d67d9b91bc2a4",
}
COORDINATORS = (
    ("LiveTunnel", "CLiveTunnel", "srchybrid/LiveTunnel.cpp", "srchybrid/LiveTunnel.h"),
    ("WebServer", "CWebServer", "srchybrid/WebServer.cpp", "srchybrid/WebServer.h"),
    ("LiveStreamManager", "CLiveStreamManager", "srchybrid/LiveStreamManager.cpp", "srchybrid/LiveStreamManager.h"),
)
EXPECTED_CARDS = {
    *(f"LT{index}" for index in range(1, 11)),
    *(f"W{index}" for index in range(1, 13)),
    *(f"LS{index}" for index in range(1, 7)),
}
EXPECTED_NON_MODULE_CARDS = {
    "LT10": ("coordinator/header close", "LiveTunnel"),
    "W7": ("inventory and regression goldens", "WebServer"),
    "LS6": ("coordinator/header close", "LiveStreamManager"),
}
EXPECTED_CARD_PREREQUISITES = {
    "LT1": [], "LT2": ["LT1"], "LT3": ["LT2"], "LT4": ["LT2"],
    "LT5": ["LT4"], "LT6": ["LT3", "LT5"], "LT7": ["LT3"],
    "LT8": ["LT3"],
    "LT9": ["LT1", "LT2", "LT3", "LT4", "LT5", "LT6", "LT7", "LT8"],
    "LT10": ["LT9"],
    "W1": ["LT10"], "W2": ["LT10"], "W3": ["W1", "W2"],
    "W4": ["W1", "W2"], "W5": ["W1", "W2"], "W6": ["W1", "W2"],
    "W7": ["W1", "W2", "W3", "W4", "W5", "W6"], "W8": ["W7"],
    "W9": ["W8"], "W10": ["W9"], "W11": ["W10"], "W12": ["W11"],
    "LS1": ["W12"], "LS2": ["LS1"], "LS3": ["LS1"],
    "LS4": ["LS2", "LS3"], "LS5": ["LS2"],
    "LS6": ["LS1", "LS2", "LS3", "LS4", "LS5"],
}
COORDINATOR_FILES = {
    "LiveTunnel": ("srchybrid/LiveTunnel.cpp", "srchybrid/LiveTunnel.h"),
    "WebServer": ("srchybrid/WebServer.cpp", "srchybrid/WebServer.h"),
    "LiveStreamManager": ("srchybrid/LiveStreamManager.cpp", "srchybrid/LiveStreamManager.h"),
}
CARD_BUDGET_EXCLUDED_PREFIXES = ("artifacts/",)
PARENT_BINDING_PATHS = {
    "CWebServer": ("srchybrid/WebServer.cpp",),
    "m_scheduler": ("srchybrid/LiveTunnelScheduler.cpp",),
    "m_exitServices": ("srchybrid/LiveExitServices.cpp",),
    "m_relayDispatcher": ("srchybrid/LiveRelayDispatcher.cpp",),
    "m_broadcastSession": ("srchybrid/LiveBroadcastSession.cpp",),
    "m_peerSet": ("srchybrid/LivePeerSet.cpp",),
    "m_chunkBuffer": ("srchybrid/LiveChunkWindow.cpp",),
}
PARENT_BINDING_HEADERS = {
    "m_scheduler": ("srchybrid/LiveTunnelScheduler.h",),
    "m_exitServices": ("srchybrid/LiveExitServices.h",),
    "m_relayDispatcher": ("srchybrid/LiveRelayDispatcher.h",),
    "m_broadcastSession": ("srchybrid/LiveBroadcastSession.h",),
    "m_peerSet": ("srchybrid/LivePeerSet.h",),
    "m_chunkBuffer": ("srchybrid/LiveChunkWindow.h",),
}
PARENT_BINDING_CLASSES = {
    "CWebServer": ("CWebServer",),
    "m_scheduler": ("LiveTunnelScheduler",),
    "m_exitServices": ("LiveExitServices",),
    "m_relayDispatcher": ("LiveRelayDispatcher",),
    "m_broadcastSession": ("LiveBroadcastSession",),
    "m_peerSet": ("LivePeerSet",),
    "m_chunkBuffer": ("LiveChunkWindow",),
}
BINDING_PORT_HEADER = "srchybrid/M2ABindingPort.h"


class GateError(RuntimeError): pass


def canonical(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()


def load(path: Path) -> dict[str, Any]: return json.loads(path.read_text(encoding="utf-8"))


def _w12_strict_json_bytes(blob: bytes, label: str) -> dict[str, Any]:
    """Decode a W12 authority object without JSON's duplicate-key ambiguity."""
    def pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in values:
            if key in result:
                raise GateError(f"W12 duplicate JSON member: {label}/{key}")
            result[key] = value
        return result

    try:
        value = json.loads(blob.decode("utf-8"), object_pairs_hook=pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GateError(f"W12 JSON is not strict UTF-8 JSON: {label}") from exc
    if not isinstance(value, dict):
        raise GateError(f"W12 JSON root is not an object: {label}")
    return value


def _w12_strict_json_file(path: Path) -> dict[str, Any]:
    try:
        return _w12_strict_json_bytes(path.read_bytes(), path.as_posix())
    except OSError as exc:
        raise GateError(f"W12 JSON file unavailable: {path.name}") from exc


def _lines(path: str, overrides: dict[str, bytes] | None) -> list[str]:
    raw = overrides[path] if overrides and path in overrides else (ROOT / path).read_bytes()
    return raw.decode("utf-8", errors="replace").splitlines()


def _raw(path: str, overrides: dict[str, bytes] | None) -> bytes:
    return overrides[path] if overrides and path in overrides else (ROOT / path).read_bytes()


def _free_helpers(
    lines: list[str], path: str, minimum_length: int = 150
) -> list[dict[str, Any]]:
    """Find non-member helpers too; M2A must not hide a 151-line body there."""
    result: list[dict[str, Any]] = []
    attributes = r"(?:\[\[[^\]]+\]\]\s*)*"
    declaration_prefix = (
        rf"(?:{attributes}|extern\s+\"C(?:\+\+)?\"\s+|"
        r"__declspec\s*\([^)]*\)\s+|"
        r"(?:static|inline|constexpr|consteval|constinit|friend)\s+)*"
    )
    exception_spec = r"(?:noexcept(?:\s*\([^)]*\))?\s*)?"
    signature = re.compile(
        rf"^\s*{declaration_prefix}[\w:<>,~*&\s]+\s+"
        rf"([A-Za-z_]\w*)\s*\([^;{{}}]*\)\s*(?:const\s*)?"
        rf"{exception_spec}{attributes}(?:->\s*[\w:<>,~*&\s]+)?"
        rf"{attributes}\{{"
    )
    lambda_signature = re.compile(
        rf"^\s*{attributes}(?:(?:static|inline|constexpr|constinit)\s+)*"
        rf"(?:const\s+auto|auto\s+const|auto)\s+([A-Za-z_]\w*)\s*="
        rf"\s*\[[^]]*\]\s*(?:<[^;{{}}]*>\s*)?"
        rf"(?:\([^;{{}}]*\))?\s*(?:mutable\s*)?{exception_spec}"
        rf"{attributes}(?:->\s*[\w:<>,~*&\s]+)?{attributes}\{{"
    )
    ignored = {"if", "for", "while", "switch", "catch"}
    for index, line in enumerate(lines):
        # Deliberately use a small lexical window: declarations commonly wrap
        # before the opening brace; this remains parser-free and fail-closed.
        window = "\n".join(lines[index:index + 6])
        # A qualified *function name* belongs to MOD-0.1's member parser.
        # Do not discard std:: return types while identifying free helpers.
        if re.search(r"::\s*[A-Za-z_]\w*\s*\(", window):
            continue
        match = signature.match(window) or lambda_signature.match(window)
        if not match or match.group(1) in ignored:
            continue
        end = mod01.find_function_end(lines, index)
        length = end - index + 1
        if length > minimum_length:
            result.append({"name": f"{path}::{match.group(1)}@{index + 1}", "length_approx": length})
    return result


def _structural_long_bodies(raw: str) -> dict[str, list[int]]:
    """Inventory every >150-line braced body, independent of C++ syntax."""
    normalized = mod51._normalize_translation_input(raw)
    translated = mod51._mask_comments_and_literals(
        "<coordinator>", mod51._splice_phase_two(normalized)
    )
    stack: list[tuple[int, int]] = []
    bodies: dict[str, list[int]] = {}
    line = 1
    for index, current in enumerate(translated):
        if current == "\n":
            line += 1
        elif current == "{":
            stack.append((index, line))
        elif current == "}" and stack:
            start, start_line = stack.pop()
            length = line - start_line + 1
            if length <= 150:
                continue
            previous = max(
                translated.rfind(delimiter, 0, start)
                for delimiter in (";", "}", "{")
            )
            prefix = " ".join(translated[previous + 1:start].split())[-300:]
            key = hashlib.sha256(prefix.encode("utf-8")).hexdigest()
            bodies.setdefault(key, []).append(length)
    for lengths in bodies.values():
        lengths.sort()
    return bodies


@functools.lru_cache(maxsize=None)
def _baseline_coordinator_text(path: str) -> str:
    return _git_blob(BASELINE_COMMIT, path).decode(
        "utf-8", errors="replace"
    )


def _structural_body_growth(
    lines: list[str], path: str
) -> list[dict[str, Any]]:
    """Fail closed when any long body is new or grows, even if unparsed."""
    current = _structural_long_bodies("\n".join(lines))
    baseline = _structural_long_bodies(_baseline_coordinator_text(path))
    growth: list[dict[str, Any]] = []
    for key, lengths in current.items():
        previous = baseline.get(key, [])
        for index, length in enumerate(lengths):
            if index >= len(previous) or length > previous[index]:
                growth.append({
                    "name": f"{path}::unclassified-body-{key[:12]}-{index}",
                    "length_approx": length,
                })
    return growth


def _baseline_overrides() -> dict[str, bytes]:
    """Read every governed source from the immutable baseline Git object."""
    config, contract = load(MOD04), load(MOD03)
    paths = {path for _, _, cpp, header in COORDINATORS for path in (cpp, header)}
    for entry in mod04._entry_map(config, contract).values():
        paths.update(entry["implementation_files"] + entry["interface_files"])
    result: dict[str, bytes] = {}
    for path in sorted(paths):
        try:
            result[path] = subprocess.check_output(["git", "show", f"{BASELINE_COMMIT}:{path}"], cwd=ROOT)
        except (OSError, subprocess.CalledProcessError) as exc:
            raise GateError(f"baseline blob unavailable: {path}") from exc
    return result


def _combined_catalogue(matrix: dict[str, Any], ledger: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    """Generate the v1+active-M2A include catalogue; no per-card code edits."""
    config, contract = copy.deepcopy(load(MOD04)), copy.deepcopy(load(MOD03))
    config["approved_non_module_code"].extend(
        copy.deepcopy(load(MOD04V2)["approved_non_module_code"])
    )
    active = [item for item in matrix["additional_modules"] if ledger["cards"][item["card"]]["state"] == "active"]
    if not active:
        return config, contract
    contract["coordinators"].append({"owner": "M2A", "planned_modules": [{"module": item["name"], "layer": item["layer"]} for item in active]})
    entries = config["module_catalog"]["entries"]
    entries.extend({
        "name": item["name"], "owner": "M2A", "layer": item["layer"],
        "implementation_files": [f"srchybrid/{item['name']}.cpp"],
        "interface_files": [f"srchybrid/{item['name']}.h"],
        "declared_direct_dependencies": item["dependencies"],
    } for item in active)
    config["module_catalog"]["state"] = "EXTRACTION_ACTIVE"
    return config, contract


def _git_blob(commit: str, path: str, repo_root: Path = ROOT) -> bytes:
    try:
        return subprocess.check_output(
            ["git", "show", f"{commit}:{path}"],
            cwd=repo_root,
            stderr=subprocess.DEVNULL,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise GateError(f"Git blob unavailable: {commit}:{path}") from exc


def _is_ancestor(base: str, target: str, repo_root: Path = ROOT) -> bool:
    try:
        return subprocess.run(
            ["git", "merge-base", "--is-ancestor", base, target],
            cwd=repo_root,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        ).returncode == 0
    except OSError as exc:
        raise GateError("Git ancestry unavailable") from exc


def _activation_parent(commit: str, repo_root: Path = ROOT) -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", f"{commit}^"],
            cwd=repo_root,
            text=True,
        ).strip()
    except (OSError, subprocess.CalledProcessError) as exc:
        raise GateError("M2A activation parent commit unavailable") from exc


def _git_path_exists(commit: str, path: str, repo_root: Path = ROOT) -> bool:
    try:
        return subprocess.run(
            ["git", "cat-file", "-e", f"{commit}:{path}"],
            cwd=repo_root,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        ).returncode == 0
    except OSError as exc:
        raise GateError("M2A Git path history unavailable") from exc


def _git_path_changed(
    base: str, target: str, path: str, repo_root: Path = ROOT
) -> bool:
    try:
        return bool(
            subprocess.check_output(
                ["git", "diff", "--name-only", base, target, "--", path],
                cwd=repo_root,
                text=True,
            ).strip()
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise GateError("M2A evidence diff unavailable") from exc


def _card_test_requirements(matrix: dict[str, Any]) -> dict[str, set[str]]:
    requirements = {
        card: {f"card:{card}"} for card in EXPECTED_CARDS
    }
    for module in matrix["additional_modules"] + matrix["existing_modules"]:
        requirements[module["card"]].add(f"module:{module['name']}")
        requirements[module["card"]].add(f"binding:{module['name']}")
    for coordinator, section in matrix["field_matrix"].items():
        for transfer in section["transfers"]:
            requirements[transfer["card"]].add(
                f"fields:{coordinator}:{transfer['owner']}"
            )
    for item in matrix["function_matrix"]:
        terminal = item["card"].split("-")[-1]
        requirements[terminal].add(f"function:{item['name']}")
    return requirements


def _coverage_test_method(coverage: str) -> str:
    return "test_m2a_" + hashlib.sha256(
        coverage.encode("utf-8")
    ).hexdigest()[:16]


def _validate_test_source(blob: bytes, covers: list[str]) -> None:
    try:
        tree = ast.parse(blob.decode("utf-8"))
    except (UnicodeDecodeError, SyntaxError) as exc:
        raise GateError("active M2A test_source is not valid Python") from exc
    methods: dict[
        str, list[ast.FunctionDef | ast.AsyncFunctionDef]
    ] = collections.defaultdict(list)
    for node in ast.walk(tree):
        if isinstance(
            node, (ast.FunctionDef, ast.AsyncFunctionDef)
        ) and node.name.startswith("test_"):
            methods[node.name].append(node)

    def decorator_name(node: ast.expr) -> str:
        if isinstance(node, ast.Call):
            return decorator_name(node.func)
        if isinstance(node, ast.Attribute):
            return f"{decorator_name(node.value)}.{node.attr}".strip(".")
        if isinstance(node, ast.Name):
            return node.id
        return ""

    def meaningful_assertion(statement: ast.stmt) -> bool:
        if isinstance(statement, ast.Expr) and isinstance(
            statement.value, ast.Call
        ):
            call = statement.value
            if not (
                isinstance(call.func, ast.Attribute)
                and call.func.attr.startswith("assert")
            ):
                return False
            if call.func.attr in {"assertTrue", "assertFalse"} and call.args:
                if isinstance(call.args[0], ast.Constant):
                    return False
            if call.func.attr in {"assertEqual", "assertIs"} and len(
                call.args
            ) >= 2:
                if ast.dump(call.args[0]) == ast.dump(call.args[1]):
                    return False
            return True
        if isinstance(statement, (ast.With, ast.AsyncWith)):
            return any(
                isinstance(item.context_expr, ast.Call)
                and isinstance(item.context_expr.func, ast.Attribute)
                and item.context_expr.func.attr.startswith("assert")
                for item in statement.items
            )
        return False

    for coverage in covers:
        candidates = methods.get(_coverage_test_method(coverage), [])
        if len(candidates) != 1:
            raise GateError(
                f"active M2A test_source lacks one unique coverage method: {coverage}"
            )
        method = candidates[0]
        if isinstance(method, ast.AsyncFunctionDef):
            raise GateError(
                f"active M2A coverage method may not be asynchronous: {coverage}"
            )
        if any(
            isinstance(node, (ast.Yield, ast.YieldFrom, ast.Await))
            for node in ast.walk(method)
        ):
            raise GateError(
                f"active M2A coverage method may not defer execution: {coverage}"
            )
        decorators = {
            decorator_name(item).casefold()
            for item in method.decorator_list
        }
        if any(
            "skip" in item or "expectedfailure" in item
            for item in decorators
        ):
            raise GateError(
                f"active M2A coverage method may not be skipped: {coverage}"
            )
        if method.decorator_list:
            raise GateError(
                f"active M2A coverage method may not be decorated: {coverage}"
            )
        reachable_assertion = bool(
            method.body and meaningful_assertion(method.body[0])
        )
        if not reachable_assertion:
            raise GateError(
                f"active M2A coverage method has no reachable nontrivial assertion: {coverage}"
            )


def _run_required_tests(test_path: str, covers: set[str]) -> None:
    """Run evidence and prove every required method ended in addSuccess."""
    runner = r"""
import contextlib
import importlib.util
import io
import json
import pathlib
import sys
import types
import unittest

OriginalTestCase = unittest.TestCase
OriginalObjectNew = object.__new__
OriginalCodeType = types.CodeType
OriginalFunctionType = types.FunctionType
original_test_case_methods = {
    name: getattr(unittest.TestCase, name)
    for name in (
        "__init__", "run", "__call__", "_callSetUp",
        "_callTestMethod", "_callTearDown", "doCleanups",
    )
}
original_test_case_assertions = {
    name: getattr(unittest.TestCase, name)
    for name in dir(unittest.TestCase)
    if name.startswith("assert")
    or name in {"fail", "failIf", "failUnless", "skipTest"}
}
OriginalTestResult = unittest.TestResult
required_methods = json.loads(sys.argv[2])

class TrackingResult(unittest.TestResult):
    def __init__(self):
        super().__init__()
        self.successes = []

    def addSuccess(self, test):
        super().addSuccess(test)
        self.successes.append(test._testMethodName)

original_tracking_add_success = TrackingResult.addSuccess
path = pathlib.Path(sys.argv[1])
spec = importlib.util.spec_from_file_location("_m2a_evidence", path)
module = importlib.util.module_from_spec(spec)
expected_module_code = spec.loader.get_code("_m2a_evidence")
expected_codes = {}

def collect_codes(code):
    for constant in code.co_consts:
        if isinstance(constant, OriginalCodeType):
            if constant.co_name in required_methods:
                expected_codes.setdefault(constant.co_name, []).append(constant)
            collect_codes(constant)

collect_codes(expected_module_code)
if (
    set(expected_codes) != set(required_methods)
    or any(len(items) != 1 for items in expected_codes.values())
):
    raise RuntimeError("one compiled evidence method is required")
spec.loader.exec_module(module)
# Evidence is executable but not authoritative over the runner itself.
unittest.TestCase = OriginalTestCase
unittest.case.TestCase = OriginalTestCase
unittest.TestResult = OriginalTestResult
unittest.result.TestResult = OriginalTestResult
for name, implementation in original_test_case_methods.items():
    setattr(OriginalTestCase, name, implementation)
for name, implementation in original_test_case_assertions.items():
    setattr(OriginalTestCase, name, implementation)
TrackingResult.addSuccess = original_tracking_add_success

result = TrackingResult()
captured = io.StringIO()
with contextlib.redirect_stdout(captured), contextlib.redirect_stderr(captured):
    for method in required_methods:
        forbidden = {
            "__init__", "__new__", "id", "run", "__call__",
            "_callSetUp", "_callTestMethod",
            "_callTearDown", "doCleanups", "setUp", "tearDown",
            "setUpClass", "tearDownClass", "__getattribute__",
            "__getattr__", "__setattr__", "fail", "skipTest",
            "failureException",
        }
        forbidden.update(original_test_case_assertions)
        candidates = [
            value
            for value in vars(module).values()
            if (
                isinstance(value, type)
                and type(value) is type
                and value.__bases__ == (OriginalTestCase,)
                and method in value.__dict__
            )
        ]
        if len(candidates) != 1:
            raise RuntimeError("one direct evidence TestCase is required")
        test_type = candidates[0]
        if forbidden.intersection(test_type.__dict__):
            raise RuntimeError("evidence test runner override forbidden")
        runtime_method = test_type.__dict__[method]
        if (
            type(runtime_method) is not OriginalFunctionType
            or runtime_method.__code__ != expected_codes[method][0]
            or runtime_method.__defaults__ is not None
            or runtime_method.__kwdefaults__ is not None
            or runtime_method.__closure__ is not None
        ):
            raise RuntimeError("evidence method changed after validation")
        test = OriginalObjectNew(test_type)
        original_test_case_methods["__init__"](test, method)
        if (
            test.__dict__.get("_testMethodName") != method
            or any(
                name in test.__dict__
                for name in original_test_case_assertions
            )
        ):
            raise RuntimeError("evidence method identity was redirected")
        original_test_case_methods["run"](test, result)
payload = {
    "testsRun": result.testsRun,
    "successes": result.successes,
    "skipped": [
        (test._testMethodName, reason) for test, reason in result.skipped
    ],
    "failures": [
        test._testMethodName for test, _ in result.failures
    ],
    "errors": [test._testMethodName for test, _ in result.errors],
    "expectedFailures": [
        test._testMethodName for test, _ in result.expectedFailures
    ],
    "unexpectedSuccesses": [
        test._testMethodName for test in result.unexpectedSuccesses
    ],
}
print("__M2A_TEST_RESULT__" + json.dumps(payload, sort_keys=True))
"""
    try:
        completed = subprocess.run(
            [
                sys.executable,
                "-c",
                runner,
                test_path,
                json.dumps(sorted(
                    _coverage_test_method(coverage)
                    for coverage in covers
                )),
            ],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=120,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise GateError(
            f"active M2A evidence test could not run: {test_path}"
        ) from exc
    marker = "__M2A_TEST_RESULT__"
    result_lines = [
        line[len(marker):]
        for line in completed.stdout.splitlines()
        if line.startswith(marker)
    ]
    if completed.returncode or len(result_lines) != 1:
        raise GateError(f"active M2A evidence test failed: {test_path}")
    try:
        result = json.loads(result_lines[0])
    except json.JSONDecodeError as exc:
        raise GateError(
            f"active M2A evidence test result is invalid: {test_path}"
        ) from exc
    if (
        set(result)
        != {
            "testsRun", "successes", "skipped", "failures", "errors",
            "expectedFailures", "unexpectedSuccesses",
        }
        or not isinstance(result["testsRun"], int)
        or result["testsRun"] != len(result["successes"])
        or any(
            result[key]
            for key in (
                "skipped", "failures", "errors", "expectedFailures",
                "unexpectedSuccesses",
            )
        )
    ):
        raise GateError(
            f"active M2A evidence test did not finish cleanly: {test_path}"
        )
    successes = result["successes"]
    if not isinstance(successes, list) or not all(
        isinstance(item, str) for item in successes
    ):
        raise GateError(
            f"active M2A evidence success ledger is invalid: {test_path}"
        )
    for coverage in covers:
        method = _coverage_test_method(coverage)
        matches = [
            test_id for test_id in successes
            if test_id.rsplit(".", 1)[-1] == method
        ]
        if len(matches) != 1:
            raise GateError(
                f"active M2A evidence method did not execute successfully: {coverage}"
            )


def validate_activation_provenance(
    state: dict[str, Any],
    module_paths: list[str],
    repo_root: Path = ROOT,
    baseline_commit: str = BASELINE_COMMIT,
    head_commit: str = "HEAD",
    card: str | None = None,
    activation_ledger_path: str | None = None,
    prerequisites: list[str] | None = None,
) -> None:
    """Prove B <= A < H and bind evidence/current sources to activation A."""
    activation_commit = state["activation_commit"]
    if not _is_ancestor(baseline_commit, activation_commit, repo_root):
        raise GateError("active M2A commit is not descended from the frozen baseline")
    activation_parent = _activation_parent(activation_commit, repo_root)
    if not _is_ancestor(baseline_commit, activation_parent, repo_root):
        raise GateError("active M2A implementation commit must follow the frozen baseline")
    if not _is_ancestor(activation_commit, head_commit, repo_root):
        raise GateError("active M2A commit is not an ancestor of HEAD")
    try:
        if (
            subprocess.check_output(
                ["git", "rev-parse", activation_commit],
                cwd=repo_root,
                text=True,
            ).strip()
            == subprocess.check_output(
                ["git", "rev-parse", head_commit],
                cwd=repo_root,
                text=True,
            ).strip()
        ):
            raise GateError("active M2A commit must precede its attestation commit")
    except (OSError, subprocess.CalledProcessError) as exc:
        raise GateError("M2A activation/attestation commit unavailable") from exc
    if card is not None and activation_ledger_path is not None:
        try:
            at_activation = json.loads(
                _git_blob(
                    activation_commit, activation_ledger_path, repo_root
                ).decode("utf-8")
            )
            at_head_blob = _git_blob(
                head_commit, activation_ledger_path, repo_root
            )
            at_head = json.loads(at_head_blob.decode("utf-8"))
            at_parent = json.loads(
                _git_blob(
                    activation_parent, activation_ledger_path, repo_root
                ).decode("utf-8")
            )
        except (UnicodeDecodeError, json.JSONDecodeError, KeyError) as exc:
            raise GateError("M2A activation ledger history unavailable") from exc
        planned = at_activation.get("cards", {}).get(card)
        planned_state = {
            "state": "planned", "activation_commit": None, "evidence": []
        }
        if at_parent != at_activation:
            raise GateError(
                "M2A implementation commit A must not modify the activation ledger"
            )
        if (
            planned != planned_state
            or at_parent.get("cards", {}).get(card) != planned_state
        ):
            raise GateError(
                "M2A card was not continuously planned before and at its implementation commit"
            )
        for prerequisite in prerequisites or []:
            prerequisite_state = at_activation.get("cards", {}).get(
                prerequisite
            )
            prerequisite_at_parent = at_parent.get("cards", {}).get(
                prerequisite
            )
            if (
                not isinstance(prerequisite_state, dict)
                or prerequisite_state.get("state") != "active"
                or not re.fullmatch(
                    r"[0-9a-f]{40}",
                    prerequisite_state.get("activation_commit", ""),
                )
                or not prerequisite_state.get("evidence")
                or prerequisite_at_parent != prerequisite_state
                or not _is_ancestor(
                    prerequisite_state["activation_commit"],
                    activation_parent,
                    repo_root,
                )
            ):
                raise GateError(
                    f"M2A card prerequisite was not previously active/attested before A: {prerequisite}"
                )
        if at_head.get("cards", {}).get(card) != state:
            raise GateError("M2A HEAD attestation differs from the active ledger")
        current_ledger = repo_root / activation_ledger_path
        if not current_ledger.is_file() or current_ledger.read_bytes() != at_head_blob:
            raise GateError("M2A active ledger is not committed at HEAD")
    for evidence in state["evidence"]:
        blob = _git_blob(evidence["commit"], evidence["path"], repo_root)
        if hashlib.sha256(blob).hexdigest() != evidence["sha256"]:
            raise GateError("active M2A evidence hash drift")
    for path in module_paths:
        frozen = _git_blob(activation_commit, path, repo_root)
        current_path = repo_root / path
        if not current_path.is_file():
            raise GateError(f"active M2A module source missing: {path}")
        if current_path.read_bytes() != frozen:
            raise GateError(f"active M2A module differs from its activation commit: {path}")


def validate_source_activation(
    state: dict[str, Any],
    module_paths: list[str],
    repo_root: Path = ROOT,
    baseline_commit: str = BASELINE_COMMIT,
    head_commit: str = "HEAD",
) -> None:
    present = [path for path in module_paths if (repo_root / path).is_file()]
    if state["state"] == "planned":
        if present:
            raise GateError(f"M2A additional module appeared before card activation: {present[0]}")
        return
    missing = sorted(set(module_paths) - set(present))
    if missing:
        raise GateError(f"active M2A module source missing: {missing[0]}")
    validate_activation_provenance(
        state, module_paths, repo_root, baseline_commit, head_commit
    )
    activation_parent = _activation_parent(
        state["activation_commit"], repo_root
    )
    for path in module_paths:
        if _git_path_exists(activation_parent, path, repo_root):
            raise GateError(
                f"M2A additional module existed before its activation commit: {path}"
            )


def validate_existing_module_activations(
    modules: list[dict[str, Any]],
    ledger: dict[str, Any],
    entries: dict[str, dict[str, Any]],
    repo_root: Path = ROOT,
    baseline_commit: str = BASELINE_COMMIT,
    head_commit: str = "HEAD",
) -> None:
    """Byte-bind pre-existing modules reused by an active M2A card to A."""
    for module in modules:
        state = ledger["cards"][module["card"]]
        if state["state"] != "active":
            continue
        entry = entries[module["name"]]
        validate_activation_provenance(
            state,
            entry["implementation_files"] + entry["interface_files"],
            repo_root,
            baseline_commit,
            head_commit,
        )


def _numstat(base: str, target: str, paths: list[str], repo_root: Path = ROOT) -> tuple[int, int]:
    """Physical add/delete accounting from immutable Git trees."""
    try:
        output = subprocess.check_output(["git", "diff", "--numstat", base, target, "--", *paths], cwd=repo_root, text=True)
    except (OSError, subprocess.CalledProcessError) as exc:
        raise GateError("M2A activation budget commit unavailable") from exc
    added = deleted = 0
    for row in output.splitlines():
        parts = row.split("\t")
        if len(parts) < 3 or not parts[0].isdigit() or not parts[1].isdigit():
            raise GateError("M2A card numstat contains an unaccounted binary or malformed row")
        path = parts[-1].replace("\\", "/")
        if not paths and path.startswith(CARD_BUDGET_EXCLUDED_PREFIXES):
            continue
        added += int(parts[0]); deleted += int(parts[1])
    return added, deleted


def validate_active_budgets(
    matrix: dict[str, Any],
    ledger: dict[str, Any],
    numstat_provider: Any = _numstat,
    loc_provider: Any = None,
    base_provider: Any = _activation_parent,
) -> None:
    """Apply physical module limits and aggregate A/D/net per active card."""
    if loc_provider is None:
        loc_provider = lambda paths: sum(mod04.loc_physical((ROOT / path).read_bytes()) for path in paths)
    base_entries = mod04._entry_map(load(MOD04), load(MOD03))
    active_by_card: dict[str, list[dict[str, Any]]] = {
        card: [] for card, state in ledger["cards"].items() if state["state"] == "active"
    }
    for module in matrix["additional_modules"]:
        if module["card"] in active_by_card:
            active_by_card[module["card"]].append(module)
    for module in matrix["existing_modules"]:
        if module["card"] in active_by_card:
            active_by_card[module["card"]].append(module)

    for card, modules in active_by_card.items():
        state = ledger["cards"][card]
        budget = matrix["card_budgets"][card]
        activation_base = base_provider(state["activation_commit"])
        module_paths: list[str] = []
        for module in modules:
            if module["name"] in base_entries:
                entry = base_entries[module["name"]]
                paths = entry["implementation_files"] + entry["interface_files"]
            else:
                paths = [
                    f"srchybrid/{module['name']}.cpp",
                    f"srchybrid/{module['name']}.h",
                ]
            module_paths.extend(paths)
            if loc_provider(paths) > min(module["budget"]["module_loc"], 1200, 1500):
                raise GateError(f"active M2A module LOC budget exceeded: {module['name']}")

        coordinator_paths = list(COORDINATOR_FILES[budget["coordinator"]])
        # The card budget is the complete implementation-commit delta.  Only
        # generated artifacts are explicitly excluded; tests/docs count.
        added, deleted = numstat_provider(
            activation_base, state["activation_commit"], []
        )
        if added > budget["add"] or deleted < budget["delete"] or added - deleted > budget["net"]:
            raise GateError(f"active M2A card A/D/net budget exceeded: {card}")
        facade_added, facade_deleted = numstat_provider(
            activation_base, state["activation_commit"], coordinator_paths
        )
        if facade_added > budget["facade_add_max"]:
            raise GateError(f"active M2A card facade budget exceeded: {card}")
        if budget["reduction_required"] and facade_deleted <= facade_added:
            raise GateError(f"active M2A card coordinator reduction budget exceeded: {card}")


def _validate_active_include_semantics(
    config: dict[str, Any],
    contract: dict[str, Any],
    matrix: dict[str, Any],
    ledger: dict[str, Any],
    overrides: dict[str, bytes] | None,
) -> None:
    """Apply MOD-0.4 semantics using MOD-5.1's robust include lexer."""
    entries = mod04._entry_map(config, contract)
    file_owner = mod04._module_file_owner(entries)
    repo_paths = mod04._repo_code_paths(overrides, file_owner)
    coordinator_headers = {
        header.casefold() for header in mod04.COORDINATOR_HEADERS
    }
    # Once any card is active, its implementation commit may touch any
    # governed v1 file.  Re-scan the entire combined catalogue robustly so a
    # card cannot degrade a historical module outside its own module list.
    for name in sorted(entries):
        entry = entries[name]
        module_dependencies: set[str] = set()
        direct_targets: set[str] = set()
        for path in entry["implementation_files"] + entry["interface_files"]:
            raw = _raw(path, overrides).decode("utf-8", errors="replace")
            is_public_header = path in entry["interface_files"]
            if (
                entry["layer"] == "domain_state"
                and mod04.DOMAIN_CONCRETE_TYPE_RE.search(raw)
            ):
                raise GateError(
                    f"domain concrete dependency forbidden: {name} uses concrete UI/socket/Kad/Win32 type"
                )
            for include in mod51._literal_includes(path, raw):
                include = mod04._normal_include(include)
                include_name = PurePosixPath(include).name
                if mod04._include_escapes_repo(include, path):
                    raise GateError(
                        f"repo-local include escapes repository: {name} includes {include}"
                    )
                if include_name.casefold() in coordinator_headers:
                    raise GateError(
                        f"reverse coordinator include: {name} includes {include}"
                    )
                if (
                    entry["layer"] == "domain_state"
                    and mod04._include_is_domain_concrete(include)
                ):
                    raise GateError(
                        f"domain concrete dependency forbidden: {name} includes {include}"
                    )
                if (
                    entry["layer"] == "domain_state"
                    and is_public_header
                    and mod04._include_is_pch(include)
                ):
                    raise GateError(
                        f"domain public header precompiled include forbidden: {name} includes {include}"
                    )
                target = mod04._resolve_include(include, path, repo_paths)
                if target is None:
                    continue
                target_module = file_owner.get(target)
                if target_module and target_module != name:
                    module_dependencies.add(target_module)
                    direct_targets.add(f"module:{target_module}")
                elif target_module != name:
                    direct_targets.add(f"repo:{target}")
        if len(direct_targets) > 8:
            raise GateError(
                f"direct dependency count exceeds 8: {name} current={len(direct_targets)}"
            )
        if module_dependencies != set(entry["declared_direct_dependencies"]):
            raise GateError(f"declared direct dependency drift: {name}")


def validate_active_include_contract(matrix: dict[str, Any], ledger: dict[str, Any], overrides: dict[str, bytes] | None = None) -> dict[str, Any]:
    """Bind active sources to their declared includes and the combined SCC graph."""
    config, contract = _combined_catalogue(matrix, ledger)
    entries = mod04._entry_map(config, contract)
    _validate_active_include_semantics(
        config, contract, matrix, ledger, overrides
    )
    # Apply all MOD-0.4 reverse-coordinator, UI/concrete-header, dependency
    # count, declared-edge, layer and cycle rules to the combined v1+M2A set.
    mod04.validate_modules(config, contract, entries, overrides)
    graph = mod51.build_graph(config, contract, overrides)
    if graph["sccs"]:
        raise GateError("active M2A source creates a combined include SCC")
    active = {item["name"]: item for item in matrix["additional_modules"] if ledger["cards"][item["card"]]["state"] == "active"}
    actual: dict[str, set[str]] = {name: set() for name in active}
    for source, target in graph["edges"]:
        if source in actual:
            actual[source].add(target)
    for name, module in active.items():
        if actual[name] != set(module["dependencies"]):
            raise GateError(f"active M2A include dependencies differ from declared catalogue: {name}")
    return graph


def validate_coordinator_module_isolation(
    matrix: dict[str, Any],
    ledger: dict[str, Any],
    overrides: dict[str, bytes] | None = None,
) -> None:
    """Forbid coordinator fields/pointers/references to active M2A types."""
    active_names = sorted(
        item["name"]
        for item in matrix["additional_modules"]
        if ledger["cards"][item["card"]]["state"] == "active"
    )
    if not active_names:
        return
    token = re.compile(
        r"\b(?:" + "|".join(re.escape(name) for name in active_names) + r")\b"
    )
    split_tokens: list[re.Pattern[str]] = []
    for name in active_names:
        atoms = re.findall(
            r"[A-Z]+(?=[A-Z][a-z]|\d|\b)|[A-Z]?[a-z]+|\d+", name
        )
        for boundary in range(1, len(atoms)):
            left = "".join(atoms[:boundary])
            right = "".join(atoms[boundary:])
            split_tokens.append(
                re.compile(
                    rf"\b{re.escape(left)}\b[\s\S]{{0,80}}"
                    rf"\b{re.escape(right)}\b"
                )
            )
    active_headers = {
        f"{name}.h".casefold() for name in active_names
    }
    config, contract = _combined_catalogue(matrix, ledger)
    entries = mod04._entry_map(config, contract)
    file_owner = mod04._module_file_owner(entries)
    repo_paths = mod04._repo_code_paths(overrides, file_owner)
    active_paths = {
        path
        for name, entry in entries.items()
        if name in active_names
        for path in entry["implementation_files"] + entry["interface_files"]
    }
    frontier = collections.deque(
        path for _, _, cpp, header in COORDINATORS for path in (cpp, header)
    )
    visited: set[str] = set()
    translated_by_path: dict[str, str] = {}
    baseline_translated_by_path: dict[str, str] = {}
    token_paste_macros: set[str] = set()
    def baseline_translation(path: str) -> str:
        if path in baseline_translated_by_path:
            return baseline_translated_by_path[path]
        try:
            baseline_raw = _git_blob(BASELINE_COMMIT, path).decode(
                "utf-8", errors="replace"
            )
            baseline_normalized = mod51._normalize_translation_input(
                baseline_raw
            )
            value = mod51._mask_comments_and_literals(
                path, mod51._splice_phase_two(baseline_normalized)
            )
        except GateError:
            value = ""
        baseline_translated_by_path[path] = value
        return value
    while frontier:
        path = frontier.popleft()
        if path in visited:
            continue
        visited.add(path)
        raw = _raw(path, overrides).decode("utf-8", errors="replace")
        normalized = mod51._normalize_translation_input(raw)
        translated = mod51._mask_comments_and_literals(
            path, mod51._splice_phase_two(normalized)
        )
        translated_by_path[path] = translated
        if "##" in translated:
            baseline_translated = baseline_translation(path)
            current_paste = collections.Counter(
                line.strip() for line in translated.splitlines()
                if "##" in line
            )
            baseline_paste = collections.Counter(
                line.strip() for line in baseline_translated.splitlines()
                if "##" in line
            )
            if any(
                count > baseline_paste[line]
                for line, count in current_paste.items()
            ):
                raise GateError(
                    f"M2A coordinator include closure contains new token-paste: {path}"
                )
            token_paste_macros.update(
                re.findall(
                    r"(?m)^\s*#\s*define\s+([A-Za-z_]\w*)"
                    r"\s*(?:\([^)]*\))?[^\r\n]*##",
                    translated,
                )
            )
        if token.search(translated) or any(
            pattern.search(translated) for pattern in split_tokens
        ):
            raise GateError(
                f"M2A coordinator include closure references an additional module: {path}"
            )
        for include in mod51._literal_includes(path, raw):
            target = mod04._resolve_include(include, path, repo_paths)
            if target is None:
                continue
            if target in active_paths:
                raise GateError(
                    f"M2A coordinator transitively reaches an additional module: {path} -> {target}"
                )
            if target not in visited:
                frontier.append(target)
    for macro in token_paste_macros:
        invocation = re.compile(rf"\b{re.escape(macro)}\s*\(")
        for path, translated in translated_by_path.items():
            if len(invocation.findall(translated)) > len(
                invocation.findall(baseline_translation(path))
            ):
                raise GateError(
                    f"M2A coordinator include closure adds token-paste use: {path}"
                )
    for _, _, cpp, header in COORDINATORS:
        for path in (cpp, header):
            raw = _raw(path, overrides).decode("utf-8", errors="replace")
            for include in mod51._literal_includes(path, raw):
                if PurePosixPath(include).name.casefold() in active_headers:
                    raise GateError(
                        f"M2A coordinator includes an additional module: {path}"
                    )
            normalized = mod51._normalize_translation_input(raw)
            mod51._preflight_raw_content_splices(path, normalized)
            translated = mod51._mask_comments_and_literals(
                path, mod51._splice_phase_two(normalized)
            )
            if token.search(translated):
                raise GateError(
                    f"M2A coordinator directly references an additional module: {path}"
                )


def _class_body(raw: str, owner: str) -> str:
    normalized = mod51._normalize_translation_input(raw)
    translated = mod51._mask_comments_and_literals(
        owner, mod51._splice_phase_two(normalized)
    )
    declaration = re.search(
        rf"\b(?:class|struct)\s+{re.escape(owner)}\b[^;{{]*\{{",
        translated,
    )
    if declaration is None:
        raise GateError(f"M2A governed coordinator class unavailable: {owner}")
    start = declaration.end() - 1
    depth = 0
    end = None
    for index in range(start, len(translated)):
        if translated[index] == "{":
            depth += 1
        elif translated[index] == "}":
            depth -= 1
            if depth == 0:
                end = index
                break
    if end is None:
        raise GateError(f"M2A governed coordinator class is unbalanced: {owner}")
    return translated[start + 1:end]


def _depth_one_declarations(raw: str, owner: str) -> collections.Counter[str]:
    body = re.sub(r"(?m)^\s*#.*$", "", _class_body(raw, owner))
    declarations: list[str] = []
    start = index = 0
    while index < len(body):
        current = body[index]
        if current == "{":
            depth = 1
            cursor = index + 1
            while cursor < len(body) and depth:
                if body[cursor] == "{":
                    depth += 1
                elif body[cursor] == "}":
                    depth -= 1
                cursor += 1
            if depth:
                raise GateError(
                    f"M2A governed coordinator declaration is unbalanced: {owner}"
                )
            while cursor < len(body) and body[cursor].isspace():
                cursor += 1
            if cursor < len(body) and body[cursor] == ";":
                cursor += 1
            declarations.append(body[start:cursor])
            start = index = cursor
            continue
        if current == ";":
            declarations.append(body[start:index + 1])
            start = index + 1
        index += 1
    tokens_re = re.compile(
        r"[A-Za-z_]\w*|::|->|&&|<=|>=|==|!=|"
        r"[{}()\[\];,:*&#<>=+\-/]"
    )
    result: collections.Counter[str] = collections.Counter()
    access = "private"
    for declaration in declarations:
        tokens = tokens_re.findall(declaration)
        while len(tokens) >= 2 and tokens[0] in {
            "public", "protected", "private",
        } and tokens[1] == ":":
            access = tokens[0]
            tokens = tokens[2:]
        if tokens:
            result[f"{access}|" + " ".join(tokens)] += 1
    return result


def _class_data_identifiers(raw: str, owner: str) -> set[str]:
    """Return private per-instance identifiers physically owned at depth one."""
    default_access = (
        "public"
        if re.search(rf"\bstruct\s+{re.escape(owner)}\b", raw)
        else "private"
    )
    try:
        body = re.sub(r"(?m)^\s*#.*$", "", _class_body(raw, owner))
    except GateError:
        return set()
    segments: list[str] = []
    start = index = 0
    while index < len(body):
        if body[index] == "{":
            depth = 1
            cursor = index + 1
            while cursor < len(body) and depth:
                if body[cursor] == "{":
                    depth += 1
                elif body[cursor] == "}":
                    depth -= 1
                cursor += 1
            while cursor < len(body) and body[cursor].isspace():
                cursor += 1
            if cursor < len(body) and body[cursor] == ";":
                cursor += 1
            segments.append(body[start:cursor])
            start = index = cursor
            continue
        if body[index] == ";":
            segments.append(body[start:index + 1])
            start = index + 1
        index += 1
    result: set[str] = set()
    access = default_access
    for segment in segments:
        cleaned = segment
        while True:
            access_match = re.match(
                r"^\s*(public|protected|private)\s*:\s*", cleaned
            )
            if access_match is None:
                break
            access = access_match.group(1)
            cleaned = cleaned[access_match.end():]
        cleaned = cleaned.strip()
        if not cleaned or re.match(
            r"^(?:using|typedef|friend|static_assert|class|struct|enum)\b",
            cleaned,
        ):
            continue
        words = set(re.findall(r"\b[A-Za-z_]\w*\b", cleaned))
        if access != "private" or words & {
            "static", "constexpr", "const", "consteval", "constinit",
        }:
            continue
        first_paren = cleaned.find("(")
        first_equal = cleaned.find("=")
        function_pointer = re.search(r"\(\s*[*&]", cleaned) is not None
        if (
            first_paren >= 0
            and not function_pointer
            and not (0 <= first_equal < first_paren)
        ):
            continue
        result.update(words)
    return result


def _binding_marker(module: dict[str, Any]) -> str:
    suffix = hashlib.sha256(
        module["name"].encode("utf-8")
    ).hexdigest()[:10].upper()
    return f"M2A_BIND_{module['card']}_{suffix}"


def _binding_member(module: dict[str, Any]) -> str:
    suffix = hashlib.sha256(
        module["name"].encode("utf-8")
    ).hexdigest()[:10]
    return f"m_m2a_binding_{suffix}"


def _translated(path: str, blob: bytes) -> str:
    raw = blob.decode("utf-8", errors="replace")
    normalized = mod51._normalize_translation_input(raw)
    mod51._preflight_raw_content_splices(path, normalized)
    return mod51._mask_comments_and_literals(
        path, mod51._splice_phase_two(normalized)
    )


def _matching_brace(raw: str, opening: int) -> int | None:
    depth = 0
    for index in range(opening, len(raw)):
        if raw[index] == "{":
            depth += 1
        elif raw[index] == "}":
            depth -= 1
            if depth == 0:
                return index
    return None


def _parent_binding_classes(module: dict[str, Any]) -> tuple[str, ...]:
    parent = module["parent"]
    if parent in {
        item["name"] for item in load(MATRIX)["additional_modules"]
    }:
        return (parent,)
    if parent == "m_kadBridge":
        return (
            ("CLiveKadBridge",)
            if module["name"] == "LiveReachabilityService"
            else ("LiveTunnelKadBridge",)
        )
    classes = PARENT_BINDING_CLASSES.get(parent)
    if classes is None:
        raise GateError(
            f"M2A physical parent class is undefined: {module['name']}/{parent}"
        )
    return classes


def _parent_binding_headers(
    module: dict[str, Any],
    entries: dict[str, dict[str, Any]],
) -> list[str]:
    parent = module["parent"]
    if parent in entries:
        return entries[parent]["interface_files"]
    if parent == "m_kadBridge":
        return [
            "srchybrid/LiveKadBridge.h"
            if module["name"] == "LiveReachabilityService"
            else "srchybrid/LiveTunnelKadBridge.h"
        ]
    if parent == "CWebServer":
        return ["srchybrid/WebServer.h"]
    headers = PARENT_BINDING_HEADERS.get(parent)
    if headers is None:
        raise GateError(
            f"M2A physical parent header is undefined: {module['name']}/{parent}"
        )
    return list(headers)


def _preexisting_parent_route(
    current: str,
    previous: str,
    classes: tuple[str, ...],
    call_start: int,
) -> bool:
    """Require an unconditional first statement in a pre-existing member."""

    for owner in classes:
        signature = re.compile(
            rf"\b{re.escape(owner)}::([A-Za-z_]\w*)\s*"
            r"\([^;{}]*\)\s*(?:const\s*)?(?:noexcept\s*)?"
            r"(?:->\s*[^{}]+)?\{"
        )
        for match in signature.finditer(current):
            opening = current.find("{", match.start(), match.end())
            closing = _matching_brace(current, opening)
            prefix = current[opening + 1:call_start]
            prior_bindings = re.compile(
                r"(?:\s*m_m2a_binding_[0-9a-f]+\s*=\s*"
                r"M2A_BIND_[A-Z0-9_]+\s*\(\s*"
                r"M2AParentPort\s*\{\s*this\s*\}\s*\)\s*;\s*)+"
            )
            if (
                closing is None
                or not (opening < call_start < closing)
                or (
                    prefix.strip()
                    and prior_bindings.fullmatch(prefix) is None
                )
            ):
                continue
            old_signature = re.compile(
                rf"\b{re.escape(owner)}::{re.escape(match.group(1))}\s*\("
            )
            if old_signature.search(previous) and (
                not prefix.strip()
                or all(
                    statement.strip() in previous
                    for statement in prefix.split(";")
                    if statement.strip()
                )
            ):
                return True
    return False


def _preexisting_local_handle_route(
    current: str,
    previous: str,
    classes: tuple[str, ...],
    marker: str,
    call_start: int,
) -> bool:
    """Allow only consecutive, fail-closed local bindings at member entry."""

    prior_pair = re.compile(
        r"\s*M2AModuleHandle\s+([A-Za-z_]\w*)\s*=\s*"
        r"M2A_BIND_[A-Z0-9]+_[0-9A-F]{10}\s*\(\s*"
        r"M2AParentPort\s*\{\s*this\s*\}\s*\)\s*;\s*"
        r"if\s*\(\s*!\s*\1\s*\)\s*return\s*;"
    )
    target = re.compile(
        r"\s*M2AModuleHandle\s+([A-Za-z_]\w*)\s*=\s*"
        rf"{re.escape(marker)}\s*\(\s*M2AParentPort\s*"
        r"\{\s*this\s*\}\s*\)\s*;\s*"
        r"if\s*\(\s*!\s*\1\s*\)\s*return"
        r"(?:\s+(?:false|0|CString\s*\(\s*\)))?\s*;"
    )
    for owner in classes:
        signature = re.compile(
            rf"\b{re.escape(owner)}::([A-Za-z_]\w*)\s*"
            r"\([^;{}]*\)\s*(?:const\s*)?(?:noexcept\s*)?"
            r"(?:->\s*[^{}]+)?\{"
        )
        for match in signature.finditer(current):
            opening = current.find("{", match.start(), match.end())
            closing = _matching_brace(current, opening)
            if closing is None or not (opening < call_start < closing):
                continue
            if re.search(
                rf"\b{re.escape(owner)}::{re.escape(match.group(1))}\s*\(",
                previous,
            ) is None:
                continue
            cursor = opening + 1
            while current[cursor:call_start].strip():
                prior = prior_pair.match(current, cursor, call_start)
                if prior is None:
                    break
                cursor = prior.end()
            if current[cursor:call_start].strip():
                continue
            routed = target.match(current, call_start, closing)
            if routed is not None and routed.end() <= closing:
                return True
    return False


def _preexisting_web_static_thread_route(
    current: str, previous: str, current_header: str, previous_header: str,
    marker: str, method: str,
) -> bool:
    """Accept only CWebServer's assigned, pre-existing static ThreadData seam."""
    definition = re.compile(
        rf"\bCString\s+CWebServer::{re.escape(method)}\s*"
        r"\(\s*const\s+ThreadData\s*&\s*Data\s*\)\s*\{"
    )
    current_matches = list(definition.finditer(current))
    if len(current_matches) != 1 or len(list(definition.finditer(previous))) != 1:
        return False
    declaration = (
        f"private|static CString {method} ( const ThreadData & Data ) ;"
    )
    if (
        _depth_one_declarations(current_header, "CWebServer")[declaration] != 1
        or _depth_one_declarations(previous_header, "CWebServer")[declaration] != 1
    ):
        return False
    opening = current.find(
        "{", current_matches[0].start(), current_matches[0].end()
    )
    closing = _matching_brace(current, opening)
    if closing is None:
        return False
    binding = re.compile(
        rf"\bM2AModuleHandle\s+[A-Za-z_]\w*\s*=\s*"
        rf"{re.escape(marker)}\s*\(\s*M2AParentPort\s*"
        r"\{\s*Data\s*\.\s*pThis\s*\}\s*\)\s*;"
    )
    calls = list(binding.finditer(current, opening + 1, closing))
    return (
        len(calls) == 1
        and not current[opening + 1:calls[0].start()].strip()
    )


def _same_card_parent_constructor_route(
    current: str, owner: str, call_start: int
) -> bool:
    """Allow a new parent module to bind its same-card child in its constructor."""

    signature = re.compile(
        rf"\b{re.escape(owner)}::{re.escape(owner)}\s*"
        r"\([^;{}]*\)\s*(?:noexcept\s*)?(?::[^{}]*)?\{"
    )
    for match in signature.finditer(current):
        opening = current.find("{", match.start(), match.end())
        closing = _matching_brace(current, opening)
        if (
            closing is not None
            and opening < call_start < closing
            and not current[opening + 1:call_start].strip()
        ):
            return True
    return False


def _new_default_parent_constructor_route(
    current: str, previous: str, owner: str, marker: str,
    member: str, call_start: int,
) -> bool:
    """Allow only a new, pure binding constructor for an implicit-default parent."""

    if re.search(rf"\b{re.escape(owner)}::{re.escape(owner)}\s*\(", previous):
        return False
    signature = re.compile(
        rf"\b{re.escape(owner)}::{re.escape(owner)}\s*\(\s*\)\s*:\s*"
        rf"{re.escape(member)}\s*\(\s*M2AAssignmentPolicy\s*::\s*"
        r"RetainExisting\s*\)\s*\{"
    )
    assignment = (
        rf"{re.escape(member)}\s*=\s*{re.escape(marker)}\s*\(\s*"
        r"M2AParentPort\s*\{\s*this\s*\}\s*\)\s*;"
    )
    match = signature.search(current)
    if match is None:
        return False
    opening = current.find("{", match.start(), match.end())
    closing = _matching_brace(current, opening)
    return (
        closing is not None and opening < call_start < closing and
        re.fullmatch(rf"\s*{assignment}\s*", current[opening + 1:closing])
        is not None
    )


def _lt5_state_parent_constructor_route(
    current: str, owner: str, marker: str, member: str
) -> bool:
    """Accept only LT5's complete, synchronous state-view binding."""

    signature = re.compile(
        rf"\b{re.escape(owner)}::{re.escape(owner)}\s*"
        r"\([^;{}]*\)\s*(?:noexcept\s*)?(?::[^{}]*)?\{"
    )
    state = (
        r"LT5StreamStateBinding\s+state\s*\{\s*"
        r"&m_k6ExitStreams\s*,\s*&m_k6OriginStreams\s*,\s*"
        r"&m_k6SendCredits\s*,\s*&m_k6ReceiveCredits\s*,\s*"
        r"&m_k6FlowStreamsByCircuit\s*,\s*&m_nextGeneration\s*\}\s*;"
    )
    assignment = (
        rf"{re.escape(member)}\s*=\s*{re.escape(marker)}\s*\(\s*"
        r"M2AParentPort\s*\{\s*&state\s*\}\s*\)\s*;"
    )
    for match in signature.finditer(current):
        opening = current.find("{", match.start(), match.end())
        closing = _matching_brace(current, opening)
        if closing is not None and re.fullmatch(
            rf"\s*{state}\s*{assignment}\s*",
            current[opening + 1:closing],
        ):
            return True
    return False


def _parent_binding_paths(
    module: dict[str, Any],
    entries: dict[str, dict[str, Any]],
) -> list[str]:
    parent = module["parent"]
    if parent in entries:
        return entries[parent]["implementation_files"]
    if parent == "m_kadBridge":
        return [
            "srchybrid/LiveKadBridge.cpp"
            if module["name"] == "LiveReachabilityService"
            else "srchybrid/LiveTunnelKadBridge.cpp"
        ]
    paths = PARENT_BINDING_PATHS.get(parent)
    if paths is None:
        raise GateError(
            f"M2A physical parent binding path is undefined: {module['name']}/{parent}"
        )
    return list(paths)


def validate_coordinator_header_monotonicity(
    overrides: dict[str, bytes] | None = None,
) -> None:
    """Coordinator class declarations may only disappear, never be added."""
    for _, owner, _, header in COORDINATORS:
        baseline = _depth_one_declarations(
            _baseline_coordinator_text(header), owner
        )
        current = _depth_one_declarations(
            _raw(header, overrides).decode("utf-8", errors="replace"), owner
        )
        for declaration, count in current.items():
            if count > baseline[declaration]:
                raise GateError(
                    f"M2A coordinator header gained or changed a declaration: {header}"
                )


def _coordinator_snapshot(
    overrides: dict[str, bytes] | None = None,
) -> dict[str, dict[str, Any]]:
    snapshot: dict[str, dict[str, Any]] = {}
    for name, owner, cpp, header in COORDINATORS:
        cpp_lines = _lines(cpp, overrides)
        header_lines = _lines(header, overrides)
        functions = (
            mod01.functions(cpp_lines, owner, cpp)
            + mod01.inline_functions(header_lines, owner, header)
            + _free_helpers(cpp_lines, cpp, 0)
            + _free_helpers(header_lines, header, 0)
            + _structural_body_growth(cpp_lines, cpp)
            + _structural_body_growth(header_lines, header)
        )
        by_name: dict[str, list[int]] = {}
        for function in functions:
            stable_name = re.sub(r"@\d+$", "", function["name"])
            by_name.setdefault(stable_name, []).append(
                function["length_approx"]
            )
        for lengths in by_name.values():
            lengths.sort()
        snapshot[name] = {
            "files": {
                cpp: mod04.loc_physical(_raw(cpp, overrides)),
                header: mod04.loc_physical(_raw(header, overrides)),
            },
            "declarations": _depth_one_declarations(
                _raw(header, overrides).decode("utf-8", errors="replace"),
                owner,
            ),
            "functions": by_name,
            "long_bodies": {
                f"{path}:{key}": lengths
                for path, lines in ((cpp, cpp_lines), (header, header_lines))
                for key, lengths in _structural_long_bodies(
                    "\n".join(lines)
                ).items()
            },
        }
    return snapshot


def _length_multiset_fits(
    current: list[int], prior: list[int]
) -> bool:
    prior_index = 0
    for length in current:
        while (
            prior_index < len(prior)
            and prior[prior_index] < length
        ):
            prior_index += 1
        if prior_index == len(prior):
            return False
        prior_index += 1
    return True


def validate_active_card_outcomes(
    matrix: dict[str, Any],
    ledger: dict[str, Any],
    overrides: dict[str, bytes] | None = None,
) -> None:
    """Turn the owner/field/function matrix into per-card exit constraints."""
    config, contract = _combined_catalogue(matrix, ledger)
    entries = mod04._entry_map(config, contract)
    module_entries = {
        item["name"]: entries[item["name"]]
        for item in matrix["additional_modules"] + matrix["existing_modules"]
        if item["name"] in entries
    }
    owner_classes = {
        "LiveTunnel": "CLiveTunnel",
        "LiveStreamManager": "CLiveStreamManager",
    }
    active_cards = {
        card for card, state in ledger["cards"].items()
        if state["state"] == "active"
    }
    for module in matrix["additional_modules"]:
        if module["card"] not in active_cards:
            continue
        marker = _binding_marker(module)
        member = _binding_member(module)
        entry = module_entries[module["name"]]
        parent_paths = _parent_binding_paths(module, entries)
        parent_headers = _parent_binding_headers(module, entries)
        parent_classes = _parent_binding_classes(module)
        same_card_parent = next(
            (
                parent
                for parent in matrix["additional_modules"]
                if parent["name"] == module["parent"]
                and parent["card"] == module["card"]
            ),
            None,
        )
        activation_parent = _activation_parent(
            ledger["cards"][module["card"]]["activation_commit"]
        )
        web_static_methods = [
            item["name"].split("::", 1)[1]
            for item in matrix["function_matrix"]
            if item["owner"] == module["name"]
            and item["name"].startswith("CWebServer::")
        ]
        for label, reader in (
            (
                "A",
                lambda path, commit=ledger["cards"][module["card"]][
                    "activation_commit"
                ]: _git_blob(commit, path),
            ),
            ("HEAD", lambda path: _raw(path, overrides)),
        ):
            module_implementation = "\n".join(
                _translated(path, reader(path))
                for path in entry["implementation_files"]
            )
            module_interface = "\n".join(
                _translated(path, reader(path))
                for path in entry["interface_files"]
            )
            definition = re.search(
                rf"\bM2AModuleHandle\s+{re.escape(marker)}\s*"
                r"\(\s*const\s+M2AParentPort\s*&\s*parent\s*\)\s*\{",
                module_implementation,
            )
            definition_open = (
                module_implementation.find(
                    "{", definition.start(), definition.end()
                )
                if definition is not None else -1
            )
            definition_close = (
                _matching_brace(module_implementation, definition_open)
                if definition_open >= 0 else None
            )
            body = (
                module_implementation[
                    definition_open + 1:definition_close
                ]
                if definition_close is not None else ""
            )
            construction = re.search(
                rf"\bMakeM2AModuleHandle\s*\(\s*new\s+"
                rf"{re.escape(module['name'])}\s*\(\s*parent\s*\)\s*\)",
                body,
            )
            constructor = re.search(
                rf"\bexplicit\s+{re.escape(module['name'])}\s*"
                r"\(\s*const\s+M2AParentPort\s*&",
                module_interface,
            )
            module_includes_port = all(
                PurePosixPath(BINDING_PORT_HEADER).name
                in mod51._literal_includes(
                    path, reader(path).decode("utf-8", errors="replace")
                )
                for path in entry["interface_files"]
            )
            route_found = False
            declaration_found = False
            for path in parent_paths:
                raw = reader(path)
                translated = _translated(path, raw)
                declaration_found = declaration_found or re.search(
                    rf"\bM2AModuleHandle\s+{re.escape(marker)}\s*"
                    r"\(\s*const\s+M2AParentPort\s*&\s*\)\s*;",
                    translated,
                ) is not None
                assignment = (
                    re.compile(
                        rf"\b{re.escape(member)}\s*=\s*"
                        rf"{re.escape(marker)}\s*\(\s*"
                        r"M2AParentPort\s*\{\s*this\s*\}\s*\)"
                    )
                    if module["parent"] != "CWebServer"
                    else re.compile(
                        rf"\bM2AModuleHandle\s+[A-Za-z_]\w*\s*=\s*"
                        rf"{re.escape(marker)}\s*\(\s*"
                        r"M2AParentPort\s*\{\s*this\s*\}\s*\)"
                    )
                )
                previous = (
                    ""
                    if same_card_parent is not None
                    else _translated(
                        path, _git_blob(activation_parent, path)
                    )
                )
                for call in assignment.finditer(translated):
                    preexisting_route = (
                        _preexisting_local_handle_route(
                            translated, previous, parent_classes, marker,
                            call.start(),
                        )
                        if module["parent"] == "CWebServer"
                        else _preexisting_parent_route(
                            translated, previous, parent_classes, call.start()
                        )
                    )
                    if preexisting_route or (
                        same_card_parent is not None
                        and _same_card_parent_constructor_route(
                            translated, same_card_parent["name"], call.start()
                        )
                    ) or (
                        same_card_parent is None
                        and any(_new_default_parent_constructor_route(
                            translated, previous, owner, marker, member,
                            call.start(),
                        ) for owner in parent_classes)
                    ):
                        route_found = True
                if (
                    module["parent"] == "CWebServer"
                    and len(web_static_methods) == 1
                    and _preexisting_web_static_thread_route(
                        translated, previous,
                        "\n".join(
                            reader(header).decode("utf-8", errors="replace")
                            for header in parent_headers
                        ),
                        "\n".join(
                            _git_blob(activation_parent, header).decode(
                                "utf-8", errors="replace"
                            )
                            for header in parent_headers
                        ),
                        marker, web_static_methods[0],
                    )
                ):
                    route_found = True
                if (
                    same_card_parent is not None
                    and module["name"] == "Kad6StreamTransportAdapter"
                    and _lt5_state_parent_constructor_route(
                        translated,
                        same_card_parent["name"],
                        marker,
                        member,
                    )
                ):
                    route_found = True
            parent_header_code = "\n".join(
                _translated(path, reader(path))
                for path in parent_headers
            )
            owns_handle = (
                module["parent"] == "CWebServer"
                or re.search(
                    rf"\bM2AModuleHandle\s+{re.escape(member)}\s*;",
                    parent_header_code,
                ) is not None
            )
            parent_includes_port = any(
                PurePosixPath(BINDING_PORT_HEADER).name
                in mod51._literal_includes(
                    path, reader(path).decode("utf-8", errors="replace")
                )
                for path in parent_paths + parent_headers
            )
            if (
                definition is None
                or definition_close is None
                or construction is None
                or constructor is None
                or not module_includes_port
                or not declaration_found
                or not route_found
                or not owns_handle
                or not parent_includes_port
            ):
                raise GateError(
                    f"M2A active module lacks physical parent binding at {label}: {module['name']}"
                )
    for module in matrix["existing_modules"]:
        if module["card"] not in active_cards:
            continue
        coordinator = matrix["card_budgets"][module["card"]][
            "coordinator"
        ]
        owner = next(
            item[1] for item in COORDINATORS if item[0] == coordinator
        )
        header = COORDINATOR_FILES[coordinator][1]
        for label, raw in (
            (
                "A",
                _git_blob(
                    ledger["cards"][module["card"]]["activation_commit"],
                    header,
                ),
            ),
            ("HEAD", _raw(header, overrides)),
        ):
            identifiers = _class_data_identifiers(
                raw.decode("utf-8", errors="replace"), owner
            )
            if (
                module["parent"] not in identifiers
                or module["name"] not in identifiers
            ):
                raise GateError(
                    f"M2A existing module physical parent binding drift at {label}: {module['name']}"
                )
    for card in sorted(active_cards):
        activation_commit = ledger["cards"][card]["activation_commit"]
        for coordinator, section in matrix["field_matrix"].items():
            transfers = [
                transfer for transfer in section["transfers"]
                if transfer["card"] == card
            ]
            if not transfers:
                continue
            header = COORDINATOR_FILES[coordinator][1]
            for label, raw in (
                ("A", _git_blob(activation_commit, header)),
                ("HEAD", _raw(header, overrides)),
            ):
                remaining = {
                    item["name"]
                    for item in mod01.fields(
                        raw.decode(
                            "utf-8", errors="replace"
                        ).splitlines(),
                        owner_classes[coordinator],
                        header,
                    )
                }
                moved = {
                    field
                    for transfer in transfers
                    for field in transfer["fields"]
                }
                if remaining & moved:
                    raise GateError(
                        f"M2A active card retains transferred fields in coordinator at {label}: {card}"
                    )
            moved = {
                field
                for transfer in transfers
                for field in transfer["fields"]
            }
            for label, reader in (
                (
                    "A",
                    lambda path, commit=activation_commit: _git_blob(
                        commit, path
                    ),
                ),
                ("HEAD", lambda path: _raw(path, overrides)),
            ):
                for path in COORDINATOR_FILES[coordinator]:
                    raw = reader(path).decode("utf-8", errors="replace")
                    translated = mod51._mask_comments_and_literals(
                        path,
                        mod51._splice_phase_two(
                            mod51._normalize_translation_input(raw)
                        ),
                    )
                    if any(
                        re.search(
                            rf"\b{re.escape(field)}\b", translated
                        )
                        for field in moved
                    ):
                        raise GateError(
                            f"M2A active card retains transferred field token in coordinator at {label}: {card}/{path}"
                        )
            for transfer in transfers:
                entry = module_entries[transfer["owner"]]
                for label, reader in (
                    (
                        "A",
                        lambda path, commit=activation_commit: _git_blob(
                            commit, path
                        ),
                    ),
                    ("HEAD", lambda path: _raw(path, overrides)),
                ):
                    governed_fields: set[str] = set()
                    for path in (
                        entry["implementation_files"]
                        + entry["interface_files"]
                    ):
                        governed_fields.update(
                            _class_data_identifiers(
                                reader(path).decode(
                                    "utf-8", errors="replace"
                                ),
                                transfer["owner"],
                            )
                        )
                    for field in transfer["fields"]:
                        if field not in governed_fields:
                            raise GateError(
                                f"M2A active card owner lacks transferred field at {label}: {card}/{field}"
                            )
    current_snapshot = _coordinator_snapshot(overrides)
    for item in matrix["function_matrix"]:
        terminal_card = item["card"].split("-")[-1]
        if terminal_card not in active_cards:
            continue
        coordinator = matrix["card_budgets"][terminal_card]["coordinator"]
        activation_commit = ledger["cards"][terminal_card][
            "activation_commit"
        ]
        activation_overrides = {
            path: _git_blob(activation_commit, path)
            for path in COORDINATOR_FILES[coordinator]
        }
        at_activation = _coordinator_snapshot(
            activation_overrides
        )[coordinator]["functions"].get(item["name"], [])
        at_head = current_snapshot[coordinator]["functions"].get(
            item["name"], []
        )
        if any(length > 150 for length in at_activation + at_head):
            raise GateError(
                f"M2A active card did not close its assigned oversized function: {terminal_card}/{item['name']}"
            )


def validate_active_head_ratchet(
    ledger: dict[str, Any],
    overrides: dict[str, bytes] | None = None,
) -> None:
    """Make the newest active A the irreversible coordinator floor for HEAD."""
    commits = [
        state["activation_commit"]
        for state in ledger["cards"].values()
        if state["state"] == "active"
    ]
    if not commits:
        return
    if len(commits) != len(set(commits)):
        raise GateError("M2A cards cannot share one implementation commit A")
    latest = [
        candidate
        for candidate in commits
        if all(
            other == candidate or _is_ancestor(other, candidate)
            for other in commits
        )
    ]
    if len(latest) != 1:
        raise GateError("M2A activation commits must form one ordered Git chain")
    current = _coordinator_snapshot(overrides)
    for commit in commits:
        activation_overrides = {
            path: _git_blob(commit, path)
            for _, _, cpp, header in COORDINATORS
            for path in (cpp, header)
        }
        activation = _coordinator_snapshot(activation_overrides)
        for name, prior in activation.items():
            now = current[name]
            for path, prior_loc in prior["files"].items():
                if now["files"][path] > prior_loc:
                    raise GateError(
                        f"M2A active coordinator LOC regressed after A: {path}"
                    )
            for declaration, count in now["declarations"].items():
                if count > prior["declarations"][declaration]:
                    raise GateError(
                        f"M2A active coordinator declaration regressed after A: {name}"
                    )
            for collection in ("functions", "long_bodies"):
                for function, lengths in now[collection].items():
                    if not _length_multiset_fits(
                        lengths, prior[collection].get(function, [])
                    ):
                        raise GateError(
                            f"M2A active coordinator body/function regressed after A: {function}"
                        )


def metrics(overrides: dict[str, bytes] | None = None, force_v1_graph: bool = False) -> dict[str, Any]:
    result: dict[str, Any] = {"coordinators": {}}
    for name, owner, cpp, header in COORDINATORS:
        cpp_lines, header_lines = _lines(cpp, overrides), _lines(header, overrides)
        functions = (
            mod01.functions(cpp_lines, owner, cpp)
            + mod01.inline_functions(header_lines, owner, header)
            + _free_helpers(cpp_lines, cpp)
            + _free_helpers(header_lines, header)
            + _structural_body_growth(cpp_lines, cpp)
            + _structural_body_growth(header_lines, header)
        )
        fields = mod01.fields(_lines(header, overrides), owner, header)
        result["coordinators"][name] = {
            "files": {cpp: mod04.loc_physical(_raw(cpp, overrides)), header: mod04.loc_physical(_raw(header, overrides))},
            "fields": sorted(item["name"] for item in fields),
            "oversized_functions": sorted([[item["name"], item["length_approx"]] for item in functions if item["length_approx"] > 150]),
        }
    config, contract = (load(MOD04), load(MOD03)) if force_v1_graph else _combined_catalogue(load(MATRIX), load(ACTIVATION))
    graph = mod51.build_graph(config, contract, overrides)
    result["sccs"] = graph["sccs"]
    result["include_graph_sha256"] = mod51.canonical_sha256(graph)
    return result


def validate_binding_port_contract() -> None:
    """Freeze the 00.4 portable ABI and executable unlock characterization."""
    header_path = ROOT / BINDING_PORT_HEADER
    source_path = ROOT / "srchybrid/M2ABindingPort.cpp"
    project_path = ROOT / "srchybrid/emule.vcxproj"
    scheduler_path = ROOT / "srchybrid/LiveTunnelScheduler.cpp"
    if not all(
        path.is_file()
        for path in (
            header_path, source_path, project_path, scheduler_path,
        )
    ):
        raise GateError("M2A binding port source/project is unavailable")
    header = header_path.read_text(encoding="utf-8")
    source = source_path.read_text(encoding="utf-8")
    project = project_path.read_text(encoding="utf-8")
    scheduler = scheduler_path.read_text(encoding="utf-8")
    required_header = (
        "struct M2AParentPort final",
        "void* const context",
        "class M2AModuleHandle final",
        "M2AModuleHandle(const M2AModuleHandle&) = delete",
        "M2AModuleHandle& operator=(const M2AModuleHandle&) = delete",
        "M2AModuleHandle(M2AModuleHandle&& other) noexcept",
        "void Reset() noexcept",
        "M2AModuleHandle MakeM2AModuleHandle(Module* instance) noexcept",
    )
    if not all(marker in header for marker in required_header):
        raise GateError("M2A immutable binding-port ABI drift")
    if mod04.DOMAIN_CONCRETE_TYPE_RE.search(header):
        raise GateError("M2A binding port gained a concrete dependency")
    forbidden_headers = {
        *mod04.PCH_HEADERS,
        *(name.casefold() for name in mod04.COORDINATOR_HEADERS),
    }
    if any(
        PurePosixPath(include).name.casefold() in forbidden_headers
        for include in mod51._literal_includes(BINDING_PORT_HEADER, header)
    ):
        raise GateError("M2A binding port gained PCH/reverse include")
    callback_start = source.find("bool CharacterizeCallbackAfterUnlock()")
    lock = source.find("std::lock_guard<std::mutex>", callback_start)
    unlock_scope = source.find(
        "    }\n    return callback(snapshot)", lock
    )
    callback = source.find("return callback(snapshot)", lock)
    if (
        callback_start < 0
        or lock < 0
        or unlock_scope < 0
        or callback < unlock_scope
        or "if (!mutex.try_lock())" not in source[callback_start:callback]
    ):
        raise GateError("M2A no-callback-under-lock characterization drift")
    if (
        '<ClCompile Include="M2ABindingPort.cpp">' not in project
        or '<ClInclude Include="M2ABindingPort.h" />' not in project
        or '#include "M2ABindingPort.h"' not in scheduler
        or "&& RunM2ABindingPortCharacterizationSelfTest()"
        not in scheduler
    ):
        raise GateError("M2A binding-port characterization is not compiled")


def validate_inputs(contract: dict[str, Any], matrix: dict[str, Any], baseline: dict[str, Any], ledger: dict[str, Any] | None = None) -> None:
    ledger = load(ACTIVATION) if ledger is None else ledger
    # W12 v2 is an overlay, not a retroactive v1 module activation.  Preserve
    # the exact historical v1 interpretation when its state-specific H/R row
    # is present; the v2 verifier below validates that expanded row in full.
    w12_state = ledger.get("cards", {}).get("W12") if isinstance(ledger, dict) else None
    if (
        W12_MATRIX.is_file()
        and isinstance(w12_state, dict)
        and set(w12_state) == {
            "state", "stage", "activation_commit", "evidence", "r_evidence",
        }
        and w12_state.get("state") == "active"
        and w12_state.get("stage") in {"H", "R"}
    ):
        ledger = copy.deepcopy(ledger)
        ledger["cards"]["W12"] = {
            "state": "planned", "activation_commit": None, "evidence": [],
        }
    closed = {
        CONTRACT: {"schema","baseline_commit","scope","inputs","ratchet","module_policy","status"},
        MATRIX: {"schema","scope","field_matrix","function_matrix","additional_module_paths","dependency_policy","parent_edges","card_prerequisites","card_budgets","non_module_cards","existing_modules","additional_modules"},
        BASELINE: {"schema","baseline_commit","metrics","status"},
        MOD03V2: {"schema","supersedes","status","scope","rules","approval"},
        MOD04V2: {
            "schema", "supersedes", "status", "scope", "policy",
            "catalogue_source", "approved_non_module_code", "approval",
        },
    }
    for path, keys in closed.items():
        document = {CONTRACT: contract, MATRIX: matrix, BASELINE: baseline}.get(path) or load(path)
        if set(document) != keys:
            raise GateError(f"closed schema drift: {path.name}")
        expected = EXPECTED_DOC_HASHES.get(path.name)
        if expected and hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise GateError(f"hash-pinned M2A input drift: {path.name}")
    if contract.get("schema") != "ese.mod52.migration-contract/v1" or contract.get("baseline_commit") != BASELINE_COMMIT:
        raise GateError("M2A contract identity/baseline drift")
    if contract.get("status") != "PASS" or contract.get("module_policy", {}).get("hard_physical_loc_max") != 1500:
        raise GateError("M2A contract policy drift")
    if matrix.get("schema") != "ese.mod52.migration-matrix/v1": raise GateError("M2A matrix schema drift")
    ownership_v2, catalogue_v2 = load(MOD03V2), load(MOD04V2)
    if ownership_v2.get("schema") != "ese.mod03.ownership-layering-contract/v2" or ownership_v2.get("rules", {}).get("new_coordinator_fields") != "forbidden; additional services are physically owned by the existing parent named in the M2A matrix" or ownership_v2.get("rules", {}).get("parent_injection") != "a matrix parent is aggregation/injected construction, not an implicit direct include; actual direct includes are only the matrix dependencies array":
        raise GateError("MOD-0.3 v2 overlay drift")
    if catalogue_v2.get("schema") != "ese.mod04.architecture-gate-catalog/v2" or catalogue_v2.get("catalogue_source") != "docs/architecture/mod52_migration_matrix_v1.json":
        raise GateError("MOD-0.4 v2 catalogue overlay drift")
    if catalogue_v2.get("approved_non_module_code") != [
        {
            "path": BINDING_PORT_HEADER,
            "reason": (
                "Move-only type-erased composition handle and opaque parent "
                "port shared by M2A parents and children without a reverse "
                "include or a coordinator field."
            ),
            "adr": (
                "docs/architecture/"
                "MOD52_ADDITIONAL_EXTRACTION_PLAN_2026-07-30.md"
            ),
        },
        {
            "path": "srchybrid/M2ABindingPort.cpp",
            "reason": (
                "Portable characterization of move-only M2A ownership and "
                "snapshot-unlock-callback ordering, compiled into the existing "
                "headless self-test path."
            ),
            "adr": (
                "docs/architecture/"
                "MOD52_ADDITIONAL_EXTRACTION_PLAN_2026-07-30.md"
            ),
        },
        {
            "path": "srchybrid/LiveTunnelGatewayStorePort.h",
            "reason": (
                "Closed, storage-neutral LT3 command vocabulary shared by the "
                "domain-state owner and the Kad6 adapter without introducing "
                "a reverse dependency."
            ),
            "adr": (
                "docs/architecture/"
                "MOD52_ADDITIONAL_EXTRACTION_PLAN_2026-07-30.md"
            ),
        },
        {
            "path": "srchybrid/LiveTunnelSourcePublisherPort.h",
            "reason": (
                "Value-only LT4 publish runtime and action vocabulary shared "
                "by the source-publisher owner and its parent without a "
                "reverse coordinator dependency."
            ),
            "adr": (
                "docs/architecture/"
                "MOD52_ADDITIONAL_EXTRACTION_PLAN_2026-07-30.md"
            ),
        },
        {
            "path": "srchybrid/LiveTunnelStreamFlowPort.h",
            "reason": (
                "Value-only LT5 stream runtime and credit-ledger vocabulary "
                "shared by the state owner and transport adapter without a "
                "reverse coordinator dependency."
            ),
            "adr": (
                "docs/architecture/"
                "MOD52_ADDITIONAL_EXTRACTION_PLAN_2026-07-30.md"
            ),
        },
        {
            "path": "srchybrid/LiveTunnelOriginPort.h",
            "reason": (
                "Value-only LT6 lookup, activation, route and worker-action "
                "vocabulary shared by the origin owner and Kad6 adapter "
                "without a reverse coordinator dependency."
            ),
            "adr": (
                "docs/architecture/"
                "MOD52_ADDITIONAL_EXTRACTION_PLAN_2026-07-30.md"
            ),
        },
        {
            "path": "srchybrid/LiveTunnelBulkStatePort.h",
            "reason": (
                "Value-only LT7 bulk, proxy and reassembly state vocabulary "
                "shared by the state owner and its parent without a reverse "
                "coordinator dependency."
            ),
            "adr": (
                "docs/architecture/"
                "MOD52_ADDITIONAL_EXTRACTION_PLAN_2026-07-30.md"
            ),
        },
        {
            "path": "srchybrid/LiveTunnelBulkFacade.inl",
            "reason": (
                "LT7 coordinator method bodies retained as a textual facade "
                "partition so physical coordinator reduction does not create "
                "a reverse module dependency or change linkage."
            ),
            "adr": (
                "docs/architecture/"
                "MOD52_ADDITIONAL_EXTRACTION_PLAN_2026-07-30.md"
            ),
        },
        {
            "path": "srchybrid/LiveTunnelSearchPort.h",
            "reason": (
                "Value-only LT8 search-job and reply-aggregate vocabulary "
                "shared by the search owner and relay parent without a "
                "reverse coordinator dependency."
            ),
            "adr": (
                "docs/architecture/"
                "MOD52_ADDITIONAL_EXTRACTION_PLAN_2026-07-30.md"
            ),
        },
        {
            "path": "srchybrid/LiveTunnelSearchFacade.inl",
            "reason": (
                "LT8 coordinator method bodies retained as a textual facade "
                "partition so physical coordinator reduction does not create "
                "a reverse module dependency or change linkage."
            ),
            "adr": (
                "docs/architecture/"
                "MOD52_ADDITIONAL_EXTRACTION_PLAN_2026-07-30.md"
            ),
        },
        {
            "path": "srchybrid/LiveTunnelCoordinatorPort.h",
            "reason": (
                "Value-only LT9 guard and RTT vocabulary shared by the "
                "coordinator-state owner and scheduler without a reverse "
                "dependency."
            ),
            "adr": (
                "docs/architecture/"
                "MOD52_ADDITIONAL_EXTRACTION_PLAN_2026-07-30.md"
            ),
        },
        {
            "path": "srchybrid/LiveTunnelCoordinatorMethods.inl",
            "reason": (
                "LT9 coordinator method bodies retained as a textual facade "
                "partition so physical coordinator reduction does not create "
                "a reverse module dependency or change linkage."
            ),
            "adr": (
                "docs/architecture/"
                "MOD52_ADDITIONAL_EXTRACTION_PLAN_2026-07-30.md"
            ),
        },
    ]:
        raise GateError("MOD-0.4 v2 approved non-module binding drift")
    validate_binding_port_contract()
    fields: list[str] = []
    retained: list[str] = []
    expected_counts = {"LiveTunnel": (76, 11), "LiveStreamManager": (30, 17)}
    for coordinator in ("LiveTunnel", "LiveStreamManager"):
        section = matrix["field_matrix"][coordinator]
        local_retained = section["retained_parent_fields"]
        local_fields: list[str] = []
        retained += local_retained
        for transfer in section["transfers"]:
            if set(transfer) != {"card","owner","parent","lock","wire","test","budget","fields"}:
                raise GateError("M2A field transfer schema incomplete")
            budget = transfer["budget"]
            if (
                set(budget) != {"module_loc", "add", "delete", "net"}
                or not all(
                    isinstance(value, int) and value > 0
                    for value in budget.values()
                )
                or budget["net"] > budget["add"]
            ):
                raise GateError("M2A field budget must be a typed closed object")
            if budget["module_loc"] > 1200 or budget["module_loc"] > 1500 or budget["net"] >= 1500:
                raise GateError("M2A module/card budget exceeds policy")
            fields += transfer["fields"]; local_fields += transfer["fields"]
        transfer_count, retained_count = expected_counts[coordinator]
        baseline_fields = set(baseline["metrics"]["coordinators"][coordinator]["fields"])
        if len(local_fields) != transfer_count or len(set(local_fields)) != transfer_count or len(local_retained) != retained_count or len(set(local_retained)) != retained_count or set(local_fields) & set(local_retained) or set(local_fields + local_retained) != baseline_fields:
            raise GateError(f"M2A {coordinator} transfer/retained matrix does not exactly match baseline")
    if len(fields) != 106 or len(retained) != 28:
        raise GateError("M2A field matrix must be exactly 106 transferred plus 28 retained")
    if baseline.get("baseline_commit") != BASELINE_COMMIT: raise GateError("M2A baseline report commit drift")
    if len(fields) + len(retained) != 134 or baseline["metrics"]["coordinators"]["LiveTunnel"]["field_count"] + baseline["metrics"]["coordinators"]["LiveStreamManager"]["field_count"] != 134:
        raise GateError("M2A field matrix does not exhaust the frozen 134 governed fields")
    function_names: list[str] = []
    for item in matrix["function_matrix"]:
        if set(item) != {"name","card","owner","state","lock","wire","test","budget"}:
            raise GateError("M2A function row schema incomplete")
        budget = item["budget"]
        if (
            set(budget) != {"module_loc", "add", "delete", "net"}
            or not all(
                isinstance(value, int) and value > 0
                for value in budget.values()
            )
            or budget["net"] > budget["add"]
        ):
            raise GateError("M2A function budget must be a typed closed object")
        if budget["module_loc"] > 1200 or budget["net"] >= 1500:
            raise GateError("M2A function budget exceeds policy")
        function_names.append(item["name"])
    oversized = [name for item in baseline["metrics"]["coordinators"].values() for name, _ in item["oversized_functions"]]
    if len(function_names) != 26 or len(set(function_names)) != 26 or sorted(function_names) != sorted(oversized):
        raise GateError("M2A function matrix does not exhaust 26 oversized functions")
    if matrix.get("additional_module_paths") != {"directory":"srchybrid","implementation_template":"{name}.cpp","interface_template":"{name}.h"}:
        raise GateError("M2A additional module paths drift")
    if matrix.get("dependency_policy") != "parent denotes physical aggregation/injected construction, never an implicit #include; only dependencies[] count toward MOD-0.4 direct dependencies and future cards must prove this with an include scan":
        raise GateError("M2A parent/dependency policy drift")
    parent_evidence = matrix.get("parent_edges")
    required_parent_evidence = {"kind", "baseline_parent_fields", "root_owner", "named_parent_rule", "include_rule"}
    if not isinstance(parent_evidence, dict) or set(parent_evidence) != required_parent_evidence or parent_evidence["kind"] != "typed_parent_port_or_aggregation" or parent_evidence["root_owner"] != "CWebServer" or set(parent_evidence["baseline_parent_fields"]) != {"m_scheduler", "m_kadBridge", "m_exitServices", "m_relayDispatcher", "m_broadcastSession", "m_peerSet", "m_chunkBuffer"}:
        raise GateError("M2A typed parent evidence drift")
    if set(ledger) != {"schema", "scope", "cards"} or ledger.get("schema") != "ese.mod52.activation-ledger/v1":
        raise GateError("M2A activation ledger schema drift")
    activation = ledger.get("cards")
    if not isinstance(activation, dict) or not activation:
        raise GateError("M2A card activation catalogue missing")
    if matrix.get("card_prerequisites") != EXPECTED_CARD_PREREQUISITES:
        raise GateError("M2A card prerequisite DAG drift")
    test_requirements = _card_test_requirements(matrix)
    for card, state in activation.items():
        if not isinstance(card, str) or set(state) != {"state", "activation_commit", "evidence"}:
            raise GateError("M2A activation schema incomplete")
        if state["state"] not in {"planned", "active"} or not isinstance(state["evidence"], list):
            raise GateError("M2A activation state invalid")
        if state["state"] == "planned" and (state["activation_commit"] is not None or state["evidence"]):
            raise GateError("planned M2A card has activation evidence")
        if state["state"] == "active" and (not isinstance(state["activation_commit"], str) or not re.fullmatch(r"[0-9a-f]{40}", state["activation_commit"]) or not state["evidence"]):
            raise GateError("active M2A card lacks immutable commit/evidence")
        if state["state"] == "active":
            covered: set[str] = set()
            has_executable_test_evidence = False
            test_source_covers: dict[str, set[str]] = (
                collections.defaultdict(set)
            )
            activation_parent = _activation_parent(
                state["activation_commit"]
            )
            for evidence in state["evidence"]:
                evidence_path = (
                    PurePosixPath(evidence["path"])
                    if isinstance(evidence, dict)
                    and isinstance(evidence.get("path"), str)
                    else None
                )
                evidence_keys = {
                    "kind", "path", "sha256", "commit", "covers",
                }
                if not isinstance(evidence, dict) or set(evidence) != evidence_keys or evidence["commit"] != state["activation_commit"] or evidence_path is None or evidence_path.is_absolute() or ".." in evidence_path.parts or not re.fullmatch(r"[0-9a-f]{64}", evidence["sha256"]) or evidence["kind"] not in {"test_source", "golden", "test_result"} or not isinstance(evidence["covers"], list) or not evidence["covers"] or len(evidence["covers"]) != len(set(evidence["covers"])) or not all(isinstance(item, str) for item in evidence["covers"]):
                    raise GateError("active M2A evidence object invalid")
                if not set(evidence["covers"]).issubset(
                    test_requirements[card]
                ):
                    raise GateError("active M2A evidence coverage ID invalid")
                if evidence["kind"] in {"test_source", "golden"}:
                    path_text = evidence_path.as_posix()
                    if not (
                        path_text.startswith("tests/")
                        or path_text.startswith("srchybrid/tests/")
                    ):
                        raise GateError(
                            "active M2A test evidence must live under a versioned test directory"
                        )
                    if evidence["kind"] == "test_source":
                        if re.fullmatch(
                            r"tests/test_v92_m2a[A-Za-z0-9_]*\.py",
                            path_text,
                        ) is None:
                            raise GateError(
                                "active M2A test_source is not discoverable by the CI M2A pattern"
                            )
                        has_executable_test_evidence = True
                        test_source_covers[path_text].update(
                            evidence["covers"]
                        )
                if not _git_path_changed(
                    activation_parent,
                    state["activation_commit"],
                    evidence["path"],
                ):
                    raise GateError(
                        "active M2A evidence was not changed by implementation commit A"
                    )
                if not _git_path_exists("HEAD", evidence["path"]):
                    raise GateError(
                        "active M2A evidence is absent from HEAD"
                    )
                head_evidence = _git_blob("HEAD", evidence["path"])
                current_evidence = ROOT / evidence["path"]
                if (
                    hashlib.sha256(head_evidence).hexdigest()
                    != evidence["sha256"]
                    or not current_evidence.is_file()
                    or current_evidence.read_bytes() != head_evidence
                ):
                    raise GateError(
                        "active M2A evidence was modified or neutralized after A"
                    )
                if evidence["kind"] == "test_source":
                    _validate_test_source(
                        head_evidence, evidence["covers"]
                    )
                covered.update(evidence["covers"])
            if (
                not has_executable_test_evidence
                or covered != test_requirements[card]
            ):
                raise GateError(
                    f"active M2A card lacks complete typed test evidence: {card}"
                )
            for test_path, covers in sorted(test_source_covers.items()):
                _run_required_tests(test_path, covers)
            validate_activation_provenance(
                state,
                [],
                card=card,
                activation_ledger_path=ACTIVATION.relative_to(ROOT).as_posix(),
                prerequisites=matrix["card_prerequisites"][card],
            )
    modules = matrix.get("additional_modules")
    if not isinstance(modules, list) or not modules: raise GateError("M2A additional module catalogue missing")
    names: set[str] = set()
    name_casefold: set[str] = set()
    dependency_edges = 0
    for module in modules:
        if set(module) != {"name","card","parent","layer","dependencies","budget"}:
            raise GateError("M2A additional module schema incomplete")
        if not isinstance(module["name"], str) or not re.fullmatch(r"[A-Z][A-Za-z0-9]*", module["name"]) or module["name"] in names or module["layer"] not in {"foundation","ports","domain_state","application","adapters","facade"}:
            raise GateError("M2A additional module identity drift")
        if module["name"].casefold() in name_casefold:
            raise GateError("M2A module path case collision")
        names.add(module["name"]); name_casefold.add(module["name"].casefold())
        dependency_edges += len(module["dependencies"])
        budget = module["budget"]
        if (
            set(budget) != {"module_loc", "add", "delete", "net"}
            or not all(
                isinstance(value, int) and value > 0
                for value in budget.values()
            )
            or budget["module_loc"] > 1200
            or budget["net"] >= 1500
            or budget["net"] > budget["add"]
            or len(module["dependencies"]) > 8
        ):
            raise GateError("M2A additional module budget/dependency drift")
        if module["card"] not in activation:
            raise GateError("M2A module references an undeclared activation card")
        if not isinstance(module["dependencies"], list) or len(module["dependencies"]) != len(set(module["dependencies"])) or module["name"] in module["dependencies"]:
            raise GateError("M2A additional module has invalid dependency edge")
        # The planned/active status is per card and is the only authority for
        # source presence; this permits later cards without changing the gate.
        if not isinstance(module["parent"], str) or module["parent"] not in {parent_evidence["root_owner"]} | set(parent_evidence["baseline_parent_fields"]) | names:
            raise GateError("M2A parent must be an explicit typed port/aggregation edge")
        module_paths = [
            (
                Path(matrix["additional_module_paths"]["directory"])
                / f"{module['name']}{suffix}"
            ).as_posix()
            for suffix in (".cpp", ".h")
        ]
        validate_source_activation(
            activation[module["card"]], module_paths
        )
    if dependency_edges < 2 or "WebLiveApiControllers" in names or not {"WebLiveApiStreamController","WebLiveApiStatusController","WebLiveApiTransferController","WebLiveApiSearchController","WebLiveApiSettingsController","WebLiveApiDiagnosticsController","WebLiveApiLegacyController"}.issubset(names):
        raise GateError("M2A additional module catalogue is collapsed or placeholder")
    if len(modules) != 33 or not {module["card"] for module in modules}.issubset(activation):
        raise GateError("M2A catalogue must have the exact 33 modules and matching activation cards")
    if set(activation) != EXPECTED_CARDS:
        raise GateError("M2A activation ledger card set drift")
    card_budgets = matrix.get("card_budgets")
    budget_keys = {
        "add", "delete", "net", "coordinator", "facade_add_max",
        "reduction_required",
    }
    if (
        not isinstance(card_budgets, dict)
        or set(card_budgets) != EXPECTED_CARDS
        or any(
            set(value) != budget_keys
            or not all(isinstance(value[key], int) and value[key] >= 0 for key in ("add", "delete", "net", "facade_add_max"))
            or value["net"] > value["add"]
            or value["coordinator"] not in COORDINATOR_FILES
            or not isinstance(value["reduction_required"], bool)
            for value in card_budgets.values()
        )
    ):
        raise GateError("M2A closed card budget drift")
    non_module_cards = matrix.get("non_module_cards")
    if (
        not isinstance(non_module_cards, list)
        or {
            item.get("card"): (item.get("purpose"), item.get("coordinator"))
            for item in non_module_cards
            if isinstance(item, dict) and set(item) == {"card", "purpose", "coordinator"}
        }
        != EXPECTED_NON_MODULE_CARDS
    ):
        raise GateError("M2A non-module card catalogue drift")
    existing = matrix.get("existing_modules")
    if existing != [{
        "name": "LiveStreamRecovery",
        "card": "LS4",
        "parent": "m_streamRecovery",
        "layer": "application",
        "budget": {"module_loc": 1100},
    }]:
        raise GateError("M2A existing module cross-link drift")
    validate_existing_module_activations(
        existing, ledger, mod04._entry_map(load(MOD04), load(MOD03))
    )
    module_by_name = {item["name"]: item for item in modules} | {item["name"]: item for item in existing}
    for section in matrix["field_matrix"].values():
        for transfer in section["transfers"]:
            owner = module_by_name.get(transfer["owner"])
            if owner is None or owner["card"] != transfer["card"] or owner["parent"] != transfer["parent"]:
                raise GateError("M2A transfer owner/card/parent cross-link drift")
    for item in matrix["function_matrix"]:
        owners = item["owner"].split("..")
        cards = set(item["card"].split("-"))
        if not owners or any(owner not in module_by_name or module_by_name[owner]["card"] not in cards for owner in owners):
            raise GateError("M2A function owner/card cross-link drift")
    known_dependencies = names | set(mod04._entry_map(load(MOD04), load(MOD03)))
    graph: dict[str, list[str]] = {}
    for module in modules:
        if not set(module["dependencies"]).issubset(known_dependencies):
            raise GateError("M2A dependency targets must be catalogued")
        graph[module["name"]] = [item for item in module["dependencies"] if item in names]
        for dependency in graph[module["name"]]:
            target = next(item for item in modules if item["name"] == dependency)
            if (module["layer"], target["layer"]) not in {("application", "ports"), ("application", "domain_state"), ("adapters", "ports"), ("facade", "application")}:
                raise GateError("M2A dependency layer edge is not authorised")
    visiting, visited = set(), set()
    def walk(node: str) -> None:
        if node in visiting: raise GateError("M2A dependency DAG cycle")
        if node not in visited:
            visiting.add(node)
            for child in graph[node]: walk(child)
            visiting.remove(node); visited.add(node)
    for node in graph: walk(node)


def _matrix_field_sets(matrix: dict[str, Any]) -> dict[str, set[str]]:
    return {
        name: set(section["retained_parent_fields"] + [field for transfer in section["transfers"] for field in transfer["fields"]])
        for name, section in matrix["field_matrix"].items()
    }


def validate_ratchet(baseline: dict[str, Any], current: dict[str, Any], matrix: dict[str, Any]) -> None:
    for name, prior in baseline["metrics"]["coordinators"].items():
        now = current["coordinators"][name]
        for path, count in prior["files"].items():
            if now["files"][path] > count: raise GateError(f"ratchet coordinator LOC grew: {path}")
        if name in ("LiveTunnel", "LiveStreamManager"):
            allowed = _matrix_field_sets(matrix)[name]
            if len(now["fields"]) > prior["field_count"] or not set(now["fields"]).issubset(allowed):
                raise GateError(f"ratchet mutable fields grew: {name}")
        elif len(now["fields"]) > prior["field_count"] or not set(now["fields"]).issubset(prior["fields"]):
            raise GateError(f"ratchet mutable fields grew: {name}")
        prior_functions = dict(prior["oversized_functions"])
        for function, length in now["oversized_functions"]:
            if function not in prior_functions or length > prior_functions[function]:
                raise GateError(f"ratchet oversized function grew: {function}")
    if current["sccs"]: raise GateError("ratchet new include SCC")


def _closed_object(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise GateError(f"W12 closed schema drift: {label}")
    return value


def _closed_list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise GateError(f"W12 closed schema drift: {label}")
    return value


def _positive_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and value > 0


def _nonnegative_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _validate_budget(
    value: Any,
    keys: set[str],
    label: str,
    *,
    text_keys: set[str] | None = None,
) -> dict[str, Any]:
    budget = _closed_object(value, keys, label)
    text_keys = set() if text_keys is None else text_keys
    for key, item in budget.items():
        if key in text_keys:
            if not isinstance(item, str) or not item.strip():
                raise GateError(f"W12 budget field is not typed text: {label}/{key}")
        elif not _nonnegative_int(item):
            raise GateError(f"W12 budget field is not a nonnegative integer: {label}/{key}")
    return budget


def _safe_w12_path(path: Any) -> str:
    if not isinstance(path, str) or not path or "\\" in path or "\x00" in path:
        raise GateError("W12 CARD_PATHS contains a malformed path")
    parsed = PurePosixPath(path)
    if (
        parsed.is_absolute()
        or parsed.as_posix() != path
        or any(part in {"", ".", ".."} for part in parsed.parts)
        or parsed.parts[0].casefold() in {".git", ".codex", ".agents"}
        or not (
            path.startswith("srchybrid/")
            or path.startswith("tests/")
            or path.startswith("tools/")
            or path.startswith("docs/")
        )
    ):
        raise GateError(f"W12 CARD_PATHS unsafe path: {path}")
    return path


def _coverage_mentions(values: Any, label: str) -> set[str]:
    result: set[str] = set()
    for text in _closed_list(values, label):
        if not isinstance(text, str) or not text.strip():
            raise GateError(f"W12 acceptance evidence is not typed text: {label}")
        for start, end in re.findall(
            r"W12-COV-(\d{2})(?:\s+through\s+W12-COV-(\d{2}))?",
            text,
        ):
            first = int(start)
            last = int(end) if end else first
            if first > last:
                raise GateError(f"W12 acceptance coverage range reversed: {label}")
            result.update(f"W12-COV-{index:02d}" for index in range(first, last + 1))
    return result


def _validate_w12_historical_inputs() -> None:
    for relative, expected in W12_HISTORICAL_HASHES.items():
        path = ROOT / relative
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise GateError(f"W12 hash-pinned historical input drift: {relative}")
    try:
        base_ledger = json.loads(
            _git_blob(
                W12_BASE_COMMIT,
                ACTIVATION.relative_to(ROOT).as_posix(),
            ).decode("utf-8")
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GateError("W12 base activation ledger is unreadable") from exc
    cards = base_ledger.get("cards", {})
    if (
        cards.get("W11", {}).get("state") != "active"
        or cards.get("W12") != {
            "state": "planned", "activation_commit": None, "evidence": [],
        }
    ):
        raise GateError("W12 base is not the exact active-W11/planned-W12 state")


def _validate_w12_surface_schemas(card: dict[str, Any]) -> None:
    surface_budget_keys = {
        "WebServerFacade", "WebHlsCapabilityController", "LiveHlsReadLease",
        "WebAuthPolicy", "WebRequestDispatch", "WebRouteTable",
        "WebStaticAssets", "WebSocketResponse", "WebSocket",
    }
    budgets = _closed_object(
        card["surface_budgets"], surface_budget_keys, "matrix.card.surface_budgets"
    )
    for name, budget in budgets.items():
        if name == "LiveHlsReadLease":
            keys = {"header_path", "header_loc_max", "cpp_path", "cpp_loc_max"}
        elif name == "WebHlsCapabilityController":
            keys = {"paths", "loc_max", "dependencies"}
        elif name == "WebAuthPolicy":
            keys = {"paths", "loc_max", "hard_loc_max"}
        else:
            keys = {"paths", "loc_max"}
        _closed_object(budget, keys, f"matrix.card.surface_budgets.{name}")
        for key, item in budget.items():
            if key.endswith("_max") and not _nonnegative_int(item):
                raise GateError(f"W12 surface LOC budget is not typed: {name}/{key}")
            if key in {"path", "header_path", "cpp_path"}:
                _safe_w12_path(item)
            if key == "paths":
                paths = _closed_list(item, f"surface paths {name}")
                if (
                    not paths
                    or not all(isinstance(path, str) for path in paths)
                    or len(paths) != len(set(paths))
                ):
                    raise GateError(f"W12 surface path set is empty or duplicated: {name}")
                for path in paths:
                    _safe_w12_path(path)
            if key == "dependencies" and (
                not isinstance(item, list)
                or not item
                or not all(isinstance(value, str) and value for value in item)
                or len(item) != len(set(item))
            ):
                raise GateError(f"W12 surface dependency set invalid: {name}")

    modules = _closed_list(card["additional_modules"], "matrix.card.additional_modules")
    if len(modules) != 2:
        raise GateError("W12 additional module catalogue must contain exactly two modules")
    module_names: list[str] = []
    for module in modules:
        name = module.get("name") if isinstance(module, dict) else None
        keys = {"name", "paths", "role", "loc_max"}
        if name == "WebHlsCapabilityController":
            keys.add("direct_dependencies")
        _closed_object(module, keys, f"matrix.card.additional_modules.{name}")
        if not isinstance(name, str) or not re.fullmatch(r"[A-Z][A-Za-z0-9]*", name):
            raise GateError("W12 additional module identity invalid")
        module_names.append(name)
        if module["paths"] != budgets[name]["paths"] or module["loc_max"] != budgets[name]["loc_max"]:
            raise GateError(f"W12 module/surface budget cross-link drift: {name}")
        expected = budgets[name].get("dependencies", [])
        if module.get("direct_dependencies", []) != expected:
            raise GateError(f"W12 module dependency cross-link drift: {name}")
    if module_names != ["WebServerFacade", "WebHlsCapabilityController"]:
        raise GateError("W12 additional module order/identity drift")

    surfaces = _closed_list(card["surfaces"], "matrix.card.surfaces")
    if not surfaces:
        raise GateError("W12 governed surface catalogue missing")
    seen: set[str] = set()
    for surface in surfaces:
        if not isinstance(surface, dict):
            raise GateError("W12 governed surface row invalid")
        keys = {"path", "role"}
        if "loc_max" in surface:
            keys.add("loc_max")
        if "dependencies" in surface:
            keys.add("dependencies")
        _closed_object(surface, keys, f"matrix.card.surface.{surface.get('path')}")
        path = _safe_w12_path(surface["path"])
        if path in seen:
            raise GateError("W12 governed surface path duplicated")
        seen.add(path)
        if not isinstance(surface["role"], str) or not surface["role"].strip():
            raise GateError(f"W12 governed surface role missing: {path}")
        if "loc_max" in surface and not _nonnegative_int(surface["loc_max"]):
            raise GateError(f"W12 governed surface LOC budget invalid: {path}")
        if "dependencies" in surface and (
            not isinstance(surface["dependencies"], list)
            or not all(isinstance(item, str) and item for item in surface["dependencies"])
            or len(surface["dependencies"]) != len(set(surface["dependencies"]))
        ):
            raise GateError(f"W12 governed surface dependencies invalid: {path}")
    budget_paths: set[str] = set()
    for budget in budgets.values():
        budget_paths.update(budget.get("paths", []))
        budget_paths.update(
            value for key, value in budget.items()
            if key in {"header_path", "cpp_path"}
        )
    if seen != budget_paths:
        raise GateError("W12 surfaces and surface budgets do not cover the same paths")


def validate_w12_overlay_documents(
    matrix: dict[str, Any],
    contract: dict[str, Any],
    ownership: dict[str, Any],
    catalogue: dict[str, Any],
) -> dict[str, Any]:
    """Validate the PRE-A overlay without reinterpreting the v1 programme."""
    _validate_w12_historical_inputs()
    _closed_object(matrix, {
        "schema", "status", "w12_base_commit", "scope", "supersedes",
        "supersedes_for_card", "change_scope", "v1_evidence",
        "programme_budget", "cards",
    }, "matrix v2")
    _closed_object(contract, {
        "schema", "status", "w12_base_commit", "scope", "supersedes",
        "supersedes_for_card", "change_scope", "v1_evidence", "inputs",
        "card_prerequisites", "card_total_budget", "coordinator_limits",
        "ratchet", "additional_modules", "approved_header_only_ports",
        "coverage_requirements", "security_invariants", "acceptance",
    }, "contract v2")
    _closed_object(ownership, {
        "schema", "status", "scope", "supersedes", "supersedes_for_card",
        "change_scope", "historical_evidence", "owners", "layer_rules",
        "callback_rule", "approval",
    }, "MOD-0.3 v3")
    _closed_object(catalogue, {
        "schema", "status", "scope", "supersedes", "supersedes_for_card",
        "change_scope", "historical_evidence", "catalogue_source",
        "card_prerequisites", "additional_modules",
        "approved_header_only_ports", "coordinator_limits",
        "coverage_requirements", "coverage_map", "gates", "stop_conditions",
        "approval",
    }, "MOD-0.4 v3")
    if (
        matrix["schema"] != "ese.mod52.migration-matrix/v2"
        or contract["schema"] != "ese.mod52.migration-contract/v2"
        or ownership["schema"] != "ese.mod03.ownership-layering-contract/v3"
        or catalogue["schema"] != "ese.mod04.architecture-gate-catalog/v3"
        or {matrix["status"], contract["status"], ownership["status"], catalogue["status"]}
        != {"PRE-A"}
        or matrix["w12_base_commit"] != W12_BASE_COMMIT
        or contract["w12_base_commit"] != W12_BASE_COMMIT
        or any(
            item["supersedes_for_card"] != "M2A-W12"
            for item in (matrix, contract, ownership, catalogue)
        )
    ):
        raise GateError("W12 overlay identity/base/status drift")
    if matrix["supersedes"] != ["docs/architecture/mod52_migration_matrix_v1.json"]:
        raise GateError("W12 matrix supersedes scope drift")
    if contract["supersedes"] != ["docs/architecture/mod52_migration_contract_v1.json"]:
        raise GateError("W12 contract supersedes scope drift")
    if ownership["supersedes"] != [
        "docs/architecture/mod03_ownership_layering_contract_v1.json",
        "docs/architecture/mod03_ownership_layering_contract_v2.json",
    ]:
        raise GateError("W12 ownership supersedes scope drift")
    if catalogue["supersedes"] != [
        "docs/architecture/mod04_architecture_gate_baseline_v1.json",
        "docs/architecture/mod04_architecture_gate_catalog_v2.json",
    ]:
        raise GateError("W12 gate catalogue supersedes scope drift")

    matrix_v1 = _closed_object(
        matrix["v1_evidence"], {"path", "sha256", "immutable"},
        "matrix.v1_evidence",
    )
    contract_v1 = _closed_object(
        contract["v1_evidence"], {"path", "sha256", "immutable"},
        "contract.v1_evidence",
    )
    for evidence, path in (
        (matrix_v1, "docs/architecture/mod52_migration_matrix_v1.json"),
        (contract_v1, "docs/architecture/mod52_migration_contract_v1.json"),
    ):
        if evidence != {
            "path": path,
            "sha256": W12_HISTORICAL_HASHES[path],
            "immutable": True,
        }:
            raise GateError(f"W12 declared historical hash drift: {path}")

    ownership_history = _closed_object(
        ownership["historical_evidence"],
        {"v1_path", "v1_sha256", "v2_path"},
        "ownership.historical_evidence",
    )
    if ownership_history != {
        "v1_path": "docs/architecture/mod03_ownership_layering_contract_v1.json",
        "v1_sha256": W12_HISTORICAL_HASHES[
            "docs/architecture/mod03_ownership_layering_contract_v1.json"
        ],
        "v2_path": "docs/architecture/mod03_ownership_layering_contract_v2.json",
    }:
        raise GateError("W12 MOD-0.3 historical evidence drift")
    catalogue_history = _closed_object(
        catalogue["historical_evidence"],
        {"v1_path", "v1_sha256", "v2_path"},
        "catalogue.historical_evidence",
    )
    if catalogue_history != {
        "v1_path": "docs/architecture/mod04_architecture_gate_baseline_v1.json",
        "v1_sha256": W12_HISTORICAL_HASHES[
            "docs/architecture/mod04_architecture_gate_baseline_v1.json"
        ],
        "v2_path": "docs/architecture/mod04_architecture_gate_catalog_v2.json",
    }:
        raise GateError("W12 MOD-0.4 historical evidence drift")

    inputs = _closed_object(
        contract["inputs"], {"matrix", "ownership", "gates", "security_contract"},
        "contract.inputs",
    )
    if inputs != {
        "matrix": W12_MATRIX.relative_to(ROOT).as_posix(),
        "ownership": W12_MOD03.relative_to(ROOT).as_posix(),
        "gates": W12_MOD04.relative_to(ROOT).as_posix(),
        "security_contract": (
            "docs/architecture/MOD52_W12_SECURITY_EXPANSION_PLAN_2026-08-02.md"
        ),
    } or catalogue["catalogue_source"] != inputs["matrix"]:
        raise GateError("W12 overlay input cross-link drift")

    cards = _closed_list(matrix["cards"], "matrix.cards")
    if len(cards) != 1:
        raise GateError("W12 overlay must contain one closed card")
    card = _closed_object(cards[0], {
        "card", "name", "parent", "layer", "depends_on",
        "card_prerequisites", "completion_requires", "card_total_budget",
        "coordinator_budget", "coordinator_limits",
        "live_stream_manager_budget", "surface_budgets", "additional_modules",
        "approved_header_only_ports", "surfaces", "card_paths",
        "coverage_ids", "coverage_requirements", "approval",
    }, "matrix.card.M2A-W12")
    if (
        card["card"] != "M2A-W12"
        or card["parent"] != "CWebServer"
        or card["layer"] != "facade/application"
        or card["completion_requires"] != ["PRE-A", "A", "H", "R"]
        or card["depends_on"] != ["M2A-W11", "WebAuthPolicy", "LiveStreamManager"]
    ):
        raise GateError("W12 card identity/dependency/prerequisite drift")
    if not isinstance(card["card_prerequisites"], list) or not card["card_prerequisites"]:
        raise GateError("W12 card prerequisites missing")

    programme = _closed_object(matrix["programme_budget"], {
        "w12_jp", "w12_hours", "v92_jp", "v92_hours", "m2a_jp", "m2a_hours",
    }, "matrix.programme_budget")
    if not all(_positive_number(value) for value in programme.values()) or any(
        programme[f"{prefix}_hours"] != programme[f"{prefix}_jp"] * 7
        for prefix in ("w12", "v92", "m2a")
    ):
        raise GateError("W12 programme budget typing/conversion drift")

    card_total = _validate_budget(
        card["card_total_budget"], {"add_max", "delete_min", "net_max", "scope"},
        "matrix.card.card_total_budget", text_keys={"scope"},
    )
    contract_total = _validate_budget(
        contract["card_total_budget"], {"add_max", "delete_min", "net_max", "scope"},
        "contract.card_total_budget", text_keys={"scope"},
    )
    if (
        card_total["add_max"] <= 0
        or card_total["delete_min"] <= 0
        or card_total["net_max"] > card_total["add_max"]
        or contract_total["add_max"] <= 0
        or contract_total["delete_min"] <= 0
        or contract_total["net_max"] > contract_total["add_max"]
    ):
        raise GateError("W12 total card budget bounds are nonsensical")
    if {key: card_total[key] for key in ("add_max", "delete_min", "net_max")} != {
        key: contract_total[key] for key in ("add_max", "delete_min", "net_max")
    }:
        raise GateError("W12 total card budget cross-link drift")
    if (
        {key: card_total[key] for key in W12_CARD_BUDGET_PIN}
        != W12_CARD_BUDGET_PIN
        or {key: contract_total[key] for key in W12_CARD_BUDGET_PIN}
        != W12_CARD_BUDGET_PIN
    ):
        raise GateError("W12 literal-pinned total card budget drift")
    coordinator = _closed_object(card["coordinator_budget"], {
        "paths", "add_max", "delete_min", "net_max", "cpp_hard_loc_max",
        "cpp_target_loc_max", "header_hard_loc_max", "new_mutable_fields",
        "actual_w12_delta",
    }, "matrix.card.coordinator_budget")
    for key in (
        "add_max", "delete_min", "net_max", "cpp_hard_loc_max",
        "cpp_target_loc_max", "header_hard_loc_max", "new_mutable_fields",
    ):
        if not _nonnegative_int(coordinator[key]):
            raise GateError(f"W12 coordinator budget is not typed: {key}")
    if (
        coordinator["add_max"] <= 0
        or coordinator["delete_min"] <= 0
        or coordinator["net_max"] > coordinator["add_max"]
        or coordinator["cpp_target_loc_max"] <= 0
        or coordinator["cpp_target_loc_max"] > coordinator["cpp_hard_loc_max"]
        or coordinator["header_hard_loc_max"] <= 0
    ):
        raise GateError("W12 coordinator budget bounds are nonsensical")
    if coordinator["paths"] != ["srchybrid/WebServer.cpp", "srchybrid/WebServer.h"]:
        raise GateError("W12 coordinator budget path scope drift")
    _closed_object(coordinator["actual_w12_delta"], {
        "WebServer.cpp", "WebServer.h", "combined_add", "combined_delete",
        "combined_net",
    }, "matrix.card.coordinator_budget.actual_w12_delta")
    _closed_object(coordinator["actual_w12_delta"]["WebServer.cpp"], {
        "baseline_physical_loc", "current_physical_loc", "add", "delete", "net",
    }, "matrix.card.coordinator_budget.actual_w12_delta.WebServer.cpp")
    _closed_object(coordinator["actual_w12_delta"]["WebServer.h"], {"net"},
                   "matrix.card.coordinator_budget.actual_w12_delta.WebServer.h")

    matrix_limits = _closed_object(
        card["coordinator_limits"], {"CWebServer", "CLiveStreamManager"},
        "matrix.card.coordinator_limits",
    )
    contract_limits = _closed_object(
        contract["coordinator_limits"], {"WebServer", "LiveStreamManager"},
        "contract.coordinator_limits",
    )
    catalogue_limits = _closed_object(
        catalogue["coordinator_limits"], {"WebServer", "LiveStreamManager"},
        "catalogue.coordinator_limits",
    )
    web_limit_keys = {
        "combined_add_max", "combined_delete_min", "combined_net_max",
        "cpp_target_loc_max", "cpp_hard_loc_max", "header_hard_loc_max",
        "new_mutable_fields",
    }
    stream_limit_keys = {"header_hard_loc_max", "cpp_growth_max"}
    _closed_object(matrix_limits["CWebServer"], web_limit_keys | {"actual_w12_delta"},
                   "matrix.card.coordinator_limits.CWebServer")
    _closed_object(matrix_limits["CLiveStreamManager"], stream_limit_keys | {"w12_actual_delta"},
                   "matrix.card.coordinator_limits.CLiveStreamManager")
    _closed_object(contract_limits["WebServer"], web_limit_keys | {"actual_w12_delta"},
                   "contract.coordinator_limits.WebServer")
    _closed_object(contract_limits["LiveStreamManager"], stream_limit_keys | {"actual_w12_delta"},
                   "contract.coordinator_limits.LiveStreamManager")
    _closed_object(catalogue_limits["WebServer"], web_limit_keys,
                   "catalogue.coordinator_limits.WebServer")
    _closed_object(catalogue_limits["LiveStreamManager"], stream_limit_keys,
                   "catalogue.coordinator_limits.LiveStreamManager")
    expected_web_limits = {
        "combined_add_max": coordinator["add_max"],
        "combined_delete_min": coordinator["delete_min"],
        "combined_net_max": coordinator["net_max"],
        "cpp_target_loc_max": coordinator["cpp_target_loc_max"],
        "cpp_hard_loc_max": coordinator["cpp_hard_loc_max"],
        "header_hard_loc_max": coordinator["header_hard_loc_max"],
        "new_mutable_fields": coordinator["new_mutable_fields"],
    }
    for label, limits in (
        ("matrix", matrix_limits["CWebServer"]),
        ("contract", contract_limits["WebServer"]),
        ("catalogue", catalogue_limits["WebServer"]),
    ):
        if {key: limits[key] for key in web_limit_keys} != expected_web_limits:
            raise GateError(f"W12 WebServer coordinator limit cross-link drift: {label}")
    stream_budget = _closed_object(card["live_stream_manager_budget"], {
        "header_hard_loc_max", "cpp_growth_max", "rule",
    }, "matrix.card.live_stream_manager_budget")
    if not isinstance(stream_budget["rule"], str) or not stream_budget["rule"].strip():
        raise GateError("W12 LiveStreamManager budget rationale missing")
    expected_stream_limits = {
        key: stream_budget[key] for key in stream_limit_keys
    }
    for label, limits in (
        ("matrix", matrix_limits["CLiveStreamManager"]),
        ("contract", contract_limits["LiveStreamManager"]),
        ("catalogue", catalogue_limits["LiveStreamManager"]),
    ):
        if {key: limits[key] for key in stream_limit_keys} != expected_stream_limits:
            raise GateError(f"W12 LiveStreamManager limit cross-link drift: {label}")

    _validate_w12_surface_schemas(card)
    ports = card["approved_header_only_ports"]
    for label, value in (
        ("matrix", ports),
        ("contract", contract["approved_header_only_ports"]),
        ("catalogue", catalogue["approved_header_only_ports"]),
    ):
        value = _closed_object(value, {"entries", "policy"}, f"{label}.approved_header_only_ports")
        if value["entries"] != [] or not isinstance(value["policy"], str) or "LiveHlsReadLease" not in value["policy"]:
            raise GateError(f"W12 header-only port policy drift: {label}")

    card_paths = _closed_list(card["card_paths"], "matrix.card.card_paths")
    if (
        not card_paths
        or not all(isinstance(path, str) for path in card_paths)
        or len(card_paths) != len(set(card_paths))
        or len(card_paths) != len({path.casefold() for path in card_paths})
    ):
        raise GateError("W12 CARD_PATHS is empty or contains duplicates")
    safe_paths = [_safe_w12_path(path) for path in card_paths]
    if len(safe_paths) != W12_CARD_PATH_COUNT:
        raise GateError("W12 CARD_PATHS exact count drift")
    if not W12_SCOPE_EXPANSION_PATHS.issubset(safe_paths):
        raise GateError("W12 CARD_PATHS lacks reviewed reach/port scope")
    forbidden_historical = {
        f"tests/test_v92_m2a_w{index}_{suffix}.py"
        for index, suffix in (
            (8, "live_api_stream_status"), (9, "live_api_transfer_search"),
            (10, "live_api_settings_diagnostics"), (11, "live_api_legacy"),
        )
    }
    if forbidden_historical & set(safe_paths):
        raise GateError("W12 CARD_PATHS rewrites historical W8-W11 evidence")
    required_paths = {
        W12_MATRIX.relative_to(ROOT).as_posix(),
        W12_CONTRACT.relative_to(ROOT).as_posix(),
        W12_MOD03.relative_to(ROOT).as_posix(),
        W12_MOD04.relative_to(ROOT).as_posix(),
        "tools/architecture/verify_m2a00_migration_ratchet.py",
        "tests/test_v92_m2a00_migration_ratchet.py",
        "tools/architecture/run_w12_security_runtime.ps1",
        "tools/architecture/verify_w12_security_evidence.py",
        "tools/architecture/collect_w12_browser_cdp.mjs",
        "tests/test_v92_m2a_w12_security_evidence.py",
        "tests/test_v92_m2a_w12_browser_collector.py",
        "docs/architecture/mod23_web_route_inventory_v1.json",
        "srchybrid/DirectReachabilityManager.h",
        "srchybrid/DirectReachabilityManager.cpp",
        "srchybrid/WebLiveApiDiagnosticsController.h",
        "srchybrid/WebLiveApiDiagnosticsController.cpp",
        "srchybrid/eSE/test/live_tv_regression.test.js",
        "srchybrid/Kad6GatewaySocket.cpp",
        "tests/test_v92_k03_port_roles.py",
        "tools/architecture/verify_mod04_architecture_gate.py",
        "tests/test_v92_mod04_architecture_gate.py",
    }
    if not required_paths.issubset(safe_paths):
        raise GateError("W12 CARD_PATHS lacks governance or R evidence runners")
    governed_surface_paths = {
        surface["path"] for surface in card["surfaces"]
    }
    if not governed_surface_paths.issubset(safe_paths):
        raise GateError("W12 CARD_PATHS does not cover every governed surface")

    coverage_ids = card["coverage_ids"]
    requirements = card["coverage_requirements"]
    if coverage_ids != list(W12_COVERAGE_IDS) or requirements != list(W12_TYPED_COVERAGE):
        raise GateError("W12 card coverage catalogue drift")
    for label, value in (
        ("contract", contract["coverage_requirements"]),
        ("catalogue", catalogue["coverage_requirements"]),
    ):
        if value != requirements:
            raise GateError(f"W12 typed coverage cross-link drift: {label}")
    module_names = [item["name"] for item in card["additional_modules"]]
    if contract["additional_modules"] != module_names or catalogue["additional_modules"] != module_names:
        raise GateError("W12 additional module cross-link drift")

    coverage_map = _closed_object(
        catalogue["coverage_map"], set(W12_TYPED_COVERAGE),
        "catalogue.coverage_map",
    )
    mapped_ids: set[str] = set()
    for requirement, identifiers in coverage_map.items():
        if (
            not isinstance(identifiers, list)
            or not identifiers
            or not all(isinstance(identifier, str) for identifier in identifiers)
            or len(identifiers) != len(set(identifiers))
            or not set(identifiers).issubset(W12_COVERAGE_IDS)
        ):
            raise GateError(f"W12 coverage map row invalid: {requirement}")
        mapped_ids.update(identifiers)
    if mapped_ids != set(W12_COVERAGE_IDS):
        raise GateError("W12 coverage map does not cover all eleven gates")
    if coverage_map["card:W12"] != list(W12_COVERAGE_IDS):
        raise GateError("W12 card coverage is incomplete")
    if coverage_map["contract:W12-HLS-SECURITY"] != list(W12_COVERAGE_IDS[:7]):
        raise GateError("W12 HLS security contract coverage is incomplete")

    gates = _closed_list(catalogue["gates"], "catalogue.gates")
    if len(gates) != len(W12_COVERAGE_IDS):
        raise GateError("W12 gate catalogue must contain exactly eleven gates")
    stage_by_id: dict[str, str] = {}
    for gate in gates:
        gate = _closed_object(gate, {"id", "stage", "assertion", "evidence"},
                              f"catalogue.gate.{gate.get('id') if isinstance(gate, dict) else '?'}")
        if (
            not isinstance(gate["id"], str)
            or not isinstance(gate["stage"], str)
            or gate["id"] in stage_by_id
            or gate["id"] not in W12_COVERAGE_IDS
            or gate["stage"] not in {"PRE-A", "A/H", "R"}
            or not isinstance(gate["assertion"], str)
            or not gate["assertion"].strip()
            or not isinstance(gate["evidence"], str)
            or not gate["evidence"].strip()
        ):
            raise GateError("W12 gate row invalid")
        stage_by_id[gate["id"]] = gate["stage"]
    expected_stages = {
        **{identifier: "PRE-A" for identifier in W12_COVERAGE_IDS[:5]},
        W12_COVERAGE_IDS[5]: "A/H",
        W12_COVERAGE_IDS[6]: "R",
        **{identifier: "PRE-A" for identifier in W12_COVERAGE_IDS[7:]},
    }
    if stage_by_id != expected_stages:
        raise GateError("W12 coverage stage assignment drift")

    acceptance = _closed_object(
        contract["acceptance"], {"pre_a", "a", "h", "r", "complete"},
        "contract.acceptance",
    )
    expected_acceptance = {
        "pre_a": set(W12_COVERAGE_IDS[:5]) | set(W12_COVERAGE_IDS[7:]),
        "a": {W12_COVERAGE_IDS[5]},
        "h": {W12_COVERAGE_IDS[5]},
        "r": {W12_COVERAGE_IDS[6]},
        "complete": set(W12_COVERAGE_IDS),
    }
    for stage, expected in expected_acceptance.items():
        if _coverage_mentions(acceptance[stage], f"contract.acceptance.{stage}") != expected:
            raise GateError(f"W12 acceptance coverage drift: {stage}")

    owners = _closed_list(ownership["owners"], "ownership.owners")
    owner_names: list[str] = []
    for owner in owners:
        owner = _closed_object(owner, {"surface", "owns", "must_not_own"},
                               f"ownership.owner.{owner.get('surface') if isinstance(owner, dict) else '?'}")
        if (
            not isinstance(owner["surface"], str)
            or owner["surface"] in owner_names
            or not isinstance(owner["owns"], list)
            or not owner["owns"]
            or not isinstance(owner["must_not_own"], list)
            or not owner["must_not_own"]
        ):
            raise GateError("W12 ownership row invalid")
        owner_names.append(owner["surface"])
    expected_owners = {
        "CWebServer", "WebAuthPolicy", "WebHlsCapabilityController",
        "LiveHlsReadLease", "LiveStreamManager", "WebSocketResponse",
        "WebStaticAssets",
    }
    if set(owner_names) != expected_owners:
        raise GateError("W12 ownership surface catalogue drift")
    layer_rules = _closed_object(ownership["layer_rules"], {
        "WebHlsCapabilityController", "LiveHlsReadLease", "WebSocketResponse",
        "forbidden_reverse_dependencies",
    }, "ownership.layer_rules")
    lease_rule = _closed_object(layer_rules["LiveHlsReadLease"], {
        "header_direct_dependencies", "cpp_direct_dependencies", "callback",
    }, "ownership.layer_rules.LiveHlsReadLease")
    if (
        layer_rules["WebHlsCapabilityController"] != ["WebAuthPolicy"]
        or layer_rules["WebSocketResponse"] != []
        or lease_rule["header_direct_dependencies"] != 0
        or lease_rule["cpp_direct_dependencies"] != ["LiveStreamManager"]
        or not isinstance(lease_rule["callback"], str)
        or not layer_rules["forbidden_reverse_dependencies"]
    ):
        raise GateError("W12 ownership layer/dependency rule drift")
    return card


def _git_text(*arguments: str, repo_root: Path = ROOT) -> str:
    try:
        return subprocess.check_output(
            ["git", *arguments], cwd=repo_root, text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except (OSError, subprocess.CalledProcessError) as exc:
        raise GateError(f"W12 Git query failed: {' '.join(arguments)}") from exc


def _git_z_paths(*arguments: str, repo_root: Path = ROOT) -> set[str]:
    if not arguments:
        raise GateError("W12 empty Git path query")
    try:
        raw = subprocess.check_output(
            ["git", arguments[0], "-z", *arguments[1:]], cwd=repo_root,
            stderr=subprocess.DEVNULL,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise GateError(f"W12 Git path query failed: {' '.join(arguments)}") from exc
    try:
        return {
            item.decode("utf-8") for item in raw.split(b"\0") if item
        }
    except UnicodeDecodeError as exc:
        raise GateError("W12 Git path is not UTF-8") from exc


def _w12_worktree_path_sets(repo_root: Path = ROOT) -> tuple[set[str], set[str]]:
    tracked = _git_z_paths(
        "diff", "--name-only", "--no-renames", "--ignore-submodules=none",
        W12_BASE_COMMIT, "--", repo_root=repo_root,
    )
    untracked = _git_z_paths(
        "ls-files", "--others", "--exclude-standard", repo_root=repo_root,
    )
    staged = _git_z_paths(
        "diff", "--cached", "--name-only", "--no-renames",
        "--ignore-submodules=none", "--", repo_root=repo_root,
    )
    return tracked | untracked, staged


def validate_w12_card_path_scope(
    card_paths: list[str],
    changed_paths: set[str],
    staged_paths: set[str] | None = None,
    *,
    require_exact: bool = True,
) -> None:
    declared = set(card_paths)
    staged_paths = set() if staged_paths is None else staged_paths
    unlisted_staged = staged_paths - declared
    if unlisted_staged:
        raise GateError(
            "W12 staged path is outside CARD_PATHS: "
            + ", ".join(sorted(unlisted_staged))
        )
    unlisted = changed_paths - declared
    if unlisted:
        raise GateError(
            "W12 changed path is outside CARD_PATHS: "
            + ", ".join(sorted(unlisted))
        )
    missing = declared - changed_paths
    if require_exact and missing:
        raise GateError(
            "W12 declared CARD_PATHS not present in the A cut: "
            + ", ".join(sorted(missing))
        )


def _w12_commit_changed_paths(
    base: str, target: str, repo_root: Path = ROOT
) -> set[str]:
    return _git_z_paths(
        "diff", "--name-only", "--no-renames", "--ignore-submodules=none",
        base, target, "--", repo_root=repo_root,
    )


def _w12_numstat(
    base: str,
    target: str | None,
    paths: list[str],
    repo_root: Path = ROOT,
) -> dict[str, tuple[int, int]]:
    command = [
        "git", "diff", "--numstat", "--no-renames", "--ignore-submodules=none",
        base,
    ]
    if target is not None:
        command.append(target)
    command.extend(["--", *paths])
    try:
        output = subprocess.check_output(
            command, cwd=repo_root, text=True, stderr=subprocess.DEVNULL,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise GateError("W12 numstat query failed") from exc
    result: dict[str, tuple[int, int]] = {}
    for line in output.splitlines():
        columns = line.split("\t")
        if len(columns) != 3 or columns[0] == "-" or columns[1] == "-":
            raise GateError("W12 binary or malformed CARD_PATHS numstat")
        path = columns[2]
        if path in result:
            raise GateError(f"W12 duplicate numstat path: {path}")
        try:
            result[path] = (int(columns[0]), int(columns[1]))
        except ValueError as exc:
            raise GateError("W12 non-numeric CARD_PATHS numstat") from exc
    if target is None:
        untracked = _git_z_paths(
            "ls-files", "--others", "--exclude-standard", "--", *paths,
            repo_root=repo_root,
        )
        for path in untracked:
            raw = (repo_root / path).read_bytes()
            if b"\0" in raw:
                raise GateError(f"W12 binary untracked CARD_PATHS entry: {path}")
            result[path] = (len(raw.splitlines()), 0)
    return result


def _w12_blob_or_none(commit: str, path: str) -> bytes | None:
    try:
        return subprocess.check_output(
            ["git", "show", f"{commit}:{path}"], cwd=ROOT,
            stderr=subprocess.DEVNULL,
        )
    except subprocess.CalledProcessError:
        return None
    except OSError as exc:
        raise GateError("W12 Git blob query unavailable") from exc


def _w12_current_or_none(path: str) -> bytes | None:
    candidate = ROOT / path
    return candidate.read_bytes() if candidate.is_file() else None


def _w12_physical_loc(raw: bytes | None) -> int:
    return 0 if raw is None else mod04.loc_physical(raw)


def _w12_declared_classes(raw: bytes | None) -> set[str]:
    if raw is None:
        return set()
    return set(re.findall(
        r"\b(?:class|struct)\s+([A-Za-z_]\w*)",
        raw.decode("utf-8", errors="replace"),
    ))


def _w12_function_inventory(
    raw: bytes | None,
    path: str,
    extra_classes: set[str] | None = None,
) -> dict[str, int]:
    if raw is None or PurePosixPath(path).suffix.casefold() not in {".h", ".hpp", ".cpp", ".cc", ".cxx", ".inl"}:
        return {}
    lines = raw.decode("utf-8", errors="replace").splitlines()
    text = "\n".join(lines)
    suffix = PurePosixPath(path).suffix.casefold()
    classes = _w12_declared_classes(raw)
    if suffix in {".cpp", ".cc", ".cxx"}:
        candidates = classes | (set() if extra_classes is None else extra_classes)
        classes = {
            owner for owner in candidates
            if re.search(rf"\b{re.escape(owner)}\s*::", text)
        }
    elif extra_classes:
        classes.update(extra_classes)
    functions: list[dict[str, Any]] = _free_helpers(lines, path, 150)
    for owner in classes:
        try:
            functions.extend(mod01.functions(lines, owner, path))
        except (IndexError, ValueError):
            pass
        if suffix in {".h", ".hpp", ".inl"}:
            try:
                functions.extend(mod01.inline_functions(lines, owner, path))
            except (IndexError, ValueError):
                pass
    result: dict[str, int] = {}
    for function in functions:
        length = function["length_approx"]
        if length <= 150:
            continue
        name = re.sub(r"@\d+$", "", function["name"])
        result[name] = max(result.get(name, 0), length)
    return result


def validate_w12_field_monotonicity(
    baseline_raw: bytes,
    current_raw: bytes,
    owner: str,
    path: str,
    allowed_new_fields: int = 0,
) -> None:
    baseline = {
        item["name"] for item in mod01.fields(
            baseline_raw.decode("utf-8", errors="replace").splitlines(),
            owner, path,
        )
    }
    current = {
        item["name"] for item in mod01.fields(
            current_raw.decode("utf-8", errors="replace").splitlines(),
            owner, path,
        )
    }
    added = current - baseline
    if len(added) > allowed_new_fields:
        raise GateError(f"W12 {owner} mutable fields grew: " + ", ".join(sorted(added)))


def _w12_literal_module_dependencies(
    paths: list[str],
    reader: Any = _w12_current_or_none,
) -> set[str]:
    dependencies: set[str] = set()
    own_stems = {PurePosixPath(path).stem for path in paths}
    ignored = {"stdafx", "M2ABindingPort"}
    for path in paths:
        raw = reader(path)
        if raw is None:
            continue
        for include in mod51._literal_includes(
            path, raw.decode("utf-8", errors="replace")
        ):
            stem = PurePosixPath(include).stem
            if stem not in own_stems and stem not in ignored:
                local = reader(f"srchybrid/{stem}.h")
                local_cpp = reader(f"srchybrid/{stem}.cpp")
                if local is not None or local_cpp is not None:
                    dependencies.add(stem)
    return dependencies


def _w12_tarjan(graph: dict[str, set[str]]) -> list[tuple[str, ...]]:
    index = 0
    indices: dict[str, int] = {}
    low: dict[str, int] = {}
    stack: list[str] = []
    on_stack: set[str] = set()
    result: list[tuple[str, ...]] = []

    def visit(node: str) -> None:
        nonlocal index
        indices[node] = low[node] = index
        index += 1
        stack.append(node)
        on_stack.add(node)
        for child in sorted(graph.get(node, set())):
            if child not in graph:
                continue
            if child not in indices:
                visit(child)
                low[node] = min(low[node], low[child])
            elif child in on_stack:
                low[node] = min(low[node], indices[child])
        if low[node] == indices[node]:
            component: list[str] = []
            while True:
                child = stack.pop()
                on_stack.remove(child)
                component.append(child)
                if child == node:
                    break
            if len(component) > 1 or node in graph.get(node, set()):
                result.append(tuple(sorted(component)))

    for node in sorted(graph):
        if node not in indices:
            visit(node)
    return sorted(result)


def validate_w12_dependencies_and_scc(card: dict[str, Any], ownership: dict[str, Any]) -> None:
    modules = {item["name"]: item for item in card["additional_modules"]}
    rules = ownership["layer_rules"]
    expected = {
        "WebServerFacade": set(),
        "WebHlsCapabilityController": set(rules["WebHlsCapabilityController"]),
        "LiveHlsReadLease.h": set(),
        "LiveHlsReadLease.cpp": set(
            rules["LiveHlsReadLease"]["cpp_direct_dependencies"]
        ),
        "WebSocketResponse": set(rules["WebSocketResponse"]),
    }
    observed = {
        "WebServerFacade": _w12_literal_module_dependencies(
            modules["WebServerFacade"]["paths"]
        ),
        "WebHlsCapabilityController": _w12_literal_module_dependencies(
            modules["WebHlsCapabilityController"]["paths"]
        ),
        "LiveHlsReadLease.h": _w12_literal_module_dependencies(
            ["srchybrid/LiveHlsReadLease.h"]
        ),
        "LiveHlsReadLease.cpp": _w12_literal_module_dependencies(
            ["srchybrid/LiveHlsReadLease.cpp"]
        ),
        "WebSocketResponse": _w12_literal_module_dependencies(
            ["srchybrid/WebSocketResponse.h", "srchybrid/WebSocketResponse.cpp"]
        ),
    }
    for name in expected:
        if observed[name] != expected[name]:
            raise GateError(
                f"W12 declared direct dependency drift: {name}; "
                f"expected={sorted(expected[name])}, observed={sorted(observed[name])}"
            )
    reverse_targets = {
        "WebServerFacade", "WebHlsCapabilityController", "LiveHlsReadLease",
    }
    for name in reverse_targets:
        paths = (
            modules[name]["paths"] if name in modules
            else ["srchybrid/LiveHlsReadLease.h", "srchybrid/LiveHlsReadLease.cpp"]
        )
        if "WebServer" in _w12_literal_module_dependencies(paths):
            raise GateError(f"W12 reverse coordinator include: {name} -> WebServer")
    for source, paths, forbidden in (
        (
            "WebAuthPolicy",
            card["surface_budgets"]["WebAuthPolicy"]["paths"],
            "WebServer",
        ),
        (
            "LiveStreamManager",
            ["srchybrid/LiveStreamManager.h", "srchybrid/LiveStreamManager.cpp"],
            "WebServer",
        ),
        (
            "WebSocketResponse",
            card["surface_budgets"]["WebSocketResponse"]["paths"],
            "WebAuthPolicy",
        ),
    ):
        if forbidden in _w12_literal_module_dependencies(paths):
            raise GateError(
                f"W12 forbidden reverse dependency: {source} -> {forbidden}"
            )

    # Build the relevant real include graph twice. LiveHlsReadLease is an
    # approved physical partition, so its h/cpp paths and include name fold
    # into LiveStreamManager rather than manufacturing a two-node SCC.
    node_paths = {
        "WebServer": ["srchybrid/WebServer.h", "srchybrid/WebServer.cpp"],
        "WebServerFacade": modules["WebServerFacade"]["paths"],
        "WebHlsCapabilityController": modules["WebHlsCapabilityController"]["paths"],
        "WebAuthPolicy": card["surface_budgets"]["WebAuthPolicy"]["paths"],
        "LiveStreamManager": [
            "srchybrid/LiveStreamManager.h", "srchybrid/LiveStreamManager.cpp",
            "srchybrid/LiveHlsReadLease.h", "srchybrid/LiveHlsReadLease.cpp",
        ],
        "WebSocketResponse": card["surface_budgets"]["WebSocketResponse"]["paths"],
        "WebStaticAssets": card["surface_budgets"]["WebStaticAssets"]["paths"],
        "WebSocket": card["surface_budgets"]["WebSocket"]["paths"],
        "WebRequestDispatch": card["surface_budgets"]["WebRequestDispatch"]["paths"],
        "WebRouteTable": card["surface_budgets"]["WebRouteTable"]["paths"],
    }
    stem_owner = {
        PurePosixPath(path).stem: node
        for node, paths in node_paths.items()
        for path in paths
    }
    stem_owner["LiveHlsReadLease"] = "LiveStreamManager"

    def graph_for(reader: Any) -> dict[str, set[str]]:
        graph: dict[str, set[str]] = {node: set() for node in node_paths}
        for node, paths in node_paths.items():
            dependencies = _w12_literal_module_dependencies(paths, reader)
            graph[node].update(
                owner for dependency in dependencies
                if (owner := stem_owner.get(dependency)) is not None
                and owner != node
            )
        return graph

    baseline_reader = lambda path: _w12_blob_or_none(W12_BASE_COMMIT, path)
    baseline_scc = set(_w12_tarjan(graph_for(baseline_reader)))
    current_scc = set(_w12_tarjan(graph_for(_w12_current_or_none)))
    introduced = current_scc - baseline_scc
    if introduced:
        raise GateError(
            "W12 new include SCC: "
            + ", ".join("/".join(component) for component in sorted(introduced))
        )


def validate_w12_source_ratchets(
    card: dict[str, Any],
    numstat: dict[str, tuple[int, int]],
) -> dict[str, Any]:
    card_paths = card["card_paths"]
    additions = sum(numstat.get(path, (0, 0))[0] for path in card_paths)
    deletions = sum(numstat.get(path, (0, 0))[1] for path in card_paths)
    total = card["card_total_budget"]
    if additions > total["add_max"]:
        raise GateError(f"W12 total CARD_PATHS additions exceed budget: {additions}")
    if deletions < total["delete_min"]:
        raise GateError(f"W12 total CARD_PATHS deletions below budget: {deletions}")
    if additions - deletions > total["net_max"]:
        raise GateError(f"W12 total CARD_PATHS net growth exceeds budget: {additions - deletions}")

    coordinator_paths = card["coordinator_budget"]["paths"]
    coordinator_add = sum(numstat.get(path, (0, 0))[0] for path in coordinator_paths)
    coordinator_delete = sum(numstat.get(path, (0, 0))[1] for path in coordinator_paths)
    coordinator_net = coordinator_add - coordinator_delete
    coordinator = card["coordinator_budget"]
    if coordinator_add > coordinator["add_max"]:
        raise GateError(f"W12 WebServer coordinator additions exceed budget: {coordinator_add}")
    if coordinator_delete < coordinator["delete_min"]:
        raise GateError(f"W12 WebServer coordinator deletions below budget: {coordinator_delete}")
    if coordinator_net > coordinator["net_max"]:
        raise GateError(f"W12 WebServer coordinator net growth exceeds budget: {coordinator_net}")

    baseline_web_cpp = _w12_blob_or_none(W12_BASE_COMMIT, "srchybrid/WebServer.cpp")
    current_web_cpp = _w12_current_or_none("srchybrid/WebServer.cpp")
    current_web_h = _w12_current_or_none("srchybrid/WebServer.h")
    cpp_loc = _w12_physical_loc(current_web_cpp)
    header_loc = _w12_physical_loc(current_web_h)
    if cpp_loc > coordinator["cpp_hard_loc_max"]:
        raise GateError(f"W12 WebServer.cpp hard LOC exceeded: {cpp_loc}")
    if cpp_loc > coordinator["cpp_target_loc_max"]:
        raise GateError(f"W12 WebServer.cpp target LOC exceeded: {cpp_loc}")
    if header_loc > coordinator["header_hard_loc_max"]:
        raise GateError(f"W12 WebServer.h hard LOC exceeded: {header_loc}")

    actual = coordinator["actual_w12_delta"]
    cpp_stat = numstat.get("srchybrid/WebServer.cpp", (0, 0))
    header_stat = numstat.get("srchybrid/WebServer.h", (0, 0))
    measured_cpp = {
        "baseline_physical_loc": _w12_physical_loc(baseline_web_cpp),
        "current_physical_loc": cpp_loc,
        "add": cpp_stat[0], "delete": cpp_stat[1],
        "net": cpp_stat[0] - cpp_stat[1],
    }
    if actual["WebServer.cpp"] != measured_cpp:
        raise GateError("W12 declared WebServer.cpp actual delta is stale")
    if actual["WebServer.h"] != {"net": header_stat[0] - header_stat[1]}:
        raise GateError("W12 declared WebServer.h actual delta is stale")
    if (
        actual["combined_add"] != coordinator_add
        or actual["combined_delete"] != coordinator_delete
        or actual["combined_net"] != coordinator_net
    ):
        raise GateError("W12 declared WebServer combined actual delta is stale")

    validate_w12_field_monotonicity(
        _w12_blob_or_none(W12_BASE_COMMIT, "srchybrid/WebServer.h"),
        current_web_h,
        "CWebServer",
        "srchybrid/WebServer.h",
        coordinator["new_mutable_fields"],
    )

    live_budget = card["live_stream_manager_budget"]
    base_live_cpp = _w12_blob_or_none(W12_BASE_COMMIT, "srchybrid/LiveStreamManager.cpp")
    base_live_h = _w12_blob_or_none(W12_BASE_COMMIT, "srchybrid/LiveStreamManager.h")
    current_live_cpp = _w12_current_or_none("srchybrid/LiveStreamManager.cpp")
    current_live_h = _w12_current_or_none("srchybrid/LiveStreamManager.h")
    live_cpp_growth = _w12_physical_loc(current_live_cpp) - _w12_physical_loc(base_live_cpp)
    live_h_growth = _w12_physical_loc(current_live_h) - _w12_physical_loc(base_live_h)
    if live_cpp_growth > live_budget["cpp_growth_max"]:
        raise GateError(f"W12 LiveStreamManager.cpp grew: {live_cpp_growth}")
    if _w12_physical_loc(current_live_h) > live_budget["header_hard_loc_max"]:
        raise GateError("W12 LiveStreamManager.h hard LOC exceeded")
    validate_w12_field_monotonicity(
        base_live_h,
        current_live_h,
        "CLiveStreamManager",
        "srchybrid/LiveStreamManager.h",
    )

    matrix_limits = card["coordinator_limits"]
    web_declared = matrix_limits["CWebServer"]["actual_w12_delta"]
    expected_web_declared = {
        "cpp_add": cpp_stat[0], "cpp_delete": cpp_stat[1],
        "cpp_net": cpp_stat[0] - cpp_stat[1],
        "header_add": header_stat[0], "header_delete": header_stat[1],
        "header_net": header_stat[0] - header_stat[1],
        "combined_add": coordinator_add, "combined_delete": coordinator_delete,
        "combined_net": coordinator_net,
    }
    if web_declared != expected_web_declared:
        raise GateError("W12 matrix WebServer actual metric cross-link is stale")
    if matrix_limits["CLiveStreamManager"]["w12_actual_delta"] != {
        "header": live_h_growth, "cpp": live_cpp_growth,
    }:
        raise GateError("W12 matrix LiveStreamManager actual metric is stale")

    budgets = card["surface_budgets"]
    for name, budget in budgets.items():
        if name == "LiveHlsReadLease":
            header = _w12_current_or_none(budget["header_path"])
            source = _w12_current_or_none(budget["cpp_path"])
            if header is None or source is None:
                raise GateError("W12 LiveHlsReadLease partition is missing")
            if _w12_physical_loc(header) > budget["header_loc_max"]:
                raise GateError("W12 LiveHlsReadLease header LOC exceeded")
            if _w12_physical_loc(source) > budget["cpp_loc_max"]:
                raise GateError("W12 LiveHlsReadLease cpp LOC exceeded")
            continue
        raw_paths = [_w12_current_or_none(path) for path in budget["paths"]]
        if any(raw is None for raw in raw_paths):
            raise GateError(f"W12 governed surface is missing: {name}")
        surface_loc = sum(_w12_physical_loc(raw) for raw in raw_paths)
        if surface_loc > budget["loc_max"]:
            raise GateError(f"W12 governed surface LOC exceeded: {name}/{surface_loc}")
        if "hard_loc_max" in budget and surface_loc > budget["hard_loc_max"]:
            raise GateError(f"W12 governed surface hard LOC exceeded: {name}/{surface_loc}")

    for path in card_paths:
        if (
            not path.startswith("srchybrid/")
            or path.startswith("srchybrid/tests/")
            or PurePosixPath(path).suffix.casefold()
            not in {".cpp", ".h", ".hpp", ".inl"}
        ):
            continue
        stem = PurePosixPath(path).stem
        sibling_header = f"srchybrid/{stem}.h"
        baseline_header = _w12_blob_or_none(W12_BASE_COMMIT, sibling_header)
        current_header = _w12_current_or_none(sibling_header)
        baseline_functions = _w12_function_inventory(
            _w12_blob_or_none(W12_BASE_COMMIT, path), path,
            _w12_declared_classes(baseline_header),
        )
        current_functions = _w12_function_inventory(
            _w12_current_or_none(path), path,
            _w12_declared_classes(current_header),
        )
        for name, length in current_functions.items():
            if name not in baseline_functions:
                raise GateError(f"W12 new oversized function: {name}/{length}")
            if length > baseline_functions[name]:
                raise GateError(f"W12 baseline oversized function grew: {name}/{length}")
    return {
        "card_add": additions,
        "card_delete": deletions,
        "card_net": additions - deletions,
        "coordinator_add": coordinator_add,
        "coordinator_delete": coordinator_delete,
        "coordinator_net": coordinator_net,
        "webserver_cpp_loc": cpp_loc,
        "webserver_header_loc": header_loc,
        "live_stream_manager_cpp_growth": live_cpp_growth,
        "live_stream_manager_header_growth": live_h_growth,
    }


def _w12_dirty_paths(repo_root: Path = ROOT) -> set[str]:
    tracked = _git_z_paths(
        "diff", "--name-only", "--no-renames", "--ignore-submodules=none",
        "HEAD", "--", repo_root=repo_root,
    )
    untracked = _git_z_paths(
        "ls-files", "--others", "--exclude-standard", repo_root=repo_root,
    )
    # git diff's submodule summary is configuration-sensitive on older Git.
    # Ask submodule directly as well, so a dirty nested checkout cannot hide.
    try:
        status = subprocess.check_output(
            ["git", "submodule", "status", "--recursive"], cwd=repo_root,
            text=True, stderr=subprocess.DEVNULL,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise GateError("W12 submodule status query failed") from exc
    dirty_submodules: set[str] = set()
    for line in status.splitlines():
        if not line:
            continue
        if line[0] in {"+", "U"}:
            fields = line[1:].strip().split()
            if len(fields) < 2:
                raise GateError("W12 malformed submodule status")
            dirty_submodules.add(fields[1])
    return tracked | untracked | dirty_submodules


def _validate_w12_activation_evidence(
    state: dict[str, Any], card: dict[str, Any], activation_commit: str
) -> None:
    covered: set[str] = set()
    executable: dict[str, set[str]] = collections.defaultdict(set)
    if not state["evidence"]:
        raise GateError("W12 active overlay lacks immutable typed evidence")
    for evidence in state["evidence"]:
        evidence = _closed_object(evidence, {
            "kind", "path", "sha256", "commit", "covers",
        }, "activation.W12.evidence")
        path = _safe_w12_path(evidence["path"])
        covers = evidence["covers"]
        if (
            evidence["kind"] not in {"test_source", "golden", "test_result"}
            or evidence["commit"] != activation_commit
            or not isinstance(evidence["sha256"], str)
            or re.fullmatch(r"[0-9a-f]{64}", evidence["sha256"]) is None
            or not isinstance(covers, list)
            or not covers
            or not all(isinstance(cover, str) for cover in covers)
            or len(covers) != len(set(covers))
            or not set(covers).issubset(W12_TYPED_COVERAGE)
            or path not in card["card_paths"]
        ):
            raise GateError("W12 active overlay evidence object invalid")
        blob = _w12_blob_or_none(activation_commit, path)
        if blob is None or hashlib.sha256(blob).hexdigest() != evidence["sha256"]:
            raise GateError(f"W12 active overlay evidence SHA drift: {path}")
        if not _git_path_changed(W12_BASE_COMMIT, activation_commit, path):
            raise GateError(f"W12 active overlay evidence was not introduced by A: {path}")
        if evidence["kind"] in {"test_source", "golden"} and not (
            path.startswith("tests/") or path.startswith("srchybrid/tests/")
        ):
            raise GateError("W12 executable/golden evidence must live in a test directory")
        if evidence["kind"] == "test_source":
            if re.fullmatch(r"tests/test_v92_m2a[A-Za-z0-9_]*\.py", path) is None:
                raise GateError("W12 test_source is not discoverable by the M2A CI pattern")
            _validate_test_source(blob, covers)
            executable[path].update(covers)
        covered.update(covers)
    if covered != set(W12_TYPED_COVERAGE):
        raise GateError("W12 active overlay lacks complete typed coverage")
    if not executable:
        raise GateError("W12 active overlay lacks executable typed evidence")
    for path, covers in sorted(executable.items()):
        _run_required_tests(path, covers)


def _w12_strict_json_blob(commit: str, path: str) -> dict[str, Any]:
    blob = _w12_blob_or_none(commit, path)
    if blob is None:
        raise GateError(f"W12 JSON blob unavailable: {commit}:{path}")
    return _w12_strict_json_bytes(blob, path)


def _w12_exact_parent(commit: str, repo_root: Path = ROOT) -> str:
    """Return the sole parent; a merge is never an admissible W12 link."""
    line = _git_text("rev-list", "--parents", "-n1", commit, repo_root=repo_root)
    fields = line.split()
    if len(fields) != 2 or not all(re.fullmatch(r"[0-9a-f]{40}", item) for item in fields):
        raise GateError("W12 commit must have exactly one parent")
    return fields[1]


def _w12_planned_state() -> dict[str, Any]:
    return {"state": "planned", "activation_commit": None, "evidence": []}


def _w12_r_artifact_paths(activation_commit: str) -> dict[str, str]:
    root = f"artifacts/mod52-w12-r-{activation_commit[:12]}"
    return {
        key: f"{root}/{filename}"
        for key, filename in W12_R_ARTIFACT_NAMES.items()
    }


def _w12_resolve_r_history(
    activation_commit: str, ledger_path: str, artifact_paths: dict[str, str],
    card_paths: list[str],
) -> tuple[str, str]:
    ledger_history = _git_text("rev-list", "--reverse",
        f"{activation_commit}..HEAD", "--", ledger_path).splitlines()
    if len(ledger_history) != 2 or any(re.fullmatch(r"[0-9a-f]{40}", item) is None
                                       for item in ledger_history):
        raise GateError("W12 history must contain exactly one H and one R ledger commit")
    h_commit, r_commit = ledger_history
    if _w12_exact_parent(h_commit) != activation_commit: raise GateError("W12 H must be the direct child of A")
    if _w12_exact_parent(r_commit) != h_commit: raise GateError("W12 R must be the direct child of H")
    if not _is_ancestor(r_commit, "HEAD"):
        raise GateError("W12 immutable R is not in HEAD history")
    descendants = _git_text("rev-list", "--reverse", "--ancestry-path",
                            f"{r_commit}..HEAD").splitlines()
    previous = r_commit
    for commit in descendants:
        if re.fullmatch(r"[0-9a-f]{40}", commit) is None or \
                _w12_exact_parent(commit) != previous:
            raise GateError("W12 post-R history must be one linear chain")
        previous = commit
    protected_paths = sorted({*card_paths, ledger_path, *artifact_paths.values()}); changed_after_r = _git_z_paths("log", "--format=", "--name-only",
        f"{r_commit}..HEAD", "--", *protected_paths)
    if changed_after_r:
        raise GateError(
            "W12 protected path changed after R: "
            + ", ".join(sorted(changed_after_r))
        )
    return h_commit, r_commit


def validate_w12_r_evidence_schema(
    value: Any, activation_commit: str
) -> dict[str, str]:
    evidence = _closed_object(value, {
        *W12_R_ARTIFACT_NAMES,
        "candidate_commit", "emule_sha256", "verifier_sha256",
    }, "activation.W12.r_evidence")
    if evidence["candidate_commit"] != activation_commit:
        raise GateError("W12 R candidate_commit is not activation A")
    for key in ("emule_sha256", "verifier_sha256"):
        if not isinstance(evidence[key], str) or re.fullmatch(r"[0-9a-f]{64}", evidence[key]) is None:
            raise GateError(f"W12 R {key} is not canonical SHA-256")
    expected_paths = _w12_r_artifact_paths(activation_commit)
    for key, expected_path in expected_paths.items():
        artifact = _closed_object(
            evidence[key], {"path", "sha256"}, f"activation.W12.r_evidence.{key}"
        )
        if artifact["path"] != expected_path:
            raise GateError(f"W12 R artifact path is not fixed: {key}")
        if not isinstance(artifact["sha256"], str) or re.fullmatch(
            r"[0-9a-f]{64}", artifact["sha256"]
        ) is None:
            raise GateError(f"W12 R artifact SHA is invalid: {key}")
    return expected_paths


def _w12_sha256(value: Any, where: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise GateError(f"W12 R {where} is not canonical SHA-256")
    return value


def _w12_production_tree(activation_commit: str) -> tuple[str, int]:
    """Recreate verifier canonical_production_tree from immutable Git blobs.

    The persisted activation file is only a claim.  The authority is A's
    ``git ls-tree -r --full-tree A -- srchybrid`` listing, serialized as real
    UTF-8 ``blob-oid TAB path LF`` records in canonical path order.
    """
    try:
        raw = subprocess.check_output(
            ["git", "ls-tree", "-r", "--full-tree", "-z", activation_commit,
             "--", "srchybrid"],
            cwd=ROOT,
            stderr=subprocess.DEVNULL,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise GateError("W12 production tree is unavailable at activation A") from exc
    entries: list[tuple[str, str]] = []
    for record in raw.split(b"\0"):
        if not record:
            continue
        metadata, separator, raw_path = record.partition(b"\t")
        fields = metadata.split()
        if separator != b"\t" or len(fields) != 3 or fields[1] != b"blob":
            raise GateError("W12 production tree entry is not a Git blob")
        try:
            oid = fields[2].decode("ascii")
            path = raw_path.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise GateError("W12 production tree entry is not UTF-8") from exc
        if (
            re.fullmatch(r"[0-9a-f]{40}", oid) is None
            or not path.startswith("srchybrid/")
            or any(char in path for char in ("\0", "\t", "\n"))
        ):
            raise GateError("W12 production tree path is not canonical")
        entries.append((oid, path))
    if not entries or len({path for _, path in entries}) != len(entries):
        raise GateError("W12 production tree is empty or has duplicate paths")
    payload = "".join(
        f"{oid}\t{path}\n" for oid, path in sorted(entries, key=lambda item: item[1])
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest(), len(entries)


def _w12_toolset_sha256(tools: dict[str, str]) -> str:
    return hashlib.sha256(
        json.dumps(tools, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _w12_v2_candidate(
    value: Any, activation_commit: str, emule_sha256: str, where: str
) -> dict[str, str]:
    candidate = _closed_object(value, {
        "build_commit", "emule_sha256", "build_info_sha256", "release",
    }, where)
    if candidate["build_commit"] != activation_commit:
        raise GateError(f"W12 R {where} BUILD_INFO candidate is not exactly A")
    if candidate["emule_sha256"] != emule_sha256:
        raise GateError(f"W12 R {where} binary SHA differs from the ledger")
    _w12_sha256(candidate["build_info_sha256"], f"{where}.build_info_sha256")
    if (
        not isinstance(candidate["release"], str)
        or not candidate["release"]
        or len(candidate["release"]) > 96
        or any(ord(char) < 0x20 for char in candidate["release"])
    ):
        raise GateError(f"W12 R {where} release is malformed")
    return candidate


def _w12_v2_binding(
    value: Any, activation_commit: str, production_tree_sha256: str,
    toolset_sha256: str, where: str,
) -> dict[str, str]:
    binding = _closed_object(value, {
        "activation_commit", "production_tree_sha256", "toolset_sha256",
        "run_id_sha256", "challenge_nonce_sha256", "canary_sha256",
    }, where)
    for key, item in binding.items():
        if key == "activation_commit":
            if item != activation_commit:
                raise GateError(f"W12 R {where} is not bound to A")
        else:
            _w12_sha256(item, f"{where}.{key}")
    if binding["production_tree_sha256"] != production_tree_sha256:
        raise GateError(f"W12 R {where} production tree differs from A")
    if binding["toolset_sha256"] != toolset_sha256:
        raise GateError(f"W12 R {where} toolset differs from immutable A tools")
    return binding


def _validate_w12_r_artifacts(
    state: dict[str, Any], activation_commit: str, paths: dict[str, str]
) -> dict[str, str]:
    evidence = state["r_evidence"]
    for key, path in paths.items():
        blob = _w12_blob_or_none("HEAD", path)
        if (
            blob is None
            or hashlib.sha256(blob).hexdigest() != evidence[key]["sha256"]
        ):
            raise GateError(f"W12 R artifact is absent or not immutable: {key}")
    activation = _w12_strict_json_blob("HEAD", paths["activation"])
    _closed_object(activation, {
        "schema", "activation_commit", "production_tree_sha256",
        "production_path_count", "tool_sha256",
    }, "W12 R activation artifact")
    if (
        activation["schema"] != "ese.v92.w12.activation/v2"
        or activation["activation_commit"] != activation_commit
    ):
        raise GateError("W12 R activation artifact is not bound to A")
    production_tree_sha256, production_path_count = _w12_production_tree(
        activation_commit
    )
    if (
        activation["production_tree_sha256"] != production_tree_sha256
        or activation["production_path_count"] != production_path_count
        or isinstance(activation["production_path_count"], bool)
    ):
        raise GateError("W12 R activation production identity differs from Git A")
    tools = _closed_object(
        activation["tool_sha256"], set(W12_R_TOOL_PATHS),
        "W12 R activation artifact.tool_sha256",
    )
    expected_tools: dict[str, str] = {}
    for key, path in W12_R_TOOL_PATHS.items():
        at_a = _w12_blob_or_none(activation_commit, path)
        if (
            at_a is None
            or _w12_blob_or_none("HEAD", path) != at_a
        ):
            raise GateError(f"W12 R activation tool is not immutable from A: {path}")
        expected_tools[key] = hashlib.sha256(at_a).hexdigest()
    if tools != expected_tools:
        raise GateError("W12 R activation tool hashes are not the immutable A tools")
    if tools["verifier"] != evidence["verifier_sha256"]:
        raise GateError("W12 R activation/verifier ledger hash binding drift")
    verifier_at_a = _w12_blob_or_none(activation_commit, W12_EVIDENCE_VERIFIER)
    verifier_at_head = _w12_blob_or_none("HEAD", W12_EVIDENCE_VERIFIER)
    if (
        verifier_at_a is None
        or verifier_at_head != verifier_at_a
        or hashlib.sha256(verifier_at_a).hexdigest() != evidence["verifier_sha256"]
    ):
        raise GateError("W12 R verifier is not the immutable A verifier")
    toolset_sha256 = _w12_toolset_sha256(expected_tools)
    runtime = _w12_strict_json_blob("HEAD", paths["runtime"])
    _closed_object(runtime, {
        "schema", "candidate", "execution", "cases", "canary", "privacy",
        "binding", "verdict",
    }, "W12 R runtime")
    if runtime["schema"] != "ese.v92.w12.security-runtime/v2" or runtime["verdict"] != "PASS":
        raise GateError("W12 R runtime schema or verdict drift")
    candidate = _w12_v2_candidate(
        runtime["candidate"], activation_commit, evidence["emule_sha256"], "runtime.candidate"
    )
    binding = _w12_v2_binding(
        runtime["binding"], activation_commit, production_tree_sha256,
        toolset_sha256, "runtime.binding",
    )
    challenge = _w12_strict_json_blob("HEAD", paths["browser_challenge"])
    _closed_object(challenge, {"schema", "candidate", "binding"}, "W12 R challenge")
    if challenge["schema"] != "ese.v92.w12.browser-challenge/v2":
        raise GateError("W12 R challenge schema drift")
    if _w12_v2_candidate(challenge["candidate"], activation_commit, evidence["emule_sha256"], "challenge.candidate") != candidate:
        raise GateError("W12 R challenge candidate differs from runtime")
    if _w12_v2_binding(challenge["binding"], activation_commit, production_tree_sha256, toolset_sha256, "challenge.binding") != binding:
        raise GateError("W12 R challenge binding differs from runtime")
    trace = _w12_strict_json_blob("HEAD", paths["browser_cdp_trace"])
    _closed_object(trace, {"schema", "activation_commit", "candidate", "binding", "collector_sha256", "browser_binding_sha256", "product_sha256", "version_sha256", "user_agent_sha256", "events"}, "W12 R browser trace")
    if trace["schema"] != "ese.v92.w12.browser-cdp/v3" or trace["activation_commit"] != activation_commit:
        raise GateError("W12 R browser trace schema or activation binding drift")
    for key in ("collector_sha256", "browser_binding_sha256", "product_sha256", "version_sha256", "user_agent_sha256"):
        if not isinstance(trace[key], str) or re.fullmatch(r"[0-9a-f]{64}", trace[key]) is None:
            raise GateError(f"W12 R browser trace {key} is malformed")
    if trace["collector_sha256"] != expected_tools["collector"]:
        raise GateError("W12 R browser trace collector is not the immutable A collector")
    if _w12_v2_candidate(trace["candidate"], activation_commit, evidence["emule_sha256"], "trace.candidate") != candidate:
        raise GateError("W12 R browser trace candidate differs from runtime")
    if _w12_v2_binding(trace["binding"], activation_commit, production_tree_sha256, toolset_sha256, "trace.binding") != binding:
        raise GateError("W12 R browser trace binding differs from runtime")
    _run_w12_r_verifier(paths, evidence, activation_commit)
    return paths


def _run_w12_r_verifier(
    paths: dict[str, str], evidence: dict[str, Any], activation_commit: str
) -> None:
    """Reproduce R using only checked-in Git blobs, never checkout paths."""
    with tempfile.TemporaryDirectory(prefix="w12-r-verdict-") as temporary:
        root = Path(temporary)
        head = _git_text("rev-parse", "HEAD")
        if re.fullmatch(r"[0-9a-f]{40}", head) is None:
            raise GateError("W12 R HEAD is not an immutable commit")

        def materialize(name: str, source_path: str, expected_sha256: str | None = None) -> Path:
            blob = _w12_blob_or_none(head, source_path)
            if blob is None:
                raise GateError(f"W12 R Git blob unavailable: {name}")
            digest = hashlib.sha256(blob).hexdigest()
            if expected_sha256 is not None and digest != expected_sha256:
                raise GateError(f"W12 R Git blob hash differs: {name}")
            target = root / name
            target.write_bytes(blob)
            if hashlib.sha256(target.read_bytes()).hexdigest() != digest:
                raise GateError(f"W12 R blob materialization changed: {name}")
            return target

        verifier = materialize(
            "verify_w12_security_evidence.py", W12_EVIDENCE_VERIFIER,
            evidence["verifier_sha256"],
        )
        inputs = {
            key: materialize(f"{key}.json", path, evidence[key]["sha256"])
            for key, path in paths.items()
        }
        output = root / "reproduced-verdict.json"
        command = [
            sys.executable, "-B", str(verifier),
            "--activation", str(inputs["activation"]),
            "--runtime", str(inputs["runtime"]),
            "--challenge", str(inputs["browser_challenge"]),
            "--browser-trace", str(inputs["browser_cdp_trace"]),
            "--output", str(output),
        ]
        try:
            completed = subprocess.run(
                command, cwd=root, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, check=False, timeout=120,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise GateError("W12 R evidence verifier did not complete") from exc
        if completed.returncode != 0 or not output.is_file():
            raise GateError("W12 R evidence verifier did not PASS")
        generated = output.read_bytes()
        committed = inputs["verdict"].read_bytes()
    if generated != committed:
        raise GateError("W12 R persisted verdict is not verifier-reproducible")
    verdict = _w12_strict_json_blob("HEAD", paths["verdict"])
    _closed_object(verdict, {
        "schema", "activation_commit", "emule_sha256", "cases", "verdict",
    }, "W12 R verdict")
    if verdict["schema"] != "ese.v92.w12.security-verdict/v2" or verdict["verdict"] != "PASS":
        raise GateError("W12 R verdict identity/status drift")
    if (
        verdict["activation_commit"] != activation_commit
        or verdict["emule_sha256"] != evidence["emule_sha256"]
    ):
        raise GateError("W12 R verdict candidate is not activation A/binary")
    if not isinstance(verdict["cases"], list):
        raise GateError("W12 R verdict cases are malformed")


def validate_w12_activation_state(
    card: dict[str, Any], ledger: dict[str, Any]
) -> tuple[str, str | None, dict[str, tuple[int, int]]]:
    if set(ledger) != {"schema", "scope", "cards"} or ledger.get("schema") != "ese.mod52.activation-ledger/v1":
        raise GateError("W12 activation ledger schema drift")
    state = ledger.get("cards", {}).get("W12")
    if not isinstance(state, dict):
        raise GateError("W12 activation state is missing or malformed")
    head = _git_text("rev-parse", "HEAD")
    if state == _w12_planned_state():
        if head == W12_BASE_COMMIT:
            changed, staged = _w12_worktree_path_sets()
            validate_w12_card_path_scope(card["card_paths"], changed, staged)
            for path in card["card_paths"]:
                if _w12_current_or_none(path) is None and _w12_blob_or_none(
                    W12_BASE_COMMIT, path
                ) is None:
                    raise GateError(f"W12 declared CARD_PATHS entry is unavailable: {path}")
            return "PRE-A", None, _w12_numstat(
                W12_BASE_COMMIT, None, card["card_paths"]
            )
        if _w12_exact_parent(head) != W12_BASE_COMMIT:
            raise GateError("W12 A must be one exact A^..A cut over the frozen W11 base")
        if _w12_dirty_paths():
            raise GateError("W12 A worktree/index must be clean")
        changed = _w12_commit_changed_paths(W12_BASE_COMMIT, head)
        validate_w12_card_path_scope(card["card_paths"], changed)
        return "A", head, _w12_numstat(
            W12_BASE_COMMIT, head, card["card_paths"]
        )
    _closed_object(state, {
        "state", "stage", "activation_commit", "evidence", "r_evidence",
    }, "activation.W12.active")
    if state.get("state") != "active" or state.get("stage") not in {"H", "R"}:
        raise GateError("W12 activation state must be planned or active")
    activation_commit = state.get("activation_commit")
    if (
        not isinstance(activation_commit, str)
        or re.fullmatch(r"[0-9a-f]{40}", activation_commit) is None
    ):
        raise GateError("W12 active overlay lacks an immutable A commit")
    if _w12_exact_parent(activation_commit) != W12_BASE_COMMIT:
        raise GateError("W12 activation A parent is not the exact frozen W11 base")
    if not _is_ancestor(activation_commit, "HEAD"):
        raise GateError("W12 activation A is not in HEAD history")
    if _w12_dirty_paths():
        raise GateError("W12 H/R worktree/index must be clean")
    changed = _w12_commit_changed_paths(W12_BASE_COMMIT, activation_commit)
    validate_w12_card_path_scope(card["card_paths"], changed)
    ledger_path = ACTIVATION.relative_to(ROOT).as_posix()
    if _w12_strict_json_blob(activation_commit, ledger_path).get(
        "cards", {}
    ).get("W12") != _w12_planned_state():
        raise GateError("W12 implementation A must retain the planned ledger state")
    for path in card["card_paths"]:
        at_a = _w12_blob_or_none(activation_commit, path)
        at_head = _w12_blob_or_none("HEAD", path)
        if at_a != at_head or _w12_current_or_none(path) != at_a:
            raise GateError(f"W12 CARD_PATHS changed after immutable A: {path}")
    _validate_w12_activation_evidence(state, card, activation_commit)
    if state["stage"] == "H":
        if state["r_evidence"] is not None:
            raise GateError("W12 H must not contain R evidence")
        if _w12_exact_parent("HEAD") != activation_commit:
            raise GateError("W12 H must be the direct child of A")
        if _w12_commit_changed_paths(activation_commit, "HEAD") != {ledger_path}:
            raise GateError("W12 H may change only the activation ledger")
        stage = "H"
    else:
        artifact_paths = validate_w12_r_evidence_schema(
            state["r_evidence"], activation_commit
        )
        h_commit, r_commit = _w12_resolve_r_history(
            activation_commit, ledger_path, artifact_paths, card["card_paths"]
        )
        h_ledger = _w12_strict_json_blob(h_commit, ledger_path)
        h_state = h_ledger.get("cards", {}).get("W12")
        expected_h = {
            "state": "active", "stage": "H",
            "activation_commit": activation_commit,
            "evidence": state["evidence"], "r_evidence": None,
        }
        if h_state != expected_h:
            raise GateError("W12 R parent is not the exact H attestation")
        if _w12_commit_changed_paths(activation_commit, h_commit) != {ledger_path}:
            raise GateError("W12 H parent changed more than the activation ledger")
        expected_r_paths = {ledger_path, *artifact_paths.values()}
        if _w12_commit_changed_paths(h_commit, r_commit) != expected_r_paths:
            raise GateError("W12 R commit must contain only ledger plus five fixed artifacts")
        _validate_w12_r_artifacts(state, activation_commit, artifact_paths)
        stage = "R"
    return stage, activation_commit, _w12_numstat(
        W12_BASE_COMMIT, activation_commit, card["card_paths"]
    )


def _validate_w12_contract_metrics(
    card: dict[str, Any], contract: dict[str, Any], metrics: dict[str, Any]
) -> None:
    matrix_web = card["coordinator_limits"]["CWebServer"]["actual_w12_delta"]
    contract_web = contract["coordinator_limits"]["WebServer"]["actual_w12_delta"]
    expected_contract_web = {
        "cpp_baseline_physical_loc": card["coordinator_budget"]["actual_w12_delta"]["WebServer.cpp"]["baseline_physical_loc"],
        "cpp_current_physical_loc": metrics["webserver_cpp_loc"],
        **matrix_web,
    }
    if contract_web != expected_contract_web:
        raise GateError("W12 contract WebServer actual metric cross-link is stale")
    matrix_live = card["coordinator_limits"]["CLiveStreamManager"]["w12_actual_delta"]
    if contract["coordinator_limits"]["LiveStreamManager"]["actual_w12_delta"] != matrix_live:
        raise GateError("W12 contract LiveStreamManager actual metric cross-link is stale")
    ratchet = _closed_object(contract["ratchet"], {
        "card_paths_closed", "unlisted_production_path",
        "coordinator_added_lines_max", "coordinator_deleted_lines_min",
        "coordinator_net_lines_max", "webserver_cpp_hard_loc_max",
        "webserver_cpp_target_loc_max", "webserver_header_hard_loc_max",
        "webserver_new_mutable_fields", "live_stream_manager_header_hard_loc_max",
        "live_stream_manager_cpp_growth_max", "no_new_scc",
        "no_new_over_150_function", "no_baseline_oversized_function_growth",
    }, "contract.ratchet")
    coordinator = card["coordinator_budget"]
    live = card["live_stream_manager_budget"]
    expected_values = {
        "coordinator_added_lines_max": coordinator["add_max"],
        "coordinator_deleted_lines_min": coordinator["delete_min"],
        "coordinator_net_lines_max": coordinator["net_max"],
        "webserver_cpp_hard_loc_max": coordinator["cpp_hard_loc_max"],
        "webserver_cpp_target_loc_max": coordinator["cpp_target_loc_max"],
        "webserver_header_hard_loc_max": coordinator["header_hard_loc_max"],
        "webserver_new_mutable_fields": coordinator["new_mutable_fields"],
        "live_stream_manager_header_hard_loc_max": live["header_hard_loc_max"],
        "live_stream_manager_cpp_growth_max": live["cpp_growth_max"],
    }
    if any(ratchet[key] != value for key, value in expected_values.items()):
        raise GateError("W12 executable ratchet/declared budget cross-link drift")
    if any(
        ratchet[key] is not True
        for key in (
            "card_paths_closed", "no_new_scc", "no_new_over_150_function",
            "no_baseline_oversized_function_growth",
        )
    ) or not isinstance(ratchet["unlisted_production_path"], str):
        raise GateError("W12 executable ratchet boolean/STOP policy drift")
    security = _closed_object(contract["security_invariants"], {
        "commit_order", "live_lock_order", "forbidden_under_lease",
        "buffer_cap_per_response_bytes", "buffer_cap_aggregate_bytes",
        "capacity_rejection", "generation_reuse",
    }, "contract.security_invariants")
    if (
        not _nonnegative_int(security["buffer_cap_per_response_bytes"])
        or security["buffer_cap_per_response_bytes"] <= 0
        or not _nonnegative_int(security["buffer_cap_aggregate_bytes"])
        or security["buffer_cap_aggregate_bytes"] <= 0
        or security["buffer_cap_per_response_bytes"] >= security["buffer_cap_aggregate_bytes"]
        or not isinstance(security["forbidden_under_lease"], list)
        or not security["forbidden_under_lease"]
        or any(
            not isinstance(security[key], str) or not security[key].strip()
            for key in ("commit_order", "live_lock_order", "capacity_rejection", "generation_reuse")
        )
    ):
        raise GateError("W12 security invariant schema/value drift")


def verify_w12_overlay() -> dict[str, Any]:
    matrix = _w12_strict_json_file(W12_MATRIX)
    contract = _w12_strict_json_file(W12_CONTRACT)
    ownership = _w12_strict_json_file(W12_MOD03)
    catalogue = _w12_strict_json_file(W12_MOD04)
    card = validate_w12_overlay_documents(matrix, contract, ownership, catalogue)
    ledger = _w12_strict_json_file(ACTIVATION)
    stage, activation_commit, numstat = validate_w12_activation_state(card, ledger)
    metrics = validate_w12_source_ratchets(card, numstat)
    validate_w12_dependencies_and_scc(card, ownership)
    _validate_w12_contract_metrics(card, contract, metrics)
    return {
        "schema": "ese.m2a00.w12-overlay-ratchet-report/v2",
        "baseline_commit": W12_BASE_COMMIT,
        "stage": stage,
        "activation_commit": activation_commit,
        "metrics": metrics,
        "coverage": {
            "pre_a": list(W12_COVERAGE_IDS[:5]) + list(W12_COVERAGE_IDS[7:]),
            "a_h": [W12_COVERAGE_IDS[5]],
            "r": [W12_COVERAGE_IDS[6]],
        },
        "status": "PASS",
    }


def report() -> dict[str, Any]:
    """Reproduce the baseline only from Git blobs, never from the worktree."""
    measured = metrics(_baseline_overrides(), force_v1_graph=True)
    condensed: dict[str, Any] = {"coordinators": {}, "include_graph_sha256": measured["include_graph_sha256"], "sccs": measured["sccs"]}
    for name, item in measured["coordinators"].items():
        row = {"files": item["files"], "field_count": len(item["fields"]), "field_sha256": canonical(item["fields"]), "fields": item["fields"], "oversized_functions": item["oversized_functions"]}
        condensed["coordinators"][name] = row
    return {"schema":"ese.m2a00.baseline-report/v1", "baseline_commit":BASELINE_COMMIT, "metrics":condensed, "status":"PASS"}


def verify(overrides: dict[str, bytes] | None = None) -> dict[str, Any]:
    overlay_paths = (W12_MATRIX, W12_CONTRACT, W12_MOD03, W12_MOD04)
    present = [path.is_file() for path in overlay_paths]
    if any(present):
        if not all(present):
            raise GateError("W12 overlay is partially present")
        if overrides is not None:
            raise GateError("W12 overlay verification does not accept v1 source overrides")
        return verify_w12_overlay()
    contract, matrix, baseline = load(CONTRACT), load(MATRIX), load(BASELINE)
    ledger = load(ACTIVATION)
    validate_inputs(contract, matrix, baseline, ledger)
    validate_active_card_outcomes(matrix, ledger, overrides)
    validate_active_head_ratchet(ledger, overrides)
    validate_active_budgets(matrix, ledger)
    config, mod03 = _combined_catalogue(matrix, ledger)
    mod51_contract = load(MOD51)
    if not any(item["state"] == "active" for item in ledger["cards"].values()):
        mod04.validate(config, mod03, overrides=overrides)
    graph = validate_active_include_contract(matrix, ledger, overrides)
    mod51.verify_scc_policy(mod51_contract, graph)
    validate_coordinator_module_isolation(matrix, ledger, overrides)
    validate_coordinator_header_monotonicity(overrides)
    current = metrics(overrides)
    validate_ratchet(baseline, current, matrix)
    return {"schema":"ese.m2a00.ratchet-report/v1", "baseline_commit":BASELINE_COMMIT, "metrics":current, "status":"PASS"}


def main(argv: list[str] | None = None) -> int:
    parser=argparse.ArgumentParser(); parser.add_argument("--report",action="store_true"); parser.add_argument("--verify",action="store_true")
    args=parser.parse_args(argv)
    try:
        if args.report:
            print(json.dumps(report(), sort_keys=True, indent=2)); return 0
        if args.verify:
            print("M2A-00 PASS: green migration ratchet") if verify() else None; return 0
        raise GateError("choose --report or --verify")
    except (OSError, KeyError, TypeError, ValueError, mod04.GateError, mod51.GateError, GateError) as exc:
        print(f"M2A-00 FAIL: {exc}", file=sys.stderr); return 1
if __name__ == "__main__": raise SystemExit(main())
