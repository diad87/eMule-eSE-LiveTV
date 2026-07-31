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
BASELINE_COMMIT = "8534bf9ee48a16084c0368bf33dcafb4ba12558d"
# Deliberately held in executable code rather than in the documents they pin:
# changing a contract cannot silently authorize its own replacement.
EXPECTED_DOC_HASHES: dict[str, str] = {
    "mod52_migration_contract_v1.json": "b3957aca15b7c25e42229c3f9623bff881b450c7277323a28c7639e0ea9f3caf",
    "mod52_migration_matrix_v1.json": "0b84a0898a78f62f253587b4085b2c35167fa4f7ead4d0720a5b6cedfbf6d0ca",
    "mod52_migration_baseline_v1.json": "4c162b457059776f13c26341fdab60778088014e183acc48926f22f5d1cbc5c3",
    "mod03_ownership_layering_contract_v2.json": "c3aa3d90bccbc63ff7a0c8ebafd199e9ed2b00acc2c2ef488c5e11515a3f28b1",
    "mod04_architecture_gate_catalog_v2.json": "24559b15a4f30a090298764d6ddca11fdda57e4afcbb01f4da452c1b6df373d2",
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
                for call in assignment.finditer(translated):
                    previous = (
                        ""
                        if same_card_parent is not None
                        else _translated(
                            path, _git_blob(activation_parent, path)
                        )
                    )
                    if _preexisting_parent_route(
                        translated, previous, parent_classes, call.start()
                    ) or (
                        same_card_parent is not None
                        and _same_card_parent_constructor_route(
                            translated, same_card_parent["name"], call.start()
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


def report() -> dict[str, Any]:
    """Reproduce the baseline only from Git blobs, never from the worktree."""
    measured = metrics(_baseline_overrides(), force_v1_graph=True)
    condensed: dict[str, Any] = {"coordinators": {}, "include_graph_sha256": measured["include_graph_sha256"], "sccs": measured["sccs"]}
    for name, item in measured["coordinators"].items():
        row = {"files": item["files"], "field_count": len(item["fields"]), "field_sha256": canonical(item["fields"]), "fields": item["fields"], "oversized_functions": item["oversized_functions"]}
        condensed["coordinators"][name] = row
    return {"schema":"ese.m2a00.baseline-report/v1", "baseline_commit":BASELINE_COMMIT, "metrics":condensed, "status":"PASS"}


def verify(overrides: dict[str, bytes] | None = None) -> dict[str, Any]:
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
