#!/usr/bin/env python3
"""Closed, source-level architecture gate for MOD-0.4."""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path, PurePosixPath
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
BASELINE_PATH = ROOT / "docs" / "architecture" / "mod04_architecture_gate_baseline_v1.json"
CONTRACT_PATH = ROOT / "docs" / "architecture" / "mod03_ownership_layering_contract_v1.json"
BASELINE_COMMIT = "161d948281682d39acdcea796b1edddc6d68904c"
EXPECTED_SCOPE = "binding CI architecture gates only; no extraction or production behavior change"
EXPECTED_SLICE_RULE = (
    "for each catalogued extraction, git diff --numstat from its declared "
    "slice_base_commit to the worktree must show source_coordinator removed "
    "lines strictly greater than added lines"
)
EXPECTED_FINAL_LIMITS = {
    "enforced_now": False,
    "activation": "end-state review only; each extraction slice remains bound by no coordinator growth",
}
EXPECTED_MODULE_POLICY = {
    "recommended_implementation_loc_min": 300,
    "recommended_implementation_loc_max": 1200,
    "hard_stop_implementation_loc": 1500,
    "max_direct_dependencies": 8,
}
EXPECTED_COORDINATORS = [
    {"coordinator": "LiveTunnel", "path": "srchybrid/LiveTunnel.cpp", "kind": "source", "baseline_loc_physical": 11647, "baseline_sha256": "ab611f9750f1e9ea57d16947ec2fc0490738a5585561c508a0747700e802315a", "final_target_loc_max": 3500, "final_hard_stop_loc": 4000},
    {"coordinator": "LiveTunnel", "path": "srchybrid/LiveTunnel.h", "kind": "header", "baseline_loc_physical": 1355, "baseline_sha256": "402355f12423ee03b6e4786c21bbf1658740f23dbf0a940c968929afd8946cbd", "final_target_loc_max": 750, "final_hard_stop_loc": 900},
    {"coordinator": "WebServer", "path": "srchybrid/WebServer.cpp", "kind": "source", "baseline_loc_physical": 8257, "baseline_sha256": "acc6445200922865d1bbf1e2a2aa967898065f537376d0fb5a7fb9bc3c707e96", "final_target_loc_max": 3000, "final_hard_stop_loc": 3500},
    {"coordinator": "WebServer", "path": "srchybrid/WebServer.h", "kind": "header", "baseline_loc_physical": 410, "baseline_sha256": "db9982186b4a4b52addd094314fa8550a8f4cf730e799564af7339f8e6eb759c", "final_target_loc_max": None, "final_hard_stop_loc": None, "final_limit_status": "not_specified_by_plan"},
    {"coordinator": "LiveStreamManager", "path": "srchybrid/LiveStreamManager.cpp", "kind": "source", "baseline_loc_physical": 5067, "baseline_sha256": "33d509c439836fce2fc35e509f933637687505394daeb5b66e29cb599eb62cc2", "final_target_loc_max": 2500, "final_hard_stop_loc": 3000},
    {"coordinator": "LiveStreamManager", "path": "srchybrid/LiveStreamManager.h", "kind": "header", "baseline_loc_physical": 886, "baseline_sha256": "e93b3c7467a389872fb5084e9912bcbf1b2cd6693d3990d3dda54fcaec0449fd", "final_target_loc_max": 600, "final_hard_stop_loc": 700},
]
OWNER_SOURCE = {
    "CLiveTunnel": "srchybrid/LiveTunnel.cpp",
    "CWebServer": "srchybrid/WebServer.cpp",
    "CLiveStreamManager": "srchybrid/LiveStreamManager.cpp",
}
INCLUDE_RE = re.compile(r'^\s*#\s*include\s*(?:\"([^"]+)\"|<([^>]+)>)', re.MULTILINE)
SOURCE_SUFFIXES = {".c", ".cc", ".cp", ".cpp", ".cxx", ".c++", ".cppm", ".ixx"}
INTERFACE_CODE_SUFFIXES = {".h", ".hh", ".hpp", ".hxx", ".h++", ".inl", ".ipp", ".tpp", ".inc"}
CODE_SUFFIXES = SOURCE_SUFFIXES | INTERFACE_CODE_SUFFIXES
COORDINATOR_HEADERS = {"LiveTunnel.h", "WebServer.h", "LiveStreamManager.h", "EmuleDlg.h"}
DOMAIN_CONCRETE_HINTS = ("dlg", "dialog", "socket", "kad", "kademlia", "windows.h", "winsock")
PCH_HEADERS = {"stdafx.h", "pch.h"}
DOMAIN_CONCRETE_TYPE_RE = re.compile(
    r"\b(?:C[A-Za-z0-9_]*(?:Socket|Dlg|Dialog)|CKad[A-Za-z0-9_]*|"
    r"Kademlia|HANDLE|C(?:File|StdioFile|Wnd|WinApp|WinThread)|"
    r"PROCESS_INFORMATION|HWND|SOCKET|WSADATA|SOCKADDR(?:_IN(?:6)?)?)\b"
)
EXCLUDED_REPO_PARTS = {
    ".git", "build", "build_output", "x64", "release", "debug",
    "cryptopp", "cximage", "id3lib", "libpng",
    "libutp", "mbedtls",
    "miniupnpc", "resizablelib", "zlib", "node_modules",
}


class GateError(RuntimeError):
    """A deterministic MOD-0.4 gate failure."""


def loc_physical(raw: bytes) -> int:
    return len(raw.splitlines())


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _require_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        raise GateError(f"{label} keys drift")


def _run_git(args: list[str], text: bool = False) -> str | bytes:
    try:
        return subprocess.check_output(["git", *args], cwd=ROOT, text=text, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError as exc:
        raise GateError(f"git command failed: {' '.join(args)}") from exc


def git_blob(commit: str, path: str) -> bytes:
    try:
        return _run_git(["show", f"{commit}:{path}"])  # type: ignore[return-value]
    except GateError as exc:
        raise GateError(f"baseline Git blob unavailable: {commit}:{path}") from exc


def _planned_modules(contract: dict[str, Any]) -> dict[str, dict[str, str]]:
    planned: dict[str, dict[str, str]] = {}
    for coordinator in contract["coordinators"]:
        for item in coordinator["planned_modules"]:
            name = item["module"]
            if name in planned:
                raise GateError(f"MOD-0.3 duplicate planned module: {name}")
            planned[name] = {"owner": coordinator["owner"], "layer": item["layer"]}
    return planned


def _normal_path(path: str) -> str:
    if not isinstance(path, str) or "\\" in path:
        raise GateError(f"module path is not normalized: {path!r}")
    parsed = PurePosixPath(path)
    if not path.startswith("srchybrid/") or parsed.is_absolute() or ".." in parsed.parts or "." in parsed.parts:
        raise GateError(f"module path escapes srchybrid: {path}")
    if parsed.suffix.lower() not in CODE_SUFFIXES:
        raise GateError(f"module path is not C/C++ code: {path}")
    return parsed.as_posix()


def _normal_repo_path(path: str) -> str | None:
    if not isinstance(path, str) or "\\" in path:
        return None
    parsed = PurePosixPath(path)
    if parsed.is_absolute():
        return None
    parts: list[str] = []
    for part in parsed.parts:
        if part in {"", "."}:
            continue
        if part == "..":
            if not parts:
                return None
            parts.pop()
        else:
            parts.append(part)
    return "/".join(parts) if parts else None


def _normal_include(include: str) -> str:
    return include.replace("\\", "/")


def _is_excluded_repo_path(path: str) -> bool:
    return any(part.casefold() in EXCLUDED_REPO_PARTS for part in PurePosixPath(path).parts)


def _normal_doc_path(path: str) -> str:
    if not isinstance(path, str) or "\\" in path:
        raise GateError(f"ADR path is not normalized: {path!r}")
    parsed = PurePosixPath(path)
    if parsed.is_absolute() or ".." in parsed.parts or "." in parsed.parts or parsed.suffix.lower() != ".md":
        raise GateError(f"ADR path invalid: {path}")
    return parsed.as_posix()


def validate_config(
    config: dict[str, Any], contract: dict[str, Any], adr_overrides: set[str] | None = None,
) -> None:
    _require_keys(config, {
        "schema", "gate_id", "status", "scope", "baseline_commit", "coordinator_files",
        "final_limits", "module_policy", "module_catalog", "approved_non_module_code",
        "slice_evidence", "mod03_contract", "slice_rule",
    }, "MOD-0.4 baseline")
    if config["schema"] != "ese.mod04.architecture-gate-baseline/v1":
        raise GateError("MOD-0.4 baseline schema drift")
    if config["gate_id"] != "urn:emule:architecture:mod-0.4:architecture-gate:v1":
        raise GateError("MOD-0.4 gate_id drift")
    if config["status"] != "PASS":
        raise GateError("MOD-0.4 status must be PASS")
    if config["baseline_commit"] != BASELINE_COMMIT:
        raise GateError("baseline_commit drift")
    if config["scope"] != EXPECTED_SCOPE:
        raise GateError("baseline scope drift")
    if config["slice_rule"] != EXPECTED_SLICE_RULE:
        raise GateError("slice_rule drift")
    if config["final_limits"] != EXPECTED_FINAL_LIMITS:
        raise GateError("final limit activation policy drift")
    if config["module_policy"] != EXPECTED_MODULE_POLICY:
        raise GateError("module size/dependency policy drift")
    rows = config["coordinator_files"]
    if not isinstance(rows, list) or [row.get("path") for row in rows] != [row["path"] for row in EXPECTED_COORDINATORS]:
        raise GateError("coordinator baseline path/order drift")
    for actual, expected in zip(rows, EXPECTED_COORDINATORS):
        if actual.get("path") != expected["path"]:
            raise GateError("coordinator baseline path/order drift")
        metric_keys = {"coordinator", "path", "kind", "baseline_loc_physical", "baseline_sha256"}
        if {key: actual.get(key) for key in metric_keys} != {key: expected[key] for key in metric_keys}:
            raise GateError(f"coordinator baseline metric drift: {expected['path']}")
        final_keys = set(expected) - metric_keys
        if set(actual) != set(expected) or {key: actual.get(key) for key in final_keys} != {key: expected[key] for key in final_keys}:
            raise GateError(f"coordinator final limit drift: {expected['path']}")
    if config["mod03_contract"] != {
        "path": "docs/architecture/mod03_ownership_layering_contract_v1.json",
        "edge_policy": "deny_unlisted", "planned_module_count": 30,
    }:
        raise GateError("MOD-0.3 binding drift")
    if len(_planned_modules(contract)) != 30 or contract["layer_model"]["edge_policy"] != "deny_unlisted":
        raise GateError("MOD-0.3 deny_unlisted binding drift")
    _require_keys(config["module_catalog"], {"state", "entries"}, "module_catalog")
    if config["module_catalog"]["state"] not in {"NO_EXTRACTED_MODULES_DECLARED", "EXTRACTION_ACTIVE"}:
        raise GateError("module_catalog state invalid")
    if not isinstance(config["module_catalog"]["entries"], list):
        raise GateError("module_catalog entries must be a list")
    if not isinstance(config["approved_non_module_code"], list):
        raise GateError("approved_non_module_code must be a list")
    approved_paths: set[str] = set()
    for item in config["approved_non_module_code"]:
        _require_keys(item, {"path", "reason", "adr"}, "approved_non_module_code entry")
        normalized = _normal_path(item["path"])
        if normalized in approved_paths:
            raise GateError(f"approved_non_module_code duplicate path: {normalized}")
        approved_paths.add(normalized)
        if not isinstance(item["reason"], str) or not isinstance(item["adr"], str) or not item["reason"] or not item["adr"]:
            raise GateError(f"approved_non_module_code reason/ADR missing: {item['path']}")
        adr = _normal_doc_path(item["adr"])
        if adr_overrides is None and not (ROOT / adr).is_file():
            raise GateError(f"approved_non_module_code ADR unavailable: {adr}")
        if adr_overrides is not None and adr not in adr_overrides and not (ROOT / adr).is_file():
            raise GateError(f"approved_non_module_code ADR unavailable: {adr}")
    _require_keys(config["slice_evidence"], {"state", "entries"}, "slice_evidence")
    if config["slice_evidence"]["state"] not in {"NO_EXTRACTION", "EXTRACTION_ACTIVE"} or not isinstance(config["slice_evidence"]["entries"], list):
        raise GateError("slice_evidence state invalid")


def validate_baseline_blobs(config: dict[str, Any]) -> None:
    for item in config["coordinator_files"]:
        raw = git_blob(config["baseline_commit"], item["path"])
        if sha256(raw) != item["baseline_sha256"]:
            raise GateError(f"baseline SHA256 mismatch: {item['path']}")
        if loc_physical(raw) != item["baseline_loc_physical"]:
            raise GateError(f"baseline LOC mismatch: {item['path']}")


def _read_worktree(path: str, overrides: dict[str, bytes] | None) -> bytes:
    if overrides is not None and path in overrides:
        return overrides[path]
    try:
        return (ROOT / path).read_bytes()
    except FileNotFoundError as exc:
        raise GateError(f"required source missing: {path}") from exc


def validate_coordinator_growth(config: dict[str, Any], overrides: dict[str, bytes] | None) -> int:
    reduction = 0
    for item in config["coordinator_files"]:
        current = loc_physical(_read_worktree(item["path"], overrides))
        baseline = item["baseline_loc_physical"]
        if current > baseline:
            raise GateError(
                f"coordinator LOC grew over baseline: {item['path']} baseline={baseline} current={current}"
            )
        reduction += baseline - current
    return reduction


def _entry_map(config: dict[str, Any], contract: dict[str, Any]) -> dict[str, dict[str, Any]]:
    planned = _planned_modules(contract)
    entries: dict[str, dict[str, Any]] = {}
    for entry in config["module_catalog"]["entries"]:
        _require_keys(entry, {
            "name", "owner", "layer", "implementation_files", "interface_files",
            "declared_direct_dependencies",
        }, "module catalog entry")
        name = entry["name"]
        if name in entries:
            raise GateError(f"duplicate module catalog entry: {name}")
        if name not in planned:
            raise GateError(f"module not planned by MOD-0.3: {name}")
        if (entry["owner"], entry["layer"]) != (planned[name]["owner"], planned[name]["layer"]):
            raise GateError(f"module owner/layer drift from MOD-0.3: {name}")
        if not isinstance(entry["implementation_files"], list) or not entry["implementation_files"]:
            raise GateError(f"module implementation_files must be non-empty: {name}")
        if not isinstance(entry["interface_files"], list) or not isinstance(entry["declared_direct_dependencies"], list):
            raise GateError(f"module catalog lists invalid: {name}")
        files = entry["implementation_files"] + entry["interface_files"]
        normalized = [_normal_path(path) for path in files]
        if len(normalized) != len(set(normalized)):
            raise GateError(f"module catalog files invalid: {name}")
        if not all(PurePosixPath(path).suffix.lower() in SOURCE_SUFFIXES for path in entry["implementation_files"]):
            raise GateError(f"module implementation file invalid: {name}")
        deps = entry["declared_direct_dependencies"]
        if any(not isinstance(dep, str) or not dep for dep in deps):
            raise GateError(f"declared direct dependency empty: {name}")
        if len(deps) != len(set(deps)):
            raise GateError(f"declared direct dependency duplicate: {name}")
        if name in deps:
            raise GateError(f"declared direct dependency self: {name}")
        entries[name] = entry
    expected_state = "EXTRACTION_ACTIVE" if entries else "NO_EXTRACTED_MODULES_DECLARED"
    if config["module_catalog"]["state"] != expected_state:
        raise GateError("module_catalog state does not match entries")
    for name, entry in entries.items():
        for dependency in entry["declared_direct_dependencies"]:
            if dependency not in entries:
                raise GateError(f"declared direct dependency uncatalogued: {name} -> {dependency}")
    return entries


def _module_file_owner(entries: dict[str, dict[str, Any]]) -> dict[str, str]:
    owners: dict[str, str] = {}
    for name, entry in entries.items():
        for path in entry["implementation_files"] + entry["interface_files"]:
            normalized = _normal_path(path)
            if normalized in owners:
                raise GateError(f"module file belongs to more than one module: {normalized}")
            owners[normalized] = name
    return owners


def _name_status_destinations(line: str) -> list[str]:
    """Return only newly materialized paths from Git --name-status output."""
    fields = line.split("\t")
    status = fields[0] if fields else ""
    if status.startswith(("R", "C")):
        return fields[2:3]
    if status.startswith("A"):
        return fields[1:2]
    return []


def _baseline_new_or_renamed_code(
    discovery_overrides: set[str] | None, name_status_overrides: list[str] | None = None,
) -> set[str]:
    if discovery_overrides is not None:
        return {_normal_path(path) for path in discovery_overrides}
    changed = (
        "\n".join(name_status_overrides)
        if name_status_overrides is not None
        else _run_git(["diff", "--name-status", "--find-renames", BASELINE_COMMIT, "--", "srchybrid"], text=True)
    )
    paths: set[str] = set()
    for line in changed.splitlines():
        for path in _name_status_destinations(line):
            if path.startswith("srchybrid/") and PurePosixPath(path).suffix.lower() in CODE_SUFFIXES:
                paths.add(_normal_path(path))
    untracked = _run_git(["ls-files", "--others", "--exclude-standard", "--", "srchybrid"], text=True)
    for path in untracked.splitlines():
        if PurePosixPath(path).suffix.lower() in CODE_SUFFIXES:
            paths.add(_normal_path(path))
    return paths


def _first_party_companion_paths(
    contract: dict[str, Any], name_status_overrides: list[str] | None,
    untracked_overrides: set[str] | None,
) -> set[str]:
    planned = _planned_modules(contract)
    changed = (
        "\n".join(name_status_overrides)
        if name_status_overrides is not None
        else _run_git(["diff", "--name-status", "--find-renames", BASELINE_COMMIT], text=True)
    )
    candidates: set[str] = set()
    for line in changed.splitlines():
        for path in _name_status_destinations(line):
            normalized = _normal_repo_path(path)
            if normalized and PurePosixPath(normalized).suffix.lower() in CODE_SUFFIXES:
                candidates.add(normalized)
    untracked = untracked_overrides
    if untracked is None:
        untracked = set(_run_git(["ls-files", "--others", "--exclude-standard"], text=True).splitlines())
    for path in untracked:
        normalized = _normal_repo_path(path)
        if normalized and PurePosixPath(normalized).suffix.lower() in CODE_SUFFIXES:
            candidates.add(normalized)
    companions: set[str] = set()
    for path in candidates:
        if path.startswith("srchybrid/") or _is_excluded_repo_path(path):
            continue
        if _companion_owner(path, planned):
            companions.add(path)
    return companions


def _companion_owner(path: str, planned: dict[str, dict[str, str]]) -> str | None:
    pure = PurePosixPath(path)
    matches = [
        name for name in planned
        if pure.stem.casefold().startswith(name.casefold())
        or any(part.casefold() == name.casefold() for part in pure.parts[:-1])
    ]
    if len(matches) > 1:
        raise GateError(f"ambiguous planned module companion: {path}")
    return matches[0] if matches else None


def validate_discovery(
    config: dict[str, Any], contract: dict[str, Any], entries: dict[str, dict[str, Any]],
    overrides: dict[str, bytes] | None, discovery_overrides: set[str] | None,
    name_status_overrides: list[str] | None, first_party_companion_overrides: set[str] | None,
) -> set[str]:
    file_owner = _module_file_owner(entries)
    allowed = {item["path"] for item in config["approved_non_module_code"]}
    overlap = set(file_owner) & allowed
    if overlap:
        raise GateError(f"approved_non_module_code overlaps module catalog: {sorted(overlap)[0]}")
    discovered = _baseline_new_or_renamed_code(discovery_overrides, name_status_overrides)
    planned = _planned_modules(contract)
    external_companions = _first_party_companion_paths(
        contract, name_status_overrides, first_party_companion_overrides,
    )
    if external_companions:
        path = sorted(external_companions)[0]
        raise GateError(f"planned module companion outside srchybrid: {path} expected={_companion_owner(path, planned)}")
    for path in discovered:
        if path not in file_owner and path not in allowed:
            raise GateError(f"new or renamed C/C++ file is uncatalogued: {path}")
        companion = _companion_owner(path, planned)
        if companion and file_owner.get(path) != companion:
            raise GateError(f"planned module companion uncatalogued: {path} expected={companion}")
    for path in file_owner:
        _read_worktree(path, overrides)
    for path in allowed:
        _read_worktree(path, overrides)
    return discovered


def _repo_code_paths(overrides: dict[str, bytes] | None, file_owner: dict[str, str]) -> set[str]:
    paths = set(file_owner)
    for path in ROOT.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in CODE_SUFFIXES:
            continue
        relative = path.relative_to(ROOT)
        if _is_excluded_repo_path(relative.as_posix()):
            continue
        paths.add(relative.as_posix())
    if overrides:
        for path in overrides:
            if PurePosixPath(path).suffix.lower() in CODE_SUFFIXES:
                normalized = _normal_repo_path(path)
                if normalized is not None:
                    paths.add(normalized)
    return paths


def _include_is_domain_concrete(include: str) -> bool:
    lower = include.casefold()
    name = PurePosixPath(include).name.casefold()
    return (
        any(hint in lower for hint in DOMAIN_CONCRETE_HINTS)
        or name.startswith("afx") and name.endswith(".h")
    )


def _include_is_pch(include: str) -> bool:
    return PurePosixPath(include).name.casefold() in PCH_HEADERS


def validate_approved_non_module_code(
    config: dict[str, Any], overrides: dict[str, bytes] | None,
) -> None:
    for item in config["approved_non_module_code"]:
        path = item["path"]
        raw = _read_worktree(path, overrides).decode("utf-8", errors="replace")
        if DOMAIN_CONCRETE_TYPE_RE.search(raw):
            raise GateError(f"approved non-module code concrete dependency forbidden: {path}")
        for quoted, angled in INCLUDE_RE.findall(raw):
            include = _normal_include(quoted or angled)
            if PurePosixPath(include).name.casefold() in {name.casefold() for name in COORDINATOR_HEADERS}:
                raise GateError(f"approved non-module code reverse coordinator include: {path} includes {include}")
            if _include_is_domain_concrete(include):
                raise GateError(f"approved non-module code concrete dependency forbidden: {path} includes {include}")


def _resolve_include(include: str, current: str, repo_paths: set[str]) -> str | None:
    include = _normal_include(include)
    current_parent = PurePosixPath(current).parent
    candidates = (
        _normal_repo_path((current_parent / include).as_posix()),
        _normal_repo_path(include),
        _normal_repo_path((PurePosixPath("srchybrid") / include).as_posix()),
    )
    by_casefold: dict[str, list[str]] = {}
    for path in repo_paths:
        by_casefold.setdefault(path.casefold(), []).append(path)
    for candidate in candidates:
        if candidate is not None:
            matches = by_casefold.get(candidate.casefold(), [])
            if len(matches) == 1:
                return matches[0]
            if len(matches) > 1:
                raise GateError(f"repo-local include casefold ambiguity: {include}")
    same_name = [
        path for path in repo_paths
        if PurePosixPath(path).name.casefold() == PurePosixPath(include).name.casefold()
    ]
    if len(same_name) > 1:
        raise GateError(f"repo-local include casefold ambiguity: {include}")
    return same_name[0] if same_name else None


def _include_escapes_repo(include: str, current: str) -> bool:
    include = _normal_include(include)
    return ".." in PurePosixPath(include).parts and _normal_repo_path(
        (PurePosixPath(current).parent / include).as_posix()
    ) is None


def _find_cycle(graph: dict[str, set[str]]) -> list[str] | None:
    visiting: set[str] = set()
    visited: set[str] = set()
    stack: list[str] = []

    def visit(node: str) -> list[str] | None:
        if node in visiting:
            return stack[stack.index(node):] + [node]
        if node in visited:
            return None
        visiting.add(node)
        stack.append(node)
        for target in sorted(graph[node]):
            result = visit(target)
            if result:
                return result
        stack.pop()
        visiting.remove(node)
        visited.add(node)
        return None

    for node in sorted(graph):
        result = visit(node)
        if result:
            return result
    return None


def validate_modules(
    config: dict[str, Any], contract: dict[str, Any], entries: dict[str, dict[str, Any]],
    overrides: dict[str, bytes] | None,
) -> list[str]:
    if not entries:
        return ["NO_EXTRACTED_MODULES_DISCOVERED"]
    file_owner = _module_file_owner(entries)
    repo_paths = _repo_code_paths(overrides, file_owner)
    graph = {name: set() for name in entries}
    warnings: list[str] = []
    allowed_edges = {tuple(edge) for edge in contract["layer_model"]["allowed_edges"]}
    for name, entry in entries.items():
        code_files = entry["implementation_files"] + entry["interface_files"]
        module_loc = sum(loc_physical(_read_worktree(path, overrides)) for path in code_files)
        if module_loc > config["module_policy"]["hard_stop_implementation_loc"]:
            raise GateError(f"STOP module code exceeds 1500 LOC: {name} current={module_loc}")
        if not (config["module_policy"]["recommended_implementation_loc_min"] <= module_loc <= config["module_policy"]["recommended_implementation_loc_max"]):
            warnings.append(f"WARN module LOC outside recommended 300-1200: {name} current={module_loc}")
        module_dependencies: set[str] = set()
        direct_targets: set[str] = set()
        for path in code_files:
            raw = _read_worktree(path, overrides).decode("utf-8", errors="replace")
            is_public_header = path in entry["interface_files"]
            if entry["layer"] == "domain_state" and DOMAIN_CONCRETE_TYPE_RE.search(raw):
                raise GateError(f"domain concrete dependency forbidden: {name} uses concrete UI/socket/Kad/Win32 type")
            for quoted, angled in INCLUDE_RE.findall(raw):
                include = _normal_include(quoted or angled)
                include_name = PurePosixPath(include).name
                if _include_escapes_repo(include, path):
                    raise GateError(f"repo-local include escapes repository: {name} includes {include}")
                if include_name.casefold() in {header.casefold() for header in COORDINATOR_HEADERS}:
                    raise GateError(f"reverse coordinator include: {name} includes {include}")
                if entry["layer"] == "domain_state" and _include_is_domain_concrete(include):
                    raise GateError(f"domain concrete dependency forbidden: {name} includes {include}")
                if entry["layer"] == "domain_state" and is_public_header and _include_is_pch(include):
                    raise GateError(f"domain public header precompiled include forbidden: {name} includes {include}")
                target = _resolve_include(include, path, repo_paths)
                if target is None:
                    continue
                target_module = file_owner.get(target)
                if target_module and target_module != name:
                    module_dependencies.add(target_module)
                    direct_targets.add(f"module:{target_module}")
                elif target_module != name:
                    direct_targets.add(f"repo:{target}")
        if len(direct_targets) > config["module_policy"]["max_direct_dependencies"]:
            raise GateError(f"direct dependency count exceeds 8: {name} current={len(direct_targets)}")
        if set(entry["declared_direct_dependencies"]) != module_dependencies:
            raise GateError(f"declared direct dependency drift: {name}")
        graph[name] = module_dependencies
    cycle = _find_cycle(graph)
    if cycle:
        raise GateError("dependency SCC cycle: " + " -> ".join(cycle))
    for source, targets in graph.items():
        for target in targets:
            edge = (entries[source]["layer"], entries[target]["layer"])
            if edge not in allowed_edges:
                raise GateError(f"deny_unlisted layer dependency: {source}({edge[0]}) -> {target}({edge[1]})")
    return warnings


def _head_commit() -> str:
    return _run_git(["rev-parse", "HEAD"], text=True).strip()


def _is_ancestor(base: str, head: str) -> bool:
    try:
        completed = subprocess.run(
            ["git", "merge-base", "--is-ancestor", base, head],
            cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False,
        )
    except OSError as exc:
        raise GateError("slice ancestry check unavailable") from exc
    return completed.returncode == 0


def _git_numstat(base_commit: str, path: str) -> tuple[int, int]:
    output = _run_git(["diff", "--numstat", base_commit, "--", path], text=True).strip()
    if not output:
        return 0, 0
    fields = output.splitlines()[-1].split("\t")
    if len(fields) < 2 or not fields[0].isdigit() or not fields[1].isdigit():
        raise GateError(f"slice numstat unavailable: {path}")
    return int(fields[0]), int(fields[1])


def validate_slice_evidence(
    config: dict[str, Any], entries: dict[str, dict[str, Any]],
    diff_overrides: dict[str, tuple[int, int]] | None,
    ancestry_overrides: dict[str, bool] | None,
) -> list[str]:
    evidence = config["slice_evidence"]
    if not entries:
        if evidence != {"state": "NO_EXTRACTION", "entries": []}:
            raise GateError("slice_evidence must declare NO_EXTRACTION before extraction")
        return []
    if evidence["state"] != "EXTRACTION_ACTIVE":
        raise GateError("slice_evidence must be active with catalogued modules")
    by_module: dict[str, dict[str, Any]] = {}
    head = _head_commit()
    for item in evidence["entries"]:
        _require_keys(item, {"module", "slice_base_commit", "source_coordinator"}, "slice evidence entry")
        module = item["module"]
        if module in by_module:
            raise GateError(f"duplicate slice evidence entry: {module}")
        if module not in entries:
            raise GateError(f"slice evidence names uncatalogued module: {module}")
        if not re.fullmatch(r"[0-9a-f]{40}", item["slice_base_commit"]):
            raise GateError(f"slice base commit invalid: {module}")
        expected_source = OWNER_SOURCE[entries[module]["owner"]]
        if item["source_coordinator"] != expected_source:
            raise GateError(f"slice source coordinator owner mismatch: {module}")
        base = item["slice_base_commit"]
        if base == head:
            raise GateError(f"slice base commit must precede HEAD: {module}")
        ancestor = ancestry_overrides[base] if ancestry_overrides is not None and base in ancestry_overrides else _is_ancestor(base, head)
        if not ancestor:
            raise GateError(f"slice base commit is not an ancestor of HEAD: {module}")
        by_module[module] = item
    if set(by_module) != set(entries):
        raise GateError("slice evidence/catalog module set drift")
    messages: list[str] = []
    for module, item in by_module.items():
        added, removed = (
            diff_overrides[module] if diff_overrides is not None and module in diff_overrides
            else _git_numstat(item["slice_base_commit"], item["source_coordinator"])
        )
        if removed <= added:
            raise GateError(f"slice coordinator shrink insufficient: {module} added={added} removed={removed}")
        messages.append(f"slice {module}: coordinator added={added} removed={removed}")
    return messages


def validate(
    config: dict[str, Any], contract: dict[str, Any], overrides: dict[str, bytes] | None = None,
    check_git_baseline: bool = True, slice_diff_overrides: dict[str, tuple[int, int]] | None = None,
    discovery_overrides: set[str] | None = None, ancestry_overrides: dict[str, bool] | None = None,
    discovery_status_overrides: list[str] | None = None, adr_overrides: set[str] | None = None,
    first_party_companion_overrides: set[str] | None = None,
) -> list[str]:
    validate_config(config, contract, adr_overrides)
    if check_git_baseline:
        validate_baseline_blobs(config)
    reduction = validate_coordinator_growth(config, overrides)
    entries = _entry_map(config, contract)
    validate_discovery(
        config, contract, entries, overrides, discovery_overrides, discovery_status_overrides,
        first_party_companion_overrides,
    )
    validate_approved_non_module_code(config, overrides)
    messages = validate_modules(config, contract, entries, overrides)
    messages.extend(validate_slice_evidence(config, entries, slice_diff_overrides, ancestry_overrides))
    messages.append(f"coordinator reduction since MOD-0.4 baseline={reduction}")
    return messages


def _fixture_config(base: dict[str, Any], entries: list[dict[str, Any]]) -> dict[str, Any]:
    config = copy.deepcopy(base)
    config["module_catalog"] = {
        "state": "EXTRACTION_ACTIVE" if entries else "NO_EXTRACTED_MODULES_DECLARED",
        "entries": entries,
    }
    config["slice_evidence"] = {
        "state": "EXTRACTION_ACTIVE" if entries else "NO_EXTRACTION",
        "entries": [{
            "module": entry["name"], "slice_base_commit": _run_git(["rev-parse", f"{BASELINE_COMMIT}^"], text=True).strip(),
            "source_coordinator": OWNER_SOURCE[entry["owner"]],
        } for entry in entries],
    }
    return config


def _entry(contract: dict[str, Any], name: str, implementation: list[str], deps: list[str], interface: list[str] | None = None) -> dict[str, Any]:
    planned = _planned_modules(contract)[name]
    return {
        "name": name, "owner": planned["owner"], "layer": planned["layer"],
        "implementation_files": implementation, "interface_files": interface or [],
        "declared_direct_dependencies": deps,
    }


def _expect_invalid(
    name: str, config: dict[str, Any], contract: dict[str, Any], expected: str,
    overrides: dict[str, bytes] | None = None, discovery: set[str] | None = None,
    diffs: dict[str, tuple[int, int]] | None = None, ancestry: dict[str, bool] | None = None,
    statuses: list[str] | None = None, adrs: set[str] | None = None,
    first_party_companions: set[str] | None = None,
) -> None:
    try:
        validate(
            config, contract, overrides=overrides, check_git_baseline=False,
            discovery_overrides=discovery, slice_diff_overrides=diffs,
            ancestry_overrides=ancestry, discovery_status_overrides=statuses,
            adr_overrides=adrs, first_party_companion_overrides=first_party_companions,
        )
    except GateError as exc:
        if expected not in str(exc):
            raise GateError(f"negative fixture {name} wrong reason: {exc}") from exc
    else:
        raise GateError(f"negative fixture {name} unexpectedly passed")


def run_negative_fixtures(base: dict[str, Any], contract: dict[str, Any]) -> None:
    first = base["coordinator_files"][0]["path"]
    first_raw = _read_worktree(first, None)
    first_baseline = base["coordinator_files"][0]["baseline_loc_physical"]
    lines_to_exceed_baseline = first_baseline - loc_physical(first_raw) + 1
    _expect_invalid(
        "coordinator-growth", base, contract, "coordinator LOC grew over baseline",
        overrides={first: first_raw + (b"// growth fixture\n" * lines_to_exceed_baseline)},
    )
    for field, expected in (
        ("baseline_commit", "baseline_commit drift"),
        ("scope", "baseline scope drift"),
        ("slice_rule", "slice_rule drift"),
    ):
        mutated = copy.deepcopy(base)
        mutated[field] = "drift"
        _expect_invalid(f"frozen-{field}", mutated, contract, expected)
    metric = copy.deepcopy(base)
    metric["coordinator_files"][0]["baseline_loc_physical"] += 1
    _expect_invalid("frozen-metric", metric, contract, "coordinator baseline metric drift")
    path = copy.deepcopy(base)
    path["coordinator_files"][0]["path"] = "srchybrid/Other.cpp"
    _expect_invalid("frozen-path", path, contract, "coordinator baseline path/order drift")
    limit = copy.deepcopy(base)
    limit["coordinator_files"][0]["final_hard_stop_loc"] += 1
    _expect_invalid("frozen-limit", limit, contract, "coordinator final limit drift")

    oversized = _fixture_config(base, [
        _entry(contract, "LiveTunnelFraming", ["srchybrid/LiveTunnelFraming.cpp"], [], ["srchybrid/LiveTunnelFraming.h"]),
    ])
    _expect_invalid(
        "header-counts-to-loc", oversized, contract, "STOP module code exceeds 1500 LOC",
        overrides={"srchybrid/LiveTunnelFraming.cpp": b"x\n" * 2, "srchybrid/LiveTunnelFraming.h": b"x\n" * 1499},
        discovery={"srchybrid/LiveTunnelFraming.cpp", "srchybrid/LiveTunnelFraming.h"},
    )
    header_only = _fixture_config(base, [
        _entry(contract, "LiveTunnelFraming", [], [], ["srchybrid/LiveTunnelFraming.h"]),
    ])
    _expect_invalid(
        "header-only", header_only, contract, "module implementation_files must be non-empty",
        overrides={"srchybrid/LiveTunnelFraming.h": b""},
        discovery={"srchybrid/LiveTunnelFraming.h"},
    )
    companion = _fixture_config(base, [])
    companion["approved_non_module_code"] = [{
        "path": "srchybrid/LiveTunnelFraming/Codec.h", "reason": "fixture",
        "adr": "docs/architecture/ADR_MOD03_OWNERSHIP_AND_LAYERING_V1.md",
    }]
    _expect_invalid(
        "companion-uncatalogued", companion, contract, "planned module companion uncatalogued",
        overrides={"srchybrid/LiveTunnelFraming/Codec.h": b""},
        discovery={"srchybrid/LiveTunnelFraming/Codec.h"},
    )
    uncatalogued = _fixture_config(base, [])
    _expect_invalid(
        "new-uncatalogued", uncatalogued, contract, "new or renamed C/C++ file is uncatalogued",
        overrides={"srchybrid/NewHelper.h": b""}, discovery={"srchybrid/NewHelper.h"},
    )
    for status in ("M\tsrchybrid/LiveTunnel.cpp", "D\tsrchybrid/DeletedFuture.cpp"):
        validate(base, contract, check_git_baseline=False, discovery_status_overrides=[status])
    _expect_invalid(
        "added-uncatalogued", _fixture_config(base, []), contract,
        "new or renamed C/C++ file is uncatalogued",
        statuses=["A\tsrchybrid/AddedFuture.cpp"],
    )
    _expect_invalid(
        "added-inline-uncatalogued", _fixture_config(base, []), contract,
        "new or renamed C/C++ file is uncatalogued",
        statuses=["A\tsrchybrid/AddedFuture.inl"],
    )
    _expect_invalid(
        "untracked-template-uncatalogued", _fixture_config(base, []), contract,
        "new or renamed C/C++ file is uncatalogued",
        overrides={"srchybrid/UntrackedFuture.tpp": b""},
        discovery={"srchybrid/UntrackedFuture.tpp"},
    )
    _expect_invalid(
        "renamed-destination-uncatalogued", _fixture_config(base, []), contract,
        "new or renamed C/C++ file is uncatalogued",
        statuses=["R100\tsrchybrid/Old.cpp\tsrchybrid/RenamedFuture.cpp"],
    )
    _expect_invalid(
        "copied-destination-uncatalogued", _fixture_config(base, []), contract,
        "new or renamed C/C++ file is uncatalogued",
        statuses=["C100\tsrchybrid/Old.cpp\tsrchybrid/CopiedFuture.cpp"],
    )
    _expect_invalid(
        "first-party-companion-added", _fixture_config(base, []), contract,
        "planned module companion outside srchybrid",
        statuses=["A\tlibreach/src/LiveTunnelFramingImpl.cpp"],
    )
    _expect_invalid(
        "first-party-companion-copied-casefold", _fixture_config(base, []), contract,
        "planned module companion outside srchybrid",
        statuses=["C100\tlibreach/src/Old.cpp\tlibreach/src/livetunnelframingimpl.cpp"],
    )
    _expect_invalid(
        "first-party-companion-untracked", _fixture_config(base, []), contract,
        "planned module companion outside srchybrid",
        first_party_companions={"librelaycore/src/livetunnelframing/Codec.tpp"},
    )
    validate(
        base, contract, check_git_baseline=False,
        discovery_status_overrides=["A\tlibreach/src/GenericFirstPartyHelper.cpp"],
        first_party_companion_overrides=set(),
    )
    bad_adr = _fixture_config(base, [])
    bad_adr["approved_non_module_code"] = [{
        "path": "srchybrid/NewHelper.h", "reason": "fixture", "adr": "docs/architecture/MISSING.md",
    }]
    _expect_invalid("allowlist-adr", bad_adr, contract, "approved_non_module_code ADR unavailable")
    allow_reverse = _fixture_config(base, [])
    allow_reverse["approved_non_module_code"] = [{
        "path": "srchybrid/NewHelper.h", "reason": "fixture",
        "adr": "docs/architecture/ADR_MOD03_OWNERSHIP_AND_LAYERING_V1.md",
    }]
    _expect_invalid(
        "allowlist-reverse", allow_reverse, contract,
        "approved non-module code reverse coordinator include",
        overrides={"srchybrid/NewHelper.h": b"#include <LiveTunnel.h>\n"},
        discovery={"srchybrid/NewHelper.h"},
    )
    overlap = _fixture_config(base, [
        _entry(contract, "LiveTunnelFraming", ["srchybrid/LiveTunnelFraming.cpp"], []),
    ])
    overlap["approved_non_module_code"] = [{
        "path": "srchybrid/LiveTunnelFraming.cpp", "reason": "fixture",
        "adr": "docs/architecture/ADR_MOD03_OWNERSHIP_AND_LAYERING_V1.md",
    }]
    _expect_invalid(
        "allowlist-overlap", overlap, contract, "approved_non_module_code overlaps module catalog",
        overrides={"srchybrid/LiveTunnelFraming.cpp": b""},
        discovery={"srchybrid/LiveTunnelFraming.cpp"},
    )

    cycle = _fixture_config(base, [
        _entry(contract, "LiveTunnelFraming", ["srchybrid/LiveTunnelFraming.cpp"], ["LiveTunnelMetrics"]),
        _entry(contract, "LiveTunnelMetrics", ["srchybrid/LiveTunnelMetrics.cpp"], ["LiveTunnelFraming"]),
    ])
    _expect_invalid(
        "angle-cycle", cycle, contract, "dependency SCC cycle",
        overrides={
            "srchybrid/LiveTunnelFraming.cpp": b"#include <LiveTunnelMetrics.cpp>\n",
            "srchybrid/LiveTunnelMetrics.cpp": b"#include <LiveTunnelFraming.cpp>\n",
        },
        discovery={"srchybrid/LiveTunnelFraming.cpp", "srchybrid/LiveTunnelMetrics.cpp"},
    )
    reverse = _fixture_config(base, [
        _entry(contract, "LiveTunnelPending", ["srchybrid/LiveTunnelPending.cpp"], []),
    ])
    _expect_invalid(
        "angle-reverse", reverse, contract, "reverse coordinator include",
        overrides={"srchybrid/LiveTunnelPending.cpp": b"#include <LiveTunnel.h>\n"},
        discovery={"srchybrid/LiveTunnelPending.cpp"},
    )
    windows_reverse = _fixture_config(base, [
        _entry(contract, "LiveTunnelPending", ["srchybrid/LiveTunnelPending.cpp"], []),
    ])
    _expect_invalid(
        "windows-backslash-reverse", windows_reverse, contract, "reverse coordinator include",
        overrides={"srchybrid/LiveTunnelPending.cpp": b'#include "subdir\\\\..\\\\LiveTunnel.h"\n'},
        discovery={"srchybrid/LiveTunnelPending.cpp"},
    )
    lowercase_reverse = _fixture_config(base, [
        _entry(contract, "LiveTunnelPending", ["srchybrid/LiveTunnelPending.cpp"], []),
    ])
    _expect_invalid(
        "windows-case-reverse", lowercase_reverse, contract, "reverse coordinator include",
        overrides={"srchybrid/LiveTunnelPending.cpp": b"#include <livetunnel.h>\n"},
        discovery={"srchybrid/LiveTunnelPending.cpp"},
    )
    casing_cycle = _fixture_config(base, [
        _entry(contract, "LiveTunnelFraming", ["srchybrid/LiveTunnelFraming.cpp"], ["LiveTunnelMetrics"]),
        _entry(contract, "LiveTunnelMetrics", ["srchybrid/LiveTunnelMetrics.cpp"], ["LiveTunnelFraming"]),
    ])
    _expect_invalid(
        "windows-case-backslash-dependency", casing_cycle, contract, "dependency SCC cycle",
        overrides={
            "srchybrid/LiveTunnelFraming.cpp": b'#include <subdir\\\\..\\\\livetunnelmetrics.cpp>\n',
            "srchybrid/LiveTunnelMetrics.cpp": b'#include <LIVETUNNELFRAMING.cpp>\n',
        },
        discovery={"srchybrid/LiveTunnelFraming.cpp", "srchybrid/LiveTunnelMetrics.cpp"},
    )
    layer = _fixture_config(base, [
        _entry(contract, "LiveCircuitHandshake", ["srchybrid/LiveCircuitHandshake.cpp"], ["LiveTunnelMetrics"]),
        _entry(contract, "LiveTunnelMetrics", ["srchybrid/LiveTunnelMetrics.cpp"], []),
    ])
    _expect_invalid(
        "deny-unlisted", layer, contract, "deny_unlisted layer dependency",
        overrides={
            "srchybrid/LiveCircuitHandshake.cpp": b"#include <LiveTunnelMetrics.cpp>\n",
            "srchybrid/LiveTunnelMetrics.cpp": b"",
        },
        discovery={"srchybrid/LiveCircuitHandshake.cpp", "srchybrid/LiveTunnelMetrics.cpp"},
    )

    domain = _fixture_config(base, [
        _entry(contract, "LiveTunnelPending", ["srchybrid/LiveTunnelPending.cpp"], []),
    ])
    _expect_invalid(
        "domain-concrete", domain, contract, "domain concrete dependency forbidden",
        overrides={"srchybrid/LiveTunnelPending.cpp": b"CClientReqSocket socket;\n"},
        discovery={"srchybrid/LiveTunnelPending.cpp"},
    )
    windows_domain = _fixture_config(base, [
        _entry(contract, "LiveTunnelPending", ["srchybrid/LiveTunnelPending.cpp"], []),
    ])
    _expect_invalid(
        "domain-windows", windows_domain, contract, "domain concrete dependency forbidden",
        overrides={"srchybrid/LiveTunnelPending.cpp": b"#include <windows.h>\nPROCESS_INFORMATION pi;\n"},
        discovery={"srchybrid/LiveTunnelPending.cpp"},
    )
    mfc_domain = _fixture_config(base, [
        _entry(contract, "LiveTunnelPending", ["srchybrid/LiveTunnelPending.cpp"], []),
    ])
    _expect_invalid(
        "domain-mfc-winsock", mfc_domain, contract, "domain concrete dependency forbidden",
        overrides={"srchybrid/LiveTunnelPending.cpp": b'#include "stdafx.h"\nCWnd* w; SOCKET s; CStdioFile f;\n'},
        discovery={"srchybrid/LiveTunnelPending.cpp"},
    )
    pch_header = _fixture_config(base, [
        _entry(
            contract, "LiveTunnelPending", ["srchybrid/LiveTunnelPending.cpp"], [],
            ["srchybrid/LiveTunnelPending.h"],
        ),
    ])
    _expect_invalid(
        "domain-public-pch", pch_header, contract, "domain public header precompiled include forbidden",
        overrides={
            "srchybrid/LiveTunnelPending.cpp": b"",
            "srchybrid/LiveTunnelPending.h": b'#include "stdafx.h"\n',
        },
        discovery={"srchybrid/LiveTunnelPending.cpp", "srchybrid/LiveTunnelPending.h"},
    )
    dep_names = [
        "LiveTunnelFraming", "LiveCircuitRegistry", "WebRequestParser",
        "LiveRelayDispatcher", "LiveExitServices", "LiveTunnelScheduler",
        "LiveTunnelPeerState", "LiveTunnelKadBridge", "LiveTunnelMetrics",
    ]
    entries = [_entry(contract, "LiveCircuitHandshake", ["srchybrid/LiveCircuitHandshake.cpp"], dep_names)]
    entries.extend(_entry(contract, item, [f"srchybrid/{item}.cpp"], []) for item in dep_names)
    too_many = _fixture_config(base, entries)
    dep_overrides = {
        "srchybrid/LiveCircuitHandshake.cpp": "".join(f"#include <{item}.cpp>\n" for item in dep_names).encode(),
    }
    dep_overrides.update({f"srchybrid/{item}.cpp": b"" for item in dep_names})
    _expect_invalid(
        "dependency-limit", too_many, contract, "direct dependency count exceeds 8",
        overrides=dep_overrides, discovery=set(dep_overrides),
    )
    repo_limit = _fixture_config(base, [
        _entry(contract, "LiveTunnelFraming", ["srchybrid/LiveTunnelFraming.cpp"], []),
    ])
    repo_targets = [f"srchybrid/OtherLocal{i}.h" for i in range(9)]
    repo_overrides = {
        "srchybrid/LiveTunnelFraming.cpp": "".join(
            f'#include <OtherLocal{i}.h>\n' for i in range(9)
        ).encode(),
    }
    repo_overrides.update({target: b"" for target in repo_targets})
    _expect_invalid(
        "repo-local-dependency-limit", repo_limit, contract, "direct dependency count exceeds 8",
        overrides=repo_overrides, discovery={"srchybrid/LiveTunnelFraming.cpp"},
    )
    first_party_headers = [
        "libreach/include/reach/reach.h",
        "libreach/include/reach/reach_cascade.h",
        "libreach/include/reach/reach_codec.h",
        "libreach/include/reach/reach_types.h",
        "libreach/src/reach_engine.h",
        "librelayclient/include/relayclient/relay_client.h",
        "librelayclient/include/relayclient/relay_wss_transport.h",
        "librelaycore/include/relay/epr_lease.h",
        "librelaycore/include/relay/kad6_authority_adapter.h",
    ]
    first_party = _fixture_config(base, [
        _entry(contract, "LiveTunnelFraming", ["srchybrid/LiveTunnelFraming.cpp"], []),
    ])
    _expect_invalid(
        "first-party-dependency-limit", first_party, contract, "direct dependency count exceeds 8",
        overrides={
            "srchybrid/LiveTunnelFraming.cpp": "".join(
                f"#include <{path}>\n" for path in first_party_headers
            ).encode(),
        },
        discovery={"srchybrid/LiveTunnelFraming.cpp"},
    )
    relative_include = _fixture_config(base, [
        _entry(contract, "LiveTunnelFraming", ["srchybrid/LiveTunnelFraming.cpp"], []),
    ])
    validate(
        relative_include, contract,
        overrides={
            "srchybrid/LiveTunnelFraming.cpp": b'#include "../tools/shared.h"\n',
            "tools/shared.h": b"",
        },
        check_git_baseline=False, discovery_overrides={"srchybrid/LiveTunnelFraming.cpp"},
        slice_diff_overrides={"LiveTunnelFraming": (0, 1)},
    )
    escaped_include = _fixture_config(base, [
        _entry(contract, "LiveTunnelFraming", ["srchybrid/LiveTunnelFraming.cpp"], []),
    ])
    _expect_invalid(
        "include-escapes-repository", escaped_include, contract, "repo-local include escapes repository",
        overrides={"srchybrid/LiveTunnelFraming.cpp": b'#include "../../../../outside.h"\n'},
        discovery={"srchybrid/LiveTunnelFraming.cpp"},
    )
    allow_limit = _fixture_config(base, [
        _entry(contract, "LiveTunnelFraming", ["srchybrid/LiveTunnelFraming.cpp"], []),
    ])
    allow_paths = [f"srchybrid/ApprovedSupport{i}.h" for i in range(9)]
    allow_limit["approved_non_module_code"] = [{
        "path": path, "reason": "fixture",
        "adr": "docs/architecture/ADR_MOD03_OWNERSHIP_AND_LAYERING_V1.md",
    } for path in allow_paths]
    allow_overrides = {
        "srchybrid/LiveTunnelFraming.cpp": "".join(
            f'#include <ApprovedSupport{i}.h>\n' for i in range(9)
        ).encode(),
    }
    allow_overrides.update({path: b"" for path in allow_paths})
    _expect_invalid(
        "allowlist-counted-as-repo-local", allow_limit, contract, "direct dependency count exceeds 8",
        overrides=allow_overrides, discovery={"srchybrid/LiveTunnelFraming.cpp", *allow_paths},
    )
    duplicate = _fixture_config(base, [
        _entry(contract, "LiveTunnelFraming", ["srchybrid/LiveTunnelFraming.cpp"], ["LiveTunnelMetrics", "LiveTunnelMetrics"]),
        _entry(contract, "LiveTunnelMetrics", ["srchybrid/LiveTunnelMetrics.cpp"], []),
    ])
    _expect_invalid(
        "declared-duplicate", duplicate, contract, "declared direct dependency duplicate",
        overrides={"srchybrid/LiveTunnelFraming.cpp": b"", "srchybrid/LiveTunnelMetrics.cpp": b""},
        discovery={"srchybrid/LiveTunnelFraming.cpp", "srchybrid/LiveTunnelMetrics.cpp"},
    )

    shrink = _fixture_config(base, [
        _entry(contract, "LiveTunnelFraming", ["srchybrid/LiveTunnelFraming.cpp"], []),
    ])
    _expect_invalid(
        "slice-shrink", shrink, contract, "slice coordinator shrink insufficient",
        overrides={"srchybrid/LiveTunnelFraming.cpp": b"x\n" * 300},
        discovery={"srchybrid/LiveTunnelFraming.cpp"},
        diffs={"LiveTunnelFraming": (4, 4)},
    )
    foreign = copy.deepcopy(shrink)
    foreign["slice_evidence"]["entries"][0]["source_coordinator"] = "srchybrid/WebServer.cpp"
    _expect_invalid(
        "slice-foreign-owner", foreign, contract, "slice source coordinator owner mismatch",
        overrides={"srchybrid/LiveTunnelFraming.cpp": b"x\n" * 300},
        discovery={"srchybrid/LiveTunnelFraming.cpp"},
    )
    unrelated = copy.deepcopy(shrink)
    unrelated["slice_evidence"]["entries"][0]["slice_base_commit"] = "f" * 40
    _expect_invalid(
        "slice-non-ancestor", unrelated, contract, "slice base commit is not an ancestor of HEAD",
        overrides={"srchybrid/LiveTunnelFraming.cpp": b"x\n" * 300},
        discovery={"srchybrid/LiveTunnelFraming.cpp"},
        ancestry={"f" * 40: False},
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--negative-fixtures", action="store_true")
    args = parser.parse_args(argv)
    if args.verify == args.negative_fixtures:
        parser.error("choose exactly one of --verify or --negative-fixtures")
    config = load_json(BASELINE_PATH)
    contract = load_json(CONTRACT_PATH)
    try:
        if args.verify:
            print("MOD-0.4 PASS: " + "; ".join(validate(config, contract)))
        else:
            run_negative_fixtures(config, contract)
            print("MOD-0.4 PASS: 41 negative fixtures rejected with exact reasons")
    except GateError as exc:
        print(f"MOD-0.4 FAIL: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
