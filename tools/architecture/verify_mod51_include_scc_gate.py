#!/usr/bin/env python3
"""Reproducible, closed include-SCC gate for completed MOD-1 through MOD-3 modules.

MOD-0.4 owns the source catalogue and include resolution rules.  This gate
deliberately reuses those rules instead of maintaining a second parser: it
serialises the resulting *inter-module* include graph and rejects SCCs that
were not present in the MOD-5.1 baseline.  The graph JSON can be written by
CI or a developer and is stable across Windows path separator/casing variants.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

import verify_mod04_architecture_gate as mod04


ROOT = Path(__file__).resolve().parents[2]
CONTRACT_PATH = ROOT / "docs" / "architecture" / "mod51_include_scc_contract_v1.json"
MOD04_PATH = ROOT / "docs" / "architecture" / "mod04_architecture_gate_baseline_v1.json"
MOD03_PATH = ROOT / "docs" / "architecture" / "mod03_ownership_layering_contract_v1.json"

SCHEMA = "ese.mod51.include-scc-contract/v1"
GATE_ID = "urn:emule:architecture:mod-5.1:include-scc-gate:v1"
SCOPE = (
    "reproducible inter-module include graph for completed MOD-1 through MOD-3 "
    "extractions; no new SCC/cycle is permitted"
)
EXPECTED_INPUTS = {
    "mod03_contract": "docs/architecture/mod03_ownership_layering_contract_v1.json",
    "mod04_catalog": "docs/architecture/mod04_architecture_gate_baseline_v1.json",
    "completed_module_count": 30,
}
EXPECTED_NORMALIZATION = {
    "include_parser": "one leading BOM removal, CRLF/CR-to-LF normalization, raw-literal candidate plus physical backslash-LF reject, phase-2 splice, raw/string/comment masking, # or %: literal include parser; non-literal active #include fails closed",
    "include_resolution": "MOD-0.4 current-parent, repository-root, srchybrid-root casefold lookup",
    "path_separator": "forward-slash",
    "path_case": "casefold for repository-local lookup",
    "graph_scope": "inter-module includes only; intra-module includes do not form module edges",
}
EXPECTED_POLICY = {
    "baseline_sccs_are_allowlist": True,
    "new_sccs_must_be_empty": True,
}
# This deliberately pins the approved empty-SCC baseline.  Without this
# independent value, editing baseline_graph, sccs and its self-reported digest
# together could silently turn a newly introduced cycle into an allowlist.
EXPECTED_BASELINE_GRAPH_SHA256 = "254138a09563255244172aabdc0aa15e91b2f4290dc37c956aca0ecb4442b16c"
HORIZONTAL_WHITESPACE = " \t\v\f"
INCLUDE_DIRECTIVE_RE = re.compile(
    r"^[ \t\v\f]*(?:\#|%:)[ \t\v\f]*include(?![A-Za-z0-9_])([^\r\n]*)",
    re.MULTILINE,
)
INCLUDE_OPERAND_PREFIX_RE = re.compile(
    r"^[ \t\v\f]*(?:\#|%:)[ \t\v\f]*include(?![A-Za-z0-9_])[ \t\v\f]*$"
)
LITERAL_INCLUDE_RE = re.compile(r'^[ \t\v\f]*(?:"([^"\r\n]+)"|<([^>\r\n]+)>)[ \t\v\f]*$')


class GateError(RuntimeError):
    """A deterministic MOD-5.1 gate failure."""


def _json_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(_json_bytes(value)).hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _require_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    if not isinstance(value, dict) or set(value) != expected:
        raise GateError(f"{label} keys drift")


def _component_key(component: list[str]) -> tuple[str, ...]:
    return tuple(component)


def _sccs(graph: dict[str, set[str]]) -> list[list[str]]:
    """Return non-trivial SCCs in one canonical order (Tarjan's algorithm)."""
    index = 0
    indices: dict[str, int] = {}
    lowlinks: dict[str, int] = {}
    stack: list[str] = []
    on_stack: set[str] = set()
    components: list[list[str]] = []

    def visit(node: str) -> None:
        nonlocal index
        indices[node] = index
        lowlinks[node] = index
        index += 1
        stack.append(node)
        on_stack.add(node)
        for target in sorted(graph[node]):
            if target not in indices:
                visit(target)
                lowlinks[node] = min(lowlinks[node], lowlinks[target])
            elif target in on_stack:
                lowlinks[node] = min(lowlinks[node], indices[target])
        if lowlinks[node] != indices[node]:
            return
        component: list[str] = []
        while True:
            target = stack.pop()
            on_stack.remove(target)
            component.append(target)
            if target == node:
                break
        component.sort()
        # A module self-include is intentionally not an inter-module edge.
        if len(component) > 1:
            components.append(component)

    for node in sorted(graph):
        if node not in indices:
            visit(node)
    return sorted(components, key=_component_key)


def _splice_phase_two(source: str) -> str:
    """Apply C/C++ translation phase 2 after physical lines are normalized."""
    return source.replace("\\\n", "")


def _normalize_translation_input(source: str) -> str:
    """Perform the bounded file-start/BOL normalization preceding phase 2."""
    if source.startswith("\ufeff"):
        source = source[1:]
    return source.replace("\r\n", "\n").replace("\r", "\n")


def _preflight_raw_content_splices(source_file: str, source: str) -> None:
    """Conservatively reject phase-2 ambiguity around any raw token candidate.

    C++'s raw-literal phase reversion makes a global splice pass unsafe when
    a physical backslash-LF coexists with a raw-literal token candidate.  MOD-
    5.1 deliberately rejects that rare combination before parsing directives;
    plain raw literals and ordinary phase-2 splices remain supported.
    """
    if "\\\n" not in source:
        return

    def match(index: int, token: str) -> int | None:
        for expected in token:
            while source.startswith("\\\n", index):
                index += 2
            if index >= len(source) or source[index] != expected:
                return None
            index += 1
        return index

    index = 0
    while index < len(source):
        line_comment = match(index, "//")
        if line_comment is not None:
            index = line_comment
            while index < len(source):
                if source.startswith("\\\n", index):
                    index += 2
                elif source[index] == "\n":
                    index += 1
                    break
                else:
                    index += 1
            continue
        block_comment = match(index, "/*")
        if block_comment is not None:
            index = block_comment
            while index < len(source):
                block_end = match(index, "*/")
                if block_end is not None:
                    index = block_end
                    break
                index += 2 if source.startswith("\\\n", index) else 1
            continue
        if source[index] in {'"', "'"}:
            quote = source[index]
            index += 1
            while index < len(source):
                if source.startswith("\\\n", index):
                    index += 2
                elif source[index] == "\\":
                    index += 2
                elif source[index] == quote:
                    index += 1
                    break
                elif source[index] == "\n":
                    break
                else:
                    index += 1
            continue
        if any(match(index, prefix) is not None for prefix in ("u8R\"", "uR\"", "UR\"", "LR\"", "R\"")):
            raise GateError(f"raw-literal candidate with backslash-LF forbidden: {source_file}")
        index += 2 if source.startswith("\\\n", index) else 1


def _masked_segment(source: str) -> str:
    """Replace a token with spaces while preserving every physical line break."""
    return "".join(character if character in "\r\n" else " " for character in source)


def _masked_literal_segment(source: str) -> str:
    """Mask a literal without turning its occupied line into whitespace only."""
    result: list[str] = []
    needs_sentinel = True
    for character in source:
        if character in "\r\n":
            result.append(character)
            needs_sentinel = True
        elif needs_sentinel:
            # Comments are preprocessing whitespace; literals are not.  The
            # sentinel prevents a following # on this physical line from
            # becoming a false directive after the literal is hidden.
            result.append("0")
            needs_sentinel = False
        else:
            result.append(" ")
    return "".join(result)


def _raw_literal_end(source_file: str, source: str, start: int, prefix: str) -> int:
    """Return the first index after a valid raw literal, or fail closed."""
    delimiter_start = start + len(prefix)
    delimiter_end = delimiter_start
    while delimiter_end < len(source) and source[delimiter_end] != "(":
        character = source[delimiter_end]
        if (
            character in " \t\v\f\r\n()\\"
            or not (0x21 <= ord(character) <= 0x7E)
            or delimiter_end - delimiter_start >= 16
        ):
            raise GateError(f"malformed raw string literal: {source_file}")
        delimiter_end += 1
    if delimiter_end == len(source) or delimiter_end - delimiter_start > 16:
        raise GateError(f"malformed raw string literal: {source_file}")
    delimiter = source[delimiter_start:delimiter_end]
    terminator = ")" + delimiter + '"'
    content_end = source.find(terminator, delimiter_end + 1)
    if content_end < 0:
        raise GateError(f"unterminated raw string literal: {source_file}")
    return content_end + len(terminator)


def _ordinary_literal_end(source_file: str, source: str, start: int, quote: str) -> int:
    """Return the first index after a normal string/character literal."""
    index = start + 1
    while index < len(source):
        character = source[index]
        if character in "\r\n":
            raise GateError(f"unterminated {('string' if quote == '"' else 'character')} literal: {source_file}")
        if character == "\\":
            if index + 1 >= len(source):
                raise GateError(f"unterminated {('string' if quote == '"' else 'character')} literal: {source_file}")
            index += 2
            continue
        index += 1
        if character == quote:
            return index
    raise GateError(f"unterminated {('string' if quote == '"' else 'character')} literal: {source_file}")


def _mask_comments_and_literals(source_file: str, source: str) -> str:
    """Mask comments and C++ literals, preserving lines for directive scanning.

    This runs after phase 2.  Raw literals are recognized before comment
    delimiters, so text such as ``R"tag(/*)tag"`` cannot alter lexer state.
    Invalid/unterminated constructs fail closed because they could otherwise
    hide an active directive on a later line.
    """
    result: list[str] = []
    line_prefix = ""

    def append(text: str) -> None:
        """Append masked output and retain only its current physical line."""
        nonlocal line_prefix
        result.append(text)
        newline = max(text.rfind("\n"), text.rfind("\r"))
        line_prefix = text[newline + 1:] if newline >= 0 else line_prefix + text

    index = 0
    while index < len(source):
        current = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""
        raw_prefix = next(
            (prefix for prefix in ("u8R\"", "uR\"", "UR\"", "LR\"", "R\"")
             if source.startswith(prefix, index)),
            None,
        )
        if raw_prefix is not None:
            end = _raw_literal_end(source_file, source, index, raw_prefix)
            append(_masked_literal_segment(source[index:end]))
            index = end
            continue
        if current == "/" and following == "/":
            end = index + 2
            while end < len(source) and source[end] not in "\r\n":
                end += 1
            append(_masked_segment(source[index:end]))
            index = end
            continue
        if current == "/" and following == "*":
            end = source.find("*/", index + 2)
            if end < 0:
                raise GateError(f"unterminated block comment: {source_file}")
            end += 2
            append(_masked_segment(source[index:end]))
            index = end
            continue
        if current in {'"', "'"}:
            end = _ordinary_literal_end(source_file, source, index, current)
            if current == '"' and INCLUDE_OPERAND_PREFIX_RE.fullmatch(line_prefix):
                # Preserve only a verified header-name token.  Every other
                # ordinary literal remains masked, so its multiline-looking
                # contents cannot be mistaken for a directive.
                append(source[index:end])
            else:
                append(_masked_literal_segment(source[index:end]))
            index = end
            continue
        append(current)
        index += 1
    return "".join(result)


def _literal_includes(source_file: str, raw: str) -> list[str]:
    """Return active literal includes after phase 2; reject macro includes closed."""
    normalized = _normalize_translation_input(raw)
    _preflight_raw_content_splices(source_file, normalized)
    translated = _mask_comments_and_literals(source_file, _splice_phase_two(normalized))
    includes: list[str] = []
    for match in INCLUDE_DIRECTIVE_RE.finditer(translated):
        literal = LITERAL_INCLUDE_RE.fullmatch(match.group(1))
        if literal is None:
            raise GateError(f"non-literal active #include forbidden: {source_file}")
        includes.append(literal.group(1) or literal.group(2))
    return includes


def build_graph(
    mod04_config: dict[str, Any], mod03_contract: dict[str, Any],
    overrides: dict[str, bytes] | None = None,
) -> dict[str, Any]:
    """Build the canonical inter-module include graph using MOD-0.4 resolution."""
    entries = mod04._entry_map(mod04_config, mod03_contract)
    owners = mod04._module_file_owner(entries)
    repo_paths = mod04._repo_code_paths(overrides, owners)
    graph = {name: set() for name in entries}
    include_edges: set[tuple[str, str, str, str]] = set()

    for source_module in sorted(entries):
        entry = entries[source_module]
        for source_file in sorted(entry["implementation_files"] + entry["interface_files"]):
            raw = mod04._read_worktree(source_file, overrides).decode("utf-8", errors="replace")
            for raw_include in _literal_includes(source_file, raw):
                include = mod04._normal_include(raw_include)
                target_file = mod04._resolve_include(include, source_file, repo_paths)
                target_module = owners.get(target_file) if target_file else None
                if target_module is None or target_module == source_module:
                    continue
                graph[source_module].add(target_module)
                include_edges.add((source_module, source_file, target_module, target_file))

    edges = [[source, target] for source in sorted(graph) for target in sorted(graph[source])]
    includes = [
        {
            "source_module": source_module,
            "source_file": source_file,
            "target_module": target_module,
            "target_file": target_file,
        }
        for source_module, source_file, target_module, target_file in sorted(include_edges)
    ]
    return {
        "nodes": sorted(graph),
        "edges": edges,
        "includes": includes,
        "sccs": _sccs(graph),
    }


def _graph_payload(graph: dict[str, Any]) -> dict[str, Any]:
    _require_keys(graph, {"nodes", "edges", "includes", "sccs"}, "include graph")
    return graph


def _validate_graph_shape(graph: dict[str, Any], label: str) -> None:
    _graph_payload(graph)
    nodes = graph["nodes"]
    if not isinstance(nodes, list) or not all(isinstance(node, str) and node for node in nodes):
        raise GateError(f"{label} nodes invalid")
    if nodes != sorted(nodes) or len(nodes) != len(set(nodes)):
        raise GateError(f"{label} nodes are not canonical")
    node_set = set(nodes)
    edges = graph["edges"]
    if not isinstance(edges, list) or edges != sorted(edges) or len(edges) != len({tuple(edge) for edge in edges if isinstance(edge, list)}):
        raise GateError(f"{label} edges are not canonical")
    for edge in edges:
        if not isinstance(edge, list) or len(edge) != 2 or not all(isinstance(item, str) for item in edge):
            raise GateError(f"{label} edge invalid")
        if edge[0] == edge[1] or edge[0] not in node_set or edge[1] not in node_set:
            raise GateError(f"{label} edge outside inter-module graph")
    includes = graph["includes"]
    if not isinstance(includes, list):
        raise GateError(f"{label} includes invalid")
    expected_include_order = sorted(
        includes,
        key=lambda item: (
            item.get("source_module", "") if isinstance(item, dict) else "",
            item.get("source_file", "") if isinstance(item, dict) else "",
            item.get("target_module", "") if isinstance(item, dict) else "",
            item.get("target_file", "") if isinstance(item, dict) else "",
        ),
    )
    if includes != expected_include_order:
        raise GateError(f"{label} includes are not canonical")
    include_pairs: set[tuple[str, str]] = set()
    for include in includes:
        _require_keys(include, {"source_module", "source_file", "target_module", "target_file"}, f"{label} include")
        values = tuple(include[key] for key in ("source_module", "source_file", "target_module", "target_file"))
        if not all(isinstance(value, str) and value for value in values):
            raise GateError(f"{label} include invalid")
        source_module, source_file, target_module, target_file = values
        if source_module == target_module or source_module not in node_set or target_module not in node_set:
            raise GateError(f"{label} include outside inter-module graph")
        if not source_file.startswith("srchybrid/") or not target_file.startswith("srchybrid/"):
            raise GateError(f"{label} include path invalid")
        include_pairs.add((source_module, target_module))
    if include_pairs != {tuple(edge) for edge in edges}:
        raise GateError(f"{label} includes do not cover graph edges")
    graph_from_edges = {node: set() for node in nodes}
    for source, target in edges:
        graph_from_edges[source].add(target)
    if graph["sccs"] != _sccs(graph_from_edges):
        raise GateError(f"{label} SCCs drift")


def _format_components(components: list[list[str]]) -> str:
    return "; ".join(",".join(component) for component in components)


def validate_contract(
    contract: dict[str, Any], mod04_config: dict[str, Any], mod03_contract: dict[str, Any],
) -> None:
    _require_keys(contract, {
        "schema", "gate_id", "status", "scope", "inputs", "normalization",
        "completed_modules", "baseline_graph", "baseline_graph_sha256", "policy",
    }, "MOD-5.1 contract")
    if contract["schema"] != SCHEMA:
        raise GateError("MOD-5.1 contract schema drift")
    if contract["gate_id"] != GATE_ID:
        raise GateError("MOD-5.1 gate_id drift")
    if contract["status"] != "PASS":
        raise GateError("MOD-5.1 status must be PASS")
    if contract["scope"] != SCOPE:
        raise GateError("MOD-5.1 scope drift")
    if contract["inputs"] != EXPECTED_INPUTS:
        raise GateError("MOD-5.1 inputs drift")
    if contract["normalization"] != EXPECTED_NORMALIZATION:
        raise GateError("MOD-5.1 normalization drift")
    if contract["policy"] != EXPECTED_POLICY:
        raise GateError("MOD-5.1 policy drift")
    completed = contract["completed_modules"]
    _require_keys(completed, {"names", "sha256"}, "completed_modules")
    expected_names = sorted(mod04._entry_map(mod04_config, mod03_contract))
    if completed["names"] != expected_names:
        raise GateError("completed MOD-1..MOD-3 module list drift")
    if completed["sha256"] != canonical_sha256(expected_names):
        raise GateError("completed MOD-1..MOD-3 module digest drift")
    baseline = contract["baseline_graph"]
    _validate_graph_shape(baseline, "baseline graph")
    if baseline["nodes"] != expected_names:
        raise GateError("baseline graph nodes do not match completed modules")
    if contract["baseline_graph_sha256"] != canonical_sha256(_graph_payload(baseline)):
        raise GateError("baseline graph sha256 drift")
    if contract["baseline_graph_sha256"] != EXPECTED_BASELINE_GRAPH_SHA256:
        raise GateError("baseline graph digest is not the approved MOD-5.1 baseline")
    if baseline["sccs"] != []:
        raise GateError("baseline graph must remain SCC-free")


def verify_scc_policy(contract: dict[str, Any], current_graph: dict[str, Any]) -> dict[str, Any]:
    _validate_graph_shape(current_graph, "current graph")
    baseline_sccs = contract["baseline_graph"]["sccs"]
    current_sccs = current_graph["sccs"]
    baseline_set = {tuple(component) for component in baseline_sccs}
    new_sccs = [component for component in current_sccs if tuple(component) not in baseline_set]
    if contract["policy"]["new_sccs_must_be_empty"] and new_sccs:
        raise GateError("new include SCCs forbidden: " + _format_components(new_sccs))
    return {
        "schema": "ese.mod51.include-scc-report/v1",
        "gate_id": GATE_ID,
        "baseline_graph_sha256": contract["baseline_graph_sha256"],
        "current_graph": current_graph,
        "current_graph_sha256": canonical_sha256(_graph_payload(current_graph)),
        "baseline_sccs": baseline_sccs,
        "new_sccs": new_sccs,
        "status": "PASS",
    }


def validate(
    contract: dict[str, Any], mod04_config: dict[str, Any], mod03_contract: dict[str, Any],
) -> dict[str, Any]:
    # Keep MOD-0.4's closed discovery/catalogue/layer gates binding before
    # accepting an include graph derived from that catalogue.
    mod04.validate(mod04_config, mod03_contract)
    validate_contract(contract, mod04_config, mod03_contract)
    graph = build_graph(mod04_config, mod03_contract)
    if graph["nodes"] != contract["completed_modules"]["names"]:
        raise GateError("current graph nodes do not match completed modules")
    return verify_scc_policy(contract, graph)


def _expect_cycle(
    name: str, contract: dict[str, Any], mod04_config: dict[str, Any],
    mod03_contract: dict[str, Any], overrides: dict[str, bytes], expected: str,
) -> None:
    graph = build_graph(mod04_config, mod03_contract, overrides)
    try:
        verify_scc_policy(contract, graph)
    except GateError as exc:
        if expected not in str(exc):
            raise GateError(f"negative {name} failed for the wrong reason: {exc}") from exc
    else:
        raise GateError(f"negative {name} unexpectedly passed")


def _expect_non_literal_include(
    name: str, mod04_config: dict[str, Any], mod03_contract: dict[str, Any],
    overrides: dict[str, bytes], expected: str,
) -> None:
    try:
        build_graph(mod04_config, mod03_contract, overrides)
    except GateError as exc:
        if expected not in str(exc):
            raise GateError(f"negative {name} failed for the wrong reason: {exc}") from exc
    else:
        raise GateError(f"negative {name} unexpectedly passed")


def run_negative_fixtures(
    contract: dict[str, Any], mod04_config: dict[str, Any], mod03_contract: dict[str, Any],
) -> None:
    framing = "srchybrid/LiveTunnelFraming.cpp"
    original = mod04._read_worktree(framing, None)
    variants = (
        ("quoted-cycle", b'\n#include "LiveHandshakeWire.h"\n'),
        ("windows-backslash-cycle", b'\n#include "subdir\\..\\LiveHandshakeWire.h"\n'),
        ("windows-case-cycle", b'\n#include "SUBDIR\\..\\livehandshakewire.h"\n'),
        ("digraph-cycle", b'\n%:include "LiveHandshakeWire.h"\n'),
        ("formfeed-leading-cycle", b'\n\f#include "LiveHandshakeWire.h"\n'),
        ("formfeed-after-hash-cycle", b'\n#\finclude "LiveHandshakeWire.h"\n'),
        ("bare-cr-after-comment-cycle", b'// MOD51 separator\r#include "LiveHandshakeWire.h"\r'),
        (
            "raw-literal-state-cycle",
            b'\nR"tag(/*)tag"\n#include "LiveHandshakeWire.h"\nR"tag(*/)tag"\n',
        ),
    )
    for name, suffix in variants:
        _expect_cycle(
            name, contract, mod04_config, mod03_contract, {framing: original + suffix},
            "new include SCCs forbidden: LiveHandshakeWire,LiveTunnelFraming",
        )
    _expect_cycle(
        "line-spliced-literal-cycle", contract, mod04_config, mod03_contract,
        {framing: original + b'\r\n#include \\\r\n "LiveHandshakeWire.h"\r\n'},
        "new include SCCs forbidden: LiveHandshakeWire,LiveTunnelFraming",
    )
    _expect_cycle(
        "bom-first-line-cycle", contract, mod04_config, mod03_contract,
        {framing: b'\xef\xbb\xbf#include "LiveHandshakeWire.h"\r\n' + original},
        "new include SCCs forbidden: LiveHandshakeWire,LiveTunnelFraming",
    )
    _expect_non_literal_include(
        "macro-include", mod04_config, mod03_contract,
        {framing: original + b'\n#define MOD51_TARGET "LiveHandshakeWire.h"\n#include MOD51_TARGET\n'},
        f"non-literal active #include forbidden: {framing}",
    )
    _expect_non_literal_include(
        "raw-literal-splice-ambiguity", mod04_config, mod03_contract,
        {framing: original + (
            b'\nconst char* a = R"tag(\n)\\\ntag" /* \n)tag";\n'
            b'#include "LiveHandshakeWire.h"\n'
            b'const char* b = R"x( */ " )x";\n'
        )},
        f"raw-literal candidate with backslash-LF forbidden: {framing}",
    )
    _expect_non_literal_include(
        "raw-prefix-splice-ambiguity", mod04_config, mod03_contract,
        {framing: original + b'\nconst char* raw = R\\\n"tag(payload)tag";\nint marker = 1;\\\n'},
        f"raw-literal candidate with backslash-LF forbidden: {framing}",
    )
    baseline = copy.deepcopy(contract)
    baseline["baseline_graph"]["edges"].append(["LiveTunnelFraming", "LiveCircuitHandshake"])
    baseline["baseline_graph"]["includes"].append({
        "source_module": "LiveTunnelFraming",
        "source_file": "srchybrid/LiveTunnelFraming.cpp",
        "target_module": "LiveCircuitHandshake",
        "target_file": "srchybrid/LiveCircuitHandshake.h",
    })
    baseline["baseline_graph"]["sccs"] = [[
        "LiveCircuitHandshake", "LiveHandshakeWire", "LiveTunnelFraming",
    ]]
    baseline["baseline_graph_sha256"] = canonical_sha256(baseline["baseline_graph"])
    try:
        validate_contract(baseline, mod04_config, mod03_contract)
    except GateError as exc:
        if "baseline graph digest is not the approved MOD-5.1 baseline" not in str(exc):
            raise GateError(f"negative baseline-SCC failed for the wrong reason: {exc}") from exc
    else:
        raise GateError("negative baseline-SCC unexpectedly passed")
    digest = copy.deepcopy(contract)
    digest["baseline_graph"]["nodes"] = list(reversed(digest["baseline_graph"]["nodes"]))
    try:
        validate_contract(digest, mod04_config, mod03_contract)
    except GateError as exc:
        if "baseline graph nodes are not canonical" not in str(exc):
            raise GateError(f"negative graph-order failed for the wrong reason: {exc}") from exc
    else:
        raise GateError("negative graph-order unexpectedly passed")


def _safe_report_path(path: Path) -> Path:
    candidate = (ROOT / path).resolve() if not path.is_absolute() else path.resolve()
    artifacts_root = (ROOT / "artifacts").resolve()
    try:
        candidate.relative_to(artifacts_root)
    except ValueError as exc:
        raise GateError("report path must remain under artifacts/") from exc
    if candidate.suffix.lower() != ".json":
        raise GateError("report path must use a .json suffix")
    return candidate


def _write_report(path: Path, report: dict[str, Any]) -> None:
    path = _safe_report_path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--verify", action="store_true")
    mode.add_argument("--negative-fixtures", action="store_true")
    parser.add_argument("--write-json", type=Path, help="write the canonical reproducible graph report under artifacts/")
    args = parser.parse_args(argv)
    try:
        contract = load_json(CONTRACT_PATH)
        mod04_config = load_json(MOD04_PATH)
        mod03_contract = load_json(MOD03_PATH)
        if args.verify:
            report = validate(contract, mod04_config, mod03_contract)
            if args.write_json:
                _write_report(args.write_json, report)
            graph = report["current_graph"]
            print(
                "MOD-5.1 PASS: "
                f"modules={len(graph['nodes'])}; edges={len(graph['edges'])}; "
                f"includes={len(graph['includes'])}; baseline_sccs={len(report['baseline_sccs'])}; "
                f"new_sccs={len(report['new_sccs'])}"
            )
        else:
            validate_contract(contract, mod04_config, mod03_contract)
            run_negative_fixtures(contract, mod04_config, mod03_contract)
            print("MOD-5.1 PASS: 15 negative include-SCC fixtures rejected with exact reasons")
    except (OSError, json.JSONDecodeError, KeyError, TypeError, mod04.GateError, GateError) as exc:
        print(f"MOD-5.1 FAIL: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
