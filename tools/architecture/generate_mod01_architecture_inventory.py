#!/usr/bin/env python3
"""Generate or verify the MOD-0.1 coordinator architecture inventory.

The extractor is deliberately lexical, not a C++ compiler.  It operates on
the immutable Git object named by BASELINE, so line endings and a developer's
checkout location cannot alter the recorded inventory. Verification also
requires the working-tree coordinator sources to normalize to those frozen
objects. The only exception is a versioned, exact-hash overlay manifest for an
approved later-phase test seam; it never changes the baseline.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any


BASELINE = "b875d3dd61a2d675b2138d61161f0a8fec9d9888"
ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / "docs" / "architecture" / "mod01_architecture_inventory_v1.json"
OVERLAY_MANIFEST = ROOT / "docs" / "architecture" / "mod01_approved_overlays_v1.json"
TARGETS = {
    "LiveTunnel": ("CLiveTunnel", "srchybrid/LiveTunnel.cpp", "srchybrid/LiveTunnel.h"),
    "WebServer": ("CWebServer", "srchybrid/WebServer.cpp", "srchybrid/WebServer.h"),
    "LiveStreamManager": (
        "CLiveStreamManager",
        "srchybrid/LiveStreamManager.cpp",
        "srchybrid/LiveStreamManager.h",
    ),
}
RESPONSIBILITIES = {
    "LiveTunnel": [
        "Circuit, relay and Kad6 request coordination.",
        "Pending-request lifecycle and callback completion fencing.",
        "Tunnel ingress, peer caches and release/lease state.",
    ],
    "WebServer": [
        "HTTP/websocket request dispatch and presentation projection.",
        "Synchronous GUI-message bridge for explicitly supported live actions.",
        "Read-only status, search, transfer and live API integration.",
    ],
    "LiveStreamManager": [
        "Live-stream session, peer and chunk state coordination.",
        "Protocol ingestion, peer refresh and debug/channel snapshots.",
        "Main-thread-facing live join, leave and broadcast request handling.",
    ],
}
RISKS = {
    "LiveTunnel": [
        "High lock density; observed lock order is lexical evidence only.",
        "Deferred Kad callbacks and worker entrypoints can outlive initiating state.",
    ],
    "WebServer": [
        "Synchronous SendMessage crossings can couple web and GUI execution.",
        "Large dispatcher has broad product dependencies and privacy-sensitive output paths.",
    ],
    "LiveStreamManager": [
        "Shared live state is accessed from protocol, UI and web-facing paths.",
        "Chunk/peer lifetime and refresh callbacks need generation-aware fencing.",
    ],
}
STOP_CONDITIONS = {
    "LiveTunnel": [
        "Do not extract while a proposed seam needs a new lock order without a dedicated concurrency proof.",
        "Stop if callback ownership or pending-request completion cannot be expressed as an explicit contract.",
    ],
    "WebServer": [
        "Do not extract handlers that require synchronous GUI calls before defining a marshalled boundary.",
        "Stop if a projection would expose raw endpoint, credential or session material.",
    ],
    "LiveStreamManager": [
        "Do not extract shared state before snapshot ownership and caller thread are explicit.",
        "Stop if protocol callback lifetime crosses a manager boundary without a cancellation/fence contract.",
    ],
}


def normalized(data: bytes) -> bytes:
    return data.replace(b"\r\n", b"\n").replace(b"\r", b"\n")


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def git_show(relative: str) -> bytes:
    return subprocess.check_output(
        ["git", "show", f"{BASELINE}:{relative}"], cwd=ROOT
    )


def logical_lines(text: str) -> int:
    """A transparent approximate LOC metric: blank/comment-only lines excluded."""
    in_block = False
    count = 0
    for raw in text.splitlines():
        line = raw
        if in_block:
            end = line.find("*/")
            if end < 0:
                continue
            line, in_block = line[end + 2 :], False
        while "/*" in line:
            start = line.find("/*")
            end = line.find("*/", start + 2)
            if end < 0:
                line, in_block = line[:start], True
                break
            line = line[:start] + line[end + 2 :]
        line = line.split("//", 1)[0].strip()
        if line:
            count += 1
    return count


def strip_comments(line: str) -> str:
    """Strip a line comment while preserving ordinary and same-line raw literals."""
    quote: str | None = None
    escaped = False
    index = 0
    while index < len(line):
        character = line[index]
        if quote is not None:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = None
        else:
            raw_prefix = next(
                (prefix for prefix in ("u8R\"", "uR\"", "UR\"", "LR\"", "R\"")
                 if line.startswith(prefix, index)),
                None,
            )
            if raw_prefix is not None:
                delimiter_start = index + len(raw_prefix)
                delimiter_end = line.find("(", delimiter_start)
                if delimiter_end >= 0:
                    delimiter = line[delimiter_start:delimiter_end]
                    valid_delimiter = (
                        len(delimiter) <= 16
                        and not any(character in " \t\v\f\r\n()\\" for character in delimiter)
                    )
                    terminator = ")" + delimiter + '"'
                    raw_end = line.find(terminator, delimiter_end + 1) if valid_delimiter else -1
                    if raw_end >= 0:
                        index = raw_end + len(terminator)
                        continue
                    if valid_delimiter:
                        return line
            if character == "'":
                token_start = index
                while token_start > 0 and (line[token_start - 1].isalnum() or line[token_start - 1] in "._"):
                    token_start -= 1
                numeric_token = line[token_start:index].lstrip(".")
                if numeric_token and numeric_token[0].isdigit() and index + 1 < len(line) and line[index + 1].isalnum():
                    index += 1
                    continue
                quote = character
            elif character == '"':
                quote = character
            elif line.startswith("//", index):
                return line[:index]
        index += 1
    return line


def includes(lines: list[str]) -> list[dict[str, str]]:
    found = []
    pattern = re.compile(r'^\s*#\s*include\s*([<"])([^>"]+)[>"]')
    for number, line in enumerate(lines, 1):
        match = pattern.match(line)
        if not match:
            continue
        delimiter, target = match.groups()
        if delimiter == "<":
            scope = "toolchain_or_external"
        elif target.startswith("../") or target.startswith("zlib/"):
            scope = "external_or_sibling"
        else:
            scope = "srchybrid_internal"
        found.append({"line": number, "target": target, "scope": scope})
    return found


def find_function_end(lines: list[str], start: int) -> int:
    depth = 0
    seen_open = False
    for index in range(start, len(lines)):
        code = strip_comments(lines[index])
        depth += code.count("{") - code.count("}")
        if "{" in code:
            seen_open = True
        if seen_open and depth <= 0:
            return index + 1
    return len(lines)


def role_for(name: str) -> str:
    bare = name.rsplit("::", 1)[-1].lstrip("~_")
    owner = name.rsplit("::", 1)[0].rsplit("::", 1)[-1].lstrip("~_")
    if bare == owner:
        return "lifecycle_or_state_transition"
    if re.match(r"^(On|Handle|Process|Dispatch|Receive)", bare):
        return "event_or_callback_handler"
    if re.match(
        r"^(Start|Stop|Init|Create|Destroy|Reset|Shutdown|Join|Leave|Set|Add|Remove|"
        r"Enable|Disable|Activate|Deactivate|Bind|Unbind)",
        bare,
    ):
        return "lifecycle_or_state_transition"
    if re.match(r"^(Get|Is|Has|Can|Find|BuildSnapshot)", bare):
        return "query_or_snapshot"
    if re.match(r"^(Send|Write|Publish|Forward|Queue)", bare):
        return "egress_or_queueing"
    if "Worker" in bare or "Thread" in bare:
        return "worker_or_thread_entry"
    return "coordination_or_helper"


def functions(lines: list[str], owner: str, relative: str) -> list[dict[str, Any]]:
    """Find qualified out-of-class definitions with a bounded lexical parser."""
    results = []
    pattern = re.compile(r"\b(" + re.escape(owner) + r"::(?:~?\w+))\s*\(")
    seen: set[tuple[str, int]] = set()
    for index, line in enumerate(lines):
        match = pattern.search(strip_comments(line))
        if not match:
            continue
        signature_parts = []
        has_body = False
        for candidate in lines[index : min(index + 128, len(lines))]:
            signature_parts.append(strip_comments(candidate).strip())
            signature = " ".join(signature_parts)
            brace = signature.find("{")
            semicolon = signature.find(";")
            if semicolon >= 0 and (brace < 0 or semicolon < brace):
                break
            if brace >= 0:
                has_body = True
                break
        if not has_body:
            continue
        name = match.group(1)
        key = (name, index + 1)
        if key in seen:
            continue
        seen.add(key)
        end = find_function_end(lines, index)
        results.append({
            "name": name,
            "file": relative,
            "line_start": index + 1,
            "line_end_approx": end,
            "length_approx": end - index,
            "role": role_for(name),
            "role_basis": "name_heuristic",
        })
    return results


def inline_functions(lines: list[str], owner: str, relative: str) -> list[dict[str, Any]]:
    """Find same-class inline definitions at class-body depth one."""
    results = []
    body_start, body_end = class_body(lines, owner)
    depth = 0
    pattern = re.compile(r"\b(?P<name>~?" + re.escape(owner) + r"|[A-Za-z_]\w*)\s*\(")
    rejected = {"if", "for", "while", "switch", "return", "sizeof", "static_cast"}
    for index in range(body_start, body_end + 1):
        code = strip_comments(lines[index])
        depth_before = depth
        depth += code.count("{") - code.count("}")
        if depth_before != 1:
            continue
        match = pattern.search(code)
        if not match or match.group("name") in rejected:
            continue
        window = " ".join(strip_comments(item).strip() for item in lines[index : min(index + 8, body_end + 1)])
        prefix = code[: match.start()]
        if "typedef" in prefix or "using " in prefix:
            continue
        before_body = window.split("{", 1)[0]
        if "{" not in window or ";" in before_body:
            continue
        end = find_function_end(lines, index)
        name = f"{owner}::{match.group('name')}"
        results.append({
            "name": name,
            "file": relative,
            "line_start": index + 1,
            "line_end_approx": end,
            "length_approx": end - index,
            "role": role_for(name),
            "role_basis": "name_heuristic",
        })
    return results


def class_body(lines: list[str], owner: str) -> tuple[int, int]:
    declaration = re.compile(r"^\s*class\s+" + re.escape(owner) + r"\b")
    for index, line in enumerate(lines):
        if not declaration.search(strip_comments(line)):
            continue
        depth = 0
        opened = False
        for end in range(index, len(lines)):
            code = strip_comments(lines[end])
            depth += code.count("{") - code.count("}")
            opened = opened or "{" in code
            if opened and depth <= 0:
                return index, end
    raise ValueError(f"cannot find class body for {owner}")


def fields(lines: list[str], owner: str, relative: str) -> list[dict[str, Any]]:
    results = []
    pattern = re.compile(r"\b(?P<name>m_[A-Za-z0-9_]+)\s*(?=[;=\[\{,])")
    # Only class-depth-one statements are eligible. This excludes fields of
    # nested structs and references inside inline method bodies.
    body_start, body_end = class_body(lines, owner)
    depth = 0
    previous = ""
    for index in range(body_start, body_end + 1):
        code = strip_comments(lines[index]).strip()
        depth_before = depth
        depth += code.count("{") - code.count("}")
        if depth_before != 1:
            previous = ""
            continue
        declaration = (previous + " " + code).strip() if previous else code
        for match in pattern.finditer(code):
            prefix = code[: match.start()]
            if "return" in prefix or "{" in prefix or "&" == prefix.rstrip()[-1:]:
                continue
            results.append({
                "name": match.group("name"), "owner": owner,
                "file": relative, "line": index + 1,
                "declaration": declaration,
                "scope": "owner_class_body",
            })
        previous = "" if ";" in code or "{" in code or "}" in code else declaration
    return results


def _record_fields(
    lines: list[str], start: int, end: int, record_owner: str, relative: str,
) -> list[dict[str, Any]]:
    results = []
    if start == end and "{" in lines[start] and "}" in lines[start]:
        inner = strip_comments(lines[start]).split("{", 1)[1].rsplit("}", 1)[0]
        for fragment in inner.split(";"):
            declaration = fragment.strip()
            if not declaration or "(" in declaration:
                continue
            declaration += ";"
            name_match = re.search(
                r"\b([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*(?:=[^;]*|\{[^;]*\})?;$",
                declaration,
            )
            results.append({
                "owner": record_owner,
                "name": name_match.group(1) if name_match else "UNPARSED",
                "file": relative,
                "line": start + 1,
                "declaration": declaration,
                "scope": "record_body_depth_one",
            })
        return results
    depth = 0
    for index in range(start, end + 1):
        code = strip_comments(lines[index]).strip()
        depth_before = depth
        depth += code.count("{") - code.count("}")
        if depth_before != 1 or ";" not in code or code.startswith("}"):
            continue
        if "(" in code or code.startswith(("typedef ", "using ")):
            continue
        declaration = code.split(";", 1)[0].strip() + ";"
        name_match = re.search(
            r"\b([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*(?:=[^;]*|\{[^;]*\})?;$",
            declaration,
        )
        results.append({
            "owner": record_owner,
            "name": name_match.group(1) if name_match else "UNPARSED",
            "file": relative,
            "line": index + 1,
            "declaration": declaration,
            "scope": "record_body_depth_one",
        })
    return results


def state_records(
    lines: list[str], owner: str, relative: str,
    owner_fields: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Inventory nested records and externally declared records held directly."""
    ranges: dict[str, tuple[int, int, str]] = {}
    body_start, body_end = class_body(lines, owner)
    depth = 0
    for index in range(body_start, body_end + 1):
        code = strip_comments(lines[index])
        depth_before = depth
        depth += code.count("{") - code.count("}")
        match = re.search(r"\bstruct\s+([A-Za-z_]\w*)\b", code)
        if depth_before >= 1 and match:
            ranges[match.group(1)] = (
                index, find_function_end(lines, index), "nested_record",
            )

    # CWebServer directly embeds two legacy anonymous-typedef records. Resolve
    # any such direct member type without attributing the record's fields to
    # CWebServer itself.
    direct_types = {
        declaration.split()[0]
        for field in owner_fields
        for declaration in [field["declaration"]]
        if declaration and declaration.split()
    }
    for record_name in direct_types:
        ending = re.compile(r"}\s*" + re.escape(record_name) + r"\s*;")
        for end, line in enumerate(lines):
            if not ending.search(strip_comments(line)):
                continue
            for start in range(end - 1, -1, -1):
                if re.match(r"^\s*typedef\s+struct\b", strip_comments(lines[start])):
                    ranges.setdefault(record_name, (start, end + 1, "header_typedef"))
                    break
            break

    parsed_fields = {
        record_name: _record_fields(lines, start, end - 1, record_name, relative)
        for record_name, (start, end, _scope) in ranges.items()
    }
    aliases: dict[str, str] = {}
    for line in lines[body_start : body_end + 1]:
        match = re.match(
            r"^\s*typedef\s+(?P<target>.+?)\s+(?P<alias>[A-Za-z_]\w*)\s*;",
            strip_comments(line),
        )
        if match:
            aliases[match.group("alias")] = match.group("target")
    records = []
    for record_name, (start, end, declaration_scope) in sorted(
        ranges.items(), key=lambda item: item[1][0],
    ):
        container = owner
        if declaration_scope == "nested_record":
            enclosing = [
                (other_end - other_start, other_name)
                for other_name, (other_start, other_end, _other_scope) in ranges.items()
                if other_name != record_name and other_start < start and end <= other_end
            ]
            if enclosing:
                container = min(enclosing)[1]
            declaration_scope = f"declared_within:{container}"
        relationships = []
        candidate_containers = [(owner, owner_fields)] + [
            (other_name, other_fields)
            for other_name, other_fields in parsed_fields.items()
            if other_name != record_name
        ]
        for candidate_owner, candidate_fields in candidate_containers:
            names = [
                field["name"] for field in candidate_fields
                if re.search(
                    r"\b" + re.escape(record_name) + r"\b", field["declaration"],
                )
            ]
            if names:
                relationships.append({
                    "owner": candidate_owner,
                    "fields": names,
                    "via_alias": None,
                })
        for alias, target in aliases.items():
            if not re.search(r"\b" + re.escape(record_name) + r"\b", target):
                continue
            names = [
                field["name"] for field in owner_fields
                if re.search(r"\b" + re.escape(alias) + r"\b", field["declaration"])
            ]
            if names:
                relationships.append({
                    "owner": owner,
                    "fields": names,
                    "via_alias": alias,
                })
        unique_relationships = []
        seen_relationships = set()
        for relationship in relationships:
            key = (
                relationship["owner"],
                tuple(relationship["fields"]),
                relationship["via_alias"],
            )
            if key not in seen_relationships:
                seen_relationships.add(key)
                unique_relationships.append(relationship)
        if unique_relationships:
            container = unique_relationships[0]["owner"]
        contained_by = sorted({
            field
            for relationship in unique_relationships
            for field in relationship["fields"]
        })
        records.append({
            "owner": record_name,
            "file": relative,
            "line_start": start + 1,
            "line_end_approx": end,
            "declaration_scope": declaration_scope,
            "contained_by_owner": container,
            "contained_by_fields": contained_by,
            "containment_relationships": unique_relationships,
            "fields": parsed_fields[record_name],
        })
    return records


def lock_inventory(
    header_fields: list[dict[str, Any]], source_lines: list[str], source: str,
    source_functions: list[dict[str, Any]],
) -> dict[str, Any]:
    member_locks = [
        field for field in header_fields
        if any(token in field["declaration"] for token in ("CCriticalSection", "CMutex", "CEvent"))
    ]
    local_locks = []
    operations = []
    acquisitions = []
    sequence_edges: set[tuple[str, str, str]] = set()
    declaration_pattern = re.compile(
        r"\b(?P<storage>static\s+)?(?P<type>CCriticalSection|CMutex|CEvent)"
        r"\s+(?P<lock>[A-Za-z_]\w*)\s*(?:[;({=])"
    )
    guard_pattern = re.compile(
        r"\bCSingleLock\s+(?P<guard>[A-Za-z_]\w*)\s*\(\s*&\s*"
        r"(?:(?:self|this)\s*->\s*)?(?P<lock>[A-Za-z_]\w*)"
        r"\s*,\s*(?P<immediate>TRUE|FALSE)\b"
    )
    direct_pattern = re.compile(
        r"(?:(?:self|this)\s*->\s*)?(?P<lock>[ms]_[A-Za-z_]\w*)"
        r"\s*\.\s*(?P<operation>Lock|Unlock)\s*\("
    )
    guard_operation_pattern = re.compile(
        r"\b(?P<guard>[A-Za-z_]\w*)\s*\.\s*(?P<operation>Lock|Unlock)\s*\("
    )

    owner_ranges = [
        (item["line_start"], item["line_end_approx"]) for item in source_functions
    ]
    local_lock_names: set[str] = set()
    for number, line in enumerate(source_lines, 1):
        for match in declaration_pattern.finditer(strip_comments(line)):
            inside_owner = any(start <= number <= end for start, end in owner_ranges)
            storage = (
                "function_static" if match.group("storage") and inside_owner
                else "anonymous_namespace_static" if match.group("storage")
                else "function_local" if inside_owner
                else "source_scope"
            )
            local_lock_names.add(match.group("lock"))
            local_locks.append({
                "file": source,
                "line": number,
                "name": match.group("lock"),
                "type": match.group("type"),
                "storage": storage,
            })

    # Record lexical operations inside one extracted function.  Sequence edges
    # express source order only: they deliberately do not claim that a previous
    # guard is still held across scopes, early returns or explicit Unlock calls.
    for function in source_functions:
        acquired_sequence: list[str] = []
        guards: dict[str, str] = {}
        for number in range(function["line_start"], function["line_end_approx"] + 1):
            code = strip_comments(source_lines[number - 1])
            guard_spans = []
            for match in guard_pattern.finditer(code):
                guard_spans.append(match.span())
                lock = match.group("lock")
                guard = match.group("guard")
                guards[guard] = lock
                immediate = match.group("immediate") == "TRUE"
                operation = {
                    "file": source, "line": number, "lock": lock,
                    "guard": guard, "operation": "construct_and_lock" if immediate else "construct_unlocked",
                    "function": function["name"],
                    "scope": "lexical_function_range",
                }
                operations.append(operation)
                if immediate:
                    acquisitions.append(operation)
                    for earlier in acquired_sequence:
                        if earlier != lock:
                            sequence_edges.add((function["name"], earlier, lock))
                    acquired_sequence.append(lock)
            for match in direct_pattern.finditer(code):
                if any(start <= match.start() < end for start, end in guard_spans):
                    continue
                lock = match.group("lock")
                kind = match.group("operation").lower()
                operation = {
                    "file": source, "line": number, "lock": lock,
                    "operation": f"direct_{kind}", "function": function["name"],
                    "scope": "lexical_function_range",
                }
                operations.append(operation)
                if kind == "lock":
                    acquisitions.append(operation)
                    for earlier in acquired_sequence:
                        if earlier != lock:
                            sequence_edges.add((function["name"], earlier, lock))
                    acquired_sequence.append(lock)
            for match in guard_operation_pattern.finditer(code):
                guard = match.group("guard")
                if guard not in guards:
                    continue
                lock = guards[guard]
                kind = match.group("operation").lower()
                operation = {
                    "file": source, "line": number, "lock": lock,
                    "guard": guard, "operation": f"guard_{kind}",
                    "function": function["name"],
                    "scope": "lexical_function_range",
                }
                operations.append(operation)
                if kind == "lock":
                    acquisitions.append(operation)
                    for earlier in acquired_sequence:
                        if earlier != lock:
                            sequence_edges.add((function["name"], earlier, lock))
                    acquired_sequence.append(lock)

    # Namespace/source helpers are outside the owning class's qualified method
    # ranges but can still guard coordinator state or policy. Record their
    # immediate RAII acquisitions without pretending they are owner methods.
    covered = {(item["line"], item["lock"], item["operation"]) for item in operations}
    for number, line in enumerate(source_lines, 1):
        for match in guard_pattern.finditer(strip_comments(line)):
            lock = match.group("lock")
            if lock not in local_lock_names:
                continue
            operation_name = (
                "construct_and_lock" if match.group("immediate") == "TRUE"
                else "construct_unlocked"
            )
            if (number, lock, operation_name) in covered:
                continue
            helper = "source_helper"
            for candidate in range(number - 1, max(0, number - 12), -1):
                helper_match = re.search(
                    r"\b([A-Za-z_]\w*)\s*\([^;{}]*\)\s*(?:const\s*)?\{?\s*$",
                    strip_comments(source_lines[candidate - 1]).strip(),
                )
                if helper_match:
                    helper = f"anonymous_namespace::{helper_match.group(1)}"
                    break
            operation = {
                "file": source, "line": number, "lock": lock,
                "guard": match.group("guard"), "operation": operation_name,
                "function": helper, "scope": "lexical_source_helper",
            }
            operations.append(operation)
            if match.group("immediate") == "TRUE":
                acquisitions.append(operation)
    return {
        "member_fields": member_locks,
        "local_definitions": local_locks,
        "operation_sites": operations,
        "acquisition_sites": acquisitions,
        "lexical_acquisition_sequence_edges": [
            {"function": function, "before": before, "after": after,
             "scope": "same_function_source_sequence_not_held-set_proof"}
            for function, before, after in sorted(sequence_edges)
        ],
        "target_order": "UNSPECIFIED: inventory only; no lock-order policy is introduced by MOD-0.1.",
    }


def entrypoints(
    lines: list[str], relative: str, owner: str,
    source_functions: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    pattern = re.compile(
        r"\b(AfxBeginThread|CreateThread|PostMessage|SendMessage|CALLBACK|"
        r"\w*(?:Worker|Callback)\w*|\w*(?:Thread|Timer)Proc)\b"
    )
    results = []
    for number, line in enumerate(lines, 1):
        hits = sorted(set(pattern.findall(strip_comments(line))))
        if hits:
            results.append({
                "file": relative, "line": number, "markers": hits,
                "evidence_kind": "dispatch_or_thread_token",
            })
        callbacks = sorted(set(re.findall(
            r"=\s*&?" + re.escape(owner) + r"::([A-Za-z_]\w*)", strip_comments(line),
        )))
        if callbacks:
            results.append({
                "file": relative, "line": number,
                "markers": [f"{owner}::{name}" for name in callbacks],
                "evidence_kind": "explicit_callback_assignment",
            })
        qsort_callbacks = sorted(set(re.findall(
            r"\bqsort_s\s*\(.*?&(_[A-Za-z_]\w*)", strip_comments(line),
        )))
        if qsort_callbacks:
            results.append({
                "file": relative, "line": number,
                "markers": [f"{owner}::{name}" for name in qsort_callbacks],
                "evidence_kind": "explicit_sync_callback_assignment",
            })
    for function in source_functions:
        if function["role"] not in {"event_or_callback_handler", "worker_or_thread_entry"}:
            continue
        results.append({
            "file": function["file"], "line": function["line_start"],
            "markers": [function["name"]],
            "evidence_kind": "name_based_entrypoint_candidate",
        })
    results.sort(key=lambda item: (item["file"], item["line"], item["evidence_kind"]))
    return results


def explicit_callback_names(lines: list[str], owner: str) -> set[str]:
    pattern = re.compile(
        r"=\s*&?" + re.escape(owner) + r"::([A-Za-z_]\w*)",
    )
    names = {
        f"{owner}::{name}"
        for line in lines
        for name in pattern.findall(strip_comments(line))
    }
    names.update({
        f"{owner}::{name}"
        for line in lines
        for name in re.findall(
            r"\bqsort_s\s*\(.*?&(_[A-Za-z_]\w*)", strip_comments(line),
        )
    })
    return names


def external_async_callback_edges(key: str) -> list[dict[str, Any]]:
    if key != "LiveStreamManager":
        return []
    evidence = [
        ("srchybrid/LiveStreamManager.cpp", 298, "auto chunkCb"),
        ("srchybrid/LiveStreamManager.cpp", 300, "FeedSegment"),
        ("srchybrid/LiveStreamManager.cpp", 305, "chunkCb"),
        ("srchybrid/LiveStreamManager.cpp", 307, "chunkCb"),
        ("srchybrid/LiveStreamManager.cpp", 315, "chunkCb"),
        ("srchybrid/LiveStreamManager.cpp", 317, "chunkCb"),
        ("srchybrid/RTMPIngest.h", 11, "watcher thread"),
        ("srchybrid/RTMPIngest.h", 19, "watcher thread"),
        ("srchybrid/RTMPIngest.cpp", 344, "m_callback"),
        ("srchybrid/RTMPIngest.cpp", 512, "m_callback"),
        ("srchybrid/RTMPIngest.cpp", 610, "m_callback"),
        ("srchybrid/RTMPIngest.cpp", 1015, "m_callback"),
        ("srchybrid/RTMPIngest.cpp", 1392, "m_callback"),
        ("srchybrid/RTMPIngest.cpp", 1394, "m_callback"),
    ]
    for relative, line, token in evidence:
        source_lines = git_show(relative).decode("utf-8", errors="replace").splitlines()
        if line > len(source_lines) or token not in source_lines[line - 1]:
            raise ValueError(
                f"async callback evidence drifted: {relative}:{line} lacks {token!r}"
            )
    return [{
        "edge": "CRTMPIngest watcher thread -> chunkCb -> CLiveStreamManager::FeedSegment",
        "callback": "chunkCb",
        "thread_contract": "invoked_on_rtmp_watcher_thread",
        "definition": {"file": evidence[0][0], "line": evidence[0][1]},
        "target": {"file": evidence[1][0], "line": evidence[1][1],
                   "function": "CLiveStreamManager::FeedSegment"},
        "registration_lines": [305, 307, 315, 317],
        "external_contract_evidence": [
            {"file": relative, "line": line, "token": token}
            for relative, line, token in evidence[6:]
        ],
        "lifetime_risk": (
            "callback crosses the RTMP watcher thread and dereferences the global "
            "liveStreamManager; extraction requires explicit shutdown/lifetime fencing"
        ),
    }]


def test_seams(key: str, owner: str) -> list[dict[str, Any]]:
    terms = (key, owner, f"{key}.cpp", f"{key}.h")
    matches = []
    pattern = "|".join(re.escape(term) for term in terms)
    grep = subprocess.run(
        ["git", "grep", "-l", "-E", pattern, BASELINE, "--"], cwd=ROOT,
        text=True, encoding="utf-8", stdout=subprocess.PIPE, check=False,
    )
    for listed in grep.stdout.splitlines():
        prefix, separator, relative = listed.partition(":")
        if not separator or prefix != BASELINE:
            continue
        parts = {part.lower() for part in Path(relative).parts}
        if not ({"test", "tests"} & parts):
            continue
        if Path(relative).suffix.lower() not in {".py", ".ps1", ".cpp", ".h", ".md", ".js", ".ts"}:
            continue
        text = git_show(relative).decode("utf-8", errors="replace")
        count = sum(text.count(term) for term in terms)
        if count:
            matches.append({
                "file": relative, "term_hits": count,
                "evidence_kind": "lexical_reference_not_coverage_proof",
            })
    return sorted(matches, key=lambda item: item["file"])


def monolith(key: str, owner: str, source: str, header: str) -> dict[str, Any]:
    source_bytes, header_bytes = git_show(source), git_show(header)
    source_text = source_bytes.decode("utf-8", errors="replace")
    header_text = header_bytes.decode("utf-8", errors="replace")
    source_lines, header_lines = source_text.splitlines(), header_text.splitlines()
    header_fields = fields(header_lines, owner, header)
    source_functions = functions(source_lines, owner, source)
    header_inline_functions = inline_functions(header_lines, owner, header)
    callback_names = explicit_callback_names(source_lines, owner)
    for function in source_functions + header_inline_functions:
        if function["name"] in callback_names:
            function["role"] = "event_or_callback_handler"
            function["role_basis"] = "explicit_callback_assignment"
    async_edges = external_async_callback_edges(key)
    thread_entrypoints = entrypoints(source_lines, source, owner, source_functions)
    for edge in async_edges:
        thread_entrypoints.append({
            "file": edge["definition"]["file"],
            "line": edge["definition"]["line"],
            "markers": [edge["callback"], edge["target"]["function"]],
            "evidence_kind": "explicit_async_worker_callback",
            "registration_lines": edge["registration_lines"],
        })
    thread_entrypoints.sort(
        key=lambda item: (item["file"], item["line"], item["evidence_kind"]),
    )
    return {
        "name": key,
        "owner": owner,
        "files": [
            {"path": source, "sha256": digest(source_bytes), "loc_physical": len(source_lines), "loc_logical_approx": logical_lines(source_text)},
            {"path": header, "sha256": digest(header_bytes), "loc_physical": len(header_lines), "loc_logical_approx": logical_lines(header_text)},
        ],
        "qualified_source_definitions": source_functions,
        "inline_header_definitions": header_inline_functions,
        "mutable_fields": header_fields,
        "state_records": state_records(header_lines, owner, header, header_fields),
        "direct_includes": {source: includes(source_lines), header: includes(header_lines)},
        "locks": lock_inventory(header_fields, source_lines, source, source_functions),
        "thread_task_callback_entrypoints": thread_entrypoints,
        "external_async_callback_edges": async_edges,
        "existing_test_seams": test_seams(key, owner),
        "candidate_responsibilities": RESPONSIBILITIES[key],
        "risks": RISKS[key],
        "stop_conditions": STOP_CONDITIONS[key],
    }


def build() -> dict[str, Any]:
    subprocess.check_call(["git", "cat-file", "-e", f"{BASELINE}^{{commit}}"], cwd=ROOT)
    return {
        "inventory_id": "urn:emule:architecture-inventory:mod-0.1:v1",
        "baseline_commit": BASELINE,
        "baseline_content_encoding": (
            "git-blob UTF-8; hashes and LOC use the exact Git object bytes; "
            "working-tree drift checks normalize line endings"
        ),
        "scope": "inventory only: no extraction or production behavior change",
        "privacy_sanitization": {
            "contains_raw_network_endpoints": False,
            "contains_credentials_or_session_values": False,
            "recorded_content": "identifiers, relative paths, hashes, metrics and lexical structural metadata only",
        },
        "parser_limitations": [
            "Lexical C++/MFC scan; it is not a preprocessor, compiler or whole-program call graph.",
            "Function ranges are approximate and can be affected by macros, lambdas, braces in literals or conditional compilation.",
            "Header inline definitions and state records are class-depth lexical inventories; macro-generated declarations still require human review.",
            "Roles marked name_heuristic are routing aids, not semantic call-graph classifications; explicit callback assignments override that heuristic.",
            "Lock operations and sequence edges are same-function lexical evidence; they do not prove simultaneous ownership, deadlock freedom or a required order.",
            "Thread/callback markers are token matches; indirect dispatch and macro-expanded entrypoints require human review.",
        ],
        "monoliths": [monolith(key, *value) for key, value in TARGETS.items()],
    }


def approved_overlays(data: dict[str, Any]) -> tuple[dict[str, str], list[str]]:
    """Return only exact, baseline-bound approved current file hashes."""
    errors: list[str] = []
    try:
        manifest = json.loads(OVERLAY_MANIFEST.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        return {}, [f"MOD-0.1 overlay manifest unavailable: {error}"]
    if manifest.get("schema") != "ese.mod01.approved-overlays/v1":
        errors.append("MOD-0.1 overlay manifest schema is invalid")
    if manifest.get("baseline_commit") != BASELINE:
        errors.append("MOD-0.1 overlay manifest baseline is not the frozen baseline")
    frozen = {
        entry["path"]: entry["sha256"]
        for record in data.get("monoliths", []) for entry in record.get("files", [])
    }
    approved: dict[str, str] = {}
    overlays = manifest.get("overlays")
    if not isinstance(overlays, list) or not overlays:
        errors.append("MOD-0.1 overlay manifest has no explicit overlays")
        return approved, errors
    required = {"path", "baseline_sha256", "overlay_sha256", "task", "reason"}
    for overlay in overlays:
        if not isinstance(overlay, dict) or set(overlay) != required:
            errors.append("MOD-0.1 overlay record must contain only exact approval fields")
            continue
        path = overlay["path"]
        baseline_hash = overlay["baseline_sha256"]
        overlay_hash = overlay["overlay_sha256"]
        valid = (
            isinstance(path, str) and path in frozen and path not in approved
            and baseline_hash == frozen.get(path)
            and isinstance(overlay_hash, str)
            and re.fullmatch(r"[0-9a-f]{64}", overlay_hash) is not None
            and isinstance(overlay["task"], str) and bool(overlay["task"].strip())
            and isinstance(overlay["reason"], str) and bool(overlay["reason"].strip())
        )
        if not valid:
            errors.append(f"MOD-0.1 overlay record is not exact and baseline-bound: {path}")
            continue
        approved[path] = overlay_hash
    return approved, errors


def verify(data: dict[str, Any], content_overrides: dict[str, bytes] | None = None) -> list[str]:
    errors = []
    if data != build():
        errors.append("stored inventory is not reproducible from the frozen baseline")
    approved, overlay_errors = approved_overlays(data)
    errors.extend(overlay_errors)
    for record in data.get("monoliths", []):
        for file_record in record.get("files", []):
            path = ROOT / file_record["path"]
            if not path.is_file():
                errors.append(f"missing working-tree source: {file_record['path']}")
                continue
            current = (content_overrides or {}).get(file_record["path"], path.read_bytes())
            current_hash = digest(normalized(current))
            if current_hash == file_record["sha256"]:
                continue
            if approved.get(file_record["path"]) == current_hash:
                continue
            if file_record["path"] in approved:
                errors.append(f"approved overlay hash drifted: {file_record['path']}")
            else:
                errors.append(f"working-tree monolith changed without a new frozen inventory: {file_record['path']}")
    return errors


def negative_overlay_fixture(data: dict[str, Any]) -> list[str]:
    approved, errors = approved_overlays(data)
    if errors:
        return errors
    path = next(iter(sorted(approved)), None)
    if path is None:
        return ["MOD-0.1 negative overlay fixture needs an approved overlay"]
    mutated = normalized((ROOT / path).read_bytes()) + b"\n// MOD-0.1 negative overlay fixture\n"
    if not verify(data, {path: mutated}):
        return ["MOD-0.1 negative overlay fixture was accepted"]
    return []


def main() -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--verify", action="store_true")
    mode.add_argument("--negative-overlay-fixture", action="store_true")
    args = parser.parse_args()
    if args.write:
        OUTPUT.parent.mkdir(parents=True, exist_ok=True)
        OUTPUT.write_text(json.dumps(build(), indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
        return 0
    try:
        data = json.loads(OUTPUT.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        print(f"MOD-0.1 inventory unavailable: {error}", file=sys.stderr)
        return 1
    errors = negative_overlay_fixture(data) if args.negative_overlay_fixture else verify(data)
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
