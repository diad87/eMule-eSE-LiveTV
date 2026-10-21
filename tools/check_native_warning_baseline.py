#!/usr/bin/env python3
"""Fail when an MSBuild log introduces a new first-party C++ warning."""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path


WARNING_RE = re.compile(
    r"^(?P<path>.+?)\((?P<line>\d+)(?:,\d+)?\): warning "
    r"(?P<code>C\d+):",
    re.IGNORECASE,
)


def first_party_path(raw_path: str) -> str | None:
    normalized = raw_path.replace("/", "\\")
    marker = "\\srchybrid\\"
    lowered = normalized.lower()
    position = lowered.rfind(marker)
    if position < 0:
        return None
    return "srchybrid/" + normalized[position + len(marker) :].replace("\\", "/")


def warnings_from_log(log_path: Path) -> Counter[str]:
    # A C4191 diagnostic prints a second explanatory line with the same
    # location. Deduplicate location+code before reducing to file+code counts.
    unique: set[tuple[str, int, str]] = set()
    for line in log_path.read_text(encoding="utf-8", errors="replace").splitlines():
        match = WARNING_RE.match(line)
        if not match:
            continue
        relative = first_party_path(match.group("path"))
        if relative is None:
            continue
        unique.add(
            (relative, int(match.group("line")), match.group("code").upper())
        )

    counts: Counter[str] = Counter()
    for relative, _line, code in unique:
        counts[f"{relative}|{code}"] += 1
    return counts


def write_baseline(path: Path, counts: Counter[str]) -> None:
    payload = {
        "version": 1,
        "scope": "first-party paths containing /srchybrid/",
        "total": sum(counts.values()),
        "warnings": dict(sorted(counts.items())),
    }
    path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("log", type=Path, help="MSBuild text log")
    parser.add_argument(
        "--baseline",
        type=Path,
        default=Path(__file__).with_name("native_warning_baseline.json"),
    )
    parser.add_argument(
        "--write-baseline",
        action="store_true",
        help="replace the baseline from this reviewed build log",
    )
    args = parser.parse_args()

    if not args.log.is_file():
        print(f"native warning gate FAIL: log not found: {args.log}", file=sys.stderr)
        return 2

    current = warnings_from_log(args.log)
    if args.write_baseline:
        write_baseline(args.baseline, current)
        print(
            f"Native warning baseline written: {sum(current.values())} "
            f"first-party warnings in {len(current)} file/code buckets"
        )
        return 0

    if not args.baseline.is_file():
        print(
            f"native warning gate FAIL: baseline not found: {args.baseline}",
            file=sys.stderr,
        )
        return 2

    baseline = json.loads(args.baseline.read_text(encoding="utf-8"))
    if baseline.get("version") != 1 or not isinstance(
        baseline.get("warnings"), dict
    ):
        print("native warning gate FAIL: unsupported baseline format", file=sys.stderr)
        return 2

    allowed = {key: int(value) for key, value in baseline["warnings"].items()}
    regressions = [
        (key, count, allowed.get(key, 0))
        for key, count in sorted(current.items())
        if count > allowed.get(key, 0)
    ]
    if regressions:
        print("native warning gate FAIL: new first-party warnings:", file=sys.stderr)
        for key, count, maximum in regressions:
            print(f"  {key}: current {count}, baseline {maximum}", file=sys.stderr)
        return 1

    removed = sum(allowed.values()) - sum(current.values())
    print(
        "Native warning ratchet PASS: "
        f"{sum(current.values())}/{sum(allowed.values())} warnings "
        f"({removed} removed from baseline)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
