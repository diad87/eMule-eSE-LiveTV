#!/usr/bin/env python3
"""Reject synchronous child-process calls from the production eSE server."""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SERVER = ROOT / "srchybrid" / "eSE"
EXCLUDED_PARTS = {"node_modules", "test", "tools", "vendor", "_deprecated"}
SYNC_CALL = re.compile(r"\b(?:execFileSync|execSync|spawnSync)\s*\(")

# Hardware probing runs once, serially, before server.listen(). It intentionally
# remains synchronous so the selected encoder is fixed before route setup.
STARTUP_EXCEPTION = SERVER / "hw_encoder.js"


def main() -> int:
    violations: list[str] = []
    exception_calls = 0

    for source in SERVER.rglob("*.js"):
        if any(part in EXCLUDED_PARTS for part in source.relative_to(SERVER).parts):
            continue
        text = source.read_text(encoding="utf-8")
        for line_no, line in enumerate(text.splitlines(), 1):
            if not SYNC_CALL.search(line):
                continue
            if source == STARTUP_EXCEPTION and "spawnSync(" in line:
                exception_calls += 1
                continue
            violations.append(
                f"{source.relative_to(ROOT).as_posix()}:{line_no}: {line.strip()}")

    if exception_calls != 1:
        violations.append(
            "srchybrid/eSE/hw_encoder.js must contain exactly one documented "
            f"startup-only spawnSync call (found {exception_calls})")

    if violations:
        print("Synchronous production child-process gate FAILED:")
        for violation in violations:
            print(f"  {violation}")
        return 1

    print(
        "Synchronous production child-process gate PASS "
        "(only startup hardware probing is exempt)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
