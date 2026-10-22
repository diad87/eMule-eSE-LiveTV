#!/usr/bin/env python3
"""Reject the LiveTunnel pending->tunnel lock edge that caused an AB-BA cycle.

This is a focused structural gate, not a substitute for the runtime stress
test.  It protects the exact integration rule that is otherwise easy to
reintroduce while editing the fair queue:

    m_lock -> m_pendingLock -> leaf locks

The shared USER32 timer is a leaf protected by m_k6ShapeTimerLock and may be
used from either parent domain without nesting those parents.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "srchybrid" / "LiveTunnel.cpp"
HEADER = ROOT / "srchybrid" / "LiveTunnel.h"


def function_body(text: str, signature: str) -> str:
    start = text.find(signature)
    if start < 0:
        raise ValueError(f"missing function: {signature}")
    brace = text.find("{", start)
    if brace < 0:
        raise ValueError(f"missing body: {signature}")
    depth = 0
    for index in range(brace, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return text[brace : index + 1]
    raise ValueError(f"unterminated body: {signature}")


def code_only(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    return re.sub(r"//[^\n]*", "", text)


def main() -> int:
    source = SOURCE.read_text(encoding="utf-8-sig")
    header = HEADER.read_text(encoding="utf-8-sig")
    failures: list[str] = []

    queue = code_only(function_body(source, "bool CLiveTunnel::QueueK6FairPayloadLocked"))
    if "m_lock" in queue or "m_pendingLock" in queue:
        failures.append("QueueK6FairPayloadLocked must not acquire tunnel or pending locks")

    # rc.2 design: the class-5 timer token lives in the fair scheduler and is
    # armed by EnsureK6ShapeTimerLocked() while the caller already holds the
    # tunnel lock and before any pending-rank section, so the helper itself
    # must not take either lock and must publish the token to the scheduler.
    ensure = code_only(function_body(source, "bool CLiveTunnel::EnsureK6ShapeTimerLocked"))
    if "m_lock" in ensure or "m_pendingLock" in ensure:
        failures.append("EnsureK6ShapeTimerLocked must not acquire tunnel or pending locks")
    if "PublishClass5Timer(" not in ensure:
        failures.append("class-5 timer token must be published to the scheduler")
    if "bool EnsureK6ShapeTimerLocked();" not in header:
        failures.append("EnsureK6ShapeTimerLocked declaration is missing from LiveTunnel.h")

    stale_order = re.compile(r"m_pendingLock\s*-+>\s*m_lock")
    if stale_order.search(source) or stale_order.search(header):
        failures.append("stale pending->tunnel lock-order contract found")

    if failures:
        print("LiveTunnel lock-order gate failed:")
        for failure in failures:
            print(f"  - {failure}")
        return 1

    print("LiveTunnel lock-order gate PASS: tunnel -> pending; timer armed under tunnel lock")
    return 0


if __name__ == "__main__":
    sys.exit(main())
