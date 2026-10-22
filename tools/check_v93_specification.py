#!/usr/bin/env python3
"""Check specification coverage and references; this is not a product test."""

from collections import Counter
from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "docs/V9.3_IMPLEMENTATION_SPECIFICATION.md"
INVENTORY = ROOT / "docs/EMULEAI_PARITY_AND_SUPERIORITY_PROGRAM.md"
PLAN = ROOT / "docs/V9.3_PLUS_RELEASE_TRAIN.md"
STATE = ROOT / "docs/V9.3_EXECUTION_STATE.md"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def main():
    spec = SPEC.read_text(encoding="utf-8")
    inventory = INVENTORY.read_text(encoding="utf-8")
    inventory_ids = re.findall(r"(?m)^\| `(AI-[FI]\d{2})` \|", inventory)
    expected = set(inventory_ids)
    require(len(inventory_ids) == len(expected) == 92, "inventory must contain 92 unique requirements")

    begin = "<!-- V93-SPEC-TRACE:BEGIN -->"
    end = "<!-- V93-SPEC-TRACE:END -->"
    require(spec.count(begin) == spec.count(end) == 1, "missing or duplicate specification trace block")
    before, remainder = spec.split(begin)
    trace, after = remainder.split(end)
    body = before + after
    records = re.findall(
        r"(?m)^\| `(AI-[FI]\d{2})` \| ([^|]+) \| `([A-Z]+-[A-Z0-9]+)` \|$",
        trace,
    )
    counts = Counter(row[0] for row in records)
    require(len(records) == 92 and set(counts) == expected, "trace differs from the complete inventory")
    require(all(count == 1 for count in counts.values()), "requirement assigned more than once")
    tests = [row[2] for row in records]
    require(len(set(tests)) == 92, "primary test must be uniquely identified per requirement")
    plan = PLAN.read_text(encoding="utf-8")
    owner_by_group = {"B0-BASE": "BASE", "V92-ALIGNED": "A", "V95-CORE": "E",
                      "V96-PRODUCT": "F", "V97-NETWORK": "C"}
    plan_owners = {}
    for group, row in re.findall(
        r"(?m)^\| (B0-BASE|V92-ALIGNED|V95-CORE|V96-PRODUCT|V97-NETWORK) \|([^\n]+)$", plan
    ):
        for req in re.findall(r"AI-[FI]\d{2}", row):
            require(req not in plan_owners, f"duplicate plan owner: {req}")
            plan_owners[req] = owner_by_group[group]
    require(set(plan_owners) == expected, "plan ownership map is incomplete")
    for req, owner, test in records:
        require(owner.strip() in {"BASE", "A", "C", "E", "F"}, f"unknown owner: {req}")
        require(owner.strip() == plan_owners[req], f"owner differs from plan: {req}")
        require(req in body, f"requirement has no contract outside trace: {req}")
        require(test in body, f"primary test has no definition outside trace: {test}")

    deltas = re.findall(r"(?m)^\| `(AI16-D\d{2})` \|", spec)
    require(set(deltas) == {f"AI16-D{i:02d}" for i in range(1, 20)}, "missing 1.6 delta contract")
    # Some chapters also cross-reference a delta table; coverage is a set, not
    # a claim that a reference creates another feature or another test run.
    for number in range(1, 8):
        require(f"V98-F{number:02d}" in body, f"server scope missing V98-F{number:02d}")

    for document in (PLAN, STATE):
        require(SPEC.name in document.read_text(encoding="utf-8"), f"{document.name} does not link the specification")
    require(PLAN.name in spec and STATE.name in spec, "specification does not link plan and execution state")
    for link in re.findall(r"\]\(([^)\n]+)\)", spec):
        target = link.split("#", 1)[0]
        if not target or "://" in target:
            continue
        require((SPEC.parent / target).exists(), f"local link does not exist: {target}")
    require(not re.search(r"(?m)^(<<<<<<<|>>>>>>>)", spec), "merge conflict marker in specification")
    table_columns = None
    in_fence = False
    for number, line in enumerate(spec.splitlines(), 1):
        if line.startswith("```"):
            in_fence = not in_fence
        if not in_fence and line.startswith("|"):
            columns = len(re.findall(r"(?<!\\)\|", line)) - 1
            if table_columns is None:
                table_columns = columns
            require(columns == table_columns, f"malformed Markdown table at line {number}")
        else:
            table_columns = None
    require(not in_fence, "unclosed code fence")

    print("v9.3 specification: PASS (92 unique contracts/test mappings, 19 deltas, 7 server features, local links)")
    print("This validates document coverage only; no product test or implementation is certified.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, OSError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        sys.exit(1)
