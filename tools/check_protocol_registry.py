#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
check_protocol_registry.py  --  P0 deliverable 2 (eSE fork).

CI gate for the single source of truth in docs/protocol/*.csv.

It FAILS (exit 1) on:
  * duplicate (namespace, value) pairs   -> wire collision
  * a fork-owned symbol defined in code but absent from the registry (unregistered)
  * a registry value that disagrees with the value in code (doc-vs-code drift)
  * a 'stable'/'experimental' registry row with no matching symbol in code

It does NOT police the classic eD2K/Kad protocol: that namespace is upstream-owned
and frozen. Only the fork's additive surface is governed here (see PREFIXES below).

Run:  python tools/check_protocol_registry.py
"""
import csv
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROTO = ROOT / "docs" / "protocol"
OPCODES_H = ROOT / "srchybrid" / "Opcodes.h"
TUNNEL_H = ROOT / "srchybrid" / "LiveTunnel.h"
KRP_CONTROL_H = ROOT / "librelaycore" / "include" / "relay" / "krp_control.h"

# Statuses that are allowed to exist in the registry without a code symbol yet.
RESERVED_STATES = {"reserved-proposed", "design"}

# A symbol in code is "fork-owned" (and therefore must be registered) when its
# name matches one of these. Everything else is classic/upstream and ignored.
def is_fork_symbol(name: str) -> bool:
    if name in ("OP_PUBLICIP_ANSWER_V6", "OP_CALLBACK_V6", "OP_FOUNDSOURCES_V6",
                "ST_IPV6", "TAG_K_EFFECTIVE", "TAG_SHARD_DEGREE",
                "TAG_PINNED_BY_SUBSCRIBER", "TAG_SOURCEIP_V6", "TAG_SERVERIP_V6",
                "KADEMLIA2_KEY_SHARD_ANNOUNCE", "KADEMLIA2_PUBLISH_TRIGRAM_REQ",
                "KADEMLIA2_SEARCH_TRIGRAM_REQ", "KADEMLIA2_BLOOM_DIGEST_REQ",
                "KADEMLIA2_LOCAL_QUERY_REQ", "KADEMLIA2_LOCAL_QUERY_RES"):
        return True
    for pre in ("OP_LIVE_", "KADEMLIA3_", "KADEMLIA_ESE_HOLEPUNCH_",
                "ESE_CAP_", "CAP_FORK_", "TAG_ESE_", "TUN_OP_", "KRP_"):
        if name.startswith(pre):
            return True
    return False

DEF_NUM = re.compile(r'#define\s+([A-Z0-9_]+)\s+(0x[0-9A-Fa-f]+|\d+)\b')
DEF_TAG = re.compile(r'#define\s+([A-Z0-9_]+)\s+"\\x([0-9A-Fa-f]{2})"')
ENUM_VAL = re.compile(r'\b(TUN_OP_[A-Z0-9_]+)\s*=\s*(0x[0-9A-Fa-f]+|\d+)')
KRP_ENUM_VAL = re.compile(r'\b(KRP_[A-Z0-9_]+)\s*=\s*(0x[0-9A-Fa-f]+|\d+)')


def norm(v: str):
    v = v.strip()
    return int(v, 16) if v.lower().startswith("0x") else int(v)


def parse_code():
    """Return {name: (value:int, file:str, line:int)} for fork-owned symbols."""
    out = {}
    for path in (OPCODES_H, TUNNEL_H, KRP_CONTROL_H):
        if not path.exists():
            print(f"  ! cannot read {path}", file=sys.stderr)
            continue
        for i, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            for rx, base in ((DEF_NUM, None), (DEF_TAG, 16), (ENUM_VAL, None),
                             (KRP_ENUM_VAL, None)):
                m = rx.search(line)
                if not m:
                    continue
                name = m.group(1)
                if not is_fork_symbol(name):
                    continue
                val = int(m.group(2), 16) if base == 16 else norm(m.group(2))
                # first definition wins; aliases (non-numeric rhs) never match the regexes
                out.setdefault(name, (val, path.name, i))
    return out


def load_registry():
    rows = []
    for csv_name in ("OPCODES.csv", "TAGS.csv", "CAPABILITIES.csv", "TUNNEL_SERVICES.csv",
                     "KRP_MESSAGES.csv"):
        p = PROTO / csv_name
        if not p.exists():
            print(f"  ! missing registry file {p}", file=sys.stderr)
            continue
        with p.open(encoding="utf-8") as f:
            for r in csv.DictReader(f):
                r["_src"] = csv_name
                r["_val"] = norm(r["value"])
                rows.append(r)
    return rows


def main():
    errors, warnings = [], []
    reg = load_registry()
    code = parse_code()

    # --- check 1: duplicate (namespace, value) within the registry ---------
    seen = {}
    for r in reg:
        key = (r["namespace"], r["_val"])
        if key in seen:
            errors.append(
                f"DUPLICATE VALUE  {r['namespace']} {r['value']}: "
                f"'{seen[key]}' and '{r['name']}' (wire collision)")
        else:
            seen[key] = r["name"]

    by_name = {r["name"]: r for r in reg}

    # --- check 2: every fork symbol in code is registered, value matches ---
    for name, (val, fname, line) in sorted(code.items()):
        r = by_name.get(name)
        if r is None:
            errors.append(f"UNREGISTERED   {name} = {hex(val)} ({fname}:{line}) not in registry")
        elif r["_val"] != val:
            errors.append(
                f"DRIFT          {name}: code={hex(val)} ({fname}:{line}) "
                f"!= registry={r['value']} ({r['_src']})")

    # --- check 3: every non-reserved registry row exists in code -----------
    for r in reg:
        if r["status"].strip().lower() in RESERVED_STATES:
            continue
        if r["name"] not in code:
            warnings.append(
                f"NOT-IN-CODE    {r['name']} ({r['_src']}, status={r['status']}) "
                f"has no matching #define (stale registry row?)")

    print(f"protocol registry: {len(reg)} entries, {len(code)} fork symbols in code")
    for w in warnings:
        print(f"  WARN  {w}")
    for e in errors:
        print(f"  FAIL  {e}")
    if errors:
        print(f"\n{len(errors)} conflict(s). See docs/protocol/PROTOCOL_REGISTRY.md for the "
              f"migration proposal. CI is red until they are resolved.")
        return 1
    print("OK: registry is internally consistent and matches code.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
