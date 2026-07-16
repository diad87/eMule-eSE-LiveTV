#!/usr/bin/env python3
"""Freeze the D0 inventory of legacy local-port reads.

The direct-reachability work must replace each public-advertisement read
deliberately. A new direct call to CPreferences::GetPort/GetUDPPort is therefore
an audit failure until docs/DIRECT_REACHABILITY_D0_AUDIT.md is updated.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path


EXPECTED = {
    "ClientList.cpp": 3,
    "ClientUDPSocket.cpp": 6,
    "DownloadClient.cpp": 1,
    "Emule.cpp": 7,
    "EmuleDlg.cpp": 4,
    "ListenSocket.cpp": 5,
    "kademlia/kademlia/Prefs.cpp": 1,
    "LiveTunnel.cpp": 1,
    "NetworkInfoDlg.cpp": 5,
    "PartFile.cpp": 2,
    "PartFile.utf8.cpp": 2,
    "PPgConnection.cpp": 6,
    "PShtWiz1.cpp": 5,
    "RelayClient.cpp": 1,
    "WebServer.cpp": 2,
}

PATTERN = re.compile(r"thePrefs\.Get(?:UDP)?Port\(\)")


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    source_root = root / "srchybrid"
    found: dict[str, int] = {}
    line_count = 0

    for path in source_root.rglob("*"):
        if path.suffix.lower() not in {".cpp", ".h"} or path.name == "WebServer_original.cpp":
            continue
        text = path.read_text(encoding="utf-8-sig", errors="replace")
        count = len(PATTERN.findall(text))
        if count:
            key = path.relative_to(source_root).as_posix()
            found[key] = count
            line_count += sum(bool(PATTERN.search(line)) for line in text.splitlines())

    failures = []
    for key in sorted(set(EXPECTED) | set(found)):
        if EXPECTED.get(key) != found.get(key):
            failures.append(f"{key}: expected {EXPECTED.get(key, 0)}, found {found.get(key, 0)}")

    total = sum(found.values())
    if total != 51:
        failures.append(f"total: expected 51, found {total}")
    if line_count != 50:
        failures.append(f"lines: expected 50, found {line_count}")

    if failures:
        print("Direct-port inventory drift detected:")
        for failure in failures:
            print(f"  - {failure}")
        print("Classify every changed use before updating EXPECTED and the D0 audit.")
        return 1

    print(f"Legacy local-port inventory stable: {total} calls on {line_count} lines in {len(found)} files.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
