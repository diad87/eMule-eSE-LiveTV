#!/usr/bin/env python3
"""Freeze the inventory of legacy local-port reads.

The direct-reachability work must replace each public-advertisement read
deliberately. A new direct call to CPreferences::GetPort/GetUDPPort is therefore
a failure until it is reviewed and added to the explicit allowlist below.
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
    "FirewallProberV6.cpp": 2,
    "ListenSocket.cpp": 5,
    "kademlia/kademlia/Prefs.cpp": 1,
    "LiveTunnel.cpp": 1,
    "NetworkInfoDlg.cpp": 5,
    "PartFile.cpp": 2,
    "PartFile.utf8.cpp": 2,
    # D0 reviewed: UI enablement and Windows Firewall rule management only;
    # these reads never advertise a public endpoint to a peer.
    "PPgConnection.cpp": 7,
    "PShtWiz1.cpp": 5,
    "RelayClient.cpp": 1,
    "WebServer.cpp": 2,
    # D0 reviewed: decides whether the selected Kad2/Kad6 instances may start
    # when no local UDP socket is configured; it is not an advertised port.
    "kademlia/kademlia/Kademlia.cpp": 1,
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
    if total != 55:
        failures.append(f"total: expected 55, found {total}")
    if line_count != 54:
        failures.append(f"lines: expected 54, found {line_count}")

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
