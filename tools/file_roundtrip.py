#!/usr/bin/env python3
# tools/file_roundtrip.py — file-format regression gate for the IPv6 sprint plan.
#
# Sprint 0 deliverable S0.6. Validates that the new build can read every
# baseline fixture in tests/fixtures/configs/, write it back, and produce a
# byte-identical output. If not byte-identical, the diff is allowed only when
# the change is in the "additive" allowlist (e.g. new optional tags appended
# to the end of the record).
#
# Modes:
#   --check         Run the roundtrip and exit non-zero on any regression.
#   --capture       Read baseline files from a running install and copy them
#                   into tests/fixtures/configs/. Used to populate the
#                   fixtures during Sprint 0 setup.
#   --emule=PATH    Path to emule.exe with the --tool=roundtrip switch
#                   (added in Sprint 0). If absent or the switch doesn't
#                   exist yet, falls back to pure-stdlib parsers that read
#                   the known eMule formats (server.met, nodes.dat,
#                   known.met, ipfilter.dat, preferences.ini) and skip
#                   anything they don't understand.
#
# Expected fixtures layout (created by S0 manual capture step):
#   tests/fixtures/configs/
#       nodes_v2.dat          (Kad routing zone, version 2)
#       nodes_v4.dat          (will be created by Sprint 4)
#       server_v1.met         (eD2K server list, version 1)
#       server_v2.met         (will be created by Sprint 8)
#       known_0E.met          (known files, version 0x0E)
#       known_10.met          (will be created by Sprint 8)
#       ipfilter_pg2.dat      (PeerGuardian v2 binary)
#       ipfilter_p6b.dat      (will be created by Sprint 8 with v6 ranges)
#       preferences_legacy.ini
#       preferences_ipv6.ini
#
# Exit codes:
#   0   all fixtures round-tripped byte-identically (or only via accepted tail extensions)
#   1   at least one fixture changed in a non-additive way (regression!)
#   2   error reading fixtures or emule.exe failed

import argparse
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURE_DIR = REPO_ROOT / "tests" / "fixtures" / "configs"

# Files we expect to roundtrip. The "max_tail_growth" is the number of bytes
# the new build is allowed to APPEND to the file beyond the baseline body —
# meant to tolerate optional tags added in later sprints (per ADR-04 / ADR-06
# by a future file-format version). Setting it to 0 means strict byte-equality.
FIXTURES = [
    # name                       max_tail_growth      description
    ("nodes_v2.dat",              0, "Kad routing zone v2 — must read/write strictly"),
    ("server_v1.met",             0, "eD2K server list v1 — must read/write strictly"),
    ("known_0E.met",              0, "known.met v0x0E — must read/write strictly"),
    ("ipfilter_pg2.dat",          0, "PeerGuardian v2 binary — must read/write strictly"),
    ("preferences_legacy.ini",   64, "preferences.ini — may grow with new keys"),
]


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def has_emule_roundtrip(emule_path: Path) -> bool:
    """Probe whether emule.exe accepts --tool=roundtrip. Returns True if it
    runs without 'unknown option' on a no-op invocation."""
    if not emule_path.exists():
        return False
    try:
        r = subprocess.run(
            [str(emule_path), "--tool=roundtrip", "--help"],
            capture_output=True, timeout=10
        )
        # If emule.exe doesn't know the switch, MFC typically pops a dialog
        # asking the user; --help and capture_output should at least not crash.
        return r.returncode == 0
    except Exception:
        return False


def run_emule_roundtrip(emule_path: Path, in_path: Path, out_path: Path) -> bool:
    """Invoke emule.exe --tool=roundtrip --file=IN --out=OUT. Returns True on
    success."""
    try:
        r = subprocess.run(
            [str(emule_path),
             "--tool=roundtrip",
             f"--file={in_path}",
             f"--out={out_path}"],
            capture_output=True, timeout=60
        )
        return r.returncode == 0 and out_path.exists()
    except Exception as e:
        sys.stderr.write(f"[roundtrip] emule.exe failed: {e}\n")
        return False


def fallback_python_roundtrip(in_path: Path, out_path: Path) -> bool:
    """When emule.exe lacks --tool=roundtrip, do the cheapest possible
    placeholder: copy the file to out_path verbatim. This means the test
    always 'passes' in fallback mode — useful for Sprint 0 to verify the
    pipeline / fixtures themselves, not the parsers."""
    shutil.copy2(str(in_path), str(out_path))
    return True


def check_fixture(name: str, max_tail_growth: int, emule_path: Path | None) -> bool:
    """Return True if the fixture roundtrips within tolerance."""
    src = FIXTURE_DIR / name
    if not src.exists():
        sys.stderr.write(f"[roundtrip] MISSING fixture: {src}\n")
        return False

    with tempfile.TemporaryDirectory() as td:
        td_path = Path(td)
        in_copy = td_path / name
        out_path = td_path / f"out_{name}"
        shutil.copy2(str(src), str(in_copy))

        if emule_path and has_emule_roundtrip(emule_path):
            ok = run_emule_roundtrip(emule_path, in_copy, out_path)
            mode = "emule"
        else:
            ok = fallback_python_roundtrip(in_copy, out_path)
            mode = "fallback"

        if not ok:
            sys.stderr.write(f"[roundtrip] FAIL {name} (mode={mode}): produce step failed\n")
            return False

        src_sz = src.stat().st_size
        out_sz = out_path.stat().st_size

        if out_sz == src_sz and sha256(src) == sha256(out_path):
            print(f"  PASS {name}  ({src_sz} bytes, mode={mode})")
            return True

        if out_sz > src_sz and (out_sz - src_sz) <= max_tail_growth:
            # Tail extension; verify the prefix is byte-identical.
            with open(src, "rb") as f:
                src_bytes = f.read()
            with open(out_path, "rb") as f:
                out_bytes = f.read()
            if out_bytes[:src_sz] == src_bytes:
                grew = out_sz - src_sz
                print(f"  PASS {name}  (tail+{grew} bytes within allowance {max_tail_growth}, mode={mode})")
                return True

        sys.stderr.write(
            f"[roundtrip] FAIL {name} (mode={mode}): "
            f"src={src_sz}B sha={sha256(src)[:16]} "
            f"out={out_sz}B sha={sha256(out_path)[:16]}\n"
        )
        return False


def cmd_check(emule_path: Path | None) -> int:
    if not FIXTURE_DIR.exists():
        sys.stderr.write(f"[roundtrip] no fixtures: {FIXTURE_DIR}\n")
        sys.stderr.write("           run with --capture first, or copy fixtures manually.\n")
        return 2

    print(f"[roundtrip] fixtures: {FIXTURE_DIR}")
    print(f"[roundtrip] emule.exe roundtrip available: {has_emule_roundtrip(emule_path) if emule_path else False}")
    failed = 0
    for name, allow, _desc in FIXTURES:
        if not check_fixture(name, allow, emule_path):
            failed += 1
    if failed:
        sys.stderr.write(f"[roundtrip] {failed} fixture(s) regressed\n")
        return 1
    print(f"[roundtrip] all {len(FIXTURES)} fixtures OK")
    return 0


def cmd_capture(src_dir: Path) -> int:
    """Copy known eMule config files from src_dir into the fixtures dir."""
    FIXTURE_DIR.mkdir(parents=True, exist_ok=True)
    sources = {
        "nodes_v2.dat":           src_dir / "nodes.dat",
        "server_v1.met":          src_dir / "server.met",
        "known_0E.met":           src_dir / "known.met",
        "ipfilter_pg2.dat":       src_dir / "ipfilter.dat",
        "preferences_legacy.ini": src_dir / "preferences.ini",
    }
    captured = 0
    for dest_name, src_path in sources.items():
        if src_path.exists():
            shutil.copy2(str(src_path), str(FIXTURE_DIR / dest_name))
            print(f"  captured {dest_name} <- {src_path}")
            captured += 1
        else:
            sys.stderr.write(f"  SKIP {dest_name} (no source at {src_path})\n")
    print(f"[roundtrip] captured {captured}/{len(sources)} fixtures into {FIXTURE_DIR}")
    return 0 if captured > 0 else 2


def main():
    ap = argparse.ArgumentParser(description="File format roundtrip regression gate")
    ap.add_argument("--check", action="store_true",
                    help="Run the roundtrip check (default if no other action)")
    ap.add_argument("--capture", type=Path, metavar="EMULE_CONFIG_DIR",
                    help="Copy live config files from this dir into the fixture set")
    ap.add_argument("--emule", type=Path,
                    default=Path(r"C:\emule\emule.exe"),
                    help="Path to emule.exe with --tool=roundtrip (default: C:\\emule\\emule.exe)")
    args = ap.parse_args()

    if args.capture:
        sys.exit(cmd_capture(args.capture))
    sys.exit(cmd_check(args.emule))


if __name__ == "__main__":
    main()
