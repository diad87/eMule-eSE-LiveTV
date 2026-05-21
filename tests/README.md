# Tests directory

> Sprint 0 deliverable S0.10. Describes how to run each test level
> defined in [docs/IPV6_SPRINT_PLAN.md §1.1](../docs/IPV6_SPRINT_PLAN.md).

Seven levels, increasing in scope and human cost:

| Level | What it tests                                     | Where it runs                | Cost      | Status today |
|-------|---------------------------------------------------|------------------------------|-----------|--------------|
| L0    | Compilation (Debug/Release × x86/x64)             | MSBuild local + CI           | seconds   | Local works; CI pending S0.2 |
| L1    | Unit tests (CAddress, parsers, hashers)           | C++ unit harness + Python    | seconds   | C++ harness pending |
| L2    | Integration (Kad bootstrap, source exchange, …)   | CI + dev workstation         | minutes   | CI pending |
| L3    | Smoke matrix `tests/REGRESSION.md`                | Two real eMule peers (PC1+PC2) | ~30 min | Manual; harness pending S0.9 |
| L4    | Wire pcap diff vs baseline                        | `tools/pcap_diff.py`         | seconds (once fixtures exist) | Tool ready, fixtures pending S0.4 |
| L5    | File-format roundtrip                             | `tools/file_roundtrip.py`    | seconds   | Tool ready, fixtures pending |
| L6    | Long-running (24 h with Kad active)               | One dev box, overnight       | one day   | Manual |

Levels L0–L2 are the developer's individual responsibility. L3–L5 are the
**merge gates** for any PR landing on `feature/ipv6-integration`. L6 runs
at the end of each sprint.

---

## L0 — Build

```powershell
& "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\MSBuild.exe" `
    srchybrid\emule.vcxproj /p:Configuration=Release /p:Platform=x64 /m /nologo
```

For a full matrix once CI exists (S0.2):

```
matrix: { config: [Debug, Release], platform: [Win32, x64] }
```

A successful L0 produces `srchybrid\x64\Release\emule.exe`. No errors,
new warnings allowed only if explicitly accepted in the PR.

---

## L1 — Unit tests

The C++ unit harness is not yet checked in. Sprint 0 stores its
placeholders in `tests/Address_test.cpp` etc.; Sprint 1 wires them into
a buildable target (`tests/unit.vcxproj` is the planned name).

Until then, L1 covers what the helpers in `tools/` can reach with pure
Python.

**Python spec-regression tests** in `tests/` (run each directly; exit 0 = pass):

| Test | Locks down |
|------|------------|
| `test_address_wire.py`   | `CAddress` wire format (IPv6 Sprint 1) |
| `test_tunnel_framing.py` | v8.1 onion-tunnel sub-header + fragment header (Sprint A) |

Each replicates a C++ wire format in Python against fixed vectors; the
eventual C++ unit test MUST agree with these vectors byte-for-byte.

---

## L2 — Integration

Reserved for tests that exercise more than one component but don't need
two physical hosts. Examples: parser composition, socket bind/rebind
sequences, Kad routing migration v2→v4.

Land each as `tests/<component>_test.cpp` and add to `tests/unit.vcxproj`
once it exists.

---

## L3 — Smoke matrix

The 29-row checklist in [`REGRESSION.md`](REGRESSION.md). Run on the
two-VM harness (PC1 + PC2). Without the harness, run on two physical
machines in the same LAN, snapshotting `%APPDATA%\eMule` between runs.

**Quick path** (Sprint-0 form, no harness yet):

1. Tag the current state of `%APPDATA%\eMule` on PC1 and PC2.
2. Install the candidate `emule.exe` over `C:\emule\emule.exe` on both.
3. Walk the matrix top-to-bottom, mark each `[x]` as you go.
4. On any FAIL, attach the relevant logs/pcaps to the PR and stop.

The full automation (snapshotted VMs + scripted scenarios) lands in
S0.9 of the sprint plan.

---

## L4 — Pcap diff

Capture under baseline + capture under new build with identical setup,
then:

```bash
python tools/pcap_diff.py baseline_B09.pcap new_B09.pcap
```

Exit 0 = identical (modulo timestamps + accepted additive tags),
exit 1 = regression, exit 2 = tool error.

The accepted-additive set is documented inside `pcap_diff.py`. New
opcodes introduced by the fork (0xC0 .. 0xCC) are treated as additive
when present only on the new side; they fail the diff only with `--strict`.

Required fixtures live in `tests/fixtures/pcaps/` and are captured by
QA from the baseline build (S0.4 of the sprint plan).

---

## L5 — File-format roundtrip

```bash
# One-time setup: capture live config from a working install.
python tools/file_roundtrip.py --capture C:/Users/<you>/AppData/Local/eMule/config

# Per-PR gate:
python tools/file_roundtrip.py --check
```

For each fixture in `tests/fixtures/configs/`, the tool runs
`emule.exe --tool=roundtrip --file=IN --out=OUT` and compares SHA-256.
Tail growth up to the per-fixture allowance is accepted (e.g.
`preferences_legacy.ini` may grow by ≤64 bytes for new keys).

Until Sprint 0 wires the `--tool=roundtrip` switch into emule.exe,
the tool runs in **fallback mode** which copies the file verbatim — it
verifies the fixture pipeline, not the parsers. Sprint 1 replaces the
fallback with the real switch.

---

## L6 — Long-running

Open a Debug-build emule.exe with Kad active and let it run 24 hours.
Watch:

- Memory growth < 5 % of starting RSS.
- No assertion failures in the log.
- Clean exit on close (no zombie ffmpeg processes etc.).

A leak detector (Visual Leak Detector, or eMule's built-in
`_CRTDBG_MAP_ALLOC`) attached to the Debug build catches anything
that escapes the visual inspection.

---

## What's NOT yet running here

These items in the sprint plan depend on infrastructure outside the
scope of a single developer working in a worktree:

| Plan item | Why it's not here yet                               |
|-----------|-----------------------------------------------------|
| S0.2 — CI with build matrix | No `.github/workflows/*.yml` yet; needs repo-owner setup |
| S0.4 — 16 baseline pcaps | Requires Wireshark on the baseline build, manual walk through B1–B16 |
| S0.9 — Two-VM harness with snapshots | Needs Hyper-V/VBox + two VM images; one-time human effort |
| S10/S11 telemetry endpoint | Needs server side + opt-in flow |

When those land, this README is updated to point at the canonical commands.
