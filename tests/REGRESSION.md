# eMule eSE — Regression Smoke Matrix

> **Sprint 0 deliverable S0.7.** This is the gate-of-merge checklist for
> every PR landing on `feature/ipv6-integration`. See
> [docs/IPV6_SPRINT_PLAN.md §3](../docs/IPV6_SPRINT_PLAN.md) for the canonical
> source.
>
> **Invariant**: every block in §B below must pass with `IPv6Enabled=false`
> **before AND after** each sprint, byte-identical to the baseline tagged
> `baseline-v0.70b-pre-ipv6`. Blocks §V apply only once the sprint
> introduces IPv6 traffic (Sprint 3+) and require `IPv6Enabled=true`.
> Block §C runs whenever a sprint touches the wire protocol or an on-disk
> format.
>
> Mark each box with `[x]` once verified for the sprint under test.
> A PR landing without 100% green on the relevant blocks DOES NOT MERGE.

---

## How to use this file

1. Copy this file into the PR description (or link to a per-PR copy).
2. Mark each row as you verify it.
3. Attach pcaps captured during §C6 to the PR if any diff is non-empty.
4. Reviewer cross-checks before approving.

---

## §B — Baseline IPv4 (always)

These 16 scenarios MUST pass on every PR. They define "the product still
works" — anything that fails here is a regression, full stop.

| #   | Scenario              | How to verify                                              | Expected                                                    | [ ] |
|-----|-----------------------|------------------------------------------------------------|-------------------------------------------------------------|-----|
| B1  | Launch                | Double-click `emule.exe`                                   | UI opens, no crash, log clean                               | [ ] |
| B2  | Server connect        | Connect to `DonkeyServer No2` (or any IPv4 server)          | Status bar "Connected", server IP shown                     | [ ] |
| B3  | HighID/LowID          | Inspect status bar after connection                         | HighID if v4 public allows, LowID otherwise — no error      | [ ] |
| B4  | Search                | Search `linux iso` with default options                     | ≥1 result in list                                           | [ ] |
| B5  | Download start        | Right-click → Download on a result                          | Appears in downloads, sources arrive                        | [ ] |
| B6  | Download complete     | Wait for a ≤10 MB file to finish                            | Status "Complete", hash verified                            | [ ] |
| B7  | Hash check            | Compare downloaded hash vs known                            | Identical                                                   | [ ] |
| B8  | Share                 | Share a file from Incoming                                  | Appears in Shared Files with count > 0                      | [ ] |
| B9  | Kad bootstrap         | Activate Kad (Network → Kad → Bootstrap from known clients) | Kad status "Connected" within 2 min                         | [ ] |
| B10 | Kad contacts          | Wait 5 min after B9                                         | Active contacts > 50                                        | [ ] |
| B11 | Kad search            | Search the same term as B4 via Kad                          | ≥1 result                                                   | [ ] |
| B12 | Upload                | Another peer downloads from us (PC2 → PC1)                  | Up Stats counter increments, bytes uploaded > 0             | [ ] |
| B13 | Long-running          | 24h session with Kad active                                 | Memory growth < 5%, no asserts, clean exit                  | [ ] |
| B14 | Restart with config   | Close and reopen                                            | Downloads resume, servers/Kad reconnect                     | [ ] |
| B15 | Legacy config         | Drop a baseline `nodes.dat` over the current one + restart  | Loads without error, contacts visible                       | [ ] |
| B16 | LiveTV broadcast      | PC1 broadcast, PC2 subscribes via LiveStreamDlg             | PC2 sees HLS stream played in VLC                           | [ ] |

---

## §V — IPv6 extras (when `IPv6Enabled=true`, from Sprint 3 onwards)

These apply only after the sprint that introduces v6 traffic. Sprints
before that ship with `IPv6Enabled=false` default and don't need §V.

| #  | Scenario             | How to verify                                                 | Expected                                                    | [ ] |
|----|----------------------|---------------------------------------------------------------|-------------------------------------------------------------|-----|
| V1 | Listener v6          | `netstat -an` after startup                                   | TCP `:::4662` and UDP `:::4672` listening                   | [ ] |
| V2 | Public v6 IP         | Status bar after 30 s                                         | Shows detected own IPv6                                     | [ ] |
| V3 | Firewall probe       | Status bar after probe (≤30 s)                                | One of: HighID / PCP / Keepalive / Hole-punch / Buddy / Unreachable | [ ] |
| V4 | Kad-v6 contacts      | Kad tab after 10 min with IPv6 enabled                        | v6 contacts visible, ≥10                                    | [ ] |
| V5 | Cross-family interop | PC1 v4-only + PC2 dual-stack talk to each other               | TCP works via v4 (V6ONLY=0 allows it)                       | [ ] |
| V6 | v6-only end-to-end   | PC1 dual-stack + PC2 with v4 disabled in OS                   | Find each other via Kad-v6 and transfer a chunk             | [ ] |
| V7 | LiveTV v6 mesh       | PC1 broadcaster v6 + PC2 viewer v6                            | Stream arrives, no v4 packets in path (tcpdump confirms)    | [ ] |

---

## §C — Compatibility (always when touching wire or disk format)

These run any time a sprint introduces or modifies a wire opcode or a
file-format reader/writer.

| #  | Scenario                   | How to verify                                                                   | Expected                              | [ ] |
|----|----------------------------|---------------------------------------------------------------------------------|---------------------------------------|-----|
| C1 | Wire ↔ baseline            | PC1 new + PC2 baseline. Complete a download both ways.                          | No functional differences             | [ ] |
| C2 | Wire ↔ upstream 0.70b      | PC1 new + PC2 upstream eMule official 0.70b                                     | Connection OK, search OK              | [ ] |
| C3 | Disk ↔ baseline            | Copy baseline `nodes.dat`/`server.met`/`known.met` over the new build's files   | Boots, data preserved                 | [ ] |
| C4 | Disk ↔ upstream            | Same with upstream eMule 0.70b files                                            | Boots, data preserved                 | [ ] |
| C5 | Downgrade                  | After running new, restore `.bak` over the modified files, boot baseline        | Baseline boots normally               | [ ] |
| C6 | Pcap diff                  | Capture 5 min of Kad activity on baseline + identical setup on new with `IPv6Enabled=false`. Run `tools/pcap_diff.py baseline.pcap new.pcap` | Diff empty (modulo timestamps)        | [ ] |

---

## Per-sprint quick reference

| Sprint | §B all | §V relevant | §C trigger              |
|--------|--------|-------------|-------------------------|
| 0      | yes    | n/a         | no                      |
| 1      | yes    | n/a         | no                      |
| 2      | yes    | n/a         | no                      |
| 3      | yes    | V1, V2, V3  | yes (listener changes)  |
| 4      | yes    | V4          | yes (nodes.dat v4)      |
| 5      | yes    | V4 (re-run) | no                      |
| 6      | yes    | V5          | yes (wire eD2K)         |
| 7      | yes    | V7          | yes (LiveTV opcodes)    |
| 8      | yes    | V6          | yes (server.met, known.met, ipfilter) |
| 9      | yes    | V1–V7 full  | yes (default flip)      |
| 10     | yes    | V1–V7 full  | yes (beta release)      |
| 11     | yes    | V1–V7 full  | yes (GA release)        |

---

## Notes

- §B15 expects fixtures in `tests/fixtures/configs/` populated by
  `tools/file_roundtrip.py --capture <emule-config-dir>`.
- §C6 uses `tools/pcap_diff.py`. Pcaps captured per scenario live in
  `tests/fixtures/pcaps/` named `B01_*.pcap` through `B16_*.pcap`.
- "Baseline" = the build at tag `baseline-v0.70b-pre-ipv6`. This tag
  MUST exist before Sprint 1 begins.
