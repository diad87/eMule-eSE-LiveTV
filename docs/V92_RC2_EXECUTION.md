# eSE 9.2.0-rc.2 execution plan

## 1. Candidate identity

`rc.2` is the commit on `claude/v92-close` that carries the template
fallback fix (`srchybrid/WebTemplateRenderer.cpp`) and the `9.2.0-rc.2`
version stamp. Its product tree differs from the withdrawn `rc.1`
(`b2a9a56c`) only by that fix. The exact commit, package and executable
hashes are recorded by `tools/build_all.ps1` in `BUILD_INFO.txt`,
`SHA256SUMS.txt` and the release receipt, and copied into
`docs/V9.2_STATE.md` §1.

Every later change to the product tree produces a new candidate. Evidence is
never relabelled from one candidate to another.

## 2. Build and local gates

Build with the official pipeline from a clean tree:

```powershell
powershell -ExecutionPolicy Bypass -File tools\build_all.ps1 -ReleaseTag v0.70b-eSE9.2.0-rc.2
```

The pipeline runs the preflight, Core suite, `libutp`, Release x64, the
version stamp check, Integration suite, package assembly and package smoke.
Required beyond the pipeline, on the same commit:

1. `libnatmap` and `libreach` complete gates;
2. `tools\lab\handoff93\validate_reach_status.ps1 -Goldens` and the envelope mock;
3. runtime of the packaged executable with mappings off (schema
   `ESE_REACH_STATUS_V1`, `READY`) and with mappings on over a topology
   without a usable mapper (blocked, never verified);
4. the 9.1.0 → rc.2 → 9.1.0 profile upgrade, restart, crash and rollback cycle;
5. pre-publication checks on the produced package: Windows Defender scan of
   the zip and the extracted directory, zip sidecar hash, `--selftest` of the
   packaged executable, a user-style `--portable` launch with the dashboard
   auto-spawn, and an upgrade with a copy of a real 9.1.0 profile followed by
   rollback (all recorded PASS for `75c97525` in
   `quality/v9.2/75c97525/handoff-9.3/prepublish-checks.json`);
6. `tools\lab\handoff93\gate_matrix.ps1` on the commit, expected
   `BLOCKED` with fourteen `PASS` and only `H93-15`/`H93-16` pending until
   the physical session.

## 3. Physical session

One afternoon on a real router with a second Windows node, following
`V9.2_PHYSICAL_SESSION_RUNBOOK.md`: three `CANDIDATE → VERIFIED → WITHDRAWN`
cycles (`H93-15`), data path outside the overlay plus LAN → hotspot → LAN
(`H93-16`), which also cover T7 and T3, and the UPnP census before and after.
Evidence goes to `C:\tmp\g9293-<commit>\` and, sanitized, to
`quality/v9.2/<commit>/handoff-9.3/`.

## 4. Soak

`V92-O01` as written in the plan: eight hours, samples every five minutes,
one provoked mapping loss, one router restart, natural shutdown, census
afterwards. Runner: `tools\lab\v92_simple_soak.ps1`; verdict rules in
`V9.2_O01_SIMPLE_SOAK.md`. The formal controller is optional and cannot
block the release.

## 5. Decision

`rc.2` stays `NO_GO` while any of §2–§4 is missing, failed or belongs to
another commit. With all of them recorded, the matrix `G92-93-DEV` reads
`PASS`, 9.3 may start from this commit, and `9.2.0` is tagged from the same
commit after the automated matrix is repeated on another day. Gaps that
remain (inherited 9.1 IPv6 cases, second router brand, remote topology) are
disclosed in `RELEASE_NOTES_v9.2.0.md`, never hidden.
