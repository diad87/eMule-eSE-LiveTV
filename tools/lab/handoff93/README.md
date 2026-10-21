# `G92-93-DEV` handoff harness

Fixture for the 9.2 → 9.3 technical handoff gate (`HG01`–`HG08`,
`H93-01`–`H93-16`). It builds on the WP0 toolkit in the parent directory and
reuses its helpers, artifact schemas and canonical report collector.

Read [`docs/V9.2_HANDOFF_GATE_LAB_READINESS.md`](../../../docs/V9.2_HANDOFF_GATE_LAB_READINESS.md)
first. **`HG06` is not runnable today** — not for lack of hardware, but because
per-plane mapping state is not observable from outside the process. Run
`reach_probe.ps1` to confirm that on your own build before booking a session.

Like the rest of the toolkit, these scripts are passive: they never enable a
feature, never launch eMule, never overwrite recorded evidence, and redact
addresses unless `-IncludeSensitive` is given.

## 0. Check whether a session is worth booking

```powershell
powershell -ExecutionPolicy Bypass -File tools\lab\handoff93\reach_probe.ps1 `
  -NodeRole A -OutFile C:\tmp\g9293\A\reach-baseline.json
```

`gate_readiness = READY` means the evidence a physical session produces will be
admissible. `INSUFFICIENT_OBSERVABILITY` names each gap and the gate rows it
blocks. Do not book the router session until this reads `READY`.

## 0b. The contract the adapter must satisfy

`goldens/` holds the five reference payloads `HG03` asks to distinguish —
`empty`, `candidate`, `verified`, `expired`, `stale` — and they double as the
implementation target for
[the adapter card](../../../docs/V9.2_REACH_STATUS_ADAPTER_CARD.md).

`validate_reach_status.ps1` is the executable specification. It checks
structure, semantics and privacy:

```powershell
# self-check the reference payloads
powershell -ExecutionPolicy Bypass -File tools\lab\handoff93\validate_reach_status.ps1 -Goldens

# check a running node once the adapter exists
powershell -ExecutionPolicy Bypass -File tools\lab\handoff93\validate_reach_status.ps1 -Live
```

The checks with teeth are the semantic and privacy ones. It rejects a payload
that maps `Verifying` to `VERIFIED` (verification in progress is not proof),
one that reads `VERIFIED` while its evidence is stale or expired, one whose
`reason` and `reason_code` disagree, and any payload carrying the PCP
`ownership_nonce`, the internal monotonic clock, or a full IP literal. Each of
those five is covered by an injected-mutant test, so the validator is known to
fail when it should.

Exit code is non-zero on any violation, so it can gate CI.

## 1. HG07 — physical path and network change

Capture three phases, running the command on the node that owns the transfer.
Keep data flowing during `baseline`.

```powershell
# on the original LAN, transfer running
powershell -ExecutionPolicy Bypass -File tools\lab\handoff93\route_change.ps1 `
  -Phase baseline -RunDirectory C:\tmp\g9293 `
  -TargetProcessId 1234 -ExpectedRemotePort 4662 -RequiredFamily IPv4

# after switching to the hotspot
powershell -ExecutionPolicy Bypass -File tools\lab\handoff93\route_change.ps1 `
  -Phase hotspot -RunDirectory C:\tmp\g9293 -TargetProcessId 1234

# after returning to the LAN
powershell -ExecutionPolicy Bypass -File tools\lab\handoff93\route_change.ps1 `
  -Phase restored -RunDirectory C:\tmp\g9293 -TargetProcessId 1234

# verdict
powershell -ExecutionPolicy Bypass -File tools\lab\handoff93\route_change.ps1 `
  -Summarize -RunDirectory C:\tmp\g9293
```

A captured phase is never overwritten; re-running a phase is a hard error, so
a mistaken run must be resolved deliberately rather than silently replaced.

Tailscale may administer the machines. It may not carry the data used as proof
— `assert_data_route.ps1` rejects it as the measured path by default.

## 2. HG08 — gate verdict

Maintain a verdicts file (start from `verdicts.template.json`) recording, per
row, the verdict and the evidence artifacts relative to the run directory.

```powershell
powershell -ExecutionPolicy Bypass -File tools\lab\handoff93\gate_matrix.ps1 `
  -VerdictsFile C:\tmp\g9293\verdicts.json `
  -RunDirectory C:\tmp\g9293 `
  -Commit 0ce0d88f -Toolchain "VS2022 17.x / Release x64"
```

The script enforces the gate's own stop rules rather than trusting the file:

- all sixteen rows must be present and `PASS`;
- `BLOCKED`, `SKIP`, `FAIL` and `PENDING` never count as `PASS`;
- a `PASS` row with no evidence artifact is a blocker;
- a cited artifact that does not exist is a blocker;
- an artifact recording a different `commit` invalidates the gate;
- `H93-15` and `H93-16` cannot pass from a run marked `"simulated": true`.

Exit code is non-zero unless the gate verdict is `PASS`, so it can gate CI.

## 3. Canonical report

Index everything with the existing collector:

```powershell
powershell -ExecutionPolicy Bypass -File tools\lab\collect_report.ps1 `
  -RunDirectory C:\tmp\g9293 -CaseId G92-93-DEV -Outcome PASS -Version 9.2
```

## Boundary

These scripts decide and record; they do not implement the missing read
adapter. That adapter touches `WebServer.cpp`, which the `M2A-W10` programme is
modularizing right now, so it belongs in the 9.2 branch — building it on `main`
guarantees a merge conflict.
