# eSE v9 laboratory toolkit (WP0)

This directory contains the common, version-independent tools used to produce
repeatable evidence for the v9 release gates. The scripts target Windows
PowerShell 5.1 because that is the lowest common denominator of the available
Windows nodes.

The toolkit is deliberately passive by default:

- it never enables an experimental feature;
- it never launches eMule or the eSE server;
- it never overwrites an existing prepared node or soak sample file;
- it restricts API reads to loopback unless `-AllowRemoteApi` is explicit;
- it omits machine names and full IP addresses unless `-IncludeSensitive` is
  explicit;
- Tailscale may be used to control a node, but `assert_data_route.ps1` rejects
  it as the measured data path by default.

## Common workflow

Run all commands from the repository root.

### 1. Record each machine

```powershell
powershell -ExecutionPolicy Bypass -File tools\lab\inventory.ps1 `
  -NodeRole A -PackagePath C:\tmp\eSE-package `
  -OutFile C:\tmp\v9-run\A\inventory.json
```

The default `ese.lab.inventory/v1` artifact records address classes and
interface/route capabilities without publishing hostnames or complete
addresses. `-PackagePath` adds the candidate version plus hashes of
`BUILD_INFO.txt`, `emule.exe`, and `ese-server.exe`. Use `-IncludeSensitive`
only for a private diagnostic bundle.

### 2. Create isolated A/B/R profiles

```powershell
powershell -ExecutionPolicy Bypass -File tools\lab\prepare_node.ps1 `
  -NodeRole A -SourcePackage C:\tmp\eSE-package `
  -OutputRoot C:\tmp\v9-nodes -RunId 20260724-v90
```

Default offsets are A=`0`, B=`100`, and R=`200`, giving each local instance a
different TCP, UDP, and web/API port. An explicit `-PortOffset` overrides that
mapping. Every profile contains `LAB_NODE.json`, source hashes, and safe
experimental defaults. A pre-existing target is a hard error.

### 3. Capture state before and after a case

```powershell
powershell -ExecutionPolicy Bypass -File tools\lab\capture_status.ps1 `
  -NodeRole A -BaseUrl http://127.0.0.1:4711 `
  -OutFile C:\tmp\v9-run\A\status-before.json
```

`-AllowUnavailable` turns an unreachable API into recorded evidence instead of
aborting the capture. Authentication tokens are accepted in memory and are
always redacted from artifacts.

### 4. Prove that TCP data did not travel through Tailscale

```powershell
powershell -ExecutionPolicy Bypass -File tools\lab\assert_data_route.ps1 `
  -TargetProcessId 1234 -ExpectedRemoteAddress 203.0.113.10 `
  -ExpectedRemotePort 4662 -RequiredFamily IPv4 `
  -OutFile C:\tmp\v9-run\A\route.json
```

The assertion requires an established socket belonging to the selected
process, maps its local address to a Windows interface, and fails if the
interface name or description matches `Tailscale`. This proves established TCP
routes only. UDP cases must attach `pktmon`, Wireshark/tshark, or equivalent
packet-capture evidence.

### 5. Monitor a soak

```powershell
powershell -ExecutionPolicy Bypass -File tools\lab\soak_monitor.ps1 `
  -NodeRole A -TargetProcessId 1234 -RequireProcess `
  -DurationSeconds 43200 -IntervalSeconds 300 `
  -OutFile C:\tmp\v9-run\A\soak.json
```

The monitor writes append-only JSON Lines while the test is running and an
`ese.lab.soak-summary/v1` verdict at the end. The default limits are 64 MB of
working-set growth and 256 handles. API failure is fatal unless
`-AllowUnavailable` is explicitly selected.

Candidate-specific V91 harnesses read `BUILD_INFO.txt` through
`Get-LabCandidateInfo`. Pass `-Commit` to pin an expected 40-character commit;
dirty packages and mismatched identities are rejected before a test starts.

The supporting source/local reruns additionally require the repository to be
the exact package commit with no tracked or untracked worktree changes, both
before and after execution. Keep `OutputRoot` outside the repository:

```powershell
powershell -ExecutionPolicy Bypass -File tools\lab\test_v91_safe_core.ps1 `
  -CandidatePackage C:\tmp\v91-package -RepoRoot $PWD `
  -OutputRoot C:\tmp\v91-safe-core -Commit <40-character-commit>

powershell -ExecutionPolicy Bypass `
  -File tools\lab\test_v91_local_executables.ps1 `
  -CandidatePackage C:\tmp\v91-package `
  -TestRoot "$PWD\srchybrid\tests\build" -RepoRoot $PWD `
  -OutputRoot C:\tmp\v91-local-executables -Commit <40-character-commit>

powershell -ExecutionPolicy Bypass `
  -File tools\lab\test_v91_prebuilt_libraries.ps1 `
  -CandidatePackage C:\tmp\v91-package -RepoRoot $PWD `
  -OutputRoot C:\tmp\v91-prebuilt-libraries -Commit <40-character-commit>
```

These are supporting executions. Location constraints do not prove how an
existing executable was built; the clean compiler/linker pipeline remains the
authoritative build-provenance gate.

For `V91-K03`, the downgrade target is not operator-selectable. Use the clean
official `v0.70b-eSE8.1.0` ZIP
(`9481C71C7216CECDE82345372C9494F8DDE2FD61601CFB5791D7A2EA9DD18F77`).
The harness also pins `ese-server.exe` to
`9563DA8E16A8EF3EC05CC58479C0BDA2CB0655899B0CE7B10FD9F4C44580A76F`
and rejects rollback copies where it was renamed to `.disabled`:

```powershell
powershell -ExecutionPolicy Bypass `
  -File tools\lab\test_v91_k03_downgrade.ps1 `
  -CandidatePackage C:\tmp\v91-package `
  -PreviousPackage C:\tmp\v0.70b-eSE8.1.0\package `
  -OutputRoot C:\tmp\v91-k03 -Commit <40-character-commit> `
  -ExpectedPreviousEmuleSha256 `
    3F5F9AD4F305DE15BF345E11A5FE1652969B07AFCDDE136B9277989415CE4187 `
  -ExpectedPreviousBuildInfoSha256 `
    26FC4348044868FC65C04F73E78CAFE966D38CB2178C0C093944164C7AAFDFCE
```

It saves a Kad6-only candidate profile, opens an isolated copy with the pinned
old package, and requires `NetworkKademlia=0` before/after, a live old process,
and continuously false `kad_connected` samples from the legacy port for at
least 30 seconds. This is the minimum observable evidence that Kad2 did not
start or reactivate.

### Two-host I03, I04 and D01 campaigns

`V91-I03`, `V91-I04` and `V91-D01` are paired-role harnesses. Start the
Coordinator role on the downloader first. It creates a nonce-scoped directory
under the shared `CoordinationRoot` and prints the complete command to run on
the controlled Peer/Source host. Run that printed command on the second host;
do not invent or reuse a nonce from another campaign.

All three harnesses require the exact clean candidate package, its commit and
`emule.exe` SHA-256, two elevated PowerShell sessions, two distinct physical
Windows hosts and direct native public IPv4/IPv6 routes. Tailscale, WARP,
VPNs, tunnels, proxies and relays may carry the coordination files but cannot
be the measured data path. A missing physical prerequisite returns
`BLOCKED`; once the complete fixture is valid, contradictory product evidence
returns `FAIL`.

```powershell
# Route policy: Auto must use IPv4; Preferred must use IPv6.
powershell -ExecutionPolicy Bypass `
  -File tools\lab\test_v91_i03_route_selection.ps1 `
  -Role Coordinator -PackagePath C:\tmp\v91-package `
  -OutputRoot C:\tmp\v91-i03 -CoordinationRoot \\labshare\v91 `
  -Commit <40-character-commit> -ExpectedEmuleSha256 <sha256> `
  -PeerIPv4 <peer-public-v4> -PeerLocalIPv4 <peer-adapter-v4> `
  -PeerIPv6 <peer-global-v6> -ControlledPeerAcknowledged

# Silent IPv6 DROP: one bounded retry over the retained real IPv4 route.
powershell -ExecutionPolicy Bypass `
  -File tools\lab\test_v91_i04_fallback.ps1 `
  -Role Coordinator -PackagePath C:\tmp\v91-package `
  -OutputRoot C:\tmp\v91-i04 -CoordinationRoot \\labshare\v91 `
  -Commit <40-character-commit> -ExpectedEmuleSha256 <sha256> `
  -PeerIPv4 <peer-public-v4> -PeerLocalIPv4 <peer-adapter-v4> `
  -PeerIPv6 <peer-global-v6> -ControlledPeerAcknowledged

# Controlled A+AAAA source: exact AAAA-side silent DROP; A completes the transfer.
powershell -ExecutionPolicy Bypass `
  -File tools\lab\test_v91_d01_dual_dns.ps1 `
  -Role Coordinator -PackagePath C:\tmp\v91-package `
  -PackageZipPath C:\tmp\eSE-v91-rc2-x64.zip `
  -OutputRoot C:\tmp\v91-d01 -CoordinationRoot \\labshare\v91 `
  -Commit <40-character-commit> -ExpectedEmuleSha256 <sha256> `
  -ExpectedPackageZipSha256 <zip-sha256> -Hostname <controlled-hostname> `
  -SourcePublicIPv4 <source-public-v4> `
  -SourceLocalIPv4 <source-adapter-v4> -SourceIPv6 <source-global-v6> `
  -CoordinatorPublicIPv4 <coordinator-public-v4> `
  -CoordinatorLocalIPv4 <coordinator-adapter-v4> `
  -CoordinatorIPv6 <coordinator-global-v6> `
  -ControlledFixtureAcknowledged
```

I04 changes firewall and packet-capture state only on the controlled peer and
rolls it back in `finally`. D01 additionally requires an exact, stable DNS
answer containing one A and one AAAA record, the A-side forward to the Source
TCP listener, an exact reversible IPv6 `DROP` on that controlled Source, and
the original candidate ZIP. Its packet evidence is accepted only when the
candidate PID, physical adapter, full 5-tuple and time window all agree. Never
point either harness at an uncontrolled third-party peer.

For the normative `V91-I02` LiveTV case, use the dedicated monitor after the
viewer has joined the broadcaster directly:

```powershell
powershell -ExecutionPolicy Bypass -File tools\lab\live_ipv6_soak_monitor.ps1 `
  -BaseUrl http://127.0.0.1:4811 -TargetProcessId 1234 `
  -ExpectedRemotePort 4662 -DurationSeconds 7200 -IntervalSeconds 15 `
  -OutFile C:\tmp\v91-run\live-summary.json `
  -SamplesFile C:\tmp\v91-run\live-samples.jsonl
```

It sends the same player-alive signal as an open web player, fetches and
validates the HLS playlist, requires the chunk counter to advance, and records
the established Live data socket family on every sample. Any IPv4 connection
to the expected Live port, missing playlist, missing buffer chunk, stopped
viewer, or unavailable process makes the final verdict fail.

### 6. Build the canonical case report

```powershell
powershell -ExecutionPolicy Bypass -File tools\lab\collect_report.ps1 `
  -RunDirectory C:\tmp\v9-run -CaseId V90-N01 -Outcome PASS `
  -Version 9.0.0-beta.2
```

The `ese.lab.report/v1` file indexes every evidence artifact using its relative
path, byte length, SHA-256, schema, node, and verdict when available. Artifact
contents are not copied into the report, so private packet captures remain
separate. The companion Markdown file is intended for human review.

## Toolkit gate

```powershell
powershell -ExecutionPolicy Bypass -File tools\lab\test_lab_tools.ps1
```

The smoke test uses only a dummy package, the current PowerShell process, an
unavailable loopback API, and a temporary loopback TCP connection. It checks
redaction, profile isolation, safe defaults, status capture, route attribution,
short-soak accounting, report hashing, and cleanup. No eMule process or remote
machine is needed.

## V91 RC ledger

The normative matrix contains 27 cases, including `V91-A02`. Reconcile a
campaign without hardcoded beta hashes:

```powershell
powershell -ExecutionPolicy Bypass -File tools\lab\write_v91_campaign_ledger.ps1 `
  -CandidatePackage C:\tmp\v91-package `
  -EvidenceRoot C:\tmp\v91-rc-evidence `
  -ResultsPath C:\tmp\v91-rc-evidence\case-results.json `
  -Commit 0123456789abcdef0123456789abcdef01234567
```

`case-results.json` is an array (or an object containing `cases`) with `id`,
`status`, `executed`, `execution_state`, `reason`, and evidence paths relative
to `EvidenceRoot`. The bundle or every adjudicated result must bind the exact
candidate commit and `emule.exe` SHA-256; flat
`candidate_commit`/`candidate_binary_sha256` and the harnesses' nested
`candidate.commit`/`candidate.expected_emule_sha256` forms are accepted.
A `PASS` additionally requires `executed=true`, `execution_state=COMPLETE`, a
non-empty reason and at least one JSON evidence artifact carrying that same
exact identity. Missing cases remain `BLOCKED`; the ledger returns `GO` only
with all 27 cases at admissible `PASS`.

Build the defensive final report from that ledger with:

```powershell
powershell -ExecutionPolicy Bypass `
  -File tools\lab\write_v91_campaign_report.ps1 `
  -EvidenceRoot C:\tmp\v91-rc-evidence
```

The report generator independently verifies all 27 unique IDs, recomputes
counts and rejects a stale or edited `gate_decision`.

## eSE 9.0 local runtime gate

After producing an extracted candidate package:

```powershell
powershell -ExecutionPolicy Bypass -File tools\lab\test_v90_local.ps1 `
  -PackagePath C:\tmp\eSE-beta2-package
```

The default run observes a declined profile for 30 minutes, then verifies an
accepted profile's kill switch, its five-second deadline and persistence after
a forced restart. It also checks that non-loopback unauthenticated API access
is rejected and that WebServer UPnP remains inactive. `-ObservationSeconds`
may be shortened for harness development, but such a run does not satisfy the
normative `V90-C01` duration.

The runtime harness deliberately preconfigures declined/accepted consent
states. The visible first-run prompt and the user's Yes/No choice remain a
separate GUI observation.

## WP0 boundary

These scripts are the common WP0 foundation. Version-specific fixtures remain
separate work packages: the Windows x64 IPv6 echo fixture for 9.1/9.3, the
configurable NAT gateway for 9.2, and the private KRP CA/edge configuration for
9.4. No Android installation is required by the v9.1 test plan. These fixtures
should reuse the artifact schemas and the canonical report collector.
