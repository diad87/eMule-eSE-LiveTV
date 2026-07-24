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
separate work packages: the configurable NAT gateway for 9.2, the Android IPv6
echo fixture for 9.1/9.3, and the private KRP CA/edge configuration for 9.4.
They should reuse these artifact schemas and the canonical report collector.
