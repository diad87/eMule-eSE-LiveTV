# V91-R01 execution runbook

## Current adjudication

`V91-R01` remains **BLOCKED**, not FAIL, until one physical T3 run completes.
The offline harness is ready and self-tested. No physical result is inferred
from parser tests, the earlier partial attempt or the ongoing `V91-O01` soak.

R01 is independent from I07. R01 tests clean roaming from the home LAN to the
mobile hotspot over IPv4. Native global IPv6 is recorded as an optional
diagnostic only; its presence or absence cannot block or fail R01. Run R01
first in the next tethering window and run I07 afterwards; I07 independently
switches from the restored Home profile to the hotspot.

## 2026-08-01 tethering preflight

A non-adjudicating physical preflight used the authenticated small-frame agent
without starting eMule or changing the WLAN profile. It established all of the
following:

- the laptop agent is online with protocol 2, `cooperative_cancel`, an `IDLE`
  state and the exact installed runner SHA-256
  `441650d699ad63e971a59cfdea1cb6c0418e1bc20e3c0dd882c4b57b4f441773`;
- the laptop already holds the byte-identical RC3 ZIP: 212040831 bytes and
  SHA-256
  `359272c764c532c32cfd97eeb92e2db4feaa620c5d3f6318a82a7453dbf1b56f`;
- the two distinct saved Home/hotspot WLAN profiles and the single physical
  Wi-Fi interface were identified. Clear profile names, addresses and the
  interface GUID remain only in private, untracked controller evidence; and
- a TCP connection to a public IPv6 endpoint completed from a provider-routed
  global IPv6 address on that physical Wi-Fi interface in 44 ms. This is only
  a mobile-path prerequisite observation, not an R01 or I07 result.

The same preflight also proved that the original agent task runs as `SYSTEM`.
Running the candidate through that task would create an intentionally
inadmissible result. A second protocol-2 agent was therefore installed under a
new dedicated disposable local administrator account, on an isolated root,
port, mutex, task and firewall rule. Its independent preflight passed: the
identity is not SYSTEM, its profile is loaded, the required `Run` key exists
without `eMuleAutoStart`, the `ed2k` subtree is absent, no eMule process exists
and the isolated ZIP again matches the frozen RC3 bytes. The original SYSTEM
agent remains online as the recovery/control plane. Account name, SID digest,
port and paths stay in private controller evidence.

A separate transactional H1 UPnP probe then stopped before creating a mapping:
Windows SSDP Discovery and UPnP Device Host were already running, but
`HNetCfg.NATUPnP.StaticPortMappingCollection` was null. No router mapping or
local firewall rule was left behind. R01 therefore remains `BLOCKED` until the
H1 router exposes the required static UPnP mapping collection (or the normative
harness is deliberately revised and re-audited for an equally strict
pre-provisioned public mapping). The disposable H3 side no longer blocks the
next attempt.

The controller and remote runner use the same strict IPv4 classifier. Private,
CGNAT, loopback, link-local, documentation, protocol-assignment, AS112,
deprecated 6to4-relay and benchmarking ranges (including `198.18.0.0/15`) do
not qualify as a public path. The offline suite exercises both implementations
with boundary cases, but this classification test is not physical roaming
evidence.

## Normative PASS contract

One complete run must prove all of the following:

1. the exact frozen package starts one identity-bound candidate on H3. Its PID,
   UTC start time, executable-path SHA-256 and executable SHA-256 must remain the
   same at every process, socket and cleanup observation;
2. that PID logs in to the nonce-scoped controlled eD2K server over H3's
   physical home Wi-Fi address;
3. after switching the same running PID to the hotspot, a separate nonce probe
   reaches the globally routable H1 endpoint from the physical Wi-Fi NIC;
   Home and hotspot must be distinct saved WLAN profiles, the same physical
   `InterfaceGuid` must remain in use, both WLAN and NLA hashes must change,
   and the probe's local IPv4 must differ from the initial candidate socket.
   `Find-NetRoute` must bind every initial, probe and reconnected socket to its
   exact source address, interface index and GUID; virtual or overlay adapters
   are forbidden on both H1 and H3 candidate data paths;
4. the old LAN socket and endpoint disappear within 45 seconds;
5. the same PID reconnects to the public controlled endpoint from the new
   physical Wi-Fi address within the bounded 90-second interval;
6. both logins carry the same client identity and receive a classic HighID
   `IDCHANGE` from the controlled server;
7. `/api/status` reports `ed2k_connected=true` before and after the transition,
   and the Web API listener is owned by the candidate PID;
8. all five server, probe and candidate ports are distinct. Complete TCP/UDP
   endpoint enumeration must prove the two H1 and three H3 ports free before
   mutation; a collector error is not interpreted as an empty result;
9. proxy and candidate UPnP data paths remain disabled, while a nonce-owned
   inbound firewall rule isolates the wildcard Web API listener. Every firewall
   create/delete is guarded by an exact name, group, program, protocol, port,
   direction, action, profile and address tuple;
10. H3 starts with zero pre-existing `emule` processes; the isolated staging
   tree is removed only after a sanitised effective-config snapshot and a real
   timestamped log fragment have been retained;
11. the disposable H3 account and its protected registry subtrees remain
    byte-semantically unchanged across the run; the four startup/integration
    preferences listed below remain disabled; and
12. the candidate, two controlled listeners, exact firewall rules and the two
     nonce-owned router mappings are all removed during cleanup; and
13. the original Home WLAN/NLA identity is restored on the same physical NIC.
     An independent nonce-owned watchdog performs that restore even if the main
     runner is killed; I07 later performs its own hotspot switch and restore.

The result is `FAIL` only when the mobile public path and the controlled
fixture have both been independently validated and the candidate then violates
the roaming invariant. That product verdict is established before cleanup, so
a later cleanup incident is retained beside, but cannot downgrade, a proven
`FAIL`. Missing topology, identity, agent reachability, port/collector evidence
or safe cleanup is `BLOCKED`.

## Frozen candidate prerequisite

The controller refuses a loose development executable. It requires:

- an unpacked package containing `emule.exe`, `ese-server.exe` and
  `BUILD_INFO.txt`, plus the matching ZIP on H1;
- the expected clean 40-hex commit; and
- an absolute H3 path to its own byte-identical copy of that ZIP.

The controller creates the canonical `ese.v91.package-zip-binding/v3` manifest
from a breadth-first census of every regular package file. It keeps every source
file and the ZIP open with `FileShare.Read` for the whole comparison, hashes the
ZIP through the same stream consumed by `ZipArchive`, and requires an exact file
count, total byte count, relative-path spelling, byte size and SHA-256 match.
The census rejects reparse-point ancestors or entries. ZIP validation rejects
absolute paths, traversal, empty/ambiguous components, case-fold collisions,
duplicate entries and Unix symlink metadata.

H3 independently opens its ZIP as a locked snapshot, verifies the requested
ZIP size/hash and manifest size/hash/count, and extracts each file with
`FileMode.CreateNew` below reparse-free ancestors. It then performs an exact
post-extraction census and explicitly binds the three required files in
`ese.v91.r01-remote-package-binding/v2`. `BUILD_INFO.txt` is read and hashed
from one held descriptor; `emule.exe` is rehashed from a held descriptor
immediately around process creation. No loose, unmanifested or changed tree is
executed, closing the package-to-launch TOCTOU window.

The executable used by formal O01 currently has SHA-256
`0bc2ca4e0d161fc90c1f42009bc1c2e793f6dc1c13c973bebb935d65aff839bd`,
but that hash alone is not a frozen package contract and is not attributed to
the current repository HEAD. If that executable remains the candidate, create
and deploy its matching clean package, ZIP and `BUILD_INFO.txt` before R01.

## Disposable H3 account and registry preflight

Formal R01 must run the H3 agent and remote runner as a dedicated disposable
lab account, never as a normal personal account. The controller requires both
an explicit `-DisposableH3AccountConfirmed` switch and the SHA-256 of the exact
current Windows SID text. On H3, while signed in as that account, obtain only
the hash to copy into the controller command:

```powershell
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$sha = [Security.Cryptography.SHA256]::Create()
try {
  (($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($sid)) |
    ForEach-Object { $_.ToString('x2') }) -join '')
} finally {
  $sha.Dispose()
  Remove-Variable sid
}
```

Before the run, `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` must
already exist and its `eMuleAutoStart` value must be absent.
`HKCU\Software\Classes\ed2k` may be present or absent. H3 captures canonical
pre/post snapshots of both complete subtrees, including key/value counts,
value kinds and hashed value data. Any difference is a cleanup incident and
prevents `PASS`; the runner deliberately does not attempt a destructive
registry restore.

The isolated candidate profile also forces these exact values under `[eMule]`:

- `AutoStart=0`
- `AutoTakeED2KLinks=0`
- `WatchClipboard4ED2kFilelinks=0`
- `OpenPortsOnStartUp=0`

## One-command physical execution

Do not invoke this while O01 or any eMule process is running on H1. O01's agent
may remain protocol v1 until its soak ends; afterwards install the updated
small-frame agent, whose ping must report protocol 2, `cooperative_cancel`, an
`IDLE` state and `utc_now`. R01 checks its clock offset bound (maximum 1 second)
before making any UPnP, firewall, server or Wi-Fi mutation.

Once the package/ZIP exist on H1, the same ZIP exists on H3, the disposable
account/registry preflight is satisfied, and both Wi-Fi profiles are saved on
H3:

```powershell
.\tools\lab\invoke_v91_r01_campaign.ps1 `
  -HomeProfile '<saved-home-profile>' `
  -HotspotProfile '<saved-hotspot-profile>' `
  -AgentIPv4 '<H3-control-IPv4>' `
  -CandidatePackagePath '<unpacked-frozen-package-on-H1>' `
  -CandidateZipPath '<matching-frozen-zip-on-H1>' `
  -ExpectedCommit '<40-hex-package-commit>' `
  -RemoteCandidateZipPath '<absolute-matching-zip-path-on-H3>' `
  -ExpectedH3SidSha256 '<64-hex-SHA256-of-exact-H3-account-SID-text>' `
  -DisposableH3AccountConfirmed
```

The command performs the remaining work unattended:

- validates the complete package-to-H1-ZIP-to-H3-ZIP locked-snapshot contract;
- rejects a busy or incompatible H3 agent, a SID/account/registry mismatch, a
  pre-existing H3 eMule, any occupied campaign port or any failed collector;
- selects the active physical, non-virtual, non-overlay H1 NIC and later binds
  each H3 candidate/probe socket to its exact selected physical route;
- creates two nonce-owned TCP UPnP mappings and matching firewall rules;
- starts the controlled eD2K server and the independent public-path probe;
- deploys and starts the H3 runner through the existing authenticated agent;
- arms an independent, typed Home-profile watchdog and changes H3 from LAN to
  hotspot without restarting the candidate;
- downloads all evidence; and
- restores Home and removes only resources whose nonce ownership, process
  identity and exact filter/mapping tuple still match. Controller timeout uses
  cooperative cancel;
  the remote runner also enforces an autonomous deadline.

Profile names occur only in the local, untracked request used to operate H3.
The private manifest and aggregate retain their SHA-256 values, not the clear
names; the public result excludes both those values and their hashes.

## Evidence layout

Each run writes under `lab-runs/v91-r01/<run-id>/`:

- `manifest.json` (**PRIVATE**): job, SID hash and frozen-candidate identity;
- `server-ready.json` (**PRIVATE**): controlled listener and physical-interface
  preflight;
- `server-result.json` (**PRIVATE**): two logins, hashed client identity, nonce
  probe and
  listener cleanup;
- `remote-result.json` (**PRIVATE**): account/registry and port preflights, the
  identity-bound PID, physical NIC `InterfaceGuid`, exact selected routes and
  old/new sockets,
  expiry/reconnection timings, exact API/firewall evidence, typed Home restore,
  watchdog state, remote ZIP/manifest binding and staging cleanup;
- `aggregate-result.json` (**PRIVATE**): the full final `PASS`, `FAIL` or
  `BLOCKED` adjudication;
- `public-result.json` (**PUBLIC**): the only publishable projection; and
- local/remote stdout, stderr and agent status (**PRIVATE**) where available.

The aggregate schema is `ese.v91.r01-campaign/v1`. It cross-binds remote and
server evidence by schema, case, nonce, candidate tuple and ports, retains
the full ZIP/package binding, UPnP lifecycle/rollback and cooperative recovery,
and never accepts stale artifacts. A proven product `FAIL` remains `FAIL` even
if a later cleanup incident is recorded. I07 must consume this private
`aggregate-result.json` to obtain the contractual
`topology.home_profile_sha256` and `topology.hotspot_profile_sha256` NLA hashes;
requested WLAN-name hashes are separate root fields.

The controller returns and writes only `ese.v91.r01-public-result/v1` as its
public projection. Its exact allowlist is case/status/completion time, frozen
candidate version/commit/file/ZIP hashes and ZIP size, the three strict booleans
`product_failure_proven`, `cleanup_complete`, `cleanup_incident`, and the
private aggregate's byte count and SHA-256. It contains no IP address, port,
path, PID, process time, interface GUID, SID/account/profile hash, nonce,
run/job identifier, registry detail, error or log text. A final privacy guard
rejects both supplied sensitive values and their text digests before writing
the public file.

## Offline verification

These commands perform no network transition and start no eMule process:

```powershell
.\tools\lab\test_v91_r01_remote.ps1
.\tools\lab\test_v91_r01_campaign.ps1
```

Current result:

- all seven R01/agent-contract PowerShell files parse cleanly;
- profile builder self-test: PASS;
- campaign/adjudication self-test: PASS;
- 28 IPv4 classification cases against both controller and remote
  implementations (56 assertions): PASS;
- 16 PASS/FAIL/BLOCKED cross-evidence cases, including SID/port/process/route,
  overlay, package-lock and cleanup-incident negatives: PASS;
- login, post-login frame drain, EOF and second-login sequence: PASS;
- six controller ZIP/package cases plus two strict-manifest and six safe-path
  remote negatives, covering mismatch, traversal, case collision, symlink and
  reparse-point rejection: PASS;
- four safe preferences, registry snapshot change detection and safe
  nonce-tree/reparse cleanup: PASS;
- UPnP Add rollback, cooperative cancel and autonomous deadline: PASS; and
- clock-before-mutation, independent watchdog, IPv6-diagnostic-only and exact
  API isolation, identity-bound cleanup, fail-closed collectors and public
  privacy contracts: PASS.

Frozen offline checkpoint for this revision:

- both commands completed twice with `status=PASS`,
  `formal_case_status=BLOCKED` and
  `physical_execution_performed=false`;
- campaign canonical-result SHA-256:
  `ff3e6ab7d4a0a4cd54e7ad390ecef162bb47d7c50e6876fd1f10afaf98552ee9`;
- remote-profile canonical-result SHA-256:
  `a839ac3b8959f80e6319fb0c77b3058e6d5949475f4bed4248e18a157c2169a9`.

These hashes freeze only the offline outputs. They are not a physical R01
aggregate and cannot change the matrix status.

## Remaining physical prerequisites

Only external state remains:

1. let O01 finish and release H1/H3;
2. install the protocol-v2 agent, sign it into the dedicated disposable H3
   account, satisfy the Run/autostart preflight, and obtain its SID SHA-256;
3. freeze the package/ZIP and place a byte-identical ZIP on H3;
4. provide the two distinct saved home and hotspot profile names to the one
   command;
5. keep the phone hotspot available for the short R01 transition; and
6. require the H1 router to expose a real global IPv4 through UPnP. A private
   or CGNAT external address keeps R01 `BLOCKED` and can never become FAIL.
