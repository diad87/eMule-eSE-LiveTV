# Plan delta de ejecución eSE 9.1.0-rc.2

## 1. Parent candidate

- Parent: `9.1.0-rc.1`.
- Commit: `f4f813d2976ddf4da877771f3f6a6a6d68de7dfd`.
- `emule.exe` SHA-256:
  `CD5E05FA930903E2F59C23C2D536824AE31387BC7C86AD32C2949E561FBCD5CF`.
- Decision: `NO_GO`; `V91-I04` is a demonstrated static-analysis failure.

The parent soak finished with all three monitors at `PASS` and was archived
under its own `f4f813d` identity. It is useful regression evidence, but it is
not relabeled as evidence from `rc.2`; its formal O01 status remains `BLOCKED`
because the run used two isolated profiles on one Windows host.

### Current pre-freeze verification

- Release metadata preflight passes for
  `v0.70b-eSE9.1.0-rc.2` in dirty-worktree development mode.
- The fallback policy executable compiles with `/W4 /WX` and passes.
- The fallback and 45-second logical-attempt deadlines are covered at their
  exact boundaries across `GetTickCount` wrap.
- Pure policy tests prove that an IPv6 `HELLO` retains a dual peer's real IPv4
  endpoint while rejecting either byte order of an IPv6-only synthetic value.
- The source-resolution policy fixes the canonical evidence bytes as family,
  network-order address and big-endian port; hostname and endpoint test
  vectors pass.
- The standalone gate passes 14/14 executables, the dashboard regression gate
  passes 35/35 tests and the complete `ClCompile` target passes with the
  release x64 compiler.
- Packaging requires build stamps that bind both executables and the exact
  43-DLL language set to the source fingerprint, commit, release tag, size
  and SHA-256. Language primary outputs and both mirrors are cleaned before
  every official build. The packaged runtime smoke checks the rc.2 version,
  loopback listener and fail-closed remote/update routes.
- These checks validate the source delta only. They are not substitutes for
  the clean exact-commit build and packaged runtime gates below.

## 2. Freeze the successor source

1. Finish code review of the bounded direct fallback.
2. Run the standalone policy executable with warnings as errors.
3. Commit only reviewed product, specification and laboratory changes.
4. Record the new 40-character commit before building.
5. Build a clean `9.1.0-rc.2` package and record hashes for every packaged
   executable and metadata file.

No result from another commit or package hash can produce an `rc.2` PASS.

## 3. Build and local gates

Run, in order:

1. `Release|x64`.
2. Core gate.
3. Integration gate.
4. Packaged `--selftest`.
5. The fixed eMule AI 1.5.2 A/B corpus.
6. All Kad6 executables.
7. Prebuilt library Release and ASan suites.
8. Consent and proxy campaigns.

Any failure rejects the candidate before network mutation.

### K03 downgrade baseline

The only accepted previous package is the clean official
`v0.70b-eSE8.1.0` asset, pinned by:

- `emule.exe` SHA-256:
  `3F5F9AD4F305DE15BF345E11A5FE1652969B07AFCDDE136B9277989415CE4187`;
- `ese-server.exe` SHA-256:
  `9563DA8E16A8EF3EC05CC58479C0BDA2CB0655899B0CE7B10FD9F4C44580A76F`;
- `BUILD_INFO.txt` SHA-256:
  `26FC4348044868FC65C04F73E78CAFE966D38CB2178C0C093944164C7AAFDFCE`;
- official ZIP SHA-256:
  `9481C71C7216CECDE82345372C9494F8DDE2FD61601CFB5791D7A2EA9DD18F77`.

`test_v91_k03_downgrade.ps1` rejects operator-supplied hashes that differ from
this versioned baseline, rejects rollback directories where
`ese-server.exe` was renamed to `.disabled`, rechecks the originals and
isolated copies after the run, and observes the old process/API for at least
30 seconds on its legacy port.

## 4. I03/I04 runtime campaign

Use one HighID eSE peer which has retained both a real IPv4 endpoint and a
public IPv6 endpoint learned through authenticated `HELLO`.

### I03

- Run Auto and Preferred policy separately.
- Keep NetLab, advanced consent and contribution disabled on both peers; any
  laboratory activation invalidates this stable-route test.
- Teach the same ordinary dual-stack HighID peer's real public IPv6 endpoint
  through authenticated `HELLO`, without DNS or a synthetic source.
- Preserve and compare the source user hash across restarts so both policy
  runs demonstrably target the same peer identity.
- Capture the actual candidate-owned TCP route after that learning step.
- PASS only if Auto uses the peer's real IPv4 route and Preferred uses its real
  IPv6 route, both over physical interfaces in an observed direct `T1` or
  `T2` topology. VPN, overlay, proxy and relay dataplanes invalidate the run.

### I04

- Keep NetLab, advanced consent and contribution disabled on both peers and
  prove the source user hash remains unchanged across the controlled restart.
- Keep the peer's IPv4 listener reachable.
- Apply silent inbound `DROP` only to the peer's IPv6 TCP port.
- Prove that the first SYN IPv6 receives no RST, ICMP error or application
  response for at least 2.75 seconds.
- Capture the following IPv4 SYN between 2.75 seconds and less than 8 seconds
  after the first IPv6 SYN, then the completed connection.
- Measure from first IPv6 SYN to connected IPv4; PASS requires less than
  10 seconds.
- Prove exactly one family fallback, one logical `HELLO`, exactly one
  connecting-client add for the complete dial, no add during the family retry
  and responsive UI/API throughout.
- Restore and verify the firewall state in `finally`.

A closed IPv6 port, `REJECT` or immediate socket error is a separate smoke and
cannot substitute for the blackhole case.

## 5. D01

Use the Coordinator and Source roles on two distinct physical Windows hosts in
an observed direct native `T1` or `T2` topology. Use a controlled hostname with
exact, valid A and AAAA records, canonical ASCII/IDNA A-label spelling, one link
injection, a private minimal eD2K fixture, Kad disabled and no third-party
server. The Source must install an exact nonce-scoped inbound IPv6 TCP `DROP`
for the candidate address and port while leaving the IPv4 listener/forward
operational, then prove that rule was removed during cleanup.

Take a baseline from
`GET /api/debug/source-resolutions`, inject once and fetch
`?after=<baseline>`. PASS requires exactly one new
`ese.debug.source-resolutions/v1` event. It must prove the canonical A+AAAA set
was resolved and simultaneously retained, both candidates have
`source_origin=hostname_link`, and each outcome is `added` or
`merged_existing`. The endpoint is localhost-only and exposes SHA-256 values,
not raw hostnames or addresses.

Also record the controlled DNS answers, candidate-owned OS sockets, a lossless
PktMon/ETW capture, API/UI responsiveness and the final transfer hash. Each SYN
used for adjudication must match the candidate PID, expected physical adapter,
full 5-tuple and temporal window; ambiguous or unmatched packets cannot prove
the case. Missing topology or capture prerequisites are `BLOCKED`; once the
external fixture is armed, a crash, hang, absent packet/telemetry/source,
unresponsive UI/API or contradictory product evidence is `FAIL`.

## 6. I05 physical IPv4 control

Use two distinct physical Windows hosts on the same IPv4 LAN. Before changing
the candidate profile, prove that IPv6 remains bound and works between the
physical adapters. Then set `IPv6Mode=Off` inside both candidate profiles while
leaving the Windows IPv6 stack enabled. Link-local, ULA or global IPv6 is valid
for this baseline; link-local does not demonstrate public IPv6 reachability.

Run the canonical 4 GiB transfer with Kad2 and Kad6 disabled, one literal
on-link IPv4 eD2K link, no eD2K server connection and no third-party source.
Record every candidate-owned established peer socket. The Downloader may have
only peer tuples terminating at the Source IPv4 and controlled port; the Source
may have only the inverse tuples for that same flow.

Because `T1` uses RFC1918 addresses, both isolated profiles set and continuously
verify `FilterBadIPs=0`. This is a fixture-only exception: it does not change
the product default and does not broaden the effective network scope, because
nonce-owned firewall rules still permit only the exact Source/Downloader tuple.

Before link injection, the Downloader must install exactly ten nonce-owned,
program-scoped `Block` rules on `Profile=Any` and all interfaces. Together they
close TCP/UDP over IPv4 and IPv6 except for the exact IPv4 peer tuple to the
Source and the API's TCP loopback response from local port `8011`; all UDP,
including loopback, remains blocked. Every watchdog sample must revalidate
`MpsSvc`, Domain/Private/Public profiles and all ten rules plus their complete
port, application, address and interface filters. The exact-filter check count
must equal the watchdog sample count.

Resolve one PktMon component from the exact physical adapter GUID. Capture that
component and convert its valid `Id` and nonzero `SecondaryId`, if present,
separately. Exactly one conversion must contain the tuple previously observed
in the candidate PID's socket inventory; zero or multiple hits are `BLOCKED`.
PCAPNG does not itself attribute a PID, so adjudication combines that PID-bound
socket inventory with program-scoped containment, physical-interface mapping
and the Source's independent evidence. Preserve stable `pre`, `armed` and
`post` inventories and require zero ETW loss. Alias-only attribution or
unfiltered conversion cannot adjudicate the case.

PktMon uses `snaplen=256`, so truncated IPv4 peer packets are expected and
informational rather than a failure. A structurally invalid PCAPNG, ETW loss or
unadjudicable conversion is `BLOCKED`. Once the capture is valid, missing or
contradictory classic framing, large-file opcodes or fixture evidence on the
exact tuple is `FAIL`. Raw IPv6, rejected-tuple or third-party packets seen on
the physical NIC without sufficient process attribution are contamination and
remain `BLOCKED`; a candidate-owned IPv6 or third-party peer socket is `FAIL`.

The Source must receive and validate the Downloader evidence bundle before
declaring `PASS`: exact manifest, hashes and sizes; packet analysis; component
mapping; loss/status records; socket proof; and hashes of the retained full
ETL, PCAPNG, samples and logs. Full raw artifacts remain on the Downloader and
must be retrieved to repeat packet-level analysis. Both endpoints must
independently calculate size, SHA-256 and ED2K from the completed file; echoing
the command/link ED2K is not evidence.

`COMPLETE.evidence_bundle` contains `schema`, `encoding=base64`, `bytes`,
`sha256`, `manifest_sha256` and `content_base64`. The ZIP is at most 524,288
bytes, contains exactly 11 entries and expands to at most 4,194,304 bytes. The
complete control frame is at most 1,048,576 bytes.

Before the first firewall, PktMon or process mutation, each node must persist
its nonce-owned `ACTIVE/session` state with pending flags and update it after
every mutation. Cleanup must resolve partial states, remove only owned
resources and report its result.

`FAILURE.status` accepts only `LAB_BLOCKED` and `PRODUCT_INVARIANT`, mapped to
`BLOCKED` and `FAIL` respectively. Every frame also contains `schema`,
`case_id`, `nonce`, `phase`, `category`, `message_sha256` and `cleanup`. At
every available API checkpoint, `kad_connected`, `kad6_running` and
`kad6_connected` must exist as booleans and be false. Throughout the measured
transfer, `IPv6Mode=0`, `KadNetworkMask=0`, `NetworkKademlia=0` and
`NetworkED2K=0` must also remain unchanged; `FilterBadIPs=0` must stay fixed so
the one authorized RFC1918 peer is not discarded by the fixture profile.

Laboratory/capture/control/cleanup failures and pre-existing third-party
contamination remain `BLOCKED`. With a clean fixture and topology,
contradictory product behavior is `FAIL`; a valid capture is additionally
required only for wire invariants. A demonstrated `PRODUCT_INVARIANT` remains
`FAIL` if control or cleanup later fails, with both incidents recorded. If the
laboratory failure prevents proving the alleged invariant, the result is
`BLOCKED`.

## 7. Final stability and decision

After functional gates:

1. Repeat the exact-candidate IPv6/IPv4 transfer smoke.
2. Repeat the exact-candidate LiveTV IPv6 run required by the matrix.
3. Run the exact-candidate stability soak.
4. Reconcile all 27 cases into the ledger.

Promotion requires 27 PASS, zero FAIL and zero BLOCKED. Otherwise the ledger
remains `NO_GO` and the remaining topology or defect is named explicitly.

### Current exact-candidate reconciliation

The generated `V91_RC2_CASE_RESULTS.json` is the canonical rc.2 ledger. It
binds commit `08aa6521f7d7907edb3584266abc3a9e31693161` and `emule.exe`
SHA-256
`55c5aa0e968b25330720cfb7f622cbc28ea9875365145333cbcf9d9585c1c44a`.
The current result is 11 PASS, 0 FAIL and 16 BLOCKED, therefore `NO_GO`.
Partial, earlier-candidate and laboratory-failed runs do not alter those
counts.
