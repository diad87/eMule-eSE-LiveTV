# V91-I01 exact-candidate execution

## Result

`V91-I01` is **PASS**.

- Run: `7dc355480de14910ac746ac42f8f4c93`
- Candidate `emule.exe` SHA-256:
  `0bc2ca4e0d161fc90c1f42009bc1c2e793f6dc1c13c973bebb935d65aff839bd`
- Candidate size: 11,280,384 bytes
- H1 job: `f8bae490d42b49188acaaca42ad1ca84`, COMPLETE, exit code 0
- H3 job: `ba4ee46d97e84bf0bf6ed56d9ae12872`, COMPLETE, exit code 0
- Aggregate finalizer: PASS at `2026-07-31T08:35:36.6721648+00:00`

## What was proved

Two physical Windows hosts completed the canonical 4 GiB eMule transfer on the
controlled T5 IPv6-only path. The source used Ethernet and the downloader used
Wi-Fi; both exact ULA endpoints are redacted from this public projection.
Owned firewall rules blocked every candidate IPv4 socket in both directions.

The downloader observed the IPv6 peer throughout the transfer and observed no
IPv4 peer socket. The source and destination independently agreed on:

- Size: 4,294,967,296 bytes
- SHA-256:
  `1016d6f63ae1649a879a7c0de30865ed132deb37b1c3b2bc9ca004c88feee26c`
- ED2K: `796A95E75DF8E78D54A57CDEA1FEDE84`

The download began at 10:29:06 local time, entered final hashing at 10:32:28
and completed at 10:33:16. The API remained responsive after completion.

## Product and harness corrections

The first clean attempt exposed that a direct T5 ULA source was admitted by
the NetLab policy but then lost its full 128-bit address through the ordinary
public-only address setter. The materialization path now uses the explicit
direct-IPv6 setter. Ordinary discovery, PeX and server sources remain
public-only; the ULA exception remains limited to explicit T5 NetLab
configuration and contribution consent.

The fresh laboratory profile also inherited eMule's conservative 80 KiB/s
upload default. The I01 harness now sets the established unlimited laboratory
profile values so the 4 GiB integrity case measures the physical link rather
than an unrelated default throttle.

## Verification

- eSE Live regression suite: 39/39 PASS.
- PowerShell 5.1 parser: zero errors in runner and controller.
- Release x64 project build: zero errors.
- Exact candidate present on both physical hosts.
- Node adjudication: PASS on H1 and H3.
- Cross-node aggregate adjudication: PASS.
- Cleanup: both unattended agents returned COMPLETE/0 and IDLE.

## Evidence

- `../lab-runs/v91-k04/7dc355480de14910ac746ac42f8f4c93/manifest.json`
- `../lab-runs/v91-k04/7dc355480de14910ac746ac42f8f4c93/h1-result.json`
- `../lab-runs/v91-k04/7dc355480de14910ac746ac42f8f4c93/h3-result.json`
- `../lab-runs/v91-k04/7dc355480de14910ac746ac42f8f4c93/aggregate-result.json`
- `../lab-runs/v91-k04/7dc355480de14910ac746ac42f8f4c93/h3-emule.log`

## Campaign impact

The cumulative v9.1 matrix is now **21 PASS, 0 FAIL and 6 BLOCKED**
(77.8% PASS). The normative release gate remains NO_GO while mandatory cases
remain BLOCKED.
