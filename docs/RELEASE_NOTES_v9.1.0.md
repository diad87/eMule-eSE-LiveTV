# eMule eSE 9.1.0

eSE 9.1.0 is the final Windows x64 release of the v9.1 line. It promotes the
RC.3 direct-link fix together with the accepted post-RC3 IPv6, Kad6, LiveTV
and stability changes.

## Qualification status

The cumulative v9.1 campaign records **22 PASS, 0 FAIL and 5 BLOCKED** across
27 cases. The remaining cases are:

- `V91-I03`: public dual-stack route selection.
- `V91-I04`: silent native-IPv6 DROP and bounded IPv4 fallback.
- `V91-I07`: native public mobile-IPv6 LiveTV after mobility qualification.
- `V91-D01`: controlled public A+AAAA DNS fallback.
- `V91-R01`: LAN-to-mobile-hotspot address change and reconnection.

The required end-to-end physical conditions for these five cases could not be
completed in the final campaign. In R01, the router was reached but returned
UPnP error 501 before the simultaneous-mapping and inbound-probe sequence.
They are unverified coverage, not recorded product failures. Under the strict
matrix definition the gate therefore remains `NO_GO`; this release is an
explicit maintainer publication with those gaps disclosed.

The 22 accepted results span the immutable RC.3 package and hash-pinned
post-RC3 candidates. They were not all rerun against one final binary. The
published package is produced only after passing the clean build,
unit/integration, manifest and package-smoke pipeline. The detailed provenance boundary is
recorded in [the cumulative campaign report](https://github.com/diad87/eMule-eSE-LiveTV/blob/v0.70b-eSE9.1.0/docs/V91_POST_RC3_CAMPAIGN_STATUS.md).

## Highlights

- Native IPv6 transport between capable eSE peers without reducing addresses
  to synthetic IPv4 identities.
- Independently selectable Kad2 and Kad6 planes with separate routing state.
- Direct IPv6 LiveTV joins, IPv6-aware SOCKS5 and HTTP CONNECT, and an
  offline-qualified bounded IPv6-to-IPv4 fallback. The physical silent-DROP
  path remains the blocked `V91-I04` case described above.
- Direct HighID sources supplied by an eD2K link remain usable when eD2K
  server and Kad discovery are intentionally disconnected.
- IPv6 queue and credit accounting groups endpoints by `/64` while preserving
  compatibility with classic IPv4 peers.
- Kad6 source publication, signed contact persistence and authenticated
  anti-amplification handling.
- Improved simultaneous broadcasting/viewing isolation, bounded queues and
  large-transfer handling.
- Safe shared-file intake and the frozen eMule AI 1.5.2 comparison gates.

## Safe defaults and scope

- Dashboard, native API and received-HLS routes remain loopback-only.
- Port 8080 is never mapped automatically through UPnP.
- NetLab contribution, Punch3, port prediction, relay contribution, KRP and
  Kad6 Beta Exit remain separately consent-gated and OFF by default.
- No remote dashboard or remote launcher is shipped in v9.1.
- Automatic updating remains disabled; no updater executable is included.
- eSE 9.1 does not claim universal High ID, universal CGNAT traversal, strong
  anonymity or compatibility with every ISP/router IPv6 deployment.

## Install or update

1. Stop eMule completely.
2. Back up `%APPDATA%\eMule`, `%APPDATA%\eSE`, or the portable `config`
   directory, plus any configured temporary directory containing `.part` and
   `.part.met` files.
3. Verify the SHA-256 file published with the ZIP.
4. Extract 9.1.0 into a new empty directory. Do not merge executable or web
   assets from an older build.
5. Start `emule.exe`, connect to eD2K/Kad as desired and open the eSE dashboard
   from the toolbar.

## Rollback

Stop 9.1.0 and restore the previous application directory together with its
matching profile/download snapshot. Never run two versions concurrently over
the same profile or partial downloads.

## Platform

- Windows 10 or 11 x64.
- Portable ZIP; no installer and no automatic updater.
- GPL-2.0-only.
