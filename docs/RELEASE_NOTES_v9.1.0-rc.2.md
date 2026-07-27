# eMule eSE 9.1.0-rc.2

`rc.2` is the successor candidate to `rc.1`. It does not add a user-facing
feature. It closes release-blocking defects and evidence gaps found while
reconciling the mandatory v9.1 IPv6 matrix.

## Why rc.1 was rejected

`V91-I04` requires a dual-stack eSE peer to fall back to its real IPv4 route in
less than 10 seconds when the native IPv6 route silently drops traffic.
`rc.1` retried IPv4 after an explicit IPv6 socket error, but had no bounded
address-family timer for a blackhole. That path could remain pending until the
45-second global client-connection timeout.

The exact `rc.1` candidate is therefore retained as test evidence but is not
promotable.

## Delta in rc.2

- A silent/no-error IPv6 attempt to a direct dual-stack HighID peer gets one
  IPv4 retry after a three-second grace period. With the five-second socket
  sweep, the retry is scheduled between 3 and less than 8 seconds after the
  IPv6 attempt begins. An explicit IPv6 socket error keeps the existing
  immediate retry behavior.
- The retry reuses the same `CClientReqSocket`, connecting-client entry and
  queued `HELLO`; it does not create parallel dials or extend the 45-second
  logical-attempt deadline.
- IPv6-only peers, LowID peers, peers without a real IPv4 endpoint and detached
  sockets cannot enter the fallback.
- SOCKS/HTTP proxy negotiation is excluded from this direct-route timer, so
  proxy authentication or configuration failures cannot be mislabeled as an
  IPv6 route failure.
- HTTP and Kad6 socket subclasses wait for the final retry result instead of
  reporting the superseded IPv6 error.
- A successful native-IPv6 `HELLO` no longer replaces a dual-stack peer's real
  IPv4 endpoint with its compatibility-only synthetic value. The real route
  survives later reconnects, inbound-client merges and fallback decisions;
  genuinely IPv6-only peers remain classified as such.
- The fallback timer, the unchanged 45-second logical-attempt deadline and the
  general socket timeout now use modular tick arithmetic. Regression coverage
  exercises the exact boundaries across `GetTickCount` wrap as well as every
  ineligible fallback state.
- A current peer `HELLO` carrying a public IPv6 endpoint plus the stable
  `IPV6_WIRE` and `IPV6_DUALSTACK` capabilities now enables the ordinary IPv6
  route independently of NetLab consent.
- Enabling or revoking NetLab no longer rewrites the user's independent IPv6
  `Off`/`Auto`/`Preferred` choice. Experimental cold-Kad reach metadata and
  hole-punch paths remain consent-gated.
- The local status API exposes the runtime user hash, all three NetLab consent
  states and read-only connecting-client current/add/high-water/duplicate
  counters. These diagnostics let the I03/I04 harnesses prove peer continuity,
  exactly one logical dial and that a family retry does not create a second
  connecting-client entry. Persistent identity and those connection counters
  are populated only for loopback callers. The rc.2 release package binds its
  dashboard and API to loopback; LAN/remote dashboard access is postponed.
  Legacy pairing, QR, launcher, mobile-app and tunnel-status routes return
  `410`; the remote launcher is not included in the package.
- Direct hostname source links now consume one coherent `AF_UNSPEC` result
  instead of combining answers from two DNS instants. Valid A and AAAA
  candidates share the source cap and retain `hostname_link` provenance.
- A bounded localhost-only diagnostic reports hashed D01 resolution,
  materialization and candidate outcomes. It never returns a raw hostname or
  endpoint and lets the two-host harness prove simultaneous A+AAAA retention
  after exactly one link injection.

## Backup, update and rollback

Automatic updating is disabled in rc.2. No updater executable or installer is
packaged or invoked. Updating is a manual download-and-replace operation using
the exact release asset and its published SHA-256.

Before updating, close eMule and identify the active profile. A normal install
uses `%APPDATA%\eMule` and `%APPDATA%\eSE`; `--portable` uses the package's
`config` directory. Back up the applicable profile directories, the current
application directory and every configured incoming/temporary directory that
contains `.part` or `.part.met` files. Keep credits, keys, `known.met` and
preferences together in the same snapshot.

Install rc.2 into a new empty application directory. In normal mode, leave the
backed-up AppData profile and configured incoming/temporary paths in place. In
`--portable` mode, copy the backed-up `config` plus its configured download data
to the new portable directory while eMule is stopped. Never overlay the new
executables or web assets with files from an older build. Confirm that
`BUILD_INFO.txt` reports `9.1.0-rc.2` and that `emule.exe` and
`ese-server.exe` match the packaged manifest before starting it.

To roll back, stop rc.2, preserve any newly completed downloads separately and
restore the old application directory plus the corresponding AppData or
portable profile and temporary-download snapshot. Do not open the same profile
or `.part` files concurrently with two versions. If rc.2 changed state after
the backup, keep a copy for diagnosis rather than merging metadata files by
hand.

## Qualification status

The policy unit test is green. This source tree is not promotable until the
following exact-`rc.2` gates complete:

1. `Release|x64`, Core, Integration and packaged self-test.
2. `V91-P01` through `V91-P03`.
3. A real two-host `V91-I03` route-selection run over direct native IPv4/IPv6.
4. A real two-host silent-`DROP` `V91-I04` run proving SYN IPv6, one IPv4 retry in less
   than 10 seconds, one logical `HELLO` and responsive UI/API.
5. Two-host `V91-D01` with a controlled hostname whose valid A and AAAA answers
   are both simultaneously materialized, matched to hashed product evidence,
   and exercised under an exact reversible IPv6 `DROP` with PID/adapter/5-tuple
   packet attribution before the IPv4 transfer completes.
6. The exact-candidate transfer/LiveTV smoke and soak required by the v9.1
   release matrix.

Until those gates finish, `rc.2` is a development candidate, not a published
release.
