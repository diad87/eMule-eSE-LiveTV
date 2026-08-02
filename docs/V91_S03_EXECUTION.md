# V91-S03 exact-candidate execution

## Result

`V91-S03` is **PASS** for product commit
`622813d5944951efbdba68a1bd7bd68f4d79a2d2` and `emule.exe` SHA-256
`0cb269cedc4b9f7d2c3ceeadd77c7ea291e25d59feff060ac1e2d976e8032c77`.

This is a post-RC.3 product delta. It advances cumulative v9.1 campaign
coverage, but it does not rewrite the immutable RC.3 package ledger or claim
that the older RC.3 ZIP contains this commit.

## Physical topology

- Two independent physical Windows hosts on the same LAN.
- H1 source used a redacted ULA endpoint on physical interface `eth2`; its
  MAC is redacted in this public projection.
- H3 candidate used a redacted ULA endpoint on physical `Wi-Fi`, UDP port
  `49372`; its MAC is redacted.
- The ULA addresses were explicitly bound for the isolated T1 fixture.
- The control overlay was not used as the data route.
- `tcpdump` on the mirrored physical H1 interface supplied the normative wire
  capture. The H3 PktMon trace was retained only as auxiliary evidence because
  its converted PCAP contained no traffic.

## Procedure

`BOOTSTRAP_REQ`, `REQ` and `FIND_SOURCE_REQ` were each sent from a new
unverified identity and port against a freshly started candidate process.
Every run used the same hash-pinned executable and ended with process, capture,
firewall and temporary-address cleanup.

| Request | Request bytes | Response | Response bytes | Physical frames | Result |
| --- | ---: | --- | ---: | ---: | --- |
| `BOOTSTRAP_REQ` | 260 | signed `HELLO_REQ` | 260 | 2 | PASS |
| `REQ` | 280 | signed `HELLO_REQ` | 260 | 2 | PASS |
| `FIND_SOURCE_REQ` | 280 | signed `HELLO_REQ` | 260 | 2 | PASS |

All three signatures and envelopes were valid. Each request produced exactly
one bounded challenge, with zero amplified responses, zero semantic responses,
zero additional responses, zero unexpected physical frames and zero capture
drops.

## Evidence

The compact adjudication is
[`V91_S03_RESULT.json`](V91_S03_RESULT.json). It fixes the candidate identity,
topology, job identifiers, payload hashes, capture hashes and cleanup outcome.
Raw JSON and PCAP artifacts remain under
`lab-runs/v91-s03-622813d5/`; their sizes and SHA-256 values are recorded in
the compact result.

## Matrix effect

The immutable `9.1.0-rc.3` ledger remains at 12 PASS, 0 FAIL and 15 BLOCKED.
The cumulative v9.1 campaign is now **13 PASS, 0 FAIL and 14 BLOCKED**
(48.1% PASS), with `V91-S03` removed from the blocked set.
