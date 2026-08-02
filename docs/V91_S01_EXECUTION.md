# V91-S01 exact-candidate execution

## Result

`V91-S01` is **PASS** for product commit
`622813d5944951efbdba68a1bd7bd68f4d79a2d2` and `emule.exe` SHA-256
`0cb269cedc4b9f7d2c3ceeadd77c7ea291e25d59feff060ac1e2d976e8032c77`.

This is a post-RC.3 product delta. It advances cumulative v9.1 campaign
coverage, but it does not rewrite the immutable RC.3 package ledger or claim
that the older RC.3 ZIP contains this commit.

## Physical topology

- Two independent physical Windows hosts on the same LAN.
- H1 source used two redacted ULA endpoints on physical interface `eth2`;
  the MAC is also redacted in this public projection.
- The addresses are different 128-bit values in different `/64` prefixes but
  deliberately share low 32 bits `12345678`.
- H3 candidate used one redacted ULA endpoint on physical `Wi-Fi`, UDP port
  `49372`; its MAC is redacted.
- The control overlay was not used as the data route.
- Temporary `/128` routes and permanent neighbor fixtures made delivery
  deterministic despite the colliding addresses also sharing a solicited-node
  multicast suffix. All such fixtures were removed by the remote runner.

## Procedure and observations

Each source address used a distinct Kad identity and UDP port. The probe
completed the signed transaction-bound `HELLO_REQ`/`HELLO_RES` verification
for the first address, then repeated it for the second address without
discarding the first contact.

The candidate API progressed from zero to two simultaneous verified Kad6
contacts and stayed at two for the rest of the remote sample window. Kad2 was
stopped in every sample. Both source addresses received their independent
challenge and completed their bootstrap.

The normative physical capture contains exactly the nine protocol frames
reported by the probe: two bootstrap requests, two challenges, two challenge
responses, two bootstrap responses and one settled request. It contains no
unexpected frame and reports zero kernel capture drops.

## Evidence

The compact adjudication is
[`V91_S01_RESULT.json`](V91_S01_RESULT.json). It fixes the candidate identity,
full IPv6 endpoints, job identifier, physical capture, artifact hashes and
cleanup outcome. Raw JSON, PCAP and decoded capture artifacts remain under
`lab-runs/v91-s01-622813d5/`.

## Matrix effect

The immutable `9.1.0-rc.3` ledger remains at 12 PASS, 0 FAIL and 15 BLOCKED.
The cumulative v9.1 campaign is now **14 PASS, 0 FAIL and 13 BLOCKED**
(51.9% PASS), with `V91-S01` and `V91-S03` removed from the blocked set.
