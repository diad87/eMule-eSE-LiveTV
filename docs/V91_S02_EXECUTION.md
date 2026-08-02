# V91-S02 exact-candidate execution

## Result

`V91-S02` is **PASS** for product commit
`622813d5944951efbdba68a1bd7bd68f4d79a2d2` and `emule.exe` SHA-256
`0cb269cedc4b9f7d2c3ceeadd77c7ea291e25d59feff060ac1e2d976e8032c77`.

This is a post-RC.3 product delta. It advances cumulative v9.1 campaign
coverage, but it does not rewrite the immutable RC.3 package ledger.

## Physical topology

- Two independent physical Windows hosts on the same LAN.
- H1 reused the same redacted ULA endpoint and UDP port on physical interface
  `eth2`; its MAC is redacted in this public projection.
- H3 used one redacted ULA endpoint on physical `Wi-Fi`, UDP port `49372`;
  its MAC is redacted.
- The control overlay was not used as the data route.
- The temporary `/128` route and permanent neighbor fixture were removed.

## Procedure and observations

Identity A used a short-lived signed router record. It received and answered a
fresh transaction-bound challenge, completed bootstrap and raised the
verified-contact count from zero to one. After its signed validity window
elapsed, runtime maintenance reduced the count to zero.

Identity B then reused the same complete IPv6 address and UDP port with a
distinct node key and a strictly higher epoch. It did not inherit A's verified
state: the candidate issued another fresh challenge before returning the
bootstrap response. The verified-contact count returned from zero to one.

Finally, the exact expired packet from A was replayed. During the three-second
observation window it caused zero challenges and zero semantic responses. The
physical capture contains all 11 reported frames, no unexpected frame and
zero kernel capture drops.

## Evidence

The compact adjudication is
[`V91_S02_RESULT.json`](V91_S02_RESULT.json). It fixes the candidate identity,
both identities and epochs, reused endpoint, runtime transitions, capture,
artifact hashes and cleanup. Raw evidence remains under
`lab-runs/v91-s02-622813d5/`.

## Matrix effect

The immutable `9.1.0-rc.3` ledger remains at 12 PASS, 0 FAIL and 15 BLOCKED.
The cumulative v9.1 campaign is now **15 PASS, 0 FAIL and 12 BLOCKED**
(55.6% PASS), with all three `V91-S01` through `V91-S03` security cases
removed from the blocked set.
