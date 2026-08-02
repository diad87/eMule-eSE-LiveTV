# V91-K02 exact-candidate execution

## Result

`V91-K02` is **PASS** for product commit
`622813d5944951efbdba68a1bd7bd68f4d79a2d2` and `emule.exe` SHA-256
`0cb269cedc4b9f7d2c3ceeadd77c7ea291e25d59feff060ac1e2d976e8032c77`.

This is a post-RC.3 product qualification result. It advances cumulative v9.1
campaign coverage, but it does not rewrite the immutable RC.3 package ledger.

## Physical topology

- Two independent physical Windows hosts on the same LAN.
- H1 used one private IPv4 address and three phase-scoped IPv6 identities on
  physical interface `eth2`; exact addresses and the MAC are redacted from
  this public projection.
- H3 used private IPv4 and benchmark IPv6 on physical `Wi-Fi`, UDP port
  `49372`; exact addresses and the MAC are redacted.
- The IPv6 fixture used the RFC 5180 benchmarking prefix `2001:2::/48`, with
  local `/128` routes and fixed neighbors only. It is evidence of physical
  dual-stack transport, not public Internet reachability.
- The control overlay was not used as the data route.

The Kad2 fixture explicitly permitted only the private H1 peer and set
`FilterBadIPs=0` and `FilterLevel=0` inside the isolated profile. Those values
do not alter product defaults. Three distinct IPv6 probe addresses prevented
Kad6 identity-reuse protection from contaminating the plane-isolation
measurement.

## Procedure and observations

One candidate process started with mask 3 (Kad2+Kad6). The unattended
controller then used the real Preferences UI to apply mask 2 (Kad6-only) and
mask 1 (Kad2-only), without restarting the process. Each phase remained active
for 18 seconds and contributed 18 one-second API samples:

| Phase | Mask | Kad2 | Kad6 | Physical frames |
|---|---:|---|---|---:|
| Both | 3 | bootstrap response | challenge + bootstrap response | 7 |
| Kad6-only | 2 | no response | challenge + bootstrap response | 5 |
| Kad2-only | 1 | bootstrap response | no challenge or response | 3 |

All 54 samples reported the exact configured and running mask. All 14 declared
protocol events were present in the physical capture. The Both phase also
contained one `FIND_NODE_REQ` maintenance frame from the enabled Kad6 plane,
so the three PCAPs contain 15 frames in total. There was no missing or
unexpected frame and zero kernel capture drops. The stopped plane remained
silent while the other plane continued to answer.

The runner stopped the candidate and capture, restored the PktMon inventory
and removed its firewall rules, addresses, routes and neighbors.

## Evidence

The compact adjudication is
[`V91_K02_RESULT.json`](V91_K02_RESULT.json). It fixes the candidate identity,
all three masks, runtime samples, protocol observations, physical-capture
hashes and cleanup. Raw evidence remains under
`lab-runs/v91-k02-622813d5-attempt15/`.

## Matrix effect

The immutable `9.1.0-rc.3` ledger remains at 12 PASS, 0 FAIL and 15 BLOCKED.
The cumulative v9.1 campaign is now **16 PASS, 0 FAIL and 11 BLOCKED**
(59.3% PASS). `V91-K02` is removed from the blocked set.
