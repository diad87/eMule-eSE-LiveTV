# V91-I02 exact-candidate execution

## Result

`V91-I02` is **PASS** for `emule.exe` SHA-256
`6f3d7ce29a0c1df42d3b37eb378b4be3b2adcdb7802b3a22696454229e5a3dc2`
(11,253,248 bytes).

The exact candidate sustained a 12 Mbps LiveTV test-pattern stream for the
required two hours over the physical T5 IPv6-only data path. Both independent
Windows nodes completed with exit code 0. This is a post-RC3 qualification
result and does not rewrite the immutable RC3 package ledger.

## Physical topology

- H1 was the source on a redacted ULA endpoint, physical `Ethernet`, interface
  index 7, TCP port 48062.
- H3 was the viewer on a redacted ULA endpoint, physical `Wi-Fi`, interface
  index 22, TCP port 48262.
- Tailscale carried control and evidence only. The LiveTV peer sockets were
  constrained to the two physical-interface ULA endpoints.
- Both nodes ran the same hash-pinned executable.

## Procedure and observations

Before the formal run, a 120-second preflight completed PASS and the viewer
advanced from 0 to 62 received chunks. The formal run then requested 7,200
seconds at 12,000 kbps.

| Node | Observed wall time | Samples | Inactive | IPv4 peer samples |
|---|---:|---:|---:|---:|
| H1 source | 7,207.9 s | 470 | 0 | 0 |
| H3 viewer | 7,209.0 s | 475 | 0 | 0 |

The viewer advanced from 0 to 3,749 chunks. Both nodes observed the expected
IPv6 peer route, a valid HLS playlist and real non-empty segment files. No
sample observed an IPv4 peer socket. Maximum working set remained below 92 MB
on both nodes, and maximum handle counts were 555 on H1 and 415 on H3.

The qualification work exposed two laboratory issues before the formal pass:
the filesystem HLS verifier originally looked at the wrong namespace, and the
unattended viewer did not mirror the browser's `player-alive` heartbeat. The
latter intentionally triggered the product's 60-second ghost-viewer watchdog.
The runner now sends the same key-scoped heartbeat as the real web player.
That harness behaviour is covered by the LiveTV regression suite.

The candidate also bounds the initial high-bitrate bootstrap burst below half
of the per-peer queue budget and allows 15 seconds for fragmented segment
reassembly. The final regression suite is 36/36 PASS and the Release x64 build
is PASS.

## Evidence

- Compact adjudication: [`V91_I02_RESULT.json`](V91_I02_RESULT.json).
- Formal run:
  `lab-runs/v91-k04/f0100c75f4374008bf83a58c0c806888/`.
- Passing preflight:
  `lab-runs/v91-k04/4cfeecc532ed403da63817fb4ae3dda4/`.

## Matrix effect

The immutable `9.1.0-rc.3` ledger remains at 12 PASS, 0 FAIL and 15 BLOCKED.
The cumulative v9.1 campaign is now **18 PASS, 0 FAIL and 9 BLOCKED**
(66.7% PASS). `V91-I02` is removed from the blocked set.
