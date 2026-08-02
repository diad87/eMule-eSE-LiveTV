# V91-K04 exact-candidate execution

## Result

`V91-K04` is **PASS** for `emule.exe` SHA-256
`71786be8ed1be9a16dc7b47f1c08d2487102833d5141e1cc0a3f0b5ec34cc694`
(11,252,224 bytes).

This is a post-RC.3 product qualification result. It advances cumulative v9.1
campaign coverage but does not rewrite the immutable RC.3 package ledger. The
binary was built from source base
`1a0f8a272a56af4999902d49ac868388c47e1732` plus the still-uncommitted K04
product delta, so the executable hash is the authoritative candidate identity
until that delta is integrated.

## Physical topology

- H1 used a redacted ULA endpoint on physical `Ethernet`, interface index 7,
  UDP port 48072.
- H3 used a redacted ULA endpoint on physical `Wi-Fi`, interface index 22,
  UDP port 48272.
- The RFC 4193 addresses and `/128` routes were created only for this isolated
  T5 laboratory path. Tailscale carried control and artifact delivery, not
  Kad6 test traffic.
- Both independent Windows hosts executed the same hash-pinned candidate.

## Procedure and observations

Each node first ran with Kad2+Kad6, established one authenticated Kad6 contact
and persisted a 194-byte signed `nodes_v6.dat`. The runner then stopped eMule
gracefully, blocked the exact peer UDP tuple, restarted in Kad6-only mode and
observed zero verified contacts. This proves verification was not inherited
across the restart. Immediately after removing the tuple-specific firewall
rules, each node performed a fresh HELLO and returned to one verified contact
inside the 90-second bound.

| Node | Before restart | Isolated restart | Fresh re-verification |
|---|---:|---:|---:|
| H1 | 1 | 0 | 1 |
| H3 | 1 | 0 | 1 |

The first final attempt exposed an orchestration race: H1 had already passed
all three phases and closed while H3 was beginning its final HELLO window. The
runner now keeps a successful peer alive for a 20-second grace period. The
second run completed with exit code 0 on both hosts. This changed only the
laboratory lifecycle; the candidate executable remained byte-identical.

The product defect found during qualification was in persisted probation
expiry. Snapshot v2 preserves the selected signed candidate but not the
complete endpoint-set transcript. `Load()` therefore leaves the endpoint-set
expiry at zero until HELLO reconstructs it. `Expire()` incorrectly treated
that sentinel as already expired and erased the contact on the first tick.
Expiry now uses the candidate while the endpoint set is absent. A second fix
makes an explicit IPv6 bind authoritative, preventing an unrelated VPN public
IPv6 address from replacing the T5 ULA in the signed sender record.

## Validation and evidence

- Release x64 build: PASS.
- LiveTV/eSE source regressions: 35/35 PASS.
- Kad6 executable suites: 29/29 PASS. The DPAPI persistence suite passed
  15/15 when run outside the filesystem sandbox.
- Compact adjudication:
  [`V91_K04_RESULT.json`](V91_K04_RESULT.json).
- Raw aggregate:
  `lab-runs/v91-k04/bec884b2de364679bc4a467a2ee59607/aggregate-result.json`.

## Matrix effect

The immutable `9.1.0-rc.3` ledger remains at 12 PASS, 0 FAIL and 15 BLOCKED.
The cumulative v9.1 campaign is now **17 PASS, 0 FAIL and 10 BLOCKED**
(63.0% PASS). `V91-K04` is removed from the blocked set.
