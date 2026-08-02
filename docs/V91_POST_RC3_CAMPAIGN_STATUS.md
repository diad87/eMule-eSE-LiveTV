# v9.1 post-RC3 qualification campaign

## Scope and interpretation

This document is the cumulative campaign view after the immutable RC3 ledger.
It does not rewrite `V91_RC3_CASE_RESULTS.json` and it does not claim that all
historical PASS results were rerun against one final binary.

- Immutable RC3 ledger: 12 PASS, 0 FAIL, 15 BLOCKED.
- Post-RC3 exact candidate for K02, S01, S02 and S03:
  `622813d5944951efbdba68a1bd7bd68f4d79a2d2`,
  `emule.exe` SHA-256
  `0cb269cedc4b9f7d2c3ceeadd77c7ea291e25d59feff060ac1e2d976e8032c77`.
- K04 exact candidate: `emule.exe` SHA-256
  `71786be8ed1be9a16dc7b47f1c08d2487102833d5141e1cc0a3f0b5ec34cc694`;
  its source delta is retained in this branch, while the binary hash remains
  authoritative for that historical run.
- I02 exact candidate: `emule.exe` SHA-256
  `6f3d7ce29a0c1df42d3b37eb378b4be3b2adcdb7802b3a22696454229e5a3dc2`;
  its source delta is retained in this branch, while the binary hash remains
  authoritative for that historical run.
- K01 exact candidate: `emule.exe` SHA-256
  `fdce4011f28a7792b1e80d749f5a07f9f35dbf50e9f4b558a760134e9edbd4e9`;
  its source delta is retained in this branch, while the binary hash remains
  authoritative for that historical run.
- I08 exact candidate: `emule.exe` SHA-256
  `8b0e2f554d369a7cae7c53e7d118f8d88bddd729b5981ae7e974aedcd295c506`;
  its source delta is retained in this branch, while the binary hash remains
  authoritative for that historical run.
- I01 and O01 exact candidate: `emule.exe` SHA-256
  `0bc2ca4e0d161fc90c1f42009bc1c2e793f6dc1c13c973bebb935d65aff839bd`;
  its source delta is retained in this branch, while the binary hash remains
  authoritative for those historical runs.
- Cumulative campaign coverage: 22 PASS, 0 FAIL, 5 BLOCKED.
- Normative 9.1 release gate: **NO_GO** while any mandatory case remains
  BLOCKED.

The ten post-RC3 results are V91-I01, V91-I02, V91-I08, V91-K01, V91-K02,
V91-K04, V91-S01, V91-S02, V91-S03 and V91-O01. Their result files pin the candidate
identity, physical topology, packet evidence and cleanup independently.

## Complete 27-case matrix

| Case | Status | Provenance or remaining requirement |
|---|---|---|
| V91-A01 | PASS | Immutable RC3 ledger: exact-candidate build, wire and package gates. |
| V91-A02 | PASS | Immutable RC3 ledger: fixed eMule AI 1.5.2 A/B corpus and clean pipeline. |
| V91-I01 | PASS | Post-RC3 run `7dc355480de14910ac746ac42f8f4c93`: two physical T5 peers completed the canonical 4 GiB transfer over IPv6; source and destination matched size, SHA-256 and ED2K, the downloader observed the IPv6 peer and no IPv4 peer socket, and both unattended jobs completed with exit code 0. |
| V91-I02 | PASS | Post-RC3 `V91_I02_RESULT.json`: two physical T5 nodes sustained 12 Mbps LiveTV for 7,200 seconds, the viewer advanced 0 -> 3,749 chunks and 945 combined samples observed no IPv4 peer socket. |
| V91-I03 | BLOCKED | Offline qualification is reproducible at 419/419 PASS in two runs over identical bytes. Formal PASS still needs one dual HighID peer with real public IPv4 and native public IPv6; the current LAN has IPv4 only, and WARP, Tailscale and RFC 5180 benchmark addresses cannot satisfy this public-route requirement. |
| V91-I04 | BLOCKED | Offline qualification is reproducible at 410/410 PASS in two runs over identical bytes. Peer and Coordinator terminal publication now follows all Job Object, immutable-lock, registry/firewall and PktMon cleanup guards; receipts bind the terminal evidence. Formal PASS still needs the I03 public dual-stack fixture and exact silent IPv6 TCP DROP. |
| V91-I05 | PASS | Immutable RC3 ledger and `V91_RC3_I05_RESULT.json`: canonical 4 GiB physical IPv4 transfer, exact hashes and packet adjudication. |
| V91-I06 | PASS | Immutable RC3 ledger: two physical Windows hosts, 300-second LiveTV transfer over explicitly labelled T6 IPv6 overlay. |
| V91-I07 | BLOCKED | The offline T3 harness and runbook are complete: they independently revalidate the node ZIP/package, native route, pre-candidate bidirectional control path, PID-owned socket, exact peer, fresh HLS, retained evidence, cleanup and Home restoration. PASS still requires a prior physical R01 PASS plus two controlled peers with native public IPv6, including H3 on the mobile hotspot. |
| V91-I08 | PASS | Post-RC3 run `6cc46ecc95b9465e9eeac5a2a9773539`: the production EXE opened TCP and UDP to the independent Windows fixture; both echoed the same 79-byte nonce-bound payload, and the fixture recorded the exact 128-bit destination `fd910091050320260000000000000001`. |
| V91-D01 | BLOCKED | Offline qualification is reproducible at 35/35 PASS in three runs over identical bytes, with independent P0=0/P1=0 review. Formal PASS still needs two physical hosts with public dual stack, controlled stable A+AAAA DNS, exact AAAA DROP and working A forward. |
| V91-P01 | PASS | Immutable RC3 ledger: SOCKS5 used ATYP=4 and preserved the full IPv6 destination and port. |
| V91-P02 | PASS | Immutable RC3 ledger: HTTP CONNECT emitted the correct bracketed IPv6 authority and port. |
| V91-P03 | PASS | Immutable RC3 ledger: SOCKS4 rejected IPv6 explicitly without a truncated outbound connection. |
| V91-K01 | PASS | Post-RC3 run `1a9c4ddc09f147889a28e5e110865cdb`: Kad6-only source and requester used authenticated two-hop circuits; the source pipeline changed advertised 0 -> 1, the requester changed recovered 0 -> 1, both physical nodes completed with exit code 0 and the aggregate finalizer returned PASS. |
| V91-K02 | PASS | Post-RC3 `V91_K02_RESULT.json`: one PID, hot masks Both → Kad6-only → Kad2-only, 54/54 runtime samples and exact physical wire isolation. |
| V91-K03 | PASS | Immutable RC3 ledger: saved Kad6-only profile remained Kad2-off under the pinned eSE 8.1 compatibility package. |
| V91-K04 | PASS | Post-RC3 `V91_K04_RESULT.json`: two physical T5 nodes persisted signed contacts, restarted at zero inherited verification and independently returned to one verified contact through fresh HELLO. |
| V91-C01 | PASS | Immutable RC3 ledger: pinned vanilla 0.70b peer on independent Windows, complete classic framing and intact transfer. |
| V91-C02 | PASS | Immutable RC3 ledger: all rejected consent levels kept their surfaces closed in two rounds. |
| V91-C03 | PASS | Immutable RC3 ledger: general revocation persisted and stopped gated activity within the deadline in two rounds. |
| V91-C04 | PASS | Immutable RC3 ledger: incomplete KRP configuration failed closed in two rounds. |
| V91-S01 | PASS | Post-RC3 `V91_S01_RESULT.json`: two full-width colliding endpoints remained distinct and simultaneously verified on the physical path. |
| V91-S02 | PASS | Post-RC3 `V91_S02_RESULT.json`: temporal address reuse required independent verification and rejected the expired record replay. |
| V91-S03 | PASS | Post-RC3 `V91_S03_RESULT.json`: all three unverified-request opcodes were limited to a transaction-bound challenge without amplified response. |
| V91-R01 | BLOCKED | The audited offline v2 harness, dedicated disposable-account agent and exact RC3 candidate passed their unattended preflights. The laptop has separately demonstrated native mobile IPv6. The current Home router does not expose a UPnP static-mapping collection, so the nonce-owned public IPv4 mapping cannot yet be armed and rolled back; no mapping was created. |
| V91-O01 | PASS | Formal run `9108ff953fb044ef91f4d6c3cab521cc`: both physical nodes completed the uninterrupted 43,200-second window with exit code 0; LiveTV remained on IPv6, the canonical 4 GiB transfer completed on IPv4 with exact SHA-256/ED2K, the viewer advanced 62 -> 44,631 chunks, duplicate ratio was 3.24%, drift was 3.24 points and the aggregate finalizer returned PASS. |

## Evidence index

- `V91_RC3_CASE_RESULTS.json`: immutable 27-case RC3 ledger and evidence paths
  for the twelve historical PASS results.
- `V91_RC3_I05_RESULT.json`: compact physical I05 adjudication.
- `V91_I01_EXECUTION.md` and
  `../lab-runs/v91-k04/7dc355480de14910ac746ac42f8f4c93/aggregate-result.json`:
  post-RC3 I01.
- `V91_I02_RESULT.json` and `V91_I02_EXECUTION.md`: post-RC3 I02.
- `V91_I08_EXECUTION.md` and
  `../lab-runs/v91-k04/6cc46ecc95b9465e9eeac5a2a9773539/aggregate-result.json`:
  post-RC3 I08.
- `V91_K01_EXECUTION.md` and
  `../lab-runs/v91-k04/1a9c4ddc09f147889a28e5e110865cdb/aggregate-result.json`:
  post-RC3 K01.
- `V91_K02_RESULT.json` and `V91_K02_EXECUTION.md`: post-RC3 K02.
- `V91_K04_RESULT.json` and `V91_K04_EXECUTION.md`: post-RC3 K04.
- `V91_S01_RESULT.json` and `V91_S01_EXECUTION.md`: post-RC3 S01.
- `V91_S02_RESULT.json` and `V91_S02_EXECUTION.md`: post-RC3 S02.
- `V91_S03_RESULT.json` and `V91_S03_EXECUTION.md`: post-RC3 S03.
- `V91_R01_EXECUTION.md`, `invoke_v91_r01_campaign.ps1`,
  `test_v91_r01_remote.ps1` and `test_v91_r01_campaign.ps1`: unattended R01
  procedure, raw-evidence adjudicator and offline regressions. These validate
  the harness, not the still-pending physical LAN-to-hotspot result.
- `V91_I07_EXECUTION.md`, `invoke_v91_i07_campaign.ps1` and
  `test_v91_i07_offline.ps1`: unattended I07 T3 procedure and offline
  regressions. These validate the harness, not the still-pending physical
  native-public-IPv6 result.
- `V91_I03_EXECUTION.md` and `test_v91_i03_offline.ps1`: two reproducible
  419/419 offline preflight runs over the frozen I03 harness bytes.
- `V91_I04_EXECUTION.md` and `test_v91_i04_offline.ps1`: two reproducible
  410/410 offline preflight runs over the frozen post-audit I04 harness bytes.
- `V91_D01_EXECUTION.md` and `test_v91_d01_offline.ps1`: three reproducible
  35/35 offline preflight runs over the frozen D01 harness bytes.
- `test_v91_effective_ini_sections.ps1`: regression for the effective
  `NetworkED2K` and `CryptLayer*` section in I03, I04 and D01 fixtures.
- `V91_R01_EXECUTION.md`: first physical attempt, local controlled-login
  evidence, corrected defects and the exact remaining PASS procedure.
- `V91_O01_RESULT.json`, `V91_O01_EXECUTION.md` and
  `../lab-runs/v91-k04/9108ff953fb044ef91f4d6c3cab521cc/aggregate-result.json`:
  formal 12-hour physical dual-stack O01 PASS and compact evidence index.

## Fastest path to the next PASS

V91-R01 remains the cheapest next physical attempt after the Home-side public
IPv4 mapping prerequisite is solved. A physical R01 PASS is a prerequisite for
I07, which also needs a second controlled peer with native public IPv6. The
current fixture does not unlock I03, I04 or D01 because those cases
deliberately require real public dual-stack routes.
