# eMule eSE documentation

This directory contains the public documentation required to use, release and
maintain eMule eSE.

## User documentation

- [eSE 9.1.0-rc.3 release notes](RELEASE_NOTES_v9.1.0-rc.3.md)
  — successor candidate that restores direct-link-only downloads when eD2K
  and Kad discovery are intentionally disconnected.
- [eSE 9.1.0-rc.2 release notes](RELEASE_NOTES_v9.1.0-rc.2.md)
  — successor candidate that bounds direct IPv6-to-IPv4 fallback and closes
  the silent-blackhole defect found while qualifying rc.1.
- [eSE 9.1.0-rc.1 release notes](RELEASE_NOTES_v9.1.0-rc.1.md)
  — rejected-candidate record for the frozen v9.1 feature set; retained only
  for traceability after the silent-blackhole fallback defect.
- [eSE 9.1.0-beta.3 release notes](RELEASE_NOTES_v9.1.0-beta.3.md)
  — safe shared-file intake parity and A/B superiority over the frozen eMule
  AI 1.5.2 filename-policy baseline.
- [eSE 9.1.0-beta.3 gate report](V91_BETA3_GATE_REPORT.md)
  — exact candidate provenance, complete release pipeline, package hashes and
  isolated package self-test.
- [AI-I03 v9.1 evidence](AI_I03_V9.1_EVIDENCE.md)
  — implementation scope, fixed baseline, reproducible corpus and validation
  gates for the shared-file intake policy.
- [eSE 9.1.0-beta.2 release notes](RELEASE_NOTES_v9.1.0-beta.2.md)
  — IPv6/Kad6 between eSE peers, persistent laboratory revocation, explicit
  proxy-family handling and current beta limitations.
- [eSE 9.1.0-beta.2 gate report](V91_BETA2_GATE_REPORT.md)
  — exact candidate provenance, local executable gates and release decision.
- [eSE 9.1.0-beta.2 forum draft](FORUM_POST_v9.1.0-beta.2.md)
  — publication text with checksum, scope and honest topology limitations.
- [eSE 9.1.0-beta.1 release notes](RELEASE_NOTES_v9.1.0-beta.1.md)
  — initial public 9.1 laboratory beta and its recorded limitations.
- [eSE 9.0.0-beta.2 candidate release notes](RELEASE_NOTES_v9.0.0-beta.2.md)
  — post-beta.1 reliability, laboratory and security scope under validation.
- [User guide](USER_GUIDE.md) — installation, playback, broadcasting,
  networking and troubleshooting.
- [eSE 9.0.0-beta.1 release notes](RELEASE_NOTES_v9.0.0-beta.1.md) — beta
  scope, safe defaults, privacy limits and rollback.
- [eSE 8.1.0 release notes](RELEASE_NOTES_v0.70b-eSE8.1.0.md) — previous
  stable release and its one-hop control-tunnel limitations.

## Maintainer documentation

- [v9.1 post-RC3 qualification campaign](V91_POST_RC3_CAMPAIGN_STATUS.md)
  - complete 27-case cumulative view, provenance boundary between the
    immutable RC3 ledger and the post-RC3 candidate, and exact prerequisites
    for the remaining 5 BLOCKED cases.
- [V91-I01 exact-candidate execution](V91_I01_EXECUTION.md)
  - canonical 4 GiB transfer between two physical Windows peers over the
    IPv6-only T5 path; cumulative coverage is 21 PASS and 6 BLOCKED.
- [V91-O01 physical dual-stack execution](V91_O01_EXECUTION.md)
  - unattended two-host LiveTV-IPv6 plus 4 GiB-IPv4 soak; the formal
    43,200-second physical result is PASS.
- [V91-O01 compact result](V91_O01_RESULT.json)
  - hash-pinned 12-hour aggregate, sample coverage, LiveTV progress, dual-stack
    transport evidence and bounded duplicate/resource deltas.
- [V91-R01 unattended mobility execution](V91_R01_EXECUTION.md)
  - audited offline harness for a LAN-to-mobile-hotspot transition, direct
    eD2K reconnection, stale-endpoint expiry and automatic Home restoration;
    the physical tethering result remains pending.
- [V91-I07 native-mobile-IPv6 execution](V91_I07_EXECUTION.md)
  - audited offline T3 harness for a direct eSE LiveTV session over native
    public IPv6, with raw route/socket attribution, independent Home watchdog
    and retained evidence; the physical two-peer result remains pending.
- [V91-I03 public dual-stack route selection](V91_I03_EXECUTION.md)
  - reproducible offline preflight for Auto/Preferred route selection; the
    physical public dual-stack result remains pending.
- [V91-I04 silent IPv6 fallback](V91_I04_EXECUTION.md)
  - reproducible offline preflight for the bounded IPv6-to-IPv4 fallback,
    terminal leases and PktMon ownership; the physical DROP result remains
    pending.
- [V91-D01 dual A+AAAA DNS fallback](V91_D01_EXECUTION.md)
  - reproducible offline preflight for canonical DNS candidates, packet-drop
    evidence and global PktMon rollback; the physical two-host result remains
    pending.
- [V91-I08 exact-candidate execution](V91_I08_EXECUTION.md)
  - production-client TCP/UDP IPv6 echo against an independent Windows
    fixture, with exact 128-bit destination evidence; historical coverage at
    that checkpoint was 20 PASS and 7 BLOCKED.
- [V91-K01 exact-candidate execution](V91_K01_EXECUTION.md)
  - Kad6-only source publication and recovery through authenticated two-hop
    circuits; historical coverage at that checkpoint was 19 PASS and
    8 BLOCKED.
- [V91-I02 exact-candidate execution](V91_I02_EXECUTION.md)
  - two-hour 12 Mbps LiveTV soak over the physical IPv6-only T5 path;
    historical cumulative coverage at that checkpoint was 18 PASS and
    9 BLOCKED.
- [V91-I02 compact result](V91_I02_RESULT.json)
  - hash-pinned candidate, physical endpoint identities, 945 active samples,
    zero IPv4 peer observations and viewer progress from 0 to 3,749 chunks.
- [V91-K04 exact-candidate execution](V91_K04_EXECUTION.md)
  - two-host Kad6 restart persistence, zero inherited verification and bounded
    fresh re-verification; cumulative coverage is 17 PASS and 10 BLOCKED.
- [V91-K04 compact result](V91_K04_RESULT.json)
  - hash-pinned candidate, physical T5 identities, persisted snapshot hashes
    and the 1 -> 0 -> 1 verification sequence on both hosts.
- [V91-K02 exact-candidate execution](V91_K02_EXECUTION.md)
  - live Kad2/Kad6 plane isolation on one process, with three physical phases;
    cumulative campaign coverage is 16 PASS, 0 FAIL and 11 BLOCKED.
- [V91-K02 compact result](V91_K02_RESULT.json)
  - hash-pinned masks, runtime samples, protocol silence/continuity, physical
    captures and cleanup evidence.
- [V91-S02 exact-candidate execution](V91_S02_EXECUTION.md)
  - physical two-host temporal IPv6 reuse, independent re-verification and
    expired-record replay rejection; cumulative campaign coverage is
    15 PASS, 0 FAIL and 12 BLOCKED.
- [V91-S02 compact result](V91_S02_RESULT.json)
  - hash-pinned identities, epoch transition, runtime samples, physical
    capture and cleanup evidence.
- [V91-S01 exact-candidate execution](V91_S01_EXECUTION.md)
  - physical two-host Kad6 qualification of full-width IPv6 collision
    isolation.
- [V91-S01 compact result](V91_S01_RESULT.json)
  - hash-pinned candidate, two colliding low-32-bit endpoints, physical
    capture and cleanup evidence.
- [V91-S03 exact-candidate execution](V91_S03_EXECUTION.md)
  - physical two-host Kad6 anti-amplification qualification for the post-RC.3
    product delta.
- [V91-S03 compact result](V91_S03_RESULT.json)
  - hash-pinned candidate, per-opcode physical captures and cleanup evidence.
- [eSE 9.1.0-rc.3 delta execution plan](V91_RC3_EXECUTION.md)
  - exact RC.3 freeze, package identity and mandatory V91-I05 rerun.
- [eSE 9.1.0-rc.3 case ledger](V91_RC3_CASE_RESULTS.json)
  - RC.3 delta qualification with `V91-I05` PASS; currently
    12 PASS, 0 FAIL and 15 BLOCKED.
- [eSE 9.1.0-rc.2 delta execution plan](V91_RC2_EXECUTION.md)
  - exact rc.1 rejection evidence, successor build gates and mandatory runtime
  qualification for the bounded fallback.
- [eSE 9.1.0-rc.2 case ledger](V91_RC2_CASE_RESULTS.json)
  - exact-candidate reconciliation of all 27 normative cases; currently
    11 PASS, 0 FAIL and 16 BLOCKED.
- [eSE 9.1.0-rc.1 execution plan](V91_RC1_EXECUTION.md)
  - exact rejected-candidate identity, historical qualification rules,
  physical/local campaigns and final `NO_GO` state.
- [Pre-RC 9.1 case-result seed](V91_RC1_CASE_RESULTS.json)
  - historical reconciliation input for commit `8d40100`; it is not the final
    `f4f813d` rc.1 ledger and must not be used to promote rc.1 or rc.2.
- [eSE 9.x release specification and test plan](V9_RELEASE_SPECIFICATION.md)
  - normative scope, current lab topology, acceptance matrices and development
  plan for versions 9.0 through 9.4.
- [Kad6 design, boundaries and promotion policy](KAD6_IMPLEMENTATION_PLAN.md)
  - default-on experimental client decision, native/gateway/exit separation,
  persistence, wire evolution and 9.0/9.1 gates.
- [Kad2 and Kad6 network selection](KAD_NETWORK_SELECTION.md)
  - masks, profile migration, hot switching and observable state.
- [WP0 laboratory toolkit](https://github.com/diad87/eMule-eSE-LiveTV/blob/main/tools/lab/README.md)
  - isolated node profiles, sanitized evidence, data-route assertions, soak
  monitoring and reports.

- [Architecture](../ARCHITECTURE.md) — process boundaries, media flow,
  discovery and source layout.
- [Changes from upstream](../CHANGES_FROM_EMULE_0.70b.md) — implemented
  differences from eMule 0.70b.
- [Protocol registry](protocol/PROTOCOL_REGISTRY.md) — namespaces,
  compatibility rules and generated consistency checks.
- [Third-party licenses](../THIRD_PARTY_LICENSES.md) — dependency
  attribution and redistribution notices.

The CSV files in [`protocol/`](protocol/) are checked by
`tools/check_protocol_registry.py` and are the source of truth for eSE-owned
opcodes, tags, capabilities and tunnel services.
