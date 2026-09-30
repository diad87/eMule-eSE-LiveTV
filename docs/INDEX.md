# eMule eSE documentation

This directory contains the public documentation required to use, release and
maintain eMule eSE.

## User documentation

- [eSE 9.2.0-rc.2 release notes](RELEASE_NOTES_v9.2.0-rc.2.md)
  - candidate that replaces rc.1 with the profile-template upgrade fix.
- [eSE 9.2.0-rc.2 execution contract](V92_RC2_EXECUTION.md)
  - build, local gates, physical session, soak and decision for rc.2.
- [eSE 9.2.0 release notes (draft)](RELEASE_NOTES_v9.2.0.md)
  - final-release text pending the physical session; disclosed gaps.
- [eSE 9.2.0-rc.1 release notes](RELEASE_NOTES_v9.2.0-rc.1.md)
  - qualification-candidate scope, `NO_GO` release state, fixed limitations
  and rollback boundary.
- [eSE 9.2.0-rc.1 execution contract](V92_RC1_EXECUTION.md)
  - exact build, package, physical campaign and promotion requirements.
- [eSE 9.2 estado de cierre (tablero vivo)](V9.2_STATE.md)
- [eSE 9.2 runbook de la sesión física](V9.2_PHYSICAL_SESSION_RUNBOOK.md)
- [eSE 9.2 soak simple V92-O01](V9.2_O01_SIMPLE_SOAK.md)
- [Cierre del gate G91 (9.1.0 con huecos declarados)](V9.1_G91_DECISION_2026-09-05.md)
- [eSE 9.1.0 release notes](RELEASE_NOTES_v9.1.0.md)
  — final Windows x64 scope, cumulative qualification limits, safe defaults,
  update procedure and rollback.
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

## 9.3+ planning (decided 2026-09-30)

- [eSE 9.3 single release](V9.3_PLUS_RELEASE_TRAIN.md) — **start here**. The
  owner decisions of 2026-09-30 merge the former 9.3-9.8 train into one 9.3,
  published only at the end, with six blocks on two parallel lanes: Direct
  Core; DirectOnlyV1 without relay; QUIC and receive-first interop; server
  callback and RendezvousV2; engine, shares, persistence and Download
  Validator; search, UI, accessibility and platforms. Private LiveTV follows
  as 9.4. The documents below are design references for those blocks; where
  they disagree, the plan and the owner decisions win until the specification
  amendment is written.
- 9.3: [development and test plan](V9.3_DEVELOPMENT_AND_TEST_PLAN.md),
  [execution state](V9.3_EXECUTION_STATE.md),
  [runbook](V9.3_EXECUTION_RUNBOOK.md),
  [preparation handoff](V9.3_PREPARATION_HANDOFF_2026-09-04.md); archived by
  D8: [assurance stack](V9.3_ASSURANCE_STACK.md),
  [model orchestration](V9.3_MODEL_ORCHESTRATION.md) and
  [ADR-0001](adr/ADR-0001-tesis-vs-especificacion-9.3.md) (its section 4.2 is
  obsolete: the hole-punch identity defect was fixed in `58458afe`).
- 9.4 DirectOnlyV1: [development and test plan](V9.4_DEVELOPMENT_AND_TEST_PLAN.md),
  [execution state](V9.4_EXECUTION_STATE.md),
  [runbook](V9.4_EXECUTION_RUNBOOK.md); archived by D8:
  [assurance stack](V9.4_ASSURANCE_STACK.md),
  [model orchestration](V9.4_MODEL_ORCHESTRATION.md).
- eMule AI parity programme: [integrated roadmap](EMULEAI_INTEGRATED_RELEASE_ROADMAP.md),
  [parity and superiority programme](EMULEAI_PARITY_AND_SUPERIORITY_PROGRAM.md),
  [v1.6 delta baseline](EMULEAI_V1.6_DELTA_BASELINE.md),
  [9.8 interop envelope (parked)](V9.8_ECOSYSTEM_INTEROP_ENVELOPE.md),
  [server conformance lab](SERVER_CONFORMANCE_LAB.md) and
  [external interop catalog](protocol/EXTERNAL_INTEROP_CATALOG.csv).
- Design sources: [LowID-to-LowID minimal direct core](LOWID_LOWID_MINIMAL_DIRECT_CORE_DESIGN.md),
  [consolidated thesis](TESIS_CONSOLIDADA_LOWID_A_LOWID_DIRECTO_V9.1_2026.md)
  ([.docx](TESIS_CONSOLIDADA_LOWID_A_LOWID_DIRECTO_V9.1_2026.docx)),
  [technical thesis RC1 (.docx)](TESIS_TECNICA_LOWID_A_LOWID_DIRECTO_V9.1_RC1.docx),
  [functional LowID abolition v3](TESIS_ABOLICION_FUNCIONAL_LOWID_EMULE_V3_2026.md),
  [Kad without LowID](THESIS_KAD_SIN_LOWID.md),
  [LowID NAT traversal plan](LOWID_NAT_TRAVERSAL_PLAN.md),
  [Kad6 architecture](KAD6_ARCHITECTURE.md),
  [Kad2 traffic cost/benefit](KAD2_TRAFFIC_COST_BENEFIT_PLAN.md).
- 9.2 programme history: [development and test plan](V9.2_DEVELOPMENT_AND_TEST_PLAN.md),
  [modularization plan](V9.2_MODULARIZATION_AND_ARCHITECTURE_PLAN.md),
  [historical execution ledger](V9.2_EXECUTION_STATE.md),
  [runbook](V9.2_EXECUTION_RUNBOOK.md),
  [assurance stack](V9.2_ASSURANCE_STACK.md),
  [model orchestration](V9.2_MODEL_ORCHESTRATION.md),
  [reach-status adapter card](V9.2_REACH_STATUS_ADAPTER_CARD.md),
  [handoff lab readiness](V9.2_HANDOFF_GATE_LAB_READINESS.md),
  [entry evidence](V9.2_ENTRY_EVIDENCE_2026-07-24.md),
  [9.1 gate gap evidence](V9.1_GATE_GAP_EVIDENCE_2026-07-24.md),
  [9.1 to 9.2 handoff](V9.1_TO_V9.2_PROVISIONAL_HANDOFF_2026-07-27.md),
  [9.1 beta.2 plan](V9.1_BETA2_DEVELOPMENT_AND_TEST_PLAN.md).
- Track plans mapped to 9.5-9.7 by the train: [Swarm DVR](SWARM_DVR_PLAN.md),
  [channel manifest](CHANNEL_MANIFEST_PLAN.md),
  [mobile viewer](MOBILE_VIEWER_PLAN.md),
  [part-hash thread](PART_HASH_THREAD_PLAN.md),
  [performance audit](PERF_AUDIT.md),
  [modernization roadmap](MODERNIZATION_ROADMAP.md),
  [Sprint E breakdown](V8.1.1_SPRINT_E_BREAKDOWN.md) and
  [its validation recipe](V8.1.2_VALIDATION_RECIPE.md),
  [authenticated tunnel handshake](AUTHENTICATED_TUNNEL_HANDSHAKE_PLAN.md) and
  [its 3-PC validation](protocol/AUTH_TUNNEL_3PC_VALIDATION.md),
  [reach host adapter](REACH_HOST_ADAPTER_PLAN.md),
  [Linux/Docker/ARM daemon spec (parked)](SPEC_ESE_DAEMON_LINUX_DOCKER_ARM.md).
- [KRP relay archive](relay/README.md) — P0-P4 design, closures and threat
  model of the relay that 9.4 DirectOnlyV1 removes from the build (D7). Kept
  for traceability; not a current plan.
