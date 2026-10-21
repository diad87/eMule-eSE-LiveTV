# eMule eSE documentation

This directory contains the public documentation required to use, release and
maintain eMule eSE.

## User documentation

- [eSE 9.1.0-beta.2 release notes](RELEASE_NOTES_v9.1.0-beta.2.md)
  — concurrency, protocol honesty, loopback dashboard and binding release gates.
- [eSE 9.1.0-beta.1 release notes](RELEASE_NOTES_v9.1.0-beta.1.md)
  — IPv6/Kad6 between eSE peers, staged laboratory consent, current evidence
  and known beta limitations.
- [User guide](USER_GUIDE.md) — installation, playback, broadcasting,
  networking and troubleshooting.
- [eSE 9.0.0-beta.1 release notes](RELEASE_NOTES_v9.0.0-beta.1.md) — beta
  scope, safe defaults, privacy limits and rollback.
- [eSE 8.1.0 release notes](RELEASE_NOTES_v0.70b-eSE8.1.0.md) — previous
  stable release and its one-hop control-tunnel limitations.

## Maintainer documentation

- [eSE 9.x release specification and test plan](V9_RELEASE_SPECIFICATION.md)
  - preserves the 9.0–9.2 commitments; its opening amendment names the unified
    9.3 plan as current authority. The former sections 10–11 are historical
    design references, including the superseded KRP release proposal.
- [eSE 9.3 single release (decided 2026-09-30)](V9.3_PLUS_RELEASE_TRAIN.md)
  - **main implementation and release plan** for the former 9.3–9.8 scope,
    with early QUIC after the minimum Direct Core contract, DirectOnlyV1
    without relay, server interop tested against our own reference, and a
    parallel engine/UI lane. Uses proportional validation and no dependency
    on external operators; private LiveTV follows as 9.4.
- [eSE 9.3 execution state](V9.3_EXECUTION_STATE.md)
  - **current operational ledger**, kept short on purpose: board of blocks
    A–F, last result and next step per card, and the logging rules.
- [eSE 9.3 execution log up to 2026-10-21](V9.3_EXECUTION_LOG_2026-10.md)
  - full previous ledger preserved unchanged (candidates 1–65, night windows,
    hashes and limits of each run); history, not a second set of gates.
- [eSE 9.3 complete implementation and acceptance specification](V9.3_IMPLEMENTATION_SPECIFICATION.md)
  - technical contract of the single-release plan: data/state models,
    interfaces, error handling, defaults, code integration points and concrete
    fixtures/procedures/oracles covering all 92 cases and the 19 v1.6 deltas.
    Proposed modules and future test runners are explicitly identified.
    Design revision 2 adds Kad6 direct-source discovery and replaceable peer
    rendezvous without fixed servers or payload relay (N.6.1), plus explicit
    Kad2/TCP compatibility and serverless acceptance cases (N.13). These are
    implementation contracts, not claims of completed network validation.
- [ADR-0001: thesis vs specification reconciliation for 9.3](adr/ADR-0001-tesis-vs-especificacion-9.3.md)
  - historical requirement crosswalk; retained as an unaccepted draft. The
    current SPEC amendment resolves authority without requiring this ADR's
    approval or named-model reviews.
- [eSE 9.1.0-beta.2 stabilization and validation plan](V9.1_BETA2_DEVELOPMENT_AND_TEST_PLAN.md)
  - 30 JP programme to harden concurrency, protocol capability claims,
    dashboard exposure, CI, native tests and release consistency.
- [eSE 9.2 development and validation plan](V9.2_DEVELOPMENT_AND_TEST_PLAN.md)
  - 105 JP base programme: 50 functional, 3 thesis handoff, 14 assurance and
    38 architecture, plus eight hosted eMule AI checkpoints; the live ledger
    currently records 152.75 JP after the separately authorized M2A expansion.
- [eSE 9.2 monolith modularization plan](V9.2_MODULARIZATION_AND_ARCHITECTURE_PLAN.md)
  - 38 JP incremental programme to reduce LiveTunnel, WebServer and
    LiveStreamManager with compatibility, dependency and regression gates.
- [eSE 9.2 execution runbook](V9.2_EXECUTION_RUNBOOK.md)
  - microcards, stop conditions, recovery and evidence procedures.
- [eSE 9.2 assurance stack](V9.2_ASSURANCE_STACK.md)
  - compiler, static analysis, coverage, mutation, fuzz, QA and release gauntlet.
- [eSE 9.2 model orchestration](V9.2_MODEL_ORCHESTRATION.md)
  - autonomous Sol/Terra/Luna routing, fallbacks, escalation and audit policy.
- [eSE 9.2 execution state](V9.2_EXECUTION_STATE.md)
  - authoritative active-task ledger, gates, routing history and programme state.
- [9.2 card: /api/reach/status read adapter](V9.2_REACH_STATUS_ADAPTER_CARD.md)
  - implementation-ready card for the hard prerequisite of G92-93-DEV: output
    contract, normative state table, exact insertion points, red tests and DoD.
- [G92-93-DEV physical lab readiness](V9.2_HANDOFF_GATE_LAB_READINESS.md)
  - why HG06 is not runnable today, the missing read-only reachability adapter,
    which rows are executable now, and the hardware inventory for the session.
- [eSE 9.3 development and validation plan](V9.3_DEVELOPMENT_AND_TEST_PLAN.md)
  - historical detailed design, mapped into unified blocks A/B; its former
    estimates and gates do not add another release or mandatory campaign.
- [eSE 9.3 execution runbook](V9.3_EXECUTION_RUNBOOK.md)
  - historical Core/Advanced/Birthday/DVL procedure; current execution is
    governed by the single-release plan and its ledger.
- [eSE 9.3 assurance stack](V9.3_ASSURANCE_STACK.md)
  - historical test inventory; applicable cases can be reused under the
    unified plan's proportional validation policy.
- [eSE 9.3 model orchestration](V9.3_MODEL_ORCHESTRATION.md)
  - retired model-routing policy, retained for history.
- [eSE 9.4 DirectOnlyV1 development and validation plan](V9.4_DEVELOPMENT_AND_TEST_PLAN.md)
  - historical detailed design absorbed into unified blocks A/B; does not
    describe the future LiveTV/privacy 9.4.
- [eSE 9.4 execution runbook](V9.4_EXECUTION_RUNBOOK.md)
  - historical DirectOnlyV1 execution procedures.
- [eSE 9.4 assurance stack](V9.4_ASSURANCE_STACK.md)
  - historical protocol and physical test inventory.
- [eSE 9.4 model orchestration](V9.4_MODEL_ORCHESTRATION.md)
  - retired model-routing policy, retained for history.
- [eSE 9.4 execution state](V9.4_EXECUTION_STATE.md)
  - historical ledger; current work is tracked in the unified 9.3 ledger.
- [Consolidated direct LowID-to-LowID thesis](TESIS_CONSOLIDADA_LOWID_A_LOWID_DIRECTO_V9.1_2026.docx)
  - design source for Direct Core, Advanced Traversal, Birthday NetLab, DVL
    and the revised statistical validation model.
- [eMule AI parity and superiority programme](EMULEAI_PARITY_AND_SUPERIORITY_PROGRAM.md)
  - per-feature gap matrix, measurable superiority gates and execution order
    with a frozen 1.5.2 history and a separately tracked current candidate
    baseline.
- [eMule AI 1.6 delta baseline](EMULEAI_V1.6_DELTA_BASELINE.md)
  - exact 1.6 commit, 19-change crosswalk and freeze gate without duplicating
    the historical 92 cases.
- [eMule AI integrated release roadmap](EMULEAI_INTEGRATED_RELEASE_ROADMAP.md)
  - detailed case and scope reference for the unified plan; former release
    assignments are mapped to blocks A–F rather than separate 9.5–9.8 releases.
- [Server and mod conformance lab](SERVER_CONFORMANCE_LAB.md)
  - pinned external snapshots, receiver-first gates, golden packets, PCAPs and
    parser checks supporting unified blocks C/D and a local server reference.
- [eSE 9.8 ecosystem-interoperability planning envelope](V9.8_ECOSYSTEM_INTEROP_ENVELOPE.md)
  - detailed server-interoperability design now mapped to unified block D:
    callback, authenticated rendezvous, TLS/TCP and optional server QUIC.
- [Kad6 architecture, boundaries and promotion policy](KAD6_ARCHITECTURE.md)
  - default-on experimental client decision, native/gateway/exit separation,
  persistence, wire evolution and 9.0/9.1 gates.
- [Kad2 and Kad6 network selection](KAD_NETWORK_SELECTION.md)
  - masks, profile migration, hot switching and observable state.
- [JEmuleServer IPv6 source-discovery private dialect](JEMULESERVER_IPV6_PROTOCOL.md)
  - eSE-private `0xF0/0xE2` contract, kept distinct from the eMuleQt/eNode
    sentinel dialect.
- [WP0 laboratory toolkit](../tools/lab/README.md) - isolated node profiles,
  sanitized evidence, data-route assertions, soak monitoring and reports.

- [Architecture](../ARCHITECTURE.md) — process boundaries, media flow,
  discovery and source layout.
- [Changes from upstream](../CHANGES_FROM_EMULE_0.70b.md) — implemented
  differences from eMule 0.70b.
- [Protocol registry](protocol/PROTOCOL_REGISTRY.md) — eSE-owned namespaces,
  external observational catalog, compatibility rules and consistency checks.
- [Third-party licenses](../THIRD_PARTY_LICENSES.md) — dependency
  attribution and redistribution notices.

The six eSE-owned registry CSVs in [`protocol/`](protocol/) are checked by
`tools/check_protocol_registry.py` and form the governed local registry for
opcodes, tags, capabilities and tunnel services. `REG-DEBT-001` remains an
explicit blocking exception until `CT_FORK_CAPABILITIES 0xF0` is represented
with its private-dialect ownership. The external catalog is
observational and has its separate `tests/test_external_interop_catalog.py`
gate.
