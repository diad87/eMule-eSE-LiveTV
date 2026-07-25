# eMule eSE documentation

This directory contains the public documentation required to use, release and
maintain eMule eSE.

## User documentation

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

- [eSE 9.1.0-rc.1 execution plan](V91_RC1_EXECUTION.md)
  - exact candidate identity, promotion rules, physical/local campaigns and
  current execution state.
- [eSE 9.1.0-rc.1 case results](V91_RC1_CASE_RESULTS.json)
  - machine-readable reconciliation input for the 27-case RC ledger.
- [eSE 9.x release specification and test plan](V9_RELEASE_SPECIFICATION.md)
  - normative scope, current lab topology, acceptance matrices and development
  plan for versions 9.0 through 9.4.
- [Kad6 design, boundaries and promotion policy](KAD6_IMPLEMENTATION_PLAN.md)
  - default-on experimental client decision, native/gateway/exit separation,
  persistence, wire evolution and 9.0/9.1 gates.
- [Kad2 and Kad6 network selection](KAD_NETWORK_SELECTION.md)
  - masks, profile migration, hot switching and observable state.
- [WP0 laboratory toolkit](../tools/lab/README.md) - isolated node profiles,
  sanitized evidence, data-route assertions, soak monitoring and reports.

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
