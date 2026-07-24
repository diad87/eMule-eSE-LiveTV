# eMule eSE documentation

This directory contains the public documentation required to use, release and
maintain eMule eSE.

## User documentation

- [eSE 9.0.0-beta.2 candidate release notes](RELEASE_NOTES_v9.0.0-beta.2.md)
  — post-beta.1 reliability, laboratory and security scope under validation.
- [User guide](USER_GUIDE.md) — installation, playback, broadcasting,
  networking and troubleshooting.
- [eSE 9.0.0-beta.1 release notes](RELEASE_NOTES_v9.0.0-beta.1.md) — beta
  scope, safe defaults, privacy limits and rollback.
- [eSE 8.1.0 release notes](RELEASE_NOTES_v0.70b-eSE8.1.0.md) — previous
  stable release and its one-hop control-tunnel limitations.

## Maintainer documentation

- [eSE 9.x release specification and test plan](V9_RELEASE_SPECIFICATION.md)
  - normative scope, current lab topology, acceptance matrices and development
  plan for versions 9.0 through 9.4.
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
