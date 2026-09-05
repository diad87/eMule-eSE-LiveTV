# eMule eSE 9.2.0-rc.2

`9.2.0-rc.2` replaces `9.2.0-rc.1` as the release candidate for the v9.2
direct reachability and automatic-mapping milestone. It is a qualification
candidate, not a declaration that the v9.2 physical exit gate has passed.

## What changed since rc.1

- **Upgrade fix.** A profile restored from 9.1.0 (or any older release)
  carries `config\eMule.tmpl` with template version 7, while 9.2 requires
  version 8. rc.1 reacted by disabling its web server silently, which left
  the dashboard and `/api/*` unreachable after following the documented
  upgrade procedure, and raised a modal box on non-headless starts. rc.2
  falls back to the template shipped next to the executable and logs one
  line. Found by the local 9.1.0 → 9.2 upgrade and rollback test; rc.1 is
  withdrawn.
- No other product change. Mapping, ownership, verification, generation and
  wire behaviour are identical to rc.1.

## What 9.2 changes (unchanged from rc.1)

- Direct reachability models TCP and UDP mappings as one generation-bound
  pair and publishes neither half on its own.
- PCP, NAT-PMP and UPnP observations are admitted only when their route,
  ownership, ports, generation and lease are structurally coherent.
- PCP ownership is tied to the exact TCP and UDP identities returned by the
  gateway; a pair whose two replies disagree on the public address is
  rejected and rolled back.
- NAT-PMP cleanup authority stays bound to the exact route and generation;
  foreign mappings are never cleanup targets.
- `GET /api/reach/status` exposes the three reachability planes with state,
  reason, generation and lease, without addresses, nonces or tokens.

## Safety and privacy

The mapper fails closed. It does not relax address classification, ownership
proof, structural validation or cleanup authorization. Evidence contains
counters, enums and hashes only; it excludes raw endpoints, ports, process
identifiers, credentials, nonces and payloads.

## Qualification status

Automated qualification is green on this candidate's tree: Release x64
build, Core and Integration suites, complete `libnatmap`, `libreach` and
`libkad6` gates, simulated NAT gateway matrix, reach-status goldens, runtime
checks of the exact executable with mappings off and on behind a double NAT,
and the 9.1.0 → rc.2 → 9.1.0 upgrade, crash and rollback cycle.

The candidate remains `NO_GO` until the physical cases are recorded on a
real router (`H93-15`, `H93-16`) and the eight-hour lease soak `V92-O01`
completes, as described in `V9.2_PHYSICAL_SESSION_RUNBOOK.md` and
`V9.2_O01_SIMPLE_SOAK.md`. The formal eight-hour controller of rc.1 is no
longer a release gate; it remains available as an optional nightly.

## Backup, installation and rollback

Automatic updating remains disabled. Before testing, close eMule and back up
the active profile, application directory, incoming directory and temporary
download directory. Keep `preferences.ini`, credits, keys, `known.met`,
`.part` and `.part.met` files from the same snapshot.

Install the candidate into a new empty directory. For portable use, restore a
copy of the backed-up profile into that new directory while eMule is stopped;
rc.2 tolerates the older `eMule.tmpl` that such a copy contains. Verify
`BUILD_INFO.txt` and `SHA256SUMS.txt` before starting it.

To roll back, stop the candidate, preserve newly completed downloads
separately, and restore the previous application and profile snapshot. Never
open one profile concurrently with two eMule versions.
