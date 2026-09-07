# eMule eSE 9.2.0 (DRAFT)

Status: **draft, not published**. This text becomes final only after the
physical session recorded in `V9.2_PHYSICAL_SESSION_RUNBOOK.md` and the
eight-hour soak of `V9.2_O01_SIMPLE_SOAK.md` have run. Until then the
candidate is `v0.70b-eSE9.2.0-rc.2` and its qualification state is `NO_GO`.
rc.1 was withdrawn after local upgrade qualification found that a profile
restored from 9.1.0 silently disabled the web server (fixed in rc.2).

## What 9.2 delivers

- Automatic direct reachability over IPv4: UPnP IGD, PCP and NAT-PMP mappings
  are requested, read back, owned and cleaned up by the client, and the TCP
  and UDP halves are published together or not at all.
- A mapping accepted by the router is only a *candidate*. It becomes
  *verified* when the eD2K server evidence and a real inbound connection
  belong to the same network generation. No green icon is shown on a
  router acknowledgement alone.
- Every change of interface, address, gateway, external port, lease or
  mapper epoch starts a new generation; stale callbacks from an older
  generation can never modify the current state.
- Honest failure: behind a double NAT, a carrier-grade NAT or a router that
  answers no mapping protocol, the client reports the blocked state and its
  reason instead of claiming a high ID. Verified on the maintainer's own
  double-NAT setup during qualification.
- `GET /api/reach/status`: a read-only, privacy-bounded snapshot of the three
  reachability planes (eD2K TCP, Kad UDP, direct IPv6) with state, reason,
  generation and lease, without addresses, nonces or tokens.
- A frozen, versioned candidate snapshot (`DirectCandidateSnapshotV1`) that
  9.3 consumes without reading logs or GUI state.
- Upgrade safety: a profile restored from an older release carries an older
  `config\eMule.tmpl`; 9.2 now falls back to the template shipped next to the
  executable instead of disabling the web server (found by the 9.1.0 → 9.2
  upgrade test, fixed in rc.2).
- Internal: the LiveTunnel, WebServer and LiveStream coordinators were split
  into owned modules with enforced size and dependency limits; the wire
  format and on-disk files stay byte-compatible with 0.70b, 8.1 and 9.1.

## Qualification status

Automated qualification of the candidate passed twice, the second time from
a clean checkout: Release x64 build, Core and Integration suites, the full
`libnatmap`, `libreach` and `libkad6` gates, the simulated NAT gateway (T8)
matrix, the reach-status schema goldens and a runtime check of the exact
executable with mappings off and with mappings on behind a double NAT. Local
upgrade and rollback between 9.1.0 and this candidate on one profile passed,
including a simulated crash.

The following physical results are required before this note is final:

| Case | Status |
|---|---|
| `H93-15` three mapping cycles on a real router (candidate → verified → withdrawn) | passed on 2026-09-06: 3 consecutive cycles on the maintainer's ISP router (Movistar HGU, UPnP IGD, single NAT); mapping granted within 5 s, verified through an eD2K server HighID plus an accepted inbound TCP connection within 5 s, mappings withdrawn on a clean exit |
| `H93-16` data path outside the overlay and LAN → hotspot → LAN change | pending |
| `V92-O01` eight-hour lease soak on a real router | run on 2026-09-06/07: lease renewals, provoked mapping loss, reachability API and clean shutdown all passed; **failed the memory criterion** (working set +66.6 % in 8 h with an eD2K server and Kad connected, plan limit 50 %; handles and threads flat; growth slowing from 10 to 1.5 MiB/h). Attribution over eight isolated instances traced the growth to Kad holder duty on a reachable node, not to a leak: instances without a router mapping stay flat under the same load, and the Kad index a mapped instance writes to disk grows in step. A 30 h run is measuring where it levels off, and the soak threshold will be recalibrated against that |
| T7 (UPnP on a second router brand) and a remote topology | not planned for 9.2.0; disclosed limitation |

## Known limitations

- Disclosed gaps inherited from 9.1.0 and still unverified: public dual-stack
  route selection (`V91-I03`), silent native-IPv6 drop with bounded IPv4
  fallback (`V91-I04`), native mobile-IPv6 LiveTV (`V91-I07`) and controlled
  A+AAAA DNS fallback (`V91-D01`). They require native IPv6 in the lab.
- Direct IPv6 reachability ships disabled by preference in the default
  profile of this candidate.
- When no gateway answers any mapping protocol, the reported reason is
  `MappingDenied`; a more specific `NoRoute` reason may follow in a later
  release. The state itself is correct (blocked, never verified).
- Portable installs: the dashboard's download list and library views still
  read `%USERPROFILE%\Downloads\eMule` unless `eSE\emule_paths.json` points
  them at the package's own `Incoming` and `Temp`; the native client itself
  uses the package directories. Fix planned for 9.2.x.
- The classic web pages of the native WebServer become available a few
  seconds after `/api/status`; the dashboard retries and is not affected.
- Sources with private or loopback addresses embedded in an eD2K link are
  discarded as non-routable; LAN-only transfers must go through the normal
  discovery path.
- The WebServer is never mapped automatically.
- A mapping deleted by the router administrator is not noticed between lease
  renewals. With the 7200 s leases the product requests, the renewal at 45 %
  (about 54 minutes) re-creates the entry, so the plane can report `VERIFIED`
  for up to that long while the router has no mapping. Periodic readback for
  finite leases is planned for 9.3.
- Some eD2K servers answer the port check negatively at once, or refuse to
  re-check a client that reconnects within about ten minutes. The product then
  reports `WITHDRAWN` with reason `ServerCallbackFailed` (a LowID) even though
  the mapping works; connecting to another server, or waiting, restores
  `VERIFIED`.
- The dashboard (`ese-server.exe`) listens on `127.0.0.1:8080` and does not
  start when another local program holds that port. The `ESE_PORT` environment
  variable selects another port. The native client and the reachability state
  machine do not depend on the dashboard.
- No universal HighID is promised. Routers that reject or limit UPnP (the
  maintainer's ISP router returned SOAP fault 501 with 64 table entries
  during 9.1 qualification) still produce a LowID, reported honestly.

## Backup, installation and rollback

Automatic updating is disabled. Before installing, close eMule and back up
the profile (`config` directory: `preferences.ini`, credits, keys,
`known.met`, `.part` and `.part.met` files). Install into a new empty
directory and restore a copy of the profile there while eMule is stopped.
Verify `BUILD_INFO.txt` and `SHA256SUMS.txt` before starting.

To roll back, stop 9.2.0, restore the previous application directory and
the profile snapshot. Files that 9.2.0 adds to the profile can be left in
place or removed; 9.1.0 starts with either. Never open one profile with two
versions at the same time.
