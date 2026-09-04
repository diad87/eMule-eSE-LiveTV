# eMule eSE 9.2.0-rc.1

`9.2.0-rc.1` is the first exact release candidate for the v9.2 direct
reachability and automatic-mapping milestone. It is a qualification candidate,
not a declaration that the v9.2 physical exit gate has passed.

## What changes

- Direct reachability now models TCP and UDP mappings as one generation-bound
  pair and publishes neither half on its own.
- PCP, NAT-PMP and UPnP observations are admitted only when their route,
  ownership, ports, generation and lease are structurally coherent.
- PCP ownership is tied to the exact TCP and UDP identities returned by the
  gateway. A pair whose two replies disagree on the public address is rejected
  and rolled back.
- PCP and NAT-PMP result builders now retain the mapper service endpoint, so a
  valid mapping is not rejected later as an unusable gateway.
- NAT-PMP cleanup authority remains bound to the exact route and generation;
  foreign mappings are never cleanup targets.
- The v9.2 T8 laboratory provides real PCP/NAT-PMP wire exchanges, hostile
  replies, bounded recovery, privacy-safe observations and exact teardown.
- The dashboard home page waits for asynchronous media lists before replying,
  reports a failed load without leaving the request open, and uses the completed
  file player for completed videos. File names remain data in card click handlers.
- The formal O01 controller requires 8 uninterrupted hours, 2,880 observation
  ticks, 96 five-minute fault slots, 480 product samples, 95 checkpoints and a
  chained terminal record. The live gateway caps PCP and NAT-PMP grants at 120
  seconds and holds delayed replies for eight seconds so every fault and
  recovery is exercised by real wire traffic. Simulation cannot award a
  formal PASS.

## Safety and privacy

Shared TMDB and OMDb credentials have been removed. Optional movie metadata
requires the user's own local configuration or environment credentials; see
the user guide. The browser uses the local metadata proxy and receives no
provider credential. Upstream metadata responses are bounded and scrubbed,
and movie titles are no longer interpolated into Explore click-handler code.

Native `--selftest` skips secure-user relaunch, link-association changes,
Windows autostart registration and startup firewall configuration. Tests still
require a fresh portable profile; they must not reuse a user's active profile.

The mapper continues to fail closed. It does not relax address classification,
ownership proof, structural validation or cleanup authorization. Formal
evidence contains counters, enums and hashes only; it excludes raw endpoints,
ports, process identifiers, credentials, nonces and payloads.

The release build is accepted only from one clean Git commit. Its Release
receipt binds the commit, complete production-source fingerprint, executable
length and SHA-256. MOD02, the package and the formal run must all name that
same executable.

## Qualification status

This candidate remains `NO_GO` until the independently validated v9.2 evidence
is committed. In particular, the short physical preflight is NON_RELEASE and
can only demonstrate readiness. The formal V92-O01 campaign must complete once
for 28,800,000 monotonic milliseconds with exact cleanup and baseline
restoration before it can contribute a PASS.

Any failed or interrupted campaign remains attributed to its own exact commit
and package. It is never relabeled as evidence for a successor candidate.

## Backup, installation and rollback

Automatic updating remains disabled. Before testing, close eMule and back up
the active profile, application directory, incoming directory and temporary
download directory. Keep `preferences.ini`, credits, keys, `known.met`,
`.part` and `.part.met` files from the same snapshot.

Install the candidate into a new empty directory. For portable use, restore a
copy of the backed-up profile into that new directory while eMule is stopped.
Do not overlay the candidate with executables or web assets from another build.
Verify `BUILD_INFO.txt` and `SHA256SUMS.txt` before starting it.

To roll back, stop the candidate, preserve newly completed downloads
separately, and restore the previous application and profile snapshot. Never
open one profile concurrently with two eMule versions.
