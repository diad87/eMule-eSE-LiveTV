# eMule eSE 9.3.0-rc.1

**Draft for candidate qualification. Publication and download are pending.**

## Changes in development

- The Direct Core and native peer QUIC work are integrated on top of eSE
  9.2.0-rc.2. The standard x64 build passed the local reachability self-test,
  including TCP and UDP binding, topology invalidation and resume handling.
- Two client instances in private Windows desktops recovered a 1 GiB QUIC
  transfer after 15 seconds of UDP packet discard. The verified parts were
  preserved and the completed file matched the source SHA-256. This test used
  the integrated x64 laboratory build on a single host.
- The x64 package verifies the signed QUIC dependencies and bundles the
  runtime DLLs, notices and corresponding sources. In Connection preferences,
  Direct QUIC can be enabled explicitly with Net Lab consent and a pinned
  peer key. It starts disabled. Initial transfer authorization still depends
  on a compatible current route and the ordinary upload queue.
- Active QUIC sessions track useful transfer progress. An isolated pair
  completed 1 GiB after 15 seconds of UDP discard. With UDP blocked for
  longer and no viable alternative, it ended with a no-progress reason
  and kept the completed parts.

## Qualification still open

The candidate must complete the two-machine transfer and recovery checks,
TCP fallback, mobility, classic interoperability and the integrated 24-hour
campaign. The exact distribution package, supported profiles, experimental
features and network limitations will be recorded after qualification.
[Candidate execution record](V93_RC1_EXECUTION.md)

## Installation and rollback during qualification

Close eMule and back up the application, profile and download state before
testing a qualified package. Extract it into a new directory and start with a
copy of the profile. To roll back, close the candidate, preserve newly
completed downloads separately, and restore the previous application and
profile snapshot.
