# eMule eSE 9.3.0

The Windows portable packages are prepared for 9.3.0. Physical route
qualification is pending.

- Direct QUIC is experimental and starts disabled. It requires explicit
  user consent, a pinned peer key, an eligible current route and admission
  through the ordinary upload queue.
- Both architectures include the QUIC and TLS runtime, notices and
  corresponding sources. The x64 package includes LiveTV and the dashboard.
  The x86 package includes the native authenticated WebServer.
- The client verifies the full MD4 hashset before publishing it internally.
  A failed replacement of preferences.ini or .part.met preserves the previous
  saved file. Active authenticated QUIC transfers keep their route when a
  duplicate classic connection arrives.
- KRP and the LiveTV buddy relay are retired. Their wire identifiers remain
  reserved.

## Validation

The preceding RC passed local 1 GiB QUIC transfers after 15 seconds of UDP
discard on x64 and x86. A separate x64 lab build based on that RC also
completed both directions between two physical hosts over Tailscale.
[Public RC results](https://github.com/diad87/eMule-eSE-LiveTV/releases/tag/v0.70b-eSE9.3.0-rc.1)

H93-16 remains pending for direct transfer and the LAN → hotspot → LAN cycle.
Physical interoperability and TCP fallback must still be verified for the
network profiles advertised as supported. [Release criteria](V9.3_PLUS_RELEASE_TRAIN.md#17-salida-de-v93-y-validación-proporcional)

## Installation and rollback

Close eMule and back up your existing profile and downloads. Extract the ZIP
to a writable directory and test with a copy of the profile. To roll back,
close eMule, set aside any files completed since the upgrade, and restore your
previous application and profile snapshot.
