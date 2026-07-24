# Forum draft — eMule eSE 9.1.0-beta.1

## Suggested title

`[BETA] eMule eSE 9.1.0-beta.1 — native IPv6/Kad6 testing between eSE peers`

## Post

Hi,

eMule eSE 9.1.0-beta.1 is ready for public beta testing on Windows x64.

This build advances the native IPv6 and Kad6 work already present in the 9.0
betas. It is intended to form a sufficiently large, explicitly consenting test
population and collect real-world evidence before the 9.1 RC. It does not claim
universal High ID, CGNAT traversal or compatibility with every IPv6 ISP/router
combination.

Main changes:

- native dual-stack listener and outgoing connections between capable eSE
  peers;
- IPv6 sources, callbacks and LiveTV peer lists without truncating addresses;
- native `[IPv6]:port` LiveTV direct join for IPv6-only data-plane tests;
- SOCKS5 and HTTP CONNECT support for IPv6 destinations; explicit IPv6
  rejection through SOCKS4/4A;
- Kad2 and Kad6 remain independently selectable and use separate routing
  state;
- IPv6 queueing, bans and anti-abuse accounting no longer rely on synthetic
  IPv4 identities;
- neutral credit policy for IPv6-only peers in this beta;
- safer relay lease reconnection and stricter callback/peer-list parsing;
- bounded per-peer Live send queues so slow viewers cannot grow relay memory
  without limit;
- three explicit laboratory consent levels: base measurements, advanced
  experiments and resource contribution.

All laboratory levels are disabled by default. Declining or not answering
leaves them disabled. Resource contribution, relay and Kad6 Beta Exit require
their own opt-in, can be revoked, and do not enable a stable/public Kad6 exit.
KRP also remains fail-closed unless a complete authenticated local
configuration is present. No automatic telemetry is uploaded.

Evidence completed before publication:

- Windows x64 full build and standalone regression suite;
- relay edge regression suite with real TLS/WSS loopback;
- 12,000,000,000-byte transfer with abrupt interruption, recovery and
  identical final SHA-256;
- local Kad/Live soak exceeding 12 hours without observed Kad disconnect or
  missing Live chunks;
- strict IPv6 LiveTV data-plane soak: 2 hours at 12 Mbps between two isolated
  Windows instances on the same host, 468 valid samples, valid HLS playlist
  and MPEG-TS segments, no buffer gaps and zero IPv4 fallback;
- local consent, kill-switch and web/API security tests;
- direct beta.2 -> eSE 8.1 compatibility test.

The physical three-node Live test, LAN -> tethering transition and the
IPv6-only cases that require the third Windows machine are tracked separately.
They are not reported as PASS until they have actually run. Overlay tests are
labelled as overlay tests, not public IPv6 reachability.
The same-host IPv6 soak above validates the strict data plane; it is not
reported as the normative two-physical-machine `T5` case.

Known beta limitation: A/AAAA results and both address families are supported,
but moving every `getaddrinfo(AF_UNSPEC)` call to a non-blocking worker remains
work for a later beta before RC.

Download:

`<RELEASE_URL>`

SHA-256:

`<ZIP_SHA256>`

Please back up the complete `config` directory and all `.met` files, test with
a copied profile first, and keep `emule.exe` and `ese-server.exe` from the same
package. The detailed release notes and rollback procedure are included.

Useful reports include:

- whether the peer used IPv4 or IPv6;
- ISP/router setup and whether CGNAT was present;
- direct, relay or overlay path;
- LAN/hotspot transition result;
- anonymised log excerpt and exact test time;
- whether each laboratory consent level was enabled.

Please do not publish authentication tokens, private keys, full public IP
addresses or unsanitised configuration files.
