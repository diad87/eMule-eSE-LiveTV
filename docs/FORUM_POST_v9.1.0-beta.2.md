# Forum draft — eMule eSE 9.1.0-beta.2

## Suggested title

`[BETA] eMule eSE 9.1.0-beta.2 — IPv6/Kad6, persistent NetLab kill switch and proxy fixes`

## Post

Hi,

eMule eSE 9.1.0-beta.2 is ready for public beta testing on Windows x64.

This is a focused update to beta.1. It keeps the native IPv6 and Kad6 work and
fixes the two reproducible failures found during the beta.1 freeze:

- disabling NetLab now persists across forced restarts;
- the NetLab kill switch closes its base, advanced, relay, KRP and Kad6 Beta
  Exit surfaces in under five seconds;
- stable Kad6 public-exit consent remains independent and is not changed by
  the NetLab switch;
- an IPv6 destination through SOCKS4/4A is explicitly rejected before dialing,
  instead of reporting a connection attempt that the proxy cannot represent.

The IPv6 proxy matrix passes for SOCKS5, HTTP CONNECT and the SOCKS4 rejection
case. The consent matrix passes twice, including restart persistence. The
complete Windows x64 Core and Integration suites, package smoke and signed
local-ingest selftest also pass.

The broader 26-case 9.1 matrix currently has 8 PASS, 0 FAIL and 18 BLOCKED.
Those blocked cases require physical multi-node, IPv6-only or network-transition
topologies that were not available. They are not being reported as PASS. This
is therefore a public laboratory beta intended to grow an explicitly
consenting test cohort, not a 9.1 RC or a claim of universal High ID/CGNAT
traversal.

All laboratory features remain disabled by default. Participation requires
explicit consent, contribution is a separate level, and no automatic telemetry
is uploaded.

Download:

`https://github.com/diad87/eMule-eSE-LiveTV/releases/tag/v0.70b-eSE9.1.0-beta.2`

ZIP SHA-256:

`DFB372F94B4EC928F1BA7771B677342C0218C5F8AD601B641D8059F1E82D5694`

Please back up the complete `config` directory and all `.met` files, extract
the beta into a new directory, and keep `emule.exe` and `ese-server.exe` from
the same package.

Useful reports include the exact beta version, IPv4/IPv6 route, ISP/router,
CGNAT status, direct/relay/overlay path, consent levels enabled, exact test time
and a sanitised log excerpt. Please do not publish tokens, private keys, full
public IP addresses or unsanitised configuration files.
