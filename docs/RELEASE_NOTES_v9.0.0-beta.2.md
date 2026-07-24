# eMule eSE 9.0.0-beta.2

Status: **release candidate under validation**. This build has not been
published. The currently published public beta remains 9.0.0-beta.1 until the
beta.2 release gate is complete.

Beta.2 is still a Windows x64 network-laboratory beta, not the stable channel.
It consolidates the post-beta.1 core work without claiming that the planned
9.1–9.4 networking functions are production-ready.

## Changes since beta.1

### Core reliability and compatibility

- Hardened inherited eMule core behavior, localization and shutdown paths.
- Preserved 64-bit part-file and `known2.met` offsets.
- Added regression policies for part-file I/O, upload limits, Kad wire
  compatibility and Kad network selection.
- Kept Kad2 and Kad6 state, selection and persistence separate.
- Added deterministic checks for legacy peers and additive capability
  negotiation.

### IPv6 development available to the laboratory

- Added negotiated IPv6 server-source responses and IPv6 callbacks.
- Extended address-safe transport paths without replacing legacy IPv4 wire
  formats for peers that do not advertise support.
- Added dual-stack selection and explicit Kad2/Kad6 modes.
- Added standalone address, wire, routing, quota, lease and deterministic fuzz
  gates.

The native Kad6 client is intentionally selected together with Kad2 in a
fresh or migrated profile (`KadNetworkMask=3`). This forms an eSE beta
population for routing and source-discovery validation. It does not enable a
Kad6 public exit, gateway/carrier service, relay duty or bandwidth
contribution. Those surfaces remain separately gated and off.

These paths remain beta laboratory functionality. Beta.2 does **not** claim
complete IPv6-only support; that promotion belongs to eSE 9.1 after its
topology and compatibility gates pass.

The detailed boundary and beta wire-evolution policy are documented in
[`KAD6_IMPLEMENTATION_PLAN.md`](KAD6_IMPLEMENTATION_PLAN.md).

### LiveTV and local dashboard hardening

- Preserved the packaged offline HLS player and local playback workflow.
- Hardened LiveTV source selection, FFmpeg startup and cleanup.
- Restricted URL ingest to allowed protocols and public addresses, resolving
  and pinning the selected address before FFmpeg starts.
- Added bounded request-body handling and safer download actions.
- Prevented cross-site browser requests from inheriting localhost trust.
- Kept received HLS local-only unless remote authentication succeeds.
- Expanded LiveTV/security regression coverage.

### Reproducible laboratory evidence

- Added isolated A/B/R profile preparation.
- Added sanitized inventory and status capture.
- Added a TCP data-route assertion that rejects Tailscale as test evidence.
- Added soak monitoring and canonical JSON/Markdown reports with SHA-256
  evidence indexes.

No laboratory report is uploaded automatically.

## Consent and safe defaults

A fresh profile starts with NetLab undecided and disabled. Accepting base
NetLab does not activate advanced or contribution functions.

```ini
[WebServer]
WebUseUPnP=0

[eSE]
EseNetLabConsent=0
EseNetLabEnabled=0
EseV9Experimental=0
EseKad3Rendezvous=0
EseAutoKeepalive=0
EseRelayAccept=0
EseRelayEgress=0
EseReachSelector=0
EseHolePunchPortPredict=0
EseEd2kPunch3=0
Kad6PublicExitOptIn=0

[KRPRelay]
KrpRelayEnabled=0
KrpRelayKillSwitch=0
ExperimentalTcpDataPlane=0
```

Relay duty, bandwidth contribution, KRP, Punch3, port prediction, public Kad6
exit and experimental data planes remain separately gated and off by default.

## Security and privacy limits

Beta.2 does not claim:

- strong anonymity;
- universal High ID or universal CGNAT traversal;
- complete IPv6 support across every socket and topology;
- a public relay or Kad6 exit service.

The dashboard is local by default. Remote API, dashboard and HLS access require
authentication. Tailscale may control laboratory nodes but does not count as
proof of a direct eSE data route.

## Profile safety and rollback

1. Back up the complete `config` directory and all `.met` files.
2. Use a copied profile for upgrade and rollback tests.
3. Never open one profile with two eMule processes at the same time.
4. Keep `emule.exe` and `ese-server.exe` from the same package together.
5. To roll back, disable NetLab and every separate experiment, close eMule,
   restore the saved profile and reinstall the previous package.

The release is blocked until build, extracted-package self-test, consent,
security, compatibility, LiveTV, soak and rollback evidence has been reviewed.
