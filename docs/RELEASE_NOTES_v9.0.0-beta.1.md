# eMule eSE 9.0.0-beta.1

Published on 2026-07-23 as a **public network-lab beta** for Windows x64.
This is not the stable channel.

## Download

- [Portable x64 ZIP](https://github.com/diad87/eMule-eSE-LiveTV/releases/download/v0.70b-eSE9.0.0-beta.1/eSE-LiveTV-v0.70b-eSE9.0.0-beta.1-x64.zip)
- [SHA-256 checksum](https://github.com/diad87/eMule-eSE-LiveTV/releases/download/v0.70b-eSE9.0.0-beta.1/eSE-LiveTV-v0.70b-eSE9.0.0-beta.1-x64.zip.sha256)

The package is portable and contains `emule.exe`, `ese-server.exe`, FFmpeg,
ffprobe, the local web assets, language DLLs, a pinned `nodes.dat`, per-file
hashes and `BUILD_INFO.txt`.

## Included in this beta

- The eD2K/Kad and LiveTV feature set from eSE 8.1.
- RTMP/OBS, screen, media-file and test-pattern broadcasting.
- Live HLS distribution through the peer mesh and local browser/VLC playback.
- Hardware encoder verification with NVENC, Intel QSV and AMD AMF selection,
  plus a safe CPU/x264 fallback.
- Source replenishment, signed-chunk verification, bounded request handling
  and HLS cleanup.
- Kad keepalive and reachability lifecycle improvements.
- In-band IPv6 detection with IPv4 fallback.
- Authenticated tunnel framing, Bulk/FEC support and abuse-control switches.
- A release pipeline with pinned media inputs, verified manifests, an external
  ZIP checksum and embedded build provenance.

## Consent-based NetLab

On a fresh profile, eSE asks for explicit consent before advertising
`ESE_NETLAB_V1`. If accepted, the beta may perform bounded measurements of
IPv6, LowID, hole punching and CGNAT behavior with other consenting beta
participants during real transfers or broadcasts.

- It does not scan random Internet hosts.
- It does not require confirmation before every individual attempt after
  consent has been granted.
- NetLab can be disabled immediately.
- Sanitized reports stay local; no implicit central telemetry is uploaded.
- Full IP addresses and private keys are not part of the report.

## Experimental functions that remain OFF

These functions require separate activation and are not enabled by NetLab
consent:

- Punch3 and anti-CGNAT port prediction.
- Relay acceptance and relay bandwidth donation.
- KRP relay service.
- Kad6 public exit.
- Any experimental data plane without its own opt-in and kill switch.

The presence of code in the executable is not a support claim.

## Safe defaults

Fresh beta profiles use fail-closed defaults:

```ini
[WebServer]
WebUseUPnP=0

[eSE]
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

The dashboard is local by default, port 8080 is not automatically mapped with
UPnP, and remote dashboard/HLS access requires explicit authentication.

## Privacy limits

This beta does not claim:

- strong anonymity;
- universal High ID;
- complete IPv6 support across every socket and topology;
- traversal of every NAT or CGNAT;
- a public relay or Kad6 exit service.

Endpoint-free LiveTV links do not contain an IP address, but resolving and
transferring a stream can still expose network endpoints to participating
peers. The production control tunnel inherited from 8.1 uses one relay hop, so
the exit can identify the viewer; the media path may also remain direct.

## Compatibility and profile safety

The fork uses additive capability negotiation for eSE-owned protocol
extensions. Before testing the beta:

1. Back up the eMule `config` directory, `.met` files, preferences and keys.
2. Do not run 8.1 and 9.0.0-beta.1 against the same profile simultaneously.
3. Keep `emule.exe` and `ese-server.exe` from the same package together.
4. Use Release x64 builds only.

## Rollback

1. Disable NetLab.
2. Disable every separately enabled experimental feature.
3. Close eMule and keep the logs needed for a bug report.
4. Restore the saved profile.
5. Reinstall the
   [eSE 8.1.0 package](https://github.com/diad87/eMule-eSE-LiveTV/releases/tag/v0.70b-eSE8.1.0).

Do not reuse a laboratory profile as a fresh-profile safety test.

## Reporting a problem

Open a
[GitHub issue](https://github.com/diad87/eMule-eSE-LiveTV/issues/new/choose)
and include:

- the release and commit from `BUILD_INFO.txt`;
- Windows version and hardware/driver details;
- the number of PCs, network topology, IPv4/IPv6 and known NAT type;
- the experimental switches that were enabled;
- exact reproduction steps and timestamps;
- relevant eMule/eSE logs and `/api/status` output.

Remove tokens, keys, private hashes and addresses that you do not want to
publish.
