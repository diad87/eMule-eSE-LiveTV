# Changes from upstream eMule 0.70b

This repository is a modified eMule 0.70b source tree. The changes below
describe the main first-party differences shipped in eMule eSE 9.1.0.

The list is intentionally limited to implemented behavior. Experimental code
is identified as gated and is not presented as a supported public service.

## Live streaming engine

eSE adds a native LiveTV subsystem to the MFC client:

- broadcast and viewer lifecycle management;
- RTMP/OBS, screen, media-file and test-pattern sources;
- FFmpeg HLS orchestration;
- prebuffer checks and startup rollback;
- signed chunk ingest and verification;
- chunk fragmentation, deduplication and local reconstruction;
- peer subscription, source replenishment and cleanup;
- stream metadata, viewer counts and per-stream isolation;
- local HLS playback through the dashboard or another player.

The principal native classes live in:

- `srchybrid/LiveStreamManager.*`
- `srchybrid/LiveMeshManager.*`
- `srchybrid/LiveTypes.h`
- `srchybrid/LiveFEC.*`
- `srchybrid/LiveBulk.*`
- `srchybrid/LiveTunnel.*`

The native client remains the authority for network and stream state.

## Stream discovery

LiveTV discovery uses several complementary mechanisms:

- Kad publication and keyword search;
- PEX gossip through connected eSE peers;
- LAN multicast on `224.0.0.251:5354`;
- a local cache of recently seen streams;
- direct or endpoint-free `ed2k://|live|...|/` links.

The packaged `nodes.dat` input is pinned and structurally verified.

## Web dashboard

The release includes a packaged Node.js dashboard server:

- stream browser, search, favorites and cinema player;
- broadcast controls and source selection;
- local HLS.js playback without a CDN dependency;
- status, diagnostics and metrics views;
- first-run and network configuration;
- localhost-only dashboard, API proxy and received-HLS access in 9.1.0;
- native API proxying with bounded responses and timeouts.

`emule.exe` starts `ese-server.exe` when the eSE toolbar action is used. The
dashboard listens on port 8080 and proxies native operations to the eMule
WebServer on port 4711. Both HTTP surfaces bind to loopback in 9.1.0;
LAN/remote access is postponed.

## Encoding and media handling

eSE adds:

- FFmpeg and ffprobe integration;
- hardware encoder discovery and functional probing;
- NVENC, Intel QSV and AMD AMF selection when usable;
- CPU/x264 fallback;
- fixed-GOP HLS generation for controlled sources;
- RTMP codec-copy handling for OBS input;
- stream-specific HLS directories and bounded cleanup;
- packaged HLS.js browser playback.

An encoder name being present is not treated as success: eSE verifies that the
selected hardware path can start and falls back safely when it cannot.

## Wire protocol extensions

The fork adds capability-negotiated eD2K/Kad extensions for:

- LiveTV discovery, subscription, heartbeat and chunk transfer;
- large live-chunk fragmentation;
- tunnel cells and tunnel services;
- reachability and hole-punch coordination;
- IPv6 address exchange;
- authenticated identity and tunnel negotiation;
- experimental Kad6 and relay components.

The extensions are additive. They are sent only to peers that advertise the
required capability. The canonical registry is
[`docs/protocol/PROTOCOL_REGISTRY.md`](docs/protocol/PROTOCOL_REGISTRY.md) and
its CSV files.

## Reachability and transport

Network changes include:

- uTP integration for streaming and peer transport;
- IPv6 address handling and in-band public-address detection;
- IPv4 fallback;
- Kad keepalive;
- NAT-PMP, PCP and UPnP mapping lifecycle support;
- direct-path selection and bounded reachability escalation;
- reachability diagnostics and counters;
- consent-based NetLab measurements.

Punch3, anti-CGNAT port prediction, relay bandwidth donation, KRP and Kad6
public exit are gated and disabled by default in the release profile.

## Tunnel and privacy controls

eSE adds a capability-negotiated tunnel control plane for LiveTV search and
subscription, together with authenticated framing and optional Bulk/FEC data
services.

Privacy limits are explicit:

- an endpoint-free link omits the IP and port but is not anonymity by itself;
- the production 8.1 control circuit uses one relay hop;
- the exit can identify the viewer;
- the media path can remain direct;
- no strong-anonymity or universal-reachability claim is made.

## Security hardening

First-party hardening includes:

- loopback-first API boundaries;
- localhost-only dashboard/API/HLS binding for the 9.1.0 package;
- removal of automatic dashboard UPnP exposure;
- HLS path validation;
- bounded proxy responses and request timeouts;
- rate limits and saturation behavior that fail closed;
- HTML, attribute and log escaping;
- signed-chunk verification and tamper rejection;
- capability checks before experimental dispatch;
- CSPRNG-backed identity and nonce generation;
- crash dump support.

Automatic updating is disabled for 9.1.0. No updater executable or
installer is packaged or invoked; update and rollback are manual, with an
explicit profile/download backup.

## Native reachability libraries

The fork contains small first-party libraries used by the host client:

| Component | Purpose |
|---|---|
| `libreach` | Reachability selection and escalation policy |
| `libnatmap` | UPnP, NAT-PMP and PCP mapping lifecycle |
| `libkad6` | Experimental Kad6 framing and routing |
| `librelaycore` | Relay protocol core |
| `librelayclient` | Relay client integration |
| `relayedge` | Relay edge process |

Experimental components are built and tested independently from whether their
runtime service is enabled.

## Build and release system

The original Visual Studio solution remains the native build entry point. eSE
adds:

- Visual Studio 2022/v143 x64 build support;
- a pinned `libutp` submodule;
- Node.js packaging for `ese-server.exe`;
- a single PowerShell release pipeline;
- version/preflight consistency checks;
- pinned FFmpeg, ffprobe and `nodes.dat` inputs;
- clean-tree provenance in `BUILD_INFO.txt`;
- per-file SHA-256 manifests;
- an external ZIP checksum;
- portable-package smoke tests.

Release binaries are published through
[GitHub Releases](https://github.com/diad87/eMule-eSE-LiveTV/releases), not
tracked in the source tree.

## Tests and CI

The repository adds:

- Node.js regression tests;
- standalone C++ tests for LiveTV, rate limits, FEC, bulk transfer and
  reachability;
- protocol registry and direct-port ownership checks;
- address and tunnel framing tests;
- library integration tests;
- sanitizer and fuzz targets for experimental parsers;
- package and executable self-tests;
- GitHub Actions build and CodeQL workflows.

See the
[`tests/README.md` source guide](https://github.com/diad87/eMule-eSE-LiveTV/blob/main/tests/README.md)
for local commands.

## Third-party components

The fork adds or updates dependencies used by the new runtime and transport
features. Redistribution requirements and bundled binary attribution are
listed in [`THIRD_PARTY_LICENSES.md`](THIRD_PARTY_LICENSES.md).

Original eMule copyright notices, translations and GPL licensing remain in the
tree.

## GPL source notice

These modifications are distributed under the GNU General Public License v2,
the same license as eMule. See [`license.txt`](license.txt).

Downstream distributors must provide the corresponding modified source,
preserve notices and include the required third-party attributions.
