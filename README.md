# 🐴 eMule eSE — Live TV Edition

[![Public beta](https://img.shields.io/badge/public%20beta-9.0.0--beta.1-orange)](https://github.com/diad87/eMule-eSE-LiveTV/releases/tag/v0.70b-eSE9.0.0-beta.1)
[![Windows build](https://github.com/diad87/eMule-eSE-LiveTV/actions/workflows/build.yml/badge.svg)](https://github.com/diad87/eMule-eSE-LiveTV/actions/workflows/build.yml)
[![CodeQL](https://github.com/diad87/eMule-eSE-LiveTV/actions/workflows/codeql.yml/badge.svg)](https://github.com/diad87/eMule-eSE-LiveTV/actions/workflows/codeql.yml)
[![License: GPL-2.0](https://img.shields.io/badge/license-GPL--2.0-blue.svg)](license.txt)

**eMule Streaming Engine (eSE)** is an eMule 0.70b fork for decentralized
P2P live streaming over eD2K and Kad. It combines the native Windows client,
FFmpeg-based HLS broadcasting and a local web dashboard in one portable
Windows x64 package.

## Download

### [Download eSE 9.0.0-beta.1 for Windows x64](https://github.com/diad87/eMule-eSE-LiveTV/releases/download/v0.70b-eSE9.0.0-beta.1/eSE-LiveTV-v0.70b-eSE9.0.0-beta.1-x64.zip)

[SHA-256 checksum](https://github.com/diad87/eMule-eSE-LiveTV/releases/download/v0.70b-eSE9.0.0-beta.1/eSE-LiveTV-v0.70b-eSE9.0.0-beta.1-x64.zip.sha256)
· [Release notes](docs/RELEASE_NOTES_v9.0.0-beta.1.md)
· [All releases](https://github.com/diad87/eMule-eSE-LiveTV/releases)

> [!IMPORTANT]
> 9.0.0-beta.1 is a public network-lab beta, not the stable channel. The latest
> stable build remains
> [eSE 8.1.0](https://github.com/diad87/eMule-eSE-LiveTV/releases/tag/v0.70b-eSE8.1.0).

### Run it

1. Extract the ZIP to a writable folder such as `C:\eSE\`.
2. Run `emule.exe`.
3. Connect to eD2K and Kad.
4. Press the **eSE** toolbar button.
5. The dashboard opens at
   [http://localhost:8080/live](http://localhost:8080/live).

The portable package already includes the dashboard server, FFmpeg, ffprobe,
the local HLS player and language DLLs. User data is stored under
`%APPDATA%\eMule\` and `%APPDATA%\eSE\`.

- [Quick start in Spanish](GUIA-RAPIDA.md)
- [Full user guide](docs/USER_GUIDE.md)

## What the beta includes

### P2P Live TV

- Broadcast from OBS/RTMP, screen capture, a media file or a test pattern.
- Distribute live HLS chunks through the eD2K/Kad peer mesh.
- Watch in the bundled browser player or through a local HLS URL.
- Select NVENC, Intel QSV or AMD AMF when the encoder is usable, with a safe
  CPU/x264 fallback.
- Recover sources after peer loss and reject duplicate or tampered chunks.
- Browse streams with search, thumbnails, favorites and cinema playback.

```text
OBS / screen / media
         │
         ▼
 emule.exe + FFmpeg ── eD2K/Kad mesh ── viewer's emule.exe
         │                                  │
         ▼                                  ▼
  local HLS preview                 localhost HLS playback
```

### Decentralized discovery

Stream discovery does not require a central tracker:

- Kad publishes and resolves stream records.
- PEX gossip shares recent announcements between connected peers.
- LAN multicast discovers nearby streams on `224.0.0.251:5354`.
- A local cache remembers recently seen streams.

The release package contains a structurally checked and SHA-256-pinned
`nodes.dat`; it does not fetch a mutable bootstrap file while building or
starting.

### Reachability and IPv6

The beta adds consent-based NetLab measurements for real-world IPv6, LowID,
hole-punching and CGNAT behavior. On first run, eSE asks before advertising the
NetLab capability. Reports stay local and are sanitized; there is no implicit
central telemetry.

NetLab participation does not enable every experimental transport. Punch3,
port prediction, relay bandwidth donation, KRP and Kad6 public exit remain
separately gated and **OFF by default**.

### Local dashboard and hardening

- Dashboard and stream browser on `127.0.0.1:8080`.
- Native status/control API on `127.0.0.1:4711`.
- Remote dashboard and received-HLS access require explicit authentication.
- Port 8080 is never exposed automatically through UPnP.
- Request limits, path validation, signed chunks and protocol capability
  checks fail closed.
- Release artifacts include file hashes and build provenance.

## Privacy limits

Endpoint-free links use:

```text
ed2k://|live|KEY||TITLE|/
```

The link does not contain an IP address or port; the viewer resolves a source
through Kad. This does not make either endpoint anonymous by itself.

The 8.1 control tunnel hides the viewer from the broadcaster and Kad search
path, but its production circuit has one relay hop: the exit can identify the
viewer, and the media path can still be direct. The 9.0.0 beta therefore makes
no claim of strong anonymity, universal High ID, complete IPv6 support or
traversal of every NAT.

## Network ports

| Service | Default | Protocol | Exposure |
|---|---:|---|---|
| eMule client | 4662 | TCP | Inbound P2P |
| eMule/Kad | 4672 | UDP | Kad and UDP transport |
| Native WebServer/API | 4711 | TCP | Local control by default |
| eSE dashboard | 8080 | TCP | Local by default; never auto-mapped |
| RTMP ingest | 1935 | TCP | Needed remotely only when OBS is on another PC |
| LAN discovery | 5354 | UDP multicast | TTL 1; local subnet only |

Only expose the dashboard, API or RTMP ports when the use case requires it.

## Build from source

### Requirements

- Windows 10 or 11 x64.
- Visual Studio 2022 with Desktop development with C++, MFC and ATL.
- Node.js 22 and npm.
- Python 3.
- The pinned `libutp` submodule.

```powershell
git clone --recurse-submodules https://github.com/diad87/eMule-eSE-LiveTV.git
Set-Location eMule-eSE-LiveTV
```

For a local developer build:

```powershell
.\tools\build_all.ps1 `
  -ReleaseTag v0.70b-eSE9.0.0-beta.1 `
  -AllowDirty `
  -MaxCpuCount 1
```

`-AllowDirty` is a development override. Release artifacts must be built from a
clean tagged commit without that switch. The full pipeline runs preflight,
core tests, C++ and Node builds, integration tests, language builds,
deterministic packaging and package smoke tests.

Artifacts are written under:

```text
dist\<release-tag>\
├── package\
├── eSE-LiveTV-<release-tag>-x64.zip
└── eSE-LiveTV-<release-tag>-x64.zip.sha256
```

Run the complete local test set with:

```powershell
.\tools\run_alpha_tests.ps1 -Suite All
```

## Documentation

| Document | Purpose |
|---|---|
| [User guide](docs/USER_GUIDE.md) | Install, watch, broadcast and troubleshoot |
| [Beta release notes](docs/RELEASE_NOTES_v9.0.0-beta.1.md) | Safety defaults, limitations and rollback |
| [Architecture](ARCHITECTURE.md) | Runtime processes, data flow and code layout |
| [Changes from eMule 0.70b](CHANGES_FROM_EMULE_0.70b.md) | Implemented fork changes |
| [Protocol registry](docs/protocol/PROTOCOL_REGISTRY.md) | Fork wire namespaces and compatibility rules |
| [Documentation index](docs/INDEX.md) | Complete first-party documentation list |
| [Third-party licenses](THIRD_PARTY_LICENSES.md) | Bundled component attribution |

## License and credits

eMule and this fork are licensed under the
[GNU General Public License v2](license.txt).

- Original client: [eMule Project](https://www.emule-project.net/).
- Native dependencies include CryptoPP, mbedTLS, miniupnpc, libutp, zlib,
  libpng, id3lib, CxImage and ResizableLib.
- The portable runtime includes Node.js, FFmpeg and packaged npm modules.

Downstream distributors must preserve the GPL notices and the attributions in
[THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).
