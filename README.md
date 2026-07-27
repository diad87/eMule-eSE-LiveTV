# 🐴 eMule eSE — Live TV Edition

[![Release candidate](https://img.shields.io/badge/release%20candidate-9.1.0--rc.2-yellow)](docs/RELEASE_NOTES_v9.1.0-rc.2.md)
[![CodeQL](https://github.com/diad87/eMule-eSE-LiveTV/actions/workflows/codeql.yml/badge.svg)](https://github.com/diad87/eMule-eSE-LiveTV/actions/workflows/codeql.yml)
[![License: GPL-2.0](https://img.shields.io/badge/license-GPL--2.0-blue.svg)](license.txt)

**eMule Streaming Engine (eSE)** is an eMule 0.70b fork for decentralized
P2P live streaming over eD2K and Kad. It combines the native Windows client,
FFmpeg-based HLS broadcasting and a local web dashboard in one portable
Windows x64 package.

## Release candidate

### eSE 9.1.0-rc.2 for Windows x64

This source tree builds the exact `9.1.0-rc.2` qualification candidate. Its
immutable package is frozen before the physical release matrix runs; check the
matching release page and 27-case ledger before treating it as promoted.

[RC.2 release notes](docs/RELEASE_NOTES_v9.1.0-rc.2.md)
· [All releases](https://github.com/diad87/eMule-eSE-LiveTV/releases)
· [Previous public beta.1](https://github.com/diad87/eMule-eSE-LiveTV/releases/tag/v0.70b-eSE9.1.0-beta.1)

> [!IMPORTANT]
> 9.1.0-rc.2 is a prerelease IPv6/Kad6 candidate, not the stable channel.
> The latest stable build remains
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

## What the candidate includes

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
`nodes.dat`.

### Reachability, native IPv6 and Kad6

The 9.1 candidate promotes native IPv6 transport between capable eSE peers. Sources,
callbacks and LiveTV peer lists preserve the full 128-bit address; LiveTV
direct join accepts `[IPv6]:port`; and SOCKS5 and HTTP CONNECT support IPv6
destinations. IPv6-only peers use neutral credits, while queue anti-abuse
accounting groups endpoints by `/64` instead of synthetic IPv4 identities.

Kad2 and Kad6 remain independently selectable and keep separate routing state.
A strict same-host IPv6 LiveTV data-plane soak completed two hours at 12 Mbps
with 468 valid samples and zero IPv4 fallback. This validates the data plane;
it is not presented as certification between two physical machines or as
universal public-IPv6 reachability.

NetLab offers separate consent for base measurements, advanced experiments and
resource contribution. Reports stay local and sanitized. Punch3, port
prediction, relay contribution, KRP and Kad6 Beta Exit remain separately gated
and **OFF by default**.

### Local dashboard and hardening

- Dashboard and stream browser on `127.0.0.1:8080`.
- Native status/control API on `127.0.0.1:4711`.
- Dashboard, API and received-HLS access are localhost-only in 9.1.0-rc.2.
  LAN/remote access is postponed to a later version.
- Legacy pairing/remote routes fail closed and the remote launcher is not
  shipped in the rc.2 package.
- Port 8080 is never exposed automatically through UPnP.
- Automatic updating is disabled. No updater executable or installer is
  packaged; updates are manual, after a profile/download backup and with the
  rollback procedure in the release notes.
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
viewer, and the media path can still be direct. The 9.1.0 candidate therefore makes
no claim of strong anonymity, universal High ID, IPv6 support through every
ISP/router combination or traversal of every NAT.

## Network ports

| Service | Default | Protocol | Exposure |
|---|---:|---|---|
| eMule client | 4662 | TCP | Inbound P2P |
| eMule/Kad | 4672 | UDP | Kad and UDP transport |
| Native WebServer/API | 4711 | TCP | Loopback only in rc.2 |
| eSE dashboard | 8080 | TCP | Loopback only in rc.2; never auto-mapped |
| RTMP ingest | 1935 | TCP | Needed remotely only when OBS is on another PC |
| LAN discovery | 5354 | UDP multicast | TTL 1; local subnet only |

Do not forward ports 4711 or 8080: remote dashboard/API access is not part of
9.1.0-rc.2. Expose RTMP only when OBS intentionally runs on another PC.

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
  -ReleaseTag v0.70b-eSE9.1.0-rc.2 `
  -AllowDirty `
  -MaxCpuCount 1
```

`-AllowDirty` is a development override. Release artifacts must be built from a
clean tagged commit without that switch. The full pipeline runs preflight,
core tests, C++ and Node builds, integration tests, language builds,
pinned-input packaging, manifest verification and package smoke tests. The
candidate ZIP is identified by its recorded SHA-256; byte-for-byte
reproducibility is not claimed.

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
| [RC.2 release notes](docs/RELEASE_NOTES_v9.1.0-rc.2.md) | IPv6 fallback changes, qualification gates, safety limits and rollback |
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
- The portable runtime includes an embedded Node.js runtime, FFmpeg/ffprobe and
  hls.js 1.6.16.

Downstream distributors must preserve the GPL notices and the attributions in
[THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).
