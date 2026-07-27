# eMule eSE architecture

eMule eSE extends eMule 0.70b with a native LiveTV subsystem and a local web
interface. The native client remains the authority for eD2K, Kad, peer state,
stream publication and P2P chunk transport.

## Runtime processes

```text
┌──────────────────────────────────────────────────────────────┐
│ emule.exe                                                    │
│ eD2K/Kad · LiveStreamManager · discovery · reachability      │
│ native API on 127.0.0.1:4711                                 │
└───────────────┬──────────────────────────────┬───────────────┘
                │ local HTTP                   │ process control
                ▼                              ▼
┌───────────────────────────────┐   ┌──────────────────────────┐
│ ese-server.exe                │   │ ffmpeg.exe               │
│ dashboard on 127.0.0.1:8080   │   │ ingest/transcode/HLS     │
└───────────────┬───────────────┘   └──────────────────────────┘
                │
                ▼
       browser or local HLS player
```

`ese-server.exe` presents the UI and proxies native operations. It does not
replace eMule's network state or maintain a second authoritative broadcaster.

## Broadcast flow

1. The user starts a broadcast through the native UI or dashboard.
2. `CLiveStreamManager` validates the source and prepares an isolated stream
   directory.
3. FFmpeg receives RTMP/OBS input, captures the screen, reads a media file or
   creates a test source.
4. Controlled sources must produce an HLS prebuffer before startup succeeds.
   RTMP can enter a waiting-for-input state while OBS connects.
5. The native client signs and publishes the stream record.
6. HLS chunks are read, validated and distributed to subscribed peers.
7. Stop, failure and stream-end paths remove publication state, terminate the
   owned FFmpeg process and clean stream-specific HLS files.

Hardware encoders are selected only after a functional probe. Failed NVENC,
QSV or AMF initialization falls back to CPU/x264 rather than reporting a false
successful broadcast.

## Viewer flow

1. A stream is found through Kad, PEX gossip, LAN multicast, a cached record or
   an `ed2k://|live|...|/` link.
2. The native client resolves candidate sources and selects a compatible
   connection path.
3. The viewer subscribes and receives signed HLS chunks.
4. Chunks are verified, deduplicated and written below the viewer's isolated
   local HLS directory.
5. The dashboard serves the reconstructed playlist from
   `/hls-local/<stream-key>/`.
6. If a source disappears, bounded replenishment rotates through known
   candidates without violating a strict tunnel-only privacy policy.

## Discovery

The discovery mechanisms complement one another:

- **Kad** stores and searches stream records.
- **PEX gossip** distributes recent announcements through connected peers.
- **LAN multicast** uses `224.0.0.251:5354` with TTL 1.
- **Local cache** retries recently seen streams during startup.

The release package carries a pinned and structurally verified `nodes.dat`.

## Protocol compatibility

eSE-owned opcodes, tags and capability bits are additive. A feature is sent
only when the peer advertises the matching capability; unknown extensions are
ignored by older clients.

The source of truth is:

- [`docs/protocol/OPCODES.csv`](docs/protocol/OPCODES.csv)
- [`docs/protocol/TAGS.csv`](docs/protocol/TAGS.csv)
- [`docs/protocol/CAPABILITIES.csv`](docs/protocol/CAPABILITIES.csv)
- [`docs/protocol/TUNNEL_SERVICES.csv`](docs/protocol/TUNNEL_SERVICES.csv)

`tools/check_protocol_registry.py` verifies ownership, namespace separation and
agreement with the C++ definitions.

## Reachability

Direct IPv4/IPv6 connections are preferred. When a direct path is unavailable,
the client can select a capability-gated reachability method. Experimental
punch3, port prediction, relay, KRP and Kad6 public-exit paths remain disabled
unless their individual preferences and safety conditions permit them.

NetLab consent controls participation in bounded interoperability
measurements. It is not a master switch for ordinary IPv6/Kad6 transport,
relay or bandwidth donation. In particular, toggling NetLab does not rewrite
the independent IPv6 Off/Auto/Preferred choice.

## Privacy boundaries

An endpoint-free LiveTV link omits the IP address and port, but discovery and
media transfer can still reveal endpoints to peers.

The 8.1 control tunnel can proxy search and subscription through an exit. The
production topology uses one relay hop, so the exit can identify the viewer;
the data path may remain direct. The beta does not claim strong anonymity.

## Local HTTP boundaries

| Port | Owner | Purpose |
|---:|---|---|
| 4711 | `emule.exe` | Native status and control API |
| 8080 | `ese-server.exe` | Dashboard, player and local HLS |
| 1935 | FFmpeg/native orchestration | RTMP ingest |

For 9.1.0-rc.2 the API, dashboard and received-HLS HTTP surfaces bind to
loopback only. LAN/remote dashboard access is deliberately postponed and is
not a supported configuration for this candidate. The dashboard is never
exposed with UPnP; legacy pairing/remote routes return `410` and the remote
launcher is excluded from the package.

Automatic updating is disabled in the release runtime. No updater executable
or installer is packaged or invoked. The compatibility module is inert,
performs no network/process action and returns `410` from its update routes. An
update is a manual replacement of the application directory after backing up
the active profile and download state; rollback restores that snapshot and the
previous application directory.

## Source layout

| Path | Responsibility |
|---|---|
| `srchybrid/LiveStreamManager.*` | Broadcast/viewer lifecycle and native API state |
| `srchybrid/LiveMeshManager.*` | Live peer topology and chunk requests |
| `srchybrid/LiveTunnel.*` | Tunnel framing and control/data services |
| `srchybrid/KadKeepalive.*` | Kad/firewall reachability maintenance |
| `srchybrid/FirewallProberV6.*` | IPv6 reachability probing |
| `srchybrid/eMuleAI/` | Address and uTP integration |
| `srchybrid/eSE/` | Dashboard server, routes and browser assets |
| `libreach/` | Reachability selection logic |
| `libnatmap/` | Port-mapping protocols and lifecycle |
| `libkad6/` | Experimental Kad6 library |
| `librelaycore/`, `librelayclient/`, `relayedge/` | Gated relay components |
| `docs/protocol/` | Wire registry |
| `tools/` | Build, verification and release tooling |

## Concurrency and cleanup

The MFC application owns network objects and GUI-thread state. Worker paths
communicate through bounded queues or explicit synchronization; web requests
that touch GUI-owned objects are marshalled to the owning thread.

Long-running work such as part hashing, FFmpeg prebuffering and dashboard I/O
must not block the UI thread. Shutdown paths stop workers, release sockets and
processes, and remove transient HLS data.

## Release layout

`tools/build_all.ps1` builds and tests the native client, dashboard executable
and language DLLs. `build_package.ps1` then creates:

```text
dist\<release-tag>\
├── package\
│   ├── emule.exe
│   ├── ese-server.exe
│   ├── ffmpeg.exe
│   ├── ffprobe.exe
│   ├── BUILD_INFO.txt
│   └── SHA256SUMS.txt
├── eSE-LiveTV-<release-tag>-x64.zip
└── eSE-LiveTV-<release-tag>-x64.zip.sha256
```

Packaging verifies pinned inputs, records exact build provenance and checks
the per-file manifest plus the external ZIP checksum. The ZIP is frozen and
identified by its SHA-256; byte-for-byte reproducibility is not claimed.
