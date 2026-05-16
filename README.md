# 🐴 eMule eSE — Live TV Edition

> **eMule Streaming Engine (eSE)** — A heavily modified eMule 0.70b fork with P2P live streaming, a modern web dashboard, and zero-setup portable distribution.

---

## ⬇️ Download

### 📦 [Download eSE LiveTV v0.70b-eSE7.0 — Portable x64 (ZIP ~170 MB)](https://github.com/diad87/eMule-eSE-LiveTV/releases/download/v0.70b-eSE7.0/eSE-LiveTV-v0.70b-eSE7.0-2026-05-17-x64.zip)

> Also available on the [Releases](../../releases) page — always pick **Latest**.

**How to run:** Extract the ZIP → double-click `eSE.vbs` → everything starts automatically:
- eMule client (minimized to tray)
- `ese-server.exe` (embedded Node.js dashboard, no install needed)
- Browser opens to `http://localhost:8080`

No installer required. No dependencies. 100% portable.

> For the full broadcast / watch workflow see [docs/USER_GUIDE.md](docs/USER_GUIDE.md).

---

## ✨ Key Features

### 🔴 Live TV over P2P
- **Broadcast & watch** live streams over the ed2k/Kad network
- RTMP ingest (port 1935) → HLS transcoding via bundled FFmpeg
- **Adaptive bitrate (ABR)** — 360p/540p/720p/1080p variants, hardware-accelerated when an NVENC / QSV / AMF encoder is detected
- **YouTube-style prebuffer** — 3 chunks (~12 s) cached before the stream returns to the viewer to avoid the "live edge / black screen" failure mode
- Per-stream HLS isolation, gap recovery, mesh metrics, Prometheus `/api/live/metrics`
- Stream browser at <http://localhost:8080/live> with thumbnails, search, favorites, cinema player

### 🛰️ 100% Decentralized Discovery (no trackers, no servers)
Three independent discovery layers, all P2P:
1. **PEX gossip** piggy-backed in `OP_LIVE_HEARTBEAT` — every peer relays its top-5 recent streams to its neighbors. Viral propagation in `O(log N)` heartbeats.
2. **mDNS-style LAN multicast** on `224.0.0.251:5354` — instant (<1 s) discovery between peers on the same Wi-Fi/Ethernet. Works fully offline.
3. **Bootstrap cache** at `%APPDATA%\eMule\last_streams.json` — last 20 streams pinged directly at startup (~5 s) before Kad is ready.

No HTTPS trackers, no Cloudflare workers, no central service that can be taken down. See [docs/DECENTRALIZED_DISCOVERY.md](docs/DECENTRALIZED_DISCOVERY.md) for the design.

### 🌐 Modern Web Dashboard
- Full-featured web UI at `localhost:8080` replacing the legacy Win32 interface
- TMDB integration for movie posters, search, and metadata
- Cinema player with streaming capabilities
- Real-time download/upload monitoring

### 🔒 Security Hardening
- Challenge-Response authentication (SHA-256 + CSPRNG nonces)
- XSS remediation across all web components (SafeDOM)
- SSRF prevention, path traversal protection, input sanitization
- Encrypted Kad hole-punch payloads (CryptoPP)

### ⚡ Network Improvements
- **uTP/LEDBAT** streaming-optimized (300ms target delay)
- NAT traversal with hole-punching and 15s keepalive
- NAT health telemetry and diagnostic dashboard
- Sybil attack mitigation for Kad discovery

### 🛡️ Code Quality
- 80+ bugs remediated (P0-P3 functional audit)
- Thread-safe atomic counters throughout
- Silent catch blocks eliminated with diagnostic logging
- Modernized crypto (CryptoPP replacing rand()/srand())

---

## 🏗️ Building from Source

### Requirements
- **Visual Studio 2022** with C++ Desktop, MFC/ATL workloads
- **Windows 10/11 x64**

### Build
```powershell
# Open Developer Command Prompt or use MSBuild directly
msbuild srchybrid/emule.sln /p:Configuration=Release /p:Platform=x64
```

The output binary will be at `srchybrid/x64/Release/emule.exe`.

### Package (portable ZIP)
```powershell
.\build_package.ps1
```

---

## 📡 Network Ports

| Service | Port | Protocol | Notes |
|---------|------|----------|-------|
| eMule TCP | 4662 | TCP | Inbound — opened via UPnP if available. |
| eMule UDP | 4672 | UDP | Kad / extended search. |
| WebServer | 4711 | TCP | Legacy eMule webserver + `/api/live/*`. |
| eSE Dashboard | 8080 | TCP | Modern Node.js UI (`/live`). |
| Live RTMP Ingest | 1935 | TCP | OBS / FFmpeg push target for broadcasters. |
| LAN Discovery | 5354 | UDP multicast (`224.0.0.251`) | Local mDNS-style announce, TTL=1 (subnet-only). Coexists with Bonjour on 5353. |

---

## 📜 License

eMule is released under the **GNU General Public License v2**. See [license.txt](license.txt).

This fork inherits the same licensing terms. All source modifications are public in this repository.

Third-party components bundled in the binary distribution (FFmpeg, Node.js, cloudflared, statically-linked native libraries, npm modules) are documented in [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md) — required reading for downstream redistributors.

---

## 🙏 Credits

- **eMule Project** — Original client ([emule-project.net](https://www.emule-project.net)). This is a fork of eMule **0.70b** — see [CHANGES_FROM_EMULE_0.70b.md](CHANGES_FROM_EMULE_0.70b.md) for the full diff vs upstream.
- **eSE modifications** — Live TV (RTMP→HLS→eD2K), web dashboard, decentralized discovery (PEX + mDNS + bootstrap cache), security hardening, uTP streaming
- **Native libraries** — CryptoPP, mbedTLS, miniupnpc, libutp, zlib, libpng, id3lib, CxImage, ResizableLib
- **Runtime** — Node.js (via [pkg](https://github.com/vercel/pkg)), FFmpeg, cloudflared (optional)

Full license attribution: [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).
