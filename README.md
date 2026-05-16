# 🐴 eMule eSE — Live TV Edition

> **eMule Streaming Engine (eSE)** — A heavily modified eMule 0.70b fork
> that adds **P2P live streaming** over the eD2K + Kad network. No CDN,
> no central trackers, no operating cost beyond your own connection.

---

## 🆕 What's new in v0.70b-eSE7.0 (2026-05-17)

- **🔒 Anonymous broadcast links by default** — share without leaking your IP. The viewer resolves the broadcaster via Kad at click time; the URL string carries nothing identifiable.
- **🛰️ 100% decentralized discovery** — three independent layers (PEX gossip, mDNS LAN multicast, bootstrap cache). Sub-second on LAN, ~3 s on a warm mesh, <5 s cold-start with cache.
- **⚡ Adaptive bitrate (ABR)** with NVENC / QSV / AMF / x264 hardware encoder auto-detection + YouTube-style 3-chunk prebuffer.
- **🔄 Auto-update** — toast in the dashboard when a new GitHub release is published; one-click update via bundled PowerShell installer.
- **💥 Crash dump auto-prompt** — minidumps to `%APPDATA%\eMule\crashdumps\`, next-launch dialog offers to open the folder for issue reporting.
- **🔐 First formal security audit** + 2 medium XSS fixes in legacy inline pages.
- **🛠️ CI builds** (GitHub Actions) on every push/PR.

Full release notes: [docs/RELEASE_NOTES_v0.70b-eSE7.0.md](docs/RELEASE_NOTES_v0.70b-eSE7.0.md).
Diff vs upstream eMule 0.70b: [CHANGES_FROM_EMULE_0.70b.md](CHANGES_FROM_EMULE_0.70b.md).

---

## ⬇️ Download

### 📦 [Download eSE LiveTV v0.70b-eSE7.0 — Portable x64 (ZIP ~170 MB)](https://github.com/diad87/eMule-eSE-LiveTV/releases/download/v0.70b-eSE7.0/eSE-LiveTV-v0.70b-eSE7.0-2026-05-17-x64.zip)

> Also on the [Releases](../../releases) page — always pick **Latest**.

**How to run:**

1. Extract the ZIP anywhere (e.g. `C:\eSE\`)
2. Double-click `eSE.vbs` — eMule starts minimized to tray, the dashboard launches in the background, and your browser opens to `http://localhost:8080/live`.

Alternatively, double-click `emule.exe` directly: it auto-spawns `ese-server.exe` on startup, so the dashboard becomes available regardless. The `.vbs` only adds the convenience of auto-opening the browser.

No installer required. No external dependencies. 100% portable. Settings live under `%APPDATA%\eMule\`.

> For the full broadcast / watch / troubleshoot walkthrough see [docs/USER_GUIDE.md](docs/USER_GUIDE.md).

---

## ✨ Key features

### 🔴 P2P live TV
- **Broadcast & watch** live streams over the existing eD2K / Kad mesh
- RTMP ingest (port 1935) → FFmpeg HLS transcoding → eD2K chunk distribution
- Adaptive bitrate ladder: **360p / 540p / 720p / 1080p** with HW encoder
- YouTube-style 3-chunk prebuffer (~12 s) avoids the "live edge / black screen" failure mode
- Per-stream HLS isolation, gap recovery, Prometheus `/api/live/metrics`
- Stream browser at [`localhost:8080/live`](http://localhost:8080/live) with thumbnails, search, favorites, cinema player
- Cross-host broadcast verified end-to-end (PC1 → PC2 different ISPs, 2026-05-15)

### 🛰️ 100% decentralized discovery (no trackers, no servers)
Three independent P2P layers run in parallel:

1. **PEX gossip** piggy-backed in `OP_LIVE_HEARTBEAT` — every peer relays its top-5 recent streams. Viral propagation in `O(log N)` heartbeats.
2. **mDNS-style LAN multicast** on `224.0.0.251:5354` — sub-second discovery between peers on the same Wi-Fi/Ethernet. Works fully offline.
3. **Bootstrap cache** at `%APPDATA%\eMule\last_streams.json` — last 20 streams pinged at startup (~5 s) before Kad is ready.

No HTTPS trackers, no Cloudflare workers, no central service that can be taken down. See [docs/DECENTRALIZED_DISCOVERY.md](docs/DECENTRALIZED_DISCOVERY.md) for the design.

### 🔒 Privacy-by-default share links
- The link the broadcaster shares is `ed2k://|live|HEX||TITLE|/` — **no IP, no port** in the URL string
- Survives dynamic IP changes — the link doesn't bind to a specific address
- Viewer does a Kad lookup at click time to find the current broadcaster
- The classic direct link (with IP) is still available behind a collapsible toggle for LAN-only use cases

A future "relay-protected" mode (planned, single-hop) will hide the broadcaster's IP from Kad entirely. See [docs/ANONYMOUS_BROADCAST.md](docs/ANONYMOUS_BROADCAST.md).

### 🌐 Modern web dashboard
- Full-featured UI at `:8080` replacing the legacy Win32 interface (64 JS modules)
- Stream browser with cross-peer thumbnails fetched over HTTP
- Cinema player (HLS.js + multi-audio track picker)
- TMDB integration for movie posters & metadata
- First-run wizard with Kad / NAT / FFmpeg / public-IP checks + actionable tips
- Real-time `/api/live/metrics` Prometheus exposition for Grafana

### 🔐 Security hardening
- Localhost-only gate on `/api/live/*`, `/api/holepunch/*`, `/api/status`, `/dashboard`, `/hls/*`
- XSS fixes in legacy inline pages — broadcaster-controlled `title` / `category` / `quality` always HTML-escaped
- HLS chunk-path allowlist (no `..` / `/` / `\` permitted)
- Challenge-Response authentication (SHA-256 + CSPRNG nonces)
- Encrypted Kad hole-punch payloads (CryptoPP)
- Sybil defenses on Kad search results (viewer count clamped at 100k, bitrate rejected above 50 Mbps)
- Full audit: [docs/SECURITY_AUDIT.md](docs/SECURITY_AUDIT.md)

### ⚡ Network improvements
- **uTP / LEDBAT** streaming-optimized (300 ms target delay)
- NAT traversal with UDP hole-punching + 15 s keepalive
- NAT health telemetry exposed via `/api/live/diagnose`
- Multi-parent topology (≥3 active sources per viewer) with RTT-biased mesh fallback
- Tier classification (LEAF / MID / SUPER_SEEDER / MEGA_SEEDER) for ratio enforcement and fair upload sharing

### 🛡️ Code quality
- 80+ functional bugs remediated (P0–P3 audit)
- Thread-safe atomic counters throughout the new live subsystem
- Silent catch blocks eliminated with `LIVE_LOG` diagnostic logging
- Modern crypto (CryptoPP CSPRNG replacing `rand()` / `srand()` in security-critical paths)
- 16 modernization candidates documented for future work: [docs/MODERNIZATION.md](docs/MODERNIZATION.md)

---

## 📚 Documentation

| Doc | What's in it |
|---|---|
| [docs/USER_GUIDE.md](docs/USER_GUIDE.md) | Install, watch, broadcast workflow + troubleshooting |
| [docs/MASTER_PLAN.md](docs/MASTER_PLAN.md) | Architecture, sprint roadmap, scalability targets (2909 lines) |
| [docs/DECENTRALIZED_DISCOVERY.md](docs/DECENTRALIZED_DISCOVERY.md) | The 3-layer discovery design |
| [docs/ANONYMOUS_BROADCAST.md](docs/ANONYMOUS_BROADCAST.md) | Relay-protected broadcast spec (planned) |
| [docs/IPV6_ANALYSIS.md](docs/IPV6_ANALYSIS.md) | IPv6 dual-stack roadmap, threat model |
| [docs/SECURITY_AUDIT.md](docs/SECURITY_AUDIT.md) | First formal security review |
| [docs/MODERNIZATION.md](docs/MODERNIZATION.md) | 16 candidates for 2026 upgrades (id3lib → TagLib, IE → WebView2, etc.) |
| [docs/ACCEPTANCE_CHECKLIST.md](docs/ACCEPTANCE_CHECKLIST.md) | D4 / D5 hardware-required test matrices |
| [docs/DISTRIBUTION_ANALYSIS.md](docs/DISTRIBUTION_ANALYSIS.md) | Release pipeline inventory |
| [docs/RELEASE_NOTES_v0.70b-eSE7.0.md](docs/RELEASE_NOTES_v0.70b-eSE7.0.md) | This release's notes |
| [docs/PAPER_eSE_Live_EN.md](docs/PAPER_eSE_Live_EN.md) / [ES](docs/PAPER_eSE_Live_ES.md) | Academic paper (~6 k words each) |
| [CHANGES_FROM_EMULE_0.70b.md](CHANGES_FROM_EMULE_0.70b.md) | Full diff vs upstream eMule 0.70b (GPL §2(a) notice) |
| [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md) | Attribution for every bundled binary |

---

## 🏗️ Building from source

### Requirements
- **Visual Studio 2022** (Community or BuildTools) with `C++ Desktop development` + MFC / ATL workloads
- **Node.js 18+** (for `ese-server.exe` rebuild)
- **Windows 10 / 11 x64**
- For `v141_xp` language DLLs (optional): the `MSVC v141 - VS 2017 C++ x64/x86 build tools (v14.16)` individual component + the `Windows XP support for C++` component

### One-shot full build (recommended)
```powershell
.\tools\build_all.ps1
```
Builds `emule.exe` (Release|x64) + `ese-server.exe` (Node + pkg) + 43 language DLLs, then packages everything into a portable ZIP on your Desktop. ~15–20 min total.

Useful flags:
```powershell
.\tools\build_all.ps1 -Skip langs              # skip language DLLs (if v141_xp toolset missing)
.\tools\build_all.ps1 -Skip emule,langs        # reuse existing emule.exe, just rebuild Node + package
.\tools\build_all.ps1 -ReleaseTag v0.70b-eSE7.1  # override release tag in the ZIP filename + BUILD_INFO
.\tools\build_all.ps1 -DryRun                  # print the plan, don't execute
```

### Individual steps
```powershell
# Just emule.exe
msbuild srchybrid/emule.sln /p:Configuration=Release /p:Platform=x64 /m

# Just ese-server.exe (requires npm install first)
cd srchybrid/eSE
npm install
npm run build

# Just the portable ZIP (uses whatever's already built)
.\build_package.ps1
```

Output binary: `srchybrid/x64/Release/emule.exe` · Output ZIP: `Desktop/eSE-LiveTV-v{TAG}-{DATE}-x64.zip`.

---

## 📡 Network ports

| Service | Port | Protocol | Notes |
|---------|------|----------|-------|
| eMule TCP | 4662 | TCP | Inbound — opened via UPnP if available. |
| eMule UDP | 4672 | UDP | Kad / extended search. |
| WebServer | 4711 | TCP | Legacy eMule webserver + `/api/live/*` (localhost-only gate). |
| eSE Dashboard | 8080 | TCP | Modern Node.js UI (`/live`). |
| Live RTMP Ingest | 1935 | TCP | OBS / FFmpeg push target for broadcasters. |
| LAN Discovery | 5354 | UDP multicast (`224.0.0.251`) | mDNS-style announce, TTL=1 (subnet-only). Coexists with Bonjour on 5353. |

---

## 📜 License

eMule is released under the **GNU General Public License v2**. See [license.txt](license.txt).

This fork inherits the same licensing terms. All source modifications are public in this repository.

Third-party components bundled in the binary distribution (FFmpeg, Node.js, cloudflared, statically-linked native libraries, npm modules) are documented in [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md) — required reading for downstream redistributors.

---

## 🙏 Credits

- **eMule Project** — Original client ([emule-project.net](https://www.emule-project.net)). This is a fork of eMule **0.70b**.
- **eSE modifications** — P2P live streaming, decentralized 3-layer discovery, web dashboard, security hardening, uTP streaming, auto-update lifecycle.
- **Native libraries** — CryptoPP, mbedTLS, miniupnpc, libutp, zlib, libpng, id3lib, CxImage, ResizableLib.
- **Runtime** — Node.js (packaged via [pkg](https://github.com/vercel/pkg)), FFmpeg, cloudflared (optional HTTPS tunnel).

Full attribution: [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md). Detailed diff vs upstream: [CHANGES_FROM_EMULE_0.70b.md](CHANGES_FROM_EMULE_0.70b.md).
