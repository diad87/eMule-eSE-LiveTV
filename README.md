# 🐴 eMule eSE — Live TV Edition

> **eMule Streaming Engine (eSE)** — A heavily modified eMule 0.70b fork with P2P live streaming, a modern web dashboard, and zero-setup portable distribution.

---

## ⬇️ Download

### 📦 [Download eSE LiveTV v0.70b — Portable x64 (ZIP ~84 MB)](https://github.com/diad87/eMule-eSE-LiveTV/releases/download/v0.70b-eSE/eSE-LiveTV-x64-2026-05-03.zip)

> Also available on the [Releases](../../releases) page.

**How to run:** Extract the ZIP → double-click `eSE.vbs` → everything starts automatically:
- eMule client (minimized to tray)
- Node.js web server (embedded, no install needed)
- Browser opens to `http://localhost:8080`

No installer required. No dependencies. 100% portable.

---

## ✨ Key Features

### 🔴 Live TV over P2P
- **Broadcast & watch** live streams over the ed2k/Kad network
- RTMP ingest → HLS transcoding via bundled FFmpeg
- Kad-based stream discovery with multi-keyword publishing
- Per-stream HLS isolation, gap recovery, and mesh metrics

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

| Service | Port | Protocol |
|---------|------|----------|
| eMule TCP | 4662 | TCP |
| eMule UDP | 4672 | UDP |
| WebServer | 4711 | TCP |
| eSE Dashboard | 8080 | TCP |
| Live RTMP Ingest | 1935 | TCP |

---

## 📜 License

eMule is released under the **GNU General Public License v2**. See [license.txt](license.txt).

This fork includes the same licensing terms. All source code modifications are available in this repository.

---

## 🙏 Credits

- **eMule Project** — Original client (emule-project.net)
- **eSE modifications** — Live TV, web dashboard, security hardening, uTP streaming
- **Libraries**: CryptoPP, mbedTLS, miniupnpc, libutp, zlib, libpng, id3lib, CxImage
