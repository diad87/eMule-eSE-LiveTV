# eMule eSE LiveTV v0.70b-eSE7.0 — 2026-05-17

Major release. Discovery, security, lifecycle, distribution.

---

## Highlights

### P2P Live streaming — verified end-to-end (2026-05-15)
First working broadcast PC1 → PC2 with HLS reconstructed from eD2K
chunks playable in VLC. The complete pipeline (RTMP ingest → FFmpeg →
HLS chunking → eD2K mesh distribution → viewer reassembly) is now
production-grade.

### 100% decentralized discovery — three new layers
No trackers, no central service. Three independent layers find
streams in different scenarios:
- **PEX gossip** piggy-backed in `OP_LIVE_HEARTBEAT` (viral O(log N))
- **mDNS-style LAN multicast** on `224.0.0.251:5354` (sub-second on Wi-Fi/LAN)
- **Bootstrap cache** at `%APPDATA%\eMule\last_streams.json` (cold start in <5 s)

Cold-start time for a viewer dropped from 2-5 min to under 5 s in the
warm-cache + LAN case; warm-mesh first-discovery dropped from ~30 s to
~3 s via PEX. See [docs/DECENTRALIZED_DISCOVERY.md](docs/DECENTRALIZED_DISCOVERY.md).

### Adaptive Bitrate (ABR)
360p / 540p / 720p / 1080p variants produced automatically. Hardware
encoder auto-detected — NVENC, QSV, AMF, or x264 CPU. YouTube-style
3-chunk prebuffer (~12 s) eliminates the live-edge black-screen.

### Stream browser
Modern UI at `http://localhost:8080/live` with cross-peer thumbnails,
search, favorites, cinema player, and direct paste-link join.

### Security
First security audit ([docs/SECURITY_AUDIT.md](docs/SECURITY_AUDIT.md)) —
10 findings, 2 medium-severity XSS in the legacy C++ inline `/live`
pages fixed (broadcaster-controlled `title`/`category`/`quality` now
properly HTML-escaped). Localhost-only gate on `/api/live/*` verified.

### Lifecycle plumbing
- **Auto-update**: in-app toast when GitHub Releases publishes a newer
  version + one-click `tools/update_check.ps1` interactive updater.
  Never auto-installs silently.
- **Crash reports**: minidumps now write to `%APPDATA%\eMule\crashdumps\`
  by default. Next launch detects unread dumps and prompts the user
  to open the folder (so they can attach to a bug report).
- **Language auto-detect**: the 43 lang DLLs are now actually built
  by the release pipeline (they weren't in `emule.sln` — silent gap).
  Auto-detect widened to match by primary language so any Spanish
  locale picks up `es_AS.dll` / `es_ES_T.dll`. No more annoying
  "fell back to English" popup on every launch.

### CI
GitHub Actions workflow ([.github/workflows/build.yml](.github/workflows/build.yml))
builds emule.exe + ese-server.exe on every push/PR + uploads the
artifact bundle.

---

## Distribution

This is the first release built through `tools/build_all.ps1`, the
master pipeline that handles emule.exe + ese-server.exe + 43 language
DLLs + packaging in one command.

| Artifact | Size (approx.) | Contents |
|---|---|---|
| `eSE-LiveTV-v0.70b-eSE7.0-2026-05-17-x64.zip` | ~85 MB | emule.exe, ese-server.exe, ffmpeg essentials, node.exe, cloudflared.exe, 43 language DLLs, eMule.tmpl, server.met, nodes.dat, default preferences.ini, eSE.vbs launcher, tools/update_check.ps1, full docs |

To run: extract → double-click `eSE.vbs`. Browser opens automatically.

---

## What's NOT in this release

- **Inno Setup `.exe` installer** — only ZIP this time. Installer
  requires Inno Setup compiler; `installer/setup_ese.iss` is updated
  to 7.0 and ready for the next build that has the compiler.
- **Digital signature** — SmartScreen will show "publisher unknown"
  on first launch. Click "More info → Run anyway". Code-signing cert
  pending budget approval.
- **Cross-PC E2E acceptance test** — see [docs/ACCEPTANCE_CHECKLIST.md](docs/ACCEPTANCE_CHECKLIST.md)
  for the test matrix the user runs on their own hardware. The 2026-05-15
  smoke validated NVIDIA+NVENC; iGPU (QSV) and AMD (AMF) still pending.

---

## Upgrading from v6.x

Extract the new ZIP over the old install **with eMule + ese-server stopped**.
Your settings under `%APPDATA%\eMule\` are preserved. The first launch
will scan for the new lang DLL matching your OS locale; the legacy
"choose your language" wizard is no longer needed.

If you used the legacy C++ `/live` pages directly, you may want to
switch to `:8080/live` (the modern Node UI) which has been the
recommended path since v6.0 and is what `eSE.vbs` opens by default.

---

## Known issues

- Multi-instance same-host stress runs need `--tcp-port` + `--udp-port`
  + `--ignoreinstances` + the new `--headless` (which regenerates
  UserHash to avoid self-rejection). Cross-host is unaffected.
- Drops after very long broadcasts (>2 h) — peer churn isn't yet
  amortized; deferred to v7.1.
- The `gruk.org` server.met fetch in the build script uses HTTP
  rather than HTTPS. Pin to a known checksum, or replace the source,
  in v7.1.

---

## Credits

Built by [@diad87](https://github.com/diad87) with Claude Code.
Inherits eMule (eMule Project), FFmpeg, Node.js + npm ecosystem,
CryptoPP, mbedTLS, miniupnpc, libutp, zlib, libpng, id3lib, CxImage,
ResizableLib. See [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).

GPL-2.0-only.
