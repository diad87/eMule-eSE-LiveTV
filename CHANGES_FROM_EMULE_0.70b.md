# Changes from upstream eMule 0.70b

This is a **fork** of [eMule 0.70b](https://www.emule-project.net/)
released by the eMule Project on 2022-12-19. The upstream client is
**unchanged in its core eD2K + Kad functionality** — every existing
peer keeps working with us and we keep working with them.

What we added on top is documented below in detail. Files we
**modified in place** carry inline notice comments per **GPL-2 §2(a)**;
files marked "new" are 100% original work under the same license.

Counts you can verify: **72 commits**, **20 new C++ source files**
(`srchybrid/Live*.{h,cpp}`, `RTMPIngest.*`), **64 new Node.js files**
(`srchybrid/eSE/`), **8 planning docs** (~6,500 lines of design /
sprint catalogs), **43 language DLLs** built (upstream `.sln` had 0).

> If you want to bisect "is this an upstream behavior or a fork
> change?" — anything not on this list is upstream.

---

## Table of contents

- [At a glance](#at-a-glance)
- [A. Live streaming engine (C++)](#a-live-streaming-engine-c)
- [B. Mesh topology + transport](#b-mesh-topology--transport)
- [C. Encoding / quality / playback](#c-encoding--quality--playback)
- [D. Stream discovery (3 decentralized layers + hardening)](#d-stream-discovery)
- [E. Stream browser + cinema UI](#e-stream-browser--cinema-ui)
- [F. Modern web dashboard (Node.js, `:8080`)](#f-modern-web-dashboard)
- [G. C++ WebServer endpoints (`:4711/api/*`)](#g-c-webserver-endpoints)
- [H. Security hardening](#h-security-hardening)
- [I. Lifecycle + operability](#i-lifecycle--operability)
- [J. CLI flags + multi-instance support](#j-cli-flags--multi-instance-support)
- [K. Internationalization](#k-internationalization)
- [L. Build + distribution pipeline](#l-build--distribution-pipeline)
- [M. New documentation](#m-new-documentation)
- [N. Notable bug fixes](#n-notable-bug-fixes)
- [What we DID NOT change in upstream](#what-we-did-not-change-in-upstream)

---

## At a glance

| Area | Upstream 0.70b | This fork (eSE 7.0) |
|---|---|---|
| eD2K file sharing | ✓ | ✓ unchanged |
| Kad DHT | ✓ | ✓ extended (new opcodes for live, backward compat) |
| MFC desktop UI | ✓ | ✓ + "Live" tab + headless mode |
| WebServer (`:4711`) | ✓ basic stats | ✓ + 25+ new endpoints + Prometheus metrics |
| **P2P live streaming** | — | ✓ entire new subsystem (20 C++ files) |
| **Modern web dashboard (`:8080`)** | — | ✓ Node.js + browser UI (64 JS files) |
| **Decentralized stream discovery** | — | ✓ 3 layers (PEX / mDNS / bootstrap cache) |
| **Adaptive bitrate (ABR)** | — | ✓ 360p/540p/720p/1080p + HW encoder auto-detect |
| **uTP / LEDBAT** | — | ✓ for streaming flows |
| **Auto-update + crash dump UX** | — | ✓ |
| **CI builds** | — | ✓ GitHub Actions |
| Bundled FFmpeg / Node / cloudflared | — | ✓ in portable ZIP |
| Language DLLs built by default | 0 in `.sln` | ✓ all 43 |
| Cross-PC live broadcast verified | n/a | ✓ 2026-05-15 (PC1→PC2, VLC plays HLS reconstructed from eD2K chunks) |

Legend used below: **✓** done & shipped · **◷** planned/researched
but not yet code · **✗** explicitly skipped (with reason)

---

## A. Live streaming engine (C++)

20 new files. The whole subsystem; nothing exists upstream.

### New files (`srchybrid/`)
- ✓ `LiveStreamManager.{h,cpp}` — broadcaster + viewer state machine, per-peer counters, ratio enforcement, tier classification
- ✓ `LiveKadBridge.{h,cpp}` — publish / search live keys in Kad with throttle, tombstones, dedupe
- ✓ `LivePackets.{h,cpp}` — wire format for new opcodes
- ✓ `LiveProtocol.{h,cpp}` — eD2K opcode dispatch for live extensions
- ✓ `LiveMeshManager.{h,cpp}` — tree topology with multi-parent + RTT-biased mesh fallback
- ✓ `LiveChunkBuffer.{h,cpp}` — sliding window of HLS chunks per stream
- ✓ `LiveStreamDlg.{h,cpp}`, `LiveStreamDlgUI.cpp`, `LiveStreamHandlers.cpp` — MFC "Live" tab
- ✓ `LiveDebugLog.{h,cpp}` — `LIVE_LOG(category, ...)` ring buffer + `/api/live/log` endpoint
- ✓ `RTMPIngest.{h,cpp}` — RTMP listener on port 1935 + FFmpeg pipeline orchestration

### New eD2K wire opcodes (live extension, behind capability flag)
- ✓ `OP_LIVE_HEARTBEAT` — periodic peer state; extended to carry PEX gossip of top-5 streams (22→23-133 bytes, backward compat)
- ✓ `OP_LIVE_CHUNK_REQUEST` / `OP_LIVE_CHUNK_RESPONSE`
- ✓ `OP_LIVE_PING` (`0xE7`) / `OP_LIVE_PONG` (`0xE8`) — RTT measurement
- ✓ New Kad keywords: `live:HEXKEY`, `livehash:HEXKEY` (secondary sources), `livehelp:HEXKEY` (anycast capacity)
- ◷ `livename:ALIAS` (DNS-like aliases, Capa 4 from `DECENTRALIZED_DISCOVERY.md`)

Backward compat: peers without the live capability bit see only the
classic eD2K traffic. Live opcodes are silently ignored by upstream
clients.

### V2 sprints S01–S22 (observability → tier → tree topology)
All ✓ DONE (commits `ac59bc4` through `d054d63`):

- **S01** Per-peer counters: bytes_in/out, RTT_EWMA, last_chunk timestamps
- **S02** 60-second sliding window for ratio calculation
- **S03** RTT measurement via PING/PONG opcodes (5s interval)
- **S04** `/api/live/metrics` Prometheus endpoint
- **S05** Chunk arrival latency histogram (p50/p95/p99) via `LatencyHistogram` class
- **S11** Bandwidth probe at startup (`MeasureUploadCapacity`)
- **S12** Auto-tier classification: `LEAF_RESTRICTED` / `LEAF` / `MID` / `SUPER_SEEDER` / `MEGA_SEEDER`
- **S13** Max concurrent uploads per tier (0 / 1 / 3 / 10 / 25)
- **S14** Ratio enforcement gradient throttle (drop 1/5 @ 0.4-0.7, drop 4/5 @ <0.4)
- **S15** Bootstrap grace for first 5 viewers (no throttle until >5)
- **S16** Broadcaster caps direct viewers at 10 (forces tree topology)
- **S17** Viewer publishes as secondary source to Kad (`livehash:`) when buffer >5
- **S18** Viewer prefers connecting to other viewers before broadcaster
- **S19** Multi-parent: maintain ≥3 active sources (1 primary + 2 warm spares)
- **S20** Mesh fallback for missing chunks (select peer by RTT bitmap query)
- **S21** Proactive push: relay sends chunks to children when received (no req/res)
- **S22** Anycast spare-capacity: orphan peer searches `livehelp:` keyword
- **S24** miniupnpc at startup for NAT-PMP/PCP port mapping (logged in `/api/live/log`)

### V2 sprints still planned
- ◷ **S23** IPv6 awareness (full AAAA support — currently IPv4 only)
- ◷ **S25** Birthday-paradox UDP hole-punching (multiple sockets, 1024 probes)
- ◷ **S26** STUN NAT classification (full-cone / restricted / port-restricted / symmetric)

### V3 / V4 sprints — designed but not in this release
See `docs/SPRINTS_V3.md` (948 lines) and `docs/SPRINTS_V4.md` (383 lines).
Major designed work: libsrt transport (S01-S05), RLNC FEC (S06-S09),
packet-level forwarding (S10-S13), WebRTC bridge, E2EE per-chunk
(AES-256-GCM), HyParView gossip, SVC encoding, super-relays.

---

## B. Mesh topology + transport

- ✓ Tree topology with broadcaster cap (10 direct viewers) → V2-S16
- ✓ Multi-parent (≥3 sources) → V2-S19
- ✓ Mesh fallback via peer bitmaps → V2-S20
- ✓ Proactive chunk push to children → V2-S21
- ✓ Anycast orphan recovery via `livehelp:` Kad keyword → V2-S22
- ✓ Stress test simulator (multi-instance orchestrator + Chart.js dashboard + sweep N=10/50/100) → V2-S06..S10
- ✓ uTP / LEDBAT integration for streaming flows
- ✓ Encrypted Kad hole-punch payloads (CryptoPP, 15s keepalive)
- ◷ packet-level forwarding (V3-S10..S13)
- ◷ Adaptive FEC (V3-S13, 1.1-2.0× based on observed loss)

---

## C. Encoding / quality / playback

- ✓ **RTMP ingest listener** on port 1935 ([RTMPIngest.cpp](srchybrid/RTMPIngest.cpp))
- ✓ **FFmpeg pipeline** with auto-detection of `ffmpeg.exe` in 5 known paths
- ✓ **ABR (Adaptive Bitrate)** with 360p / 540p / 720p / 1080p variants (commit `1f0a1d2`)
- ✓ **Hardware encoder auto-detection**: NVENC → QSV → AMF → x264 CPU fallback ([hw_encoder.js](srchybrid/eSE/hw_encoder.js))
- ✓ **YouTube-style prebuffer** — 3 chunks (~12 s) before broadcast/start returns, avoids live-edge black screen
- ✓ **Multi-audio HLS** — multiple audio tracks (e.g. dub language) with viewer track picker
- ✓ **Segment-name watcher** rejects audio-variant segments masquerading as video (commit `b54365e`, MKV regression fix)
- ✓ **Per-hash thumbnail extraction** every 20 s, JPG cached in `%APPDATA%\eSE\thumbs\` ([thumbnail_extractor.js](srchybrid/eSE/eSE-live/thumbnail_extractor.js))
- ✓ **Independent-segments flag** + `-g 48` keyframe alignment to fix audio-cuts-after-3.4s

---

## D. Stream discovery

Three independent layers, all 100% decentralized — no trackers,
no central service. See [docs/DECENTRALIZED_DISCOVERY.md](docs/DECENTRALIZED_DISCOVERY.md).

### Capa 1 — PEX gossip (commit `1421cf4`)
- ✓ Top-5 recently-seen streams piggy-backed in `OP_LIVE_HEARTBEAT`
- ✓ Wire extension 22 → 23-133 bytes (backward compat with upstream)
- ✓ `OnPexEntry()` routes via `OnKadSearchResult()` — reuses all existing throttle/dedupe/IsGoodIP/etc
- ✓ Viral propagation in O(log N) heartbeats

### Capa 2 — mDNS-style LAN multicast (commit `9c1adfe`)
- ✓ UDP multicast on `224.0.0.251:5354` (non-conflicting with Bonjour on 5353)
- ✓ Plain-text `eSE-LAN/1.0` announce every 30 s, TTL=1 (subnet only)
- ✓ Listener filters own-IP, enqueues via `direct_join`
- ✓ Sub-second discovery between peers on the same Wi-Fi / LAN
- ✓ Works fully offline (no internet, no Kad)

### Capa 3 — Bootstrap cache (commit `bd0f06c`)
- ✓ Last 20 streams cached in `%APPDATA%\eMule\last_streams.json` (JSONL)
- ✓ Persists after first chunk received
- ✓ Bootstrap ping 5 s after startup, before Kad is ready
- ✓ Cold-start with cached favorites: 2-5 min → <5 s

### Capa 4 — DHT aliases
- ◷ Designed in [DECENTRALIZED_DISCOVERY.md](docs/DECENTRALIZED_DISCOVERY.md) §4 — `livename:torrente` → streamKey. Not implemented this release.

### DISC sprints (discovery hardening)
All ✓ DONE in commits `2a00f26`, `024880c`, `f2efda8`, `bda99fd`:

- **DISC-S01** Graceful unpublish on exit (atexit + signal handler) — `TAG_ESE_LIVE_BYE`
- **DISC-S02** Heartbeat freshness via direct UDP ping (90s stale, TTL→120s)
- **DISC-S03** Re-publish retry after late Kad connect (handles `m_bPublishRequested` flag)
- **DISC-S04** Persistent streamKey in prefs + ghost cleanup at startup
- **DISC-S05** Periodic search retry in `JoinStream` (15s interval, max 10) when viewer pool empty
- **DISC-S06** Throttle auto-dial in `OnKadSearchResult` (3/sec max, FIFO drop at 50)
- **DISC-S07** Hard cap on viewer peers at 8 (`MAX_VIEW_PEERS` constant)
- **DISC-S08** Global rate limit on `SearchStreams` (10/min token bucket + per-keyword 30s cooldown)
- **DISC-S09** Link-parser error logging — `LIVE_LOG("[LINK]")` with failure reason
- **DISC-S10** `/api/live/diagnose` endpoint — exports streamDirectory, Kad status, UPnP, IPFilter
- **DISC-S11** Kad-search metrics (latency, results count, empty searches) in `/api/live/metrics`
- **DISC-S12** Time-to-first-chunk histogram (p50/p95/p99) — `esmule_join_to_first_chunk_ms`
- **DISC-S14** Sanity-clamp Kad result `viewerCount` (max 100k) + reject bogus bitrate (>50 Mbps) — Sybil defense
- **DISC-S15** Distinguish broadcaster vs relay in wire (`TAG_ESE_LIVE_ROLE` 0/1)
- ◷ **DISC-S13** "Discovery health" dashboard panel (UI side; deferred — `/api/live/diagnose` covers the data)

---

## E. Stream browser + cinema UI

Full Node-side UI at `http://localhost:8080/live`. See
[STREAM_BROWSER_PLAN.md](docs/STREAM_BROWSER_PLAN.md).

- ✓ **BROWSE-S01** Cross-peer thumbnail fetch (commit `5e164b2`) — `http://{broadcasterIP}:8080/live/thumb/{hash}.jpg` for remote, relative URL for local
- ✓ **BROWSE-S03** ese-server.exe rebuild pipeline (commit `1dced79`) — npm + pkg auto-trigger when JS changes
- ✓ **BROWSE-S05** Search debounce 250 ms + global refresh throttle 10 s (commit `5e164b2`)
- ✓ Grid with filters (search, category, language, sort) — [live_tv_directory.js](srchybrid/eSE/eSE-live/live_tv_directory.js)
- ✓ Cinema player with HLS.js, multi-audio track picker, autoplay — [cinema_player.js](srchybrid/eSE/cinema_player.js)
- ✓ Favorites persisted in `%APPDATA%\eSE\favorites.json` — [favorites_manager.js](srchybrid/eSE/eSE-live/favorites_manager.js)
- ✓ Channel rating widget — [channel_rating.js](srchybrid/eSE/eSE-live/channel_rating.js)
- ✓ Channel search — [channel_search.js](srchybrid/eSE/eSE-live/channel_search.js)
- ✓ Direct-paste-link join (handles `ed2k://|live|HEX|IP:PORT|TITLE|/` + anonymous variant)
- ✗ **BROWSE-S02** MFC native Discover tab — skipped, duplicated `/live`
- ✗ **BROWSE-S04** Trending ranking — skipped, snapshot-sort-by-viewers sufficient for v2

---

## F. Modern web dashboard

64 source files under [srchybrid/eSE/](srchybrid/eSE/) outside `node_modules`. None of this exists upstream. Packaged as `ese-server.exe` via [`pkg`](https://github.com/vercel/pkg).

### Architecture
- ✓ Auto-spawned by `emule.exe` at startup ([EmuleDlg.cpp:687](srchybrid/EmuleDlg.cpp:687)) — dashboard available immediately
- ✓ `runtime_dir.js` helper for pkg-mode writable paths (`%APPDATA%\eSE` outside snapshot)
- ✓ Debug log capture (hooks `console.*`) with `/api/live/log` API
- ✓ Hardware encoder detection module ([hw_encoder.js](srchybrid/eSE/hw_encoder.js))

### Pages
- ✓ `/` — main UI, hero, library, recently watched
- ✓ `/live` — live TV directory
- ✓ `/live/cinema?key=HASH` — cinema player
- ✓ `/connect`, `/explore`, `/search`, `/mylist` — feature pages
- ✓ `/dashboard` — operations view
- ✓ `/live-debug` — internal diagnostics page

### Features
- ✓ TMDB integration for movie posters / metadata ([tmdb_api.js](srchybrid/eSE/tmdb_api.js))
- ✓ Cinema player with hero, poster, smart-play ([cinema_player.js](srchybrid/eSE/cinema_player.js), [poster_hero.js](srchybrid/eSE/poster_hero.js), [smart_play.js](srchybrid/eSE/smart_play.js))
- ✓ MSE-based playback engine ([mse_engine.js](srchybrid/eSE/mse_engine.js))
- ✓ AI assistant skeleton + OAuth flow ([ai_assistant.js](srchybrid/eSE/ai_assistant.js), [ai_oauth.js](srchybrid/eSE/ai_oauth.js))
- ✓ TMDB / API key configuration ([api_keys.js](srchybrid/eSE/api_keys.js))
- ✓ Cloudflare tunnel optional (HTTPS public URL) ([cloudflare_tunnel.js](srchybrid/eSE/eSE-live/cloudflare_tunnel.js), [tunnel.js](srchybrid/eSE/tunnel.js))
- ✓ WebSocket tunnel for legacy compat ([ws_tunnel.js](srchybrid/eSE/eSE-live/ws_tunnel.js))
- ✓ First-run wizard with Kad / NAT / FFmpeg / public-IP checks + actionable tips ([live_tv_page.js:537](srchybrid/eSE/eSE-live/live_tv_page.js:537))
- ✓ Update-available toast polling `/api/live/update_status` every 60s ([live_tv_page.js:687](srchybrid/eSE/eSE-live/live_tv_page.js:687))
- ✓ SafeDOM helper for XSS-resistant innerHTML ([shared/safe_dom.js](srchybrid/eSE/shared/safe_dom.js))
- ✓ Device scanner (LAN UPnP) ([device_scanner.js](srchybrid/eSE/eSE-live/device_scanner.js))
- ✓ Source selector (camera / screen / file / RTMP) ([source_selector.js](srchybrid/eSE/eSE-live/source_selector.js))
- ✓ RTMP relay (Node-side) ([rtmp_server.js](srchybrid/eSE/eSE-live/rtmp_server.js))
- ✓ FFmpeg pipeline orchestration (Node-side mirror) ([ffmpeg_pipeline.js](srchybrid/eSE/eSE-live/ffmpeg_pipeline.js))

---

## G. C++ WebServer endpoints

Added to [WebServer.cpp](srchybrid/WebServer.cpp). Every endpoint
listed is new; upstream WebServer only had basic stats.

### Live API
- ✓ `GET /api/live/join?key=HEX&title=...` — start P2P viewing for a stream
- ✓ `GET /api/live/broadcast/start?source=...&title=...&bitrate=...&file=...` — start a broadcast (web-driven, no MFC click needed)
- ✓ `GET /api/live/broadcast/stop` — stop broadcast + Kad unpublish + tombstone
- ✓ `GET /api/live/preflight` — read-only health (Kad status, public IP, port, ffmpeg, NAT)
- ✓ `GET /api/live/metrics` — **Prometheus exposition** (chunks, peers, latency histograms)
- ✓ `GET /api/live/log[?n=N]` — tail of LIVE_LOG ring buffer (JSON)
- ✓ `GET /api/live/diagnose?key=HEX` — self-diagnostic (Kad / PEX / LAN / bootstrap status per layer)
- ✓ `GET /api/live/direct_join?link=ed2k://... | ?key=HEX&ip=...&port=...&title=...` — bypass Kad, dial directly
- ✓ `GET /api/live/channels` — JSON list of active streams (Kad + local + PEX + LAN, with thumbnail URLs)
- ✓ `GET /api/live/mesh` — core P2P mesh stats for Node bridge
- ✓ `GET /api/live/kad/streams` — Kad-discovered live stream directory
- ✓ `GET /api/live/debug` — phase-0 observability (peer counters, chunk buffer state)
- ✓ `GET /api/live/{hash}/stream.m3u8` — dynamic HLS playlist
- ✓ `GET /api/live/{hash}/seg_NNNNN.ts` — segment binary data
- ✓ `GET /live` — legacy inline page (kept for compat, XSS-fixed)
- ✓ `GET /live/{hash}` — legacy inline player page (XSS-fixed)

### Status / NAT API
- ✓ `GET /api/status` — overall network health (UPnP, Kad, ed2k, hole-punch counters)
- ✓ `GET /api/holepunch/*` — NAT traversal diagnostics

### Security gate
- ✓ All `/api/live/*`, `/api/holepunch/*`, `/api/status`, `/dashboard`, `/hls/*` are **127.0.0.1-only** ([WebServer.cpp:4486](srchybrid/WebServer.cpp:4486)). Remote requests get HTTP 403 + `LIVE_LOG("SEC", ...)`.

---

## H. Security hardening

Documented in [docs/SECURITY_AUDIT.md](docs/SECURITY_AUDIT.md). Summary:

- ✓ **Localhost-only gate** for `/api/live/*`, `/api/holepunch/*`, `/api/status`, `/dashboard`, `/hls/*` ([WebServer.cpp:4486](srchybrid/WebServer.cpp:4486))
- ✓ **XSS fix** in legacy C++ `/live` page — `esc()` helper for broadcaster-controlled `title`/`category`/`quality`/`viewers` ([WebServer.cpp:5736](srchybrid/WebServer.cpp:5736))
- ✓ **XSS fix** in legacy C++ `/live/{hash}` player page — same `esc()` helper for `ch.title` ([WebServer.cpp:5843](srchybrid/WebServer.cpp:5843))
- ✓ **`EseIsSafeHlsResourceA`** allowlist for HLS chunk paths ([WebServer.cpp:4417](srchybrid/WebServer.cpp:4417)) — rejects `..`, `/`, `\`, `[a-zA-Z0-9_.\-]` only, requires `stream.m3u8` / `stream_*.m3u8` / `seg_*.ts` pattern
- ✓ **`EseIsHexA`** strict 32-char hex check for streamKey before any FS / URL use
- ✓ **CORS explicit origin** `Access-Control-Allow-Origin: http://127.0.0.1` (not wildcard) on every JSON response
- ✓ **Strict streamKey allowlist** `[a-zA-Z0-9_-]` in [live_tv_player.js:125](srchybrid/eSE/eSE-live/live_tv_player.js:125) before URL injection
- ✓ **SafeDOM helper** for the Node UI ([shared/safe_dom.js](srchybrid/eSE/shared/safe_dom.js))
- ✓ **`escH()` helper** consistently used in [live_tv_directory.js:190](srchybrid/eSE/eSE-live/live_tv_directory.js:190), [live_tv_player.js:103](srchybrid/eSE/eSE-live/live_tv_player.js:103)
- ✓ **Challenge-Response auth** (SHA-256 + CSPRNG nonces) for sensitive flows
- ✓ **CryptoPP CSPRNG** replacing `rand()`/`srand()` in security-critical paths (per README)
- ✓ **Encrypted Kad hole-punch payloads** (CryptoPP, 15s keepalive)
- ✓ **DISC-S14 Sybil defense** — clamp `viewerCount` ≤ 100k, reject `bitrate` > 50 Mbps
- ✓ **`SECURITY_AUDIT.md`** — first formal audit (10 findings, 2 medium XSS fixed, 8 verified mitigated)
- ◷ Endpoint coverage audit with fuzz testing — not yet
- ◷ Tor/I2P fallback — designed in V4, deferred

---

## I. Lifecycle + operability

Items D1–D10 from the user-led roadmap (2026-05-16):

- ✓ **D1** [README.md](README.md) substantially rewritten for end users + [docs/USER_GUIDE.md](docs/USER_GUIDE.md) (install, watch, broadcast, ports, CLI flags, troubleshooting)
- ✓ **D2** Portable ZIP distribution via [build_package.ps1](build_package.ps1) — bundles emule.exe + ese-server.exe + ffmpeg + node + cloudflared + 43 langs + configs + docs
- ✓ **D3** [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md) — GPL-2 §3 compliance attribution for every bundled component
- ◷ **D4** Cross-GPU acceptance tests (iGPU QSV / AMD AMF / no-GPU / NVENC) — hardware required, checklist in [docs/ACCEPTANCE_CHECKLIST.md](docs/ACCEPTANCE_CHECKLIST.md)
- ◷ **D5** Cross-PC cross-ISP E2E acceptance — hardware required, checklist in same doc
- ✓ **D6** Auto-update: [tools/update_check.ps1](tools/update_check.ps1) + [update_notifier.js](srchybrid/eSE/eSE-live/update_notifier.js) + 3 endpoints (`/api/live/update_status`, `/update_check`, `/update_run`) + dashboard toast in [live_tv_page.js:687](srchybrid/eSE/eSE-live/live_tv_page.js:687)
- ✓ **D7** Crash reports: `CMiniDumper` default ON ([emule.cpp:441](srchybrid/emule.cpp:441)), dumps to dedicated `%APPDATA%\eMule\crashdumps\` subdir, post-launch prompt to open folder ([EmuleDlg.cpp:715](srchybrid/EmuleDlg.cpp:715))
- ✓ **D8** GitHub Actions CI ([.github/workflows/build.yml](.github/workflows/build.yml)) — builds emule.exe + ese-server.exe on every push/PR + uploads artifact
- ✓ **D9** Security audit ([docs/SECURITY_AUDIT.md](docs/SECURITY_AUDIT.md)) + 2 XSS fixes (see §H)
- ✓ **D10** First-run wizard ([live_tv_page.js:537](srchybrid/eSE/eSE-live/live_tv_page.js:537)) — Kad / NAT / FFmpeg / public-IP checks with contextual fix-it tips + test-broadcast CTA

### Other operability work
- ✓ Graceful unpublish on `ExitInstance` (DISC-S01)
- ✓ FFmpeg orphan process cleanup on broadcast stop / error
- ✓ Persistent ghost streamKey cleanup at startup (DISC-S04)
- ✓ `/api/live/diagnose` endpoint for support
- ✓ Auto-spawn of `ese-server.exe` from `emule.exe` ([EmuleDlg.cpp:687](srchybrid/EmuleDlg.cpp:687))
- ✓ 3-tier fallback for ese-server discovery: same-dir → node + server.js → well-known paths

---

## J. CLI flags + multi-instance support

Added to [emule.cpp](srchybrid/emule.cpp). Upstream had none of these.

- ✓ `--headless` — no GUI, regenerates UserHash to avoid self-rejection across instances on same host
- ✓ `--viewer=KEY` — auto-join a stream on startup (8s delay)
- ✓ `--metrics-port=N` — bind `/api/live/metrics` on a separate port (multi-instance stress)
- ✓ `--tcp-port=N` — override TCP port (multi-instance — applied before mutex check for unique name + after `thePrefs.Init()`)
- ✓ `--udp-port=N` — override UDP port (same logic)
- ✓ `--selftest` — one-shot self-broadcast → self-join → assert chunks received → exit 0/1
- ✓ `--ignoreinstances` — skip single-instance mutex check
- ✓ `CPreferences::RegenerateUserHash()` — called when `--headless` is set; prevents same-host instances rejecting each other
- ✓ Loopback IP bypass in `TryConnectToStreamSource` when `m_bHeadless` (for local stress runs)

### Stress test infrastructure
- ✓ Multi-instance orchestrator in [tools/stress-test/](tools/) — spawn N headless instances
- ✓ Chart.js dashboard showing alive count, latency, chunks per instance
- ✓ Automated sweep N=10/50/100 → `sweep-report.json`
- ✓ Production-grade local-PC topology validated up to ~10-20 viewers per stream (per `MASTER_PLAN.md` §1.2)

---

## K. Internationalization

Upstream has 43 language `.vcxproj` files but **none of them are in `emule.sln`** — a silent regression we caught while preparing the v7.0 release.

- ✓ **43 language DLLs now actually built** in the release pipeline ([build_package.ps1:9](build_package.ps1:9) — new `[1b]` step + [tools/build_all.ps1](tools/build_all.ps1) stage `langs`)
- ✓ **Auto-detect widened** ([I18n.cpp:262](srchybrid/I18n.cpp:262)) — if full `LANGID` doesn't match (e.g. `es-MX`), falls back to primary-only (`es_*`) so any Spanish locale picks up `es_AS.dll` / `es_ES_T.dll`
- ✓ **"Fell back to English" modal removed** ([I18n.cpp:266](srchybrid/I18n.cpp:266)) — used to pop on every launch when no matching DLL; now silent `TRACE` log
- ◷ Translation of new MFC strings (the "Live" tab) into the 43 languages — currently English only
- ◷ Dashboard Node UI in languages other than Spanish — currently es-only

---

## L. Build + distribution pipeline

Everything in this section is new vs upstream.

### Scripts
- ✓ [build_package.ps1](build_package.ps1) — packages emule.exe + ese-server.exe + ffmpeg + node + cloudflared + 43 langs + configs + docs + tools/ into a portable ZIP. Auto-downloads `server.met` and `nodes.dat` if missing.
- ✓ [tools/build_all.ps1](tools/build_all.ps1) — master pipeline: MSBuild emule + npm build ese-server + MSBuild 43 lang DLLs + package. Flags `-Skip`, `-DryRun`, `-ReleaseTag`. ASCII-only for PS 5.1 compat.
- ✓ [tools/build_ese_server.ps1](tools/build_ese_server.ps1) — idempotent rebuild of `ese-server.exe` from JS sources. Wired as `PreBuildEvent` in `emule.vcxproj` so the C++ build auto-keeps the bundled exe in sync.
- ✓ [tools/update_check.ps1](tools/update_check.ps1) — auto-update poller + interactive installer (download zip, kill processes, extract in place, restart).

### CI
- ✓ [.github/workflows/build.yml](.github/workflows/build.yml) — Windows runner, Node 18 → ese-server.exe → MSBuild emule.exe → stage artifact bundle → upload (14-day retention).

### Bundled binaries
- ✓ `ffmpeg.exe` (essentials build, ~40 MB) — auto-downloaded from gyan.dev if not cached
- ✓ `node.exe` (v18+) — from PATH or NVM
- ✓ `cloudflared.exe` — auto-downloaded from Cloudflare GitHub if not present
- ✓ `eMule.tmpl` (WebServer template) — bundled in `config/` AND root for fallback resolution
- ✓ `server.met` (eD2K server list) — bundled or auto-fetched from gruk.org
- ✓ `nodes.dat` (Kad bootstrap) — bundled or auto-fetched from nodes-dat.com

### Installer
- ✓ [installer/setup_ese.iss](installer/setup_ese.iss) — Inno Setup script (modern wizard, ES+EN, firewall rules, taskkill, uninstall) — version bumped to `0.70b-eSE7.0`. Not built for this release (Solo ZIP portable per decision 2026-05-16).
- ✓ [installer/eSE.vbs](installer/eSE.vbs) — VBScript launcher (eMule minimized to tray + Node server + browser auto-open)
- ✓ `preferences.ini` defaults — sensible zero-config (UPnP on, WebServer on, port 4711, AutoStart=1)

---

## M. New documentation

Upstream has `readme.txt` (~50 lines) + license. We added:

| File | Lines | Purpose |
|---|---|---|
| [README.md](README.md) | ~110 | User-facing front page (heavily rewritten) |
| [CHANGES_FROM_EMULE_0.70b.md](CHANGES_FROM_EMULE_0.70b.md) | this file | Diff vs upstream (GPL §2(a) notice) |
| [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md) | ~130 | GPL §3 compliance attribution |
| [docs/USER_GUIDE.md](docs/USER_GUIDE.md) | ~250 | Install, watch, broadcast, ports, troubleshooting |
| [docs/MASTER_PLAN.md](docs/MASTER_PLAN.md) | **2909** | Architecture bible — escalability, sprints, design |
| [docs/SPRINTS_V2.md](docs/SPRINTS_V2.md) | 1471 | 30 V2 micro-sprints with paste-ready code |
| [docs/SPRINTS_V3.md](docs/SPRINTS_V3.md) | 948 | 30 V3 micro-sprints (SRT, RLNC FEC, WebRTC, E2EE) |
| [docs/SPRINTS_V4.md](docs/SPRINTS_V4.md) | 383 | 24 V4 exploratory sprints (SVC, super-relays, onion) |
| [docs/DISCOVERY_PLAN.md](docs/DISCOVERY_PLAN.md) | 344 | DISC-S01..S15 catalog |
| [docs/STREAM_BROWSER_PLAN.md](docs/STREAM_BROWSER_PLAN.md) | 140 | BROWSE-S01..S05 catalog |
| [docs/DISCOVERY_STRATEGIES.md](docs/DISCOVERY_STRATEGIES.md) | 214 | 26 discovery ideas + 3-phase rollout |
| [docs/DECENTRALIZED_DISCOVERY.md](docs/DECENTRALIZED_DISCOVERY.md) | 228 | 4-layer P2P discovery design (C1+C2+C3 done) |
| [docs/SECURITY_AUDIT.md](docs/SECURITY_AUDIT.md) | ~200 | First security review (10 findings, 2 XSS fixed) |
| [docs/MODERNIZATION.md](docs/MODERNIZATION.md) | ~150 | "2005-era code in 2026" inventory — 16 modernization candidates |
| [docs/ACCEPTANCE_CHECKLIST.md](docs/ACCEPTANCE_CHECKLIST.md) | ~120 | D4 (cross-GPU) + D5 (cross-PC) hardware test matrices |
| [docs/DISTRIBUTION_ANALYSIS.md](docs/DISTRIBUTION_ANALYSIS.md) | ~150 | Build/release current state + gaps |
| [docs/RELEASE_NOTES_v0.70b-eSE7.0.md](docs/RELEASE_NOTES_v0.70b-eSE7.0.md) | ~120 | This release |

**Total new documentation: ~7,800 lines.**

---

## N. Notable bug fixes

Things that broke during development and were fixed (not pre-existing
upstream bugs):

- ✓ **t=8s crash 0xC0000005** — `%S` format specifier passing an `int` (`UPNP_IMPL_MINIUPNPLIB=1`) cast to `LPCWSTR`; `wcsnlen` reading from `0x1`. Fixed `%d` in LIVE_LOG. Diagnosed via `/MAP` linker flag + minidump + llvm-symbolizer. (Commits `1657be7`, `c31dc89`)
- ✓ **TIER overflow** with `MaxUpload=UINT_MAX` — `kbs*8` overflowed DWORD. Added unlimited check → maps to 999999 kbps. (Commit `1657be7`)
- ✓ **`GetTickCount64` not available on NT 4.0 target** — replaced with `(uint64)GetTickCount()`.
- ✓ **`--selftest` + `--headless` crash** — multi-instance same-host shared `UserHash` causing self-rejection. Added `RegenerateUserHash()` when `--headless`. (Commit `b54365e`)
- ✓ **Multi-instance TCP/UDP port collision** — added `--tcp-port` + `--udp-port` with override BEFORE mutex check (unique mutex name) and AFTER `thePrefs.Init()` (which overwrote from .ini). (Commit `f365e74`)
- ✓ **Loopback IP rejected** in `TryConnectToStreamSource` — added `&& !theApp.m_bHeadless` bypass.
- ✓ **Video MKV `chunk_buffer_count=0`** — watcher's `parseSegNum` was picking audio variants `seg_eng_13697.ts` as max. Fixed to reject filenames with letters after `seg_`. (Commit `b54365e`)
- ✓ **`chunk_buffer_count` stays at 0 during prebuffer** — `FeedSegment` dropped chunks because `m_bBroadcasting=false` during wait. Fixed by calling `StartBroadcast()` BEFORE the wait loop.
- ✓ **Stale FFmpeg orphans writing to same temp dir** — added kill-all-ffmpeg before testing + proper child reaping in RTMPIngest.
- ✓ **Master playlist `stream.m3u8` had single-stream content** — overwritten by orphan FFmpeg processes. Fixed by killing all + clean temp before new pipeline.
- ✓ **Audio cuts after 3.4s in VLC** — `-g 120` keyframe interval (5s) ≠ `-hls_time 2`; multiple `DEFAULT=YES` on audio tracks. Fixed `-g 48` + `DEFAULT=YES` only first track + `EXT-X-INDEPENDENT-SEGMENTS` flag.
- ✓ **VLC tirones at 1080p** — 4 simultaneous libx264 1080p encodes saturated CPU. Fixed with NVENC auto-detection (RTX 3070) — GPU offload.
- ✓ **VLC black screen after few seconds** — hit live edge with empty buffer. Fixed with 3-chunk (~12s) prebuffer before broadcast/start returns.
- ✓ **`ese-server.exe` ENOENT in pkg mode** — `tunnel.js` write to `__dirname/config.json` which is `C:\snapshot\eSE\` (read-only). Created `runtime_dir.js` helper + updated all writers.
- ✓ **pkg "No available node version satisfies node20"** — pkg 5.8.1 only supports up to node18. Reverted `package.json` target.
- ✓ **PowerShell em-dash encoding** — script with `—` failed to parse as ANSI. Replaced all em-dashes with hyphens. (Same fix applied to `build_all.ps1` and `build_package.ps1` today.)
- ✓ **`$PSScriptRoot` empty** — added fallback to `Split-Path -Parent $MyInvocation.MyCommand.Definition`.
- ✓ **PostToolUse permission denials** — user auto-mode blocked renaming pre-existing `ese-server.exe`. Resolved by killing running processes first.
- ✓ **Invisible field underflow** in `LiveChunkBuffer::AddSegment` — uint32 boundary check missing. (Commit `7fc806e`)
- ✓ **Invisible MFC labels** — text rendering bug in Live Stream dialog. Fixed by embedding prefix in dynamic text. (Commit `08fc4e8`)
- ✓ **UPnP result invisible** — surfaced in `/api/live/log`. (Commit `054e776`)
- ✓ **LowID false positive** — anonymous-link UI warning calibrated less aggressively. (Commit `fabe9fb`)

---

## What we DID NOT change in upstream

For transparency, the following remain byte-identical (or near
byte-identical, modulo `#include` additions) to upstream eMule 0.70b:

- **eD2K wire protocol baseline** — everything that isn't a new live opcode
- **Kad DHT** routing, store, search algorithms
- **AICH hash tree** (SHA-1, kept for compat with all existing peers)
- **Classic file-sharing UI** — Transfers / Server / Search / Files / Statistics tabs
- **File hashing, partfile handling, source exchange, friends list**
- **Bundled third-party libs** (CryptoPP, mbedTLS, miniupnpc, libutp, zlib, libpng, id3lib, CxImage, ResizableLib) — all unchanged from their upstreams
- **`Mdump.cpp`** itself (we only changed *how* it's invoked from `emule.cpp`)
- **All `srchybrid/lang/*.rc`** translated string tables (we built them, didn't translate them)

If you trust upstream eMule 0.70b for file-sharing, you trust this
fork for file-sharing — that surface area is byte-identical save for
header file inclusions that pull in the new live subsystem.

---

## License

GPL-2.0-only, inherited from upstream. See [license.txt](license.txt)
for the full text. All modifications in this fork are released under
the same license. Source for every binary we ship is in this
repository.

Third-party bundled binaries (FFmpeg, Node.js, cloudflared,
statically-linked native libraries, npm modules) are attributed in
[THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).

---

_If you're an eMule Project maintainer reading this: thank you for
the work that made this possible. The eD2K + Kad core remains the
unchanged foundation we built on top of._

_Last updated: 2026-05-16._
