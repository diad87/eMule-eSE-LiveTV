# eMule eSE — User Guide

This guide covers the end-user workflow: install, watch a stream,
broadcast your own, troubleshoot.

For the design / architecture see [MASTER_PLAN.md](MASTER_PLAN.md) and
[DECENTRALIZED_DISCOVERY.md](DECENTRALIZED_DISCOVERY.md).

---

## 1. Install

1. Download `eSE-LiveTV-x64-*.zip` from the [Releases](../../../releases) page.
2. Extract anywhere (e.g. `C:\eSE\`).
3. Double-click **`emule.exe`**.
4. Wait for eD2K + Kad to connect (status icons go green/yellow).
5. Click the **`eSE`** button in the eMule toolbar.

That triggers:

- `emule.exe` keeps running — handles eD2K / Kad / mesh transport
- `ese-server.exe` is auto-spawned in background — the Node.js dashboard on port 8080
- Default browser opens to <http://localhost:8080/live>

If a UAC prompt appears the first time, accept it — needed for UPnP
to map the eD2K ports on your router. If Windows Firewall asks about
`emule.exe`, `ese-server.exe`, or `ffmpeg.exe`, allow all three.

> **Note:** earlier releases used a `eSE.vbs` launcher. That was
> dropped — you now launch `emule.exe` directly and the eSE button
> in the toolbar does the rest.

### What writable files get created

| Path | Purpose |
|---|---|
| `%APPDATA%\eMule\` | Config, server.met, nodes.dat, `last_streams.json` (bootstrap cache) |
| `%APPDATA%\eSE\` | Node-side config, tunnel URL, telegram bot key |
| `%TEMP%\eMule_RTMP\` | Transient HLS playlists and chunks while a broadcast is active |

To uninstall, delete the install folder + both `%APPDATA%` folders.

---

## 2. Watch a stream

### 2.1 From the browser

1. Open <http://localhost:8080/live>.
2. The grid shows every stream currently discoverable via:
   - **Kad** (DHT search, 2-30 s typical)
   - **PEX gossip** from your connected peers
   - **LAN multicast** from anyone on the same Wi-Fi / LAN
   - **Bootstrap cache** of streams you recently watched
3. Click any tile → the player opens at `/live/watch/<hash>`.
4. The player waits for the local receiver to reconstruct enough HLS data, then starts. Initial buffering depends on discovery and network conditions.

### 2.2 From a paste link

If a friend sent you an `ed2k://|live|...|/` URL, paste it into the
search box at the top of `/live`. A link containing `IP:port` can dial
the broadcaster directly. The privacy-preserving form has an empty
endpoint (`ed2k://|live|KEY||TITLE|/`) and resolves the broadcaster
through Kad instead, which normally takes longer.

### 2.3 In VLC / any HLS player

For the broadcaster's own output, use:

```
http://127.0.0.1:8080/hls/stream.m3u8
```

For a stream being received from the P2P mesh, use:

```
http://127.0.0.1:8080/hls-local/<hash>/stream.m3u8
```

Paste it into VLC → Media → Open Network Stream. Useful if you want
hardware-accelerated decode or PiP.

---

## 3. Broadcast your own stream

### 3.1 Quick start — push from OBS

1. In eMule eSE, click the **Live** tab → **Start Broadcast**. The local API equivalent is `GET /api/live/broadcast/start?source=rtmp&title=My%20Channel`. This:
   - Opens the RTMP ingest listener on **port 1935**
   - Generates the stream key
   - Publishes a Kad keyword for the title
   - Begins announcing on LAN multicast (port 5354)
2. In OBS → Settings → Stream:
   - **Service:** Custom
   - **Server:** `rtmp://127.0.0.1:1935/live`
   - **Stream key:** `stream`
3. OBS → **Start Streaming**. The API can initially report
   `waiting_input` while the RTMP listener waits for OBS; the channel is
   ready after FFmpeg has produced HLS chunks.
4. Verify viewers can find you:
   - On the same machine: open the cinema player from `/live`.
   - On the LAN: open <http://OTHER_PC:8080/live> on another laptop — LAN discovery should advertise the stream without waiting for Kad propagation.
   - WAN: share the `ed2k://|live|...|/` link from the cinema player URL bar.

### 3.2 Recommended OBS settings

| Setting | Value | Reason |
|---|---|---|
| Output mode | Advanced | Lets you set keyframe interval explicitly |
| Encoder | H.264 (x264 / NVENC / QSV) | RTMP ingest remuxes the OBS stream, so use a browser-compatible H.264 source |
| Keyframe interval | **2 s** | Aligns with `-hls_time 2` so chunks are independent |
| Rate control | CBR | Steadier bitrate → smoother viewer experience |
| Bitrate | 2500–6000 kbps for 1080p, 1500–3000 for 720p | Upload bandwidth permitting |
| Audio | AAC, 128 kbps, 48 kHz, stereo | Wider device support than 44.1 |

### 3.3 Output variants

RTMP/OBS, screen capture and test-pattern sources currently produce a
single HLS rendition. Broadcasting a media file can produce an ABR
ladder selected from the encoders FFmpeg actually exposes: NVENC can
produce up to five variants, QSV/AMF up to three, and the CPU fallback
two. The P2P watcher sends one selected rendition to the mesh.

### 3.4 Stop broadcasting

- Stop OBS, **then** click **Stop Broadcast** in the dashboard (or call `GET /api/live/broadcast/stop`).
- The Kad tombstone is published so other peers stop seeing your
  ghost entry immediately. (`Kad unpublish` is best-effort but the
  tombstone is propagated via the next PEX heartbeat.)

---

## 4. Network ports — open these on your router for best results

| Port | Protocol | Direction | Required? |
|---|---|---|---|
| 4662 | TCP | inbound | **Yes** — without it you stay LowID and viewers can't reach you over WAN. UPnP usually opens this automatically. |
| 4672 | UDP | inbound | Yes — Kad discovery. |
| 4711 | TCP | inbound | Optional — only if you want to expose `/api/*` to external machines. |
| 8080 | TCP | inbound | Optional — only if you want remote browsers on the dashboard. |
| 1935 | TCP | inbound | Optional — only if your OBS is on a different machine. Keep closed otherwise. |
| 5354 | UDP multicast | LAN | TTL=1, never escapes your subnet — no router config needed. |

UPnP is enabled by default (`EnableUPnP=1` in `preferences.ini`).
Check `Options → Connection → "UPnP NAT traversal: OK"` in the eMule
UI. This maps eMule's P2P ports, not the dashboard. Port 8080 is never
auto-exposed; forward it only deliberately and with an access token. If your
router refuses UPnP, manually forward 4662/TCP + 4672/UDP.

---

## 5. Troubleshooting

### "No streams visible after 5 minutes"

Check, in order:

1. **Kad status** — bottom-right of the eMule UI must say `Kad: Connected`. If it says `Firewalled` or `Searching`, viewer-only mode still works but discovery is slower. Wait 1-5 min for first Kad bootstrap.
2. **Run `/api/live/diagnose`** — open <http://localhost:4711/api/live/diagnose> in the browser. The response tells you whether each layer (Kad, PEX, LAN, bootstrap) is functioning and how many peers each sees.
3. **Verify port 5354 is bound** — in PowerShell: `netstat -an | findstr 5354` should show the LAN discovery socket. If the dashboard is also unavailable, restart eMule and open eSE again from the toolbar.
4. **Check `last_streams.json`** at `%APPDATA%\eMule\last_streams.json`. If empty, this is your first run — no bootstrap cache yet. Watch something for 30 s, then restart eMule; the second boot should ping cached streams in <5 s.

### "Black screen in cinema player"

Two failure modes:

- **Live edge / no buffer** — wait 15 s. The prebuffer is 3 chunks (~12 s); if your network is slow the first chunk takes longer.
- **HLS reconstruction stuck** — check `/api/live/metrics` for `live_chunks_received_total`. If it's stuck at 0, the broadcaster isn't reachable. Either they're firewalled (Kad LowID) or your peer-routing has no path yet.

### "Audio cuts out after a few seconds"

This was the keyframe-misalignment bug fixed in `1657cf` / `9c1adfe`.
Confirm with `ffmpeg -i master.m3u8` — every variant playlist should
have `#EXT-X-INDEPENDENT-SEGMENTS`. If yours doesn't, you're on an
old `ese-server.exe` — rebuild via `tools\build_ese_server.ps1` or
download a fresh release.

### "ese-server.exe not found" dialog

The portable ZIP must contain `ese-server.exe` next to `emule.exe`.
If it's missing, either re-extract the ZIP or rebuild:

```powershell
cd srchybrid\eSE
npm install
npm run build
# Copy dist\ese-server.exe next to emule.exe
```

The `tools\build_ese_server.ps1` PreBuildEvent does this automatically
during Release|x64 builds — see the script header for details.

### Logs

- **eMule log** — bottom pane of the eMule UI, or `%APPDATA%\eMule\logs\`.
- **eSE / Node log** — `ese-server.exe` writes to stdout when launched from a console.
- **HLS chunks** — `%TEMP%\eMule_RTMP\` while a broadcast is live; received streams use per-stream subdirectories. Generated files are removed when the corresponding stream stops.

---

## 6. Stress / dev features (CLI flags)

These are for testing only and apply to `emule.exe` when launched from a console.

| Flag | Purpose |
|---|---|
| `--headless` | No window; regenerates UserHash so multiple instances on the same host don't reject each other. |
| `--viewer=<key>` | Auto-join a stream on startup. |
| `--tcp-port=N --udp-port=N` | Override ports (needed for multi-instance same-host). |
| `--metrics-port=N` | Bind `/api/live/metrics` on a separate port. |
| `--selftest` | Start a test-pattern broadcast for about five seconds and stop it. This is a launch/stop smoke test, not a multi-peer end-to-end assertion. |
| `--ignoreinstances` | Skip the single-instance mutex check. |

---

_Last updated: 2026-07-14._
