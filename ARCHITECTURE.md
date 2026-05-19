# eMule eSE Live — Architecture

End-to-end map of how a live broadcast travels from the broadcaster's screen
to a remote viewer's browser, plus where every piece lives in the source tree.

---

## 1. The 30-second mental model

```
                BROADCASTER                                              VIEWER
   ┌─────────────────────────────┐                       ┌─────────────────────────────┐
   │ OBS / file / screen / test  │                       │   Browser (hls.js player)   │
   │           │                 │                       │              ▲              │
   │           ▼ RTMP / lavfi    │                       │              │ HTTP HLS     │
   │   ┌──────────────┐          │                       │     ┌──────────────┐        │
   │   │   FFmpeg     │ HLS .ts  │                       │     │ Node.js dash │        │
   │   │   (child)    ├─────────►│                       │     │ port 8080    │        │
   │   └──────────────┘ %TEMP%   │                       │     └──────┬───────┘        │
   │           │                 │                       │            │                │
   │           ▼ FeedSegment()   │                       │            │ /hls/*.ts      │
   │   ┌─────────────────────┐   │                       │            ▼                │
   │   │ CLiveStreamManager  │   │                       │     %TEMP%\eMule_RTMP\      │
   │   │  m_chunkBuffer (16) │   │                       │            ▲                │
   │   │  m_broadcastPeers   │   │                       │            │ written by     │
   │   └────────┬────────────┘   │                       │            │ OnChunkRecvd   │
   │            │                │                       │     ┌──────┴───────┐        │
   │            │  Kad publish   │      ┌────────────┐   │     │ CLiveStream  │        │
   │            ├───────────────►│      │   Kad DHT  │   │     │ Manager      │        │
   │            │                │      │ (P2P node) │   │     │  m_viewPeers │        │
   │            │ OP_LIVE_CHUNK  │      │            │   │     │  m_chunkBuf  │        │
   │            ▼                │      │ TAG_ESE_*  │   │     └──────▲───────┘        │
   │       eD2K TCP 4662    ────►│   ┌─►│ TAG_SOURCE*│   │            │                │
   │  (or uTP hole-punch UDP)    │   │  └────────────┘   │            │                │
   │       eMule.exe             │   │         │         │       eMule.exe             │
   └────────────┬────────────────┘   │         ▼         └────────────┬────────────────┘
                │                    │  Kad keyword search             │
                │                    │  on "eselive" finds source      │
                │                    │  IP:TCP_port:UDP_port           │
                └────────────────────┴─────────────────────────────────┘
                       OP_LIVE_SUBSCRIBE → OP_LIVE_REQUEST → OP_LIVE_CHUNK
                       (over TCP if HighID, over uTP/UDP if hole-punched)
```

---

## 2. Process layout (current state)

| Process | Port | Purpose | Source |
|---|---|---|---|
| `emule.exe` (MFC + Win32) | TCP 4662 | eD2K + Live P2P | `srchybrid/*.cpp` |
| `emule.exe` (Kademlia) | UDP 4672 | Kad DHT + UDP firewall test + uTP hole-punch | `srchybrid/kademlia/` |
| `emule.exe` (WebServer) | TCP 4711 | C++ HTTP API (`/api/live/*`, `/api/status`, `/api/holepunch/*`, etc.) | `srchybrid/WebServer.cpp` |
| `ese-server.exe` (Node.js) | TCP 8080 | Web dashboard, HLS file serving, proxies → 4711 | `srchybrid/eSE/server.js` + `eSE-live/*.js` |
| `ffmpeg.exe` (child of emule) | — | RTMP listener / encoder / file looper | spawned by `RTMPIngest.cpp` |
| `cloudflared.exe` (opt-in) | — | HTTPS tunnel (only if user explicitly enables) | spawned by `eSE-live/cloudflare_tunnel.js` |

**Note:** Sprint 5 may eliminate `ese-server.exe` by serving its assets directly
from the C++ WebServer (single-binary deployment).

---

## 3. Live broadcast — broadcaster side flow

1. **User presses START** in MFC `LiveStreamDlg` or in web wizard ("Crear emisión de prueba").
2. `CLiveStreamManager::StartBroadcastWithSource(source, title, ...)`:
   - Spawns FFmpeg via `CRTMPIngest` (Test Pattern, RTMP listen, gdigrab, or file).
   - Waits up to 2 s polling `IsRunning()` (catches early FFmpeg crashes).
   - Publishes stream metadata to Kad with `CLiveStreamManager::StartBroadcast()`.
3. FFmpeg writes `.ts` segments + `stream.m3u8` to `%TEMP%\eMule_RTMP\`.
4. `CRTMPIngest::WatcherLoop` (background thread) detects each new `.ts`,
   reads the bytes, and invokes the `chunkCb` lambda.
5. The lambda calls `theApp.liveStreamManager->FeedSegment(data, size)`,
   which adds the chunk to `m_chunkBuffer` (16-slot ring) and increments
   `m_nNextSeqNum`.
6. Every 1 s in `Process()`:
   - `SendBitmapToAll()` — heartbeat to all subscribed viewers.
   - `SendAnnounceToAll()` — "I have segment N" notification.
   - `PublishToKad()` — re-publish stream metadata in DHT.
7. When a viewer sends `OP_LIVE_REQUEST(seqNum)`, `OnPeerRequest()` looks
   up the chunk in `m_chunkBuffer` and replies with `OP_LIVE_CHUNK`.

### Watchdog (Sprint 2 E.3)
If FFmpeg dies mid-stream, `WatcherLoop` notices and calls
`TryWatchdogRestart()`, which re-spawns FFmpeg with the same source/bitrate.
Capped at 5 restarts in any 5-min window.

---

## 4. Live broadcast — viewer side flow

1. User opens `localhost:8080/live` (Node dashboard).
2. Wizard or "Direct Join" panel triggers `JoinStream(streamKey, title)`.
3. `JoinStream()` issues a Kad `SearchStreams("eselive")` keyword lookup.
4. Each Kad result containing `TAG_ESE_LIVE_MARKER=1` arrives at
   `Search.cpp::ProcessResultKeyword`, which extracts:
   - `TAG_SOURCEIP` → broadcaster IP
   - `TAG_SOURCEPORT` → broadcaster TCP port
   - `TAG_SOURCEUPORT` → broadcaster Kad UDP port (Sprint 1 A.4)
   - `TAG_ESE_LIVE_*` → metadata (title, category, language, bitrate, ...)
5. `LiveKadBridge::OnKadSearchResult` registers the entry and calls
   `TryConnectToStreamSource(streamKey, IP, port, udpPort)`.
6. `TryConnectToStreamSource` creates a `CUpDownClient`, sets its Kad UDP
   port via `SetKadPort()`, and sends `OP_LIVE_SUBSCRIBE`.
7. The TCP `SafeConnectAndSendPacket` invokes `TryToConnect`:
   - If broadcaster is HighID → direct TCP, done.
   - If LowID → tries Direct UDP Callback (SOURCETYPE 6).
   - If LowID and Kad UDP port known → fires `SendEseHolePunchReq` (uTP
     hole-punch). Adaptive cooldown 5s × 3 then 30s. After 4 fails,
     classified as symmetric NAT (Sprint 1 A.2/A.3).
8. Broadcaster's `OnPeerJoin` proactively pushes the last 3 segments to
   the new viewer (BOOT-5), so playback starts in ~6-10 s.
9. `OnChunkReceived` writes each chunk to the viewer's local
   `%TEMP%\eMule_RTMP\<streamKey>\seg_NNNNN.ts`.
10. The web player (`live_player_html.js`) pulls `/hls/stream.m3u8` from
    Node, which serves the local files. Auto-reconnect with exponential
    backoff if hls.js reports a fatal error (Sprint 2 E.2).

---

## 5. Key data structures

| Type | Where | Purpose |
|---|---|---|
| `LiveChunk` | `LiveProtocol.h` | One HLS .ts segment + metadata (16-byte streamKey, seqNum, timestamp, size, bitrate). Owns its data buffer. |
| `LiveStreamInfo` | `LiveProtocol.h` | Broadcaster metadata for Kad publishing. |
| `PeerBitmapInfo` | `LiveProtocol.h` | Sprint 1 BOOT-1: bitmap (16-bit) + `oldestSeq` anchor + `lastUpdate` for one peer. |
| `PeerTrust` | `LiveProtocol.h` | Anti-Sybil response-rate tracking + trust tier (leaf / middle / super-seeder). |
| `LiveStreamEntry` | `LiveKadBridge.h` | Entry in the local Kad-discovered streams directory. |
| `LiveStreamCounters` | `LiveStreamManager.h` | Atomic LONG counters for `/api/live/debug` observability. |
| `CLiveChunkBuffer` | `LiveChunkBuffer.h` | 16-slot ring buffer of `LiveChunk*` indexed by seqNum. |

---

## 6. Wire protocol (eD2K extension)

| Opcode | Hex | Direction | Body |
|---|---|---|---|
| `OP_LIVE_SUBSCRIBE`  | 0xC3 | viewer → broadcaster | streamKey(16) + viewerHash(16) + uploadCapacity(4) |
| `OP_LIVE_UNSUBSCRIBE`| 0xC4 | viewer → broadcaster | streamKey(16) + viewerHash(16) |
| `OP_LIVE_REQUEST`    | 0xC1 | viewer → peer | streamKey(16) + seqNum(4) |
| `OP_LIVE_CHUNK`      | 0xC2 | peer → viewer | streamKey(16) + seqNum(4) + timestamp(4) + chunkSize(4) + payload |
| `OP_LIVE_HEARTBEAT`  | 0xC6 | peer → peer | streamKey(16) + bitmap(2) + oldestSeq(4) |
| `OP_LIVE_ANNOUNCE`   | 0xC0 | broadcaster → all | streamKey(16) + newestSeq(4) + bitrate(2) |
| `OP_LIVE_PEER_LIST`  | 0xCA | broadcaster → viewer | streamKey(16) + count(2) + (IP+port)[count] |
| `OP_LIVE_DENY`       | 0xC7 | broadcaster → viewer | streamKey(16) + reason(1) |
| `OP_LIVE_END`        | 0xC8 | broadcaster → all | streamKey(16) + reason(1) |

Plus Kad layer:
- `KADEMLIA_ESE_HOLEPUNCH_REQ` — initiator → target via Kad UDP
- `KADEMLIA_ESE_HOLEPUNCH_ACK` — target → initiator with echoed nonce
- `OP_DIRECTCALLBACKREQ` — eD2K UDP for "I'm HighID UDP, you're LowID TCP, please call me back"

---

## 7. Web API (port 4711, served by C++ WebServer)

| Endpoint | Method | Purpose |
|---|---|---|
| `/api/status` | GET | Network health (Kad/eD2K/UPnP/hole-punch counters) |
| `/api/live/preflight` | GET | Pre-flight check (Kad+HighID+Upload+FFmpeg+IP) |
| `/api/live/debug` | GET | Full snapshot of LiveStreamManager state |
| `/api/live/channels` | GET | List of currently known live streams |
| `/api/live/mesh` | GET | Mesh topology, super-seeder / middle / leaf counts |
| `/api/live/kad/streams` | GET | Raw Kad directory dump |
| `/api/live/join` | GET | `?key=HEX&title=...` — start viewing by stream key |
| `/api/live/direct_join` | GET | `?link=ed2k://\|live\|...` — pasted link parser |
| `/api/live/broadcast/start` | GET | `?source=&title=&bitrate=` — start broadcasting |
| `/api/live/broadcast/stop` | GET | Stop broadcast + FFmpeg ingest |
| `/api/holepunch/test` | GET | `?ip=&udp_port=` — manual hole-punch trigger (rate-limited) |

The Node dashboard at port 8080 proxies most of these so the browser doesn't
need to know about port 4711.

---

## 8. Where things live (cheatsheet)

```
srchybrid/
├── LiveProtocol.h           # Constants, LiveChunk, PeerBitmapInfo, PeerTrust
├── LiveChunkBuffer.{h,cpp}  # 16-slot ring buffer
├── LivePackets.{h,cpp}      # Build OP_LIVE_* packets
├── LiveStreamManager.{h,cpp}# Core broadcaster+viewer state machine
├── LiveStreamHandlers.cpp   # Stub (real handlers in ListenSocket.cpp)
├── LiveKadBridge.{h,cpp}    # Kad publish/search wrapper
├── LiveMeshManager.{h,cpp}  # Viewer-to-viewer P2P relay topology
├── LiveStreamDlg.{h,cpp}    # MFC dialog for the "Live" tab
├── LiveStreamDlgUI.cpp      # Status bar + share panel for the dialog
├── RTMPIngest.{h,cpp}       # FFmpeg child process management
├── BaseClient.cpp:1471-1500 # uTP hole-punch trigger in TryToConnect
├── kademlia/
│   ├── kademlia/Search.cpp:1130-1300  # Live keyword result handler
│   ├── kademlia/Search.cpp:1572-1614  # Live publish builder
│   └── net/KademliaUDPListener.cpp:2069-2210  # HOLEPUNCH_REQ/ACK handlers
├── eMuleAI/UtpSocket.{h,cpp}  # libutp wrapper, RegisterExpectedPeer
├── EmuleDlg.cpp:3175-3300   # ese-server.exe launcher (3-tier fallback)
└── eSE/                     # Node.js dashboard (runs as ese-server.exe)
    ├── server.js            # Entry point, port 8080
    ├── eSE-live/
    │   ├── channel_api.js   # All /api/live/* + /api/eSE/* + proxies
    │   ├── live_tv_page.js  # Renders /live page (wizard, panels)
    │   ├── cloudflare_tunnel.js   # Opt-in Cloudflare tunnel wrapper
    │   ├── ffmpeg_pipeline.js     # Alternative ingest path
    │   └── ...
    └── live_player_html.js  # hls.js player page
```

---

## 9. Build artifacts

```
srchybrid/x64/Release/
├── emule.exe                # The main binary (~12 MB)
├── ese-server.exe           # Node.js dashboard bundled (~74 MB) — drop here for tests
├── ffmpeg.exe               # FFmpeg encoder (~97 MB) — bundled by build_package.ps1
├── nodes.dat                # Kad bootstrap nodes
├── config/preferences.ini   # Default prefs (UPnP+autoconnect on)
└── eSE/                     # Node modules + assets (if not bundled into ese-server.exe)
```

The `build_package.ps1` script assembles all of these into a single ZIP for
release.

---

## 10. Threading model

| Thread | Owns | Notes |
|---|---|---|
| Main UI (MFC) | Dialogs, message pump | Sleep-free since Sprint 0bis (uses message-pump wait) |
| FFmpeg watcher | One per `CRTMPIngest`, polls `%TEMP%\eMule_RTMP\` for new `.ts` | Calls `FeedSegment` on the manager (locks `m_lock`) |
| Kad UDP listener | `CKademliaUDPListener::Process()` | Runs `Process_ESE_HOLEPUNCH_REQ/ACK` |
| uTP / libutp | `CUtpSocket::Process()` | Reads NAT-traversed UDP packets |
| ListenSocket | TCP accept + dispatch | Routes `OP_LIVE_*` to `CLiveStreamManager::On*` |

`CLiveStreamManager` uses one `CCriticalSection m_lock`. The broadcaster's
proactive push (Sprint 1 BOOT-5 refined) **builds packets under the lock**,
**releases the lock**, then sends — so socket I/O never blocks the watcher
that's feeding chunks in.

---

## 11. State persistence

| Path | What |
|---|---|
| `%LOCALAPPDATA%\eMule\config\preferences.ini` | All eMule prefs (port, UPnP, etc.) |
| `%LOCALAPPDATA%\eMule\config\nodes.dat` | Kad routing-table seed |
| `%APPDATA%\eMule\config\eSE_seen.flag` | First-run wizard dismissed (Sprint 2.1) |
| `%TEMP%\eMule_RTMP\` | Live HLS dir (cleaned on graceful shutdown — Sprint 2 E.4) |

---

## 12. Known limits & roadmap

- 16-segment ring buffer (uint16 bitmap). Going beyond requires a wire format change.
- Single broadcast at a time per emule.exe instance (multi-stream is Sprint 5+ territory).
- IPv4 only (eMule core).
- Symmetric NAT bilateral: hole-punch fails ~30-50% of the time. Cloudflare tunnel
  is the manual opt-in fallback (Tier 3.1 / F.6).
- No E2E encryption of stream content (only Kad signaling is encrypted).
