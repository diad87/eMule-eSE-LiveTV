# eSE Live: Decentralized Live Streaming on a Veteran File-Sharing DHT

**Author:** Iñaki Unanue
**Affiliation:** Independent
**Version:** 1.0 — 2026-05-17
**Status:** Pre-print
**Code:** [github.com/diad87/eMule-eSE-LiveTV](https://github.com/diad87/eMule-eSE-LiveTV)

---

## Abstract

We present **eSE Live**, an extension to eMule (a long-lived eD2K +
Kademlia [Kad] file-sharing client) that adds first-class support for
**P2P live broadcasting**. The system shares the same overlay,
transport, and discovery substrate as conventional file sharing — no
trackers, no CDNs, no central indexer — yet sustains real-time
chunked video distribution between unrelated peers with sub-second
discovery on the local network and 3-second discovery across a warm
mesh. We extend the eD2K wire protocol with five backward-compatible
opcodes that introduce live capability negotiation, RTT measurement,
and **peer-exchange gossip of recent streams**, allowing live
directories to propagate virally in `O(log N)` heartbeats. We
complement Kad-based discovery with two additional decentralized
layers: an mDNS-style UDP multicast on the LAN and a per-client
bootstrap cache, eliminating cold-start latency in the most common
scenarios. We describe a complete implementation across a hybrid C++
(MFC) + Node.js codebase, totalling 20 new C++ source files, 64 new
JavaScript modules, and the addition of 25 HTTP API endpoints. We
report an end-to-end verification of a real broadcast crossing two
hosts on different ISPs, with the receiver reconstructing the HTTP
Live Streaming (HLS) playlist directly from eD2K chunks. We discuss
the bandwidth economics that make the architecture sustainable beyond
the broadcaster's own uplink capacity, the tier-based topology that
limits direct-viewer fanout, and a security model that keeps the
local administration surface confined to loopback. We close with a
roadmap to scale from the currently-validated 10–20 viewers per
stream to several thousand using techniques borrowed from recent P2P
literature: SRT transport, random linear network coding, and gossip
membership protocols.

**Keywords:** peer-to-peer live streaming, Kademlia, eD2K, DHT,
decentralized systems, HLS, censorship resistance, NAT traversal,
mesh networking, adaptive bitrate.

---

## 1. Introduction

Live video on the public Internet today depends almost exclusively on
**centralized infrastructure**: Content Delivery Networks (Akamai,
Cloudflare, Fastly), proprietary platforms (Twitch, YouTube Live), or
single-tenant deployments. This model concentrates trust, censorship
risk, and operating cost in a small number of administrative
boundaries. The same model dominates *recorded* video as well, but
recorded media has thriving decentralized alternatives — most
prominently BitTorrent and its many derivatives — that have been
operationally significant for over two decades. **Live media has no
equivalent decentralized success story at production scale.**

This work asks a focused question: *can a peer-to-peer file-sharing
network designed in 2000 — eD2K plus its Kademlia DHT — be retrofitted
to carry live streams without sacrificing the properties that made
the file-sharing variant durable (no central server, censorship
resistance, organic peer participation)?*

We answer affirmatively and present **eSE Live**, a fork of the
eMule 0.70b client (released 2022-12-19 by the eMule Project) that
adds:

1. A **live broadcasting subsystem** that ingests RTMP from any
   off-the-shelf encoder (OBS, FFmpeg), transcodes to multi-bitrate
   HLS, and publishes the resulting chunks as eD2K resources.
2. A **viewer subsystem** that reassembles the HLS playlist locally
   from chunks fetched over the existing eD2K transport, allowing
   any HLS-capable player (VLC, browser HTML5 video) to play the
   live feed.
3. **Three decentralized discovery layers** — DHT publish/search,
   peer-exchange gossip in the existing heartbeat, and LAN UDP
   multicast — that combine to give sub-second discovery on the LAN,
   ~3 second discovery on a warm mesh, and <5 second cold start when
   the bootstrap cache is non-empty.
4. **Bandwidth economics** (tiered classification by upload capacity,
   ratio enforcement, viewer-as-secondary-source publication) that
   sustain network capacity sublinearly in the number of viewers,
   rather than exhausting the broadcaster's uplink.
5. A **modern web dashboard** that replaces the legacy MFC UI as the
   primary user surface for live content, while preserving the
   classic interface for the file-sharing functionality the upstream
   client provides.

### 1.1 Contributions

- We design and implement five **backward-compatible** wire-protocol
  extensions that turn eD2K peers into live-aware peers without
  breaking interoperability with unmodified upstream clients
  (Section 3.3).
- We characterize a **three-layer decentralized discovery** stack
  combining DHT, peer-exchange gossip, and LAN multicast that
  empirically outperforms either layer alone in the common case
  (Section 3.2).
- We document a **complete end-to-end implementation** in 20 new C++
  files (~5,800 LOC), 64 new Node.js modules (~12,000 LOC), and 25
  new HTTP endpoints, available under GPL-2.0 (Section 4).
- We report a **verified cross-host broadcast** (PC1 → PC2,
  different ISPs, 2026-05-15) and characterize discovery latency
  along each layer (Section 5).
- We articulate the **bandwidth economics** required for the
  architecture to scale beyond the broadcaster's local uplink
  (Section 6).

### 1.2 Non-goals

We do **not** claim to replace CDN-backed live streaming for
audiences of millions; the current implementation has been validated
empirically up to ~10–20 viewers per stream and we are explicit about
the design changes (Section 7) required to push that into the
thousands. We do not provide content moderation, copyright
enforcement, or any centralized administrative function — these are
deliberate non-features inherited from the eD2K substrate.

### 1.3 Paper structure

Section 2 surveys related work in P2P live streaming and the eD2K /
Kad lineage. Section 3 presents the system design across discovery,
transport, topology, encoding, and economics. Section 4 describes the
implementation. Section 5 evaluates the deployed system. Section 6
discusses limitations, Section 7 future work, and Section 8
concludes.

---

## 2. Background and Related Work

### 2.1 The eD2K / Kad substrate

The eDonkey 2000 (eD2K) network was launched in 2000 by Jed McCaleb
[1] and reached its mainstream form through the eMule client
[2]. Files are identified by a hierarchical MD4-based hash and
distributed across a heterogeneous swarm of peers. From 2004 onward,
eMule integrated a **Kademlia** [3] distributed hash table (Kad) to
replace the original eD2K server architecture, providing
serverless keyword and source lookup. The combined eD2K + Kad system
has been studied as a measurement target (Steiner et al. [4]) and is
operationally significant even today, with the eMule Project
continuing to release maintenance versions (the most recent being
0.70b, December 2022).

Two properties of the eD2K + Kad substrate are critical to our work:

- **Existing peer base.** Any node already running eMule can be
  reused — there is no bootstrap problem unique to our application.
  The DHT is hardened against churn and Sybil attacks by twenty
  years of operational adversarial pressure.
- **Censorship resistance.** Without a central index or trackers,
  there is no party that can be served a takedown notice for
  content discovery. Individual peers can be blocked at the network
  layer, but the directory itself has no single point of failure.

The properties we *need to add* relate to **liveness**: eD2K is
optimized for content that does not change (a movie file is constant
once published), whereas live streaming requires continuous
publication of new chunks, fast freshness invalidation when a
broadcaster stops, and tight latency bounds on chunk delivery.

### 2.2 Decentralized live streaming

The literature on P2P live streaming clusters into three eras:

**(a) Tree-overlay systems (early 2000s).** Single-tree multicast
overlays such as ESM [5] and Narada [6] showed that application-layer
multicast was feasible but suffered from poor recovery under churn:
the loss of any interior node disconnects an entire subtree.

**(b) Mesh-pull systems (mid-2000s).** Chunk-based mesh systems such
as PPLive [7], SOPCast, CoolStreaming [8] dominated practical
deployment. Each viewer maintains a small set of neighbors and pulls
missing chunks reactively. PPLive in particular reached millions of
concurrent users on broadcast events in China during 2006–2010.
However, all of these depended on **central trackers** for
peer-list bootstrap; the protocols themselves were proprietary and
none survived as open community infrastructure beyond a few years.

**(c) Modern DHT- and gossip-based systems (2010s–today).** Tribler
[9] integrates live streaming on top of BitTorrent's mainline DHT.
PeerTube [10] uses federated WebTorrent for hybrid CDN-assisted
streaming. PULSE [11] uses HyParView / Plumtree gossip [12,13] to
build a partial-membership overlay with sub-second cross-continent
chunk delivery. None of these has reached the mainstream visibility
of the tracker-based 2000s systems, but they constitute the design
space we draw from.

The closest commercial relative is **BitTorrent Live**, BitTorrent
Inc.'s 2013 live-streaming product based on the proprietary "Mosaic"
protocol; it was discontinued in 2017 and never released as open
source.

### 2.3 Modern alternatives

For completeness we note three contemporary approaches we explicitly
do not adopt:

- **WebRTC-based** systems (Janus, Galène, peer.js) provide
  sub-second latency over browser-mediated SCTP/RTP but rely on
  centralized signaling and TURN servers; the discovery problem is
  unsolved.
- **CDN-assisted P2P** (Peer5, Streamroot) offloads up to 80% of
  viewer egress to peers but requires a central CDN as the source
  of truth — exactly the centralization we aim to eliminate.
- **Federated streaming** (PeerTube, Owncast) replaces a single CDN
  with a federation of independent servers. This is a step toward
  decentralization, but each "instance" remains a single
  administrative entity subject to local pressure.

### 2.4 Why retrofit eD2K rather than design from scratch?

A common reaction is: *if you want a new live-streaming P2P system,
why not start from a modern transport and DHT?* Three reasons:

1. **Existing user base.** The eD2K network still has on the order
   of 10^5 concurrent peers worldwide. A green-field design starts
   with zero.
2. **Existing trust attestation.** eMule has been compiled by tens
   of millions of distinct users since 2002 and audited (informally)
   by the file-sharing community. Greenfield code has none of that
   history.
3. **Existing institutional knowledge.** NAT traversal, source
   exchange, peer reputation, partfile recovery — all of these are
   solved and battle-tested in the eMule codebase. We inherit them
   for free.

The cost of this choice is that we work inside an MFC (Microsoft
Foundation Classes) C++ codebase from a previous era, with the
attendant maintenance and modernization overhead (see Section 6.2).

---

## 3. System Design

### 3.1 Overview

Figure 1 (conceptual) summarizes the data flow on the
broadcaster and viewer sides:

```
  BROADCASTER                          MESH                  VIEWER

  ┌──────────┐    rtmp://127.0.0.1                       ┌──────────┐
  │   OBS    │ ─────────────────►                        │   VLC    │
  │ (or any  │                                           │ or browser│
  │  RTMP    │                                           │ HTML5     │
  │ encoder) │                                           │ <video>   │
  └──────────┘                                           └──────────┘
       │                                                       ▲
       ▼                                                       │
  ┌──────────┐                                           ┌──────────┐
  │ RTMP     │                                           │ Local    │
  │ Ingest   │ (port 1935)                               │ HLS      │
  │ Listener │                                           │ Server   │
  └──────────┘                                           └──────────┘
       │                                                       ▲
       ▼                                                       │
  ┌──────────┐    ┌──────────┐                                 │
  │ FFmpeg   │ -> │ HLS      │                                 │
  │ pipeline │    │ chunks   │ (4s, multi-bitrate ABR)         │
  │ (HW enc) │    │ on disk  │                                 │
  └──────────┘    └──────────┘                                 │
                        │                                      │
                        ▼                                      │
                  ┌──────────────────────────────────────┐    │
                  │   Publish chunks as eD2K resources   │    │
                  │   Publish stream key to Kad DHT      │    │
                  │   Announce on LAN multicast (5354)   │    │
                  │   Embed top-5 streams in heartbeat   │    │
                  │     PEX gossip                       │    │
                  └──────────────────────────────────────┘    │
                                  │                            │
                                  │                            │
                                  ▼                            │
                  ┌──────────────────────────────────────┐    │
                  │            eD2K + Kad mesh           │    │
                  │   (TCP + UDP, NAT-traversed)         │    │
                  └──────────────────────────────────────┘    │
                                  │                            │
                                  │ Chunk request /            │
                                  │ Chunk response opcodes     │
                                  ▼                            │
                  ┌──────────────────────────────────────┐    │
                  │   Viewer: discover stream (3 layers) │    │
                  │   Viewer: dial broadcaster + relays  │    │
                  │   Viewer: reassemble HLS chunks      │ ───┘
                  │   Viewer: serve local m3u8           │
                  └──────────────────────────────────────┘
```

The architecture is conventional in its outline (RTMP-in / HLS-out
with chunk-pull P2P in the middle) and **novel only in the
substrate it operates on** — every prior chunk-pull live-streaming
system has used a bespoke overlay; we are the first, to our
knowledge, to deploy this pattern on the eD2K + Kad network.

### 3.2 Discovery: three decentralized layers

Stream discovery is the operation by which a viewer learns of the
existence and current network endpoint of a broadcaster, given only
the broadcaster's stream key (a 16-byte identifier). The three
layers we deploy in parallel are:

**Layer 1 — DHT publish/search (Kad).** The broadcaster publishes
its IP:port under the Kad keyword `live:<HEXKEY>` with a deliberately
short TTL of 60 seconds (vs the default 5 hours for files), so that
crashed or stopped broadcasters disappear from the directory within
one TTL period. Viewers issue Kad searches; results are validated
(IP:port sanity-checked, viewer count and bitrate clamped against
plausible upper bounds to defend against Sybil-flooding attacks).

To accelerate viewer-to-viewer recruitment we add a second Kad
keyword `livehash:<HEXKEY>` published by **viewers** (not
broadcasters) once their local chunk buffer exceeds 5 chunks. A
fresh viewer searching for the stream therefore finds not only the
broadcaster but every relay-capable viewer, allowing the tree
topology (Section 3.4) to form organically without explicit
coordination.

**Layer 2 — Peer-exchange gossip in the live heartbeat.** Every
60 seconds, each peer holding the live-capability bit sends an
`OP_LIVE_HEARTBEAT` opcode to its mesh neighbors. We extend the
payload format from the original 22 bytes to a variable 23–133 bytes
that carries the peer's top-5 most-recently-observed streams (their
keys, IPs, and ports). Receivers merge these entries into their
local stream directory via the same code path as Kad search results,
inheriting all existing rate-limiting, deduplication, and IP-filter
logic.

The wire format is **bit-flagged for backward compatibility**: an
upstream eMule client without the live-capability bit ignores the
trailing PEX block as protocol slop. We measured no observed
disruption on a mixed mesh of 6 peers running fork + upstream
clients during a 24-hour soak.

The propagation dynamics are viral: in a mesh of `N` peers where
each peer reports the 5 streams it has seen, every peer learns of
every "popular" stream (one observed by 5 or more peers) in
`O(log N)` heartbeats — empirically ~3 heartbeats (3 minutes) for
meshes of 50 peers in our internal testing.

**Layer 3 — LAN UDP multicast (mDNS-style).** Many real-world
viewer scenarios occur within a single LAN: a home network sharing a
broadcast with family members, an office showing a presentation, a
LAN party. For these cases we deploy a per-broadcaster announcement
on the standard mDNS multicast group `224.0.0.251` (already
permitted on essentially every consumer router) but on a deliberately
non-conflicting port `5354` (Bonjour is on `5353`). The payload is
a plain-text 7-line record:

```
eSE-LAN/1.0
hash: <32-hex-streamKey>
ip: <broadcaster-LAN-IP>
port: <broadcaster-eD2K-TCP-port>
title: <stream-title>
bitrate: <kbps>
category: <free-form>
language: <ISO-639-2>
```

Announcements are emitted every 30 seconds with TTL=1 (never escapes
the subnet). Listeners filter out their own IPs to avoid loops.
Sub-second cross-LAN discovery is the norm.

**Layer 4 — Bootstrap cache.** A persistent per-client cache stored
at `%APPDATA%\eMule\last_streams.json` records the last 20 streams
the user successfully joined, including the most recent IP:port for
each. On startup, before Kad bootstrap completes, the client pings
these endpoints directly. In the common case where the user is
re-joining a favorite stream and the broadcaster is still on the same
endpoint, this delivers the first chunk in under 5 seconds — versus
the 30–120 seconds typical of cold Kad search.

### 3.3 Transport: wire-protocol extensions

We add five new opcodes to the eD2K wire protocol:

| Opcode | Bytes | Purpose |
|---|---|---|
| `OP_LIVE_HEARTBEAT` | 23–133 | Periodic peer state + PEX (top-5 streams) |
| `OP_LIVE_CHUNK_REQUEST` | 20 | Request chunk *N* for stream *K* |
| `OP_LIVE_CHUNK_RESPONSE` | variable | Chunk payload (typically 1–8 KiB) |
| `OP_LIVE_PING` (0xE7) | 16 | RTT probe — viewer to peer |
| `OP_LIVE_PONG` (0xE8) | 16 | RTT response — echoes timestamp |

All five are gated by a capability bit advertised during the eD2K
hello handshake. Peers without the bit are never sent live opcodes,
preserving full forward and backward compatibility.

Chunk transport reuses eD2K's existing TCP framing for chunk content
and Kad's existing UDP framing for ping/pong. We deliberately avoid
introducing a third transport (e.g. WebRTC data channels) in this
release; transport modernization is enumerated as future work in
Section 7.

NAT traversal reuses eMule's existing UDP hole-punching machinery,
with one extension: hole-punch signaling payloads are now encrypted
with a peer-derived AES-128 key to prevent passive observers from
correlating broadcast endpoints with stream identifiers.

### 3.4 Topology: tree with multi-parent and mesh fallback

We constrain the topology with three rules:

1. **Direct fanout cap.** No broadcaster serves more than 10 direct
   viewers. The 11th and subsequent viewers must be served by other
   viewers (relays).
2. **Multi-parent.** Each non-broadcaster peer maintains at least 3
   parents in steady state: one primary (lowest RTT) and 2 warm
   spares. Missing chunks trigger a request to a spare without waiting
   for the primary to time out.
3. **Mesh fallback.** Each peer publishes a *bitmap* of currently-held
   chunks; when a viewer detects a gap (e.g. due to packet loss or
   parent churn), it queries the bitmaps of its parents and any peer
   it has recently exchanged heartbeats with, fetching the missing
   chunk from whoever has it with the lowest measured RTT.

The combination yields **median 200 ms recovery from parent loss** in
our internal stress tests, versus the 5+ seconds typical of pure
single-tree overlays. This is the principal architectural lesson we
took from the mesh-pull literature (Section 2.2).

A simplified pseudocode for the chunk-request loop on the viewer:

```
for each missing chunk c in window [tail, head + 3]:
    candidates = parents ∪ recently_pexed_peers
    candidates = filter(candidates, p => p.bitmap.has(c))
    candidates = sort_by_rtt(candidates)
    if candidates is empty:
        // Anycast: search livehelp:<streamKey> in Kad
        candidates = kad_search("livehelp:" + streamKey)
    pick = candidates.head
    send OP_LIVE_CHUNK_REQUEST(pick, c)
    schedule_retry(pick, c, timeout=300 ms)
```

### 3.5 Encoding and playback

The broadcaster's local pipeline ingests RTMP on port 1935 (the
de-facto standard), pipes the stream through FFmpeg for transcoding,
and emits HLS chunks of 4 seconds each in up to four resolution
variants (360p, 540p, 720p, 1080p). The FFmpeg invocation
auto-detects available hardware encoders at startup, preferring (in
order): NVIDIA NVENC → Intel QSV → AMD AMF → x264 software fallback.
Failing detection (e.g. on a server without GPU) the system falls
back to a 540p-cap CPU encode that preserves wide compatibility at
the expense of resolution.

We adopt three small but important details from production live
systems:

- **Independent segments.** Every variant emits the
  `EXT-X-INDEPENDENT-SEGMENTS` directive, ensuring that chunk
  boundaries are I-frame aligned and a viewer can switch variant on
  any chunk boundary without a black frame.
- **YouTube-style prebuffer.** The broadcaster does not return
  control to the user from `Start Broadcast` until 3 chunks
  (~12 seconds) have been encoded and published. This eliminates the
  "live edge → empty buffer → black screen" failure mode that
  afflicts naive live deployments.
- **Audio defaults.** The HLS master playlist marks only the first
  audio track as `DEFAULT=YES`, with secondary tracks (e.g. dub
  language) marked `AUTOSELECT=NO`. We hit a real regression where
  multiple `DEFAULT=YES` tracks caused VLC to truncate the audio
  stream after 3.4 seconds.

The viewer side hosts a tiny local HLS server (the same C++
WebServer used for the legacy eMule web UI), which serves the
reassembled `master.m3u8` and per-variant chunk files to any HLS
player on the local machine. Browser HTML5 `<video>` and VLC both
work without configuration; the user perceives a normal HLS stream.

### 3.6 Bandwidth economics

The architecture's ability to scale beyond the broadcaster's local
uplink depends on a **mandatory upload contribution** from each
viewer. The mechanism has three parts:

1. **Tier classification.** At startup, each peer measures its
   recent upload capacity from the user's `MaxUpload` preference (a
   value already maintained by eMule for file-sharing) and is
   classified into one of five tiers:

   | Tier | Min upload | Max concurrent uploads served |
   |---|---|---|
   | LEAF_RESTRICTED | 0 | 0 (pure consumer) |
   | LEAF | 128 kbps | 1 |
   | MID | 512 kbps | 3 |
   | SUPER_SEEDER | 2 Mbps | 10 |
   | MEGA_SEEDER | 8 Mbps | 25 |

2. **Ratio enforcement.** A 60-second sliding window tracks the
   ratio of each peer's served bytes to received bytes. Peers below
   0.4 are throttled to drop 4 out of 5 chunk requests; peers between
   0.4 and 0.7 are throttled to drop 1 in 5. Peers ≥0.7 are unaffected.
   The throttle is *not* applied to the first 5 viewers of a stream,
   allowing bootstrap before the network effect engages.

3. **Viewer-as-secondary-source.** Once a viewer's chunk buffer
   exceeds 5 chunks (~20 seconds), it publishes itself to Kad under
   `livehash:<streamKey>` and accepts chunk requests from other
   viewers up to its tier's cap. This is the mechanism by which
   demand for a popular stream creates supply.

Provided ratio enforcement is active and broadcasters cap their
direct fanout (Section 3.4), aggregate available bandwidth grows
roughly linearly in the viewer count, supporting the architecture's
claim of "more viewers = more capacity" — *more viewers = more
capacity* — rather than the more common "more viewers = collapsed
broadcaster".

---

## 4. Implementation

The system is implemented as a fork of the eMule 0.70b client. The
codebase is hybrid:

- A **C++ MFC (Microsoft Foundation Classes)** core, implementing
  the live subsystem in 20 new source files (~5,800 LOC) alongside
  modifications to ~30 existing eMule files (~1,200 LOC of changes,
  each annotated with GPL-2 §2(a) notice comments).
- A **Node.js dashboard** packaged via [`pkg`](https://github.com/vercel/pkg)
  into a single ~55 MB `ese-server.exe` executable, comprising 64
  JavaScript modules (~12,000 LOC) hosted on TCP port 8080.

The two halves communicate via local HTTP: the Node side proxies
requests to the C++ side via `http://127.0.0.1:4711/api/live/*`. A
strict **loopback-only gate** rejects any non-`127.0.0.1` request to
the live API (Section 4.4).

### 4.1 Codebase organization

The 20 new C++ files cluster into three groups:

- **Protocol / wire:** `LivePackets.{h,cpp}`, `LiveProtocol.{h,cpp}`,
  `LiveKadBridge.{h,cpp}` — opcode definitions, serialization, Kad
  publish/search wrappers.
- **State and topology:** `LiveStreamManager.{h,cpp}`,
  `LiveMeshManager.{h,cpp}`, `LiveChunkBuffer.{h,cpp}` — viewer/peer
  state machine, tree topology with multi-parent, sliding chunk window.
- **I/O and UX:** `RTMPIngest.{h,cpp}` (broadcaster pipeline),
  `LiveStreamDlg.{h,cpp}` (MFC UI tab), `LiveDebugLog.{h,cpp}`
  (in-memory ring buffer exposed via HTTP).

The Node side is organized into `pages/` (UI routes), `routes/`
(REST endpoints), `eSE-live/` (live-specific modules: thumbnail
extraction, LAN discovery, channel API, cinema player), and `shared/`
(cross-cutting utilities including the `safe_dom.js` XSS-resistant
DOM helper).

### 4.2 Wire-protocol extensions

The five new opcodes (Section 3.3) are dispatched from
`ListenSocket.cpp` (TCP) and `UDPSocket.cpp` (UDP) into the
`LiveProtocol::OnPacket` and `LiveProtocol::OnUDPPacket` handlers
respectively. Backward compatibility is preserved by gating dispatch
on the live-capability bit advertised in the eD2K hello handshake;
peers without the bit are never sent live opcodes, and incoming live
opcodes from un-advertised peers are silently dropped.

The PEX extension to `OP_LIVE_HEARTBEAT` uses a length-prefixed TLV
trailing block. A receiver that does not understand the trailing
block (e.g. an older fork that pre-dates the extension) simply
truncates parsing at byte 22, which is the original heartbeat size.
This is the same wire-extension pattern used by BitTorrent's
extension protocol [14].

### 4.3 Local pipeline

The broadcaster's `RTMPIngest::Start()` method spawns a child
FFmpeg process with a command line constructed at runtime to match
the detected hardware encoder. For NVIDIA NVENC the relevant
fragment is:

```
ffmpeg -listen 1 -i rtmp://127.0.0.1:1935/live/stream
  -filter_complex "[0:v]split=4[v1][v2][v3][v4];
                   [v1]scale=640:360[v1s];
                   [v2]scale=960:540[v2s];
                   [v3]scale=1280:720[v3s];
                   [v4]scale=1920:1080[v4s]"
  -map "[v1s]" -c:v h264_nvenc -b:v 600k -g 48 -keyint_min 48
  -map "[v2s]" -c:v h264_nvenc -b:v 1200k -g 48 -keyint_min 48
  -map "[v3s]" -c:v h264_nvenc -b:v 2500k -g 48 -keyint_min 48
  -map "[v4s]" -c:v h264_nvenc -b:v 5000k -g 48 -keyint_min 48
  -map 0:a -c:a aac -b:a 128k -ar 48000 -ac 2
  -f hls -hls_time 4 -hls_list_size 20
  -hls_segment_type mpegts
  -hls_flags independent_segments+omit_endlist+program_date_time
  -master_pl_name master.m3u8
  ...output paths...
```

The `-g 48 -keyint_min 48` flags force keyframes every 48 frames
(2 seconds at 24 fps), aligned with the `-hls_time 4` so that each
chunk begins on a keyframe and viewer-side variant switching is
seamless.

A watcher process polls the FFmpeg output directory every 250 ms,
detects newly-emitted `seg_NNNNN.ts` files, and publishes each as an
eD2K resource keyed by the stream key + sequence number. We hit a
specific regression here, fixed in a recent commit: the watcher's
filename parser previously treated `seg_eng_13697.ts` (an audio-only
variant) as the highest-numbered video segment, causing the chunk
buffer to never advance. The fix is a 4-line regex that rejects
filenames with any non-digit characters between `seg_` and `.ts`.

### 4.4 Security model

The local administration surface is confined to TCP loopback. Every
endpoint under `/api/live/*`, `/api/holepunch/*`, `/api/status`,
`/dashboard`, and `/hls/*` checks the connecting peer's IP against
`htonl(INADDR_LOOPBACK)` and returns HTTP 403 with a logged
diagnostic for any non-loopback source. This prevents a curious or
hostile LAN peer (e.g. someone the user has admitted via the
classic `AllowedRemoteAccessIPs` for file-sharing) from
inadvertently controlling the live subsystem.

Two cross-site scripting (XSS) vulnerabilities were identified
during a 2026-05-16 security review: broadcaster-controlled
`title` / `category` / `quality` strings were interpolated unescaped
into the inline `/live` and `/live/{hash}` pages served from the C++
WebServer. A malicious broadcaster could publish a stream with a
title of `<img src=x onerror=fetch("/api/live/broadcast/stop")>` and
trigger script execution in any viewer's browser that opened the
legacy page, with access (under the loopback origin) to every
"protected" `/api/live/*` endpoint. The fix is a minimal inline
`esc()` helper applied at every concatenation point. The modern
Node-side dashboard at port 8080 was already safe (consistent use of
an `escH()` helper), but it is worth noting that even the loopback
gate does not protect against an XSS payload running in the user's
own browser — the gate protects against *remote* attackers, not
against *content* attackers reachable through the user's own
trusted-origin browser.

The HLS chunk endpoint validates the request path against a strict
allowlist regex (`stream.m3u8`, `stream_*.m3u8`, `seg_*.ts`, with no
`..` or `/` characters permitted), preventing directory traversal.

---

## 5. Evaluation

We report measurements from internal testing on commodity hardware.
We make no claim of statistical significance; the results are
illustrative of the system's order-of-magnitude behavior.

### 5.1 End-to-end verification

On 2026-05-15 we conducted the first cross-host live broadcast
test:

- **PC1 (broadcaster):** Windows 11, NVIDIA RTX 3070, residential
  ISP (Symmetric 600 Mbps fiber).
- **PC2 (viewer):** Windows 10, Intel iGPU, mobile-hotspot
  connection (LTE, ~30 Mbps down).

PC1 opened OBS, configured `rtmp://127.0.0.1:1935/live` as the
target, and started a desktop-capture broadcast at 1080p / 5000 kbps.
Within 8 seconds, the FFmpeg pipeline produced the first multi-variant
HLS chunk; within 12 seconds (the prebuffer threshold), the stream
was published to Kad and the broadcaster's dashboard showed the
stream tile.

PC2 received the `ed2k://|live|<HEX>|<IP>:<PORT>|<TITLE>|/` link
via out-of-band channels (the user pasted it from the broadcaster's
dashboard), entered it into the `/live` paste-link field, and within
3 seconds was watching the stream in VLC. The viewer's local
`master.m3u8` was a byte-for-byte (modulo `EXT-X-START` tag)
reconstruction of the broadcaster's playlist, with chunk content
fetched over the eD2K mesh.

This is the formal "P2P live verified end-to-end" milestone
referenced in our project notes.

### 5.2 Discovery latency

Table 1 summarizes discovery latency for the four scenarios that
correspond to each of our discovery layers, plus an "all layers
miss" fallback:

| Scenario | Layer used | Median time-to-first-chunk |
|---|---|---|
| Re-join recently-watched stream | Bootstrap cache | **4.7 s** |
| New stream on same LAN | mDNS multicast | **0.9 s** |
| New stream, broadcaster known to a mesh neighbor | PEX gossip | **3.2 s** |
| New stream, only DHT publication | Kad search | **38 s** |
| Worst case: cold cache, no LAN, no PEX, slow Kad | Kad search (slow) | **115 s** |

The Kad-search median of 38 seconds is consistent with general
measurement studies of Kad lookup latency under churn [4]; our
contribution is **not** to improve Kad search but to *render Kad
search non-load-bearing in the common case* via the three
complementary layers.

### 5.3 Multi-instance stress

We exercise the architecture's load behavior using a Node.js
orchestrator that spawns up to 50 headless eMule instances on a
single host. Each instance is given a unique `--tcp-port`,
`--udp-port`, `--metrics-port`, and (since shared `UserHash` would
cause self-rejection) a freshly regenerated user hash. The
orchestrator collects `/api/live/metrics` from each instance every
2 seconds and renders the result in a real-time dashboard.

Single-host stress is limited by the fact that all "peers" share the
same NIC and contend for the same socket buffers; we observe
graceful behavior up to ~20 simultaneous instances per stream
before the per-instance chunk-drop rate exceeds 1%. **We make no
claim about behavior beyond this point** — the validation of
larger swarms requires multi-host deployment, which we document as
open work in Section 7.

---

## 6. Discussion and Limitations

### 6.1 What the architecture demonstrably does

- It carries live video chunks over the eD2K + Kad substrate with
  end-to-end latency that is competitive with mainstream HLS-over-CDN
  for non-interactive live content (~10–15 seconds glass-to-glass).
- It discovers streams without any central index in three independent
  ways, each empirically faster than the others under specific
  conditions.
- It respects existing eD2K interoperability — peers running
  unmodified upstream eMule are not disrupted, and remain useful as
  file-sharing peers.
- It survives broadcaster churn: when the broadcaster disconnects,
  a tombstone is published to Kad and propagated via PEX so that
  viewers see the stream end within 30 seconds.

### 6.2 What it does not yet do

- **Audiences beyond ~20 viewers per stream.** Single-host stress
  hits this ceiling. Multi-host validation is pending.
- **Sub-second latency.** Current end-to-end is dominated by the
  HLS 4-second chunk duration plus the 3-chunk prebuffer; reducing
  either requires moving off HLS-as-protocol toward something like
  WebRTC or SRT (Section 7).
- **Content moderation.** We provide no tools for any party to
  remove content from circulation. This is a deliberate non-feature
  inherited from the eD2K substrate.
- **Identity binding.** A stream key is a 16-byte ephemeral
  identifier; nothing in the system binds it to a stable broadcaster
  identity. Anti-impersonation requires out-of-band channels (e.g.
  the broadcaster sharing the stream key via a trusted website or
  signed message).

### 6.3 Implementation realities

The choice to fork an MFC C++ codebase from 2000-era design has
two specific costs we encountered:

- **String-formatting bugs.** We crashed once at `t=8s` of every
  run due to a `%S` format specifier (expecting `LPCWSTR`) receiving
  an integer cast (`UPNP_IMPL_MINIUPNPLIB`). The bug was diagnosed
  via `/MAP` linker flag, minidump capture, and manual symbol
  resolution. Modern alternatives like `std::format` (C++20) catch
  this at compile time; our codebase predates C++17.
- **Synchronous network stack.** The eMule transport layer is
  built on MFC `CAsyncSocket` / `CSocket`, which do not scale past
  a few hundred connections. We worked around this by capping
  direct fanout per peer (Section 3.4), but a deep rewrite onto
  IOCP or `asio` is required for the next order of magnitude in
  scale.

We catalogued these and 14 other "this was 2005-fine, 2026-not-fine"
modernization candidates in a separate internal document.

### 6.4 Threat model

The system is designed to resist three threat classes:

- **Censorship of discovery.** Defended by the lack of any central
  index — there is no party to issue takedown notices to. Discovery
  cannot be denied without taking down the entire Kad network, an
  outcome no actor has achieved in twenty years.
- **Censorship of distribution.** Defended only weakly: a powerful
  network-level adversary (ISP, national firewall) can block
  individual peer IPs but not the protocol as a whole, given the
  proliferation of NAT-traversed UDP traffic. Tor-style anonymity
  is not provided.
- **Sybil flooding of the directory.** Defended by sanity-clamping
  of advertised metrics (viewer counts capped at 100,000, bitrates
  rejected above 50 Mbps), and by the limited utility of fake
  entries (they fail to deliver chunks, so viewers fall back to
  legitimate sources within seconds).

The system is **not** designed to resist:

- **Content moderation.** No party can prevent legal content; no
  party can ensure illegal content.
- **Traffic analysis.** An observer on the broadcaster's uplink
  can trivially distinguish live-streaming traffic from file
  sharing by packet timing.
- **Compromise of the broadcaster's machine.** A broadcaster
  whose machine is compromised loses the ability to make
  authenticity claims about their stream.

---

## 7. Future Work

### 7.1 Transport modernization

The next major architectural lift is replacing TCP-on-eD2K chunk
delivery with **SRT** (Secure Reliable Transport, RFC draft;
implementation `libsrt` 1.5+) on the live path. SRT provides
inherent encryption (AES-256), configurable end-to-end latency
(target 120 ms), and survives 5–10% packet loss without
retransmission storms. Co-design with Random Linear Network Coding
(RLNC) [15] would further allow any K chunks from any subset of N
peers to reconstruct the original content, eliminating the need for
explicit retransmission requests.

### 7.2 Sub-second latency via WebRTC bridge

For audiences willing to use a modern browser, a WebRTC bridge on
the broadcaster side would offer sub-second glass-to-glass latency
for viewers, while the eD2K mesh continues to serve as the
distribution backbone. The browser is the WebRTC terminator, the
eD2K peer is the WebRTC initiator, and the cross-protocol gateway
is implemented in the Node dashboard.

### 7.3 Gossip membership for scale

Beyond ~5,000 viewers per stream, the current pair-wise overlay
maintenance becomes the bottleneck. **HyParView** [12] + **Plumtree**
[13] gossip protocols are the standard answer in the literature and
have been deployed in production at companies like Bleemeo and on
Erlang/OTP's `partisan` framework. Adapting these to a heterogeneous
fork like eMule is non-trivial but well-understood; we estimate
~3–4 weeks of full-time engineering.

### 7.4 End-to-end encrypted payloads

For broadcasters who want to control viewer access, a per-stream
AES-256-GCM encryption layer applied per chunk would allow
distribution over the (still-anyone-can-relay) mesh while keeping
payload confidential. The key distribution problem is solved
out-of-band (the broadcaster shares the key via a side channel of
their choice).

### 7.5 Onion routing for anonymity

The current system reveals broadcaster IP to viewers and viewer IP
to broadcaster (this is the cost of direct P2P). For threat models
that require anonymity, a Tor-style multi-hop onion-routed delivery
path is a credible extension, drawing on prior work by the I2P and
Garlicat communities. The cost is several seconds of additional
end-to-end latency per hop.

---

## 8. Conclusion

We have presented eSE Live, a working extension of a twenty-year-old
file-sharing client into a live-broadcasting platform that requires
no central servers, no CDN, and no operating-cost beyond what the
broadcaster's own connection imposes. The system has been verified
end-to-end across two hosts on different ISPs and exhibits
discovery latency competitive with mainstream alternatives across
the common scenarios its three-layer discovery stack covers.

Our principal claim is **architectural**: a veteran DHT designed for
file sharing can carry live media with a small, backward-compatible
set of protocol extensions, and the resulting system inherits the
political and operational properties (no central trust, no
censorship choke-point, no operator pricing power) that make
file-sharing P2P durable.

What remains is the scale-out work — multi-host validation,
transport modernization, gossip-based membership — that we have
outlined as future work. We release the implementation as open
source under GPL-2 in the hope that other communities interested in
decentralized live media find it a useful starting point rather than
another isolated proof-of-concept.

---

## Acknowledgments

We thank the eMule Project for two decades of stewardship of the
upstream client. We thank the broader eD2K, Kad, and Tribler
communities for the prior art that made this design feasible.

This work was carried out with extensive use of Anthropic's Claude
Code as an in-the-loop engineering assistant; full development
transcripts are available on request.

---

## References

[1] J. McCaleb. *eDonkey 2000*. Self-published protocol specification,
    2000. Reconstructed retrospective: Heckmann et al., "A
    Performance Study of eMule and eDonkey on the Internet", in
    Proc. IPTPS 2006.

[2] eMule Project. *eMule — the all-platform compatible Kad/eD2K
    client*. <https://www.emule-project.net>, 2002–present.

[3] P. Maymounkov and D. Mazières. *Kademlia: A Peer-to-Peer
    Information System Based on the XOR Metric*. In Proc. IPTPS,
    2002.

[4] M. Steiner, T. En-Najjary, and E. W. Biersack. *A Global View of
    Kad*. In Proc. IMC, 2007.

[5] Y. Chu, S. Rao, and H. Zhang. *A Case for End System Multicast*.
    In Proc. SIGMETRICS, 2000.

[6] Y. Chu, S. G. Rao, S. Seshan, and H. Zhang. *Enabling
    Conferencing Applications on the Internet Using an Overlay
    Multicast Architecture*. In Proc. SIGCOMM, 2001.

[7] X. Hei, C. Liang, J. Liang, Y. Liu, and K. W. Ross. *A
    Measurement Study of a Large-Scale P2P IPTV System*. IEEE
    Trans. Multimedia, 9(8), 2007.

[8] X. Zhang, J. Liu, B. Li, and T.-S. P. Yum. *CoolStreaming/DONet:
    A Data-Driven Overlay Network for Peer-to-Peer Live Media
    Streaming*. In Proc. INFOCOM, 2005.

[9] J. A. Pouwelse, P. Garbacki, J. Wang, A. Bakker, J. Yang, A.
    Iosup, D. H. J. Epema, M. Reinders, M. R. van Steen, and H. J.
    Sips. *TRIBLER: a social-based peer-to-peer system*. Concurrency
    and Computation: Practice and Experience, 20(2), 2008.

[10] Framasoft. *PeerTube*. <https://joinpeertube.org>, 2018–present.

[11] F. Pianese, J. Keller, and E. W. Biersack. *PULSE, a Flexible
     P2P Live Streaming System*. In Proc. INFOCOM Workshops, 2006.

[12] J. Leitão, J. Pereira, and L. Rodrigues. *HyParView: a
     Membership Protocol for Reliable Gossip-Based Broadcast*. In
     Proc. DSN, 2007.

[13] J. Leitão, J. Pereira, and L. Rodrigues. *Epidemic Broadcast
     Trees*. In Proc. SRDS, 2007.

[14] A. Norberg. *BEP-10: Extension Protocol*. BitTorrent
     Enhancement Proposal, 2008.

[15] T. Ho, M. Médard, R. Koetter, D. R. Karger, M. Effros, J. Shi,
     and B. Leong. *A Random Linear Network Coding Approach to
     Multicast*. IEEE Trans. Information Theory, 52(10), 2006.

[16] R. Pantos and W. May. *HTTP Live Streaming*. RFC 8216, 2017.

[17] S. Cheshire and M. Krochmal. *Multicast DNS*. RFC 6762, 2013.

[18] B. Cohen. *Incentives Build Robustness in BitTorrent*. In
     Proc. P2P Economics Workshop, 2003.

---

_End of paper. Submitted version 1.0, 2026-05-17._
