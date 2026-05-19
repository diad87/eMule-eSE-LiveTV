# eMule eSE LiveTV v0.70b-eSE7.1.6 — 2026-05-17

Sixth point release of the day. Makes file broadcasts viable for
viewers on 4G / CGN / other constrained links — previously the
`source=file` path always pushed the 720p variant (~3 Mbps) over P2P
regardless of what the broadcaster asked for, which broke playback
for any viewer that couldn't sustain that bitrate. Also fixes the
browser autoplay block that forced viewers to click the video before
playback started.

---

## The main fix — bitrate parameter now actually controls P2P load

### Symptom
Cross-ISP validation from PC1 (home fiber) to PC2 (4G LowID/CGN)
worked end-to-end after v7.1.5: discovery, dial, subscribe — all
green. But playback stuttered to a halt after ~8 seconds with
**48 peer-disconnects** accumulating on the broadcaster side. PC2's
chunk reception kept dying mid-stream, never recovered enough buffer
to refresh its `stream.m3u8`, browser polled and got 404s, frame froze.

### Root cause
File broadcasts (`source=file`) run an ABR ffmpeg ladder with
**4 hardcoded variants** (360p/540p/720p/1080p, 800/1600/2800/4500 kbps).
The watcher in [`srchybrid/RTMPIngest.cpp`](srchybrid/RTMPIngest.cpp) was
hardcoded to pick `seg_2_*.ts` (the 720p variant) as the one fed into
`m_chunkBuffer` for P2P distribution. The `bitrate` parameter passed
to `/api/live/broadcast/start?bitrate=...` had **zero effect** on what
flowed through P2P — it was used only for stat reporting.

Net effect: every file broadcast pushed ~3 Mbps to every viewer,
regardless of what the broadcaster requested. Fine on home/office LANs,
fatal for 4G CGN viewers because:
- Each chunk is ~1.5 MB at 720p × 4 s segments
- Upload takes ~3 s over the cellular link
- CGN aggressively kills sessions on retransmits/RST
- Disconnect → re-subscribe → 2-4 chunks → disconnect again

### Fix
Added `m_nPreferredVariant` to `CRTMPIngest`. `StartMediaFile` now
maps the bitrate hint to an ABR variant:

| Bitrate (kbps) | Variant | Resolution | P2P load |
|---|---|---|---|
| ≤ 1000  | 0 | 360p  | ~600-800 kbps |
| ≤ 2000  | 1 | 540p  | ~1.4 Mbps |
| ≤ 3500  | 2 | 720p  | ~2.8 Mbps *(prior default)* |
| > 3500  | 3 | 1080p | ~4.5 Mbps |

The watcher's `WatcherLoop` builds the pattern-try order dynamically:
preferred variant first, then walks outward to neighbouring variants
as fallback (NVENC sometimes finishes a higher variant before a lower
one for a given segment number). Other variants are still encoded by
ffmpeg — no encoder-side change. Only the P2P-feed selection changed.

Verified locally with `bitrate=800` + Titanic.mkv:
```
seg_00004.ts (P2P feed) = 301 KB  ← matches seg_0_00004.ts (360p)
seg_2_00004.ts (720p)    = 875 KB  ← would have been pushed pre-v7.1.6
seg_3_00004.ts (1080p)   = 1397 KB ← would have crushed 4G
```

3-4× reduction in what gets transmitted over P2P for 4G-targeted
broadcasts. Viewers on home networks can request `bitrate=3500` (or
higher) and get the same quality as before.

### How to use
```
http://localhost:8080/api/live/broadcast/start?source=file
  &file=C:\path\to\movie.mkv
  &title=My+Channel
  &bitrate=800     # 4G-friendly (360p)
  &bitrate=1500    # mid-tier (540p)
  &bitrate=3000    # home network HD (720p, default)
  &bitrate=4500    # high-bandwidth (1080p)
```

The receiving viewer's emule does NOT need updating — variant
selection happens entirely on the broadcaster side. Viewers running
v7.1.2+ will pick up the smaller chunks transparently.

---

## Bonus — `muted` autoplay

### Symptom
Browser console spammed with:
```
Uncaught (in promise) NotAllowedError: play() failed because the user
didn't interact with the document first.
```
Viewer had to click the video element to start playback. HLS.js loaded
fine, chunks were available, but Chrome/Firefox refused to autoplay
audio without prior user interaction.

### Fix
Added `muted` to the `<video>` tag in
[`srchybrid/eSE/eSE-live/channel_api.js`](srchybrid/eSE/eSE-live/channel_api.js#L1209).
Browsers DO allow muted autoplay. Viewer sees the broadcast immediately;
the existing mute button (speaker icon, top-left of controls) toggles
audio when they want it.

---

## What's NOT in this release

- **uTP transport for live chunks** — eMule already uses uTP for
  regular P2P downloads (it survives aggressive NATs/CGN better than
  raw TCP). The live broadcast protocol still uses TCP to the
  broadcaster's listener port (default 38362). Migrating live to uTP
  would fix the CGN disconnect issue at the transport layer, but it's
  a 1-2 day change that needs real CGN testing — deferred to v7.2.
- **Per-viewer variant negotiation** — the broadcaster currently picks
  ONE variant for ALL viewers (driven by its own bitrate parameter).
  A 4G viewer joining a broadcast set up for HD would still get the HD
  feed. Deferred to v7.1.7 once we have the wire-protocol bits for
  viewers to express their bandwidth preference at subscribe time.

---

## Upgrading from v7.1.5

Hot-swap supported. Both `emule.exe` AND `ese-server.exe` changed
this release:

1. **Re-download the ZIP** and extract over your v7.1.5 install.
2. **Hot-swap** the two binaries: download `emule.exe` and
   `ese-server.exe` from this release's assets and replace yours.
   Close eMule first; reopen after.

---

## Carried over

- v7.1.5 — orphan ffmpeg reap on broadcast start (test-pattern bleed fix)
- v7.1.4 — `/player` → `/live/watch/local` direct-link redirect fix
- v7.1.3 — preflight badges SyntaxError + cosmetic upload label
- v7.1.2 — Kad publish TAG_SOURCEIP for cross-PC discovery
- v7.1.1 — IPv4 localhost fix for login

---

GPL-2.0-only.
