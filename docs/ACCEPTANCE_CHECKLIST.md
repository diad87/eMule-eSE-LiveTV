# Acceptance Checklist — Hardware-Required Tests

The two items below were the last blockers for declaring the project
"closed" but they require physical hardware that the assistant doesn't
have access to. Run them in this order and tick off as you go.

If any step fails, paste the symptom + the last 50 lines of the eMule
log into the issue tracker.

---

## D4 — Cross-platform / cross-GPU sanity (one PC each)

Goal: confirm broadcasting works without a dedicated NVIDIA GPU.

| # | Platform | Encoder expected | Pass criteria |
|---|---|---|---|
| 1 | Win 10 22H2 x64, **Intel iGPU** only (no discrete) | QSV (`h264_qsv`) | `[RTMP] selected encoder: h264_qsv` appears in log; viewer hits 720p variant without dropped frames over 5 min |
| 2 | Win 11 x64, **AMD Radeon** (RDNA2+) | AMF (`h264_amf`) | `selected encoder: h264_amf`; same 5 min smoke as above |
| 3 | Win 10 x64, **no GPU acceleration** (or `--no-hwaccel`) | x264 (CPU) | `selected encoder: libx264`; 540p variant is the highest stable choice |
| 4 | Win 11 x64, **NVIDIA RTX 30/40** (already validated 2026-05-15) | NVENC | 1080p stable for ≥15 min |

### What to record

For each row: CPU model, GPU model, encoder selected, peak CPU%
during the 5-min broadcast, viewer-side dropped-frames count from
`/api/live/metrics` (`live_dropped_frames_total`).

### Failure modes that block ship

- Falls back to libx264 on a machine that has a working QSV/AMF
  encoder (FFmpeg detection bug — open issue).
- Variant ladder picks 1080p on iGPU and dies → cap to 720p when
  encoder is QSV/AMF on integrated parts.
- Broadcast crashes `ese-server.exe`.

### Failure modes that are merely warnings

- 1080p drops frames on iGPU — expected, viewer will downshift via ABR.
- First chunk takes >15 s — slow Kad bootstrap, second run should be fast.

---

## D5 — Cross-PC end-to-end (two PCs, two networks)

Goal: prove the discovery + transport stack works across the real
internet, not just localhost.

### Setup

- **PC-A (broadcaster):** any of the boxes from D4. Behind a normal
  home router (UPnP allowed).
- **PC-B (viewer):** physically on a **different ISP/IP** (use a
  phone hotspot if you only have one home). Fresh extract of the
  portable ZIP — no `%APPDATA%\eMule` leftovers.

### Run order

1. **PC-A** — launch `eSE.vbs`. Wait until tray icon shows `Kad: Connected` (1-5 min).
2. **PC-A** — start broadcasting per [USER_GUIDE.md §3.1](USER_GUIDE.md#31-quick-start--push-from-obs).
3. **PC-A** — verify in dashboard: own tile visible at <http://localhost:8080/live>, log says `Kad publish OK` and `LAN announce sent`.
4. **PC-B** — launch `eSE.vbs`. Wait for `Kad: Connected`.
5. **PC-B** — open <http://localhost:8080/live>. **Wait up to 5 min.**

### Pass criteria

| Discovery path | Expected time-to-find | Notes |
|---|---|---|
| Bootstrap cache | n/a (first run, empty) | — |
| LAN multicast (5354) | n/a (different network) | — |
| **PEX gossip** | 1-3 heartbeats (~3 s) **if** PC-B is connected to a peer that knows about PC-A | This is the realistic path on a small mesh |
| **Kad search** | 30 s - 5 min | The cold-discovery worst case |
| **Direct paste link** | 1-3 s | Get the `ed2k://\|live\|...\|/` from PC-A's cinema URL → paste into PC-B's search box |

You only need **ONE** of the above paths to succeed for the test to
pass — they're redundant by design.

### Then verify the actual stream

- PC-B clicks PC-A's tile → cinema player.
- First chunk arrives in <15 s.
- Stream plays for 5 min without falling back to "buffering" more than twice.
- Audio + video stay in sync (`±300 ms`).
- Stop OBS on PC-A → within 30 s PC-B's player shows "stream ended" (tombstone propagated).

### Failure modes that block ship

- Direct paste link doesn't work → broadcaster is unreachable (LowID + no UPnP). Confirm with PC-A's `/api/live/preflight` returning a public IP.
- PEX gossip never propagates → check `OP_LIVE_HEARTBEAT` packet size in PC-A's log (should be 23-133 bytes per peer; if stuck at 22 the PEX block isn't being attached).
- Audio out of sync → keyframe interval ≠ 2 s. Reconfigure OBS.

### Failure modes that are expected

- First viewer takes 30-60 s of Kad search. This is by design; we
  trade latency for full decentralization.
- Drops after a long broadcast (>2 h) — known: peer churn isn't yet
  amortized. Document, defer.

---

## Sign-off

When both D4 (at least rows 1 + 4) and D5 are green, the project is
"closed" in the sense the user asked about. The other items I flagged
(D6 auto-update, D7 crash reports, D8 CI, D9 endpoint audit,
D10 first-run wizard) are post-1.0 polish.

Date completed: ______________  Tester: ______________
