# eMule eSE LiveTV v0.70b-eSE7.1.9 — 2026-05-18

Cleanup release. Kills ghost channel entries (own + remote) and stale
Kad directory entries that survived broadcast stops, streamKey changes,
or eMule restarts. Also makes the remote-channel uptime stop resetting
to "0min" on every Kad poll.

Both `emule.exe` and `ese-server.exe` changed.

---

## What this fixes

### Ghost local channels in the directory
`channel_search.js::registerChannel` now sweeps every other `isLocal`
entry from the in-memory channel registry before inserting the new
broadcast. Previously each `Start broadcast` added a new entry keyed
by streamKey; old `local_<ts>` / `obs_<ts>` / `external_<ts>` entries
from prior sessions piled up and stayed visible because the
"pipeline-active" liveness flag in `search()` is GLOBAL, not
per-streamKey. After many broadcasts the same machine showed itself
3-4 times in the channel list.

### Uptime reset on every Kad poll
`channel_search.js::addRemoteChannel` preserves the original `started`
timestamp across updates. The C++ Kad layer doesn't emit a stable
start time, so each poll passed `new Date().toISOString()` through
`Object.assign`, overwriting the existing one. Result: every remote
broadcast in the directory had its uptime reset to `0min` 4 times a
minute, instead of growing as expected.

### Immortal own-stream entries in Kad directory
`LiveKadBridge::PublishStream` now sweeps any prior `isOwnStream`
entries from `m_streamDirectory` when the streamKey changes. Before
this, `m_streamDirectory[strKey] = entry` just added the new one and
the previous own entries stuck around forever — until v7.1.9
`PruneStaleEntries` also explicitly skipped them. So any user who
broadcast more than once per session showed up multiple times in
their own directory.

### PruneStaleEntries no longer skips own entries
The `if (entry.isOwnStream) continue;` early-skip is replaced with
`keep only the currently-published own entry; everything else
(including own-but-stale) gets pruned`. Together with the new
`PublishStream` sweep, this guarantees the directory has AT MOST one
own entry at all times — the one for the active broadcast (or zero
if nothing is broadcasting).

### Kad TTL shortened
`ESE_KAD_ENTRY_TTL` from 180 s (3 min) → **120 s (2 min)**. The
broadcaster republishes every 60 s, so any remote entry that misses
two consecutive republishes is presumed dead and pruned. (Original
upstream eMule was 10 min.) `ESE_KAD_PRUNE_INTERVAL` stays at 30 s.

---

## Still pending (not urgent)

Remote-broadcaster entries in **other Kad nodes' caches** can still
outlive the broadcaster by hours — their `lastSeen` gets refreshed
locally by every echo of the original Kad publish even after the
broadcaster's emule has exited. Truly killing those requires a
separate `lastVerifiedAlive` field updated only when a heartbeat or
chunk arrives directly from the broadcaster. Bigger change, deferred
to v7.2.

---

## Hashes

- `emule.exe`      → `4B8298EFE7D52E08D8648F48876960A5B07C257F62A1902AF6E35470262DB66C`
- `ese-server.exe` → `4B6483D524D015D01A3765E724E7B5CD6688D22D6CABC7089D733F49C117811C`

---

## Upgrading from v7.1.8

Hot-swap supported, but both binaries changed this time:

1. Close eMule fully (kill `emule.exe`, `ese-server.exe`, and any
   leftover `ffmpeg.exe` — emule does not own ffmpeg as a child
   process via job-object, so it can survive an emule kill).
2. Replace BOTH `emule.exe` and `ese-server.exe` from this release's
   assets (or re-extract the full ZIP).
3. Reopen eMule.

Don't forget to also clean `%TEMP%\eMule_RTMP\` if you had failed
broadcasts earlier — stale `seg_*.ts` files give the watcher a
misleading `baseSeg` start point.

---

## Carried over

- v7.1.8 — `~CUpDownClient` → `OnPeerDisconnected` (use-after-free fix on viewer disconnect)
- v7.1.7 — `/live` SyntaxError fix (real one) + Cache-Control headers
- v7.1.6 — bitrate-driven ABR variant + muted autoplay
- v7.1.5 — orphan ffmpeg reap on broadcast start
- v7.1.4 — paste-link redirect fix
- v7.1.3 — preflight badges SyntaxError + ilimitada cosmetic
- v7.1.2 — Kad publish TAG_SOURCEIP
- v7.1.1 — IPv4 localhost for login

---

GPL-2.0-only.
