# eMule eSE LiveTV v0.70b-eSE7.2.0 — 2026-05-18

Minor-version bump (7.1.x → 7.2.0) because this adds a real network
feature, not just a fix: peer-to-peer **gossip of dead-stream
notifications** plus a **local watchdog** that catches broadcaster
crashes (which by definition can't send the notification themselves).

Both `emule.exe` and `ese-server.exe` changed.

---

## Why

After yesterday's full day of crash-driven ghost streams, the
constraint became clear: **Kad caches outlive the broadcaster by
hours**. Every node that learned about your stream keeps echoing it
back to fresh searchers for ~5 h after you die. Local-only fixes
(TTL, registry sweep, prune intervals) help the broadcaster's own
machine but not anyone else's. To kill a ghost across the network
you need **active propagation of the death signal**.

`OP_LIVE_END` was already a defined opcode (0xC8) and the broadcaster
already sent it from `StopBroadcast` to its direct viewers. What was
missing:

1. Receivers didn't *do* anything useful with it — they just removed
   the sender from their peer list, but kept the streamKey in their
   Kad directory.
2. The notification stopped at one hop — mesh peers, super-seeders,
   and anyone discovering via Kad never heard.
3. If the broadcaster **crashed** instead of stopping cleanly,
   `OP_LIVE_END` was never sent at all. Most ghost streams come from
   this path, not from graceful stops.

---

## Changes

### 1. Tombstone map per peer
`CLiveStreamManager` now keeps a `CMap<CString, DWORD> m_streamTombstones`
mapping hex streamKeys to expiration tick (default 30 min TTL).

Lookups:
- `IsStreamTombstoned(streamKey)` — called by `CLiveKadBridge::GetKnownStreams`
  and `OnKadSearchResult` to discard cached Kad echoes that try to
  resurrect streams we already know are dead.

Writes:
- `OnStreamEnded(streamKey, reason, fromPeer)` — single entry point
  used by both the OP_LIVE_END handler and the watchdog.
- Pruned each `Process()` tick (every minute).

### 2. OP_LIVE_END handler now does the work
[`ListenSocket.cpp:OP_LIVE_END`](srchybrid/ListenSocket.cpp#L1888)
now reads `<streamKey 16><reason 1>` from the packet (was: just
removing the sender), then calls `OnStreamEnded` which:

1. Tombstones the streamKey for 30 min.
2. Leaves the stream if we were viewing it.
3. **Gossips the END to our mesh peers** (broadcastPeers ∪ viewPeers,
   excluding the peer that informed us). Each receiver tombstones
   first and ignores duplicates, so propagation is bounded — no
   storms.

### 3. Crash-detection watchdog
[`CLiveStreamManager::Process`](srchybrid/LiveStreamManager.cpp#L1638)
now tracks `m_dwLastLiveActivity` — refreshed on every chunk receive
AND every bitmap heartbeat. If we are viewing and the clock goes
silent for >90 s, we fabricate a synthetic `OP_LIVE_END(reason=error)`
locally:

```cpp
OnStreamEnded(deadKey, ESE_END_ERROR, /*fromPeer=*/ NULL);
```

Tombstones locally and gossips to the mesh. Broadcaster crashed
silently → 90 s later, every direct viewer notices → 90+ε seconds
later, every mesh peer of those viewers notices → fan-out, no
caching node ever sees a fresh `lastSeen` because nobody's still
publishing the stream.

The 90 s threshold is generous on purpose: heartbeats fire every 1 s
and chunks every 2-4 s, so 22-90 missed beats = unambiguously dead,
not a 4G blip.

### 4. StopBroadcast notifies wider
[`CLiveStreamManager::StopBroadcast`](srchybrid/LiveStreamManager.cpp#L257)
used to send `OP_LIVE_END` only to `m_broadcastPeers` (direct viewers
subscribed via `OP_LIVE_SUBSCRIBE`). Now it ALSO sends to `m_viewPeers`
(in case we were a relay) and to every key in `m_peerCounters` (every
mesh peer we've talked to). Covers super-seeders that were
redistributing to others.

Also pre-tombstones our own streamKey before gossiping so an echo
that bounces back through the mesh doesn't trigger another round.

### 5. Kad result filter on read
[`CLiveKadBridge::OnKadSearchResult`](srchybrid/LiveKadBridge.cpp#L541)
and [`GetKnownStreams`](srchybrid/LiveKadBridge.cpp#L503) consult
`IsStreamTombstoned` and drop matching entries. Stale Kad echoes from
other nodes can no longer resurrect a stream we've already buried.

---

## What this does NOT fix

**Cold Kad nodes** — machines that learned about a stream from a
search result but never connected to the mesh — won't receive the
gossip. They keep echoing the dead stream to fresh searchers until
their own local TTL expires (~5 h with vanilla eMule's
`KADEMLIAREPUBLISHTIMEK = 24h` and indexer-side prune at
~5 h half-life).

For those nodes, only **time** plus **everyone's local
`IsStreamTombstoned` check on incoming results** eventually evicts
the entry. Anyone running 7.2.0 won't display it; anyone running
older clients will, until Kad TTL.

Listed for v7.2.x if it bites:
- Publish a deliberate "deprecated" Kad entry (bitrate=0 sentinel)
  more aggressively to overwrite the active one in cold caches.
  Partially exists already in `UnpublishStream` — could be extended
  to also publish on tombstone-from-gossip.

---

## Hashes

- `emule.exe`      → `47139CB568A325F96A40B81E26893DE5788A52D151BEAF059BCC444B6B196B7C`
- `ese-server.exe` → `A90C54E3FB6BE0A64F8B80400EBE33688AF2D87E121B370A5C8D9059F0A8C48A`

(ese-server.exe rebuilt as part of the emule.sln pre-build step.
No source-level changes from v7.1.9 in the Node side.)

---

## Upgrading from v7.1.9

Hot-swap supported. Both binaries changed.

1. Close emule (kill `emule.exe`, `ese-server.exe`, and any leftover
   `ffmpeg.exe`).
2. Replace BOTH binaries from the assets (or re-extract the ZIP).
3. Reopen emule.

If you were broadcasting when you stopped, expect a tombstone to be
sent to whoever was watching as part of `StopBroadcast`. They'll
hide your channel from their lists for 30 min — which is correct,
because the streamKey of your next broadcast will be different.

---

## Wire compatibility

`OP_LIVE_END` (opcode 0xC8) was already eSE-only. Vanilla eMule
0.70b ignores it. Older eSE versions process it (remove peer) but
don't gossip; they're consumers, not propagators. v7.2.0+ peers
form the gossip-active subset of the mesh, which is enough — most
networks will converge to all-7.2.0 within days as people update.

---

## Carried over

- v7.1.9 — ghost-channel + stale-Kad-entry cleanup
- v7.1.8 — `~CUpDownClient` → `OnPeerDisconnected` (use-after-free)
- v7.1.7 — `/live` SyntaxError fix (final) + Cache-Control
- v7.1.6 — bitrate-driven ABR variant + muted autoplay
- v7.1.5 — orphan ffmpeg reap
- v7.1.4 — paste-link redirect
- v7.1.3 — preflight badges SyntaxError
- v7.1.2 — Kad publish TAG_SOURCEIP
- v7.1.1 — IPv4 localhost

---

GPL-2.0-only.
