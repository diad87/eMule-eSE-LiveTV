# eMule eSE LiveTV v0.70b-eSE7.2.1 — 2026-05-18

Hotfix for a regression in v7.1.8: the viewer counter on the
broadcaster's UI showed `0` even when several TCP connections were
actively receiving chunks. Same root cause family as v7.1.8 itself —
the interaction between `CClientList`'s connection-merging behaviour
and our peer lists.

`emule.exe` only. `ese-server.exe` is byte-identical to v7.2.0.

---

## The regression

v7.1.8 fixed a use-after-free by calling `OnPeerDisconnected` from
`CUpDownClient`'s destructor. Correct for the "TCP closed, client
genuinely gone" case. **Also fires** for a less obvious one:
`CClientList::AttachToAlreadyKnown` merges two `CUpDownClient`
objects when the same peer sends a second `OP_HELLO` (e.g. after a
silent reconnect). The OLD object is destroyed, the NEW object keeps
the live TCP socket.

Result with v7.1.8 / v7.2.0:
1. PC2 reconnects → second `OP_HELLO` → `AttachToAlreadyKnown` swap
2. OLD `CUpDownClient` destructed → v7.1.8 calls `OnPeerDisconnected`
   → peer removed from `m_broadcastPeers`
3. NEW `CUpDownClient` is now the live TCP owner, but **isn't in the
   peer list** — `OP_LIVE_JOIN` was already sent (once, on first
   connect), only `OP_LIVE_BITMAP` heartbeats arrive now
4. Internal viewer count: `0`. Actual TCP-connected viewers: 4.

Confirmed empirically:
```
m_broadcastPeers count: 0
ESTABLISHED TCP connections to port 38362: 4
subscribeAccepted: 138   peerDisconnects: 134   (delta = 4)
```

138 unique subscribes − 134 disconnect events = 4 live peers. But the
broadcaster's list shows 0 because each peer was disconnected from
the LIST while staying connected on TCP.

## The fix

Self-heal the peer lists from the regular heartbeat. `OnPeerBitmap`
arrives every 1 s for every active peer. If we are broadcasting AND
the streamKey matches AND the peer is NOT in `m_broadcastPeers`, we
re-add them. Same for the viewer side with `m_viewPeers`:

```cpp
if (m_bBroadcasting && m_broadcastPeers.Find(peer) == NULL) {
    m_broadcastPeers.AddTail(peer);
    m_streamInfo.viewerCount = (uint32)m_broadcastPeers.GetCount();
    LIVE_LOG("PEER", "REJOIN viewer=... total=%u", ...);
}
if (m_bViewing && m_viewPeers.Find(peer) == NULL) {
    m_viewPeers.AddTail(peer);
}
```

Now any spurious removal — whether by `~CUpDownClient` after a
client-list swap, a future regression, or anything else — recovers
on the next heartbeat tick.

The streamKey check that gates this entire function still applies:
re-adding only happens for peers actively transmitting bitmaps for
OUR current streamKey, so a stale peer from a previous broadcast
won't be revived.

---

## Hashes

- `emule.exe`      → `D6C82FAA47DDEFBDE678E1AF8447F0C9A5ECFC4D3706D3AC17798836E83480ED`
- `ese-server.exe` → `A90C54E3FB6BE0A64F8B80400EBE33688AF2D87E121B370A5C8D9059F0A8C48A` *(unchanged from v7.2.0)*

---

## Upgrading from v7.2.0

Just hot-swap `emule.exe`. `ese-server.exe` is unchanged so no need
to touch it.

1. Close emule (kill `emule.exe`, leftover `ffmpeg.exe`)
2. Replace `emule.exe` from this release's assets
3. Reopen emule

The viewer counter will start populating correctly on the next
heartbeat tick (1 s) after a peer connects.

---

## Carried over

- v7.2.0 — OP_LIVE_END tombstone + mesh gossip + crash-detect watchdog
- v7.1.9 — ghost-channel + stale-Kad-entry cleanup
- v7.1.8 — `~CUpDownClient` → `OnPeerDisconnected` (use-after-free)
- v7.1.7 — `/live` SyntaxError fix + Cache-Control
- v7.1.6 — bitrate-driven ABR variant + muted autoplay
- v7.1.5 — orphan ffmpeg reap
- v7.1.4 — paste-link redirect
- v7.1.3 — preflight badges SyntaxError
- v7.1.2 — Kad publish TAG_SOURCEIP
- v7.1.1 — IPv4 localhost

---

GPL-2.0-only.
