# eMule eSE LiveTV v0.70b-eSE7.1.4 — 2026-05-17

Fourth point release of the day. Fixes a 404 in the "Conectar directo por
link" flow on the `/live` page.

---

## The fix

After pasting an `ed2k://|live|...` link into the "Conectar directo por
link" box and pressing Conectar, the success path redirected to `/player`,
which doesn't exist as a route in `ese-server.exe` — net effect: the
browser showed **"Not Found"** and the console logged `player:1 Failed to
load resource: 404`.

The actual player page lives at `/live/watch/local`. There IS code that
handles `/player` in [`srchybrid/eSE/live_player_server.js`](srchybrid/eSE/live_player_server.js),
but that file is **never `require()`d anywhere** — it's orphan code. The
live routing in `channel_api.js` only knows about
`/live/watch/local` and `/live/watch/{hash}`.

**Fix:** one-line change in [`srchybrid/eSE/eSE-live/live_tv_page.js`](srchybrid/eSE/eSE-live/live_tv_page.js#L708)
— redirect to `/live/watch/local` instead of `/player`. Direct links now
land on the actual player.

---

## What this unlocks

This release was triggered by a real cross-ISP validation: PC1 on home
fiber broadcasting a test pattern, PC2 on **4G mobile** (LowID, behind
carrier-grade NAT, different ISP) pasting the `link_direct` into the box
above — previously hitting 404 on the player redirect, now landing on
the player and reproducing the broadcast end-to-end with the broadcaster
correctly seeing `1 viewer` in their eMule counter.

Combined with the v7.1.2 Kad publish IP fix, this closes the LiveTV
cross-ISP discovery + playback loop:

- Discovery via Kad (with valid TAG_SOURCEIP) — works for any peer.
- Discovery via paste-link — now also lands on the player without 404.
- Playback over P2P chunks across NATs (LowID viewer ↔ HighID broadcaster) — works.

---

## Upgrading from v7.1.3

Hot-swap supported. This release only changes `ese-server.exe`.
`emule.exe` is unchanged from v7.1.2 / v7.1.3.

1. **Re-download the ZIP** and extract over your v7.1.3 install.
2. **Hot-swap `ese-server.exe`**: download it from this release's
   assets and replace yours. Close eMule first; reopen after.

---

## Carried over

- v7.1.3 — preflight badges SyntaxError + cosmetic upload label fix.
- v7.1.2 — Kad publish TAG_SOURCEIP for cross-PC discovery.
- v7.1.1 — IPv4 localhost fix for login.

---

GPL-2.0-only.
