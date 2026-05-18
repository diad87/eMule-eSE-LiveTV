# eMule eSE LiveTV v0.70b-eSE7.1.7 — 2026-05-18

Two fixes for the second-PC viewer experience: a long-running
SyntaxError that silently disabled the whole `/live` UI on some
machines despite v7.1.3's earlier "fix", plus a no-cache header that
prevents stale HTML from surviving `ese-server.exe` hot-swaps.

`emule.exe` is unchanged from v7.1.6. Only `ese-server.exe` changed.

---

## The main fix — SyntaxError at /live, take 2

### Symptom
Identical to v7.1.3's: the inline `<script>` block at `/live` aborts on
parse, leaving every interactive element broken — preflight badges
stuck on hourglasses, channel poller dead, "Buscando..." spinner
eternal, paste-link button non-functional. Browser console shows:

```
live:498 Uncaught SyntaxError: Invalid or unexpected token
```

Only triggered on **PC2** during today's testing. PC1 with the same
exact `ese-server.exe` binary (SHA256 verified identical) rendered the
page fine. Confusing as hell until we looked at the served bytes:

| Position | PC1 (works) | PC2 (broken) |
|---|---|---|
| After `modal.innerHTML = '` | `\` + `n` (2 chars, valid JS escape) | **LF** (real newline) |

### Root cause
The `/live` page's inline `<script>` is built by Node template literal
in `live_tv_page.js`. v7.1.3 had tried to fix the original SyntaxError
by **double-escaping** newlines in the wizard's `modal.innerHTML` —
source had `\\n` so the outer template would emit a literal `\n`
(two-char escape) that the browser would interpret as a valid newline
inside the single-quoted string.

That round-trip worked deterministically on PC1 but somehow produced
a real LF in some pkg-bundled execution context on PC2 (different
Node version sandbox? different snapshot state inside the bundled
binary? unconfirmed). The single-quoted string ended up split across
two physical lines — JS doesn't allow that → SyntaxError → cascade
failure of every JS feature on the page.

### Fix
Stop relying on escape-sequence round-tripping entirely. The wizard
`modal.innerHTML` is now a **single source line with zero newline
escapes of any kind** — neither `\n` nor `\\n`. The rendered HTML
lays out and styles identically; only its physical line count
differs. No newline → impossible to break the single-quoted string,
regardless of how pkg bundles or how Node parses.

See [`srchybrid/eSE/eSE-live/live_tv_page.js`](srchybrid/eSE/eSE-live/live_tv_page.js#L575).

### Discoverability bonus during fix
Adding a comment that itself contained `'\n' (two chars)` immediately
re-triggered the exact same bug — confirming that ANY backslash-n
inside the inline-`<script>` template literal is a hazard. The
comment was rewritten without backslash-n; lesson logged for any
future edits to inline browser-side code in this file.

---

## Bonus fix — `Cache-Control: no-cache` for `/live` and `/live/watch/*`

### Symptom
After updating `ese-server.exe` on PC2 from v7.1.2 to v7.1.6, the
browser kept serving the **old HTML** (the v7.1.2 version with the
`/player` redirect bug). Hard refresh (Ctrl+Shift+R) didn't help.
Incognito mode also showed the old page. The cached page had no
expiration metadata, so the browser treated it as "fresh forever"
until manually purged.

### Root cause
The handlers at [`srchybrid/eSE/eSE-live/channel_api.js`](srchybrid/eSE/eSE-live/channel_api.js#L1349)
served `/live` and `/live/watch/*` with only `Content-Type` — no
`Cache-Control`, no `ETag`, no `Last-Modified`. Browsers heuristically
caches such responses indefinitely.

### Fix
Both handlers now send:

```
Cache-Control: no-cache, no-store, must-revalidate
Pragma: no-cache
Expires: 0
```

So future `ese-server.exe` upgrades take effect on the next page load,
not on whenever the browser decides to revalidate. The HTML embeds an
inline `<script>` that changes between releases — this header makes
the "update the binary, refresh the page, see the new code" workflow
work reliably.

---

## Upgrading from v7.1.6

Hot-swap supported. Only `ese-server.exe` changed.

1. **Re-download the ZIP** and extract over your v7.1.6 install. Or:
2. **Hot-swap only**: download [`ese-server.exe`](https://github.com/diad87/eMule-eSE-LiveTV/releases/download/v0.70b-eSE7.1.7/ese-server.exe)
   from this release. Close eMule first (or just kill `ese-server.exe`),
   replace, reopen eMule.

If you're upgrading from v7.1.2/3/4 and the old `/live` page is
cached, this release's no-cache headers will start applying on the
next clean load — but the very first load after upgrade may still
need a manual hard refresh.

---

## Carried over

- v7.1.6 — bitrate parameter drives ABR variant selection + muted autoplay
- v7.1.5 — orphan ffmpeg reap on broadcast start (test-pattern bleed fix)
- v7.1.4 — `/player` → `/live/watch/local` direct-link redirect fix
- v7.1.3 — preflight badges SyntaxError + cosmetic upload label *(partial fix; full fix is this release)*
- v7.1.2 — Kad publish TAG_SOURCEIP for cross-PC discovery
- v7.1.1 — IPv4 localhost fix for login

---

GPL-2.0-only.
