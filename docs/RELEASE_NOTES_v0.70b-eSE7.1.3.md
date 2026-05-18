# eMule eSE LiveTV v0.70b-eSE7.1.3 — 2026-05-17

Third point release of the day. Fixes the inline-script SyntaxError on the
`/live` page that was silently disabling every preflight badge, the
welcome wizard, browser notifications, and the channel auto-refresh
poller. Also a small cosmetic fix for the upload bandwidth label.

---

## The main fix

The `/live` page contained a JavaScript SyntaxError that aborted parsing
of the entire inline `<script>` block. Net effect:

- Preflight badges (Kad / HighID / Subida / FFmpeg) stayed on the
  "loading" hourglass icon forever, even when everything was actually
  ready.
- The first-run welcome wizard never appeared.
- The browser-notification setup never ran.
- The channel-list poller didn't update.
- Pretty much every interactive feature on `/live` silently no-op'd.

**Root cause:** the JS source had

```js
modal.innerHTML = '\n<div ...>\n  ...\n</div>';
```

inside a single-quoted string. That source line is itself embedded in
the outer template literal that builds the `/live` HTML page. Template
literals interpret `\n` as a real newline character — so the rendered
output became

```js
modal.innerHTML = '
<div ...>
  ...
</div>';
```

A real newline inside a single-quoted JS string is a SyntaxError.
Browsers reported it at `live:645:23`, but the actual cause was the
unterminated string starting at the rendered script line 332.

**Fix:** double-escape every newline in that string (`\n` → `\\n` in the
source), so the outer template literal emits the literal two-character
sequence `\n` that the browser then correctly interprets as a newline
escape inside the single-quoted string. See
[srchybrid/eSE/eSE-live/live_tv_page.js:565](srchybrid/eSE/eSE-live/live_tv_page.js#L565).

## Cosmetic fix

The preflight panel was showing **"Subida 4294967295 KB/s"** when the
user had no upload-rate cap set. That value is `0xFFFFFFFF` — eMule's
UNLIMITED sentinel, not a literal 4 GB/s cap. Now correctly displayed as
**"Subida ilimitada"**.

---

## Upgrading from v7.1.2

Hot-swap supported. This release only changes `ese-server.exe` (the
inline script lives in the Node-served `/live` page). `emule.exe` is
unchanged from v7.1.2.

Two options:

1. **Re-download the ZIP** and extract over your v7.1.2 install.
2. **Hot-swap `ese-server.exe`**: download it from this release's
   assets and replace yours. Close eMule first; reopen after.

---

## Verifying the fix works

After upgrading, open `/live` in your browser and confirm:

- The preflight badges (Kad / HighID / Subida / FFmpeg) turn **green**
  within a few seconds, not stuck on hourglasses.
- The upload badge says **"ilimitada"** (or your actual KB/s cap if you
  have one set), not the raw uint32.
- Browser DevTools console (F12) has **no SyntaxError** at startup.

---

## Carried over from v7.1.2

- Kad publish now includes `TAG_SOURCEIP` so cross-PC LiveTV discovery
  actually works ([release notes](RELEASE_NOTES_v0.70b-eSE7.1.2.md)).
- All the v7.1 and v7.1.1 fixes (login error, IPv4 localhost, etc.) are
  still in.

---

GPL-2.0-only.
