# eMule eSE LiveTV v0.70b-eSE7.1 — 2026-05-17

Bugfix + UX release. Kills the recurring "eMule login failed" error new
users were hitting on first run. Drops the legacy `.vbs` launcher. Adds
Spanish quickstart guide. Carries over two pending fixes from parallel
work (eSE Live disk-persist + Mi Lista button).

---

## Highlights

### The "Error de conexion — eMule login failed" is gone

Reported by ForoCoches user *Gobin3* (and others) right after installing
the v7.0 ZIP: open the dashboard, search a movie, press Play → "Error de
conexion" with a useless **Reintentar** button that never works.

**Root cause:** eMule reads `preferences.ini` once at startup. The previous
`ese-server.exe` tried to enable the WebInterface and write the password
to the INI at runtime, but the already-running eMule has the file loaded
in memory and ignored the changes — login forever failed.

**Fix:** the WebServer sync now happens inside `emule.exe` (C++ side), in
memory, right before it spawns `ese-server.exe`. The plaintext password
is then passed to the child via the `ESE_EMULE_PASSWORD` env var, so
the very first login succeeds.

**Bonus:** when something does go wrong at runtime (user closes eMule
mid-session, port collision, etc.) the error UI now shows a contextual
button — **"He abierto eMule"** for `webserver_down`, **"Resincronizar"**
for `password_mismatch` — instead of the dead-end `Reintentar`.

See PR [#5](https://github.com/diad87/eMule-eSE-LiveTV/pull/5) for the
full architecture writeup.

### `.vbs` launcher dropped — single-binary launch

`eSE.vbs` (and `eSE-dist/eSE.vbs` and `installer/eSE.vbs`) removed. The
canonical launch flow is now: **double-click `emule.exe` → click the eSE
toolbar button**. eMule.exe itself spawns `ese-server.exe`, opens the
browser, and manages the lifecycle. No more `wscript.exe` window, no
more "blocked by SmartScreen" friction on the `.vbs`.

### Spanish quickstart guide

[GUIA-RAPIDA.md](GUIA-RAPIDA.md) + [GUIA-RAPIDA.bbcode](GUIA-RAPIDA.bbcode)
(BBCode flavour for forum posts). One-page "how to get streaming in 60
seconds" walkthrough, since the existing user community is mostly
Spanish-speaking.

### eSE Live disk-persist channel directory

The list of broadcasting peers + their stream keys now survives an
eMule restart — was rebuilt from scratch every launch, leaving users
staring at an empty `/live` for ~30 seconds while Kad re-discovered.
Background `pollKadStreams` + an empty→populated auto-refresh on the
`/live` page complete the UX. Carried over from
[claude/intelligent-lalande-7516d5](https://github.com/diad87/eMule-eSE-LiveTV/tree/claude/intelligent-lalande-7516d5).

### "Mi Lista" button no longer does nothing

`toggleMyListBtn` was missing from the prebuilt `_player_bundle.js` — the
modular source had it but the bundling script skipped it. Bundle
regenerated; button works. Same upstream branch as above.

---

## Distribution

| Artifact | Size (approx.) | Contents |
|---|---|---|
| `eSE-LiveTV-v0.70b-eSE7.1-2026-05-17-x64.zip` | ~85 MB | emule.exe, ese-server.exe, ffmpeg essentials, node.exe, cloudflared.exe, 43 language DLLs, eMule.tmpl, server.met, nodes.dat, default preferences.ini, tools/update_check.ps1, full docs |

To run: extract → double-click `emule.exe` → click the **eSE** toolbar
button. The dashboard opens at http://localhost:8080.

---

## What's NOT in this release

- **Inno Setup `.exe` installer** — still ZIP-only. `installer/setup_ese.iss`
  updated and ready for the next build that has the compiler.
- **Digital signature** — SmartScreen "publisher unknown" persists.
- The deferred items from v7.0 ("drops after very long broadcasts",
  `gruk.org` HTTP fetch) are still pending; not regressed.

---

## Upgrading from v7.0

Extract the new ZIP over the old install **with eMule + ese-server stopped**.
Your settings under `%APPDATA%\eMule\` are preserved. The new C++
pre-flight will overwrite the `[WebServer] Password` in `preferences.ini`
with a per-install random value (32 hex chars), persisted at
`<config>\eSE_pass.bin`. If you were using the WebInterface from outside
eSE with a custom password, it'll be replaced — re-set yours via
Preferences → Web Server after the upgrade if needed.

The `.vbs` files are gone — any desktop shortcut pointing at `eSE.vbs`
will break. Repoint it at `emule.exe`.

---

## Backward compatibility

- `preferences.ini` — only standard upstream `[WebServer]` keys touched
  (`Enabled`, `Port`, `Password`). No new fields.
- `settings.json` — no new fields. Env-var fallback keeps standalone
  `ese-server.exe` launches working unchanged.
- Wire protocol — unchanged, compatible with vanilla 0.70b peers and
  all v6.x / v7.0 fork clients.

---

## Credits

Built by [@diad87](https://github.com/diad87) with Claude Code.
Integration of three claude/ work branches into one PR; merged as
[PR #5](https://github.com/diad87/eMule-eSE-LiveTV/pull/5).

GPL-2.0-only.
