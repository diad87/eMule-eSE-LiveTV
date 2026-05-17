# eMule eSE LiveTV v0.70b-eSE7.1.1 — 2026-05-17

Point release on top of [v0.70b-eSE7.1](RELEASE_NOTES_v0.70b-eSE7.1.md). One
critical bugfix that broke the v7.1 release for almost everyone.

---

## The fix

`ese-server.exe` was getting `ECONNREFUSED` when calling eMule's WebServer
at `http://localhost:4711`, even though eMule's WebServer was correctly
listening on that port (v7.1's whole C++ pre-flight worked as designed).

**Root cause:** Node 18 (which `pkg` uses to bundle `ese-server.exe`) resolves
`localhost` to `::1` (IPv6) first on Windows. eMule's WebServer binds
`INADDR_ANY` ([WebSocket.cpp:449](srchybrid/WebSocket.cpp#L449)) which is
IPv4-only — so the request hits `::1:4711` and fails ECONNREFUSED. Node 18
does NOT auto-fall-back to IPv4 like browsers do.

The new error UI introduced in v7.1 helpfully diagnosed this as
`webserver_down` and offered a "He abierto eMule" button, but the underlying
issue persisted regardless of how many times the user retried.

**Fix:** one-line change in [`srchybrid/eSE/emule_api.js`](srchybrid/eSE/emule_api.js)
— use the IPv4 literal `127.0.0.1` instead of `localhost`. Forces IPv4 always.

---

## Upgrading from v7.1

Two options:

1. **Re-download the ZIP** and extract over your v7.1 install (your settings
   under `%APPDATA%\eMule\` are preserved).
2. **Hot-swap just `ese-server.exe`**: download `ese-server.exe` from this
   release's assets and replace the one in your v7.1 install. Then close
   and reopen eMule.

---

## Known issues

### Streaming-time crash (inherited from upstream eMule 0.70b)

A small fraction of streaming sessions can trigger an access-violation crash
(`0xc0000005`) in eMule's MFC string code, with eMule writing a minidump to
`%APPDATA%\eMule\config\crashdumps\` and offering to open the folder on
next launch.

This is a **pre-existing bug from before this fork** — the same crash signature
(access violation reading what looks like a UTF-16 string treated as a
pointer, suggesting a `CString` use-after-free) appeared multiple times during
v7.0 testing too. It has nothing to do with the v7.1.x WebServer/login work.

The eSE streaming pipeline is resilient to eMule restarts (the .part files
on disk are intact; ese-server picks up where it left off when eMule comes
back), so impact is "eMule disappears, restart it". Investigation continues
toward a fix in a future release.

If you hit it: the `.dmp` file in `%APPDATA%\eMule\config\crashdumps\` is
useful — attach it to a GitHub issue if you're willing.

---

## Everything else

See [v0.70b-eSE7.1 release notes](RELEASE_NOTES_v0.70b-eSE7.1.md) — that's the
substantive release. v7.1.1 is purely the IPv4 hotfix on top.

---

GPL-2.0-only.
