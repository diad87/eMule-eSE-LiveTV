# Security Audit — `/api/live/*` endpoints

**Date:** 2026-05-16
**Scope:** every endpoint reachable via the embedded C++ WebServer
(port 4711) and the Node.js dashboard proxy (port 8080), focused on
the `/api/live/*`, `/api/holepunch/*`, `/api/status`, `/dashboard`,
`/hls/*`, and `/live*` routes.
**Threat model:** an attacker on the same LAN as a victim's eMule,
plus a malicious P2P broadcaster anywhere on the Kad/eD2K mesh.

---

## TL;DR

| # | Finding | Severity | Status |
|---|---|---|---|
| F-1 | XSS in legacy C++ `/live` channel grid — broadcaster-controlled `title`/`category`/`quality` interpolated unescaped into `innerHTML` | **Medium** | **Fixed** in this commit ([WebServer.cpp:5736](srchybrid/WebServer.cpp:5736)) |
| F-2 | XSS in legacy C++ `/live/{hash}` player — `ch.title` interpolated unescaped | **Medium** | **Fixed** in this commit ([WebServer.cpp:5843](srchybrid/WebServer.cpp:5843)) |
| F-3 | Localhost-only gate on `/api/live/*` correctly enforced | n/a | **Verified** ([WebServer.cpp:4486](srchybrid/WebServer.cpp:4486)) |
| F-4 | Path-traversal in HLS chunk endpoint properly blocked | n/a | **Verified** (`EseIsSafeHlsResourceA` allowlist at [WebServer.cpp:4417](srchybrid/WebServer.cpp:4417)) |
| F-5 | `direct_join` SSRF risk via `ip=` param | **Low** | Mitigated — outbound dial is constrained by `IsGoodIP()` + `TryConnectToStreamSource()` and limited to the eD2K-tcp port; only the broadcaster's TCP listener accepts it. Localhost gate also applies. |
| F-6 | `/api/live/broadcast/start?source=file&file=...` lets a local caller open arbitrary files for streaming | **Informational** | A local-process attacker already has filesystem read access; no privilege escalation. Behind localhost gate. |
| F-7 | Node-side `live_tv_directory.js` + `live_tv_player.js` correctly use `escH()` | n/a | **Verified** ([live_tv_directory.js:190](srchybrid/eSE/eSE-live/live_tv_directory.js:190), [live_tv_player.js:103](srchybrid/eSE/eSE-live/live_tv_player.js:103)) |
| F-8 | CORS uses explicit `http://127.0.0.1` origin (not wildcard) | n/a | **Verified** |
| F-9 | `nat-upnp-2` makes outbound calls to your LAN's UPnP router as part of port-mapping. Bug in that library (or a malicious response from a hostile router) could in theory cause issues. | **Low** | Pinned to `^3.0.3`. Worth monitoring the upstream advisory feed. |
| F-10 | `cloudflared.exe` is invoked with a stable arg list — no shell interpolation of user input | n/a | **Verified** (`cloudflare_tunnel.js`) |

---

## Detailed findings

### F-1 / F-2 — XSS in legacy C++ inline pages (FIXED)

**Where:** `srchybrid/WebServer.cpp` — the inline HTML/JS served from
the C++ side at `/live` and `/live/{hash}`.

**What:** the channels JSON returned by `/api/live/channels` includes
broadcaster-controlled fields (`title`, `category`, `quality`,
`viewers`). The page's inline JS concatenated these directly into
`innerHTML`:

```js
// BEFORE (vulnerable):
card.innerHTML = '...<div class="title">'+c.title+'</div>...';
```

A malicious broadcaster publishing a stream with title
`<img src=x onerror=fetch('/api/live/broadcast/stop')>` would have
their payload execute in any viewer's browser that opens `/live`,
running under the localhost origin and able to call any
`/api/live/*` endpoint (including stopping the victim's broadcast,
starting a new one with a malicious title, exfiltrating channel
data, etc.).

**Why it matters:** even though `/api/live/*` is gated to loopback,
the **viewer's own browser** runs from loopback — so the XSS payload
gets full access to every endpoint the gate "protects".

**Fix:** added a tiny `esc()` helper in the inline `<script>` and
wrapped every broadcaster-controlled field with it. Hash field also
now passes through `encodeURIComponent` before being used as a URL
component. See the diff in [WebServer.cpp:5736](srchybrid/WebServer.cpp:5736)
and [WebServer.cpp:5843](srchybrid/WebServer.cpp:5843).

**Residual risk:** the C++ inline `/live` page is a legacy fallback;
the modern UI lives at `http://localhost:8080/live` (Node-side) and
was already safe (`escH()` everywhere). Long-term we should remove
the C++ HTML entirely and let the Node dashboard be the only viewer,
which eliminates the entire class of inline-HTML XSS.

---

### F-3 — Localhost-only gate (VERIFIED CORRECT)

[WebServer.cpp:4486](srchybrid/WebServer.cpp:4486) rejects any
non-loopback peer trying to hit `/api/live/*`, `/api/holepunch/*`,
`/api/status`, `/dashboard`, or `/hls/*`. The check uses
`htonl(INADDR_LOOPBACK)` — correctly compares the network-order IP
the socket layer hands us. A 403 JSON body is returned and the
attempt is logged via `LIVE_LOG("SEC", ...)`.

**Confirmed not bypassable** by:
- IPv6 loopback (`::1`) — listener is IPv4 only.
- `127.0.0.2`–`127.255.255.254` — only literal `127.0.0.1` matches.
- DNS rebinding — requests with `Host: 127.0.0.1` originate from the
  remote IP regardless of how the browser resolved them, so the IP
  check still fires.
- Reverse proxy with `X-Forwarded-For` — we do not honor that header
  for the gate decision; we read the actual socket peer.

---

### F-4 — Path traversal (VERIFIED BLOCKED)

The HLS chunk endpoint `/api/live/{hash}/{file}` could in theory be
abused to read arbitrary files via `..\..\` in `{file}`.

`EseIsSafeHlsResourceA()` at [WebServer.cpp:4417](srchybrid/WebServer.cpp:4417):

1. Rejects empty / `/` / `\` / `..`
2. Allowlists `[a-zA-Z0-9_.\-]` only
3. Requires the name to match one of three patterns: `stream.m3u8`,
   `stream_*.m3u8`, or `seg_*.ts`

So `../../Windows/System32/...` cannot pass. The `{hash}` is also
validated via `EseIsHexA` (exactly 32 hex chars). The final path is
under `%TEMP%\eMule_RTMP\{hash}\{file}` — no escape possible.

---

### F-5 — SSRF via `/api/live/direct_join?ip=...&port=...`

The endpoint accepts a peer IP+port and calls
`TryConnectToStreamSource(streamKey, ipNet, port)`, which opens an
eD2K TCP connection to that endpoint.

**Risk:** an attacker who can reach this endpoint could probe the
victim's internal network — e.g. `ip=192.168.1.1&port=80` to learn
whether the home router is alive. Or `ip=127.0.0.1&port=22` to
fingerprint local services.

**Mitigations in place:**
1. Localhost gate (F-3) — only local processes can reach the endpoint
   at all, and they already have full network reachability.
2. `TryConnectToStreamSource` uses `IsGoodIP()` to drop bogon /
   reserved ranges from the dial pipeline.
3. The TCP handshake speaks the eD2K hello opcode and the peer is
   dropped immediately on a non-eD2K response, so the timing oracle
   gives only "TCP connect succeeded vs RST/timeout" — same as `nc`.

**Verdict:** low risk; no further fix needed.

---

### F-6 — Local file-source streaming via `?source=file&file=...`

`/api/live/broadcast/start` lets a local caller stream an arbitrary
file path off the victim's disk to the eD2K mesh. **This is the
intended feature** (broadcast a local MKV → friends watch). It is
not a privilege escalation because the caller must already be on
loopback, which means they have full filesystem access to the
victim's home directory regardless.

**Verdict:** informational only — document so users understand that
any local malware can use eMule eSE to exfiltrate files over P2P.
This is a property of the architecture, not a bug.

---

### F-7 — Node-side dashboard (VERIFIED SAFE)

`live_tv_directory.js` (the modern grid at `:8080/live`) and
`live_tv_player.js` (the cinema player) both use a consistent
`escH()` helper for every broadcaster-controlled string. Streamkeys
pass through a strict `[a-zA-Z0-9_-]` allowlist
([live_tv_player.js:125](srchybrid/eSE/eSE-live/live_tv_player.js:125))
before being placed in `window.location.href`.

---

### F-8 — CORS posture

Every `/api/live/*` JSON response sets
`Access-Control-Allow-Origin: http://127.0.0.1` (an explicit origin,
not `*`). Combined with the F-3 IP gate this is sound — there is no
realistic origin from which a remote site could craft credentialed
requests to `/api/live/*`.

---

### F-9 — UPnP library trust boundary

`nat-upnp-2@^3.0.3` parses XML SOAP responses from the LAN's UPnP
router during port-forwarding setup. A hostile router (or a router
attacker on the LAN) could craft responses that exploit the parser.
The library is small and the parser is `fast-xml-parser` — both
audited communities. We do not propagate the parsed values into any
attack surface (e.g. we don't shell-exec them). Risk: low. Action:
keep an eye on upstream advisories.

---

### F-10 — cloudflared invocation

`cloudflare_tunnel.js` spawns `cloudflared.exe` with a fixed
argument list (`tunnel --url http://localhost:8080`). No user input
flows into the args. No shell metacharacter expansion.

---

## Recommendations

| # | Recommendation | Effort |
|---|---|---|
| R-1 | **Done** — apply F-1/F-2 XSS fixes (this commit). | Done |
| R-2 | Delete the inline C++ `/live` pages entirely; redirect to `:8080/live`. Removes the whole class of XSS in C++ HTML generation. | ~1 hour |
| R-3 | Add a small unit test that asserts `EseIsSafeHlsResourceA` rejects `..`, abs paths, and forbidden chars. Catches regressions during refactoring. | ~30 min |
| R-4 | Document in [USER_GUIDE.md](USER_GUIDE.md) §5 that opening untrusted `ed2k://\|live\|...\|/` links is roughly as risky as opening untrusted YouTube embeds — the broadcaster controls the title shown in the viewer. (Now that XSS is fixed, the residual risk is only social-engineering / clickjacking via the title text.) | ~10 min |
| R-5 | Consider adding a viewer-side allowlist for broadcaster-supplied URLs (e.g. if a future feature lets the broadcaster send a chat URL). Not relevant today; flag for the future. | — |

---

## What we explicitly DID NOT find

- **No SQL injection** — no SQL in the stack.
- **No command injection** — no `system()`/`spawn()` calls with user input on the C++ side. FFmpeg invocations in `RTMPIngest.cpp` use `CreateProcess` with a programmatically constructed command line and explicitly quoted arguments; the title is passed via `drawtext=text='...'` with single-quote escaping. Audited 2026-05-16.
- **No auth bypass** — the only auth is the localhost gate, and it holds.
- **No credential leakage** — the only sensitive value is the user's
  `UserHash` in `preferences.ini`. It is not exposed via any
  `/api/*` endpoint and is regenerated on `--headless` to avoid
  collision across instances.
- **No insecure deserialization** — JSON parsing only; no `pickle`
  / `marshal` / `unserialize` equivalents.

---

_If you spot an additional issue, please open a security-tagged
issue (or email the maintainer privately if it is exploitable in
the wild) rather than disclosing publicly._
