# Third-Party Licenses

eMule eSE (this fork) is GPL-2.0 — see [license.txt](license.txt).
The binary distribution ships with several third-party components, each
under its own license. This document lists them so downstream users and
redistributors can comply with GPL §3 (binary distribution must come
with, or offer, the corresponding source / written license).

If you are repackaging this build, **ship this file alongside the
binaries** and keep the upstream LICENSE files in their original
directories.

---

## Bundled executables (binary distribution)

| Binary | Upstream | License | Notes |
|---|---|---|---|
| `emule.exe` | this repo, fork of eMule 0.70b | GPL-2.0-only | Full source in this repo. See [license.txt](license.txt). |
| `ese-server.exe` | this repo (`srchybrid/eSE/`) | GPL-2.0-only | Node.js project compiled with [`pkg`](https://github.com/vercel/pkg). Embeds Node.js runtime — see below. |
| `ffmpeg.exe` | [ffmpeg.org](https://ffmpeg.org) (Gyan build) | LGPL-2.1-or-later, **GPL-3.0** if built with `--enable-gpl` | We bundle the unmodified upstream binary. Per LGPL §6 the user may replace `ffmpeg.exe` with any compatible build. |
| `node.exe` | [nodejs.org](https://nodejs.org) | MIT | Used to run `eSE/server.js` in dev / unpackaged mode. |
| `cloudflared.exe` | [github.com/cloudflare/cloudflared](https://github.com/cloudflare/cloudflared) | Apache-2.0 | Optional HTTPS fallback tunnel. Disabled by default. See `feedback_cloudflare_tos.md` — relying on CF for content delivery is discouraged. |

---

## Native libraries statically linked into `emule.exe`

These ship as source in the repository (their unmodified upstream
LICENSE files are preserved). When you redistribute `emule.exe` in
binary form, you are redistributing object code derived from these
libraries.

| Library | Path in repo | License | Effect on GPL combined work |
|---|---|---|---|
| **Crypto++** | [cryptopp/License.txt](cryptopp/License.txt) | Boost-1.0-equivalent (compilation) / Public Domain (individual files) | GPL-compatible |
| **mbedTLS** | [mbedtls/LICENSE](mbedtls/LICENSE) | Apache-2.0 | GPL-compatible (GPL-2-or-later only — we are GPL-2-only, see Note 1) |
| **miniupnpc** | [miniupnpc/LICENSE](miniupnpc/LICENSE) | BSD-3-Clause | GPL-compatible |
| **libutp** | [libutp/LICENSE](libutp/LICENSE) | MIT | GPL-compatible |
| **zlib** | [zlib/LICENSE](zlib/LICENSE) | Zlib | GPL-compatible |
| **libpng** | [libpng/LICENSE](libpng/LICENSE) | libpng license (BSD-style) | GPL-compatible |
| **id3lib** | [id3lib/COPYING](id3lib/COPYING) | LGPL-2.0-or-later | GPL-compatible |
| **CxImage** | [CxImage/CxImage/license.txt](CxImage/CxImage/license.txt) | zlib-style | GPL-compatible |
| **ResizableLib** | [ResizableLib/LICENSE.md](ResizableLib/LICENSE.md) | Artistic-2.0 / MIT dual | GPL-compatible |

**Note 1 (mbedTLS / GPL-2 only):** Apache-2.0 is compatible with GPL-3
but generally regarded as incompatible with GPL-2-only. Upstream eMule
shipped this combination historically and we preserve the practice;
downstream redistributors who care about strict purity should consider
either (a) re-licensing the combined work as GPL-2-or-later, which the
GPL-2 text permits, or (b) replacing mbedTLS with a GPL-2-compatible
TLS implementation.

---

## Node.js runtime (embedded in `ese-server.exe`)

`pkg` bundles a full Node.js runtime into `ese-server.exe`. That
bundled runtime contains, at minimum:

- **Node.js** — MIT
- **V8** — BSD-3-Clause
- **OpenSSL** — Apache-2.0 (Node 18+)
- **libuv** — MIT
- **c-ares** — MIT
- **zlib, llhttp, nghttp2** — Zlib / MIT / MIT

The unmodified upstream license texts are reproduced inside the
official Node.js distribution; see <https://github.com/nodejs/node/blob/main/LICENSE>.

---

## npm dependencies (resolved into `ese-server.exe`)

Direct dependency declared in [srchybrid/eSE/package.json](srchybrid/eSE/package.json):

- **nat-upnp-2** — MIT

`pkg` walks the transitive tree at build time. The complete list of
modules under `srchybrid/eSE/node_modules/` (each retaining its own
LICENSE file) includes roughly: `bl`, `buffer`, `debug`, `fast-xml-parser`,
`https-proxy-agent`, `iconv-lite`, `ip`, `nat-upnp-2`, `needle`,
`node-fetch`, `pkg-fetch`, `pump`, `safe-buffer`, `semver`, `tar-stream`,
`yargs`, and their transitive closure.

All are individually published under permissive licenses — overwhelmingly
**MIT**, with a few **ISC**, **BSD-2-Clause**, **BSD-3-Clause**, and
**Apache-2.0**. None are GPL or copyleft.

To regenerate the exact list against your current install:

```powershell
cd srchybrid\eSE
npm ls --all --json | ConvertFrom-Json | ... # inspect "name" + license
# or:
npm install -g license-checker
license-checker --production --csv > THIRD_PARTY_NPM.csv
```

---

## Runtime data files (bundled in the portable ZIP)

- **`config/server.met`** — eD2K server list, public domain (community-maintained, fetched from `gruk.org` if missing).
- **`config/nodes.dat`** — Kad DHT bootstrap nodes, public domain (fetched from `nodes-dat.com` if missing).
- **`config/eMule.tmpl`** — WebServer template, eMule project (GPL-2.0).
- **`emule_mascot.svg`, `favicon.ico`** — this repo, GPL-2.0.

---

## Trademarks

- "eMule" is the name of the upstream project at <https://emule-project.net>.
  This fork is **not** an official eMule release; it is a derivative
  work distributed under the GPL.
- "FFmpeg" and "Cloudflare" are trademarks of their respective owners
  and are used here in their nominative sense (to identify the
  bundled binary).
- "Node.js" is a trademark of the OpenJS Foundation.

---

## How to obtain corresponding source

Per GPL-2 §3, the complete corresponding source code for every
GPL/LGPL component in this distribution is available:

- **eMule eSE (this fork)** — this Git repository.
- **FFmpeg** — <https://ffmpeg.org/download.html> (the upstream
  release matching the version printed by `ffmpeg.exe -version`).
- **id3lib (LGPL)** — see [id3lib/](id3lib/) in this repo.
- **mbedTLS, miniupnpc, libutp, zlib, libpng, CxImage, ResizableLib,
  CryptoPP** — see their respective subdirectories.
- **Node.js, pkg, npm modules** — see the URLs in [srchybrid/eSE/package.json](srchybrid/eSE/package.json) `dependencies` / the `repository` field of each `node_modules/*/package.json`.

---

_Last updated: 2026-05-16. If you spot a missing attribution, open
an issue or PR._
