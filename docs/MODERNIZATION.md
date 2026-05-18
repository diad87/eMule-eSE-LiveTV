# Modernization candidates — "this was fine in 2005, not in 2026"

A pragmatic inventory of components in this codebase whose age now
costs us correctness, security, performance, or maintainability.
Ranked by ROI (impact ÷ effort). Items at the top are the ones I'd
do first if I were spending a quarter on this.

The "blast radius" column is what breaks if you swap in the
replacement.

| # | Component | Replace with | Why | Effort | Blast radius |
|---|---|---|---|---|---|
| 1 | **id3lib** (last release 2003-09; abandonware) | **TagLib** (active, LGPL/MPL) or **libid3tag** | Reads MP3 ID3v1/v2 metadata for shared audio files. Carries known UB. TagLib also supports FLAC, OGG, MP4, M4A, WAV, ASF — useful for the modern shared-media world. | ~3 days | `KnownFile.cpp`, `FileInfoDialog.cpp` — both call a tiny ID3 surface. |
| 2 | **Inline HTML in WebServer.cpp** (`/live`, `/live/{hash}`, `/dashboard`, etc.) | Delete entirely; redirect to the Node dashboard at `:8080/live` | Just bit us with two XSS bugs (see `SECURITY_AUDIT.md` F-1/F-2). C++ string-concatenated HTML has zero tooling — no linter, no template engine, no auto-escape. Node side already has the modern UI and uses `escH()` everywhere. | 1 day | The legacy `:4711/live` URL becomes a 302 to `:8080/live`. Nobody bookmarks the legacy page. |
| 3 | **CxImage** (last release 2011; CVEs unfixed) | **WIC** (Windows Imaging Component, built into Windows since XP SP3) or **stb_image** for the few formats we care about | Image decode for thumbnails, file-info dialogs, captcha. WIC is OS-native, hardware-accelerated for common formats, and patched via Windows Update. CxImage is ~150k LOC of unmaintained C++ that we don't need. | ~1 week | `CaptchaGenerator.cpp`, `FileInfoDialog.cpp`, `MiniMule.cpp`, `TitleMenu.cpp`, `BaseClient.cpp`. Mechanical replace — the surface is just "load image bytes → HBITMAP". |
| 4 | **IE WebBrowser COM control** (`IESecurity.cpp`, several dialogs) | **WebView2** (Edge Chromium) | IE is end-of-life since June 2022. Microsoft pushes apps to WebView2. Smaller surface, modern JS, no zone-security tax, no SBCS warnings. | ~1 week | Dialogs that currently embed `IWebBrowser2`. Need to ship `WebView2Loader.dll` (~150 KB) and an evergreen Edge runtime presence (already installed by Win10/11). |
| 5 | **MFC CSocket / CAsyncSocket** (`ListenSocket`, `WebSocket`, `UDPSocket`, `ServerSocket`, `ServerConnect`) | **IOCP** directly, or **asio (Boost.Asio / standalone)** | The current per-socket-message-pump model doesn't scale past a few hundred connections; you can feel it during peer churn (UI hitches). IOCP scales to 10k+ trivially, asio gives you composable async patterns and is what every modern C++ network app uses. | ~3 weeks (very invasive) | Most of the network layer. Worth doing alongside a transport switch (item #8). |
| 6 | **printf-style format strings (`%S`, `%s`, `%d`, …)** | **`std::format` (C++20)** or **fmtlib** | The t=8s crash on 2026-05-15 was `%S` (expects `LPCWSTR`) passed an `int`. `std::format("{}", ...)` catches the mismatch at compile time. Convert hot logging paths first. | ~ongoing, by file | None — `std::format` and printf can coexist. |
| 7 | **Crypto API (`HCRYPTPROV` + `CryptAcquireContext` family)** in `SendMail.cpp` | **BCrypt / CNG** | The classic Crypto API is in maintenance mode since Vista; CNG is the supported path (BCryptGenRandom, BCryptOpenAlgorithmProvider, etc.). For random bytes specifically, `BCryptGenRandom(BCRYPT_USE_SYSTEM_PREFERRED_RNG)` is a one-line replacement. | half a day | Just `SendMail.cpp`. |
| 8 | **Custom uTP + manual NAT hole-punch** | **QUIC** (RFC 9000, e.g. **msquic** by Microsoft, **picoquic**) | QUIC gives encryption, multipath, 0-RTT, congestion control, and connection migration for free, with NAT traversal that just works for ~80% of NATs. Our `eMuleAI/UtpSocket.cpp` reimplements a chunk of this. Massive simplification long-term. | ~6 weeks | Wire protocol change. Can be opt-in next to the existing eD2K-tcp/uTP transports; existing peers keep working. |
| 9 | **MFC dialog UI** as the primary surface | **WebView2 host** rendering the existing `/live` Node UI | The win32/MFC UI looks like 2005 because it _is_ 2005. We already have a modern UI on `:8080/live`. Replacing the main window with a WebView2 control pointed at `http://127.0.0.1:8080/live` would let us delete ~30% of the C++ codebase (`PPg*.cpp` preferences pages, `*Dlg.cpp` dialogs) and ship a UI that scales DPI / supports dark mode / is themeable. | ~2 months | Whole UI tree. Can be done incrementally one dialog at a time. |
| 10 | **`v141_xp` toolset** (still targets Windows XP via `v141_xp` PlatformToolset) | **`v143`** (VS2022 default), drop XP/Vista/7 | We're spending compile time and code complexity supporting OSes that Microsoft hasn't patched in years. Modern toolset enables `std::filesystem`, `std::format`, `concepts`, thread pools (`CreateThreadpoolWork`), `GetSystemTimePreciseAsFileTime`, etc. | half a day to flip + ongoing simplification | All `#ifdef _WIN32_WINNT_*` guards. None at runtime — the resulting binary is smaller and faster, runs on Win10+. |
| 11 | **Manual `HANDLE` + `CreateThread` + `CRITICAL_SECTION` + `WaitForSingleObject`** | **`std::thread` / `std::mutex` / `std::condition_variable` / `std::jthread` (C++20)** | RAII, exception-safe, no leaked handles. We've already mixed both styles; consolidating on the std side removes a ton of `CloseHandle` boilerplate and a class of "forgot to release the CS on exception" bugs. | ~ongoing, by file | None — interop is fine. |
| 12 | **WinINet via `#include <afxinet.h>` / `CHttpFile` / `CInternetSession`** (`SendMail.cpp`) | **WinHTTP** (`<winhttp.h>`) | WinINet is the IE HTTP stack. WinHTTP is the system-service one — better TLS, no per-user proxy quirks, supported on Windows Server. Same API shape, mostly mechanical. | half a day | `SendMail.cpp` only — small. |
| 13 | **Random number generation (`rand()` / `srand()` scattered)** | **`std::mt19937` + `std::random_device`** for non-crypto; **`BCryptGenRandom` / CryptoPP** for crypto | We already migrated security-critical paths (good). Remaining `rand()` calls are mostly cosmetic (jitter, retry backoff) but `rand()` is single-seed-per-program with awful distribution. | ~half a day | None — drop-in. |
| 14 | **Charset / codepage juggling for filenames (windows-1252 / shift_jis / big5)** in `I18n.cpp` | **UTF-8 everywhere** with `/manifest:utf8` (Win10 1903+) | Modern Windows lets a process declare UTF-8 as its ANSI code page. eD2K wire protocol can stay legacy; only the in-memory representation collapses to one codepath. Removes ~500 LOC of charset detection. | ~1 week | Anywhere we lower-case / compare filenames. Test on Japanese / Cyrillic / Hebrew filenames. |
| 15 | **SHA-1 in AICH (hash tree)** | **BLAKE3** or **SHA-256** for new extensions | SHA-1 is collision-broken since SHAttered (2017). For content-addressed P2P this isn't a security catastrophe (you can't sign anything), but a new mesh-extension opcode could carry BLAKE3 hashes alongside SHA-1 for forward compat. The eD2K base protocol stays SHA-1 for compat with all existing peers. | ~1 week | Additive — old peers keep working. |
| 16 | **CMake / Bazel build** instead of `.vcxproj` + `.sln` | **CMake** | The 9-project `.sln` doesn't include the 43 language projects (we discovered this fixing the lang-DLL build today). CMake would express the whole thing in ~300 LOC, build on CI without msbuild gymnastics, and unlock cross-compilation if we ever care. | ~2 weeks | All build tooling. The CI workflow (D8) would simplify too. |

---

## What I would actually ship next quarter

If I had to pick three:

1. **#2 (delete inline C++ HTML)** — small, removes a real XSS class, and we get back the same UX from the Node side.
2. **#6 (`std::format`)** — incremental, prevents the next %S crash, no risk.
3. **#10 (drop v141_xp)** — half-day flip, unlocks #11 / #14 / #16 cleanly.

The rest are real but each is a multi-week project. Most of them have
real ROI; none of them are required to ship the current version.

---

## What I'd explicitly NOT replace

- **MFC** itself — replacing it costs months and gains nothing concrete because the dialogs *work*. If we ever do #9, MFC dies naturally.
- **CryptoPP** — heavy but stable, well-audited, and used in the eD2K protocol where we can't change algorithms without breaking compat. Keep for protocol crypto; use BCrypt for new system-level needs.
- **miniupnpc, libutp, zlib, libpng, mbedTLS, ResizableLib** — these are the right call. Stable, small, well-maintained.

---

_Last updated: 2026-05-16._
