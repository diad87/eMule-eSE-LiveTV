# Third-party notices for eMule eSE 9.1.0-rc.2

This inventory describes the content of the Windows x64 portable candidate,
not every development tool installed on a build machine. eMule eSE and its
first-party modifications are distributed under the GNU General Public License
version 2; the complete text is included as [`license.txt`](license.txt).

Keep this file and `license.txt` with redistributed binaries. `BUILD_INFO.txt`,
`SHA256SUMS.txt` and the external ZIP checksum identify the exact candidate to
which this inventory applies.

## Executables and browser runtime in the portable package

| Packaged component | Version/source | License and notice |
|---|---|---|
| `emule.exe`, language DLLs, first-party dashboard code and project artwork | eMule eSE, derived from eMule 0.70b | GPL-2.0; see packaged [`license.txt`](license.txt) and the [project source](https://github.com/diad87/eMule-eSE-LiveTV). |
| `ese-server.exe` | First-party server built for a Node.js 22 Windows x64 runtime with `@yao-pkg/pkg` | The first-party application remains GPL-2.0. The executable embeds Node.js runtime components; see the official [Node.js license and bundled third-party notices](https://github.com/nodejs/node/blob/main/LICENSE). The build tool is MIT-licensed; see the [`@yao-pkg/pkg` license](https://github.com/yao-pkg/pkg/blob/main/LICENSE). |
| `ffmpeg.exe`, `ffprobe.exe` | FFmpeg 8.1 full build distributed by Gyan.dev | The selected build reports `--enable-gpl --enable-version3`; its distributor labels the static builds GPLv3. See [FFmpeg legal information](https://ffmpeg.org/legal.html), the exact [FFmpeg 8.1 source tag](https://github.com/FFmpeg/FFmpeg/tree/n8.1) and the [Gyan.dev build/source page](https://www.gyan.dev/ffmpeg/builds/). The exact configure line remains available with `ffmpeg.exe -version`. |
| `eSE/eSE-live/vendor/hls.min.js` | hls.js 1.6.16 | Apache-2.0. The complete notice is packaged at `eSE/eSE-live/vendor/hls.LICENSE`; upstream source and notices are at [video-dev/hls.js 1.6.16](https://github.com/video-dev/hls.js/tree/v1.6.16). |

There is no separate `node.exe` in the portable package. Development
`node_modules` are not copied into it, and `hls.js` is the only production npm
dependency declared for the dashboard. Automatic updating is disabled:
`eSE-live/update_notifier.js` is an inert first-party compatibility stub
(`UPDATES_DISABLED=true`) with no network or process launch, and its update
routes return `410`. No updater executable or installer is packaged or
invoked.

## Libraries incorporated into `emule.exe`

The native executable is a GPL combined work. The current build links the
following third-party libraries. Their source is present in the corresponding
source distribution, while these HTTPS links provide durable license notices
for readers of the portable binary package.

| Library | License used by its upstream project | Official notice/source |
|---|---|---|
| Crypto++ | Boost Software License 1.0 for the compilation; individual-file notices also apply | [Crypto++ `License.txt`](https://github.com/weidai11/cryptopp/blob/master/License.txt) |
| Mbed TLS | Dual Apache-2.0 OR GPL-2.0-or-later | [Mbed TLS `LICENSE`](https://github.com/Mbed-TLS/mbedtls/blob/development/LICENSE) |
| miniupnpc | BSD-3-Clause | [miniupnp `LICENSE`](https://github.com/miniupnp/miniupnp/blob/master/LICENSE) |
| libutp | MIT | [libutp `LICENSE`](https://github.com/bittorrent/libutp/blob/master/LICENSE) |
| zlib | zlib License | [zlib license](https://zlib.net/zlib_license.html) |
| libpng | PNG Reference Library License version 2 | [libpng `LICENSE`](https://github.com/pnggroup/libpng/blob/libpng16/LICENSE) |
| id3lib | GNU Library General Public License 2.0 or later | [id3lib project files](https://sourceforge.net/projects/id3lib/files/) |
| CxImage | CxImage license (zlib-style permissive terms) | [license in the eMule eSE source tree](https://github.com/diad87/eMule-eSE-LiveTV/blob/main/CxImage/CxImage/license.txt) |
| ResizableLib | Artistic License 2.0 | [license in the eMule eSE source tree](https://github.com/diad87/eMule-eSE-LiveTV/blob/main/ResizableLib/LICENSE.md) |

Windows system libraries supplied by the operating system and the Visual C++
toolchain are not redistributed as standalone files by this package.

## Corresponding source

- eMule eSE source, including the native libraries above and the first-party
  dashboard: [github.com/diad87/eMule-eSE-LiveTV](https://github.com/diad87/eMule-eSE-LiveTV).
  Use the commit recorded in `BUILD_INFO.txt`; a candidate is not a published
  release until its matching tag and assets exist.
- FFmpeg and the libraries enabled in the bundled full build: use the exact
  8.1 source/build links above and retain the configure line printed by the
  packaged executable.
- hls.js 1.6.16 and Node.js: use the exact upstream links in the executable
  inventory above.

Data/configuration files are not presented here as separately licensed
executable dependencies.

_Inventory checked against the intended 9.1.0-rc.2 package layout on
2026-07-26._
