#!/usr/bin/env bash
set -euo pipefail

source_archive=$1
inputs=$2
output=$3
toolchain_cache=$4
offline=$5
recipe=$(dirname -- "$(realpath -- "${BASH_SOURCE[0]}")")

export LC_ALL=C TZ=UTC SOURCE_DATE_EPOCH=0
case "$(. /etc/os-release; printf '%s/%s' "$ID" "$VERSION_ID")/$(dpkg --print-architecture)" in
    ubuntu/24.04/amd64) ;;
    *) echo 'The Win32 dependency recipe requires Ubuntu 24.04 amd64.' >&2; exit 1 ;;
esac
[[ $toolchain_cache = /* && -d $output ]]
mkdir -p -- "$toolchain_cache"
toolchain_cache=$(realpath -- "$toolchain_cache")

build_root=$(mktemp -d /var/tmp/ese-quic-win32.XXXXXXXX)
trap '[[ $build_root == /var/tmp/ese-quic-win32.???????? ]] && rm -rf -- "$build_root"' EXIT
mkdir -- "$build_root/toolchain" "$build_root/build"

# Pin compiler, linker, headers and CRT. APT authenticates the Ubuntu archive,
# while the lock also authenticates copies supplied in offline caches.
while read -r sha archive; do
    archive=${archive%$'\r'}
    if [[ ! -f $toolchain_cache/$archive ]]; then
        [[ $offline == 0 ]] || { echo "Offline archive missing: $archive" >&2; exit 1; }
        IFS=_ read -r package version architecture <<< "$archive"
        (cd "$build_root" && apt-get download "$package:${architecture%.deb}=$version")
        (cd "$build_root" && printf '%s  %s\n' "$sha" "$archive" | sha256sum -c -)
        cp -- "$build_root/$archive" "$toolchain_cache/$archive"
    fi
    (cd "$toolchain_cache" && printf '%s  %s\n' "$sha" "$archive" | sha256sum -c -)
    dpkg-deb -x "$toolchain_cache/$archive" "$build_root/toolchain"
done < "$recipe/gnutls-win32-toolchain.sha256"

printf '%s  %s\n' ffed8ec1bf09c2426d4f14aae377de4753b53e537d685e604e99a8b16ca9c97e "$source_archive" | sha256sum -c -
tar -xf "$source_archive" -C "$build_root"
export PATH="$build_root/toolchain/usr/bin:/usr/bin:/bin"
export CC=i686-w64-mingw32-gcc-posix
export PKG_CONFIG_LIBDIR="$inputs/mingw32/lib/pkgconfig"
export PKG_CONFIG_SYSROOT_DIR="$inputs"
export CPPFLAGS="-I$inputs/mingw32/include"
export CFLAGS="-O2 -D_POSIX_C_SOURCE -ffile-prefix-map=$build_root=/usr/src/ese-quic -ffile-prefix-map=$inputs=/mingw-sysroot"
export LDFLAGS="-L$inputs/mingw32/lib -Wl,--no-insert-timestamp"
export gl_cv_have_weak=no

cd "$build_root/build"
"$build_root/gnutls-3.8.13/configure" --host=i686-w64-mingw32 --prefix=/mingw32 \
    --enable-shared --disable-static --disable-cxx --disable-nls --disable-rpath --disable-gtk-doc \
    --disable-libdane --disable-tests --without-p11-kit --disable-hardware-acceleration \
    gl_cv_double_slash_root=yes > "$output/gnutls-configure.log" 2>&1
make -C gl -j 4 > "$output/gnutls-gl.log" 2>&1
make -C lib -j 4 > "$output/gnutls-library.log" 2>&1
cp -- lib/.libs/libgnutls-30.dll "$output/libgnutls-30.dll"
