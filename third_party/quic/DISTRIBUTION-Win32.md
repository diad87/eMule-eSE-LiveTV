# Win32 QUIC dependency notices

The Win32 build compiles ngtcp2 and its GnuTLS adapter from the signed
ngtcp2 source archive with the Visual Studio toolchain recorded in
`dependencies.lock.json`. It builds GnuTLS from the upstream archive in the
signed MSYS2 source package using `rebuild_gnutls_win32.sh` without hardware
acceleration. The alternative avoids a fault in accelerated AES-GCM on x86.

The associated source bundle includes the rebuild script, its cross-compiler
archive hashes, the ngtcp2 source, and the corresponding MSYS2 source archives
with their packaging recipes and patches. Each upstream or MSYS2 archive has
a detached signature. The MSYS2 inventory records the URLs and signing
fingerprints for these archives and the corresponding binary inputs.

GnuTLS and its runtime libraries are dynamically linked. Keep the Win32 DLLs
next to `emule.exe`. The associated notices and license texts apply to each
component. You can replace a DLL with a compatible modified build under its
license. The inventory lists the component supplying each DLL.
