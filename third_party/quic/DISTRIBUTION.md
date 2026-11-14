# QUIC dependency notices

The Windows x64 QUIC build uses ngtcp2 and its GnuTLS adapter. The build
compiles both from the signed ngtcp2 source archive with the Visual Studio
toolchain recorded in `dependencies.lock.json`. GnuTLS and its runtime
libraries come from the signed MSYS2 packages recorded in
`msys2-gnutls-x64-candidate.json`.

The dependency manifest records the exact DLL, notice and source archive
hashes. The source archives include the corresponding upstream source and,
for the MSYS2 packages, the package build recipes and patches. Each archive
is accompanied by its detached signature. The package inventory records the
upstream URLs and signing fingerprints.

The GnuTLS dependency and its runtime libraries are dynamically linked. Keep
the DLLs next to `emule.exe`. The respective notices and license texts apply
to each component. You can replace a DLL with a compatible modified build
under its license. The inventory lists the component supplying each DLL.
