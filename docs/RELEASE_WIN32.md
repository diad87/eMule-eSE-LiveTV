# eMule eSE for Win32

The Win32 portable ZIP contains the 32-bit eMule application, the verified
Win32 QUIC runtime, language DLLs, and the native authenticated WebServer.
The bundled profile and native WebServer template are in `config`.

Extract the ZIP to a writable directory. For an upgrade, close eMule, back up
your existing profile and downloads, and copy the new program and runtime DLLs
into the installation. Keep your existing `config`, incoming files and partial
downloads. Import a fresh packaged profile only for a new installation.

Configure the native WebServer password in Options before using the web
interface. Use the configured loopback port from the same computer and sign in
with that password. The native WebServer keeps its existing authentication.

The companion dashboard and bundled FFmpeg are supplied by the x64 ZIP. The
Win32 ZIP covers the native eMule and QUIC workflow.
