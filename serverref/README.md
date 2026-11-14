# eSE server reference

The reference listens on IPv4 loopback over TLS 1.3 with ALPN `ese-server/1`.
Provide PEM files for the TLS certificate, its private key and a separate,
persistent Ed25519 application key. Use a distinct key and certificate for
each reference instance.

Build with the verified signed Windows x64 dependency directory.

```powershell
$dependencyDirectory = 'D:/tmp/ese-quic-x64'
cmake -S serverref -B D:/tmp/ese-server-ref-build -A x64 "-DESE_QUIC_RELEASE_ROOT=$dependencyDirectory"
cmake --build D:/tmp/ese-server-ref-build --config Release
ctest --test-dir D:/tmp/ese-server-ref-build -C Release --output-on-failure
```

Run a bounded number of connections on a configurable port. Port zero asks
Windows to assign an unused loopback port, printed after the listener is ready.

```powershell
& D:/tmp/ese-server-ref-build/Release/ese-server-ref.exe 0 certificate.pem tls-key.pem node-key.pem 1
```

The current reference implements the authenticated handshake, eD2K login,
server identity, empty server list, ping, lease renewal and disconnect.
The request cache is session-local. Publication, search, source hints,
cross-session replay, a classic plaintext listener, QUIC and RendezvousV2
remain pending. eMule does not connect to this listener yet.

The independent integration test requires a Python environment with
`pyOpenSSL`. Set `ESE_SERVER_INTEROP_PYTHON` to its Python executable to add
the test to CTest. The test generates disposable keys and a trusted localhost
certificate, runs the reference on an assigned port and exercises the entire
TLS, application proof and login exchange.
