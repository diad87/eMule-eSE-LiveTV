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

Append the explicit UDP port to enable RendezvousV2 on IPv4 loopback. Passing
`0` as the final argument asks Windows to assign the UDP port as well. The
server prints `RDV <port>` alongside the TLS port when both listeners are
ready. UDP return proof is bound to a logged-in TLS session that selected RDV2.
The verified observed endpoint and its remaining lease arrive over TLS.

The current reference implements the authenticated handshake, eD2K login,
server identity, empty server list, ping, lease renewal, atomic publication,
source hints and disconnect. It accepts up to sixteen simultaneous sockets
and retains publication state for up to sixteen primary identities per server
epoch. Only a current, authenticated primary makes its committed records
visible to source queries. Auxiliary sessions can request hints.

Clients that also negotiate CROSS_CALLBACK can use the reference's
voucher, consent and pairing exchange. Both sides must have a current UDP
return proof. The target must still publish the requested file. The reference
sends the verified endpoints only after an explicit consent response.
The pool allows up to 64 vouchers and 16 pending pairings.

The request cache remains session-local. Unicode search, cross-session
request replay, a classic plaintext listener, and QUIC remain pending.
eMule does not connect to this listener yet. The integration test proves
pairing on a single IPv4 loopback server, without DCO file transfer.

The independent integration test requires a Python environment with
`pyOpenSSL`. Set `ESE_SERVER_INTEROP_PYTHON` to its Python executable to add
the test to CTest. The test generates disposable keys and a trusted localhost
certificate, runs the reference on an assigned port and exercises the entire
TLS, application proof and login exchange.
